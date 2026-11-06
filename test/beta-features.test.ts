// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { AuditTrail } from "../src/core/audit.ts";
import { AgentShield } from "../src/core/engine.ts";
import { isCommandSafe, isSqlSafe, isUrlSafe } from "../src/core/sanitizer.ts";
import type { ShieldPolicy } from "../src/core/types.ts";

test("isUrlSafe blocks SSRF targets including cloud metadata and private IPs", () => {
  // Loopback and metadata
  assert.equal(isUrlSafe("http://localhost:8080").safe, false);
  assert.equal(isUrlSafe("http://127.0.0.1/admin").safe, false);
  assert.equal(isUrlSafe("http://169.254.169.254/latest/meta-data/").safe, false);
  assert.equal(isUrlSafe("http://metadata.google.internal/computeMetadata/v1/").safe, false);

  // Private networks
  assert.equal(isUrlSafe("http://10.0.1.5:3000").safe, false);
  assert.equal(isUrlSafe("http://192.168.1.100").safe, false);
  assert.equal(isUrlSafe("http://172.16.0.2").safe, false);

  // Dangerous protocols
  assert.equal(isUrlSafe("file:///etc/passwd").safe, false);
  assert.equal(isUrlSafe("gopher://127.0.0.1:25").safe, false);

  // Public domain without whitelist
  assert.equal(isUrlSafe("https://api.github.com/repos").safe, true);

  // Allowed domains whitelist
  assert.equal(isUrlSafe("https://api.stripe.com/v1/charges", ["stripe.com"]).safe, true);
  assert.equal(isUrlSafe("https://sub.stripe.com/v1", ["stripe.com"]).safe, true);
  assert.equal(isUrlSafe("https://evil.com", ["stripe.com"]).safe, false);
});

test("isSqlSafe detects destructive SQL operations on read-only tools", () => {
  assert.equal(isSqlSafe("SELECT id, name FROM users WHERE active = 1", true).safe, true);
  assert.equal(isSqlSafe("DROP TABLE users;", true).safe, false);
  assert.equal(isSqlSafe("SELECT * FROM u; TRUNCATE TABLE logs;", true).safe, false);
  assert.equal(isSqlSafe("DELETE FROM accounts WHERE balance < 0", true).safe, false);
  assert.equal(isSqlSafe("UPDATE users SET admin = 1", true).safe, false);
});

test("isCommandSafe validates shell commands and injection metacharacters", () => {
  assert.equal(isCommandSafe("ls -la", ["ls", "cat"]).safe, true);
  assert.equal(isCommandSafe("rm -rf /", ["ls"], ["rm -rf"]).safe, false);
  assert.equal(isCommandSafe("cat notes.txt\0rm -rf", ["cat"]).safe, false);
  assert.equal(isCommandSafe("whoami", ["ls"]).safe, false);
});

test("AgentShield enforces cumulative session quotas and spend budgets", async () => {
  const policy: ShieldPolicy = {
    version: "1.0",
    defaultAction: "deny",
    rules: [
      {
        id: "budgeted-payment",
        tool: "process_payment",
        action: "allow",
        constraints: {
          sessionQuota: {
            maxCalls: 3,
            maxCumulativeValue: {
              field: "amount",
              max: 100,
            },
          },
        },
      },
    ],
  };

  const shield = new AgentShield({ policy, enableAudit: false });
  const sessionId = "session-user-42";

  // Call 1: $40 -> allowed
  const c1 = await shield.evaluate({
    agentId: "bot",
    tool: "process_payment",
    sessionId,
    args: { amount: 40 },
  });
  assert.equal(c1.verdict, "ALLOW");

  // Call 2: $50 (cumulative $90 <= 100) -> allowed
  const c2 = await shield.evaluate({
    agentId: "bot",
    tool: "process_payment",
    sessionId,
    args: { amount: 50 },
  });
  assert.equal(c2.verdict, "ALLOW");

  // Call 3: $30 (cumulative would be $120 > 100) -> DENIED
  const c3 = await shield.evaluate({
    agentId: "bot",
    tool: "process_payment",
    sessionId,
    args: { amount: 30 },
  });
  assert.equal(c3.verdict, "DENY");
  assert.match(c3.reason, /Session cumulative budget exceeded/);

  // Call 4: $5 (cumulative $95 <= 100, this is call #3) -> allowed
  const c4 = await shield.evaluate({
    agentId: "bot",
    tool: "process_payment",
    sessionId,
    args: { amount: 5 },
  });
  assert.equal(c4.verdict, "ALLOW");

  // Call 5: exceeds maxCalls (which is 3) -> DENIED
  const c5 = await shield.evaluate({
    agentId: "bot",
    tool: "process_payment",
    sessionId,
    args: { amount: 1 },
  });
  assert.equal(c5.verdict, "DENY");
  assert.match(c5.reason, /Session call quota exceeded/);

  // Reset session
  shield.resetSession(sessionId);
  assert.equal(shield.getSessionStats(sessionId), undefined);

  // Can execute again
  const c6 = await shield.evaluate({
    agentId: "bot",
    tool: "process_payment",
    sessionId,
    args: { amount: 10 },
  });
  assert.equal(c6.verdict, "ALLOW");
});

test("AgentShield validates policy schema structure and inheritance", () => {
  // Invalid version
  const badVersion = AgentShield.validatePolicy({ version: "2.0", defaultAction: "allow", rules: [] });
  assert.equal(badVersion.valid, false);
  assert.match(badVersion.errors[0] || "", /version/);

  // Duplicate rule IDs
  const dupRules = AgentShield.validatePolicy({
    version: "1.0",
    defaultAction: "deny",
    rules: [
      { id: "rule-1", tool: "a", action: "allow" },
      { id: "rule-1", tool: "b", action: "deny" },
    ],
  });
  assert.equal(dupRules.valid, false);
  assert.match(dupRules.errors[0] || "", /Duplicate rule id/);

  // Valid policy
  const good = AgentShield.validatePolicy({
    version: "1.0",
    defaultAction: "deny",
    rules: [{ id: "rule-ok", tool: "a", action: "allow" }],
  });
  assert.equal(good.valid, true);
});

test("AgentShield policy inheritance merges base rules with child overrides", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "shield-extends-"));
  try {
    const baseFile = path.join(tmpDir, "base.json");
    const childFile = path.join(tmpDir, "child.json");

    const basePolicy: ShieldPolicy = {
      version: "1.0",
      defaultAction: "deny",
      rules: [
        { id: "base-read", tool: "read_file", action: "allow" },
        { id: "base-write", tool: "write_file", action: "ask" },
      ],
    };

    const childPolicy = {
      version: "1.0",
      extends: "./base.json",
      defaultAction: "deny",
      rules: [
        // Override base-write to deny
        { id: "base-write", tool: "write_file", action: "deny" },
        { id: "child-exec", tool: "exec", action: "ask" },
      ],
    };

    fs.writeFileSync(baseFile, JSON.stringify(basePolicy));
    fs.writeFileSync(childFile, JSON.stringify(childPolicy));

    const loaded = AgentShield.loadPolicyFromFile(childFile);
    assert.equal(loaded.rules.length, 3);
    assert.equal(loaded.rules[0]?.id, "base-write");
    assert.equal(loaded.rules[0]?.action, "deny"); // overridden
    assert.equal(loaded.rules[1]?.id, "child-exec");
    assert.equal(loaded.rules[2]?.id, "base-read"); // inherited
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("AuditTrail computes forensic stats and exports JSON, CSV, Markdown", () => {
  const audit = new AuditTrail();
  audit.append({ agentId: "agent-1", tool: "read", args: {}, decision: "ALLOW", reason: "ok" });
  audit.append({ agentId: "agent-1", tool: "write", args: {}, decision: "DENY", reason: "blocked" });
  audit.append({ agentId: "agent-2", tool: "read", args: {}, decision: "ASK_APPROVED", reason: "confirmed" });

  const stats = audit.getStats();
  assert.equal(stats.totalRecords, 3);
  assert.equal(stats.valid, true);
  assert.equal(stats.uniqueAgents, 2);
  assert.equal(stats.uniqueTools, 2);
  assert.equal(stats.decisions.ALLOW, 1);
  assert.equal(stats.decisions.DENY, 1);
  assert.equal(stats.decisions.ASK_APPROVED, 1);

  // Formats
  const jsonExport = audit.exportAs("json");
  assert.ok(jsonExport.startsWith("["));

  const csvExport = audit.exportAs("csv");
  assert.ok(csvExport.includes("index,timestamp,agentId,tool,decision,reason"));
  assert.ok(csvExport.includes('"agent-1","read","ALLOW"'));

  const mdExport = audit.exportAs("markdown");
  assert.ok(mdExport.includes("# AgentShield Audit Trail Report"));
  assert.ok(mdExport.includes("| **ALLOW** |"));
});
