// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";
import { AuditTrail } from "../src/core/audit.ts";
import { AgentShield, getNestedProperty } from "../src/core/engine.ts";
import type { ShieldPolicy } from "../src/core/types.ts";

test("getNestedProperty extracts dot-notation properties", () => {
  const obj = {
    nested: {
      deep: {
        val: 42,
      },
    },
    arr: [1, 2],
  };

  assert.equal(getNestedProperty(obj, "nested.deep.val"), 42);
  assert.equal(getNestedProperty(obj, "nested.nonexistent"), undefined);
  assert.equal(getNestedProperty(obj, "arr"), obj.arr);
});

test("AuditTrail with HMAC secret signs records and verifies authenticity", () => {
  const secretKey = "super-secret-enterprise-key-123";
  const audit = new AuditTrail(undefined, secretKey);

  audit.append({
    agentId: "agent-alpha",
    tool: "transfer_funds",
    args: { amount: 100 },
    decision: "ALLOW",
    reason: "Within budget",
  });

  const records = audit.getRecords();
  assert.equal(records.length, 1);
  assert.ok(records[0]?.signature, "Record should have HMAC signature");

  // Verify with correct secret
  const verification = audit.verify();
  assert.equal(verification.valid, true);

  // Verify with wrong secret
  const badAudit = new AuditTrail(undefined, "wrong-secret-key");
  // Inject the record from good audit
  (badAudit as unknown as { inMemoryRecords: unknown[] }).inMemoryRecords = records;
  const badVerification = badAudit.verify();
  assert.equal(badVerification.valid, false);
  assert.match(badVerification.error || "", /HMAC signature verification failed/);
});

test("AuditTrail query filtering works by agent, tool, and decision", () => {
  const audit = new AuditTrail();
  audit.append({ agentId: "bot-1", tool: "read", args: {}, decision: "ALLOW", reason: "ok" });
  audit.append({ agentId: "bot-1", tool: "write", args: {}, decision: "DENY", reason: "blocked" });
  audit.append({ agentId: "bot-2", tool: "read", args: {}, decision: "ALLOW", reason: "ok" });
  audit.append({ agentId: "bot-2", tool: "write", args: {}, decision: "ASK_APPROVED", reason: "hitl" });

  const bot1Records = audit.query({ agentId: "bot-1" });
  assert.equal(bot1Records.length, 2);

  const deniedRecords = audit.query({ decision: "DENY" });
  assert.equal(deniedRecords.length, 1);
  assert.equal(deniedRecords[0]?.tool, "write");

  const readRecords = audit.query({ tool: "read" });
  assert.equal(readRecords.length, 2);

  const limited = audit.query({ limit: 1 });
  assert.equal(limited.length, 1);
});

test("AgentShield validates numeric boundaries (min and max)", async () => {
  const policy: ShieldPolicy = {
    version: "1.0",
    defaultAction: "deny",
    rules: [
      {
        id: "payment-bounds",
        tool: "send_payment",
        action: "allow",
        constraints: {
          numericBounds: {
            amount: { min: 1, max: 500 },
          },
        },
      },
    ],
  };

  const shield = new AgentShield({ policy, enableAudit: false });

  // Valid payment
  const resValid = await shield.evaluate({
    agentId: "agent-finance",
    tool: "send_payment",
    args: { amount: 250 },
  });
  assert.equal(resValid.verdict, "ALLOW");

  // Below min
  const resLow = await shield.evaluate({
    agentId: "agent-finance",
    tool: "send_payment",
    args: { amount: 0 },
  });
  assert.equal(resLow.verdict, "DENY");
  assert.match(resLow.reason, /below minimum allowed/);

  // Exceeds max
  const resHigh = await shield.evaluate({
    agentId: "agent-finance",
    tool: "send_payment",
    args: { amount: 1500 },
  });
  assert.equal(resHigh.verdict, "DENY");
  assert.match(resHigh.reason, /exceeds maximum allowed/);
});

test("AgentShield evaluates nested dot-notation constraints and argument matches", async () => {
  const policy: ShieldPolicy = {
    version: "1.0",
    defaultAction: "deny",
    rules: [
      {
        id: "git-push-safe",
        tool: "git_push",
        action: "allow",
        constraints: {
          argumentMatches: {
            "options.force": false,
          },
          argumentPatterns: {
            "target.branch": "^(main|feature/.*)$",
          },
        },
      },
    ],
  };

  const shield = new AgentShield({ policy, enableAudit: false });

  // Safe push to feature branch
  const res1 = await shield.evaluate({
    agentId: "dev-bot",
    tool: "git_push",
    args: {
      options: { force: false },
      target: { branch: "feature/auth" },
    },
  });
  assert.equal(res1.verdict, "ALLOW");

  // Force push blocked
  const resForce = await shield.evaluate({
    agentId: "dev-bot",
    tool: "git_push",
    args: {
      options: { force: true },
      target: { branch: "main" },
    },
  });
  assert.equal(resForce.verdict, "DENY");
  assert.match(resForce.reason, /Argument match violated for 'options.force'/);

  // Illegal branch pattern blocked
  const resBadBranch = await shield.evaluate({
    agentId: "dev-bot",
    tool: "git_push",
    args: {
      options: { force: false },
      target: { branch: "malicious-inject; rm" },
    },
  });
  assert.equal(resBadBranch.verdict, "DENY");
  assert.match(resBadBranch.reason, /failed validation against pattern/);
});

test("AgentShield evaluates context conditions", async () => {
  const policy: ShieldPolicy = {
    version: "1.0",
    defaultAction: "deny",
    rules: [
      {
        id: "admin-only-tool",
        tool: "restart_server",
        action: "allow",
        contextConditions: {
          userRole: "admin",
          environment: "production",
        },
      },
    ],
  };

  const shield = new AgentShield({ policy, enableAudit: false });

  // Admin in production -> allowed
  const resAdmin = await shield.evaluate({
    agentId: "operator",
    tool: "restart_server",
    context: { userRole: "admin", environment: "production" },
  });
  assert.equal(resAdmin.verdict, "ALLOW");

  // Guest in production -> denied (falls back to defaultAction)
  const resGuest = await shield.evaluate({
    agentId: "operator",
    tool: "restart_server",
    context: { userRole: "guest", environment: "production" },
  });
  assert.equal(resGuest.verdict, "DENY");
});

test("filterAvailableTools filters denied tools and annotates ask tools for MCP", () => {
  const policy: ShieldPolicy = {
    version: "1.0",
    defaultAction: "deny",
    rules: [
      {
        id: "allow-read",
        tool: "read_file",
        action: "allow",
      },
      {
        id: "ask-modify",
        tool: "modify_db",
        action: "ask",
      },
      {
        id: "deny-wipe",
        tool: "wipe_disk",
        action: "deny",
      },
    ],
  };

  const shield = new AgentShield({ policy, enableAudit: false });

  const rawTools = [
    { name: "read_file", description: "Reads a document" },
    { name: "modify_db", description: "Alters table records" },
    { name: "wipe_disk", description: "Wipes disk completely" },
    { name: "unknown_tool", description: "Not in rules" },
  ];

  const visible = shield.filterAvailableTools(rawTools, "my-agent");

  // wipe_disk and unknown_tool (default deny) are filtered out!
  assert.equal(visible.length, 2);
  assert.equal(visible[0]?.name, "read_file");
  assert.equal(visible[0]?.description, "Reads a document");

  assert.equal(visible[1]?.name, "modify_db");
  assert.match(visible[1]?.description || "", /AgentShield: Requires Human Approval/);
});

test("AgentShield ask action times out and defaults to safe reject", async () => {
  const policy: ShieldPolicy = {
    version: "1.0",
    defaultAction: "deny",
    rules: [
      {
        id: "ask-test",
        tool: "expensive_operation",
        action: "ask",
      },
    ],
  };

  // Configure short timeout of 0.05 seconds (50ms)
  const shield = new AgentShield({
    policy,
    enableAudit: false,
    askTimeoutSeconds: 0.05,
    onHumanApproval: async () => {
      // Simulate taking too long to respond
      await new Promise((r) => setTimeout(r, 200));
      return true;
    },
  });

  const res = await shield.evaluate({
    agentId: "timeout-bot",
    tool: "expensive_operation",
  });

  assert.equal(res.verdict, "ASK_REJECTED");
  assert.match(res.reason, /rejected or timed out/);
});
