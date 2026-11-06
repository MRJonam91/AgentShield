// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";
import { parseLooseJson } from "../src/cli/index.ts";
import { AgentShield } from "../src/core/engine.ts";
import { isPathSafe, redactSecrets } from "../src/core/sanitizer.ts";
import type { ShieldPolicy } from "../src/core/types.ts";

test("redactSecrets safely handles circular references without stack overflow", () => {
  const circularObj: Record<string, unknown> = {
    name: "test",
    apiKey: "sk-12345678901234567890abcdef",
  };
  circularObj.self = circularObj;

  const result = redactSecrets(circularObj);
  assert.equal(result.name, "test");
  assert.equal(result.apiKey, "[REDACTED]");
  assert.equal(result.self, "[CIRCULAR]");
});

test("isPathSafe blocks Windows reserved device names and Alternate Data Streams", () => {
  // Reserved DOS device names
  assert.equal(isPathSafe("CON.txt").safe, false);
  assert.equal(isPathSafe("NUL").safe, false);
  assert.equal(isPathSafe("aux.json").safe, false);
  assert.equal(isPathSafe("COM1").safe, false);
  assert.equal(isPathSafe("lpt1.log").safe, false);

  // Alternate Data Streams
  assert.equal(isPathSafe("data.txt:hidden").safe, false);
  assert.equal(isPathSafe("test.txt::$DATA").safe, false);

  // Legitimate paths should be safe
  assert.equal(isPathSafe("./workspace/file.txt", ["./workspace"]).safe, true);
});

test("AgentShield prioritizes specific tool rules over generic wildcard rules", async () => {
  const policy: ShieldPolicy = {
    version: "1.0",
    defaultAction: "allow",
    rules: [
      // Wildcard defined FIRST
      {
        id: "wildcard-allow",
        tool: "*",
        action: "allow",
      },
      // Specific tool rule defined SECOND
      {
        id: "specific-deny",
        tool: ["delete_account", "destroy_*"],
        action: "deny",
        reason: "Account destruction blocked",
      },
    ],
  };

  const shield = new AgentShield({ policy, enableAudit: false });

  // Specific rule must take precedence over wildcard rule!
  const res = await shield.evaluate({
    agentId: "bot",
    tool: "delete_account",
  });

  assert.equal(res.verdict, "DENY");
  assert.equal(res.ruleId, "specific-deny");

  // General tools still match wildcard
  const resOther = await shield.evaluate({
    agentId: "bot",
    tool: "search_data",
  });
  assert.equal(resOther.verdict, "ALLOW");
  assert.equal(resOther.ruleId, "wildcard-allow");
});

test("AgentShield matches deep structured objects in argumentMatches", async () => {
  const policy: ShieldPolicy = {
    version: "1.0",
    defaultAction: "deny",
    rules: [
      {
        id: "structured-match",
        tool: "deploy",
        action: "allow",
        constraints: {
          argumentMatches: {
            config: { mode: "safe", env: "production" },
          },
        },
      },
    ],
  };

  const shield = new AgentShield({ policy, enableAudit: false });

  // Exact structured match -> allow
  const ok = await shield.evaluate({
    agentId: "bot",
    tool: "deploy",
    args: { config: { mode: "safe", env: "production" } },
  });
  assert.equal(ok.verdict, "ALLOW");

  // Mismatched subfield -> deny
  const bad = await shield.evaluate({
    agentId: "bot",
    tool: "deploy",
    args: { config: { mode: "yolo", env: "production" } },
  });
  assert.equal(bad.verdict, "DENY");
});

test("parseLooseJson handles relaxed CLI quotes and standard JSON", () => {
  // Standard JSON
  const s1 = parseLooseJson('{"tool":"read","limit":5}');
  assert.equal(s1.tool, "read");
  assert.equal(s1.limit, 5);

  // Loose unquoted string from PowerShell
  const s2 = parseLooseJson("{command:rm -rf /,force:true,code:42}");
  assert.equal(s2.command, "rm -rf /");
  assert.equal(s2.force, true);
  assert.equal(s2.code, 42);
});
