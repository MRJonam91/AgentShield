// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";
import { AgentShield, matchesPattern } from "../src/core/engine.ts";
import type { ShieldPolicy } from "../src/core/types.ts";

const testPolicy: ShieldPolicy = {
  version: "1.0",
  defaultAction: "deny",
  rules: [
    {
      id: "allow-reads",
      tool: ["read_*", "fs:read"],
      action: "allow",
      constraints: {
        allowedPaths: ["./workspace"],
        forbiddenPaths: [".env"],
      },
    },
    {
      id: "ask-writes",
      tool: "write_file",
      action: "ask",
    },
    {
      id: "block-bad-commands",
      tool: "exec",
      action: "deny",
      constraints: {
        forbiddenCommands: ["rm -rf", "drop table"],
      },
    },
    {
      id: "limited-tool",
      tool: "call_external_api",
      action: "allow",
      constraints: {
        rateLimit: {
          maxCalls: 2,
          windowSeconds: 60,
        },
      },
    },
  ],
};

test("matchesPattern wildcard evaluation", () => {
  assert.equal(matchesPattern("*", "anything"), true);
  assert.equal(matchesPattern("read_*", "read_file"), true);
  assert.equal(matchesPattern("fs:*", "fs:write"), true);
  assert.equal(matchesPattern("exact", "exact"), true);
  assert.equal(matchesPattern("exact", "different"), false);
});

test("AgentShield allows authorized tool calls within path boundary", async () => {
  const shield = new AgentShield({ policy: testPolicy, enableAudit: false });
  const result = await shield.evaluate({
    agentId: "test-bot",
    tool: "read_file",
    args: { path: "./workspace/data.json" },
  });

  assert.equal(result.verdict, "ALLOW");
  assert.equal(result.ruleId, "allow-reads");
});

test("AgentShield denies path escaping allowed directories", async () => {
  const shield = new AgentShield({ policy: testPolicy, enableAudit: false });
  const result = await shield.evaluate({
    agentId: "test-bot",
    tool: "read_file",
    args: { path: "./outside/secret.txt" },
  });

  assert.equal(result.verdict, "DENY");
  assert.match(result.reason, /outside authorized directory roots/);
});

test("AgentShield enforces human-in-the-loop approval on 'ask' action", async () => {
  let approvalCalled = false;
  const shield = new AgentShield({
    policy: testPolicy,
    enableAudit: false,
    onHumanApproval: async (_req, rule) => {
      approvalCalled = true;
      assert.equal(rule.id, "ask-writes");
      return true; // Approved
    },
  });

  const resApproved = await shield.evaluate({
    agentId: "test-bot",
    tool: "write_file",
    args: { path: "./workspace/output.txt", content: "data" },
  });

  assert.equal(approvalCalled, true);
  assert.equal(resApproved.verdict, "ASK_APPROVED");

  // Test rejection
  const shieldReject = new AgentShield({
    policy: testPolicy,
    enableAudit: false,
    onHumanApproval: async () => false,
  });

  const resRejected = await shieldReject.evaluate({
    agentId: "test-bot",
    tool: "write_file",
    args: { path: "./workspace/output.txt" },
  });

  assert.equal(resRejected.verdict, "ASK_REJECTED");
});

test("AgentShield rate limits burst tool calls", async () => {
  const shield = new AgentShield({ policy: testPolicy, enableAudit: false });
  const call1 = await shield.evaluate({ agentId: "bot", tool: "call_external_api" });
  const call2 = await shield.evaluate({ agentId: "bot", tool: "call_external_api" });
  const call3 = await shield.evaluate({ agentId: "bot", tool: "call_external_api" });

  assert.equal(call1.verdict, "ALLOW");
  assert.equal(call2.verdict, "ALLOW");
  assert.equal(call3.verdict, "DENY");
  assert.match(call3.reason, /Rate limit exceeded/);
});

test("AgentShield falls back to defaultAction when no rule matches", async () => {
  const shield = new AgentShield({ policy: testPolicy, enableAudit: false });
  const result = await shield.evaluate({ agentId: "bot", tool: "unknown_secret_tool" });
  assert.equal(result.verdict, "DENY");
});
