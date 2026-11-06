// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";
import { wrapTool, SecurityPolicyError } from "../src/adapters/wrapper.ts";
import { AgentShield } from "../src/core/engine.ts";
import type { ShieldPolicy } from "../src/core/types.ts";

const policy: ShieldPolicy = {
  version: "1.0",
  defaultAction: "deny",
  rules: [
    {
      id: "allow-echo",
      tool: "echo",
      action: "allow",
    },
    {
      id: "deny-dangerous",
      tool: "delete_db",
      action: "deny",
      reason: "Database deletion blocked",
    },
  ],
};

test("wrapTool executes allowed function and sanitizes args", async () => {
  const shield = new AgentShield({ policy, enableAudit: false });
  const echoTool = wrapTool(
    shield,
    async (args: { text: string; token?: string }) => {
      return { output: args.text, token: args.token };
    },
    { toolName: "echo" }
  );

  const result = await echoTool({ text: "hello", token: "sk-12345678901234567890123" });
  assert.equal(result.output, "hello");
  assert.equal(result.token, "[REDACTED]");
});

test("wrapTool throws SecurityPolicyError when denied", async () => {
  const shield = new AgentShield({ policy, enableAudit: false });
  const deleteTool = wrapTool(
    shield,
    async () => {
      return "deleted";
    },
    { toolName: "delete_db" }
  );

  await assert.rejects(
    async () => {
      await deleteTool({});
    },
    (err: unknown) => {
      assert.ok(err instanceof SecurityPolicyError);
      assert.equal(err.evaluation.verdict, "DENY");
      assert.match(err.message, /Database deletion blocked/);
      return true;
    }
  );
});
