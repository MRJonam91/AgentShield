// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { PassThrough } from "node:stream";
import test from "node:test";
import { startMcpProxy } from "../src/adapters/mcp.ts";
import { AgentShield } from "../src/core/engine.ts";
import type { ShieldPolicy } from "../src/core/types.ts";

const mcpPolicy: ShieldPolicy = {
  version: "1.0",
  defaultAction: "deny",
  rules: [
    {
      id: "allow-mcp-read",
      tool: "read_file",
      action: "allow",
    },
    {
      id: "deny-mcp-exec",
      tool: "exec_shell",
      action: "deny",
      reason: "Shell execution disabled via MCP",
    },
  ],
};

test("MCP proxy blocks denied tool call and emits error response", async () => {
  const shield = new AgentShield({ policy: mcpPolicy, enableAudit: false });
  const clientIn = new PassThrough();
  const clientOut = new PassThrough();

  // Spawn node with no-op script as backend
  const proxy = startMcpProxy(shield, {
    command: process.execPath,
    args: ["-e", "process.stdin.resume()"],
    input: clientIn,
    output: clientOut,
  });

  const responses: string[] = [];
  clientOut.on("data", (chunk: Buffer) => {
    responses.push(chunk.toString("utf8"));
  });

  const deniedCall = JSON.stringify({
    jsonrpc: "2.0",
    id: 101,
    method: "tools/call",
    params: {
      name: "exec_shell",
      arguments: { cmd: "whoami" },
    },
  });

  clientIn.write(deniedCall + "\n");

  await new Promise((r) => setTimeout(r, 150));
  proxy.stop();

  const joined = responses.join("");
  assert.match(joined, /"isError":true/);
  assert.match(joined, /Shell execution disabled via MCP/);
});
