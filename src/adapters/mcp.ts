// SPDX-License-Identifier: Apache-2.0

import { spawn, type ChildProcess } from "node:child_process";
import readline from "node:readline";
import type { AgentShield } from "../core/engine.ts";

export interface McpProxyOptions {
  agentId?: string;
  command: string;
  args?: string[];
  env?: NodeJS.ProcessEnv;
  input?: NodeJS.ReadableStream;
  output?: NodeJS.WritableStream;
}

interface JsonRpcRequest {
  jsonrpc: "2.0";
  id?: string | number;
  method: string;
  params?: {
    name?: string;
    arguments?: Record<string, unknown>;
    [key: string]: unknown;
  };
}

/**
 * Runs an MCP server wrapped with AgentShield security policy verification
 */
export function startMcpProxy(shield: AgentShield, options: McpProxyOptions): {
  child: ChildProcess;
  stop: () => void;
} {
  const agentId = options.agentId || "mcp-agent";
  const inputStream = options.input || process.stdin;
  const outputStream = options.output || process.stdout;

  const child = spawn(options.command, options.args || [], {
    stdio: ["pipe", "pipe", "inherit"],
    env: { ...process.env, ...options.env },
  });

  const clientLineReader = readline.createInterface({
    input: inputStream,
    terminal: false,
  });

  clientLineReader.on("line", async (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;

    let request: JsonRpcRequest;
    try {
      request = JSON.parse(trimmed) as JsonRpcRequest;
    } catch {
      // Non-JSON line or raw passthrough
      if (child.stdin?.writable) {
        child.stdin.write(line + "\n");
      }
      return;
    }

    // Intercept tool calls
    if (request.method === "tools/call" && request.params && request.params.name) {
      const toolName = request.params.name;
      const toolArgs = request.params.arguments || {};

      const evaluation = await shield.evaluate({
        agentId,
        tool: toolName,
        args: toolArgs,
      });

      if (evaluation.verdict === "DENY" || evaluation.verdict === "ASK_REJECTED") {
        // Return standard MCP tool call error response
        const errorResponse = {
          jsonrpc: "2.0",
          id: request.id ?? null,
          result: {
            content: [
              {
                type: "text",
                text: `[AgentShield DENY] Action blocked by policy: ${evaluation.reason}`,
              },
            ],
            isError: true,
          },
        };
        outputStream.write(JSON.stringify(errorResponse) + "\n");
        return;
      }

      // If allowed/redacted, replace arguments with sanitized args
      request.params.arguments = evaluation.sanitizedArgs;
      if (child.stdin?.writable) {
        child.stdin.write(JSON.stringify(request) + "\n");
      }
      return;
    }

    // Forward other messages (initialize, tools/list, ping, resources, etc.)
    if (child.stdin?.writable) {
      child.stdin.write(JSON.stringify(request) + "\n");
    }
  });

  // Pipe child MCP server stdout back to client
  child.stdout?.on("data", (chunk) => {
    outputStream.write(chunk);
  });

  const stop = () => {
    clientLineReader.close();
    try {
      child.kill();
    } catch {
      // ignore
    }
  };

  child.on("exit", () => {
    clientLineReader.close();
  });

  return { child, stop };
}
