// SPDX-License-Identifier: Apache-2.0

import { spawn, type ChildProcess } from "node:child_process";
import readline from "node:readline";
import type { AgentShield } from "../core/engine.ts";
import type { McpToolDefinition } from "../core/types.ts";

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

interface JsonRpcResponse {
  jsonrpc: "2.0";
  id?: string | number;
  result?: {
    tools?: McpToolDefinition[];
    [key: string]: unknown;
  };
  error?: unknown;
}

/**
 * Runs an MCP server wrapped with AgentShield security policy verification
 */
export function startMcpProxy(
  shield: AgentShield,
  options: McpProxyOptions
): {
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

  const pendingToolsListRequests = new Set<string | number>();

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

    // Track tools/list queries to filter responses from the MCP server
    if (request.method === "tools/list" && request.id !== undefined) {
      pendingToolsListRequests.add(request.id);
      if (child.stdin?.writable) {
        child.stdin.write(JSON.stringify(request) + "\n");
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
        // Return standard MCP tool call error response if request expects a response (not a notification)
        if (request.id !== undefined) {
          const errorResponse = {
            jsonrpc: "2.0",
            id: request.id,
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
        }
        return;
      }

      // If allowed/redacted, replace arguments with sanitized args
      request.params.arguments = evaluation.sanitizedArgs;
      if (child.stdin?.writable) {
        child.stdin.write(JSON.stringify(request) + "\n");
      }
      return;
    }

    // Forward other messages (initialize, ping, resources, etc.)
    if (child.stdin?.writable) {
      child.stdin.write(JSON.stringify(request) + "\n");
    }
  });

  // Handle server responses line-by-line
  if (child.stdout) {
    const serverLineReader = readline.createInterface({
      input: child.stdout,
      terminal: false,
    });

    serverLineReader.on("line", (line) => {
      const trimmed = line.trim();
      if (!trimmed) return;

      try {
        const response = JSON.parse(trimmed) as JsonRpcResponse;
        if (response.id !== undefined && pendingToolsListRequests.has(response.id)) {
          pendingToolsListRequests.delete(response.id);
          if (response.result && Array.isArray(response.result.tools)) {
            response.result.tools = shield.filterAvailableTools(response.result.tools, agentId);
          }
          outputStream.write(JSON.stringify(response) + "\n");
          return;
        }
      } catch {
        // Non-JSON or unparseable, passthrough
      }

      outputStream.write(line + "\n");
    });
  }

  const stop = () => {
    clientLineReader.close();
    try {
      child.kill();
    } catch {
      // ignore
    }
  };

  child.on("error", (err) => {
    process.stderr.write(`[AgentShield MCP Error] Process spawn failed: ${err.message}\n`);
    clientLineReader.close();
  });

  child.on("exit", () => {
    clientLineReader.close();
  });

  return { child, stop };
}
