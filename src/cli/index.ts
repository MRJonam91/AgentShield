#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";
import { startMcpProxy } from "../adapters/mcp.ts";
import { AuditTrail } from "../core/audit.ts";
import { DEFAULT_AUDIT_LOG_FILE, DEFAULT_POLICY_FILE } from "../core/constants.ts";
import { AgentShield } from "../core/engine.ts";
import type { ShieldPolicy } from "../core/types.ts";
import { SPONSOR_HELP_LINE, sponsorFooter } from "../sponsor.ts";

const VERSION = "0.1.0";

const HELP_TEXT = `AgentShield v${VERSION} — Deterministic AI Agent Tool Security Firewall

Usage:
  agentshield <command> [options]

Commands:
  init                     Create a default starter agentshield.json policy
  eval                     Evaluate a tool call request without executing it
  exec                     Evaluate and safely execute a command if allowed
  mcp                      Proxy an MCP stdio server with active policy guard
  audit verify             Verify cryptographic hash chain integrity of audit log
  audit tail               Show recent audit trail events

Options for eval/exec:
  --tool <name>            Tool name (e.g. read_file, exec_command, query_db)
  --agent <id>             Calling agent identifier (default: "default-agent")
  --args <json>            Tool arguments formatted as JSON string (default: "{}")
  --policy <file>          Path to policy file (default: "./agentshield.json")
  --audit <file>           Path to audit log file (default: "./agentshield-audit.jsonl")

Options for audit tail:
  -n <number>              Number of records to display (default: 10)
  --log <file>             Path to audit log file

General options:
  -v, --version            Show version
  -h, --help               Show this help message

${SPONSOR_HELP_LINE}
`;

function parseArgs(args: string[]) {
  const result: Record<string, string> = {};
  const positional: string[] = [];
  let doubleDashIndex = args.indexOf("--");
  const parsedSlice = doubleDashIndex !== -1 ? args.slice(0, doubleDashIndex) : args;
  const trailingCommand = doubleDashIndex !== -1 ? args.slice(doubleDashIndex + 1) : [];

  for (let i = 0; i < parsedSlice.length; i++) {
    const item = parsedSlice[i]!;
    if (item.startsWith("--")) {
      const key = item.slice(2);
      const next = parsedSlice[i + 1];
      if (next && !next.startsWith("-")) {
        result[key] = next;
        i++;
      } else {
        result[key] = "true";
      }
    } else if (item.startsWith("-")) {
      const key = item.slice(1);
      const next = parsedSlice[i + 1];
      if (next && !next.startsWith("-")) {
        result[key] = next;
        i++;
      } else {
        result[key] = "true";
      }
    } else {
      positional.push(item);
    }
  }

  return { result, positional, trailingCommand };
}

async function askUserConfirmation(promptText: string): Promise<boolean> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stderr,
  });

  return new Promise((resolve) => {
    rl.question(promptText, (answer) => {
      rl.close();
      const normalized = answer.trim().toLowerCase();
      resolve(normalized === "y" || normalized === "yes" || normalized === "si");
    });
  });
}

const STARTER_POLICY: ShieldPolicy = {
  version: "1.0",
  name: "Default Safe Agent Policy",
  description: "Standard local tool policy allowing read operations, confirming modifications, blocking secrets and high-risk paths",
  defaultAction: "ask",
  rules: [
    {
      id: "allow-safe-reads",
      description: "Permit safe workspace file reads",
      tool: ["read_file", "fs:read", "get_*"],
      action: "allow",
      constraints: {
        allowedPaths: ["."],
        forbiddenPaths: [".env", ".git/config", "id_rsa", "/etc/passwd"],
      },
    },
    {
      id: "sanitize-secrets",
      description: "Redact API keys and authorization tokens in tool arguments",
      tool: "*",
      action: "redact",
    },
    {
      id: "ask-file-writes",
      description: "Require human confirmation before writing or modifying files",
      tool: ["write_file", "fs:write", "delete_file"],
      action: "ask",
      constraints: {
        allowedPaths: ["."],
      },
    },
    {
      id: "block-dangerous-commands",
      description: "Deny dangerous system destruction commands",
      tool: ["exec", "bash", "run_command"],
      action: "deny",
      reason: "Execution of destructive system commands is strictly forbidden",
      constraints: {
        forbiddenCommands: ["rm -rf", "mkfs", "dd if=", "chmod -R 777", "powershell -enc"],
      },
    },
    {
      id: "rate-limit-queries",
      description: "Limit tool call bursts to 20 calls per minute",
      tool: "*",
      action: "allow",
      constraints: {
        rateLimit: {
          maxCalls: 20,
          windowSeconds: 60,
        },
      },
    },
  ],
};

async function main() {
  const rawArgs = process.argv.slice(2);
  const { result: flags, positional, trailingCommand } = parseArgs(rawArgs);

  if (flags.v || flags.version) {
    console.log(`AgentShield ${VERSION}`);
    return;
  }

  if (flags.h || flags.help || positional.length === 0) {
    console.log(HELP_TEXT);
    return;
  }

  const command = positional[0]?.toLowerCase();
  const subCommand = positional[1]?.toLowerCase();

  // Command: init
  if (command === "init") {
    const targetFile = flags.policy || DEFAULT_POLICY_FILE;
    if (fs.existsSync(targetFile)) {
      console.error(`Error: Policy file '${targetFile}' already exists.`);
      process.exitCode = 1;
      return;
    }
    fs.writeFileSync(targetFile, JSON.stringify(STARTER_POLICY, null, 2) + "\n", "utf8");
    console.log(`✓ Created starter policy at ${targetFile}`);
    sponsorFooter("agentshield");
    return;
  }

  // Command: audit verify
  if (command === "audit" && subCommand === "verify") {
    const logFile = flags.log || flags.audit || DEFAULT_AUDIT_LOG_FILE;
    console.log(`Verifying audit trail integrity in: ${logFile}...`);
    const verification = AuditTrail.verifyFile(logFile);
    if (verification.valid) {
      console.log(`✓ Audit chain VALID: ${verification.totalRecords} records verified without tampering.`);
    } else {
      console.error(`✗ Audit chain TAMPERED or INVALID: ${verification.error}`);
      if (verification.tamperedIndex !== undefined) {
        console.error(`  Tampering detected at record index: ${verification.tamperedIndex}`);
      }
      process.exitCode = 2;
    }
    sponsorFooter("agentshield");
    return;
  }

  // Command: audit tail
  if (command === "audit" && (subCommand === "tail" || subCommand === "show")) {
    const logFile = flags.log || flags.audit || DEFAULT_AUDIT_LOG_FILE;
    const count = parseInt(flags.n || "10", 10);
    if (!fs.existsSync(logFile)) {
      console.log(`No audit log found at ${logFile}`);
      return;
    }
    const audit = new AuditTrail(logFile);
    const tail = audit.getTail(count);
    console.log(`Recent ${tail.length} audit records in ${logFile}:`);
    for (const record of tail) {
      const icon = record.decision === "ALLOW" ? "✓" : record.decision === "ASK_APPROVED" ? "★" : "✗";
      console.log(`[#${record.index}] ${record.timestamp} ${icon} ${record.decision} | Agent: ${record.agentId} | Tool: ${record.tool} | Hash: ${record.hash.slice(0, 8)}...`);
    }
    sponsorFooter("agentshield");
    return;
  }

  // Command: eval
  if (command === "eval") {
    const policyPath = flags.policy || DEFAULT_POLICY_FILE;
    let policy: ShieldPolicy;
    if (fs.existsSync(policyPath)) {
      policy = AgentShield.loadPolicyFromFile(policyPath);
    } else {
      policy = STARTER_POLICY;
    }

    const tool = flags.tool;
    if (!tool) {
      console.error("Error: --tool <name> is required for eval.");
      process.exitCode = 1;
      return;
    }

    const agentId = flags.agent || "default-agent";
    let argsObj: Record<string, unknown> = {};
    if (flags.args) {
      try {
        argsObj = JSON.parse(flags.args);
      } catch (err) {
        console.error(`Error parsing --args JSON: ${(err as Error).message}`);
        process.exitCode = 1;
        return;
      }
    }

    const shield = new AgentShield({
      policy,
      auditLogPath: flags.audit || DEFAULT_AUDIT_LOG_FILE,
      onHumanApproval: async (_req, rule) => {
        return await askUserConfirmation(
          `[AgentShield Human-in-the-Loop] Rule '${rule.id}' requests approval for tool '${tool}'. Approve? (y/N): `
        );
      },
    });

    const result = await shield.evaluate({ agentId, tool, args: argsObj });
    console.log(JSON.stringify(result, null, 2));
    if (result.verdict === "DENY" || result.verdict === "ASK_REJECTED") {
      process.exitCode = 1;
    }
    sponsorFooter("agentshield");
    return;
  }

  // Command: exec
  if (command === "exec") {
    if (trailingCommand.length === 0) {
      console.error("Error: command to execute must be provided after '--'. Example: agentshield exec --tool bash -- ls -la");
      process.exitCode = 1;
      return;
    }

    const policyPath = flags.policy || DEFAULT_POLICY_FILE;
    const policy = fs.existsSync(policyPath) ? AgentShield.loadPolicyFromFile(policyPath) : STARTER_POLICY;
    const tool = flags.tool || "exec";
    const agentId = flags.agent || "default-agent";
    const rawCmd = trailingCommand.join(" ");

    let argsObj: Record<string, unknown> = { command: rawCmd };
    if (flags.args) {
      try {
        argsObj = { ...argsObj, ...JSON.parse(flags.args) };
      } catch {
        // ignore
      }
    }

    const shield = new AgentShield({
      policy,
      auditLogPath: flags.audit || DEFAULT_AUDIT_LOG_FILE,
      onHumanApproval: async () => {
        return await askUserConfirmation(`[AgentShield HITL] Approve executing '${rawCmd}'? (y/N): `);
      },
    });

    const evalResult = await shield.evaluate({ agentId, tool, args: argsObj });
    if (evalResult.verdict === "DENY" || evalResult.verdict === "ASK_REJECTED") {
      console.error(`✗ AgentShield BLOCKED execution: ${evalResult.reason}`);
      process.exitCode = 1;
      return;
    }

    console.error(`✓ AgentShield ALLOWED execution (${evalResult.verdict}): ${rawCmd}`);
    const bin = trailingCommand[0]!;
    const binArgs = trailingCommand.slice(1);
    const child = spawn(bin, binArgs, { stdio: "inherit", shell: true });
    child.on("exit", (code) => {
      process.exitCode = code ?? 0;
    });
    return;
  }

  // Command: mcp
  if (command === "mcp") {
    if (trailingCommand.length === 0) {
      console.error("Error: MCP server command must be specified after '--'. Example: agentshield mcp -- node my-mcp.js");
      process.exitCode = 1;
      return;
    }

    const policyPath = flags.policy || DEFAULT_POLICY_FILE;
    const policy = fs.existsSync(policyPath) ? AgentShield.loadPolicyFromFile(policyPath) : STARTER_POLICY;
    const agentId = flags.agent || "mcp-agent";

    const shield = new AgentShield({
      policy,
      auditLogPath: flags.audit || DEFAULT_AUDIT_LOG_FILE,
    });

    const bin = trailingCommand[0]!;
    const binArgs = trailingCommand.slice(1);
    startMcpProxy(shield, {
      agentId,
      command: bin,
      args: binArgs,
    });
    return;
  }

  console.error(`Unknown command: ${command}. Run 'agentshield --help' for usage.`);
  process.exitCode = 1;
}

main().catch((err: unknown) => {
  console.error(`Fatal error: ${err instanceof Error ? err.message : String(err)}`);
  process.exitCode = 1;
});
