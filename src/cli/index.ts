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
import type { DecisionVerdict, ShieldPolicy } from "../core/types.ts";
import { SPONSOR_HELP_LINE, sponsorFooter } from "../sponsor.ts";

const VERSION = "0.2.0-alpha.1";

const useColors = process.stdout.isTTY && !process.env.NO_COLOR;
const c = {
  green: (s: string) => (useColors ? `\x1b[32m${s}\x1b[0m` : s),
  red: (s: string) => (useColors ? `\x1b[31m${s}\x1b[0m` : s),
  yellow: (s: string) => (useColors ? `\x1b[33m${s}\x1b[0m` : s),
  cyan: (s: string) => (useColors ? `\x1b[36m${s}\x1b[0m` : s),
  bold: (s: string) => (useColors ? `\x1b[1m${s}\x1b[0m` : s),
  dim: (s: string) => (useColors ? `\x1b[2m${s}\x1b[0m` : s),
};

const HELP_TEXT = `${c.bold(`AgentShield v${VERSION}`)} — Deterministic AI Agent Tool Security Firewall

Usage:
  agentshield <command> [options]

Commands:
  init                     Create a default starter agentshield.json policy
  eval                     Evaluate a tool call request without executing it
  exec                     Evaluate and safely execute a command if allowed
  mcp                      Proxy an MCP stdio server with active policy guard
  audit verify             Verify cryptographic hash chain integrity of audit log
  audit tail               Show recent audit trail events
  audit search             Query and filter audit trail events

Options for eval/exec:
  --tool <name>            Tool name (e.g. read_file, exec_command, query_db)
  --agent <id>             Calling agent identifier (default: "default-agent")
  --args <json>            Tool arguments formatted as JSON string (default: "{}")
  --context <json>         Context object as JSON string (e.g. '{"env":"prod"}')
  --policy <file>          Path to policy file (default: "./agentshield.json" or $AGENTSHIELD_POLICY)
  --audit <file>           Path to audit log file (default: "./agentshield-audit.jsonl" or $AGENTSHIELD_AUDIT_LOG)
  --secret <key>           Secret key for HMAC signature verification ($AGENTSHIELD_SECRET)
  --timeout <sec>          Human prompt timeout in seconds (default: 30)

Options for audit search:
  --agent <id>             Filter by agent ID
  --tool <name>            Filter by tool name
  --decision <verdict>     Filter by verdict (ALLOW, DENY, ASK_APPROVED, ASK_REJECTED)
  -n, --limit <number>     Maximum results to return (default: 20)

General options:
  -v, --version            Show version
  -h, --help               Show this help message

${SPONSOR_HELP_LINE}
`;

function parseArgs(args: string[]) {
  const result: Record<string, string> = {};
  const positional: string[] = [];
  const doubleDashIndex = args.indexOf("--");
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

async function askUserConfirmation(promptText: string, timeoutSec: number = 30): Promise<boolean> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stderr,
  });

  return new Promise((resolve) => {
    let resolved = false;
    const timer = setTimeout(() => {
      if (!resolved) {
        resolved = true;
        rl.close();
        process.stderr.write(`\n${c.yellow(`[AgentShield Timeout]`)} No answer within ${timeoutSec}s. Defaulting to safe REJECT.\n`);
        resolve(false);
      }
    }, timeoutSec * 1000);

    rl.question(promptText, (answer) => {
      if (!resolved) {
        resolved = true;
        clearTimeout(timer);
        rl.close();
        const normalized = answer.trim().toLowerCase();
        resolve(normalized === "y" || normalized === "yes" || normalized === "si");
      }
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

  const policyFile = flags.policy || process.env.AGENTSHIELD_POLICY || DEFAULT_POLICY_FILE;
  const auditFile = flags.audit || flags.log || process.env.AGENTSHIELD_AUDIT_LOG || DEFAULT_AUDIT_LOG_FILE;
  const secretKey = flags.secret || process.env.AGENTSHIELD_SECRET;
  const timeoutSec = parseInt(flags.timeout || "30", 10);

  // Command: init
  if (command === "init") {
    if (fs.existsSync(policyFile)) {
      console.error(c.red(`Error: Policy file '${policyFile}' already exists.`));
      process.exitCode = 1;
      return;
    }
    fs.writeFileSync(policyFile, JSON.stringify(STARTER_POLICY, null, 2) + "\n", "utf8");
    console.log(c.green(`✓ Created starter policy at ${policyFile}`));
    sponsorFooter("agentshield");
    return;
  }

  // Command: audit verify
  if (command === "audit" && subCommand === "verify") {
    console.log(`Verifying audit trail integrity in: ${c.cyan(auditFile)}...`);
    const verification = AuditTrail.verifyFile(auditFile, secretKey);
    if (verification.valid) {
      console.log(
        c.green(
          `✓ Audit chain VALID: ${verification.totalRecords} records verified without tampering.${
            secretKey ? " (HMAC signature verified)" : ""
          }`
        )
      );
    } else {
      console.error(c.red(`✗ Audit chain TAMPERED or INVALID: ${verification.error}`));
      if (verification.tamperedIndex !== undefined) {
        console.error(c.red(`  Tampering detected at record index: ${verification.tamperedIndex}`));
      }
      process.exitCode = 2;
    }
    sponsorFooter("agentshield");
    return;
  }

  // Command: audit tail
  if (command === "audit" && (subCommand === "tail" || subCommand === "show")) {
    const count = parseInt(flags.n || "10", 10);
    if (!fs.existsSync(auditFile)) {
      console.log(c.yellow(`No audit log found at ${auditFile}`));
      return;
    }
    const audit = new AuditTrail(auditFile, secretKey);
    const tail = audit.getTail(count);
    console.log(`Recent ${tail.length} audit records in ${auditFile}:`);
    for (const record of tail) {
      const icon =
        record.decision === "ALLOW"
          ? c.green("✓ ALLOW")
          : record.decision === "ASK_APPROVED"
          ? c.cyan("★ APPROVED")
          : record.decision === "ASK_REJECTED"
          ? c.yellow("✗ REJECTED")
          : c.red("✗ DENY");
      console.log(
        `[#${record.index}] ${c.dim(record.timestamp)} ${icon} | Agent: ${record.agentId} | Tool: ${c.bold(
          record.tool
        )} | Hash: ${record.hash.slice(0, 8)}...`
      );
    }
    sponsorFooter("agentshield");
    return;
  }

  // Command: audit search
  if (command === "audit" && (subCommand === "search" || subCommand === "query")) {
    if (!fs.existsSync(auditFile)) {
      console.log(c.yellow(`No audit log found at ${auditFile}`));
      return;
    }
    const audit = new AuditTrail(auditFile, secretKey);
    const limit = parseInt(flags.n || flags.limit || "20", 10);
    const results = audit.query({
      agentId: flags.agent,
      tool: flags.tool,
      decision: flags.decision as DecisionVerdict | undefined,
      limit,
    });

    console.log(`Found ${results.length} matching audit record(s) in ${auditFile}:`);
    for (const r of results) {
      console.log(
        `[#${r.index}] ${c.dim(r.timestamp)} ${c.bold(r.decision)} | Agent: ${r.agentId} | Tool: ${
          r.tool
        } | Reason: ${r.reason}`
      );
    }
    sponsorFooter("agentshield");
    return;
  }

  // Command: eval
  if (command === "eval") {
    let policy: ShieldPolicy;
    if (fs.existsSync(policyFile)) {
      policy = AgentShield.loadPolicyFromFile(policyFile);
    } else {
      policy = STARTER_POLICY;
    }

    const tool = flags.tool;
    if (!tool) {
      console.error(c.red("Error: --tool <name> is required for eval."));
      process.exitCode = 1;
      return;
    }

    const agentId = flags.agent || "default-agent";
    let argsObj: Record<string, unknown> = {};
    if (flags.args) {
      try {
        argsObj = JSON.parse(flags.args);
      } catch (err) {
        console.error(c.red(`Error parsing --args JSON: ${(err as Error).message}`));
        process.exitCode = 1;
        return;
      }
    }

    let contextObj: Record<string, unknown> | undefined;
    if (flags.context) {
      try {
        contextObj = JSON.parse(flags.context);
      } catch (err) {
        console.error(c.red(`Error parsing --context JSON: ${(err as Error).message}`));
        process.exitCode = 1;
        return;
      }
    }

    const shield = new AgentShield({
      policy,
      auditLogPath: auditFile,
      auditSecret: secretKey,
      askTimeoutSeconds: timeoutSec,
      onHumanApproval: async (_req, rule) => {
        return await askUserConfirmation(
          `${c.yellow("[AgentShield Human-in-the-Loop]")} Rule '${rule.id}' requests approval for tool '${tool}'. Approve? (y/N): `,
          timeoutSec
        );
      },
    });

    const result = await shield.evaluate({ agentId, tool, args: argsObj, context: contextObj });
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
      console.error(
        c.red("Error: command to execute must be provided after '--'. Example: agentshield exec --tool bash -- ls -la")
      );
      process.exitCode = 1;
      return;
    }

    const policy = fs.existsSync(policyFile) ? AgentShield.loadPolicyFromFile(policyFile) : STARTER_POLICY;
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
      auditLogPath: auditFile,
      auditSecret: secretKey,
      askTimeoutSeconds: timeoutSec,
      onHumanApproval: async () => {
        return await askUserConfirmation(
          `${c.yellow("[AgentShield HITL]")} Approve executing '${rawCmd}'? (y/N): `,
          timeoutSec
        );
      },
    });

    const evalResult = await shield.evaluate({ agentId, tool, args: argsObj });
    if (evalResult.verdict === "DENY" || evalResult.verdict === "ASK_REJECTED") {
      console.error(c.red(`✗ AgentShield BLOCKED execution: ${evalResult.reason}`));
      process.exitCode = 1;
      return;
    }

    console.error(c.green(`✓ AgentShield ALLOWED execution (${evalResult.verdict}): ${rawCmd}`));
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
      console.error(
        c.red("Error: MCP server command must be specified after '--'. Example: agentshield mcp -- node my-mcp.js")
      );
      process.exitCode = 1;
      return;
    }

    const policy = fs.existsSync(policyFile) ? AgentShield.loadPolicyFromFile(policyFile) : STARTER_POLICY;
    const agentId = flags.agent || "mcp-agent";

    const shield = new AgentShield({
      policy,
      auditLogPath: auditFile,
      auditSecret: secretKey,
      askTimeoutSeconds: timeoutSec,
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

  console.error(c.red(`Unknown command: ${command}. Run 'agentshield --help' for usage.`));
  process.exitCode = 1;
}

main().catch((err: unknown) => {
  console.error(c.red(`Fatal error: ${err instanceof Error ? err.message : String(err)}`));
  process.exitCode = 1;
});
