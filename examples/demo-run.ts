// SPDX-License-Identifier: Apache-2.0

import { wrapTool, AgentShield } from "../src/index.ts";
import type { ShieldPolicy } from "../src/core/types.ts";

const policy: ShieldPolicy = {
  version: "1.0",
  name: "Example Policy",
  defaultAction: "deny",
  rules: [
    {
      id: "allow-safe-reads",
      tool: ["read_file", "view_doc"],
      action: "allow",
      constraints: {
        allowedPaths: ["."],
        forbiddenPaths: [".env", "id_rsa"],
      },
    },
    {
      id: "ask-payment",
      tool: "send_payment",
      action: "ask",
    },
  ],
};

async function main() {
  console.log("=== AgentShield Demo ===");

  const shield = new AgentShield({
    policy,
    auditLogPath: "./demo-audit.jsonl",
    onHumanApproval: async (req) => {
      console.log(`[HITL] Human approved payment of ${JSON.stringify(req.args)}`);
      return true;
    },
  });

  // 1. Programmatic tool wrapper
  const readFileTool = wrapTool(
    shield,
    async (args: { path: string }) => {
      return `[File Content of ${args.path}]`;
    },
    { toolName: "read_file" }
  );

  console.log("1. Executing allowed tool call...");
  const content = await readFileTool({ path: "README.md" }, "researcher-agent");
  console.log("Result:", content);

  console.log("\n2. Executing HITL confirmed tool call...");
  const paymentEval = await shield.evaluate({
    agentId: "billing-agent",
    tool: "send_payment",
    args: { amount: 50, currency: "EUR", token: "sk-12345678901234567890abcdef" },
  });
  console.log("Verdict:", paymentEval.verdict, "| Sanitized Args:", paymentEval.sanitizedArgs);

  console.log("\n3. Verifying Cryptographic Audit Trail...");
  const verification = shield.getAuditTrail().verify();
  console.log(`Audit Chain Status: ${verification.valid ? "VALID" : "INVALID"} (${verification.totalRecords} records)`);
}

main().catch(console.error);
