// SPDX-License-Identifier: Apache-2.0

export type PolicyAction = "allow" | "deny" | "ask" | "redact";

export type DecisionVerdict =
  | "ALLOW"
  | "DENY"
  | "ASK_APPROVED"
  | "ASK_REJECTED";

export interface RateLimitConstraint {
  maxCalls: number;
  windowSeconds: number;
}

export interface PolicyConstraints {
  /** Allowed directory paths for file operations (prevents directory traversal) */
  allowedPaths?: string[];
  /** Explicitly forbidden paths or sensitive patterns (e.g. .env, id_rsa, /etc) */
  forbiddenPaths?: string[];
  /** Regex patterns or exact substrings permitted for command/shell execution */
  allowedCommands?: string[];
  /** Regex patterns forbidden for command/shell execution */
  forbiddenCommands?: string[];
  /** Regex patterns to validate specific string arguments: key -> regex string */
  argumentPatterns?: Record<string, string>;
  /** Rate limit constraints */
  rateLimit?: RateLimitConstraint;
  /** Max allowed payload string length */
  maxArgumentLength?: number;
}

export interface PolicyRule {
  id: string;
  description?: string;
  /** Agent ID or wildcard pattern (e.g. '*', 'code-agent', 'research-*') */
  agent?: string | string[];
  /** Tool name or wildcard pattern (e.g. 'fs:*', 'exec_command', 'sql:*') */
  tool: string | string[];
  action: PolicyAction;
  reason?: string;
  constraints?: PolicyConstraints;
}

export interface ShieldPolicy {
  version: "1.0";
  name?: string;
  description?: string;
  /** Action applied when no explicit rule matches */
  defaultAction: PolicyAction;
  rules: PolicyRule[];
}

export interface ToolCallRequest {
  agentId: string;
  tool: string;
  args?: Record<string, unknown>;
  context?: Record<string, unknown>;
}

export interface EvaluationResult {
  verdict: DecisionVerdict;
  action: PolicyAction;
  ruleId?: string;
  reason: string;
  sanitizedArgs: Record<string, unknown>;
  timestamp: string;
  requiresConfirmation: boolean;
  metadata?: Record<string, unknown>;
}

export interface AuditRecord {
  index: number;
  id: string;
  timestamp: string;
  agentId: string;
  tool: string;
  args: Record<string, unknown>;
  decision: DecisionVerdict;
  reason: string;
  prevHash: string;
  hash: string;
}

export interface AuditVerificationResult {
  valid: boolean;
  totalRecords: number;
  error?: string;
  tamperedIndex?: number;
}

export type HumanApprovalHandler = (
  request: ToolCallRequest,
  rule: PolicyRule,
  sanitizedArgs: Record<string, unknown>
) => Promise<boolean> | boolean;

export interface ShieldOptions {
  policy: ShieldPolicy;
  auditLogPath?: string;
  enableAudit?: boolean;
  onHumanApproval?: HumanApprovalHandler;
  workingDirectory?: string;
}
