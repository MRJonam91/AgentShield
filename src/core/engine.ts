// SPDX-License-Identifier: Apache-2.0

import fs from "node:fs";
import path from "node:path";
import { AuditTrail } from "./audit.ts";
import { DEFAULT_POLICY_FILE, SHIELD_ERROR_UNAUTHORIZED } from "./constants.ts";
import { isPathSafe, redactSecrets } from "./sanitizer.ts";
import type {
  DecisionVerdict,
  EvaluationResult,
  HumanApprovalHandler,
  McpToolDefinition,
  PolicyConstraints,
  PolicyRule,
  ShieldOptions,
  ShieldPolicy,
  ToolCallRequest,
} from "./types.ts";

/** Regex cache to eliminate repeated RegExp compilation overhead */
const REGEX_CACHE: Map<string, RegExp> = new Map();

function getCachedRegex(pattern: string, flags: string = ""): RegExp {
  const key = `${pattern}__${flags}`;
  let reg = REGEX_CACHE.get(key);
  if (!reg) {
    reg = new RegExp(pattern, flags);
    REGEX_CACHE.set(key, reg);
  }
  return reg;
}

/**
 * Checks whether a target string matches a glob pattern (supports `*` and `?`)
 */
export function matchesPattern(pattern: string, target: string): boolean {
  if (pattern === "*" || pattern === target) return true;
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".");
  const regex = getCachedRegex(`^${escaped}$`, "i");
  return regex.test(target);
}

/**
 * Checks if target matches any pattern in a string or array
 */
export function matchesAny(patterns: string | string[] | undefined, target: string): boolean {
  if (!patterns) return true;
  if (typeof patterns === "string") return matchesPattern(patterns, target);
  return patterns.some((p) => matchesPattern(p, target));
}

/**
 * Safely extracts a nested property using dot notation (e.g. "options.force", "user.role")
 */
export function getNestedProperty(obj: Record<string, unknown>, propPath: string): unknown {
  if (!obj || typeof obj !== "object") return undefined;
  if (propPath in obj) return obj[propPath];

  const parts = propPath.split(".");
  let curr: unknown = obj;
  for (const part of parts) {
    if (curr === null || typeof curr !== "object") return undefined;
    curr = (curr as Record<string, unknown>)[part];
  }
  return curr;
}

/**
 * AgentShield Core Policy Engine
 */
export class AgentShield {
  private policy: ShieldPolicy;
  private audit: AuditTrail;
  private onHumanApproval?: HumanApprovalHandler;
  private askTimeoutSeconds: number;
  private callHistory: Map<string, number[]> = new Map();

  constructor(options: ShieldOptions) {
    this.policy = options.policy;
    this.audit = new AuditTrail(
      options.enableAudit !== false ? options.auditLogPath : undefined,
      options.auditSecret
    );
    this.onHumanApproval = options.onHumanApproval;
    this.askTimeoutSeconds = options.askTimeoutSeconds ?? 30;
  }

  public getPolicy(): ShieldPolicy {
    return this.policy;
  }

  public getAuditTrail(): AuditTrail {
    return this.audit;
  }

  /**
   * Evaluates rate limiting constraints for an agent calling a tool
   */
  private checkRateLimit(key: string, maxCalls: number, windowSeconds: number): boolean {
    const now = Date.now();
    const windowMs = windowSeconds * 1000;
    const history = this.callHistory.get(key) || [];
    const recent = history.filter((timestamp) => now - timestamp < windowMs);
    if (recent.length >= maxCalls) {
      return false;
    }
    recent.push(now);
    this.callHistory.set(key, recent);
    return true;
  }

  /**
   * Validates arguments against specified constraints
   */
  private validateConstraints(
    args: Record<string, unknown>,
    constraints?: PolicyConstraints,
    agentToolKey?: string
  ): { valid: boolean; reason?: string } {
    if (!constraints) return { valid: true };

    // Rate limit
    if (constraints.rateLimit && agentToolKey) {
      const allowed = this.checkRateLimit(
        agentToolKey,
        constraints.rateLimit.maxCalls,
        constraints.rateLimit.windowSeconds
      );
      if (!allowed) {
        return {
          valid: false,
          reason: `Rate limit exceeded: max ${constraints.rateLimit.maxCalls} calls per ${constraints.rateLimit.windowSeconds}s`,
        };
      }
    }

    // Argument string length check
    if (constraints.maxArgumentLength) {
      const jsonStr = JSON.stringify(args);
      if (jsonStr.length > constraints.maxArgumentLength) {
        return {
          valid: false,
          reason: `Argument payload length (${jsonStr.length}) exceeds maximum allowed (${constraints.maxArgumentLength})`,
        };
      }
    }

    // Numeric boundaries (e.g. amount min/max)
    if (constraints.numericBounds) {
      for (const [key, bound] of Object.entries(constraints.numericBounds)) {
        const rawVal = getNestedProperty(args, key);
        if (typeof rawVal === "number") {
          if (bound.min !== undefined && rawVal < bound.min) {
            return {
              valid: false,
              reason: `Numeric constraint violated for '${key}': value ${rawVal} is below minimum allowed (${bound.min})`,
            };
          }
          if (bound.max !== undefined && rawVal > bound.max) {
            return {
              valid: false,
              reason: `Numeric constraint violated for '${key}': value ${rawVal} exceeds maximum allowed (${bound.max})`,
            };
          }
        }
      }
    }

    // Exact argument match conditions
    if (constraints.argumentMatches) {
      for (const [key, expectedVal] of Object.entries(constraints.argumentMatches)) {
        const actualVal = getNestedProperty(args, key);
        if (actualVal !== expectedVal) {
          return {
            valid: false,
            reason: `Argument match violated for '${key}': expected '${String(expectedVal)}', got '${String(actualVal)}'`,
          };
        }
      }
    }

    // Path constraints on path-like arguments
    const pathKeys = [
      "path",
      "filePath",
      "filepath",
      "file",
      "dest",
      "destination",
      "source",
      "src",
      "target",
      "dir",
      "directory",
    ];
    for (const key of pathKeys) {
      const val = getNestedProperty(args, key);
      if (typeof val === "string") {
        const check = isPathSafe(val, constraints.allowedPaths, constraints.forbiddenPaths);
        if (!check.safe) {
          return { valid: false, reason: check.reason || "Unsafe path detected" };
        }
      }
    }

    // Command constraints on command-like arguments
    const cmdKeys = ["command", "cmd", "exec", "script", "shell"];
    for (const key of cmdKeys) {
      const val = getNestedProperty(args, key);
      if (typeof val === "string") {
        if (constraints.forbiddenCommands) {
          for (const pattern of constraints.forbiddenCommands) {
            const regex = getCachedRegex(pattern, "i");
            if (regex.test(val)) {
              return { valid: false, reason: `Command matches forbidden pattern: '${pattern}'` };
            }
          }
        }
        if (constraints.allowedCommands && constraints.allowedCommands.length > 0) {
          const matched = constraints.allowedCommands.some((pat) =>
            getCachedRegex(pat, "i").test(val)
          );
          if (!matched) {
            return { valid: false, reason: `Command '${val}' not in allowed commands whitelist` };
          }
        }
      }
    }

    // Generic argument regex patterns (supports dot notation)
    if (constraints.argumentPatterns) {
      for (const [argKey, patternStr] of Object.entries(constraints.argumentPatterns)) {
        const argVal = String(getNestedProperty(args, argKey) ?? "");
        const regex = getCachedRegex(patternStr);
        if (!regex.test(argVal)) {
          return {
            valid: false,
            reason: `Argument '${argKey}' failed validation against pattern '${patternStr}'`,
          };
        }
      }
    }

    return { valid: true };
  }

  /**
   * Matches rule against agentId, tool, and optional context
   */
  private matchRule(
    agentId: string,
    tool: string,
    context?: Record<string, unknown>
  ): PolicyRule | undefined {
    for (const rule of this.policy.rules) {
      if (!matchesAny(rule.agent, agentId) || !matchesAny(rule.tool, tool)) {
        continue;
      }

      // Check context conditions if rule specifies them
      if (rule.contextConditions && context) {
        let contextMatched = true;
        for (const [cKey, cVal] of Object.entries(rule.contextConditions)) {
          if (context[cKey] !== cVal) {
            contextMatched = false;
            break;
          }
        }
        if (!contextMatched) continue;
      }

      return rule;
    }
    return undefined;
  }

  /**
   * Filters a list of tool definitions (e.g. for MCP tools/list), omitting denied tools
   * and annotating tools that require human confirmation.
   */
  public filterAvailableTools(
    tools: McpToolDefinition[],
    agentId: string,
    context?: Record<string, unknown>
  ): McpToolDefinition[] {
    const visible: McpToolDefinition[] = [];

    for (const toolDef of tools) {
      const matchedRule = this.matchRule(agentId, toolDef.name, context);
      const action = matchedRule ? matchedRule.action : this.policy.defaultAction;

      // Completely omit explicitly denied tools to prevent probing
      if (action === "deny") {
        continue;
      }

      // Annotate tools that require human confirmation
      if (action === "ask") {
        visible.push({
          ...toolDef,
          description: toolDef.description
            ? `${toolDef.description} [AgentShield: Requires Human Approval]`
            : "[AgentShield: Requires Human Approval]",
        });
      } else {
        visible.push(toolDef);
      }
    }

    return visible;
  }

  /**
   * Evaluates a tool call request
   */
  public async evaluate(request: ToolCallRequest): Promise<EvaluationResult> {
    const timestamp = new Date().toISOString();
    const rawArgs = request.args || {};
    let sanitizedArgs = redactSecrets(rawArgs);

    const matchedRule = this.matchRule(request.agentId, request.tool, request.context);
    const effectiveAction = matchedRule ? matchedRule.action : this.policy.defaultAction;
    const ruleId = matchedRule?.id;
    const rateLimitKey = `${request.agentId}:${request.tool}`;

    // Validate constraints if rule exists
    if (matchedRule?.constraints) {
      const constraintCheck = this.validateConstraints(sanitizedArgs, matchedRule.constraints, rateLimitKey);
      if (!constraintCheck.valid) {
        const verdict: DecisionVerdict = "DENY";
        const reason = constraintCheck.reason || SHIELD_ERROR_UNAUTHORIZED;
        this.audit.append({
          agentId: request.agentId,
          tool: request.tool,
          args: sanitizedArgs,
          decision: verdict,
          reason,
          timestamp,
        });
        return {
          verdict,
          action: "deny",
          ruleId,
          reason,
          sanitizedArgs,
          timestamp,
          requiresConfirmation: false,
        };
      }
    }

    // Handle Policy Actions
    if (effectiveAction === "deny") {
      const verdict: DecisionVerdict = "DENY";
      const reason = matchedRule?.reason || `Tool '${request.tool}' explicitly denied by policy`;
      this.audit.append({
        agentId: request.agentId,
        tool: request.tool,
        args: sanitizedArgs,
        decision: verdict,
        reason,
        timestamp,
      });
      return {
        verdict,
        action: "deny",
        ruleId,
        reason,
        sanitizedArgs,
        timestamp,
        requiresConfirmation: false,
      };
    }

    if (effectiveAction === "redact") {
      sanitizedArgs = redactSecrets(sanitizedArgs);
      const verdict: DecisionVerdict = "ALLOW";
      const reason = matchedRule?.reason || "Arguments sanitized and permitted";
      this.audit.append({
        agentId: request.agentId,
        tool: request.tool,
        args: sanitizedArgs,
        decision: verdict,
        reason,
        timestamp,
      });
      return {
        verdict,
        action: "redact",
        ruleId,
        reason,
        sanitizedArgs,
        timestamp,
        requiresConfirmation: false,
      };
    }

    if (effectiveAction === "ask") {
      let approved = false;
      if (this.onHumanApproval) {
        try {
          const timeoutMs = this.askTimeoutSeconds * 1000;
          const approvalPromise = Promise.resolve(
            this.onHumanApproval(
              request,
              matchedRule || { id: "default-ask", tool: "*", action: "ask" },
              sanitizedArgs
            )
          );

          let timeoutId: NodeJS.Timeout | undefined;
          const timeoutPromise = new Promise<boolean>((resolve) => {
            timeoutId = setTimeout(() => resolve(false), timeoutMs);
          });

          approved = await Promise.race([
            approvalPromise.then((res) => {
              if (timeoutId) clearTimeout(timeoutId);
              return Boolean(res);
            }),
            timeoutPromise,
          ]);
        } catch {
          approved = false;
        }
      }

      const verdict: DecisionVerdict = approved ? "ASK_APPROVED" : "ASK_REJECTED";
      const reason = approved
        ? "Human-in-the-loop approved execution"
        : "Human-in-the-loop rejected or timed out execution";

      this.audit.append({
        agentId: request.agentId,
        tool: request.tool,
        args: sanitizedArgs,
        decision: verdict,
        reason,
        timestamp,
      });

      return {
        verdict,
        action: "ask",
        ruleId,
        reason,
        sanitizedArgs,
        timestamp,
        requiresConfirmation: true,
      };
    }

    // Default 'allow'
    const verdict: DecisionVerdict = "ALLOW";
    const reason = matchedRule?.reason || "Execution permitted by policy";
    this.audit.append({
      agentId: request.agentId,
      tool: request.tool,
      args: sanitizedArgs,
      decision: verdict,
      reason,
      timestamp,
    });

    return {
      verdict,
      action: "allow",
      ruleId,
      reason,
      sanitizedArgs,
      timestamp,
      requiresConfirmation: false,
    };
  }

  /**
   * Helper to load policy from JSON file
   */
  public static loadPolicyFromFile(filePath: string = DEFAULT_POLICY_FILE): ShieldPolicy {
    const resolved = path.resolve(filePath);
    if (!fs.existsSync(resolved)) {
      throw new Error(`Policy file not found: ${filePath}`);
    }
    const raw = fs.readFileSync(resolved, "utf8");
    return JSON.parse(raw) as ShieldPolicy;
  }
}
