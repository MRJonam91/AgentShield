// SPDX-License-Identifier: Apache-2.0

import fs from "node:fs";
import path from "node:path";
import { AuditTrail, canonicalJson } from "./audit.ts";
import { DEFAULT_POLICY_FILE, SHIELD_ERROR_UNAUTHORIZED } from "./constants.ts";
import { isCommandSafe, isPathSafe, isSqlSafe, isUrlSafe, redactSecrets } from "./sanitizer.ts";
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
  private sessionStats: Map<string, { callCount: number; cumulativeTotals: Record<string, number> }> = new Map();

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

  public resetSession(sessionId: string): void {
    this.sessionStats.delete(sessionId);
  }

  public getSessionStats(sessionId: string): { callCount: number; cumulativeTotals: Record<string, number> } | undefined {
    const stats = this.sessionStats.get(sessionId);
    return stats ? JSON.parse(JSON.stringify(stats)) : undefined;
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
    agentToolKey?: string,
    sessionId?: string
  ): { valid: boolean; reason?: string } {
    if (!constraints) return { valid: true };

    // Rate limit (sliding window)
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

    // Session quota check (cumulative budget)
    if (constraints.sessionQuota && sessionId) {
      const stats = this.sessionStats.get(sessionId) || { callCount: 0, cumulativeTotals: {} };
      if (constraints.sessionQuota.maxCalls !== undefined && stats.callCount >= constraints.sessionQuota.maxCalls) {
        return {
          valid: false,
          reason: `Session call quota exceeded: max ${constraints.sessionQuota.maxCalls} calls allowed per session`,
        };
      }

      if (constraints.sessionQuota.maxCumulativeValue) {
        const { field, max } = constraints.sessionQuota.maxCumulativeValue;
        const val = getNestedProperty(args, field);
        if (typeof val === "number") {
          const currentTotal = stats.cumulativeTotals[field] || 0;
          if (currentTotal + val > max) {
            return {
              valid: false,
              reason: `Session cumulative budget exceeded for '${field}': attempted +${val}, current ${currentTotal}, max limit ${max}`,
            };
          }
        }
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

    // Exact argument match conditions (supports primitives and structured objects)
    if (constraints.argumentMatches) {
      for (const [key, expectedVal] of Object.entries(constraints.argumentMatches)) {
        const actualVal = getNestedProperty(args, key);
        const matches =
          typeof expectedVal === "object" && expectedVal !== null
            ? canonicalJson(actualVal) === canonicalJson(expectedVal)
            : actualVal === expectedVal;

        if (!matches) {
          return {
            valid: false,
            reason: `Argument match violated for '${key}': expected '${JSON.stringify(expectedVal)}', got '${JSON.stringify(actualVal)}'`,
          };
        }
      }
    }

    // Path constraints on path-like arguments
    const pathKeys = ["path", "filePath", "filepath", "file", "dest", "destination", "source", "src", "target", "dir", "directory"];
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
        const cmdCheck = isCommandSafe(val, constraints.allowedCommands, constraints.forbiddenCommands);
        if (!cmdCheck.safe) {
          return { valid: false, reason: cmdCheck.reason };
        }
      }
    }

    // SSRF / Network URL protection
    if (constraints.allowedDomains) {
      const urlKeys = ["url", "uri", "endpoint", "webhook", "targetUrl", "target_url"];
      for (const key of urlKeys) {
        const val = getNestedProperty(args, key);
        if (typeof val === "string") {
          const urlCheck = isUrlSafe(val, constraints.allowedDomains);
          if (!urlCheck.safe) {
            return { valid: false, reason: urlCheck.reason };
          }
        }
      }
    }

    // SQL safety protection
    if (constraints.readOnlySql) {
      const sqlKeys = ["query", "sql", "statement"];
      for (const key of sqlKeys) {
        const val = getNestedProperty(args, key);
        if (typeof val === "string") {
          const sqlCheck = isSqlSafe(val, true);
          if (!sqlCheck.safe) {
            return { valid: false, reason: sqlCheck.reason };
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

  private updateSessionStats(sessionId: string, args: Record<string, unknown>, constraints?: PolicyConstraints): void {
    if (!constraints?.sessionQuota) return;
    const stats = this.sessionStats.get(sessionId) || { callCount: 0, cumulativeTotals: {} };
    stats.callCount++;

    if (constraints.sessionQuota.maxCumulativeValue) {
      const { field } = constraints.sessionQuota.maxCumulativeValue;
      const val = getNestedProperty(args, field);
      if (typeof val === "number") {
        stats.cumulativeTotals[field] = (stats.cumulativeTotals[field] || 0) + val;
      }
    }

    this.sessionStats.set(sessionId, stats);
  }

  private getRuleSpecificity(rule: PolicyRule, agentId: string, tool: string): number {
    let score = 0;

    // Tool score
    if (Array.isArray(rule.tool)) {
      if (rule.tool.includes(tool)) score += 30;
      else if (rule.tool.some((t) => t !== "*" && matchesPattern(t, tool))) score += 20;
      else score += 10;
    } else if (rule.tool === tool) {
      score += 30;
    } else if (rule.tool !== "*" && matchesPattern(rule.tool, tool)) {
      score += 20;
    } else {
      score += 10;
    }

    // Agent score
    if (rule.agent) {
      if (Array.isArray(rule.agent)) {
        if (rule.agent.includes(agentId)) score += 3;
        else if (rule.agent.some((a) => a !== "*" && matchesPattern(a, agentId))) score += 2;
        else score += 1;
      } else if (rule.agent === agentId) {
        score += 3;
      } else if (rule.agent !== "*" && matchesPattern(rule.agent, agentId)) {
        score += 2;
      } else {
        score += 1;
      }
    }

    return score;
  }

  /**
   * Matches rule against agentId, tool, and optional context, selecting the highest-specificity matching rule
   */
  private matchRule(
    agentId: string,
    tool: string,
    context?: Record<string, unknown>
  ): PolicyRule | undefined {
    let bestRule: PolicyRule | undefined;
    let highestScore = -1;

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

      const score = this.getRuleSpecificity(rule, agentId, tool);
      if (score > highestScore) {
        highestScore = score;
        bestRule = rule;
      }
    }

    return bestRule;
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
      const constraintCheck = this.validateConstraints(
        sanitizedArgs,
        matchedRule.constraints,
        rateLimitKey,
        request.sessionId
      );
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
      if (request.sessionId) {
        this.updateSessionStats(request.sessionId, sanitizedArgs, matchedRule?.constraints);
      }
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

      if (approved && request.sessionId) {
        this.updateSessionStats(request.sessionId, sanitizedArgs, matchedRule?.constraints);
      }

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
    if (request.sessionId) {
      this.updateSessionStats(request.sessionId, sanitizedArgs, matchedRule?.constraints);
    }
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
   * Validates structural syntax of a policy configuration object
   */
  public static validatePolicy(policy: unknown): { valid: boolean; errors: string[] } {
    const errors: string[] = [];
    if (!policy || typeof policy !== "object") {
      return { valid: false, errors: ["Policy must be a non-null object"] };
    }

    const p = policy as Partial<ShieldPolicy>;
    if (p.version !== "1.0") {
      errors.push("Invalid policy version: expected '1.0'");
    }

    if (!p.defaultAction || !["allow", "deny", "ask", "redact"].includes(p.defaultAction)) {
      errors.push("Invalid or missing 'defaultAction': must be 'allow', 'deny', 'ask', or 'redact'");
    }

    if (!Array.isArray(p.rules)) {
      errors.push("'rules' must be an array");
    } else {
      const ruleIds = new Set<string>();
      for (let i = 0; i < p.rules.length; i++) {
        const rule = p.rules[i];
        if (!rule || typeof rule !== "object") {
          errors.push(`Rule at index ${i} is not a valid object`);
          continue;
        }
        if (!rule.id || typeof rule.id !== "string") {
          errors.push(`Rule at index ${i} is missing a string 'id'`);
        } else if (ruleIds.has(rule.id)) {
          errors.push(`Duplicate rule id: '${rule.id}'`);
        } else {
          ruleIds.add(rule.id);
        }
        if (!rule.tool) {
          errors.push(`Rule '${rule.id || i}' missing 'tool' pattern`);
        }
        if (!rule.action || !["allow", "deny", "ask", "redact"].includes(rule.action)) {
          errors.push(`Rule '${rule.id || i}' has invalid action: '${String(rule.action)}'`);
        }
      }
    }

    return { valid: errors.length === 0, errors };
  }

  /**
   * Helper to load policy from JSON file with 'extends' inheritance support
   */
  public static loadPolicyFromFile(filePath: string = DEFAULT_POLICY_FILE): ShieldPolicy {
    const resolved = path.resolve(filePath);
    if (!fs.existsSync(resolved)) {
      throw new Error(`Policy file not found: ${filePath}`);
    }
    const raw = fs.readFileSync(resolved, "utf8");
    const childPolicy = JSON.parse(raw) as ShieldPolicy;

    // Handle policy inheritance if 'extends' is present
    if (childPolicy.extends) {
      const baseResolved = path.resolve(path.dirname(resolved), childPolicy.extends);
      if (!fs.existsSync(baseResolved)) {
        throw new Error(`Base policy file to extend not found: ${baseResolved}`);
      }
      const basePolicy = AgentShield.loadPolicyFromFile(baseResolved);
      const childRuleIds = new Set(childPolicy.rules.map((r) => r.id));
      const inheritedRules = basePolicy.rules.filter((r) => !childRuleIds.has(r.id));

      return {
        ...basePolicy,
        ...childPolicy,
        rules: [...childPolicy.rules, ...inheritedRules],
      };
    }

    return childPolicy;
  }
}
