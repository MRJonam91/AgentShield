// SPDX-License-Identifier: Apache-2.0

import type { AgentShield } from "../core/engine.ts";
import type { EvaluationResult } from "../core/types.ts";

export class SecurityPolicyError extends Error {
  public readonly evaluation: EvaluationResult;

  constructor(message: string, evaluation: EvaluationResult) {
    super(message);
    this.name = "SecurityPolicyError";
    this.evaluation = evaluation;
  }
}

export interface WrapToolOptions {
  toolName: string;
  defaultAgentId?: string;
}

/**
 * Wraps an asynchronous tool implementation with AgentShield policy checks and audit logging
 */
export function wrapTool<TArgs extends Record<string, unknown>, TResult>(
  shield: AgentShield,
  fn: (args: TArgs) => Promise<TResult> | TResult,
  options: WrapToolOptions
): (args: TArgs, agentId?: string) => Promise<TResult> {
  return async (args: TArgs, agentId?: string): Promise<TResult> => {
    const effectiveAgentId = agentId || options.defaultAgentId || "default-agent";
    const evalResult = await shield.evaluate({
      agentId: effectiveAgentId,
      tool: options.toolName,
      args,
    });

    if (evalResult.verdict === "DENY" || evalResult.verdict === "ASK_REJECTED") {
      throw new SecurityPolicyError(
        `AgentShield policy denied execution of '${options.toolName}': ${evalResult.reason}`,
        evalResult
      );
    }

    // Execute with sanitized arguments
    return await fn(evalResult.sanitizedArgs as TArgs);
  };
}
