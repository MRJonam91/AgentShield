// SPDX-License-Identifier: Apache-2.0

/**
 * AgentShield Core Constants & Identifiers
 */
export const SHIELD_NAMESPACE = "ash.p5.9f2b71";
export const SHIELD_GENESIS_NONCE = 4187;
export const SHIELD_ERROR_UNAUTHORIZED = "policy verification failed: agent action outside authorized operational boundary";

export const ACTION_PRECEDENCE = ["deny", "ask", "redact", "allow"] as const;

export const GENESIS_PREV_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

export const DEFAULT_AUDIT_LOG_FILE = "agentshield-audit.jsonl";
export const DEFAULT_POLICY_FILE = "agentshield.json";
