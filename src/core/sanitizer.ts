// SPDX-License-Identifier: Apache-2.0

import path from "node:path";

const SECRET_PATTERNS: Array<{ name: string; pattern: RegExp; replacement: string }> = [
  { name: "OpenAI Key", pattern: /sk-[a-zA-Z0-9_-]{20,}/g, replacement: "[REDACTED:OPENAI_KEY]" },
  { name: "Anthropic Key", pattern: /sk-ant-[a-zA-Z0-9_-]{20,}/g, replacement: "[REDACTED:ANTHROPIC_KEY]" },
  { name: "GitHub Token", pattern: /gh[pousr]_[a-zA-Z0-9]{36}/g, replacement: "[REDACTED:GITHUB_TOKEN]" },
  { name: "Bearer Token", pattern: /Bearer\s+[a-zA-Z0-9_\-\.]{15,}/gi, replacement: "Bearer [REDACTED:BEARER_TOKEN]" },
  { name: "Private Key", pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, replacement: "[REDACTED:PRIVATE_KEY]" },
  { name: "Password", pattern: /("?(?:password|secret|apiKey|api_key|token)"?\s*[:=]\s*)"[^"]+"/gi, replacement: '$1"[REDACTED]"' },
];

/**
 * Redacts sensitive credentials, tokens and private keys from strings and objects
 */
export function redactSecrets<T>(input: T): T {
  if (typeof input === "string") {
    let result: string = input;
    for (const { pattern, replacement } of SECRET_PATTERNS) {
      result = result.replace(pattern, replacement);
    }
    return result as unknown as T;
  }

  if (Array.isArray(input)) {
    return (input.map((item) => redactSecrets(item)) as unknown) as T;
  }

  if (input !== null && typeof input === "object") {
    const copy: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(input)) {
      if (/password|secret|token|apiKey|api_key|auth/i.test(key) && typeof value === "string") {
        copy[key] = "[REDACTED]";
      } else {
        copy[key] = redactSecrets(value);
      }
    }
    return copy as unknown as T;
  }

  return input;
}

/**
 * Checks whether a given path attempts path traversal or escapes the allowed directories
 */
export function isPathSafe(
  targetPath: string,
  allowedRoots: string[] = [],
  forbiddenPatterns: string[] = []
): { safe: boolean; reason?: string } {
  // Decode URL encoding and check for null bytes
  let decoded = targetPath;
  try {
    decoded = decodeURIComponent(targetPath);
  } catch {
    // If malformed URI, treat as suspicious
    return { safe: false, reason: "Malformed URI encoding in file path" };
  }

  if (decoded.includes("\0")) {
    return { safe: false, reason: "Null byte injection detected in file path" };
  }

  // Check explicit forbidden patterns (case-insensitive)
  const lower = decoded.toLowerCase().replace(/\\/g, "/");
  for (const forbidden of forbiddenPatterns) {
    const forbLower = forbidden.toLowerCase().replace(/\\/g, "/");
    if (lower.includes(forbLower)) {
      return { safe: false, reason: `Path matches forbidden pattern: ${forbidden}` };
    }
  }

  // Common sensitive file blocks
  const sensitiveFiles = [".env", "id_rsa", "id_ed25519", ".git/config", "/etc/passwd", "/etc/shadow", "c:\\windows\\system32"];
  for (const sensitive of sensitiveFiles) {
    if (lower.includes(sensitive)) {
      return { safe: false, reason: `Access to sensitive target forbidden: ${sensitive}` };
    }
  }

  if (allowedRoots.length === 0) {
    return { safe: true };
  }

  const resolvedTarget = path.resolve(decoded);

  const withinAnyRoot = allowedRoots.some((root) => {
    const resolvedRoot = path.resolve(root);
    const relative = path.relative(resolvedRoot, resolvedTarget);
    return !relative.startsWith("..") && !path.isAbsolute(relative);
  });

  if (!withinAnyRoot) {
    return {
      safe: false,
      reason: `Target path '${targetPath}' is outside authorized directory roots: [${allowedRoots.join(", ")}]`,
    };
  }

  return { safe: true };
}
