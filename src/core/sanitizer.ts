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
  let decoded = targetPath;
  try {
    decoded = decodeURIComponent(targetPath);
  } catch {
    return { safe: false, reason: "Malformed URI encoding in file path" };
  }

  if (decoded.includes("\0")) {
    return { safe: false, reason: "Null byte injection detected in file path" };
  }

  const lower = decoded.toLowerCase().replace(/\\/g, "/");
  for (const forbidden of forbiddenPatterns) {
    const forbLower = forbidden.toLowerCase().replace(/\\/g, "/");
    if (lower.includes(forbLower)) {
      return { safe: false, reason: `Path matches forbidden pattern: ${forbidden}` };
    }
  }

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

/**
 * Checks whether a shell command is safe against injection and destructive patterns
 */
export function isCommandSafe(
  cmd: string,
  allowedCommands?: string[],
  forbiddenCommands?: string[]
): { safe: boolean; reason?: string } {
  const trimmed = cmd.trim();
  if (!trimmed) {
    return { safe: false, reason: "Empty command string" };
  }

  // Null byte or control character checks
  if (/[\0\x01-\x08\x0E-\x1F]/.test(trimmed)) {
    return { safe: false, reason: "Suspicious control characters in command" };
  }

  // Forbidden patterns check
  if (forbiddenCommands) {
    for (const pattern of forbiddenCommands) {
      if (new RegExp(pattern, "i").test(trimmed)) {
        return { safe: false, reason: `Command matches forbidden pattern: '${pattern}'` };
      }
    }
  }

  // Whitelist check
  if (allowedCommands && allowedCommands.length > 0) {
    const matched = allowedCommands.some((pat) => new RegExp(pat, "i").test(trimmed));
    if (!matched) {
      return { safe: false, reason: `Command '${trimmed}' not in allowed commands whitelist` };
    }
  }

  return { safe: true };
}

/**
 * Checks whether a URL is safe against SSRF (Server-Side Request Forgery) attacks
 */
export function isUrlSafe(
  urlStr: string,
  allowedDomains?: string[]
): { safe: boolean; reason?: string } {
  let parsed: URL;
  try {
    parsed = new URL(urlStr);
  } catch {
    return { safe: false, reason: `Invalid URL format: '${urlStr}'` };
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return { safe: false, reason: `Disallowed URL protocol: '${parsed.protocol}' (must be http or https)` };
  }

  const host = parsed.hostname.toLowerCase();

  // Localhost & metadata addresses
  if (
    host === "localhost" ||
    host === "127.0.0.1" ||
    host === "0.0.0.0" ||
    host === "::1" ||
    host === "[::1]" ||
    host === "169.254.169.254" || // AWS / GCP / Azure metadata service
    host === "metadata.google.internal" ||
    host.endsWith(".localhost") ||
    host.endsWith(".local")
  ) {
    return { safe: false, reason: `SSRF protection: access to loopback/metadata host '${host}' is blocked` };
  }

  // Private IPv4 ranges
  const ipv4Match = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4Match) {
    const p1 = parseInt(ipv4Match[1]!, 10);
    const p2 = parseInt(ipv4Match[2]!, 10);
    if (
      p1 === 10 || // 10.0.0.0/8
      (p1 === 172 && p2 >= 16 && p2 <= 31) || // 172.16.0.0/12
      (p1 === 192 && p2 === 168) || // 192.168.0.0/16
      (p1 === 169 && p2 === 254) // 169.254.0.0/16 link-local
    ) {
      return { safe: false, reason: `SSRF protection: access to private IP address '${host}' is blocked` };
    }
  }

  // Allowed domains check
  if (allowedDomains && allowedDomains.length > 0) {
    const isAllowed = allowedDomains.some((d) => {
      const lowerD = d.toLowerCase();
      return host === lowerD || host.endsWith("." + lowerD);
    });
    if (!isAllowed) {
      return { safe: false, reason: `Host '${host}' not in allowed domains whitelist: [${allowedDomains.join(", ")}]` };
    }
  }

  return { safe: true };
}

/**
 * Checks whether an SQL statement is safe, preventing destructive statements when readOnly
 */
export function isSqlSafe(
  query: string,
  readOnly: boolean = false
): { safe: boolean; reason?: string } {
  const trimmed = query.trim();
  if (!trimmed) {
    return { safe: false, reason: "Empty SQL query" };
  }

  if (readOnly) {
    const destructiveRegex = /\b(DROP|TRUNCATE|ALTER|DELETE|UPDATE|INSERT|CREATE|REPLACE|GRANT|REVOKE)\b/i;
    if (destructiveRegex.test(trimmed)) {
      return { safe: false, reason: "Destructive SQL operation detected on read-only database tool" };
    }
  }

  return { safe: true };
}
