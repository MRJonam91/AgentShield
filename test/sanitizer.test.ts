// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";
import { isPathSafe, redactSecrets } from "../src/core/sanitizer.ts";

test("redactSecrets masks API keys, tokens and private keys", () => {
  const sample = {
    apiKey: "sk-12345678901234567890abcdef",
    nested: {
      github: "ghp_123456789012345678901234567890123456",
      header: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummysecretpayload",
      message: "safe message",
    },
  };

  const sanitized = redactSecrets(sample);
  assert.equal(sanitized.apiKey, "[REDACTED]");
  assert.equal(sanitized.nested.github, "[REDACTED:GITHUB_TOKEN]");
  assert.match(sanitized.nested.header, /Bearer \[REDACTED:BEARER_TOKEN\]/);
  assert.equal(sanitized.nested.message, "safe message");

  // Also test direct string redaction with OpenAI key in prose
  const rawText = "Calling api with sk-12345678901234567890abcdef now";
  assert.equal(redactSecrets(rawText), "Calling api with [REDACTED:OPENAI_KEY] now");
});

test("isPathSafe catches directory traversal attempts", () => {
  assert.equal(isPathSafe("../../secret.txt", ["./workspace"]).safe, false);
  assert.equal(isPathSafe("..%2fsecret.txt", ["./workspace"]).safe, false);
  assert.equal(isPathSafe("workspace/test\0.txt", ["./workspace"]).safe, false);
  assert.equal(isPathSafe("/etc/passwd").safe, false);
  assert.equal(isPathSafe(".env").safe, false);
  assert.equal(isPathSafe(".git/config").safe, false);
});
