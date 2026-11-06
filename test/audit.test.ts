// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { AuditTrail, verifyAuditChain } from "../src/core/audit.ts";

test("AuditTrail generates tamper-evident cryptographic hash chain", () => {
  const audit = new AuditTrail();

  audit.append({
    agentId: "agent-1",
    tool: "read_file",
    args: { path: "notes.txt" },
    decision: "ALLOW",
    reason: "Safe read permitted",
  });

  audit.append({
    agentId: "agent-1",
    tool: "write_file",
    args: { path: "notes.txt", content: "hello" },
    decision: "ASK_APPROVED",
    reason: "Approved by human",
  });

  audit.append({
    agentId: "agent-2",
    tool: "exec",
    args: { command: "rm -rf /" },
    decision: "DENY",
    reason: "Destructive command blocked",
  });

  const records = audit.getRecords();
  assert.equal(records.length, 3);
  assert.equal(records[0]?.index, 0);
  assert.equal(records[1]?.index, 1);
  assert.equal(records[2]?.index, 2);
  assert.equal(records[1]?.prevHash, records[0]?.hash);
  assert.equal(records[2]?.prevHash, records[1]?.hash);

  const verification = audit.verify();
  assert.equal(verification.valid, true);
  assert.equal(verification.totalRecords, 3);
});

test("Audit verification detects tampering or modification", () => {
  const audit = new AuditTrail();
  audit.append({
    agentId: "agent-a",
    tool: "t1",
    args: { val: 1 },
    decision: "ALLOW",
    reason: "ok",
  });
  audit.append({
    agentId: "agent-a",
    tool: "t2",
    args: { val: 2 },
    decision: "ALLOW",
    reason: "ok",
  });

  const tampered = JSON.parse(JSON.stringify(audit.getRecords()));
  // Tamper with second record's arguments without recalculating hash
  tampered[1].args = { val: 999 };

  const check = verifyAuditChain(tampered);
  assert.equal(check.valid, false);
  assert.equal(check.tamperedIndex, 1);
});

test("AuditTrail persists and verifies from file", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "agentshield-test-"));
  const logFile = path.join(tmpDir, "test-audit.jsonl");

  try {
    const audit = new AuditTrail(logFile);
    audit.append({
      agentId: "persisted-agent",
      tool: "ping",
      args: {},
      decision: "ALLOW",
      reason: "ping",
    });

    const fileVerification = AuditTrail.verifyFile(logFile);
    assert.equal(fileVerification.valid, true);
    assert.equal(fileVerification.totalRecords, 1);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
