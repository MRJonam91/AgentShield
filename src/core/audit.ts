// SPDX-License-Identifier: Apache-2.0

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { GENESIS_PREV_HASH } from "./constants.ts";
import type { AuditRecord, AuditVerificationResult, DecisionVerdict } from "./types.ts";

/**
 * Deterministically sorts object keys for canonical JSON hashing
 */
export function canonicalJson(obj: unknown): string {
  if (obj === null || typeof obj !== "object") {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return `[${obj.map((item) => canonicalJson(item)).join(",")}]`;
  }
  const keys = Object.keys(obj as Record<string, unknown>).sort();
  const pairs = keys.map((k) => `${JSON.stringify(k)}:${canonicalJson((obj as Record<string, unknown>)[k])}`);
  return `{${pairs.join(",")}}`;
}

/**
 * Computes cryptographic SHA-256 hash for an audit record linked to prevHash
 */
export function computeRecordHash(params: {
  index: number;
  timestamp: string;
  id: string;
  agentId: string;
  tool: string;
  args: Record<string, unknown>;
  decision: DecisionVerdict;
  reason: string;
  prevHash: string;
}): string {
  const payload = [
    params.index,
    params.timestamp,
    params.id,
    params.agentId,
    params.tool,
    canonicalJson(params.args),
    params.decision,
    params.reason,
    params.prevHash,
  ].join("|");

  return crypto.createHash("sha256").update(payload, "utf8").digest("hex");
}

/**
 * Verifies the integrity of an array of chained audit records
 */
export function verifyAuditChain(records: AuditRecord[]): AuditVerificationResult {
  if (records.length === 0) {
    return { valid: true, totalRecords: 0 };
  }

  let expectedPrevHash = GENESIS_PREV_HASH;
  let lastTimestamp = 0;

  for (let i = 0; i < records.length; i++) {
    const record = records[i];
    if (!record) {
      return { valid: false, totalRecords: records.length, tamperedIndex: i, error: "Undefined record found" };
    }

    if (record.index !== i) {
      return {
        valid: false,
        totalRecords: records.length,
        tamperedIndex: i,
        error: `Sequence index broken: expected ${i}, found ${record.index}`,
      };
    }

    if (record.prevHash !== expectedPrevHash) {
      return {
        valid: false,
        totalRecords: records.length,
        tamperedIndex: i,
        error: `PrevHash mismatch at index ${i}: expected '${expectedPrevHash}', found '${record.prevHash}'`,
      };
    }

    const currentTimestamp = Date.parse(record.timestamp);
    if (!isNaN(currentTimestamp) && currentTimestamp < lastTimestamp) {
      return {
        valid: false,
        totalRecords: records.length,
        tamperedIndex: i,
        error: `Timestamp anomaly at index ${i}: record timestamp went backward in time`,
      };
    }
    if (!isNaN(currentTimestamp)) {
      lastTimestamp = currentTimestamp;
    }

    const recomputedHash = computeRecordHash({
      index: record.index,
      timestamp: record.timestamp,
      id: record.id,
      agentId: record.agentId,
      tool: record.tool,
      args: record.args,
      decision: record.decision,
      reason: record.reason,
      prevHash: record.prevHash,
    });

    if (recomputedHash !== record.hash) {
      return {
        valid: false,
        totalRecords: records.length,
        tamperedIndex: i,
        error: `Hash verification failure at index ${i}: stored '${record.hash}' does not match computed '${recomputedHash}'`,
      };
    }

    expectedPrevHash = record.hash;
  }

  return { valid: true, totalRecords: records.length };
}

/**
 * Verifiable Audit Trail Manager
 */
export class AuditTrail {
  private filePath?: string;
  private inMemoryRecords: AuditRecord[] = [];
  private lastHash: string = GENESIS_PREV_HASH;
  private nextIndex: number = 0;

  constructor(filePath?: string) {
    if (filePath) {
      this.filePath = path.resolve(filePath);
      this.loadExisting();
    }
  }

  private loadExisting(): void {
    if (!this.filePath || !fs.existsSync(this.filePath)) {
      return;
    }

    try {
      const content = fs.readFileSync(this.filePath, "utf8");
      const lines = content.split("\n").filter((l) => l.trim().length > 0);
      for (const line of lines) {
        const record = JSON.parse(line) as AuditRecord;
        this.inMemoryRecords.push(record);
        this.lastHash = record.hash;
        this.nextIndex = record.index + 1;
      }
    } catch (err) {
      throw new Error(`Failed to read existing audit log from ${this.filePath}: ${(err as Error).message}`);
    }
  }

  public append(params: {
    agentId: string;
    tool: string;
    args: Record<string, unknown>;
    decision: DecisionVerdict;
    reason: string;
    timestamp?: string;
    id?: string;
  }): AuditRecord {
    const timestamp = params.timestamp || new Date().toISOString();
    const id = params.id || crypto.randomUUID();
    const index = this.nextIndex++;
    const prevHash = this.lastHash;

    const hash = computeRecordHash({
      index,
      timestamp,
      id,
      agentId: params.agentId,
      tool: params.tool,
      args: params.args,
      decision: params.decision,
      reason: params.reason,
      prevHash,
    });

    const record: AuditRecord = {
      index,
      id,
      timestamp,
      agentId: params.agentId,
      tool: params.tool,
      args: params.args,
      decision: params.decision,
      reason: params.reason,
      prevHash,
      hash,
    };

    this.inMemoryRecords.push(record);
    this.lastHash = hash;

    if (this.filePath) {
      const dir = path.dirname(this.filePath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      fs.appendFileSync(this.filePath, JSON.stringify(record) + "\n", "utf8");
    }

    return record;
  }

  public getRecords(): AuditRecord[] {
    return [...this.inMemoryRecords];
  }

  public getTail(count: number = 10): AuditRecord[] {
    return this.inMemoryRecords.slice(-count);
  }

  public verify(): AuditVerificationResult {
    return verifyAuditChain(this.inMemoryRecords);
  }

  public static verifyFile(filePath: string): AuditVerificationResult {
    const resolved = path.resolve(filePath);
    if (!fs.existsSync(resolved)) {
      return { valid: false, totalRecords: 0, error: `Audit log file not found: ${filePath}` };
    }
    const content = fs.readFileSync(resolved, "utf8");
    const lines = content.split("\n").filter((l) => l.trim().length > 0);
    const records: AuditRecord[] = [];
    for (let i = 0; i < lines.length; i++) {
      try {
        records.push(JSON.parse(lines[i]!) as AuditRecord);
      } catch (err) {
        return {
          valid: false,
          totalRecords: i,
          tamperedIndex: i,
          error: `Malformed JSON at line ${i + 1}: ${(err as Error).message}`,
        };
      }
    }
    return verifyAuditChain(records);
  }
}
