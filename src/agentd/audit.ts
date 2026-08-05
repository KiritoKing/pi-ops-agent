import { createHash } from "node:crypto";
import { appendFile, mkdir, readFile } from "node:fs/promises";
import { dirname } from "node:path";
import { requireRecord, requireString } from "../shared/guards.js";
import { redact } from "../shared/redaction.js";

interface AuditEnvelope {
  timestamp: string;
  previousHash: string;
  hash: string;
  event: unknown;
}

export class AuditLog {
  readonly #path: string;
  #previousHash = "0".repeat(64);
  #queue: Promise<void> = Promise.resolve();

  constructor(path: string) {
    this.#path = path;
  }

  async initialize(): Promise<void> {
    await mkdir(dirname(this.#path), { recursive: true, mode: 0o750 });
    let contents: string;
    try {
      contents = await readFile(this.#path, "utf8");
    } catch (error) {
      if (error instanceof Error && "code" in error && error.code === "ENOENT") return;
      throw error;
    }

    let expectedPrevious = "0".repeat(64);
    for (const [index, line] of contents.split("\n").entries()) {
      if (line.length === 0) continue;
      let decoded: unknown;
      try {
        decoded = JSON.parse(line) as unknown;
      } catch {
        throw new Error(`audit chain contains invalid JSON at line ${index + 1}`);
      }
      const envelope = requireRecord(decoded, `audit line ${index + 1}`);
      const timestamp = requireString(envelope.timestamp, "audit timestamp", { max: 64 });
      const previousHash = requireString(envelope.previousHash, "audit previousHash", {
        max: 64,
        pattern: /^[a-f0-9]{64}$/,
      });
      const hash = requireString(envelope.hash, "audit hash", {
        max: 64,
        pattern: /^[a-f0-9]{64}$/,
      });
      if (previousHash !== expectedPrevious) {
        throw new Error(`audit chain previous hash mismatch at line ${index + 1}`);
      }
      const body = JSON.stringify({ timestamp, event: envelope.event });
      const expectedHash = createHash("sha256")
        .update(expectedPrevious)
        .update("\n")
        .update(body)
        .digest("hex");
      if (hash !== expectedHash) {
        throw new Error(`audit chain hash mismatch at line ${index + 1}`);
      }
      expectedPrevious = hash;
    }
    this.#previousHash = expectedPrevious;
  }

  append(event: unknown): Promise<void> {
    const write = async (): Promise<void> => {
      const timestamp = new Date().toISOString();
      const safeEvent = redact(event);
      const body = JSON.stringify({ timestamp, event: safeEvent });
      const hash = createHash("sha256")
        .update(this.#previousHash)
        .update("\n")
        .update(body)
        .digest("hex");
      const envelope: AuditEnvelope = {
        timestamp,
        previousHash: this.#previousHash,
        hash,
        event: safeEvent,
      };
      await appendFile(this.#path, `${JSON.stringify(envelope)}\n`, {
        encoding: "utf8",
        mode: 0o600,
      });
      this.#previousHash = hash;
    };
    this.#queue = this.#queue.then(write, write);
    return this.#queue;
  }
}
