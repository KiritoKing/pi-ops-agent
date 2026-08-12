import { spawn } from "node:child_process";
import { createConnection } from "node:net";
import {
  parseApprovalReview,
  type ApprovalReview,
  type ApprovalReviewRequest,
} from "../shared/approval-review.js";
import { requireExactRecord } from "../shared/strict.js";
import { requireString } from "../shared/guards.js";
import { encodeFrame, FrameDecoder } from "../shared/framing.js";

const MAX_REVIEW_RESPONSE_BYTES = 256 * 1024;
const DEFAULT_REVIEW_TIMEOUT_MS = 30_000;

export interface ApprovalReviewProvider {
  review(request: ApprovalReviewRequest): Promise<ApprovalReview>;
}

function parseReviewerResponse(value: unknown): ApprovalReview {
  const response = requireExactRecord(value, "reviewer response", [
    "ok", "review", "error",
  ]);
  if (response.ok !== true) {
    throw new Error(requireString(response.error, "reviewer response.error", { max: 8192 }));
  }
  return parseApprovalReview(response.review);
}

export class UnixSocketApprovalReviewer implements ApprovalReviewProvider {
  readonly #socketPath: string;
  readonly #timeoutMs: number;

  constructor(
    socketPath = "/run/ops-agent/reviewer/reviewer.sock",
    timeoutMs = DEFAULT_REVIEW_TIMEOUT_MS,
  ) {
    this.#socketPath = socketPath;
    this.#timeoutMs = timeoutMs;
  }

  async review(request: ApprovalReviewRequest): Promise<ApprovalReview> {
    return await new Promise<ApprovalReview>((resolve, reject) => {
      const socket = createConnection(this.#socketPath);
      const decoder = new FrameDecoder(MAX_REVIEW_RESPONSE_BYTES);
      let settled = false;
      const finish = (error?: unknown, review?: ApprovalReview): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        socket.destroy();
        if (error !== undefined) {
          reject(error instanceof Error ? error : new Error("approval reviewer failed"));
        } else if (review !== undefined) {
          resolve(review);
        } else {
          reject(new Error("approval reviewer closed without a response"));
        }
      };
      const timer = setTimeout(() => {
        finish(new Error("approval reviewer timed out"));
      }, this.#timeoutMs);
      socket.once("connect", () => socket.write(encodeFrame(request)));
      socket.on("data", (chunk: Buffer) => {
        try {
          const frames = decoder.push(chunk);
          if (frames.length !== 1) {
            if (frames.length === 0) return;
            throw new Error("approval reviewer returned multiple responses");
          }
          finish(undefined, parseReviewerResponse(frames[0]));
        } catch (error) {
          finish(error);
        }
      });
      socket.once("error", (error) => finish(error));
      socket.once("close", () => finish());
    });
  }
}

export class SubprocessApprovalReviewer implements ApprovalReviewProvider {
  readonly #executable: string;
  readonly #timeoutMs: number;

  constructor(
    executable = "/opt/pi-ops-agent/bin/agentd-approval-reviewer",
    timeoutMs = DEFAULT_REVIEW_TIMEOUT_MS,
  ) {
    this.#executable = executable;
    this.#timeoutMs = timeoutMs;
  }

  async review(request: ApprovalReviewRequest): Promise<ApprovalReview> {
    const child = spawn(this.#executable, [], {
      shell: false,
      stdio: ["pipe", "pipe", "pipe"],
      cwd: "/",
      env: { PATH: "/usr/bin:/bin", LANG: "C.UTF-8" },
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    child.stdout.on("data", (chunk: Buffer | string) => {
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      stdoutBytes += bytes.length;
      if (stdoutBytes <= MAX_REVIEW_RESPONSE_BYTES) stdout.push(bytes);
      else child.kill("SIGKILL");
    });
    child.stderr.on("data", (chunk: Buffer | string) => {
      if (stderrBytes >= 8192) return;
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      const remaining = 8192 - stderrBytes;
      stderr.push(bytes.subarray(0, remaining));
      stderrBytes += Math.min(bytes.length, remaining);
    });
    child.stdin.end(`${JSON.stringify(request)}\n`);
    const timer = setTimeout(() => child.kill("SIGKILL"), this.#timeoutMs);
    const exit = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(
      (resolve, reject) => {
        child.once("error", reject);
        child.once("close", (code, signal) => resolve({ code, signal }));
      },
    ).finally(() => clearTimeout(timer));
    if (exit.code !== 0 || exit.signal !== null) {
      const detail = Buffer.concat(stderr).toString("utf8").trim();
      throw new Error(`approval reviewer failed (${exit.signal ?? exit.code ?? "unknown"})${detail ? `: ${detail}` : ""}`);
    }
    if (stdoutBytes > MAX_REVIEW_RESPONSE_BYTES) {
      throw new Error("approval reviewer response exceeded its size limit");
    }
    const lines = Buffer.concat(stdout).toString("utf8").trim().split("\n");
    if (lines.length !== 1 || lines[0] === undefined) {
      throw new Error("approval reviewer returned an invalid response frame");
    }
    return parseReviewerResponse(JSON.parse(lines[0]) as unknown);
  }
}
