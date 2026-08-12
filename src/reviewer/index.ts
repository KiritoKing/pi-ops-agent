#!/usr/bin/env node
import { createInterface } from "node:readline";
import { parseApprovalReviewRequest } from "../shared/approval-review.js";
import { deterministicApprovalReview } from "./reviewer.js";
import { listenApprovalReviewer } from "./server.js";

const MAX_REQUEST_BYTES = 256 * 1024;

async function main(): Promise<void> {
  const socketArgument = process.argv.slice(2).find((argument) => argument.startsWith("--socket="));
  if (socketArgument !== undefined) {
    if (process.argv.length !== 3) throw new Error("usage: agentd-approval-reviewer --socket=PATH");
    const server = await listenApprovalReviewer(socketArgument.slice("--socket=".length));
    const stop = (): void => {
      server.close(() => { process.exitCode = 0; });
    };
    process.once("SIGTERM", stop);
    process.once("SIGINT", stop);
    return;
  }
  if (process.argv.length !== 2) {
    throw new Error("usage: agentd-approval-reviewer [--socket=PATH]");
  }
  const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
  for await (const line of lines) {
    if (Buffer.byteLength(line) > MAX_REQUEST_BYTES) {
      process.stdout.write(`${JSON.stringify({ ok: false, error: "review request is too large" })}\n`);
      continue;
    }
    try {
      const request = parseApprovalReviewRequest(JSON.parse(line) as unknown);
      process.stdout.write(`${JSON.stringify({
        ok: true,
        review: deterministicApprovalReview(request),
      })}\n`);
    } catch (error) {
      process.stdout.write(`${JSON.stringify({
        ok: false,
        error: error instanceof Error ? error.message : String(error),
      })}\n`);
    }
  }
}

main().catch((error: unknown) => {
  process.stderr.write(`agentd-approval-reviewer: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
