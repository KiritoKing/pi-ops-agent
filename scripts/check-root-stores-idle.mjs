#!/usr/bin/env node
import { lstat, readFile } from "node:fs/promises";

const TRANSIENT_STATES = new Set([
  "PREPARING",
  "EXECUTING",
  "VERIFYING",
  "ROLLING_BACK",
]);
const TERMINAL_OR_IDLE_STATES = new Set([
  "PENDING_APPROVAL",
  "REJECTED",
  "COMMITTED",
  "ROLLED_BACK",
  "RECOVERY_REQUIRED",
]);
const MAX_STORE_BYTES = 32 * 1024 * 1024;

if (process.argv.length < 3) {
  throw new Error("usage: check-root-stores-idle.mjs STATE_JSON...");
}

let inFlight = false;
for (const storePath of process.argv.slice(2)) {
  let stat;
  try {
    stat = await lstat(storePath);
  } catch (error) {
    if (error?.code === "ENOENT") continue;
    throw error;
  }
  const rootInvocation = typeof process.geteuid === "function" && process.geteuid() === 0;
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > MAX_STORE_BYTES
      || (rootInvocation && (stat.uid !== 0 || (stat.mode & 0o022) !== 0))) {
    throw new Error(`root broker store is unsafe or oversized: ${storePath}`);
  }
  const state = JSON.parse(await readFile(storePath, "utf8"));
  if (state === null || typeof state !== "object" || Array.isArray(state)
      || state.changes === null || typeof state.changes !== "object"
      || Array.isArray(state.changes)) {
    throw new Error(`root broker store has an unsupported shape: ${storePath}`);
  }
  for (const [changeId, change] of Object.entries(state.changes)) {
    if (change === null || typeof change !== "object" || Array.isArray(change)
        || typeof change.state !== "string") {
      throw new Error(`root broker store has an invalid change: ${storePath}:${changeId}`);
    }
    if (!TRANSIENT_STATES.has(change.state) && !TERMINAL_OR_IDLE_STATES.has(change.state)) {
      throw new Error(`root broker store has an unknown change state: ${storePath}:${changeId}`);
    }
    if (TRANSIENT_STATES.has(change.state)) {
      process.stderr.write(`${storePath}: ${changeId} is ${change.state}\n`);
      inFlight = true;
    }
  }
}

if (inFlight) {
  process.stderr.write("Refusing to interrupt an in-flight privileged change.\n");
  process.exitCode = 4;
}
