#!/usr/bin/env node
import { spawn } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const MAX_EVENT_LINE_BYTES = 128 * 1024;
const MAX_CHANNEL_CONTENT_BYTES = 64 * 1024;
const MAX_TRANSPORT_ERROR_BYTES = 8 * 1024;
const TRUNCATION_MARKER = "\n[TRUNCATED]";

function sessionIdFromArguments(arguments_) {
  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index];
    if (argument === "--session-id") return arguments_[index + 1];
    if (argument?.startsWith("--session-id=")) return argument.slice("--session-id=".length);
  }
  return undefined;
}

function boundContent(content) {
  const encoded = Buffer.from(content, "utf8");
  if (encoded.length <= MAX_CHANNEL_CONTENT_BYTES) return content;
  const markerBytes = Buffer.byteLength(TRUNCATION_MARKER);
  let end = MAX_CHANNEL_CONTENT_BYTES - markerBytes;
  while (end > 0 && (encoded[end] ?? 0) >> 6 === 0b10) end -= 1;
  return `${encoded.subarray(0, end).toString("utf8")}${TRUNCATION_MARKER}`;
}

function isCompletionEvent(value) {
  return value !== null
    && typeof value === "object"
    && value.version === 1
    && value.type === "completion"
    && (value.outcome === "success" || value.outcome === "error")
    && typeof value.content === "string";
}

async function runTransport(sessionId, content) {
  if (content.length === 0) return;
  const directory = await mkdtemp(join(tmpdir(), "ops-agent-botmux-adapter-"));
  const contentFile = join(directory, "content.md");
  try {
    await writeFile(contentFile, boundContent(content), {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    });
    await new Promise((resolvePromise, rejectPromise) => {
      const child = spawn("botmux", [
        "send",
        "--session-id",
        sessionId,
        "--mention-back",
        "--content-file",
        contentFile,
      ], {
        shell: false,
        stdio: ["ignore", "ignore", "pipe"],
      });
      const errors = [];
      let errorBytes = 0;
      child.stderr.on("data", (chunk) => {
        if (errorBytes >= MAX_TRANSPORT_ERROR_BYTES) return;
        const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        const remaining = MAX_TRANSPORT_ERROR_BYTES - errorBytes;
        errors.push(bytes.subarray(0, remaining));
        errorBytes += Math.min(bytes.length, remaining);
      });
      child.once("error", rejectPromise);
      child.once("close", (code) => {
        if (code === 0) {
          resolvePromise();
          return;
        }
        const detail = Buffer.concat(errors).toString("utf8").trim();
        rejectPromise(new Error(
          `botmux send exited with code ${code ?? "unknown"}${detail ? `: ${detail}` : ""}`,
        ));
      });
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

async function main() {
  const arguments_ = process.argv.slice(2);
  const sessionId = sessionIdFromArguments(arguments_);
  const bridgeSessionId = process.env.BOTMUX_SESSION_ID;
  const canReply = sessionId !== undefined && bridgeSessionId === sessionId;
  if (sessionId !== undefined && !canReply) {
    process.stderr.write("ops-agent-botmux: session binding mismatch; outbound replies disabled\n");
  }

  const configuredRoot = process.env.OPS_AGENT_CORE_ROOT;
  const root = configuredRoot === undefined
    ? resolve(dirname(fileURLToPath(import.meta.url)), "../..")
    : resolve(configuredRoot);
  if (configuredRoot !== undefined && root !== "/opt/pi-ops-agent/current") {
    throw new Error("OPS_AGENT_CORE_ROOT must resolve to /opt/pi-ops-agent/current");
  }
  const coreExecutable = resolve(root, "bin/ops-agent");
  const childEnvironment = { ...process.env, OPS_AGENT_EVENT_FD: "3" };
  for (const key of Object.keys(childEnvironment)) {
    if (/^(?:BOTMUX|FEISHU|LARK)_/u.test(key)) delete childEnvironment[key];
  }

  const child = spawn(coreExecutable, arguments_, {
    env: childEnvironment,
    shell: false,
    stdio: ["inherit", "inherit", "inherit", "pipe"],
  });
  const eventStream = child.stdio[3];
  if (!eventStream) throw new Error("failed to allocate completion event pipe");

  let pending = Buffer.alloc(0);
  let sendQueue = Promise.resolve();
  eventStream.on("data", (chunk) => {
    pending = Buffer.concat([pending, Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)]);
    while (true) {
      const newline = pending.indexOf(0x0a);
      if (newline < 0) break;
      const line = pending.subarray(0, newline);
      pending = pending.subarray(newline + 1);
      if (line.length === 0) continue;
      if (line.length > MAX_EVENT_LINE_BYTES) {
        process.stderr.write("ops-agent-botmux: oversized completion event ignored\n");
        continue;
      }
      try {
        const event = JSON.parse(line.toString("utf8"));
        if (!isCompletionEvent(event)) throw new Error("unsupported event schema");
        if (canReply) {
          sendQueue = sendQueue
            .then(() => runTransport(sessionId, event.content))
            .catch((error) => {
              process.stderr.write(`ops-agent-botmux: outbound reply failed: ${error.message}\n`);
            });
        }
      } catch (error) {
        process.stderr.write(
          `ops-agent-botmux: invalid completion event: ${error instanceof Error ? error.message : String(error)}\n`,
        );
      }
    }
    if (pending.length > MAX_EVENT_LINE_BYTES) {
      pending = Buffer.alloc(0);
      process.stderr.write("ops-agent-botmux: unterminated oversized event discarded\n");
    }
  });

  const exit = await new Promise((resolvePromise, rejectPromise) => {
    child.once("error", rejectPromise);
    child.once("close", (code, signal) => resolvePromise({ code, signal }));
  });
  await sendQueue;
  if (exit.signal) {
    process.kill(process.pid, exit.signal);
    return;
  }
  process.exitCode = exit.code ?? 1;
}

main().catch((error) => {
  process.stderr.write(`ops-agent-botmux: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
