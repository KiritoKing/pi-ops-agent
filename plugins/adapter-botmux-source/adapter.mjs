#!/usr/bin/env node
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { createReadStream, createWriteStream, realpathSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { Writable } from "node:stream";
import { fileURLToPath, pathToFileURL } from "node:url";

const MAX_EVENT_LINE_BYTES = 128 * 1024;
const MAX_CHANNEL_CONTENT_BYTES = 64 * 1024;
const MAX_TRANSPORT_ERROR_BYTES = 8 * 1024;
const TRUNCATION_MARKER = "\n[TRUNCATED]";
const BRACKETED_PASTE_START = "\u001b[200~";
const BRACKETED_PASTE_END = "\u001b[201~";
const BRACKETED_PASTE_START_BYTES = Buffer.from(BRACKETED_PASTE_START);
const BRACKETED_PASTE_END_BYTES = Buffer.from(BRACKETED_PASTE_END);
const BOTMUX_PREFIX_MARKER = /<(?:botmux_[a-z_]+|session_id|identity|role|whiteboard|chat_context)(?:\s|>)/u;
const USER_MESSAGE_OPEN = /(?:^|\r?\n)<user_message>\r?\n/gu;
const USER_MESSAGE_CLOSE = /\r?\n<\/user_message>(?=\r?\n|$)/gu;
const SENDER_TAG = /<sender\s+[^>]*\btype=(?:"(user|bot)"|'(user|bot)')[^>]*\/\s*>/gu;
const COMPLETION_EVENT_KEYS = new Set([
  "version", "type", "eventId", "outcome", "content",
  "sessionId", "turnId", "machineId", "targetId",
]);
const STRICT_UTF8_DECODER = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

export const descriptor = Object.freeze({
  apiVersion: "agentd.adapter/v1",
  schemaVersion: 1,
  adapterId: "adapter.botmux",
  runtimeAuthority: Object.freeze({
    execution: "source-process",
    filesystem: "host-as-runtime-uid",
    network: "host",
    credentials: "runtime-uid-readable",
    actionScopeEnforcement: "digest-review-and-typed-ipc-contract",
  }),
  session: Object.freeze({
    mapping: "adapter-owned",
    writerLease: "gateway-global",
    controlApiVersion: "agentd.adapter-session-control/v1",
    supportedControls: Object.freeze(["bind"]),
  }),
  inbound: Object.freeze({
    transport: "stdin",
    framing: "botmux-v1",
    contractApiVersion: "agentd.adapter-inbound/v1",
    supportedTypes: Object.freeze(["text"]),
    maxFrameBytes: MAX_EVENT_LINE_BYTES,
  }),
  outbound: Object.freeze({
    transport: "completion-fd",
    framing: "ndjson",
    schema: "completion.v1",
    actionApiVersion: "agentd.adapter-outbound-action/v1",
    supportedActions: Object.freeze(["send"]),
    maxFrameBytes: MAX_EVENT_LINE_BYTES,
  }),
  approval: Object.freeze({
    mode: "status-only",
    identitySource: "none",
    replayProtection: "none",
  }),
});

function firstMatch(expression, value) {
  expression.lastIndex = 0;
  return expression.exec(value) ?? undefined;
}

function lastMatch(expression, value) {
  expression.lastIndex = 0;
  let result;
  for (let match = expression.exec(value); match !== null; match = expression.exec(value)) {
    result = match;
  }
  return result;
}

export function inspectBotMuxEnvelope(value) {
  const opening = firstMatch(USER_MESSAGE_OPEN, value);
  const closing = lastMatch(USER_MESSAGE_CLOSE, value);
  if (!opening || !closing) return { unwrapped: false };
  const contentStart = opening.index + opening[0].length;
  if (closing.index < contentStart) return { unwrapped: false };
  if (!BOTMUX_PREFIX_MARKER.test(value.slice(0, opening.index))) return { unwrapped: false };
  const sender = lastMatch(
    SENDER_TAG,
    value.slice(closing.index + closing[0].length),
  );
  const senderType = sender?.[1] ?? sender?.[2];
  return {
    unwrapped: true,
    content: value.slice(contentStart, closing.index),
    ...(senderType === undefined ? {} : { senderType }),
  };
}

export function createBotMuxInputConsumer(onEnvelope) {
  let pending = Buffer.alloc(0);
  let pasted = Buffer.alloc(0);
  let inPaste = false;
  const scan = (value, final = false) => {
    pending = Buffer.concat([pending, value]);
    const messages = [];
    while (pending.length > 0) {
      if (!inPaste) {
        const start = pending.indexOf(BRACKETED_PASTE_START_BYTES);
        if (start < 0) {
          pending = final
            ? Buffer.alloc(0)
            : pending.subarray(Math.max(0, pending.length - BRACKETED_PASTE_START_BYTES.length + 1));
          return messages;
        }
        pending = pending.subarray(start + BRACKETED_PASTE_START_BYTES.length);
        pasted = Buffer.alloc(0);
        inPaste = true;
      }

      const end = pending.indexOf(BRACKETED_PASTE_END_BYTES);
      if (end < 0) {
        const keep = final ? 0 : BRACKETED_PASTE_END_BYTES.length - 1;
        const available = Math.max(0, pending.length - keep);
        if (pasted.length + available > descriptor.inbound.maxFrameBytes) {
          throw new Error("BotMux inbound envelope exceeds the declared raw byte limit");
        }
        pasted = Buffer.concat([pasted, pending.subarray(0, available)]);
        pending = pending.subarray(available);
        if (final) throw new Error("BotMux input ended inside a bracketed-paste frame");
        return messages;
      }
      if (pasted.length + end > descriptor.inbound.maxFrameBytes) {
        throw new Error("BotMux inbound envelope exceeds the declared raw byte limit");
      }
      pasted = Buffer.concat([pasted, pending.subarray(0, end)]);
      let text;
      try {
        text = STRICT_UTF8_DECODER.decode(pasted);
      } catch {
        throw new Error("BotMux inbound envelope is not valid UTF-8");
      }
      const inspected = inspectBotMuxEnvelope(text);
      messages.push(inspected.unwrapped ? inspected : { ...inspected, content: text });
      pending = pending.subarray(end + BRACKETED_PASTE_END_BYTES.length);
      pasted = Buffer.alloc(0);
      inPaste = false;
    }
    return messages;
  };

  return new Writable({
    write(chunk, _encoding, callback) {
      try {
        const messages = scan(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
        messages.reduce(
          (queue, message) => queue.then(async () => await onEnvelope(message)),
          Promise.resolve(),
        ).then(() => callback(), callback);
      } catch (error) {
        callback(error);
      }
    },
    final(callback) {
      try {
        const messages = scan(Buffer.alloc(0), true);
        messages.reduce(
          (queue, message) => queue.then(async () => await onEnvelope(message)),
          Promise.resolve(),
        ).then(() => callback(), callback);
      } catch (error) {
        callback(error);
      }
    },
  });
}

export function parseBotMuxInvocationArguments(arguments_) {
  let sessionId;
  let extensionSeen = false;
  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index];
    if (argument === "--session-id") {
      const value = arguments_[index + 1];
      if (value === undefined || value.length === 0) {
        throw new Error("--session-id requires a value");
      }
      if (sessionId !== undefined) throw new Error("--session-id may only be specified once");
      sessionId = value;
      index += 1;
      continue;
    }
    if (argument?.startsWith("--session-id=")) {
      if (sessionId !== undefined) throw new Error("--session-id may only be specified once");
      sessionId = argument.slice("--session-id=".length);
      if (sessionId.length === 0) throw new Error("--session-id requires a value");
      continue;
    }
    if (argument === "--extension") {
      const value = arguments_[index + 1];
      if (value === undefined || !isAbsolute(value)) {
        throw new Error("--extension requires an absolute path");
      }
      if (extensionSeen) throw new Error("--extension may only be specified once");
      extensionSeen = true;
      index += 1;
      continue;
    }
    if (argument?.startsWith("--extension=")) {
      const value = argument.slice("--extension=".length);
      if (!isAbsolute(value)) throw new Error("--extension requires an absolute path");
      if (extensionSeen) throw new Error("--extension may only be specified once");
      extensionSeen = true;
      continue;
    }
    if (argument?.startsWith("-")) throw new Error(`unsupported BotMux option: ${argument}`);
    throw new Error(
      "BotMux positional and @file prompts are forbidden; submit framed input on stdin",
    );
  }
  if (sessionId === undefined) throw new Error("--session-id is required");
  return { sessionId };
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
    && Object.keys(value).every((key) => COMPLETION_EVENT_KEYS.has(key))
    && value.version === 1
    && value.type === "completion"
    && typeof value.eventId === "string"
    && (value.outcome === "success" || value.outcome === "error")
    && typeof value.content === "string"
    && [value.sessionId, value.turnId, value.machineId, value.targetId]
      .every((item) => item === undefined || typeof item === "string");
}

function hasForbiddenMessageControl(value) {
  return Array.from(value).some((character) => {
    const code = character.codePointAt(0) ?? 0;
    if (code === 0x09 || code === 0x0a || code === 0x0d) return false;
    return code < 0x20
      || (code >= 0x7f && code <= 0x9f)
      || code === 0x061c
      || code === 0x200e
      || code === 0x200f
      || (code >= 0x2028 && code <= 0x202e)
      || (code >= 0x2066 && code <= 0x2069)
      || code === 0xfeff;
  });
}

function terminalSafeErrorText(value, maximumBytes = MAX_TRANSPORT_ERROR_BYTES) {
  let safe = "";
  let bytes = 0;
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    const replacement = character === "\n"
      ? character
      : hasForbiddenMessageControl(character)
        ? code <= 0xff
          ? `\\x${code.toString(16).padStart(2, "0")}`
          : `\\u{${code.toString(16)}}`
        : character;
    const nextBytes = Buffer.byteLength(replacement, "utf8");
    if (bytes + nextBytes > maximumBytes) break;
    safe += replacement;
    bytes += nextBytes;
  }
  return safe.trim();
}

export function parseCompletionEventLine(line, contracts) {
  if (!Buffer.isBuffer(line) || line.length === 0
    || line.length > descriptor.outbound.maxFrameBytes) {
    throw new Error("completion event is empty or exceeds the declared frame limit");
  }
  let text;
  try {
    text = STRICT_UTF8_DECODER.decode(line);
  } catch {
    throw new Error("completion event is not valid UTF-8");
  }
  const event = contracts.parseStrictJson(text, descriptor.outbound.maxFrameBytes);
  if (!isCompletionEvent(event)) throw new Error("unsupported event schema");
  return event;
}

export function createDeclaredSendAction(event, externalSessionId, contracts) {
  if (hasForbiddenMessageControl(event.content)) {
    throw new Error("completion content contains a forbidden control character");
  }
  const action = contracts.parseDeclaredAdapterOutboundAction(descriptor, {
    apiVersion: descriptor.outbound.actionApiVersion,
    schemaVersion: 1,
    type: "send",
    actionId: event.eventId,
    externalSessionId,
    content: event.content,
  });
  if (Buffer.byteLength(JSON.stringify(action), "utf8") > descriptor.outbound.maxFrameBytes) {
    throw new Error("declared send action exceeds the adapter frame limit");
  }
  return action;
}

async function loadCoreContracts(root) {
  const [adapterRuntime, workloadRuntime] = await Promise.all([
    import(pathToFileURL(resolve(root, "dist/shared/adapter-runtime.js")).href),
    import(pathToFileURL(resolve(root, "dist/shared/workload-runtime.js")).href),
  ]);
  if (typeof adapterRuntime.parseDeclaredAdapterOutboundAction !== "function"
    || typeof adapterRuntime.parseDeclaredAdapterInbound !== "function"
    || typeof adapterRuntime.parseDeclaredAdapterSessionControl !== "function"
    || typeof workloadRuntime.parseStrictJson !== "function") {
    throw new Error("core Adapter protocol validators are unavailable");
  }
  return {
    parseDeclaredAdapterOutboundAction: adapterRuntime.parseDeclaredAdapterOutboundAction,
    parseDeclaredAdapterInbound: adapterRuntime.parseDeclaredAdapterInbound,
    parseDeclaredAdapterSessionControl: adapterRuntime.parseDeclaredAdapterSessionControl,
    parseStrictJson: workloadRuntime.parseStrictJson,
  };
}

function requireFixedDescriptor(name, expected) {
  if (process.env[name] !== String(expected)) {
    throw new Error(`${name} must be the fixed descriptor ${expected}`);
  }
  return expected;
}

function encodeDeclaredInputFrame(frame) {
  const payload = Buffer.from(JSON.stringify(frame), "utf8");
  if (payload.length === 0 || payload.length > descriptor.inbound.maxFrameBytes) {
    throw new Error("declared Adapter input frame exceeds the raw wire byte limit");
  }
  return Buffer.concat([payload, Buffer.from("\n")]);
}

async function writeDeclaredInputFrame(output, frame) {
  const payload = encodeDeclaredInputFrame(frame);
  await new Promise((resolvePromise, rejectPromise) => {
    output.write(payload, (error) => {
      if (error) rejectPromise(error);
      else resolvePromise();
    });
  });
}

export function createDeclaredBind(sessionId, externalSessionId, contracts) {
  return contracts.parseDeclaredAdapterSessionControl(descriptor, {
    apiVersion: descriptor.session.controlApiVersion,
    schemaVersion: 1,
    type: "bind",
    controlId: `control:botmux:${randomUUID()}`,
    externalSessionId,
    sessionId,
  });
}

export function createDeclaredInboundText(
  content,
  senderType,
  externalSessionId,
  contracts,
) {
  const observedAt = new Date().toISOString();
  return contracts.parseDeclaredAdapterInbound(descriptor, {
    apiVersion: descriptor.inbound.contractApiVersion,
    schemaVersion: 1,
    type: "text",
    ingressId: `ingress:botmux:${randomUUID()}`,
    externalSessionId,
    conversationType: "direct",
    text: content,
    source: {
      authentication: "unverified",
      principalId: `botmux:${senderType ?? "unknown"}`,
    },
    observedAt,
  });
}

export function mentionArgument(senderType) {
  return senderType === "bot" ? "--no-mention" : "--mention-back";
}

async function runTransport(sessionId, content, senderType) {
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
        mentionArgument(senderType),
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
        const detail = terminalSafeErrorText(Buffer.concat(errors).toString("utf8"));
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
  const { sessionId } = parseBotMuxInvocationArguments(arguments_);
  const bridgeSessionId = process.env.BOTMUX_SESSION_ID;
  if (sessionId === undefined || bridgeSessionId === undefined || bridgeSessionId !== sessionId) {
    throw new Error("BotMux session binding is missing or does not match the Client session");
  }

  const configuredRoot = process.env.OPS_AGENT_CORE_ROOT;
  const root = configuredRoot === undefined
    ? resolve(dirname(fileURLToPath(import.meta.url)), "../..")
    : resolve(configuredRoot);
  if (configuredRoot !== undefined && root !== "/opt/pi-ops-agent/current") {
    throw new Error("OPS_AGENT_CORE_ROOT must resolve to /opt/pi-ops-agent/current");
  }
  const contracts = await loadCoreContracts(root);
  const inputDescriptor = requireFixedDescriptor("OPS_AGENT_ADAPTER_INPUT_FD", 4);
  const completionDescriptor = requireFixedDescriptor("OPS_AGENT_COMPLETION_FD", 3);
  const adapterInput = createWriteStream("", { fd: inputDescriptor });
  const eventStream = createReadStream("", { fd: completionDescriptor });
  const replySenders = [];
  await writeDeclaredInputFrame(
    adapterInput,
    createDeclaredBind(sessionId, bridgeSessionId, contracts),
  );
  const emitEnvelope = async (envelope) => {
    const content = envelope.content;
    if (typeof content !== "string" || content.length === 0) return;
    const frame = createDeclaredInboundText(
      content,
      envelope.senderType,
      bridgeSessionId,
      contracts,
    );
    await writeDeclaredInputFrame(adapterInput, frame);
    replySenders.push(envelope.senderType);
  };
  const inputConsumer = createBotMuxInputConsumer(emitEnvelope);
  process.stdin.pipe(inputConsumer);

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
      try {
        const event = parseCompletionEventLine(line, contracts);
        const senderType = replySenders.shift();
        const action = createDeclaredSendAction(event, sessionId, contracts);
        sendQueue = sendQueue
          .then(() => runTransport(action.externalSessionId, action.content, senderType))
          .catch((error) => {
            process.stderr.write(
              `ops-agent-botmux: outbound reply failed: ${terminalSafeErrorText(error.message)}\n`,
            );
          });
      } catch (error) {
        process.stderr.write(
          `ops-agent-botmux: invalid completion event: ${terminalSafeErrorText(error instanceof Error ? error.message : String(error))}\n`,
        );
      }
    }
    if (pending.length > MAX_EVENT_LINE_BYTES) {
      eventStream.destroy(new Error("unterminated completion event exceeds the declared byte limit"));
    }
  });

  const inputDone = new Promise((resolvePromise, rejectPromise) => {
    inputConsumer.once("error", rejectPromise);
    adapterInput.once("error", rejectPromise);
    inputConsumer.once("finish", () => {
      adapterInput.end(resolvePromise);
    });
  });
  const completionDone = new Promise((resolvePromise, rejectPromise) => {
    eventStream.once("error", rejectPromise);
    eventStream.once("end", resolvePromise);
  });
  await Promise.all([inputDone, completionDone]);
  await sendQueue;
}

function isMainModule() {
  const entry = process.argv[1];
  if (entry === undefined) return false;
  try {
    return realpathSync(entry) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (isMainModule()) {
  if (process.argv.length === 3 && process.argv[2] === "--agentd-adapter-describe") {
    process.stdout.write(`${JSON.stringify(descriptor)}\n`);
  } else {
    main().catch((error) => {
      process.stderr.write(
        `ops-agent-botmux: ${terminalSafeErrorText(error instanceof Error ? error.message : String(error))}\n`,
      );
      process.exitCode = 1;
    });
  }
}
