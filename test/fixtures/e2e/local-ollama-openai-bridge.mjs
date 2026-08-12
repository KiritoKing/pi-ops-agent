#!/usr/bin/env node

// One-shot live-model evidence fixture. The CLI accepts no arguments: a
// canonical 32-byte base64url bearer token arrives on inherited FD 3, while
// non-secret listener/model bindings arrive through the narrow OPS_E2E_*
// environment below. The exported test entrypoint is only for a fake Ollama
// on an ephemeral port; the CLI always uses the fixed loopback endpoint.

import { createHash, timingSafeEqual } from "node:crypto";
import { readSync } from "node:fs";
import { createServer, request as httpRequest } from "node:http";
import { isIP } from "node:net";
import { resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { TextDecoder } from "node:util";
import { fileURLToPath } from "node:url";

const OLLAMA_HOST = "127.0.0.1";
const OLLAMA_PORT = 11_434;
const OLLAMA_MODEL = "qwen3-8b8q-clzh:latest";
const OLLAMA_TAGS_PATH = "/api/tags";
const OLLAMA_SHOW_PATH = "/api/show";
const OLLAMA_CHAT_PATH = "/api/chat";
const OPENAI_PATH = "/v1/chat/completions";
const MAX_REQUEST_BYTES = 2 * 1024 * 1024;
const MAX_UPSTREAM_BYTES = 1024 * 1024;
const MAX_SYSTEM_BYTES = 256 * 1024;
const HEADER_TIMEOUT_MS = 5_000;
const REQUEST_TIMEOUT_MS = 10_000;
const IDLE_TIMEOUT_MS = 30_000;
const UPSTREAM_TIMEOUT_MS = 180_000;
const RESPONSE_PHASE_TIMEOUT_MS = 240_000;
const EXPECTED_TOOL_NAMES = Object.freeze([
  "ops_artifact_catalog",
  "ops_bash",
  "ops_breakglass_prepare",
  "ops_change_status",
  "ops_inspect",
  "ops_machine_describe",
  "ops_machine_list",
  "ops_propose_change",
]);
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
const DIGEST_PATTERN = /^[a-f0-9]{64}$/u;
const SYSTEM_DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const MODEL_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const NONCE_PATTERN = /^[a-z0-9][a-z0-9-]{15,63}$/u;
const IPV4_WILDCARDS = new Set(["0.0.0.0", "255.255.255.255"]);
const SECURITY_HEADERS = Object.freeze([
  "authorization",
  "content-length",
  "content-type",
  "expect",
  "host",
  "proxy-authorization",
  "proxy-connection",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

class BridgeError extends Error {
  constructor(code) {
    super(code);
    this.name = "BridgeError";
    this.code = code;
  }
}

function reject(code) {
  throw new BridgeError(code);
}

function errorCode(error, fallback = "internal_error") {
  return error instanceof BridgeError ? error.code : fallback;
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function requireExactKeys(value, label, required, optional = []) {
  if (!isPlainObject(value)) reject(`${label}_shape`);
  const allowed = new Set([...required, ...optional]);
  const keys = Object.keys(value);
  if (keys.some((key) => !allowed.has(key))
      || required.some((key) => !Object.hasOwn(value, key))) {
    reject(`${label}_fields`);
  }
  return value;
}

function skipWhitespace(scanner) {
  while (/^[\u0009\u000a\u000d\u0020]$/u.test(scanner.text[scanner.offset] ?? "")) {
    scanner.offset += 1;
  }
}

function scanJsonString(scanner) {
  const start = scanner.offset;
  if (scanner.text[scanner.offset] !== "\"") reject("json_string_open");
  scanner.offset += 1;
  while (scanner.offset < scanner.text.length) {
    const character = scanner.text[scanner.offset];
    if (character === "\"") {
      scanner.offset += 1;
      try {
        const value = JSON.parse(scanner.text.slice(start, scanner.offset));
        if (typeof value !== "string") reject("json_string_type");
        return value;
      } catch (error) {
        if (error instanceof BridgeError) throw error;
        reject("json_string_invalid");
      }
    }
    if (character === undefined || character.charCodeAt(0) < 0x20) {
      reject("json_string_control");
    }
    if (character !== "\\") {
      scanner.offset += 1;
      continue;
    }
    scanner.offset += 1;
    const escaped = scanner.text[scanner.offset];
    if (escaped === "u") {
      if (!/^[a-fA-F0-9]{4}$/u.test(scanner.text.slice(scanner.offset + 1, scanner.offset + 5))) {
        reject("json_unicode_escape");
      }
      scanner.offset += 5;
      continue;
    }
    if (escaped === undefined || !/^["\\/bfnrt]$/u.test(escaped)) {
      reject("json_escape");
    }
    scanner.offset += 1;
  }
  reject("json_string_unterminated");
}

function scanJsonNumber(scanner) {
  const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u.exec(
    scanner.text.slice(scanner.offset),
  );
  if (match === null) reject("json_number");
  scanner.offset += match[0].length;
}

function scanJsonValue(scanner, depth) {
  if (depth > 64) reject("json_depth");
  skipWhitespace(scanner);
  const character = scanner.text[scanner.offset];
  if (character === "\"") {
    scanJsonString(scanner);
    return;
  }
  if (character === "{") {
    scanner.offset += 1;
    skipWhitespace(scanner);
    const keys = new Set();
    if (scanner.text[scanner.offset] === "}") {
      scanner.offset += 1;
      return;
    }
    for (;;) {
      skipWhitespace(scanner);
      const key = scanJsonString(scanner);
      if (keys.has(key)) reject("json_duplicate_key");
      keys.add(key);
      skipWhitespace(scanner);
      if (scanner.text[scanner.offset] !== ":") reject("json_object_colon");
      scanner.offset += 1;
      scanJsonValue(scanner, depth + 1);
      skipWhitespace(scanner);
      const separator = scanner.text[scanner.offset];
      if (separator === "}") {
        scanner.offset += 1;
        return;
      }
      if (separator !== ",") reject("json_object_separator");
      scanner.offset += 1;
    }
  }
  if (character === "[") {
    scanner.offset += 1;
    skipWhitespace(scanner);
    if (scanner.text[scanner.offset] === "]") {
      scanner.offset += 1;
      return;
    }
    for (;;) {
      scanJsonValue(scanner, depth + 1);
      skipWhitespace(scanner);
      const separator = scanner.text[scanner.offset];
      if (separator === "]") {
        scanner.offset += 1;
        return;
      }
      if (separator !== ",") reject("json_array_separator");
      scanner.offset += 1;
    }
  }
  for (const literal of ["true", "false", "null"]) {
    if (scanner.text.startsWith(literal, scanner.offset)) {
      scanner.offset += literal.length;
      return;
    }
  }
  scanJsonNumber(scanner);
}

function parseStrictJson(buffer, maximumBytes, codePrefix) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 1 || buffer.length > maximumBytes) {
    reject(`${codePrefix}_size`);
  }
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(buffer);
  } catch {
    reject(`${codePrefix}_utf8`);
  }
  if (text.startsWith("\ufeff")) reject(`${codePrefix}_bom`);
  const scanner = { text, offset: 0 };
  try {
    scanJsonValue(scanner, 0);
    skipWhitespace(scanner);
    if (scanner.offset !== text.length) reject("json_trailing_value");
    return JSON.parse(text);
  } catch (error) {
    if (error instanceof BridgeError) {
      if (error.code.startsWith(`${codePrefix}_`)) throw error;
      reject(`${codePrefix}_${error.code}`);
    }
    reject(`${codePrefix}_invalid_json`);
  }
}

function sha256(value) {
  return `sha256:${createHash("sha256").update(value, "utf8").digest("hex")}`;
}

function exactAuthorizationFromToken(token) {
  if (typeof token !== "string" || !TOKEN_PATTERN.test(token)) reject("token_format");
  const decoded = Buffer.from(token, "base64url");
  if (decoded.length !== 32 || decoded.toString("base64url") !== token) reject("token_canonical");
  decoded.fill(0);
  return Buffer.from(`Bearer ${token}`, "ascii");
}

function readAuthorizationFromFd3() {
  const tokenBytes = Buffer.alloc(44);
  let offset = 0;
  for (;;) {
    let count;
    try {
      count = readSync(3, tokenBytes, offset, tokenBytes.length - offset, null);
    } catch {
      tokenBytes.fill(0);
      reject("token_fd_read");
    }
    if (count === 0) break;
    offset += count;
    if (offset === tokenBytes.length) {
      tokenBytes.fill(0);
      reject("token_fd_oversize");
    }
  }
  if (offset !== 43) {
    tokenBytes.fill(0);
    reject("token_fd_size");
  }
  const token = tokenBytes.subarray(0, offset).toString("ascii");
  tokenBytes.fill(0);
  return exactAuthorizationFromToken(token);
}

function requiredEnvironment(environment, name, pattern) {
  const value = environment[name];
  if (value === undefined || !pattern.test(value)) reject("environment_invalid");
  return value;
}

function requireExactIpv4(value) {
  if (isIP(value) !== 4 || IPV4_WILDCARDS.has(value)) reject("ipv4_invalid");
  return value;
}

function parseCliOptions(environment) {
  const listenHost = requireExactIpv4(requiredEnvironment(
    environment,
    "OPS_E2E_LISTEN_HOST",
    /^[0-9.]{7,15}$/u,
  ));
  const allowedPeer = requireExactIpv4(requiredEnvironment(
    environment,
    "OPS_E2E_ALLOWED_PEER",
    /^[0-9.]{7,15}$/u,
  ));
  const portText = requiredEnvironment(environment, "OPS_E2E_LISTEN_PORT", /^[1-9][0-9]{0,4}$/u);
  const listenPort = Number.parseInt(portText, 10);
  if (listenPort > 65_535) reject("listen_port_invalid");
  return {
    listenHost,
    listenPort,
    allowedPeer,
    expectedAuthorization: readAuthorizationFromFd3(),
    expectedModel: requiredEnvironment(environment, "OPS_E2E_EXPECTED_MODEL", MODEL_PATTERN),
    expectedSystemDigest: requiredEnvironment(
      environment,
      "OPS_E2E_SYSTEM_PROMPT_SHA256",
      SYSTEM_DIGEST_PATTERN,
    ),
    nonce: requiredEnvironment(environment, "OPS_E2E_NONCE", NONCE_PATTERN),
    expectedOllamaDigest: requiredEnvironment(
      environment,
      "OPS_E2E_OLLAMA_DIGEST",
      DIGEST_PATTERN,
    ),
    upstreamPort: OLLAMA_PORT,
    idleTimeoutMs: IDLE_TIMEOUT_MS,
    requestTimeoutMs: REQUEST_TIMEOUT_MS,
    upstreamTimeoutMs: UPSTREAM_TIMEOUT_MS,
    responsePhaseTimeoutMs: RESPONSE_PHASE_TIMEOUT_MS,
    log: writeMetadataLog,
  };
}

function rawHeaderValues(request, expectedName) {
  const values = [];
  for (let index = 0; index < request.rawHeaders.length; index += 2) {
    const name = request.rawHeaders[index];
    const value = request.rawHeaders[index + 1];
    if (typeof name === "string" && name.toLowerCase() === expectedName && typeof value === "string") {
      values.push(value);
    }
  }
  return values;
}

function authorizationMatches(actual, expected) {
  const actualBytes = Buffer.from(actual, "ascii");
  return actualBytes.length === expected.length && timingSafeEqual(actualBytes, expected);
}

function validateInboundHeaders(request, expectedHost, expectedAuthorization) {
  for (const name of SECURITY_HEADERS) {
    const values = rawHeaderValues(request, name);
    if (values.length > 1) reject("request_duplicate_security_header");
  }
  const hostValues = rawHeaderValues(request, "host");
  const authorizationValues = rawHeaderValues(request, "authorization");
  const contentTypeValues = rawHeaderValues(request, "content-type");
  const contentLengthValues = rawHeaderValues(request, "content-length");
  if (hostValues.length !== 1 || hostValues[0] !== expectedHost) reject("request_host");
  if (authorizationValues.length !== 1
      || !authorizationMatches(authorizationValues[0] ?? "", expectedAuthorization)) {
    reject("request_authorization");
  }
  if (contentTypeValues.length !== 1 || contentTypeValues[0] !== "application/json") {
    reject("request_content_type");
  }
  if (contentLengthValues.length !== 1 || !/^(?:0|[1-9][0-9]*)$/u.test(contentLengthValues[0] ?? "")) {
    reject("request_content_length");
  }
  for (const forbidden of [
    "expect",
    "proxy-authorization",
    "proxy-connection",
    "trailer",
    "transfer-encoding",
    "upgrade",
  ]) {
    if (rawHeaderValues(request, forbidden).length !== 0) reject("request_forbidden_header");
  }
  const contentLength = Number.parseInt(contentLengthValues[0] ?? "", 10);
  if (!Number.isSafeInteger(contentLength) || contentLength < 1 || contentLength > MAX_REQUEST_BYTES) {
    reject("request_content_length_bound");
  }
  return contentLength;
}

function readInboundBody(request, expectedLength, timeoutMs) {
  return new Promise((resolveBody, rejectBody) => {
    const chunks = [];
    let received = 0;
    let settled = false;
    const fail = (code) => {
      if (settled) return;
      settled = true;
      rejectBody(new BridgeError(code));
    };
    request.setTimeout(timeoutMs, () => {
      fail("request_body_timeout");
      request.destroy();
    });
    request.on("aborted", () => fail("request_body_aborted"));
    request.on("error", () => fail("request_body_error"));
    request.on("data", (chunk) => {
      if (settled) return;
      if (!Buffer.isBuffer(chunk)) {
        fail("request_body_chunk");
        request.destroy();
        return;
      }
      received += chunk.length;
      if (received > expectedLength || received > MAX_REQUEST_BYTES) {
        fail("request_body_oversize");
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => {
      if (settled) return;
      if (received !== expectedLength || !request.complete) {
        fail("request_body_length_mismatch");
        return;
      }
      settled = true;
      resolveBody(Buffer.concat(chunks, received));
    });
  });
}

function validateMessages(messages, expectedSystemDigest, nonce) {
  if (!Array.isArray(messages) || messages.length !== 2) reject("request_messages_count");
  const system = requireExactKeys(messages[0], "request_system_message", ["role", "content"]);
  const user = requireExactKeys(messages[1], "request_user_message", ["role", "content"]);
  if (system.role !== "system" || typeof system.content !== "string"
      || Buffer.byteLength(system.content, "utf8") < 1
      || Buffer.byteLength(system.content, "utf8") > MAX_SYSTEM_BYTES
      || sha256(system.content) !== expectedSystemDigest) {
    reject("request_system_message_binding");
  }
  const expectedUser = `Reply with exactly LOCAL_MODEL_E2E_OK_${nonce} and nothing else. Do not call tools.`;
  if (user.role !== "user" || user.content !== expectedUser) reject("request_user_message_binding");
  return [
    { role: "system", content: system.content },
    { role: "user", content: user.content },
  ];
}

function validateTools(tools) {
  if (!Array.isArray(tools) || tools.length !== EXPECTED_TOOL_NAMES.length) {
    reject("request_tools_count");
  }
  const names = [];
  for (const [index, rawTool] of tools.entries()) {
    const tool = requireExactKeys(rawTool, "request_tool", ["type", "function"]);
    if (tool.type !== "function") reject("request_tool_type");
    const functionSpec = requireExactKeys(
      tool.function,
      "request_tool_function",
      ["name", "description", "parameters"],
      ["strict"],
    );
    if (typeof functionSpec.name !== "string"
        || typeof functionSpec.description !== "string"
        || functionSpec.description.length < 1
        || functionSpec.description.length > 4096
        || !isPlainObject(functionSpec.parameters)
        || (Object.hasOwn(functionSpec, "strict") && functionSpec.strict !== false)) {
      reject("request_tool_function_shape");
    }
    names.push(functionSpec.name);
    if (index > 0 && names[index - 1] >= functionSpec.name) reject("request_tool_order");
  }
  if (names.some((name, index) => name !== EXPECTED_TOOL_NAMES[index])) {
    reject("request_tool_names");
  }
}

function validateOpenAiRequest(value, options) {
  const input = requireExactKeys(
    value,
    "request_body",
    ["model", "messages", "stream", "max_tokens", "tools"],
  );
  if (input.model !== options.expectedModel || input.stream !== true || input.max_tokens !== 64) {
    reject("request_model_contract");
  }
  const messages = validateMessages(input.messages, options.expectedSystemDigest, options.nonce);
  validateTools(input.tools);
  return messages;
}

function requestOllamaJson({ method, path, body, upstreamPort, timeoutMs, signal }) {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > RESPONSE_PHASE_TIMEOUT_MS) {
    return Promise.reject(new BridgeError("upstream_timeout_bound"));
  }
  const deadlineAt = performance.now() + timeoutMs;
  return new Promise((resolveJson, rejectJson) => {
    let request;
    let response;
    let deadlineTimer;
    let settled = false;
    let abortListener;
    const cleanup = () => {
      if (deadlineTimer !== undefined) clearTimeout(deadlineTimer);
      if (abortListener !== undefined) signal?.removeEventListener("abort", abortListener);
    };
    const destroyTransport = () => {
      if (response !== undefined && !response.destroyed) response.destroy();
      if (request !== undefined && !request.destroyed) request.destroy();
    };
    const fail = (error) => {
      if (settled) return;
      settled = true;
      cleanup();
      destroyTransport();
      rejectJson(error instanceof BridgeError ? error : new BridgeError("upstream_connection"));
    };
    const succeed = (value) => {
      if (settled) return;
      settled = true;
      cleanup();
      destroyTransport();
      resolveJson(value);
    };
    const armAbsoluteDeadline = () => {
      const remaining = deadlineAt - performance.now();
      if (remaining <= 0) {
        fail(new BridgeError("upstream_timeout"));
        return;
      }
      deadlineTimer = setTimeout(() => {
        if (performance.now() >= deadlineAt) fail(new BridgeError("upstream_timeout"));
        else armAbsoluteDeadline();
      }, Math.max(1, Math.ceil(remaining)));
    };
    if (signal?.aborted === true) {
      rejectJson(new BridgeError("response_phase_timeout"));
      return;
    }
    abortListener = () => fail(new BridgeError("response_phase_timeout"));
    signal?.addEventListener("abort", abortListener, { once: true });
    if (signal?.aborted === true) {
      abortListener();
      return;
    }
    const encoded = body === undefined ? undefined : Buffer.from(JSON.stringify(body), "utf8");
    const headers = {
      accept: "application/json",
      connection: "close",
      host: `${OLLAMA_HOST}:${upstreamPort}`,
      ...(encoded === undefined ? {} : {
        "content-type": "application/json",
        "content-length": String(encoded.length),
      }),
    };
    try {
      request = httpRequest({
        host: OLLAMA_HOST,
        port: upstreamPort,
        method,
        path,
        headers,
        agent: false,
      }, (incomingResponse) => {
        response = incomingResponse;
        if (settled) {
          incomingResponse.destroy();
          return;
        }
        if (performance.now() >= deadlineAt) {
          fail(new BridgeError("upstream_timeout"));
          return;
        }
        const contentType = incomingResponse.headers["content-type"];
        if (incomingResponse.statusCode !== 200
            || typeof contentType !== "string"
            || !/^application\/json(?:;\s*charset=utf-8)?$/iu.test(contentType)
            || (incomingResponse.headers["content-encoding"] !== undefined
              && incomingResponse.headers["content-encoding"] !== "identity")) {
          fail(new BridgeError("upstream_http_contract"));
          return;
        }
        const chunks = [];
        let received = 0;
        incomingResponse.on("data", (chunk) => {
          if (settled) return;
          if (performance.now() >= deadlineAt) {
            fail(new BridgeError("upstream_timeout"));
            return;
          }
          if (!Buffer.isBuffer(chunk)) {
            fail(new BridgeError("upstream_body_chunk"));
            return;
          }
          received += chunk.length;
          if (received > MAX_UPSTREAM_BYTES) {
            fail(new BridgeError("upstream_body_oversize"));
            return;
          }
          chunks.push(chunk);
        });
        incomingResponse.on("aborted", () => fail(new BridgeError("upstream_body_aborted")));
        incomingResponse.on("error", () => fail(new BridgeError("upstream_body_error")));
        incomingResponse.on("end", () => {
          if (settled) return;
          if (performance.now() >= deadlineAt) {
            fail(new BridgeError("upstream_timeout"));
            return;
          }
          const responseBody = Buffer.concat(chunks, received);
          let value;
          try {
            value = parseStrictJson(responseBody, MAX_UPSTREAM_BYTES, "upstream_json");
          } catch (error) {
            fail(error);
            return;
          }
          if (performance.now() >= deadlineAt) {
            fail(new BridgeError("upstream_timeout"));
            return;
          }
          succeed(value);
        });
      });
      request.on("error", (error) => fail(error));
      armAbsoluteDeadline();
      if (encoded !== undefined) request.write(encoded);
      request.end();
    } catch (error) {
      fail(error);
    }
  });
}

async function verifyOllamaModel(options, signal) {
  const tagsValue = await requestOllamaJson({
    method: "GET",
    path: OLLAMA_TAGS_PATH,
    upstreamPort: options.upstreamPort,
    timeoutMs: options.upstreamTimeoutMs,
    signal,
  });
  const tags = requireExactKeys(tagsValue, "ollama_tags", ["models"]);
  if (!Array.isArray(tags.models) || tags.models.length < 1 || tags.models.length > 128) {
    reject("ollama_tags_models");
  }
  const matches = tags.models.filter((value) =>
    isPlainObject(value) && value.name === OLLAMA_MODEL && value.model === OLLAMA_MODEL);
  if (matches.length !== 1 || matches[0].digest !== options.expectedOllamaDigest) {
    reject("ollama_model_digest");
  }
  const showValue = await requestOllamaJson({
    method: "POST",
    path: OLLAMA_SHOW_PATH,
    body: { model: OLLAMA_MODEL },
    upstreamPort: options.upstreamPort,
    timeoutMs: options.upstreamTimeoutMs,
    signal,
  });
  if (!isPlainObject(showValue) || !Array.isArray(showValue.capabilities)
      || showValue.capabilities.length !== 1 || showValue.capabilities[0] !== "completion") {
    reject("ollama_model_capabilities");
  }
  return Object.freeze({ digest: options.expectedOllamaDigest, capabilities: "completion" });
}

function requireBoundedInteger(value, label, maximum) {
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum) reject(label);
  return value;
}

function validateOllamaChat(value, nonce) {
  const response = requireExactKeys(value, "ollama_chat", [
    "model",
    "created_at",
    "message",
    "done",
    "done_reason",
    "total_duration",
    "load_duration",
    "prompt_eval_count",
    "prompt_eval_duration",
    "eval_count",
    "eval_duration",
  ]);
  const message = requireExactKeys(response.message, "ollama_chat_message", ["role", "content"]);
  const expectedOutput = `LOCAL_MODEL_E2E_OK_${nonce}`;
  if (response.model !== OLLAMA_MODEL
      || typeof response.created_at !== "string" || response.created_at.length > 64
      || response.done !== true || response.done_reason !== "stop"
      || message.role !== "assistant" || message.content !== expectedOutput) {
    reject("ollama_chat_contract");
  }
  requireBoundedInteger(response.total_duration, "ollama_total_duration", Number.MAX_SAFE_INTEGER);
  requireBoundedInteger(response.load_duration, "ollama_load_duration", Number.MAX_SAFE_INTEGER);
  requireBoundedInteger(response.prompt_eval_count, "ollama_prompt_eval_count", 1_000_000);
  requireBoundedInteger(response.prompt_eval_duration, "ollama_prompt_eval_duration", Number.MAX_SAFE_INTEGER);
  requireBoundedInteger(response.eval_count, "ollama_eval_count", 64);
  requireBoundedInteger(response.eval_duration, "ollama_eval_duration", Number.MAX_SAFE_INTEGER);
  return expectedOutput;
}

async function runInference(messages, options, signal) {
  const value = await requestOllamaJson({
    method: "POST",
    path: OLLAMA_CHAT_PATH,
    body: {
      model: OLLAMA_MODEL,
      messages,
      stream: false,
      think: false,
      options: { temperature: 0, num_predict: 64 },
    },
    upstreamPort: options.upstreamPort,
    timeoutMs: options.upstreamTimeoutMs,
    signal,
  });
  return validateOllamaChat(value, options.nonce);
}

function endJson(response, statusCode) {
  const body = Buffer.from('{"error":"request rejected"}\n', "utf8");
  response.writeHead(statusCode, {
    "content-type": "application/json",
    "content-length": String(body.length),
    connection: "close",
  });
  response.end(body);
}

function endSse(response, expectedModel, content) {
  const chunk = {
    id: "chatcmpl-local-model-e2e",
    object: "chat.completion.chunk",
    created: 1,
    model: expectedModel,
    choices: [{
      index: 0,
      delta: { role: "assistant", content },
      finish_reason: "stop",
    }],
  };
  const body = Buffer.from(`data: ${JSON.stringify(chunk)}\n\ndata: [DONE]\n\n`, "utf8");
  response.writeHead(200, {
    "content-type": "text/event-stream; charset=utf-8",
    "content-length": String(body.length),
    "cache-control": "no-cache",
    connection: "close",
  });
  response.end(body);
}

function writeMetadataLog(event, fields = {}) {
  process.stdout.write(`${JSON.stringify({ event, ...fields })}\n`);
}

function rejectionStatus(code) {
  if (code === "request_authorization") return 401;
  if (code === "response_phase_timeout") return 504;
  if (code.startsWith("request_")) return 400;
  if (code.startsWith("ollama_") || code.startsWith("upstream_")) return 502;
  return 500;
}

async function runBoundedResponsePhase(encoded, response, options) {
  const deadlineAt = performance.now() + options.responsePhaseTimeoutMs;
  const controller = new AbortController();
  let deadlineTimer;
  let expired = false;
  const expire = () => {
    if (expired) return;
    expired = true;
    controller.abort();
    if (!response.destroyed) response.destroy();
  };
  const armAbsoluteDeadline = () => {
    const remaining = deadlineAt - performance.now();
    if (remaining <= 0) {
      expire();
      return;
    }
    deadlineTimer = setTimeout(() => {
      if (performance.now() >= deadlineAt) expire();
      else armAbsoluteDeadline();
    }, Math.max(1, Math.ceil(remaining)));
  };
  armAbsoluteDeadline();
  try {
    const input = parseStrictJson(encoded, MAX_REQUEST_BYTES, "request_json");
    const messages = validateOpenAiRequest(input, options);
    const output = await runInference(messages, options, controller.signal);
    await verifyOllamaModel(options, controller.signal);
    if (expired || performance.now() >= deadlineAt || response.destroyed) {
      reject("response_phase_timeout");
    }
    endSse(response, options.expectedModel, output);
  } finally {
    if (deadlineTimer !== undefined) clearTimeout(deadlineTimer);
  }
}

async function processInboundRequest(request, response, options, expectedHost) {
  try {
    if (request.socket.remoteAddress !== options.allowedPeer
        || request.method !== "POST" || request.url !== OPENAI_PATH
        || request.httpVersion !== "1.1") {
      reject("request_line_contract");
    }
    const contentLength = validateInboundHeaders(
      request,
      expectedHost,
      options.expectedAuthorization,
    );
    const encoded = await readInboundBody(request, contentLength, options.requestTimeoutMs);
    request.setTimeout(0);
    request.socket.setTimeout(0);
    await runBoundedResponsePhase(encoded, response, options);
    return { ok: true, code: "completed" };
  } catch (error) {
    const code = errorCode(error);
    if (!response.headersSent && !response.destroyed) {
      endJson(response, rejectionStatus(code));
    } else if (!response.destroyed) {
      response.destroy();
    }
    return { ok: false, code };
  }
}

async function startBridge(options) {
  if (!Number.isSafeInteger(options.requestTimeoutMs) || options.requestTimeoutMs < 1
      || options.requestTimeoutMs > REQUEST_TIMEOUT_MS
      || !Number.isSafeInteger(options.responsePhaseTimeoutMs)
      || options.responsePhaseTimeoutMs < 1
      || options.responsePhaseTimeoutMs > RESPONSE_PHASE_TIMEOUT_MS) {
    reject("phase_timeout_bound");
  }
  await verifyOllamaModel(options);
  let finishCompletion;
  const completion = new Promise((resolveCompletion) => {
    finishCompletion = resolveCompletion;
  });
  let consumed = false;
  let finished = false;
  let idleTimer;
  const finish = (result) => {
    if (finished) return;
    finished = true;
    if (idleTimer !== undefined) clearTimeout(idleTimer);
    finishCompletion(result);
  };
  const server = createServer((request, response) => {
    if (consumed) {
      request.destroy();
      return;
    }
    consumed = true;
    if (idleTimer !== undefined) clearTimeout(idleTimer);
    const address = server.address();
    const port = isPlainObject(address) ? address.port : options.listenPort;
    const expectedHost = `${options.listenHost}:${port}`;
    server.close();
    void processInboundRequest(request, response, options, expectedHost).then((result) => {
      options.log("request_finished", { ok: result.ok, code: result.code });
      finish(result);
    }, () => {
      if (!response.destroyed) response.destroy();
      finish({ ok: false, code: "request_internal_error" });
    });
  });
  server.maxConnections = 1;
  server.maxRequestsPerSocket = 1;
  server.headersTimeout = Math.min(HEADER_TIMEOUT_MS, options.requestTimeoutMs);
  server.requestTimeout = options.requestTimeoutMs;
  server.keepAliveTimeout = 1_000;
  server.on("connection", (socket) => {
    socket.setTimeout(options.requestTimeoutMs, () => socket.destroy());
    if (consumed || socket.remoteAddress !== options.allowedPeer) {
      consumed = true;
      server.close();
      socket.destroy();
      finish({ ok: false, code: "peer_rejected" });
    }
  });
  server.on("clientError", (_error, socket) => {
    consumed = true;
    server.close();
    socket.destroy();
    finish({ ok: false, code: "malformed_http" });
  });
  server.on("error", () => finish({ ok: false, code: "listener_error" }));
  await new Promise((resolveListen, rejectListen) => {
    const onError = () => rejectListen(new BridgeError("listener_start"));
    server.once("error", onError);
    server.listen(options.listenPort, options.listenHost, () => {
      server.off("error", onError);
      resolveListen();
    });
  });
  const address = server.address();
  if (!isPlainObject(address) || address.address !== options.listenHost
      || typeof address.port !== "number") {
    server.close();
    reject("listener_binding");
  }
  idleTimer = setTimeout(() => {
    consumed = true;
    server.close();
    finish({ ok: false, code: "idle_timeout" });
  }, options.idleTimeoutMs);
  idleTimer.unref();
  return {
    host: address.address,
    port: address.port,
    completion,
    close: async () => {
      if (idleTimer !== undefined) clearTimeout(idleTimer);
      await new Promise((resolveClose) => {
        if (!server.listening) {
          resolveClose();
          return;
        }
        server.close(() => resolveClose());
      });
      finish({ ok: false, code: "closed" });
    },
  };
}

export async function startBridgeForTest(options) {
  return await startBridge({
    listenHost: options.listenHost,
    listenPort: options.listenPort,
    allowedPeer: options.allowedPeer,
    expectedAuthorization: exactAuthorizationFromToken(options.token),
    expectedModel: options.expectedModel,
    expectedSystemDigest: options.expectedSystemDigest,
    nonce: options.nonce,
    expectedOllamaDigest: options.expectedOllamaDigest,
    upstreamPort: options.upstreamPort,
    idleTimeoutMs: options.idleTimeoutMs ?? IDLE_TIMEOUT_MS,
    requestTimeoutMs: options.requestTimeoutMs ?? REQUEST_TIMEOUT_MS,
    upstreamTimeoutMs: options.upstreamTimeoutMs ?? UPSTREAM_TIMEOUT_MS,
    responsePhaseTimeoutMs: options.responsePhaseTimeoutMs ?? RESPONSE_PHASE_TIMEOUT_MS,
    log: () => {},
  });
}

async function main() {
  let authorization;
  try {
    if (process.argv.length !== 2) reject("argv_forbidden");
    const options = parseCliOptions(process.env);
    authorization = options.expectedAuthorization;
    const handle = await startBridge(options);
    options.log("ready", {
      host: handle.host,
      port: handle.port,
      upstream: `${OLLAMA_HOST}:${OLLAMA_PORT}`,
      ollamaModel: OLLAMA_MODEL,
    });
    const result = await handle.completion;
    options.log("exit", { ok: result.ok, code: result.code });
    if (!result.ok) process.exitCode = 1;
  } catch (error) {
    writeMetadataLog("fatal", { ok: false, code: errorCode(error, "startup_error") });
    process.exitCode = 1;
  } finally {
    authorization?.fill(0);
  }
}

const invokedPath = process.argv[1] === undefined ? undefined : resolve(process.argv[1]);
if (invokedPath !== undefined && fileURLToPath(import.meta.url) === invokedPath) {
  await main();
}
