#!/usr/bin/env node

import { createServer } from "node:http";

const MAX_BODY_BYTES = 2 * 1024 * 1024;
const TOKEN = "fixture-only-not-a-secret-0001";
const MODEL = "fixture-model";
const SCENARIOS = new Set(["sandbox", "inspect", "prepare-package", "prepare-file"]);
const PENDING_CHANGE_INSTRUCTION =
  "This change is pending model-external local review and exact client approval.";

function fail(message) {
  process.stderr.write(`mock-openai: ${message}\n`);
  process.exit(1);
}

function requiredEnvironment(name, pattern) {
  const value = process.env[name];
  if (value === undefined || !pattern.test(value)) fail(`${name} is missing or invalid`);
  return value;
}

const scenario = requiredEnvironment("MOCK_SCENARIO", /^[a-z-]{1,32}$/u);
if (!SCENARIOS.has(scenario)) fail("MOCK_SCENARIO is unsupported");
const port = Number.parseInt(requiredEnvironment("MOCK_PORT", /^[1-9][0-9]{3,4}$/u), 10);
if (port > 65_535) fail("MOCK_PORT is out of range");
const machineId = scenario === "sandbox"
  ? undefined
  : requiredEnvironment("MOCK_MACHINE_ID", /^[a-zA-Z0-9][a-zA-Z0-9._:-]{6,158}[a-zA-Z0-9]$/u);
const targetId = scenario === "sandbox"
  ? undefined
  : requiredEnvironment("MOCK_TARGET_ID", /^[a-zA-Z0-9][a-zA-Z0-9._:-]{6,158}[a-zA-Z0-9]$/u);
const nonce = requiredEnvironment("MOCK_NONCE", /^[a-z0-9][a-z0-9-]{7,63}$/u);

const scenarioTool = Object.freeze({
  sandbox: "ops_bash",
  inspect: "ops_inspect",
  "prepare-package": "ops_propose_change",
  "prepare-file": "ops_propose_change",
}[scenario]);

const sandboxCommand = String.raw`set -eu
test "$$" -eq 1
test -w /workspace
test ! -w /usr
cap_eff=
while read -r field value _; do
  if test "$field" = "CapEff:"; then cap_eff=$value; break; fi
done < /proc/self/status
test "$cap_eff" = 0000000000000000
test "$(/usr/bin/readlink /proc/1/ns/pid)" = "$(/usr/bin/readlink /proc/self/ns/pid)"
if /usr/bin/timeout 2 /bin/bash -c 'exec 3<>/dev/tcp/127.0.0.1/7443' 2>/dev/null; then exit 91; fi
printf '%s\n' '${nonce}' > /workspace/model-source-e2e.txt
printf 'MODEL_E2E_SANDBOX_OK nonce=%s pid=%s cap=%s usr_readonly=yes loopback_blocked=yes\n' '${nonce}' "$$" "$cap_eff"`;

function toolArguments() {
  switch (scenario) {
    case "sandbox":
      return { command: sandboxCommand, timeoutSeconds: 15 };
    case "inspect":
      return { machineId, targetId, operation: "host_snapshot" };
    case "prepare-package":
      return {
        machineId,
        targetId,
        operation: { kind: "package.install", package: "ops-agent-e2e-never-install" },
      };
    case "prepare-file":
      return {
        machineId,
        targetId,
        operation: {
          kind: "file.write",
          path: "/etc/ops-agent-e2e/model-approved.txt",
          content: `ops-agent scripted-model approval e2e ${nonce}\n`,
          mode: "0644",
        },
      };
    default:
      throw new Error("unreachable scenario");
  }
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function sendJson(response, status, value) {
  const body = `${JSON.stringify(value)}\n`;
  response.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(body),
    connection: "close",
  });
  response.end(body);
}

function writeSse(response, chunks) {
  response.writeHead(200, {
    "content-type": "text/event-stream; charset=utf-8",
    "cache-control": "no-cache",
    connection: "close",
  });
  for (const chunk of chunks) response.write(`data: ${JSON.stringify(chunk)}\n\n`);
  response.end("data: [DONE]\n\n");
}

function chunk(id, delta, finishReason) {
  return {
    id,
    object: "chat.completion.chunk",
    created: 1,
    model: MODEL,
    choices: [{ index: 0, delta, finish_reason: finishReason }],
  };
}

function toolResultText(body) {
  const toolMessage = body.messages.findLast?.((message) => message?.role === "tool")
    ?? [...body.messages].reverse().find((message) => message?.role === "tool");
  if (!isPlainObject(toolMessage) || toolMessage.tool_call_id !== "call_ops_agent_e2e_1"
      || typeof toolMessage.content !== "string" || toolMessage.content.length > 256 * 1024) {
    throw new Error("second request is missing the exact bounded tool result");
  }
  const assistant = [...body.messages].reverse().find((message) =>
    message?.role === "assistant" && Array.isArray(message.tool_calls));
  const replay = assistant?.tool_calls?.find((call) => call?.id === "call_ops_agent_e2e_1");
  if (replay?.type !== "function" || replay.function?.name !== scenarioTool
      || replay.function.arguments !== JSON.stringify(toolArguments())) {
    throw new Error("second request did not replay the exact assistant tool call");
  }
  return toolMessage.content;
}

function validateToolResult(text) {
  switch (scenario) {
    case "sandbox":
      if (!text.includes(`MODEL_E2E_SANDBOX_OK nonce=${nonce} pid=1`)
          || !text.includes("cap=0000000000000000")
          || !text.includes("usr_readonly=yes loopback_blocked=yes")) {
        throw new Error("sandbox tool result omitted a required containment marker");
      }
      break;
    case "inspect":
      if (!text.includes('"uptime"') || !text.includes('"df"') || !text.includes('"free"')) {
        throw new Error("inspect tool result omitted the required host snapshot fields");
      }
      break;
    case "prepare-package":
    case "prepare-file":
      if (!text.includes("changeRef=opschg1_")
          || text.split("\n").filter((line) => line === PENDING_CHANGE_INSTRUCTION).length !== 1) {
        throw new Error("prepare tool result omitted the signed pending-approval evidence");
      }
      break;
    default:
      throw new Error("unreachable scenario");
  }
}

function preparedChangeRef(text) {
  if (scenario !== "prepare-package" && scenario !== "prepare-file") return undefined;
  const matches = text.split("\n")
    .filter((line) => line.startsWith("changeRef="))
    .map((line) => line.slice("changeRef=".length));
  if (matches.length !== 1 || matches[0].length < 24 || matches[0].length > 1024
      || !/^opschg1_[A-Za-z0-9_-]+$/u.test(matches[0])) {
    throw new Error("prepare tool result did not contain one bounded canonical changeRef");
  }
  const changeRef = matches[0];
  let decoded;
  try {
    decoded = JSON.parse(Buffer.from(changeRef.slice("opschg1_".length), "base64url").toString("utf8"));
  } catch {
    throw new Error("prepare tool result changeRef was not base64url JSON");
  }
  const keys = ["version", "serverId", "machineId", "targetId", "changeId"];
  if (!isPlainObject(decoded) || Object.keys(decoded).length !== keys.length
      || !keys.every((key) => Object.hasOwn(decoded, key)) || decoded.version !== 1) {
    throw new Error("prepare tool result changeRef payload was not an exact v1 record");
  }
  const identifier = /^[a-zA-Z0-9](?:[a-zA-Z0-9._:-]{6,158}[a-zA-Z0-9])?$/u;
  const changeIdentifier = /^[a-zA-Z0-9](?:[a-zA-Z0-9._-]{6,158}[a-zA-Z0-9])?$/u;
  const validIdentifier = (value, pattern) => typeof value === "string"
    && value.length >= 8 && value.length <= 160 && pattern.test(value);
  if (!validIdentifier(decoded.serverId, identifier)
      || !validIdentifier(decoded.machineId, identifier)
      || !validIdentifier(decoded.targetId, identifier)
      || !validIdentifier(decoded.changeId, changeIdentifier)) {
    throw new Error("prepare tool result changeRef contained an invalid identifier");
  }
  const canonicalPayload = JSON.stringify({
    version: 1,
    serverId: decoded.serverId,
    machineId: decoded.machineId,
    targetId: decoded.targetId,
    changeId: decoded.changeId,
  });
  if (`opschg1_${Buffer.from(canonicalPayload).toString("base64url")}` !== changeRef) {
    throw new Error("prepare tool result changeRef was not canonically encoded");
  }
  return changeRef;
}

let requestCount = 0;
let terminalFailure;
const server = createServer((request, response) => {
  const reject = (status, message) => {
    terminalFailure = message;
    sendJson(response, status, { error: { message } });
    setImmediate(() => server.close());
  };
  try {
    if (request.method !== "POST" || request.url !== "/v1/chat/completions") {
      reject(404, "unexpected request path or method");
      return;
    }
    if (request.headers.authorization !== `Bearer ${TOKEN}`) {
      reject(401, "authorization did not match the local fixture token");
      return;
    }
    const contentLength = Number.parseInt(request.headers["content-length"] ?? "", 10);
    if (!Number.isSafeInteger(contentLength) || contentLength < 2 || contentLength > MAX_BODY_BYTES) {
      reject(413, "request body length is missing or out of range");
      return;
    }
    const chunks = [];
    let bytes = 0;
    request.on("data", (data) => {
      bytes += data.length;
      if (bytes > MAX_BODY_BYTES) request.destroy(new Error("request body exceeded the limit"));
      else chunks.push(data);
    });
    request.on("error", () => {
      terminalFailure = "request stream failed";
      server.close();
    });
    request.on("end", () => {
      try {
        const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        if (!isPlainObject(body) || body.model !== MODEL || body.stream !== true
            || !Array.isArray(body.messages) || body.messages.length < 1 || body.messages.length > 64
            || !Array.isArray(body.tools) || body.tools.length < 1 || body.tools.length > 64) {
          throw new Error("request has an invalid model/messages/tools envelope");
        }
        const availableTool = body.tools.find((tool) =>
          tool?.type === "function" && tool.function?.name === scenarioTool);
        if (!isPlainObject(availableTool?.function?.parameters)) {
          throw new Error(`request did not expose ${scenarioTool} with a schema`);
        }
        requestCount += 1;
        process.stdout.write(`MOCK_REQUEST_OK scenario=${scenario} sequence=${requestCount}\n`);
        if (requestCount === 1) {
          writeSse(response, [
            chunk("chatcmpl-ops-agent-e2e-1", {
              role: "assistant",
              tool_calls: [{
                index: 0,
                id: "call_ops_agent_e2e_1",
                type: "function",
                function: { name: scenarioTool, arguments: JSON.stringify(toolArguments()) },
              }],
            }, null),
            chunk("chatcmpl-ops-agent-e2e-1", {}, "tool_calls"),
          ]);
          return;
        }
        if (requestCount === 2) {
          const resultText = toolResultText(body);
          validateToolResult(resultText);
          const changeRef = preparedChangeRef(resultText);
          process.stdout.write(`MOCK_TOOL_RESULT_OK scenario=${scenario}\n`);
          writeSse(response, [
            chunk("chatcmpl-ops-agent-e2e-2", {
              role: "assistant",
              content: `SCRIPTED_MODEL_E2E_${scenario.toUpperCase().replaceAll("-", "_")}_OK nonce=${nonce}${changeRef === undefined ? "" : ` changeRef=${changeRef}`}`,
            }, null),
            chunk("chatcmpl-ops-agent-e2e-2", {}, "stop"),
          ]);
          setImmediate(() => server.close());
          return;
        }
        throw new Error("mock received more than two inference requests");
      } catch (error) {
        reject(400, error instanceof Error ? error.message : "invalid request");
      }
    });
  } catch (error) {
    reject(500, error instanceof Error ? error.message : "unexpected mock error");
  }
});

server.on("error", (error) => fail(`server failed: ${error.message}`));
server.on("close", () => {
  if (terminalFailure !== undefined) fail(terminalFailure);
  if (requestCount !== 2) fail(`expected exactly two requests, received ${requestCount}`);
  process.stdout.write(`MOCK_COMPLETE scenario=${scenario} requests=2 nonce=${nonce}\n`);
});
server.listen(port, "127.0.0.1", () => {
  process.stdout.write(`MOCK_READY scenario=${scenario} address=127.0.0.1 port=${port} nonce=${nonce}\n`);
});
