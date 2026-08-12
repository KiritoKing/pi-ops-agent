#!/usr/bin/env node

import { createServer } from "node:http";

const MAX_BODY_BYTES = 2 * 1024 * 1024;
const TOKEN = "fixture-only-not-a-secret-0001";
const MODEL = "fixture-model";
const SCENARIOS = new Set([
  "sandbox",
  "inspect",
  "prepare-package",
  "prepare-file",
  "plugin-register-pve",
  "pve-inspect",
  "pve-start",
]);
const PENDING_CHANGE_INSTRUCTION =
  "This change is pending model-external local review and exact client approval.";
const PVE_NON_APPROVAL_INSTRUCTIONS = new Map([
  [
    "The broker committed this change under an explicit standing grant; its signed terminal status was verified.",
    "COMMITTED",
  ],
  [
    "The signed broker state is EXECUTING; no new approval action is currently available.",
    "EXECUTING",
  ],
  [
    "The signed broker state is VERIFYING; no new approval action is currently available.",
    "VERIFYING",
  ],
]);
const PVE_STATUS_STATES = new Set(["EXECUTING", "VERIFYING", "COMMITTED"]);
const PVE_STATUS_RANK = Object.freeze({ EXECUTING: 1, VERIFYING: 2, COMMITTED: 3 });
const MAX_PVE_STATUS_POLLS = 10;
const PVE_STATUS_POLL_DELAY_MS = 1_100;
const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const PVE_CHANGE_ID_PATTERN = /^pve-change-[a-f0-9]{32}$/u;
const PVE_PLUGIN_CAPABILITIES = Object.freeze([
  "pve.backup",
  "pve.cluster.inspect",
  "pve.guest.inspect",
  "pve.guest.lifecycle",
  "pve.guest.migrate",
  "pve.guest.restore",
  "pve.node.inspect",
  "pve.snapshot.manage",
  "pve.storage.inspect",
  "pve.task.inspect",
]);
const PVE_PLUGIN_REQUESTED_SCOPES = Object.freeze([
  "pve.backup.prepare",
  "pve.cluster.read",
  "pve.guest.lifecycle",
  "pve.guest.migrate",
  "pve.guest.read",
  "pve.guest.restore",
  "pve.node.read",
  "pve.snapshot.manage",
  "pve.storage.read",
  "pve.task.read",
]);
const PVE_STATUS_DATA_KEYS = new Set([
  "serverId",
  "machineId",
  "targetId",
  "policyRevision",
  "capabilityRevision",
  "planHash",
  "kind",
  "backupRefs",
  "verification",
  "rollbackAvailable",
  "rollbackUnavailableReason",
  "authorizationBasis",
  "authorizationScope",
  "authorizedAt",
  "lastError",
  "recoveryOfChangeId",
  "resolution",
  "pveMutationVersion",
  "mutationDisposition",
  "recoveryOnly",
  "recoveryDescriptor",
  "plan",
]);
const PVE_STATUS_REQUIRED_DATA_KEYS = Object.freeze([
  "serverId",
  "machineId",
  "targetId",
  "policyRevision",
  "capabilityRevision",
  "planHash",
  "kind",
  "backupRefs",
  "verification",
  "rollbackAvailable",
  "authorizationBasis",
  "authorizationScope",
  "authorizedAt",
  "recoveryOnly",
]);
const PVE_RECEIPT_KEYS = Object.freeze([
  "version",
  "keyId",
  "domain",
  "requestId",
  "method",
  "action",
  "serverId",
  "machineId",
  "targetId",
  "changeId",
  "planHash",
  "state",
  "auditId",
  "resultDigest",
  "issuedAt",
  "signature",
]);

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
const serverId = scenario.startsWith("pve-") || scenario === "plugin-register-pve"
  ? requiredEnvironment("MOCK_SERVER_ID", /^[a-zA-Z0-9][a-zA-Z0-9._:-]{6,158}[a-zA-Z0-9]$/u)
  : undefined;
const pvePolicyRevision = scenario === "pve-start"
  ? requiredEnvironment("MOCK_PVE_POLICY_REVISION", /^policy-[a-zA-Z0-9][a-zA-Z0-9._:-]{6,152}[a-zA-Z0-9]$/u)
  : undefined;
const pvePluginSourceDigest = scenario === "plugin-register-pve"
  ? requiredEnvironment("MOCK_PVE_PLUGIN_SOURCE_DIGEST", SHA256_PATTERN)
  : undefined;
const nonce = requiredEnvironment("MOCK_NONCE", /^[a-z0-9][a-z0-9-]{7,63}$/u);

const scenarioTool = Object.freeze({
  sandbox: "ops_bash",
  inspect: "ops_inspect",
  "prepare-package": "ops_propose_change",
  "prepare-file": "ops_propose_change",
  "plugin-register-pve": "ops_propose_change",
  "pve-inspect": "ops_pve_guest_inspect",
  "pve-start": "ops_pve_guest_lifecycle_prepare",
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
    case "plugin-register-pve":
      return {
        machineId,
        targetId,
        operation: {
          kind: "plugin.register",
          pluginId: "workload.pve",
          pluginKind: "workload",
          version: "0.3.0",
          publisher: "KiritoKing/pi-ops-agent",
          digest: pvePluginSourceDigest,
          capabilities: PVE_PLUGIN_CAPABILITIES,
          requestedScopes: PVE_PLUGIN_REQUESTED_SCOPES,
        },
      };
    case "pve-inspect":
      return {
        machineId,
        targetId,
        node: "pve-e2e",
        guestType: "qemu",
        vmid: 100,
      };
    case "pve-start":
      return {
        machineId,
        targetId,
        node: "pve-e2e",
        guestType: "qemu",
        vmid: 100,
        action: "start",
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

function requireExactKeys(value, label, allowedKeys, requiredKeys = allowedKeys) {
  if (!isPlainObject(value)) throw new Error(`${label} is not a plain object`);
  const keys = Object.keys(value);
  if (keys.some((key) => !allowedKeys.includes(key))
      || requiredKeys.some((key) => !Object.hasOwn(value, key))) {
    throw new Error(`${label} did not contain its exact bounded fields`);
  }
  return value;
}

function toolResultText(body, expectedCall) {
  const matchingToolMessages = body.messages.filter((message) =>
    message?.role === "tool" && message.tool_call_id === expectedCall.id);
  const toolMessage = matchingToolMessages[0];
  if (matchingToolMessages.length !== 1 || !isPlainObject(toolMessage)
      || typeof toolMessage.content !== "string" || toolMessage.content.length > 256 * 1024) {
    throw new Error(`request is missing the exact bounded result for ${expectedCall.id}`);
  }
  const assistants = [...body.messages].reverse().filter((message) =>
    message?.role === "assistant" && Array.isArray(message.tool_calls)
      && message.tool_calls.some((call) => call?.id === expectedCall.id));
  const assistant = assistants[0];
  const replay = assistant?.tool_calls?.[0];
  if (assistants.length !== 1 || assistant.tool_calls.length !== 1
      || replay?.id !== expectedCall.id || replay.type !== "function"
      || replay.function?.name !== expectedCall.name
      || replay.function.arguments !== JSON.stringify(expectedCall.arguments)) {
    throw new Error(`request did not replay the exact assistant call ${expectedCall.id}`);
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
    case "pve-inspect":
      try {
        const result = requireExactKeys(
          JSON.parse(text),
          "PVE inspect tool result",
          ["status", "lock"],
        );
        if (result.status !== "stopped" || result.lock !== "") {
          throw new Error("PVE inspect tool result did not report the exact stopped guest state");
        }
      } catch (error) {
        if (error instanceof SyntaxError) {
          throw new Error("PVE inspect tool result was not exact JSON");
        }
        throw error;
      }
      break;
    case "prepare-package":
    case "prepare-file":
      if (!text.includes("changeRef=opschg1_")
          || text.split("\n").filter((line) => line === PENDING_CHANGE_INSTRUCTION).length !== 1) {
        throw new Error("prepare tool result omitted the signed pending-approval evidence");
      }
      break;
    case "plugin-register-pve": {
      const lines = text.split("\n");
      if (lines.filter((line) => line === `machineId=${machineId}`).length !== 1
          || lines.filter((line) => line === `targetId=${targetId}`).length !== 1
          || lines.filter((line) => line.startsWith("changeRef=opschg1_")).length !== 1
          || lines.filter((line) => line === PENDING_CHANGE_INSTRUCTION).length !== 1
          || lines.at(-1) !== PENDING_CHANGE_INSTRUCTION
          || lines.some((line) => PVE_NON_APPROVAL_INSTRUCTIONS.has(line))) {
        throw new Error(
          "PVE plugin registration result omitted its signed PENDING_APPROVAL instruction",
        );
      }
      break;
    }
    case "pve-start": {
      const lines = text.split("\n");
      if (lines.filter((line) => line === `machineId=${machineId}`).length !== 1
          || lines.filter((line) => line === `targetId=${targetId}`).length !== 1
          || lines.filter((line) => line.startsWith("changeRef=opschg1_")).length !== 1
          || lines.filter((line) => PVE_NON_APPROVAL_INSTRUCTIONS.has(line)).length !== 1
          || !PVE_NON_APPROVAL_INSTRUCTIONS.has(lines.at(-1))
          || lines.includes(PENDING_CHANGE_INSTRUCTION)) {
        throw new Error("PVE start result omitted its signed non-approval lifecycle evidence");
      }
      break;
    }
    default:
      throw new Error("unreachable scenario");
  }
}

function preparedChangeRef(text) {
  if (scenario !== "prepare-package" && scenario !== "prepare-file"
      && scenario !== "plugin-register-pve" && scenario !== "pve-start") {
    return undefined;
  }
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
  if (scenario === "pve-start"
      && (decoded.serverId !== serverId || decoded.machineId !== machineId
        || decoded.targetId !== targetId || !PVE_CHANGE_ID_PATTERN.test(decoded.changeId))) {
    throw new Error("PVE start changeRef was not bound to the exact endpoint and change identity");
  }
  if (scenario === "plugin-register-pve"
      && (decoded.serverId !== serverId || decoded.machineId !== machineId
        || decoded.targetId !== targetId)) {
    throw new Error("PVE plugin registration changeRef was not bound to the exact endpoint");
  }
  return {
    ref: changeRef,
    serverId: decoded.serverId,
    machineId: decoded.machineId,
    targetId: decoded.targetId,
    changeId: decoded.changeId,
  };
}

function validateCanonicalBase64Signature(value) {
  if (typeof value !== "string" || value.length !== 86) return false;
  const decoded = Buffer.from(value, "base64");
  return decoded.length === 64
    && decoded.toString("base64").replace(/=+$/u, "") === value;
}

function validatePVEStatusResult(text, change) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("PVE status tool result was not JSON");
  }
  const response = requireExactKeys(parsed, "PVE status response", [
    "version",
    "requestId",
    "ok",
    "auditId",
    "changeId",
    "state",
    "summary",
    "data",
    "brokerReceipt",
  ]);
  if (response.version !== 1 || response.ok !== true
      || typeof response.requestId !== "string" || response.requestId.length < 8
      || response.requestId.length > 160
      || !/^audit-[a-f0-9]{32}$/u.test(response.auditId)
      || response.changeId !== change.changeId || !PVE_STATUS_STATES.has(response.state)
      || typeof response.summary !== "string" || response.summary.length > 64 * 1024) {
    throw new Error("PVE status response had an invalid signed lifecycle identity");
  }

  const data = requireExactKeys(
    response.data,
    "PVE status metadata",
    [...PVE_STATUS_DATA_KEYS],
    PVE_STATUS_REQUIRED_DATA_KEYS,
  );
  const expectedAuthorizationBasis =
    `standing-policy:${pvePolicyRevision}:pve.guest.start`;
  if (data.serverId !== serverId || data.machineId !== machineId || data.targetId !== targetId
      || data.policyRevision !== pvePolicyRevision
      || typeof data.capabilityRevision !== "string" || data.capabilityRevision.length < 8
      || data.capabilityRevision.length > 160 || !SHA256_PATTERN.test(data.planHash)
      || data.kind !== "pve.guest.action" || !Array.isArray(data.backupRefs)
      || data.backupRefs.length > 64 || data.backupRefs.some((entry) => typeof entry !== "string")
      || typeof data.verification !== "string" || data.verification.length > 8_192
      || typeof data.rollbackAvailable !== "boolean"
      || data.authorizationBasis !== expectedAuthorizationBasis
      || data.authorizationScope !== "pve.guest.start"
      || typeof data.authorizedAt !== "string"
      || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/u.test(data.authorizedAt)
      || !Number.isFinite(Date.parse(data.authorizedAt)) || data.recoveryOnly !== false) {
    throw new Error("PVE status metadata was not bound to the exact standing start scope");
  }
  if (data.plan !== undefined) {
    if (!isPlainObject(data.plan) || data.plan.planHash !== data.planHash
        || data.plan.policyRevision !== pvePolicyRevision) {
      throw new Error("PVE status ApprovalPlan did not match the signed plan identity");
    }
  }
  if (data.pveMutationVersion !== undefined && data.pveMutationVersion !== 1) {
    throw new Error("PVE status metadata had an unsupported mutation version");
  }
  if (data.mutationDisposition !== undefined
      && !new Set(["NO_MUTATION_STARTED", "TASKS_TERMINAL", "STARTED_OR_UNKNOWN"])
        .has(data.mutationDisposition)) {
    throw new Error("PVE status metadata had an unsupported mutation disposition");
  }

  const receipt = requireExactKeys(
    response.brokerReceipt,
    "PVE status broker receipt",
    PVE_RECEIPT_KEYS,
  );
  if (receipt.version !== 1 || typeof receipt.keyId !== "string"
      || receipt.keyId.length < 8 || receipt.keyId.length > 160
      || receipt.domain !== "pve" || receipt.requestId !== response.requestId
      || receipt.method !== "change.status" || receipt.action !== "status"
      || receipt.serverId !== serverId || receipt.machineId !== machineId
      || receipt.targetId !== targetId || receipt.changeId !== change.changeId
      || receipt.planHash !== data.planHash || receipt.state !== response.state
      || receipt.auditId !== response.auditId || !SHA256_PATTERN.test(receipt.resultDigest)
      || typeof receipt.issuedAt !== "string"
      || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/u.test(receipt.issuedAt)
      || !Number.isFinite(Date.parse(receipt.issuedAt))
      || !validateCanonicalBase64Signature(receipt.signature)) {
    throw new Error("PVE status broker receipt was not bound to the exact response identity");
  }
  return response.state;
}

function requireExposedTool(body, name) {
  const matches = body.tools.filter((tool) =>
    tool?.type === "function" && tool.function?.name === name);
  if (matches.length !== 1 || !isPlainObject(matches[0]?.function?.parameters)) {
    throw new Error(`request did not expose exactly one ${name} tool with a schema`);
  }
}

function validateToolExposure(body) {
  requireExposedTool(body, scenarioTool);
  if (!scenario.startsWith("pve-")) return;
  requireExposedTool(body, "ops_change_status");
  const hiddenProviders = new Set(["ops_pve_propose", "ops_pve_inspect"]);
  if (body.tools.some((tool) => hiddenProviders.has(tool?.function?.name))) {
    throw new Error("request exposed a hidden typed PVE provider to the model");
  }
}

function sendToolCall(response, sequence, expectedCall) {
  writeSse(response, [
    chunk(`chatcmpl-ops-agent-e2e-${sequence}`, {
      role: "assistant",
      tool_calls: [{
        index: 0,
        id: expectedCall.id,
        type: "function",
        function: {
          name: expectedCall.name,
          arguments: JSON.stringify(expectedCall.arguments),
        },
      }],
    }, null),
    chunk(`chatcmpl-ops-agent-e2e-${sequence}`, {}, "tool_calls"),
  ]);
}

function sendSuccess(response, sequence, marker) {
  writeSse(response, [
    chunk(`chatcmpl-ops-agent-e2e-${sequence}`, {
      role: "assistant",
      content: marker,
    }, null),
    chunk(`chatcmpl-ops-agent-e2e-${sequence}`, {}, "stop"),
  ]);
}

let requestCount = 0;
let terminalFailure;
let expectedCall = {
  id: "call_ops_agent_e2e_1",
  name: scenarioTool,
  arguments: toolArguments(),
};
let pveChange;
let pveInitialState;
let pveStatusPolls = 0;
let lastPVEStatusRank = 0;
let pveCommitted = false;
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
        validateToolExposure(body);
        requestCount += 1;
        process.stdout.write(`MOCK_REQUEST_OK scenario=${scenario} sequence=${requestCount}\n`);
        if (requestCount === 1) {
          sendToolCall(response, requestCount, expectedCall);
          return;
        }
        if (scenario !== "pve-start") {
          if (requestCount !== 2) throw new Error("mock received more than two inference requests");
          const resultText = toolResultText(body, expectedCall);
          validateToolResult(resultText);
          const change = preparedChangeRef(resultText);
          process.stdout.write(`MOCK_TOOL_RESULT_OK scenario=${scenario}\n`);
          sendSuccess(
            response,
            requestCount,
            `SCRIPTED_MODEL_E2E_${scenario.toUpperCase().replaceAll("-", "_")}_OK nonce=${nonce}${change === undefined ? "" : ` changeRef=${change.ref}`}`,
          );
          setImmediate(() => server.close());
          return;
        }

        if (requestCount === 2) {
          const resultText = toolResultText(body, expectedCall);
          validateToolResult(resultText);
          pveChange = preparedChangeRef(resultText);
          if (pveChange === undefined) throw new Error("PVE start did not return a change identity");
          const instruction = resultText.split("\n").at(-1);
          pveInitialState = PVE_NON_APPROVAL_INSTRUCTIONS.get(instruction);
          if (pveInitialState === undefined) {
            throw new Error("PVE start did not return an allowed signed initial state");
          }
          process.stdout.write(
            `MOCK_TOOL_RESULT_OK scenario=${scenario} state=${pveInitialState} changeId=${pveChange.changeId}\n`,
          );
          pveStatusPolls = 1;
          expectedCall = {
            id: `call_ops_agent_e2e_status_${pveStatusPolls}`,
            name: "ops_change_status",
            arguments: {
              machineId,
              targetId,
              changeId: pveChange.changeId,
            },
          };
          sendToolCall(response, requestCount, expectedCall);
          return;
        }

        if (pveChange === undefined || requestCount > MAX_PVE_STATUS_POLLS + 2) {
          throw new Error("PVE status polling exceeded its bounded request count");
        }
        const statusText = toolResultText(body, expectedCall);
        const state = validatePVEStatusResult(statusText, pveChange);
        const stateRank = PVE_STATUS_RANK[state];
        const initialRank = PVE_STATUS_RANK[pveInitialState];
        if (stateRank < lastPVEStatusRank || stateRank < initialRank) {
          throw new Error("PVE signed status regressed from an already observed lifecycle state");
        }
        lastPVEStatusRank = stateRank;
        process.stdout.write(
          `MOCK_PVE_STATUS_OK poll=${pveStatusPolls} state=${state} changeId=${pveChange.changeId}\n`,
        );
        if (state === "COMMITTED") {
          pveCommitted = true;
          sendSuccess(
            response,
            requestCount,
            `SCRIPTED_MODEL_E2E_PVE_START_OK nonce=${nonce} state=COMMITTED changeId=${pveChange.changeId} changeRef=${pveChange.ref}`,
          );
          setImmediate(() => server.close());
          return;
        }
        if (pveStatusPolls >= MAX_PVE_STATUS_POLLS) {
          throw new Error(`PVE change did not reach COMMITTED after ${pveStatusPolls} signed polls`);
        }
        pveStatusPolls += 1;
        expectedCall = {
          id: `call_ops_agent_e2e_status_${pveStatusPolls}`,
          name: "ops_change_status",
          arguments: {
            machineId,
            targetId,
            changeId: pveChange.changeId,
          },
        };
        setTimeout(() => {
          if (response.destroyed) {
            terminalFailure = "PVE status polling response closed during the bounded delay";
            server.close();
            return;
          }
          sendToolCall(response, requestCount, expectedCall);
        }, PVE_STATUS_POLL_DELAY_MS);
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
  if (scenario === "pve-start") {
    if (!pveCommitted || pveStatusPolls < 1 || requestCount !== pveStatusPolls + 2) {
      fail(`PVE start did not complete after exact signed polling; requests=${requestCount} polls=${pveStatusPolls}`);
    }
  } else if (requestCount !== 2) {
    fail(`expected exactly two requests, received ${requestCount}`);
  }
  process.stdout.write(
    `MOCK_COMPLETE scenario=${scenario} requests=${requestCount} nonce=${nonce}\n`,
  );
});
server.listen(port, "127.0.0.1", () => {
  process.stdout.write(`MOCK_READY scenario=${scenario} address=127.0.0.1 port=${port} nonce=${nonce}\n`);
});
