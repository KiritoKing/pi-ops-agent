const string = (options = {}) => Object.freeze({ type: "string", ...options });
const integer = (options = {}) => Object.freeze({ type: "integer", ...options });
const literal = (value) => Object.freeze({ type: "string", const: value });
const object = (properties, required = Object.keys(properties)) => Object.freeze({
  type: "object",
  properties: Object.freeze(properties),
  required: Object.freeze(required),
  additionalProperties: false,
});
const union = (...anyOf) => Object.freeze({ anyOf: Object.freeze(anyOf) });
const machineId = string({
  minLength: 8,
  maxLength: 160,
  pattern: "^[A-Za-z0-9][A-Za-z0-9._:-]{6,158}[A-Za-z0-9]$",
});
const targetId = machineId;
const account = string({
  minLength: 1,
  maxLength: 32,
  pattern: "^[a-z_][a-z0-9_-]{0,31}$",
});
const unit = literal("botmux.service");
const configPath = union(
  literal("/root/.botmux/bots.json"),
  string({
    minLength: 2,
    maxLength: 256,
    pattern: "^/home/[a-z_][a-z0-9_-]{0,31}/\\.botmux/bots\\.json$",
  }),
);
const manager = Object.freeze({ type: "string", enum: Object.freeze(["system", "user"]) });
const serviceAction = Object.freeze({
  type: "string",
  enum: Object.freeze(["reload", "reset-failed", "restart", "start", "stop"]),
});
const selectorValue = string({
  minLength: 1,
  maxLength: 256,
});
const modelId = string({
  minLength: 1,
  maxLength: 256,
  pattern: "^[A-Za-z0-9._:@/-]{1,256}$",
});
const absoluteWorkingDirectory = string({
  minLength: 2,
  maxLength: 4096,
  pattern: "^/[A-Za-z0-9._/-]{1,4095}$",
});
const clearValue = object({ kind: literal("clear") });
const configEdit = union(
  object({
    fieldKey: literal("model"),
    value: union(object({ kind: literal("string"), stringValue: modelId }), clearValue),
  }),
  object({
    fieldKey: literal("backendType"),
    value: union(
      object({ kind: literal("string"), stringValue: Object.freeze({ type: "string", enum: Object.freeze(["pty", "tmux"]) }) }),
      clearValue,
    ),
  }),
  object({
    fieldKey: literal("defaultWorkingDir"),
    value: union(object({ kind: literal("string"), stringValue: absoluteWorkingDirectory }), clearValue),
  }),
  object({
    fieldKey: literal("showInTeam"),
    value: union(object({ kind: literal("boolean"), booleanValue: Object.freeze({ type: "boolean" }) }), clearValue),
  }),
);

const MAX_SETUP_JSON_BYTES = 64 * 1024;
const MAX_SETUP_JSON_DEPTH = 16;
const MAX_SETUP_JSON_VALUES = 4096;
const MAX_SETUP_JSON_CONTAINER_ITEMS = 1024;
const sensitiveDiagnosticLine = /[a-z0-9_.-]*(?:api[_-]?key|secret|token|password|credential|authorization|cookie|env|command|cwd|path)[a-z0-9_.-]*\s*[:=]/iu;
// These are exact, case-sensitive output field names. Unknown names are never
// normalized into this allowlist, so case and Unicode confusables remain
// unknown and are discarded.
const safeSetupStringKeys = new Set([
  "processName", "name", "displayName", "brand", "cliId", "backendType", "model",
]);
const safeSetupBooleanKeys = new Set(["apiOnly", "showInTeam"]);
const unsafeSetupText = /[\p{Cc}\p{Cf}]/u;

function requireSafeSelectorValue(value) {
  if (typeof value !== "string" || value.length < 1 || value.length > 256) {
    throw new Error("BotMux selectorValue must be a bounded string");
  }
  for (const character of value) {
    const codePoint = character.codePointAt(0) ?? 0;
    if (codePoint < 0x20
      || (codePoint >= 0x7f && codePoint <= 0x9f)
      || codePoint === 0x061c
      || codePoint === 0x200e
      || codePoint === 0x200f
      || (codePoint >= 0x2028 && codePoint <= 0x202e)
      || (codePoint >= 0x2066 && codePoint <= 0x2069)
      || codePoint === 0xfeff) {
      throw new Error("BotMux selectorValue contains a forbidden control character");
    }
  }
  return value;
}

function invalidSetupJson() {
  return new Error("BotMux setup list did not return bounded strict JSON");
}

// JSON.parse accepts duplicate object keys. This source-local recursive
// descent parser rejects them after escape decoding, and also keeps parsing
// work, allocation, nesting, and the accepted byte envelope bounded. It is
// intentionally part of the digest-covered plugin rather than imported from
// Core.
function parseStrictSetupJson(text) {
  if (typeof text !== "string" || Buffer.byteLength(text, "utf8") > MAX_SETUP_JSON_BYTES) {
    throw invalidSetupJson();
  }
  let offset = 0;
  let values = 0;

  function fail() {
    throw invalidSetupJson();
  }

  function skipWhitespace() {
    while (offset < text.length
      && (text[offset] === " " || text[offset] === "\t"
        || text[offset] === "\n" || text[offset] === "\r")) {
      offset += 1;
    }
  }

  function parseString() {
    if (text[offset] !== "\"") fail();
    const start = offset;
    offset += 1;
    while (offset < text.length) {
      const code = text.charCodeAt(offset);
      if (code === 0x22) {
        offset += 1;
        try {
          return JSON.parse(text.slice(start, offset));
        } catch {
          fail();
        }
      }
      if (code === 0x5c) {
        offset += 1;
        if (offset >= text.length) fail();
        const escape = text[offset];
        if (escape === "u") {
          if (offset + 4 >= text.length) fail();
          for (let index = 1; index <= 4; index += 1) {
            if (!/[0-9a-f]/iu.test(text[offset + index])) fail();
          }
          offset += 5;
          continue;
        }
        if (!/["\\/bfnrt]/u.test(escape)) fail();
        offset += 1;
        continue;
      }
      if (code < 0x20) fail();
      offset += 1;
    }
    fail();
  }

  function parseArray(depth) {
    offset += 1;
    const result = [];
    skipWhitespace();
    if (text[offset] === "]") {
      offset += 1;
      return result;
    }
    while (true) {
      if (result.length >= MAX_SETUP_JSON_CONTAINER_ITEMS) fail();
      result.push(parseValue(depth + 1));
      skipWhitespace();
      if (text[offset] === "]") {
        offset += 1;
        return result;
      }
      if (text[offset] !== ",") fail();
      offset += 1;
      skipWhitespace();
    }
  }

  function parseObject(depth) {
    offset += 1;
    const result = Object.create(null);
    const keys = new Set();
    skipWhitespace();
    if (text[offset] === "}") {
      offset += 1;
      return result;
    }
    let count = 0;
    while (true) {
      if (count >= MAX_SETUP_JSON_CONTAINER_ITEMS || text[offset] !== "\"") fail();
      const key = parseString();
      if (keys.has(key)) fail();
      keys.add(key);
      count += 1;
      skipWhitespace();
      if (text[offset] !== ":") fail();
      offset += 1;
      skipWhitespace();
      result[key] = parseValue(depth + 1);
      skipWhitespace();
      if (text[offset] === "}") {
        offset += 1;
        return result;
      }
      if (text[offset] !== ",") fail();
      offset += 1;
      skipWhitespace();
    }
  }

  function parseValue(depth) {
    if (depth > MAX_SETUP_JSON_DEPTH || values >= MAX_SETUP_JSON_VALUES) fail();
    values += 1;
    skipWhitespace();
    const next = text[offset];
    if (next === "{") return parseObject(depth);
    if (next === "[") return parseArray(depth);
    if (next === "\"") return parseString();
    for (const [literalValue, parsedValue] of [
      ["true", true], ["false", false], ["null", null],
    ]) {
      if (text.startsWith(literalValue, offset)) {
        offset += literalValue.length;
        return parsedValue;
      }
    }
    const number = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/u.exec(text.slice(offset));
    if (number === null) fail();
    offset += number[0].length;
    const parsed = Number(number[0]);
    if (!Number.isFinite(parsed)) fail();
    return parsed;
  }

  skipWhitespace();
  const parsed = parseValue(0);
  skipWhitespace();
  if (offset !== text.length) fail();
  return parsed;
}

function commandDetails(value, profileKey) {
  if (typeof value !== "object" || value === null || Array.isArray(value)
    || typeof value.details !== "object" || value.details === null || Array.isArray(value.details)
    || value.details.profileKey !== profileKey || typeof value.details.output !== "string"
    || typeof value.details.truncated !== "boolean"
    || value.details.executableTrust !== "root-owned-nonwritable-path") {
    throw new Error(`BotMux command provider returned an invalid ${profileKey} result`);
  }
  return value.details;
}

function sanitizedTextCommandResult(value, profileKey) {
  const details = commandDetails(value, profileKey);
  const output = details.output.split("\n").map((line) =>
    sensitiveDiagnosticLine.test(line) ? "[REDACTED SENSITIVE DIAGNOSTIC FIELD]" : line).join("\n");
  return Object.freeze({
    content: Object.freeze([{ type: "text", text: output }]),
    details: Object.freeze({
      profileKey,
      truncated: details.truncated,
      executableTrust: details.executableTrust,
    }),
  });
}

function safeSetupEntry(value) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw invalidSetupJson();
  const safe = {};
  for (const key of safeSetupStringKeys) {
    if (!Object.hasOwn(value, key)) continue;
    const field = value[key];
    if (typeof field !== "string" || field.length === 0 || field.length > 256
      || Buffer.byteLength(field, "utf8") > 512 || unsafeSetupText.test(field)) {
      throw invalidSetupJson();
    }
    safe[key] = field;
  }
  for (const key of safeSetupBooleanKeys) {
    if (!Object.hasOwn(value, key)) continue;
    if (typeof value[key] !== "boolean") throw invalidSetupJson();
    safe[key] = value[key];
  }
  // Upstream `setup list --json` is exactly `bots.map(botJsonView)`, and each
  // view contains both the generated processName and BotConfig.name. Requiring
  // both prevents silently accepting an unrelated JSON array as a setup list.
  if (typeof safe.processName !== "string" || typeof safe.name !== "string") {
    throw invalidSetupJson();
  }
  return Object.freeze(safe);
}

function sanitizeSetupCollection(value) {
  if (Array.isArray(value)) return value.map((entry) => safeSetupEntry(entry)).filter(Boolean);
  throw invalidSetupJson();
}

function setupEntries(value) {
  return sanitizeSetupCollection(value);
}

function sanitizedSetupSummary(value) {
  const details = commandDetails(value, "botmux.setup.summary");
  if (details.truncated) throw invalidSetupJson();
  const parsed = parseStrictSetupJson(details.output);
  const entries = setupEntries(parsed);
  const output = JSON.stringify({ version: 1, entries }, null, 2);
  if (Buffer.byteLength(output, "utf8") > MAX_SETUP_JSON_BYTES) throw invalidSetupJson();
  return Object.freeze({
    content: Object.freeze([{ type: "text", text: output }]),
    details: Object.freeze({
      profileKey: "botmux.setup.summary",
      count: entries.length,
      truncated: details.truncated,
      executableTrust: details.executableTrust,
    }),
  });
}

const tools = Object.freeze([
  Object.freeze({
    name: "ops_botmux_config_edit",
    label: "Prepare one BotMux config field edit",
    description: "Prepare one policy-mapped model, pty/tmux backend, existing safe working-directory, or show-in-team/default edit. Config path, selector key and actual JSON field remain root-policy-owned; every edit requires local per-change approval and service restart is separate.",
    capability: "botmux.config.edit",
    parameters: object({ machineId, targetId, selectorValue, edit: configEdit }),
    providers: Object.freeze(["workload.json-config.edit"]),
    executionMode: "sequential",
  }),
  Object.freeze({
    name: "ops_botmux_config_inspect",
    label: "Inspect BotMux config metadata",
    description: "Inspect metadata only for a fixed-profile BotMux bots.json path; contents remain unavailable.",
    capability: "botmux.config.inspect",
    parameters: object({ machineId, targetId, path: configPath }),
    providers: Object.freeze(["target.inspect"]),
    executionMode: "parallel",
  }),
  Object.freeze({
    name: "ops_botmux_health_inspect",
    label: "Inspect BotMux health",
    description: "Read the fixed-profile systemd status for one policy-allowed BotMux service.",
    capability: "botmux.health.inspect",
    parameters: object({ machineId, targetId, unit }),
    providers: Object.freeze(["target.inspect"]),
    executionMode: "parallel",
  }),
  Object.freeze({
    name: "ops_botmux_service_inspect",
    label: "Inspect BotMux service",
    description: "Read fixed-profile BotMux service status or a bounded journal tail.",
    capability: "botmux.service.inspect",
    parameters: union(
      object({ machineId, targetId, operation: literal("service_status"), unit }),
      object(
        { machineId, targetId, operation: literal("journal_tail"), unit, lines: integer({ minimum: 1, maximum: 200 }) },
        ["machineId", "targetId", "operation", "unit"],
      ),
    ),
    providers: Object.freeze(["target.inspect"]),
    executionMode: "parallel",
  }),
  Object.freeze({
    name: "ops_botmux_service_manage",
    label: "Prepare BotMux service action",
    description: "Prepare a digest-bound reload, reset-failed, start, stop, or restart for one policy-allowed BotMux service and account; reload and reset-failed always require per-change approval.",
    capability: "botmux.service.manage",
    parameters: object({ machineId, targetId, account, manager, unit, action: serviceAction }),
    providers: Object.freeze(["workload.service.manage"]),
    executionMode: "sequential",
  }),
  Object.freeze({
    name: "ops_botmux_sessions_list",
    label: "List bounded BotMux sessions",
    description: "Run the root-policy-owned BotMux session summary recipe without accepting argv, paths, or environment from the agent.",
    capability: "botmux.sessions.inspect",
    parameters: object({ machineId, targetId }),
    providers: Object.freeze(["workload.command.inspect"]),
    executionMode: "parallel",
  }),
  Object.freeze({
    name: "ops_botmux_setup_summary",
    label: "Inspect sanitized BotMux setup summary",
    description: "Parse BotMux setup list with a bounded duplicate-rejecting JSON parser and expose only an exact local allowlist; unknown, env, cliRuntime, update, command, path, and credential fields are removed.",
    capability: "botmux.setup.inspect",
    parameters: object({ machineId, targetId }),
    providers: Object.freeze(["workload.command.inspect"]),
    executionMode: "parallel",
  }),
  Object.freeze({
    name: "ops_botmux_status",
    label: "Inspect BotMux status",
    description: "Run the root-policy-owned BotMux status recipe as the target non-root account in a network-isolated transient service.",
    capability: "botmux.status.inspect",
    parameters: object({ machineId, targetId }),
    providers: Object.freeze(["workload.command.inspect"]),
    executionMode: "parallel",
  }),
]);

export const workload = Object.freeze({
  apiVersion: "agentd.workload/v1",
  tools,
  async invoke(request, api) {
    switch (request.tool) {
      case "ops_botmux_config_inspect":
        return await api.call("target.inspect", { ...request.input, operation: "file_metadata" });
      case "ops_botmux_config_edit": {
        const { edit, selectorValue: candidateSelector, ...scope } = request.input;
        return await api.call("workload.json-config.edit", {
          ...scope,
          selectorValue: requireSafeSelectorValue(candidateSelector),
          profileKey: "botmux.bots",
          fieldKey: edit.fieldKey,
          value: edit.value,
        });
      }
      case "ops_botmux_health_inspect":
        return await api.call("target.inspect", { ...request.input, operation: "systemd_unit" });
      case "ops_botmux_service_inspect": {
        const { operation, ...input } = request.input;
        return await api.call("target.inspect", {
          ...input,
          operation: operation === "service_status" ? "systemd_unit" : "journal_tail",
        });
      }
      case "ops_botmux_service_manage":
        return await api.call("workload.service.manage", request.input);
      case "ops_botmux_sessions_list":
        return sanitizedTextCommandResult(await api.call("workload.command.inspect", {
          ...request.input,
          profileKey: "botmux.sessions.list",
        }), "botmux.sessions.list");
      case "ops_botmux_setup_summary":
        return sanitizedSetupSummary(await api.call("workload.command.inspect", {
          ...request.input,
          profileKey: "botmux.setup.summary",
        }));
      case "ops_botmux_status":
        return sanitizedTextCommandResult(await api.call("workload.command.inspect", {
          ...request.input,
          profileKey: "botmux.status",
        }), "botmux.status");
      default:
        throw new Error("workload.botmux-ops received an unknown tool");
    }
  },
});
