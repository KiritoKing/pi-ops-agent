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
const unit = union(
  literal("hermes-gateway.service"),
  string({
    minLength: 24,
    maxLength: 88,
    pattern: "^hermes-gateway-[A-Za-z0-9_.-]{1,64}\\.service$",
  }),
);
const configPath = union(
  string({
    minLength: 19,
    maxLength: 256,
    enum: Object.freeze([
      "/root/.hermes/.env",
      "/root/.hermes/config.yaml",
      "/root/.hermes/config.yml",
      "/root/.hermes/settings.json",
    ]),
  }),
  string({ minLength: 2, maxLength: 256, pattern: "^/home/[a-z_][a-z0-9_-]{0,31}/\\.hermes/\\.env$" }),
  string({ minLength: 2, maxLength: 256, pattern: "^/home/[a-z_][a-z0-9_-]{0,31}/\\.hermes/config\\.yaml$" }),
  string({ minLength: 2, maxLength: 256, pattern: "^/home/[a-z_][a-z0-9_-]{0,31}/\\.hermes/config\\.yml$" }),
  string({ minLength: 2, maxLength: 256, pattern: "^/home/[a-z_][a-z0-9_-]{0,31}/\\.hermes/settings\\.json$" }),
);
const manager = Object.freeze({ type: "string", enum: Object.freeze(["system", "user"]) });
const serviceAction = Object.freeze({
  type: "string",
  enum: Object.freeze(["reload", "reset-failed", "restart", "start", "stop"]),
});

const replacementCsi = /\uFFFD\[[0-?]*[ -/]*[@-~]/gu;

function commandResultDetails(value, profileKey) {
  if (typeof value !== "object" || value === null || Array.isArray(value)
    || typeof value.details !== "object" || value.details === null || Array.isArray(value.details)
    || value.details.profileKey !== profileKey || typeof value.details.output !== "string"
    || typeof value.details.truncated !== "boolean"
    || value.details.executableTrust !== "root-owned-nonwritable-path") {
    throw new Error(`Hermes command provider returned an invalid ${profileKey} result`);
  }
  return value.details;
}

function normalizedDiagnosticLines(output) {
  // The privileged provider replaces C0 controls, including ESC, with U+FFFD.
  // The first replacement also makes direct unit-test/runtime callers follow
  // the same path. No raw line is ever returned to the model.
  const replacedEsc = output.split(String.fromCharCode(27)).join("\uFFFD");
  return replacedEsc.split("\n").slice(0, 4096).map((line) =>
    line.replace(replacementCsi, "").replace(/\r$/u, ""));
}

function diagnosticMarkerCounts(lines) {
  const counts = { passed: 0, warnings: 0, failed: 0 };
  for (const line of lines) {
    const marker = /^\s{0,4}([✓⚠✗])(?:\s|$)/u.exec(line)?.[1];
    if (marker === "✓") counts.passed += 1;
    else if (marker === "⚠") counts.warnings += 1;
    else if (marker === "✗") counts.failed += 1;
  }
  return Object.freeze(counts);
}

function sanitizedDoctorResult(value) {
  const details = commandResultDetails(value, "hermes.doctor");
  const lines = normalizedDiagnosticLines(details.output);
  let status = "unknown";
  let issueCount;
  if (details.truncated) {
    status = "incomplete";
  } else {
    const passedSummaries = lines.filter((line) => /^\s*All checks passed!\s*(?:🎉)?\s*$/u.test(line));
    const issueSummaries = lines.flatMap((line) => {
      const match = /^\s*Found ([0-9]{1,4}) issue\(s\) to address:\s*$/u.exec(line);
      return match === null ? [] : [Number(match[1])];
    });
    if (passedSummaries.length === 1 && issueSummaries.length === 0) {
      status = "passed";
      issueCount = 0;
    } else if (passedSummaries.length === 0 && issueSummaries.length === 1
      && Number.isSafeInteger(issueSummaries[0])) {
      status = "issues";
      [issueCount] = issueSummaries;
    }
  }
  const summary = {
    version: 1,
    profile: "hermes.doctor",
    status,
    ...(issueCount === undefined ? {} : { issueCount }),
    markers: diagnosticMarkerCounts(lines),
    complete: !details.truncated,
  };
  return Object.freeze({
    content: Object.freeze([{ type: "text", text: JSON.stringify(summary) }]),
    details: Object.freeze({
      profileKey: "hermes.doctor",
      truncated: details.truncated,
      executableTrust: details.executableTrust,
      summaryVersion: 1,
    }),
  });
}

function gatewayState(lines, truncated) {
  if (truncated) return "incomplete";
  let running = false;
  let stopped = false;
  for (const line of lines) {
    if (/^\s*✓ (?:User|System-wide) gateway service is running\s*$/u.test(line)
      || /^\s*✓ Gateway is running \(PID: [0-9]+(?:, [0-9]+)*\)\s*$/u.test(line)
      || /^\s*✓ Gateway is supervised by launchd \(PID [0-9]+\)\s*$/u.test(line)
      || /^\s*✓ Detached fallback process is running \(PID [0-9]+\)\s*$/u.test(line)) {
      running = true;
    }
    if (/^\s*✗ (?:User|System-wide) gateway service is stopped\s*$/u.test(line)
      || /^\s*✗ Gateway is not running\s*$/u.test(line)
      || /^\s*✗ No fallback process is running\s*$/u.test(line)) {
      stopped = true;
    }
  }
  if (running && stopped) return "conflicting";
  if (running) return "running";
  if (stopped) return "stopped";
  return "unknown";
}

function sanitizedGatewayResult(value) {
  const details = commandResultDetails(value, "hermes.gateway.status");
  const summary = Object.freeze({
    version: 1,
    profile: "hermes.gateway.status",
    state: gatewayState(normalizedDiagnosticLines(details.output), details.truncated),
    complete: !details.truncated,
  });
  return Object.freeze({
    content: Object.freeze([{ type: "text", text: JSON.stringify(summary) }]),
    details: Object.freeze({
      profileKey: "hermes.gateway.status",
      truncated: details.truncated,
      executableTrust: details.executableTrust,
      summaryVersion: 1,
    }),
  });
}

const tools = Object.freeze([
  Object.freeze({
    name: "ops_hermes_config_inspect",
    label: "Inspect Hermes config metadata",
    description: "Inspect metadata only for a fixed-profile Hermes configuration path; contents remain unavailable.",
    capability: "hermes.config.inspect",
    parameters: object({ machineId, targetId, path: configPath }),
    providers: Object.freeze(["target.inspect"]),
    executionMode: "parallel",
  }),
  Object.freeze({
    name: "ops_hermes_doctor",
    label: "Run bounded Hermes diagnostics",
    description: "Run the root-policy-owned hermes doctor recipe as the target non-root account in a network-isolated transient service.",
    capability: "hermes.doctor.inspect",
    parameters: object({ machineId, targetId }),
    providers: Object.freeze(["workload.command.inspect"]),
    executionMode: "parallel",
  }),
  Object.freeze({
    name: "ops_hermes_gateway_status",
    label: "Inspect Hermes gateway status",
    description: "Run the root-policy-owned hermes gateway status recipe as the target non-root account without accepting argv from the agent.",
    capability: "hermes.gateway.inspect",
    parameters: object({ machineId, targetId }),
    providers: Object.freeze(["workload.command.inspect"]),
    executionMode: "parallel",
  }),
  Object.freeze({
    name: "ops_hermes_health_inspect",
    label: "Inspect Hermes health",
    description: "Read the fixed-profile systemd status for one policy-allowed Hermes service.",
    capability: "hermes.health.inspect",
    parameters: object({ machineId, targetId, unit }),
    providers: Object.freeze(["target.inspect"]),
    executionMode: "parallel",
  }),
  Object.freeze({
    name: "ops_hermes_service_inspect",
    label: "Inspect Hermes service",
    description: "Read fixed-profile Hermes service status or a bounded journal tail.",
    capability: "hermes.service.inspect",
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
    name: "ops_hermes_service_manage",
    label: "Prepare Hermes service action",
    description: "Prepare a digest-bound reload, reset-failed, start, stop, or restart for one policy-allowed Hermes service and account; reload and reset-failed always require per-change approval.",
    capability: "hermes.service.manage",
    parameters: object({ machineId, targetId, account, manager, unit, action: serviceAction }),
    providers: Object.freeze(["workload.service.manage"]),
    executionMode: "sequential",
  }),
]);

export const workload = Object.freeze({
  apiVersion: "agentd.workload/v1",
  tools,
  async invoke(request, api) {
    switch (request.tool) {
      case "ops_hermes_config_inspect":
        return await api.call("target.inspect", { ...request.input, operation: "file_metadata" });
      case "ops_hermes_doctor":
        return sanitizedDoctorResult(await api.call("workload.command.inspect", {
          ...request.input,
          profileKey: "hermes.doctor",
        }));
      case "ops_hermes_gateway_status":
        return sanitizedGatewayResult(await api.call("workload.command.inspect", {
          ...request.input,
          profileKey: "hermes.gateway.status",
        }));
      case "ops_hermes_health_inspect":
        return await api.call("target.inspect", { ...request.input, operation: "systemd_unit" });
      case "ops_hermes_service_inspect": {
        const { operation, ...input } = request.input;
        return await api.call("target.inspect", {
          ...input,
          operation: operation === "service_status" ? "systemd_unit" : "journal_tail",
        });
      }
      case "ops_hermes_service_manage":
        return await api.call("workload.service.manage", request.input);
      default:
        throw new Error("workload.hermes-ops received an unknown tool");
    }
  },
});
