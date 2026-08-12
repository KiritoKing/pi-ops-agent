const string = (options = {}) => Object.freeze({ type: "string", ...options });
const integer = (options = {}) => Object.freeze({ type: "integer", ...options });
const boolean = () => Object.freeze({ type: "boolean" });
const array = (items, options = {}) => Object.freeze({ type: "array", items, ...options });
const object = (properties, required = Object.keys(properties)) => Object.freeze({
  type: "object",
  properties: Object.freeze(properties),
  required: Object.freeze(required),
  additionalProperties: false,
});
const union = (...anyOf) => Object.freeze({ anyOf: Object.freeze(anyOf) });
const literal = (value) => Object.freeze({ type: typeof value, const: value });

const machineId = string({ minLength: 8, maxLength: 160 });
const targetId = string({ minLength: 8, maxLength: 160 });
const unit = string({ minLength: 9, maxLength: 200 });
const absolutePath = string({ minLength: 2, maxLength: 4096 });

const inspection = union(
  object({ machineId, targetId, operation: literal("host_snapshot") }),
  object({ machineId, targetId, operation: literal("process_list") }),
  object({ machineId, targetId, operation: literal("systemd_unit"), unit }),
  object(
    { machineId, targetId, operation: literal("journal_tail"), unit, lines: integer({ minimum: 1, maximum: 200 }) },
    ["machineId", "targetId", "operation", "unit"],
  ),
  object({ machineId, targetId, operation: literal("file_metadata"), path: absolutePath }),
  object(
    { machineId, targetId, operation: literal("file_read"), path: absolutePath, maxBytes: integer({ minimum: 1, maximum: 131072 }) },
    ["machineId", "targetId", "operation", "path"],
  ),
);

const changeOperation = union(
  object(
    { kind: literal("package.install"), package: string({ minLength: 1, maxLength: 128 }), version: string({ maxLength: 128 }) },
    ["kind", "package"],
  ),
  object({
    kind: literal("service.action"),
    unit,
    action: Object.freeze({ type: "string", enum: ["restart", "reload", "start", "stop"] }),
  }),
  object(
    { kind: literal("file.write"), path: absolutePath, content: string({ maxLength: 131072 }), mode: string({ pattern: "^0{0,1}[0246]{3}$", maxLength: 4 }) },
    ["kind", "path", "content"],
  ),
  object({
    kind: literal("plugin.install"),
    pluginId: string({ maxLength: 128 }),
    version: string({ maxLength: 128 }),
    publisher: string({ maxLength: 160 }),
    digest: string({ minLength: 71, maxLength: 71 }),
    artifactRef: string({ minLength: 79, maxLength: 79 }),
  }),
  object({
    kind: literal("plugin.register"),
    pluginId: string({ maxLength: 72 }),
    pluginKind: Object.freeze({ type: "string", enum: ["adapter", "workload"] }),
    version: string({ maxLength: 128 }),
    publisher: string({ maxLength: 160 }),
    digest: string({ minLength: 71, maxLength: 71 }),
    capabilities: array(string({ maxLength: 128 }), { maxItems: 64, uniqueItems: true }),
    requestedScopes: array(string({ maxLength: 128 }), { maxItems: 64, uniqueItems: true }),
  }),
  object({
    kind: literal("workload.deploy"),
    pluginId: string({ maxLength: 128 }),
    version: string({ maxLength: 128 }),
    publisher: string({ maxLength: 160 }),
    digest: string({ minLength: 71, maxLength: 71 }),
    artifactRef: string({ minLength: 79, maxLength: 79 }),
  }),
);

const tools = Object.freeze([
  Object.freeze({
    name: "ops_artifact_catalog",
    label: "List trusted artifacts",
    description: "List immutable artifacts exposed by an explicit registered machine target.",
    capability: "artifact.catalog",
    parameters: object({ machineId, targetId }),
    providers: Object.freeze(["artifact.catalog"]),
    executionMode: "parallel",
  }),
  Object.freeze({
    name: "ops_bash",
    label: "Run sandboxed shell",
    description: "Run an unprivileged, offline command with only the current session workspace writable.",
    capability: "command.exec.sandbox",
    parameters: object(
      { command: string({ minLength: 1, maxLength: 32768 }), timeoutSeconds: integer({ minimum: 1, maximum: 120 }) },
      ["command"],
    ),
    providers: Object.freeze(["command.exec.sandbox"]),
    executionMode: "sequential",
  }),
  Object.freeze({
    name: "ops_breakglass_prepare",
    label: "Prepare manually approved root capsule",
    description: "Prepare an exact digest-bound root script for an operation outside standing policy. Backup paths and a caller-provided privileged postcondition script are optional but missing evidence is highlighted as critical; this tool never approves.",
    capability: "breakglass.prepare",
    parameters: object(
      {
        machineId,
        targetId,
        script: string({ minLength: 1, maxLength: 131072 }),
        backupPaths: array(absolutePath, { maxItems: 32, uniqueItems: true }),
        verifyScript: string({ minLength: 1, maxLength: 32768 }),
        network: boolean(),
      },
      ["machineId", "targetId", "script", "backupPaths", "network"],
    ),
    providers: Object.freeze(["breakglass.prepare"]),
    executionMode: "sequential",
  }),
  Object.freeze({
    name: "ops_change_status",
    label: "Get target-scoped change status",
    description: "Read the authoritative state of an existing target-scoped change.",
    capability: "change.status",
    parameters: object({ machineId, targetId, changeId: string({ minLength: 8, maxLength: 160 }) }),
    providers: Object.freeze(["change.status"]),
    executionMode: "parallel",
  }),
  Object.freeze({
    name: "ops_inspect",
    label: "Inspect remote target",
    description: "Run one trusted read-only inspection against an explicit registered machine and target.",
    capability: "target.inspect",
    parameters: inspection,
    providers: Object.freeze(["target.inspect"]),
    executionMode: "parallel",
  }),
  Object.freeze({
    name: "ops_machine_describe",
    label: "Describe registered machine",
    description: "Refresh pinned machine identity, targets, capabilities, and policy revision.",
    capability: "machine.describe",
    parameters: object({ machineId }),
    providers: Object.freeze(["machine.describe"]),
    executionMode: "parallel",
  }),
  Object.freeze({
    name: "ops_machine_list",
    label: "List registered machines",
    description: "List controller-pinned machine registrations without trusting or executing server code.",
    capability: "machine.list",
    parameters: object({}),
    providers: Object.freeze(["machine.list"]),
    executionMode: "parallel",
  }),
  Object.freeze({
    name: "ops_propose_change",
    label: "Propose target-scoped change",
    description: "Prepare a typed immutable change. Exact standing grants may commit ordinary operations; plugin installation always requires separate approval.",
    capability: "change.prepare",
    parameters: object({ machineId, targetId, operation: changeOperation }),
    providers: Object.freeze(["change.prepare"]),
    executionMode: "sequential",
  }),
]);

const route = Object.freeze(Object.fromEntries(tools.map((tool) => [tool.name, tool.providers[0]])));

export const workload = Object.freeze({
  apiVersion: "agentd.workload/v1",
  tools,
  async invoke(request, api) {
    const provider = route[request.tool];
    if (provider === undefined) throw new Error("workload.base received an unknown tool");
    return await api.call(provider, request.input);
  },
});
