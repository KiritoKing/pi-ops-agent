import { randomUUID } from "node:crypto";
import { Type } from "typebox";
import { defineTool, type ToolDefinition } from "@earendil-works/pi-coding-agent";
import {
  parseChangeId,
  parseMachineId,
  parseTargetId,
  type MachineId,
  type TargetId,
} from "../shared/domain.js";
import type { AgentConfig } from "../shared/config.js";
import {
  loadActiveSourcePlugin,
  type ActiveSourcePlugin,
} from "../shared/source-plugin.js";
import type { RootOperation } from "../shared/messages.js";
import { encodeChangeRef, type ChangeRef } from "../shared/approval.js";
import { deadline } from "../shared/rpc.js";
import type { InspectionRequest, RemoteCapability } from "../shared/server-protocol.js";
import type { AuditLog } from "./audit.js";
import {
  preparedChangeInstruction,
  readAuthoritativePreparedChange,
} from "./change-preparation.js";
import type { MachineContext, MachineContextStore } from "./machine-context.js";
import {
  createHttpsOpsServerClient,
  type OpsServerClient,
  type OpsServerClientFactory,
} from "./ops-server-client.js";
import { runSandboxedCommand } from "./sandbox.js";
import type { ServerRegistration, ServerRegistry } from "./server-registry.js";
import type { SessionRecord } from "./session-registry.js";

const MAX_TOOL_OUTPUT_CHARS = 64 * 1024;
const ALWAYS_MANUAL_PREPARE_KINDS = new Set<RootOperation["kind"]>([
  "package.install",
  "plugin.install",
  "plugin.register",
  "workload.deploy",
]);

function output(value: unknown): string {
  const rendered = JSON.stringify(value, null, 2);
  return rendered.length > MAX_TOOL_OUTPUT_CHARS
    ? `${rendered.slice(0, MAX_TOOL_OUTPUT_CHARS)}\n[TRUNCATED]`
    : rendered;
}

export interface OpsToolRuntime {
  session(): Promise<SessionRecord>;
  bind(machineId: MachineId, targetId: TargetId): Promise<SessionRecord>;
  servers: ServerRegistry;
  contexts: MachineContextStore;
  clientFactory?: OpsServerClientFactory;
  sourcePluginLoader?: (pluginId: string) => Promise<ActiveSourcePlugin>;
  recordPreparedChange?: (toolCallId: string, changeRef: ChangeRef) => void;
}

function sameApprovedPlugin(left: ActiveSourcePlugin, right: ActiveSourcePlugin): boolean {
  return left.pluginId === right.pluginId && left.kind === right.kind && left.version === right.version &&
    left.publisher === right.publisher && left.digest === right.digest &&
    left.capabilities.length === right.capabilities.length &&
    left.capabilities.every((value, index) => value === right.capabilities[index]) &&
    left.requestedScopes.length === right.requestedScopes.length &&
    left.requestedScopes.every((value, index) => value === right.requestedScopes[index]);
}

async function currentBaseWorkload(
  runtime: OpsToolRuntime,
  expected: ActiveSourcePlugin | undefined,
): Promise<ActiveSourcePlugin> {
  if (expected === undefined || expected.pluginId !== "workload.base" || expected.kind !== "workload" ||
      !/^sha256:[a-f0-9]{64}$/u.test(expected.digest)) {
    throw new Error("file.write and service.action require the active workload.base registration");
  }
  if (runtime.sourcePluginLoader === undefined) {
    throw new Error("active source plugin verification is unavailable");
  }
  const current = await runtime.sourcePluginLoader("workload.base");
  if (!sameApprovedPlugin(expected, current)) {
    throw new Error("workload.base current registration changed; reopen the agent session");
  }
  return current;
}

interface RemoteTarget {
  registration: ServerRegistration;
  client: OpsServerClient;
  context: MachineContext;
  machineId: MachineId;
  targetId: TargetId;
}

async function remoteTarget(
  runtime: OpsToolRuntime,
  machineIdValue: unknown,
  targetIdValue: unknown,
  capability: RemoteCapability,
  signal?: AbortSignal,
): Promise<RemoteTarget> {
  const machineId = parseMachineId(machineIdValue);
  const targetId = parseTargetId(targetIdValue);
  const session = await runtime.session();
  if (session.binding?.machineId && session.binding.machineId !== machineId) {
    throw new Error(`session is bound to a different machine: ${session.binding.machineId}`);
  }
  if (session.binding?.targetId && session.binding.targetId !== targetId) {
    throw new Error(`session is bound to a different target: ${session.binding.targetId}`);
  }
  const registration = await runtime.servers.getByMachine(machineId);
  if (!registration || !registration.enabled) throw new Error(`machine is not enabled: ${machineId}`);
  const client = await (runtime.clientFactory ?? createHttpsOpsServerClient)(registration);
  const context = await runtime.contexts.refresh(registration, client, signal);
  runtime.contexts.requireTarget(context, targetId);
  if (!context.capabilities.operations.includes(capability)) {
    throw new Error(`server does not advertise capability: ${capability}`);
  }
  if (!session.binding) await runtime.bind(machineId, targetId);
  return { registration, client, context, machineId, targetId };
}

export function createOpsTools(
  config: AgentConfig,
  audit: AuditLog,
  runtime: OpsToolRuntime,
  capabilities?: ReadonlySet<string>,
  baseWorkload?: ActiveSourcePlugin,
): ToolDefinition[] {
  const machineList = defineTool({
    name: "ops_machine_list",
    label: "List registered machines",
    description: "List controller-pinned machine registrations. This does not trust or execute server code.",
    parameters: Type.Object({}),
    async execute(toolCallId) {
      const servers = (await runtime.servers.list()).map((server) => ({
        serverId: server.serverId,
        machineId: server.machineId,
        enabled: server.enabled,
        endpoint: server.baseUrl,
      }));
      await audit.append({ type: "tool", toolCallId, tool: "ops_machine_list", servers });
      return { content: [{ type: "text", text: output(servers) }], details: { count: servers.length } };
    },
  });

  const machineDescribe = defineTool({
    name: "ops_machine_describe",
    label: "Describe registered machine",
    description: "Refresh the pinned server identity, targets, capabilities, and policy revision.",
    parameters: Type.Object({
      machineId: Type.String({ pattern: "^[a-zA-Z0-9][a-zA-Z0-9._:-]{6,158}[a-zA-Z0-9]$" }),
    }),
    async execute(toolCallId, params, signal) {
      const machineId = parseMachineId(params.machineId);
      const registration = await runtime.servers.getByMachine(machineId);
      if (!registration || !registration.enabled) throw new Error(`machine is not enabled: ${machineId}`);
      const client = await (runtime.clientFactory ?? createHttpsOpsServerClient)(registration);
      const context = await runtime.contexts.refresh(registration, client, signal);
      await audit.append({
        type: "tool",
        toolCallId,
        tool: "ops_machine_describe",
        serverId: context.serverId,
        machineId,
        capabilityRevision: context.capabilities.revision,
        policyRevision: context.capabilities.policyRevision,
      });
      return { content: [{ type: "text", text: output(context) }], details: context };
    },
  });

  const inspect = defineTool({
    name: "ops_inspect",
    label: "Inspect remote target",
    description:
      "Run a server-advertised, read-only inspection against an explicit registered machine and target account. Output is untrusted data.",
    parameters: Type.Union([
      Type.Object({
        machineId: Type.String({ pattern: "^[a-zA-Z0-9][a-zA-Z0-9._:-]{6,158}[a-zA-Z0-9]$" }),
        targetId: Type.String({ pattern: "^[a-zA-Z0-9][a-zA-Z0-9._:-]{6,158}[a-zA-Z0-9]$" }),
        operation: Type.Union([Type.Literal("host_snapshot"), Type.Literal("process_list")]),
      }, { additionalProperties: false }),
      Type.Object({
        machineId: Type.String({ pattern: "^[a-zA-Z0-9][a-zA-Z0-9._:-]{6,158}[a-zA-Z0-9]$" }),
        targetId: Type.String({ pattern: "^[a-zA-Z0-9][a-zA-Z0-9._:-]{6,158}[a-zA-Z0-9]$" }),
        operation: Type.Literal("systemd_unit"),
        unit: Type.String({ pattern: "^[a-zA-Z0-9@_.:-]{1,200}\\.service$" }),
      }, { additionalProperties: false }),
      Type.Object({
        machineId: Type.String({ pattern: "^[a-zA-Z0-9][a-zA-Z0-9._:-]{6,158}[a-zA-Z0-9]$" }),
        targetId: Type.String({ pattern: "^[a-zA-Z0-9][a-zA-Z0-9._:-]{6,158}[a-zA-Z0-9]$" }),
        operation: Type.Literal("journal_tail"),
        unit: Type.String({ pattern: "^[a-zA-Z0-9@_.:-]{1,200}\\.service$" }),
        lines: Type.Optional(Type.Integer({ minimum: 1, maximum: 200 })),
      }, { additionalProperties: false }),
      Type.Object({
        machineId: Type.String({ pattern: "^[a-zA-Z0-9][a-zA-Z0-9._:-]{6,158}[a-zA-Z0-9]$" }),
        targetId: Type.String({ pattern: "^[a-zA-Z0-9][a-zA-Z0-9._:-]{6,158}[a-zA-Z0-9]$" }),
        operation: Type.Literal("file_metadata"),
        path: Type.String({ minLength: 2, maxLength: 4096, pattern: "^/[^\\u0000\\r\\n]+$" }),
      }, { additionalProperties: false }),
      Type.Object({
        machineId: Type.String({ pattern: "^[a-zA-Z0-9][a-zA-Z0-9._:-]{6,158}[a-zA-Z0-9]$" }),
        targetId: Type.String({ pattern: "^[a-zA-Z0-9][a-zA-Z0-9._:-]{6,158}[a-zA-Z0-9]$" }),
        operation: Type.Literal("file_read"),
        path: Type.String({ minLength: 2, maxLength: 4096, pattern: "^/[^\\u0000\\r\\n]+$" }),
        maxBytes: Type.Optional(Type.Integer({ minimum: 1, maximum: 128 * 1024 })),
      }, { additionalProperties: false }),
    ]),
    async execute(toolCallId, params, signal) {
      const capabilityByOperation = {
        host_snapshot: "host.snapshot",
        process_list: "process.list",
        systemd_unit: "systemd.unit",
        journal_tail: "journal.tail",
        file_metadata: "file.metadata",
        file_read: "file.read",
      } as const satisfies Record<typeof params.operation, RemoteCapability>;
      const capability = capabilityByOperation[params.operation];
      const remote = await remoteTarget(
        runtime,
        params.machineId,
        params.targetId,
        capability,
        signal,
      );
      const requestId = randomUUID();
      const base = {
        version: 1 as const,
        requestId,
        deadline: deadline(20),
        machineId: remote.machineId,
        targetId: remote.targetId,
      };
      let request: InspectionRequest;
      switch (params.operation) {
        case "host_snapshot":
          request = { ...base, method: "host.snapshot" };
          break;
        case "process_list":
          request = { ...base, method: "process.list" };
          break;
        case "systemd_unit":
          request = { ...base, method: "systemd.unit", unit: params.unit };
          break;
        case "journal_tail":
          request = {
            ...base,
            method: "journal.tail",
            unit: params.unit,
            ...(params.lines === undefined ? {} : { lines: params.lines }),
          };
          break;
        case "file_metadata":
          request = { ...base, method: "file.metadata", path: params.path };
          break;
        case "file_read":
          request = {
            ...base,
            method: "file.read",
            path: params.path,
            ...(params.maxBytes === undefined ? {} : { maxBytes: params.maxBytes }),
          };
          break;
      }
      const response = await remote.client.inspect(request, signal);
      await audit.append({
        type: "tool",
        toolCallId,
        tool: "ops_inspect",
        request,
        response: {
          version: response.version,
          requestId: response.requestId,
          ok: response.ok,
          auditId: response.auditId,
          dataReturned: response.data !== undefined,
        },
      });
      if (!response.ok) throw new Error(response.error ?? "inspection failed");
      return {
        content: [{ type: "text", text: output(response.data ?? response.summary) }],
        details: { auditId: response.auditId, requestId, machineId: remote.machineId },
      };
    },
  });

  const bash = defineTool({
    name: "ops_bash",
    label: "Run sandboxed shell",
    description:
      "Run an unprivileged, offline Bash command. Only this session's isolated /workspace is writable.",
    parameters: Type.Object({
      command: Type.String({ minLength: 1, maxLength: 32 * 1024 }),
      timeoutSeconds: Type.Optional(Type.Integer({ minimum: 1, maximum: 120 })),
    }),
    executionMode: "sequential",
    async execute(toolCallId, params, signal) {
      const session = await runtime.session();
      const result = await runSandboxedCommand({
        command: params.command,
        timeoutSeconds: params.timeoutSeconds ?? 30,
        workspaceDir: session.workspacePath,
        bwrapPath: config.bwrapPath,
        bashPath: config.bashPath,
        ...(signal === undefined ? {} : { signal }),
      });
      await audit.append({
        type: "tool",
        toolCallId,
        tool: "ops_bash",
        sessionId: session.sessionId,
        command: params.command,
        result,
      });
      const text = [
        `exitCode=${result.exitCode} timedOut=${result.timedOut} truncated=${result.truncated}`,
        result.stdout ? `stdout:\n${result.stdout}` : "",
        result.stderr ? `stderr:\n${result.stderr}` : "",
      ].filter(Boolean).join("\n");
      return { content: [{ type: "text", text }], details: result };
    },
  });

  const artifactCatalog = defineTool({
    name: "ops_artifact_catalog",
    label: "List trusted artifacts",
    description:
      "List immutable artifacts available to an explicit machine target. Kind, identity, publisher, version, digest, and builtin reference are validated.",
    parameters: Type.Object({
      machineId: Type.String({ pattern: "^[a-zA-Z0-9][a-zA-Z0-9._:-]{6,158}[a-zA-Z0-9]$" }),
      targetId: Type.String({ pattern: "^[a-zA-Z0-9][a-zA-Z0-9._:-]{6,158}[a-zA-Z0-9]$" }),
    }),
    async execute(toolCallId, params, signal) {
      const remote = await remoteTarget(
        runtime,
        params.machineId,
        params.targetId,
        "change.prepare",
        signal,
      );
      const artifacts = await remote.client.artifacts(remote.targetId, signal);
      await audit.append({
        type: "tool",
        toolCallId,
        tool: "ops_artifact_catalog",
        machineId: remote.machineId,
        targetId: remote.targetId,
        artifacts: artifacts.map((artifact) => ({
          id: artifact.id,
          kind: artifact.kind,
          version: artifact.version,
          publisher: artifact.publisher,
          digest: artifact.digest,
          artifactRef: artifact.artifactRef,
        })),
      });
      return {
        content: [{ type: "text", text: output(artifacts) }],
        details: { count: artifacts.length },
      };
    },
  });

  const operationSchema = Type.Union([
    Type.Object({
      kind: Type.Literal("package.install"),
      package: Type.String({ pattern: "^[a-zA-Z0-9][a-zA-Z0-9+._-]{0,127}$" }),
      version: Type.Optional(Type.String({ maxLength: 128 })),
    }),
    Type.Object({
      kind: Type.Literal("service.action"),
      unit: Type.String({ pattern: "^[a-zA-Z0-9@_.:-]{1,200}\\.service$" }),
      action: Type.Union([
        Type.Literal("restart"), Type.Literal("reload"), Type.Literal("start"), Type.Literal("stop"),
      ]),
    }),
    Type.Object({
      kind: Type.Literal("file.write"),
      path: Type.String({ minLength: 2, maxLength: 4096 }),
      content: Type.String({ maxLength: 128 * 1024 }),
      mode: Type.Optional(Type.String({ pattern: "^0?[0246]{3}$" })),
    }),
    Type.Object({
      kind: Type.Literal("plugin.install"),
      pluginId: Type.String({ pattern: "^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$" }),
      version: Type.String({ pattern: "^[a-zA-Z0-9][a-zA-Z0-9+.:~_-]{0,127}$" }),
      publisher: Type.String({ pattern: "^[a-zA-Z0-9][a-zA-Z0-9._/@:-]{0,159}$" }),
      digest: Type.String({ pattern: "^sha256:[a-f0-9]{64}$" }),
      artifactRef: Type.String({ pattern: "^builtin:sha256:[a-f0-9]{64}$" }),
    }),
    Type.Object({
      kind: Type.Literal("plugin.register"),
      pluginId: Type.String({
        pattern: "^(adapter|workload)\\.[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?$",
      }),
      pluginKind: Type.Union([Type.Literal("adapter"), Type.Literal("workload")]),
      version: Type.String({ pattern: "^[a-zA-Z0-9][a-zA-Z0-9+.:~_-]{0,127}$" }),
      publisher: Type.String({ pattern: "^[a-zA-Z0-9][a-zA-Z0-9._/@:-]{0,159}$" }),
      digest: Type.String({ pattern: "^sha256:[a-f0-9]{64}$" }),
      capabilities: Type.Array(Type.String({
        minLength: 1,
        maxLength: 128,
        pattern: "^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*$",
      }), { maxItems: 64, uniqueItems: true }),
      requestedScopes: Type.Array(Type.String({
        minLength: 1,
        maxLength: 128,
        pattern: "^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*$",
      }), { maxItems: 64, uniqueItems: true }),
    }),
    Type.Object({
      kind: Type.Literal("workload.deploy"),
      pluginId: Type.String({ pattern: "^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$" }),
      version: Type.String({ pattern: "^[a-zA-Z0-9][a-zA-Z0-9+.:~_-]{0,127}$" }),
      publisher: Type.String({ pattern: "^[a-zA-Z0-9][a-zA-Z0-9._/@:-]{0,159}$" }),
      digest: Type.String({ pattern: "^sha256:[a-f0-9]{64}$" }),
      artifactRef: Type.String({ pattern: "^builtin:sha256:[a-f0-9]{64}$" }),
    }),
  ]);

  const propose = defineTool({
    name: "ops_propose_change",
    label: "Propose target-scoped change",
    description:
      "Prepare an immutable change for a registered machine and target. An exact standing grant may commit ordinary operations; package/artifact installation, source registration, and workload deployment always remain pending for model-external client approval.",
    parameters: Type.Object({
      machineId: Type.String({ pattern: "^[a-zA-Z0-9][a-zA-Z0-9._:-]{6,158}[a-zA-Z0-9]$" }),
      targetId: Type.String({ pattern: "^[a-zA-Z0-9][a-zA-Z0-9._:-]{6,158}[a-zA-Z0-9]$" }),
      operation: operationSchema,
    }),
    executionMode: "sequential",
    async execute(toolCallId, params, signal) {
      if ((params.operation.kind === "plugin.install" || params.operation.kind === "workload.deploy") &&
          params.operation.artifactRef !== `builtin:${params.operation.digest}`) {
        throw new Error("artifactRef does not match the pinned digest");
      }
      if (params.operation.kind === "plugin.register") {
        if (!params.operation.pluginId.startsWith(`${params.operation.pluginKind}.`)) {
          throw new Error("source plugin ID does not match pluginKind");
        }
        const unsorted = (values: string[]): boolean => values.some((value, index, all) => {
          if (index === 0) return false;
          const previous = all[index - 1];
          return previous !== undefined && previous >= value;
        });
        if (unsorted(params.operation.capabilities) || unsorted(params.operation.requestedScopes)) {
          throw new Error("source plugin capabilities and requestedScopes must be sorted and unique");
        }
      }
      const remote = await remoteTarget(
        runtime,
        params.machineId,
        params.targetId,
        "change.prepare",
        signal,
      );
      let operation = params.operation as RootOperation;
      if (params.operation.kind === "service.action" || params.operation.kind === "file.write") {
        const base = await currentBaseWorkload(runtime, baseWorkload);
        operation = {
          ...params.operation,
          pluginId: "workload.base",
          pluginDigest: base.digest,
        };
      }
      const requestId = randomUUID();
      const request = {
        version: 1 as const,
        requestId,
        deadline: deadline(60),
        machineId: remote.machineId,
        targetId: remote.targetId,
        method: "change.prepare" as const,
        operation,
        policyRevision: remote.context.capabilities.policyRevision,
        capabilityRevision: remote.context.capabilities.revision,
      };
      const prepareResponse = await remote.client.prepareChange(request, signal);
      await audit.append({
        type: "tool",
        toolCallId,
        tool: "ops_propose_change",
        request,
        response: prepareResponse,
      });
      if (!prepareResponse.ok) {
        throw new Error(prepareResponse.error ?? "change preparation failed");
      }
      if (!prepareResponse.changeId) throw new Error("server prepared a change without a changeId");
      const authoritative = await readAuthoritativePreparedChange(remote.client, {
        machineId: remote.machineId,
        targetId: remote.targetId,
        changeId: prepareResponse.changeId,
      }, signal);
      await audit.append({
        type: "tool",
        phase: "post-prepare-signed-status",
        toolCallId,
        tool: "ops_propose_change",
        request: authoritative.request,
        response: authoritative.response,
      });
      if (ALWAYS_MANUAL_PREPARE_KINDS.has(params.operation.kind)
        && authoritative.response.state !== "PENDING_APPROVAL") {
        throw new Error(
          `${params.operation.kind} violated the mandatory per-change approval boundary`,
        );
      }
      const preparedChange: ChangeRef = {
        version: 1,
        serverId: remote.registration.serverId,
        machineId: remote.machineId,
        targetId: remote.targetId,
        changeId: authoritative.response.changeId,
      };
      if (authoritative.response.state === "PENDING_APPROVAL") {
        runtime.recordPreparedChange?.(toolCallId, preparedChange);
      }
      const changeRef = encodeChangeRef(preparedChange);
      return {
        content: [{
          type: "text",
          text: `${authoritative.response.summary ?? prepareResponse.summary ?? "Change prepared."}\nmachineId=${remote.machineId}\ntargetId=${remote.targetId}\nchangeRef=${changeRef}\n${preparedChangeInstruction(authoritative.response.state)}`,
        }],
        details: {
          auditId: authoritative.response.auditId,
          machineId: remote.machineId,
          targetId: remote.targetId,
          changeId: authoritative.response.changeId,
          changeRef,
          state: authoritative.response.state,
        },
      };
    },
  });

  const status = defineTool({
    name: "ops_change_status",
    label: "Get target-scoped change status",
    description: "Read authoritative status for a change on its registered machine and target.",
    parameters: Type.Object({
      machineId: Type.String({ pattern: "^[a-zA-Z0-9][a-zA-Z0-9._:-]{6,158}[a-zA-Z0-9]$" }),
      targetId: Type.String({ pattern: "^[a-zA-Z0-9][a-zA-Z0-9._:-]{6,158}[a-zA-Z0-9]$" }),
      changeId: Type.String({ pattern: "^[a-zA-Z0-9][a-zA-Z0-9._-]{6,158}[a-zA-Z0-9]$" }),
    }),
    async execute(toolCallId, params, signal) {
      const remote = await remoteTarget(
        runtime,
        params.machineId,
        params.targetId,
        "change.status",
        signal,
      );
      const request = {
        version: 1 as const,
        requestId: randomUUID(),
        deadline: deadline(20),
        machineId: remote.machineId,
        targetId: remote.targetId,
        method: "change.status" as const,
        changeId: parseChangeId(params.changeId),
      };
      const response = await remote.client.changeStatus(request, signal);
      await audit.append({ type: "tool", toolCallId, tool: "ops_change_status", request, response });
      if (!response.ok) throw new Error(response.error ?? "status lookup failed");
      return { content: [{ type: "text", text: output(response) }], details: response };
    },
  });

  let tools = config.sandboxEnabled
    ? [machineList, machineDescribe, inspect, bash, artifactCatalog, propose, status]
    : [machineList, machineDescribe, inspect, artifactCatalog, propose, status];
  if (capabilities !== undefined) {
    const capabilityByTool = new Map<string, string>([
      ["ops_machine_list", "machine.list"],
      ["ops_machine_describe", "machine.describe"],
      ["ops_inspect", "target.inspect"],
      ["ops_bash", "command.exec.sandbox"],
      ["ops_artifact_catalog", "artifact.catalog"],
      ["ops_propose_change", "change.prepare"],
      ["ops_change_status", "change.status"],
    ]);
    tools = tools.filter((tool) => capabilities.has(capabilityByTool.get(tool.name) ?? ""));
  }
  return tools;
}

async function revalidateCurrentPVEPlugin(
  config: AgentConfig,
  runtime: OpsToolRuntime,
  sessionPlugin: ActiveSourcePlugin,
): Promise<ActiveSourcePlugin> {
  if (sessionPlugin.kind !== "workload"
    || !/^workload\.[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?$/u.test(sessionPlugin.pluginId)
    || !/^sha256:[a-f0-9]{64}$/u.test(sessionPlugin.digest)) {
    throw new Error("typed PVE provider requires a valid source-workload caller");
  }
  const current = await (runtime.sourcePluginLoader === undefined
    ? loadActiveSourcePlugin(config, sessionPlugin.pluginId)
    : runtime.sourcePluginLoader(sessionPlugin.pluginId));
  if (!sameApprovedPlugin(current, sessionPlugin)) {
    throw new Error(`${sessionPlugin.pluginId} registration changed; reopen the agent session`);
  }
  return current;
}

export function createPVETypedProviderTools(
  config: AgentConfig,
  audit: AuditLog,
  runtime: OpsToolRuntime,
  plugin: ActiveSourcePlugin,
): ToolDefinition[] {
  if (plugin.kind !== "workload"
    || !/^workload\.[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?$/u.test(plugin.pluginId)
    || !/^sha256:[a-f0-9]{64}$/u.test(plugin.digest)) {
    throw new Error("typed PVE provider requires a valid source-workload caller");
  }
  const pveInspect = defineTool({
    name: "ops_pve_inspect",
    label: "Inspect Proxmox VE",
    description:
      "Run a digest-approved source workload PVE read operation. PVE output is bounded, typed, and untrusted.",
    parameters: Type.Union([
      Type.Object({
        machineId: Type.String({ pattern: "^[a-zA-Z0-9][a-zA-Z0-9._:-]{6,158}[a-zA-Z0-9]$" }),
        targetId: Type.String({ pattern: "^[a-zA-Z0-9][a-zA-Z0-9._:-]{6,158}[a-zA-Z0-9]$" }),
        operation: Type.Literal("cluster_status"),
      }, { additionalProperties: false }),
      Type.Object({
        machineId: Type.String({ pattern: "^[a-zA-Z0-9][a-zA-Z0-9._:-]{6,158}[a-zA-Z0-9]$" }),
        targetId: Type.String({ pattern: "^[a-zA-Z0-9][a-zA-Z0-9._:-]{6,158}[a-zA-Z0-9]$" }),
        operation: Type.Literal("node_status"),
        node: Type.String({ pattern: "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$" }),
      }, { additionalProperties: false }),
      Type.Object({
        machineId: Type.String({ pattern: "^[a-zA-Z0-9][a-zA-Z0-9._:-]{6,158}[a-zA-Z0-9]$" }),
        targetId: Type.String({ pattern: "^[a-zA-Z0-9][a-zA-Z0-9._:-]{6,158}[a-zA-Z0-9]$" }),
        operation: Type.Literal("storage_status"),
        node: Type.String({ pattern: "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$" }),
        storage: Type.String({ pattern: "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$" }),
      }, { additionalProperties: false }),
      Type.Object({
        machineId: Type.String({ pattern: "^[a-zA-Z0-9][a-zA-Z0-9._:-]{6,158}[a-zA-Z0-9]$" }),
        targetId: Type.String({ pattern: "^[a-zA-Z0-9][a-zA-Z0-9._:-]{6,158}[a-zA-Z0-9]$" }),
        operation: Type.Literal("task_status"),
        node: Type.String({ pattern: "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$" }),
        upid: Type.String({
          minLength: 16,
          maxLength: 512,
          pattern: "^UPID:[A-Za-z0-9][A-Za-z0-9._-]{0,63}:[A-Fa-f0-9]+:[A-Fa-f0-9]+:[A-Fa-f0-9]+:[A-Za-z0-9._-]+:[^/:]{0,128}:[^/:]{1,128}:$",
        }),
      }, { additionalProperties: false }),
      Type.Object({
        machineId: Type.String({ pattern: "^[a-zA-Z0-9][a-zA-Z0-9._:-]{6,158}[a-zA-Z0-9]$" }),
        targetId: Type.String({ pattern: "^[a-zA-Z0-9][a-zA-Z0-9._:-]{6,158}[a-zA-Z0-9]$" }),
        operation: Type.Literal("guest_status"),
        node: Type.String({ pattern: "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$" }),
        guestType: Type.Union([Type.Literal("qemu"), Type.Literal("lxc")]),
        vmid: Type.Integer({ minimum: 100, maximum: 999999999 }),
      }, { additionalProperties: false }),
    ]),
    async execute(toolCallId, params, signal) {
      const currentPlugin = await revalidateCurrentPVEPlugin(config, runtime, plugin);
      if (params.operation === "task_status" && !params.upid.startsWith(`UPID:${params.node}:`)) {
        throw new Error("PVE task UPID is not bound to the selected node");
      }
      const capabilityByOperation = {
        cluster_status: "pve.cluster.status",
        node_status: "pve.node.status",
        storage_status: "pve.storage.status",
        task_status: "pve.task.status",
        guest_status: "pve.guest.status",
      } as const satisfies Record<typeof params.operation, RemoteCapability>;
      const remote = await remoteTarget(
        runtime,
        params.machineId,
        params.targetId,
        capabilityByOperation[params.operation],
        signal,
      );
      const base = {
        version: 1 as const,
        requestId: randomUUID(),
        deadline: deadline(20),
        machineId: remote.machineId,
        targetId: remote.targetId,
        pluginId: currentPlugin.pluginId,
        pluginDigest: currentPlugin.digest,
      };
      let request: InspectionRequest;
      switch (params.operation) {
        case "cluster_status":
          request = { ...base, method: "pve.cluster.status" };
          break;
        case "node_status":
          request = { ...base, method: "pve.node.status", node: params.node };
          break;
        case "storage_status":
          request = {
            ...base,
            method: "pve.storage.status",
            node: params.node,
            storage: params.storage,
          };
          break;
        case "task_status":
          request = { ...base, method: "pve.task.status", node: params.node, upid: params.upid };
          break;
        case "guest_status":
          request = {
            ...base,
            method: "pve.guest.status",
            node: params.node,
            guestType: params.guestType,
            vmid: params.vmid,
          };
          break;
      }
      const response = await remote.client.inspect(request, signal);
      await audit.append({
        type: "tool",
        toolCallId,
        tool: "ops_pve_inspect",
        pluginId: currentPlugin.pluginId,
        pluginDigest: currentPlugin.digest,
        request,
        response: {
          requestId: response.requestId,
          ok: response.ok,
          auditId: response.auditId,
          dataReturned: response.data !== undefined,
        },
      });
      if (!response.ok) throw new Error(response.error ?? "PVE inspection failed");
      return {
        content: [{ type: "text", text: output(response.data ?? response.summary) }],
        details: { auditId: response.auditId, requestId: request.requestId },
      };
    },
  });

  const pveRecoveryParentSchema = Type.Optional(Type.String({
    pattern: "^pve-change-[a-zA-Z0-9._-]{8,149}$",
  }));
  const pveOperationSchema = Type.Union([
    Type.Object({
      kind: Type.Literal("pve.guest.action"),
      recoveryOfChangeId: pveRecoveryParentSchema,
      node: Type.String({ pattern: "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$" }),
      guestType: Type.Union([Type.Literal("qemu"), Type.Literal("lxc")]),
      vmid: Type.Integer({ minimum: 100, maximum: 999999999 }),
      action: Type.Union([
        Type.Literal("start"), Type.Literal("shutdown"), Type.Literal("stop"), Type.Literal("reboot"),
      ]),
    }, { additionalProperties: false }),
    Type.Object({
      kind: Type.Literal("pve.snapshot.create"),
      recoveryOfChangeId: pveRecoveryParentSchema,
      node: Type.String({ pattern: "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$" }),
      guestType: Type.Union([Type.Literal("qemu"), Type.Literal("lxc")]),
      vmid: Type.Integer({ minimum: 100, maximum: 999999999 }),
      snapshot: Type.String({ pattern: "^(?!current$)[A-Za-z0-9][A-Za-z0-9._-]{0,63}$" }),
      description: Type.Optional(Type.String({ maxLength: 1024, pattern: "^(?!-)[^\\u0000\\r\\n]*$" })),
    }, { additionalProperties: false }),
    Type.Object({
      kind: Type.Union([Type.Literal("pve.snapshot.delete"), Type.Literal("pve.snapshot.rollback")]),
      recoveryOfChangeId: pveRecoveryParentSchema,
      node: Type.String({ pattern: "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$" }),
      guestType: Type.Union([Type.Literal("qemu"), Type.Literal("lxc")]),
      vmid: Type.Integer({ minimum: 100, maximum: 999999999 }),
      snapshot: Type.String({ pattern: "^(?!current$)[A-Za-z0-9][A-Za-z0-9._-]{0,63}$" }),
      backupStorage: Type.String({ pattern: "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$" }),
    }, { additionalProperties: false }),
    Type.Object({
      kind: Type.Literal("pve.guest.backup"),
      recoveryOfChangeId: pveRecoveryParentSchema,
      node: Type.String({ pattern: "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$" }),
      guestType: Type.Union([Type.Literal("qemu"), Type.Literal("lxc")]),
      vmid: Type.Integer({ minimum: 100, maximum: 999999999 }),
      storage: Type.String({ pattern: "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$" }),
    }, { additionalProperties: false }),
    Type.Object({
      kind: Type.Literal("pve.guest.restore"),
      recoveryOfChangeId: pveRecoveryParentSchema,
      node: Type.String({ pattern: "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$" }),
      guestType: Type.Union([Type.Literal("qemu"), Type.Literal("lxc")]),
      vmid: Type.Integer({ minimum: 100, maximum: 999999999 }),
      backupVolume: Type.String({
        minLength: 24,
        maxLength: 256,
        pattern: "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}:backup/vzdump-(qemu|lxc)-[1-9][0-9]{2,8}-[A-Za-z0-9_.:+-]+\\.(vma|tar)(\\.(zst|gz|lzo))?$",
      }),
      storage: Type.String({ pattern: "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$" }),
    }, { additionalProperties: false }),
    Type.Object({
      kind: Type.Literal("pve.guest.migrate"),
      recoveryOfChangeId: pveRecoveryParentSchema,
      node: Type.String({ pattern: "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$" }),
      guestType: Type.Union([Type.Literal("qemu"), Type.Literal("lxc")]),
      vmid: Type.Integer({ minimum: 100, maximum: 999999999 }),
      targetNode: Type.String({ pattern: "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$" }),
      online: Type.Boolean(),
      restart: Type.Boolean(),
      withLocalDisks: Type.Boolean(),
    }, { additionalProperties: false }),
  ]);

  const pvePropose = defineTool({
    name: "ops_pve_propose",
    label: "Propose Proxmox VE change",
    description:
      "Prepare a typed PVE change. The active source workload identity and digest are injected by the harness. recoveryOfChangeId creates a separately reviewed recovery child for the same locked cluster-global VMID and is never standing-authorized.",
    parameters: Type.Object({
      machineId: Type.String({ pattern: "^[a-zA-Z0-9][a-zA-Z0-9._:-]{6,158}[a-zA-Z0-9]$" }),
      targetId: Type.String({ pattern: "^[a-zA-Z0-9][a-zA-Z0-9._:-]{6,158}[a-zA-Z0-9]$" }),
      operation: pveOperationSchema,
    }, { additionalProperties: false }),
    executionMode: "sequential",
    async execute(toolCallId, params, signal) {
      const currentPlugin = await revalidateCurrentPVEPlugin(config, runtime, plugin);
      if (params.operation.kind === "pve.guest.restore"
        && !params.operation.backupVolume.includes(
          `/vzdump-${params.operation.guestType}-${params.operation.vmid}-`,
        )) {
        throw new Error("PVE backup volume does not match the selected guest type and VMID");
      }
      if (params.operation.kind === "pve.guest.migrate") {
        if (params.operation.node === params.operation.targetNode) {
          throw new Error("PVE migration target must differ from the source node");
        }
        if (params.operation.guestType === "qemu" && params.operation.restart) {
          throw new Error("QEMU migration cannot request the LXC restart mode");
        }
        if (params.operation.guestType === "lxc"
          && (params.operation.online || params.operation.withLocalDisks)) {
          throw new Error("LXC migration cannot request QEMU online or local-disk flags");
        }
      }
      const operation = {
        ...params.operation,
        pluginId: currentPlugin.pluginId,
        pluginDigest: currentPlugin.digest,
      } as RootOperation;
      const remote = await remoteTarget(
        runtime,
        params.machineId,
        params.targetId,
        "change.prepare",
        signal,
      );
      const requestId = randomUUID();
      const request = {
        version: 1 as const,
        requestId,
        deadline: deadline(60),
        machineId: remote.machineId,
        targetId: remote.targetId,
        method: "change.prepare" as const,
        operation,
        policyRevision: remote.context.capabilities.policyRevision,
        capabilityRevision: remote.context.capabilities.revision,
      };
      const prepareResponse = await remote.client.prepareChange(request, signal);
      await audit.append({
        type: "tool",
        toolCallId,
        tool: "ops_pve_propose",
        pluginId: currentPlugin.pluginId,
        pluginDigest: currentPlugin.digest,
        request,
        response: prepareResponse,
      });
      if (!prepareResponse.ok) {
        throw new Error(prepareResponse.error ?? "PVE change preparation failed");
      }
      if (!prepareResponse.changeId) {
        throw new Error("server prepared a PVE change without a changeId");
      }
      const authoritative = await readAuthoritativePreparedChange(remote.client, {
        machineId: remote.machineId,
        targetId: remote.targetId,
        changeId: prepareResponse.changeId,
      }, signal);
      await audit.append({
        type: "tool",
        phase: "post-prepare-signed-status",
        toolCallId,
        tool: "ops_pve_propose",
        pluginId: currentPlugin.pluginId,
        pluginDigest: currentPlugin.digest,
        request: authoritative.request,
        response: authoritative.response,
      });
      const preparedChange: ChangeRef = {
        version: 1,
        serverId: remote.registration.serverId,
        machineId: remote.machineId,
        targetId: remote.targetId,
        changeId: authoritative.response.changeId,
      };
      if (authoritative.response.state === "PENDING_APPROVAL") {
        runtime.recordPreparedChange?.(toolCallId, preparedChange);
      }
      const changeRef = encodeChangeRef(preparedChange);
      return {
        content: [{
          type: "text",
          text: `${authoritative.response.summary ?? prepareResponse.summary ?? "PVE change prepared."}\nmachineId=${remote.machineId}\ntargetId=${remote.targetId}\nchangeRef=${changeRef}\n${preparedChangeInstruction(authoritative.response.state)}`,
        }],
        details: {
          auditId: authoritative.response.auditId,
          machineId: remote.machineId,
          targetId: remote.targetId,
          changeId: authoritative.response.changeId,
          changeRef,
          state: authoritative.response.state,
          pluginDigest: currentPlugin.digest,
        },
      };
    },
  });

  return [pveInspect, pvePropose];
}
