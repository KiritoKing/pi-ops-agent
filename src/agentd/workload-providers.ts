import { createHash, randomUUID } from "node:crypto";
import { Type } from "typebox";
import { Check } from "typebox/value";
import { defineTool, type ToolDefinition } from "@earendil-works/pi-coding-agent";
import type { AgentConfig } from "../shared/config.js";
import { encodeChangeRef, type ChangeRef } from "../shared/approval.js";
import {
  parseMachineId,
  parseTargetId,
  type MachineId,
  type TargetId,
} from "../shared/domain.js";
import type { RootOperation } from "../shared/messages.js";
import { deadline } from "../shared/rpc.js";
import type { RemoteCapability } from "../shared/server-protocol.js";
import { requireString } from "../shared/guards.js";
import { redactText } from "../shared/redaction.js";
import { requireExactRecord } from "../shared/strict.js";
import type { AuditLog } from "./audit.js";
import type { MachineContext } from "./machine-context.js";
import {
  createHttpsOpsServerClient,
  type OpsServerClient,
} from "./ops-server-client.js";
import type { ServerRegistration } from "./server-registry.js";
import {
  createOpsTools,
  createPVETypedProviderTools,
  type OpsToolRuntime,
} from "./tools.js";
import type { ActiveSourcePlugin } from "../shared/source-plugin.js";
import {
  preparedChangeInstruction,
  readAuthoritativePreparedChange,
} from "./change-preparation.js";

const MACHINE_ID_PATTERN = "^[a-zA-Z0-9][a-zA-Z0-9._:-]{6,158}[a-zA-Z0-9]$";
const ABSOLUTE_BACKUP_PATH_PATTERN = "^/(?!$)(?!.*(?:^|/)\\.\\.(?:/|$))[^\\u0000\\r\\n]+$";

export interface TrustedWorkloadProviderPolicy {
  name: string;
  requiredScopes: readonly string[];
  executionMode: "parallel" | "sequential";
}

export interface TrustedWorkloadProvider extends TrustedWorkloadProviderPolicy {
  invoke(
    toolCallId: string,
    input: unknown,
    signal: AbortSignal | undefined,
    caller: ActiveSourcePlugin,
  ): Promise<unknown>;
}

export interface TrustedWorkloadProviderCatalog {
  known: ReadonlyMap<string, TrustedWorkloadProviderPolicy>;
  active: ReadonlyMap<string, TrustedWorkloadProvider>;
}

const PROVIDER_BINDINGS = Object.freeze([
  Object.freeze({
    provider: "artifact.catalog",
    tool: "ops_artifact_catalog",
    requiredScopes: Object.freeze(["control.target.prepare"]),
    executionMode: "parallel" as const,
    baseOnly: true,
  }),
  Object.freeze({
    provider: "change.prepare",
    tool: "ops_propose_change",
    requiredScopes: Object.freeze(["control.target.prepare"]),
    executionMode: "sequential" as const,
    baseOnly: true,
  }),
  Object.freeze({
    provider: "change.status",
    tool: "ops_change_status",
    requiredScopes: Object.freeze(["control.target.status"]),
    executionMode: "parallel" as const,
    baseOnly: true,
  }),
  Object.freeze({
    provider: "command.exec.sandbox",
    tool: "ops_bash",
    requiredScopes: Object.freeze(["command.exec.sandbox"]),
    executionMode: "sequential" as const,
    baseOnly: true,
  }),
  Object.freeze({
    provider: "machine.describe",
    tool: "ops_machine_describe",
    requiredScopes: Object.freeze(["control.machine.read"]),
    executionMode: "parallel" as const,
    baseOnly: true,
  }),
  Object.freeze({
    provider: "machine.list",
    tool: "ops_machine_list",
    requiredScopes: Object.freeze(["control.machine.read"]),
    executionMode: "parallel" as const,
    baseOnly: true,
  }),
  Object.freeze({
    provider: "target.inspect",
    tool: "ops_inspect",
    requiredScopes: Object.freeze(["control.target.inspect"]),
    executionMode: "parallel" as const,
    baseOnly: false,
  }),
] as const);

const BREAKGLASS_POLICY: TrustedWorkloadProviderPolicy = Object.freeze({
  name: "breakglass.prepare",
  requiredScopes: Object.freeze(["control.breakglass.prepare"]),
  executionMode: "sequential",
});

const WORKLOAD_SERVICE_POLICY: TrustedWorkloadProviderPolicy = Object.freeze({
  name: "workload.service.manage",
  requiredScopes: Object.freeze(["control.workload.service.manage"]),
  executionMode: "sequential",
});

const WORKLOAD_COMMAND_POLICY: TrustedWorkloadProviderPolicy = Object.freeze({
  name: "workload.command.inspect",
  requiredScopes: Object.freeze(["control.workload.command.inspect"]),
  executionMode: "parallel",
});

const WORKLOAD_JSON_CONFIG_POLICY: TrustedWorkloadProviderPolicy = Object.freeze({
  name: "workload.json-config.edit",
  requiredScopes: Object.freeze(["control.workload.json-config.edit"]),
  executionMode: "sequential",
});

const PVE_PROVIDER_POLICIES = Object.freeze([
  Object.freeze({
    provider: "pve.backup",
    requiredScopes: Object.freeze(["pve.backup.prepare"]),
    executionMode: "sequential" as const,
    tool: "ops_pve_propose",
    operations: Object.freeze(["pve.guest.backup"]),
  }),
  Object.freeze({
    provider: "pve.cluster.inspect",
    requiredScopes: Object.freeze(["pve.cluster.read"]),
    executionMode: "parallel" as const,
    tool: "ops_pve_inspect",
    operations: Object.freeze(["cluster_status"]),
  }),
  Object.freeze({
    provider: "pve.guest.inspect",
    requiredScopes: Object.freeze(["pve.guest.read"]),
    executionMode: "parallel" as const,
    tool: "ops_pve_inspect",
    operations: Object.freeze(["guest_status"]),
  }),
  Object.freeze({
    provider: "pve.guest.lifecycle",
    requiredScopes: Object.freeze(["pve.guest.lifecycle"]),
    executionMode: "sequential" as const,
    tool: "ops_pve_propose",
    operations: Object.freeze(["pve.guest.action"]),
  }),
  Object.freeze({
    provider: "pve.guest.migrate",
    requiredScopes: Object.freeze(["pve.guest.migrate"]),
    executionMode: "sequential" as const,
    tool: "ops_pve_propose",
    operations: Object.freeze(["pve.guest.migrate"]),
  }),
  Object.freeze({
    provider: "pve.guest.restore",
    requiredScopes: Object.freeze(["pve.guest.restore"]),
    executionMode: "sequential" as const,
    tool: "ops_pve_propose",
    operations: Object.freeze(["pve.guest.restore"]),
  }),
  Object.freeze({
    provider: "pve.node.inspect",
    requiredScopes: Object.freeze(["pve.node.read"]),
    executionMode: "parallel" as const,
    tool: "ops_pve_inspect",
    operations: Object.freeze(["node_status"]),
  }),
  Object.freeze({
    provider: "pve.snapshot.manage",
    requiredScopes: Object.freeze(["pve.snapshot.manage"]),
    executionMode: "sequential" as const,
    tool: "ops_pve_propose",
    operations: Object.freeze([
      "pve.snapshot.create",
      "pve.snapshot.delete",
      "pve.snapshot.rollback",
    ]),
  }),
  Object.freeze({
    provider: "pve.storage.inspect",
    requiredScopes: Object.freeze(["pve.storage.read"]),
    executionMode: "parallel" as const,
    tool: "ops_pve_inspect",
    operations: Object.freeze(["storage_status"]),
  }),
  Object.freeze({
    provider: "pve.task.inspect",
    requiredScopes: Object.freeze(["pve.task.read"]),
    executionMode: "parallel" as const,
    tool: "ops_pve_inspect",
    operations: Object.freeze(["task_status"]),
  }),
] as const);

export interface TrustedWorkloadRegistrations {
  base: ActiveSourcePlugin;
}

const WORKLOAD_PLUGIN_ID_PATTERN = /^workload\.[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?$/u;
const WORKLOAD_PROFILE_KEY_PATTERN = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+){0,7}$/u;

function exactPluginCaller(caller: ActiveSourcePlugin, expected: ActiveSourcePlugin): boolean {
  return caller.pluginId === expected.pluginId && caller.kind === expected.kind &&
    caller.version === expected.version && caller.publisher === expected.publisher &&
    caller.digest === expected.digest &&
    caller.capabilities.length === expected.capabilities.length &&
    caller.capabilities.every((value, index) => value === expected.capabilities[index]) &&
    caller.requestedScopes.length === expected.requestedScopes.length &&
    caller.requestedScopes.every((value, index) => value === expected.requestedScopes[index]);
}

function requirePluginCaller(
  policy: TrustedWorkloadProviderPolicy,
  caller: ActiveSourcePlugin,
  expected: ActiveSourcePlugin,
): void {
  if (!exactPluginCaller(caller, expected)) {
    throw new Error(
      `trusted provider ${policy.name} rejected a caller outside ${expected.pluginId}@${expected.digest}`,
    );
  }
}

function wrapToolProvider(
  policy: TrustedWorkloadProviderPolicy,
  tool: ToolDefinition,
): TrustedWorkloadProvider {
  return {
    ...policy,
    async invoke(toolCallId, input, signal) {
      if (!Check(tool.parameters, input)) {
        throw new Error(`trusted provider ${policy.name} rejected plugin input`);
      }
      return await tool.execute(
        toolCallId,
        input,
        signal,
        undefined,
        undefined as never,
      );
    },
  };
}

function requireGenericWorkloadCaller(caller: ActiveSourcePlugin): void {
  if (caller.kind !== "workload" || !WORKLOAD_PLUGIN_ID_PATTERN.test(caller.pluginId)
    || !/^sha256:[a-f0-9]{64}$/u.test(caller.digest)) {
    throw new Error("trusted provider rejected an invalid source-workload caller identity");
  }
}

async function revalidateCurrentWorkloadCaller(
  runtime: OpsToolRuntime,
  caller: ActiveSourcePlugin,
): Promise<ActiveSourcePlugin> {
  requireGenericWorkloadCaller(caller);
  if (runtime.sourcePluginLoader === undefined) {
    throw new Error("trusted provider cannot revalidate the active source-workload caller");
  }
  const current = await runtime.sourcePluginLoader(caller.pluginId);
  if (!exactPluginCaller(caller, current)) {
    throw new Error(`${caller.pluginId} current registration changed; reopen the agent session`);
  }
  return current;
}

function pveOperation(input: unknown): string | undefined {
  if (typeof input !== "object" || input === null || Array.isArray(input)) return undefined;
  const operation = (input as { operation?: unknown }).operation;
  if (typeof operation === "string") return operation;
  if (typeof operation !== "object" || operation === null || Array.isArray(operation)) {
    return undefined;
  }
  const kind = (operation as { kind?: unknown }).kind;
  return typeof kind === "string" ? kind : undefined;
}

function wrapRestrictedPVEProvider(
  policy: TrustedWorkloadProviderPolicy,
  toolName: string,
  operations: readonly string[],
  config: AgentConfig,
  audit: AuditLog,
  runtime: OpsToolRuntime,
): TrustedWorkloadProvider {
  return {
    ...policy,
    async invoke(toolCallId, input, signal, caller) {
      if (caller.pluginId === "workload.base") {
        throw new Error("workload.base cannot call a business provider");
      }
      const operation = pveOperation(input);
      if (operation === undefined || !operations.includes(operation)) {
        throw new Error(`trusted provider ${policy.name} rejected an operation outside its fixed PVE profile`);
      }
      const current = await revalidateCurrentWorkloadCaller(runtime, caller);
      const tool = createPVETypedProviderTools(config, audit, runtime, current)
        .find((candidate) => candidate.name === toolName);
      if (tool === undefined) throw new Error(`trusted provider ${policy.name} is unavailable`);
      const provider = wrapToolProvider(policy, tool);
      return await provider.invoke(toolCallId, input, signal, caller);
    },
  };
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

interface WorkloadCommandResult {
  kind: "workload.command.inspect-result/v1";
  pluginId: string;
  pluginDigest: string;
  profileKey: string;
  targetAccount: string;
  runAsAccount: string;
  output: string;
  truncated: boolean;
  executableTrust: "root-owned-nonwritable-path";
}

function boundedUtf8Output(value: string, maximum: number): { text: string; truncated: boolean } {
  let bytes = 0;
  let end = 0;
  for (const character of value) {
    const size = Buffer.byteLength(character, "utf8");
    if (bytes + size > maximum) return { text: value.slice(0, end), truncated: true };
    bytes += size;
    end += character.length;
  }
  return { text: value, truncated: false };
}

function parseWorkloadCommandResult(
  value: unknown,
  caller: ActiveSourcePlugin,
  profileKey: string,
): WorkloadCommandResult {
  const result = requireExactRecord(value, "workload command result", [
    "kind", "pluginId", "pluginDigest", "profileKey", "targetAccount", "runAsAccount",
    "output", "truncated", "executableTrust",
  ]);
  const kind = requireString(result.kind, "workload command result.kind", { max: 64 });
  const pluginId = requireString(result.pluginId, "workload command result.pluginId", {
    pattern: WORKLOAD_PLUGIN_ID_PATTERN,
  });
  const pluginDigest = requireString(result.pluginDigest, "workload command result.pluginDigest", {
    pattern: /^sha256:[a-f0-9]{64}$/u,
  });
  const actualProfileKey = requireString(result.profileKey, "workload command result.profileKey", {
    max: 96,
    pattern: WORKLOAD_PROFILE_KEY_PATTERN,
  });
  if (kind !== "workload.command.inspect-result/v1" || pluginId !== caller.pluginId
    || pluginDigest !== caller.digest || actualProfileKey !== profileKey) {
    throw new Error("workload command result does not match the invoking digest-bound profile");
  }
  const targetAccount = requireString(
    result.targetAccount,
    "workload command result.targetAccount",
    { max: 32, pattern: /^[a-z_][a-z0-9_-]{0,31}$/u },
  );
  const runAsAccount = requireString(
    result.runAsAccount,
    "workload command result.runAsAccount",
    { max: 32, pattern: /^[a-z_][a-z0-9_-]{0,31}$/u },
  );
  const output = requireString(result.output, "workload command result.output", {
    min: 0,
    max: 64 * 1024,
  });
  if (/[^\t\n\x20-\x7e\u0080-\u{10ffff}]/u.test(output)) {
    throw new Error("workload command result.output contains unsafe control characters");
  }
  if (typeof result.truncated !== "boolean") {
    throw new Error("workload command result.truncated must be boolean");
  }
  const executableTrust = requireString(
    result.executableTrust,
    "workload command result.executableTrust",
    { max: 64 },
  );
  if (executableTrust !== "root-owned-nonwritable-path") {
    throw new Error("workload command result has no trusted executable path evidence");
  }
  const redacted = boundedUtf8Output(redactText(output), 64 * 1024);
  return {
    kind: "workload.command.inspect-result/v1",
    pluginId,
    pluginDigest,
    profileKey: actualProfileKey,
    targetAccount,
    runAsAccount,
    output: redacted.text,
    truncated: result.truncated || redacted.truncated,
    executableTrust,
  };
}

function createWorkloadCommandProvider(
  audit: AuditLog,
  runtime: OpsToolRuntime,
): TrustedWorkloadProvider {
  const parameters = Type.Object({
    machineId: Type.String({ pattern: MACHINE_ID_PATTERN }),
    targetId: Type.String({ pattern: MACHINE_ID_PATTERN }),
    profileKey: Type.String({ maxLength: 96, pattern: WORKLOAD_PROFILE_KEY_PATTERN.source }),
  }, { additionalProperties: false });
  return {
    ...WORKLOAD_COMMAND_POLICY,
    async invoke(toolCallId, input, signal, caller) {
      if (caller.pluginId === "workload.base") {
        throw new Error("workload.base cannot call a business command provider");
      }
      if (!Check(parameters, input)) {
        throw new Error("trusted provider workload.command.inspect rejected plugin input");
      }
      const current = await revalidateCurrentWorkloadCaller(runtime, caller);
      const params = input;
      const remote = await remoteTarget(
        runtime,
        params.machineId,
        params.targetId,
        "workload.command.inspect",
        signal,
      );
      const request = {
        version: 1 as const,
        requestId: randomUUID(),
        deadline: deadline(135),
        machineId: remote.machineId,
        targetId: remote.targetId,
        method: "workload.command.inspect" as const,
        pluginId: current.pluginId,
        pluginDigest: current.digest,
        profileKey: params.profileKey,
      };
      const response = await remote.client.workloadCommandInspect(request, signal);
      if (!response.ok) {
        throw new Error(response.error ?? "workload command inspection failed");
      }
      const result = parseWorkloadCommandResult(response.data, current, params.profileKey);
      const outputBytes = Buffer.byteLength(result.output, "utf8");
      const outputDigest = `sha256:${createHash("sha256").update(result.output, "utf8").digest("hex")}`;
      await audit.append({
        type: "tool",
        toolCallId,
        tool: WORKLOAD_COMMAND_POLICY.name,
        pluginId: current.pluginId,
        pluginDigest: current.digest,
        request,
        response: {
          version: response.version,
          requestId: response.requestId,
          ok: response.ok,
          auditId: response.auditId,
          summary: response.summary,
          brokerReceipt: response.brokerReceipt,
          data: {
            kind: result.kind,
            pluginId: result.pluginId,
            pluginDigest: result.pluginDigest,
            profileKey: result.profileKey,
            targetAccount: result.targetAccount,
            runAsAccount: result.runAsAccount,
            truncated: result.truncated,
            executableTrust: result.executableTrust,
            outputDigest,
            outputBytes,
          },
        },
      });
      return {
        content: [{
          type: "text" as const,
          text: result.output,
        }],
        details: {
          auditId: response.auditId,
          machineId: remote.machineId,
          targetId: remote.targetId,
          ...result,
        },
      };
    },
  };
}

function createWorkloadServiceProvider(
  audit: AuditLog,
  runtime: OpsToolRuntime,
): TrustedWorkloadProvider {
  const tool = defineTool({
    name: "ops_workload_service_manage_provider",
    label: "Prepare source-workload service action",
    description: "Prepare one typed, policy-bounded systemd service action for the invoking source workload.",
    parameters: Type.Object({
      machineId: Type.String({ pattern: MACHINE_ID_PATTERN }),
      targetId: Type.String({ pattern: MACHINE_ID_PATTERN }),
      account: Type.String({ pattern: "^[a-z_][a-z0-9_-]{0,31}$" }),
      manager: Type.Union([Type.Literal("system"), Type.Literal("user")]),
      unit: Type.String({ pattern: "^[a-zA-Z0-9@_.:-]{1,200}\\.service$" }),
      action: Type.Union([
        Type.Literal("reload"), Type.Literal("reset-failed"), Type.Literal("restart"),
        Type.Literal("start"), Type.Literal("stop"),
      ]),
    }, { additionalProperties: false }),
    executionMode: "sequential",
    execute() {
      return Promise.reject(new Error("workload service provider requires an injected source caller"));
    },
  });
  return {
    ...WORKLOAD_SERVICE_POLICY,
    async invoke(toolCallId, input, signal, caller) {
      if (caller.pluginId === "workload.base") {
        throw new Error("workload.base cannot call a business provider");
      }
      if (!Check(tool.parameters, input)) {
        throw new Error("trusted provider workload.service.manage rejected plugin input");
      }
      const current = await revalidateCurrentWorkloadCaller(runtime, caller);
      const params = input as {
        machineId: string;
        targetId: string;
        account: string;
        manager: "system" | "user";
        unit: string;
        action: "reload" | "reset-failed" | "restart" | "start" | "stop";
      };
      const remote = await remoteTarget(
        runtime,
        params.machineId,
        params.targetId,
        "change.prepare",
        signal,
      );
      const operation: RootOperation = {
        kind: "workload.service.action",
        pluginId: current.pluginId,
        pluginDigest: current.digest,
        account: params.account,
        manager: params.manager,
        unit: params.unit,
        action: params.action,
      };
      const request = {
        version: 1 as const,
        requestId: randomUUID(),
        deadline: deadline(30),
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
        tool: WORKLOAD_SERVICE_POLICY.name,
        pluginId: current.pluginId,
        pluginDigest: current.digest,
        request,
        response: prepareResponse,
      });
      if (!prepareResponse.ok) {
        throw new Error(prepareResponse.error ?? "workload service action preparation failed");
      }
      if (prepareResponse.changeId === undefined) {
        throw new Error("server prepared a workload service action without a changeId");
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
        tool: WORKLOAD_SERVICE_POLICY.name,
        pluginId: current.pluginId,
        pluginDigest: current.digest,
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
          type: "text" as const,
          text: `${authoritative.response.summary ?? prepareResponse.summary ?? "Workload service action prepared."}\nchangeRef=${changeRef}\n${preparedChangeInstruction(authoritative.response.state)}`,
        }],
        details: {
          auditId: authoritative.response.auditId,
          machineId: remote.machineId,
          targetId: remote.targetId,
          changeId: authoritative.response.changeId,
          changeRef,
          state: authoritative.response.state,
          pluginId: current.pluginId,
          pluginDigest: current.digest,
        },
      };
    },
  };
}

function createWorkloadJSONConfigProvider(
  audit: AuditLog,
  runtime: OpsToolRuntime,
): TrustedWorkloadProvider {
  const taggedValue = Type.Union([
    Type.Object({
      kind: Type.Literal("string"),
      stringValue: Type.String({ minLength: 1, maxLength: 512 }),
    }, { additionalProperties: false }),
    Type.Object({
      kind: Type.Literal("boolean"),
      booleanValue: Type.Boolean(),
    }, { additionalProperties: false }),
    Type.Object({ kind: Type.Literal("clear") }, { additionalProperties: false }),
  ]);
  const tool = defineTool({
    name: "ops_workload_json_config_edit_provider",
    label: "Prepare one policy-mapped JSON config edit",
    description:
      "Prepare one digest-bound semantic field edit. Account, UID, home, config path, selector key, actual JSON field, helper, executable and argv are supplied only by root-owned policy.",
    parameters: Type.Object({
      machineId: Type.String({ pattern: MACHINE_ID_PATTERN }),
      targetId: Type.String({ pattern: MACHINE_ID_PATTERN }),
      profileKey: Type.String({
        minLength: 1,
        maxLength: 96,
        pattern: "^[a-z][a-z0-9]*(?:[._-][a-z0-9]+){0,7}$",
      }),
      selectorValue: Type.String({ minLength: 1, maxLength: 256 }),
      fieldKey: Type.String({ minLength: 1, maxLength: 64, pattern: "^[a-zA-Z][a-zA-Z0-9_-]{0,63}$" }),
      value: taggedValue,
    }, { additionalProperties: false }),
    executionMode: "sequential",
    execute() {
      return Promise.reject(new Error("workload JSON config provider requires an injected source caller"));
    },
  });
  return {
    ...WORKLOAD_JSON_CONFIG_POLICY,
    async invoke(toolCallId, input, signal, caller) {
      if (caller.pluginId === "workload.base") {
        throw new Error("workload.base cannot call a business JSON config provider");
      }
      if (!Check(tool.parameters, input)) {
        throw new Error("trusted provider workload.json-config.edit rejected plugin input");
      }
      const current = await revalidateCurrentWorkloadCaller(runtime, caller);
      const params = input as {
        machineId: string;
        targetId: string;
        profileKey: string;
        selectorValue: string;
        fieldKey: string;
        value:
          | { kind: "string"; stringValue: string }
          | { kind: "boolean"; booleanValue: boolean }
          | { kind: "clear" };
      };
      if (/[\p{Cc}\p{Cf}]/u.test(params.selectorValue)
        || (params.value.kind === "string" && /[\p{Cc}\p{Cf}]/u.test(params.value.stringValue))) {
        throw new Error("trusted provider workload.json-config.edit rejected unsafe text");
      }
      const remote = await remoteTarget(
        runtime,
        params.machineId,
        params.targetId,
        "change.prepare",
        signal,
      );
      const operation: RootOperation = {
        kind: "workload.json-config.edit",
        pluginId: current.pluginId,
        sourceDigest: current.digest,
        profileKey: params.profileKey,
        selectorValue: params.selectorValue,
        fieldKey: params.fieldKey,
        value: params.value,
      };
      const request = {
        version: 1 as const,
        requestId: randomUUID(),
        deadline: deadline(30),
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
        tool: WORKLOAD_JSON_CONFIG_POLICY.name,
        pluginId: current.pluginId,
        pluginDigest: current.digest,
        request,
        response: prepareResponse,
      });
      if (!prepareResponse.ok || prepareResponse.changeId === undefined) {
        throw new Error(prepareResponse.error ?? "workload JSON config edit preparation failed");
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
        tool: WORKLOAD_JSON_CONFIG_POLICY.name,
        pluginId: current.pluginId,
        pluginDigest: current.digest,
        request: authoritative.request,
        response: authoritative.response,
      });
      if (authoritative.response.state !== "PENDING_APPROVAL") {
        throw new Error("workload JSON config edit violated mandatory local per-change approval");
      }
      const preparedChange: ChangeRef = {
        version: 1,
        serverId: remote.registration.serverId,
        machineId: remote.machineId,
        targetId: remote.targetId,
        changeId: authoritative.response.changeId,
      };
      runtime.recordPreparedChange?.(toolCallId, preparedChange);
      const changeRef = encodeChangeRef(preparedChange);
      return {
        content: [{
          type: "text" as const,
          text: `${authoritative.response.summary ?? prepareResponse.summary ?? "JSON config edit prepared."}\nchangeRef=${changeRef}\nThis edit requires local model-external per-change review and approval; the workload cannot approve it.`,
        }],
        details: {
          auditId: authoritative.response.auditId,
          machineId: remote.machineId,
          targetId: remote.targetId,
          changeId: authoritative.response.changeId,
          changeRef,
          state: authoritative.response.state,
          pluginId: current.pluginId,
          sourceDigest: current.digest,
          profileKey: params.profileKey,
          selectorValue: params.selectorValue,
          fieldKey: params.fieldKey,
          valueKind: params.value.kind,
        },
      };
    },
  };
}

async function anyServerAdvertisesBreakglass(runtime: OpsToolRuntime): Promise<boolean> {
  for (const registration of await runtime.servers.list()) {
    if (!registration.enabled) continue;
    try {
      const client = await (runtime.clientFactory ?? createHttpsOpsServerClient)(registration);
      const context = await runtime.contexts.refresh(registration, client);
      if (context.capabilities.operations.includes("breakglass.prepare")) return true;
    } catch {
      // A capability is never inferred from an unavailable or invalid server.
    }
  }
  return false;
}

function createBreakglassProvider(
  audit: AuditLog,
  runtime: OpsToolRuntime,
  baseWorkload: ActiveSourcePlugin,
): TrustedWorkloadProvider {
  const tool = defineTool({
    name: "ops_breakglass_prepare",
    label: "Prepare manually approved root capsule",
    description:
      "Prepare an exact digest-bound root script for work outside standing policy. Missing backup or caller-provided postcondition evidence is shown as critical; this never approves or executes it.",
    parameters: Type.Object({
      machineId: Type.String({ pattern: MACHINE_ID_PATTERN }),
      targetId: Type.String({ pattern: MACHINE_ID_PATTERN }),
      script: Type.String({ minLength: 1, maxLength: 128 * 1024 }),
      backupPaths: Type.Array(Type.String({
        minLength: 2,
        maxLength: 4096,
        pattern: ABSOLUTE_BACKUP_PATH_PATTERN,
      }), { maxItems: 32, uniqueItems: true }),
      verifyScript: Type.Optional(Type.String({ minLength: 1, maxLength: 32 * 1024 })),
      network: Type.Boolean(),
    }, { additionalProperties: false }),
    executionMode: "sequential",
    async execute(toolCallId, params, signal) {
      for (const path of params.backupPaths) {
        if (path === "/" || path.split("/").includes("..")) {
          throw new Error("break-glass backup paths must be clean absolute paths below root");
        }
      }
      const remote = await remoteTarget(
        runtime,
        params.machineId,
        params.targetId,
        "breakglass.prepare",
        signal,
      );
      const operation: RootOperation = {
        kind: "breakglass.script",
        script: params.script,
        backupPaths: params.backupPaths,
        ...(params.verifyScript === undefined ? {} : { verifyScript: params.verifyScript }),
        network: params.network,
      };
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
        tool: "ops_breakglass_prepare",
        request,
        response: prepareResponse,
      });
      if (!prepareResponse.ok) {
        throw new Error(prepareResponse.error ?? "break-glass preparation failed");
      }
      if (!prepareResponse.changeId) {
        throw new Error("server prepared break-glass without a changeId");
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
        tool: "ops_breakglass_prepare",
        request: authoritative.request,
        response: authoritative.response,
      });
      if (authoritative.response.state !== "PENDING_APPROVAL") {
        throw new Error("manual root capsule violated the mandatory per-change approval boundary");
      }
      const preparedChange: ChangeRef = {
        version: 1,
        serverId: remote.registration.serverId,
        machineId: remote.machineId,
        targetId: remote.targetId,
        changeId: authoritative.response.changeId,
      };
      runtime.recordPreparedChange?.(toolCallId, preparedChange);
      const changeRef = encodeChangeRef(preparedChange);
      return {
        content: [{
          type: "text" as const,
          text: `${authoritative.response.summary ?? prepareResponse.summary ?? "Manual root capsule prepared."}\nchangeRef=${changeRef}\nThis critical action requires the local model-external review and exact TTY approval flow.`,
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
  const provider = wrapToolProvider(BREAKGLASS_POLICY, tool);
  return {
    ...provider,
    async invoke(toolCallId, input, signal, caller) {
      requirePluginCaller(BREAKGLASS_POLICY, caller, baseWorkload);
      return await provider.invoke(toolCallId, input, signal, caller);
    },
  };
}

export async function createTrustedBaseProviderCatalog(
  config: AgentConfig,
  audit: AuditLog,
  runtime: OpsToolRuntime,
  registrations: TrustedWorkloadRegistrations,
): Promise<TrustedWorkloadProviderCatalog> {
  if (registrations.base.pluginId !== "workload.base" || registrations.base.kind !== "workload" ||
      !/^sha256:[a-f0-9]{64}$/u.test(registrations.base.digest)) {
    throw new Error("workload.base registration does not match the core provider identity");
  }
  const known = new Map<string, TrustedWorkloadProviderPolicy>();
  const active = new Map<string, TrustedWorkloadProvider>();
  const hiddenTools = new Map(
    createOpsTools(config, audit, runtime, undefined, registrations.base)
      .map((tool) => [tool.name, tool] as const),
  );
  for (const binding of PROVIDER_BINDINGS) {
    const policy: TrustedWorkloadProviderPolicy = {
      name: binding.provider,
      requiredScopes: binding.requiredScopes,
      executionMode: binding.executionMode,
    };
    known.set(binding.provider, policy);
    const tool = hiddenTools.get(binding.tool);
    if (tool !== undefined) {
      const provider = wrapToolProvider(policy, tool);
      active.set(binding.provider, {
        ...provider,
        async invoke(toolCallId, input, signal, caller) {
          if (binding.baseOnly) requirePluginCaller(policy, caller, registrations.base);
          else await revalidateCurrentWorkloadCaller(runtime, caller);
          return await provider.invoke(toolCallId, input, signal, caller);
        },
      });
    }
  }
  known.set(BREAKGLASS_POLICY.name, BREAKGLASS_POLICY);
  if (await anyServerAdvertisesBreakglass(runtime)) {
    active.set(
      BREAKGLASS_POLICY.name,
      createBreakglassProvider(audit, runtime, registrations.base),
    );
  }
  known.set(WORKLOAD_SERVICE_POLICY.name, WORKLOAD_SERVICE_POLICY);
  active.set(WORKLOAD_SERVICE_POLICY.name, createWorkloadServiceProvider(audit, runtime));
  known.set(WORKLOAD_COMMAND_POLICY.name, WORKLOAD_COMMAND_POLICY);
  active.set(WORKLOAD_COMMAND_POLICY.name, createWorkloadCommandProvider(audit, runtime));
  known.set(WORKLOAD_JSON_CONFIG_POLICY.name, WORKLOAD_JSON_CONFIG_POLICY);
  active.set(WORKLOAD_JSON_CONFIG_POLICY.name, createWorkloadJSONConfigProvider(audit, runtime));
  for (const binding of PVE_PROVIDER_POLICIES) {
    const policy: TrustedWorkloadProviderPolicy = {
      name: binding.provider,
      requiredScopes: binding.requiredScopes,
      executionMode: binding.executionMode,
    };
    known.set(binding.provider, policy);
    active.set(
      binding.provider,
      wrapRestrictedPVEProvider(
        policy,
        binding.tool,
        binding.operations,
        config,
        audit,
        runtime,
      ),
    );
  }
  return { known, active };
}
