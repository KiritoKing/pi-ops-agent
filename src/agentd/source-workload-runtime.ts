import { defineTool, type ToolDefinition } from "@earendil-works/pi-coding-agent";
import { Check } from "typebox/value";
import type { AgentConfig } from "../shared/config.js";
import {
  loadActiveRuntimeSourcePlugin,
  type ActiveRuntimeSourcePlugin,
  withActiveRuntimeSourcePluginLease,
} from "../shared/source-plugin.js";
import type { AuditLog } from "./audit.js";
import {
  BubblewrapWorkloadHostRunner,
  type WorkloadHostRunner,
} from "./workload-host-runner.js";
import type {
  TrustedWorkloadProviderCatalog,
  TrustedWorkloadProviderPolicy,
} from "./workload-providers.js";

interface SourceWorkloadRuntimeOptions {
  config: AgentConfig;
  audit: AuditLog;
  registrations: readonly ActiveRuntimeSourcePlugin[];
  providers: TrustedWorkloadProviderCatalog;
  reservedToolNames?: ReadonlySet<string>;
  hostRunner?: WorkloadHostRunner;
}

interface LoadedTool {
  plugin: ActiveRuntimeSourcePlugin;
  name: string;
  label: string;
  description: string;
  capability: string;
  parameters: ToolDefinition["parameters"];
  providers: readonly string[];
  executionMode: "parallel" | "sequential";
}

function exactValues(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function sameRegistration(
  expected: ActiveRuntimeSourcePlugin,
  current: ActiveRuntimeSourcePlugin,
): boolean {
  return expected.pluginId === current.pluginId && expected.kind === current.kind &&
    expected.version === current.version && expected.publisher === current.publisher &&
    expected.digest === current.digest && expected.entrypoint === current.entrypoint &&
    expected.snapshotPath === current.snapshotPath &&
    exactValues(expected.capabilities, current.capabilities) &&
    exactValues(expected.requestedScopes, current.requestedScopes);
}

function validateActiveCapabilityOwnership(
  registrations: readonly ActiveRuntimeSourcePlugin[],
): void {
  const owners = new Map<string, string>();
  for (const plugin of registrations) {
    if (plugin.kind !== "workload") throw new Error("runtime workload discovery returned a non-workload plugin");
    for (const capability of plugin.capabilities) {
      const owner = owners.get(capability);
      if (owner !== undefined) {
        throw new Error(`active workload capability ${capability} is duplicated by ${owner} and ${plugin.pluginId}`);
      }
      owners.set(capability, plugin.pluginId);
    }
  }
}

function validateProviderAuthorization(
  plugin: ActiveRuntimeSourcePlugin,
  providerName: string,
  policy: TrustedWorkloadProviderPolicy | undefined,
): TrustedWorkloadProviderPolicy {
  if (policy === undefined) {
    throw new Error(`${plugin.pluginId} requested unknown trusted provider ${providerName}`);
  }
  for (const scope of policy.requiredScopes) {
    if (!plugin.requestedScopes.includes(scope)) {
      throw new Error(`${plugin.pluginId} is not approved for provider scope ${scope}`);
    }
  }
  return policy;
}

async function assertCurrent(
  config: AgentConfig,
  plugin: ActiveRuntimeSourcePlugin,
): Promise<void> {
  const current = await loadActiveRuntimeSourcePlugin(config, plugin.pluginId);
  if (!sameRegistration(plugin, current)) {
    throw new Error(`${plugin.pluginId} current registration changed; reopen the agent session`);
  }
}

export async function createSourceWorkloadTools(
  options: SourceWorkloadRuntimeOptions,
): Promise<ToolDefinition[]> {
  validateActiveCapabilityOwnership(options.registrations);
  const base = options.registrations.find((plugin) => plugin.pluginId === "workload.base");
  if (base === undefined || base.kind !== "workload") {
    throw new Error("workload.base must be an active source-runtime workload");
  }
  const sourcePlugins = options.registrations;
  const host = options.hostRunner ?? new BubblewrapWorkloadHostRunner(options.config.bwrapPath);
  const loaded: LoadedTool[] = [];
  const toolOwners = new Map<string, string>();
  for (const reserved of options.reservedToolNames ?? []) toolOwners.set(reserved, "compiled core binding");

  for (const plugin of sourcePlugins) {
    await assertCurrent(options.config, plugin);
    const descriptor = await host.describe(plugin);
    await assertCurrent(options.config, plugin);
    const describedCapabilities = descriptor.tools.map((tool) => tool.capability).sort();
    if (!exactValues(describedCapabilities, [...plugin.capabilities].sort())) {
      throw new Error(`${plugin.pluginId} descriptor capabilities do not exactly match its approved registration`);
    }
    for (const tool of descriptor.tools) {
      const priorOwner = toolOwners.get(tool.name);
      if (priorOwner !== undefined) {
        throw new Error(`workload tool ${tool.name} conflicts between ${priorOwner} and ${plugin.pluginId}`);
      }
      toolOwners.set(tool.name, plugin.pluginId);
      const policies = tool.providers.map((provider) =>
        validateProviderAuthorization(plugin, provider, options.providers.known.get(provider)));
      const available = tool.providers.every((provider) => options.providers.active.has(provider));
      if (!available) continue;
      loaded.push({
        plugin,
        name: tool.name,
        label: tool.label,
        description: tool.description,
        capability: tool.capability,
        parameters: tool.parameters,
        providers: tool.providers,
        executionMode: policies.some((policy) => policy.executionMode === "sequential")
          ? "sequential"
          : tool.executionMode,
      });
    }
  }

  return loaded.map((tool) => defineTool({
    name: tool.name,
    label: tool.label,
    description: tool.description,
    parameters: tool.parameters,
    executionMode: tool.executionMode,
    async execute(toolCallId, params, signal) {
      if (!Check(tool.parameters, params)) {
        throw new Error(`${tool.plugin.pluginId} tool input failed its source-defined schema`);
      }
      return await withActiveRuntimeSourcePluginLease(
        options.config,
        tool.plugin,
        async (leaseSignal) => {
          const result = await host.invoke(
            tool.plugin,
            tool.name,
            params,
            async (request, providerSignal) => {
              if (!tool.providers.includes(request.provider)) {
                throw new Error(`${tool.plugin.pluginId} tool ${tool.name} requested an undeclared provider`);
              }
              validateProviderAuthorization(
                tool.plugin,
                request.provider,
                options.providers.known.get(request.provider),
              );
              const provider = options.providers.active.get(request.provider);
              if (provider === undefined) {
                throw new Error(`trusted provider ${request.provider} is not currently available`);
              }
              return await provider.invoke(toolCallId, request.input, providerSignal, tool.plugin);
            },
            leaseSignal,
          );
          await options.audit.append({
            type: "source-workload",
            toolCallId,
            tool: tool.name,
            capability: tool.capability,
            pluginId: tool.plugin.pluginId,
            pluginDigest: tool.plugin.digest,
          });
          return { ...result, details: result.details };
        },
        signal,
      );
    },
  }));
}
