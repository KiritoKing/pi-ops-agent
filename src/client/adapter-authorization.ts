import type { ActiveRuntimeSourcePlugin } from "../shared/source-plugin.js";
import type { EnrolledLocalAdministrator } from "../shared/local-administrator.js";
import {
  adapterDescriptorGrant,
  type AdapterClientContext as TrustedAdapterClientContext,
} from "../shared/adapter-runtime.js";

const TUI_CAPABILITIES = [
  "adapter.inbound.text",
  "adapter.outbound.display",
  "adapter.session.bind",
  "approval.local",
] as const;
const TUI_SCOPES = [
  "adapter.inbound.text.local",
  "adapter.outbound.display.local",
  "adapter.session.bind.local",
  "approval.submit.local",
] as const;
const RESERVED_SERVICE_ACCOUNTS = new Set([
  "ops-agent",
  "ops-agent-botmux",
  "ops-agent-reviewer",
  "ops-agent-server",
]);

function reservedServiceNamespace(username: string): boolean {
  return username === "root" || username.startsWith("ops-agent")
    || username.startsWith("ops-adapter-");
}

export interface ClientAdapterContext {
  adapterId: string;
  digest: string;
  canSubmitApproval: boolean;
}

function exactValues(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

export function requireClientAdapterContext(
  plugin: ActiveRuntimeSourcePlugin,
  trustedContext: TrustedAdapterClientContext,
  options: {
    environment: NodeJS.ProcessEnv;
    username: string;
    effectiveUid: number;
    enrolledAdministrator?: EnrolledLocalAdministrator;
    inputIsTTY: boolean;
    outputIsTTY: boolean;
    hasExternalEventSink: boolean;
  },
): ClientAdapterContext {
  const adapterId = options.environment.OPS_AGENT_ADAPTER_ID;
  const digest = options.environment.OPS_AGENT_ADAPTER_DIGEST;
  const approvalMode = options.environment.OPS_AGENT_ADAPTER_APPROVAL_MODE;
  if (adapterId === undefined || digest === undefined || approvalMode === undefined) {
    throw new Error("compiled client must be launched by the digest-validating adapter runner");
  }
  if (plugin.kind !== "adapter" || plugin.pluginId !== adapterId || plugin.digest !== digest
    || trustedContext.pluginId !== adapterId || trustedContext.digest !== digest
    || trustedContext.descriptor.adapterId !== adapterId) {
    throw new Error("client adapter identity or digest no longer matches the active source registration");
  }
  const declaredGrant = adapterDescriptorGrant(trustedContext.descriptor);
  if (!exactValues(plugin.capabilities, declaredGrant.capabilities)
    || !exactValues(plugin.requestedScopes, declaredGrant.requestedScopes)) {
    throw new Error("trusted Adapter descriptor does not match the active digest grant");
  }
  if (adapterId === "adapter.tui") {
    const enrolled = options.enrolledAdministrator;
    if (approvalMode !== "local-tty"
      || trustedContext.descriptor.runtimeAuthority.execution !== "compiled-client"
      || trustedContext.descriptor.approval.mode !== "local-tty"
      || !exactValues(plugin.capabilities, TUI_CAPABILITIES)
      || !exactValues(plugin.requestedScopes, TUI_SCOPES)
      || RESERVED_SERVICE_ACCOUNTS.has(options.username)
      || reservedServiceNamespace(options.username)
      || enrolled === undefined
      || options.effectiveUid !== enrolled.uid
      || options.username !== enrolled.username
      || !options.inputIsTTY
      || !options.outputIsTTY
      || options.hasExternalEventSink) {
      throw new Error("adapter.tui approval requires its exact grant and a local administrator TTY");
    }
    return { adapterId, digest, canSubmitApproval: true };
  }
  if (approvalMode !== "status-only"
    || trustedContext.descriptor.runtimeAuthority.execution !== "source-process"
    || trustedContext.descriptor.approval.mode !== "status-only"
    || !options.hasExternalEventSink
    || plugin.capabilities.includes("approval.local")
    || plugin.requestedScopes.some((scope) => scope.startsWith("approval.submit"))) {
    throw new Error("external adapters must use the status-only approval contract");
  }
  return { adapterId, digest, canSubmitApproval: false };
}
