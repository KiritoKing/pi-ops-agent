import { describe, expect, it } from "vitest";
import { requireClientAdapterContext } from "../../src/client/adapter-authorization.js";
import type { ActiveRuntimeSourcePlugin } from "../../src/shared/source-plugin.js";
import type { AdapterClientContext } from "../../src/shared/adapter-runtime.js";

function plugin(pluginId: string): ActiveRuntimeSourcePlugin {
  const tui = pluginId === "adapter.tui";
  return {
    apiVersion: "agentd.plugin-registration/v1",
    schemaVersion: 1,
    pluginId,
    kind: "adapter",
    version: "0.3.0",
    publisher: "example/adapter",
    digest: `sha256:${"a".repeat(64)}`,
    capabilities: tui
      ? ["adapter.inbound.text", "adapter.outbound.display", "adapter.session.bind", "approval.local"]
      : ["adapter.inbound.text", "adapter.outbound.send", "adapter.session.bind", "approval.status"],
    requestedScopes: tui
      ? [
          "adapter.inbound.text.local",
          "adapter.outbound.display.local",
          "adapter.session.bind.local",
          "approval.submit.local",
        ]
      : [
          "adapter.inbound.text.botmux",
          "adapter.outbound.send.botmux",
          "adapter.session.bind.botmux",
          "approval.status.remote",
        ],
    approvedBy: "local-admin:1000",
    approvedAt: "2026-08-08T00:00:00Z",
    entrypoint: "adapter.mjs",
    snapshotPath: `/var/lib/ops-agent/plugins/snapshots/sha256/${"a".repeat(64)}`,
  };
}

function options(active: ActiveRuntimeSourcePlugin, approvalMode: string) {
  return {
    environment: {
      OPS_AGENT_ADAPTER_ID: active.pluginId,
      OPS_AGENT_ADAPTER_DIGEST: active.digest,
      OPS_AGENT_ADAPTER_APPROVAL_MODE: approvalMode,
    },
    username: "local-admin",
    effectiveUid: 1000,
    enrolledAdministrator: { version: 1 as const, uid: 1000, username: "local-admin" },
    inputIsTTY: true,
    outputIsTTY: true,
    hasExternalEventSink: false,
  };
}

function context(active: ActiveRuntimeSourcePlugin): AdapterClientContext {
  const tui = active.pluginId === "adapter.tui";
  return {
    apiVersion: "agentd.adapter-client-context/v1",
    schemaVersion: 1,
    pluginId: active.pluginId,
    digest: active.digest,
    descriptor: {
      apiVersion: "agentd.adapter/v1",
      schemaVersion: 1,
      adapterId: active.pluginId,
      runtimeAuthority: {
        execution: tui ? "compiled-client" : "source-process",
        filesystem: "host-as-runtime-uid",
        network: "host",
        credentials: "runtime-uid-readable",
        actionScopeEnforcement: "digest-review-and-typed-ipc-contract",
      },
      session: {
        mapping: tui ? "local-terminal" : "adapter-owned",
        writerLease: "gateway-global",
        controlApiVersion: "agentd.adapter-session-control/v1",
        supportedControls: ["bind"],
      },
      inbound: {
        transport: tui ? "tty" : "stdin",
        framing: tui ? "terminal-text" : "botmux-v1",
        contractApiVersion: "agentd.adapter-inbound/v1",
        supportedTypes: ["text"],
        maxFrameBytes: 131_072,
      },
      outbound: {
        transport: tui ? "stdout" : "completion-fd",
        framing: tui ? "terminal-text" : "ndjson",
        schema: tui ? "terminal.text/v1" : "completion.v1",
        actionApiVersion: "agentd.adapter-outbound-action/v1",
        supportedActions: tui ? ["display"] : ["send"],
        maxFrameBytes: 131_072,
      },
      approval: tui
        ? { mode: "local-tty", identitySource: "os-user+tty+sudo-pam", replayProtection: "local-command" }
        : { mode: "status-only", identitySource: "none", replayProtection: "none" },
    },
  };
}

describe("compiled client adapter approval gate", () => {
  it("allows only the exact active adapter.tui grant on a local administrator TTY", () => {
    const active = plugin("adapter.tui");
    expect(requireClientAdapterContext(active, context(active), options(active, "local-tty")))
      .toEqual({ adapterId: active.pluginId, digest: active.digest, canSubmitApproval: true });

    expect(() => requireClientAdapterContext(active, context(active), {
      ...options(active, "local-tty"),
      username: "ops-agent-botmux",
    })).toThrow("local administrator TTY");
    expect(() => requireClientAdapterContext(active, context(active), {
      ...options(active, "local-tty"),
      hasExternalEventSink: true,
    })).toThrow("local administrator TTY");
  });

  it("rejects a custom adapter UID with a forged TUI environment and PTY", () => {
    const active = plugin("adapter.tui");
    expect(() => requireClientAdapterContext(active, context(active), {
      ...options(active, "local-tty"),
      username: "ops-adapter-evil",
      effectiveUid: 2001,
    })).toThrow("local administrator TTY");
  });

  it("makes external adapters status-only and rejects missing or drifted runner bindings", () => {
    const active = plugin("adapter.botmux");
    const externalOptions = { ...options(active, "status-only"), hasExternalEventSink: true };
    expect(requireClientAdapterContext(active, context(active), externalOptions).canSubmitApproval)
      .toBe(false);
    expect(() => requireClientAdapterContext(active, context(active), {
      ...externalOptions,
      environment: {},
    })).toThrow("digest-validating adapter runner");
    expect(() => requireClientAdapterContext(active, context(active), {
      ...externalOptions,
      environment: {
        ...options(active, "status-only").environment,
        OPS_AGENT_ADAPTER_DIGEST: `sha256:${"b".repeat(64)}`,
      },
    })).toThrow("no longer matches");
  });

  it("rejects non-TUI approval submission scopes even if the adapter claims status-only", () => {
    const active = plugin("adapter.botmux");
    active.requestedScopes = [...active.requestedScopes, "approval.submit.remote"];
    expect(() => requireClientAdapterContext(
      active,
      context(active),
      { ...options(active, "status-only"), hasExternalEventSink: true },
    ))
      .toThrow("active digest grant");
  });
});
