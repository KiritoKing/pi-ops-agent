import { readFileSync, readdirSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { Check } from "typebox/value";
import { AuditLog } from "../../src/agentd/audit.js";
import { MachineContextStore } from "../../src/agentd/machine-context.js";
import type { OpsServerClient } from "../../src/agentd/ops-server-client.js";
import { ServerRegistry } from "../../src/agentd/server-registry.js";
import { SessionRegistry } from "../../src/agentd/session-registry.js";
import type { OpsToolRuntime } from "../../src/agentd/tools.js";
import { createTrustedBaseProviderCatalog } from "../../src/agentd/workload-providers.js";
import type { AgentConfig } from "../../src/shared/config.js";
import {
  parseChangeId,
  parseMachineId,
  parseServerId,
  parseSessionId,
  parseTargetId,
} from "../../src/shared/domain.js";
import type { ChangeRef } from "../../src/shared/approval.js";
import type {
  CapabilityDescriptor,
  ChangeActionRequest,
  ChangeStatusRequest,
  InspectionRequest,
  PrepareChangeRequest,
  RemoteResponse,
} from "../../src/shared/server-protocol.js";
import type { ActiveSourcePlugin } from "../../src/shared/source-plugin.js";
import { parseWorkloadDescriptor, type WorkloadDescriptor } from "../../src/shared/workload-runtime.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map(async (path) =>
    await rm(path, { recursive: true, force: true })));
});

async function temporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "ops-source-workload-profile-"));
  temporaryDirectories.push(directory);
  return directory;
}

function testConfig(root: string): AgentConfig {
  return {
    socketPath: join(root, "agentd.sock"),
    backendSocketPath: join(root, "agentd-backend.sock"),
    stateDir: root,
    workspaceRoot: join(root, "workspaces"),
    sessionDir: join(root, "sessions"),
    sessionRegistryPath: join(root, "sessions.json"),
    serverRegistryPath: join(root, "servers.json"),
    reviewerSocket: join(root, "reviewer.sock"),
    guardianHeartbeatPath: join(root, "heartbeat.json"),
    pluginRegistryPath: join(root, "plugins"),
    pluginLeaseSocketPath: join(root, "plugin-lease.sock"),
    pluginCtlPath: join(root, "agentd-pluginctl"),
    approvalSubmitPath: join(root, "agentd-approval-submit"),
    machineContextDir: join(root, "machines"),
    agentDir: join(root, "agent"),
    modelsPath: join(root, "models.json"),
    provider: "deepseek",
    model: "deepseek-test",
    apiKeyCredential: "deepseek_api_key",
    auditPath: join(root, "audit.jsonl"),
    bwrapPath: "/usr/bin/bwrap",
    bashPath: "/bin/bash",
    sandboxEnabled: true,
  };
}

function activePlugin(
  pluginId: string,
  digestCharacter: string,
  capabilities: readonly string[],
  requestedScopes: readonly string[],
): ActiveSourcePlugin {
  return {
    apiVersion: "agentd.plugin-registration/v1",
    schemaVersion: 1,
    pluginId,
    kind: "workload",
    version: "0.1.0",
    publisher: "example/source-workload",
    digest: `sha256:${digestCharacter.repeat(64)}`,
    capabilities,
    requestedScopes,
    approvedBy: "local-admin:1000",
    approvedAt: "2026-08-08T00:00:00Z",
  };
}

interface SourceWorkloadModule {
  apiVersion: string;
  tools: unknown;
  invoke(
    request: { tool: string; input: Record<string, unknown> },
    api: { call(provider: string, input: unknown): Promise<unknown> },
  ): Promise<unknown>;
}

async function loadWorkload(directory: string): Promise<{
  workload: SourceWorkloadModule;
  descriptor: WorkloadDescriptor;
}> {
  const loaded = await import(
    new URL(`../../plugins/${directory}/workload.mjs`, import.meta.url).href
  ) as unknown as { workload: SourceWorkloadModule };
  return {
    workload: loaded.workload,
    descriptor: parseWorkloadDescriptor({
      apiVersion: loaded.workload.apiVersion,
      tools: loaded.workload.tools,
    }),
  };
}

class FakeOpsServerClient implements OpsServerClient {
  readonly prepareRequests: PrepareChangeRequest[] = [];
  readonly statusRequests: ChangeStatusRequest[] = [];
  readonly commandRequests: Array<Parameters<OpsServerClient["workloadCommandInspect"]>[0]> = [];
  commandOutput = "command-output-must-not-be-audited\napiToken=super-secret-value\n";
  statusState: "PENDING_APPROVAL" | "COMMITTED" = "PENDING_APPROVAL";

  async identity() {
    return await Promise.resolve({
      serverId: parseServerId("server-standard-1234"),
      machineId: parseMachineId("machine-standard-1234"),
      machineName: "source-workload-test",
      account: "ops-agent-server",
      protocolVersion: 1 as const,
    });
  }

  async capabilities(): Promise<CapabilityDescriptor> {
    return await Promise.resolve({
      revision: "capability-standard-1234",
      policyRevision: "policy-standard-1234",
      operations: ["workload.command.inspect", "change.prepare", "change.status"],
    });
  }

  async targets() {
    return await Promise.resolve([{
      targetId: parseTargetId("target-standard-1234"),
      account: "alice",
      displayName: "Alice services",
      artifacts: [],
    }]);
  }

  async artifacts() { return await Promise.resolve([]); }

  async inspect(request: InspectionRequest): Promise<RemoteResponse> {
    return await Promise.resolve({ version: 1, requestId: request.requestId, ok: true });
  }

  async workloadCommandInspect(
    request: Parameters<OpsServerClient["workloadCommandInspect"]>[0],
  ): Promise<RemoteResponse> {
    this.commandRequests.push(request);
    return await Promise.resolve({
      version: 1,
      requestId: request.requestId,
      ok: true,
      auditId: "audit-command-1234",
      data: {
        kind: "workload.command.inspect-result/v1",
        pluginId: request.pluginId,
        pluginDigest: request.pluginDigest,
        profileKey: request.profileKey,
        targetAccount: "alice",
        runAsAccount: "alice",
        output: this.commandOutput,
        truncated: false,
        executableTrust: "root-owned-nonwritable-path",
      },
    });
  }

  async prepareChange(request: PrepareChangeRequest): Promise<RemoteResponse> {
    this.prepareRequests.push(request);
    return await Promise.resolve({
      version: 1,
      requestId: request.requestId,
      ok: true,
      auditId: "audit-service-1234",
      changeId: parseChangeId("change-service-1234"),
      state: "PENDING_APPROVAL",
      summary: "service action prepared",
    });
  }

  async changeStatus(request: ChangeStatusRequest): Promise<RemoteResponse> {
    this.statusRequests.push(request);
    return await Promise.resolve({
      version: 1,
      requestId: request.requestId,
      ok: true,
      auditId: "audit-status-1234",
      changeId: request.changeId,
      state: this.statusState,
      data: { planHash: `sha256:${"c".repeat(64)}` },
    });
  }

  async changeAction(request: ChangeActionRequest): Promise<RemoteResponse> {
    return await Promise.resolve({ version: 1, requestId: request.requestId, ok: true });
  }
}

async function providerHarness() {
  const root = await temporaryDirectory();
  const config = testConfig(root);
  const servers = new ServerRegistry(config.serverRegistryPath);
  const contexts = new MachineContextStore(config.machineContextDir);
  const sessions = new SessionRegistry(config.sessionRegistryPath, config.workspaceRoot);
  const audit = new AuditLog(config.auditPath);
  await Promise.all([servers.initialize(), contexts.initialize(), sessions.initialize(), audit.initialize()]);
  await servers.register({
    serverId: parseServerId("server-standard-1234"),
    machineId: parseMachineId("machine-standard-1234"),
    baseUrl: "https://127.0.0.1:9443",
    caPath: "/etc/ops-agent/ca.pem",
    certPath: "/etc/ops-agent/agent.pem",
    keyPath: "/etc/ops-agent/agent-key.pem",
    enabled: true,
  });
  const client = new FakeOpsServerClient();
  const base = activePlugin("workload.base", "a", ["base.machine.list"], ["control.machine.read"]);
  const custom = activePlugin(
    "workload.example-service",
    "b",
    ["example.service.manage"],
    ["control.workload.service.manage"],
  );
  let currentCustom = custom;
  const preparedChanges: Array<{ toolCallId: string; changeRef: ChangeRef }> = [];
  const sessionId = parseSessionId("session-standard-1234");
  const runtime: OpsToolRuntime = {
    session: async () => await sessions.open(sessionId),
    bind: async (machineId, targetId) =>
      await sessions.bind(sessionId, machineId, targetId, contexts),
    servers,
    contexts,
    clientFactory: async () => await Promise.resolve(client),
    sourcePluginLoader: async (pluginId) => {
      if (pluginId === base.pluginId) return await Promise.resolve(base);
      if (pluginId === currentCustom.pluginId) return await Promise.resolve(currentCustom);
      throw new Error("source workload is inactive");
    },
    recordPreparedChange: (toolCallId, changeRef) => preparedChanges.push({ toolCallId, changeRef }),
  };
  const catalog = await createTrustedBaseProviderCatalog(config, audit, runtime, { base });
  return {
    auditPath: config.auditPath,
    base,
    catalog,
    client,
    custom,
    preparedChanges,
    setCurrentCustom(value: ActiveSourcePlugin) { currentCustom = value; },
  };
}

function collectTypeScript(directory: URL): string {
  return readdirSync(directory, { withFileTypes: true }).map((entry) => {
    const child = new URL(`${entry.name}${entry.isDirectory() ? "/" : ""}`, directory);
    if (entry.isDirectory()) return collectTypeScript(child);
    return entry.name.endsWith(".ts") ? readFileSync(child, "utf8") : "";
  }).join("\n");
}

describe("source-owned standard workload profiles", () => {
  it("loads the shipped base descriptor with its bounded file mode schema", async () => {
    const base = await loadWorkload("workload-base");
    const propose = base.descriptor.tools.find((tool) => tool.name === "ops_propose_change");
    if (propose === undefined) throw new Error("base change tool is missing");
    const fileWrite = {
      machineId: "machine-12345678",
      targetId: "target-12345678",
      operation: {
        kind: "file.write",
        path: "/etc/example.conf",
        content: "fixture\n",
      },
    };
    expect(Check(propose.parameters, { ...fileWrite, operation: { ...fileWrite.operation, mode: "644" } }))
      .toBe(true);
    expect(Check(propose.parameters, { ...fileWrite, operation: { ...fileWrite.operation, mode: "0644" } }))
      .toBe(true);
    for (const mode of ["1644", "0645", "00644", ""] as const) {
      expect(Check(propose.parameters, { ...fileWrite, operation: { ...fileWrite.operation, mode } }), mode)
        .toBe(false);
    }
  });

  it("keeps business identities and validation rules in digest-approved source", async () => {
    for (const [directory, id] of [
      ["workload-hermes-ops", "workload.hermes-ops"],
      ["workload-botmux-ops", "workload.botmux-ops"],
      ["workload-pve", "workload.pve"],
    ] as const) {
      const manifest = JSON.parse(readFileSync(
        new URL(`../../plugins/${directory}/manifest.json`, import.meta.url),
        "utf8",
      )) as {
        apiVersion: string;
        schemaVersion: number;
        id: string;
        kind: string;
        entrypoint: string;
        capabilities: string[];
        requestedScopes: string[];
      };
      expect(manifest).toMatchObject({
        apiVersion: "agentd.plugin/v1",
        schemaVersion: 1,
        id,
        kind: "workload",
      });
      expect(manifest).not.toHaveProperty("compiledBinding");
      expect(manifest.capabilities).toEqual([...manifest.capabilities].sort());
      expect(manifest.requestedScopes).toEqual([...manifest.requestedScopes].sort());
      const { descriptor } = await loadWorkload(directory);
      expect(descriptor.tools.map((tool) => tool.capability)).toEqual(manifest.capabilities);
    }

    const hermes = await loadWorkload("workload-hermes-ops");
    const hermesManage = hermes.descriptor.tools.find((tool) =>
      tool.name === "ops_hermes_service_manage");
    const hermesConfig = hermes.descriptor.tools.find((tool) =>
      tool.name === "ops_hermes_config_inspect");
    const hermesDoctor = hermes.descriptor.tools.find((tool) =>
      tool.name === "ops_hermes_doctor");
    if (hermesManage === undefined || hermesConfig === undefined || hermesDoctor === undefined) {
      throw new Error("Hermes source profile is incomplete");
    }
    const scope = { machineId: "machine-12345678", targetId: "target-12345678" };
    expect(hermesManage.providers).toEqual(["workload.service.manage"]);
    expect(Check(hermesManage.parameters, {
      ...scope, account: "alice", manager: "user", unit: "hermes-gateway-coder.service", action: "restart",
    })).toBe(true);
    for (const unit of ["ssh.service", "hermes-gateway@coder.service", "botmux.service"]) {
      expect(Check(hermesManage.parameters, {
        ...scope, account: "alice", manager: "user", unit, action: "restart",
      }), unit).toBe(false);
    }
    expect(Check(hermesConfig.parameters, {
      ...scope, path: "/home/alice/.hermes/config.yaml",
    })).toBe(true);
    expect(Check(hermesConfig.parameters, { ...scope, path: "/etc/shadow" })).toBe(false);
    expect(hermesDoctor.providers).toEqual(["workload.command.inspect"]);
    expect(Check(hermesDoctor.parameters, scope)).toBe(true);
    expect(Check(hermesDoctor.parameters, { ...scope, profileKey: "attacker.argv" })).toBe(false);

    const botmux = await loadWorkload("workload-botmux-ops");
    const botmuxManage = botmux.descriptor.tools.find((tool) =>
      tool.name === "ops_botmux_service_manage");
    const botmuxEdit = botmux.descriptor.tools.find((tool) =>
      tool.name === "ops_botmux_config_edit");
    if (botmuxManage === undefined || botmuxEdit === undefined) {
      throw new Error("BotMux source profile is incomplete");
    }
    expect(botmuxManage.providers).toEqual(["workload.service.manage"]);
    expect(Check(botmuxManage.parameters, {
      ...scope, account: "alice", manager: "user", unit: "botmux.service", action: "restart",
    })).toBe(true);
    expect(Check(botmuxManage.parameters, {
      ...scope, account: "alice", manager: "user", unit: "botmux@alice.service", action: "restart",
    })).toBe(false);
    for (const action of ["reload", "reset-failed", "restart", "start", "stop"]) {
      expect(Check(botmuxManage.parameters, {
        ...scope, account: "alice", manager: "user", unit: "botmux.service", action,
      }), action).toBe(true);
    }
    expect(Check(botmuxManage.parameters, {
      ...scope, account: "alice", manager: "user", unit: "botmux.service", action: "daemon-reload",
    })).toBe(false);
    expect(botmuxEdit.providers).toEqual(["workload.json-config.edit"]);
    expect(Check(botmuxEdit.parameters, {
      ...scope,
      selectorValue: "ops-agent",
      edit: { fieldKey: "backendType", value: { kind: "string", stringValue: "tmux" } },
    })).toBe(true);
    expect(Check(botmuxEdit.parameters, {
      ...scope,
      selectorValue: "ops-agent",
      edit: { fieldKey: "backendType", value: { kind: "string", stringValue: "shell" } },
    })).toBe(false);
    expect(Check(botmuxEdit.parameters, {
      ...scope,
      selectorValue: "ops-agent",
      edit: { fieldKey: "larkAppSecret", value: { kind: "string", stringValue: "secret" } },
    })).toBe(false);
  });

  it("routes source business tools through generic providers", async () => {
    const scope = { machineId: "machine-12345678", targetId: "target-12345678" };
    for (const [directory, tool, unit] of [
      ["workload-hermes-ops", "ops_hermes_service_manage", "hermes-gateway.service"],
      ["workload-botmux-ops", "ops_botmux_service_manage", "botmux.service"],
    ] as const) {
      const { workload } = await loadWorkload(directory);
      const calls: Array<{ provider: string; input: unknown }> = [];
      const input = { ...scope, account: "alice", manager: "user", unit, action: "restart" };
      await workload.invoke({ tool, input }, {
        call(provider, providerInput) {
          calls.push({ provider, input: providerInput });
          return Promise.resolve({ content: [{ type: "text", text: "prepared" }] });
        },
      });
      expect(calls).toEqual([{ provider: "workload.service.manage", input }]);
    }

    const { workload: botmux } = await loadWorkload("workload-botmux-ops");
    const editCalls: Array<{ provider: string; input: unknown }> = [];
    await botmux.invoke({
      tool: "ops_botmux_config_edit",
      input: {
        ...scope,
        selectorValue: "ops-agent",
        edit: { fieldKey: "showInTeam", value: { kind: "clear" } },
      },
    }, {
      call(provider, input) {
        editCalls.push({ provider, input });
        return Promise.resolve({ content: [{ type: "text", text: "prepared" }] });
      },
    });
    expect(editCalls).toEqual([{
      provider: "workload.json-config.edit",
      input: {
        ...scope,
        selectorValue: "ops-agent",
        profileKey: "botmux.bots",
        fieldKey: "showInTeam",
        value: { kind: "clear" },
      },
    }]);

    for (const control of [
      "\0", "\u001f", "\u007f", "\u0085", "\u061c", "\u200e", "\u200f",
      "\u2028", "\u202e", "\u2066", "\u2069", "\ufeff",
    ]) {
      await expect(botmux.invoke({
        tool: "ops_botmux_config_edit",
        input: {
          ...scope,
          selectorValue: `safe${control}unsafe`,
          edit: { fieldKey: "showInTeam", value: { kind: "clear" } },
        },
      }, {
        call() {
          throw new Error("unsafe selectorValue reached the provider");
        },
      })).rejects.toThrow("forbidden control character");
    }
  });

  it("maps diagnostic recipes to semantic profile keys and sanitizes BotMux setup JSON", async () => {
    const scope = { machineId: "machine-12345678", targetId: "target-12345678" };
    const hermes = await loadWorkload("workload-hermes-ops");
    const calls: Array<{ provider: string; input: unknown }> = [];
    const providerResult = (profileKey: string, output = "healthy\n") => ({
      content: [{ type: "text", text: output }],
      details: {
        profileKey,
        output,
        truncated: false,
        executableTrust: "root-owned-nonwritable-path",
      },
    });
    const doctor = await hermes.workload.invoke({ tool: "ops_hermes_doctor", input: scope }, {
      call(provider, input) {
        calls.push({ provider, input });
        return Promise.resolve(providerResult(
          "hermes.doctor",
          "  ✓ Runtime healthy\n  ⚠ workspace=must-hide\n  ✗ arbitrary exception must-hide-too\n"
            + "Found 2 issue(s) to address:\n  1. token-without-a-label=must-hide-three\n",
        ));
      },
    });
    expect(calls).toEqual([{
      provider: "workload.command.inspect",
      input: { ...scope, profileKey: "hermes.doctor" },
    }]);
    const doctorResult = doctor as { content: Array<{ text: string }> };
    expect(JSON.parse(doctorResult.content[0]?.text ?? "")).toEqual({
      version: 1,
      profile: "hermes.doctor",
      status: "issues",
      issueCount: 2,
      markers: { passed: 1, warnings: 1, failed: 1 },
      complete: true,
    });
    expect(JSON.stringify(doctor)).not.toContain("must-hide");

    const gateway = await hermes.workload.invoke({ tool: "ops_hermes_gateway_status", input: scope }, {
      call(provider, input) {
        calls.push({ provider, input });
        return Promise.resolve(providerResult(
          "hermes.gateway.status",
          "✓ User gateway service is running\n  PID(s): 4242\nRecent gateway health:\n"
            + "  attacker-controlled health text must-hide-four\n",
        ));
      },
    });
    expect(calls.at(-1)).toEqual({
      provider: "workload.command.inspect",
      input: { ...scope, profileKey: "hermes.gateway.status" },
    });
    const gatewayResult = gateway as { content: Array<{ text: string }> };
    expect(JSON.parse(gatewayResult.content[0]?.text ?? "")).toEqual({
      version: 1,
      profile: "hermes.gateway.status",
      state: "running",
      complete: true,
    });
    expect(JSON.stringify(gateway)).not.toContain("must-hide-four");

    const botmux = await loadWorkload("workload-botmux-ops");
    const setupRaw = JSON.stringify([{
        processName: "botmux-primary",
        name: "Primary",
        displayName: "Primary Bot",
        brand: "Codex",
        apiOnly: false,
        cliId: "codex",
        backendType: "tmux",
        model: "openai/gpt-5",
        showInTeam: true,
        env: { LARK_APP_SECRET: "lark-secret", SAFE_LOOKING: "still-secret" },
        cliRuntime: { path: "/home/alice/.local/bin/botmux" },
        update: { args: ["--unsafe"] },
        command: "node adapter.mjs",
        cwd: "/home/alice/private",
        path: "/home/alice/.botmux/bots.json",
        larkAppSecret: "masked-is-not-trusted",
      }]);
    const setup = await botmux.workload.invoke({ tool: "ops_botmux_setup_summary", input: scope }, {
      call(provider, input) {
        calls.push({ provider, input });
        return Promise.resolve(providerResult("botmux.setup.summary", setupRaw));
      },
    });
    expect(calls.at(-1)).toEqual({
      provider: "workload.command.inspect",
      input: { ...scope, profileKey: "botmux.setup.summary" },
    });
    const serialized = JSON.stringify(setup);
    expect(serialized).toContain("Primary");
    for (const secret of [
      "cliRuntime", "update", "env", "lark-secret", "still-secret", "secret-runtime",
      "update-secret", "adapter.mjs", "/home/alice", "masked-is-not-trusted",
    ]) expect(serialized).not.toContain(secret);
  });

  it("parses BotMux setup output strictly and emits only exact allowlisted fields", async () => {
    const scope = { machineId: "machine-12345678", targetId: "target-12345678" };
    const botmux = await loadWorkload("workload-botmux-ops");
    const invokeSetup = async (output: string, truncated = false): Promise<unknown> =>
      await botmux.workload.invoke({ tool: "ops_botmux_setup_summary", input: scope }, {
        call(provider, input) {
          expect(provider).toBe("workload.command.inspect");
          expect(input).toEqual({ ...scope, profileKey: "botmux.setup.summary" });
          return Promise.resolve({
            content: [{ type: "text", text: output }],
            details: {
              profileKey: "botmux.setup.summary",
              output,
              truncated,
              executableTrust: "root-owned-nonwritable-path",
            },
          });
        },
      });

    const sanitized = await invokeSetup(JSON.stringify([
        {
          processName: "botmux-primary",
          name: "Primary",
          displayName: "Primary Bot",
          brand: "Codex",
          apiOnly: false,
          cliId: "codex",
          backendType: "pty",
          model: "openai/gpt-5",
          showInTeam: true,
          ENV: "case-env-secret",
          "ｅｎｖ": "fullwidth-env-secret",
          Credential: "case-credential-secret",
          "credenтial": "unicode-credential-secret",
          PATH: "/private/case-path-secret",
          "paтh": "/private/unicode-path-secret",
          Command: "case-command-secret",
          "cоmmand": "unicode-command-secret",
          description: "control\u0000secret",
          version: "format\u202esecret",
        },
      ]));
    const result = sanitized as { content: Array<{ text: string }> };
    expect(JSON.parse(result.content[0]?.text ?? "")).toEqual({
      version: 1,
      entries: [{
        processName: "botmux-primary",
        name: "Primary",
        displayName: "Primary Bot",
        brand: "Codex",
        apiOnly: false,
        cliId: "codex",
        backendType: "pty",
        model: "openai/gpt-5",
        showInTeam: true,
      }],
    });
    const serialized = JSON.stringify(sanitized);
    for (const secret of [
      "case-env-secret", "fullwidth-env-secret", "case-credential-secret",
      "unicode-credential-secret", "case-path-secret", "unicode-path-secret",
      "case-command-secret", "unicode-command-secret", "control", "format",
    ]) expect(serialized).not.toContain(secret);

    const deeplyNested = `${"[".repeat(18)}${"]".repeat(18)}`;
    const oversized = JSON.stringify([{ name: "x".repeat(65 * 1024) }]);
    const invalidOutputs: Array<[label: string, output: string, truncated?: boolean]> = [
      ["duplicate key", '[{"processName":"botmux-safe","name":"safe","name":"duplicate-secret"}]'],
      ["escape-equivalent duplicate key", '[{"processName":"botmux-safe","name":"safe","\\u006eame":"duplicate-secret"}]'],
      ["trailing value", "[] true"],
      ["excessive depth", deeplyNested],
      ["excessive bytes", oversized],
      ["raw control character", '[{"processName":"botmux-safe","name":"safe\nsecret"}]'],
      ["unrecognized fallback object", '{"fallback-secret":{"name":"must-not-leak"}}'],
      ["wrong allowlisted type", '[{"processName":"botmux-safe","name":"safe","showInTeam":"true"}]'],
      ["missing process identity", '[{"name":"safe"}]'],
      ["truncated provider output", "[]", true],
    ];
    for (const [label, output, truncated] of invalidOutputs) {
      await expect(invokeSetup(output, truncated), label).rejects.toThrow(/bounded strict JSON/u);
    }
  });

  it("keeps PVE policy prose and provider composition in editable source", async () => {
    const { workload, descriptor } = await loadWorkload("workload-pve");
    const lifecycle = descriptor.tools.find((tool) => tool.name === "ops_pve_guest_lifecycle_prepare");
    expect(lifecycle?.description).toContain("stop and reboot always require separate human approval");
    const calls: Array<{ provider: string; input: unknown }> = [];
    const input = {
      machineId: "machine-12345678",
      targetId: "target-12345678",
      action: "start",
      node: "pve1",
      guestType: "qemu",
      vmid: 100,
    };
    await workload.invoke({ tool: "ops_pve_guest_lifecycle_prepare", input }, {
      call(provider, providerInput) {
        calls.push({ provider, input: providerInput });
        return Promise.resolve({ content: [{ type: "text", text: "prepared" }] });
      },
    });
    expect(calls).toEqual([{
      provider: "pve.guest.lifecycle",
      input: {
        machineId: input.machineId,
        targetId: input.targetId,
        operation: {
          kind: "pve.guest.action",
          node: "pve1",
          guestType: "qemu",
          vmid: 100,
          action: "start",
        },
      },
    }]);
  });

  it("does not embed standard business identities or profiles in production core", () => {
    const core = [
      collectTypeScript(new URL("../../src/agentd/", import.meta.url)),
      readFileSync(new URL("../../src/client/approval-router.ts", import.meta.url), "utf8"),
    ].join("\n");
    expect(core).not.toMatch(/workload\.(?:hermes-ops|botmux-ops|pve)/u);
    expect(core).not.toContain("hermes-gateway");
    expect(core).not.toContain("botmux.service");
  });
});

describe("generic source-workload service provider", () => {
  it("injects the actual caller identity and holds the typed protocol boundary", async () => {
    const { catalog, client, custom, preparedChanges } = await providerHarness();
    expect(catalog.known.get("workload.service.manage")).toMatchObject({
      name: "workload.service.manage",
      requiredScopes: ["control.workload.service.manage"],
    });
    const provider = catalog.active.get("workload.service.manage");
    if (provider === undefined) throw new Error("generic service provider is missing");
    const input = {
      machineId: "machine-standard-1234",
      targetId: "target-standard-1234",
      account: "alice",
      manager: "user",
      unit: "example.service",
      action: "restart",
    } as const;
    const result = await provider.invoke("example-service-1", input, undefined, custom);
    expect(result).toMatchObject({
      details: {
        pluginId: "workload.example-service",
        pluginDigest: custom.digest,
        state: "PENDING_APPROVAL",
      },
    });
    expect(client.prepareRequests[0]?.operation).toEqual({
      kind: "workload.service.action",
      pluginId: "workload.example-service",
      pluginDigest: custom.digest,
      account: "alice",
      manager: "user",
      unit: "example.service",
      action: "restart",
    });
    expect(preparedChanges).toMatchObject([{
      toolCallId: "example-service-1",
      changeRef: { changeId: "change-service-1234" },
    }]);
  });

  it("rejects wrong fields, workload.base borrowing, and digest drift before prepare", async () => {
    const harness = await providerHarness();
    const { base, catalog, client, custom } = harness;
    const provider = catalog.active.get("workload.service.manage");
    if (provider === undefined) throw new Error("generic service provider is missing");
    const input = {
      machineId: "machine-standard-1234",
      targetId: "target-standard-1234",
      account: "alice",
      manager: "user",
      unit: "example.service",
      action: "restart",
    } as const;
    await expect(provider.invoke("wrong-unit", {
      ...input,
      unit: "../example.service",
    }, undefined, custom)).rejects.toThrow(/rejected plugin input/u);
    await expect(provider.invoke("base-borrow", input, undefined, base))
      .rejects.toThrow("workload.base cannot call a business provider");
    harness.setCurrentCustom({ ...custom, digest: `sha256:${"d".repeat(64)}` });
    await expect(provider.invoke("digest-drift", input, undefined, custom))
      .rejects.toThrow(/current registration changed/u);
    expect(client.prepareRequests).toHaveLength(0);
  });
});

describe("generic source-workload JSON config provider", () => {
  it("injects the exact caller digest and exposes only a pending local approval", async () => {
    const { catalog, client, custom, preparedChanges } = await providerHarness();
    expect(catalog.known.get("workload.json-config.edit")).toMatchObject({
      name: "workload.json-config.edit",
      requiredScopes: ["control.workload.json-config.edit"],
      executionMode: "sequential",
    });
    const provider = catalog.active.get("workload.json-config.edit");
    if (provider === undefined) throw new Error("generic JSON config provider is missing");
    const input = {
      machineId: "machine-standard-1234",
      targetId: "target-standard-1234",
      profileKey: "botmux.bots",
      selectorValue: "ops-agent",
      fieldKey: "model",
      value: { kind: "string", stringValue: "openai/gpt-5" },
    } as const;
    const result = await provider.invoke("example-json-config-1", input, undefined, custom);
    expect(client.prepareRequests[0]?.operation).toEqual({
      kind: "workload.json-config.edit",
      pluginId: custom.pluginId,
      sourceDigest: custom.digest,
      profileKey: input.profileKey,
      selectorValue: input.selectorValue,
      fieldKey: input.fieldKey,
      value: input.value,
    });
    expect(result).toMatchObject({
      details: {
        pluginId: custom.pluginId,
        sourceDigest: custom.digest,
        state: "PENDING_APPROVAL",
      },
    });
    expect(JSON.stringify(result)).toContain("local model-external per-change");
    expect(preparedChanges).toMatchObject([{
      toolCallId: "example-json-config-1",
      changeRef: { changeId: "change-service-1234" },
    }]);
  });

  it("rejects confused tags, unsafe text, execution details, base borrowing, and digest drift", async () => {
    const harness = await providerHarness();
    const provider = harness.catalog.active.get("workload.json-config.edit");
    if (provider === undefined) throw new Error("generic JSON config provider is missing");
    const input = {
      machineId: "machine-standard-1234",
      targetId: "target-standard-1234",
      profileKey: "botmux.bots",
      selectorValue: "ops-agent",
      fieldKey: "showInTeam",
      value: { kind: "boolean", booleanValue: true },
    } as const;
    await expect(provider.invoke("confused-tag", {
      ...input,
      value: { kind: "boolean", booleanValue: true, stringValue: "true" },
    }, undefined, harness.custom)).rejects.toThrow("rejected plugin input");
    await expect(provider.invoke("unsafe-selector", {
      ...input,
      selectorValue: "ops-agent\u202e",
    }, undefined, harness.custom)).rejects.toThrow("rejected unsafe text");
    await expect(provider.invoke("raw-path", {
      ...input,
      configPath: "/root/.ssh/authorized_keys",
    }, undefined, harness.custom)).rejects.toThrow("rejected plugin input");
    await expect(provider.invoke("base-borrow", input, undefined, harness.base))
      .rejects.toThrow("workload.base cannot call a business JSON config provider");
    harness.setCurrentCustom({ ...harness.custom, digest: `sha256:${"e".repeat(64)}` });
    await expect(provider.invoke("digest-drift", input, undefined, harness.custom))
      .rejects.toThrow("current registration changed");
    expect(harness.client.prepareRequests).toHaveLength(0);
  });

  it("fails closed if signed broker status reports standing execution", async () => {
    const harness = await providerHarness();
    const provider = harness.catalog.active.get("workload.json-config.edit");
    if (provider === undefined) throw new Error("generic JSON config provider is missing");
    harness.client.statusState = "COMMITTED";
    await expect(provider.invoke("standing-json-config", {
      machineId: "machine-standard-1234",
      targetId: "target-standard-1234",
      profileKey: "botmux.bots",
      selectorValue: "ops-agent",
      fieldKey: "showInTeam",
      value: { kind: "boolean", booleanValue: true },
    }, undefined, harness.custom)).rejects.toThrow("mandatory local per-change approval");
    expect(harness.preparedChanges).toHaveLength(0);
  });
});

describe("generic source-workload command provider", () => {
  it("injects caller identity, returns bounded output, and audits metadata only", async () => {
    const { auditPath, catalog, client, custom } = await providerHarness();
    expect(catalog.known.get("workload.command.inspect")).toMatchObject({
      name: "workload.command.inspect",
      requiredScopes: ["control.workload.command.inspect"],
      executionMode: "parallel",
    });
    const provider = catalog.active.get("workload.command.inspect");
    if (provider === undefined) throw new Error("generic command provider is missing");
    const input = {
      machineId: "machine-standard-1234",
      targetId: "target-standard-1234",
      profileKey: "example.status",
    } as const;
    const result = await provider.invoke("example-command-1", input, undefined, custom);
    expect(client.commandRequests).toMatchObject([{
      machineId: input.machineId,
      targetId: input.targetId,
      method: "workload.command.inspect",
      pluginId: custom.pluginId,
      pluginDigest: custom.digest,
      profileKey: input.profileKey,
    }]);
    expect(result).toMatchObject({
      details: {
        pluginId: custom.pluginId,
        pluginDigest: custom.digest,
        profileKey: input.profileKey,
        executableTrust: "root-owned-nonwritable-path",
      },
    });
    const serialized = JSON.stringify(result);
    expect(serialized).toContain("command-output-must-not-be-audited");
    expect(serialized).not.toContain("super-secret-value");
    expect(serialized).toContain("apiToken=[REDACTED]");

    const audit = readFileSync(auditPath, "utf8");
    expect(audit).not.toContain("command-output-must-not-be-audited");
    expect(audit).not.toContain("super-secret-value");
    expect(audit).toContain("outputDigest");
    expect(audit).toContain("outputBytes");
  });

  it("rejects workload.base, invocation recipe fields, and current-digest drift", async () => {
    const harness = await providerHarness();
    const provider = harness.catalog.active.get("workload.command.inspect");
    if (provider === undefined) throw new Error("generic command provider is missing");
    const input = {
      machineId: "machine-standard-1234",
      targetId: "target-standard-1234",
      profileKey: "example.status",
    } as const;
    await expect(provider.invoke("base-command", input, undefined, harness.base))
      .rejects.toThrow("workload.base cannot call a business command provider");
    await expect(provider.invoke("raw-command", {
      ...input,
      executable: "/bin/sh",
    }, undefined, harness.custom)).rejects.toThrow("rejected plugin input");
    await expect(provider.invoke("bad-profile", {
      ...input,
      profileKey: "../status",
    }, undefined, harness.custom)).rejects.toThrow("rejected plugin input");
    harness.setCurrentCustom({ ...harness.custom, digest: `sha256:${"e".repeat(64)}` });
    await expect(provider.invoke("digest-drift", input, undefined, harness.custom))
      .rejects.toThrow("current registration changed");
    expect(harness.client.commandRequests).toHaveLength(0);
  });
});
