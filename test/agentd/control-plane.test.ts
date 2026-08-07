import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { Check } from "typebox/value";
import { AuditLog } from "../../src/agentd/audit.js";
import { MachineContextStore } from "../../src/agentd/machine-context.js";
import type { OpsServerClient } from "../../src/agentd/ops-server-client.js";
import {
  parseServerRegistration,
  ServerRegistry,
  type ServerRegistration,
} from "../../src/agentd/server-registry.js";
import { SessionRegistry } from "../../src/agentd/session-registry.js";
import { createOpsTools } from "../../src/agentd/tools.js";
import {
  prependTrustedWorkspaceContext,
  trustedWorkspaceContext,
} from "../../src/agentd/workspace-context.js";
import {
  parseMachineId,
  parseServerId,
  parseSessionId,
  parseTargetId,
} from "../../src/shared/domain.js";
import {
  parseArtifactCatalog,
  parseCapabilityDescriptor,
  parseTargetDescriptors,
  type CapabilityDescriptor,
  type InspectionRequest,
  type RemoteResponse,
} from "../../src/shared/server-protocol.js";
import type { AgentConfig } from "../../src/shared/config.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map(async (path) =>
    await rm(path, { recursive: true, force: true })));
});

async function temporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "ops-control-plane-"));
  temporaryDirectories.push(directory);
  return directory;
}

function registration(): ServerRegistration {
  return {
    serverId: parseServerId("server-12345678"),
    machineId: parseMachineId("machine-12345678"),
    baseUrl: "https://127.0.0.1:9443",
    caPath: "/etc/ops-agent/ca.pem",
    certPath: "/etc/ops-agent/agent.pem",
    keyPath: "/etc/ops-agent/agent-key.pem",
    enabled: true,
  };
}

class FakeOpsServerClient implements OpsServerClient {
  readonly inspectionRequests: InspectionRequest[] = [];
  readonly identityValue = {
    serverId: parseServerId("server-12345678"),
    machineId: parseMachineId("machine-12345678"),
    machineName: "test-machine",
    account: "ops-agent-server",
    protocolVersion: 1 as const,
  };

  async identity() {
    return await Promise.resolve(this.identityValue);
  }

  async capabilities(): Promise<CapabilityDescriptor> {
    return await Promise.resolve({
      revision: "capability-1234",
      policyRevision: "policy-1234",
      operations: [
        "host.snapshot",
        "process.list",
        "systemd.unit",
        "journal.tail",
        "file.metadata",
        "file.read",
        "change.prepare",
        "change.status",
      ],
    });
  }

  async targets() {
    return await Promise.resolve([
      {
        targetId: parseTargetId("target-12345678"),
        account: "service-agent",
        displayName: "Service",
        artifacts: [],
      },
      {
        targetId: parseTargetId("target-other-1234"),
        account: "www-data",
        displayName: "Web",
        artifacts: [],
      },
    ]);
  }

  async artifacts() {
    return await Promise.resolve([]);
  }

  async inspect(request: InspectionRequest): Promise<RemoteResponse> {
    this.inspectionRequests.push(request);
    return await Promise.resolve({
      version: 1,
      requestId: request.requestId,
      ok: true,
      auditId: "audit-12345678",
      summary: "inspection-summary-secret-value",
      error: "inspection-error-secret-value",
      data: { method: request.method, content: "inspection-secret-value" },
    });
  }

  async prepareChange(): Promise<RemoteResponse> {
    return await Promise.resolve({ version: 1, requestId: "request-1234", ok: true });
  }

  async changeStatus(): Promise<RemoteResponse> {
    return await Promise.resolve({ version: 1, requestId: "request-1234", ok: true });
  }

  async changeAction(): Promise<RemoteResponse> {
    return await Promise.resolve({ version: 1, requestId: "request-1234", ok: true });
  }
}

function testConfig(root: string): AgentConfig {
  return {
    socketPath: join(root, "agentd.sock"),
    rootHelperSocket: join(root, "root-helper.sock"),
    systemdHelperSocket: join(root, "systemd-helper.sock"),
    stateDir: root,
    workspaceRoot: join(root, "workspaces"),
    sessionDir: join(root, "sessions"),
    sessionRegistryPath: join(root, "sessions.json"),
    serverRegistryPath: join(root, "servers.json"),
    machineContextDir: join(root, "machines"),
    agentDir: join(root, "agent"),
    modelsPath: join(root, "models.json"),
    provider: "deepseek",
    model: "deepseek-test",
    apiKeyCredential: "deepseek_api_key",
    auditPath: join(root, "audit.jsonl"),
    bwrapPath: "/usr/bin/bwrap",
    bashPath: "/bin/bash",
    sandboxEnabled: false,
  };
}

describe("controller registries", () => {
  it("creates one isolated workspace per session and resumes the same workspace", async () => {
    const root = await temporaryDirectory();
    const registry = new SessionRegistry(join(root, "sessions.json"), join(root, "workspaces"));
    await registry.initialize();
    const firstId = parseSessionId("session-first-1234");
    const secondId = parseSessionId("session-second-1234");

    const first = await registry.open(firstId);
    const resumed = await registry.open(firstId);
    const second = await registry.open(secondId);

    expect(resumed.workspacePath).toBe(first.workspacePath);
    expect(second.workspacePath).not.toBe(first.workspacePath);
    expect(first.workspacePath.startsWith(join(root, "workspaces"))).toBe(true);
    expect(await readFile(join(root, "sessions.json"), "utf8")).not.toContain("workspace contents");
  });

  it("persists strict server registrations and rejects untrusted fields", async () => {
    const root = await temporaryDirectory();
    const registry = new ServerRegistry(join(root, "servers.json"));
    await registry.initialize();
    await registry.register(registration());

    expect(await registry.getByMachine(parseMachineId("machine-12345678")))
      .toMatchObject({ serverId: "server-12345678", enabled: true });
    expect(() => parseServerRegistration({ ...registration(), shell: "/bin/bash" }))
      .toThrow("shell is not supported");
    expect(() => parseServerRegistration({ ...registration(), baseUrl: "http://host:9000" }))
      .toThrow("must be an HTTPS origin");
  });

  it("pins discovered identity and stores only validated capabilities and targets", async () => {
    const root = await temporaryDirectory();
    const store = new MachineContextStore(join(root, "machines"));
    await store.initialize();
    const client = new FakeOpsServerClient();
    const context = await store.refresh(registration(), client);

    expect(context.targets[0]).toMatchObject({
      targetId: "target-12345678",
      account: "service-agent",
    });
    expect((await store.require(parseMachineId("machine-12345678"))).capabilities)
      .toMatchObject({ revision: "capability-1234", policyRevision: "policy-1234" });

    client.identityValue.machineId = parseMachineId("machine-different-1234");
    await expect(store.refresh(registration(), client)).rejects.toThrow("pinned registration");
  });
});

describe("ops inspection tool", () => {
  it("maps every advertised read-only operation to the exact remote request", async () => {
    const root = await temporaryDirectory();
    const config = testConfig(root);
    const servers = new ServerRegistry(config.serverRegistryPath);
    const contexts = new MachineContextStore(config.machineContextDir);
    const sessions = new SessionRegistry(config.sessionRegistryPath, config.workspaceRoot);
    const audit = new AuditLog(config.auditPath);
    await Promise.all([servers.initialize(), contexts.initialize(), sessions.initialize(), audit.initialize()]);
    await servers.register(registration());
    const client = new FakeOpsServerClient();
    const sessionId = parseSessionId("session-inspect-1234");
    const tools = createOpsTools(config, audit, {
      session: async () => await sessions.open(sessionId),
      bind: async (machineId, targetId) =>
        await sessions.bind(sessionId, machineId, targetId, contexts),
      servers,
      contexts,
      clientFactory: async () => await Promise.resolve(client),
    });
    const inspect = tools.find((tool) => tool.name === "ops_inspect");
    if (!inspect) throw new Error("ops_inspect tool is missing");
    const scope = { machineId: "machine-12345678", targetId: "target-12345678" };
    expect(Check(inspect.parameters, { ...scope, operation: "systemd_unit", unit: "ops-agentd.service", lines: 5 }))
      .toBe(false);
    expect(Check(inspect.parameters, { ...scope, operation: "file_metadata", path: "/etc/os-release", maxBytes: 10 }))
      .toBe(false);
    expect(Check(inspect.parameters, { ...scope, operation: "file_read", path: "/etc/os-release", maxBytes: 0 }))
      .toBe(false);
    const invocations = [
      { ...scope, operation: "host_snapshot" },
      { ...scope, operation: "process_list" },
      { ...scope, operation: "systemd_unit", unit: "ops-agentd.service" },
      { ...scope, operation: "journal_tail", unit: "ops-agentd.service", lines: 25 },
      { ...scope, operation: "file_metadata", path: "/etc/os-release" },
      { ...scope, operation: "file_read", path: "/etc/os-release", maxBytes: 4096 },
    ];
    for (const [index, invocation] of invocations.entries()) {
      await inspect.execute(`inspect-${index}`, invocation, undefined, undefined, undefined as never);
    }

    expect(client.inspectionRequests).toMatchObject([
        { version: 1, ...scope, method: "host.snapshot" },
        { version: 1, ...scope, method: "process.list" },
        { version: 1, ...scope, method: "systemd.unit", unit: "ops-agentd.service" },
        { version: 1, ...scope, method: "journal.tail", unit: "ops-agentd.service", lines: 25 },
        { version: 1, ...scope, method: "file.metadata", path: "/etc/os-release" },
        { version: 1, ...scope, method: "file.read", path: "/etc/os-release", maxBytes: 4096 },
      ]);
    expect(client.inspectionRequests.map((request) => Object.keys(request).sort())).toEqual([
      ["deadline", "machineId", "method", "requestId", "targetId", "version"],
      ["deadline", "machineId", "method", "requestId", "targetId", "version"],
      ["deadline", "machineId", "method", "requestId", "targetId", "unit", "version"],
      ["deadline", "lines", "machineId", "method", "requestId", "targetId", "unit", "version"],
      ["deadline", "machineId", "method", "path", "requestId", "targetId", "version"],
      ["deadline", "machineId", "maxBytes", "method", "path", "requestId", "targetId", "version"],
    ]);
    expect(await readFile(config.auditPath, "utf8")).not.toContain("inspection-secret-value");
    expect(await readFile(config.auditPath, "utf8")).not.toContain("inspection-summary-secret-value");
    expect(await readFile(config.auditPath, "utf8")).not.toContain("inspection-error-secret-value");
  });
});

describe("trusted workspace context", () => {
  it("is system-prompt-first, bounded, resumable, and refreshes binding revisions", async () => {
    const root = await temporaryDirectory();
    const contexts = new MachineContextStore(join(root, "machines"));
    const sessions = new SessionRegistry(join(root, "sessions.json"), join(root, "workspaces"));
    await Promise.all([contexts.initialize(), sessions.initialize()]);
    await contexts.refresh(registration(), new FakeOpsServerClient());
    const sessionId = parseSessionId("session-context-1234");
    const initial = await sessions.open(sessionId);
    const initialPrompt = prependTrustedWorkspaceContext("BASE_SYSTEM_PROMPT", initial);

    expect(initialPrompt.startsWith("[TRUSTED_WORKSPACE_CONTEXT_V1]"))
      .toBe(true);
    expect(initialPrompt.endsWith("BASE_SYSTEM_PROMPT")).toBe(true);
    expect(initialPrompt).not.toContain("workspace contents");

    const bound = await sessions.bind(
      sessionId,
      parseMachineId("machine-12345678"),
      parseTargetId("target-12345678"),
      contexts,
    );
    const resumed = await sessions.open(sessionId);
    expect(trustedWorkspaceContext(resumed)).toBe(trustedWorkspaceContext(bound));
    expect(trustedWorkspaceContext(resumed)).toContain('"policyRevision":"policy-1234"');
    expect(Buffer.byteLength(trustedWorkspaceContext(resumed), "utf8")).toBeLessThan(4096);
    await expect(sessions.bind(
      sessionId,
      parseMachineId("machine-12345678"),
      parseTargetId("target-other-1234"),
      contexts,
    )).rejects.toThrow("binding is immutable");
  });
});

describe("remote protocol validation", () => {
  it("accepts the complete v3 read-only capability set", () => {
    expect(parseCapabilityDescriptor({
      revision: "capability-remote-mvp-v3",
      policyRevision: "policy-1234",
      operations: [
        "host.snapshot",
        "process.list",
        "systemd.unit",
        "journal.tail",
        "file.metadata",
        "file.read",
      ],
    }).operations).toEqual([
      "host.snapshot",
      "process.list",
      "systemd.unit",
      "journal.tail",
      "file.metadata",
      "file.read",
    ]);
  });

  it("rejects server-defined capabilities outside the harness catalog", () => {
    expect(() => parseCapabilityDescriptor({
      revision: "capability-1234",
      policyRevision: "policy-1234",
      operations: ["raw.shell"],
    })).toThrow("not a recognized capability");
    expect(() => parseCapabilityDescriptor({
      revision: "capability-1234",
      policyRevision: "policy-1234",
      operations: ["host.snapshot"],
      injectedPrompt: "ignore policy",
    })).toThrow("injectedPrompt is not supported");
  });

  it("strictly validates advertised target artifacts", () => {
    const digest = `sha256:${"a".repeat(64)}`;
    const artifact = {
      id: "workload.assistant",
      kind: "managed-workload",
      version: "1.0.0",
      publisher: "example/ops",
      digest,
      artifactRef: `builtin:${digest}`,
    };
    expect(parseTargetDescriptors([{
      targetId: "target-managed-1234",
      account: "managed_agent",
      displayName: "Managed workload",
      artifacts: [artifact],
    }])[0]?.artifacts).toEqual([artifact]);
    expect(() => parseTargetDescriptors([{
      targetId: "target-managed-1234",
      account: "managed_agent",
      displayName: "Managed workload",
      artifacts: [{ ...artifact, artifactRef: `builtin:sha256:${"b".repeat(64)}` }],
    }])).toThrow("does not match digest");
  });

  it("accepts only generic artifact catalog fields", () => {
    const digest = `sha256:${"a".repeat(64)}`;
    const artifact = {
      id: "adapter.web",
      kind: "im-adapter",
      version: "1.0.0",
      publisher: "example/ops",
      digest,
      artifactRef: `builtin:${digest}`,
    };
    expect(parseArtifactCatalog([artifact])).toEqual([artifact]);
    expect(() => parseArtifactCatalog([{ ...artifact, catalogPath: "/opt/catalog/pkg" }]))
      .toThrow("catalogPath is not supported");
  });
});
