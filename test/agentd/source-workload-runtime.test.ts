import { createHash } from "node:crypto";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  writeFile,
} from "node:fs/promises";
import { createServer, type Server, type Socket } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import type { ChangeRef } from "../../src/shared/approval.js";
import type { AgentConfig } from "../../src/shared/config.js";
import {
  parseChangeId,
  parseMachineId,
  parseServerId,
  parseSessionId,
  parseTargetId,
} from "../../src/shared/domain.js";
import type {
  CapabilityDescriptor,
  ChangeActionRequest,
  ChangeStatusRequest,
  InspectionRequest,
  PrepareChangeRequest,
  RemoteResponse,
  WorkloadCommandInspectionRequest,
} from "../../src/shared/server-protocol.js";
import type { ActiveRuntimeSourcePlugin } from "../../src/shared/source-plugin.js";
import {
  parseStrictJson,
  parseWorkloadDescriptor,
  parseWorkloadToolResult,
  requireBoundedJson,
  type WorkloadDescriptor,
  type WorkloadToolResult,
} from "../../src/shared/workload-runtime.js";
import { AuditLog } from "../../src/agentd/audit.js";
import { MachineContextStore } from "../../src/agentd/machine-context.js";
import type { OpsServerClient } from "../../src/agentd/ops-server-client.js";
import { ServerRegistry } from "../../src/agentd/server-registry.js";
import { SessionRegistry } from "../../src/agentd/session-registry.js";
import {
  createSourceWorkloadTools,
} from "../../src/agentd/source-workload-runtime.js";
import type { OpsToolRuntime } from "../../src/agentd/tools.js";
import type {
  WorkloadHostRunner,
  WorkloadProviderRequest,
} from "../../src/agentd/workload-host-runner.js";
import type {
  TrustedWorkloadProvider,
  TrustedWorkloadProviderCatalog,
  TrustedWorkloadProviderPolicy,
} from "../../src/agentd/workload-providers.js";
import { createTrustedBaseProviderCatalog } from "../../src/agentd/workload-providers.js";
import { encodeFrame, FrameDecoder } from "../../src/shared/framing.js";

const fakeLeaseBrokers = new Map<string, {
  server: Server;
  sockets: Set<Socket>;
  registrations: Map<string, ActiveRuntimeSourcePlugin>;
  activeLeases: Set<string>;
  events: Array<{
    state: "LEASED" | "RELEASED";
    pluginId: string;
    digest: string;
  }>;
}>();

afterEach(async () => {
  await Promise.all([...fakeLeaseBrokers.values()].map(async ({ server, sockets }) => {
    for (const socket of sockets) socket.destroy();
    await new Promise<void>((resolve) => { server.close(() => resolve()); });
  }));
  fakeLeaseBrokers.clear();
});

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

function registration(
  config: AgentConfig,
  pluginId: string,
  digestCharacter: string,
  capabilities: readonly string[],
  requestedScopes: readonly string[],
): ActiveRuntimeSourcePlugin {
  const digest = `sha256:${digestCharacter.repeat(64)}`;
  return {
    apiVersion: "agentd.plugin-registration/v1",
    schemaVersion: 1,
    pluginId,
    kind: "workload",
    version: "1.0.0",
    publisher: "example/source-workload",
    digest,
    capabilities,
    requestedScopes,
    approvedBy: "local-admin:1000",
    approvedAt: "2026-08-08T00:00:00Z",
    entrypoint: "workload.mjs",
    snapshotPath: join(config.pluginRegistryPath, "snapshots", "sha256", digest.slice(7)),
  };
}

function descriptor(
  tools: Array<{
    name: string;
    capability: string;
    providers?: string[];
  }>,
): WorkloadDescriptor {
  return parseWorkloadDescriptor({
    apiVersion: "agentd.workload/v1",
    tools: tools.map((tool) => ({
      name: tool.name,
      label: tool.name,
      description: `Source definition for ${tool.name}`,
      capability: tool.capability,
      parameters: {
        type: "object",
        properties: { message: { type: "string", minLength: 1, maxLength: 4096 } },
        required: ["message"],
        additionalProperties: false,
      },
      providers: tool.providers ?? [],
      executionMode: "parallel",
    })),
  });
}

class FakeHostRunner implements WorkloadHostRunner {
  readonly descriptors: ReadonlyMap<string, WorkloadDescriptor>;
  readonly invokeBehavior: (
    plugin: ActiveRuntimeSourcePlugin,
    tool: string,
    input: unknown,
    provider: (request: WorkloadProviderRequest, signal?: AbortSignal) => Promise<unknown>,
    signal?: AbortSignal,
  ) => Promise<WorkloadToolResult>;
  invokeCount = 0;

  constructor(
    descriptors: ReadonlyMap<string, WorkloadDescriptor>,
    invokeBehavior?: FakeHostRunner["invokeBehavior"],
  ) {
    this.descriptors = descriptors;
    this.invokeBehavior = invokeBehavior ?? (async (plugin, tool, input) => await Promise.resolve({
      content: [{ type: "text", text: `${plugin.pluginId}:${tool}:${JSON.stringify(input)}` }],
      details: { sourceDefined: true },
    }));
  }

  async describe(plugin: ActiveRuntimeSourcePlugin): Promise<WorkloadDescriptor> {
    const value = this.descriptors.get(plugin.pluginId);
    if (value === undefined) throw new Error(`no fake descriptor for ${plugin.pluginId}`);
    return await Promise.resolve(value);
  }

  async invoke(
    plugin: ActiveRuntimeSourcePlugin,
    tool: string,
    input: unknown,
    provider: (request: WorkloadProviderRequest, signal?: AbortSignal) => Promise<unknown>,
    signal?: AbortSignal,
  ): Promise<WorkloadToolResult> {
    this.invokeCount += 1;
    return await this.invokeBehavior(plugin, tool, input, provider, signal);
  }
}

function shellLiteral(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

async function writePluginCtl(
  config: AgentConfig,
  registrations: readonly ActiveRuntimeSourcePlugin[],
): Promise<void> {
  const registrationMap = new Map(registrations.map((plugin) => [plugin.pluginId, plugin]));
  const existing = fakeLeaseBrokers.get(config.pluginLeaseSocketPath);
  if (existing === undefined) {
    const sockets = new Set<Socket>();
    const activeLeases = new Set<string>();
    const events: Array<{
      state: "LEASED" | "RELEASED";
      pluginId: string;
      digest: string;
    }> = [];
    const broker = createServer((socket) => {
      sockets.add(socket);
      socket.once("close", () => sockets.delete(socket));
      const decoder = new FrameDecoder();
      let leased = false;
      let leasedPlugin: ActiveRuntimeSourcePlugin | undefined;
      socket.on("data", (chunk: Buffer) => {
        for (const value of decoder.push(chunk)) {
          const request = value as { version?: unknown; pluginId?: unknown; digest?: unknown; action?: unknown };
          if (!leased) {
            const plugin = registrationMap.get(String(request.pluginId));
            if (request.version !== 1 || plugin === undefined || request.digest !== plugin.digest) {
              socket.end(encodeFrame({ version: 1, ok: false, error: "current registration changed" }));
              return;
            }
            leased = true;
            leasedPlugin = plugin;
            activeLeases.add(`${plugin.pluginId}@${plugin.digest}`);
            events.push({ state: "LEASED", pluginId: plugin.pluginId, digest: plugin.digest });
            socket.write(encodeFrame({
              version: 1,
              ok: true,
              state: "LEASED",
              registration: plugin,
            }));
          } else if (request.version === 1 && request.action === "release") {
            if (leasedPlugin === undefined) {
              socket.destroy();
              return;
            }
            activeLeases.delete(`${leasedPlugin.pluginId}@${leasedPlugin.digest}`);
            events.push({
              state: "RELEASED",
              pluginId: leasedPlugin.pluginId,
              digest: leasedPlugin.digest,
            });
            socket.end(encodeFrame({ version: 1, ok: true, state: "RELEASED" }));
          } else {
            socket.destroy();
          }
        }
      });
    });
    await new Promise<void>((resolve, reject) => {
      broker.once("error", reject);
      broker.listen(config.pluginLeaseSocketPath, () => {
        broker.off("error", reject);
        resolve();
      });
    });
    fakeLeaseBrokers.set(config.pluginLeaseSocketPath, {
      server: broker,
      sockets,
      registrations: registrationMap,
      activeLeases,
      events,
    });
  } else {
    existing.registrations.clear();
    for (const [pluginId, plugin] of registrationMap) existing.registrations.set(pluginId, plugin);
  }
  const cases = registrations.map((plugin) =>
    `  *${plugin.pluginId}*) printf '%s\\n' ${shellLiteral(JSON.stringify(plugin))} ;;`).join("\n");
  await writeFile(config.pluginCtlPath, `#!/bin/sh
case "$*" in
${cases}
  *) exit 3 ;;
esac
`, {
    mode: 0o700,
  });
  await chmod(config.pluginCtlPath, 0o700);
}

interface RepositoryPVEManifest {
  apiVersion: "agentd.plugin/v1";
  schemaVersion: 1;
  id: "workload.pve";
  kind: "workload";
  version: string;
  publisher: string;
  description: string;
  entrypoint: "workload.mjs";
  capabilities: string[];
  requestedScopes: string[];
}

type SourceTreeEntry =
  | { kind: "directory"; relativePath: string }
  | { kind: "file"; relativePath: string; executable: boolean; payload: Buffer };

interface SnapshotWorkloadModule {
  apiVersion: string;
  tools: unknown;
  invoke(
    request: Readonly<{ tool: string; input: unknown }>,
    api: Readonly<{ call(provider: string, input: unknown): Promise<unknown> }>,
  ): Promise<unknown>;
}

const PVE_SOURCE_DIRECTORY = fileURLToPath(
  new URL("../../plugins/workload-pve/", import.meta.url),
);
const PVE_SOURCE_DIGEST =
  "sha256:a791bb69fe620f25c87b7d91ea551ab43826d49ecc70aebbd9797b91234a0f20";

function parseRepositoryPVEManifest(value: unknown): RepositoryPVEManifest {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("repository PVE manifest is not an object");
  }
  const input = value as {
    apiVersion?: unknown;
    schemaVersion?: unknown;
    id?: unknown;
    kind?: unknown;
    version?: unknown;
    publisher?: unknown;
    description?: unknown;
    entrypoint?: unknown;
    capabilities?: unknown;
    requestedScopes?: unknown;
  };
  if (input.apiVersion !== "agentd.plugin/v1" || input.schemaVersion !== 1 ||
      input.id !== "workload.pve" || input.kind !== "workload" ||
      typeof input.version !== "string" || typeof input.publisher !== "string" ||
      typeof input.description !== "string" || input.entrypoint !== "workload.mjs" ||
      !Array.isArray(input.capabilities) ||
      input.capabilities.some((item) => typeof item !== "string") ||
      !Array.isArray(input.requestedScopes) ||
      input.requestedScopes.some((item) => typeof item !== "string")) {
    throw new Error("repository PVE manifest does not match its approved workload identity");
  }
  return input as RepositoryPVEManifest;
}

async function collectSourceTree(
  root: string,
  relativeDirectory = "",
): Promise<SourceTreeEntry[]> {
  const directory = relativeDirectory === "" ? root : join(root, relativeDirectory);
  const children = (await readdir(directory, { withFileTypes: true }))
    .sort((left, right) => left.name.localeCompare(right.name, "en"));
  const entries: SourceTreeEntry[] = [];
  for (const child of children) {
    const relativePath = relativeDirectory === ""
      ? child.name
      : `${relativeDirectory}/${child.name}`;
    const sourcePath = join(root, relativePath);
    const info = await lstat(sourcePath);
    if (child.isSymbolicLink() || info.isSymbolicLink()) {
      throw new Error("repository PVE source unexpectedly contains a symlink");
    }
    if (child.isDirectory() && info.isDirectory()) {
      entries.push({ kind: "directory", relativePath });
      entries.push(...await collectSourceTree(root, relativePath));
      continue;
    }
    if (!child.isFile() || !info.isFile()) {
      throw new Error("repository PVE source unexpectedly contains a non-regular entry");
    }
    entries.push({
      kind: "file",
      relativePath,
      executable: (info.mode & 0o111) !== 0,
      payload: await readFile(sourcePath),
    });
  }
  return entries;
}

function sourceTreeHashHeader(entry: SourceTreeEntry): Buffer {
  const relativePath = Buffer.from(entry.relativePath, "utf8");
  const header = Buffer.alloc(1 + 4 + relativePath.length + 1 + 8);
  header.writeUInt8(entry.kind === "directory" ? "D".charCodeAt(0) : "F".charCodeAt(0), 0);
  header.writeUInt32BE(relativePath.length, 1);
  relativePath.copy(header, 5);
  header.writeUInt8(entry.kind === "file" && entry.executable ? 1 : 0, 5 + relativePath.length);
  header.writeBigUInt64BE(
    BigInt(entry.kind === "file" ? entry.payload.length : 0),
    6 + relativePath.length,
  );
  return header;
}

function canonicalSourceTreeDigest(entries: readonly SourceTreeEntry[]): string {
  const hash = createHash("sha256").update("agentd-source-plugin-snapshot-v1\0");
  for (const entry of entries) {
    hash.update(sourceTreeHashHeader(entry));
    if (entry.kind === "file") hash.update(entry.payload);
  }
  return `sha256:${hash.digest("hex")}`;
}

async function stageRepositoryPVE(
  config: AgentConfig,
): Promise<{ manifest: RepositoryPVEManifest; plugin: ActiveRuntimeSourcePlugin }> {
  const entries = await collectSourceTree(PVE_SOURCE_DIRECTORY);
  const digest = canonicalSourceTreeDigest(entries);
  const snapshotPath = join(
    config.pluginRegistryPath,
    "snapshots",
    "sha256",
    digest.slice("sha256:".length),
  );
  await mkdir(snapshotPath, { recursive: true, mode: 0o700 });
  for (const entry of entries) {
    const destination = join(snapshotPath, entry.relativePath);
    if (entry.kind === "directory") {
      await mkdir(destination, { mode: 0o700 });
      continue;
    }
    await mkdir(dirname(destination), { recursive: true, mode: 0o700 });
    await writeFile(destination, entry.payload, { mode: entry.executable ? 0o500 : 0o400 });
  }
  const directories = entries
    .filter((entry): entry is Extract<SourceTreeEntry, { kind: "directory" }> =>
      entry.kind === "directory")
    .map((entry) => join(snapshotPath, entry.relativePath))
    .reverse();
  for (const directory of directories) await chmod(directory, 0o500);
  await chmod(snapshotPath, 0o500);
  const manifestEntry = entries.find((entry) =>
    entry.kind === "file" && entry.relativePath === "manifest.json");
  if (manifestEntry?.kind !== "file") throw new Error("repository PVE source has no manifest");
  const manifest = parseRepositoryPVEManifest(parseStrictJson(manifestEntry.payload.toString("utf8")));
  return {
    manifest,
    plugin: {
      apiVersion: "agentd.plugin-registration/v1",
      schemaVersion: 1,
      pluginId: manifest.id,
      kind: manifest.kind,
      version: manifest.version,
      publisher: manifest.publisher,
      digest,
      capabilities: manifest.capabilities,
      requestedScopes: manifest.requestedScopes,
      approvedBy: "local-admin:1000",
      approvedAt: "2026-08-10T00:00:00Z",
      entrypoint: manifest.entrypoint,
      snapshotPath,
    },
  };
}

function requireSnapshotWorkloadModule(value: unknown): SnapshotWorkloadModule {
  if (typeof value !== "object" || value === null || !("workload" in value)) {
    throw new Error("snapshot module did not export workload");
  }
  const workload = value.workload;
  if (typeof workload !== "object" || workload === null) {
    throw new Error("snapshot workload export is not an object");
  }
  const candidate = workload as { apiVersion?: unknown; tools?: unknown; invoke?: unknown };
  if (typeof candidate.apiVersion !== "string" || !Array.isArray(candidate.tools) ||
      typeof candidate.invoke !== "function") {
    throw new Error("snapshot workload export does not implement the workload ABI");
  }
  return workload as SnapshotWorkloadModule;
}

class SnapshotPVEHostRunner implements WorkloadHostRunner {
  readonly #base: ActiveRuntimeSourcePlugin;
  invokeCount = 0;

  constructor(base: ActiveRuntimeSourcePlugin) {
    this.#base = base;
  }

  async #load(plugin: ActiveRuntimeSourcePlugin): Promise<SnapshotWorkloadModule> {
    if (plugin.pluginId !== "workload.pve") throw new Error("unexpected snapshot workload identity");
    const entrypoint = pathToFileURL(join(plugin.snapshotPath, plugin.entrypoint));
    const namespace = await import(`${entrypoint.href}?digest=${plugin.digest.slice(7)}`) as unknown;
    return requireSnapshotWorkloadModule(namespace);
  }

  async describe(plugin: ActiveRuntimeSourcePlugin): Promise<WorkloadDescriptor> {
    if (plugin.pluginId === this.#base.pluginId) {
      return descriptor([{ name: "ops_fixture_base", capability: "fixture.base" }]);
    }
    const workload = await this.#load(plugin);
    const tools = JSON.parse(JSON.stringify(workload.tools)) as unknown;
    return parseWorkloadDescriptor({ apiVersion: workload.apiVersion, tools });
  }

  async invoke(
    plugin: ActiveRuntimeSourcePlugin,
    tool: string,
    input: unknown,
    provider: (request: WorkloadProviderRequest, signal?: AbortSignal) => Promise<unknown>,
    signal?: AbortSignal,
  ): Promise<WorkloadToolResult> {
    const workload = await this.#load(plugin);
    const descriptorValue = await this.describe(plugin);
    if (!descriptorValue.tools.some((candidate) => candidate.name === tool)) {
      throw new Error("snapshot workload invocation requested an undeclared tool");
    }
    const boundedInput = structuredClone(requireBoundedJson(
      input,
      "snapshot workload invocation input",
      128 * 1024,
    ));
    let providerCalls = 0;
    this.invokeCount += 1;
    const result = await workload.invoke(
      Object.freeze({ tool, input: boundedInput }),
      Object.freeze({
        async call(providerName: string, providerInput: unknown): Promise<unknown> {
          if (!/^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*$/u.test(providerName)) {
            throw new Error("snapshot workload requested an invalid provider name");
          }
          providerCalls += 1;
          if (providerCalls > 32) throw new Error("snapshot workload exceeded its provider call limit");
          return await provider({
            provider: providerName,
            input: requireBoundedJson(providerInput, "snapshot workload provider input", 128 * 1024),
          }, signal);
        },
      }),
    );
    return parseWorkloadToolResult(result);
  }
}

function catalog(
  policies: readonly TrustedWorkloadProviderPolicy[] = [],
  providers: readonly TrustedWorkloadProvider[] = [],
): TrustedWorkloadProviderCatalog {
  return {
    known: new Map(policies.map((policy) => [policy.name, policy])),
    active: new Map(providers.map((provider) => [provider.name, provider])),
  };
}

class PVECompositionOpsServerClient implements OpsServerClient {
  readonly prepareRequests: PrepareChangeRequest[] = [];
  readonly statusRequests: ChangeStatusRequest[] = [];
  beforePrepare?: (request: PrepareChangeRequest) => void;

  async identity() {
    return await Promise.resolve({
      serverId: parseServerId("server-pve-composition-1234"),
      machineId: parseMachineId("machine-pve-composition-1234"),
      machineName: "pve-composition-fixture",
      account: "ops-agent-server",
      protocolVersion: 1 as const,
    });
  }

  async capabilities(): Promise<CapabilityDescriptor> {
    return await Promise.resolve({
      revision: "capability-pve-composition-1234",
      policyRevision: "policy-pve-composition-1234",
      operations: ["change.prepare", "change.status"],
    });
  }

  async targets() {
    return await Promise.resolve([{
      targetId: parseTargetId("target-pve-composition-1234"),
      account: "root",
      displayName: "PVE endpoint",
      artifacts: [],
    }]);
  }

  async artifacts() {
    return await Promise.resolve([]);
  }

  async inspect(request: InspectionRequest): Promise<RemoteResponse> {
    return await Promise.resolve({
      version: 1,
      requestId: request.requestId,
      ok: false,
      error: "PVE composition fixture exposes no inspection response",
    });
  }

  async workloadCommandInspect(request: WorkloadCommandInspectionRequest): Promise<RemoteResponse> {
    return await Promise.resolve({
      version: 1,
      requestId: request.requestId,
      ok: false,
      error: "PVE composition fixture exposes no command recipe",
    });
  }

  async prepareChange(request: PrepareChangeRequest): Promise<RemoteResponse> {
    this.beforePrepare?.(request);
    this.prepareRequests.push(request);
    return await Promise.resolve({
      version: 1,
      requestId: request.requestId,
      ok: true,
      auditId: "audit-pve-composition-prepare",
      changeId: parseChangeId("change-pve-composition-1234"),
      state: "PENDING_APPROVAL",
      summary: "typed PVE lifecycle plan prepared",
    });
  }

  async changeStatus(request: ChangeStatusRequest): Promise<RemoteResponse> {
    this.statusRequests.push(request);
    return await Promise.resolve({
      version: 1,
      requestId: request.requestId,
      ok: true,
      auditId: "audit-pve-composition-status",
      changeId: request.changeId,
      state: "PENDING_APPROVAL",
      summary: "typed PVE lifecycle plan pending local approval",
      data: { planHash: `sha256:${"c".repeat(64)}` },
    });
  }

  async changeAction(request: ChangeActionRequest): Promise<RemoteResponse> {
    return await Promise.resolve({
      version: 1,
      requestId: request.requestId,
      ok: false,
      error: "PVE composition fixture cannot authorize changes",
    });
  }
}

async function productionPVEProviderHarness(
  config: AgentConfig,
  audit: AuditLog,
  base: ActiveRuntimeSourcePlugin,
  pve: ActiveRuntimeSourcePlugin,
): Promise<{
  catalog: TrustedWorkloadProviderCatalog;
  client: PVECompositionOpsServerClient;
  preparedChanges: Array<{ toolCallId: string; changeRef: ChangeRef }>;
}> {
  const servers = new ServerRegistry(config.serverRegistryPath);
  const contexts = new MachineContextStore(config.machineContextDir);
  const sessions = new SessionRegistry(config.sessionRegistryPath, config.workspaceRoot);
  await Promise.all([servers.initialize(), contexts.initialize(), sessions.initialize()]);
  await servers.register({
    serverId: parseServerId("server-pve-composition-1234"),
    machineId: parseMachineId("machine-pve-composition-1234"),
    baseUrl: "https://127.0.0.1:9443",
    caPath: "/etc/ops-agent/ca.pem",
    certPath: "/etc/ops-agent/agent.pem",
    keyPath: "/etc/ops-agent/agent-key.pem",
    enabled: true,
  });
  const client = new PVECompositionOpsServerClient();
  const preparedChanges: Array<{ toolCallId: string; changeRef: ChangeRef }> = [];
  const sessionId = parseSessionId("session-pve-composition-1234");
  const runtime: OpsToolRuntime = {
    session: async () => await sessions.open(sessionId),
    bind: async (machineId, targetId) =>
      await sessions.bind(sessionId, machineId, targetId, contexts),
    servers,
    contexts,
    clientFactory: async () => await Promise.resolve(client),
    sourcePluginLoader: async (pluginId) => {
      if (pluginId === base.pluginId) return await Promise.resolve(base);
      if (pluginId === pve.pluginId) return await Promise.resolve(pve);
      throw new Error("source workload is inactive");
    },
    recordPreparedChange: (toolCallId, changeRef) => preparedChanges.push({ toolCallId, changeRef }),
  };
  return {
    catalog: await createTrustedBaseProviderCatalog(config, audit, runtime, { base }),
    client,
    preparedChanges,
  };
}

async function fixture(): Promise<{
  root: string;
  config: AgentConfig;
  audit: AuditLog;
}> {
  // macOS sandbox profiles commonly deny AF_UNIX bind in the per-user
  // /var/folders tmpdir while permitting the system /tmp namespace. The
  // production path is fixed under /run; this fixture needs only a portable
  // local Unix-socket directory.
  const root = await mkdtemp(join("/tmp", "agentd-source-workload-"));
  const config = testConfig(root);
  await mkdir(config.pluginRegistryPath, { recursive: true });
  const audit = new AuditLog(config.auditPath);
  await audit.initialize();
  return { root, config, audit };
}

describe("production workload.pve source composition", () => {
  it("runs the exact CAS snapshot through schema, scope, current, lease, and typed-provider gates", async () => {
    const { config, audit } = await fixture();
    const base = registration(config, "workload.base", "a", ["fixture.base"], []);
    const { manifest, plugin: pve } = await stageRepositoryPVE(config);
    expect(pve.digest).toBe(PVE_SOURCE_DIGEST);
    expect(pve.capabilities).toEqual(manifest.capabilities);
    expect(pve.requestedScopes).toEqual(manifest.requestedScopes);
    await writePluginCtl(config, [base, pve]);
    const broker = fakeLeaseBrokers.get(config.pluginLeaseSocketPath);
    if (broker === undefined) throw new Error("PVE composition lease broker is unavailable");
    const production = await productionPVEProviderHarness(config, audit, base, pve);
    expect(production.catalog.known.get("pve.guest.lifecycle")).toEqual({
      name: "pve.guest.lifecycle",
      requiredScopes: ["pve.guest.lifecycle"],
      executionMode: "sequential",
    });
    expect(production.catalog.active.has("pve.guest.lifecycle")).toBe(true);
    production.client.beforePrepare = () => {
      expect(broker.activeLeases).toEqual(new Set([`${pve.pluginId}@${pve.digest}`]));
    };
    const host = new SnapshotPVEHostRunner(base);
    const tools = await createSourceWorkloadTools({
      config,
      audit,
      registrations: [base, pve],
      providers: production.catalog,
      hostRunner: host,
    });
    const lifecycle = tools.find((tool) => tool.name === "ops_pve_guest_lifecycle_prepare");
    if (lifecycle === undefined) throw new Error("production PVE lifecycle tool was not composed");
    const input = {
      machineId: "machine-pve-composition-1234",
      targetId: "target-pve-composition-1234",
      action: "start",
      node: "pve1",
      guestType: "qemu",
      vmid: 100,
    } as const;
    await expect(lifecycle.execute(
      "pve-invalid-schema-call",
      { ...input, vmid: 99 },
      undefined,
      undefined,
      undefined as never,
    )).rejects.toThrow(/source-defined schema/u);
    expect(host.invokeCount).toBe(0);
    expect(broker.events).toEqual([]);

    const result = await lifecycle.execute(
      "pve-composition-call",
      input,
      undefined,
      undefined,
      undefined as never,
    );
    expect(result).toMatchObject({
      details: {
        pluginDigest: pve.digest,
        changeId: "change-pve-composition-1234",
        state: "PENDING_APPROVAL",
      },
    });
    const firstContent = result.content[0];
    expect(firstContent?.type).toBe("text");
    if (firstContent?.type === "text") {
      expect(firstContent.text).toContain("pending model-external local review");
    }
    expect(production.client.prepareRequests).toHaveLength(1);
    expect(production.client.prepareRequests[0]).toMatchObject({
      machineId: input.machineId,
      targetId: input.targetId,
      method: "change.prepare",
      policyRevision: "policy-pve-composition-1234",
      capabilityRevision: "capability-pve-composition-1234",
      operation: {
        kind: "pve.guest.action",
        pluginId: pve.pluginId,
        pluginDigest: pve.digest,
        action: "start",
        node: "pve1",
        guestType: "qemu",
        vmid: 100,
      },
    });
    expect(production.client.statusRequests).toHaveLength(1);
    expect(production.preparedChanges).toMatchObject([{
      toolCallId: "pve-composition-call",
      changeRef: {
        serverId: "server-pve-composition-1234",
        machineId: input.machineId,
        targetId: input.targetId,
        changeId: "change-pve-composition-1234",
      },
    }]);
    expect(host.invokeCount).toBe(1);
    expect(broker.activeLeases).toEqual(new Set());
    expect(broker.events).toEqual([
      { state: "LEASED", pluginId: pve.pluginId, digest: pve.digest },
      { state: "RELEASED", pluginId: pve.pluginId, digest: pve.digest },
    ]);
    const auditLines = (await readFile(config.auditPath, "utf8")).trim().split("\n");
    expect(auditLines).toHaveLength(3);
    const envelope = parseStrictJson(auditLines.at(-1) ?? "") as { event?: unknown };
    expect(envelope.event).toEqual({
      type: "source-workload",
      toolCallId: "pve-composition-call",
      tool: "ops_pve_guest_lifecycle_prepare",
      capability: "pve.guest.lifecycle",
      pluginId: pve.pluginId,
      pluginDigest: pve.digest,
    });
  });

  it("rejects the real PVE descriptor when its approved capability or scope is missing", async () => {
    const missingScopeFixture = await fixture();
    const missingScopeBase = registration(
      missingScopeFixture.config,
      "workload.base",
      "a",
      ["fixture.base"],
      [],
    );
    const { plugin: pve } = await stageRepositoryPVE(missingScopeFixture.config);
    const missingScope = {
      ...pve,
      requestedScopes: pve.requestedScopes.filter((scope) => scope !== "pve.guest.lifecycle"),
    };
    await writePluginCtl(missingScopeFixture.config, [missingScopeBase, missingScope]);
    const missingScopeProduction = await productionPVEProviderHarness(
      missingScopeFixture.config,
      missingScopeFixture.audit,
      missingScopeBase,
      missingScope,
    );
    await expect(createSourceWorkloadTools({
      config: missingScopeFixture.config,
      audit: missingScopeFixture.audit,
      registrations: [missingScopeBase, missingScope],
      providers: missingScopeProduction.catalog,
      hostRunner: new SnapshotPVEHostRunner(missingScopeBase),
    })).rejects.toThrow(/not approved for provider scope pve\.guest\.lifecycle/u);

    const missingCapabilityFixture = await fixture();
    const missingCapabilityBase = registration(
      missingCapabilityFixture.config,
      "workload.base",
      "a",
      ["fixture.base"],
      [],
    );
    const { plugin: pveCapability } = await stageRepositoryPVE(missingCapabilityFixture.config);
    const missingCapability = {
      ...pveCapability,
      capabilities: pveCapability.capabilities.filter((capability) =>
        capability !== "pve.guest.lifecycle"),
    };
    await writePluginCtl(
      missingCapabilityFixture.config,
      [missingCapabilityBase, missingCapability],
    );
    const missingCapabilityProduction = await productionPVEProviderHarness(
      missingCapabilityFixture.config,
      missingCapabilityFixture.audit,
      missingCapabilityBase,
      missingCapability,
    );
    await expect(createSourceWorkloadTools({
      config: missingCapabilityFixture.config,
      audit: missingCapabilityFixture.audit,
      registrations: [missingCapabilityBase, missingCapability],
      providers: missingCapabilityProduction.catalog,
      hostRunner: new SnapshotPVEHostRunner(missingCapabilityBase),
    })).rejects.toThrow(/descriptor capabilities do not exactly match/u);
  });

  it("rejects real PVE source invocation when the exact current digest drifts before lease", async () => {
    const { config, audit } = await fixture();
    const base = registration(config, "workload.base", "a", ["fixture.base"], []);
    const { plugin: pve } = await stageRepositoryPVE(config);
    await writePluginCtl(config, [base, pve]);
    const production = await productionPVEProviderHarness(config, audit, base, pve);
    const host = new SnapshotPVEHostRunner(base);
    const tools = await createSourceWorkloadTools({
      config,
      audit,
      registrations: [base, pve],
      providers: production.catalog,
      hostRunner: host,
    });
    const lifecycle = tools.find((tool) => tool.name === "ops_pve_guest_lifecycle_prepare");
    if (lifecycle === undefined) throw new Error("production PVE lifecycle tool was not composed");
    const changedDigest = `sha256:${"e".repeat(64)}`;
    const changed = {
      ...pve,
      digest: changedDigest,
      snapshotPath: join(config.pluginRegistryPath, "snapshots", "sha256", changedDigest.slice(7)),
    };
    await writePluginCtl(config, [base, changed]);
    await expect(lifecycle.execute(
      "pve-digest-drift-call",
      {
        machineId: "machine-pve-composition-1234",
        targetId: "target-pve-composition-1234",
        action: "start",
        node: "pve1",
        guestType: "qemu",
        vmid: 100,
      },
      undefined,
      undefined,
      undefined as never,
    )).rejects.toThrow(/current registration changed/u);
    expect(host.invokeCount).toBe(0);
    expect(production.client.prepareRequests).toEqual([]);
  });
});

describe("source workload ABI validation", () => {
  it("rejects duplicate JSON fields, unknown schema keywords, and duplicate capabilities", () => {
    expect(() => parseStrictJson('{"type":"result","type":"descriptor"}')).toThrow(/duplicate field/u);
    expect(() => parseWorkloadDescriptor({
      apiVersion: "agentd.workload/v1",
      tools: [{
        name: "ops_demo_one",
        label: "Demo",
        description: "Demo tool",
        capability: "demo.one",
        parameters: {
          type: "object",
          properties: { value: { type: "string", pattern: "(a+)+$" } },
          required: ["value"],
          additionalProperties: false,
        },
        providers: [],
        executionMode: "parallel",
      }],
    })).toThrow(/pattern/u);
    expect(() => parseWorkloadDescriptor({
      apiVersion: "agentd.workload/v1",
      tools: [
        ...descriptor([{ name: "ops_demo_one", capability: "demo.one" }]).tools,
        { ...descriptor([{ name: "ops_demo_two", capability: "demo.two" }]).tools[0], capability: "demo.one" },
      ],
    })).toThrow(/duplicate capability/u);
  });
});

describe("source workload runtime authorization", () => {
  it("routes an approved provider through source-defined tool behavior", async () => {
    const { config, audit } = await fixture();
    const base = registration(config, "workload.base", "a", ["demo.inventory"], ["control.machine.read"]);
    await writePluginCtl(config, [base]);
    const policy: TrustedWorkloadProviderPolicy = {
      name: "machine.list",
      requiredScopes: ["control.machine.read"],
      executionMode: "parallel",
    };
    const provider: TrustedWorkloadProvider = {
      ...policy,
      async invoke(_toolCallId, input) {
        return await Promise.resolve({
          content: [{ type: "text", text: `trusted:${JSON.stringify(input)}` }],
          details: { trustedProvider: true },
        });
      },
    };
    const host = new FakeHostRunner(
      new Map([[base.pluginId, descriptor([{
        name: "ops_machine_list",
        capability: "demo.inventory",
        providers: ["machine.list"],
      }])]]),
      async (_plugin, _tool, input, callProvider) =>
        await callProvider({ provider: "machine.list", input }) as WorkloadToolResult,
    );
    const tools = await createSourceWorkloadTools({
      config,
      audit,
      registrations: [base],
      providers: catalog([policy], [provider]),
      hostRunner: host,
    });
    const tool = tools[0];
    if (tool === undefined) throw new Error("source tool was not created");
    const result = await tool.execute(
      "source-provider-call",
      { message: "hello" },
      undefined,
      undefined,
      undefined as never,
    );
    expect(result.content).toEqual([{ type: "text", text: 'trusted:{"message":"hello"}' }]);
    expect(host.invokeCount).toBe(1);
  });

  it("loads an arbitrary provider-free custom workload beside workload.base", async () => {
    const { config, audit } = await fixture();
    const base = registration(config, "workload.base", "a", ["machine.list"], ["control.machine.read"]);
    const example = registration(config, "workload.example", "b", ["demo.echo"], []);
    await writePluginCtl(config, [base, example]);
    const machinePolicy: TrustedWorkloadProviderPolicy = {
      name: "machine.list",
      requiredScopes: ["control.machine.read"],
      executionMode: "parallel",
    };
    const host = new FakeHostRunner(new Map([
      [base.pluginId, descriptor([{
        name: "ops_machine_list",
        capability: "machine.list",
        providers: ["machine.list"],
      }])],
      [example.pluginId, descriptor([{ name: "ops_demo_echo", capability: "demo.echo" }])],
    ]));
    const tools = await createSourceWorkloadTools({
      config,
      audit,
      registrations: [base, example],
      providers: catalog([machinePolicy]),
      hostRunner: host,
    });
    expect(tools.map((tool) => tool.name)).toEqual(["ops_demo_echo"]);
    const result = await tools[0]?.execute(
      "custom-source-call",
      { message: "editable" },
      undefined,
      undefined,
      undefined as never,
    );
    const firstContent = result?.content[0];
    expect(firstContent?.type).toBe("text");
    if (firstContent?.type === "text") expect(firstContent.text).toContain("workload.example");
  });

  it("rejects unknown providers, missing approved scopes, and tool conflicts", async () => {
    const { config, audit } = await fixture();
    const base = registration(config, "workload.base", "a", ["machine.list"], []);
    await writePluginCtl(config, [base]);
    const host = new FakeHostRunner(new Map([[base.pluginId, descriptor([{
      name: "ops_machine_list",
      capability: "machine.list",
      providers: ["machine.list"],
    }])]]));
    const policy: TrustedWorkloadProviderPolicy = {
      name: "machine.list",
      requiredScopes: ["control.machine.read"],
      executionMode: "parallel",
    };
    await expect(createSourceWorkloadTools({
      config,
      audit,
      registrations: [base],
      providers: catalog(),
      hostRunner: host,
    })).rejects.toThrow(/unknown trusted provider/u);
    await expect(createSourceWorkloadTools({
      config,
      audit,
      registrations: [base],
      providers: catalog([policy]),
      hostRunner: host,
    })).rejects.toThrow(/not approved for provider scope/u);
    const authorized = { ...base, requestedScopes: ["control.machine.read"] };
    await writePluginCtl(config, [authorized]);
    await expect(createSourceWorkloadTools({
      config,
      audit,
      registrations: [authorized],
      providers: catalog([policy]),
      reservedToolNames: new Set(["ops_machine_list"]),
      hostRunner: host,
    })).rejects.toThrow(/conflicts/u);
  });

  it("rejects duplicate active capabilities before loading source", async () => {
    const { config, audit } = await fixture();
    const base = registration(config, "workload.base", "a", ["demo.echo"], []);
    const other = registration(config, "workload.other", "b", ["demo.echo"], []);
    await expect(createSourceWorkloadTools({
      config,
      audit,
      registrations: [base, other],
      providers: catalog(),
      hostRunner: new FakeHostRunner(new Map()),
    })).rejects.toThrow(/duplicated/u);
  });

  it("revalidates current before invoke and rejects digest drift", async () => {
    const { config, audit } = await fixture();
    const base = registration(config, "workload.base", "a", ["demo.echo"], []);
    await writePluginCtl(config, [base]);
    const host = new FakeHostRunner(new Map([
      [base.pluginId, descriptor([{ name: "ops_demo_echo", capability: "demo.echo" }])],
    ]));
    const tools = await createSourceWorkloadTools({
      config,
      audit,
      registrations: [base],
      providers: catalog(),
      hostRunner: host,
    });
    const changed = registration(config, "workload.base", "c", ["demo.echo"], []);
    await writePluginCtl(config, [changed]);
    await expect(tools[0]?.execute(
      "drifted-source-call",
      { message: "blocked" },
      undefined,
      undefined,
      undefined as never,
    )).rejects.toThrow(/current registration changed/u);
    expect(host.invokeCount).toBe(0);
  });

  it("rejects a provider request that the source tool did not declare", async () => {
    const { config, audit } = await fixture();
    const base = registration(config, "workload.base", "a", ["demo.echo", "machine.list"], [
      "control.machine.read",
    ]);
    await writePluginCtl(config, [base]);
    const policy: TrustedWorkloadProviderPolicy = {
      name: "machine.list",
      requiredScopes: ["control.machine.read"],
      executionMode: "parallel",
    };
    const provider: TrustedWorkloadProvider = {
      ...policy,
      async invoke() { return await Promise.resolve({ content: [{ type: "text", text: "unexpected" }] }); },
    };
    const host = new FakeHostRunner(new Map([[base.pluginId, descriptor([
      { name: "ops_demo_echo", capability: "demo.echo" },
      { name: "ops_machine_list", capability: "machine.list", providers: ["machine.list"] },
    ])]]), async (_plugin, _tool, input, callProvider) => {
      await callProvider({ provider: "machine.list", input });
      throw new Error("undeclared provider unexpectedly succeeded");
    });
    const tools = await createSourceWorkloadTools({
      config,
      audit,
      registrations: [base],
      providers: catalog([policy], [provider]),
      hostRunner: host,
    });
    const pureTool = tools.find((tool) => tool.name === "ops_demo_echo");
    await expect(pureTool?.execute(
      "undeclared-provider-call",
      { message: "blocked" },
      undefined,
      undefined,
      undefined as never,
    )).rejects.toThrow(/undeclared provider/u);
  });

  it("does not finish or release its invocation scope while an abort-ignoring provider is still running", async () => {
    const { config, audit } = await fixture();
    const base = registration(config, "workload.base", "a", ["machine.list"], [
      "control.machine.read",
    ]);
    await writePluginCtl(config, [base]);
    const providerStarted = Promise.withResolvers<undefined>();
    const providerFinish = Promise.withResolvers<undefined>();
    const policy: TrustedWorkloadProviderPolicy = {
      name: "machine.list",
      requiredScopes: ["control.machine.read"],
      executionMode: "parallel",
    };
    const provider: TrustedWorkloadProvider = {
      ...policy,
      async invoke() {
        providerStarted.resolve(undefined);
        await providerFinish.promise;
        return { content: [{ type: "text", text: "finished after abort" }] };
      },
    };
    const host = new FakeHostRunner(new Map([[base.pluginId, descriptor([{
      name: "ops_machine_list",
      capability: "machine.list",
      providers: ["machine.list"],
    }])]]), async (_plugin, _tool, input, callProvider, signal) =>
      await callProvider({ provider: "machine.list", input }, signal) as WorkloadToolResult);
    const tools = await createSourceWorkloadTools({
      config,
      audit,
      registrations: [base],
      providers: catalog([policy], [provider]),
      hostRunner: host,
    });
    const tool = tools[0];
    if (tool === undefined) throw new Error("source tool was not created");
    const controller = new AbortController();
    const execution = tool.execute(
      "abort-provider-call",
      { message: "finish safely" },
      controller.signal,
      undefined,
      undefined as never,
    );
    await providerStarted.promise;
    controller.abort();
    const early = await Promise.race([
      execution.then(() => "settled", () => "settled"),
      new Promise<"pending">((resolve) => setTimeout(() => resolve("pending"), 30)),
    ]);
    expect(early).toBe("pending");
    providerFinish.resolve(undefined);
    await expect(execution).resolves.toMatchObject({
      content: [{ type: "text", text: "finished after abort" }],
    });
  });
});
