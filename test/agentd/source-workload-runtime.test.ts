import { chmod, mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { createServer, type Server, type Socket } from "node:net";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { AgentConfig } from "../../src/shared/config.js";
import type { ActiveRuntimeSourcePlugin } from "../../src/shared/source-plugin.js";
import {
  parseStrictJson,
  parseWorkloadDescriptor,
  type WorkloadDescriptor,
  type WorkloadToolResult,
} from "../../src/shared/workload-runtime.js";
import { AuditLog } from "../../src/agentd/audit.js";
import {
  createSourceWorkloadTools,
} from "../../src/agentd/source-workload-runtime.js";
import type {
  WorkloadHostRunner,
  WorkloadProviderRequest,
} from "../../src/agentd/workload-host-runner.js";
import type {
  TrustedWorkloadProvider,
  TrustedWorkloadProviderCatalog,
  TrustedWorkloadProviderPolicy,
} from "../../src/agentd/workload-providers.js";
import { encodeFrame, FrameDecoder } from "../../src/shared/framing.js";

const fakeLeaseBrokers = new Map<string, {
  server: Server;
  sockets: Set<Socket>;
  registrations: Map<string, ActiveRuntimeSourcePlugin>;
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
    const broker = createServer((socket) => {
      sockets.add(socket);
      socket.once("close", () => sockets.delete(socket));
      const decoder = new FrameDecoder();
      let leased = false;
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
            socket.write(encodeFrame({
              version: 1,
              ok: true,
              state: "LEASED",
              registration: plugin,
            }));
          } else if (request.version === 1 && request.action === "release") {
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

function catalog(
  policies: readonly TrustedWorkloadProviderPolicy[] = [],
  providers: readonly TrustedWorkloadProvider[] = [],
): TrustedWorkloadProviderCatalog {
  return {
    known: new Map(policies.map((policy) => [policy.name, policy])),
    active: new Map(providers.map((provider) => [provider.name, provider])),
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
