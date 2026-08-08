import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  expectedAdapterAccount,
  containAdapterLaunch,
  prepareAdapterLaunch,
  runAdapter,
  type AdapterRunnerDependencies,
} from "../../src/runtime/adapter-run.js";
import type { ActiveRuntimeSourcePlugin } from "../../src/shared/source-plugin.js";

const temporaryDirectories: string[] = [];
const realBubblewrapContainmentAvailable = process.platform === "linux"
  && existsSync("/usr/bin/bwrap")
  && spawnSync("/usr/bin/bwrap", [
    "--die-with-parent", "--unshare-pid", "--as-pid-1", "--disable-userns",
    "--cap-drop", "ALL", "--bind", "/", "/", "--proc", "/proc",
    "--", "/usr/bin/true",
  ], { stdio: "ignore" }).status === 0;

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map(async (path) => {
    await rm(path, { recursive: true, force: true });
  }));
});

function statusDescriptor(adapterId: string): string {
  return JSON.stringify({
    apiVersion: "agentd.adapter/v1",
    schemaVersion: 1,
    adapterId,
    runtimeAuthority: {
      execution: "source-process",
      filesystem: "host-as-runtime-uid",
      network: "host",
      credentials: "runtime-uid-readable",
      actionScopeEnforcement: "digest-review-and-typed-ipc-contract",
    },
    session: {
      mapping: "adapter-owned",
      writerLease: "gateway-global",
      controlApiVersion: "agentd.adapter-session-control/v1",
      supportedControls: ["bind"],
    },
    inbound: {
      transport: "stdin",
      framing: "adapter-defined",
      contractApiVersion: "agentd.adapter-inbound/v1",
      supportedTypes: ["text"],
      maxFrameBytes: 65_536,
    },
    outbound: {
      transport: "completion-fd",
      framing: "ndjson",
      schema: "completion.v1",
      actionApiVersion: "agentd.adapter-outbound-action/v1",
      supportedActions: ["send"],
      maxFrameBytes: 65_536,
    },
    approval: { mode: "status-only", identitySource: "none", replayProtection: "none" },
  });
}

async function fixture(adapterId = "adapter.example"): Promise<{
  plugin: ActiveRuntimeSourcePlugin;
  dependencies: AdapterRunnerDependencies;
  entrypoint: string;
}> {
  const scopeNamespace = adapterId.slice("adapter.".length);
  const ownerUid = process.getuid?.() ?? 0;
  const createdRoot = await mkdtemp(join(tmpdir(), "ops-adapter-run-"));
  const root = await realpath(createdRoot);
  temporaryDirectories.push(root);
  const digest = `sha256:${"a".repeat(64)}`;
  const snapshot = join(root, "snapshots", "sha256", digest.slice("sha256:".length));
  await mkdir(snapshot, { recursive: true, mode: 0o700 });
  const entrypoint = join(snapshot, "adapter.mjs");
  const clientPath = join(root, "client.mjs");
  const bwrapPath = join(root, "bwrap");
  await writeFile(entrypoint, [
    "#!/usr/bin/env node",
    `const descriptor = ${statusDescriptor(adapterId)};`,
    "if (process.argv[2] === '--agentd-adapter-describe') {",
    "  process.stdout.write(JSON.stringify(descriptor) + '\\n');",
    "} else { process.stdout.write('ran\\n'); }",
    "",
  ].join("\n"), { mode: 0o500 });
  await chmod(entrypoint, 0o500);
  await writeFile(clientPath, "// fixed compiled client fixture\n", { mode: 0o400 });
  await chmod(clientPath, 0o400);
  await writeFile(bwrapPath, [
    `#!${process.execPath}`,
    "const { spawn } = require('node:child_process');",
    "const args = process.argv.slice(2);",
    "const separator = args.indexOf('--');",
    "const chdir = args.indexOf('--chdir');",
    "if (separator < 0 || chdir < 0) process.exit(125);",
    "const runtimeStdio = process.env.OPS_AGENT_ADAPTER_INPUT_FD === '4'",
    "  ? ['inherit', 'inherit', 'inherit', 'inherit', 'inherit'] : 'inherit';",
    "const child = spawn(args[separator + 1], args.slice(separator + 2), {",
    "  cwd: args[chdir + 1], env: process.env, shell: false, stdio: runtimeStdio,",
    "});",
    "if (Array.isArray(runtimeStdio)) {",
    "  const fs = require('node:fs'); fs.closeSync(3); fs.closeSync(4);",
    "}",
    "for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) {",
    "  process.on(signal, () => child.kill(signal));",
    "}",
    "child.once('error', (error) => { throw error; });",
    "child.once('close', (code, signal) => { process.exitCode = code ?? (signal ? 128 : 1); });",
    "",
  ].join("\n"), { mode: 0o500 });
  await chmod(bwrapPath, 0o500);
  const plugin: ActiveRuntimeSourcePlugin = {
    apiVersion: "agentd.plugin-registration/v1",
    schemaVersion: 1,
    pluginId: adapterId,
    kind: "adapter",
    version: "0.3.0",
    publisher: "example/adapter",
    digest,
    capabilities: [
      "adapter.inbound.text", "adapter.outbound.send", "adapter.session.bind", "approval.status",
    ],
    requestedScopes: [
      `adapter.inbound.text.${scopeNamespace}`,
      `adapter.outbound.send.${scopeNamespace}`,
      `adapter.session.bind.${scopeNamespace}`,
      "approval.status.remote",
    ],
    approvedBy: "local-admin:1000",
    approvedAt: "2026-08-08T00:00:00Z",
    entrypoint: "adapter.mjs",
    snapshotPath: snapshot,
  };
  const dependencies: AdapterRunnerDependencies = {
    pluginRegistryPath: root,
    pluginCtlPath: "/unused/agentd-pluginctl",
    bwrapPath,
    nodePath: process.execPath,
    clientPath,
    expectedOwnerUid: ownerUid,
    effectiveUid: Math.max(1, ownerUid),
    username: adapterId === "adapter.botmux" ? "ops-agent-botmux" : "ops-adapter-example",
    homeDirectory: join(root, "home"),
    environment: {
      NODE_OPTIONS: "--require=/untrusted.js",
      AWS_SECRET_ACCESS_KEY: "must-not-pass",
      OPS_AGENT_CONFIG: "/tmp/untrusted-agentd.json",
      BOTMUX_SESSION_ID: "session-botmux-1234",
      TERM: "xterm-256color",
    },
    stdinIsTTY: false,
    stdoutIsTTY: false,
    loadActive: async () => await Promise.resolve(plugin),
    acquireLease: async (expected) => await Promise.resolve({
      registration: expected,
      lost: new Promise<never>(() => undefined),
      release: async () => await Promise.resolve(),
    }),
    loadEnrolledAdministrator: async () => await Promise.resolve({
      version: 1,
      uid: dependencies.effectiveUid,
      username: dependencies.username,
    }),
  };
  return { plugin, dependencies, entrypoint };
}

function tuiDescriptor(): string {
  return JSON.stringify({
    apiVersion: "agentd.adapter/v1",
    schemaVersion: 1,
    adapterId: "adapter.tui",
    runtimeAuthority: {
      execution: "compiled-client",
      filesystem: "host-as-runtime-uid",
      network: "host",
      credentials: "runtime-uid-readable",
      actionScopeEnforcement: "digest-review-and-typed-ipc-contract",
    },
    session: {
      mapping: "local-terminal",
      writerLease: "gateway-global",
      controlApiVersion: "agentd.adapter-session-control/v1",
      supportedControls: ["bind"],
    },
    inbound: {
      transport: "tty",
      framing: "terminal-text",
      contractApiVersion: "agentd.adapter-inbound/v1",
      supportedTypes: ["text"],
      maxFrameBytes: 131_072,
    },
    outbound: {
      transport: "stdout",
      framing: "terminal-text",
      schema: "terminal.text/v1",
      actionApiVersion: "agentd.adapter-outbound-action/v1",
      supportedActions: ["display"],
      maxFrameBytes: 131_072,
    },
    approval: {
      mode: "local-tty",
      identitySource: "os-user+tty+sudo-pam",
      replayProtection: "local-command",
    },
  });
}

async function tuiFixture(): Promise<Awaited<ReturnType<typeof fixture>>> {
  const active = await fixture("adapter.tui");
  await rm(active.entrypoint);
  const manifest = {
    apiVersion: "agentd.plugin/v1",
    schemaVersion: 1,
    id: "adapter.tui",
    kind: "adapter",
    version: "0.3.1",
    publisher: "example/adapter",
    description: "declarative local terminal profile",
    entrypoint: "profile.json",
    capabilities: TUI_CAPABILITIES,
    requestedScopes: TUI_SCOPES,
  };
  await writeFile(join(active.plugin.snapshotPath, "manifest.json"), JSON.stringify(manifest), {
    mode: 0o400,
  });
  const profile = join(active.plugin.snapshotPath, "profile.json");
  await writeFile(profile, tuiDescriptor(), { mode: 0o400 });
  active.plugin.version = "0.3.1";
  active.plugin.entrypoint = "profile.json";
  active.plugin.capabilities = [...TUI_CAPABILITIES];
  active.plugin.requestedScopes = [...TUI_SCOPES];
  active.dependencies.username = "local-admin";
  active.dependencies.stdinIsTTY = true;
  active.dependencies.stdoutIsTTY = true;
  return { ...active, entrypoint: profile };
}

const TUI_CAPABILITIES = [
  "adapter.inbound.text", "adapter.outbound.display", "adapter.session.bind", "approval.local",
];
const TUI_SCOPES = [
  "adapter.inbound.text.local", "adapter.outbound.display.local",
  "adapter.session.bind.local", "approval.submit.local",
];

describe("source adapter runner", () => {
  it("launches adapter.tui only as a declarative profile through the fixed compiled client", async () => {
    const { plugin, dependencies } = await tuiFixture();
    const launch = await prepareAdapterLaunch(plugin.pluginId, ["--version"], dependencies);
    expect(launch.executable).toBe(await realpath(process.execPath));
    expect(launch.arguments).toEqual([await realpath(dependencies.clientPath), "--version"]);
    expect(launch.workingDirectory).toBe("/");
    expect(launch.descriptor).toEqual(JSON.parse(tuiDescriptor()));
    await expect(containAdapterLaunch(launch, dependencies)).resolves.toEqual({
      executable: launch.executable,
      arguments: launch.arguments,
      workingDirectory: "/",
    });
  });

  it("explicitly refuses executable adapter.tui source without running it", async () => {
    const active = await tuiFixture();
    const executable = join(active.plugin.snapshotPath, "adapter.mjs");
    await rm(join(active.plugin.snapshotPath, "profile.json"));
    await writeFile(executable, "throw new Error('tui source executed');\n", { mode: 0o500 });
    active.plugin.entrypoint = "adapter.mjs";
    await expect(prepareAdapterLaunch(active.plugin.pluginId, [], active.dependencies))
      .rejects.toThrow("declarative profile.json");
  });

  it("executes only a strict status-only descriptor with a sanitized environment", async () => {
    const { plugin, dependencies, entrypoint } = await fixture();
    const launch = await prepareAdapterLaunch(plugin.pluginId, [
      "--extension", "/tmp/untrusted-extension.mjs",
      "--session-id", "session-1234",
    ], dependencies);
    expect(launch.plugin.digest).toBe(plugin.digest);
    expect(launch.arguments).toEqual([entrypoint, "--session-id", "session-1234"]);
    expect(launch.client.arguments).toEqual([
      await realpath(dependencies.clientPath), "--session-id", "session-1234",
    ]);
    expect(launch.descriptor.approval.mode).toBe("status-only");
    expect(launch.environment).toMatchObject({
      OPS_AGENT_ADAPTER_ID: plugin.pluginId,
      OPS_AGENT_ADAPTER_DIGEST: plugin.digest,
      OPS_AGENT_ADAPTER_APPROVAL_MODE: "status-only",
      TERM: "xterm-256color",
    });
    expect(launch.environment).not.toHaveProperty("NODE_OPTIONS");
    expect(launch.environment).not.toHaveProperty("AWS_SECRET_ACCESS_KEY");
    expect(launch.environment).not.toHaveProperty("OPS_AGENT_CONFIG");
    expect(launch.environment).not.toHaveProperty("BOTMUX_SESSION_ID");
    const contained = await containAdapterLaunch(launch, dependencies);
    expect(contained.executable).toBe(await realpath(dependencies.bwrapPath));
    expect(contained.arguments).toEqual([
      "--die-with-parent",
      "--unshare-pid",
      "--as-pid-1",
      "--disable-userns",
      "--cap-drop", "ALL",
      "--bind", "/", "/",
      "--proc", "/proc",
      "--chdir", plugin.snapshotPath,
      "--",
      launch.executable,
      ...launch.arguments,
    ]);
    expect(contained.arguments).not.toContain("--new-session");
    expect(contained.arguments).not.toContain("--unshare-net");
  });

  it("bridges split FD4 input/FD3 completion and delivers runner-owned FD5 context", async () => {
    const active = await fixture();
    const sessionId = "session-bridge-1234";
    const externalSessionId = "external-bridge-1234";
    const sourceResult = join(active.dependencies.pluginRegistryPath, "source-result.json");
    const clientResult = join(active.dependencies.pluginRegistryPath, "client-result.json");
    const bind = {
      apiVersion: "agentd.adapter-session-control/v1",
      schemaVersion: 1,
      type: "bind",
      controlId: "control:bridge:00000001",
      externalSessionId,
      sessionId,
    };
    const inbound = {
      apiVersion: "agentd.adapter-inbound/v1",
      schemaVersion: 1,
      type: "text",
      ingressId: "ingress:bridge:00000001",
      externalSessionId,
      conversationType: "direct",
      text: "检查分片通道",
      source: { authentication: "unverified", principalId: "adapter:test" },
      observedAt: "2026-08-08T08:00:00Z",
    };
    const wire = Buffer.from(`${JSON.stringify(bind)}\n${JSON.stringify(inbound)}\n`);
    await chmod(active.entrypoint, 0o700);
    await writeFile(active.entrypoint, [
      "#!/usr/bin/env node",
      "import fs from 'node:fs';",
      `const descriptor = ${statusDescriptor(active.plugin.pluginId)};`,
      "if (process.argv[2] === '--agentd-adapter-describe') {",
      "  process.stdout.write(JSON.stringify(descriptor) + '\\n');",
      "} else {",
      `  const wire = Buffer.from(${JSON.stringify(wire.toString("base64"))}, 'base64');`,
      "  fs.writeSync(4, wire.subarray(0, 5));",
      "  fs.writeSync(4, wire.subarray(5, wire.length - 3));",
      "  fs.writeSync(4, wire.subarray(wire.length - 3));",
      "  fs.closeSync(4);",
      "  const completion = fs.readFileSync(3, 'utf8');",
      `  fs.writeFileSync(${JSON.stringify(sourceResult)}, completion);`,
      "}",
      "",
    ].join("\n"), { mode: 0o500 });
    await chmod(active.entrypoint, 0o500);

    await chmod(active.dependencies.clientPath, 0o600);
    await writeFile(active.dependencies.clientPath, [
      "import fs from 'node:fs';",
      "const context = fs.readFileSync(5, 'utf8');",
      "const input = fs.readFileSync(4, 'utf8');",
      `fs.writeFileSync(${JSON.stringify(clientResult)}, JSON.stringify({ context, input }));`,
      "fs.writeSync(3, JSON.stringify({",
      "  version: 1, type: 'completion', eventId: 'event-bridge-1234',",
      "  outcome: 'success', content: 'done',",
      "}) + '\\n');",
      "fs.closeSync(3);",
      "",
    ].join("\n"), { mode: 0o400 });
    await chmod(active.dependencies.clientPath, 0o400);

    for (const prompt of ["untrusted positional prompt", "@/tmp/untrusted.prompt"]) {
      await expect(prepareAdapterLaunch(
        active.plugin.pluginId,
        ["--session-id", sessionId, prompt],
        active.dependencies,
      )).rejects.toThrow("framed input on stdin");
    }
    await expect(runAdapter(
      active.plugin.pluginId,
      ["--session-id", sessionId],
      active.dependencies,
    )).resolves.toBe(0);
    expect(JSON.parse(await readFile(sourceResult, "utf8"))).toMatchObject({
      type: "completion",
      content: "done",
    });
    const received = JSON.parse(await readFile(clientResult, "utf8")) as {
      context: string;
      input: string;
    };
    expect(JSON.parse(received.context)).toMatchObject({
      apiVersion: "agentd.adapter-client-context/v1",
      pluginId: active.plugin.pluginId,
      digest: active.plugin.digest,
    });
    expect(received.input).toBe(wire.toString("utf8"));
    expect(received.input).not.toContain("untrusted positional prompt");
  });

  it("binds each custom adapter identity to a deterministic dedicated OS account", async () => {
    expect(expectedAdapterAccount("adapter.example")).toBe("ops-adapter-example");
    expect(expectedAdapterAccount(`adapter.${"long".repeat(12)}`)).toMatch(/^ops-adapter-[a-f0-9]{16}$/u);
    const active = await fixture("adapter.second");
    active.dependencies.username = "ops-adapter-example";
    await expect(prepareAdapterLaunch(active.plugin.pluginId, [], active.dependencies))
      .rejects.toThrow("dedicated derived account");
  });

  it("rejects a custom adapter account that forges a TUI launch even with a PTY", async () => {
    const active = await tuiFixture();
    active.dependencies.username = "ops-adapter-evil";
    active.dependencies.effectiveUid = 2001;
    active.dependencies.loadEnrolledAdministrator = async () => await Promise.resolve({
      version: 1,
      uid: 1000,
      username: "local-admin",
    });
    await expect(prepareAdapterLaunch(active.plugin.pluginId, [], active.dependencies))
      .rejects.toThrow("enrolled local administrator");
  });

  it("passes only the bounded BotMux session correlation field to adapter.botmux", async () => {
    const { plugin, dependencies } = await fixture("adapter.botmux");
    const launch = await prepareAdapterLaunch(
      plugin.pluginId,
      ["--session-id", "session-botmux-1234"],
      dependencies,
    );
    expect(launch.environment.BOTMUX_SESSION_ID).toBe("session-botmux-1234");
    for (const prompt of ["untrusted positional prompt", "@/tmp/untrusted.prompt"]) {
      await expect(prepareAdapterLaunch(
        plugin.pluginId,
        ["--session-id", "session-botmux-1234", prompt],
        dependencies,
      )).rejects.toThrow("framed input on stdin");
    }
  });

  it("fails closed on wrong kind, path tamper, and current drift", async () => {
    const wrongKind = await fixture();
    wrongKind.plugin.kind = "workload";
    await expect(prepareAdapterLaunch(wrongKind.plugin.pluginId, [], wrongKind.dependencies))
      .rejects.toThrow("non-adapter");

    const tampered = await fixture();
    await chmod(tampered.entrypoint, 0o522);
    await expect(prepareAdapterLaunch(tampered.plugin.pluginId, [], tampered.dependencies))
      .rejects.toThrow("mutable or non-owned entry");

    const escaped = await fixture();
    escaped.plugin.snapshotPath = join(escaped.dependencies.pluginRegistryPath, "outside");
    await expect(prepareAdapterLaunch(escaped.plugin.pluginId, [], escaped.dependencies))
      .rejects.toThrow("approved digest");

    const drifted = await fixture();
    let calls = 0;
    drifted.dependencies.loadActive = async () => {
      calls += 1;
      return await Promise.resolve(calls === 1 ? drifted.plugin : {
        ...drifted.plugin,
        digest: `sha256:${"b".repeat(64)}`,
      });
    };
    await expect(prepareAdapterLaunch(drifted.plugin.pluginId, [], drifted.dependencies))
      .rejects.toThrow("changed during launch");
  });

  it("recursively rejects mutable imported files and symlinks anywhere in the snapshot", async () => {
    const mutable = await fixture();
    const libraryDirectory = join(mutable.plugin.snapshotPath, "lib");
    await mkdir(libraryDirectory, { mode: 0o700 });
    const importedFile = join(libraryDirectory, "provider.mjs");
    await writeFile(importedFile, "export default 1;\n", { mode: 0o600 });
    await chmod(importedFile, 0o620);
    await expect(prepareAdapterLaunch(mutable.plugin.pluginId, [], mutable.dependencies))
      .rejects.toThrow("mutable or non-owned entry");

    const linked = await fixture();
    await symlink(linked.entrypoint, join(linked.plugin.snapshotPath, "alias.mjs"));
    await expect(prepareAdapterLaunch(linked.plugin.pluginId, [], linked.dependencies))
      .rejects.toThrow("mutable or non-owned entry");
  });

  it("rejects root execution and a non-TUI adapter claiming local approval", async () => {
    const root = await fixture();
    root.dependencies.effectiveUid = 0;
    await expect(prepareAdapterLaunch(root.plugin.pluginId, [], root.dependencies))
      .rejects.toThrow("never run as root");

    const claim = await fixture();
    await chmod(claim.entrypoint, 0o700);
    await writeFile(claim.entrypoint, [
      "#!/usr/bin/env node",
      `const descriptor = ${JSON.stringify({
        ...JSON.parse(statusDescriptor("adapter.example")) as object,
        approval: {
          mode: "local-tty",
          identitySource: "os-user+tty+sudo-pam",
          replayProtection: "local-command",
        },
      })};`,
      "process.stdout.write(JSON.stringify(descriptor) + '\\n');",
      "",
    ].join("\n"), { mode: 0o500 });
    await chmod(claim.entrypoint, 0o500);
    await expect(prepareAdapterLaunch(claim.plugin.pluginId, [], claim.dependencies))
      .rejects.toThrow("only adapter.tui");
  });

  it("rejects action-level capability confusion between descriptor and manifest", async () => {
    const active = await fixture();
    const confused = {
      ...JSON.parse(statusDescriptor(active.plugin.pluginId)) as object,
      outbound: {
        ...(JSON.parse(statusDescriptor(active.plugin.pluginId)) as {
          outbound: Record<string, unknown>;
        }).outbound,
        supportedActions: ["quote"],
      },
    };
    await chmod(active.entrypoint, 0o700);
    await writeFile(active.entrypoint, [
      "#!/usr/bin/env node",
      `const descriptor = ${JSON.stringify(confused)};`,
      "if (process.argv[2] === '--agentd-adapter-describe') {",
      "  process.stdout.write(JSON.stringify(descriptor) + '\\n');",
      "}",
      "",
    ].join("\n"), { mode: 0o500 });
    await chmod(active.entrypoint, 0o500);

    await expect(prepareAdapterLaunch(active.plugin.pluginId, [], active.dependencies))
      .rejects.toThrow("capabilities/actions do not match");
  });

  it("terminates a long-lived adapter when its active digest changes", async () => {
    const active = await fixture();
    await chmod(active.entrypoint, 0o700);
    await writeFile(active.entrypoint, [
      "#!/usr/bin/env node",
      `const descriptor = ${statusDescriptor(active.plugin.pluginId)};`,
      "if (process.argv[2] === '--agentd-adapter-describe') {",
      "  process.stdout.write(JSON.stringify(descriptor) + '\\n');",
      "} else { setInterval(() => {}, 1000); }",
      "",
    ].join("\n"), { mode: 0o500 });
    await chmod(active.entrypoint, 0o500);
    let calls = 0;
    active.dependencies.runtimeRecheckMilliseconds = 10;
    active.dependencies.loadActive = async () => {
      calls += 1;
      return await Promise.resolve(calls <= 3 ? active.plugin : {
        ...active.plugin,
        digest: `sha256:${"c".repeat(64)}`,
      });
    };
    await expect(runAdapter(
      active.plugin.pluginId,
      ["--session-id", "session-runtime-1234"],
      active.dependencies,
    ))
      .rejects.toThrow("old source process was terminated");
  });

  it("terminates a long-lived adapter when the lease broker connection is lost", async () => {
    const active = await fixture();
    const started = join(active.dependencies.pluginRegistryPath, "adapter-started");
    await chmod(active.entrypoint, 0o700);
    await writeFile(active.entrypoint, [
      "#!/usr/bin/env node",
      "import { writeFileSync } from 'node:fs';",
      `const descriptor = ${statusDescriptor(active.plugin.pluginId)};`,
      "if (process.argv[2] === '--agentd-adapter-describe') {",
      "  process.stdout.write(JSON.stringify(descriptor) + '\\n');",
      `} else { writeFileSync(${JSON.stringify(started)}, 'started'); setInterval(() => {}, 1000); }`,
      "",
    ].join("\n"), { mode: 0o500 });
    await chmod(active.entrypoint, 0o500);
    const lost = Promise.withResolvers<never>();
    let released = false;
    active.dependencies.acquireLease = async (expected) => await Promise.resolve({
      registration: expected,
      lost: lost.promise,
      release: () => {
        released = true;
        return Promise.resolve();
      },
    });

    const runtime = runAdapter(
      active.plugin.pluginId,
      ["--session-id", "session-runtime-1234"],
      active.dependencies,
    );
    void runtime.catch(() => undefined);
    for (let attempt = 0; attempt < 100 && !existsSync(started); attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    expect(existsSync(started)).toBe(true);
    lost.reject(new Error("plugin lease broker restarted"));
    await expect(runtime).rejects.toThrow("plugin lease broker restarted");
    expect(released).toBe(true);
  });

  it("holds adapter.tui's exact digest lease until the compiled client exits", async () => {
    const active = await tuiFixture();
    await chmod(active.dependencies.clientPath, 0o600);
    await writeFile(
      active.dependencies.clientPath,
      "setTimeout(() => process.exit(0), 100);\n",
      { mode: 0o400 },
    );
    await chmod(active.dependencies.clientPath, 0o400);
    let held = false;
    let releases = 0;
    const acquired = Promise.withResolvers<undefined>();
    active.dependencies.acquireLease = async (expected) => {
      held = true;
      acquired.resolve(undefined);
      return await Promise.resolve({
        registration: expected,
        lost: new Promise<never>(() => undefined),
        release: () => {
          releases += 1;
          held = false;
          return Promise.resolve();
        },
      });
    };

    const runtime = runAdapter(active.plugin.pluginId, ["--version"], active.dependencies);
    await acquired.promise;
    expect(held).toBe(true);
    await expect(runtime).resolves.toBe(0);
    expect(held).toBe(false);
    expect(releases).toBe(1);
  });

  it("acknowledges the TUI self-update handoff only after releasing the runner lease", async () => {
    const active = await tuiFixture();
    const acknowledgement = join(active.dependencies.pluginRegistryPath, "tui-handoff.json");
    await chmod(active.dependencies.clientPath, 0o600);
    await writeFile(active.dependencies.clientPath, [
      "import fs from 'node:fs';",
      `const request = ${JSON.stringify({
        apiVersion: "agentd.adapter-runner-control/v1",
        action: "release-tui-self-update-lease",
        pluginId: "adapter.tui",
        digest: active.plugin.digest,
      })};`,
      "const payload = Buffer.from(JSON.stringify(request), 'utf8');",
      "const frame = Buffer.alloc(4 + payload.length);",
      "frame.writeUInt32BE(payload.length, 0);",
      "payload.copy(frame, 4);",
      "fs.writeSync(6, frame);",
      "const readExact = (fd, bytes) => {",
      "  const value = Buffer.alloc(bytes);",
      "  let offset = 0;",
      "  while (offset < bytes) {",
      "    const count = fs.readSync(fd, value, offset, bytes - offset, null);",
      "    if (count === 0) throw new Error('runner closed the control response');",
      "    offset += count;",
      "  }",
      "  return value;",
      "};",
      "const header = readExact(7, 4);",
      "const response = JSON.parse(readExact(7, header.readUInt32BE(0)).toString('utf8'));",
      "if (!response.ok || response.state !== 'RELEASED') process.exit(2);",
      `fs.writeFileSync(${JSON.stringify(acknowledgement)}, JSON.stringify(response));`,
      "fs.closeSync(6);",
      "fs.closeSync(7);",
      "",
    ].join("\n"), { mode: 0o400 });
    await chmod(active.dependencies.clientPath, 0o400);

    const releaseStarted = Promise.withResolvers<undefined>();
    const allowRelease = Promise.withResolvers<undefined>();
    let releases = 0;
    active.dependencies.acquireLease = async (expected) => await Promise.resolve({
      registration: expected,
      lost: new Promise<never>(() => undefined),
      release: async () => {
        releases += 1;
        releaseStarted.resolve(undefined);
        await allowRelease.promise;
      },
    });

    const runtime = runAdapter(
      active.plugin.pluginId,
      ["--session-id", "session-tui-self-update-1234"],
      active.dependencies,
    );
    await releaseStarted.promise;
    expect(existsSync(acknowledgement)).toBe(false);
    allowRelease.resolve(undefined);
    await expect(runtime).resolves.toBe(0);
    expect(JSON.parse(await readFile(acknowledgement, "utf8"))).toEqual({
      apiVersion: "agentd.adapter-runner-control/v1",
      ok: true,
      state: "RELEASED",
    });
    expect(releases).toBe(1);
  });

  it("does not spawn an adapter when the leased current digest differs", async () => {
    const active = await fixture();
    let released = false;
    active.dependencies.acquireLease = async (expected) => await Promise.resolve({
      registration: { ...expected, digest: `sha256:${"d".repeat(64)}` },
      lost: new Promise<never>(() => undefined),
      release: () => {
        released = true;
        return Promise.resolve();
      },
    });
    await expect(runAdapter(active.plugin.pluginId, [], active.dependencies))
      .rejects.toThrow("changed before its runtime lease");
    expect(released).toBe(true);
  });

  it.runIf(realBubblewrapContainmentAvailable)(
    "kills detached source descendants before releasing the adapter runtime",
    async () => {
      const active = await fixture();
      const marker = join(active.dependencies.pluginRegistryPath, "detached-survived");
      await chmod(active.entrypoint, 0o700);
      await writeFile(active.entrypoint, [
        "#!/usr/bin/env node",
        "import { spawn } from 'node:child_process';",
        `const descriptor = ${statusDescriptor(active.plugin.pluginId)};`,
        "const child = spawn(process.execPath, [",
        "  '-e',",
        `  ${JSON.stringify(`setTimeout(() => require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'escaped'), 250); setTimeout(() => {}, 1000);`)},`,
        "], { detached: true, stdio: 'ignore' });",
        "child.unref();",
        "if (process.argv[2] === '--agentd-adapter-describe') {",
        "  process.stdout.write(JSON.stringify(descriptor) + '\\n');",
        "}",
        "",
      ].join("\n"), { mode: 0o500 });
      await chmod(active.entrypoint, 0o500);
      active.dependencies.bwrapPath = "/usr/bin/bwrap";

      await expect(runAdapter(
        active.plugin.pluginId,
        ["--session-id", "session-detached-1234"],
        active.dependencies,
      )).resolves.toBe(0);
      await new Promise((resolve) => setTimeout(resolve, 450));
      expect(existsSync(marker)).toBe(false);
    },
  );
});
