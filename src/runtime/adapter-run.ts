#!/usr/bin/env node
import { spawn, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat, readFile, readdir, realpath } from "node:fs/promises";
import { userInfo } from "node:os";
import { dirname, extname, isAbsolute, join } from "node:path";
import type { Readable, Writable } from "node:stream";
import { fileURLToPath } from "node:url";
import {
  ADAPTER_DESCRIBE_ARGUMENT,
  ADAPTER_CLIENT_CONTEXT_API_VERSION,
  ADAPTER_COMPLETION_FD,
  ADAPTER_CONTEXT_FD,
  ADAPTER_INPUT_FD,
  ADAPTER_RUNNER_CONTROL_API_VERSION,
  ADAPTER_RUNNER_CONTROL_REQUEST_FD,
  ADAPTER_RUNNER_CONTROL_RESPONSE_FD,
  MAX_ADAPTER_DESCRIPTOR_BYTES,
  MAX_ADAPTER_CLIENT_CONTEXT_BYTES,
  adapterDescriptorGrant,
  parseAdapterDescriptorJson,
  parseAdapterRunnerControlRequest,
  type AdapterDescriptor,
} from "../shared/adapter-runtime.js";
import { encodeFrame, FrameDecoder } from "../shared/framing.js";
import { parseSessionId } from "../shared/domain.js";
import {
  escapeUntrustedTerminalText,
  terminalSafeTextFromBytes,
} from "../shared/terminal-safety.js";
import {
  acquireActiveRuntimeSourcePluginLease,
  loadActiveRuntimeSourcePlugin,
  type ActiveRuntimeSourcePluginLease,
  type ActiveRuntimeSourcePlugin,
} from "../shared/source-plugin.js";
import {
  loadEnrolledLocalAdministrator,
  type EnrolledLocalAdministrator,
} from "../shared/local-administrator.js";

const FIXED_ROOT = "/opt/pi-ops-agent/current";
const FIXED_PLUGIN_REGISTRY = "/var/lib/ops-agent/plugins";
const FIXED_PLUGINCTL = `${FIXED_ROOT}/bin/agentd-pluginctl`;
const FIXED_BWRAP = "/usr/bin/bwrap";
const FIXED_NODE = `${FIXED_ROOT}/runtime/node`;
const FIXED_CLIENT = `${FIXED_ROOT}/dist/client/index.js`;
const FIXED_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const DESCRIBE_TIMEOUT_MILLISECONDS = 5_000;
const MAX_DESCRIPTOR_STDERR_BYTES = 8 * 1024;
const MAX_SNAPSHOT_ENTRIES = 512;
const MAX_SNAPSHOT_DEPTH = 24;
const MAX_SNAPSHOT_FILE_BYTES = 8 * 1024 * 1024;
const MAX_SNAPSHOT_TOTAL_BYTES = 32 * 1024 * 1024;
const RUNTIME_RECHECK_MILLISECONDS = 30_000;
const RUNTIME_STOP_GRACE_MILLISECONDS = 5_000;
const TUI_SELF_UPDATE_EXIT_MILLISECONDS = 11 * 60_000;
const ADAPTER_ID_PATTERN = /^adapter\.[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?$/u;

export interface AdapterRunnerDependencies {
  pluginRegistryPath: string;
  pluginCtlPath: string;
  bwrapPath: string;
  nodePath: string;
  clientPath: string;
  expectedOwnerUid: number;
  effectiveUid: number;
  username: string;
  homeDirectory: string;
  environment: NodeJS.ProcessEnv;
  stdinIsTTY: boolean;
  stdoutIsTTY: boolean;
  runtimeRecheckMilliseconds?: number;
  loadActive(pluginId: string): Promise<ActiveRuntimeSourcePlugin>;
  acquireLease(plugin: ActiveRuntimeSourcePlugin): Promise<ActiveRuntimeSourcePluginLease>;
  loadEnrolledAdministrator(): Promise<EnrolledLocalAdministrator>;
}

export interface PreparedAdapterLaunch {
  plugin: ActiveRuntimeSourcePlugin;
  descriptor: AdapterDescriptor;
  executable: string;
  arguments: string[];
  workingDirectory: string;
  environment: NodeJS.ProcessEnv;
  client: {
    executable: string;
    arguments: string[];
    workingDirectory: string;
    environment: NodeJS.ProcessEnv;
  };
}

export interface ContainedAdapterLaunch {
  executable: string;
  arguments: string[];
  workingDirectory: string;
}

function exactValues(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function sameRuntimeRegistration(
  left: ActiveRuntimeSourcePlugin,
  right: ActiveRuntimeSourcePlugin,
): boolean {
  return left.pluginId === right.pluginId && left.kind === right.kind &&
    left.version === right.version && left.publisher === right.publisher &&
    left.digest === right.digest && left.entrypoint === right.entrypoint &&
    left.snapshotPath === right.snapshotPath &&
    exactValues(left.capabilities, right.capabilities) &&
    exactValues(left.requestedScopes, right.requestedScopes);
}

function requireAdapterRegistration(plugin: ActiveRuntimeSourcePlugin): void {
  if (plugin.kind !== "adapter" || !ADAPTER_ID_PATTERN.test(plugin.pluginId)) {
    throw new Error("adapter runner received a non-adapter registration");
  }
}

export function expectedAdapterAccount(pluginId: string): string {
  const suffix = pluginId.slice("adapter.".length).replaceAll(".", "-");
  if (suffix.length <= 20) return `ops-adapter-${suffix}`;
  const shortHash = createHash("sha256").update(pluginId, "utf8").digest("hex").slice(0, 16);
  return `ops-adapter-${shortHash}`;
}

function requireAdapterAccount(
  pluginId: string,
  username: string,
  effectiveUid: number,
  enrolledAdministrator?: EnrolledLocalAdministrator,
): void {
  if (pluginId === "adapter.tui") {
    if (username === "root" || username.startsWith("ops-agent")
      || username.startsWith("ops-adapter-")
      || enrolledAdministrator === undefined
      || enrolledAdministrator.uid !== effectiveUid
      || enrolledAdministrator.username !== username) {
      throw new Error("adapter.tui must run as the enrolled local administrator account");
    }
    return;
  }
  if (pluginId === "adapter.botmux") {
    if (username !== "ops-agent-botmux") {
      throw new Error("adapter.botmux must run as its dedicated ops-agent-botmux account");
    }
    return;
  }
  if (username !== expectedAdapterAccount(pluginId)) {
    throw new Error(`custom source adapter ${pluginId} must run under its dedicated derived account`);
  }
}

async function assertImmutablePath(
  path: string,
  expectedKind: "directory" | "file",
  expectedOwnerUid: number,
  requireExecutable = false,
): Promise<void> {
  const info = await lstat(path);
  if (info.isSymbolicLink()
    || (expectedKind === "directory" ? !info.isDirectory() : !info.isFile())
    || info.uid !== expectedOwnerUid
    || (info.mode & 0o022) !== 0
    || (requireExecutable && (info.mode & 0o111) === 0)) {
    throw new Error(`adapter runtime path is not an immutable ${expectedKind}: ${path}`);
  }
}

async function assertImmutableSnapshotTree(root: string, expectedOwnerUid: number): Promise<void> {
  let entries = 0;
  let totalBytes = 0;
  const visit = async (directory: string, depth: number): Promise<void> => {
    if (depth > MAX_SNAPSHOT_DEPTH) throw new Error("adapter snapshot exceeds its depth limit");
    const children = await readdir(directory, { withFileTypes: true });
    for (const child of children) {
      entries += 1;
      if (entries > MAX_SNAPSHOT_ENTRIES) throw new Error("adapter snapshot has too many entries");
      const path = join(directory, child.name);
      const info = await lstat(path);
      if (info.isSymbolicLink() || info.uid !== expectedOwnerUid || (info.mode & 0o022) !== 0) {
        throw new Error(`adapter snapshot contains a mutable or non-owned entry: ${path}`);
      }
      if (info.isDirectory()) {
        await visit(path, depth + 1);
        continue;
      }
      if (!info.isFile()) throw new Error(`adapter snapshot contains a special file: ${path}`);
      if (info.size < 0 || info.size > MAX_SNAPSHOT_FILE_BYTES) {
        throw new Error(`adapter snapshot file exceeds its size limit: ${path}`);
      }
      totalBytes += info.size;
      if (totalBytes > MAX_SNAPSHOT_TOTAL_BYTES) {
        throw new Error("adapter snapshot exceeds its total size limit");
      }
    }
  };
  await assertImmutablePath(root, "directory", expectedOwnerUid);
  await visit(root, 0);
}

async function assertImmutableSnapshot(
  plugin: ActiveRuntimeSourcePlugin,
  pluginRegistryPath: string,
  expectedOwnerUid: number,
  requireExecutableEntrypoint: boolean,
): Promise<string> {
  const expectedSnapshot = join(
    pluginRegistryPath,
    "snapshots",
    "sha256",
    plugin.digest.slice("sha256:".length),
  );
  if (plugin.snapshotPath !== expectedSnapshot || await realpath(plugin.snapshotPath) !== plugin.snapshotPath) {
    throw new Error("adapter runtime snapshot path does not match its approved digest");
  }
  let cursor = plugin.snapshotPath;
  for (;;) {
    await assertImmutablePath(cursor, "directory", expectedOwnerUid);
    if (cursor === pluginRegistryPath) break;
    const parent = dirname(cursor);
    if (parent === cursor || !cursor.startsWith(`${pluginRegistryPath}/`)) {
      throw new Error("adapter runtime snapshot escapes the registry root");
    }
    cursor = parent;
  }
  await assertImmutableSnapshotTree(plugin.snapshotPath, expectedOwnerUid);
  const entrypoint = join(plugin.snapshotPath, plugin.entrypoint);
  if (!entrypoint.startsWith(`${plugin.snapshotPath}/`) || await realpath(entrypoint) !== entrypoint) {
    throw new Error("adapter runtime entrypoint escapes its immutable snapshot");
  }
  await assertImmutablePath(entrypoint, "file", expectedOwnerUid, requireExecutableEntrypoint);
  return entrypoint;
}

async function fixedInterpreter(path: string, expectedOwnerUid: number): Promise<string> {
  const resolved = await realpath(path);
  await assertImmutablePath(resolved, "file", expectedOwnerUid, true);
  return resolved;
}

async function fixedRuntimeFile(path: string, expectedOwnerUid: number): Promise<string> {
  const resolved = await realpath(path);
  await assertImmutablePath(resolved, "file", expectedOwnerUid);
  return resolved;
}

function interpreterFor(
  plugin: ActiveRuntimeSourcePlugin,
  entrypoint: string,
  dependencies: AdapterRunnerDependencies,
): Promise<{ executable: string; prefix: string[] }> {
  if (plugin.pluginId === "adapter.tui") {
    throw new Error("adapter.tui is a declarative profile and its source must never be executed");
  }
  const extension = extname(entrypoint);
  if (extension === ".mjs") {
    return fixedInterpreter(dependencies.nodePath, dependencies.expectedOwnerUid)
      .then((executable) => ({ executable, prefix: [entrypoint] }));
  }
  throw new Error("executable source adapter entrypoints must be .mjs");
}

function validateTUIProfile(descriptor: AdapterDescriptor): void {
  if (descriptor.adapterId !== "adapter.tui"
    || descriptor.runtimeAuthority.execution !== "compiled-client"
    || descriptor.session.mapping !== "local-terminal"
    || !exactValues(descriptor.session.supportedControls, ["bind"])
    || descriptor.inbound.transport !== "tty"
    || descriptor.inbound.framing !== "terminal-text"
    || !exactValues(descriptor.inbound.supportedTypes, ["text"])
    || descriptor.inbound.maxFrameBytes !== 131_072
    || descriptor.outbound.transport !== "stdout"
    || descriptor.outbound.framing !== "terminal-text"
    || descriptor.outbound.schema !== "terminal.text/v1"
    || !exactValues(descriptor.outbound.supportedActions, ["display"])
    || descriptor.outbound.maxFrameBytes !== 131_072
    || descriptor.approval.mode !== "local-tty"
    || descriptor.approval.identitySource !== "os-user+tty+sudo-pam"
    || descriptor.approval.replayProtection !== "local-command") {
    throw new Error("adapter.tui profile does not match the fixed local frontend contract");
  }
}

async function loadTUIProfile(entrypoint: string): Promise<AdapterDescriptor> {
  const payload = await readFile(entrypoint);
  if (payload.length === 0 || payload.length > MAX_ADAPTER_DESCRIPTOR_BYTES) {
    throw new Error("adapter.tui profile exceeds its bounded size");
  }
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(payload);
  } catch {
    throw new Error("adapter.tui profile is not valid UTF-8");
  }
  const descriptor = parseAdapterDescriptorJson(text);
  validateTUIProfile(descriptor);
  return descriptor;
}

async function assertDeclarativeTUISnapshot(snapshotPath: string): Promise<void> {
  const entries = await readdir(snapshotPath, { withFileTypes: true });
  const names = entries.map((entry) => entry.name).sort();
  if (!exactValues(names, ["manifest.json", "profile.json"])) {
    throw new Error("adapter.tui snapshot must contain only manifest.json and profile.json");
  }
  for (const entry of entries) {
    const info = await lstat(join(snapshotPath, entry.name));
    if (!entry.isFile() || (info.mode & 0o111) !== 0) {
      throw new Error("adapter.tui declarative snapshot must not contain executable source");
    }
  }
}

export function sanitizedAdapterEnvironment(
  plugin: ActiveRuntimeSourcePlugin,
  descriptor: AdapterDescriptor | undefined,
  dependencies: Pick<
    AdapterRunnerDependencies,
    "environment" | "username" | "homeDirectory"
  >,
): NodeJS.ProcessEnv {
  const source = dependencies.environment;
  const environment: NodeJS.ProcessEnv = {
    HOME: dependencies.homeDirectory,
    USER: dependencies.username,
    LOGNAME: dependencies.username,
    PATH: FIXED_PATH,
    LANG: source.LANG ?? "C.UTF-8",
    TZ: source.TZ ?? "UTC",
    OPS_AGENT_CORE_ROOT: FIXED_ROOT,
    OPS_AGENT_ADAPTER_ID: plugin.pluginId,
    OPS_AGENT_ADAPTER_DIGEST: plugin.digest,
    OPS_AGENT_ADAPTER_APPROVAL_MODE: descriptor?.approval.mode ?? "describe-only",
  };
  for (const key of [
    "TERM", "COLORTERM", "LC_ALL", "LC_CTYPE", "NO_COLOR", "FORCE_COLOR",
    "OPS_AGENT_SESSION_ID", "TMUX", "TMUX_PANE",
  ] as const) {
    const value = source[key];
    if (value !== undefined && !value.includes(String.fromCharCode(0))) environment[key] = value;
  }
  if (plugin.pluginId === "adapter.botmux") {
    const sessionId = source.BOTMUX_SESSION_ID;
    if (sessionId !== undefined && sessionId.length <= 512
      && !Array.from(sessionId).some((character) => {
        const code = character.codePointAt(0) ?? 0;
        return code === 0 || code === 10 || code === 13;
      })) {
      environment.BOTMUX_SESSION_ID = sessionId;
    }
  }
  return environment;
}

function safeStderr(value: Buffer): string {
  return terminalSafeTextFromBytes(value, 2048);
}

async function captureDescriptor(
  executable: string,
  arguments_: string[],
  cwd: string,
  environment: NodeJS.ProcessEnv,
): Promise<AdapterDescriptor> {
  return await new Promise<AdapterDescriptor>((resolve, reject) => {
    const child = spawn(executable, [...arguments_, ADAPTER_DESCRIBE_ARGUMENT], {
      cwd,
      env: environment,
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });
    const output: Buffer[] = [];
    const errors: Buffer[] = [];
    let outputBytes = 0;
    let errorBytes = 0;
    let failure: Error | undefined;
    const timer = setTimeout(() => {
      failure = new Error("adapter descriptor timed out");
      child.kill("SIGKILL");
    }, DESCRIBE_TIMEOUT_MILLISECONDS);
    child.stdout.on("data", (chunk: Buffer) => {
      outputBytes += chunk.length;
      if (outputBytes > MAX_ADAPTER_DESCRIPTOR_BYTES) {
        failure = new Error("adapter descriptor exceeds its output limit");
        child.kill("SIGKILL");
        return;
      }
      output.push(chunk);
    });
    child.stderr.on("data", (chunk: Buffer) => {
      if (errorBytes >= MAX_DESCRIPTOR_STDERR_BYTES) return;
      const remaining = MAX_DESCRIPTOR_STDERR_BYTES - errorBytes;
      errors.push(chunk.subarray(0, remaining));
      errorBytes += Math.min(chunk.length, remaining);
    });
    child.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once("close", (code, signal) => {
      clearTimeout(timer);
      if (failure !== undefined) {
        reject(failure);
        return;
      }
      if (code !== 0) {
        const detail = safeStderr(Buffer.concat(errors));
        reject(new Error(
          `adapter descriptor exited with ${signal ?? code ?? "unknown"}${detail ? `: ${detail}` : ""}`,
        ));
        return;
      }
      try {
        let text: string;
        try {
          text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true })
            .decode(Buffer.concat(output));
        } catch {
          throw new Error("adapter descriptor is not valid UTF-8");
        }
        resolve(parseAdapterDescriptorJson(text));
      } catch (error) {
        reject(error instanceof Error ? error : new Error("adapter descriptor is invalid"));
      }
    });
  });
}

function clientArgumentsForSourceAdapter(
  adapterArguments: readonly string[],
): string[] {
  let sessionId: string | undefined;
  let extensionSeen = false;
  for (let index = 0; index < adapterArguments.length; index += 1) {
    const argument = adapterArguments[index];
    if (argument === undefined) continue;
    if (argument === "--session-id") {
      const value = adapterArguments[index + 1];
      if (value === undefined || value.length === 0) throw new Error("--session-id requires a value");
      if (sessionId !== undefined) throw new Error("--session-id may only be specified once");
      sessionId = value;
      index += 1;
      continue;
    }
    if (argument.startsWith("--session-id=")) {
      if (sessionId !== undefined) throw new Error("--session-id may only be specified once");
      sessionId = argument.slice("--session-id=".length);
      continue;
    }
    if (argument === "--extension") {
      const value = adapterArguments[index + 1];
      if (value === undefined || !isAbsolute(value)) {
        throw new Error("--extension requires an absolute path");
      }
      if (extensionSeen) throw new Error("--extension may only be specified once");
      extensionSeen = true;
      index += 1;
      continue;
    }
    if (argument.startsWith("--extension=")) {
      if (!isAbsolute(argument.slice("--extension=".length))) {
        throw new Error("--extension requires an absolute path");
      }
      if (extensionSeen) throw new Error("--extension may only be specified once");
      extensionSeen = true;
      continue;
    }
    if (argument.startsWith("-")) throw new Error(`unsupported Source Adapter option: ${argument}`);
    throw new Error(
      "Source Adapter positional and @file prompts are forbidden; submit framed input on stdin",
    );
  }
  if (sessionId === undefined) throw new Error("--session-id is required");
  return ["--session-id", parseSessionId(sessionId)];
}

function clientEnvironment(
  plugin: ActiveRuntimeSourcePlugin,
  descriptor: AdapterDescriptor,
  dependencies: Pick<AdapterRunnerDependencies, "environment" | "username" | "homeDirectory">,
): NodeJS.ProcessEnv {
  const environment = Object.fromEntries(Object.entries(
    sanitizedAdapterEnvironment(plugin, descriptor, dependencies),
  ).filter(([key]) => !/^(?:BOTMUX|FEISHU|LARK)_/u.test(key)));
  environment.OPS_AGENT_ADAPTER_CONTEXT_FD = String(ADAPTER_CONTEXT_FD);
  if (descriptor.runtimeAuthority.execution === "source-process") {
    environment.OPS_AGENT_EVENT_FD = String(ADAPTER_COMPLETION_FD);
    environment.OPS_AGENT_ADAPTER_INPUT_FD = String(ADAPTER_INPUT_FD);
  }
  if (descriptor.adapterId === "adapter.tui") {
    environment.OPS_AGENT_ADAPTER_RUNNER_CONTROL_REQUEST_FD =
      String(ADAPTER_RUNNER_CONTROL_REQUEST_FD);
    environment.OPS_AGENT_ADAPTER_RUNNER_CONTROL_RESPONSE_FD =
      String(ADAPTER_RUNNER_CONTROL_RESPONSE_FD);
  }
  return environment;
}

async function containExecutableAdapterCommand(
  executable: string,
  arguments_: readonly string[],
  workingDirectory: string,
  dependencies: Pick<AdapterRunnerDependencies, "bwrapPath" | "expectedOwnerUid">,
): Promise<ContainedAdapterLaunch> {
  const bwrap = await fixedInterpreter(dependencies.bwrapPath, dependencies.expectedOwnerUid);
  return {
    executable: bwrap,
    arguments: [
      "--die-with-parent",
      "--unshare-pid",
      "--as-pid-1",
      "--disable-userns",
      "--cap-drop", "ALL",
      "--bind", "/", "/",
      "--proc", "/proc",
      "--chdir", workingDirectory,
      "--",
      executable,
      ...arguments_,
    ],
    workingDirectory: "/",
  };
}

function validateDescriptorGrant(
  plugin: ActiveRuntimeSourcePlugin,
  descriptor: AdapterDescriptor,
): void {
  if (descriptor.adapterId !== plugin.pluginId) {
    throw new Error("adapter descriptor identity does not match the active registration");
  }
  const required = adapterDescriptorGrant(descriptor);
  if (!exactValues(plugin.capabilities, required.capabilities)
    || !exactValues(plugin.requestedScopes, required.requestedScopes)) {
    throw new Error(
      "adapter descriptor capabilities/actions do not match the active manifest grant",
    );
  }
  if (descriptor.approval.mode === "local-tty") {
    if (plugin.pluginId !== "adapter.tui") {
      throw new Error("local approval requires the exact adapter.tui capability grant");
    }
    return;
  }
  if (plugin.capabilities.includes("approval.local")
    || plugin.requestedScopes.some((scope) => scope.startsWith("approval.submit"))) {
    throw new Error("non-TUI adapters must remain status-only and cannot request approval submission");
  }
}

export async function prepareAdapterLaunch(
  pluginId: string,
  adapterArguments: readonly string[],
  dependencies: AdapterRunnerDependencies,
): Promise<PreparedAdapterLaunch> {
  if (!ADAPTER_ID_PATTERN.test(pluginId)) throw new Error("adapter runner plugin id is invalid");
  if (dependencies.effectiveUid === 0) throw new Error("source adapters must never run as root");
  const enrolledAdministrator = pluginId === "adapter.tui"
    ? await dependencies.loadEnrolledAdministrator()
    : undefined;
  requireAdapterAccount(
    pluginId,
    dependencies.username,
    dependencies.effectiveUid,
    enrolledAdministrator,
  );
  const plugin = await dependencies.loadActive(pluginId);
  requireAdapterRegistration(plugin);
  if (plugin.pluginId !== pluginId) throw new Error("adapter registry returned a different identity");
  const isTUI = plugin.pluginId === "adapter.tui";
  if (isTUI && plugin.entrypoint !== "profile.json") {
    throw new Error("adapter.tui must use the fixed declarative profile.json entrypoint");
  }
  const entrypoint = await assertImmutableSnapshot(
    plugin,
    dependencies.pluginRegistryPath,
    dependencies.expectedOwnerUid,
    !isTUI,
  );
  if (isTUI) await assertDeclarativeTUISnapshot(plugin.snapshotPath);
  const interpreter = isTUI
    ? {
        executable: await fixedInterpreter(dependencies.nodePath, dependencies.expectedOwnerUid),
        prefix: [await fixedRuntimeFile(dependencies.clientPath, dependencies.expectedOwnerUid)],
      }
    : await interpreterFor(plugin, entrypoint, dependencies);
  const descriptor = isTUI
    ? await loadTUIProfile(entrypoint)
    : await (async () => {
        const contained = await containExecutableAdapterCommand(
          interpreter.executable,
          interpreter.prefix,
          plugin.snapshotPath,
          dependencies,
        );
        return await captureDescriptor(
          contained.executable,
          contained.arguments,
          contained.workingDirectory,
          sanitizedAdapterEnvironment(plugin, undefined, dependencies),
        );
      })();
  validateDescriptorGrant(plugin, descriptor);
  const current = await dependencies.loadActive(pluginId);
  if (!sameRuntimeRegistration(plugin, current)) {
    throw new Error("adapter current registration changed during launch; retry from the new active version");
  }
  const versionOnly = adapterArguments.length === 1
    && (adapterArguments[0] === "--version" || adapterArguments[0] === "-v");
  if (descriptor.approval.mode === "local-tty" && !versionOnly
    && (!dependencies.stdinIsTTY || !dependencies.stdoutIsTTY)) {
    throw new Error("adapter.tui local approval runtime requires an interactive terminal");
  }
  const runtimeEnvironment = sanitizedAdapterEnvironment(plugin, descriptor, dependencies);
  if (!isTUI) {
    runtimeEnvironment.OPS_AGENT_COMPLETION_FD = String(ADAPTER_COMPLETION_FD);
    runtimeEnvironment.OPS_AGENT_ADAPTER_INPUT_FD = String(ADAPTER_INPUT_FD);
  }
  const clientEntrypoint = await fixedRuntimeFile(
    dependencies.clientPath,
    dependencies.expectedOwnerUid,
  );
  const sourceClientArguments = versionOnly
    ? ["--version"]
    : clientArgumentsForSourceAdapter(adapterArguments);
  return {
    plugin,
    descriptor,
    executable: interpreter.executable,
    arguments: [
      ...interpreter.prefix,
      ...(isTUI ? adapterArguments : sourceClientArguments),
    ],
    workingDirectory: isTUI ? "/" : plugin.snapshotPath,
    environment: runtimeEnvironment,
    client: isTUI
      ? {
          executable: interpreter.executable,
          arguments: [...interpreter.prefix, ...adapterArguments],
          workingDirectory: "/",
          environment: clientEnvironment(plugin, descriptor, dependencies),
        }
      : {
          executable: await fixedInterpreter(dependencies.nodePath, dependencies.expectedOwnerUid),
          arguments: [clientEntrypoint, ...sourceClientArguments],
          workingDirectory: "/",
          environment: clientEnvironment(plugin, descriptor, dependencies),
        },
  };
}

/**
 * Put every Adapter runtime in a dedicated PID namespace. The source process
 * runs as PID 1, so Linux kills all of its descendants before bubblewrap can
 * report that PID 1 exited. This prevents detached/unref grandchildren from
 * surviving past the exact-digest lease held by the outer runner. We retain
 * the host filesystem, network and controlling TTY because this is lifecycle
 * containment, not a claim that business adapters have no host access.
 */
export async function containAdapterLaunch(
  launch: PreparedAdapterLaunch,
  dependencies: Pick<AdapterRunnerDependencies, "bwrapPath" | "expectedOwnerUid">,
): Promise<ContainedAdapterLaunch> {
  if (launch.plugin.pluginId === "adapter.tui") {
    return {
      executable: launch.executable,
      arguments: launch.arguments,
      workingDirectory: launch.workingDirectory,
    };
  }
  return await containExecutableAdapterCommand(
    launch.executable,
    launch.arguments,
    launch.workingDirectory,
    dependencies,
  );
}

function adapterClientContextLine(launch: PreparedAdapterLaunch): string {
  const line = `${JSON.stringify({
    apiVersion: ADAPTER_CLIENT_CONTEXT_API_VERSION,
    schemaVersion: 1,
    pluginId: launch.plugin.pluginId,
    digest: launch.plugin.digest,
    descriptor: launch.descriptor,
  })}\n`;
  if (Buffer.byteLength(line, "utf8") > MAX_ADAPTER_CLIENT_CONTEXT_BYTES + 1) {
    throw new Error("trusted Adapter client context exceeds its wire size limit");
  }
  return line;
}

function requireReadablePipe(child: ChildProcess, descriptor: number, label: string): Readable {
  const stream = child.stdio[descriptor];
  if (stream === undefined || stream === null || !("pipe" in stream)) {
    throw new Error(`${label} FD ${descriptor} is unavailable`);
  }
  return stream as Readable;
}

function requireWritablePipe(child: ChildProcess, descriptor: number, label: string): Writable {
  const stream = child.stdio[descriptor];
  if (stream === undefined || stream === null || !("write" in stream)) {
    throw new Error(`${label} FD ${descriptor} is unavailable`);
  }
  return stream;
}

async function terminateAdapterChildren(children: readonly ChildProcess[]): Promise<void> {
  await Promise.all(children.map(async (child) => {
    if (child.exitCode !== null || child.signalCode !== null) return;
    await new Promise<void>((resolve) => {
      child.once("close", () => { resolve(); });
      child.kill("SIGKILL");
    });
  }));
}

function productionDependencies(): AdapterRunnerDependencies {
  const identity = userInfo();
  return {
    pluginRegistryPath: FIXED_PLUGIN_REGISTRY,
    pluginCtlPath: FIXED_PLUGINCTL,
    bwrapPath: FIXED_BWRAP,
    nodePath: FIXED_NODE,
    clientPath: FIXED_CLIENT,
    expectedOwnerUid: 0,
    effectiveUid: process.geteuid?.() ?? process.getuid?.() ?? 0,
    username: identity.username,
    homeDirectory: identity.homedir,
    environment: process.env,
    stdinIsTTY: process.stdin.isTTY,
    stdoutIsTTY: process.stdout.isTTY,
    loadActive: async (pluginId) => await loadActiveRuntimeSourcePlugin({
      pluginRegistryPath: FIXED_PLUGIN_REGISTRY,
      pluginCtlPath: FIXED_PLUGINCTL,
    }, pluginId),
    acquireLease: async (plugin) => await acquireActiveRuntimeSourcePluginLease({
      pluginRegistryPath: FIXED_PLUGIN_REGISTRY,
      pluginLeaseSocketPath: "/run/ops-agent/plugin-lease/lease.sock",
    }, plugin),
    loadEnrolledAdministrator: async () => await loadEnrolledLocalAdministrator(),
  };
}

export async function runAdapter(
  pluginId: string,
  adapterArguments: readonly string[],
  dependencies = productionDependencies(),
): Promise<number> {
  if (!ADAPTER_ID_PATTERN.test(pluginId)) throw new Error("adapter runner plugin id is invalid");
  const expected = await dependencies.loadActive(pluginId);
  const lease = await dependencies.acquireLease(expected);
  let leaseReleaseStarted = false;
  const releaseLease = async (): Promise<void> => {
    if (leaseReleaseStarted) return;
    leaseReleaseStarted = true;
    await lease.release();
  };
  if (!sameRuntimeRegistration(expected, lease.registration)) {
    await releaseLease();
    throw new Error("adapter current registration changed before its runtime lease");
  }
  try {
    const launch = await Promise.race([
      prepareAdapterLaunch(pluginId, adapterArguments, dependencies),
      lease.lost,
    ]);
    if (!sameRuntimeRegistration(launch.plugin, lease.registration)) {
      throw new Error("adapter launch changed after its exact-digest runtime lease was acquired");
    }
    const contained = await containAdapterLaunch(launch, dependencies);
    const versionOnly = launch.client.arguments.length === 2
      && (launch.client.arguments[1] === "--version" || launch.client.arguments[1] === "-v");
    const sourceMode = launch.descriptor.runtimeAuthority.execution === "source-process"
      && !versionOnly;
    const children: ChildProcess[] = [];
    let source: ChildProcess | undefined;
    try {
      if (sourceMode) {
        source = spawn(contained.executable, contained.arguments, {
          cwd: contained.workingDirectory,
          env: launch.environment,
          shell: false,
          stdio: ["inherit", "inherit", "inherit", "pipe", "pipe"],
          windowsHide: true,
        });
        children.push(source);
      }
      const client = spawn(launch.client.executable, launch.client.arguments, {
        cwd: launch.client.workingDirectory,
        env: launch.client.environment,
        shell: false,
        stdio: sourceMode
          ? ["ignore", "inherit", "inherit", "pipe", "pipe", "pipe", "ignore", "ignore"]
          : ["inherit", "inherit", "inherit", "ignore", "ignore", "pipe", "pipe", "pipe"],
        windowsHide: true,
      });
      children.push(client);
      return await new Promise<number>((resolve, reject) => {
        let runtimeFailure: Error | undefined;
        let recheckActive = false;
        let closed = false;
        let stopTimer: NodeJS.Timeout | undefined;
        let selfUpdateExitTimer: NodeJS.Timeout | undefined;
        let selfUpdateHandoff = false;
        const stopForRuntimeFailure = (error: unknown): void => {
          if (closed || runtimeFailure !== undefined) return;
          runtimeFailure = error instanceof Error
            ? error
            : new Error("adapter current registration revalidation failed");
          for (const child of children) child.kill("SIGTERM");
          stopTimer = setTimeout(() => {
            for (const child of children) child.kill("SIGKILL");
          }, RUNTIME_STOP_GRACE_MILLISECONDS);
        };
        try {
          const contextOutput = requireWritablePipe(client, ADAPTER_CONTEXT_FD, "compiled Client");
          contextOutput.on("error", (error: NodeJS.ErrnoException) => {
            if (error.code !== "EPIPE" || !versionOnly) stopForRuntimeFailure(error);
          });
          contextOutput.end(adapterClientContextLine(launch));
          if (launch.plugin.pluginId === "adapter.tui" && !versionOnly) {
            const controlInput = requireReadablePipe(
              client,
              ADAPTER_RUNNER_CONTROL_REQUEST_FD,
              "compiled Client self-update request",
            );
            const controlOutput = requireWritablePipe(
              client,
              ADAPTER_RUNNER_CONTROL_RESPONSE_FD,
              "compiled Client self-update response",
            );
            const controlDecoder = new FrameDecoder(16 * 1024);
            let controlFrames = 0;
            controlInput.on("data", (chunk: Buffer) => {
              try {
                const frames = controlDecoder.push(chunk);
                controlFrames += frames.length;
                if (controlFrames !== 1 || frames.length !== 1) {
                  if (frames.length === 0 && controlFrames === 0) return;
                  throw new Error("compiled Client sent multiple TUI self-update handoff requests");
                }
                const request = parseAdapterRunnerControlRequest(frames[0]);
                if (request.digest !== launch.plugin.digest || selfUpdateHandoff) {
                  throw new Error("compiled Client self-update handoff does not bind the running digest");
                }
                selfUpdateHandoff = true;
                void releaseLease().then(() => {
                  controlOutput.end(encodeFrame({
                    apiVersion: ADAPTER_RUNNER_CONTROL_API_VERSION,
                    ok: true,
                    state: "RELEASED",
                  }));
                  selfUpdateExitTimer = setTimeout(() => {
                    stopForRuntimeFailure(new Error(
                      "compiled Client did not exit after its TUI self-update lease handoff",
                    ));
                  }, TUI_SELF_UPDATE_EXIT_MILLISECONDS);
                  selfUpdateExitTimer.unref();
                }).catch((error: unknown) => {
                  controlOutput.end(encodeFrame({
                    apiVersion: ADAPTER_RUNNER_CONTROL_API_VERSION,
                    ok: false,
                    error: error instanceof Error ? error.message : "Adapter lease release failed",
                  }));
                  stopForRuntimeFailure(error);
                });
              } catch (error) {
                controlOutput.end(encodeFrame({
                  apiVersion: ADAPTER_RUNNER_CONTROL_API_VERSION,
                  ok: false,
                  error: error instanceof Error ? error.message : "invalid self-update handoff",
                }));
                stopForRuntimeFailure(error);
              }
            });
            for (const stream of [controlInput, controlOutput]) {
              stream.on("error", (error: NodeJS.ErrnoException) => {
                if (error.code !== "EPIPE" || !selfUpdateHandoff) stopForRuntimeFailure(error);
              });
            }
          }
          if (source !== undefined) {
            const clientCompletion = requireReadablePipe(
              client,
              ADAPTER_COMPLETION_FD,
              "compiled Client completion",
            );
            const sourceCompletion = requireWritablePipe(
              source,
              ADAPTER_COMPLETION_FD,
              "Source Adapter completion",
            );
            const sourceInput = requireReadablePipe(source, ADAPTER_INPUT_FD, "Source Adapter input");
            const clientInput = requireWritablePipe(client, ADAPTER_INPUT_FD, "compiled Client input");
            for (const stream of [clientCompletion, sourceCompletion, sourceInput, clientInput]) {
              stream.on("error", (error: NodeJS.ErrnoException) => {
                if (error.code !== "EPIPE") stopForRuntimeFailure(error);
              });
            }
            clientCompletion.pipe(sourceCompletion);
            sourceInput.pipe(clientInput);
          }
        } catch (error) {
          reject(error instanceof Error ? error : new Error("Adapter pipe setup failed"));
          return;
        }
        void lease.lost.catch((error: unknown) => { stopForRuntimeFailure(error); });
        const recheck = (): void => {
          if (recheckActive || runtimeFailure !== undefined || selfUpdateHandoff) return;
          recheckActive = true;
          dependencies.loadActive(pluginId).then((current) => {
            if (selfUpdateHandoff) return;
            if (!sameRuntimeRegistration(launch.plugin, current)) {
              stopForRuntimeFailure(new Error(
                "adapter current registration changed while running; the old source process was terminated",
              ));
            }
          }).catch((error: unknown) => {
            if (!selfUpdateHandoff) stopForRuntimeFailure(error);
          }).finally(() => { recheckActive = false; });
        };
        const recheckTimer = setInterval(
          recheck,
          dependencies.runtimeRecheckMilliseconds ?? RUNTIME_RECHECK_MILLISECONDS,
        );
        const forward = (signal: NodeJS.Signals): void => {
          for (const child of children) child.kill(signal);
        };
        process.on("SIGINT", forward);
        process.on("SIGTERM", forward);
        process.on("SIGHUP", forward);
        const cleanup = (): void => {
          closed = true;
          clearInterval(recheckTimer);
          if (stopTimer !== undefined) clearTimeout(stopTimer);
          if (selfUpdateExitTimer !== undefined) clearTimeout(selfUpdateExitTimer);
          process.off("SIGINT", forward);
          process.off("SIGTERM", forward);
          process.off("SIGHUP", forward);
        };
        const statuses = new Map<ChildProcess, number>();
        const finish = (): void => {
          if (statuses.size !== children.length) return;
          cleanup();
          if (runtimeFailure !== undefined) {
            reject(runtimeFailure);
            return;
          }
          resolve(statuses.get(client) ?? 1);
        };
        for (const child of children) {
          child.once("error", (error) => { stopForRuntimeFailure(error); });
          child.once("close", (code, signal) => {
            statuses.set(child, code ?? (signal === null ? 1 : 128));
            const status = statuses.get(child) ?? 1;
            if (status !== 0 && runtimeFailure === undefined) {
              stopForRuntimeFailure(new Error(
                `${child === client ? "compiled Client" : "Source Adapter"} exited with status ${status}`,
              ));
            }
            finish();
          });
        }
      });
    } catch (error) {
      await terminateAdapterChildren(children);
      throw error;
    }
  } finally {
    await releaseLease();
  }
}

function parseArguments(arguments_: readonly string[]): { pluginId: string; adapterArguments: string[] } {
  const separator = arguments_.indexOf("--");
  if (separator !== 1 || arguments_.length < 2) {
    throw new Error("usage: agentd-adapter-run <adapter.id> -- [adapter arguments]");
  }
  return { pluginId: arguments_[0] ?? "", adapterArguments: arguments_.slice(2) };
}

async function main(): Promise<void> {
  const invocation = parseArguments(process.argv.slice(2));
  process.exitCode = await runAdapter(invocation.pluginId, invocation.adapterArguments);
}

if (process.argv[1] !== undefined
  && await realpath(process.argv[1]).catch(() => "") === await realpath(fileURLToPath(import.meta.url))) {
  main().catch((error: unknown) => {
    process.stderr.write(
      `agentd-adapter-run: ${escapeUntrustedTerminalText(error instanceof Error ? error.message : String(error))}\n`,
    );
    process.exitCode = 1;
  });
}
