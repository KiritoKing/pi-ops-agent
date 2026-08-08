import { execFile } from "node:child_process";
import { createConnection, type Socket } from "node:net";
import { isAbsolute, join, normalize } from "node:path";
import { promisify } from "node:util";
import type { AgentConfig } from "./config.js";
import { requireString, requireStringArray } from "./guards.js";
import { requireExactRecord } from "./strict.js";
import { parseStrictJson } from "./workload-runtime.js";
import { encodeFrame, FrameDecoder } from "./framing.js";

const execFileAsync = promisify(execFile);
const LEASE_STDIO_LIMIT_BYTES = 256 * 1024;
const LEASE_READY_TIMEOUT_MILLISECONDS = 10_000;

export interface ActiveSourcePlugin {
  apiVersion: "agentd.plugin-registration/v1";
  schemaVersion: 1;
  pluginId: string;
  kind: "adapter" | "workload";
  version: string;
  publisher: string;
  digest: string;
  capabilities: readonly string[];
  requestedScopes: readonly string[];
  approvedBy: string;
  approvedAt: string;
}

export interface ActiveRuntimeSourcePlugin extends ActiveSourcePlugin {
  entrypoint: string;
  snapshotPath: string;
}

function requireSortedNames(values: readonly string[], label: string): void {
  const pattern = /^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*$/u;
  if (values.some((value) => value.length > 128 || !pattern.test(value)) ||
      values.some((value, index) => index > 0 && (values[index - 1] ?? "") >= value)) {
    throw new Error(`${label} must contain sorted, unique capability names`);
  }
}

function parseActiveSourcePlugin(value: unknown): ActiveSourcePlugin {
  const input = requireExactRecord(value, "active source plugin", [
    "apiVersion", "schemaVersion", "pluginId", "kind", "version", "publisher", "digest",
    "capabilities", "requestedScopes", "approvedBy", "approvedAt",
  ]);
  if (input.apiVersion !== "agentd.plugin-registration/v1" || input.schemaVersion !== 1) {
    throw new Error("active source plugin has an unsupported registration version");
  }
  const kind = requireString(input.kind, "active source plugin.kind", { max: 16 });
  if (kind !== "adapter" && kind !== "workload") {
    throw new Error("active source plugin has an unsupported kind");
  }
  const approvedAt = requireString(input.approvedAt, "active source plugin.approvedAt", { max: 64 });
  if (!Number.isFinite(Date.parse(approvedAt))) {
    throw new Error("active source plugin has an invalid approval time");
  }
  const capabilities = requireStringArray(input.capabilities, "active source plugin.capabilities", 64);
  const requestedScopes = requireStringArray(
    input.requestedScopes,
    "active source plugin.requestedScopes",
    64,
  );
  requireSortedNames(capabilities, "active source plugin.capabilities");
  requireSortedNames(requestedScopes, "active source plugin.requestedScopes");
  return {
    apiVersion: "agentd.plugin-registration/v1",
    schemaVersion: 1,
    pluginId: requireString(input.pluginId, "active source plugin.pluginId", {
      pattern: /^(?:adapter|workload)\.[a-z0-9][a-z0-9.-]{0,63}$/u,
    }),
    kind,
    version: requireString(input.version, "active source plugin.version", { max: 96 }),
    publisher: requireString(input.publisher, "active source plugin.publisher", { max: 160 }),
    digest: requireString(input.digest, "active source plugin.digest", {
      pattern: /^sha256:[a-f0-9]{64}$/u,
    }),
    capabilities,
    requestedScopes,
    approvedBy: requireString(input.approvedBy, "active source plugin.approvedBy", { max: 256 }),
    approvedAt,
  };
}

function parseActiveRuntimeSourcePlugin(value: unknown): ActiveRuntimeSourcePlugin {
  const input = requireExactRecord(value, "active runtime source plugin", [
    "apiVersion", "schemaVersion", "pluginId", "kind", "version", "publisher", "digest",
    "capabilities", "requestedScopes", "approvedBy", "approvedAt",
    "entrypoint", "snapshotPath",
  ]);
  const base = parseActiveSourcePlugin(Object.fromEntries(Object.entries(input).filter(
    ([key]) => key !== "entrypoint" && key !== "snapshotPath",
  )));
  const entrypoint = requireString(input.entrypoint, "active runtime source plugin.entrypoint", {
    max: 512,
    pattern: /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))(?!.*\\).+$/u,
  });
  if (entrypoint.includes("\0") || entrypoint.includes("\r") || entrypoint.includes("\n")) {
    throw new Error("active runtime source plugin entrypoint contains a control character");
  }
  const snapshotPath = requireString(
    input.snapshotPath,
    "active runtime source plugin.snapshotPath",
    { max: 4096 },
  );
  if (!isAbsolute(snapshotPath) || normalize(snapshotPath) !== snapshotPath) {
    throw new Error("active runtime source plugin snapshotPath must be a clean absolute path");
  }
  return { ...base, entrypoint, snapshotPath };
}

function validateRuntimeSnapshotPath(
  config: Pick<AgentConfig, "pluginRegistryPath">,
  plugin: ActiveRuntimeSourcePlugin,
): ActiveRuntimeSourcePlugin {
  const expected = join(
    config.pluginRegistryPath,
    "snapshots",
    "sha256",
    plugin.digest.slice("sha256:".length),
  );
  if (plugin.snapshotPath !== expected) {
    throw new Error("plugin registry returned a runtime snapshot outside its content-addressed store");
  }
  return plugin;
}

function sameRuntimeRegistration(
  expected: ActiveRuntimeSourcePlugin,
  actual: ActiveRuntimeSourcePlugin,
): boolean {
  return expected.pluginId === actual.pluginId && expected.kind === actual.kind &&
    expected.version === actual.version && expected.publisher === actual.publisher &&
    expected.digest === actual.digest && expected.entrypoint === actual.entrypoint &&
    expected.snapshotPath === actual.snapshotPath &&
    expected.capabilities.length === actual.capabilities.length &&
    expected.capabilities.every((value, index) => value === actual.capabilities[index]) &&
    expected.requestedScopes.length === actual.requestedScopes.length &&
    expected.requestedScopes.every((value, index) => value === actual.requestedScopes[index]);
}

export interface ActiveRuntimeSourcePluginLease {
  registration: ActiveRuntimeSourcePlugin;
  /** Rejects if the broker crashes or the bounded lease expires before release. */
  lost: Promise<never>;
  release(): Promise<void>;
}

function requireLeaseIdentity(expected: { pluginId: string; digest: string }): void {
  if (!/^(?:adapter|workload)\.[a-z0-9][a-z0-9.-]{0,63}$/u.test(expected.pluginId)) {
    throw new Error("plugin invocation lease has an invalid plugin ID");
  }
  if (!/^sha256:[a-f0-9]{64}$/u.test(expected.digest)) {
    throw new Error("plugin invocation lease has an invalid digest");
  }
}

function parseLeaseResponse(value: unknown, expectedState: "LEASED" | "RELEASED"):
ActiveRuntimeSourcePlugin | undefined {
  const input = requireExactRecord(value, "plugin lease broker response", [
    "version", "ok", "state", "registration", "error",
  ]);
  if (input.version !== 1 || typeof input.ok !== "boolean") {
    throw new Error("plugin lease broker returned an unsupported response");
  }
  if (!input.ok) {
    throw new Error(requireString(input.error, "plugin lease broker error", { max: 512 }));
  }
  if (input.state !== expectedState || input.error !== undefined) {
    throw new Error(`plugin lease broker did not enter ${expectedState}`);
  }
  if (expectedState === "RELEASED") {
    if (input.registration !== undefined) {
      throw new Error("released plugin lease unexpectedly included a registration");
    }
    return undefined;
  }
  if (input.registration === undefined) {
    throw new Error("leased plugin response omitted its runtime registration");
  }
  return parseActiveRuntimeSourcePlugin(input.registration);
}

function closeSocket(socket: Socket): Promise<void> {
  if (socket.destroyed) return Promise.resolve();
  return new Promise((resolve) => {
    socket.once("close", () => resolve());
    socket.destroy();
  });
}

/**
 * Ask the peer-credential-authenticated local broker to hold a shared lock for
 * this exact active digest. Client-group processes never open registry lock
 * files themselves; the broker releases on an explicit handshake, disconnect,
 * hard workload deadline, or broker restart.
 */
export async function acquireActiveRuntimeSourcePluginLease(
  config: Pick<AgentConfig, "pluginLeaseSocketPath" | "pluginRegistryPath">,
  expected: { pluginId: string; digest: string },
  signal?: AbortSignal,
): Promise<ActiveRuntimeSourcePluginLease> {
  requireLeaseIdentity(expected);
  const socket = createConnection(config.pluginLeaseSocketPath);
  const decoder = new FrameDecoder(LEASE_STDIO_LIMIT_BYTES);
  const acquired = Promise.withResolvers<ActiveRuntimeSourcePlugin>();
  const released = Promise.withResolvers<undefined>();
  const lost = Promise.withResolvers<never>();
  void lost.promise.catch(() => undefined);
  let state: "connecting" | "leased" | "releasing" | "released" | "failed" = "connecting";
  let acquisitionTimer: NodeJS.Timeout | undefined;
  let releaseTimer: NodeJS.Timeout | undefined;
  const fail = (error: unknown): void => {
    const failure = error instanceof Error ? error : new Error("plugin lease broker connection failed");
    if (state === "connecting") acquired.reject(failure);
    else if (state === "leased") lost.reject(failure);
    else if (state === "releasing") released.reject(failure);
    state = "failed";
    socket.destroy();
  };
  socket.on("data", (chunk: Buffer) => {
    try {
      for (const value of decoder.push(chunk)) {
        if (state === "connecting") {
          const registration = parseLeaseResponse(value, "LEASED");
          if (registration === undefined) throw new Error("plugin lease broker omitted registration");
          state = "leased";
          acquired.resolve(registration);
          continue;
        }
        if (state === "releasing") {
          parseLeaseResponse(value, "RELEASED");
          state = "released";
          released.resolve(undefined);
          socket.end();
          continue;
        }
        throw new Error("plugin lease broker emitted an unexpected extra response");
      }
    } catch (error) {
      fail(error);
    }
  });
  socket.once("error", fail);
  socket.once("close", () => {
    if (state === "connecting") fail(new Error("plugin lease broker closed before acquisition"));
    else if (state === "leased") fail(new Error("plugin lease broker connection was lost"));
    else if (state === "releasing") fail(new Error("plugin lease broker closed before release acknowledgement"));
  });
  const abortAcquisition = (): void => {
    fail(new Error(`${expected.pluginId} invocation lease validation was aborted`));
  };
  if (signal?.aborted === true) {
    abortAcquisition();
  } else {
    signal?.addEventListener("abort", abortAcquisition, { once: true });
  }
  try {
    acquisitionTimer = setTimeout(() => {
      fail(new Error(`${expected.pluginId} invocation lease validation timed out`));
    }, LEASE_READY_TIMEOUT_MILLISECONDS);
    acquisitionTimer.unref();
    socket.once("connect", () => {
      socket.write(encodeFrame({
        version: 1,
        pluginId: expected.pluginId,
        digest: expected.digest,
      }));
    });
    const rawRegistration = await acquired.promise;
    const registration = validateRuntimeSnapshotPath(
      config,
      rawRegistration,
    );
    if (registration.pluginId !== expected.pluginId || registration.digest !== expected.digest) {
      throw new Error(`${expected.pluginId} current registration changed before its invocation lease`);
    }
    let releaseStarted = false;
    return {
      registration,
      lost: lost.promise,
      async release() {
        if (releaseStarted || state === "released") return;
        releaseStarted = true;
        if (state === "failed") {
          await closeSocket(socket);
          return;
        }
        if (state !== "leased") throw new Error("plugin lease is not in a releasable state");
        state = "releasing";
        releaseTimer = setTimeout(() => {
          fail(new Error(`${expected.pluginId} invocation lease release timed out`));
        }, LEASE_READY_TIMEOUT_MILLISECONDS);
        releaseTimer.unref();
        socket.write(encodeFrame({ version: 1, action: "release" }));
        try {
          await released.promise;
        } finally {
          clearTimeout(releaseTimer);
          await closeSocket(socket);
        }
      },
    };
  } catch (error) {
    await closeSocket(socket);
    throw error;
  } finally {
    if (acquisitionTimer !== undefined) clearTimeout(acquisitionTimer);
    signal?.removeEventListener("abort", abortAcquisition);
  }
}

/**
 * Run one operation while this process retains a shared registry flock for the
 * exact active digest. The callback is always awaited to settlement before the
 * FileHandle closes; abort never races the callback and releases authority in
 * the background.
 */
export async function withActiveRuntimeSourcePluginLease<T>(
  config: Pick<AgentConfig, "pluginLeaseSocketPath" | "pluginRegistryPath">,
  expected: ActiveRuntimeSourcePlugin,
  callback: (signal: AbortSignal) => Promise<T>,
  signal?: AbortSignal,
): Promise<T> {
  const lease = await acquireActiveRuntimeSourcePluginLease(config, expected, signal);
  if (!sameRuntimeRegistration(expected, lease.registration)) {
    await lease.release();
    throw new Error(`${expected.pluginId} current registration changed before its invocation lease`);
  }
  const leaseLoss = new AbortController();
  const invocationSignal = signal === undefined
    ? leaseLoss.signal
    : AbortSignal.any([signal, leaseLoss.signal]);
  let lostError: Error | undefined;
  const lost = lease.lost.catch((error: unknown) => {
    const failure = error instanceof Error
      ? error
      : new Error("plugin invocation lease was lost");
    lostError = failure;
    leaseLoss.abort(failure);
    throw failure;
  });
  const operation = callback(invocationSignal);
  try {
    return await Promise.race([operation, lost]);
  } catch (error) {
    if (lostError !== undefined) {
      await operation.catch(() => undefined);
      throw lostError;
    }
    throw error;
  } finally {
    await lease.release();
  }
}

export async function loadActiveSourcePlugin(
  config: Pick<AgentConfig, "pluginCtlPath" | "pluginRegistryPath">,
  pluginId: string,
): Promise<ActiveSourcePlugin> {
  const { stdout } = await execFileAsync(config.pluginCtlPath, [
    "current",
    "--root", config.pluginRegistryPath,
    "--plugin-id", pluginId,
  ], {
    cwd: "/",
    env: { PATH: "/usr/bin:/bin", LANG: "C.UTF-8" },
    encoding: "utf8",
    timeout: 10_000,
    maxBuffer: 256 * 1024,
    windowsHide: true,
  });
  const lines = stdout.trim().split("\n");
  if (lines.length !== 1 || lines[0] === undefined) {
    throw new Error(`plugin registry returned an invalid record for ${pluginId}`);
  }
  const registration = parseActiveSourcePlugin(parseStrictJson(lines[0]));
  if (registration.pluginId !== pluginId) {
    throw new Error("plugin registry returned a different plugin identity");
  }
  return registration;
}

export async function loadActiveRuntimeSourcePlugin(
  config: Pick<AgentConfig, "pluginCtlPath" | "pluginRegistryPath">,
  pluginId: string,
): Promise<ActiveRuntimeSourcePlugin> {
  const { stdout } = await execFileAsync(config.pluginCtlPath, [
    "current",
    "--root", config.pluginRegistryPath,
    "--plugin-id", pluginId,
    "--runtime",
  ], {
    cwd: "/",
    env: { PATH: "/usr/bin:/bin", LANG: "C.UTF-8" },
    encoding: "utf8",
    timeout: 10_000,
    maxBuffer: 256 * 1024,
    windowsHide: true,
  });
  const lines = stdout.trim().split("\n");
  if (lines.length !== 1 || lines[0] === undefined) {
    throw new Error(`plugin registry returned an invalid runtime record for ${pluginId}`);
  }
  const registration = validateRuntimeSnapshotPath(
    config,
    parseActiveRuntimeSourcePlugin(parseStrictJson(lines[0])),
  );
  if (registration.pluginId !== pluginId) {
    throw new Error("plugin registry returned a different runtime plugin identity");
  }
  return registration;
}

export async function listActiveRuntimeSourceWorkloads(
  config: Pick<AgentConfig, "pluginCtlPath" | "pluginRegistryPath">,
): Promise<ActiveRuntimeSourcePlugin[]> {
  const { stdout } = await execFileAsync(config.pluginCtlPath, [
    "list",
    "--root", config.pluginRegistryPath,
    "--kind", "workload",
  ], {
    cwd: "/",
    env: { PATH: "/usr/bin:/bin", LANG: "C.UTF-8" },
    encoding: "utf8",
    timeout: 20_000,
    maxBuffer: 1024 * 1024,
    windowsHide: true,
  });
  const lines = stdout.trim().split("\n");
  if (lines.length !== 1 || lines[0] === undefined) {
    throw new Error("plugin registry returned an invalid active workload list");
  }
  const decoded = parseStrictJson(lines[0], 1024 * 1024);
  if (!Array.isArray(decoded) || decoded.length > 128) {
    throw new Error("plugin registry active workload list is not a bounded array");
  }
  const plugins = decoded.map((value) =>
    validateRuntimeSnapshotPath(config, parseActiveRuntimeSourcePlugin(value)));
  if (plugins.some((plugin, index) =>
    index > 0 && (plugins[index - 1]?.pluginId ?? "") >= plugin.pluginId)) {
    throw new Error("plugin registry active workload list must be sorted with unique identities");
  }
  return plugins;
}

export async function loadOptionalActiveSourcePlugin(
  config: Pick<AgentConfig, "pluginCtlPath" | "pluginRegistryPath">,
  pluginId: string,
): Promise<ActiveSourcePlugin | undefined> {
  try {
    return await loadActiveSourcePlugin(config, pluginId);
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === 3) return undefined;
    throw error;
  }
}
