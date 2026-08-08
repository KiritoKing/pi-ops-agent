#!/usr/bin/env node
import { spawn } from "node:child_process";
import { lstat, realpath } from "node:fs/promises";
import { userInfo } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  acquireActiveRuntimeSourcePluginLease,
  type ActiveRuntimeSourcePlugin,
  type ActiveRuntimeSourcePluginLease,
} from "../shared/source-plugin.js";

const BOTMUX_PLUGIN_ID = "adapter.botmux";
const BOTMUX_USER = "ops-agent-botmux";
const BOTMUX_HOME = "/var/lib/ops-agent/adapters/botmux";
const BOTMUX_CONFIG = `${BOTMUX_HOME}/.botmux/bots.json`;
const PLUGIN_REGISTRY = "/var/lib/ops-agent/plugins";
const PLUGIN_LEASE_SOCKET = "/run/ops-agent/plugin-lease/lease.sock";
const BWRAP = "/usr/bin/bwrap";
const FIXED_PATH = "/opt/pi-ops-agent/botmux-bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const CHILD_STOP_GRACE_MILLISECONDS = 5_000;
const BOTMUX_CAPABILITIES = [
  "adapter.inbound.text",
  "adapter.outbound.send",
  "adapter.session.bind",
  "approval.status",
] as const;
const BOTMUX_SCOPES = [
  "adapter.inbound.text.botmux",
  "adapter.outbound.send.botmux",
  "adapter.session.bind.botmux",
  "approval.status.remote",
] as const;

export interface BotMuxSetupCommand {
  executable: string;
  arguments: readonly string[];
  label: string;
}

export interface BotMuxSetupDependencies {
  effectiveUid: number;
  username: string;
  homeDirectory: string;
  nodePath: string;
  bwrapPath: string;
  botmuxPath: string;
  configPath: string;
  environment: NodeJS.ProcessEnv;
  acquireLease(expected: {
    pluginId: string;
    digest: string;
  }): Promise<ActiveRuntimeSourcePluginLease>;
  validateHardener(path: string): Promise<string>;
  execute(command: BotMuxSetupCommand, signal: AbortSignal): Promise<number>;
}

function exactValues(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function asError(error: unknown, fallback: string): Error {
  return error instanceof Error ? error : new Error(fallback);
}

function requireBotMuxRegistration(
  registration: ActiveRuntimeSourcePlugin,
  digest: string,
): void {
  if (registration.pluginId !== BOTMUX_PLUGIN_ID
    || registration.kind !== "adapter"
    || registration.digest !== digest
    || registration.entrypoint !== "adapter.mjs"
    || !exactValues(registration.capabilities, BOTMUX_CAPABILITIES)
    || !exactValues(registration.requestedScopes, BOTMUX_SCOPES)) {
    throw new Error("plugin lease broker returned an invalid adapter.botmux registration");
  }
}

function requireBotMuxIdentity(dependencies: BotMuxSetupDependencies): void {
  if (dependencies.effectiveUid <= 0
    || dependencies.username !== BOTMUX_USER
    || dependencies.homeDirectory !== BOTMUX_HOME
    || dependencies.configPath !== BOTMUX_CONFIG) {
    throw new Error("BotMux setup runner must use the dedicated non-root BotMux identity and home");
  }
}

function throwIfAborted(signal: AbortSignal): void {
  if (!signal.aborted) return;
  throw asError(signal.reason, "BotMux setup was aborted");
}

/**
 * Execute the one fixed BotMux setup workflow while the dedicated BotMux UID
 * retains an exact-digest lease through the peer-authenticated broker socket.
 * The callback for an interrupted command must settle before the lease is
 * released, so an update can never cross a still-running hardener or restart.
 */
export async function runBotMuxSourceSetup(
  digest: string,
  dependencies: BotMuxSetupDependencies,
  signal?: AbortSignal,
): Promise<void> {
  if (!/^sha256:[a-f0-9]{64}$/u.test(digest)) {
    throw new Error("BotMux setup requires an exact sha256 source adapter digest");
  }
  requireBotMuxIdentity(dependencies);
  const lease = await dependencies.acquireLease({ pluginId: BOTMUX_PLUGIN_ID, digest });
  const leaseState: { lostError?: Error } = {};
  let releaseAttempted = false;
  try {
    requireBotMuxRegistration(lease.registration, digest);
    const hardener = await dependencies.validateHardener(
      join(lease.registration.snapshotPath, "configure-botmux.mjs"),
    );
    const leaseAbort = new AbortController();
    const invocationSignal = signal === undefined
      ? leaseAbort.signal
      : AbortSignal.any([signal, leaseAbort.signal]);
    const leaseLost = lease.lost.catch((error: unknown) => {
      const failure = asError(error, "adapter.botmux exact-digest lease was lost");
      leaseState.lostError = failure;
      leaseAbort.abort(failure);
      throw failure;
    });
    const workflow = (async (): Promise<void> => {
      const commands: readonly BotMuxSetupCommand[] = [
        { executable: dependencies.botmuxPath, arguments: ["setup"], label: "BotMux setup" },
        {
          executable: dependencies.bwrapPath,
          arguments: [
            "--die-with-parent",
            "--unshare-pid",
            "--as-pid-1",
            "--disable-userns",
            "--cap-drop", "ALL",
            "--bind", "/", "/",
            "--proc", "/proc",
            "--chdir", lease.registration.snapshotPath,
            "--",
            dependencies.nodePath,
            hardener,
            dependencies.configPath,
            "0",
          ],
          label: "approved BotMux configuration hardener",
        },
        { executable: dependencies.botmuxPath, arguments: ["restart"], label: "BotMux restart" },
      ];
      for (const command of commands) {
        throwIfAborted(invocationSignal);
        const status = await dependencies.execute(command, invocationSignal);
        if (status !== 0) {
          throw new Error(`${command.label} exited with status ${status}`);
        }
      }
    })();
    try {
      await Promise.race([workflow, leaseLost]);
      if (leaseState.lostError !== undefined) throw leaseState.lostError;
    } catch (error) {
      if (leaseState.lostError !== undefined) {
        await workflow.catch(() => undefined);
        throw leaseState.lostError;
      }
      throw error;
    }
    releaseAttempted = true;
    const release = lease.release();
    try {
      await Promise.race([release, leaseLost]);
    } catch (error) {
      await release.catch(() => undefined);
      throw error;
    }
  } finally {
    if (!releaseAttempted) await lease.release();
  }
}

async function assertRootOwnedExecutable(path: string): Promise<string> {
  const resolved = await realpath(path);
  let cursor = resolved;
  for (;;) {
    const info = await lstat(cursor);
    if (info.isSymbolicLink() || info.uid !== 0 || (info.mode & 0o022) !== 0) {
      throw new Error(`trusted BotMux setup path is mutable or not root-owned: ${cursor}`);
    }
    if (cursor === resolved && (!info.isFile() || (info.mode & 0o111) === 0)) {
      throw new Error(`trusted BotMux setup executable is invalid: ${resolved}`);
    }
    if (cursor === "/") break;
    cursor = dirname(cursor);
  }
  return resolved;
}

async function assertRootOwnedHardener(path: string): Promise<string> {
  const resolved = await realpath(path);
  if (resolved !== path) {
    throw new Error("approved BotMux hardener must not traverse a symlink");
  }
  const info = await lstat(resolved);
  if (!info.isFile() || info.isSymbolicLink() || info.uid !== 0 || (info.mode & 0o022) !== 0) {
    throw new Error("approved BotMux hardener is mutable or not root-owned");
  }
  return resolved;
}

async function findBotMuxExecutable(): Promise<string> {
  for (const candidate of ["/usr/local/bin/botmux", "/usr/bin/botmux"]) {
    try {
      return await assertRootOwnedExecutable(candidate);
    } catch {
      // The fixed allowlist deliberately has only these two entries.
    }
  }
  throw new Error("BotMux is not installed at a root-owned fixed executable path");
}

function executeCommand(
  environment: NodeJS.ProcessEnv,
  command: BotMuxSetupCommand,
  signal: AbortSignal,
): Promise<number> {
  throwIfAborted(signal);
  return new Promise((resolve, reject) => {
    const child = spawn(command.executable, [...command.arguments], {
      cwd: "/",
      env: environment,
      shell: false,
      stdio: "inherit",
      windowsHide: true,
    });
    let settled = false;
    let stopping = false;
    let stopTimer: NodeJS.Timeout | undefined;
    const settle = (callback: () => void): void => {
      if (settled) return;
      settled = true;
      signal.removeEventListener("abort", stop);
      if (stopTimer !== undefined) clearTimeout(stopTimer);
      callback();
    };
    const stop = (): void => {
      if (stopping) return;
      stopping = true;
      child.kill("SIGTERM");
      stopTimer = setTimeout(() => { child.kill("SIGKILL"); }, CHILD_STOP_GRACE_MILLISECONDS);
      stopTimer.unref();
    };
    signal.addEventListener("abort", stop, { once: true });
    if (signal.aborted) stop();
    child.once("error", (error) => { settle(() => { reject(error); }); });
    child.once("close", (code, childSignal) => {
      settle(() => {
        if (signal.aborted) {
          reject(asError(signal.reason, `${command.label} was aborted`));
          return;
        }
        resolve(code ?? (childSignal === null ? 1 : 128));
      });
    });
  });
}

async function productionDependencies(): Promise<BotMuxSetupDependencies> {
  const identity = userInfo();
  const nodePath = await assertRootOwnedExecutable(process.execPath);
  const bwrapPath = await assertRootOwnedExecutable(BWRAP);
  const botmuxPath = await findBotMuxExecutable();
  const environment: NodeJS.ProcessEnv = {
    HOME: BOTMUX_HOME,
    USER: BOTMUX_USER,
    LOGNAME: BOTMUX_USER,
    SHELL: "/bin/bash",
    PATH: FIXED_PATH,
    LANG: "C.UTF-8",
  };
  return {
    effectiveUid: process.geteuid?.() ?? process.getuid?.() ?? 0,
    username: identity.username,
    homeDirectory: identity.homedir,
    nodePath,
    bwrapPath,
    botmuxPath,
    configPath: BOTMUX_CONFIG,
    environment,
    acquireLease: async (expected) => await acquireActiveRuntimeSourcePluginLease({
      pluginRegistryPath: PLUGIN_REGISTRY,
      pluginLeaseSocketPath: PLUGIN_LEASE_SOCKET,
    }, expected),
    validateHardener: assertRootOwnedHardener,
    execute: async (command, signal) => await executeCommand(environment, command, signal),
  };
}

function parseArguments(arguments_: readonly string[]): string {
  if (arguments_.length !== 2 || arguments_[0] !== "--digest" || arguments_[1] === undefined) {
    throw new Error("usage: agentd-botmux-setup-run --digest sha256:<hex>");
  }
  return arguments_[1];
}

async function main(): Promise<void> {
  const digest = parseArguments(process.argv.slice(2));
  const controller = new AbortController();
  const forward = (signal: NodeJS.Signals): void => {
    controller.abort(new Error(`BotMux setup received ${signal}`));
  };
  process.on("SIGINT", forward);
  process.on("SIGTERM", forward);
  process.on("SIGHUP", forward);
  try {
    await runBotMuxSourceSetup(digest, await productionDependencies(), controller.signal);
  } finally {
    process.off("SIGINT", forward);
    process.off("SIGTERM", forward);
    process.off("SIGHUP", forward);
  }
}

if (process.argv[1] !== undefined
  && await realpath(process.argv[1]).catch(() => "") === await realpath(fileURLToPath(import.meta.url))) {
  main().catch((error: unknown) => {
    process.stderr.write(
      `agentd-botmux-setup-run: ${error instanceof Error ? error.message : String(error)}\n`,
    );
    process.exitCode = 1;
  });
}
