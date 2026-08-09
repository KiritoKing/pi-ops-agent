#!/usr/bin/env node
import { constants } from "node:fs";
import { access, open, readFile, readdir, readlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { runAdapter } from "../dist/runtime/adapter-run.js";
import { parseProcStartTime } from "../dist/shared/bubblewrap-containment.js";

const DETACHED_CAPTURE_TIMEOUT_MILLISECONDS = 2_000;
const MAX_HOST_PROC_ENTRIES = 32_768;
const MAX_HOST_CMDLINE_BYTES = 64 * 1024;
const MAX_HOST_PROC_METADATA_BYTES = 64 * 1024;

function argument(index, label) {
  const value = process.argv[index];
  if (value === undefined || value.length === 0) throw new Error(`missing ${label}`);
  return value;
}

async function exists(path) {
  try {
    await access(path, constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

function missingProcess(error) {
  return error instanceof Error && "code" in error && error.code === "ENOENT";
}

async function waitFor(path) {
  const deadline = Date.now() + DETACHED_CAPTURE_TIMEOUT_MILLISECONDS;
  for (;;) {
    if (await exists(path)) return;
    if (Date.now() >= deadline) {
      throw new Error("detached Adapter child did not reach its capture barrier");
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

async function readBoundedFile(path, maximumBytes) {
  const handle = await open(path, "r");
  try {
    const buffer = Buffer.alloc(maximumBytes + 1);
    let offset = 0;
    for (;;) {
      const { bytesRead } = await handle.read(
        buffer,
        offset,
        buffer.length - offset,
        null,
      );
      offset += bytesRead;
      if (bytesRead === 0 || offset === buffer.length) break;
    }
    if (offset > maximumBytes) throw new Error("host procfs record exceeds its size limit");
    return buffer.subarray(0, offset);
  } finally {
    await handle.close();
  }
}

async function captureDetachedHostIdentity(resultDirectory) {
  const readyPath = join(resultDirectory, "detached-ready");
  const observedPath = join(resultDirectory, "detached-observed");
  const token = `ops-agent-adapter-detached:${resultDirectory}`;
  await waitFor(readyPath);
  const driverCgroup = await readBoundedFile(
    "/proc/self/cgroup",
    MAX_HOST_PROC_METADATA_BYTES,
  );
  const driverNamespaces = {
    pid: await readlink("/proc/self/ns/pid"),
    mnt: await readlink("/proc/self/ns/mnt"),
    user: await readlink("/proc/self/ns/user"),
  };

  const entries = await readdir("/proc");
  const processEntries = entries.filter((entry) => /^[1-9][0-9]*$/u.test(entry));
  if (processEntries.length > MAX_HOST_PROC_ENTRIES) {
    throw new Error("host procfs exceeds the Adapter probe scan limit");
  }
  const matches = [];
  for (const entry of processEntries) {
    const pid = Number.parseInt(entry, 10);
    try {
      const commandLine = await readBoundedFile(
        `/proc/${pid}/cmdline`,
        MAX_HOST_CMDLINE_BYTES,
      );
      const arguments_ = commandLine.toString("utf8").split("\0").filter(Boolean);
      if (!arguments_.includes(token)) continue;
      const candidateCgroup = await readBoundedFile(
        `/proc/${pid}/cgroup`,
        MAX_HOST_PROC_METADATA_BYTES,
      );
      if (!candidateCgroup.equals(driverCgroup)) continue;
      const status = (await readBoundedFile(
        `/proc/${pid}/status`,
        MAX_HOST_PROC_METADATA_BYTES,
      )).toString("utf8");
      const namespacePids = /^NSpid:\s+([^\n]+)/mu.exec(status)?.[1]
        ?.trim().split(/\s+/u).map((value) => Number.parseInt(value, 10));
      if (namespacePids === undefined || namespacePids.length < 3
        || namespacePids[0] !== pid
        || namespacePids.some((value) => !Number.isSafeInteger(value) || value < 1)) {
        continue;
      }
      const namespaces = {
        pid: await readlink(`/proc/${pid}/ns/pid`),
        mnt: await readlink(`/proc/${pid}/ns/mnt`),
        user: await readlink(`/proc/${pid}/ns/user`),
      };
      if (namespaces.pid === driverNamespaces.pid
        || namespaces.mnt === driverNamespaces.mnt
        || namespaces.user === driverNamespaces.user) {
        continue;
      }
      const startTimeTicks = parseProcStartTime(
        (await readBoundedFile(
          `/proc/${pid}/stat`,
          MAX_HOST_PROC_METADATA_BYTES,
        )).toString("utf8"),
        pid,
      );
      matches.push({ pid, startTimeTicks, namespacePids, namespaces });
    } catch (error) {
      if (!missingProcess(error)
        && !(error instanceof Error && "code" in error && error.code === "EACCES")) {
        throw error;
      }
    }
  }
  if (matches.length !== 1) {
    throw new Error(`host procfs found ${matches.length} detached Adapter probe identities`);
  }
  const identity = matches[0];
  await writeFile(
    observedPath,
    `${JSON.stringify(identity)}\n`,
    { mode: 0o600 },
  );
  return identity;
}

async function hostProcessState(pid) {
  try {
    const status = await readFile(`/proc/${pid}/status`, "utf8");
    const name = /^Name:\s+([^\n]+)/mu.exec(status)?.[1] ?? "unknown";
    const parent = /^PPid:\s+([0-9]+)/mu.exec(status)?.[1] ?? "unknown";
    const namespacePids = /^NSpid:\s+([^\n]+)/mu.exec(status)?.[1] ?? "unknown";
    const state = /^State:\s+([A-Z])/mu.exec(status)?.[1] ?? "unknown";
    const pending = /^SigPnd:\s+([a-f0-9]+)/mu.exec(status)?.[1] ?? "unknown";
    const sharedPending = /^ShdPnd:\s+([a-f0-9]+)/mu.exec(status)?.[1] ?? "unknown";
    return `${state};Name=${name};PPid=${parent};NSpid=${namespacePids};SigPnd=${pending};ShdPnd=${sharedPending}`;
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") return undefined;
    throw error;
  }
}

async function main() {
  if (process.platform !== "linux") throw new Error("the real Adapter probe is Linux-only");
  const registryPath = argument(2, "registry path");
  const snapshotPath = argument(3, "snapshot path");
  argument(4, "fixture path");
  argument(5, "socket path");
  const resultDirectory = argument(6, "result directory");
  const nodePath = argument(7, "fixed Node path");
  const bwrapPath = argument(8, "fixed bubblewrap path");
  const clientPath = argument(9, "fixed probe Client path");
  const digest = `sha256:${"a".repeat(64)}`;
  const plugin = {
    apiVersion: "agentd.plugin-registration/v1",
    schemaVersion: 1,
    pluginId: "adapter.botmux",
    kind: "adapter",
    version: "0.3.0",
    publisher: "pi-ops-agent/linux-probe",
    digest,
    capabilities: [
      "adapter.inbound.text", "adapter.outbound.send", "adapter.session.bind", "approval.status",
    ],
    requestedScopes: [
      "adapter.inbound.text.botmux", "adapter.outbound.send.botmux",
      "adapter.session.bind.botmux", "approval.status.remote",
    ],
    approvedBy: "linux-probe:root",
    approvedAt: "2026-08-08T00:00:00Z",
    entrypoint: "adapter.mjs",
    snapshotPath,
  };
  const detachedIdentity = captureDetachedHostIdentity(resultDirectory);
  // The lease release path consumes this promise. Attach a handler now so an
  // early Adapter failure cannot turn a later capture failure into an
  // unhandled rejection while cleanup is still in progress.
  void detachedIdentity.catch(() => undefined);
  let leaseHeld = false;
  let releases = 0;
  const dependencies = {
    pluginRegistryPath: registryPath,
    pluginCtlPath: "/unused/agentd-pluginctl",
    bwrapPath,
    nodePath,
    clientPath,
    expectedOwnerUid: 0,
    effectiveUid: process.geteuid?.() ?? 0,
    username: "ops-agent-botmux",
    homeDirectory: resultDirectory,
    environment: { LANG: "C.UTF-8", TZ: "UTC" },
    stdinIsTTY: false,
    stdoutIsTTY: false,
    loadActive: async () => plugin,
    acquireLease: async (expected) => {
      if (expected.pluginId !== plugin.pluginId || expected.digest !== plugin.digest) {
        throw new Error("runner requested a lease for the wrong plugin digest");
      }
      if (leaseHeld) throw new Error("probe lease was acquired twice");
      leaseHeld = true;
      await writeFile(join(resultDirectory, "lease-acquired"), `${expected.digest}\n`, { mode: 0o600 });
      return {
        registration: plugin,
        lost: new Promise(() => {}),
        release: async () => {
          releases += 1;
          if (!await exists(join(resultDirectory, "adapter-success"))) {
            leaseHeld = false;
            return;
          }
          const captured = await detachedIdentity;
          let currentStartTime;
          try {
            currentStartTime = parseProcStartTime(
              await readFile(`/proc/${captured.pid}/stat`, "utf8"),
              captured.pid,
            );
          } catch (error) {
            if (missingProcess(error)) currentStartTime = undefined;
            else throw error;
          }
          if (currentStartTime !== captured.startTimeTicks) {
            leaseHeld = false;
            await writeFile(join(resultDirectory, "lease-released"), `${plugin.digest}\n`, { mode: 0o600 });
            return;
          }
          const state = await hostProcessState(captured.pid);
          if (state !== undefined) {
            throw new Error(
              `exact-digest lease released while detached host PID ${captured.pid}`
                + ` starttime ${captured.startTimeTicks} remains in state ${state}`,
            );
          }
          leaseHeld = false;
          await writeFile(join(resultDirectory, "lease-released"), `${plugin.digest}\n`, { mode: 0o600 });
        },
      };
    },
  };

  const result = await runAdapter(plugin.pluginId, [
    "--session-id", "adapter-probe-session-1234",
  ], dependencies);
  if (result !== 0) throw new Error(`Adapter runner exited ${result}`);
  if (leaseHeld || releases !== 1) throw new Error("exact-digest lease lifecycle is invalid");
  await new Promise((resolve) => setTimeout(resolve, 650));
  if (await exists(join(resultDirectory, "detached-survived"))) {
    throw new Error("detached Adapter child survived the bubblewrap PID namespace");
  }
  process.stdout.write("PASS: real bwrap preserved FD3/FD4, group DAC/socket access, killed descendants, and released the exact digest lease last\n");
}

main().catch((error) => {
  process.stderr.write(`adapter-linux-real-probe: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
