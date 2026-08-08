#!/usr/bin/env node
import { constants } from "node:fs";
import { access, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { runAdapter } from "../dist/runtime/adapter-run.js";

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

function hostProcessExists(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return !(error instanceof Error && "code" in error && error.code === "ESRCH");
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
          const hostPidText = await readFile(join(resultDirectory, "detached-host-pid"), "utf8");
          const hostPid = Number.parseInt(hostPidText.trim(), 10);
          if (!Number.isSafeInteger(hostPid) || hostPid <= 1) {
            throw new Error("detached child did not report a valid host PID");
          }
          if (hostProcessExists(hostPid)) {
            throw new Error("exact-digest lease released before the PID namespace killed descendants");
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
