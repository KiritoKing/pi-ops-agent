#!/usr/bin/env node
import { spawn } from "node:child_process";
import { closeSync, readFileSync, writeSync } from "node:fs";
import { access, readFile, writeFile } from "node:fs/promises";
import { connect } from "node:net";
import { dirname, join } from "node:path";

const descriptor = {
  apiVersion: "agentd.adapter/v1",
  schemaVersion: 1,
  adapterId: "adapter.botmux",
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
};

async function exchange(socketPath) {
  return await new Promise((resolve, reject) => {
    const socket = connect(socketPath);
    const chunks = [];
    socket.setTimeout(2_000, () => socket.destroy(new Error("probe socket timed out")));
    socket.once("connect", () => socket.write("adapter-probe\n"));
    socket.on("data", (chunk) => chunks.push(chunk));
    socket.once("error", reject);
    socket.once("end", () => resolve(Buffer.concat(chunks).toString("utf8").trim()));
  });
}

async function waitFor(path) {
  const deadline = Date.now() + 2_000;
  for (;;) {
    try {
      await access(path);
      return;
    } catch (error) {
      if (Date.now() >= deadline) throw error;
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
  }
}

async function main() {
  if (process.argv[2] === "--agentd-adapter-describe") {
    process.stdout.write(`${JSON.stringify(descriptor)}\n`);
    return;
  }

  const resultDirectory = process.env.HOME;
  if (resultDirectory === undefined || resultDirectory.length === 0) {
    throw new Error("probe HOME is missing");
  }
  const probeRoot = dirname(resultDirectory);
  const fixturePath = join(probeRoot, "root-group-readable");
  const socketPath = join(probeRoot, "socket", "agentd-client.sock");
  const fixture = (await readFile(fixturePath, "utf8")).trim();
  if (fixture !== "root-group-readable") throw new Error("group-readable fixture mismatch");
  const response = await exchange(socketPath);
  if (response !== "root-group-socket-ok") throw new Error("group socket response mismatch");
  await writeFile(join(resultDirectory, "adapter-success"), `${fixture}\n${response}\n`, {
    mode: 0o600,
  });

  const detachedReadyPath = join(resultDirectory, "detached-ready");
  const detachedObservedPath = join(resultDirectory, "detached-observed");
  const detachedToken = `ops-agent-adapter-detached:${resultDirectory}`;
  const escapedPath = join(resultDirectory, "detached-survived");
  const childScript = [
    "const fs = require('node:fs');",
    `fs.writeFileSync(${JSON.stringify(detachedReadyPath)}, 'ready\\n', { mode: 0o600 });`,
    "const observed = setInterval(() => {",
    `  if (!fs.existsSync(${JSON.stringify(detachedObservedPath)})) return;`,
    "  clearInterval(observed);",
    `  setTimeout(() => fs.writeFileSync(${JSON.stringify(escapedPath)}, 'escaped\\n'), 400);`,
    "}, 10);",
    "setTimeout(() => {}, 5_000);",
  ].join("\n");
  const child = spawn(process.execPath, ["-e", childScript, detachedToken], {
    detached: true,
    stdio: "ignore",
  });
  child.unref();
  await waitFor(detachedReadyPath);
  // The host-side probe driver must bind the real host PID and starttime from
  // its own procfs view before this Source is allowed to exit. An inner
  // bubblewrap procfs view cannot truthfully self-report a host PID.
  await waitFor(detachedObservedPath);

  const externalSessionId = "linux-probe-external-session";
  const frames = [
    {
      apiVersion: "agentd.adapter-session-control/v1",
      schemaVersion: 1,
      type: "bind",
      controlId: "control:linux-probe:00000001",
      externalSessionId,
      sessionId: "adapter-probe-session-1234",
    },
    {
      apiVersion: "agentd.adapter-inbound/v1",
      schemaVersion: 1,
      type: "text",
      ingressId: "ingress:linux-probe:00000001",
      externalSessionId,
      conversationType: "direct",
      text: "FD3/FD4 分片探针",
      source: { authentication: "unverified", principalId: "linux-probe:fixture" },
      observedAt: "2026-08-08T00:00:00Z",
    },
  ];
  const payload = Buffer.from(`${frames.map((frame) => JSON.stringify(frame)).join("\n")}\n`);
  // Split inside the CJK payload so the real bwrap path proves that inherited
  // FD4 survives exec and the runner bridge preserves byte fragments.
  const split = payload.indexOf(Buffer.from("分", "utf8")) + 1;
  writeSync(4, payload.subarray(0, split));
  writeSync(4, payload.subarray(split));
  closeSync(4);
  const completion = readFileSync(3, "utf8");
  if (completion !== "probe-completion\n") {
    throw new Error("fixed FD3 completion bridge mismatch");
  }
  closeSync(3);
}

main().catch((error) => {
  process.stderr.write(`adapter-linux-dac-probe: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
