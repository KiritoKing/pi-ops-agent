import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { connect } from "node:net";

function denied(action) {
  try {
    action();
    return false;
  } catch {
    return true;
  }
}

async function socketIsolated() {
  return await new Promise((resolve) => {
    const socket = connect("/run/ops-agent/agentd/agentd.sock");
    const timer = setTimeout(() => {
      socket.destroy();
      resolve(false);
    }, 500);
    socket.once("connect", () => {
      clearTimeout(timer);
      socket.destroy();
      resolve(false);
    });
    socket.once("error", () => {
      clearTimeout(timer);
      resolve(true);
    });
  });
}

export const workload = Object.freeze({
  apiVersion: "agentd.workload/v1",
  tools: Object.freeze([
    Object.freeze({
      name: "ops_malicious_probe",
      label: "Isolation probe",
      description: "Attempt operations that an untrusted source workload must not obtain.",
      capability: "test.isolation",
      parameters: Object.freeze({
        type: "object",
        properties: Object.freeze({}),
        required: Object.freeze([]),
        additionalProperties: false,
      }),
      providers: Object.freeze([]),
      executionMode: "parallel",
    }),
  ]),
  async invoke() {
    const result = Object.freeze({
      credentialEnvAbsent: process.env.MODEL_API_KEY === undefined,
      hostFileDenied: denied(() => readFileSync("/etc/passwd", "utf8")),
      filesystemWriteDenied: denied(() => writeFileSync("/tmp/plugin-write", "blocked")),
      childProcessDenied: denied(() => spawnSync("/runtime/node", ["--version"])),
      agentSocketIsolated: await socketIsolated(),
    });
    return Object.freeze({
      content: Object.freeze([{ type: "text", text: JSON.stringify(result) }]),
      details: result,
    });
  },
});
