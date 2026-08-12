import { spawn, type ChildProcess } from "node:child_process";
import { once } from "node:events";
import { readFileSync } from "node:fs";
import { createServer } from "node:net";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const TOKEN = "fixture-only-not-a-secret-0001";
const MODEL = "fixture-model";
const PENDING_CHANGE_INSTRUCTION =
  "This change is pending model-external local review and exact client approval.";
const PVE_EXECUTING_INSTRUCTION =
  "The signed broker state is EXECUTING; no new approval action is currently available.";
const PVE_SERVER_ID = "server-pve-fixture-e2e";
const PVE_MACHINE_ID = "machine-pve-fixture-e2e";
const PVE_TARGET_ID = "target-pve-fixture-e2e";
const PVE_POLICY_REVISION = "policy-pve-fixture-e2e-v1";
const PVE_CHANGE_ID = `pve-change-${"c".repeat(32)}`;
const PVE_PLAN_HASH = `sha256:${"d".repeat(64)}`;
const FIXTURE_PATH = fileURLToPath(new URL(
  "./fixtures/e2e/mock-openai-completions.mjs",
  import.meta.url,
));
const PVE_MANIFEST_PATH = fileURLToPath(new URL(
  "../plugins/workload-pve/manifest.json",
  import.meta.url,
));

interface FixtureRun {
  readonly child: ChildProcess;
  stdout(): string;
  stderr(): string;
}

interface StreamToolCall {
  readonly id: string;
  readonly type: "function";
  readonly function: {
    readonly name: string;
    readonly arguments: string;
  };
}

interface CompletionChunk {
  readonly choices?: readonly [{
    readonly delta?: {
      readonly content?: string | null;
      readonly tool_calls?: readonly StreamToolCall[];
    };
  }];
}

interface PVEManifest {
  readonly id: string;
  readonly kind: string;
  readonly version: string;
  readonly publisher: string;
  readonly capabilities: readonly string[];
  readonly requestedScopes: readonly string[];
}

async function reserveLoopbackPort(): Promise<number> {
  const listener = createServer();
  listener.listen(0, "127.0.0.1");
  await once(listener, "listening");
  const address = listener.address();
  if (address === null || typeof address === "string") {
    listener.close();
    throw new Error("test listener did not obtain a TCP port");
  }
  await new Promise<void>((resolve, reject) => {
    listener.close((error) => {
      if (error === undefined) resolve();
      else reject(error);
    });
  });
  return address.port;
}

function startFixture(port: number, digest: string): FixtureRun {
  let stdout = "";
  let stderr = "";
  const child = spawn(process.execPath, [FIXTURE_PATH], {
    env: {
      ...process.env,
      MOCK_SCENARIO: "plugin-register-pve",
      MOCK_PORT: String(port),
      MOCK_NONCE: "plugin-register-pve-e2e",
      MOCK_MACHINE_ID: "machine-plugin-register-e2e",
      MOCK_TARGET_ID: "target-plugin-register-e2e",
      MOCK_SERVER_ID: "server-plugin-register-e2e",
      MOCK_PVE_PLUGIN_SOURCE_DIGEST: digest,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => { stdout += chunk; });
  child.stderr.on("data", (chunk: string) => { stderr += chunk; });
  return {
    child,
    stdout: () => stdout,
    stderr: () => stderr,
  };
}

function startPVEFixture(
  port: number,
  scenario: "pve-inspect" | "pve-start",
  nonce: string,
): FixtureRun {
  let stdout = "";
  let stderr = "";
  const child = spawn(process.execPath, [FIXTURE_PATH], {
    env: {
      ...process.env,
      MOCK_SCENARIO: scenario,
      MOCK_PORT: String(port),
      MOCK_NONCE: nonce,
      MOCK_MACHINE_ID: PVE_MACHINE_ID,
      MOCK_TARGET_ID: PVE_TARGET_ID,
      MOCK_SERVER_ID: PVE_SERVER_ID,
      ...(scenario === "pve-start"
        ? { MOCK_PVE_POLICY_REVISION: PVE_POLICY_REVISION }
        : {}),
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => { stdout += chunk; });
  child.stderr.on("data", (chunk: string) => { stderr += chunk; });
  return {
    child,
    stdout: () => stdout,
    stderr: () => stderr,
  };
}

async function waitForOutput(run: FixtureRun, marker: string): Promise<void> {
  if (run.stdout().includes(marker)) return;
  await new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(() => {
      cleanup();
      reject(new Error(`fixture output timed out: ${run.stderr()}`));
    }, 5_000);
    const onData = (): void => {
      if (!run.stdout().includes(marker)) return;
      cleanup();
      resolve();
    };
    const onExit = (code: number | null): void => {
      cleanup();
      reject(new Error(`fixture exited before ${marker}: code=${code} stderr=${run.stderr()}`));
    };
    const cleanup = (): void => {
      clearTimeout(timeout);
      run.child.stdout?.off("data", onData);
      run.child.off("exit", onExit);
    };
    run.child.stdout?.on("data", onData);
    run.child.once("exit", onExit);
    onData();
  });
}

async function waitForExit(run: FixtureRun): Promise<number | null> {
  if (run.child.exitCode !== null) return run.child.exitCode;
  return await new Promise<number | null>((resolve, reject) => {
    const timeout = setTimeout(() => {
      cleanup();
      reject(new Error(`fixture exit timed out: ${run.stderr()}`));
    }, 5_000);
    const onExit = (code: number | null): void => {
      cleanup();
      resolve(code);
    };
    const cleanup = (): void => {
      clearTimeout(timeout);
      run.child.off("exit", onExit);
    };
    run.child.once("exit", onExit);
    if (run.child.exitCode !== null) {
      cleanup();
      resolve(run.child.exitCode);
    }
  });
}

async function terminateFixture(run: FixtureRun): Promise<void> {
  if (run.child.exitCode !== null || run.child.signalCode !== null) return;
  run.child.kill("SIGTERM");
  try {
    await waitForExit(run);
  } catch {
    run.child.kill("SIGKILL");
  }
}

function parseSse(text: string): readonly CompletionChunk[] {
  return text.split("\n")
    .filter((line) => line.startsWith("data: ") && line !== "data: [DONE]")
    .map((line) => JSON.parse(line.slice("data: ".length)) as CompletionChunk);
}

function onlyToolCall(text: string): StreamToolCall {
  const calls = parseSse(text).flatMap((entry) =>
    entry.choices?.[0]?.delta?.tool_calls ?? []);
  if (calls.length !== 1) throw new Error(`expected one tool call, received ${calls.length}`);
  const call = calls[0];
  if (call === undefined) throw new Error("tool call disappeared after length validation");
  return call;
}

function completionContent(text: string): { readonly content: string; readonly toolCalls: number } {
  const chunks = parseSse(text);
  return {
    content: chunks.flatMap((entry) => {
      const content = entry.choices?.[0]?.delta?.content;
      return typeof content === "string" ? [content] : [];
    }).join(""),
    toolCalls: chunks.reduce((count, entry) =>
      count + (entry.choices?.[0]?.delta?.tool_calls?.length ?? 0), 0),
  };
}

async function completionRequest(
  port: number,
  messages: readonly unknown[],
  toolNames: readonly string[] = ["ops_propose_change"],
): Promise<{ readonly status: number; readonly text: string }> {
  const response = await fetch(`http://127.0.0.1:${port}/v1/chat/completions`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${TOKEN}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      model: MODEL,
      stream: true,
      messages,
      tools: toolNames.map((name) => ({
        type: "function",
        function: {
          name,
          parameters: { type: "object", additionalProperties: false },
        },
      })),
    }),
    signal: AbortSignal.timeout(5_000),
  });
  return { status: response.status, text: await response.text() };
}

function canonicalChangeRef(): string {
  const payload = JSON.stringify({
    version: 1,
    serverId: "server-plugin-register-e2e",
    machineId: "machine-plugin-register-e2e",
    targetId: "target-plugin-register-e2e",
    changeId: "change-plugin-register-pve-e2e",
  });
  return `opschg1_${Buffer.from(payload).toString("base64url")}`;
}

function canonicalPVEChangeRef(): string {
  const payload = JSON.stringify({
    version: 1,
    serverId: PVE_SERVER_ID,
    machineId: PVE_MACHINE_ID,
    targetId: PVE_TARGET_ID,
    changeId: PVE_CHANGE_ID,
  });
  return `opschg1_${Buffer.from(payload).toString("base64url")}`;
}

function pveExecutingResult(changeRef: string): string {
  return [
    "PVE guest start accepted under the exact standing policy scope.",
    `machineId=${PVE_MACHINE_ID}`,
    `targetId=${PVE_TARGET_ID}`,
    `changeRef=${changeRef}`,
    PVE_EXECUTING_INSTRUCTION,
  ].join("\n");
}

function pveStatusResult(state: "COMMITTED" | "RECOVERY_REQUIRED"): string {
  const requestId = "request-pve-status-fixture-0001";
  const auditId = `audit-${"e".repeat(32)}`;
  const issuedAt = "2026-08-10T08:00:00Z";
  return JSON.stringify({
    version: 1,
    requestId,
    ok: true,
    auditId,
    changeId: PVE_CHANGE_ID,
    state,
    summary: state === "COMMITTED"
      ? "PVE guest start committed after the original UPID reached stopped/OK."
      : "PVE guest start outcome requires recovery.",
    data: {
      serverId: PVE_SERVER_ID,
      machineId: PVE_MACHINE_ID,
      targetId: PVE_TARGET_ID,
      policyRevision: PVE_POLICY_REVISION,
      capabilityRevision: "capability-pve-fixture-e2e-v1",
      planHash: PVE_PLAN_HASH,
      kind: "pve.guest.action",
      backupRefs: [],
      verification: "Original UPID is terminal and the guest postcondition was observed.",
      rollbackAvailable: false,
      authorizationBasis:
        `standing-policy:${PVE_POLICY_REVISION}:pve.guest.start`,
      authorizationScope: "pve.guest.start",
      authorizedAt: issuedAt,
      recoveryOnly: false,
    },
    brokerReceipt: {
      version: 1,
      keyId: "pve-receipt-fixture-v1",
      domain: "pve",
      requestId,
      method: "change.status",
      action: "status",
      serverId: PVE_SERVER_ID,
      machineId: PVE_MACHINE_ID,
      targetId: PVE_TARGET_ID,
      changeId: PVE_CHANGE_ID,
      planHash: PVE_PLAN_HASH,
      state,
      auditId,
      resultDigest: `sha256:${"f".repeat(64)}`,
      issuedAt,
      signature: Buffer.alloc(64, 0x5a).toString("base64").replace(/=+$/u, ""),
    },
  });
}

describe("scripted OpenAI-compatible plugin registration fixture", () => {
  it("prepares the exact shipped PVE source registration and stops at model-external approval", async () => {
    const port = await reserveLoopbackPort();
    const digest = `sha256:${"a".repeat(64)}`;
    const manifest = JSON.parse(readFileSync(PVE_MANIFEST_PATH, "utf8")) as PVEManifest;
    const run = startFixture(port, digest);
    try {
      await waitForOutput(run, "MOCK_READY scenario=plugin-register-pve");
      const userMessage = { role: "user", content: "Register the staged PVE source plugin." };
      const first = await completionRequest(port, [userMessage]);
      expect(first.status).toBe(200);
      const call = onlyToolCall(first.text);
      expect(call).toMatchObject({
        id: "call_ops_agent_e2e_1",
        type: "function",
        function: { name: "ops_propose_change" },
      });
      expect(JSON.parse(call.function.arguments)).toEqual({
        machineId: "machine-plugin-register-e2e",
        targetId: "target-plugin-register-e2e",
        operation: {
          kind: "plugin.register",
          pluginId: manifest.id,
          pluginKind: manifest.kind,
          version: manifest.version,
          publisher: manifest.publisher,
          digest,
          capabilities: manifest.capabilities,
          requestedScopes: manifest.requestedScopes,
        },
      });

      const changeRef = canonicalChangeRef();
      const toolResult = [
        "PVE source plugin registration prepared.",
        "machineId=machine-plugin-register-e2e",
        "targetId=target-plugin-register-e2e",
        `changeRef=${changeRef}`,
        PENDING_CHANGE_INSTRUCTION,
      ].join("\n");
      const second = await completionRequest(port, [
        userMessage,
        {
          role: "assistant",
          tool_calls: [{
            id: call.id,
            type: call.type,
            function: call.function,
          }],
        },
        { role: "tool", tool_call_id: call.id, content: toolResult },
      ]);
      expect(second.status).toBe(200);
      expect(completionContent(second.text)).toEqual({
        content:
          `SCRIPTED_MODEL_E2E_PLUGIN_REGISTER_PVE_OK nonce=plugin-register-pve-e2e changeRef=${changeRef}`,
        toolCalls: 0,
      });
      expect(await waitForExit(run)).toBe(0);
      expect(run.stdout()).toContain(
        "MOCK_COMPLETE scenario=plugin-register-pve requests=2 nonce=plugin-register-pve-e2e",
      );
    } finally {
      await terminateFixture(run);
    }
  }, 15_000);

  it("fails closed instead of emitting a marker without the exact pending instruction", async () => {
    const port = await reserveLoopbackPort();
    const digest = `sha256:${"b".repeat(64)}`;
    const run = startFixture(port, digest);
    try {
      await waitForOutput(run, "MOCK_READY scenario=plugin-register-pve");
      const userMessage = { role: "user", content: "Register the staged PVE source plugin." };
      const first = await completionRequest(port, [userMessage]);
      const call = onlyToolCall(first.text);
      const second = await completionRequest(port, [
        userMessage,
        {
          role: "assistant",
          tool_calls: [{
            id: call.id,
            type: call.type,
            function: call.function,
          }],
        },
        {
          role: "tool",
          tool_call_id: call.id,
          content: [
            "PVE source plugin registration prepared.",
            "machineId=machine-plugin-register-e2e",
            "targetId=target-plugin-register-e2e",
            `changeRef=${canonicalChangeRef()}`,
            "The model approved this change.",
          ].join("\n"),
        },
      ]);
      expect(second.status).toBe(400);
      expect(second.text).toContain(
        "PVE plugin registration result omitted its signed PENDING_APPROVAL instruction",
      );
      expect(await waitForExit(run)).toBe(1);
      expect(run.stdout()).not.toContain("SCRIPTED_MODEL_E2E_PLUGIN_REGISTER_PVE_OK");
    } finally {
      await terminateFixture(run);
    }
  }, 15_000);
});

describe("scripted OpenAI-compatible PVE fixture", () => {
  const inspectTools = ["ops_pve_guest_inspect", "ops_change_status"] as const;
  const startTools = ["ops_pve_guest_lifecycle_prepare", "ops_change_status"] as const;

  it("accepts only the exact stopped guest JSON before emitting the inspect marker", async () => {
    const port = await reserveLoopbackPort();
    const nonce = "pve-inspect-fixture-e2e";
    const run = startPVEFixture(port, "pve-inspect", nonce);
    try {
      await waitForOutput(run, "MOCK_READY scenario=pve-inspect");
      const userMessage = { role: "user", content: "Inspect guest 100 on pve-e2e." };
      const first = await completionRequest(port, [userMessage], inspectTools);
      expect(first.status).toBe(200);
      const call = onlyToolCall(first.text);
      expect(call).toMatchObject({
        id: "call_ops_agent_e2e_1",
        type: "function",
        function: { name: "ops_pve_guest_inspect" },
      });
      expect(JSON.parse(call.function.arguments)).toEqual({
        machineId: PVE_MACHINE_ID,
        targetId: PVE_TARGET_ID,
        node: "pve-e2e",
        guestType: "qemu",
        vmid: 100,
      });

      const second = await completionRequest(port, [
        userMessage,
        {
          role: "assistant",
          tool_calls: [{
            id: call.id,
            type: call.type,
            function: call.function,
          }],
        },
        {
          role: "tool",
          tool_call_id: call.id,
          content: JSON.stringify({ status: "stopped", lock: "" }),
        },
      ], inspectTools);
      expect(second.status).toBe(200);
      expect(completionContent(second.text)).toEqual({
        content: `SCRIPTED_MODEL_E2E_PVE_INSPECT_OK nonce=${nonce}`,
        toolCalls: 0,
      });
      expect(await waitForExit(run)).toBe(0);
      expect(run.stdout()).toContain(
        `MOCK_COMPLETE scenario=pve-inspect requests=2 nonce=${nonce}`,
      );
    } finally {
      await terminateFixture(run);
    }
  }, 15_000);

  it("polls a fresh status call and emits a marker only for exact signed-shaped COMMITTED", async () => {
    const port = await reserveLoopbackPort();
    const nonce = "pve-start-fixture-e2e";
    const changeRef = canonicalPVEChangeRef();
    const run = startPVEFixture(port, "pve-start", nonce);
    try {
      await waitForOutput(run, "MOCK_READY scenario=pve-start");
      const userMessage = { role: "user", content: "Start guest 100 on pve-e2e." };
      const first = await completionRequest(port, [userMessage], startTools);
      expect(first.status).toBe(200);
      const lifecycleCall = onlyToolCall(first.text);
      expect(lifecycleCall).toMatchObject({
        id: "call_ops_agent_e2e_1",
        type: "function",
        function: { name: "ops_pve_guest_lifecycle_prepare" },
      });
      expect(JSON.parse(lifecycleCall.function.arguments)).toEqual({
        machineId: PVE_MACHINE_ID,
        targetId: PVE_TARGET_ID,
        node: "pve-e2e",
        guestType: "qemu",
        vmid: 100,
        action: "start",
      });

      const lifecycleResult = pveExecutingResult(changeRef);
      const lifecycleMessages = [
        userMessage,
        {
          role: "assistant",
          tool_calls: [{
            id: lifecycleCall.id,
            type: lifecycleCall.type,
            function: lifecycleCall.function,
          }],
        },
        { role: "tool", tool_call_id: lifecycleCall.id, content: lifecycleResult },
      ];
      const second = await completionRequest(port, lifecycleMessages, startTools);
      expect(second.status).toBe(200);
      const statusCall = onlyToolCall(second.text);
      expect(statusCall.id).toBe("call_ops_agent_e2e_status_1");
      expect(statusCall.id).not.toBe(lifecycleCall.id);
      expect(statusCall.function.name).toBe("ops_change_status");
      expect(JSON.parse(statusCall.function.arguments)).toEqual({
        machineId: PVE_MACHINE_ID,
        targetId: PVE_TARGET_ID,
        changeId: PVE_CHANGE_ID,
      });

      const committedStatus = pveStatusResult("COMMITTED");
      expect(JSON.parse(committedStatus)).toMatchObject({
        changeId: PVE_CHANGE_ID,
        state: "COMMITTED",
        data: {
          serverId: PVE_SERVER_ID,
          machineId: PVE_MACHINE_ID,
          targetId: PVE_TARGET_ID,
          policyRevision: PVE_POLICY_REVISION,
          planHash: PVE_PLAN_HASH,
          authorizationBasis:
            `standing-policy:${PVE_POLICY_REVISION}:pve.guest.start`,
          authorizationScope: "pve.guest.start",
        },
        brokerReceipt: {
          domain: "pve",
          method: "change.status",
          action: "status",
          serverId: PVE_SERVER_ID,
          machineId: PVE_MACHINE_ID,
          targetId: PVE_TARGET_ID,
          changeId: PVE_CHANGE_ID,
          planHash: PVE_PLAN_HASH,
          state: "COMMITTED",
        },
      });
      const third = await completionRequest(port, [
        ...lifecycleMessages,
        {
          role: "assistant",
          tool_calls: [{
            id: statusCall.id,
            type: statusCall.type,
            function: statusCall.function,
          }],
        },
        { role: "tool", tool_call_id: statusCall.id, content: committedStatus },
      ], startTools);
      expect(third.status).toBe(200);
      expect(completionContent(third.text)).toEqual({
        content:
          `SCRIPTED_MODEL_E2E_PVE_START_OK nonce=${nonce} state=COMMITTED changeId=${PVE_CHANGE_ID} changeRef=${changeRef}`,
        toolCalls: 0,
      });
      expect(await waitForExit(run)).toBe(0);
      expect(run.stdout().match(/MOCK_PVE_STATUS_OK poll=/gu)).toHaveLength(1);
      expect(run.stdout()).toContain(
        `MOCK_PVE_STATUS_OK poll=1 state=COMMITTED changeId=${PVE_CHANGE_ID}`,
      );
      expect(run.stdout()).toContain(
        `MOCK_COMPLETE scenario=pve-start requests=3 nonce=${nonce}`,
      );
    } finally {
      await terminateFixture(run);
    }
  }, 15_000);

  it("fails closed on a signed-shaped recovery terminal instead of emitting success", async () => {
    const port = await reserveLoopbackPort();
    const nonce = "pve-start-recovery-e2e";
    const changeRef = canonicalPVEChangeRef();
    const run = startPVEFixture(port, "pve-start", nonce);
    try {
      await waitForOutput(run, "MOCK_READY scenario=pve-start");
      const userMessage = { role: "user", content: "Start guest 100 on pve-e2e." };
      const first = await completionRequest(port, [userMessage], startTools);
      const lifecycleCall = onlyToolCall(first.text);
      const lifecycleMessages = [
        userMessage,
        {
          role: "assistant",
          tool_calls: [{
            id: lifecycleCall.id,
            type: lifecycleCall.type,
            function: lifecycleCall.function,
          }],
        },
        {
          role: "tool",
          tool_call_id: lifecycleCall.id,
          content: pveExecutingResult(changeRef),
        },
      ];
      const second = await completionRequest(port, lifecycleMessages, startTools);
      const statusCall = onlyToolCall(second.text);
      const third = await completionRequest(port, [
        ...lifecycleMessages,
        {
          role: "assistant",
          tool_calls: [{
            id: statusCall.id,
            type: statusCall.type,
            function: statusCall.function,
          }],
        },
        {
          role: "tool",
          tool_call_id: statusCall.id,
          content: pveStatusResult("RECOVERY_REQUIRED"),
        },
      ], startTools);
      expect(third.status).toBe(400);
      expect(third.text).toContain(
        "PVE status response had an invalid signed lifecycle identity",
      );
      expect(await waitForExit(run)).toBe(1);
      expect(run.stdout()).not.toContain("SCRIPTED_MODEL_E2E_PVE_START_OK");
    } finally {
      await terminateFixture(run);
    }
  }, 15_000);
});
