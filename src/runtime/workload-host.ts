import { pathToFileURL } from "node:url";

const PROTOCOL_VERSION = 1;
const MAX_FRAME_BYTES = 256 * 1024;
const MAX_TOTAL_INPUT_BYTES = 1024 * 1024;
const ENTRYPOINT_PATTERN = /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))(?!.*\\).{1,512}$/u;
const TOOL_NAME_PATTERN = /^ops_[a-z][a-z0-9_]{2,63}$/u;
const PROVIDER_PATTERN = /^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*$/u;
const capturedExit = process.exit.bind(process);
const capturedWrite = process.stdout.write.bind(process.stdout);

interface CoreRequest {
  version: 1;
  type: "describe" | "invoke";
  invocationId: string;
  entrypoint: string;
  tool?: string;
  input?: unknown;
}

interface ProviderResponse {
  version: 1;
  type: "provider.response";
  invocationId: string;
  requestId: string;
  ok: boolean;
  result?: unknown;
  error?: string;
}

interface WorkloadModule {
  apiVersion: "agentd.workload/v1";
  tools: unknown;
  invoke: (
    request: Readonly<{ tool: string; input: unknown }>,
    api: Readonly<{ call: (provider: string, input: unknown) => Promise<unknown> }>,
  ) => unknown;
}

let inputBuffer = Buffer.alloc(0);
let totalInputBytes = 0;
const frames: unknown[] = [];
const waiters: Array<(value: unknown) => void> = [];

function ownRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value: Record<string, unknown>, allowed: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.every((key) => allowed.includes(key));
}

function receiveFrame(value: unknown): void {
  const waiter = waiters.shift();
  if (waiter === undefined) frames.push(value);
  else waiter(value);
}

function consumeInput(chunk: Buffer): void {
  totalInputBytes += chunk.length;
  if (totalInputBytes > MAX_TOTAL_INPUT_BYTES) throw new Error("workload host input exceeds its total limit");
  inputBuffer = Buffer.concat([inputBuffer, chunk]);
  while (inputBuffer.length >= 4) {
    const length = inputBuffer.readUInt32BE(0);
    if (length < 1 || length > MAX_FRAME_BYTES) throw new Error("workload host received an invalid frame length");
    if (inputBuffer.length < length + 4) return;
    const payload = inputBuffer.subarray(4, length + 4).toString("utf8");
    inputBuffer = inputBuffer.subarray(length + 4);
    receiveFrame(JSON.parse(payload) as unknown);
  }
}

function nextFrame(): Promise<unknown> {
  const value = frames.shift();
  if (value !== undefined) return Promise.resolve(value);
  return new Promise((resolve) => waiters.push(resolve));
}

async function writeFrame(value: unknown): Promise<void> {
  const payload = Buffer.from(JSON.stringify(value), "utf8");
  if (payload.length < 1 || payload.length > MAX_FRAME_BYTES) {
    throw new Error("workload host output exceeds its frame limit");
  }
  const frame = Buffer.allocUnsafe(payload.length + 4);
  frame.writeUInt32BE(payload.length, 0);
  payload.copy(frame, 4);
  await new Promise<void>((resolve, reject) => {
    capturedWrite(frame, (error) => error === undefined
      ? resolve()
      : reject(error instanceof Error ? error : new Error("workload host stdout write failed")));
  });
}

function parseInitialRequest(value: unknown): CoreRequest {
  if (!ownRecord(value) || !exactKeys(value, [
    "version", "type", "invocationId", "entrypoint", "tool", "input",
  ]) || value.version !== PROTOCOL_VERSION ||
      (value.type !== "describe" && value.type !== "invoke") ||
      typeof value.invocationId !== "string" || value.invocationId.length < 8 || value.invocationId.length > 128 ||
      typeof value.entrypoint !== "string" || !ENTRYPOINT_PATTERN.test(value.entrypoint) ||
      value.entrypoint.includes("\0") || value.entrypoint.includes("\r") || value.entrypoint.includes("\n")) {
    throw new Error("workload host received an invalid initial request");
  }
  if (value.type === "describe") {
    if (Object.hasOwn(value, "tool") || Object.hasOwn(value, "input")) {
      throw new Error("workload describe request contains invocation fields");
    }
    return {
      version: 1,
      type: "describe",
      invocationId: value.invocationId,
      entrypoint: value.entrypoint,
    };
  }
  if (typeof value.tool !== "string" || !TOOL_NAME_PATTERN.test(value.tool) || !Object.hasOwn(value, "input")) {
    throw new Error("workload invoke request is incomplete");
  }
  return {
    version: 1,
    type: "invoke",
    invocationId: value.invocationId,
    entrypoint: value.entrypoint,
    tool: value.tool,
    input: value.input,
  };
}

function parseProviderResponse(value: unknown, invocationId: string, requestId: string): ProviderResponse {
  if (!ownRecord(value) || !exactKeys(value, [
    "version", "type", "invocationId", "requestId", "ok", "result", "error",
  ]) || value.version !== 1 || value.type !== "provider.response" ||
      value.invocationId !== invocationId || value.requestId !== requestId || typeof value.ok !== "boolean") {
    throw new Error("workload host received an invalid provider response");
  }
  if (value.ok) {
    if (!Object.hasOwn(value, "result") || Object.hasOwn(value, "error")) {
      throw new Error("successful provider response has invalid fields");
    }
    return { version: 1, type: "provider.response", invocationId, requestId, ok: true, result: value.result };
  }
  if (typeof value.error !== "string" || value.error.length < 1 || value.error.length > 2048 ||
      Object.hasOwn(value, "result")) {
    throw new Error("failed provider response has invalid fields");
  }
  return { version: 1, type: "provider.response", invocationId, requestId, ok: false, error: value.error };
}

function loadWorkloadExport(moduleNamespace: object): WorkloadModule {
  const exportDescriptor = Object.getOwnPropertyDescriptor(moduleNamespace, "workload");
  if (exportDescriptor === undefined || !("value" in exportDescriptor) || !ownRecord(exportDescriptor.value)) {
    throw new Error("workload entrypoint must export a data property named workload");
  }
  const workload = exportDescriptor.value;
  if (!exactKeys(workload, ["apiVersion", "tools", "invoke"]) ||
      workload.apiVersion !== "agentd.workload/v1" || !Array.isArray(workload.tools) ||
      typeof workload.invoke !== "function") {
    throw new Error("workload export does not implement agentd.workload/v1");
  }
  return workload as unknown as WorkloadModule;
}

function safeError(error: unknown): string {
  const message = error instanceof Error ? error.message : "unknown workload failure";
  return message.split("\0").join(" ").split("\r").join(" ").split("\n").join(" ")
    .slice(0, 2048) || "workload failed";
}

async function main(): Promise<void> {
  process.stdin.on("data", (chunk: Buffer) => {
    try {
      consumeInput(chunk);
    } catch (error) {
      void writeFrame({
        version: 1,
        type: "error",
        invocationId: "invalid-request",
        error: safeError(error),
      }).finally(() => capturedExit(1));
    }
  });
  process.stdin.resume();
  const request = parseInitialRequest(await nextFrame());
  const entrypointUrl = pathToFileURL(`/plugin/${request.entrypoint}`);
  const moduleNamespace = await import(entrypointUrl.href) as object;
  const workload = loadWorkloadExport(moduleNamespace);
  const tools = JSON.parse(JSON.stringify(workload.tools)) as unknown;
  if (request.type === "describe") {
    await writeFrame({
      version: 1,
      type: "descriptor",
      invocationId: request.invocationId,
      descriptor: { apiVersion: workload.apiVersion, tools },
    });
    return;
  }
  const tool = request.tool;
  if (tool === undefined || !Array.isArray(tools) || !tools.some((item) =>
    ownRecord(item) && item.name === tool)) {
    throw new Error("workload invoke requested a tool not declared by the entrypoint");
  }
  let providerCounter = 0;
  const call = async (provider: string, input: unknown): Promise<unknown> => {
    if (typeof provider !== "string" || !PROVIDER_PATTERN.test(provider)) {
      throw new Error("workload requested an invalid provider name");
    }
    providerCounter += 1;
    if (providerCounter > 32) throw new Error("workload exceeded its provider call limit");
    const requestId = `${request.invocationId}:provider:${providerCounter}`;
    await writeFrame({
      version: 1,
      type: "provider.request",
      invocationId: request.invocationId,
      requestId,
      provider,
      input,
    });
    const response = parseProviderResponse(await nextFrame(), request.invocationId, requestId);
    if (!response.ok) throw new Error(response.error);
    return response.result;
  };
  const result = await workload.invoke(
    Object.freeze({ tool, input: request.input }),
    Object.freeze({ call }),
  );
  await writeFrame({ version: 1, type: "result", invocationId: request.invocationId, result });
}

void main().then(
  () => capturedExit(0),
  async (error: unknown) => {
    try {
      await writeFrame({
        version: 1,
        type: "error",
        invocationId: "runtime-error",
        error: safeError(error),
      });
    } finally {
      capturedExit(1);
    }
  },
);
