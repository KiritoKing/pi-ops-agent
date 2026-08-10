import { createHash } from "node:crypto";
import {
  createServer,
  request as httpRequest,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import {
  completeSimple,
  Type,
  type Context,
  type Model,
  type Tool,
} from "@earendil-works/pi-ai/compat";
import { beforeEach, describe, expect, it } from "vitest";

interface LocalOllamaBridgeResult {
  ok: boolean;
  code: string;
}

interface LocalOllamaBridgeHandle {
  host: string;
  port: number;
  completion: Promise<LocalOllamaBridgeResult>;
  close(): Promise<void>;
}

interface LocalOllamaBridgeModule {
  startBridgeForTest: (options: {
    listenHost: string;
    listenPort: number;
    allowedPeer: string;
    token: string;
    expectedModel: string;
    expectedSystemDigest: string;
    nonce: string;
    expectedOllamaDigest: string;
    upstreamPort: number;
    idleTimeoutMs?: number;
    requestTimeoutMs?: number;
    upstreamTimeoutMs?: number;
    responsePhaseTimeoutMs?: number;
  }) => Promise<LocalOllamaBridgeHandle>;
}

const fixtureModuleUrl = new URL(
  "../fixtures/e2e/local-ollama-openai-bridge.mjs",
  import.meta.url,
).href;
const bridgeModule = await import(fixtureModuleUrl) as unknown as LocalOllamaBridgeModule;
const { startBridgeForTest } = bridgeModule;

const OLLAMA_MODEL = "qwen3-8b8q-clzh:latest";
const OLLAMA_DIGEST = "a".repeat(64);
const TOKEN = Buffer.alloc(32, 7).toString("base64url");
const EXPECTED_TOOL_NAMES = [
  "ops_artifact_catalog",
  "ops_bash",
  "ops_breakglass_prepare",
  "ops_change_status",
  "ops_inspect",
  "ops_machine_describe",
  "ops_machine_list",
  "ops_propose_change",
] as const;
const SYSTEM_PROMPT = "Bound test system prompt.";
const SYSTEM_DIGEST = `sha256:${createHash("sha256").update(SYSTEM_PROMPT).digest("hex")}`;
const NONCE = "local-model-test-0001";
const EXPECTED_OUTPUT = `LOCAL_MODEL_E2E_OK_${NONCE}`;

interface FakeState {
  tags: number;
  show: number;
  chat: number;
  activeDrips: number;
  closedDrips: number;
  error?: string;
}

interface FakeOptions {
  chatDelayMs?: number;
  dripChat?: boolean;
  dripIntervalMs?: number;
}

interface FakeOllama {
  server: Server;
  port: number;
  state: FakeState;
}

function readBody(request: IncomingMessage): Promise<Buffer> {
  return new Promise((resolveBody, rejectBody) => {
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.on("error", rejectBody);
    request.on("end", () => resolveBody(Buffer.concat(chunks)));
  });
}

function sendJson(response: ServerResponse, value: unknown): void {
  const encoded = Buffer.from(JSON.stringify(value), "utf8");
  response.writeHead(200, {
    "content-type": "application/json; charset=utf-8",
    "content-length": String(encoded.length),
    connection: "close",
  });
  response.end(encoded);
}

async function startFakeOllama(options: FakeOptions = {}): Promise<FakeOllama> {
  const state: FakeState = { tags: 0, show: 0, chat: 0, activeDrips: 0, closedDrips: 0 };
  const server = createServer((request, response) => {
    void (async () => {
      try {
        if (request.method === "GET" && request.url === "/api/tags") {
          state.tags += 1;
          sendJson(response, {
            models: [{ name: OLLAMA_MODEL, model: OLLAMA_MODEL, digest: OLLAMA_DIGEST }],
          });
          return;
        }
        if (request.method === "POST" && request.url === "/api/show") {
          state.show += 1;
          expect(JSON.parse((await readBody(request)).toString("utf8"))).toEqual({ model: OLLAMA_MODEL });
          sendJson(response, { capabilities: ["completion"] });
          return;
        }
        if (request.method === "POST" && request.url === "/api/chat") {
          state.chat += 1;
          expect(JSON.parse((await readBody(request)).toString("utf8"))).toEqual({
            model: OLLAMA_MODEL,
            messages: [
              { role: "system", content: SYSTEM_PROMPT },
              {
                role: "user",
                content: `Reply with exactly ${EXPECTED_OUTPUT} and nothing else. Do not call tools.`,
              },
            ],
            stream: false,
            think: false,
            options: { temperature: 0, num_predict: 64 },
          });
          if (options.dripChat === true) {
            state.activeDrips += 1;
            let cleaned = false;
            const interval = setInterval(() => {
              if (response.destroyed) return;
              response.write(" ");
            }, options.dripIntervalMs ?? 5);
            interval.unref();
            const cleanup = (): void => {
              if (cleaned) return;
              cleaned = true;
              clearInterval(interval);
              state.activeDrips -= 1;
              state.closedDrips += 1;
            };
            response.once("close", cleanup);
            response.writeHead(200, {
              "content-type": "application/json; charset=utf-8",
              connection: "close",
            });
            response.write("{");
            return;
          }
          if ((options.chatDelayMs ?? 0) > 0) {
            await new Promise((resolveDelay) => setTimeout(resolveDelay, options.chatDelayMs));
          }
          if (response.destroyed) return;
          sendJson(response, {
            model: OLLAMA_MODEL,
            created_at: "2026-08-10T00:00:00Z",
            message: { role: "assistant", content: EXPECTED_OUTPUT },
            done: true,
            done_reason: "stop",
            total_duration: 100,
            load_duration: 10,
            prompt_eval_count: 20,
            prompt_eval_duration: 30,
            eval_count: 8,
            eval_duration: 40,
          });
          return;
        }
        response.writeHead(404, { connection: "close" });
        response.end();
      } catch (error) {
        state.error = error instanceof Error ? error.message : "unknown fake upstream error";
        response.writeHead(500, { connection: "close" });
        response.end();
      }
    })();
  });
  await new Promise<void>((resolveListen, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(0, "127.0.0.1", () => resolveListen());
  });
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("fake Ollama did not bind TCP");
  return { server, port: address.port, state };
}

function closeServer(server: Server): Promise<void> {
  return new Promise((resolveClose, rejectClose) => {
    server.close((error) => error === undefined ? resolveClose() : rejectClose(error));
  });
}

function serverConnections(server: Server): Promise<number> {
  return new Promise((resolveConnections, rejectConnections) => {
    server.getConnections((error, count) => {
      if (error !== null) rejectConnections(error);
      else resolveConnections(count);
    });
  });
}

async function waitFor(predicate: () => Promise<boolean>, timeoutMs = 500): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!(await predicate())) {
    if (Date.now() >= deadline) throw new Error("timed out waiting for fake upstream cleanup");
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 5));
  }
}

function requestBody(): Record<string, unknown> {
  return {
    model: "local-e2e-model",
    messages: [
      { role: "system", content: SYSTEM_PROMPT },
      {
        role: "user",
        content: `Reply with exactly ${EXPECTED_OUTPUT} and nothing else. Do not call tools.`,
      },
    ],
    stream: true,
    max_tokens: 64,
    tools: EXPECTED_TOOL_NAMES.map((name) => ({
      type: "function",
      function: {
        name,
        description: `Bound fixture definition for ${name}`,
        parameters: { type: "object", properties: {}, additionalProperties: false },
        strict: false,
      },
    })),
  };
}

function piRequest(port: number): { model: Model<"openai-completions">; context: Context } {
  const tools: Tool[] = EXPECTED_TOOL_NAMES.map((name) => ({
    name,
    description: `Bound fixture definition for ${name}`,
    parameters: Type.Object({}, { additionalProperties: false }),
  }));
  return {
    model: {
      id: "local-e2e-model",
      name: "Local E2E model",
      api: "openai-completions",
      provider: "fixture",
      baseUrl: `http://127.0.0.1:${port}/v1`,
      reasoning: false,
      input: ["text"],
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
      contextWindow: 128_000,
      maxTokens: 64,
      compat: {
        supportsStore: false,
        supportsDeveloperRole: false,
        supportsReasoningEffort: false,
        supportsUsageInStreaming: false,
        maxTokensField: "max_tokens",
      },
    },
    context: {
      systemPrompt: SYSTEM_PROMPT,
      messages: [{
        role: "user",
        content: `Reply with exactly ${EXPECTED_OUTPUT} and nothing else. Do not call tools.`,
        timestamp: 1,
      }],
      tools,
    },
  };
}

function sendOpenAiRequest(port: number, encoded: Buffer): Promise<{ status: number; body: string }> {
  return new Promise((resolveResponse, rejectResponse) => {
    const request = httpRequest({
      host: "127.0.0.1",
      port,
      method: "POST",
      path: "/v1/chat/completions",
      headers: {
        host: `127.0.0.1:${port}`,
        authorization: `Bearer ${TOKEN}`,
        "content-type": "application/json",
        "content-length": String(encoded.length),
        connection: "close",
      },
      agent: false,
    }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk: Buffer) => chunks.push(chunk));
      response.on("error", rejectResponse);
      response.on("end", () => resolveResponse({
        status: response.statusCode ?? 0,
        body: Buffer.concat(chunks).toString("utf8"),
      }));
    });
    request.on("error", rejectResponse);
    request.end(encoded);
  });
}

describe("local Ollama OpenAI one-shot bridge fixture", () => {
  let fake: FakeOllama | undefined;

  beforeEach(() => {
    fake = undefined;
  });

  it("switches from the scaled body timeout to a bounded slow-inference phase", async () => {
    // This is the deterministic scaled analogue of a >10 s cold start: the
    // 75 ms inference exceeds the injected 20 ms body window but remains
    // inside the separately bounded 500 ms response phase.
    fake = await startFakeOllama({ chatDelayMs: 75 });
    try {
      const bridge = await startBridgeForTest({
        listenHost: "127.0.0.1",
        listenPort: 0,
        allowedPeer: "127.0.0.1",
        token: TOKEN,
        expectedModel: "local-e2e-model",
        expectedSystemDigest: SYSTEM_DIGEST,
        nonce: NONCE,
        expectedOllamaDigest: OLLAMA_DIGEST,
        upstreamPort: fake.port,
        idleTimeoutMs: 5_000,
        requestTimeoutMs: 20,
        upstreamTimeoutMs: 500,
        responsePhaseTimeoutMs: 500,
      });
      const { model, context } = piRequest(bridge.port);
      let serializedPayloadKeys: string[] = [];
      const response = await completeSimple(model, context, {
        apiKey: TOKEN,
        maxRetries: 0,
        onPayload: (payload) => {
          const serialized = JSON.parse(JSON.stringify(payload)) as unknown;
          if (typeof serialized === "object" && serialized !== null && !Array.isArray(serialized)) {
            serializedPayloadKeys = Object.keys(serialized);
          }
        },
      });
      const completion = await bridge.completion;
      expect(serializedPayloadKeys).toEqual([
        "model",
        "messages",
        "stream",
        "max_tokens",
        "tools",
      ]);
      if (response.stopReason === "error") {
        throw new Error(
          `${response.errorMessage ?? "pinned pi-ai request failed without an error message"}; `
          + `bridge=${completion.code}; keys=${serializedPayloadKeys.join(",")}`,
        );
      }
      expect(response.stopReason).toBe("stop");
      expect(response.content).toEqual([{ type: "text", text: EXPECTED_OUTPUT }]);
      expect(completion).toEqual({ ok: true, code: "completed" });
      expect(fake.state).toEqual({
        tags: 2,
        show: 2,
        chat: 1,
        activeDrips: 0,
        closedDrips: 0,
      });
    } finally {
      fake.server.closeAllConnections();
      if (fake.server.listening) await closeServer(fake.server);
    }
  });

  it("fails closed on an escape-equivalent duplicate JSON key before inference", async () => {
    fake = await startFakeOllama();
    try {
      const bridge = await startBridgeForTest({
        listenHost: "127.0.0.1",
        listenPort: 0,
        allowedPeer: "127.0.0.1",
        token: TOKEN,
        expectedModel: "local-e2e-model",
        expectedSystemDigest: SYSTEM_DIGEST,
        nonce: NONCE,
        expectedOllamaDigest: OLLAMA_DIGEST,
        upstreamPort: fake.port,
        idleTimeoutMs: 5_000,
        upstreamTimeoutMs: 5_000,
      });
      const canonical = JSON.stringify(requestBody());
      const encoded = Buffer.from(canonical.replace(
        /^\{/u,
        '{"\\u006dodel":"local-e2e-model",',
      ), "utf8");
      const response = await sendOpenAiRequest(bridge.port, encoded);
      expect(response.status).toBe(400);
      await expect(bridge.completion).resolves.toMatchObject({ ok: false });
      expect(fake.state).toEqual({
        tags: 1,
        show: 1,
        chat: 0,
        activeDrips: 0,
        closedDrips: 0,
      });
    } finally {
      fake.server.closeAllConnections();
      if (fake.server.listening) await closeServer(fake.server);
    }
  });

  it("cuts off a byte-drip response at the monotonic upstream deadline and cleans handles", async () => {
    // Five-millisecond chunks keep an inactivity timeout alive indefinitely;
    // the independent 60 ms absolute deadline must still terminate it.
    fake = await startFakeOllama({ dripChat: true, dripIntervalMs: 5 });
    try {
      const bridge = await startBridgeForTest({
        listenHost: "127.0.0.1",
        listenPort: 0,
        allowedPeer: "127.0.0.1",
        token: TOKEN,
        expectedModel: "local-e2e-model",
        expectedSystemDigest: SYSTEM_DIGEST,
        nonce: NONCE,
        expectedOllamaDigest: OLLAMA_DIGEST,
        upstreamPort: fake.port,
        idleTimeoutMs: 5_000,
        requestTimeoutMs: 20,
        upstreamTimeoutMs: 60,
        responsePhaseTimeoutMs: 500,
      });
      const { model, context } = piRequest(bridge.port);
      const response = await completeSimple(model, context, { apiKey: TOKEN, maxRetries: 0 });
      const completion = await bridge.completion;
      expect(response.stopReason).toBe("error");
      expect(completion).toEqual({ ok: false, code: "upstream_timeout" });
      await waitFor(async () => fake?.state.activeDrips === 0 && await serverConnections(fake.server) === 0);
      expect(fake.state).toEqual({
        tags: 1,
        show: 1,
        chat: 1,
        activeDrips: 0,
        closedDrips: 1,
      });
    } finally {
      fake.server.closeAllConnections();
      if (fake.server.listening) await closeServer(fake.server);
    }
  });
});
