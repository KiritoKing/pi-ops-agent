import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { InMemoryCredentialStore, type Context } from "@earendil-works/pi-ai";
import { streamSimple } from "@earendil-works/pi-ai/compat";
import {
  defineTool,
  ModelRuntime,
  type ToolDefinition,
} from "@earendil-works/pi-coding-agent";
import { describe, expect, it } from "vitest";
import { applyDeepSeekOpenAICompletionsSourceToolCompatibility } from
  "../../src/agentd/deepseek-tool-schema-compat.js";
import { parseWorkloadDescriptor } from "../../src/shared/workload-runtime.js";

function requestUrl(input: string | URL | Request): string {
  if (typeof input === "string") return input;
  if (input instanceof URL) return input.href;
  return input.url;
}

interface RepositoryWorkloadModule {
  apiVersion: unknown;
  tools: unknown;
}

interface WireFunctionTool {
  type: "function";
  function: {
    name: string;
    description: string;
    parameters: Record<string, unknown>;
    strict: boolean;
  };
}

interface WirePayload {
  tools: WireFunctionTool[];
  [key: string]: unknown;
}

function requireRepositoryWorkloadModule(value: unknown): RepositoryWorkloadModule {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("workload.base module namespace is invalid");
  }
  const workload = (value as { workload?: unknown }).workload;
  if (typeof workload !== "object" || workload === null || Array.isArray(workload)) {
    throw new Error("workload.base export is invalid");
  }
  const candidate = workload as { apiVersion?: unknown; tools?: unknown };
  return { apiVersion: candidate.apiVersion, tools: candidate.tools };
}

async function loadBaseDescriptorTools(): Promise<ToolDefinition[]> {
  const namespace = await import(
    new URL("../../plugins/workload-base/workload.mjs", import.meta.url).href
  ) as unknown;
  const workload = requireRepositoryWorkloadModule(namespace);
  const descriptor = parseWorkloadDescriptor(workload);
  return descriptor.tools.map((tool) => defineTool({
    name: tool.name,
    label: tool.label,
    description: tool.description,
    parameters: tool.parameters,
    executionMode: tool.executionMode,
    async execute() {
      return await Promise.resolve({
        content: [{ type: "text", text: "unused" }],
        details: undefined,
      });
    },
  }));
}

function requireWirePayload(value: unknown): WirePayload {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("captured DeepSeek payload is not an object");
  }
  const tools = (value as { tools?: unknown }).tools;
  if (!Array.isArray(tools) || tools.some((tool) => {
    if (typeof tool !== "object" || tool === null || Array.isArray(tool)) return true;
    const candidate = tool as { type?: unknown; function?: unknown };
    if (candidate.type !== "function" || typeof candidate.function !== "object" ||
        candidate.function === null || Array.isArray(candidate.function)) return true;
    const functionValue = candidate.function as {
      name?: unknown;
      description?: unknown;
      parameters?: unknown;
      strict?: unknown;
    };
    return typeof functionValue.name !== "string" ||
      typeof functionValue.description !== "string" ||
      typeof functionValue.parameters !== "object" || functionValue.parameters === null ||
      Array.isArray(functionValue.parameters) || typeof functionValue.strict !== "boolean";
  })) {
    throw new Error("captured DeepSeek payload tools are invalid");
  }
  return value as WirePayload;
}

function successfulFakeStream(): Response {
  const chunk = {
    id: "fake-deepseek-completion",
    choices: [{
      delta: { content: "ok", role: "assistant" },
      finish_reason: "stop",
      index: 0,
    }],
    created: 1,
    model: "deepseek-v4-flash",
    object: "chat.completion.chunk",
    system_fingerprint: "fake",
  };
  return new Response(
    `data: ${JSON.stringify(chunk)}\n\ndata: [DONE]\n\n`,
    { status: 200, headers: { "content-type": "text/event-stream" } },
  );
}

describe("DeepSeek V4 Flash model configuration", () => {
  it("serializes the pinned Pi SDK request with DeepSeek-compatible reasoning fields", async () => {
    const temporaryRoot = await mkdtemp(join(tmpdir(), "ops-agent-deepseek-model-"));
    try {
      const runtime = await ModelRuntime.create({
        credentials: new InMemoryCredentialStore(),
        modelsPath: join(process.cwd(), "config/models.json"),
        modelsStorePath: join(temporaryRoot, "models-store.json"),
        allowModelNetwork: false,
      });
      const model = runtime.getModel("deepseek", "deepseek-v4-flash");
      expect(model).toBeDefined();
      if (model === undefined || model.api !== "openai-completions") {
        throw new Error("DeepSeek V4 Flash must use the openai-completions API");
      }

      expect(model).toMatchObject({
        contextWindow: 1_000_000,
        maxTokens: 16_384,
        thinkingLevelMap: {
          minimal: "high",
          low: "high",
          medium: "high",
          high: "high",
          xhigh: "max",
          max: "max",
        },
        compat: {
          supportsDeveloperRole: false,
          supportsReasoningEffort: true,
          maxTokensField: "max_tokens",
          requiresAssistantAfterToolResult: true,
          requiresReasoningContentOnAssistantMessages: true,
          thinkingFormat: "deepseek",
        },
      });

      let capturedUrl: string | undefined;
      const capturedPayloads: unknown[] = [];
      let fetchCalls = 0;
      const fakeFetch: typeof fetch = (input, init) => {
        fetchCalls += 1;
        capturedUrl = requestUrl(input);
        if (typeof init?.body !== "string") {
          throw new Error("expected the OpenAI SDK to serialize a string request body");
        }
        capturedPayloads.push(JSON.parse(init.body) as unknown);
        const chunk = {
          id: "fake-deepseek-completion",
          choices: [{
            delta: { content: "ok", role: "assistant" },
            finish_reason: "stop",
            index: 0,
          }],
          created: 1,
          model: "deepseek-v4-flash",
          object: "chat.completion.chunk",
          system_fingerprint: "fake",
        };
        return Promise.resolve(new Response(
          `data: ${JSON.stringify(chunk)}\n\ndata: [DONE]\n\n`,
          { status: 200, headers: { "content-type": "text/event-stream" } },
        ));
      };

      const runStream = async (context: Context): Promise<void> => {
        let completed = false;
        const events = streamSimple(model, context, {
          apiKey: "offline-test-key",
          reasoning: "medium",
          fetch: fakeFetch,
          maxRetries: 0,
          timeoutMs: 1_000,
        });
        for await (const event of events) {
          if (event.type === "error") {
            throw new Error(event.error.errorMessage ?? "offline DeepSeek stream failed");
          }
          if (event.type === "done") completed = true;
        }
        expect(completed).toBe(true);
      };

      const systemPrompt = "Bound offline regression prompt.";
      const firstUserMessage = { role: "user" as const, content: "ping", timestamp: 1 };
      const toolHistory: Context["messages"] = [
        firstUserMessage,
        {
          role: "assistant",
          content: [
            {
              type: "thinking",
              thinking: "bounded reasoning",
              thinkingSignature: "reasoning_content",
            },
            {
              type: "toolCall",
              id: "call-inspect-1",
              name: "inspect_host",
              arguments: { target: "node-1" },
            },
          ],
          api: "openai-completions",
          provider: "deepseek",
          model: "deepseek-v4-flash",
          usage: {
            input: 10,
            output: 5,
            cacheRead: 0,
            cacheWrite: 0,
            totalTokens: 15,
            cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
          },
          stopReason: "toolUse",
          timestamp: 2,
        },
        {
          role: "toolResult",
          toolCallId: "call-inspect-1",
          toolName: "inspect_host",
          content: [{ type: "text", text: "healthy" }],
          isError: false,
          timestamp: 3,
        },
      ];

      await runStream({ systemPrompt, messages: [firstUserMessage] });
      await runStream({ systemPrompt, messages: toolHistory });
      await runStream({
        systemPrompt,
        messages: [...toolHistory, { role: "user", content: "continue", timestamp: 4 }],
      });

      expect(fetchCalls).toBe(3);
      expect(capturedUrl).toBe("https://api.deepseek.com/chat/completions");
      expect(capturedPayloads[0]).toMatchObject({
        model: "deepseek-v4-flash",
        stream: true,
        max_tokens: 16_384,
        thinking: { type: "enabled" },
        reasoning_effort: "high",
      });
      expect(capturedPayloads[0]).not.toHaveProperty("max_completion_tokens");

      expect(capturedPayloads[1]).toMatchObject({
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: "ping" },
          {
            role: "assistant",
            content: "",
            reasoning_content: "bounded reasoning",
            tool_calls: [{
              id: "call-inspect-1",
              type: "function",
              function: { name: "inspect_host", arguments: "{\"target\":\"node-1\"}" },
            }],
          },
          { role: "tool", content: "healthy", tool_call_id: "call-inspect-1" },
        ],
        max_tokens: 16_384,
        thinking: { type: "enabled" },
        reasoning_effort: "high",
      });
      expect(capturedPayloads[1]).not.toHaveProperty("tool_choice");
      expect(capturedPayloads[1]).not.toHaveProperty("max_completion_tokens");

      expect(capturedPayloads[2]).toMatchObject({
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: "ping" },
          { role: "assistant", content: "", reasoning_content: "bounded reasoning" },
          { role: "tool", content: "healthy", tool_call_id: "call-inspect-1" },
          { role: "assistant", content: "I have processed the tool results." },
          { role: "user", content: "continue" },
        ],
      });
    } finally {
      await rm(temporaryRoot, { recursive: true, force: true });
    }
  });

  it("projects only the shipped ops_inspect root type in the pinned wire payload", async () => {
    const temporaryRoot = await mkdtemp(join(tmpdir(), "ops-agent-deepseek-tools-"));
    try {
      const runtime = await ModelRuntime.create({
        credentials: new InMemoryCredentialStore(),
        modelsPath: join(process.cwd(), "config/models.json"),
        modelsStorePath: join(temporaryRoot, "models-store.json"),
        allowModelNetwork: false,
      });
      const model = runtime.getModel("deepseek", "deepseek-v4-flash");
      if (model === undefined || model.api !== "openai-completions") {
        throw new Error("DeepSeek V4 Flash must use the openai-completions API");
      }

      const sourceTools = await loadBaseDescriptorTools();
      const sourceSchemaSnapshot = JSON.stringify(sourceTools.map((tool) => tool.parameters));
      const projectedTools = applyDeepSeekOpenAICompletionsSourceToolCompatibility(
        model,
        sourceTools,
      );
      expect(projectedTools.flatMap((tool, index) =>
        tool === sourceTools[index] ? [] : [tool.name])).toEqual(["ops_inspect"]);
      expect(JSON.stringify(sourceTools.map((tool) => tool.parameters))).toBe(sourceSchemaSnapshot);

      const capturedPayloads: unknown[] = [];
      const fakeFetch: typeof fetch = (_input, init) => {
        if (typeof init?.body !== "string") {
          throw new Error("expected the OpenAI SDK to serialize a string request body");
        }
        capturedPayloads.push(JSON.parse(init.body) as unknown);
        return Promise.resolve(successfulFakeStream());
      };
      const runStream = async (tools: ToolDefinition[]): Promise<void> => {
        const events = streamSimple(model, {
          systemPrompt: "Call ops_inspect with exact bounded input; this is an offline wire test.",
          messages: [{ role: "user", content: "Inspect the target.", timestamp: 1 }],
          tools,
        }, {
          apiKey: "offline-test-key",
          reasoning: "medium",
          fetch: fakeFetch,
          maxRetries: 0,
          timeoutMs: 1_000,
        });
        for await (const event of events) {
          if (event.type === "error") {
            throw new Error(event.error.errorMessage ?? "offline DeepSeek stream failed");
          }
        }
      };

      await runStream(sourceTools);
      await runStream(projectedTools);
      expect(capturedPayloads).toHaveLength(2);
      const baselinePayload = requireWirePayload(capturedPayloads[0]);
      const projectedPayload = requireWirePayload(capturedPayloads[1]);
      expect(baselinePayload.tools.map((tool) => tool.function.name)).toEqual([
        "ops_artifact_catalog",
        "ops_bash",
        "ops_breakglass_prepare",
        "ops_change_status",
        "ops_inspect",
        "ops_machine_describe",
        "ops_machine_list",
        "ops_propose_change",
      ]);
      expect(baselinePayload.tools.every((tool) => !tool.function.strict)).toBe(true);

      const expectedProjectedPayload = structuredClone(baselinePayload);
      const expectedInspect = expectedProjectedPayload.tools.find((tool) =>
        tool.function.name === "ops_inspect");
      if (expectedInspect === undefined) throw new Error("ops_inspect wire tool is missing");
      expect(Object.hasOwn(expectedInspect.function.parameters, "type")).toBe(false);
      expectedInspect.function.parameters = {
        type: "object",
        ...expectedInspect.function.parameters,
      };
      expect(projectedPayload).toEqual(expectedProjectedPayload);
    } finally {
      await rm(temporaryRoot, { recursive: true, force: true });
    }
  });
});
