import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { InMemoryCredentialStore, type Context } from "@earendil-works/pi-ai";
import { streamSimple } from "@earendil-works/pi-ai/compat";
import { ModelRuntime } from "@earendil-works/pi-coding-agent";
import { describe, expect, it } from "vitest";

function requestUrl(input: string | URL | Request): string {
  if (typeof input === "string") return input;
  if (input instanceof URL) return input.href;
  return input.url;
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
});
