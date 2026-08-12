import { defineTool, type ToolDefinition } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { Check } from "typebox/value";
import { describe, expect, it } from "vitest";
import { applyDeepSeekOpenAICompletionsSourceToolCompatibility } from
  "../../src/agentd/deepseek-tool-schema-compat.js";
import { parseWorkloadSchema } from "../../src/shared/workload-runtime.js";

const deepSeekModel = Object.freeze({
  provider: "deepseek",
  api: "openai-completions",
});

function objectArm(kind: string): Record<string, unknown> {
  return {
    type: "object",
    properties: {
      kind: { type: "string", const: kind },
      value: { type: "string", minLength: 1, maxLength: 32 },
    },
    required: ["kind", "value"],
    additionalProperties: false,
  };
}

function objectUnionParameters(): ToolDefinition["parameters"] {
  return parseWorkloadSchema({ anyOf: [objectArm("one"), objectArm("two")] });
}

function testTool(parameters: ToolDefinition["parameters"]): ToolDefinition {
  return defineTool({
    name: "ops_compat_test",
    label: "Compatibility test",
    description: "Exercise the model-visible Source Workload schema projection.",
    parameters,
    executionMode: "parallel",
    async execute(_toolCallId, params) {
      if (!Check(parameters, params)) throw new Error("original source schema rejected input");
      return await Promise.resolve({
        content: [{ type: "text", text: "ok" }],
        details: undefined,
      });
    },
  });
}

describe("DeepSeek Source Workload tool schema compatibility", () => {
  it("adds only a redundant object root to a non-empty object-only union", async () => {
    const parameters = objectUnionParameters();
    const originalJson = JSON.stringify(parameters);
    const originalAnyOf = (parameters as { anyOf: unknown }).anyOf;
    const tool = testTool(parameters);
    const sourceTools = [tool];

    const compatible = applyDeepSeekOpenAICompletionsSourceToolCompatibility(
      deepSeekModel,
      sourceTools,
    );
    const projectedTool = compatible[0];
    expect(projectedTool).toBeDefined();
    if (projectedTool === undefined) throw new Error("projected tool is missing");

    expect(compatible).not.toBe(sourceTools);
    expect(projectedTool).not.toBe(tool);
    expect(Object.getOwnPropertyDescriptor(projectedTool, "execute")?.value)
      .toBe(Object.getOwnPropertyDescriptor(tool, "execute")?.value);
    expect(projectedTool.parameters).not.toBe(parameters);
    expect(Object.keys(projectedTool.parameters)).toEqual(["type", "anyOf"]);
    expect(projectedTool.parameters).toMatchObject({ type: "object" });
    expect((projectedTool.parameters as { anyOf: unknown }).anyOf).toBe(originalAnyOf);
    expect(Object.hasOwn(parameters, "type")).toBe(false);
    expect(JSON.stringify(parameters)).toBe(originalJson);
    expect(Check(projectedTool.parameters, { kind: "one", value: "ok" })).toBe(true);
    expect(Check(projectedTool.parameters, { kind: "three", value: "ok" })).toBe(false);

    await expect(projectedTool.execute(
      "call-invalid",
      { kind: "three", value: "ok" },
      undefined,
      undefined,
      undefined as never,
    )).rejects.toThrow("original source schema rejected input");
  });

  it("is scoped to the DeepSeek OpenAI-completions model protocol", () => {
    const cases = [
      { provider: "deepseek", api: "openai-responses" },
      { provider: "openai", api: "openai-completions" },
      { provider: "deepseek-proxy", api: "openai-completions" },
    ];
    for (const model of cases) {
      const tool = testTool(objectUnionParameters());
      const sourceTools = [tool];
      expect(applyDeepSeekOpenAICompletionsSourceToolCompatibility(model, sourceTools)).toBe(
        sourceTools,
      );
      expect(Object.hasOwn(tool.parameters, "type")).toBe(false);
    }
  });

  it("leaves ineligible or non-plain schemas unchanged", () => {
    const eligibleArm = objectArm("one");
    const typeBoxUnion = Type.Union([
      Type.Object({ kind: Type.Literal("one") }, { additionalProperties: false }),
      Type.Object({ kind: Type.Literal("two") }, { additionalProperties: false }),
    ]);
    const cases: Array<{ label: string; parameters: ToolDefinition["parameters"] }> = [
      { label: "no anyOf", parameters: { type: "object", properties: {} } },
      { label: "existing root type", parameters: { type: "object", anyOf: [eligibleArm] } },
      { label: "empty anyOf", parameters: { anyOf: [] } },
      { label: "non-array anyOf", parameters: { anyOf: {} } },
      { label: "null arm", parameters: { anyOf: [eligibleArm, null] } },
      { label: "array arm", parameters: { anyOf: [eligibleArm, []] } },
      { label: "missing arm type", parameters: { anyOf: [eligibleArm, { properties: {} }] } },
      { label: "non-object arm", parameters: { anyOf: [eligibleArm, { type: "string" }] } },
      { label: "TypeBox metadata", parameters: typeBoxUnion },
    ];

    for (const entry of cases) {
      const tool = testTool(entry.parameters);
      const sourceTools = [tool];
      const compatible = applyDeepSeekOpenAICompletionsSourceToolCompatibility(
        deepSeekModel,
        sourceTools,
      );
      expect(compatible, entry.label).toBe(sourceTools);
      expect(compatible[0], entry.label).toBe(tool);
      expect(tool.parameters, entry.label).toBe(entry.parameters);
    }
  });
});
