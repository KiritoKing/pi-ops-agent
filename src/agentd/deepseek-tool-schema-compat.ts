import type { ToolDefinition } from "@earendil-works/pi-coding-agent";

interface ModelProtocol {
  provider: string;
  api: string;
}

type ToolParameters = ToolDefinition["parameters"];

function isPlainJsonObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as unknown;
  if (prototype !== Object.prototype && prototype !== null) return false;
  return Reflect.ownKeys(value).every((key) =>
    typeof key === "string" && Object.prototype.propertyIsEnumerable.call(value, key));
}

function withRedundantRootObjectType(parameters: ToolParameters): ToolParameters {
  if (!isPlainJsonObject(parameters) || Object.hasOwn(parameters, "type")) return parameters;
  const anyOf = parameters.anyOf;
  if (!Array.isArray(anyOf) || anyOf.length === 0 || !anyOf.every((arm) =>
    isPlainJsonObject(arm) && Object.hasOwn(arm, "type") && arm.type === "object")) {
    return parameters;
  }
  return { type: "object", ...parameters };
}

/**
 * DeepSeek's OpenAI-compatible endpoint requires an explicit object root on
 * function schemas. Source Workload descriptors remain authoritative: this
 * only supplies an equivalent model-visible root constraint for object-only
 * unions, while each tool's execute closure retains the original schema.
 */
export function applyDeepSeekOpenAICompletionsSourceToolCompatibility(
  model: Readonly<ModelProtocol>,
  sourceTools: ToolDefinition[],
): ToolDefinition[] {
  if (model.provider !== "deepseek" || model.api !== "openai-completions") {
    return sourceTools;
  }
  const compatible = sourceTools.map((tool) => {
    const parameters = withRedundantRootObjectType(tool.parameters);
    if (parameters === tool.parameters) return tool;
    return { ...tool, parameters };
  });
  return compatible.some((tool, index) => tool !== sourceTools[index]) ? compatible : sourceTools;
}
