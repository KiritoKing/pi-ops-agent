import type { TSchema } from "typebox";
import {
  requireInteger,
  requireRecord,
  requireString,
  requireStringArray,
  type JsonValue,
} from "./guards.js";
import { requireExactRecord } from "./strict.js";

export const WORKLOAD_ABI_VERSION = "agentd.workload/v1" as const;
export const WORKLOAD_HOST_PROTOCOL_VERSION = 1 as const;
export const MAX_WORKLOAD_FRAME_BYTES = 256 * 1024;
export const MAX_WORKLOAD_TOTAL_OUTPUT_BYTES = 1024 * 1024;
export const MAX_WORKLOAD_PROVIDER_CALLS = 32;

const NAME_PATTERN = /^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*$/u;
const TOOL_NAME_PATTERN = /^ops_[a-z][a-z0-9_]{2,63}$/u;
const PROPERTY_NAME_PATTERN = /^[A-Za-z][A-Za-z0-9_]{0,63}$/u;
const MAX_SAFE_WORKLOAD_PATTERN_LENGTH = 512;

// Source plugins are untrusted, so their model-visible JSON Schema cannot feed
// an arbitrary JavaScript regular expression into TypeBox. This deliberately
// tiny grammar accepts only anchored concatenations of literals, character
// classes, and one bounded repetition. It is sufficient for unit, account,
// path, and identifier profiles while excluding alternation, groups,
// look-around, backreferences, and unbounded/nested quantifiers.
function requireSafeWorkloadPattern(value: unknown, label: string, maximumInput: unknown): string {
  const pattern = requireString(value, label, {
    min: 3,
    max: MAX_SAFE_WORKLOAD_PATTERN_LENGTH,
  });
  if (!pattern.startsWith("^") || !pattern.endsWith("$")
    || typeof maximumInput !== "number" || !Number.isInteger(maximumInput)
    || maximumInput < 1 || maximumInput > 4096) {
    throw new Error(`${label} requires anchors and a maxLength between 1 and 4096`);
  }
  let index = 1;
  let boundedRanges = 0;
  while (index < pattern.length - 1) {
    const character = pattern[index];
    if (character === "\\") {
      const escaped = pattern[index + 1];
      if (escaped === undefined || !"\\./:_@-".includes(escaped)) {
        throw new Error(`${label} contains an unsupported escape`);
      }
      index += 2;
    } else if (character === "[") {
      const close = pattern.indexOf("]", index + 1);
      if (close < 0) throw new Error(`${label} contains an unterminated character class`);
      const contents = pattern.slice(index + 1, close);
      if (contents.length < 1 || contents.length > 128
        || !/^[A-Za-z0-9._:/@-]+$/u.test(contents)) {
        throw new Error(`${label} contains an unsupported character class`);
      }
      index = close + 1;
    } else {
      if (character === undefined || !/^[A-Za-z0-9_:/@-]$/u.test(character)) {
        throw new Error(`${label} contains an unsupported regular-expression construct`);
      }
      index += 1;
    }
    if (pattern[index] === "{") {
      const close = pattern.indexOf("}", index + 1);
      if (close < 0) throw new Error(`${label} contains an unterminated bounded repetition`);
      const repetition = /^(\d{1,4})(?:,(\d{1,4}))?$/u.exec(pattern.slice(index + 1, close));
      if (repetition === null) throw new Error(`${label} contains an invalid bounded repetition`);
      const minimum = Number(repetition[1]);
      const maximum = Number(repetition[2] ?? repetition[1]);
      if (minimum > maximum || maximum > 4096) {
        throw new Error(`${label} contains an excessive bounded repetition`);
      }
      boundedRanges += minimum === maximum ? 0 : 1;
      if (boundedRanges > 1) {
        throw new Error(`${label} contains more than one variable bounded repetition`);
      }
      index = close + 1;
    }
  }
  try {
    new RegExp(pattern, "u");
  } catch {
    throw new Error(`${label} is not a valid safe regular expression`);
  }
  return pattern;
}

export interface WorkloadToolDescriptor {
  name: string;
  label: string;
  description: string;
  capability: string;
  parameters: TSchema;
  providers: readonly string[];
  executionMode: "parallel" | "sequential";
}

export interface WorkloadDescriptor {
  apiVersion: typeof WORKLOAD_ABI_VERSION;
  tools: readonly WorkloadToolDescriptor[];
}

export interface WorkloadToolResult {
  content: Array<{ type: "text"; text: string }>;
  details?: JsonValue;
}

export type WorkloadHostRequest =
  | {
      version: 1;
      type: "describe";
      invocationId: string;
      entrypoint: string;
    }
  | {
      version: 1;
      type: "invoke";
      invocationId: string;
      entrypoint: string;
      tool: string;
      input: JsonValue;
    }
  | {
      version: 1;
      type: "provider.response";
      invocationId: string;
      requestId: string;
      ok: boolean;
      result?: JsonValue;
      error?: string;
    };

export type WorkloadHostMessage =
  | {
      version: 1;
      type: "descriptor";
      invocationId: string;
      descriptor: WorkloadDescriptor;
    }
  | {
      version: 1;
      type: "provider.request";
      invocationId: string;
      requestId: string;
      provider: string;
      input: JsonValue;
    }
  | {
      version: 1;
      type: "result";
      invocationId: string;
      result: WorkloadToolResult;
    }
  | {
      version: 1;
      type: "error";
      invocationId: string;
      error: string;
    };

interface JsonScanner {
  text: string;
  offset: number;
}

function skipWhitespace(scanner: JsonScanner): void {
  while (/\s/u.test(scanner.text[scanner.offset] ?? "")) scanner.offset += 1;
}

function scanString(scanner: JsonScanner): string {
  const start = scanner.offset;
  if (scanner.text[scanner.offset] !== '"') throw new Error("JSON string is missing an opening quote");
  scanner.offset += 1;
  while (scanner.offset < scanner.text.length) {
    const character = scanner.text[scanner.offset];
    if (character === '"') {
      scanner.offset += 1;
      return JSON.parse(scanner.text.slice(start, scanner.offset)) as string;
    }
    if (character === undefined || character.charCodeAt(0) < 0x20) {
      throw new Error("JSON string contains an invalid control character");
    }
    if (character !== "\\") {
      scanner.offset += 1;
      continue;
    }
    scanner.offset += 1;
    const escaped = scanner.text[scanner.offset];
    if (escaped === "u") {
      const digits = scanner.text.slice(scanner.offset + 1, scanner.offset + 5);
      if (!/^[a-fA-F0-9]{4}$/u.test(digits)) throw new Error("JSON string has an invalid unicode escape");
      scanner.offset += 5;
      continue;
    }
    if (escaped === undefined || !/^["\\/bfnrt]$/u.test(escaped)) {
      throw new Error("JSON string has an invalid escape");
    }
    scanner.offset += 1;
  }
  throw new Error("JSON string is unterminated");
}

function scanValue(scanner: JsonScanner, depth: number): void {
  if (depth > 64) throw new Error("JSON value exceeds the maximum nesting depth");
  skipWhitespace(scanner);
  const character = scanner.text[scanner.offset];
  if (character === '"') {
    scanString(scanner);
    return;
  }
  if (character === "{") {
    scanner.offset += 1;
    skipWhitespace(scanner);
    const keys = new Set<string>();
    if (scanner.text[scanner.offset] === "}") {
      scanner.offset += 1;
      return;
    }
    for (;;) {
      skipWhitespace(scanner);
      const key = scanString(scanner);
      if (keys.has(key)) throw new Error(`JSON object contains duplicate field ${JSON.stringify(key)}`);
      keys.add(key);
      skipWhitespace(scanner);
      if (scanner.text[scanner.offset] !== ":") throw new Error("JSON object field is missing a colon");
      scanner.offset += 1;
      scanValue(scanner, depth + 1);
      skipWhitespace(scanner);
      const delimiter = scanner.text[scanner.offset];
      if (delimiter === "}") {
        scanner.offset += 1;
        return;
      }
      if (delimiter !== ",") throw new Error("JSON object is missing a comma or closing brace");
      scanner.offset += 1;
    }
  }
  if (character === "[") {
    scanner.offset += 1;
    skipWhitespace(scanner);
    if (scanner.text[scanner.offset] === "]") {
      scanner.offset += 1;
      return;
    }
    for (;;) {
      scanValue(scanner, depth + 1);
      skipWhitespace(scanner);
      const delimiter = scanner.text[scanner.offset];
      if (delimiter === "]") {
        scanner.offset += 1;
        return;
      }
      if (delimiter !== ",") throw new Error("JSON array is missing a comma or closing bracket");
      scanner.offset += 1;
    }
  }
  const remainder = scanner.text.slice(scanner.offset);
  const token = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/u.exec(remainder)?.[0];
  if (token === undefined) throw new Error("JSON contains an invalid value");
  scanner.offset += token.length;
}

export function parseStrictJson(text: string, maximumBytes = MAX_WORKLOAD_FRAME_BYTES): unknown {
  if (Buffer.byteLength(text, "utf8") === 0 || Buffer.byteLength(text, "utf8") > maximumBytes) {
    throw new Error("JSON payload is empty or exceeds its size limit");
  }
  const scanner: JsonScanner = { text, offset: 0 };
  scanValue(scanner, 0);
  skipWhitespace(scanner);
  if (scanner.offset !== text.length) throw new Error("JSON payload has a trailing value");
  return JSON.parse(text) as unknown;
}

export function requireBoundedJson(
  value: unknown,
  label: string,
  maximumBytes = MAX_WORKLOAD_FRAME_BYTES,
): JsonValue {
  let encoded: unknown;
  try {
    encoded = JSON.stringify(value);
  } catch {
    throw new Error(`${label} must be JSON serializable`);
  }
  if (typeof encoded !== "string" || Buffer.byteLength(encoded, "utf8") > maximumBytes) {
    throw new Error(`${label} exceeds its JSON size limit`);
  }
  return parseStrictJson(encoded, maximumBytes) as JsonValue;
}

interface SchemaState {
  nodes: number;
}

function parseSchemaNode(value: unknown, label: string, depth: number, state: SchemaState): Record<string, unknown> {
  if (depth > 10) throw new Error(`${label} exceeds the maximum schema depth`);
  state.nodes += 1;
  if (state.nodes > 256) throw new Error(`${label} contains too many schema nodes`);
  const input = requireExactRecord(value, label, [
    "type", "properties", "required", "additionalProperties", "items", "anyOf",
    "minLength", "maxLength", "minimum", "maximum", "minItems", "maxItems",
    "uniqueItems", "minProperties", "maxProperties", "enum", "const", "description", "pattern",
  ]);
  if (input.description !== undefined) {
    requireString(input.description, `${label}.description`, { max: 1024 });
  }
  if (input.anyOf !== undefined) {
    if (Object.keys(input).some((key) => key !== "anyOf" && key !== "description")) {
      throw new Error(`${label}.anyOf cannot be combined with other schema constraints`);
    }
    if (!Array.isArray(input.anyOf) || input.anyOf.length < 1 || input.anyOf.length > 16) {
      throw new Error(`${label}.anyOf must contain between 1 and 16 schemas`);
    }
    return {
      ...(input.description === undefined ? {} : { description: input.description }),
      anyOf: input.anyOf.map((item, index) =>
        parseSchemaNode(item, `${label}.anyOf[${index}]`, depth + 1, state)),
    };
  }
  const type = requireString(input.type, `${label}.type`, { max: 16 });
  if (!["object", "array", "string", "number", "integer", "boolean", "null"].includes(type)) {
    throw new Error(`${label}.type is not supported`);
  }
  const typeFields: Record<string, readonly string[]> = {
    object: ["properties", "required", "additionalProperties", "minProperties", "maxProperties"],
    array: ["items", "minItems", "maxItems", "uniqueItems"],
    string: ["minLength", "maxLength", "pattern"],
    number: ["minimum", "maximum"],
    integer: ["minimum", "maximum"],
    boolean: [],
    null: [],
  };
  const allowedForType = new Set(["type", "description", "enum", "const", ...(typeFields[type] ?? [])]);
  for (const field of Object.keys(input)) {
    if (!allowedForType.has(field)) throw new Error(`${label}.${field} is not valid for type ${type}`);
  }
  const output: Record<string, unknown> = {
    type,
    ...(input.description === undefined ? {} : { description: input.description }),
  };
  const addInteger = (field: string, minimum: number, maximum: number): void => {
    if (input[field] !== undefined) {
      output[field] = requireInteger(input[field], `${label}.${field}`, minimum, maximum);
    }
  };
  switch (type) {
    case "object": {
      if (input.additionalProperties !== false) {
        throw new Error(`${label}.additionalProperties must be false`);
      }
      const properties = requireRecord(input.properties, `${label}.properties`);
      const propertyNames = Object.keys(properties);
      if (propertyNames.length > 64 || propertyNames.some((name) => !PROPERTY_NAME_PATTERN.test(name))) {
        throw new Error(`${label}.properties contains an invalid or excessive property name`);
      }
      const required = input.required === undefined
        ? []
        : requireStringArray(input.required, `${label}.required`, 64);
      if (new Set(required).size !== required.length || required.some((name) => !propertyNames.includes(name))) {
        throw new Error(`${label}.required must contain unique declared properties`);
      }
      output.properties = Object.fromEntries(propertyNames.map((name) => [
        name,
        parseSchemaNode(properties[name], `${label}.properties.${name}`, depth + 1, state),
      ]));
      output.required = required;
      output.additionalProperties = false;
      addInteger("minProperties", 0, 64);
      addInteger("maxProperties", 0, 64);
      if (typeof output.minProperties === "number" && typeof output.maxProperties === "number" &&
          output.minProperties > output.maxProperties) {
        throw new Error(`${label} has minProperties greater than maxProperties`);
      }
      break;
    }
    case "array":
      output.items = parseSchemaNode(input.items, `${label}.items`, depth + 1, state);
      addInteger("minItems", 0, 256);
      addInteger("maxItems", 0, 256);
      if (input.uniqueItems !== undefined) {
        if (typeof input.uniqueItems !== "boolean") throw new Error(`${label}.uniqueItems must be boolean`);
        output.uniqueItems = input.uniqueItems;
      }
      if (typeof output.minItems === "number" && typeof output.maxItems === "number" &&
          output.minItems > output.maxItems) {
        throw new Error(`${label} has minItems greater than maxItems`);
      }
      break;
    case "string":
      addInteger("minLength", 0, 128 * 1024);
      addInteger("maxLength", 0, 128 * 1024);
      if (typeof output.minLength === "number" && typeof output.maxLength === "number" &&
          output.minLength > output.maxLength) {
        throw new Error(`${label} has minLength greater than maxLength`);
      }
      if (input.pattern !== undefined) {
        output.pattern = requireSafeWorkloadPattern(
          input.pattern,
          `${label}.pattern`,
          output.maxLength,
        );
      }
      break;
    case "integer":
    case "number":
      if (input.minimum !== undefined) {
        if (typeof input.minimum !== "number" || !Number.isFinite(input.minimum)) {
          throw new Error(`${label}.minimum must be finite`);
        }
        output.minimum = input.minimum;
      }
      if (input.maximum !== undefined) {
        if (typeof input.maximum !== "number" || !Number.isFinite(input.maximum)) {
          throw new Error(`${label}.maximum must be finite`);
        }
        output.maximum = input.maximum;
      }
      if (typeof output.minimum === "number" && typeof output.maximum === "number" &&
          output.minimum > output.maximum) {
        throw new Error(`${label} has minimum greater than maximum`);
      }
      break;
    case "boolean":
    case "null":
      break;
  }
  if (input.enum !== undefined) {
    if (!Array.isArray(input.enum) || input.enum.length < 1 || input.enum.length > 64) {
      throw new Error(`${label}.enum must contain between 1 and 64 values`);
    }
    output.enum = input.enum.map((item, index) =>
      requireBoundedJson(item, `${label}.enum[${index}]`, 4096));
  }
  if (input.const !== undefined) output.const = requireBoundedJson(input.const, `${label}.const`, 4096);
  return output;
}

export function parseWorkloadSchema(value: unknown, label = "workload schema"): TSchema {
  requireBoundedJson(value, label, 64 * 1024);
  const parsed = parseSchemaNode(value, label, 0, { nodes: 0 });
  const rootUnion = parsed.anyOf;
  if (parsed.type !== "object" && (!Array.isArray(rootUnion) || rootUnion.some((item) =>
    typeof item !== "object" || item === null || (item as Record<string, unknown>).type !== "object"))) {
    throw new Error(`${label} root must be an object or an object union`);
  }
  return parsed;
}

export function parseWorkloadDescriptor(value: unknown): WorkloadDescriptor {
  requireBoundedJson(value, "workload descriptor", 128 * 1024);
  const input = requireExactRecord(value, "workload descriptor", ["apiVersion", "tools"]);
  if (input.apiVersion !== WORKLOAD_ABI_VERSION) {
    throw new Error("workload descriptor has an unsupported ABI version");
  }
  if (!Array.isArray(input.tools) || input.tools.length < 1 || input.tools.length > 32) {
    throw new Error("workload descriptor must contain between 1 and 32 tools");
  }
  const names = new Set<string>();
  const capabilities = new Set<string>();
  const tools = input.tools.map((item, index): WorkloadToolDescriptor => {
    const tool = requireExactRecord(item, `workload descriptor.tools[${index}]`, [
      "name", "label", "description", "capability", "parameters", "providers", "executionMode",
    ]);
    const name = requireString(tool.name, `workload descriptor.tools[${index}].name`, {
      max: 68,
      pattern: TOOL_NAME_PATTERN,
    });
    const capability = requireString(tool.capability, `workload descriptor.tools[${index}].capability`, {
      max: 128,
      pattern: NAME_PATTERN,
    });
    if (names.has(name)) throw new Error(`workload descriptor contains duplicate tool ${name}`);
    if (capabilities.has(capability)) {
      throw new Error(`workload descriptor contains duplicate capability ${capability}`);
    }
    names.add(name);
    capabilities.add(capability);
    const providers = requireStringArray(
      tool.providers,
      `workload descriptor.tools[${index}].providers`,
      16,
    );
    if (providers.some((provider) => !NAME_PATTERN.test(provider)) ||
        providers.some((provider, providerIndex) => providerIndex > 0 &&
          (providers[providerIndex - 1] ?? "") >= provider)) {
      throw new Error(`workload descriptor.tools[${index}].providers must be sorted and unique`);
    }
    const executionMode = tool.executionMode === "sequential" ? "sequential"
      : tool.executionMode === "parallel" ? "parallel"
        : undefined;
    if (executionMode === undefined) {
      throw new Error(`workload descriptor.tools[${index}].executionMode is unsupported`);
    }
    return {
      name,
      label: requireString(tool.label, `workload descriptor.tools[${index}].label`, { max: 96 }),
      description: requireString(tool.description, `workload descriptor.tools[${index}].description`, {
        max: 2048,
      }),
      capability,
      parameters: parseWorkloadSchema(
        tool.parameters,
        `workload descriptor.tools[${index}].parameters`,
      ),
      providers,
      executionMode,
    };
  });
  if (tools.some((tool, index) => index > 0 && (tools[index - 1]?.name ?? "") >= tool.name)) {
    throw new Error("workload descriptor tools must be sorted by name");
  }
  return { apiVersion: WORKLOAD_ABI_VERSION, tools };
}

export function parseWorkloadToolResult(value: unknown): WorkloadToolResult {
  requireBoundedJson(value, "workload result", MAX_WORKLOAD_FRAME_BYTES);
  const input = requireExactRecord(value, "workload result", ["content", "details"]);
  if (!Array.isArray(input.content) || input.content.length < 1 || input.content.length > 8) {
    throw new Error("workload result content must contain between 1 and 8 items");
  }
  let totalTextBytes = 0;
  const content = input.content.map((item, index) => {
    const block = requireExactRecord(item, `workload result.content[${index}]`, ["type", "text"]);
    if (block.type !== "text") throw new Error("workload result supports text content only");
    const text = requireString(block.text, `workload result.content[${index}].text`, {
      min: 0,
      max: 128 * 1024,
    });
    totalTextBytes += Buffer.byteLength(text, "utf8");
    return { type: "text" as const, text };
  });
  if (totalTextBytes > 128 * 1024) throw new Error("workload result text exceeds its total size limit");
  const details = input.details === undefined
    ? undefined
    : requireBoundedJson(input.details, "workload result.details", 96 * 1024);
  return { content, ...(details === undefined ? {} : { details }) };
}

export function parseWorkloadHostMessage(value: unknown): WorkloadHostMessage {
  const base = requireExactRecord(value, "workload host message", [
    "version", "type", "invocationId", "descriptor", "requestId", "provider", "input", "result", "error",
  ]);
  if (base.version !== WORKLOAD_HOST_PROTOCOL_VERSION) {
    throw new Error("workload host message has an unsupported protocol version");
  }
  const invocationId = requireString(base.invocationId, "workload host message.invocationId", {
    max: 128,
    pattern: /^[a-zA-Z0-9][a-zA-Z0-9._:-]{7,127}$/u,
  });
  switch (base.type) {
    case "descriptor":
      requireExactRecord(value, "workload descriptor message", [
        "version", "type", "invocationId", "descriptor",
      ]);
      return { version: 1, type: "descriptor", invocationId, descriptor: parseWorkloadDescriptor(base.descriptor) };
    case "provider.request":
      requireExactRecord(value, "workload provider request", [
        "version", "type", "invocationId", "requestId", "provider", "input",
      ]);
      return {
        version: 1,
        type: "provider.request",
        invocationId,
        requestId: requireString(base.requestId, "workload provider request.requestId", {
          max: 128,
          pattern: /^[a-zA-Z0-9][a-zA-Z0-9._:-]{7,127}$/u,
        }),
        provider: requireString(base.provider, "workload provider request.provider", {
          max: 128,
          pattern: NAME_PATTERN,
        }),
        input: requireBoundedJson(base.input, "workload provider request.input", 128 * 1024),
      };
    case "result":
      requireExactRecord(value, "workload result message", ["version", "type", "invocationId", "result"]);
      return { version: 1, type: "result", invocationId, result: parseWorkloadToolResult(base.result) };
    case "error":
      requireExactRecord(value, "workload error message", ["version", "type", "invocationId", "error"]);
      return {
        version: 1,
        type: "error",
        invocationId,
        error: requireString(base.error, "workload error message.error", { max: 2048 }),
      };
    default:
      throw new Error("workload host message type is unsupported");
  }
}

export function encodeWorkloadFrame(value: unknown): Buffer {
  const payload = Buffer.from(JSON.stringify(requireBoundedJson(value, "workload frame")), "utf8");
  if (payload.length > MAX_WORKLOAD_FRAME_BYTES) throw new Error("workload frame exceeds its size limit");
  const frame = Buffer.allocUnsafe(payload.length + 4);
  frame.writeUInt32BE(payload.length, 0);
  payload.copy(frame, 4);
  return frame;
}
