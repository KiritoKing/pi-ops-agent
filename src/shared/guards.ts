export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (!isRecord(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value;
}

export function requireString(
  value: unknown,
  label: string,
  options: { min?: number; max?: number; pattern?: RegExp } = {},
): string {
  if (typeof value !== "string") {
    throw new Error(`${label} must be a string`);
  }
  const min = options.min ?? 1;
  const max = options.max ?? 4096;
  if (value.length < min || value.length > max) {
    throw new Error(`${label} length must be between ${min} and ${max}`);
  }
  if (options.pattern && !options.pattern.test(value)) {
    throw new Error(`${label} has an invalid format`);
  }
  return value;
}

export function optionalString(
  value: unknown,
  label: string,
  options: { max?: number; pattern?: RegExp } = {},
): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  return requireString(value, label, { min: 0, ...options });
}

export function requireInteger(
  value: unknown,
  label: string,
  minimum: number,
  maximum: number,
): number {
  if (!Number.isInteger(value) || typeof value !== "number") {
    throw new Error(`${label} must be an integer`);
  }
  if (value < minimum || value > maximum) {
    throw new Error(`${label} must be between ${minimum} and ${maximum}`);
  }
  return value;
}

export function requireStringArray(
  value: unknown,
  label: string,
  maximumItems = 64,
): string[] {
  if (!Array.isArray(value) || value.length > maximumItems) {
    throw new Error(`${label} must be an array with at most ${maximumItems} items`);
  }
  return value.map((item, index) =>
    requireString(item, `${label}[${index}]`, { max: 4096 }),
  );
}
