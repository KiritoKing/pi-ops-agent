import { requireRecord } from "./guards.js";

export function requireExactRecord(
  value: unknown,
  label: string,
  allowedFields: readonly string[],
): Record<string, unknown> {
  const input = requireRecord(value, label);
  const allowed = new Set(allowedFields);
  for (const field of Object.keys(input)) {
    if (!allowed.has(field)) throw new Error(`${label}.${field} is not supported`);
  }
  return input;
}
