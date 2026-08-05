import { isRecord } from "./guards.js";

const SECRET_KEY = /(?:api[_-]?key|secret|token|password|credential|authorization|cookie)/i;
const SECRET_VALUE = /\b(?:sk-[a-zA-Z0-9_-]{16,}|Bearer\s+[a-zA-Z0-9._~-]{16,})\b/gi;

export function redactText(value: string): string {
  return value.replace(SECRET_VALUE, "[REDACTED]");
}

export function redact(value: unknown, depth = 0): unknown {
  if (depth > 12) {
    return "[TRUNCATED]";
  }
  if (typeof value === "string") {
    return redactText(value);
  }
  if (Array.isArray(value)) {
    return value.slice(0, 256).map((item) => redact(item, depth + 1));
  }
  if (!isRecord(value)) {
    return value;
  }
  return Object.fromEntries(
    Object.entries(value).map(([key, item]) => [
      key,
      SECRET_KEY.test(key) ? "[REDACTED]" : redact(item, depth + 1),
    ]),
  );
}
