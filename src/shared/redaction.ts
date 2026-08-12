import { isRecord } from "./guards.js";

const SECRET_KEY = /(?:api[_-]?key|secret|token|password|credential|authorization|cookie)/i;
// Bearer credentials are secret regardless of apparent length. Short values
// are common in tests, local gateways, and opaque schemes; applying a length
// threshold can also let assignment redaction consume only the word
// "Bearer" and leave the credential behind.
const SECRET_VALUE = /\b(?:sk-[a-zA-Z0-9_-]{16,}|Bearer\s+[a-zA-Z0-9._~+/-]+={0,2})\b/gi;
const SECRET_ASSIGNMENT = /(\b[a-z0-9_.-]*(?:api[_-]?key|secret|token|password|credential|authorization|cookie)[a-z0-9_.-]*\b["']?\s*[:=]\s*)("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|Bearer\s+[a-zA-Z0-9._~+/-]+={0,2}|[^\s\r\n,;{}[\]]+)/gi;

export function redactText(value: string): string {
  return value
    .replace(
      SECRET_ASSIGNMENT,
      (_match, prefix: string, secret: string) => {
        if (secret.startsWith("\"") && secret.endsWith("\"")) {
          return `${prefix}"[REDACTED]"`;
        }
        if (secret.startsWith("'") && secret.endsWith("'")) {
          return `${prefix}'[REDACTED]'`;
        }
        return `${prefix}[REDACTED]`;
      },
    )
    .replace(SECRET_VALUE, "[REDACTED]");
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
