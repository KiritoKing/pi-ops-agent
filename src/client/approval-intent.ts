import type { ChangeRef } from "../shared/approval.js";
import type { SessionId, TurnId } from "../shared/domain.js";
import { redactText } from "../shared/redaction.js";

export const MAX_BOUND_APPROVAL_INTENT_BYTES = 4096;

export interface ApprovalIntentBinding {
  readonly version: 1;
  readonly sessionId: SessionId;
  readonly turnId: TurnId;
  readonly changeRef: Readonly<ChangeRef>;
  readonly userIntent: string;
}

export type CapturedApprovalIntent =
  | { readonly available: true; readonly userIntent: string }
  | { readonly available: false; readonly reason: string };

function redactSensitiveAssignments(value: string): string {
  return redactText(value)
    .replace(
      /\b(authorization)(\s*[:=]\s*)(?:Bearer\s+)?[^\s,;]+/giu,
      "$1$2[REDACTED]",
    )
    .replace(
      /\b([a-z0-9_-]*(?:password|passwd|token|secret|api[_-]?key|cookie|credential)[a-z0-9_-]*)(["']?\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s,;]+)/giu,
      "$1$2[REDACTED]",
    )
    .replace(/([?&](?:access_token|api[_-]?key|token|secret)=)[^&\s]+/giu, "$1[REDACTED]")
    .replace(/\b([a-z][a-z0-9+.-]*:\/\/)[^\s/@:]+:[^\s/@]+@/giu, "$1[REDACTED]@");
}

export function captureApprovalIntent(value: string): CapturedApprovalIntent {
  const userIntent = redactSensitiveAssignments(value.trim());
  const bytes = Buffer.from(userIntent, "utf8");
  if (userIntent.length === 0) {
    return { available: false, reason: "the originating user input was empty" };
  }
  if (bytes.toString("utf8") !== userIntent) {
    return { available: false, reason: "the originating user input was not valid UTF-8" };
  }
  if (bytes.length > MAX_BOUND_APPROVAL_INTENT_BYTES) {
    return {
      available: false,
      reason: `the originating user input exceeded ${MAX_BOUND_APPROVAL_INTENT_BYTES} bytes`,
    };
  }
  return { available: true, userIntent };
}
