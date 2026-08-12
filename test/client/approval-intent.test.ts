import { describe, expect, it } from "vitest";
import {
  captureApprovalIntent,
  MAX_BOUND_APPROVAL_INTENT_BYTES,
} from "../../src/client/approval-intent.js";

describe("approval intent capture", () => {
  it("keeps bounded real input while redacting credential-shaped values", () => {
    expect(captureApprovalIntent(
      " restart demo token=secret-value https://alice:password@example.test/path ",
    )).toEqual({
      available: true,
      userIntent: "restart demo token=[REDACTED] https://[REDACTED]@example.test/path",
    });
  });

  it("marks oversized input unavailable instead of truncating or inventing intent", () => {
    expect(captureApprovalIntent("x".repeat(MAX_BOUND_APPROVAL_INTENT_BYTES + 1)))
      .toEqual({
        available: false,
        reason: `the originating user input exceeded ${MAX_BOUND_APPROVAL_INTENT_BYTES} bytes`,
      });
  });
});
