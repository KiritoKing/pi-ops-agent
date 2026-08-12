import { describe, expect, it } from "vitest";

import { transportTimeoutForDeadline } from "../../src/agentd/ops-server-client.js";

describe("ops server transport timeout", () => {
  const now = Date.parse("2026-08-07T12:00:00.000Z");

  it("keeps short and malformed deadlines bounded by the default", () => {
    expect(transportTimeoutForDeadline("invalid", now)).toBe(30_000);
    expect(transportTimeoutForDeadline("2026-08-07T12:00:10.000Z", now)).toBe(30_000);
  });

  it("allows a long approved mutation to use its protocol deadline", () => {
    expect(transportTimeoutForDeadline("2026-08-07T12:09:00.000Z", now)).toBe(545_000);
  });

  it("caps transport wait even when a caller supplies a distant deadline", () => {
    expect(transportTimeoutForDeadline("2026-08-08T12:00:00.000Z", now)).toBe(600_000);
  });
});
