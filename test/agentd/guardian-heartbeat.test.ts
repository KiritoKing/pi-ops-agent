import { describe, expect, it } from "vitest";
import { formatGuardianObservedAt } from "../../src/agentd/guardian-heartbeat.js";

describe("guardian heartbeat timestamp", () => {
  it.each([
    [123, "2026-08-08T04:05:06.123Z"],
    [120, "2026-08-08T04:05:06.12Z"],
    [100, "2026-08-08T04:05:06.1Z"],
    [70, "2026-08-08T04:05:06.07Z"],
    [0, "2026-08-08T04:05:06Z"],
  ])("canonicalizes JavaScript millisecond value %i", (milliseconds, expected) => {
    const date = new Date(Date.UTC(2026, 7, 8, 4, 5, 6, milliseconds));
    const observedAt = formatGuardianObservedAt(date);

    expect(observedAt).toBe(expected);
    expect(Date.parse(observedAt)).toBe(date.getTime());
  });
});
