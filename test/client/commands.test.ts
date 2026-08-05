import { afterEach, describe, expect, it, vi } from "vitest";
import {
  helperRequestFor,
  helperTimeoutFor,
  parseDirectCommand,
} from "../../src/client/commands.js";

afterEach(() => vi.useRealTimers());

describe("direct root-helper commands", () => {
  it("parses approval and rejection commands", () => {
    expect(parseDirectCommand("/approve change-1234")).toEqual({
      kind: "approve",
      changeId: "change-1234",
    });
    expect(parseDirectCommand("/reject change-1234")).toEqual({
      kind: "reject",
      changeId: "change-1234",
    });
    expect(parseDirectCommand("/rollback change-1234")).toEqual({
      kind: "rollback",
      changeId: "change-1234",
    });
  });

  it("maps status with an id to change.status", () => {
    const command = parseDirectCommand("/status change-1234");
    if (!command) throw new Error("expected status command");
    expect(helperRequestFor(command)).toMatchObject({
      version: 1,
      method: "change.status",
      changeId: "change-1234",
    });
  });

  it("gives approve and rollback nine-minute deadlines and longer transport timeouts", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-05T00:00:00.000Z"));
    const approve = parseDirectCommand("/approve change-1234");
    const rollback = parseDirectCommand("/rollback change-1234");
    const reject = parseDirectCommand("/reject change-1234");
    const status = parseDirectCommand("/status change-1234");
    if (!approve || !rollback || !reject || !status) throw new Error("expected direct commands");

    expect(helperRequestFor(approve).deadline).toBe("2026-08-05T00:09:00.000Z");
    expect(helperRequestFor(rollback)).toMatchObject({
      method: "change.rollback",
      deadline: "2026-08-05T00:09:00.000Z",
    });
    expect(helperTimeoutFor(approve)).toBeGreaterThan(9 * 60_000);
    expect(helperTimeoutFor(rollback)).toBeGreaterThan(9 * 60_000);
    expect(helperRequestFor(reject).deadline).toBe("2026-08-05T00:00:30.000Z");
    expect(helperTimeoutFor(reject)).toBe(30_000);
    expect(helperRequestFor(status).deadline).toBe("2026-08-05T00:00:30.000Z");
    expect(helperTimeoutFor(status)).toBe(30_000);
  });

  it("leaves ordinary slash commands for agentd and rejects unsafe shapes", () => {
    expect(parseDirectCommand("/help")).toBeUndefined();
    expect(() => parseDirectCommand("/status")).toThrow("usage");
    expect(() => parseDirectCommand("/approve change-1234 extra")).toThrow("usage");
  });
});
