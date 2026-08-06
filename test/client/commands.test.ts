import { afterEach, describe, expect, it, vi } from "vitest";
import {
  helperRequestFor,
  helperTimeoutFor,
  parseDirectCommand,
} from "../../src/client/commands.js";
import { encodeChangeRef } from "../../src/shared/approval.js";
import { parseChangeId, parseMachineId, parseServerId, parseTargetId } from "../../src/shared/domain.js";

const CHANGE_REF = encodeChangeRef({
  version: 1,
  serverId: parseServerId("server-12345678"),
  machineId: parseMachineId("machine-12345678"),
  targetId: parseTargetId("target-12345678"),
  changeId: parseChangeId("change-1234"),
});

afterEach(() => vi.useRealTimers());

describe("direct root-helper commands", () => {
  it("parses approval and rejection commands", () => {
    const approve = parseDirectCommand(`/approve ${CHANGE_REF}`);
    const reject = parseDirectCommand(`/reject ${CHANGE_REF}`);
    const rollback = parseDirectCommand(`/rollback ${CHANGE_REF}`);
    expect(approve?.kind).toBe("approve");
    expect(approve?.changeRef.changeId).toBe("change-1234");
    expect(reject?.kind).toBe("reject");
    expect(reject?.changeRef.changeId).toBe("change-1234");
    expect(rollback?.kind).toBe("rollback");
    expect(rollback?.changeRef.changeId).toBe("change-1234");
  });

  it("maps status with an id to change.status", () => {
    const command = parseDirectCommand(`/status ${CHANGE_REF}`);
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
    const approve = parseDirectCommand(`/approve ${CHANGE_REF}`);
    const rollback = parseDirectCommand(`/rollback ${CHANGE_REF}`);
    const reject = parseDirectCommand(`/reject ${CHANGE_REF}`);
    const status = parseDirectCommand(`/status ${CHANGE_REF}`);
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
    expect(() => parseDirectCommand(`/approve ${CHANGE_REF} extra`)).toThrow("usage");
  });
});
