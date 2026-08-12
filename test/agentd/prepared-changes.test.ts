import { describe, expect, it } from "vitest";
import { PreparedChangeTracker } from "../../src/agentd/prepared-changes.js";
import { encodeChangeRef } from "../../src/shared/approval.js";
import {
  parseChangeId,
  parseMachineId,
  parseServerId,
  parseTargetId,
} from "../../src/shared/domain.js";

const changeRef = {
  version: 1 as const,
  serverId: parseServerId("server-tracker-12345678"),
  machineId: parseMachineId("machine-tracker-12345678"),
  targetId: parseTargetId("target-tracker-12345678"),
  changeId: parseChangeId("change-tracker-12345678"),
};

describe("PreparedChangeTracker", () => {
  it("emits only trusted recorded references once for the exact tool call", () => {
    const tracker = new PreparedChangeTracker();
    tracker.record("tool-call-12345678", changeRef);
    tracker.record("tool-call-12345678", changeRef);

    expect(tracker.consume("different-tool-call-12345678")).toEqual([]);
    expect(tracker.consume("tool-call-12345678")).toEqual([encodeChangeRef(changeRef)]);
    expect(tracker.consume("tool-call-12345678")).toEqual([]);
  });

  it("rejects invalid tool-call correlation instead of creating an unbound signal", () => {
    const tracker = new PreparedChangeTracker();
    expect(() => tracker.record("bad\ncall", changeRef)).toThrow("invalid tool-call");
    expect(tracker.consume("bad\ncall")).toEqual([]);
  });
});
