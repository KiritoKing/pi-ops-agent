import { describe, expect, it } from "vitest";
import { parseDirectCommand } from "../../src/client/commands.js";
import { encodeChangeRef } from "../../src/shared/approval.js";
import { parseChangeId, parseMachineId, parseServerId, parseTargetId } from "../../src/shared/domain.js";

const CHANGE_REF = encodeChangeRef({
  version: 1,
  serverId: parseServerId("server-12345678"),
  machineId: parseMachineId("machine-12345678"),
  targetId: parseTargetId("target-12345678"),
  changeId: parseChangeId("change-1234"),
});

describe("model-external approval commands", () => {
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

  it("parses status with its full C/S change reference", () => {
    const command = parseDirectCommand(`/status ${CHANGE_REF}`);
    if (!command) throw new Error("expected status command");
    expect(command).toMatchObject({ kind: "status", changeRef: { changeId: "change-1234" } });
  });

  it("leaves ordinary slash commands for agentd and rejects unsafe shapes", () => {
    expect(parseDirectCommand("/help")).toBeUndefined();
    expect(() => parseDirectCommand("/status")).toThrow("usage");
    expect(() => parseDirectCommand(`/approve ${CHANGE_REF} extra`)).toThrow("usage");
  });
});
