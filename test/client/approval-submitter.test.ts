import { describe, expect, it } from "vitest";
import {
  approvalSubmitArguments,
  SudoApprovalSubmitter,
} from "../../src/client/approval-submitter.js";
import {
  parseChangeId,
  parseMachineId,
  parseServerId,
  parseTargetId,
} from "../../src/shared/domain.js";

describe("root-owned approval submitter", () => {
  it("uses fixed sudo argv without a shell or caller-controlled paths", () => {
    const arguments_ = approvalSubmitArguments("/opt/pi-ops-agent/current/bin/agentd-approval-submit", {
      action: "approve",
      changeRef: {
        version: 1,
        serverId: parseServerId("server-12345678"),
        machineId: parseMachineId("machine-12345678"),
        targetId: parseTargetId("target-12345678"),
        changeId: parseChangeId("change-12345678"),
      },
      userIntent: "restart the service after checking health",
    });
    expect(arguments_).toEqual([
      "-k", "--", "/opt/pi-ops-agent/current/bin/agentd-approval-submit",
      "--action", "approve",
      "--server-id", "server-12345678",
      "--machine-id", "machine-12345678",
      "--target-id", "target-12345678",
      "--change-id", "change-12345678",
      "--user-intent-b64", Buffer.from(
        "restart the service after checking health",
        "utf8",
      ).toString("base64url"),
    ]);
  });

  it("rejects empty and oversized user intent before invoking sudo", () => {
    const changeRef = {
      version: 1 as const,
      serverId: parseServerId("server-12345678"),
      machineId: parseMachineId("machine-12345678"),
      targetId: parseTargetId("target-12345678"),
      changeId: parseChangeId("change-12345678"),
    };
    expect(() => approvalSubmitArguments("/fixed/helper", {
      action: "approve", changeRef, userIntent: "   ",
    })).toThrow("user intent");
    expect(() => approvalSubmitArguments("/fixed/helper", {
      action: "approve", changeRef, userIntent: "x".repeat(4097),
    })).toThrow("user intent");
  });

  it("rejects a non-normalized helper path", () => {
    expect(() => new SudoApprovalSubmitter("/opt/pi-ops-agent/current/bin/../bin/helper"))
      .toThrow(/absolute and normalized/u);
  });
});
