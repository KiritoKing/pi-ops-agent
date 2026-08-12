import { randomUUID } from "node:crypto";
import type { ChangeId, MachineId, TargetId } from "../shared/domain.js";
import { deadline } from "../shared/rpc.js";
import type {
  ChangeStatusRequest,
  RemoteResponse,
} from "../shared/server-protocol.js";
import type { OpsServerClient } from "./ops-server-client.js";

export const CHANGE_LIFECYCLE_STATES = Object.freeze([
  "PENDING_APPROVAL",
  "REJECTED",
  "PREPARING",
  "EXECUTING",
  "VERIFYING",
  "COMMITTED",
  "ROLLING_BACK",
  "ROLLED_BACK",
  "RECOVERY_REQUIRED",
  "SUPERSEDED",
] as const);

export type ChangeLifecycleState = (typeof CHANGE_LIFECYCLE_STATES)[number];

export interface AuthoritativePreparedChange {
  request: ChangeStatusRequest;
  response: RemoteResponse & { changeId: ChangeId; state: ChangeLifecycleState };
}

function parseLifecycleState(value: string | undefined): ChangeLifecycleState {
  if (value === undefined
    || !(CHANGE_LIFECYCLE_STATES as readonly string[]).includes(value)) {
    throw new Error("signed post-prepare status has no recognized durable state");
  }
  return value as ChangeLifecycleState;
}

/**
 * A prepare response is deliberately unsigned. Always obtain a fresh status
 * through OpsServerClient, whose HTTPS implementation verifies the pinned
 * root-broker receipt, before exposing a change to either the model or client.
 */
export async function readAuthoritativePreparedChange(
  client: OpsServerClient,
  scope: {
    machineId: MachineId;
    targetId: TargetId;
    changeId: ChangeId;
  },
  signal?: AbortSignal,
): Promise<AuthoritativePreparedChange> {
  const request: ChangeStatusRequest = {
    version: 1,
    requestId: randomUUID(),
    deadline: deadline(30),
    machineId: scope.machineId,
    targetId: scope.targetId,
    method: "change.status",
    changeId: scope.changeId,
  };
  const response = await client.changeStatus(request, signal);
  if (!response.ok) {
    throw new Error(response.error ?? "signed post-prepare status lookup failed");
  }
  if (response.requestId !== request.requestId) {
    throw new Error("signed post-prepare status request ID does not match");
  }
  if (response.changeId !== scope.changeId) {
    throw new Error("signed post-prepare status change ID does not match");
  }
  const state = parseLifecycleState(response.state);
  return {
    request,
    response: { ...response, changeId: scope.changeId, state },
  };
}

export function preparedChangeInstruction(state: ChangeLifecycleState): string {
  switch (state) {
    case "PENDING_APPROVAL":
      return "This change is pending model-external local review and exact client approval.";
    case "COMMITTED":
      return "The broker committed this change under an explicit standing grant; its signed terminal status was verified.";
    case "RECOVERY_REQUIRED":
      return "The broker reports RECOVERY_REQUIRED; do not claim success or retry blindly. Inspect recovery evidence and request a separately approved recovery change.";
    case "SUPERSEDED":
      return "This unresolved change was superseded by a separately approved PVE recovery child; follow the signed resolution and child evidence instead of retrying the parent.";
    case "REJECTED":
      return "The change is rejected and cannot be approved or executed.";
    case "ROLLED_BACK":
      return "The change is already rolled back; no approval is pending.";
    case "PREPARING":
    case "EXECUTING":
    case "VERIFYING":
    case "ROLLING_BACK":
      return `The signed broker state is ${state}; no new approval action is currently available.`;
  }
}
