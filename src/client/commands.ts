import { parseChangeRef, type ChangeRef } from "../shared/approval.js";
import type { HelperRequest } from "../shared/messages.js";
import { deadline, requestId } from "../shared/rpc.js";

export type DirectCommand =
  | { kind: "approve"; changeRef: ChangeRef }
  | { kind: "rollback"; changeRef: ChangeRef }
  | { kind: "reject"; changeRef: ChangeRef }
  | { kind: "status"; changeRef: ChangeRef };

const SHORT_DEADLINE_SECONDS = 30;
const MUTATION_DEADLINE_SECONDS = 9 * 60;
const SHORT_TIMEOUT_MS = 30_000;
const MUTATION_TIMEOUT_MS = 9 * 60_000 + 15_000;

export function parseDirectCommand(text: string): DirectCommand | undefined {
  const trimmed = text.trim();
  const [name, ...parameters] = trimmed.split(/\s+/u);
  if (
    name !== "/approve"
    && name !== "/rollback"
    && name !== "/reject"
    && name !== "/status"
  ) return undefined;

  if (parameters.length !== 1) {
    throw new Error(`usage: ${name} <changeRef>`);
  }
  const changeRef = parseChangeRef(parameters[0]);
  if (name === "/approve") return { kind: "approve", changeRef };
  if (name === "/rollback") return { kind: "rollback", changeRef };
  if (name === "/reject") return { kind: "reject", changeRef };
  return { kind: "status", changeRef };
}

export function helperRequestFor(command: DirectCommand): HelperRequest {
  const isLongMutation = command.kind === "approve" || command.kind === "rollback";
  const base = {
    version: 1 as const,
    requestId: requestId(),
    deadline: deadline(isLongMutation ? MUTATION_DEADLINE_SECONDS : SHORT_DEADLINE_SECONDS),
  };
  if (command.kind === "approve") {
    return { ...base, method: "change.approve", changeId: command.changeRef.changeId };
  }
  if (command.kind === "rollback") {
    return { ...base, method: "change.rollback", changeId: command.changeRef.changeId };
  }
  if (command.kind === "reject") {
    return { ...base, method: "change.reject", changeId: command.changeRef.changeId };
  }
  return { ...base, method: "change.status", changeId: command.changeRef.changeId };
}

export function helperTimeoutFor(command: DirectCommand): number {
  return command.kind === "approve" || command.kind === "rollback"
    ? MUTATION_TIMEOUT_MS
    : SHORT_TIMEOUT_MS;
}
