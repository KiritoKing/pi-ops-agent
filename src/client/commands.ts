import { parseChangeId, type HelperRequest } from "../shared/messages.js";
import { deadline, requestId } from "../shared/rpc.js";

export type DirectCommand =
  | { kind: "approve"; changeId: string }
  | { kind: "rollback"; changeId: string }
  | { kind: "reject"; changeId: string }
  | { kind: "status"; changeId: string };

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
    throw new Error(`usage: ${name} <changeId>`);
  }
  const changeId = parseChangeId(parameters[0]);
  if (name === "/approve") return { kind: "approve", changeId };
  if (name === "/rollback") return { kind: "rollback", changeId };
  if (name === "/reject") return { kind: "reject", changeId };
  return { kind: "status", changeId };
}

export function helperRequestFor(command: DirectCommand): HelperRequest {
  const isLongMutation = command.kind === "approve" || command.kind === "rollback";
  const base = {
    version: 1 as const,
    requestId: requestId(),
    deadline: deadline(isLongMutation ? MUTATION_DEADLINE_SECONDS : SHORT_DEADLINE_SECONDS),
  };
  if (command.kind === "approve") {
    return { ...base, method: "change.approve", changeId: command.changeId };
  }
  if (command.kind === "rollback") {
    return { ...base, method: "change.rollback", changeId: command.changeId };
  }
  if (command.kind === "reject") {
    return { ...base, method: "change.reject", changeId: command.changeId };
  }
  return { ...base, method: "change.status", changeId: command.changeId };
}

export function helperTimeoutFor(command: DirectCommand): number {
  return command.kind === "approve" || command.kind === "rollback"
    ? MUTATION_TIMEOUT_MS
    : SHORT_TIMEOUT_MS;
}
