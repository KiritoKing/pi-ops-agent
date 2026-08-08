import { parseChangeRef, type ChangeRef } from "../shared/approval.js";

export type DirectCommand =
  | { kind: "approve"; changeRef: ChangeRef }
  | { kind: "rollback"; changeRef: ChangeRef }
  | { kind: "reject"; changeRef: ChangeRef }
  | { kind: "status"; changeRef: ChangeRef };

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
