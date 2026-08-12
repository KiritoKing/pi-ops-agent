import { requireString } from "./guards.js";

type Brand<Value, Name extends string> = Value & { readonly __brand: Name };

export type MachineId = Brand<string, "MachineId">;
export type ServerId = Brand<string, "ServerId">;
export type TargetId = Brand<string, "TargetId">;
export type SessionId = Brand<string, "SessionId">;
export type TurnId = Brand<string, "TurnId">;
export type ChangeId = Brand<string, "ChangeId">;

const IDENTIFIER = /^[a-zA-Z0-9](?:[a-zA-Z0-9._:-]{6,158}[a-zA-Z0-9])?$/u;
const CHANGE_IDENTIFIER = /^[a-zA-Z0-9](?:[a-zA-Z0-9._-]{6,158}[a-zA-Z0-9])?$/u;

function parseIdentifier(value: unknown, label: string): string {
  return requireString(value, label, { min: 8, max: 160, pattern: IDENTIFIER });
}

export function parseMachineId(value: unknown, label = "machineId"): MachineId {
  return parseIdentifier(value, label) as MachineId;
}

export function parseServerId(value: unknown, label = "serverId"): ServerId {
  return parseIdentifier(value, label) as ServerId;
}

export function parseTargetId(value: unknown, label = "targetId"): TargetId {
  return parseIdentifier(value, label) as TargetId;
}

export function parseSessionId(value: unknown, label = "sessionId"): SessionId {
  return parseIdentifier(value, label) as SessionId;
}

export function parseTurnId(value: unknown, label = "turnId"): TurnId {
  return parseIdentifier(value, label) as TurnId;
}

export function parseChangeId(value: unknown, label = "changeId"): ChangeId {
  return requireString(value, label, {
    min: 8,
    max: 160,
    pattern: CHANGE_IDENTIFIER,
  }) as ChangeId;
}
