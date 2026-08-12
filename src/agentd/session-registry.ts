import { createHash } from "node:crypto";
import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import {
  parseMachineId,
  parseSessionId,
  parseTargetId,
  type MachineId,
  type SessionId,
  type TargetId,
} from "../shared/domain.js";
import { optionalString, requireString } from "../shared/guards.js";
import { requireExactRecord } from "../shared/strict.js";
import { JsonFileStore } from "./json-store.js";
import type { MachineContextStore } from "./machine-context.js";

export interface SessionMachineBinding {
  machineId: MachineId;
  targetId?: TargetId;
  capabilityRevision: string;
  policyRevision: string;
}

export interface SessionRecord {
  sessionId: SessionId;
  workspacePath: string;
  binding?: SessionMachineBinding;
  createdAt: string;
  updatedAt: string;
}

interface SessionRegistryDocument {
  version: 1;
  sessions: SessionRecord[];
}

function parseBinding(value: unknown, label: string): SessionMachineBinding {
  const input = requireExactRecord(value, label, [
    "machineId", "targetId", "capabilityRevision", "policyRevision",
  ]);
  const targetId = optionalString(input.targetId, `${label}.targetId`, { max: 160 });
  return {
    machineId: parseMachineId(input.machineId, `${label}.machineId`),
    ...(targetId === undefined ? {} : { targetId: parseTargetId(targetId, `${label}.targetId`) }),
    capabilityRevision: requireString(input.capabilityRevision, `${label}.capabilityRevision`, {
      max: 160,
    }),
    policyRevision: requireString(input.policyRevision, `${label}.policyRevision`, { max: 160 }),
  };
}

function parseDate(value: unknown, label: string): string {
  const result = requireString(value, label, { max: 64 });
  if (!Number.isFinite(Date.parse(result))) throw new Error(`${label} must be an ISO date`);
  return result;
}

function parseRecord(value: unknown, label: string): SessionRecord {
  const input = requireExactRecord(value, label, [
    "sessionId", "workspacePath", "binding", "createdAt", "updatedAt",
  ]);
  const binding = input.binding === undefined ? undefined : parseBinding(input.binding, `${label}.binding`);
  return {
    sessionId: parseSessionId(input.sessionId, `${label}.sessionId`),
    workspacePath: requireString(input.workspacePath, `${label}.workspacePath`, { max: 4096 }),
    ...(binding === undefined ? {} : { binding }),
    createdAt: parseDate(input.createdAt, `${label}.createdAt`),
    updatedAt: parseDate(input.updatedAt, `${label}.updatedAt`),
  };
}

function parseDocument(value: unknown): SessionRegistryDocument {
  const input = requireExactRecord(value, "session registry", ["version", "sessions"]);
  if (input.version !== 1) throw new Error("unsupported session registry version");
  if (!Array.isArray(input.sessions) || input.sessions.length > 10_000) {
    throw new Error("session registry.sessions must contain at most 10000 entries");
  }
  const sessions = input.sessions.map((item, index) =>
    parseRecord(item, `session registry.sessions[${index}]`));
  if (new Set(sessions.map((item) => item.sessionId)).size !== sessions.length) {
    throw new Error("session registry contains duplicate sessionId entries");
  }
  return { version: 1, sessions };
}

function workspaceName(sessionId: SessionId): string {
  return createHash("sha256").update(sessionId).digest("hex").slice(0, 32);
}

export class SessionRegistry {
  readonly #workspaceRoot: string;
  readonly #store: JsonFileStore<SessionRegistryDocument>;

  constructor(path: string, workspaceRoot: string) {
    this.#workspaceRoot = workspaceRoot;
    this.#store = new JsonFileStore(path, parseDocument, () => ({ version: 1, sessions: [] }));
  }

  async initialize(): Promise<void> {
    await Promise.all([
      mkdir(this.#workspaceRoot, { recursive: true, mode: 0o750 }),
      this.#store.initialize(),
    ]);
  }

  async open(sessionId: SessionId): Promise<SessionRecord> {
    const existing = (await this.#store.read()).sessions.find((item) => item.sessionId === sessionId);
    if (existing) {
      await mkdir(existing.workspacePath, { recursive: true, mode: 0o750 });
      return existing;
    }
    const now = new Date().toISOString();
    const record: SessionRecord = {
      sessionId,
      workspacePath: join(this.#workspaceRoot, workspaceName(sessionId)),
      createdAt: now,
      updatedAt: now,
    };
    const document = await this.#store.update((current) => {
      const raced = current.sessions.find((item) => item.sessionId === sessionId);
      return raced ? current : { version: 1, sessions: [...current.sessions, record] };
    });
    const result = document.sessions.find((item) => item.sessionId === sessionId);
    if (!result) throw new Error("failed to persist session registry entry");
    await mkdir(result.workspacePath, { recursive: true, mode: 0o750 });
    return result;
  }

  async read(sessionId: SessionId): Promise<SessionRecord | undefined> {
    return (await this.#store.read()).sessions.find((item) => item.sessionId === sessionId);
  }

  async bind(
    sessionId: SessionId,
    machineId: MachineId,
    targetId: TargetId | undefined,
    contexts: MachineContextStore,
  ): Promise<SessionRecord> {
    const context = await contexts.require(machineId);
    if (targetId !== undefined) contexts.requireTarget(context, targetId);
    await this.open(sessionId);
    const document = await this.#store.update((current) => {
      const existing = current.sessions.find((item) => item.sessionId === sessionId);
      if (!existing) throw new Error("session disappeared while binding");
      if (
        existing.binding
        && (
          existing.binding.machineId !== machineId
          || existing.binding.targetId !== targetId
        )
      ) {
        throw new Error("session binding is immutable; create a new session for another machine or target");
      }
      const next: SessionRecord = {
        ...existing,
        binding: {
          machineId,
          ...(targetId === undefined ? {} : { targetId }),
          capabilityRevision: context.capabilities.revision,
          policyRevision: context.capabilities.policyRevision,
        },
        updatedAt: new Date().toISOString(),
      };
      return {
        version: 1,
        sessions: current.sessions.map((item) => item.sessionId === sessionId ? next : item),
      };
    });
    const result = document.sessions.find((item) => item.sessionId === sessionId);
    if (!result) throw new Error("failed to persist session binding");
    return result;
  }

  async refreshBinding(
    sessionId: SessionId,
    contexts: MachineContextStore,
  ): Promise<SessionRecord> {
    const record = await this.open(sessionId);
    if (!record.binding) return record;
    return await this.bind(
      sessionId,
      record.binding.machineId,
      record.binding.targetId,
      contexts,
    );
  }
}
