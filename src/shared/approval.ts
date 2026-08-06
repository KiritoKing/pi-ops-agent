import { createPrivateKey, randomBytes, sign } from "node:crypto";
import { readFile } from "node:fs/promises";
import {
  parseChangeId,
  parseMachineId,
  parseServerId,
  parseTargetId,
  type ChangeId,
  type MachineId,
  type ServerId,
  type TargetId,
} from "./domain.js";
import { requireString } from "./guards.js";
import { requireExactRecord } from "./strict.js";

export type ApprovalAction = "approve" | "reject" | "rollback";

export interface ChangeRef {
  version: 1;
  serverId: ServerId;
  machineId: MachineId;
  targetId: TargetId;
  changeId: ChangeId;
}

export interface ApprovalGrant {
  version: 1;
  keyId: string;
  action: ApprovalAction;
  serverId: ServerId;
  machineId: MachineId;
  targetId: TargetId;
  changeId: ChangeId;
  planHash: string;
  policyRevision: string;
  issuedAt: string;
  expiresAt: string;
  nonce: string;
  signature: string;
}

const CHANGE_REF_PREFIX = "opschg1_";
const SHA256 = /^sha256:[a-f0-9]{64}$/u;

export function encodeChangeRef(value: ChangeRef): string {
  const payload = JSON.stringify({
    version: 1,
    serverId: value.serverId,
    machineId: value.machineId,
    targetId: value.targetId,
    changeId: value.changeId,
  });
  return CHANGE_REF_PREFIX + Buffer.from(payload).toString("base64url");
}

export function parseChangeRef(value: unknown): ChangeRef {
  const text = requireString(value, "changeRef", { min: 24, max: 1024 });
  if (!text.startsWith(CHANGE_REF_PREFIX)) throw new Error("changeRef has an unsupported format");
  let decoded: unknown;
  try {
    decoded = JSON.parse(Buffer.from(text.slice(CHANGE_REF_PREFIX.length), "base64url").toString("utf8")) as unknown;
  } catch {
    throw new Error("changeRef is not valid base64url JSON");
  }
  const input = requireExactRecord(decoded, "changeRef payload", [
    "version", "serverId", "machineId", "targetId", "changeId",
  ]);
  if (input.version !== 1) throw new Error("changeRef has an unsupported version");
  return {
    version: 1,
    serverId: parseServerId(input.serverId),
    machineId: parseMachineId(input.machineId),
    targetId: parseTargetId(input.targetId),
    changeId: parseChangeId(input.changeId),
  };
}

export function parseChangeMetadata(value: unknown): { planHash: string; policyRevision: string } {
  const input = requireExactRecord(value, "change metadata", [
    "serverId", "machineId", "targetId", "policyRevision", "planHash", "kind",
    "backupRefs", "verification", "rollbackAvailable", "lastError",
  ]);
  return {
    planHash: requireString(input.planHash, "change metadata.planHash", { pattern: SHA256 }),
    policyRevision: requireString(input.policyRevision, "change metadata.policyRevision", {
      min: 1,
      max: 160,
    }),
  };
}

export function approvalPayload(grant: Omit<ApprovalGrant, "signature">): Buffer {
  return Buffer.from(JSON.stringify({
    version: grant.version,
    keyId: grant.keyId,
    action: grant.action,
    serverId: grant.serverId,
    machineId: grant.machineId,
    targetId: grant.targetId,
    changeId: grant.changeId,
    planHash: grant.planHash,
    policyRevision: grant.policyRevision,
    issuedAt: grant.issuedAt,
    expiresAt: grant.expiresAt,
    nonce: grant.nonce,
  }));
}

export async function signApprovalGrant(options: {
  keyId: string;
  privateKeyPath: string;
  action: ApprovalAction;
  changeRef: ChangeRef;
  planHash: string;
  policyRevision: string;
  now?: Date;
}): Promise<ApprovalGrant> {
  const now = options.now ?? new Date();
  const unsigned: Omit<ApprovalGrant, "signature"> = {
    version: 1,
    keyId: requireString(options.keyId, "approval keyId", {
      min: 8,
      max: 160,
      pattern: /^[a-zA-Z0-9][a-zA-Z0-9._:-]{7,159}$/u,
    }),
    action: options.action,
    serverId: options.changeRef.serverId,
    machineId: options.changeRef.machineId,
    targetId: options.changeRef.targetId,
    changeId: options.changeRef.changeId,
    planHash: requireString(options.planHash, "approval planHash", { pattern: SHA256 }),
    policyRevision: requireString(options.policyRevision, "approval policyRevision", { min: 1, max: 160 }),
    issuedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 2 * 60_000).toISOString(),
    nonce: randomBytes(24).toString("base64url"),
  };
  const key = createPrivateKey(await readFile(options.privateKeyPath));
  if (key.asymmetricKeyType !== "ed25519") throw new Error("approval signing key must be Ed25519");
  return {
    ...unsigned,
    signature: sign(null, approvalPayload(unsigned), key).toString("base64").replace(/=+$/u, ""),
  };
}
