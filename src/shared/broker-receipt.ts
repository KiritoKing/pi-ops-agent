import {
  createHash,
  createPublicKey,
  verify as verifySignature,
  type KeyObject,
} from "node:crypto";
import { requireInteger, requireString } from "./guards.js";
import { requireExactRecord } from "./strict.js";
import type { RemoteResponse } from "./server-protocol.js";

const ID_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,159}$/u;
const KEY_ID_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9._:-]{7,159}$/u;
const REQUEST_ID_PATTERN = /^[a-zA-Z0-9._:-]{8,160}$/u;
const CHANGE_ID_PATTERN = /^[a-zA-Z0-9._-]{8,160}$/u;
const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const AUDIT_ID_PATTERN = /^audit-[a-f0-9]{32}$/u;
const CANONICAL_UTC_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/u;
const MAX_SAFE_INTEGER = 2 ** 53 - 1;

export type BrokerDomain = "core" | "pve";
export type BrokerReceiptMethod =
  | "change.status"
  | "change.approve"
  | "change.reject"
  | "change.rollback"
  | "workload.command.inspect";

export interface BrokerReceipt {
  version: 1;
  keyId: string;
  domain: BrokerDomain;
  requestId: string;
  method: BrokerReceiptMethod;
  action: "status" | "approve" | "reject" | "rollback" | "inspect";
  serverId: string;
  machineId: string;
  targetId: string;
  changeId: string;
  planHash: string;
  state: string;
  pluginId?: string;
  pluginDigest?: string;
  profileKey?: string;
  auditId: string;
  resultDigest: string;
  issuedAt: string;
  signature: string;
}

export interface ExpectedBrokerReceipt {
  keyId: string;
  domain: BrokerDomain;
  requestId: string;
  method: BrokerReceiptMethod;
  serverId: string;
  machineId: string;
  targetId: string;
  changeId: string;
  planHash?: string;
  pluginId?: string;
  pluginDigest?: string;
  profileKey?: string;
}

function actionForMethod(method: BrokerReceiptMethod): BrokerReceipt["action"] {
  switch (method) {
    case "change.status": return "status";
    case "change.approve": return "approve";
    case "change.reject": return "reject";
    case "change.rollback": return "rollback";
    case "workload.command.inspect": return "inspect";
  }
}

function frame(value: string): Buffer {
  const bytes = Buffer.from(value, "utf8");
  return Buffer.concat([Buffer.from(`${bytes.length}:`, "ascii"), bytes]);
}

function canonicalData(value: unknown, depth = 0): Buffer {
  if (depth > 64) throw new Error("broker receipt data nesting exceeds the canonical bound");
  if (value === undefined || value === null) return Buffer.from("n", "ascii");
  if (typeof value === "boolean") return Buffer.from(value ? "t" : "f", "ascii");
  if (typeof value === "string") return Buffer.concat([Buffer.from("s", "ascii"), frame(value)]);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || Math.abs(value) > MAX_SAFE_INTEGER) {
      throw new Error("broker receipt data only permits cross-language safe integers");
    }
    const normalized = Object.is(value, -0) ? "0" : String(value);
    return Buffer.concat([Buffer.from("i", "ascii"), frame(normalized)]);
  }
  if (Array.isArray(value)) {
    return Buffer.concat([
      Buffer.from("a", "ascii"),
      frame(String(value.length)),
      ...value.map((item) => canonicalData(item, depth + 1)),
    ]);
  }
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).sort((left, right) =>
      Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8")));
    const fields: Buffer[] = [Buffer.from("o", "ascii"), frame(String(keys.length))];
    for (const key of keys) {
      fields.push(frame(key), canonicalData(record[key], depth + 1));
    }
    return Buffer.concat(fields);
  }
  throw new Error(`unsupported broker receipt data type: ${typeof value}`);
}

export function canonicalBrokerResultDigest(response: RemoteResponse): string {
  const hash = createHash("sha256");
  hash.update("agentd-broker-result-v1\0", "utf8");
  for (const value of [
    String(response.version),
    response.requestId,
    String(response.ok),
    response.auditId ?? "",
    response.changeId ?? "",
    response.state ?? "",
    response.summary ?? "",
    response.error ?? "",
  ]) hash.update(frame(value));
  hash.update(frame(canonicalData(response.data).toString("utf8")));
  return `sha256:${hash.digest("hex")}`;
}

export function brokerReceiptSigningPayload(receipt: BrokerReceipt): Buffer {
  const fields = [
    String(receipt.version), receipt.keyId, receipt.domain, receipt.requestId,
    receipt.method, receipt.action, receipt.serverId, receipt.machineId,
    receipt.targetId, receipt.changeId, receipt.planHash, receipt.state,
    receipt.auditId, receipt.resultDigest, receipt.issuedAt,
  ];
  if (receipt.method === "workload.command.inspect") {
    fields.push(receipt.pluginId ?? "", receipt.pluginDigest ?? "", receipt.profileKey ?? "");
  }
  return Buffer.concat([
    Buffer.from("agentd-broker-receipt-v1\0", "utf8"),
    ...fields.map(frame),
  ]);
}

function requireEnum<Value extends string>(
  value: unknown,
  label: string,
  allowed: readonly Value[],
): Value {
  const parsed = requireString(value, label, { max: 64 });
  if (!allowed.includes(parsed as Value)) throw new Error(`${label} is unsupported`);
  return parsed as Value;
}

export function parseBrokerReceipt(value: unknown): BrokerReceipt {
  const input = requireExactRecord(value, "broker receipt", [
    "version", "keyId", "domain", "requestId", "method", "action", "serverId",
    "machineId", "targetId", "changeId", "planHash", "state", "auditId",
    "pluginId", "pluginDigest", "profileKey", "resultDigest", "issuedAt", "signature",
  ]);
  if (requireInteger(input.version, "broker receipt.version", 1, 1) !== 1) {
    throw new Error("broker receipt has an unsupported version");
  }
  const method = requireEnum(input.method, "broker receipt.method", [
    "change.status", "change.approve", "change.reject", "change.rollback",
    "workload.command.inspect",
  ] as const);
  const commandInspection = method === "workload.command.inspect";
  const receipt: BrokerReceipt = {
    version: 1,
    keyId: requireString(input.keyId, "broker receipt.keyId", { pattern: KEY_ID_PATTERN }),
    domain: requireEnum(input.domain, "broker receipt.domain", ["core", "pve"] as const),
    requestId: requireString(input.requestId, "broker receipt.requestId", {
      pattern: REQUEST_ID_PATTERN,
    }),
    method,
    action: requireEnum(input.action, "broker receipt.action", [
      "status", "approve", "reject", "rollback", "inspect",
    ] as const),
    serverId: requireString(input.serverId, "broker receipt.serverId", { pattern: ID_PATTERN }),
    machineId: requireString(input.machineId, "broker receipt.machineId", { pattern: ID_PATTERN }),
    targetId: requireString(input.targetId, "broker receipt.targetId", { pattern: ID_PATTERN }),
    changeId: requireString(input.changeId, "broker receipt.changeId", {
      ...(commandInspection ? { min: 0, max: 0 } : { pattern: CHANGE_ID_PATTERN }),
    }),
    planHash: requireString(input.planHash, "broker receipt.planHash", commandInspection
      ? { min: 0, max: 0 }
      : { pattern: DIGEST_PATTERN }),
    state: commandInspection
      ? requireString(input.state, "broker receipt.state", { min: 0, max: 0 })
      : requireEnum(input.state, "broker receipt.state", [
        "PENDING_APPROVAL", "REJECTED", "PREPARING", "EXECUTING", "VERIFYING",
        "COMMITTED", "ROLLING_BACK", "ROLLED_BACK", "RECOVERY_REQUIRED", "SUPERSEDED",
      ] as const),
    auditId: requireString(input.auditId, "broker receipt.auditId", { pattern: AUDIT_ID_PATTERN }),
    resultDigest: requireString(input.resultDigest, "broker receipt.resultDigest", {
      pattern: DIGEST_PATTERN,
    }),
    issuedAt: requireString(input.issuedAt, "broker receipt.issuedAt", {
      pattern: CANONICAL_UTC_PATTERN,
    }),
    signature: requireString(input.signature, "broker receipt.signature", { min: 86, max: 86 }),
    ...(input.pluginId === undefined ? {} : {
      pluginId: requireString(input.pluginId, "broker receipt.pluginId", {
        pattern: /^workload\.[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?$/u,
      }),
    }),
    ...(input.pluginDigest === undefined ? {} : {
      pluginDigest: requireString(input.pluginDigest, "broker receipt.pluginDigest", {
        pattern: DIGEST_PATTERN,
      }),
    }),
    ...(input.profileKey === undefined ? {} : {
      profileKey: requireString(input.profileKey, "broker receipt.profileKey", {
        max: 96,
        pattern: /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+){0,7}$/u,
      }),
    }),
  };
  if (receipt.action !== actionForMethod(receipt.method)) {
    throw new Error("broker receipt action does not match its method");
  }
  if (commandInspection) {
    if (receipt.domain !== "core" || receipt.pluginId === undefined
      || receipt.pluginId === "workload.base" || receipt.pluginDigest === undefined
      || receipt.profileKey === undefined) {
      throw new Error("workload command receipt has an invalid digest-bound profile scope");
    }
  } else {
    if (receipt.pluginId !== undefined || receipt.pluginDigest !== undefined
      || receipt.profileKey !== undefined) {
      throw new Error("change receipt unexpectedly carries workload profile fields");
    }
    if ((receipt.domain === "core" && !receipt.changeId.startsWith("change-"))
      || (receipt.domain === "pve" && !receipt.changeId.startsWith("pve-change-"))) {
      throw new Error("broker receipt change ID does not match its domain");
    }
  }
  const signature = Buffer.from(receipt.signature, "base64");
  if (signature.length !== 64
    || signature.toString("base64").replace(/=+$/u, "") !== receipt.signature) {
    throw new Error("broker receipt signature is not canonical base64");
  }
  const issuedAt = Date.parse(receipt.issuedAt);
  if (!Number.isFinite(issuedAt)) throw new Error("broker receipt issuedAt is invalid");
  return receipt;
}

function ed25519PublicKey(publicKeyPem: Buffer): KeyObject {
  const key = createPublicKey(publicKeyPem);
  if (key.asymmetricKeyType !== "ed25519") {
    throw new Error("broker receipt verification key must be Ed25519");
  }
  return key;
}

export function verifyBrokerResponse(
  response: RemoteResponse,
  expected: ExpectedBrokerReceipt,
  publicKeyPem: Buffer,
  now = new Date(),
): void {
  const receipt = response.brokerReceipt;
  if (receipt === undefined) throw new Error("server response has no signed broker receipt");
  if (receipt.keyId !== expected.keyId || receipt.domain !== expected.domain
    || receipt.requestId !== expected.requestId || receipt.method !== expected.method
    || receipt.action !== actionForMethod(expected.method)
    || receipt.serverId !== expected.serverId || receipt.machineId !== expected.machineId
    || receipt.targetId !== expected.targetId || receipt.changeId !== expected.changeId
    || (expected.planHash !== undefined && receipt.planHash !== expected.planHash)
    || receipt.pluginId !== expected.pluginId || receipt.pluginDigest !== expected.pluginDigest
    || receipt.profileKey !== expected.profileKey) {
    throw new Error("broker receipt does not match the expected request scope");
  }
  const identityMatches = receipt.method === "workload.command.inspect"
    ? response.requestId === receipt.requestId && response.auditId === receipt.auditId
      && response.changeId === undefined && response.state === undefined
    : response.requestId === receipt.requestId && response.auditId === receipt.auditId
      && response.changeId === receipt.changeId && response.state === receipt.state;
  if (!identityMatches) {
    throw new Error("broker receipt does not match the relayed response identity");
  }
  const statusData = response.data;
  if (expected.method === "change.status"
    && (typeof statusData !== "object" || statusData === null || Array.isArray(statusData)
      || (statusData as Record<string, unknown>).planHash !== receipt.planHash)) {
    throw new Error("signed change status does not match the broker plan hash");
  }
  if (Date.parse(receipt.issuedAt) > now.getTime() + 30_000) {
    throw new Error("broker receipt was issued in the future");
  }
  if (canonicalBrokerResultDigest(response) !== receipt.resultDigest) {
    throw new Error("broker receipt result digest does not match the response");
  }
  const signature = Buffer.from(receipt.signature, "base64");
  if (!verifySignature(
    null,
    brokerReceiptSigningPayload(receipt),
    ed25519PublicKey(publicKeyPem),
    signature,
  )) {
    throw new Error("broker receipt signature is invalid");
  }
}
