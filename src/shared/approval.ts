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
import { requireString, requireStringArray } from "./guards.js";
import { requireExactRecord } from "./strict.js";
import { parseApprovalPlan, type ApprovalPlan } from "./approval-review.js";

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
  capabilityRevision: string;
  issuedAt: string;
  expiresAt: string;
  nonce: string;
  signature: string;
}

export interface RecoveryBackupObject {
  reference: string;
  digest?: string;
}

export interface RecoveryDescriptor {
  version: 1;
  compatibilityVersion: "legacy-plan-v0.1-v0.2";
  originalKind: string;
  originalTarget: string;
  originalAction: string;
  compensationTarget: string;
  compensationAction: string;
  rollbackDataDigest: string;
  backupObjects: readonly RecoveryBackupObject[];
  rollbackCompatible: boolean;
  unavailableReason?: string;
}

interface PVERecoveryResolutionBase {
  kind: "pve.recovery-transfer/v1";
  childChangeId: ChangeId;
  childPlanHash: string;
  transferredAt: string;
  parentTaskEvidence: readonly PVERecoveryTaskEvidence[];
}

export type PVERecoveryResolution = PVERecoveryResolutionBase & (
  | {
      basis?: undefined;
      parentMutationDisposition: "NO_MUTATION_STARTED" | "TASKS_TERMINAL";
    }
  | {
      basis: "local-unknown-clearance";
      parentChangeId: ChangeId;
      resourceKey: string;
      parentMutationDisposition: "STARTED_OR_UNKNOWN";
      clearanceObservationDigest: string;
      activeTaskDigest: string;
      guestStateDigest: string;
      clusterStateDigest: string;
    }
);

export interface PVERecoveryTaskEvidence {
  role: "safety-backup" | "primary";
  node: string;
  upid: string;
  status: "stopped";
  exitStatus: string;
  observedAt: string;
}

const CHANGE_REF_PREFIX = "opschg1_";
const SHA256 = /^sha256:[a-f0-9]{64}$/u;

function containsUnsafeControl(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0);
    if (codePoint !== undefined && (codePoint < 0x20
      || (codePoint >= 0x7f && codePoint <= 0x9f)
      || codePoint === 0x2028 || codePoint === 0x2029
      || (codePoint >= 0x202a && codePoint <= 0x202e)
      || (codePoint >= 0x2066 && codePoint <= 0x2069))) return true;
  }
  return false;
}

function parseRecoveryDescriptor(value: unknown): RecoveryDescriptor {
  const input = requireExactRecord(value, "recovery descriptor", [
    "version", "compatibilityVersion", "originalKind", "originalTarget", "originalAction",
    "compensationTarget", "compensationAction", "rollbackDataDigest", "backupObjects",
    "rollbackCompatible", "unavailableReason",
  ]);
  if (input.version !== 1 || input.compatibilityVersion !== "legacy-plan-v0.1-v0.2") {
    throw new Error("recovery descriptor has an unsupported version");
  }
  if (!Array.isArray(input.backupObjects) || input.backupObjects.length > 64) {
    throw new Error("recovery descriptor.backupObjects is invalid");
  }
  const backupObjects = input.backupObjects.map((value, index) => {
    const object = requireExactRecord(value, `recovery descriptor.backupObjects[${index}]`, [
      "reference", "digest",
    ]);
    const reference = requireString(
      object.reference,
      `recovery descriptor.backupObjects[${index}].reference`,
      { min: 1, max: 4096 },
    );
    const digest = object.digest === undefined
      ? undefined
      : requireString(object.digest, `recovery descriptor.backupObjects[${index}].digest`, {
        pattern: SHA256,
      });
    if (containsUnsafeControl(reference)) {
      throw new Error("recovery descriptor contains an unsafe backup reference");
    }
    return { reference, ...(digest === undefined ? {} : { digest }) };
  });
  if (new Set(backupObjects.map((object) => object.reference)).size !== backupObjects.length) {
    throw new Error("recovery descriptor contains duplicate backup objects");
  }
  if (typeof input.rollbackCompatible !== "boolean") {
    throw new Error("recovery descriptor.rollbackCompatible must be a boolean");
  }
  const unavailableReason = input.unavailableReason === undefined
    ? undefined
    : requireString(input.unavailableReason, "recovery descriptor.unavailableReason", {
      min: 1,
      max: 2048,
    });
  if (input.rollbackCompatible === (unavailableReason !== undefined)
    || (unavailableReason !== undefined && containsUnsafeControl(unavailableReason))
    || (input.rollbackCompatible && backupObjects.some((object) => object.digest === undefined))) {
    throw new Error("recovery descriptor compatibility evidence is inconsistent");
  }
  const boundedText = (field: unknown, name: string, max: number): string => {
    const text = requireString(field, `recovery descriptor.${name}`, { min: 1, max });
    if (containsUnsafeControl(text)) {
      throw new Error(`recovery descriptor.${name} contains an unsafe control character`);
    }
    return text;
  };
  return {
    version: 1,
    compatibilityVersion: "legacy-plan-v0.1-v0.2",
    originalKind: boundedText(input.originalKind, "originalKind", 128),
    originalTarget: boundedText(input.originalTarget, "originalTarget", 4096),
    originalAction: boundedText(input.originalAction, "originalAction", 128),
    compensationTarget: boundedText(input.compensationTarget, "compensationTarget", 4096),
    compensationAction: boundedText(input.compensationAction, "compensationAction", 128),
    rollbackDataDigest: requireString(
      input.rollbackDataDigest,
      "recovery descriptor.rollbackDataDigest",
      { pattern: SHA256 },
    ),
    backupObjects,
    rollbackCompatible: input.rollbackCompatible,
    ...(unavailableReason === undefined ? {} : { unavailableReason }),
  };
}

function parsePVERecoveryResolution(value: unknown): PVERecoveryResolution {
  const input = requireExactRecord(value, "PVE recovery resolution", [
    "kind", "basis", "parentChangeId", "childChangeId", "childPlanHash", "resourceKey",
    "transferredAt", "parentMutationDisposition", "parentTaskEvidence",
    "clearanceObservationDigest", "activeTaskDigest", "guestStateDigest", "clusterStateDigest",
  ]);
  if (input.kind !== "pve.recovery-transfer/v1") {
    throw new Error("PVE recovery resolution has an unsupported kind");
  }
  const childChangeId = parseChangeId(input.childChangeId);
  if (!childChangeId.startsWith("pve-change-")) {
    throw new Error("PVE recovery resolution child is outside the PVE domain");
  }
  const transferredAt = requireString(
    input.transferredAt,
    "PVE recovery resolution.transferredAt",
    {
      min: 20,
      max: 64,
      pattern: /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/u,
    },
  );
  if (!Number.isFinite(Date.parse(transferredAt))) {
    throw new Error("PVE recovery resolution transfer time is invalid");
  }
  const parentMutationDisposition = input.parentMutationDisposition;
  if (!Array.isArray(input.parentTaskEvidence) || input.parentTaskEvidence.length > 2) {
    throw new Error("PVE recovery resolution parent task evidence is invalid");
  }
  const parentTaskEvidence = input.parentTaskEvidence.map((value, index) => {
    const evidence = requireExactRecord(value, `PVE recovery task evidence[${index}]`, [
      "role", "node", "upid", "status", "exitStatus", "observedAt",
    ]);
    if ((evidence.role !== "safety-backup" && evidence.role !== "primary")
      || evidence.status !== "stopped") {
      throw new Error("PVE recovery task evidence role or status is invalid");
    }
    const role: PVERecoveryTaskEvidence["role"] = evidence.role;
    const node = requireString(evidence.node, `PVE recovery task evidence[${index}].node`, {
      min: 1,
      max: 64,
      pattern: /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u,
    });
    const upid = requireString(evidence.upid, `PVE recovery task evidence[${index}].upid`, {
      min: 16,
      max: 512,
      pattern: /^UPID:[A-Za-z0-9][A-Za-z0-9._-]{0,63}:[A-Fa-f0-9]+:[A-Fa-f0-9]+:[A-Fa-f0-9]+:[A-Za-z0-9._-]+:[^/:]{0,128}:[^/:]{1,128}:$/u,
    });
    if (!upid.startsWith(`UPID:${node}:`)) {
      throw new Error("PVE recovery task evidence UPID is outside its node");
    }
    const exitStatus = requireString(
      evidence.exitStatus,
      `PVE recovery task evidence[${index}].exitStatus`,
      { min: 1, max: 256 },
    );
    if (containsUnsafeControl(exitStatus)) {
      throw new Error("PVE recovery task evidence exit status contains unsafe control text");
    }
    const observedAt = requireString(
      evidence.observedAt,
      `PVE recovery task evidence[${index}].observedAt`,
      {
        min: 20,
        max: 64,
        pattern: /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/u,
      },
    );
    if (!Number.isFinite(Date.parse(observedAt))) {
      throw new Error("PVE recovery task evidence time is invalid");
    }
    return {
      role,
      node,
      upid,
      status: "stopped" as const,
      exitStatus,
      observedAt,
    };
  });
  if (new Set(parentTaskEvidence.map((evidence) => evidence.role)).size !== parentTaskEvidence.length
    || new Set(parentTaskEvidence.map((evidence) => evidence.upid)).size !== parentTaskEvidence.length) {
    throw new Error("PVE recovery resolution task evidence is inconsistent");
  }
  const common: PVERecoveryResolutionBase = {
    kind: "pve.recovery-transfer/v1",
    childChangeId,
    childPlanHash: requireString(
      input.childPlanHash,
      "PVE recovery resolution.childPlanHash",
      { pattern: SHA256 },
    ),
    transferredAt,
    parentTaskEvidence,
  };
  if (input.basis === undefined) {
    if (input.parentChangeId !== undefined || input.resourceKey !== undefined
      || input.clearanceObservationDigest !== undefined || input.activeTaskDigest !== undefined
      || input.guestStateDigest !== undefined || input.clusterStateDigest !== undefined
      || (parentMutationDisposition !== "NO_MUTATION_STARTED"
        && parentMutationDisposition !== "TASKS_TERMINAL")
      || (parentMutationDisposition === "NO_MUTATION_STARTED" && parentTaskEvidence.length !== 0)
      || (parentMutationDisposition === "TASKS_TERMINAL" && parentTaskEvidence.length === 0)) {
      throw new Error("legacy PVE recovery resolution terminal evidence is inconsistent");
    }
    return { ...common, parentMutationDisposition };
  }
  if (input.basis !== "local-unknown-clearance") {
    throw new Error("PVE recovery resolution has an unsupported basis");
  }
  const parentChangeId = parseChangeId(input.parentChangeId);
  if (!parentChangeId.startsWith("pve-change-") || parentChangeId === childChangeId
    || parentMutationDisposition !== "STARTED_OR_UNKNOWN" || parentTaskEvidence.length !== 0) {
    throw new Error("local PVE unknown-clearance resolution identity or disposition is invalid");
  }
  return {
    ...common,
    basis: "local-unknown-clearance",
    parentChangeId,
    resourceKey: requireString(input.resourceKey, "PVE recovery resolution.resourceKey", {
      pattern: /^pve\/vmid\/[1-9][0-9]{2,8}$/u,
    }),
    parentMutationDisposition: "STARTED_OR_UNKNOWN",
    clearanceObservationDigest: requireString(
      input.clearanceObservationDigest,
      "PVE recovery resolution.clearanceObservationDigest",
      { pattern: SHA256 },
    ),
    activeTaskDigest: requireString(input.activeTaskDigest, "PVE recovery resolution.activeTaskDigest", {
      pattern: SHA256,
    }),
    guestStateDigest: requireString(input.guestStateDigest, "PVE recovery resolution.guestStateDigest", {
      pattern: SHA256,
    }),
    clusterStateDigest: requireString(input.clusterStateDigest, "PVE recovery resolution.clusterStateDigest", {
      pattern: SHA256,
    }),
  };
}

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

export function parseChangeMetadata(value: unknown): {
  planHash: string;
  policyRevision: string;
  capabilityRevision: string;
  authorizationBasis?: string;
  authorizationScope?: string;
  authorizedAt?: string;
  kind: string;
  backupRefs: readonly string[];
  verification: string;
  rollbackAvailable: boolean;
  rollbackUnavailableReason?: string;
  lastError: string;
  recoveryOfChangeId?: ChangeId;
  resolution?: PVERecoveryResolution;
  pveMutationVersion?: 1;
  mutationDisposition?: "NO_MUTATION_STARTED" | "TASKS_TERMINAL" | "STARTED_OR_UNKNOWN";
  recoveryOnly: boolean;
  recoveryDescriptor?: RecoveryDescriptor;
  plan?: ApprovalPlan;
} {
  const input = requireExactRecord(value, "change metadata", [
    "serverId", "machineId", "targetId", "policyRevision", "capabilityRevision", "planHash", "kind",
    "backupRefs", "verification", "rollbackAvailable", "rollbackUnavailableReason", "lastError",
    "recoveryOnly", "recoveryDescriptor", "recoveryOfChangeId", "resolution",
    "pveMutationVersion", "mutationDisposition", "plan",
    "authorizationBasis", "authorizationScope", "authorizedAt",
  ]);
  const hasAuthorization = input.authorizationBasis !== undefined
    || input.authorizationScope !== undefined
    || input.authorizedAt !== undefined;
  let authorization: {
    authorizationBasis: string;
    authorizationScope?: string;
    authorizedAt: string;
  } | undefined;
  if (hasAuthorization) {
    const authorizationBasis = requireString(
      input.authorizationBasis,
      "change metadata.authorizationBasis",
      { min: 1, max: 256 },
    );
    if (authorizationBasis.includes("\0") || authorizationBasis.includes("\r")
      || authorizationBasis.includes("\n")) {
      throw new Error("change metadata.authorizationBasis contains a control delimiter");
    }
    const authorizationScope = input.authorizationScope === undefined
      ? undefined
      : requireString(
        input.authorizationScope,
        "change metadata.authorizationScope",
        { min: 1, max: 128, pattern: /^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*$/u },
      );
    const authorizedAt = requireString(input.authorizedAt, "change metadata.authorizedAt", {
      min: 20,
      max: 64,
      pattern: /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/u,
    });
    if (!Number.isFinite(Date.parse(authorizedAt))) {
      throw new Error("change metadata.authorizedAt is invalid");
    }
    authorization = {
      authorizationBasis,
      ...(authorizationScope === undefined ? {} : { authorizationScope }),
      authorizedAt,
    };
  }
  const kind = requireString(input.kind, "change metadata.kind", {
    max: 128,
    pattern: /^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*$/u,
  });
  const backupRefs = requireStringArray(input.backupRefs, "change metadata.backupRefs", 64);
  if (backupRefs.some((reference) => containsUnsafeControl(reference))) {
    throw new Error("change metadata.backupRefs contains an unsafe control character");
  }
  const verification = requireString(input.verification, "change metadata.verification", {
    min: 0,
    max: 8192,
  });
  if (typeof input.rollbackAvailable !== "boolean") {
    throw new Error("change metadata.rollbackAvailable must be a boolean");
  }
  const lastError = input.lastError === undefined
    ? ""
    : requireString(input.lastError, "change metadata.lastError", { min: 0, max: 8192 });
  if (typeof input.recoveryOnly !== "boolean") {
    throw new Error("change metadata.recoveryOnly must be a boolean");
  }
  const recoveryOfChangeId = input.recoveryOfChangeId === undefined
    ? undefined
    : parseChangeId(input.recoveryOfChangeId);
  if (recoveryOfChangeId !== undefined && !recoveryOfChangeId.startsWith("pve-change-")) {
    throw new Error("change metadata.recoveryOfChangeId is outside the PVE domain");
  }
  const resolution = input.resolution === undefined
    ? undefined
    : parsePVERecoveryResolution(input.resolution);
  if ((recoveryOfChangeId !== undefined || resolution !== undefined) && !kind.startsWith("pve.")) {
    throw new Error("only a PVE change may carry recovery-chain metadata");
  }
  const pveMutationVersion = input.pveMutationVersion === undefined
    ? undefined
    : input.pveMutationVersion;
  if (pveMutationVersion !== undefined && pveMutationVersion !== 1) {
    throw new Error("change metadata.pveMutationVersion is unsupported");
  }
  const mutationDisposition = input.mutationDisposition;
  if (mutationDisposition !== undefined
    && mutationDisposition !== "NO_MUTATION_STARTED"
    && mutationDisposition !== "TASKS_TERMINAL"
    && mutationDisposition !== "STARTED_OR_UNKNOWN") {
    throw new Error("change metadata.mutationDisposition is invalid");
  }
  if ((pveMutationVersion !== undefined || mutationDisposition !== undefined)
    && !kind.startsWith("pve.")) {
    throw new Error("only a PVE change may carry mutation reconciliation metadata");
  }
  if (resolution !== undefined
    && resolution.parentMutationDisposition !== mutationDisposition) {
    throw new Error("PVE recovery resolution does not bind the parent mutation disposition");
  }
  if (resolution !== undefined && resolution.parentTaskEvidence.some(
    (evidence) => !backupRefs.includes(`pve:task:${evidence.upid}`),
  )) {
    throw new Error("PVE recovery resolution task evidence is absent from authoritative backupRefs");
  }
  if (input.recoveryOnly && input.plan !== undefined) {
    throw new Error("recovery-only change must not contain a live ApprovalPlan");
  }
  const rollbackUnavailableReason = input.rollbackUnavailableReason === undefined
    ? undefined
    : requireString(
      input.rollbackUnavailableReason,
      "change metadata.rollbackUnavailableReason",
      { min: 1, max: 2048 },
    );
  if (rollbackUnavailableReason !== undefined && containsUnsafeControl(rollbackUnavailableReason)) {
    throw new Error("change metadata.rollbackUnavailableReason contains an unsafe control character");
  }
  let recoveryDescriptor: RecoveryDescriptor | undefined;
  if (input.recoveryOnly) {
    if (input.recoveryDescriptor === undefined) {
      throw new Error("recovery-only change must contain a signed recoveryDescriptor");
    }
    recoveryDescriptor = parseRecoveryDescriptor(input.recoveryDescriptor);
    if (recoveryDescriptor.originalKind !== kind
      || recoveryDescriptor.rollbackCompatible !== input.rollbackAvailable
      || recoveryDescriptor.unavailableReason !== rollbackUnavailableReason
      || recoveryDescriptor.backupObjects.length !== backupRefs.length
      || recoveryDescriptor.backupObjects.some(
        (object, index) => object.reference !== backupRefs[index],
      )) {
      throw new Error("recoveryDescriptor is not bound to the authoritative change metadata");
    }
  } else if (input.recoveryDescriptor !== undefined || rollbackUnavailableReason !== undefined) {
    throw new Error("live change must not contain legacy recovery metadata");
  }
  const plan = input.plan === undefined ? undefined : parseApprovalPlan(input.plan);
  let planRecoveryParent = "";
  if (plan !== undefined) {
    for (const step of plan.steps) {
      for (const field of step.fields) {
        if (field.name === "recoveryOfChangeId") {
          if (planRecoveryParent !== "" && planRecoveryParent !== field.value) {
            throw new Error("ApprovalPlan contains conflicting PVE recovery parents");
          }
          planRecoveryParent = field.value;
        }
      }
    }
  }
  if (planRecoveryParent !== (recoveryOfChangeId ?? "")) {
    throw new Error("PVE recovery parent does not match the canonical ApprovalPlan");
  }
  return {
    planHash: requireString(input.planHash, "change metadata.planHash", { pattern: SHA256 }),
    policyRevision: requireString(input.policyRevision, "change metadata.policyRevision", {
      min: 1,
      max: 160,
    }),
    capabilityRevision: requireString(
      input.capabilityRevision,
      "change metadata.capabilityRevision",
      { min: 1, max: 160 },
    ),
    kind,
    backupRefs,
    verification,
    rollbackAvailable: input.rollbackAvailable,
    ...(rollbackUnavailableReason === undefined ? {} : { rollbackUnavailableReason }),
    lastError,
    ...(recoveryOfChangeId === undefined ? {} : { recoveryOfChangeId }),
    ...(resolution === undefined ? {} : { resolution }),
    ...(pveMutationVersion === undefined ? {} : { pveMutationVersion }),
    ...(mutationDisposition === undefined ? {} : { mutationDisposition }),
    recoveryOnly: input.recoveryOnly,
    ...(recoveryDescriptor === undefined ? {} : { recoveryDescriptor }),
    ...(authorization === undefined ? {} : authorization),
    ...(plan === undefined ? {} : { plan }),
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
    capabilityRevision: grant.capabilityRevision,
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
  capabilityRevision: string;
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
    capabilityRevision: requireString(
      options.capabilityRevision,
      "approval capabilityRevision",
      { min: 1, max: 160 },
    ),
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
