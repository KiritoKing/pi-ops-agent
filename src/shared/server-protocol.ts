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
import {
  requireInteger,
  requireString,
  requireStringArray,
} from "./guards.js";
import type { RootOperation } from "./messages.js";
import type { ApprovalAction, ApprovalGrant } from "./approval.js";
import { requireExactRecord } from "./strict.js";
import { parseBrokerReceipt, type BrokerReceipt } from "./broker-receipt.js";

export const REMOTE_CAPABILITIES = [
  "host.snapshot",
  "process.list",
  "systemd.unit",
  "journal.tail",
  "file.metadata",
  "file.read",
  "workload.command.inspect",
  "pve.cluster.status",
  "pve.node.status",
  "pve.storage.status",
  "pve.task.status",
  "pve.guest.status",
  "breakglass.prepare",
  "change.prepare",
  "change.status",
  "plugin.install",
  "plugin.register",
  "workload.deploy",
] as const;

export type RemoteCapability = (typeof REMOTE_CAPABILITIES)[number];

export interface ServerIdentity {
  serverId: ServerId;
  machineId: MachineId;
  machineName: string;
  account: string;
  protocolVersion: 1;
}

export type ArtifactKind = "im-adapter" | "managed-workload";

export interface ArtifactDescriptor {
  id: string;
  kind: ArtifactKind;
  version: string;
  publisher: string;
  digest: string;
  artifactRef: string;
}

export interface TargetDescriptor {
  targetId: TargetId;
  account: string;
  displayName: string;
  artifacts: ArtifactDescriptor[];
}

export interface CapabilityDescriptor {
  revision: string;
  policyRevision: string;
  operations: RemoteCapability[];
}

export interface RemoteResponse {
  version: 1;
  requestId: string;
  ok: boolean;
  auditId?: string;
  changeId?: ChangeId;
  state?: string;
  summary?: string;
  data?: unknown;
  error?: string;
  brokerReceipt?: BrokerReceipt;
}

export type InspectionRequest =
  | {
      version: 1;
      requestId: string;
      deadline: string;
      machineId: MachineId;
      targetId: TargetId;
      method: "host.snapshot" | "process.list";
    }
  | {
      version: 1;
      requestId: string;
      deadline: string;
      machineId: MachineId;
      targetId: TargetId;
      method: "systemd.unit";
      unit: string;
    }
  | {
      version: 1;
      requestId: string;
      deadline: string;
      machineId: MachineId;
      targetId: TargetId;
      method: "journal.tail";
      unit: string;
      lines?: number;
    }
  | {
      version: 1;
      requestId: string;
      deadline: string;
      machineId: MachineId;
      targetId: TargetId;
      method: "file.metadata";
      path: string;
    }
  | {
      version: 1;
      requestId: string;
      deadline: string;
      machineId: MachineId;
      targetId: TargetId;
      method: "file.read";
      path: string;
      maxBytes?: number;
    }
  | {
      version: 1;
      requestId: string;
      deadline: string;
      machineId: MachineId;
      targetId: TargetId;
      method: "pve.cluster.status";
      pluginId: string;
      pluginDigest: string;
    }
  | {
      version: 1;
      requestId: string;
      deadline: string;
      machineId: MachineId;
      targetId: TargetId;
      method: "pve.node.status";
      pluginId: string;
      pluginDigest: string;
      node: string;
    }
  | {
      version: 1;
      requestId: string;
      deadline: string;
      machineId: MachineId;
      targetId: TargetId;
      method: "pve.storage.status";
      pluginId: string;
      pluginDigest: string;
      node: string;
      storage: string;
    }
  | {
      version: 1;
      requestId: string;
      deadline: string;
      machineId: MachineId;
      targetId: TargetId;
      method: "pve.task.status";
      pluginId: string;
      pluginDigest: string;
      node: string;
      upid: string;
    }
  | {
      version: 1;
      requestId: string;
      deadline: string;
      machineId: MachineId;
      targetId: TargetId;
      method: "pve.guest.status";
      pluginId: string;
      pluginDigest: string;
      node: string;
      guestType: "qemu" | "lxc";
      vmid: number;
    };

export interface WorkloadCommandInspectionRequest {
  version: 1;
  requestId: string;
  deadline: string;
  machineId: MachineId;
  targetId: TargetId;
  method: "workload.command.inspect";
  pluginId: string;
  pluginDigest: string;
  profileKey: string;
}

export interface PrepareChangeRequest {
  version: 1;
  requestId: string;
  deadline: string;
  machineId: MachineId;
  targetId: TargetId;
  method: "change.prepare";
  operation: RootOperation;
  policyRevision: string;
  capabilityRevision: string;
}

export interface ChangeStatusRequest {
  version: 1;
  requestId: string;
  deadline: string;
  machineId: MachineId;
  targetId: TargetId;
  method: "change.status";
  changeId: ChangeId;
}

export interface ChangeActionRequest {
  version: 1;
  requestId: string;
  deadline: string;
  machineId: MachineId;
  targetId: TargetId;
  action: ApprovalAction;
  changeId: ChangeId;
  approval: ApprovalGrant;
}

function parseCapability(value: unknown, label: string): RemoteCapability {
  const capability = requireString(value, label, { max: 64 });
  if (!(REMOTE_CAPABILITIES as readonly string[]).includes(capability)) {
    throw new Error(`${label} is not a recognized capability`);
  }
  return capability as RemoteCapability;
}

export function parseServerIdentity(value: unknown): ServerIdentity {
  const input = requireExactRecord(value, "server identity", [
    "serverId", "machineId", "machineName", "account", "protocolVersion",
  ]);
  if (input.protocolVersion !== 1) throw new Error("unsupported server protocol version");
  return {
    serverId: parseServerId(input.serverId, "server identity.serverId"),
    machineId: parseMachineId(input.machineId, "server identity.machineId"),
    machineName: requireString(input.machineName, "server identity.machineName", { max: 256 }),
    account: requireString(input.account, "server identity.account", { max: 128 }),
    protocolVersion: 1,
  };
}

export function parseTargetDescriptors(value: unknown): TargetDescriptor[] {
  if (!Array.isArray(value) || value.length > 256) {
    throw new Error("server targets must be an array with at most 256 items");
  }
  const targetIds = new Set<string>();
  return value.map((item, index) => {
    const input = requireExactRecord(item, `server targets[${index}]`, [
      "targetId", "account", "displayName", "artifacts",
    ]);
    const targetId = parseTargetId(input.targetId, `server targets[${index}].targetId`);
    if (targetIds.has(targetId)) throw new Error(`duplicate targetId: ${targetId}`);
    targetIds.add(targetId);
    return {
      targetId,
      account: requireString(input.account, `server targets[${index}].account`, { max: 128 }),
      displayName: requireString(input.displayName, `server targets[${index}].displayName`, {
        max: 256,
      }),
      artifacts: parseArtifacts(input.artifacts, `server targets[${index}].artifacts`),
    };
  });
}

export function parseCapabilityDescriptor(value: unknown): CapabilityDescriptor {
  const input = requireExactRecord(value, "server capabilities", [
    "revision", "policyRevision", "operations",
  ]);
  const rawOperations = requireStringArray(input.operations, "server capabilities.operations", 64);
  const operations = rawOperations.map((item, index) =>
    parseCapability(item, `server capabilities.operations[${index}]`));
  if (new Set(operations).size !== operations.length) {
    throw new Error("server capabilities.operations contains duplicates");
  }
  return {
    revision: requireString(input.revision, "server capabilities.revision", { max: 160 }),
    policyRevision: requireString(input.policyRevision, "server capabilities.policyRevision", {
      max: 160,
    }),
    operations,
  };
}

export function parseArtifactCatalog(value: unknown): ArtifactDescriptor[] {
  return parseArtifacts(value, "artifact catalog");
}

function parseArtifacts(value: unknown, label: string): ArtifactDescriptor[] {
  if (!Array.isArray(value) || value.length > 128) {
    throw new Error(`${label} must contain at most 128 entries`);
  }
  const identities = new Set<string>();
  return value.map((item, index) => {
    const itemLabel = `${label}[${index}]`;
    const input = requireExactRecord(item, itemLabel, [
      "id", "kind", "version", "publisher", "digest", "artifactRef",
    ]);
    const kind = requireString(input.kind, `${itemLabel}.kind`, { max: 32 });
    if (kind !== "im-adapter" && kind !== "managed-workload") {
      throw new Error(`${itemLabel}.kind is not supported`);
    }
    const digest = requireString(input.digest, `${itemLabel}.digest`, {
      pattern: /^sha256:[a-f0-9]{64}$/u,
    });
    const artifactRef = requireString(input.artifactRef, `${itemLabel}.artifactRef`, {
      pattern: /^builtin:sha256:[a-f0-9]{64}$/u,
    });
    if (artifactRef !== `builtin:${digest}`) {
      throw new Error(`${itemLabel}.artifactRef does not match digest`);
    }
    const artifact: ArtifactDescriptor = {
      id: requireString(input.id, `${itemLabel}.id`, {
        pattern: /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/u,
      }),
      kind,
      version: requireString(input.version, `${itemLabel}.version`, {
        pattern: /^[a-zA-Z0-9][a-zA-Z0-9+.:~_-]{0,127}$/u,
      }),
      publisher: requireString(input.publisher, `${itemLabel}.publisher`, {
        pattern: /^[a-zA-Z0-9][a-zA-Z0-9._/@:-]{0,159}$/u,
      }),
      digest,
      artifactRef,
    };
    const identity = [artifact.kind, artifact.id, artifact.version, artifact.publisher, artifact.digest]
      .join("\0");
    if (identities.has(identity)) throw new Error(`${label} contains a duplicate artifact`);
    identities.add(identity);
    return artifact;
  });
}

export function parseRemoteResponse(value: unknown): RemoteResponse {
  const input = requireExactRecord(value, "server response", [
    "version", "requestId", "ok", "auditId", "changeId", "state", "summary", "data", "error",
    "brokerReceipt",
  ]);
  if (input.version !== 1 || typeof input.ok !== "boolean") {
    throw new Error("server response has an unsupported version or status");
  }
  const response: RemoteResponse = {
    version: 1,
    requestId: requireString(input.requestId, "server response.requestId", { max: 160 }),
    ok: input.ok,
  };
  if (input.auditId !== undefined) {
    response.auditId = requireString(input.auditId, "server response.auditId", { max: 160 });
  }
  if (input.changeId !== undefined) {
    response.changeId = parseChangeId(input.changeId, "server response.changeId");
  }
  if (input.state !== undefined) {
    response.state = requireString(input.state, "server response.state", { max: 64 });
  }
  if (input.summary !== undefined) {
    response.summary = requireString(input.summary, "server response.summary", {
      min: 0,
      max: 64 * 1024,
    });
  }
  if (Object.hasOwn(input, "data")) response.data = input.data;
  if (input.error !== undefined) {
    response.error = requireString(input.error, "server response.error", {
      min: 0,
      max: 16 * 1024,
    });
  }
  if (input.brokerReceipt !== undefined) {
    response.brokerReceipt = parseBrokerReceipt(input.brokerReceipt);
  }
  return response;
}

export function parseLines(value: unknown): number | undefined {
  return value === undefined ? undefined : requireInteger(value, "lines", 1, 200);
}
