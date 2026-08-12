import {
  isRecord,
  optionalString,
  requireRecord,
  requireString,
} from "./guards.js";
import {
  parseChangeId as parseDomainChangeId,
  parseSessionId,
  parseTurnId,
  type MachineId,
  type SessionId,
  type TargetId,
  type TurnId,
} from "./domain.js";
import { requireExactRecord } from "./strict.js";

export const AGENT_CLIENT_PEER_API_VERSION = "agentd.client-peer/v1" as const;

export interface AgentClientPeerIdentity {
  apiVersion: typeof AGENT_CLIENT_PEER_API_VERSION;
  adapterId: string;
  digest: string;
}

export type AgentClientMessage =
  | {
      type: "hello";
      sessionId: SessionId;
      peer: AgentClientPeerIdentity;
      initialPrompt?: string;
    }
  | { type: "prompt"; turnId: TurnId; text: string }
  | { type: "abort" }
  | { type: "ping" };

interface AgentCorrelation {
  sessionId: SessionId;
  turnId: TurnId;
  machineId?: MachineId;
  targetId?: TargetId;
}

export type AgentServerMessage =
  | { type: "ready"; sessionId: SessionId }
  | ({ type: "status"; state: "idle" | "working"; route?: string } & AgentCorrelation)
  | ({ type: "delta"; text: string } & AgentCorrelation)
  | ({
      type: "tool";
      phase: "start" | "end";
      name: string;
      isError?: boolean;
      preparedChangeRefs?: readonly string[];
    } & AgentCorrelation)
  | ({ type: "done" } & AgentCorrelation)
  | ({ type: "error"; message: string } & Partial<AgentCorrelation>)
  | { type: "pong" };

export type RootOperation =
  | { kind: "package.install"; package: string; version?: string }
  | {
      kind: "service.action";
      pluginId: "workload.base";
      pluginDigest: string;
      unit: string;
      action: "restart" | "reload" | "start" | "stop";
    }
  | {
      kind: "workload.service.action";
      pluginId: string;
      pluginDigest: string;
      account: string;
      manager: "system" | "user";
      unit: string;
      action: "reload" | "reset-failed" | "restart" | "start" | "stop";
    }
  | {
      kind: "workload.json-config.edit";
      pluginId: string;
      sourceDigest: string;
      profileKey: string;
      selectorValue: string;
      fieldKey: string;
      value:
        | { kind: "string"; stringValue: string }
        | { kind: "boolean"; booleanValue: boolean }
        | { kind: "clear" };
    }
  | {
      kind: "file.write";
      pluginId: "workload.base";
      pluginDigest: string;
      path: string;
      content: string;
      mode?: string;
    }
  | {
      kind: "plugin.install";
      pluginId: string;
      version: string;
      publisher: string;
      digest: string;
      artifactRef: string;
    }
  | {
      kind: "plugin.register";
      pluginId: string;
      pluginKind: "adapter" | "workload";
      version: string;
      publisher: string;
      digest: string;
      capabilities: string[];
      requestedScopes: string[];
    }
  | {
      kind: "workload.deploy";
      pluginId: string;
      version: string;
      publisher: string;
      digest: string;
      artifactRef: string;
    }
  | {
      kind: "breakglass.script";
      script: string;
      backupPaths: string[];
      verifyScript?: string;
      network: boolean;
    }
  | {
      kind: "pve.guest.action";
      pluginId: string;
      pluginDigest: string;
      recoveryOfChangeId?: string;
      node: string;
      guestType: "qemu" | "lxc";
      vmid: number;
      action: "start" | "shutdown" | "stop" | "reboot";
    }
  | {
      kind: "pve.snapshot.create";
      pluginId: string;
      pluginDigest: string;
      recoveryOfChangeId?: string;
      node: string;
      guestType: "qemu" | "lxc";
      vmid: number;
      snapshot: string;
      description?: string;
    }
  | {
      kind: "pve.snapshot.delete" | "pve.snapshot.rollback";
      pluginId: string;
      pluginDigest: string;
      recoveryOfChangeId?: string;
      node: string;
      guestType: "qemu" | "lxc";
      vmid: number;
      snapshot: string;
      backupStorage: string;
    }
  | {
      kind: "pve.guest.backup";
      pluginId: string;
      pluginDigest: string;
      recoveryOfChangeId?: string;
      node: string;
      guestType: "qemu" | "lxc";
      vmid: number;
      storage: string;
    }
  | {
      kind: "pve.guest.restore";
      pluginId: string;
      pluginDigest: string;
      recoveryOfChangeId?: string;
      node: string;
      guestType: "qemu" | "lxc";
      vmid: number;
      backupVolume: string;
      storage: string;
    }
  | {
      kind: "pve.guest.migrate";
      pluginId: string;
      pluginDigest: string;
      recoveryOfChangeId?: string;
      node: string;
      guestType: "qemu" | "lxc";
      vmid: number;
      targetNode: string;
      online: boolean;
      restart: boolean;
      withLocalDisks: boolean;
    };

export type HelperRequest =
  | {
      version: 1;
      requestId: string;
      deadline: string;
      method: "change.prepare";
      operation: RootOperation;
    }
  | {
      version: 1;
      requestId: string;
      deadline: string;
      method: "change.status" | "change.approve" | "change.reject" | "change.rollback";
      changeId: string;
    }
  | {
      version: 1;
      requestId: string;
      deadline: string;
      method: "host.snapshot";
    }
  | {
      version: 1;
      requestId: string;
      deadline: string;
      method: "systemd.unit" | "journal.tail";
      unit: string;
      lines?: number;
    }
  | {
      version: 1;
      requestId: string;
      deadline: string;
      method: "heartbeat";
    };

export interface HelperResponse {
  version: 1;
  requestId: string;
  ok: boolean;
  auditId?: string;
  changeId?: string;
  state?: string;
  summary?: string;
  data?: unknown;
  error?: string;
}

export function parseAgentClientMessage(value: unknown): AgentClientMessage {
  const base = requireRecord(value, "agent message");
  const type = requireString(base.type, "agent message.type", { max: 32 });
  switch (type) {
    case "hello": {
      const input = requireExactRecord(base, "agent hello", [
        "type", "sessionId", "peer", "initialPrompt",
      ]);
      const sessionId = parseSessionId(input.sessionId);
      const peer = requireExactRecord(input.peer, "agent hello.peer", [
        "apiVersion", "adapterId", "digest",
      ]);
      if (peer.apiVersion !== AGENT_CLIENT_PEER_API_VERSION) {
        throw new Error("agent hello.peer has an unsupported API version");
      }
      const parsedPeer: AgentClientPeerIdentity = {
        apiVersion: AGENT_CLIENT_PEER_API_VERSION,
        adapterId: requireString(peer.adapterId, "agent hello.peer.adapterId", {
          max: 72,
          pattern: /^adapter\.[a-z0-9][a-z0-9.-]{0,63}$/u,
        }),
        digest: requireString(peer.digest, "agent hello.peer.digest", {
          pattern: /^sha256:[a-f0-9]{64}$/u,
        }),
      };
      const initialPrompt = optionalString(input.initialPrompt, "initialPrompt", {
        max: 64 * 1024,
      });
      return initialPrompt === undefined
        ? { type, sessionId, peer: parsedPeer }
        : { type, sessionId, peer: parsedPeer, initialPrompt };
    }
    case "prompt": {
      const input = requireExactRecord(base, "agent prompt", ["type", "turnId", "text"]);
      return {
        type,
        turnId: parseTurnId(input.turnId),
        text: requireString(input.text, "prompt.text", { max: 64 * 1024 }),
      };
    }
    case "abort":
    case "ping": {
      requireExactRecord(base, `agent ${type}`, ["type"]);
      return { type };
    }
    default:
      throw new Error(`unsupported agent message type: ${type}`);
  }
}

export function parseHelperResponse(value: unknown): HelperResponse {
  const input = requireRecord(value, "helper response");
  if (input.version !== 1 || typeof input.ok !== "boolean") {
    throw new Error("helper response has an unsupported version or status");
  }
  const response: HelperResponse = {
    version: 1,
    requestId: requireString(input.requestId, "requestId", { max: 160 }),
    ok: input.ok,
  };
  const fields = ["auditId", "changeId", "state", "summary", "error"] as const;
  for (const field of fields) {
    if (input[field] !== undefined) {
      const text = requireString(input[field], field, { min: 0, max: 64 * 1024 });
      Object.assign(response, { [field]: text });
    }
  }
  if (Object.hasOwn(input, "data")) {
    response.data = input.data;
  }
  return response;
}

export function parseChangeId(value: unknown): string {
  return parseDomainChangeId(value);
}

export function isAgentServerMessage(value: unknown): value is AgentServerMessage {
  return isRecord(value) && typeof value.type === "string";
}
