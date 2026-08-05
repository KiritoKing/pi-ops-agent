import {
  isRecord,
  optionalString,
  requireRecord,
  requireString,
} from "./guards.js";

const SESSION_ID = /^[a-zA-Z0-9._:-]{8,160}$/;
const CHANGE_ID = /^[a-zA-Z0-9._-]{8,160}$/;

export type AgentClientMessage =
  | {
      type: "hello";
      sessionId: string;
      initialPrompt?: string;
    }
  | { type: "prompt"; text: string }
  | { type: "abort" }
  | { type: "ping" };

export type AgentServerMessage =
  | { type: "ready"; sessionId: string }
  | { type: "status"; state: "idle" | "working"; route?: string }
  | { type: "delta"; text: string }
  | { type: "tool"; phase: "start" | "end"; name: string; isError?: boolean }
  | { type: "done" }
  | { type: "error"; message: string }
  | { type: "pong" };

export type RootOperation =
  | { kind: "package.install"; package: string; version?: string }
  | {
      kind: "service.action";
      unit: string;
      action: "restart" | "reload" | "start" | "stop";
    }
  | {
      kind: "file.write";
      path: string;
      content: string;
      mode?: string;
    }
  | {
      kind: "breakglass.script";
      script: string;
      backupPaths: string[];
      verifyScript?: string;
      network: boolean;
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
  const input = requireRecord(value, "agent message");
  const type = requireString(input.type, "agent message.type", { max: 32 });
  switch (type) {
    case "hello": {
      const sessionId = requireString(input.sessionId, "sessionId", {
        max: 160,
        pattern: SESSION_ID,
      });
      const initialPrompt = optionalString(input.initialPrompt, "initialPrompt", {
        max: 64 * 1024,
      });
      return initialPrompt === undefined
        ? { type, sessionId }
        : { type, sessionId, initialPrompt };
    }
    case "prompt":
      return {
        type,
        text: requireString(input.text, "prompt.text", { max: 64 * 1024 }),
      };
    case "abort":
    case "ping":
      return { type };
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
  return requireString(value, "changeId", { max: 160, pattern: CHANGE_ID });
}

export function isAgentServerMessage(value: unknown): value is AgentServerMessage {
  return isRecord(value) && typeof value.type === "string";
}
