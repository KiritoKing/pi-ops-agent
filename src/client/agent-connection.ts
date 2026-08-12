import { createConnection, type Socket } from "node:net";
import { randomUUID } from "node:crypto";
import {
  optionalString,
  requireRecord,
  requireString,
  requireStringArray,
} from "../shared/guards.js";
import {
  parseMachineId,
  parseSessionId,
  parseTargetId,
  parseTurnId,
  type TurnId,
} from "../shared/domain.js";
import { requireExactRecord } from "../shared/strict.js";
import { encodeChangeRef, parseChangeRef } from "../shared/approval.js";
import { encodeFrame, FrameDecoder } from "../shared/framing.js";
import type {
  AgentClientMessage,
  AgentServerMessage,
} from "../shared/messages.js";

export interface AgentConnectionHandlers {
  onMessage(message: AgentServerMessage): void;
  onError(error: Error): void;
  onClose(): void;
}

function parseAgentServerMessage(value: unknown): AgentServerMessage {
  const base = requireRecord(value, "agent response");
  const type = requireString(base.type, "agent response.type", { max: 32 });
  const correlation = (input: Record<string, unknown>) => {
    const machineId = optionalString(input.machineId, "agent response.machineId", { max: 160 });
    const targetId = optionalString(input.targetId, "agent response.targetId", { max: 160 });
    return {
      sessionId: parseSessionId(input.sessionId, "agent response.sessionId"),
      turnId: parseTurnId(input.turnId, "agent response.turnId"),
      ...(machineId === undefined ? {} : { machineId: parseMachineId(machineId) }),
      ...(targetId === undefined ? {} : { targetId: parseTargetId(targetId) }),
    };
  };
  switch (type) {
    case "ready": {
      const input = requireExactRecord(base, "agent ready response", ["type", "sessionId"]);
      return {
        type,
        sessionId: parseSessionId(input.sessionId, "agent response.sessionId"),
      };
    }
    case "status": {
      const input = requireExactRecord(base, "agent status response", [
        "type", "state", "route", "sessionId", "turnId", "machineId", "targetId",
      ]);
      const state = requireString(input.state, "agent response.state", { max: 16 });
      if (state !== "idle" && state !== "working") {
        throw new Error(`unsupported agent status: ${state}`);
      }
      const route = optionalString(input.route, "agent response.route", { max: 512 });
      return route === undefined
        ? { type, state, ...correlation(input) }
        : { type, state, route, ...correlation(input) };
    }
    case "delta": {
      const input = requireExactRecord(base, "agent delta response", [
        "type", "text", "sessionId", "turnId", "machineId", "targetId",
      ]);
      return {
        type,
        text: requireString(input.text, "agent response.text", { min: 0, max: 256 * 1024 }),
        ...correlation(input),
      };
    }
    case "tool": {
      const input = requireExactRecord(base, "agent tool response", [
        "type", "phase", "name", "isError", "preparedChangeRefs",
        "sessionId", "turnId", "machineId", "targetId",
      ]);
      const phase = requireString(input.phase, "agent response.phase", { max: 16 });
      if (phase !== "start" && phase !== "end") {
        throw new Error(`unsupported tool phase: ${phase}`);
      }
      if (input.isError !== undefined && typeof input.isError !== "boolean") {
        throw new Error("agent response.isError must be a boolean");
      }
      const preparedChangeRefs = input.preparedChangeRefs === undefined
        ? undefined
        : requireStringArray(
          input.preparedChangeRefs,
          "agent response.preparedChangeRefs",
          32,
        ).map((reference, index) => {
          const parsed = parseChangeRef(reference);
          if (encodeChangeRef(parsed) !== reference) {
            throw new Error(`agent response.preparedChangeRefs[${index}] is not canonical`);
          }
          return reference;
        });
      if (phase === "start" && preparedChangeRefs !== undefined) {
        throw new Error("agent tool start cannot report prepared changes");
      }
      if (preparedChangeRefs?.length === 0) {
        throw new Error("agent tool end preparedChangeRefs cannot be empty");
      }
      const message: AgentServerMessage = {
        type,
        phase,
        name: requireString(input.name, "agent response.name", { max: 256 }),
        ...correlation(input),
      };
      return {
        ...message,
        ...(input.isError === undefined ? {} : { isError: input.isError }),
        ...(preparedChangeRefs === undefined ? {} : { preparedChangeRefs }),
      };
    }
    case "error": {
      const input = requireExactRecord(base, "agent error response", [
        "type", "message", "sessionId", "turnId", "machineId", "targetId",
      ]);
      const sessionId = optionalString(input.sessionId, "agent response.sessionId", { max: 160 });
      const turnId = optionalString(input.turnId, "agent response.turnId", { max: 160 });
      const machineId = optionalString(input.machineId, "agent response.machineId", { max: 160 });
      const targetId = optionalString(input.targetId, "agent response.targetId", { max: 160 });
      return {
        type,
        message: requireString(input.message, "agent response.message", { max: 64 * 1024 }),
        ...(sessionId === undefined ? {} : { sessionId: parseSessionId(sessionId) }),
        ...(turnId === undefined ? {} : { turnId: parseTurnId(turnId) }),
        ...(machineId === undefined ? {} : { machineId: parseMachineId(machineId) }),
        ...(targetId === undefined ? {} : { targetId: parseTargetId(targetId) }),
      };
    }
    case "done": {
      const input = requireExactRecord(base, "agent done response", [
        "type", "sessionId", "turnId", "machineId", "targetId",
      ]);
      return { type, ...correlation(input) };
    }
    case "pong":
      requireExactRecord(base, "agent pong response", ["type"]);
      return { type };
    default:
      throw new Error(`unsupported agent response type: ${type}`);
  }
}

export interface AgentTransport {
  sendPrompt(text: string): TurnId;
  abort(): void;
  close(): void;
}

export class AgentConnection implements AgentTransport {
  readonly #socket: Socket;

  private constructor(socket: Socket) {
    this.#socket = socket;
  }

  static async connect(
    socketPath: string,
    hello: Extract<AgentClientMessage, { type: "hello" }>,
    handlers: AgentConnectionHandlers,
  ): Promise<AgentConnection> {
    return await new Promise<AgentConnection>((resolve, reject) => {
      const socket = createConnection(socketPath);
      const decoder = new FrameDecoder();
      let connected = false;
      let reportedClose = false;
      const reportClose = (): void => {
        if (reportedClose) return;
        reportedClose = true;
        handlers.onClose();
      };
      socket.once("connect", () => {
        connected = true;
        socket.write(encodeFrame(hello));
        resolve(new AgentConnection(socket));
      });
      socket.on("data", (chunk) => {
        try {
          const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
          for (const frame of decoder.push(bytes)) {
            handlers.onMessage(parseAgentServerMessage(frame));
          }
        } catch (error) {
          const parsed = error instanceof Error ? error : new Error(String(error));
          handlers.onError(parsed);
          socket.destroy();
        }
      });
      socket.once("error", (error) => {
        if (!connected) reject(error);
        else handlers.onError(error);
      });
      socket.once("close", reportClose);
    });
  }

  sendPrompt(text: string): TurnId {
    const turnId = parseTurnId(randomUUID());
    this.#send({ type: "prompt", turnId, text });
    return turnId;
  }

  abort(): void {
    this.#send({ type: "abort" });
  }

  close(): void {
    this.#socket.end();
  }

  #send(message: AgentClientMessage): void {
    if (this.#socket.destroyed || !this.#socket.writable) {
      throw new Error("agentd connection is closed");
    }
    this.#socket.write(encodeFrame(message));
  }
}
