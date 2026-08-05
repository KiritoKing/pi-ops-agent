import { createConnection, type Socket } from "node:net";
import {
  optionalString,
  requireRecord,
  requireString,
} from "../shared/guards.js";
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
  const input = requireRecord(value, "agent response");
  const type = requireString(input.type, "agent response.type", { max: 32 });
  switch (type) {
    case "ready":
      return {
        type,
        sessionId: requireString(input.sessionId, "agent response.sessionId", { max: 160 }),
      };
    case "status": {
      const state = requireString(input.state, "agent response.state", { max: 16 });
      if (state !== "idle" && state !== "working") {
        throw new Error(`unsupported agent status: ${state}`);
      }
      const route = optionalString(input.route, "agent response.route", { max: 512 });
      return route === undefined ? { type, state } : { type, state, route };
    }
    case "delta":
      return {
        type,
        text: requireString(input.text, "agent response.text", { min: 0, max: 256 * 1024 }),
      };
    case "tool": {
      const phase = requireString(input.phase, "agent response.phase", { max: 16 });
      if (phase !== "start" && phase !== "end") {
        throw new Error(`unsupported tool phase: ${phase}`);
      }
      if (input.isError !== undefined && typeof input.isError !== "boolean") {
        throw new Error("agent response.isError must be a boolean");
      }
      const message: AgentServerMessage = {
        type,
        phase,
        name: requireString(input.name, "agent response.name", { max: 256 }),
      };
      return input.isError === undefined ? message : { ...message, isError: input.isError };
    }
    case "error":
      return {
        type,
        message: requireString(input.message, "agent response.message", { max: 64 * 1024 }),
      };
    case "done":
    case "pong":
      return { type };
    default:
      throw new Error(`unsupported agent response type: ${type}`);
  }
}

export interface AgentTransport {
  sendPrompt(text: string): void;
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

  sendPrompt(text: string): void {
    this.#send({ type: "prompt", text });
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
