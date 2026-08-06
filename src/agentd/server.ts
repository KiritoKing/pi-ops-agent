import { chmod, lstat, mkdir, unlink } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { createServer, type Socket } from "node:net";
import { dirname } from "node:path";
import type { AgentConfig } from "../shared/config.js";
import { parseTurnId, type SessionId, type TurnId } from "../shared/domain.js";
import { encodeFrame, FrameDecoder } from "../shared/framing.js";
import { parseAgentClientMessage, type AgentServerMessage } from "../shared/messages.js";
import { callHelper, deadline, requestId } from "../shared/rpc.js";
import type { AuditLog } from "./audit.js";
import type { OpsSession, SessionFactory } from "./session.js";

async function removeStaleSocket(path: string): Promise<void> {
  try {
    const stat = await lstat(path);
    if (!stat.isSocket()) throw new Error(`refusing to replace non-socket path: ${path}`);
    await unlink(path);
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") return;
    throw error;
  }
}

export class AgentServer {
  readonly #config: AgentConfig;
  readonly #sessions: SessionFactory;
  readonly #audit: AuditLog;
  readonly #server = createServer();
  #heartbeat?: NodeJS.Timeout;

  constructor(config: AgentConfig, sessions: SessionFactory, audit: AuditLog) {
    this.#config = config;
    this.#sessions = sessions;
    this.#audit = audit;
  }

  async start(): Promise<void> {
    await mkdir(dirname(this.#config.socketPath), { recursive: true, mode: 0o750 });
    await removeStaleSocket(this.#config.socketPath);
    this.#server.on("connection", (socket) => this.#handleConnection(socket));
    await new Promise<void>((resolve, reject) => {
      this.#server.once("error", reject);
      this.#server.listen(this.#config.socketPath, () => {
        this.#server.off("error", reject);
        resolve();
      });
    });
    await chmod(this.#config.socketPath, 0o660);
    this.#heartbeat = setInterval(() => void this.#sendHeartbeat(), 10_000);
    this.#heartbeat.unref();
    await this.#audit.append({ type: "agentd_started", socket: this.#config.socketPath });
  }

  async stop(): Promise<void> {
    if (this.#heartbeat) clearInterval(this.#heartbeat);
    await new Promise<void>((resolve) => this.#server.close(() => resolve()));
    await unlink(this.#config.socketPath).catch(() => undefined);
    await this.#audit.append({ type: "agentd_stopped" });
  }

  #handleConnection(socket: Socket): void {
    const decoder = new FrameDecoder();
    let session: OpsSession | undefined;
    let sessionId: SessionId | undefined;
    let activeTurnId: TurnId | undefined;
    let queue = Promise.resolve();
    const emit = (message: AgentServerMessage): void => {
      if (!socket.destroyed) socket.write(encodeFrame(message));
    };
    const cleanup = (): void => {
      if (session) {
        void session.abort().catch(() => undefined).finally(() => session?.dispose());
        session = undefined;
      }
    };

    socket.on("data", (chunk) => {
      try {
        const bytes = typeof chunk === "string" ? Buffer.from(chunk) : chunk;
        for (const frame of decoder.push(bytes)) {
          queue = queue
            .then(async () => {
              const message = parseAgentClientMessage(frame);
              if (message.type === "hello") {
                if (session) throw new Error("hello already received");
                sessionId = message.sessionId;
                session = await this.#sessions.open(message.sessionId, emit);
                emit({ type: "ready", sessionId: message.sessionId });
                if (message.initialPrompt) {
                  activeTurnId = parseTurnId(randomUUID());
                  await session.prompt(message.initialPrompt, activeTurnId);
                  activeTurnId = undefined;
                }
                return;
              }
              if (!session) throw new Error("hello must be the first message");
              if (message.type === "prompt") {
                activeTurnId = message.turnId;
                await session.prompt(message.text, message.turnId);
                activeTurnId = undefined;
              }
              else if (message.type === "abort") await session.abort();
              else emit({ type: "pong" });
            })
            .catch((error: unknown) => {
              const message = error instanceof Error ? error.message : String(error);
              emit({
                type: "error",
                message,
                ...(sessionId === undefined ? {} : { sessionId }),
                ...(activeTurnId === undefined ? {} : { turnId: activeTurnId }),
              });
              void this.#audit.append({ type: "connection_error", message });
            });
        }
      } catch (error) {
        emit({ type: "error", message: error instanceof Error ? error.message : String(error) });
        socket.destroy();
      }
    });
    socket.once("error", cleanup);
    socket.once("close", cleanup);
  }

  async #sendHeartbeat(): Promise<void> {
    const request = {
      version: 1 as const,
      requestId: requestId(),
      deadline: deadline(5),
      method: "heartbeat" as const,
    };
    try {
      await callHelper(this.#config.systemdHelperSocket, request, undefined, 5000);
    } catch (error) {
      await this.#audit.append({
        type: "heartbeat_failed",
        message: error instanceof Error ? error.message : String(error),
      });
    }
  }
}
