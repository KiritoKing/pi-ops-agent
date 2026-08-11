import { chmod, lstat, mkdir, unlink } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { createServer, type Socket } from "node:net";
import { dirname } from "node:path";
import type { AgentConfig } from "../shared/config.js";
import { parseTurnId, type SessionId, type TurnId } from "../shared/domain.js";
import { encodeFrame, FrameDecoder } from "../shared/framing.js";
import { parseAgentClientMessage, type AgentServerMessage } from "../shared/messages.js";
import { redactText } from "../shared/redaction.js";
import type { AuditLog } from "./audit.js";
import type { OpsSession, SessionFactory } from "./session.js";

const CONNECTION_ERROR_MAX_BYTES = 8 * 1024;
const TRUNCATED_ERROR_SUFFIX = "\n[connection error truncated]";
const PROCESS_SESSION_RESERVATIONS = new Map<SessionId, symbol>();

type SessionOpener = Pick<SessionFactory, "open">;
type AuditAppender = Pick<AuditLog, "append">;

interface PromptControl {
  readonly turnId: TurnId;
  abortRequested: boolean;
  abortPromise?: Promise<undefined>;
}

function boundedConnectionError(error: unknown): string {
  let source = "unknown connection error";
  try {
    const detail: unknown = error instanceof Error ? error.message : error;
    source = typeof detail === "string" ? detail : String(detail);
  } catch {
    // Keep the fixed fallback when an untrusted error object has a throwing toString().
  }
  source = redactText(source);
  if (Buffer.byteLength(source, "utf8") <= CONNECTION_ERROR_MAX_BYTES) return source;

  const contentLimit = CONNECTION_ERROR_MAX_BYTES
    - Buffer.byteLength(TRUNCATED_ERROR_SUFFIX, "utf8");
  let bytes = 0;
  let end = 0;
  for (const character of source) {
    const size = Buffer.byteLength(character, "utf8");
    if (bytes + size > contentLimit) break;
    bytes += size;
    end += character.length;
  }
  return `${source.slice(0, end)}${TRUNCATED_ERROR_SUFFIX}`;
}

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
  readonly #sessions: SessionOpener;
  readonly #audit: AuditAppender;
  readonly #server = createServer();

  constructor(config: AgentConfig, sessions: SessionOpener, audit: AuditAppender) {
    this.#config = config;
    this.#sessions = sessions;
    this.#audit = audit;
  }

  async start(): Promise<void> {
    await mkdir(dirname(this.#config.backendSocketPath), { recursive: true, mode: 0o750 });
    await removeStaleSocket(this.#config.backendSocketPath);
    this.#server.on("connection", (socket) => this.#handleConnection(socket));
    await new Promise<void>((resolve, reject) => {
      this.#server.once("error", reject);
      this.#server.listen(this.#config.backendSocketPath, () => {
        this.#server.off("error", reject);
        resolve();
      });
    });
    await chmod(this.#config.backendSocketPath, 0o600);
    await this.#audit.append({
      type: "agentd_started",
      backendSocket: this.#config.backendSocketPath,
    });
  }

  async stop(): Promise<void> {
    await new Promise<void>((resolve) => this.#server.close(() => resolve()));
    await unlink(this.#config.backendSocketPath).catch(() => undefined);
    await this.#audit.append({ type: "agentd_stopped" });
  }

  #handleConnection(socket: Socket): void {
    const decoder = new FrameDecoder();
    let session: OpsSession | undefined;
    let sessionId: SessionId | undefined;
    let sessionReservation: { sessionId: SessionId; token: symbol } | undefined;
    let activeTurnId: TurnId | undefined;
    let activePrompt: PromptControl | undefined;
    const promptControls: PromptControl[] = [];
    let helloFrameSeen = false;
    let cleanupStarted = false;
    let queue: Promise<void> = Promise.resolve();
    const emit = (message: AgentServerMessage): void => {
      if (!socket.destroyed) socket.write(encodeFrame(message));
    };
    const reserveSession = (requestedSessionId: SessionId): boolean => {
      if (PROCESS_SESSION_RESERVATIONS.has(requestedSessionId)) return false;
      const token = Symbol(requestedSessionId);
      PROCESS_SESSION_RESERVATIONS.set(requestedSessionId, token);
      sessionReservation = { sessionId: requestedSessionId, token };
      return true;
    };
    const releaseSessionReservation = (): void => {
      const reservation = sessionReservation;
      if (reservation === undefined) return;
      if (PROCESS_SESSION_RESERVATIONS.get(reservation.sessionId) === reservation.token) {
        PROCESS_SESSION_RESERVATIONS.delete(reservation.sessionId);
      }
      sessionReservation = undefined;
    };
    const reportError = (error: unknown, turnId = activeTurnId): void => {
      const message = boundedConnectionError(error);
      try {
        emit({
          type: "error",
          message,
          ...(sessionId === undefined ? {} : { sessionId }),
          ...(turnId === undefined ? {} : { turnId }),
        });
      } catch {
        socket.destroy();
      }
      try {
        void this.#audit.append({ type: "connection_error", message }).catch(() => undefined);
      } catch {
        // Audit failure cannot be allowed to create an unhandled connection rejection.
      }
    };
    const enqueue = (operation: () => unknown): void => {
      queue = queue
        .then(operation)
        .then(() => undefined)
        .catch((error: unknown) => reportError(error));
    };
    const createPromptControl = (turnId: TurnId): PromptControl => {
      const control: PromptControl = {
        turnId,
        abortRequested: false,
      };
      promptControls.push(control);
      return control;
    };
    const forgetPrompt = (control: PromptControl): void => {
      const index = promptControls.indexOf(control);
      if (index !== -1) promptControls.splice(index, 1);
      if (activePrompt === control) activePrompt = undefined;
      if (activeTurnId === control.turnId) activeTurnId = undefined;
    };
    const startAbort = (control: PromptControl): Promise<undefined> => {
      control.abortRequested = true;
      if (control.abortPromise !== undefined) return control.abortPromise;
      if (activePrompt !== control || session === undefined) return Promise.resolve(undefined);

      const currentSession = session;
      const completion = Promise.withResolvers<undefined>();
      control.abortPromise = completion.promise;
      try {
        void currentSession.abort().then(
          () => completion.resolve(undefined),
          (error: unknown) => {
            reportError(error, control.turnId);
            completion.resolve(undefined);
          },
        );
      } catch (error) {
        reportError(error, control.turnId);
        completion.resolve(undefined);
      }
      return control.abortPromise;
    };
    const requestAbort = (): Promise<undefined> => {
      const control = promptControls[0];
      return control === undefined ? Promise.resolve(undefined) : startAbort(control);
    };
    const runPrompt = async (
      currentSession: OpsSession,
      text: string,
      control: PromptControl,
    ): Promise<void> => {
      activePrompt = control;
      activeTurnId = control.turnId;
      try {
        const prompt = currentSession.prompt(text, control.turnId);
        if (control.abortRequested) void startAbort(control);
        await prompt;
      } catch (error) {
        reportError(error, control.turnId);
      } finally {
        if (control.abortPromise !== undefined) await control.abortPromise;
        forgetPrompt(control);
      }
    };
    const cleanup = (): void => {
      if (cleanupStarted) return;
      cleanupStarted = true;
      const currentSession = session;
      if (currentSession === undefined) return;
      session = undefined;
      void currentSession.close().then(
        () => releaseSessionReservation(),
        (error: unknown) => reportError(error),
      );
    };

    socket.on("data", (chunk) => {
      try {
        const bytes = typeof chunk === "string" ? Buffer.from(chunk) : chunk;
        for (const frame of decoder.push(bytes)) {
          let message: ReturnType<typeof parseAgentClientMessage>;
          try {
            message = parseAgentClientMessage(frame);
          } catch (error) {
            enqueue(() => { throw error; });
            continue;
          }
          if (message.type === "hello") {
            if (helloFrameSeen) {
              enqueue(() => { throw new Error("hello already received"); });
              continue;
            }
            helloFrameSeen = true;
            sessionId = message.sessionId;
            if (!reserveSession(message.sessionId)) {
              enqueue(() => { throw new Error("session is already active"); });
              continue;
            }
            const initialPrompt = message.initialPrompt
              ? createPromptControl(parseTurnId(randomUUID()))
              : undefined;
            enqueue(async () => {
              if (session !== undefined) throw new Error("hello already received");
              let openedSession: OpsSession;
              try {
                openedSession = await this.#sessions.open(message.sessionId, emit);
              } catch (error) {
                releaseSessionReservation();
                if (initialPrompt !== undefined) forgetPrompt(initialPrompt);
                throw error;
              }
              if (cleanupStarted) {
                if (initialPrompt !== undefined) forgetPrompt(initialPrompt);
                await openedSession.close();
                releaseSessionReservation();
                return;
              }
              session = openedSession;
              emit({ type: "ready", sessionId: message.sessionId });
              if (initialPrompt !== undefined && message.initialPrompt !== undefined) {
                await runPrompt(openedSession, message.initialPrompt, initialPrompt);
              }
            });
            continue;
          }
          if (!helloFrameSeen) {
            enqueue(() => { throw new Error("hello must be the first message"); });
            continue;
          }
          if (message.type === "abort") {
            void requestAbort();
            continue;
          }
          if (message.type === "prompt") {
            const control = createPromptControl(message.turnId);
            enqueue(async () => {
              if (session === undefined) {
                forgetPrompt(control);
                throw new Error("hello must be the first message");
              }
              await runPrompt(session, message.text, control);
            });
            continue;
          }
          enqueue(() => {
            if (session === undefined) throw new Error("hello must be the first message");
            emit({ type: "pong" });
          });
        }
      } catch (error) {
        reportError(error);
        socket.destroy();
      }
    });
    socket.once("error", cleanup);
    socket.once("close", cleanup);
  }

}
