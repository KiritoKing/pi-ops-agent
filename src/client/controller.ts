import type { Writable } from "node:stream";
import { randomUUID } from "node:crypto";
import type { MachineId, SessionId, TargetId, TurnId } from "../shared/domain.js";
import type { AgentServerMessage, HelperResponse } from "../shared/messages.js";
import { redactText } from "../shared/redaction.js";
import { encodeChangeRef, parseChangeRef, type ChangeRef } from "../shared/approval.js";
import type { AgentTransport } from "./agent-connection.js";
import {
  boundClientEventContent,
  type ClientCompletionOutcome,
  type ClientEventSink,
} from "./events.js";
import { parseDirectCommand } from "./commands.js";
import type { ApprovalCommandHandler } from "./approval-router.js";
import {
  captureApprovalIntent,
  type ApprovalIntentBinding,
  type CapturedApprovalIntent,
} from "./approval-intent.js";
import { escapeUntrustedTerminalText } from "../shared/terminal-safety.js";

const MAX_BOUND_CHANGE_INTENTS = 256;
const MAX_DELAYED_AGENT_OUTPUT_BYTES = 256 * 1024;

interface PendingPrompt {
  text: string;
  intent: CapturedApprovalIntent;
}

interface TurnIntentRecord {
  sessionId: SessionId;
  turnId: TurnId;
  intent: CapturedApprovalIntent;
}

type ChangeIntentRecord =
  | { available: true; binding: ApprovalIntentBinding }
  | {
      available: false;
      sessionId: SessionId;
      turnId: TurnId;
      changeRef: Readonly<ChangeRef>;
      reason: string;
    };

export interface ClientControllerOptions {
  agent: AgentTransport;
  output: Writable;
  directCommandHandler?: ApprovalCommandHandler;
  hasInitialPrompt?: boolean;
  eventSink?: ClientEventSink | undefined;
  localConsole?: boolean;
}

function formatHelperResponse(response: HelperResponse): string {
  if (!response.ok) {
    return `[root-helper error] ${response.error ?? "request failed"}`;
  }
  const fields: string[] = [];
  if (response.summary) fields.push(response.summary);
  if (response.changeId) fields.push(`changeId=${response.changeId}`);
  if (response.state) fields.push(`state=${response.state}`);
  if (response.auditId) fields.push(`auditId=${response.auditId}`);
  if (response.data !== undefined) fields.push(JSON.stringify(response.data, undefined, 2));
  return fields.length > 0 ? fields.join("\n") : "root-helper request completed";
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function redactErrorMessage(message: string): string {
  return redactText(message)
    .replace(
      /\b(authorization)(\s*[:=]\s*)(?:Bearer\s+)?[^\s,;]+/giu,
      "$1$2[REDACTED]",
    )
    .replace(/\b(Bearer)\s+[^\s,;]+/giu, "$1 [REDACTED]")
    .replace(
      /\b([a-z0-9_-]*(?:password|passwd|token|secret|api[_-]?key|cookie|credential)[a-z0-9_-]*)(["']?\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s,;]+)/giu,
      "$1$2[REDACTED]",
    )
    .replace(/([?&](?:access_token|api[_-]?key|token|secret)=)[^&\s]+/giu, "$1[REDACTED]")
    .replace(/\b([a-z][a-z0-9+.-]*:\/\/)[^\s/@:]+:[^\s/@]+@/giu, "$1[REDACTED]@");
}

export class ClientController {
  readonly #agent: AgentTransport;
  readonly #output: Writable;
  readonly #directCommandHandler: ApprovalCommandHandler;
  readonly #eventSink: ClientEventSink | undefined;
  readonly #localConsole: boolean;
  readonly #pendingPrompts: PendingPrompt[] = [];
  #ready = false;
  #agentBusy: boolean;
  #directQueue: Promise<void> = Promise.resolve();
  #eventQueue: Promise<void> = Promise.resolve();
  #assistantContent = "";
  #assistantContentTruncated = false;
  #lastOutputEndedWithNewline = true;
  #sessionId: SessionId | undefined;
  #activeTurnId: TurnId | undefined;
  #activeMachineId: MachineId | undefined;
  #activeTargetId: TargetId | undefined;
  readonly #turnIntents = new Map<TurnId, TurnIntentRecord>();
  readonly #changeIntents = new Map<string, ChangeIntentRecord>();
  readonly #completedTurns = new Set<TurnId>();
  #approvalOutputFrozen = false;
  #frozenApprovalCommandKey: string | undefined;
  #delayedAgentOutput = "";
  #delayedAgentOutputBytes = 0;
  #delayedAgentOutputTruncated = false;

  constructor(options: ClientControllerOptions) {
    this.#agent = options.agent;
    this.#output = options.output;
    this.#directCommandHandler = options.directCommandHandler ?? (() =>
      Promise.reject(new Error("model-external HTTPS approval handler is unavailable")));
    this.#eventSink = options.eventSink;
    this.#localConsole = options.localConsole ?? false;
    this.#agentBusy = options.hasInitialPrompt ?? false;
  }

  submit(text: string): void {
    if (text.trim().length === 0) return;
    let command;
    try {
      command = parseDirectCommand(text);
    } catch (error) {
      const formatted = `[input error] ${errorMessage(error)}`;
      this.#writeLine(formatted);
      this.#queueEvent(redactErrorMessage(formatted), "error");
      return;
    }
    if (command) {
      this.#directQueue = this.#directQueue
        .then(async () => await this.#runDirectCommand(command))
        .catch((error: unknown) => {
          const formatted = escapeUntrustedTerminalText(
            `[root-helper error] ${errorMessage(error)}`,
          );
          this.#writeLine(formatted);
          this.#queueEvent(redactErrorMessage(formatted), "error");
          const failedKey = command.kind === "status"
            ? undefined
            : `${command.kind}\0${encodeChangeRef(command.changeRef)}`;
          if (failedKey !== undefined && this.#frozenApprovalCommandKey === failedKey) {
            this.#endApprovalOutputFreeze();
          }
        });
      return;
    }
    if (this.#approvalOutputFrozen) {
      const formatted = "[input error] an approval confirmation is active; repeat the exact approval command or exit the client";
      this.#writeLine(formatted);
      this.#queueEvent(formatted, "error");
      return;
    }
    this.#pendingPrompts.push({ text, intent: captureApprovalIntent(text) });
    this.#drainPrompts();
  }

  abort(): void {
    this.#pendingPrompts.length = 0;
    try {
      this.#agent.abort();
      this.#writeLine("Aborting...");
    } catch (error) {
      this.#writeAndNotifyError("agentd", error);
    }
  }

  handleAgentMessage(message: AgentServerMessage): void {
    switch (message.type) {
      case "ready":
        if (this.#ready) this.#clearIntentBindings();
        this.#sessionId = message.sessionId;
        this.#ready = true;
        this.#drainPrompts();
        break;
      case "status":
        this.#captureCorrelation(message);
        if (message.state === "working") {
          this.#agentBusy = true;
          this.#writeAgentLine("Working...");
        }
        break;
      case "delta":
        this.#captureCorrelation(message);
        this.#writeAgent(message.text);
        if (!this.#assistantContentTruncated) {
          const bounded = boundClientEventContent(`${this.#assistantContent}${message.text}`);
          this.#assistantContent = bounded.text;
          this.#assistantContentTruncated = bounded.truncated;
        }
        break;
      case "tool":
        if (message.phase === "end" && message.preparedChangeRefs !== undefined) {
          this.#bindPreparedChanges(message);
        }
        this.#captureCorrelation(message);
        break;
      case "done":
        if (this.#completedTurns.has(message.turnId)) break;
        this.#captureCorrelation(message);
        this.#rememberCompletedTurn(message.turnId);
        this.#turnIntents.delete(message.turnId);
        this.#ensureAgentNewline();
        this.#queueEvent(this.#assistantContent, "success");
        this.#resetAssistantContent();
        this.#agentBusy = false;
        this.#drainPrompts();
        break;
      case "error":
        if (message.sessionId !== undefined && message.turnId !== undefined) {
          this.#captureCorrelation({
            sessionId: message.sessionId,
            turnId: message.turnId,
            ...(message.machineId === undefined ? {} : { machineId: message.machineId }),
            ...(message.targetId === undefined ? {} : { targetId: message.targetId }),
          });
          this.#turnIntents.delete(message.turnId);
        }
        this.#ensureAgentNewline();
        this.#writeAgentError("agentd", message.message);
        this.#resetAssistantContent();
        this.#agentBusy = false;
        this.#drainPrompts();
        break;
      case "pong":
        break;
    }
  }

  handleAgentError(error: Error): void {
    this.#ensureAgentNewline();
    this.#writeAgentError("agentd", error);
  }

  async waitForDirectCommands(): Promise<void> {
    await this.#directQueue;
  }

  async waitForEvents(): Promise<void> {
    await this.#eventQueue;
  }

  isIdle(): boolean {
    return this.#ready && !this.#agentBusy && this.#pendingPrompts.length === 0;
  }

  #drainPrompts(): void {
    if (!this.#ready || this.#agentBusy) return;
    const prompt = this.#pendingPrompts.shift();
    if (prompt === undefined) return;
    this.#agentBusy = true;
    this.#resetAssistantContent();
    try {
      const sessionId = this.#sessionId;
      if (sessionId === undefined) throw new Error("agent session is not ready");
      const turnId = this.#agent.sendPrompt(prompt.text);
      if (this.#turnIntents.has(turnId) || this.#completedTurns.has(turnId)) {
        this.#poisonTurn(sessionId, turnId, "agent transport reused a turn ID");
      }
      this.#turnIntents.set(turnId, { sessionId, turnId, intent: prompt.intent });
      this.#activeTurnId = turnId;
    } catch (error) {
      this.#agentBusy = false;
      this.#writeAndNotifyError("agentd", error);
      this.#drainPrompts();
    }
  }

  async #runDirectCommand(command: NonNullable<ReturnType<typeof parseDirectCommand>>): Promise<void> {
    const approvalCommand = command.kind !== "status";
    const commandKey = approvalCommand
      ? `${command.kind}\0${encodeChangeRef(command.changeRef)}`
      : undefined;
    if (approvalCommand) {
      if (this.#frozenApprovalCommandKey !== undefined
        && this.#frozenApprovalCommandKey !== commandKey) {
        throw new Error("another approval confirmation is active; only its exact command may continue");
      }
      if (!this.isIdle()) {
        throw new Error("agent must be ready and idle before an approval command can start or continue");
      }
      if (!this.#approvalOutputFrozen) {
        this.#approvalOutputFrozen = true;
        this.#frozenApprovalCommandKey = commandKey;
      }
    }
    let keepFrozen = false;
    let completed = false;
    try {
      this.#writeLine("Working...");
      const response = await this.#directCommandHandler(
        command,
        this.#approvalContext(command),
      );
      const formatted = escapeUntrustedTerminalText(formatHelperResponse(response));
      this.#writeLine(formatted);
      this.#queueEvent(
        response.ok ? formatted : redactErrorMessage(formatted),
        response.ok ? "success" : "error",
      );
      keepFrozen = approvalCommand && response.ok && response.state === "REVIEW_REQUIRED";
      completed = true;
    } finally {
      if (approvalCommand && completed && !keepFrozen) this.#endApprovalOutputFreeze();
    }
  }

  #writeAgent(value: string): void {
    // Preserve the full bounded Agent frame here; the approval freeze below
    // owns its separate 256 KiB accounting and must be able to detect overflow.
    const escaped = escapeUntrustedTerminalText(value, Number.MAX_SAFE_INTEGER);
    if (!this.#approvalOutputFrozen) {
      this.#write(escaped);
      return;
    }
    const remaining = MAX_DELAYED_AGENT_OUTPUT_BYTES - this.#delayedAgentOutputBytes;
    if (remaining <= 0) {
      this.#delayedAgentOutputTruncated = true;
      return;
    }
    let accepted = "";
    let acceptedBytes = 0;
    for (const character of escaped) {
      const bytes = Buffer.byteLength(character);
      if (acceptedBytes + bytes > remaining) {
        this.#delayedAgentOutputTruncated = true;
        break;
      }
      accepted += character;
      acceptedBytes += bytes;
    }
    this.#delayedAgentOutput += accepted;
    this.#delayedAgentOutputBytes += acceptedBytes;
  }

  #writeAgentLine(value: string): void {
    this.#ensureAgentNewline();
    this.#writeAgent(`${value}\n`);
  }

  #ensureAgentNewline(): void {
    if (this.#approvalOutputFrozen) {
      if (this.#delayedAgentOutput.length > 0 && !this.#delayedAgentOutput.endsWith("\n")) {
        this.#writeAgent("\n");
      }
      return;
    }
    this.#ensureNewline();
  }

  #writeAgentError(source: string, error: unknown): void {
    const formatted = `[${source} error] ${errorMessage(error)}`;
    this.#writeAgentLine(formatted);
    this.#queueEvent(redactErrorMessage(formatted), "error");
  }

  #endApprovalOutputFreeze(): void {
    if (!this.#approvalOutputFrozen) return;
    const delayed = this.#delayedAgentOutput;
    const truncated = this.#delayedAgentOutputTruncated;
    this.#approvalOutputFrozen = false;
    this.#frozenApprovalCommandKey = undefined;
    this.#delayedAgentOutput = "";
    this.#delayedAgentOutputBytes = 0;
    this.#delayedAgentOutputTruncated = false;
    if (delayed.length === 0 && !truncated) return;
    this.#writeLine("--- delayed untrusted agent output; not part of the approval evidence ---");
    this.#write(delayed);
    this.#ensureNewline();
    if (truncated) this.#writeLine("[delayed agent output truncated at 256 KiB]");
    this.#writeLine("--- end delayed untrusted agent output ---");
  }

  #write(value: string): void {
    if (value.length === 0) return;
    this.#output.write(value);
    this.#lastOutputEndedWithNewline = value.endsWith("\n");
  }

  #writeLine(value: string): void {
    this.#ensureNewline();
    this.#write(`${value}\n`);
  }

  #ensureNewline(): void {
    if (!this.#lastOutputEndedWithNewline) this.#write("\n");
  }

  #queueEvent(content: string, outcome: ClientCompletionOutcome): void {
    const eventSink = this.#eventSink;
    if (!eventSink || content.length === 0) return;
    const correlation = {
      ...(this.#sessionId === undefined ? {} : { sessionId: this.#sessionId }),
      ...(this.#activeTurnId === undefined ? {} : { turnId: this.#activeTurnId }),
      ...(this.#activeMachineId === undefined ? {} : { machineId: this.#activeMachineId }),
      ...(this.#activeTargetId === undefined ? {} : { targetId: this.#activeTargetId }),
    };
    const eventId = randomUUID();
    this.#eventQueue = this.#eventQueue
      .then(async () => await eventSink.publish({
        version: 1,
        type: "completion",
        eventId,
        outcome,
        content,
        ...correlation,
      }))
      .catch((error: unknown) => {
        this.#writeLine(`[event sink error] ${errorMessage(error)}`);
      });
  }

  #writeAndNotifyError(source: string, error: unknown): void {
    const formatted = `[${source} error] ${errorMessage(error)}`;
    this.#writeLine(formatted);
    this.#queueEvent(redactErrorMessage(formatted), "error");
  }

  #resetAssistantContent(): void {
    this.#assistantContent = "";
    this.#assistantContentTruncated = false;
  }

  #captureCorrelation(message: {
    sessionId: SessionId;
    turnId: TurnId;
    machineId?: MachineId;
    targetId?: TargetId;
  }): void {
    this.#sessionId = message.sessionId;
    this.#activeTurnId = message.turnId;
    if (message.machineId !== undefined) this.#activeMachineId = message.machineId;
    if (message.targetId !== undefined) this.#activeTargetId = message.targetId;
  }

  #rememberCompletedTurn(turnId: TurnId): void {
    this.#completedTurns.add(turnId);
    if (this.#completedTurns.size <= 256) return;
    const oldest = this.#completedTurns.values().next().value;
    if (oldest !== undefined) this.#completedTurns.delete(oldest);
  }

  #approvalContext(command: Parameters<ApprovalCommandHandler>[0]): {
    intentBinding?: ApprovalIntentBinding;
    localConsole: boolean;
  } {
    if (command.kind !== "approve" && command.kind !== "rollback") {
      return { localConsole: this.#localConsole };
    }
    const key = encodeChangeRef(command.changeRef);
    const record = this.#changeIntents.get(key);
    if (record === undefined) {
      throw new Error(
        "approval intent unavailable for this change; prepare it again from this live client session",
      );
    }
    if (!record.available) {
      throw new Error(
        `approval intent unavailable for this change (${record.reason}); prepare it again from a concise user request`,
      );
    }
    if (this.#sessionId === undefined || record.binding.sessionId !== this.#sessionId) {
      throw new Error(
        "approval intent belongs to another client session; prepare the change again in this session",
      );
    }
    return { intentBinding: record.binding, localConsole: this.#localConsole };
  }

  #bindPreparedChanges(message: Extract<AgentServerMessage, { type: "tool" }>): void {
    const sessionId = this.#sessionId;
    if (sessionId === undefined || message.sessionId !== sessionId) return;
    const turn = this.#turnIntents.get(message.turnId);
    if (turn === undefined || turn.sessionId !== sessionId || turn.turnId !== message.turnId) return;
    for (const encoded of message.preparedChangeRefs ?? []) {
      let changeRef: ChangeRef;
      try {
        changeRef = parseChangeRef(encoded);
        if (encodeChangeRef(changeRef) !== encoded) continue;
      } catch {
        continue;
      }
      const incoming: ChangeIntentRecord = turn.intent.available
        ? {
            available: true,
            binding: Object.freeze({
              version: 1,
              sessionId,
              turnId: message.turnId,
              changeRef: Object.freeze({ ...changeRef }),
              userIntent: turn.intent.userIntent,
            }),
          }
        : {
            available: false,
            sessionId,
            turnId: message.turnId,
            changeRef: Object.freeze({ ...changeRef }),
            reason: turn.intent.reason,
          };
      const previous = this.#changeIntents.get(encoded);
      if (previous !== undefined && !this.#sameIntentRecord(previous, incoming)) {
        this.#changeIntents.set(encoded, {
          available: false,
          sessionId,
          turnId: message.turnId,
          changeRef: Object.freeze({ ...changeRef }),
          reason: "the change was correlated with conflicting session or turn input",
        });
        continue;
      }
      if (previous === undefined) this.#rememberChangeIntent(encoded, incoming);
    }
  }

  #sameIntentRecord(left: ChangeIntentRecord, right: ChangeIntentRecord): boolean {
    if (left.available !== right.available) return false;
    if (left.available && right.available) {
      return left.binding.sessionId === right.binding.sessionId
        && left.binding.turnId === right.binding.turnId
        && left.binding.userIntent === right.binding.userIntent;
    }
    if (!left.available && !right.available) {
      return left.sessionId === right.sessionId && left.turnId === right.turnId
        && left.reason === right.reason;
    }
    return false;
  }

  #rememberChangeIntent(key: string, record: ChangeIntentRecord): void {
    this.#changeIntents.set(key, record);
    if (this.#changeIntents.size <= MAX_BOUND_CHANGE_INTENTS) return;
    const oldest = this.#changeIntents.keys().next().value;
    if (oldest !== undefined) this.#changeIntents.delete(oldest);
  }

  #poisonTurn(sessionId: SessionId, turnId: TurnId, reason: string): void {
    for (const [key, record] of this.#changeIntents) {
      const recordSession = record.available ? record.binding.sessionId : record.sessionId;
      const recordTurn = record.available ? record.binding.turnId : record.turnId;
      if (recordSession !== sessionId || recordTurn !== turnId) continue;
      const changeRef = record.available ? record.binding.changeRef : record.changeRef;
      this.#changeIntents.set(key, {
        available: false,
        sessionId,
        turnId,
        changeRef,
        reason,
      });
    }
  }

  #clearIntentBindings(): void {
    this.#turnIntents.clear();
    this.#changeIntents.clear();
    this.#completedTurns.clear();
  }
}
