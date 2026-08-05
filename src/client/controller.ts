import type { Writable } from "node:stream";
import type { AgentServerMessage, HelperResponse } from "../shared/messages.js";
import { redactText } from "../shared/redaction.js";
import { callHelper } from "../shared/rpc.js";
import type { AgentTransport } from "./agent-connection.js";
import {
  boundClientEventContent,
  type ClientCompletionOutcome,
  type ClientEventSink,
} from "./events.js";
import { helperRequestFor, helperTimeoutFor, parseDirectCommand } from "./commands.js";

export type HelperCaller = typeof callHelper;

export interface ClientControllerOptions {
  agent: AgentTransport;
  rootHelperSocket: string;
  output: Writable;
  helperCaller?: HelperCaller;
  hasInitialPrompt?: boolean;
  eventSink?: ClientEventSink | undefined;
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
  readonly #rootHelperSocket: string;
  readonly #output: Writable;
  readonly #helperCaller: HelperCaller;
  readonly #eventSink: ClientEventSink | undefined;
  readonly #pendingPrompts: string[] = [];
  #ready = false;
  #agentBusy: boolean;
  #directQueue: Promise<void> = Promise.resolve();
  #eventQueue: Promise<void> = Promise.resolve();
  #assistantContent = "";
  #assistantContentTruncated = false;
  #lastOutputEndedWithNewline = true;

  constructor(options: ClientControllerOptions) {
    this.#agent = options.agent;
    this.#rootHelperSocket = options.rootHelperSocket;
    this.#output = options.output;
    this.#helperCaller = options.helperCaller ?? callHelper;
    this.#eventSink = options.eventSink;
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
        .then(async () => {
          this.#writeLine("Working...");
          const response = await this.#helperCaller(
            this.#rootHelperSocket,
            helperRequestFor(command),
            undefined,
            helperTimeoutFor(command),
          );
          const formatted = formatHelperResponse(response);
          this.#writeLine(formatted);
          this.#queueEvent(
            response.ok ? formatted : redactErrorMessage(formatted),
            response.ok ? "success" : "error",
          );
        })
        .catch((error: unknown) => {
          const formatted = `[root-helper error] ${errorMessage(error)}`;
          this.#writeLine(formatted);
          this.#queueEvent(redactErrorMessage(formatted), "error");
        });
      return;
    }
    this.#pendingPrompts.push(text);
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
        this.#ready = true;
        this.#drainPrompts();
        break;
      case "status":
        if (message.state === "working") {
          this.#agentBusy = true;
          this.#writeLine("Working...");
        }
        break;
      case "delta":
        this.#write(message.text);
        if (!this.#assistantContentTruncated) {
          const bounded = boundClientEventContent(`${this.#assistantContent}${message.text}`);
          this.#assistantContent = bounded.text;
          this.#assistantContentTruncated = bounded.truncated;
        }
        break;
      case "tool":
        break;
      case "done":
        this.#ensureNewline();
        this.#queueEvent(this.#assistantContent, "success");
        this.#resetAssistantContent();
        this.#agentBusy = false;
        this.#drainPrompts();
        break;
      case "error":
        this.#ensureNewline();
        this.#writeAndNotifyError("agentd", message.message);
        this.#resetAssistantContent();
        this.#agentBusy = false;
        this.#drainPrompts();
        break;
      case "pong":
        break;
    }
  }

  handleAgentError(error: Error): void {
    this.#ensureNewline();
    this.#writeAndNotifyError("agentd", error);
  }

  async waitForDirectCommands(): Promise<void> {
    await this.#directQueue;
  }

  async waitForEvents(): Promise<void> {
    await this.#eventQueue;
  }

  #drainPrompts(): void {
    if (!this.#ready || this.#agentBusy) return;
    const prompt = this.#pendingPrompts.shift();
    if (prompt === undefined) return;
    this.#agentBusy = true;
    this.#resetAssistantContent();
    try {
      this.#agent.sendPrompt(prompt);
    } catch (error) {
      this.#agentBusy = false;
      this.#writeAndNotifyError("agentd", error);
      this.#drainPrompts();
    }
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
    this.#eventQueue = this.#eventQueue
      .then(async () => await eventSink.publish({
        version: 1,
        type: "completion",
        outcome,
        content,
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
}
