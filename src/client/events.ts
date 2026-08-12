import { createWriteStream } from "node:fs";
import type { Writable } from "node:stream";
import type { MachineId, SessionId, TargetId, TurnId } from "../shared/domain.js";
import { redactText } from "../shared/redaction.js";

export const MAX_CLIENT_EVENT_CONTENT_BYTES = 64 * 1024;
const TRUNCATION_MARKER = "\n[TRUNCATED]";

export type ClientCompletionOutcome = "success" | "error";

export interface ClientCompletionEvent {
  version: 1;
  type: "completion";
  eventId: string;
  outcome: ClientCompletionOutcome;
  content: string;
  sessionId?: SessionId;
  turnId?: TurnId;
  machineId?: MachineId;
  targetId?: TargetId;
}

export interface ClientEventSink {
  publish(event: ClientCompletionEvent): Promise<void>;
}

export interface BoundedContent {
  text: string;
  truncated: boolean;
}

export function boundClientEventContent(content: string): BoundedContent {
  const encoded = Buffer.from(content, "utf8");
  if (encoded.length <= MAX_CLIENT_EVENT_CONTENT_BYTES) {
    return { text: content, truncated: false };
  }

  const markerBytes = Buffer.byteLength(TRUNCATION_MARKER);
  let end = MAX_CLIENT_EVENT_CONTENT_BYTES - markerBytes;
  while (end > 0 && (encoded[end] ?? 0) >> 6 === 0b10) end -= 1;
  return {
    text: `${encoded.subarray(0, end).toString("utf8")}${TRUNCATION_MARKER}`,
    truncated: true,
  };
}

export class NdjsonEventSink implements ClientEventSink {
  readonly #output: Writable;

  constructor(output: Writable) {
    this.#output = output;
  }

  async publish(event: ClientCompletionEvent): Promise<void> {
    const safeEvent: ClientCompletionEvent = {
      ...event,
      content: boundClientEventContent(redactText(event.content)).text,
    };
    const line = `${JSON.stringify(safeEvent)}\n`;
    await new Promise<void>((resolve, reject) => {
      this.#output.write(line, (error: Error | null | undefined) => {
        if (error) reject(error);
        else resolve();
      });
    });
  }
}

export function eventSinkFromEnvironment(
  environment: NodeJS.ProcessEnv = process.env,
): ClientEventSink | undefined {
  const rawDescriptor = environment.OPS_AGENT_EVENT_FD;
  if (rawDescriptor === undefined) return undefined;
  if (!/^[0-9]+$/u.test(rawDescriptor)) {
    throw new Error("OPS_AGENT_EVENT_FD must be an integer file descriptor");
  }
  const descriptor = Number.parseInt(rawDescriptor, 10);
  if (!Number.isSafeInteger(descriptor) || descriptor < 3 || descriptor > 1024) {
    throw new Error("OPS_AGENT_EVENT_FD must be between 3 and 1024");
  }
  return new NdjsonEventSink(createWriteStream("", { fd: descriptor, autoClose: false }));
}
