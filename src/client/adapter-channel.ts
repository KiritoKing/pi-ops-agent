import { createReadStream, type ReadStream } from "node:fs";
import type { Readable } from "node:stream";
import {
  MAX_ADAPTER_CLIENT_CONTEXT_BYTES,
  ADAPTER_CONTEXT_FD,
  ADAPTER_INPUT_FD,
  parseAdapterClientContextJson,
  parseDeclaredAdapterToClientFrame,
  type AdapterClientContext,
  type AdapterDescriptor,
  type AdapterInboundText,
} from "../shared/adapter-runtime.js";

export const ADAPTER_INPUT_FD_ENV = "OPS_AGENT_ADAPTER_INPUT_FD";
export const ADAPTER_CONTEXT_FD_ENV = "OPS_AGENT_ADAPTER_CONTEXT_FD";

function requireFixedDescriptor(
  environment: NodeJS.ProcessEnv,
  name: string,
  expected: number,
): number {
  if (environment[name] !== String(expected)) {
    throw new Error(`${name} must be the fixed descriptor ${expected}`);
  }
  return expected;
}

async function readOneBoundedNdjsonFrame(
  input: AsyncIterable<Buffer | string>,
  maximumBytes: number,
  label: string,
): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let bytes = 0;
  for await (const chunk of input) {
    const value = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    bytes += value.length;
    if (bytes > maximumBytes + 1) throw new Error(`${label} exceeds its wire size limit`);
    chunks.push(value);
  }
  const payload = Buffer.concat(chunks);
  if (payload.length < 2 || payload[payload.length - 1] !== 0x0a) {
    throw new Error(`${label} must contain one newline-terminated JSON frame`);
  }
  const frame = payload.subarray(0, -1);
  if (frame.includes(0x0a)) throw new Error(`${label} must contain exactly one JSON frame`);
  return frame;
}

export async function readAdapterClientContext(
  environment: NodeJS.ProcessEnv = process.env,
  injectedInput?: AsyncIterable<Buffer | string>,
): Promise<AdapterClientContext> {
  const descriptor = requireFixedDescriptor(
    environment,
    ADAPTER_CONTEXT_FD_ENV,
    ADAPTER_CONTEXT_FD,
  );
  const input = injectedInput
    ?? createReadStream("", { fd: descriptor, autoClose: false });
  const frame = await readOneBoundedNdjsonFrame(
    input,
    MAX_ADAPTER_CLIENT_CONTEXT_BYTES,
    "trusted adapter client context",
  );
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(frame);
  } catch {
    throw new Error("trusted adapter client context is not valid UTF-8");
  }
  return parseAdapterClientContextJson(text);
}

export function adapterInputFromEnvironment(
  environment: NodeJS.ProcessEnv = process.env,
): ReadStream {
  const descriptor = requireFixedDescriptor(
    environment,
    ADAPTER_INPUT_FD_ENV,
    ADAPTER_INPUT_FD,
  );
  return createReadStream("", { fd: descriptor, autoClose: false });
}

/** Stateful strict NDJSON parser plus process-local bind/replay enforcement. */
export class DeclaredAdapterInputParser {
  readonly #descriptor: AdapterDescriptor;
  readonly #sessionId: string;
  readonly #ingressIds = new Set<string>();
  #pending = Buffer.alloc(0);
  #externalSessionId: string | undefined;
  #ended = false;

  constructor(descriptor: AdapterDescriptor, sessionId: string) {
    this.#descriptor = descriptor;
    this.#sessionId = sessionId;
  }

  push(chunk: Buffer): AdapterInboundText[] {
    if (this.#ended) throw new Error("adapter input channel is already closed");
    if (chunk.length === 0) return [];
    this.#pending = Buffer.concat([this.#pending, chunk]);
    const messages: AdapterInboundText[] = [];
    for (;;) {
      const newline = this.#pending.indexOf(0x0a);
      if (newline < 0) break;
      const rawFrame = this.#pending.subarray(0, newline);
      this.#pending = this.#pending.subarray(newline + 1);
      const frame = parseDeclaredAdapterToClientFrame(this.#descriptor, rawFrame);
      if (frame.apiVersion === "agentd.adapter-session-control/v1") {
        if (frame.type !== "bind") {
          throw new Error(`compiled Client does not implement Adapter session control ${frame.type}`);
        }
        if (this.#externalSessionId !== undefined) {
          throw new Error("Adapter session may be bound only once per Client process");
        }
        if (frame.sessionId !== this.#sessionId) {
          throw new Error("Adapter bind sessionId does not match the compiled Client session");
        }
        this.#externalSessionId = frame.externalSessionId;
        continue;
      }
      if (this.#externalSessionId === undefined) {
        throw new Error("Adapter text arrived before the required session bind");
      }
      if (frame.externalSessionId !== this.#externalSessionId) {
        throw new Error("Adapter text externalSessionId does not match its session bind");
      }
      if (this.#ingressIds.has(frame.ingressId)) {
        throw new Error("Adapter text repeats an ingressId in the current process");
      }
      if (this.#ingressIds.size >= 4096) {
        throw new Error("Adapter input process-local ingress replay set is full");
      }
      this.#ingressIds.add(frame.ingressId);
      messages.push(frame);
    }
    if (this.#pending.length > this.#descriptor.inbound.maxFrameBytes) {
      throw new Error(
        `Adapter raw inbound frame exceeds descriptor maxFrameBytes ${this.#descriptor.inbound.maxFrameBytes}`,
      );
    }
    return messages;
  }

  end(chunk?: Buffer): AdapterInboundText[] {
    const messages = chunk === undefined ? [] : this.push(chunk);
    this.#ended = true;
    if (this.#pending.length !== 0) {
      throw new Error("Adapter input ended with an unterminated NDJSON frame");
    }
    if (this.#externalSessionId === undefined) {
      throw new Error("Adapter input ended before the required session bind");
    }
    return messages;
  }
}

export interface AdapterInputSource {
  stream: Readable;
  parser: DeclaredAdapterInputParser;
}
