import { createConnection } from "node:net";
import { randomUUID } from "node:crypto";
import { encodeFrame, FrameDecoder } from "./framing.js";
import { parseHelperResponse, type HelperRequest, type HelperResponse } from "./messages.js";

export function requestId(): string {
  return randomUUID();
}

export function deadline(seconds = 30): string {
  return new Date(Date.now() + seconds * 1000).toISOString();
}

export async function callHelper(
  socketPath: string,
  request: HelperRequest,
  signal?: AbortSignal,
  timeoutMs = 30_000,
): Promise<HelperResponse> {
  return await new Promise<HelperResponse>((resolve, reject) => {
    const socket = createConnection(socketPath);
    const decoder = new FrameDecoder();
    let settled = false;

    const finish = (error: Error | undefined, response?: HelperResponse): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      socket.destroy();
      if (error) reject(error);
      else if (response) resolve(response);
      else reject(new Error("helper closed without a response"));
    };
    const onAbort = (): void => finish(new Error("helper request aborted"));
    const timer = setTimeout(
      () => finish(new Error(`helper request timed out after ${timeoutMs}ms`)),
      timeoutMs,
    );
    timer.unref();

    signal?.addEventListener("abort", onAbort, { once: true });
    socket.once("connect", () => socket.write(encodeFrame(request)));
    socket.on("data", (chunk) => {
      try {
        const bytes = typeof chunk === "string" ? Buffer.from(chunk) : chunk;
        const frames = decoder.push(bytes);
        if (frames.length > 0) {
          finish(undefined, parseHelperResponse(frames[0]));
        }
      } catch (error) {
        finish(error instanceof Error ? error : new Error(String(error)));
      }
    });
    socket.once("error", (error) => finish(error));
    socket.once("end", () => finish(new Error("helper closed without a response")));
  });
}
