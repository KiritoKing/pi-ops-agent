import { Buffer } from "node:buffer";

export const MAX_FRAME_BYTES = 256 * 1024;

export function encodeFrame(value: unknown): Buffer {
  const payload = Buffer.from(JSON.stringify(value), "utf8");
  if (payload.length > MAX_FRAME_BYTES) {
    throw new Error(`frame exceeds ${MAX_FRAME_BYTES} bytes`);
  }
  const frame = Buffer.allocUnsafe(4 + payload.length);
  frame.writeUInt32BE(payload.length, 0);
  payload.copy(frame, 4);
  return frame;
}

export class FrameDecoder {
  readonly #maximumBytes: number;
  #buffer = Buffer.alloc(0);

  constructor(maximumBytes = MAX_FRAME_BYTES) {
    this.#maximumBytes = maximumBytes;
  }

  push(chunk: Buffer): unknown[] {
    this.#buffer = Buffer.concat([this.#buffer, chunk]);
    const decoded: unknown[] = [];

    while (this.#buffer.length >= 4) {
      const length = this.#buffer.readUInt32BE(0);
      if (length === 0 || length > this.#maximumBytes) {
        throw new Error(`invalid frame length: ${length}`);
      }
      if (this.#buffer.length < length + 4) {
        break;
      }
      const payload = this.#buffer.subarray(4, length + 4).toString("utf8");
      this.#buffer = this.#buffer.subarray(length + 4);
      decoded.push(JSON.parse(payload) as unknown);
    }

    return decoded;
  }
}
