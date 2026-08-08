import { chmod, lstat, mkdir, unlink } from "node:fs/promises";
import { createServer, type Server, type Socket } from "node:net";
import { dirname, isAbsolute } from "node:path";
import { encodeFrame, FrameDecoder } from "../shared/framing.js";
import { parseApprovalReviewRequest } from "../shared/approval-review.js";
import { deterministicApprovalReview } from "./reviewer.js";

const MAX_REQUEST_BYTES = 256 * 1024;

function responseFor(value: unknown): unknown {
  try {
    const request = parseApprovalReviewRequest(value);
    return { ok: true, review: deterministicApprovalReview(request) };
  } catch (error) {
    return {
      ok: false,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

function serveConnection(socket: Socket): void {
  const decoder = new FrameDecoder(MAX_REQUEST_BYTES);
  let requests = 0;
  socket.setTimeout(30_000, () => socket.destroy());
  socket.on("data", (chunk: Buffer) => {
    try {
      for (const frame of decoder.push(chunk)) {
        requests += 1;
        if (requests !== 1) {
          socket.destroy(new Error("reviewer accepts one request per connection"));
          return;
        }
        socket.end(encodeFrame(responseFor(frame)));
      }
    } catch (error) {
      socket.destroy(error instanceof Error ? error : new Error(String(error)));
    }
  });
}

export async function listenApprovalReviewer(socketPath: string): Promise<Server> {
  if (!isAbsolute(socketPath) || socketPath.includes("\0")) {
    throw new Error("reviewer socket path must be absolute");
  }
  await mkdir(dirname(socketPath), { recursive: true, mode: 0o750 });
  try {
    const existing = await lstat(socketPath);
    if (!existing.isSocket()) throw new Error("reviewer socket path is occupied by a non-socket");
    await unlink(socketPath);
  } catch (error) {
    if (!(error instanceof Error && "code" in error && error.code === "ENOENT")) throw error;
  }
  const server = createServer(serveConnection);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, () => {
      server.off("error", reject);
      resolve();
    });
  });
  await chmod(socketPath, 0o660);
  return server;
}
