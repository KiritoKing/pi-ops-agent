import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { AgentConnection } from "../../src/client/agent-connection.js";
import { parseSessionId, parseTurnId } from "../../src/shared/domain.js";
import { encodeFrame, FrameDecoder } from "../../src/shared/framing.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  for (const directory of temporaryDirectories.splice(0)) {
    await rm(directory, { recursive: true, force: true });
  }
});

describe("AgentConnection", () => {
  it("speaks the framed agentd protocol and validates responses", async () => {
    const temporaryRoot = process.platform === "darwin" ? "/private/tmp" : tmpdir();
    const directory = await mkdtemp(join(temporaryRoot, "ops-client-test-"));
    temporaryDirectories.push(directory);
    const socketPath = join(directory, "agentd.sock");
    const decoder = new FrameDecoder();
    const received: unknown[] = [];
    let resolvePrompt: (() => void) | undefined;
    const promptReceived = new Promise<void>((resolve) => {
      resolvePrompt = resolve;
    });
    const server = createServer((socket) => {
      socket.on("data", (chunk) => {
        for (const frame of decoder.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk))) {
          received.push(frame);
          if (received.length === 1) {
            const correlation = { sessionId: "session-1234", turnId: "turn-12345678" };
            socket.write(encodeFrame({ type: "ready", sessionId: correlation.sessionId }));
            socket.write(encodeFrame({ type: "status", state: "working", ...correlation }));
            socket.write(encodeFrame({ type: "delta", text: "ok", ...correlation }));
            socket.write(encodeFrame({ type: "done", ...correlation }));
          } else {
            resolvePrompt?.();
          }
        }
      });
    });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(socketPath, resolve);
    });

    const messages: string[] = [];
    let resolveMessages: (() => void) | undefined;
    const messagesReceived = new Promise<void>((resolve) => {
      resolveMessages = resolve;
    });
    const connection = await AgentConnection.connect(
      socketPath,
      {
        type: "hello",
        sessionId: parseSessionId("session-1234"),
        peer: {
          apiVersion: "agentd.client-peer/v1",
          adapterId: "adapter.tui",
          digest: `sha256:${"a".repeat(64)}`,
        },
      },
      {
        onMessage: (message) => {
          messages.push(message.type);
          if (message.type === "done") resolveMessages?.();
        },
        onError: (error) => {
          throw error;
        },
        onClose: () => undefined,
      },
    );
    connection.sendPrompt("next prompt");
    await Promise.all([promptReceived, messagesReceived]);

    expect(received[0]).toEqual(
      {
        type: "hello",
        sessionId: "session-1234",
        peer: {
          apiVersion: "agentd.client-peer/v1",
          adapterId: "adapter.tui",
          digest: `sha256:${"a".repeat(64)}`,
        },
      },
    );
    expect(received[1]).toMatchObject({
      type: "prompt",
      text: "next prompt",
    });
    expect(() => parseTurnId((received[1] as { turnId?: unknown }).turnId)).not.toThrow();
    expect(messages).toEqual(["ready", "status", "delta", "done"]);
    connection.close();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
});
