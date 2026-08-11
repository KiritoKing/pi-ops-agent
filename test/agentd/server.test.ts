import { once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import { connect, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { AgentServer } from "../../src/agentd/server.js";
import type { OpsSession } from "../../src/agentd/session.js";
import type { AgentTurnAbortGraceError } from "../../src/agentd/session-turn.js";
import {
  AgentTurnAbortLatch,
  closeActiveAgentTurn,
} from "../../src/agentd/session-turn.js";
import type { AgentConfig } from "../../src/shared/config.js";
import { parseSessionId, parseTurnId } from "../../src/shared/domain.js";
import { encodeFrame, FrameDecoder } from "../../src/shared/framing.js";

function config(root: string): AgentConfig {
  return {
    socketPath: join(root, "agentd.sock"),
    backendSocketPath: join(root, "backend.sock"),
    stateDir: join(root, "state"),
    workspaceRoot: join(root, "workspaces"),
    sessionDir: join(root, "sessions"),
    sessionRegistryPath: join(root, "sessions.json"),
    serverRegistryPath: join(root, "servers.json"),
    reviewerSocket: join(root, "reviewer.sock"),
    guardianHeartbeatPath: join(root, "heartbeat.json"),
    pluginRegistryPath: join(root, "plugins"),
    pluginLeaseSocketPath: "/run/ops-agent/plugin-lease/lease.sock",
    pluginCtlPath: join(root, "agentd-pluginctl"),
    approvalSubmitPath: join(root, "agentd-approval-submit"),
    machineContextDir: join(root, "machines"),
    agentDir: join(root, "pi"),
    modelsPath: join(root, "models.json"),
    provider: "fixture",
    model: "fixture-model",
    apiKeyCredential: "fixture_key",
    auditPath: join(root, "audit.jsonl"),
    bwrapPath: "/usr/bin/bwrap",
    bashPath: "/bin/bash",
    sandboxEnabled: true,
  };
}

async function within<T>(promise: Promise<T>, label: string): Promise<T> {
  let timeout: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<T>((_resolve, reject) => {
        timeout = setTimeout(() => reject(new Error(`timed out waiting for ${label}`)), 1_000);
      }),
    ]);
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
  }
}

function closeSocket(socket: Socket): Promise<void> {
  if (socket.destroyed) return Promise.resolve();
  const closed = once(socket, "close").then(() => undefined);
  socket.destroy();
  return closed;
}

function eventMessage(value: unknown, type: string): string | undefined {
  if (typeof value !== "object" || value === null || !("type" in value)) return undefined;
  if (value.type !== type || !("message" in value) || typeof value.message !== "string") {
    return undefined;
  }
  return value.message;
}

function waitForReady(socket: Socket): Promise<void> {
  const ready = Promise.withResolvers<undefined>();
  const decoder = new FrameDecoder();
  socket.on("data", (chunk) => {
    for (const message of decoder.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk))) {
      if (
        typeof message === "object"
        && message !== null
        && "type" in message
        && message.type === "ready"
      ) {
        ready.resolve(undefined);
      }
    }
  });
  return ready.promise;
}

function waitForErrorMessage(socket: Socket): Promise<string> {
  const received = Promise.withResolvers<string>();
  const decoder = new FrameDecoder();
  socket.on("data", (chunk) => {
    for (const message of decoder.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk))) {
      const error = eventMessage(message, "error");
      if (error !== undefined) received.resolve(error);
    }
  });
  return received.promise;
}

describe("AgentServer connection scheduling", () => {
  it("lets one abort bypass a hung prompt without starting a later prompt or ping", async () => {
    const temporaryRoot = process.platform === "darwin" ? "/private/tmp" : tmpdir();
    const root = await mkdtemp(join(temporaryRoot, "ops-agent-server-abort-"));
    const promptStarted = Promise.withResolvers<undefined>();
    const abortCompleted = Promise.withResolvers<undefined>();
    const disposed = Promise.withResolvers<undefined>();
    const neverSettles = new Promise<undefined>(() => undefined);
    const calls: string[] = [];
    let abortCalls = 0;
    const session: OpsSession = {
      prompt: async (text, turnId) => {
        calls.push(`prompt:${turnId}:${text}`);
        promptStarted.resolve(undefined);
        await neverSettles;
      },
      abort: () => {
        abortCalls += 1;
        calls.push("abort");
        abortCompleted.resolve(undefined);
        return Promise.resolve();
      },
      close: () => {
        calls.push("dispose");
        disposed.resolve(undefined);
        return Promise.resolve();
      },
    };
    const audits: unknown[] = [];
    const server = new AgentServer(
      config(root),
      { open: () => Promise.resolve(session) },
      { append: (event) => { audits.push(event); return Promise.resolve(); } },
    );
    let socket: Socket | undefined;
    try {
      await server.start();
      socket = connect(config(root).backendSocketPath);
      socket.on("error", () => undefined);
      await within(once(socket, "connect").then(() => undefined), "socket connect");

      const responses: unknown[] = [];
      const readyReceived = Promise.withResolvers<undefined>();
      const decoder = new FrameDecoder();
      socket.on("data", (chunk) => {
        const messages = decoder.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
        responses.push(...messages);
        if (messages.some((message) => (
          typeof message === "object"
          && message !== null
          && "type" in message
          && message.type === "ready"
        ))) {
          readyReceived.resolve(undefined);
        }
      });
      const sessionId = parseSessionId("session-server-abort-1234");
      const firstTurn = parseTurnId("turn-server-abort-1234");
      const secondTurn = parseTurnId("turn-server-later-1234");
      socket.write(Buffer.concat([
        encodeFrame({
          type: "hello",
          sessionId,
          peer: {
            apiVersion: "agentd.client-peer/v1",
            adapterId: "adapter.tui",
            digest: `sha256:${"a".repeat(64)}`,
          },
        }),
        encodeFrame({ type: "prompt", turnId: firstTurn, text: "never settle" }),
        encodeFrame({ type: "abort" }),
        encodeFrame({ type: "abort" }),
        encodeFrame({ type: "prompt", turnId: secondTurn, text: "must stay queued" }),
        encodeFrame({ type: "ping" }),
      ]));

      await within(promptStarted.promise, "first prompt start");
      await within(abortCompleted.promise, "out-of-band abort");
      await within(readyReceived.promise, "ready response");
      await new Promise<undefined>((resolve) => setImmediate(() => resolve(undefined)));

      expect(calls).toEqual([
        `prompt:${firstTurn}:never settle`,
        "abort",
      ]);
      expect(abortCalls).toBe(1);
      expect(responses).toContainEqual({ type: "ready", sessionId });
      expect(responses).not.toContainEqual({ type: "pong" });

      await closeSocket(socket);
      await within(disposed.promise, "session disposal");
      expect(abortCalls).toBe(1);
      expect(calls).toEqual([
        `prompt:${firstTurn}:never settle`,
        "abort",
        "dispose",
      ]);
      expect(audits).toEqual([
        { type: "agentd_started", backendSocket: config(root).backendSocketPath },
      ]);
    } finally {
      if (socket !== undefined) await closeSocket(socket);
      await server.stop();
      await rm(root, { recursive: true, force: true });
    }
  });

  it.each(["reject", "hang"] as const)(
    "keeps a disconnected %s-abort session reserved after the fatal hook returns",
    async (failureMode) => {
      const temporaryRoot = process.platform === "darwin" ? "/private/tmp" : tmpdir();
      const root = await mkdtemp(join(temporaryRoot, `ops-agent-server-${failureMode}-`));
      const firstSessionId = parseSessionId(`session-server-${failureMode}-1234`);
      const differentSessionId = parseSessionId(`session-server-${failureMode}-other-1234`);
      const promptStarted = Promise.withResolvers<undefined>();
      const fatalObserved = Promise.withResolvers<AgentTurnAbortGraceError>();
      const neverSettles = new Promise<undefined>(() => undefined);
      let firstPromptCalls = 0;
      let firstAbortCalls = 0;
      let firstCloseCalls = 0;
      let firstClose: Promise<void> | undefined;
      const abortLatch = new AgentTurnAbortLatch(() => {
        firstAbortCalls += 1;
        return failureMode === "reject"
          ? Promise.reject(new Error("untrusted abort failure"))
          : neverSettles;
      });
      const firstSession: OpsSession = {
        prompt: async () => {
          firstPromptCalls += 1;
          promptStarted.resolve(undefined);
          await neverSettles;
        },
        abort: () => abortLatch.request(),
        close: () => {
          firstCloseCalls += 1;
          firstClose ??= closeActiveAgentTurn(abortLatch, neverSettles, {
            timeoutMs: 180,
            abortGraceMs: 15,
            onAbortGraceExceeded: (error) => { fatalObserved.resolve(error); },
          });
          return firstClose;
        },
      };
      const differentClosed = Promise.withResolvers<undefined>();
      const differentSession: OpsSession = {
        prompt: () => Promise.resolve(),
        abort: () => Promise.resolve(),
        close: () => {
          differentClosed.resolve(undefined);
          return Promise.resolve();
        },
      };
      const openedSessionIds: string[] = [];
      const server = new AgentServer(
        config(root),
        {
          open: (externalId) => {
            openedSessionIds.push(externalId);
            return Promise.resolve(externalId === firstSessionId ? firstSession : differentSession);
          },
        },
        { append: () => Promise.resolve() },
      );
      let firstSocket: Socket | undefined;
      let secondSocket: Socket | undefined;
      let differentSocket: Socket | undefined;
      try {
        await server.start();
        firstSocket = connect(config(root).backendSocketPath);
        firstSocket.on("error", () => undefined);
        await within(once(firstSocket, "connect").then(() => undefined), "first socket connect");
        firstSocket.write(Buffer.concat([
          encodeFrame({
            type: "hello",
            sessionId: firstSessionId,
            peer: {
              apiVersion: "agentd.client-peer/v1",
              adapterId: "adapter.tui",
              digest: `sha256:${"e".repeat(64)}`,
            },
          }),
          encodeFrame({
            type: "prompt",
            turnId: parseTurnId(`turn-server-${failureMode}-1234`),
            text: "never settle",
          }),
        ]));
        await within(promptStarted.promise, "first prompt start");
        await closeSocket(firstSocket);

        const fatal = await within(fatalObserved.promise, "disconnect fatal hook");
        expect(fatal.trigger).toBe("disconnect");
        expect(fatal.reason).toBe(failureMode === "reject" ? "abort-rejected" : "grace-expired");
        expect(fatal.message).not.toContain("untrusted abort failure");
        expect(firstAbortCalls).toBe(1);
        expect(firstCloseCalls).toBe(1);

        secondSocket = connect(config(root).backendSocketPath);
        secondSocket.on("error", () => undefined);
        await within(once(secondSocket, "connect").then(() => undefined), "same-session reconnect");
        const sameSessionRejected = Promise.withResolvers<string>();
        const secondDecoder = new FrameDecoder();
        secondSocket.on("data", (chunk) => {
          for (const message of secondDecoder.push(
            Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk),
          )) {
            const error = eventMessage(message, "error");
            if (error !== undefined) sameSessionRejected.resolve(error);
          }
        });
        secondSocket.write(Buffer.concat([
          encodeFrame({
            type: "hello",
            sessionId: firstSessionId,
            peer: {
              apiVersion: "agentd.client-peer/v1",
              adapterId: "adapter.tui",
              digest: `sha256:${"f".repeat(64)}`,
            },
          }),
          encodeFrame({
            type: "prompt",
            turnId: parseTurnId(`turn-server-${failureMode}-second-1234`),
            text: "must not open",
          }),
        ]));
        expect(await within(sameSessionRejected.promise, "same-session rejection")).toBe(
          "session is already active",
        );
        expect(openedSessionIds).toEqual([firstSessionId]);
        expect(firstPromptCalls).toBe(1);
        expect(firstAbortCalls).toBe(1);

        differentSocket = connect(config(root).backendSocketPath);
        differentSocket.on("error", () => undefined);
        await within(once(differentSocket, "connect").then(() => undefined), "different-session connect");
        const differentReady = Promise.withResolvers<undefined>();
        const differentDecoder = new FrameDecoder();
        differentSocket.on("data", (chunk) => {
          for (const message of differentDecoder.push(
            Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk),
          )) {
            if (
              typeof message === "object"
              && message !== null
              && "type" in message
              && message.type === "ready"
            ) {
              differentReady.resolve(undefined);
            }
          }
        });
        differentSocket.write(encodeFrame({
          type: "hello",
          sessionId: differentSessionId,
          peer: {
            apiVersion: "agentd.client-peer/v1",
            adapterId: "adapter.tui",
            digest: `sha256:${"1".repeat(64)}`,
          },
        }));
        await within(differentReady.promise, "different-session ready");
        expect(openedSessionIds).toEqual([firstSessionId, differentSessionId]);
        await closeSocket(differentSocket);
        await within(differentClosed.promise, "different-session close");
      } finally {
        if (firstSocket !== undefined) await closeSocket(firstSocket);
        if (secondSocket !== undefined) await closeSocket(secondSocket);
        if (differentSocket !== undefined) await closeSocket(differentSocket);
        await server.stop();
        await rm(root, { recursive: true, force: true });
      }
    },
  );

  it("keeps an unsafe-close reservation across AgentServer replacement", async () => {
    const temporaryRoot = process.platform === "darwin" ? "/private/tmp" : tmpdir();
    const root = await mkdtemp(join(temporaryRoot, "ops-agent-server-replacement-"));
    const sessionId = parseSessionId("session-server-replacement-quarantine-1234");
    const promptStarted = Promise.withResolvers<undefined>();
    const closeStarted = Promise.withResolvers<undefined>();
    const neverSettles = new Promise<undefined>(() => undefined);
    const unsafeSession: OpsSession = {
      prompt: async () => {
        promptStarted.resolve(undefined);
        await neverSettles;
      },
      abort: () => neverSettles,
      close: () => {
        closeStarted.resolve(undefined);
        return Promise.reject(new Error("fixed unsafe cleanup failure"));
      },
    };
    const firstServer = new AgentServer(
      config(root),
      { open: () => Promise.resolve(unsafeSession) },
      { append: () => Promise.resolve() },
    );
    let replacementOpenCalls = 0;
    const replacementServer = new AgentServer(
      config(root),
      {
        open: () => {
          replacementOpenCalls += 1;
          return Promise.resolve(unsafeSession);
        },
      },
      { append: () => Promise.resolve() },
    );
    let firstSocket: Socket | undefined;
    let replacementSocket: Socket | undefined;
    let firstStopped = false;
    let replacementStarted = false;
    try {
      await firstServer.start();
      firstSocket = connect(config(root).backendSocketPath);
      firstSocket.on("error", () => undefined);
      await within(once(firstSocket, "connect").then(() => undefined), "first server connect");
      firstSocket.write(Buffer.concat([
        encodeFrame({
          type: "hello",
          sessionId,
          peer: {
            apiVersion: "agentd.client-peer/v1",
            adapterId: "adapter.tui",
            digest: `sha256:${"4".repeat(64)}`,
          },
        }),
        encodeFrame({
          type: "prompt",
          turnId: parseTurnId("turn-server-replacement-quarantine-1234"),
          text: "never settle",
        }),
      ]));
      await within(promptStarted.promise, "replacement fixture prompt start");
      await closeSocket(firstSocket);
      await within(closeStarted.promise, "unsafe close start");
      await firstServer.stop();
      firstStopped = true;

      await replacementServer.start();
      replacementStarted = true;
      replacementSocket = connect(config(root).backendSocketPath);
      replacementSocket.on("error", () => undefined);
      await within(
        once(replacementSocket, "connect").then(() => undefined),
        "replacement server connect",
      );
      const rejection = waitForErrorMessage(replacementSocket);
      replacementSocket.write(encodeFrame({
        type: "hello",
        sessionId,
        peer: {
          apiVersion: "agentd.client-peer/v1",
          adapterId: "adapter.tui",
          digest: `sha256:${"5".repeat(64)}`,
        },
      }));
      expect(await within(rejection, "replacement reservation rejection")).toBe(
        "session is already active",
      );
      expect(replacementOpenCalls).toBe(0);
    } finally {
      if (firstSocket !== undefined) await closeSocket(firstSocket);
      if (replacementSocket !== undefined) await closeSocket(replacementSocket);
      if (replacementStarted) await replacementServer.stop();
      if (!firstStopped) await firstServer.stop();
      await rm(root, { recursive: true, force: true });
    }
  });

  it("redacts and bounds errors before writing them to the client socket", async () => {
    const temporaryRoot = process.platform === "darwin" ? "/private/tmp" : tmpdir();
    const root = await mkdtemp(join(temporaryRoot, "ops-agent-server-error-"));
    const bearer = "provider-token.secret";
    const apiKey = `sk-${"b".repeat(24)}`;
    const neverSettles = new Promise<undefined>(() => undefined);
    const disposed = Promise.withResolvers<undefined>();
    let promptCalls = 0;
    let abortCalls = 0;
    const session: OpsSession = {
      prompt: async () => {
        promptCalls += 1;
        await neverSettles;
      },
      abort: () => {
        abortCalls += 1;
        return Promise.reject(new Error(
          `Authorization: Bearer ${bearer}\napi_key=${apiKey}\n${"x".repeat(16 * 1024)}`,
        ));
      },
      close: () => {
        disposed.resolve(undefined);
        return Promise.resolve();
      },
    };
    const audits: unknown[] = [];
    const server = new AgentServer(
      config(root),
      { open: () => Promise.resolve(session) },
      { append: (event) => { audits.push(event); return Promise.resolve(); } },
    );
    let socket: Socket | undefined;
    try {
      await server.start();
      socket = connect(config(root).backendSocketPath);
      socket.on("error", () => undefined);
      await within(once(socket, "connect").then(() => undefined), "socket connect");

      const receivedError = Promise.withResolvers<string>();
      const decoder = new FrameDecoder();
      socket.on("data", (chunk) => {
        for (const message of decoder.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk))) {
          const error = eventMessage(message, "error");
          if (error !== undefined) receivedError.resolve(error);
        }
      });
      const sessionId = parseSessionId("session-server-error-1234");
      const turnId = parseTurnId("turn-server-error-1234");
      const laterTurnId = parseTurnId("turn-server-error-later-1234");
      socket.write(Buffer.concat([
        encodeFrame({
          type: "hello",
          sessionId,
          peer: {
            apiVersion: "agentd.client-peer/v1",
            adapterId: "adapter.tui",
            digest: `sha256:${"c".repeat(64)}`,
          },
        }),
        encodeFrame({ type: "prompt", turnId, text: "fail safely" }),
        encodeFrame({ type: "abort" }),
        encodeFrame({ type: "prompt", turnId: laterTurnId, text: "stay queued" }),
      ]));

      const message = await within(receivedError.promise, "redacted error response");
      expect(message).not.toContain(bearer);
      expect(message).not.toContain(apiKey);
      expect(message).toContain("[REDACTED]");
      expect(message).toContain("[connection error truncated]");
      expect(Buffer.byteLength(message, "utf8")).toBeLessThanOrEqual(8 * 1024);
      const auditMessage = audits
        .map((event) => eventMessage(event, "connection_error"))
        .find((value) => value !== undefined);
      expect(auditMessage).toBe(message);
      expect(promptCalls).toBe(1);
      expect(abortCalls).toBe(1);

      await closeSocket(socket);
      await within(disposed.promise, "session disposal after abort rejection");
      expect(abortCalls).toBe(1);
    } finally {
      if (socket !== undefined) await closeSocket(socket);
      await server.stop();
      await rm(root, { recursive: true, force: true });
    }
  });

  it("releases a reservation after open explicitly rejects", async () => {
    const temporaryRoot = process.platform === "darwin" ? "/private/tmp" : tmpdir();
    const root = await mkdtemp(join(temporaryRoot, "ops-agent-server-open-reject-"));
    const sessionId = parseSessionId("session-server-open-reject-1234");
    let openCalls = 0;
    const session: OpsSession = {
      prompt: () => Promise.resolve(),
      abort: () => Promise.resolve(),
      close: () => Promise.resolve(),
    };
    const server = new AgentServer(
      config(root),
      {
        open: () => {
          openCalls += 1;
          return openCalls === 1
            ? Promise.reject(new Error("fixture open rejected"))
            : Promise.resolve(session);
        },
      },
      { append: () => Promise.resolve() },
    );
    let firstSocket: Socket | undefined;
    let secondSocket: Socket | undefined;
    try {
      await server.start();
      firstSocket = connect(config(root).backendSocketPath);
      firstSocket.on("error", () => undefined);
      await within(once(firstSocket, "connect").then(() => undefined), "first open-reject connect");
      const firstError = waitForErrorMessage(firstSocket);
      firstSocket.write(encodeFrame({
        type: "hello",
        sessionId,
        peer: {
          apiVersion: "agentd.client-peer/v1",
          adapterId: "adapter.tui",
          digest: `sha256:${"2".repeat(64)}`,
        },
      }));
      expect(await within(firstError, "explicit open rejection")).toBe("fixture open rejected");
      await closeSocket(firstSocket);

      secondSocket = connect(config(root).backendSocketPath);
      secondSocket.on("error", () => undefined);
      await within(once(secondSocket, "connect").then(() => undefined), "second open-reject connect");
      const ready = waitForReady(secondSocket);
      secondSocket.write(encodeFrame({
        type: "hello",
        sessionId,
        peer: {
          apiVersion: "agentd.client-peer/v1",
          adapterId: "adapter.tui",
          digest: `sha256:${"3".repeat(64)}`,
        },
      }));
      await within(ready, "same-session ready after open rejection");
      expect(openCalls).toBe(2);
    } finally {
      if (firstSocket !== undefined) await closeSocket(firstSocket);
      if (secondSocket !== undefined) await closeSocket(secondSocket);
      await server.stop();
      await rm(root, { recursive: true, force: true });
    }
  });

  it("disposes a session opened after socket close without starting or aborting its prompt", async () => {
    const temporaryRoot = process.platform === "darwin" ? "/private/tmp" : tmpdir();
    const root = await mkdtemp(join(temporaryRoot, "ops-agent-server-open-close-"));
    const openStarted = Promise.withResolvers<undefined>();
    const releaseOpen = Promise.withResolvers<OpsSession>();
    const disposed = Promise.withResolvers<undefined>();
    let openCalls = 0;
    let promptCalls = 0;
    let abortCalls = 0;
    const session: OpsSession = {
      prompt: () => {
        promptCalls += 1;
        return Promise.resolve();
      },
      abort: () => {
        abortCalls += 1;
        return Promise.resolve();
      },
      close: () => {
        disposed.resolve(undefined);
        return Promise.resolve();
      },
    };
    const server = new AgentServer(
      config(root),
      {
        open: () => {
          openCalls += 1;
          openStarted.resolve(undefined);
          return releaseOpen.promise;
        },
      },
      { append: () => Promise.resolve() },
    );
    let socket: Socket | undefined;
    let reopenedSocket: Socket | undefined;
    try {
      await server.start();
      socket = connect(config(root).backendSocketPath);
      socket.on("error", () => undefined);
      await within(once(socket, "connect").then(() => undefined), "socket connect");

      socket.write(Buffer.concat([
        encodeFrame({
          type: "hello",
          sessionId: parseSessionId("session-server-open-close-1234"),
          peer: {
            apiVersion: "agentd.client-peer/v1",
            adapterId: "adapter.tui",
            digest: `sha256:${"d".repeat(64)}`,
          },
          initialPrompt: "must never start",
        }),
        encodeFrame({ type: "abort" }),
      ]));

      await within(openStarted.promise, "session open start");
      await closeSocket(socket);
      await new Promise<undefined>((resolve) => setTimeout(() => resolve(undefined), 10));
      releaseOpen.resolve(session);
      await within(disposed.promise, "late-opened session disposal");
      expect(promptCalls).toBe(0);
      expect(abortCalls).toBe(0);

      reopenedSocket = connect(config(root).backendSocketPath);
      reopenedSocket.on("error", () => undefined);
      await within(once(reopenedSocket, "connect").then(() => undefined), "safe-close reconnect");
      const ready = waitForReady(reopenedSocket);
      reopenedSocket.write(encodeFrame({
        type: "hello",
        sessionId: parseSessionId("session-server-open-close-1234"),
        peer: {
          apiVersion: "agentd.client-peer/v1",
          adapterId: "adapter.tui",
          digest: `sha256:${"d".repeat(64)}`,
        },
      }));
      await within(ready, "same-session ready after safe close");
      expect(openCalls).toBe(2);
    } finally {
      releaseOpen.resolve(session);
      if (socket !== undefined) await closeSocket(socket);
      if (reopenedSocket !== undefined) await closeSocket(reopenedSocket);
      await server.stop();
      await rm(root, { recursive: true, force: true });
    }
  });
});
