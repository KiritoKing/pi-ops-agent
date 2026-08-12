import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";
import type { AgentTransport } from "../../src/client/agent-connection.js";
import { parseSessionId, parseTurnId } from "../../src/shared/domain.js";
import { parseChangeId, parseMachineId, parseServerId, parseTargetId } from "../../src/shared/domain.js";
import { encodeChangeRef } from "../../src/shared/approval.js";
import { ClientController } from "../../src/client/controller.js";
import type { ApprovalCommandHandler } from "../../src/client/approval-router.js";
import type {
  ClientCompletionEvent,
  ClientEventSink,
} from "../../src/client/events.js";

const CHANGE_REFERENCE = {
  version: 1,
  serverId: parseServerId("server-12345678"),
  machineId: parseMachineId("machine-12345678"),
  targetId: parseTargetId("target-12345678"),
  changeId: parseChangeId("change-1234"),
} as const;
const CHANGE_REF = encodeChangeRef(CHANGE_REFERENCE);

class FakeAgent implements AgentTransport {
  readonly prompts: string[] = [];
  abortCount = 0;
  closeCount = 0;

  sendPrompt(text: string): ReturnType<typeof parseTurnId> {
    this.prompts.push(text);
    return parseTurnId("turn-12345678");
  }

  abort(): void {
    this.abortCount += 1;
  }

  close(): void {
    this.closeCount += 1;
  }
}

class SequencedFakeAgent implements AgentTransport {
  readonly prompts: string[] = [];
  readonly #turnIds: ReturnType<typeof parseTurnId>[];

  constructor(turnIds: readonly string[]) {
    this.#turnIds = turnIds.map((turnId) => parseTurnId(turnId));
  }

  sendPrompt(text: string): ReturnType<typeof parseTurnId> {
    this.prompts.push(text);
    const turnId = this.#turnIds.shift();
    if (turnId === undefined) throw new Error("test turn IDs exhausted");
    return turnId;
  }

  abort(): void {}
  close(): void {}
}

class FakeEventSink implements ClientEventSink {
  readonly events: ClientCompletionEvent[] = [];
  error?: Error;

  publish(event: ClientCompletionEvent): Promise<void> {
    this.events.push(event);
    return this.error ? Promise.reject(this.error) : Promise.resolve();
  }
}

function capturedOutput(): { stream: PassThrough; read: () => string } {
  const stream = new PassThrough();
  let text = "";
  stream.on("data", (chunk: Buffer | string) => {
    text += chunk.toString();
  });
  return { stream, read: () => text };
}

describe("ClientController", () => {
  it("queues prompts until ready, serializes turns, and sends only assistant deltas", async () => {
    const agent = new FakeAgent();
    const eventSink = new FakeEventSink();
    const output = capturedOutput();
    const controller = new ClientController({
      agent,
      output: output.stream,
      eventSink,
    });
    controller.submit("first");
    controller.submit("second");
    expect(agent.prompts).toEqual([]);

    const sessionId = parseSessionId("session-1234");
    const turnId = parseTurnId("turn-12345678");
    controller.handleAgentMessage({ type: "ready", sessionId });
    expect(agent.prompts).toEqual(["first"]);
    controller.handleAgentMessage({ type: "status", state: "working", sessionId, turnId });
    controller.handleAgentMessage({ type: "delta", text: "result", sessionId, turnId });
    controller.handleAgentMessage({ type: "done", sessionId, turnId });
    controller.handleAgentMessage({ type: "done", sessionId, turnId });
    await controller.waitForEvents();
    expect(agent.prompts).toEqual(["first", "second"]);
    expect(output.read()).toContain("Working...\nresult\n");
    expect(eventSink.events).toMatchObject([{
      version: 1,
      type: "completion",
      outcome: "success",
      content: "result",
      sessionId,
      turnId,
    }]);
    expect(eventSink.events).toHaveLength(1);
    expect(eventSink.events.map((event) => event.content).join("\n")).not.toContain("Working...");
  });

  it("sends approval to the model-external C/S handler instead of agentd", async () => {
    const agent = new FakeAgent();
    const eventSink = new FakeEventSink();
    const output = capturedOutput();
    const commands: string[] = [];
    const directCommandHandler: ApprovalCommandHandler = (command) => {
      commands.push(`${command.kind}:${command.changeRef.changeId}`);
      return Promise.resolve({
        version: 1,
        requestId: "request-approval",
        ok: true,
        changeId: "change-1234",
        state: "COMMITTED",
        auditId: "audit-1234",
      });
    };
    const controller = new ClientController({
      agent,
      output: output.stream,
      directCommandHandler,
      eventSink,
    });

    const sessionId = parseSessionId("session-1234");
    const turnId = parseTurnId("turn-12345678");
    controller.handleAgentMessage({ type: "ready", sessionId });
    controller.submit("restart the exact service after checking health");
    controller.handleAgentMessage({
      type: "tool",
      phase: "end",
      name: "ops_propose_change",
      sessionId,
      turnId,
      preparedChangeRefs: [CHANGE_REF],
    });
    controller.handleAgentMessage({ type: "done", sessionId, turnId });
    controller.submit(`/approve ${CHANGE_REF}`);
    await controller.waitForDirectCommands();
    await controller.waitForEvents();
    expect(agent.prompts).toEqual(["restart the exact service after checking health"]);
    expect(commands).toEqual(["approve:change-1234"]);
    expect(output.read()).toContain("Working...");
    expect(output.read()).toContain("state=COMMITTED");
    expect(eventSink.events).toMatchObject([{
      version: 1,
      type: "completion",
      outcome: "success",
      content: "changeId=change-1234\nstate=COMMITTED\nauditId=audit-1234",
    }]);
    expect(eventSink.events[0]?.content).not.toContain("Working...");
  });

  it("binds approval review to the exact prepare session and turn", async () => {
    const agent = new FakeAgent();
    const output = capturedOutput();
    const contexts: Parameters<ApprovalCommandHandler>[1][] = [];
    const controller = new ClientController({
      agent,
      output: output.stream,
      localConsole: true,
      directCommandHandler: (command, context) => {
        contexts.push(context ?? {});
        return Promise.resolve({
          version: 1,
          requestId: "request-review",
          ok: true,
          changeId: command.changeRef.changeId,
          state: "REVIEW_REQUIRED",
        });
      },
    });

    const sessionId = parseSessionId("session-1234");
    const turnId = parseTurnId("turn-12345678");
    controller.handleAgentMessage({ type: "ready", sessionId });
    controller.submit("restart the demo only after checking health token=secret-value");
    controller.handleAgentMessage({
      type: "tool",
      phase: "end",
      name: "ops_propose_change",
      sessionId,
      turnId,
      preparedChangeRefs: [CHANGE_REF],
    });
    controller.handleAgentMessage({ type: "done", sessionId, turnId });
    controller.submit(`/approve ${CHANGE_REF}`);
    await controller.waitForDirectCommands();

    expect(contexts).toEqual([{
      intentBinding: {
        version: 1,
        sessionId,
        turnId,
        changeRef: CHANGE_REFERENCE,
        userIntent: "restart the demo only after checking health token=[REDACTED]",
      },
      localConsole: true,
    }]);
  });

  it("keeps multiple pending changes bound to their own turns despite later unrelated input", async () => {
    const agent = new SequencedFakeAgent([
      "turn-first-12345678",
      "turn-second-12345678",
      "turn-unrelated-12345678",
    ]);
    const output = capturedOutput();
    const sessionId = parseSessionId("session-multiple-12345678");
    const firstTurn = parseTurnId("turn-first-12345678");
    const secondTurn = parseTurnId("turn-second-12345678");
    const unrelatedTurn = parseTurnId("turn-unrelated-12345678");
    const secondReference = {
      ...CHANGE_REFERENCE,
      changeId: parseChangeId("change-5678"),
    };
    const secondEncoded = encodeChangeRef(secondReference);
    const seen: Array<{ changeId: string; userIntent?: string; turnId?: string }> = [];
    const calls = new Map<string, number>();
    const controller = new ClientController({
      agent,
      output: output.stream,
      directCommandHandler: (command, context) => {
        const binding = context?.intentBinding;
        seen.push({
          changeId: command.changeRef.changeId,
          ...(binding === undefined ? {} : {
            userIntent: binding.userIntent,
            turnId: binding.turnId,
          }),
        });
        const count = (calls.get(command.changeRef.changeId) ?? 0) + 1;
        calls.set(command.changeRef.changeId, count);
        return Promise.resolve({
          version: 1,
          requestId: `request-${command.changeRef.changeId}`,
          ok: true,
          changeId: command.changeRef.changeId,
          state: count === 1 ? "REVIEW_REQUIRED" : "COMMITTED",
        });
      },
    });

    controller.handleAgentMessage({ type: "ready", sessionId });
    controller.submit("restart the first service");
    controller.handleAgentMessage({
      type: "tool", phase: "end", name: "ops_propose_change",
      sessionId, turnId: firstTurn, preparedChangeRefs: [CHANGE_REF],
    });
    controller.handleAgentMessage({ type: "done", sessionId, turnId: firstTurn });
    controller.submit("restart the second service");
    controller.handleAgentMessage({
      type: "tool", phase: "end", name: "ops_propose_change",
      sessionId, turnId: secondTurn, preparedChangeRefs: [secondEncoded],
    });
    controller.handleAgentMessage({ type: "done", sessionId, turnId: secondTurn });
    controller.submit("what is the weather in the workspace logs?");
    controller.handleAgentMessage({ type: "done", sessionId, turnId: unrelatedTurn });

    controller.submit(`/approve ${CHANGE_REF}`);
    controller.submit(`/approve ${CHANGE_REF}`);
    controller.submit(`/approve ${secondEncoded}`);
    controller.submit(`/approve ${secondEncoded}`);
    await controller.waitForDirectCommands();

    expect(seen).toEqual([
      {
        changeId: "change-1234",
        userIntent: "restart the first service",
        turnId: firstTurn,
      },
      {
        changeId: "change-1234",
        userIntent: "restart the first service",
        turnId: firstTurn,
      },
      {
        changeId: "change-5678",
        userIntent: "restart the second service",
        turnId: secondTurn,
      },
      {
        changeId: "change-5678",
        userIntent: "restart the second service",
        turnId: secondTurn,
      },
    ]);
  });

  it("fails closed for a prepared-change notification from the wrong turn", async () => {
    const agent = new SequencedFakeAgent(["turn-real-12345678"]);
    const output = capturedOutput();
    let handled = 0;
    const controller = new ClientController({
      agent,
      output: output.stream,
      directCommandHandler: () => {
        handled += 1;
        return Promise.resolve({ version: 1, requestId: "request-never", ok: true });
      },
    });
    const sessionId = parseSessionId("session-wrong-turn-12345678");
    controller.handleAgentMessage({ type: "ready", sessionId });
    controller.submit("restart only the requested service");
    controller.handleAgentMessage({
      type: "tool",
      phase: "end",
      name: "ops_propose_change",
      sessionId,
      turnId: parseTurnId("turn-forged-12345678"),
      preparedChangeRefs: [CHANGE_REF],
    });
    controller.handleAgentMessage({
      type: "done",
      sessionId,
      turnId: parseTurnId("turn-real-12345678"),
    });
    controller.submit(`/approve ${CHANGE_REF}`);
    await controller.waitForDirectCommands();

    expect(handled).toBe(0);
    expect(output.read()).toContain("approval intent unavailable for this change");
  });

  it("does not recover an approval intent from resumed session history", async () => {
    const agent = new FakeAgent();
    const output = capturedOutput();
    let handled = 0;
    const controller = new ClientController({
      agent,
      output: output.stream,
      directCommandHandler: () => {
        handled += 1;
        return Promise.resolve({ version: 1, requestId: "request-never", ok: true });
      },
    });
    controller.handleAgentMessage({
      type: "ready",
      sessionId: parseSessionId("session-resumed-12345678"),
    });
    controller.submit(`/rollback ${CHANGE_REF}`);
    await controller.waitForDirectCommands();

    expect(handled).toBe(0);
    expect(output.read()).toContain("prepare it again from this live client session");
  });

  it("routes rollback through the model-external C/S handler", async () => {
    const agent = new FakeAgent();
    const output = capturedOutput();
    let action: string | undefined;
    const directCommandHandler: ApprovalCommandHandler = (command) => {
      action = command.kind;
      return Promise.resolve({
        version: 1,
        requestId: "request-rollback",
        ok: true,
        changeId: "change-1234",
        state: "ROLLED_BACK",
      });
    };
    const controller = new ClientController({
      agent,
      output: output.stream,
      directCommandHandler,
    });

    const sessionId = parseSessionId("session-1234");
    const turnId = parseTurnId("turn-12345678");
    controller.handleAgentMessage({ type: "ready", sessionId });
    controller.submit("undo the exact prepared change if its verification fails");
    controller.handleAgentMessage({
      type: "tool",
      phase: "end",
      name: "ops_propose_change",
      sessionId,
      turnId,
      preparedChangeRefs: [CHANGE_REF],
    });
    controller.handleAgentMessage({ type: "done", sessionId, turnId });
    controller.submit(`/rollback ${CHANGE_REF}`);
    await controller.waitForDirectCommands();
    expect(action).toBe("rollback");
    expect(output.read()).toContain("state=ROLLED_BACK");
  });

  it("fails closed when an approval command starts while agentd is busy", async () => {
    const agent = new FakeAgent();
    const output = capturedOutput();
    let handled = 0;
    const controller = new ClientController({
      agent,
      output: output.stream,
      directCommandHandler: () => {
        handled += 1;
        return Promise.resolve({ version: 1, requestId: "request-never", ok: true });
      },
    });
    controller.handleAgentMessage({
      type: "ready",
      sessionId: parseSessionId("session-busy-12345678"),
    });
    controller.submit("keep the agent turn active");
    controller.submit(`/reject ${CHANGE_REF}`);
    await controller.waitForDirectCommands();
    expect(handled).toBe(0);
    expect(output.read()).toContain("agent must be ready and idle");
  });

  it("freezes and bounds escaped agent output across review and submitter TTY confirmation", async () => {
    const agent = new FakeAgent();
    const output = capturedOutput();
    const responses: Array<(response: {
      version: 1;
      requestId: string;
      ok: boolean;
      changeId: string;
      state: string;
      summary: string;
    }) => void> = [];
    const controller = new ClientController({
      agent,
      output: output.stream,
      directCommandHandler: () => new Promise((resolve) => responses.push(resolve)),
    });
    const sessionId = parseSessionId("session-freeze-12345678");
    const preparedTurn = parseTurnId("turn-12345678");
    controller.handleAgentMessage({ type: "ready", sessionId });
    controller.submit("restart the exact service only after review");
    controller.handleAgentMessage({
      type: "tool",
      phase: "end",
      name: "ops_propose_change",
      sessionId,
      turnId: preparedTurn,
      preparedChangeRefs: [CHANGE_REF],
    });
    controller.handleAgentMessage({ type: "done", sessionId, turnId: preparedTurn });

    controller.submit(`/approve ${CHANGE_REF}`);
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(responses).toHaveLength(1);
    const injectedReviewTurn = parseTurnId("turn-injected-review-12345678");
    controller.handleAgentMessage({
      type: "status", state: "working", sessionId, turnId: injectedReviewTurn,
    });
    controller.handleAgentMessage({
      type: "delta", text: "hidden\x1b[2Jreview-spoof", sessionId, turnId: injectedReviewTurn,
    });
    controller.handleAgentMessage({ type: "done", sessionId, turnId: injectedReviewTurn });
    expect(output.read()).not.toContain("review-spoof");
    responses[0]?.({
      version: 1,
      requestId: "request-review-12345678",
      ok: true,
      changeId: "change-1234",
      state: "REVIEW_REQUIRED",
      summary: "authoritative reviewer display",
    });
    await controller.waitForDirectCommands();
    expect(output.read()).toContain("authoritative reviewer display");
    expect(output.read()).not.toContain("review-spoof");

    controller.submit(`/approve ${CHANGE_REF}`);
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(responses).toHaveLength(2);
    const injectedTTYTurn = parseTurnId("turn-injected-tty-12345678");
    controller.handleAgentMessage({
      type: "status", state: "working", sessionId, turnId: injectedTTYTurn,
    });
    controller.handleAgentMessage({
      type: "delta",
      text: `hidden\x1b[31mtty-spoof${"x".repeat(300 * 1024)}`,
      sessionId,
      turnId: injectedTTYTurn,
    });
    controller.handleAgentMessage({ type: "done", sessionId, turnId: injectedTTYTurn });
    expect(output.read()).not.toContain("tty-spoof");
    responses[1]?.({
      version: 1,
      requestId: "request-commit-12345678",
      ok: true,
      changeId: "change-1234",
      state: "COMMITTED",
      summary: "root TTY confirmation completed",
    });
    await controller.waitForDirectCommands();

    const rendered = output.read();
    const terminalIndex = rendered.indexOf("root TTY confirmation completed");
    const separatorIndex = rendered.indexOf("--- delayed untrusted agent output");
    expect(terminalIndex).toBeGreaterThan(-1);
    expect(separatorIndex).toBeGreaterThan(terminalIndex);
    expect(rendered).toContain("hidden\\x1b[2Jreview-spoof");
    expect(rendered).toContain("hidden\\x1b[31mtty-spoof");
    expect(rendered).toContain("[delayed agent output truncated at 256 KiB]");
    expect(rendered).not.toContain("\x1b");
  });

  it("clears queued prompts when aborted", () => {
    const agent = new FakeAgent();
    const output = capturedOutput();
    const controller = new ClientController({
      agent,
      output: output.stream,
      hasInitialPrompt: true,
    });
    controller.submit("must not run");
    controller.abort();
    const sessionId = parseSessionId("session-1234");
    const turnId = parseTurnId("turn-12345678");
    controller.handleAgentMessage({ type: "ready", sessionId });
    controller.handleAgentMessage({ type: "done", sessionId, turnId });
    expect(agent.abortCount).toBe(1);
    expect(agent.prompts).toEqual([]);
  });

  it("notifies sanitized input and agent errors", async () => {
    const agent = new FakeAgent();
    const eventSink = new FakeEventSink();
    const output = capturedOutput();
    const controller = new ClientController({
      agent,
      output: output.stream,
      eventSink,
    });

    controller.submit("/approve");
    controller.handleAgentMessage({
      type: "error",
      message: "upstream token=secret-value authorization: Bearer abc123",
    });
    const fakePassword = ["hunter", "2"].join("");
    const fakeToken = `sk-${"a".repeat(16)}`;
    controller.handleAgentError(new Error(
      `socket AWS_SECRET_ACCESS_KEY=${fakePassword} ${fakeToken}`,
    ));
    await controller.waitForEvents();

    expect(eventSink.events).toHaveLength(3);
    expect(eventSink.events[0]?.content).toContain("usage: /approve <changeRef>");
    expect(eventSink.events[0]?.outcome).toBe("error");
    expect(eventSink.events[1]?.content).toBe(
      "[agentd error] upstream token=[REDACTED] authorization: [REDACTED]",
    );
    expect(eventSink.events[2]?.content).toBe(
      "[agentd error] socket AWS_SECRET_ACCESS_KEY=[REDACTED] [REDACTED]",
    );
    const contents = eventSink.events.map((event) => event.content).join("\n");
    expect(contents).not.toContain("secret-value");
    expect(contents).not.toContain(fakePassword);
  });

  it("reports event sink failure locally without recursively publishing", async () => {
    const agent = new FakeAgent();
    const eventSink = new FakeEventSink();
    eventSink.error = new Error("send failed");
    const output = capturedOutput();
    const controller = new ClientController({
      agent,
      output: output.stream,
      eventSink,
    });

    controller.submit("/status");
    await controller.waitForEvents();
    expect(eventSink.events).toHaveLength(1);
    expect(output.read()).toContain("[input error] usage: /status <changeRef>");
    expect(output.read()).toContain("[event sink error] send failed");
  });
});
