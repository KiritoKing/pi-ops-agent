import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";
import type { AgentTransport } from "../../src/client/agent-connection.js";
import { ClientController, type HelperCaller } from "../../src/client/controller.js";
import type {
  ClientCompletionEvent,
  ClientEventSink,
} from "../../src/client/events.js";
import type { HelperRequest } from "../../src/shared/messages.js";

class FakeAgent implements AgentTransport {
  readonly prompts: string[] = [];
  abortCount = 0;
  closeCount = 0;

  sendPrompt(text: string): void {
    this.prompts.push(text);
  }

  abort(): void {
    this.abortCount += 1;
  }

  close(): void {
    this.closeCount += 1;
  }
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
      rootHelperSocket: "/tmp/root.sock",
      output: output.stream,
      eventSink,
    });
    controller.submit("first");
    controller.submit("second");
    expect(agent.prompts).toEqual([]);

    controller.handleAgentMessage({ type: "ready", sessionId: "session-1234" });
    expect(agent.prompts).toEqual(["first"]);
    controller.handleAgentMessage({ type: "status", state: "working" });
    controller.handleAgentMessage({ type: "delta", text: "result" });
    controller.handleAgentMessage({ type: "done" });
    await controller.waitForEvents();
    expect(agent.prompts).toEqual(["first", "second"]);
    expect(output.read()).toContain("Working...\nresult\n");
    expect(eventSink.events).toEqual([{
      version: 1,
      type: "completion",
      outcome: "success",
      content: "result",
    }]);
    expect(eventSink.events.map((event) => event.content).join("\n")).not.toContain("Working...");
  });

  it("sends approval directly to root-helper instead of agentd", async () => {
    const agent = new FakeAgent();
    const eventSink = new FakeEventSink();
    const output = capturedOutput();
    const requests: HelperRequest[] = [];
    const helperCaller: HelperCaller = (_socketPath, request) => {
      requests.push(request);
      return Promise.resolve({
        version: 1,
        requestId: request.requestId,
        ok: true,
        changeId: "change-1234",
        state: "COMMITTED",
        auditId: "audit-1234",
      });
    };
    const controller = new ClientController({
      agent,
      rootHelperSocket: "/tmp/root.sock",
      output: output.stream,
      helperCaller,
      eventSink,
    });

    controller.submit("/approve change-1234");
    await controller.waitForDirectCommands();
    await controller.waitForEvents();
    expect(agent.prompts).toEqual([]);
    expect(requests[0]).toMatchObject({
      method: "change.approve",
      changeId: "change-1234",
    });
    expect(output.read()).toContain("Working...");
    expect(output.read()).toContain("state=COMMITTED");
    expect(eventSink.events).toEqual([{
      version: 1,
      type: "completion",
      outcome: "success",
      content: "changeId=change-1234\nstate=COMMITTED\nauditId=audit-1234",
    }]);
    expect(eventSink.events[0]?.content).not.toContain("Working...");
  });

  it("uses the long transport timeout for rollback", async () => {
    const agent = new FakeAgent();
    const output = capturedOutput();
    let timeoutMs: number | undefined;
    const helperCaller: HelperCaller = (_socketPath, request, _signal, timeout) => {
      timeoutMs = timeout;
      return Promise.resolve({
        version: 1,
        requestId: request.requestId,
        ok: true,
        changeId: "change-1234",
        state: "ROLLED_BACK",
      });
    };
    const controller = new ClientController({
      agent,
      rootHelperSocket: "/tmp/root.sock",
      output: output.stream,
      helperCaller,
    });

    controller.submit("/rollback change-1234");
    await controller.waitForDirectCommands();
    expect(timeoutMs).toBeGreaterThan(9 * 60_000);
    expect(output.read()).toContain("state=ROLLED_BACK");
  });

  it("clears queued prompts when aborted", () => {
    const agent = new FakeAgent();
    const output = capturedOutput();
    const controller = new ClientController({
      agent,
      rootHelperSocket: "/tmp/root.sock",
      output: output.stream,
      hasInitialPrompt: true,
    });
    controller.submit("must not run");
    controller.abort();
    controller.handleAgentMessage({ type: "ready", sessionId: "session-1234" });
    controller.handleAgentMessage({ type: "done" });
    expect(agent.abortCount).toBe(1);
    expect(agent.prompts).toEqual([]);
  });

  it("notifies sanitized input and agent errors", async () => {
    const agent = new FakeAgent();
    const eventSink = new FakeEventSink();
    const output = capturedOutput();
    const controller = new ClientController({
      agent,
      rootHelperSocket: "/tmp/root.sock",
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
    expect(eventSink.events[0]?.content).toContain("usage: /approve <changeId>");
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
      rootHelperSocket: "/tmp/root.sock",
      output: output.stream,
      eventSink,
    });

    controller.submit("/status");
    await controller.waitForEvents();
    expect(eventSink.events).toHaveLength(1);
    expect(output.read()).toContain("[input error] usage: /status <changeId>");
    expect(output.read()).toContain("[event sink error] send failed");
  });
});
