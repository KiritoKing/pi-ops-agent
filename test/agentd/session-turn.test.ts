import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type {
  AgentSession,
  AgentSessionEvent,
} from "@earendil-works/pi-coding-agent";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  AgentTurnAbortLatch,
  AgentTurnAbortedError,
  AgentTurnAbortGraceError,
  AgentTurnPreflightGate,
  AgentTurnTimeoutError,
  closeActiveAgentTurn,
  waitForAgentSettlement,
  type AgentTurnDeadlineOptions,
} from "../../src/agentd/session-turn.js";

class FakeSettlementSource implements Pick<AgentSession, "subscribe"> {
  readonly #listeners = new Set<(event: AgentSessionEvent) => void>();
  abortCalls = 0;
  abortImplementation: () => Promise<void> = () => Promise.resolve();

  subscribe(listener: (event: AgentSessionEvent) => void): () => void {
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  }

  emit(event: AgentSessionEvent): void {
    for (const listener of this.#listeners) listener(event);
  }

  get listenerCount(): number {
    return this.#listeners.size;
  }

  abort(): Promise<void> {
    this.abortCalls += 1;
    return this.abortImplementation();
  }
}

function deadlineOptions(
  source: FakeSettlementSource,
  overrides: Partial<AgentTurnDeadlineOptions> = {},
): AgentTurnDeadlineOptions {
  return {
    timeoutMs: 1_000,
    abortGraceMs: 100,
    abort: async () => await source.abort(),
    onAbortGraceExceeded: () => undefined,
    ...overrides,
  };
}

afterEach(() => {
  vi.useRealTimers();
});

describe("Pi agent turn settlement", () => {
  it("pins installed pre-compaction ordering and simulates main-turn containment", async () => {
    const packageEntry = fileURLToPath(import.meta.resolve("@earendil-works/pi-coding-agent"));
    const agentSessionSource = await readFile(
      join(dirname(packageEntry), "core", "agent-session.js"),
      "utf8",
    );
    const promptStart = agentSessionSource.indexOf("async prompt(text, options)");
    const compactionCheck = agentSessionSource.indexOf(
      "await this._checkCompaction(lastAssistant, false);",
      promptStart,
    );
    const commitHook = agentSessionSource.indexOf("preflightResult?.(true);", compactionCheck);
    const mainTurn = agentSessionSource.indexOf(
      "await this._runAgentPrompt(messages);",
      commitHook,
    );
    const compactionMethod = agentSessionSource.indexOf("async _checkCompaction(");
    const autoCompactionCall = agentSessionSource.indexOf(
      "return await this._runAutoCompaction(",
      compactionMethod,
    );
    const autoCompactionMethod = agentSessionSource.indexOf("async _runAutoCompaction(");
    const compactionModelCall = agentSessionSource.indexOf(
      "const compactResult = await compact(",
      autoCompactionMethod,
    );

    expect(promptStart).toBeGreaterThanOrEqual(0);
    expect(compactionCheck).toBeGreaterThan(promptStart);
    expect(commitHook).toBeGreaterThan(compactionCheck);
    expect(mainTurn).toBeGreaterThan(commitHook);
    expect(agentSessionSource.slice(commitHook, mainTurn)).not.toContain("await ");
    expect(autoCompactionCall).toBeGreaterThan(compactionMethod);
    expect(compactionModelCall).toBeGreaterThan(autoCompactionMethod);

    const source = new FakeSettlementSource();
    const piPromptFinished = Promise.withResolvers<undefined>();
    const wrapperQuiesced = Promise.withResolvers<undefined>();
    let closing = false;
    const gate = new AgentTurnPreflightGate(
      () => source.abort(),
      piPromptFinished.promise,
      () => closing,
    );
    const simulatedWork = {
      preCompactionModelCalls: 1,
      mainTurnStarts: 0,
      toolStarts: 0,
    };

    closing = true;
    const close = closeActiveAgentTurn(gate.abort, wrapperQuiesced.promise, {
      timeoutMs: 180,
      abortGraceMs: 100,
      onAbortGraceExceeded: () => undefined,
    });
    expect(() => gate.observePreflight(true)).toThrow(AgentTurnAbortedError);
    piPromptFinished.resolve(undefined);
    wrapperQuiesced.resolve(undefined);
    await close;

    expect(simulatedWork).toEqual({
      preCompactionModelCalls: 1,
      mainTurnStarts: 0,
      toolStarts: 0,
    });
    expect(source.abortCalls).toBe(0);
  });

  it("cancels before Pi's main-turn commit without calling Pi abort", async () => {
    const source = new FakeSettlementSource();
    const piPromptFinished = Promise.withResolvers<undefined>();
    const gate = new AgentTurnPreflightGate(
      () => source.abort(),
      piPromptFinished.promise,
      () => false,
    );
    const abort = gate.abort.request();

    expect(() => gate.observePreflight(true)).toThrow(AgentTurnAbortedError);
    piPromptFinished.resolve(undefined);
    await abort;
    expect(source.abortCalls).toBe(0);
  });

  it("uses Pi abort after the synchronous preflight commit and blocks later tool work", async () => {
    const source = new FakeSettlementSource();
    let aborted = false;
    source.abortImplementation = () => {
      aborted = true;
      return Promise.resolve();
    };
    const gate = new AgentTurnPreflightGate(
      () => source.abort(),
      new Promise<undefined>(() => undefined),
      () => false,
    );
    let mainTurnStarts = 0;
    let toolStarts = 0;
    const wasAborted = (): boolean => aborted;

    gate.observePreflight(true);
    mainTurnStarts += 1;
    await gate.abort.request();
    if (!wasAborted()) toolStarts += 1;

    expect(mainTurnStarts).toBe(1);
    expect(source.abortCalls).toBe(1);
    expect(toolStarts).toBe(0);
  });

  it("treats Pi preflight rejection as safe completion without calling Pi abort", async () => {
    const source = new FakeSettlementSource();
    const piPromptFinished = Promise.withResolvers<undefined>();
    const gate = new AgentTurnPreflightGate(
      () => source.abort(),
      piPromptFinished.promise,
      () => false,
    );

    gate.observePreflight(false);
    piPromptFinished.resolve(undefined);
    await gate.abort.request();
    expect(source.abortCalls).toBe(0);
  });

  it("fails stop when Pi pre-compaction or another pre-commit phase never finishes", async () => {
    vi.useFakeTimers();
    const source = new FakeSettlementSource();
    const gate = new AgentTurnPreflightGate(
      () => source.abort(),
      new Promise<undefined>(() => undefined),
      () => false,
    );
    const fatalErrors: AgentTurnAbortGraceError[] = [];
    const closing = closeActiveAgentTurn(
      gate.abort,
      new Promise<undefined>(() => undefined),
      {
        timeoutMs: 180,
        abortGraceMs: 10,
        onAbortGraceExceeded: (error) => { fatalErrors.push(error); },
      },
    ).catch((error: unknown) => error);

    await vi.advanceTimersByTimeAsync(10);
    expect(await closing).toBeInstanceOf(AgentTurnAbortGraceError);
    expect(fatalErrors).toHaveLength(1);
    expect(source.abortCalls).toBe(0);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("returns a normal timeout when the deadline cancels Pi internal preflight", async () => {
    vi.useFakeTimers();
    const source = new FakeSettlementSource();
    const piPromptFinished = Promise.withResolvers<undefined>();
    const rawPrompt = Promise.withResolvers<undefined>();
    void rawPrompt.promise.then(
      () => piPromptFinished.resolve(undefined),
      () => piPromptFinished.resolve(undefined),
    );
    const gate = new AgentTurnPreflightGate(
      () => source.abort(),
      piPromptFinished.promise,
      () => false,
    );
    const fatalErrors: AgentTurnAbortGraceError[] = [];
    const waiting = waitForAgentSettlement(
      source,
      () => rawPrompt.promise,
      {
        timeoutMs: 5,
        abortGraceMs: 3,
        abort: () => gate.abort.request(),
        onAbortGraceExceeded: (error) => { fatalErrors.push(error); },
      },
    ).catch((error: unknown) => error);

    await vi.advanceTimersByTimeAsync(5);
    expect(() => gate.observePreflight(true)).toThrow(AgentTurnAbortedError);
    rawPrompt.reject(new AgentTurnAbortedError());
    const error = await waiting;
    expect(error).toBeInstanceOf(AgentTurnTimeoutError);
    expect(fatalErrors).toEqual([]);
    expect(source.abortCalls).toBe(0);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("disconnect cleanup reuses the turn latch and waits for wrapper quiescence", async () => {
    const source = new FakeSettlementSource();
    const wrapper = Promise.withResolvers<undefined>();
    const latch = new AgentTurnAbortLatch(() => source.abort());
    let completed = false;
    const closing = closeActiveAgentTurn(latch, wrapper.promise, {
      timeoutMs: 180,
      abortGraceMs: 100,
      onAbortGraceExceeded: () => undefined,
    }).then(() => { completed = true; });

    await Promise.resolve();
    expect(source.abortCalls).toBe(1);
    expect(completed).toBe(false);
    expect(latch.request()).toBe(latch.request());
    expect(source.abortCalls).toBe(1);

    wrapper.resolve(undefined);
    await closing;
    expect(completed).toBe(true);
    expect(source.abortCalls).toBe(1);
  });

  it("disconnect cleanup converts abort rejection to one fixed fatal error", async () => {
    const source = new FakeSettlementSource();
    source.abortImplementation = () => Promise.reject(new Error("provider secret detail"));
    const latch = new AgentTurnAbortLatch(() => source.abort());
    const fatalErrors: AgentTurnAbortGraceError[] = [];

    const error = await closeActiveAgentTurn(latch, Promise.resolve(), {
      timeoutMs: 180,
      abortGraceMs: 10,
      onAbortGraceExceeded: (fatal) => { fatalErrors.push(fatal); },
    }).catch((failure: unknown) => failure);

    expect(error).toBeInstanceOf(AgentTurnAbortGraceError);
    expect((error as AgentTurnAbortGraceError).trigger).toBe("disconnect");
    expect((error as AgentTurnAbortGraceError).reason).toBe("abort-rejected");
    expect((error as Error).message).toBe(
      "agent turn abort failed before idle was proven during connection cleanup",
    );
    expect((error as Error).message).not.toContain("provider secret detail");
    expect(fatalErrors).toEqual([error]);
    expect(source.abortCalls).toBe(1);
  });

  it("disconnect cleanup fails stop when idle and wrapper quiescence are not both proven", async () => {
    vi.useFakeTimers();
    const source = new FakeSettlementSource();
    const latch = new AgentTurnAbortLatch(() => source.abort());
    const fatalErrors: AgentTurnAbortGraceError[] = [];
    const closing = closeActiveAgentTurn(
      latch,
      new Promise<undefined>(() => undefined),
      {
        timeoutMs: 180,
        abortGraceMs: 10,
        onAbortGraceExceeded: (fatal) => { fatalErrors.push(fatal); },
      },
    ).catch((failure: unknown) => failure);

    await Promise.resolve();
    expect(source.abortCalls).toBe(1);
    await vi.advanceTimersByTimeAsync(10);
    const error = await closing;
    expect(error).toBeInstanceOf(AgentTurnAbortGraceError);
    expect((error as AgentTurnAbortGraceError).trigger).toBe("disconnect");
    expect((error as AgentTurnAbortGraceError).reason).toBe("grace-expired");
    expect((error as Error).message).toBe(
      "agent turn cleanup failed to settle within the 10ms disconnect grace",
    );
    expect(fatalErrors).toEqual([error]);
    expect(source.abortCalls).toBe(1);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("shares one abort and one poison hook when disconnect and deadline cleanup race", async () => {
    vi.useFakeTimers();
    const source = new FakeSettlementSource();
    source.abortImplementation = () => new Promise<void>(() => undefined);
    const latch = new AgentTurnAbortLatch(() => source.abort());
    let poison: AgentTurnAbortGraceError | undefined;
    let fatalHookCalls = 0;
    const poisonOnce = (error: AgentTurnAbortGraceError): void => {
      if (poison !== undefined) return;
      poison = error;
      fatalHookCalls += 1;
    };
    const waiting = waitForAgentSettlement(
      source,
      () => new Promise<void>(() => undefined),
      {
        timeoutMs: 5,
        abortGraceMs: 3,
        abort: () => latch.request(),
        onAbortGraceExceeded: poisonOnce,
      },
    ).catch((error: unknown) => error);
    const closing = closeActiveAgentTurn(
      latch,
      new Promise<undefined>(() => undefined),
      {
        timeoutMs: 5,
        abortGraceMs: 3,
        onAbortGraceExceeded: poisonOnce,
      },
    ).catch((error: unknown) => error);

    await Promise.resolve();
    expect(source.abortCalls).toBe(1);
    await vi.advanceTimersByTimeAsync(3);
    expect(await closing).toBeInstanceOf(AgentTurnAbortGraceError);
    expect(fatalHookCalls).toBe(1);
    expect(poison?.trigger).toBe("disconnect");

    await vi.advanceTimersByTimeAsync(5);
    expect(await waiting).toBeInstanceOf(AgentTurnAbortGraceError);
    expect(source.abortCalls).toBe(1);
    expect(fatalHookCalls).toBe(1);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("completes exactly once on agent_settled even when prompt remains pending", async () => {
    const source = new FakeSettlementSource();
    const prompt = new Promise<void>(() => undefined);
    let completions = 0;
    const waiting = waitForAgentSettlement(
      source,
      () => prompt,
      deadlineOptions(source),
    ).then(() => { completions += 1; });

    source.emit({ type: "agent_end", messages: [], willRetry: false });
    source.emit({ type: "compaction_start", reason: "threshold" });
    source.emit({
      type: "auto_retry_start",
      attempt: 1,
      maxAttempts: 2,
      delayMs: 1,
      errorMessage: "retry",
    });
    await Promise.resolve();
    expect(completions).toBe(0);

    source.emit({ type: "agent_settled" });
    source.emit({ type: "agent_settled" });
    await waiting;
    expect(completions).toBe(1);
    expect(source.listenerCount).toBe(0);
  });

  it("propagates a prompt failure before a terminal event", async () => {
    const source = new FakeSettlementSource();
    await expect(waitForAgentSettlement(
      source,
      () => Promise.reject(new Error("preflight rejected")),
      deadlineOptions(source),
    )).rejects.toThrow("preflight rejected");
    expect(source.listenerCount).toBe(0);
    expect(source.abortCalls).toBe(0);
  });

  it("does not treat prompt resolution itself as a settled turn", async () => {
    const source = new FakeSettlementSource();
    let completed = false;
    const waiting = waitForAgentSettlement(
      source,
      () => Promise.resolve(),
      deadlineOptions(source),
    ).then(() => { completed = true; });
    await Promise.resolve();
    await Promise.resolve();
    expect(completed).toBe(false);
    source.emit({ type: "agent_settled" });
    await waiting;
    expect(completed).toBe(true);
  });

  it("uses one absolute deadline and waits for abort to prove idle before failing", async () => {
    vi.useFakeTimers();
    const source = new FakeSettlementSource();
    const abort = Promise.withResolvers<undefined>();
    source.abortImplementation = () => abort.promise;
    let promptStarts = 0;
    let outcome: Error | "success" | undefined;
    const waiting = waitForAgentSettlement(
      source,
      () => {
        promptStarts += 1;
        return new Promise<void>(() => undefined);
      },
      deadlineOptions(source, { timeoutMs: 180, abortGraceMs: 10 }),
    ).then(
      () => { outcome = "success"; },
      (error: unknown) => { outcome = error instanceof Error ? error : new Error(String(error)); },
    );

    await vi.advanceTimersByTimeAsync(179);
    expect(source.abortCalls).toBe(0);
    await vi.advanceTimersByTimeAsync(1);
    expect(source.abortCalls).toBe(1);
    expect(promptStarts).toBe(1);

    source.emit({ type: "agent_settled" });
    await Promise.resolve();
    expect(outcome).toBeUndefined();
    expect(source.listenerCount).toBe(1);

    abort.resolve(undefined);
    await waiting;
    expect(outcome).toBeInstanceOf(AgentTurnTimeoutError);
    if (!(outcome instanceof Error)) throw new Error("timeout test did not capture an error");
    expect(outcome.message).toBe("agent turn timed out after 180ms and was aborted");
    expect(source.abortCalls).toBe(1);
    expect(source.listenerCount).toBe(0);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("invokes the injected fatal hook once when abort cannot settle within its grace", async () => {
    vi.useFakeTimers();
    const source = new FakeSettlementSource();
    source.abortImplementation = () => new Promise<void>(() => undefined);
    const fatalErrors: AgentTurnAbortGraceError[] = [];
    const waiting = waitForAgentSettlement(
      source,
      () => new Promise<void>(() => undefined),
      deadlineOptions(source, {
        timeoutMs: 25,
        abortGraceMs: 5,
        onAbortGraceExceeded: (error) => { fatalErrors.push(error); },
      }),
    ).then(
      () => undefined,
      (error: unknown) => error,
    );

    await vi.advanceTimersByTimeAsync(25);
    expect(source.abortCalls).toBe(1);
    await vi.advanceTimersByTimeAsync(5);
    const error = await waiting;
    expect(error).toBeInstanceOf(AgentTurnAbortGraceError);
    expect((error as Error).message).toBe(
      "agent turn timed out after 25ms and failed to settle within the 5ms abort grace",
    );
    expect(fatalErrors).toHaveLength(1);
    expect(fatalErrors[0]).toBe(error);
    expect(source.abortCalls).toBe(1);
    expect(source.listenerCount).toBe(0);
    expect(vi.getTimerCount()).toBe(0);

    source.emit({ type: "agent_settled" });
    await vi.advanceTimersByTimeAsync(100);
    expect(fatalErrors).toHaveLength(1);
  });

  it("fails stop with a fixed error when abort rejects before idle is proven", async () => {
    vi.useFakeTimers();
    const source = new FakeSettlementSource();
    source.abortImplementation = () => Promise.reject(new Error("untrusted abort detail"));
    const fatalErrors: AgentTurnAbortGraceError[] = [];
    const waiting = waitForAgentSettlement(
      source,
      () => new Promise<void>(() => undefined),
      deadlineOptions(source, {
        timeoutMs: 25,
        abortGraceMs: 5,
        onAbortGraceExceeded: (error) => { fatalErrors.push(error); },
      }),
    ).then(
      () => undefined,
      (error: unknown) => error,
    );

    await vi.advanceTimersByTimeAsync(25);
    const error = await waiting;
    expect(error).toBeInstanceOf(AgentTurnAbortGraceError);
    expect((error as AgentTurnAbortGraceError).reason).toBe("abort-rejected");
    expect((error as Error).message).toBe(
      "agent turn timed out after 25ms and abort failed before idle was proven",
    );
    expect((error as Error).message).not.toContain("untrusted abort detail");
    expect(fatalErrors).toEqual([error]);
    expect(source.abortCalls).toBe(1);
    expect(source.listenerCount).toBe(0);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("reuses a manually rejected abort at the deadline without calling Pi twice", async () => {
    vi.useFakeTimers();
    const source = new FakeSettlementSource();
    source.abortImplementation = () => Promise.reject(new Error("manual abort failed"));
    const abort = new AgentTurnAbortLatch(() => source.abort());
    const fatalErrors: AgentTurnAbortGraceError[] = [];
    const waiting = waitForAgentSettlement(
      source,
      () => new Promise<void>(() => undefined),
      deadlineOptions(source, {
        timeoutMs: 25,
        abortGraceMs: 5,
        abort: () => abort.request(),
        onAbortGraceExceeded: (error) => { fatalErrors.push(error); },
      }),
    ).then(
      () => undefined,
      (error: unknown) => error,
    );

    const rejectedAbort = abort.request();
    expect(abort.request()).toBe(rejectedAbort);
    expect(await rejectedAbort.catch((error: unknown) => error)).toBeInstanceOf(Error);
    expect(source.abortCalls).toBe(1);
    await vi.advanceTimersByTimeAsync(25);

    const error = await waiting;
    expect(error).toBeInstanceOf(AgentTurnAbortGraceError);
    expect((error as AgentTurnAbortGraceError).reason).toBe("abort-rejected");
    expect(fatalErrors).toEqual([error]);
    expect(source.abortCalls).toBe(1);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("reuses a manually hung abort through deadline grace without calling Pi twice", async () => {
    vi.useFakeTimers();
    const source = new FakeSettlementSource();
    source.abortImplementation = () => new Promise<void>(() => undefined);
    const abort = new AgentTurnAbortLatch(() => source.abort());
    const fatalErrors: AgentTurnAbortGraceError[] = [];
    const waiting = waitForAgentSettlement(
      source,
      () => new Promise<void>(() => undefined),
      deadlineOptions(source, {
        timeoutMs: 25,
        abortGraceMs: 5,
        abort: () => abort.request(),
        onAbortGraceExceeded: (error) => { fatalErrors.push(error); },
      }),
    ).then(
      () => undefined,
      (error: unknown) => error,
    );

    const hungAbort = abort.request();
    expect(abort.request()).toBe(hungAbort);
    void hungAbort;
    await Promise.resolve();
    expect(source.abortCalls).toBe(1);
    await vi.advanceTimersByTimeAsync(25);
    expect(source.abortCalls).toBe(1);
    await vi.advanceTimersByTimeAsync(5);

    const error = await waiting;
    expect(error).toBeInstanceOf(AgentTurnAbortGraceError);
    expect((error as AgentTurnAbortGraceError).reason).toBe("grace-expired");
    expect(fatalErrors).toEqual([error]);
    expect(source.abortCalls).toBe(1);
    expect(vi.getTimerCount()).toBe(0);
  });
});
