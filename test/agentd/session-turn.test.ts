import type {
  AgentSession,
  AgentSessionEvent,
} from "@earendil-works/pi-coding-agent";
import { describe, expect, it } from "vitest";
import { waitForAgentSettlement } from "../../src/agentd/session-turn.js";

class FakeSettlementSource implements Pick<AgentSession, "subscribe"> {
  readonly #listeners = new Set<(event: AgentSessionEvent) => void>();

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
}

describe("Pi agent turn settlement", () => {
  it("completes exactly once on agent_settled even when prompt remains pending", async () => {
    const source = new FakeSettlementSource();
    const prompt = new Promise<void>(() => undefined);
    let completions = 0;
    const waiting = waitForAgentSettlement(source, () => prompt).then(() => {
      completions += 1;
    });

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
    )).rejects.toThrow("preflight rejected");
    expect(source.listenerCount).toBe(0);
  });

  it("does not treat prompt resolution itself as a settled turn", async () => {
    const source = new FakeSettlementSource();
    let completed = false;
    const waiting = waitForAgentSettlement(source, () => Promise.resolve()).then(() => {
      completed = true;
    });
    await Promise.resolve();
    await Promise.resolve();
    expect(completed).toBe(false);
    source.emit({ type: "agent_settled" });
    await waiting;
    expect(completed).toBe(true);
  });
});
