import type {
  AgentSession,
  AgentSessionEvent,
} from "@earendil-works/pi-coding-agent";

type SettlementSource = Pick<AgentSession, "subscribe">;

/**
 * Wait for the public Pi turn boundary without depending on `prompt()` settling.
 *
 * Pi 0.84.1 emits `agent_settled` after retry, compaction, and queued
 * continuations have all finished. Some transports can leave the `prompt()`
 * promise pending after that event, while an early promise resolution is not a
 * transport completion boundary. `agent_settled` is therefore authoritative.
 * A short post-`agent_end` fallback exists only for older/nonconforming sessions
 * and is cancelled by retry, compaction, or a new agent start.
 */
export async function waitForAgentSettlement(
  session: SettlementSource,
  startPrompt: () => Promise<void>,
): Promise<void> {
  const { promise, resolve, reject } = Promise.withResolvers<undefined>();
  let finished = false;
  let fallback: NodeJS.Timeout | undefined;
  const cancelFallback = (): void => {
    if (fallback !== undefined) clearTimeout(fallback);
    fallback = undefined;
  };
  const succeed = (): void => {
    if (finished) return;
    finished = true;
    cancelFallback();
    resolve(undefined);
  };
  const fail = (error: unknown): void => {
    if (finished) return;
    finished = true;
    cancelFallback();
    reject(error);
  };
  const unsubscribe = session.subscribe((event: AgentSessionEvent) => {
    if (event.type === "agent_settled") {
      succeed();
      return;
    }
    if (event.type === "agent_end") {
      cancelFallback();
      if (!event.willRetry) {
        fallback = setTimeout(succeed, 1_000);
        fallback.unref();
      }
      return;
    }
    if (event.type === "agent_start" || event.type === "auto_retry_start"
      || event.type === "compaction_start") {
      cancelFallback();
    }
  });

  try {
    let prompt: Promise<void>;
    try {
      prompt = startPrompt();
    } catch (error) {
      fail(error);
      return await promise;
    }
    void prompt.catch(fail);
    await promise;
  } finally {
    cancelFallback();
    unsubscribe();
  }
}
