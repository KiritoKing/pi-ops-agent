import type {
  AgentSession,
  AgentSessionEvent,
} from "@earendil-works/pi-coding-agent";

type SettlementSource = Pick<AgentSession, "subscribe">;

export const DEFAULT_AGENT_TURN_TIMEOUT_MS = 180_000;
export const DEFAULT_AGENT_ABORT_GRACE_MS = 10_000;

const MAX_TIMER_DELAY_MS = 2_147_483_647;

export class AgentTurnTimeoutError extends Error {
  constructor(timeoutMs: number) {
    super(`agent turn timed out after ${timeoutMs}ms and was aborted`);
    this.name = "AgentTurnTimeoutError";
  }
}

export class AgentTurnAbortGraceError extends Error {
  readonly reason: "abort-rejected" | "grace-expired";
  readonly trigger: "deadline" | "disconnect";

  constructor(
    timeoutMs: number,
    abortGraceMs: number,
    reason: "abort-rejected" | "grace-expired",
    trigger: "deadline" | "disconnect" = "deadline",
  ) {
    super(trigger === "disconnect"
      ? (reason === "grace-expired"
          ? `agent turn cleanup failed to settle within the ${abortGraceMs}ms disconnect grace`
          : "agent turn abort failed before idle was proven during connection cleanup")
      : (reason === "grace-expired"
          ? `agent turn timed out after ${timeoutMs}ms and failed to settle within the ${abortGraceMs}ms abort grace`
          : `agent turn timed out after ${timeoutMs}ms and abort failed before idle was proven`));
    this.name = "AgentTurnAbortGraceError";
    this.reason = reason;
    this.trigger = trigger;
  }
}

export class AgentTurnAbortedError extends Error {
  constructor() {
    super("agent turn was cancelled before main agent execution");
    this.name = "AgentTurnAbortedError";
  }
}

/** Memoize the one Pi abort completion barrier for a single active turn. */
export class AgentTurnAbortLatch {
  readonly #abort: () => Promise<void>;
  #abortPromise: Promise<void> | undefined;

  constructor(abort: () => Promise<void>) {
    this.#abort = abort;
  }

  get requested(): boolean {
    return this.#abortPromise !== undefined;
  }

  request(): Promise<void> {
    this.#abortPromise ??= Promise.resolve().then(async () => await this.#abort());
    return this.#abortPromise;
  }
}

/**
 * Bind cancellation to Pi's synchronous prompt commit hook.
 *
 * Before `preflightResult(true)`, Pi may be awaiting authentication,
 * auto-compaction, or extension preflight while `AgentSession.abort()` would
 * report idle and fail to cancel the future main run. Pi 0.84.1 may already be
 * using its compaction model in this window; this gate does not retroactively
 * cancel or erase that bounded preflight work. A cancellation requested before
 * commit makes the hook throw, preventing the subsequent `_runAgentPrompt()`
 * and its tools. Once committed, Pi calls `_runAgentPrompt()` synchronously
 * after the hook returns, so the shared latch can safely use
 * `AgentSession.abort()` as its idle completion barrier.
 */
export class AgentTurnPreflightGate {
  readonly abort: AgentTurnAbortLatch;
  readonly #committed = Promise.withResolvers<undefined>();
  readonly #isClosing: () => boolean;

  constructor(
    abortPi: () => Promise<void>,
    precommitFinished: Promise<void>,
    isClosing: () => boolean,
  ) {
    this.#isClosing = isClosing;
    this.abort = new AgentTurnAbortLatch(async () => {
      const phase = await Promise.race([
        this.#committed.promise.then(() => "committed" as const),
        precommitFinished.then(
          () => "finished" as const,
          () => "finished" as const,
        ),
      ]);
      if (phase === "committed") await abortPi();
    });
  }

  observePreflight(accepted: boolean): void {
    if (!accepted) return;
    if (this.#isClosing() || this.abort.requested) throw new AgentTurnAbortedError();
    this.#committed.resolve(undefined);
  }
}

export interface AgentTurnDeadlineOptions {
  timeoutMs?: number;
  abortGraceMs?: number;
  abort(): Promise<void>;
  onAbortGraceExceeded(error: AgentTurnAbortGraceError): void;
}

export interface AgentTurnDisconnectOptions {
  timeoutMs?: number;
  abortGraceMs?: number;
  onAbortGraceExceeded(error: AgentTurnAbortGraceError): void;
}

function boundedTimerDelay(value: number | undefined, fallback: number, label: string): number {
  const delay = value ?? fallback;
  if (!Number.isSafeInteger(delay) || delay < 1 || delay > MAX_TIMER_DELAY_MS) {
    throw new Error(`${label} must be an integer between 1 and ${MAX_TIMER_DELAY_MS}`);
  }
  return delay;
}

/**
 * Prove both Pi idle and the surrounding prompt wrapper quiescent after a
 * connection disappears. The caller must pass the active turn's exact abort
 * latch; creating another latch would permit a second Pi abort.
 */
export async function closeActiveAgentTurn(
  abort: AgentTurnAbortLatch,
  wrapperQuiesced: Promise<void>,
  options: AgentTurnDisconnectOptions,
): Promise<void> {
  const timeoutMs = boundedTimerDelay(
    options.timeoutMs,
    DEFAULT_AGENT_TURN_TIMEOUT_MS,
    "agent turn timeout",
  );
  const abortGraceMs = boundedTimerDelay(
    options.abortGraceMs,
    DEFAULT_AGENT_ABORT_GRACE_MS,
    "agent turn disconnect grace",
  );
  let grace: NodeJS.Timeout | undefined;
  const graceExpired = new Promise<never>((_resolve, reject) => {
    grace = setTimeout(() => {
      reject(new AgentTurnAbortGraceError(
        timeoutMs,
        abortGraceMs,
        "grace-expired",
        "disconnect",
      ));
    }, abortGraceMs);
    grace.unref();
  });
  const idleAndQuiesced = abort.request().then(async () => {
    await wrapperQuiesced.then(
      () => undefined,
      () => undefined,
    );
  });
  try {
    await Promise.race([idleAndQuiesced, graceExpired]);
  } catch (error) {
    const fatalError = error instanceof AgentTurnAbortGraceError
      ? error
      : new AgentTurnAbortGraceError(
          timeoutMs,
          abortGraceMs,
          "abort-rejected",
          "disconnect",
        );
    try {
      options.onAbortGraceExceeded(fatalError);
    } catch {
      // Production exits synchronously; deterministic tests may inject a hook
      // that throws instead. The fixed cleanup error remains authoritative.
    }
    throw fatalError;
  } finally {
    if (grace !== undefined) clearTimeout(grace);
  }
}

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
  options: AgentTurnDeadlineOptions,
): Promise<void> {
  const timeoutMs = boundedTimerDelay(
    options.timeoutMs,
    DEFAULT_AGENT_TURN_TIMEOUT_MS,
    "agent turn timeout",
  );
  const abortGraceMs = boundedTimerDelay(
    options.abortGraceMs,
    DEFAULT_AGENT_ABORT_GRACE_MS,
    "agent turn abort grace",
  );
  const { promise, resolve, reject } = Promise.withResolvers<undefined>();
  let finished = false;
  let timedOut = false;
  let fallback: NodeJS.Timeout | undefined;
  let deadline: NodeJS.Timeout | undefined;
  let abortGrace: NodeJS.Timeout | undefined;
  const cancelFallback = (): void => {
    if (fallback !== undefined) clearTimeout(fallback);
    fallback = undefined;
  };
  const cancelDeadline = (): void => {
    if (deadline !== undefined) clearTimeout(deadline);
    deadline = undefined;
  };
  const cancelAbortGrace = (): void => {
    if (abortGrace !== undefined) clearTimeout(abortGrace);
    abortGrace = undefined;
  };
  const succeed = (): void => {
    if (finished || timedOut) return;
    finished = true;
    cancelFallback();
    cancelDeadline();
    cancelAbortGrace();
    resolve(undefined);
  };
  const fail = (error: unknown): void => {
    if (finished) return;
    finished = true;
    cancelFallback();
    cancelDeadline();
    cancelAbortGrace();
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

  const abortTimedOutTurn = async (): Promise<void> => {
    const abortResult = Promise.resolve().then(async () => await options.abort());
    const abortExpired = new Promise<never>((_resolve, rejectAbort) => {
      abortGrace = setTimeout(() => {
        rejectAbort(new AgentTurnAbortGraceError(timeoutMs, abortGraceMs, "grace-expired"));
      }, abortGraceMs);
      abortGrace.unref();
    });
    try {
      await Promise.race([abortResult, abortExpired]);
      fail(new AgentTurnTimeoutError(timeoutMs));
    } catch (error) {
      const fatalError = error instanceof AgentTurnAbortGraceError
        ? error
        : new AgentTurnAbortGraceError(timeoutMs, abortGraceMs, "abort-rejected");
      try {
        options.onAbortGraceExceeded(fatalError);
      } catch {
        // The caller may throw instead of terminating in deterministic tests.
      }
      fail(fatalError);
    }
  };

  deadline = setTimeout(() => {
    if (finished || timedOut) return;
    timedOut = true;
    cancelFallback();
    void abortTimedOutTurn();
  }, timeoutMs);
  deadline.unref();

  try {
    let prompt: Promise<void>;
    try {
      prompt = startPrompt();
    } catch (error) {
      fail(error);
      return await promise;
    }
    void prompt.catch((error: unknown) => {
      if (!timedOut) fail(error);
    });
    await promise;
  } finally {
    cancelFallback();
    cancelDeadline();
    cancelAbortGrace();
    unsubscribe();
  }
}
