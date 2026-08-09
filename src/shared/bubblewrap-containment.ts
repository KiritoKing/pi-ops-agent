import { readFile } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";
import { Readable, type Writable } from "node:stream";
import { parseStrictJson } from "./workload-runtime.js";

export const BUBBLEWRAP_REAPER_SYNC_FD = 8;
export const BUBBLEWRAP_REAPER_INFO_FD = 9;
export const BUBBLEWRAP_REAPER_INFO_MAX_BYTES = 16 * 1024;

export type BubblewrapReaperIdentity =
  | {
      pid: number;
      state: "captured";
      startTimeTicks: string;
    }
  | {
      pid: number;
      state: "already-exited";
    }
  | {
      pid: number;
      /**
       * The authoritative PID was parsed, but procfs identity could not be
       * captured. Only an observed ENOENT can release this conservative
       * barrier; PID reuse is deliberately not inferred without starttime.
       */
      state: "pid-only";
    };

export interface BubblewrapReaperMonitorDependencies {
  readProcStat(pid: number): Promise<string>;
  yieldBeforeRetry(): Promise<void>;
}

export interface BubblewrapReaperMonitor {
  syncStream: Readable;
  syncEof: Promise<void>;
  identity: Promise<BubblewrapReaperIdentity>;
  waitForExit(): Promise<void>;
}

type BubblewrapStdioChild = {
  readonly stdio: ReadonlyArray<Readable | Writable | null | undefined>;
};

const defaultMonitorDependencies: BubblewrapReaperMonitorDependencies = {
  async readProcStat(pid): Promise<string> {
    return await readFile(`/proc/${pid}/stat`, "utf8");
  },
  async yieldBeforeRetry(): Promise<void> {
    // This delay only limits polling load. It is never treated as evidence that
    // the captured process identity exited.
    await new Promise<void>((resolveRetry) => setTimeout(resolveRetry, 25));
  },
};

function requireReadablePipe(child: BubblewrapStdioChild, fd: number, label: string): Readable {
  const stream = child.stdio[fd];
  if (!(stream instanceof Readable)) {
    throw new Error(`${label} must be a readable pipe`);
  }
  return stream;
}

export function consumeBubblewrapReaperSync(
  child: BubblewrapStdioChild,
): Readable {
  const syncStream = requireReadablePipe(
    child,
    BUBBLEWRAP_REAPER_SYNC_FD,
    "bubblewrap reaper lifecycle FD",
  );
  syncStream.resume();
  return syncStream;
}

function waitForBubblewrapReaperSyncEof(syncStream: Readable): Promise<void> {
  return new Promise<void>((resolveSync, rejectSync) => {
    let settled = false;
    const fail = (): void => {
      if (settled) return;
      settled = true;
      rejectSync(new Error("bubblewrap reaper lifecycle pipe failed"));
    };
    syncStream.once("end", () => {
      if (settled) return;
      settled = true;
      resolveSync();
    });
    syncStream.once("error", fail);
    syncStream.once("close", () => {
      if (!settled) fail();
    });
    syncStream.resume();
  });
}

export function parseBubblewrapReaperInfo(text: string): number {
  const value = parseStrictJson(text, BUBBLEWRAP_REAPER_INFO_MAX_BYTES);
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("bubblewrap reaper info must be one JSON object");
  }
  const childPid = (value as Record<string, unknown>)["child-pid"];
  if (!Number.isSafeInteger(childPid) || Number(childPid) <= 1 || Number(childPid) > 2_147_483_647) {
    throw new Error("bubblewrap reaper info has an invalid child-pid");
  }
  return Number(childPid);
}

export function parseProcStartTime(stat: string, expectedPid: number): string {
  if (Buffer.byteLength(stat, "utf8") > 64 * 1024) {
    throw new Error("process identity record exceeds its size limit");
  }
  const commandStart = stat.indexOf("(");
  const commandEnd = stat.lastIndexOf(")");
  if (commandStart < 1 || commandEnd <= commandStart || stat[commandEnd + 1] !== " "
    || stat.slice(0, commandStart).trim() !== String(expectedPid)) {
    throw new Error("process identity record is malformed");
  }
  const fields = stat.slice(commandEnd + 2).trim().split(/\s+/u);
  const startTimeTicks = fields[19];
  if (startTimeTicks === undefined || !/^[1-9][0-9]{0,19}$/u.test(startTimeTicks)
    || BigInt(startTimeTicks) > 18_446_744_073_709_551_615n) {
    throw new Error("process identity record has an invalid start time");
  }
  return startTimeTicks;
}

function readBoundedInfo(stream: Readable): Promise<string> {
  return new Promise<string>((resolveInfo, rejectInfo) => {
    const chunks: Buffer[] = [];
    let totalBytes = 0;
    let settled = false;
    const fail = (message: string): void => {
      if (settled) return;
      settled = true;
      stream.destroy();
      rejectInfo(new Error(message));
    };
    stream.on("data", (chunk: Buffer) => {
      if (settled) return;
      totalBytes += chunk.length;
      if (totalBytes > BUBBLEWRAP_REAPER_INFO_MAX_BYTES) {
        fail("bubblewrap reaper info exceeds its size limit");
        return;
      }
      chunks.push(chunk);
    });
    stream.once("error", () => fail("bubblewrap reaper info pipe failed"));
    stream.once("close", () => {
      if (!settled) fail("bubblewrap reaper info pipe closed before EOF");
    });
    stream.once("end", () => {
      if (settled) return;
      settled = true;
      resolveInfo(Buffer.concat(chunks, totalBytes).toString("utf8"));
    });
  });
}

function isMissingProcess(error: unknown): boolean {
  return error instanceof Error && "code" in error && error.code === "ENOENT";
}

async function captureBubblewrapReaperIdentity(
  infoStream: Readable,
  dependencies: BubblewrapReaperMonitorDependencies,
): Promise<BubblewrapReaperIdentity> {
  const pid = parseBubblewrapReaperInfo(await readBoundedInfo(infoStream));
  try {
    const startTimeTicks = parseProcStartTime(await dependencies.readProcStat(pid), pid);
    return { pid, state: "captured", startTimeTicks };
  } catch (error) {
    // Bubblewrap writes the info record before releasing its child. A very
    // short-lived child can nevertheless be gone by the first procfs read;
    // record that proof immediately so a later PID reuse is never captured.
    if (isMissingProcess(error)) return { pid, state: "already-exited" };
    return { pid, state: "pid-only" };
  }
}

export async function waitForBubblewrapReaperExit(
  identity: BubblewrapReaperIdentity,
  dependencies: BubblewrapReaperMonitorDependencies = defaultMonitorDependencies,
): Promise<void> {
  if (identity.state === "already-exited") return;
  for (;;) {
    try {
      const currentStartTime = parseProcStartTime(
        await dependencies.readProcStat(identity.pid),
        identity.pid,
      );
      if (identity.state === "captured"
        && currentStartTime !== identity.startTimeTicks) return;
    } catch (error) {
      if (isMissingProcess(error)) return;
      // An unreadable or malformed live record cannot prove that the captured
      // identity disappeared. Keep the barrier pending and retry fail-closed.
    }
    try {
      await dependencies.yieldBeforeRetry();
    } catch {
      // A scheduler failure is not evidence of process exit either.
    }
  }
}

export function monitorBubblewrapReaper(
  child: BubblewrapStdioChild,
  dependencies: BubblewrapReaperMonitorDependencies = defaultMonitorDependencies,
): BubblewrapReaperMonitor {
  let syncStream: Readable;
  let syncEof: Promise<void>;
  try {
    syncStream = requireReadablePipe(
      child,
      BUBBLEWRAP_REAPER_SYNC_FD,
      "bubblewrap reaper lifecycle FD",
    );
    syncEof = waitForBubblewrapReaperSyncEof(syncStream);
  } catch (error) {
    // A missing sync pipe is a runtime failure, but authoritative info may
    // still let us prove that the outer namespace init was reaped. Return a
    // monitor instead of throwing so every caller kills the child and waits
    // for that identity before it can settle and release its digest lease.
    syncStream = new Readable({ read(): void { /* fail-stop placeholder */ } });
    syncEof = Promise.reject(error instanceof Error
      ? error
      : new Error("bubblewrap reaper lifecycle FD is unavailable"));
  }

  let identity: Promise<BubblewrapReaperIdentity>;
  try {
    const infoStream = requireReadablePipe(
      child,
      BUBBLEWRAP_REAPER_INFO_FD,
      "bubblewrap reaper info FD",
    );
    identity = captureBubblewrapReaperIdentity(infoStream, dependencies);
  } catch (error) {
    // Without child-pid there is no lifecycle proof. Rejecting identity makes
    // callers terminate the child immediately; waitForExit() below converts
    // the missing evidence into a never-settling fail-stop barrier.
    identity = Promise.reject(error instanceof Error
      ? error
      : new Error("bubblewrap reaper info FD is unavailable"));
  }
  // Callers also observe these promises to terminate their child immediately;
  // keep the shared monitor from producing transient unhandled rejections.
  void syncEof.catch(() => undefined);
  void identity.catch(() => undefined);
  return {
    syncStream,
    syncEof,
    identity,
    async waitForExit(): Promise<void> {
      const syncOutcome = syncEof.then(
        () => undefined,
        (error: unknown) => error instanceof Error
          ? error
          : new Error("bubblewrap reaper lifecycle pipe failed"),
      );
      const capturedIdentity = await identity.catch(async () => {
        // Without the authoritative child-pid there is no release proof. Keep
        // the caller (and therefore its exact-digest lease) fail-stop instead
        // of converting missing evidence into permission to settle.
        return await new Promise<never>(() => undefined);
      });
      await waitForBubblewrapReaperExit(capturedIdentity, dependencies);
      const syncFailure = await syncOutcome;
      if (syncFailure !== undefined) throw syncFailure;
    },
  };
}

export function wrapWithBubblewrapProcessReaper(
  bwrapPath: string,
  innerArguments: readonly string[],
  options: { unshareIpc?: boolean; unshareNetwork?: boolean } = {},
): { executable: string; arguments: string[] } {
  if (!isAbsolute(bwrapPath) || resolve(bwrapPath) !== bwrapPath) {
    throw new Error("bubblewrap containment requires a fixed absolute executable path");
  }

  const outerArguments = [
    "--die-with-parent",
    "--sync-fd", String(BUBBLEWRAP_REAPER_SYNC_FD),
    "--info-fd", String(BUBBLEWRAP_REAPER_INFO_FD),
    "--unshare-user",
  ];
  if (options.unshareIpc === true) outerArguments.push("--unshare-ipc");
  outerArguments.push("--unshare-pid");
  if (options.unshareNetwork === true) outerArguments.push("--unshare-net");
  outerArguments.push(
    "--cap-drop", "ALL",
    "--bind", "/", "/",
    "--dev", "/dev",
    "--proc", "/proc",
    // Keep outer bubblewrap as PID 1 so it reaps the complete inner sandbox
    // process tree. Both PID namespaces receive their own procfs view; the
    // inner sandbox remains the only layer that executes untrusted Source and
    // owns the final nested-userns denial after creating its namespaces.
    "--",
    bwrapPath,
    ...innerArguments,
  );
  return { executable: bwrapPath, arguments: outerArguments };
}
