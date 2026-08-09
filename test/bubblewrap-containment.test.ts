import { PassThrough, type Readable, type Writable } from "node:stream";
import { describe, expect, it } from "vitest";
import { wrapSandboxCommandWithProcessReaper } from "../src/agentd/sandbox.js";
import { wrapWorkloadHostWithProcessReaper } from "../src/agentd/workload-host-runner.js";
import {
  BUBBLEWRAP_REAPER_INFO_FD,
  BUBBLEWRAP_REAPER_INFO_MAX_BYTES,
  BUBBLEWRAP_REAPER_SYNC_FD,
  consumeBubblewrapReaperSync,
  monitorBubblewrapReaper,
  parseBubblewrapReaperInfo,
  waitForBubblewrapReaperExit,
  type BubblewrapReaperMonitorDependencies,
  wrapWithBubblewrapProcessReaper,
} from "../src/shared/bubblewrap-containment.js";

function procStat(pid: number, startTimeTicks: string): string {
  const fields = Array.from({ length: 20 }, () => "0");
  fields[0] = "S";
  fields[19] = startTimeTicks;
  return `${pid} (outer bwrap reaper) ${fields.join(" ")}`;
}

function missingProcessError(): Error & { code: string } {
  return Object.assign(new Error("private procfs pathname"), { code: "ENOENT" });
}

function noRetry(): Promise<void> {
  return Promise.resolve();
}

function monitorFixture(dependencies: BubblewrapReaperMonitorDependencies): {
  syncStream: PassThrough;
  infoStream: PassThrough;
  monitor: ReturnType<typeof monitorBubblewrapReaper>;
} {
  const syncStream = new PassThrough();
  const infoStream = new PassThrough();
  const stdio: Array<Readable | Writable | null | undefined> = Array.from(
    { length: BUBBLEWRAP_REAPER_INFO_FD + 1 },
    () => null,
  );
  stdio[BUBBLEWRAP_REAPER_SYNC_FD] = syncStream;
  stdio[BUBBLEWRAP_REAPER_INFO_FD] = infoStream;
  return {
    syncStream,
    infoStream,
    monitor: monitorBubblewrapReaper({ stdio }, dependencies),
  };
}

describe("bubblewrap process-tree containment", () => {
  it("keeps the outer bubblewrap as PID 1 and executes the fixed inner sandbox", () => {
    const innerArguments = [
      "--new-session",
      "--unshare-user",
      "--unshare-ipc",
      "--unshare-pid",
      "--unshare-net",
      "--as-pid-1",
      "--disable-userns",
      "--proc", "/proc",
      "--",
      "/runtime/node",
    ];

    const command = wrapWithBubblewrapProcessReaper(
      "/usr/bin/bwrap",
      innerArguments,
      { unshareIpc: true, unshareNetwork: true },
    );

    expect(command).toEqual({
      executable: "/usr/bin/bwrap",
      arguments: [
        "--die-with-parent",
        "--sync-fd", "8",
        "--info-fd", "9",
        "--unshare-user",
        "--unshare-ipc",
        "--unshare-pid",
        "--unshare-net",
        "--cap-drop", "ALL",
        "--bind", "/", "/",
        "--dev", "/dev",
        "--proc", "/proc",
        "--",
        "/usr/bin/bwrap",
        ...innerArguments,
      ],
    });
    const innerStart = command.arguments.indexOf("--") + 1;
    const outerArguments = command.arguments.slice(0, innerStart - 1);
    expect(outerArguments).not.toContain("--new-session");
    expect(outerArguments).not.toContain("--as-pid-1");
    expect(outerArguments).not.toContain("--disable-userns");
    expect(outerArguments).toContain("--proc");
    expect(innerArguments).toContain("--proc");
    expect(outerArguments.filter((argument) => argument === "--sync-fd")).toHaveLength(1);
    expect(outerArguments.filter((argument) => argument === "--info-fd")).toHaveLength(1);
    expect(innerArguments).not.toContain("--sync-fd");
    expect(innerArguments).not.toContain("--info-fd");
    expect(command.arguments.slice(innerStart + 1)).toEqual(innerArguments);
  });

  it("adds IPC and network namespaces only when requested", () => {
    const command = wrapWithBubblewrapProcessReaper(
      "/usr/bin/bwrap",
      ["--unshare-net", "--", "/bin/true"],
    );
    const outerArguments = command.arguments.slice(0, command.arguments.indexOf("--"));
    expect(outerArguments).not.toContain("--unshare-ipc");
    expect(outerArguments).not.toContain("--unshare-net");
    expect(command.arguments.slice(command.arguments.indexOf("--") + 2)).toContain("--unshare-net");
  });

  it("keeps workload hosts and ops_bash inside both IPC and network boundaries", () => {
    const innerArguments = [
      "--new-session",
      "--unshare-user",
      "--unshare-ipc",
      "--unshare-pid",
      "--unshare-net",
      "--as-pid-1",
      "--disable-userns",
      "--",
      "/runtime/entrypoint",
    ];
    for (const wrap of [
      wrapWorkloadHostWithProcessReaper,
      wrapSandboxCommandWithProcessReaper,
    ]) {
      const command = wrap("/usr/bin/bwrap", innerArguments);
      const innerStart = command.arguments.indexOf("--") + 1;
      const outerArguments = command.arguments.slice(0, innerStart - 1);
      expect(outerArguments).toContain("--unshare-ipc");
      expect(outerArguments).toContain("--unshare-net");
      expect(outerArguments).not.toContain("--new-session");
      expect(outerArguments).not.toContain("--as-pid-1");
      expect(outerArguments).not.toContain("--disable-userns");
      expect(outerArguments).toContain("--proc");
      expect(outerArguments).toContain("--sync-fd");
      expect(outerArguments).toContain("--info-fd");
      expect(innerArguments).not.toContain("--sync-fd");
      expect(innerArguments).not.toContain("--info-fd");
      expect(command.arguments.slice(innerStart + 1)).toEqual(innerArguments);
    }
  });

  it("consumes the authoritative outer reaper lifecycle pipe", () => {
    const syncStream = new PassThrough();
    const stdio: Array<Readable | Writable | null | undefined> = Array.from(
      { length: BUBBLEWRAP_REAPER_SYNC_FD + 1 },
      () => null,
    );
    stdio[BUBBLEWRAP_REAPER_SYNC_FD] = syncStream;
    const child = { stdio };

    expect(syncStream.readableFlowing).toBeNull();
    expect(consumeBubblewrapReaperSync(child)).toBe(syncStream);
    expect(syncStream.readableFlowing).toBe(true);
  });

  it("fails closed when the outer reaper lifecycle pipe is missing", () => {
    const child = {
      stdio: Array.from({ length: BUBBLEWRAP_REAPER_SYNC_FD + 1 }, () => null),
    };
    expect(() => consumeBubblewrapReaperSync(child)).toThrow(/readable pipe/u);
  });

  it("fails closed when the outer reaper info pipe is missing", async () => {
    const syncStream = new PassThrough();
    const stdio: Array<Readable | Writable | null | undefined> = Array.from(
      { length: BUBBLEWRAP_REAPER_INFO_FD + 1 },
      () => null,
    );
    stdio[BUBBLEWRAP_REAPER_SYNC_FD] = syncStream;
    const monitor = monitorBubblewrapReaper({ stdio }, {
      readProcStat(): Promise<string> {
        return Promise.reject(new Error("must not be called"));
      },
      yieldBeforeRetry: noRetry,
    });
    let barrierSettled = false;
    void monitor.waitForExit().finally(() => { barrierSettled = true; });
    syncStream.end();

    await expect(monitor.identity).rejects.toThrow(/info FD must be a readable pipe/u);
    await new Promise<void>((resolveTick) => setImmediate(resolveTick));
    expect(barrierSettled).toBe(false);
  });

  it("reports a missing sync pipe only after the authoritative identity exits", async () => {
    const infoStream = new PassThrough();
    const stdio: Array<Readable | Writable | null | undefined> = Array.from(
      { length: BUBBLEWRAP_REAPER_INFO_FD + 1 },
      () => null,
    );
    stdio[BUBBLEWRAP_REAPER_INFO_FD] = infoStream;
    const allowExit = Promise.withResolvers<undefined>();
    let reads = 0;
    const monitor = monitorBubblewrapReaper({ stdio }, {
      async readProcStat(pid): Promise<string> {
        reads += 1;
        if (reads === 1) return procStat(pid, "100");
        await allowExit.promise;
        throw missingProcessError();
      },
      yieldBeforeRetry: noRetry,
    });
    infoStream.end('{"child-pid":42}');
    let barrierSettled = false;
    const barrier = monitor.waitForExit().finally(() => { barrierSettled = true; });
    void barrier.catch(() => undefined);

    await expect(monitor.syncEof).rejects.toThrow(/lifecycle FD must be a readable pipe/u);
    await expect(monitor.identity).resolves.toEqual({
      pid: 42,
      state: "captured",
      startTimeTicks: "100",
    });
    await new Promise<void>((resolveTick) => setImmediate(resolveTick));
    expect(barrierSettled).toBe(false);

    allowExit.resolve(undefined);
    await expect(barrier).rejects.toThrow(/lifecycle FD must be a readable pipe/u);
  });

  it("strictly rejects duplicate child-pid fields", () => {
    expect(() => parseBubblewrapReaperInfo(
      '{"child-pid":42,"child-pid":43}',
    )).toThrow(/duplicate field "child-pid"/u);
  });

  it.each([
    "{}",
    '{"child-pid":1}',
    '{"child-pid":2.5}',
    '{"child-pid":2147483648}',
    '{"child-pid":"42"}',
  ])("rejects an absent or unsafe child PID in %s", (info) => {
    expect(() => parseBubblewrapReaperInfo(info)).toThrow(/invalid child-pid/u);
  });

  it("rejects an oversized info record before reading procfs", async () => {
    let procReads = 0;
    const fixture = monitorFixture({
      readProcStat(): Promise<string> {
        procReads += 1;
        return Promise.resolve(procStat(42, "100"));
      },
      yieldBeforeRetry: noRetry,
    });
    let barrierSettled = false;
    const barrier = fixture.monitor.waitForExit().finally(() => {
      barrierSettled = true;
    });
    void barrier.catch(() => undefined);
    fixture.infoStream.end(Buffer.alloc(BUBBLEWRAP_REAPER_INFO_MAX_BYTES + 1, 0x20));
    fixture.syncStream.end();

    await expect(fixture.monitor.identity).rejects.toThrow(/exceeds its size limit/u);
    await new Promise<void>((resolveTick) => setImmediate(resolveTick));
    expect(barrierSettled).toBe(false);
    expect(procReads).toBe(0);
  });

  it("treats first-read ENOENT as already exited and never binds a reused PID", async () => {
    let procReads = 0;
    const fixture = monitorFixture({
      readProcStat(): Promise<string> {
        procReads += 1;
        return Promise.reject(missingProcessError());
      },
      yieldBeforeRetry(): Promise<void> {
        return Promise.reject(new Error("must not retry an already absent process"));
      },
    });
    fixture.infoStream.end('{"child-pid":42}');
    fixture.syncStream.end();

    await expect(fixture.monitor.identity).resolves.toEqual({
      pid: 42,
      state: "already-exited",
    });
    await expect(fixture.monitor.waitForExit()).resolves.toBeUndefined();
    expect(procReads).toBe(1);
  });

  it("keeps a PID-only barrier after an unreadable initial procfs identity", async () => {
    const retryEntered = Promise.withResolvers<undefined>();
    const allowRetry = Promise.withResolvers<undefined>();
    let reads = 0;
    let missing = false;
    const fixture = monitorFixture({
      readProcStat(): Promise<string> {
        reads += 1;
        if (reads === 1) {
          return Promise.reject(new Error("sensitive /proc/42/stat failure"));
        }
        if (missing) return Promise.reject(missingProcessError());
        // A different starttime cannot prove reuse because the original
        // starttime was never captured.
        return Promise.resolve(procStat(42, "999"));
      },
      async yieldBeforeRetry(): Promise<void> {
        retryEntered.resolve(undefined);
        await allowRetry.promise;
      },
    });
    fixture.infoStream.end('{"child-pid":42}');
    fixture.syncStream.end();

    await expect(fixture.monitor.identity).resolves.toEqual({
      pid: 42,
      state: "pid-only",
    });
    let settled = false;
    const completion = fixture.monitor.waitForExit().then(() => { settled = true; });
    await retryEntered.promise;
    expect(settled).toBe(false);
    missing = true;
    allowRetry.resolve(undefined);
    await completion;
    expect(settled).toBe(true);
  });

  it("accepts PID reuse as proof that the captured identity disappeared", async () => {
    let retries = 0;
    await expect(waitForBubblewrapReaperExit(
      { pid: 42, state: "captured", startTimeTicks: "100" },
      {
        readProcStat(): Promise<string> {
          return Promise.resolve(procStat(42, "101"));
        },
        yieldBeforeRetry(): Promise<void> {
          retries += 1;
          return Promise.resolve();
        },
      },
    )).resolves.toBeUndefined();
    expect(retries).toBe(0);
  });

  it("waits after child close until the exact PID disappears", async () => {
    const retryEntered = Promise.withResolvers<undefined>();
    const allowRetry = Promise.withResolvers<undefined>();
    let disappeared = false;
    let procReads = 0;
    const fixture = monitorFixture({
      readProcStat(pid): Promise<string> {
        procReads += 1;
        if (disappeared) return Promise.reject(missingProcessError());
        return Promise.resolve(procStat(pid, "100"));
      },
      async yieldBeforeRetry(): Promise<void> {
        retryEntered.resolve(undefined);
        await allowRetry.promise;
      },
    });
    fixture.infoStream.end('{"child-pid":42}');
    await fixture.monitor.identity;

    // Simulate the caller receiving child.close before the detached namespace
    // PID 1 has disappeared. FD8 EOF alone must not complete the barrier.
    let settled = false;
    const completion = fixture.monitor.waitForExit().then(() => { settled = true; });
    await retryEntered.promise;
    fixture.syncStream.end();
    await new Promise<void>((resolveTick) => setImmediate(resolveTick));
    expect(settled).toBe(false);
    expect(procReads).toBe(2);

    disappeared = true;
    allowRetry.resolve(undefined);
    await completion;
    expect(settled).toBe(true);
    expect(procReads).toBe(3);
  });

  it("also waits for authoritative sync EOF after the captured PID is gone", async () => {
    const fixture = monitorFixture({
      readProcStat(): Promise<string> {
        return Promise.reject(missingProcessError());
      },
      yieldBeforeRetry: noRetry,
    });
    fixture.infoStream.end('{"child-pid":42}');
    await fixture.monitor.identity;

    let settled = false;
    const completion = fixture.monitor.waitForExit().then(() => { settled = true; });
    await new Promise<void>((resolveTick) => setImmediate(resolveTick));
    expect(settled).toBe(false);
    fixture.syncStream.end();
    await completion;
    expect(settled).toBe(true);
  });

  it("waits for exact identity exit before reporting a sync pipe error", async () => {
    const retryEntered = Promise.withResolvers<undefined>();
    const allowRetry = Promise.withResolvers<undefined>();
    let reads = 0;
    let missing = false;
    const fixture = monitorFixture({
      readProcStat(): Promise<string> {
        reads += 1;
        if (missing) return Promise.reject(missingProcessError());
        return Promise.resolve(procStat(42, "100"));
      },
      async yieldBeforeRetry(): Promise<void> {
        retryEntered.resolve(undefined);
        await allowRetry.promise;
      },
    });
    fixture.infoStream.end('{"child-pid":42}');
    await fixture.monitor.identity;
    let settled = false;
    const completion = fixture.monitor.waitForExit();
    void completion.finally(() => { settled = true; }).catch(() => undefined);
    fixture.syncStream.destroy(new Error("sensitive sync transport detail"));

    await retryEntered.promise;
    await new Promise<void>((resolveTick) => setImmediate(resolveTick));
    expect(settled).toBe(false);
    expect(reads).toBe(2);
    missing = true;
    allowRetry.resolve(undefined);
    await expect(completion).rejects.toThrow("bubblewrap reaper lifecycle pipe failed");
    expect(settled).toBe(true);
  });

  it("rejects a PATH-resolved or non-canonical bubblewrap executable", () => {
    expect(() => wrapWithBubblewrapProcessReaper("bwrap", [])).toThrow(/fixed absolute/u);
    expect(() => wrapWithBubblewrapProcessReaper("/usr/bin/../bin/bwrap", [])).toThrow(
      /fixed absolute/u,
    );
  });
});
