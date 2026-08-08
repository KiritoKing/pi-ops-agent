import { mkdir, readFile, readlink, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

interface ProcessIdentity {
  executable: string;
  cgroup: string;
  startTimeTicks: number;
}

function parseStartTime(stat: string): number {
  const commandEnd = stat.lastIndexOf(")");
  if (commandEnd < 2 || stat[commandEnd + 1] !== " ") {
    throw new Error("/proc/self/stat has an invalid command field");
  }
  const fields = stat.slice(commandEnd + 2).trim().split(/\s+/u);
  const value = fields[19];
  if (value === undefined || !/^[1-9][0-9]*$/u.test(value)) {
    throw new Error("/proc/self/stat has an invalid start time");
  }
  const ticks = Number(value);
  if (!Number.isSafeInteger(ticks)) throw new Error("process start time exceeds safe integer range");
  return ticks;
}

function parseUnifiedCgroup(value: string): string {
  const matches = value.trim().split("\n").filter((line) => line.startsWith("0::"));
  if (matches.length !== 1) throw new Error("a unique unified cgroup v2 path is required");
  const cgroup = matches[0]?.slice(3);
  if (!cgroup || !cgroup.startsWith("/") || cgroup.includes("\0") || cgroup.includes("..")) {
    throw new Error("process cgroup path is invalid");
  }
  return cgroup;
}

async function currentIdentity(): Promise<ProcessIdentity> {
  const [executable, stat, cgroup] = await Promise.all([
    readlink("/proc/self/exe"),
    readFile("/proc/self/stat", "utf8"),
    readFile("/proc/self/cgroup", "utf8"),
  ]);
  if (!executable.startsWith("/") || executable.endsWith(" (deleted)")) {
    throw new Error("process executable identity is invalid");
  }
  return {
    executable,
    cgroup: parseUnifiedCgroup(cgroup),
    startTimeTicks: parseStartTime(stat),
  };
}

export class GuardianHeartbeat {
  readonly #path: string;
  readonly #periodMs: number;
  readonly #onError: (error: Error) => void;
  #identity?: ProcessIdentity;
  #sequence = 0;
  #timer: NodeJS.Timeout | undefined;
  #writeQueue: Promise<void> = Promise.resolve();

  constructor(path: string, onError: (error: Error) => void, periodMs = 2_000) {
    this.#path = path;
    this.#onError = onError;
    this.#periodMs = periodMs;
  }

  async start(): Promise<void> {
    if (this.#timer !== undefined) throw new Error("guardian heartbeat already started");
    this.#identity = await currentIdentity();
    await mkdir(dirname(this.#path), { recursive: true, mode: 0o750 });
    await this.#write();
    this.#timer = setInterval(() => this.#enqueueWrite(), this.#periodMs);
    this.#timer.unref();
  }

  async stop(): Promise<void> {
    if (this.#timer !== undefined) clearInterval(this.#timer);
    this.#timer = undefined;
    await this.#writeQueue;
  }

  #enqueueWrite(): void {
    this.#writeQueue = this.#writeQueue
      .then(async () => await this.#write())
      .catch((error: unknown) => {
        this.#onError(error instanceof Error ? error : new Error(String(error)));
      });
  }

  async #write(): Promise<void> {
    const identity = this.#identity;
    if (identity === undefined) throw new Error("guardian heartbeat identity is unavailable");
    this.#sequence += 1;
    const record = {
      version: 1,
      status: "healthy",
      pid: process.pid,
      uid: process.getuid?.() ?? 0,
      executable: identity.executable,
      cgroup: identity.cgroup,
      startTimeTicks: identity.startTimeTicks,
      sequence: this.#sequence,
      observedAt: new Date().toISOString(),
    };
    if (record.uid === 0) throw new Error("guardian heartbeat refuses a root agentd identity");
    const temporary = `${this.#path}.tmp-${process.pid}`;
    await writeFile(temporary, `${JSON.stringify(record)}\n`, { mode: 0o600 });
    await rename(temporary, this.#path);
  }
}
