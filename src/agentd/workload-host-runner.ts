import { randomUUID } from "node:crypto";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import {
  existsSync,
  lstatSync,
  readdirSync,
  readlinkSync,
  realpathSync,
} from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { ActiveRuntimeSourcePlugin } from "../shared/source-plugin.js";
import {
  encodeWorkloadFrame,
  MAX_WORKLOAD_FRAME_BYTES,
  MAX_WORKLOAD_PROVIDER_CALLS,
  MAX_WORKLOAD_TOTAL_OUTPUT_BYTES,
  parseStrictJson,
  parseWorkloadHostMessage,
  requireBoundedJson,
  type WorkloadDescriptor,
  type WorkloadHostMessage,
  type WorkloadHostRequest,
  type WorkloadToolResult,
} from "../shared/workload-runtime.js";

const HOST_PATH = fileURLToPath(new URL("../runtime/workload-host.js", import.meta.url));
const STDERR_LIMIT_BYTES = 16 * 1024;
const DESCRIBE_TIMEOUT_MILLISECONDS = 8_000;
const INVOKE_TIMEOUT_MILLISECONDS = 135_000;

export interface WorkloadProviderRequest {
  provider: string;
  input: unknown;
}

export interface WorkloadHostRunner {
  describe(plugin: ActiveRuntimeSourcePlugin, signal?: AbortSignal): Promise<WorkloadDescriptor>;
  invoke(
    plugin: ActiveRuntimeSourcePlugin,
    tool: string,
    input: unknown,
    provider: (request: WorkloadProviderRequest, signal?: AbortSignal) => Promise<unknown>,
    signal?: AbortSignal,
  ): Promise<WorkloadToolResult>;
}

interface ExchangeOptions {
  plugin: ActiveRuntimeSourcePlugin;
  request: WorkloadHostRequest;
  timeoutMilliseconds: number;
  provider?: (request: WorkloadProviderRequest, signal?: AbortSignal) => Promise<unknown>;
  signal?: AbortSignal;
}

function safeError(error: unknown): string {
  const message = error instanceof Error ? error.message : "workload provider failed";
  return message.split("\0").join(" ").split("\r").join(" ").split("\n").join(" ")
    .slice(0, 2048) || "workload provider failed";
}

function fixedExecutable(path: string, label: string): string {
  if (!existsSync(path)) throw new Error(`${label} does not exist at its fixed path`);
  const resolved = realpathSync(path);
  const info = lstatSync(resolved);
  if (!info.isFile() || info.uid !== 0 || info.mode & 0o022) {
    throw new Error(`${label} must be a root-owned, non-writable regular file`);
  }
  return resolved;
}

function addLibraryMount(
  args: string[],
  path: string,
  expectedSymlink?: readonly string[],
): void {
  if (!existsSync(path)) return;
  const info = lstatSync(path);
  if (!info.isSymbolicLink()) {
    if (!info.isDirectory()) throw new Error(`workload host runtime path is not a directory: ${path}`);
    args.push("--ro-bind", path, path);
    return;
  }
  const target = readlinkSync(path);
  if (expectedSymlink === undefined || !expectedSymlink.includes(target)) {
    throw new Error(`workload host refuses unexpected library symlink: ${path} -> ${target}`);
  }
  args.push("--symlink", target, path);
}

function requireOwnedPath(path: string, expectedOwnerUid: number, directory: boolean): void {
  if (realpathSync(path) !== path) throw new Error(`source workload CAS path contains a symlink: ${path}`);
  const info = lstatSync(path);
  if (info.uid !== expectedOwnerUid || info.mode & 0o022 ||
      (directory ? !info.isDirectory() : !info.isFile())) {
    throw new Error(`source workload CAS path has unsafe owner, mode, or type: ${path}`);
  }
}

function validateSnapshotTree(
  plugin: ActiveRuntimeSourcePlugin,
  expectedOwnerUid: number,
): string {
  const snapshot = plugin.snapshotPath;
  const digestHex = plugin.digest.slice("sha256:".length);
  const shaRoot = dirname(snapshot);
  const snapshotsRoot = dirname(shaRoot);
  const registryRoot = dirname(snapshotsRoot);
  if (basename(snapshot) !== digestHex || basename(shaRoot) !== "sha256" ||
      basename(snapshotsRoot) !== "snapshots" || resolve(snapshot) !== snapshot) {
    throw new Error("source workload snapshot path is not a canonical content-addressed path");
  }
  for (const directory of [registryRoot, snapshotsRoot, shaRoot, snapshot]) {
    requireOwnedPath(directory, expectedOwnerUid, true);
  }
  const entrypoint = resolve(snapshot, plugin.entrypoint);
  if (entrypoint === snapshot || !entrypoint.startsWith(`${snapshot}/`)) {
    throw new Error("source workload entrypoint escapes its immutable snapshot");
  }

  let entries = 0;
  const inspect = (directory: string, depth: number): void => {
    if (depth > 24) throw new Error("source workload snapshot exceeds its depth limit");
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      entries += 1;
      if (entries > 512) throw new Error("source workload snapshot contains too many entries");
      const path = join(directory, entry.name);
      if (entry.isDirectory()) {
        requireOwnedPath(path, expectedOwnerUid, true);
        inspect(path, depth + 1);
      } else if (entry.isFile()) {
        requireOwnedPath(path, expectedOwnerUid, false);
      } else {
        throw new Error(`source workload snapshot contains an unsupported entry: ${path}`);
      }
    }
  };
  inspect(snapshot, 0);
  requireOwnedPath(entrypoint, expectedOwnerUid, false);
  return snapshot;
}

function sandboxArguments(
  plugin: ActiveRuntimeSourcePlugin,
  bwrapPath: string,
  hostPath: string,
  expectedOwnerUid: number,
): { executable: string; args: string[] } {
  if (process.platform !== "linux") {
    throw new Error("source workload execution requires Linux bubblewrap isolation");
  }
  const bwrap = fixedExecutable(bwrapPath, "bubblewrap");
  const node = fixedExecutable(process.execPath, "Node runtime");
  const host = fixedExecutable(hostPath, "fixed workload host");
  const prlimitCandidate = ["/usr/bin/prlimit", "/bin/prlimit"].find((path) => existsSync(path));
  if (prlimitCandidate === undefined) {
    throw new Error("source workload execution requires the fixed util-linux prlimit boundary");
  }
  const prlimit = fixedExecutable(prlimitCandidate, "prlimit");
  const snapshot = validateSnapshotTree(plugin, expectedOwnerUid);

  const args = [
    "--die-with-parent",
    "--new-session",
    // Keep this list aligned with ops-agentd.service RestrictNamespaces=.
    // bubblewrap always creates a mount namespace. Avoid UTS/cgroup namespaces:
    // ProtectHostname already gives the service a private, immutable UTS view,
    // while workloads have no reason to see a separate cgroup namespace.
    "--unshare-user",
    "--unshare-ipc",
    "--unshare-pid",
    "--unshare-net",
    "--as-pid-1",
    "--disable-userns",
    "--cap-drop", "ALL",
    "--proc", "/proc",
    "--dev", "/dev",
    "--tmpfs", "/tmp",
    "--dir", "/tmp/home",
    "--dir", "/runtime",
    "--ro-bind", node, "/runtime/node",
    "--ro-bind", host, "/runtime/workload-host.js",
    "--ro-bind", prlimit, "/runtime/prlimit",
    "--dir", "/plugin",
    "--ro-bind", snapshot, "/plugin",
    "--dir", "/etc",
    "--clearenv",
    "--setenv", "HOME", "/tmp/home",
    "--setenv", "LANG", "C.UTF-8",
    "--setenv", "TZ", "UTC",
    "--setenv", "PATH", "/nonexistent",
    "--chdir", "/plugin",
  ];
  addLibraryMount(args, "/usr/lib");
  addLibraryMount(args, "/usr/lib64");
  addLibraryMount(args, "/lib", ["usr/lib", "/usr/lib"]);
  addLibraryMount(args, "/lib64", ["usr/lib64", "/usr/lib64"]);
  if (existsSync("/etc/ld.so.cache")) {
    const cache = fixedExecutable("/etc/ld.so.cache", "dynamic loader cache");
    args.push("--ro-bind", cache, "/etc/ld.so.cache");
  }
  args.push(
    "/runtime/prlimit",
    "--as=8589934592:8589934592",
    "--core=0:0",
    "--cpu=150:150",
    "--fsize=1048576:1048576",
    "--nofile=64:64",
    "--nproc=32:32",
    "--",
    "/runtime/node",
    "--permission",
    "--allow-fs-read=/plugin",
    "--allow-fs-read=/runtime",
    "--disable-proto=throw",
    "--disallow-code-generation-from-strings",
    "--frozen-intrinsics",
    "--max-old-space-size=96",
    "--max-semi-space-size=4",
    "--no-addons",
    "--no-deprecation",
    "--no-warnings",
    "--stack-size=512",
    "/runtime/workload-host.js",
  );
  return { executable: bwrap, args };
}

function spawnSandboxedHost(
  plugin: ActiveRuntimeSourcePlugin,
  bwrapPath: string,
  hostPath = HOST_PATH,
  expectedOwnerUid = 0,
): ChildProcessWithoutNullStreams {
  const command = sandboxArguments(plugin, bwrapPath, hostPath, expectedOwnerUid);
  return spawn(command.executable, command.args, {
    cwd: "/",
    env: {},
    shell: false,
    windowsHide: true,
    stdio: ["pipe", "pipe", "pipe"],
  });
}

export class BubblewrapWorkloadHostRunner implements WorkloadHostRunner {
  readonly #bwrapPath: string;
  readonly #hostPath: string;
  readonly #expectedOwnerUid: number;

  constructor(bwrapPath: string, hostPath = HOST_PATH, expectedOwnerUid = 0) {
    if (!Number.isSafeInteger(expectedOwnerUid) || expectedOwnerUid < 0) {
      throw new Error("workload snapshot expected owner UID is invalid");
    }
    this.#bwrapPath = bwrapPath;
    this.#hostPath = hostPath;
    this.#expectedOwnerUid = expectedOwnerUid;
  }

  async describe(plugin: ActiveRuntimeSourcePlugin, signal?: AbortSignal): Promise<WorkloadDescriptor> {
    const invocationId = `describe-${randomUUID()}`;
    const message = await this.#exchange({
      plugin,
      request: {
        version: 1,
        type: "describe",
        invocationId,
        entrypoint: plugin.entrypoint,
      },
      timeoutMilliseconds: DESCRIBE_TIMEOUT_MILLISECONDS,
      ...(signal === undefined ? {} : { signal }),
    });
    if (message.type !== "descriptor") throw new Error("workload host did not return a descriptor");
    return message.descriptor;
  }

  async invoke(
    plugin: ActiveRuntimeSourcePlugin,
    tool: string,
    input: unknown,
    provider: (request: WorkloadProviderRequest, signal?: AbortSignal) => Promise<unknown>,
    signal?: AbortSignal,
  ): Promise<WorkloadToolResult> {
    const invocationId = `invoke-${randomUUID()}`;
    const message = await this.#exchange({
      plugin,
      request: {
        version: 1,
        type: "invoke",
        invocationId,
        entrypoint: plugin.entrypoint,
        tool,
        input: requireBoundedJson(input, "workload invocation input", 128 * 1024),
      },
      timeoutMilliseconds: INVOKE_TIMEOUT_MILLISECONDS,
      provider,
      ...(signal === undefined ? {} : { signal }),
    });
    if (message.type !== "result") throw new Error("workload host did not return a result");
    return message.result;
  }

  async #exchange(options: ExchangeOptions): Promise<WorkloadHostMessage> {
    const child = spawnSandboxedHost(
      options.plugin,
      this.#bwrapPath,
      this.#hostPath,
      this.#expectedOwnerUid,
    );
    return await new Promise<WorkloadHostMessage>((resolve, reject) => {
      let stdout = Buffer.alloc(0);
      let stderr = Buffer.alloc(0);
      let totalOutputBytes = 0;
      let providerCalls = 0;
      let finalMessage: WorkloadHostMessage | undefined;
      let failure: Error | undefined;
      let childClosed = false;
      let settled = false;
      let hardKill: NodeJS.Timeout | undefined;
      let chain = Promise.resolve();

      const terminate = (): void => {
        if (childClosed) return;
        child.kill("SIGTERM");
        if (hardKill === undefined) {
          hardKill = setTimeout(() => child.kill("SIGKILL"), 1000);
          hardKill.unref();
        }
      };
      const fail = (error: unknown): void => {
        if (settled || failure !== undefined) return;
        failure = error instanceof Error ? error : new Error("workload host failed");
        terminate();
      };
      const write = (value: unknown): void => {
        const frame = encodeWorkloadFrame(value);
        if (!child.stdin.write(frame)) child.stdin.once("drain", () => undefined);
      };
      const handleMessage = async (value: unknown): Promise<void> => {
        if (failure !== undefined) throw failure;
        if (finalMessage !== undefined) throw new Error("workload host emitted a frame after its final result");
        const message = parseWorkloadHostMessage(value);
        if (message.invocationId !== options.request.invocationId) {
          throw new Error("workload host response is not bound to this invocation");
        }
        if (message.type === "provider.request") {
          if (options.provider === undefined || options.request.type !== "invoke") {
            throw new Error("workload host requested a provider outside an invocation");
          }
          providerCalls += 1;
          if (providerCalls > MAX_WORKLOAD_PROVIDER_CALLS) {
            throw new Error("workload host exceeded its provider request limit");
          }
          try {
            const result = await options.provider(
              { provider: message.provider, input: message.input },
              options.signal,
            );
            write({
              version: 1,
              type: "provider.response",
              invocationId: message.invocationId,
              requestId: message.requestId,
              ok: true,
              result: requireBoundedJson(result, "workload provider result", 128 * 1024),
            });
          } catch (error) {
            write({
              version: 1,
              type: "provider.response",
              invocationId: message.invocationId,
              requestId: message.requestId,
              ok: false,
              error: safeError(error),
            });
          }
          return;
        }
        if (message.type === "error") throw new Error(`isolated workload failed: ${message.error}`);
        finalMessage = message;
      };
      const consume = (chunk: Buffer): void => {
        if (failure !== undefined) return;
        totalOutputBytes += chunk.length;
        if (totalOutputBytes > MAX_WORKLOAD_TOTAL_OUTPUT_BYTES) {
          throw new Error("workload host exceeded its total output limit");
        }
        stdout = Buffer.concat([stdout, chunk]);
        while (stdout.length >= 4) {
          const length = stdout.readUInt32BE(0);
          if (length < 1 || length > MAX_WORKLOAD_FRAME_BYTES) {
            throw new Error("workload host emitted an invalid frame length");
          }
          if (stdout.length < length + 4) return;
          const payload = stdout.subarray(4, length + 4).toString("utf8");
          stdout = stdout.subarray(length + 4);
          const decoded = parseStrictJson(payload);
          chain = chain.then(async () => await handleMessage(decoded));
          void chain.catch(fail);
        }
        if (stdout.length > MAX_WORKLOAD_FRAME_BYTES + 4) {
          throw new Error("workload host emitted an unterminated oversized frame");
        }
      };

      child.stdout.on("data", (chunk: Buffer) => {
        if (failure !== undefined) return;
        try {
          consume(chunk);
        } catch (error) {
          fail(error);
        }
      });
      child.stderr.on("data", (chunk: Buffer) => {
        if (failure !== undefined) return;
        const remaining = STDERR_LIMIT_BYTES - stderr.length;
        if (remaining > 0) stderr = Buffer.concat([stderr, chunk.subarray(0, remaining)]);
        if (chunk.length > remaining) fail(new Error("workload host exceeded its stderr limit"));
      });
      // A provider may ignore cancellation and finish after the sandbox has
      // already closed. Keep EPIPE on the response pipe inside this exchange;
      // the outer invocation/lease must not settle until that provider chain
      // has also settled.
      child.stdin.on("error", fail);
      child.once("error", fail);
      child.once("close", (code) => {
        childClosed = true;
        if (hardKill !== undefined) clearTimeout(hardKill);
        void chain.catch((error: unknown) => { fail(error); }).then(() => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          options.signal?.removeEventListener("abort", onAbort);
          if (failure !== undefined) {
            reject(failure);
            return;
          }
          if (code !== 0) {
            const diagnostic = stderr.toString("utf8").trim().slice(0, 512);
            reject(new Error(
              `workload host exited with code ${code ?? 128}${diagnostic ? `: ${diagnostic}` : ""}`,
            ));
            return;
          }
          if (stdout.length !== 0 || finalMessage === undefined) {
            reject(new Error("workload host exited without exactly one complete final frame"));
            return;
          }
          resolve(finalMessage);
        });
      });
      const timer = setTimeout(() => fail(new Error("workload host timed out")), options.timeoutMilliseconds);
      timer.unref();
      const onAbort = (): void => fail(new Error("workload host invocation was aborted"));
      options.signal?.addEventListener("abort", onAbort, { once: true });
      if (options.signal?.aborted === true) onAbort();
      try {
        write(options.request);
      } catch (error) {
        fail(error);
      }
    });
  }
}
