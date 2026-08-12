import { spawn } from "node:child_process";
import { existsSync, lstatSync, readlinkSync, realpathSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import {
  monitorBubblewrapReaper,
  type BubblewrapReaperMonitor,
  wrapWithBubblewrapProcessReaper,
} from "../shared/bubblewrap-containment.js";

const MAX_OUTPUT_BYTES = 64 * 1024;
const MAX_FILE_BYTES = 64 * 1024 * 1024;
const MAX_ADDRESS_SPACE_BYTES = 1024 * 1024 * 1024;

export function wrapSandboxCommandWithProcessReaper(
  bwrapPath: string,
  innerArguments: readonly string[],
): { executable: string; arguments: string[] } {
  return wrapWithBubblewrapProcessReaper(bwrapPath, innerArguments, {
    unshareIpc: true,
    unshareNetwork: true,
  });
}

const DENIED_COMMANDS: Array<{ pattern: RegExp; reason: string }> = [
  { pattern: /(^|[;&|\s])(sudo|doas|pkexec)(\s|$)/i, reason: "privilege escalation" },
  { pattern: /(^|[;&|\s])(su|nsenter|unshare|chroot|pivot_root)(\s|$)/i, reason: "namespace or identity escape" },
  { pattern: /(^|[;&|\s])(mount|umount|modprobe|insmod|rmmod)(\s|$)/i, reason: "kernel or mount mutation" },
  { pattern: /(^|[;&|\s])(mkfs(?:\.[a-z0-9]+)?|fdisk|parted)(\s|$)/i, reason: "block device mutation" },
  { pattern: /(^|[;&|\s])(reboot|shutdown|poweroff|halt)(\s|$)/i, reason: "host lifecycle control" },
  { pattern: /(^|[;&|\s])(docker|podman|lxc|lxd|virsh)(\s|$)/i, reason: "container or VM control socket" },
  { pattern: /(^|[;&|\s])(iptables|ip6tables|nft)(\s|$)/i, reason: "firewall mutation" },
  { pattern: /\/dev\/(?:sd[a-z]|nvme\d+n\d+|vd[a-z])\b/i, reason: "raw block device access" },
  { pattern: /:\s*\(\s*\)\s*\{[^}]*:\s*\|\s*:/, reason: "fork bomb" },
];

export interface SandboxResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  truncated: boolean;
}

export function validateSandboxCommand(command: string): void {
  if (command.length === 0 || command.length > 32 * 1024) {
    throw new Error("command length is outside the allowed range");
  }
  for (const denied of DENIED_COMMANDS) {
    if (denied.pattern.test(command)) {
      throw new Error(`sandbox command denied: ${denied.reason}`);
    }
  }
}

function fixedRootExecutable(path: string, label: string): string {
  if (!existsSync(path)) throw new Error(`${label} does not exist at its fixed path`);
  const resolved = realpathSync(path);
  const info = lstatSync(resolved);
  if (!info.isFile() || info.uid !== 0 || (info.mode & 0o022) !== 0
    || (info.mode & 0o111) === 0) {
    throw new Error(`${label} must be a root-owned, non-writable executable file`);
  }
  return resolved;
}

function fixedPrlimit(): string {
  for (const path of ["/usr/bin/prlimit", "/bin/prlimit"]) {
    if (existsSync(path)) return fixedRootExecutable(path, "prlimit");
  }
  throw new Error("sandbox requires the fixed util-linux prlimit boundary");
}

export async function runSandboxedCommand(options: {
  command: string;
  timeoutSeconds: number;
  workspaceDir: string;
  bwrapPath: string;
  bashPath: string;
  signal?: AbortSignal;
}): Promise<SandboxResult> {
  validateSandboxCommand(options.command);
  await mkdir(options.workspaceDir, { recursive: true, mode: 0o750 });
  await mkdir(join(options.workspaceDir, ".home"), { recursive: true, mode: 0o700 });

  if (process.platform !== "linux") {
    throw new Error("bubblewrap execution is supported only on Linux");
  }
  const bwrapPath = fixedRootExecutable(options.bwrapPath, "bubblewrap");
  const bashPath = fixedRootExecutable(options.bashPath, "bash");
  const prlimitPath = fixedPrlimit();

  const innerArguments = [
    "--die-with-parent",
    "--new-session",
    // Keep this list aligned with ops-agentd.service RestrictNamespaces= and
    // the Source Workload host. bwrap creates the mount namespace itself;
    // requesting --unshare-all would also request UTS/cgroup namespaces that
    // the hardened service deliberately denies.
    "--unshare-user",
    "--unshare-ipc",
    "--unshare-pid",
    "--unshare-net",
    "--as-pid-1",
    "--disable-userns",
    "--cap-drop",
    "ALL",
    "--proc",
    "/proc",
    "--dev",
    "/dev",
    "--tmpfs",
    "/tmp",
    "--dir",
    "/workspace",
    "--bind",
    options.workspaceDir,
    "/workspace",
    "--chdir",
    "/workspace",
    "--clearenv",
    "--setenv",
    "HOME",
    "/workspace/.home",
    "--setenv",
    "PATH",
    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "--setenv",
    "LANG",
    "C.UTF-8",
  ];
  if (!existsSync("/usr") || lstatSync("/usr").isSymbolicLink()) {
    throw new Error("sandbox requires a real /usr directory");
  }
  innerArguments.push("--ro-bind", "/usr", "/usr");
  for (const path of ["/bin", "/sbin", "/lib", "/lib64"]) {
    if (!existsSync(path)) continue;
    const stat = lstatSync(path);
    if (!stat.isSymbolicLink()) {
      innerArguments.push("--ro-bind", path, path);
      continue;
    }
    const target = readlinkSync(path);
    const expected = `usr/${path.slice(1)}`;
    if (target !== expected && target !== `/${expected}`) {
      throw new Error(`sandbox refuses unexpected merged-/usr link: ${path} -> ${target}`);
    }
    innerArguments.push("--symlink", target, path);
  }
  for (const path of ["/etc/passwd", "/etc/group", "/etc/nsswitch.conf"]) {
    if (existsSync(path)) innerArguments.push("--ro-bind", path, path);
  }
  const cpuSeconds = Math.min(125, Math.max(2, options.timeoutSeconds + 2));
  innerArguments.push(
    prlimitPath,
    `--as=${MAX_ADDRESS_SPACE_BYTES}:${MAX_ADDRESS_SPACE_BYTES}`,
    "--core=0:0",
    `--cpu=${cpuSeconds}:${cpuSeconds}`,
    `--fsize=${MAX_FILE_BYTES}:${MAX_FILE_BYTES}`,
    "--nofile=128:128",
    "--nproc=64:64",
    "--",
    bashPath,
    "--noprofile",
    "--norc",
    "-lc",
    options.command,
  );
  const command = wrapSandboxCommandWithProcessReaper(bwrapPath, innerArguments);
  const child = spawn(command.executable, command.arguments, {
    stdio: [
      "ignore", "pipe", "pipe",
      "ignore", "ignore", "ignore", "ignore", "ignore",
      "pipe", "pipe",
    ],
    env: {},
  });
  const childStdout = child.stdout;
  const childStderr = child.stderr;
  if (childStdout === null || childStderr === null) {
    child.kill("SIGKILL");
    throw new Error("sandbox requires piped output streams");
  }
  let reaperMonitor: BubblewrapReaperMonitor;
  try {
    reaperMonitor = monitorBubblewrapReaper(child);
  } catch (error) {
    child.kill("SIGKILL");
    throw error;
  }

  return await new Promise<SandboxResult>((resolve, reject) => {
    let stdout: Buffer<ArrayBufferLike> = Buffer.alloc(0);
    let stderr: Buffer<ArrayBufferLike> = Buffer.alloc(0);
    let truncated = false;
    let timedOut = false;
    let reaperMonitorError: Error | undefined;
    let processError: Error | undefined;
    let childClosed = false;
    let hardKill: NodeJS.Timeout | undefined;

    const collect = (
      current: Buffer<ArrayBufferLike>,
      chunk: Buffer<ArrayBufferLike>,
    ): Buffer<ArrayBufferLike> => {
      const remaining = MAX_OUTPUT_BYTES - current.length;
      if (remaining <= 0) {
        truncated = true;
        return current;
      }
      if (chunk.length > remaining) truncated = true;
      return Buffer.concat([current, chunk.subarray(0, remaining)]);
    };
    childStdout.on("data", (chunk: Buffer) => {
      stdout = collect(stdout, chunk);
    });
    childStderr.on("data", (chunk: Buffer) => {
      stderr = collect(stderr, chunk);
    });

    const terminate = (): void => {
      if (childClosed) return;
      child.kill("SIGTERM");
      if (hardKill === undefined) {
        hardKill = setTimeout(() => child.kill("SIGKILL"), 1500);
        hardKill.unref();
      }
    };
    const timer = setTimeout(() => {
      timedOut = true;
      terminate();
    }, options.timeoutSeconds * 1000);
    timer.unref();
    const onAbort = (): void => terminate();
    options.signal?.addEventListener("abort", onAbort, { once: true });
    const failReaperMonitor = (): void => {
      reaperMonitorError ??= new Error("bubblewrap reaper lifecycle monitoring failed");
      terminate();
    };
    void reaperMonitor.syncEof.catch(failReaperMonitor);
    void reaperMonitor.identity.catch(failReaperMonitor);

    child.once("error", (error) => {
      processError = error;
      terminate();
    });
    child.once("close", (code) => {
      childClosed = true;
      if (hardKill !== undefined) clearTimeout(hardKill);
      void reaperMonitor.waitForExit().catch(() => {
        failReaperMonitor();
      }).then(() => {
        clearTimeout(timer);
        options.signal?.removeEventListener("abort", onAbort);
        if (reaperMonitorError !== undefined) {
          reject(reaperMonitorError);
          return;
        }
        if (processError !== undefined) {
          reject(processError);
          return;
        }
        resolve({
          exitCode: code ?? 128,
          stdout: stdout.toString("utf8"),
          stderr: stderr.toString("utf8"),
          timedOut,
          truncated,
        });
      });
    });
  });
}
