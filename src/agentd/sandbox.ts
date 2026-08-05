import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import { join } from "node:path";

const MAX_OUTPUT_BYTES = 64 * 1024;

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
  if (!existsSync(options.bwrapPath)) {
    throw new Error(`bubblewrap not found at ${options.bwrapPath}`);
  }

  const args = [
    "--die-with-parent",
    "--new-session",
    "--unshare-all",
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
  for (const path of ["/usr", "/bin", "/sbin", "/lib", "/lib64"]) {
    if (existsSync(path)) args.push("--ro-bind", path, path);
  }
  for (const path of ["/etc/passwd", "/etc/group", "/etc/nsswitch.conf"]) {
    if (existsSync(path)) args.push("--ro-bind", path, path);
  }
  args.push(options.bashPath, "--noprofile", "--norc", "-lc", options.command);

  return await new Promise<SandboxResult>((resolve, reject) => {
    const child = spawn(options.bwrapPath, args, {
      stdio: ["ignore", "pipe", "pipe"],
      env: {},
    });
    let stdout: Buffer<ArrayBufferLike> = Buffer.alloc(0);
    let stderr: Buffer<ArrayBufferLike> = Buffer.alloc(0);
    let truncated = false;
    let timedOut = false;

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
    child.stdout.on("data", (chunk: Buffer) => {
      stdout = collect(stdout, chunk);
    });
    child.stderr.on("data", (chunk: Buffer) => {
      stderr = collect(stderr, chunk);
    });

    const terminate = (): void => {
      child.kill("SIGTERM");
      const hardKill = setTimeout(() => child.kill("SIGKILL"), 1500);
      hardKill.unref();
    };
    const timer = setTimeout(() => {
      timedOut = true;
      terminate();
    }, options.timeoutSeconds * 1000);
    timer.unref();
    const onAbort = (): void => terminate();
    options.signal?.addEventListener("abort", onAbort, { once: true });

    child.once("error", (error) => {
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", onAbort);
      reject(error);
    });
    child.once("close", (code) => {
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", onAbort);
      resolve({
        exitCode: code ?? 128,
        stdout: stdout.toString("utf8"),
        stderr: stderr.toString("utf8"),
        timedOut,
        truncated,
      });
    });
  });
}
