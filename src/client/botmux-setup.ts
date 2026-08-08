import { spawn } from "node:child_process";
import { isAbsolute, normalize } from "node:path";
import type { Readable, Writable } from "node:stream";

const DEFAULT_SETUP_HELPER = "/usr/libexec/pi-ops-agent/setup-botmux";

export type LocalClientCommand = { kind: "botmux-setup" };

export interface InteractiveCommand {
  command: string;
  arguments: readonly string[];
}

export type InteractiveCommandRunner = (
  invocation: InteractiveCommand,
  input: Readable,
  output: Writable,
) => Promise<void>;

export interface InitializeBotMuxOptions {
  input: Readable;
  output: Writable;
  runner?: InteractiveCommandRunner;
  setupHelper?: string;
}

export function parseLocalClientCommand(text: string): LocalClientCommand | undefined {
  const [name, ...parameters] = text.trim().split(/\s+/u);
  if (name !== "/botmux-setup") return undefined;
  if (parameters.length > 0) throw new Error("usage: /botmux-setup");
  return { kind: "botmux-setup" };
}

export const runInteractiveCommand: InteractiveCommandRunner = async (
  invocation,
  input,
  output,
): Promise<void> => {
  await new Promise<void>((resolve, reject) => {
    const child = spawn(invocation.command, [...invocation.arguments], {
      env: {
        PATH: "/usr/sbin:/usr/bin:/sbin:/bin",
        LANG: "C.UTF-8",
        LC_ALL: "C.UTF-8",
        ...(process.env.TERM === undefined ? {} : { TERM: process.env.TERM }),
      },
      shell: false,
      stdio: [input, output, output],
    });
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      if (code === 0) resolve();
      else reject(new Error(
        `${invocation.command} exited with ${signal ? `signal ${signal}` : `code ${code ?? "unknown"}`}`,
      ));
    });
  });
};

export async function initializeBotMux(options: InitializeBotMuxOptions): Promise<void> {
  const runner = options.runner ?? runInteractiveCommand;
  const setupHelper = options.setupHelper ?? DEFAULT_SETUP_HELPER;
  if (!isAbsolute(setupHelper) || normalize(setupHelper) !== setupHelper
    || setupHelper.includes("\0") || setupHelper.includes("\n")) {
    throw new Error("BotMux setup helper path must be absolute and normalized");
  }

  options.output.write(
    "BotMux setup is running outside the model under the dedicated ops-agent-botmux account.\n"
      + "sudo requires a fresh administrator password; secrets entered afterward are sent only to BotMux.\n",
  );
  await runner({
    command: "/usr/bin/sudo",
    arguments: ["-k", "--", setupHelper],
  }, options.input, options.output);
  options.output.write("BotMux initialized and restarted with the ops-agent adapter.\n");
}
