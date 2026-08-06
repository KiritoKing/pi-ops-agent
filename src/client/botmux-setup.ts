import { spawn } from "node:child_process";
import type { Readable, Writable } from "node:stream";

const DEFAULT_SETUP_SCRIPT =
  "/opt/pi-ops-agent/plugins/adapter.botmux/current/configure-botmux.mjs";

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
  botmuxCommand?: string;
  nodeCommand?: string;
  setupScript?: string;
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
      env: process.env,
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
  const botmuxCommand = options.botmuxCommand ?? "botmux";
  const nodeCommand = options.nodeCommand ?? process.execPath;
  const setupScript = options.setupScript ?? DEFAULT_SETUP_SCRIPT;

  options.output.write(
    "BotMux setup is running outside the model. Secrets entered below are sent only to BotMux.\n",
  );
  await runner({ command: botmuxCommand, arguments: ["setup"] }, options.input, options.output);
  await runner({ command: nodeCommand, arguments: [setupScript] }, options.input, options.output);
  await runner({ command: botmuxCommand, arguments: ["restart"] }, options.input, options.output);
  options.output.write("BotMux initialized and restarted with the ops-agent adapter.\n");
}
