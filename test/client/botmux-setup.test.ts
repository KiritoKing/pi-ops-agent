import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";
import {
  initializeBotMux,
  parseLocalClientCommand,
  type InteractiveCommand,
  type InteractiveCommandRunner,
} from "../../src/client/botmux-setup.js";

describe("model-external BotMux setup", () => {
  it("recognizes only the exact local command", () => {
    expect(parseLocalClientCommand(" /botmux-setup ")).toEqual({ kind: "botmux-setup" });
    expect(parseLocalClientCommand("please setup botmux")).toBeUndefined();
    expect(() => parseLocalClientCommand("/botmux-setup now")).toThrow("usage");
  });

  it("uses one fixed password-gated root wrapper with no caller arguments", async () => {
    const commands: InteractiveCommand[] = [];
    const runner: InteractiveCommandRunner = (invocation) => {
      commands.push(invocation);
      return Promise.resolve();
    };
    const input = new PassThrough();
    const output = new PassThrough();
    let text = "";
    output.on("data", (chunk: Buffer | string) => { text += chunk.toString(); });

    await initializeBotMux({
      input,
      output,
      runner,
      setupHelper: "/usr/libexec/pi-ops-agent/setup-botmux",
    });

    expect(commands).toEqual([
      {
        command: "/usr/bin/sudo",
        arguments: ["-k", "--", "/usr/libexec/pi-ops-agent/setup-botmux"],
      },
    ]);
    expect(text).toContain("outside the model");
    expect(text).toContain("dedicated ops-agent-botmux account");
    expect(text).toContain("initialized and restarted");
  });

  it("rejects a non-normalized setup helper path", async () => {
    await expect(initializeBotMux({
      input: new PassThrough(),
      output: new PassThrough(),
      setupHelper: "/usr/libexec/pi-ops-agent/../pi-ops-agent/setup-botmux",
    })).rejects.toThrow(/absolute and normalized/u);
  });
});
