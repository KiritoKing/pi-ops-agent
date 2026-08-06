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

  it("uses fixed argv for setup, hardening, and restart", async () => {
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
      botmuxCommand: "/usr/bin/botmux",
      nodeCommand: "/opt/runtime/node",
      setupScript: "/opt/plugin/configure-botmux.mjs",
    });

    expect(commands).toEqual([
      { command: "/usr/bin/botmux", arguments: ["setup"] },
      { command: "/opt/runtime/node", arguments: ["/opt/plugin/configure-botmux.mjs"] },
      { command: "/usr/bin/botmux", arguments: ["restart"] },
    ]);
    expect(text).toContain("outside the model");
    expect(text).toContain("initialized and restarted");
  });
});
