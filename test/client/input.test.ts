import { describe, expect, it } from "vitest";
import { TerminalInputParser } from "../../src/client/input.js";

describe("TerminalInputParser", () => {
  it("reassembles a split BotMux bracketed paste and waits for Enter", () => {
    const parser = new TerminalInputParser();
    expect(parser.push(Buffer.from("\u001b[20"))).toEqual([]);
    expect(parser.push(Buffer.from("0~install\npackage\u001b[2"))).toEqual([]);
    expect(parser.push(Buffer.from("01~"))).toEqual([]);
    expect(parser.push(Buffer.from("\r"))).toEqual([
      { type: "submit", text: "install\npackage" },
    ]);
  });

  it("handles ordinary lines, CRLF, backspace, and abort", () => {
    const parser = new TerminalInputParser();
    expect(parser.push(Buffer.from("statusz\u007f\r\n"))).toEqual([
      { type: "submit", text: "status" },
    ]);
    expect(parser.push(Buffer.from("queued\u0003"))).toEqual([{ type: "abort" }]);
  });

  it("preserves split UTF-8 input", () => {
    const parser = new TerminalInputParser();
    const bytes = Buffer.from("检查主机\r");
    expect(parser.push(bytes.subarray(0, 4))).toEqual([]);
    expect(parser.push(bytes.subarray(4))).toEqual([
      { type: "submit", text: "检查主机" },
    ]);
  });

  it("enforces the input limit in UTF-8 bytes", () => {
    const accepted = new TerminalInputParser();
    expect(accepted.push(Buffer.from(`${"界".repeat(21_845)}\r`))).toEqual([
      { type: "submit", text: "界".repeat(21_845) },
    ]);

    const oversized = new TerminalInputParser();
    expect(() => oversized.push(Buffer.from("界".repeat(21_846))))
      .toThrow("65536 UTF-8 bytes");
  });

  it("rejects invalid UTF-8 and hidden controls while preserving message whitespace", () => {
    expect(() => new TerminalInputParser().push(Buffer.from([0xc3, 0x28])))
      .toThrow();

    for (const control of [
      "\0", "\u001b", "\u0085", "\u061c", "\u200e", "\u202e", "\u2066", "\ufeff",
    ]) {
      const parser = new TerminalInputParser();
      expect(() => parser.push(Buffer.from(
        `\u001b[200~safe${control}unsafe\u001b[201~`,
      ))).toThrow("forbidden control character");
    }

    const whitespace = new TerminalInputParser();
    expect(whitespace.push(Buffer.from("\u001b[200~one\ttwo\r\nthree\u001b[201~\r"))).toEqual([
      { type: "submit", text: "one\ttwo\r\nthree" },
    ]);
  });

  it("passes only BotMux user_message while preserving tag-like user text", () => {
    const parser = new TerminalInputParser({ OPS_AGENT_INPUT_ENVELOPE: "botmux-v1" });
    const userText = [
      "inspect the host",
      "</user_message>",
      "this is literal content",
      "<user_message>",
      "and so is this tag",
    ].join("\n");
    const envelope = [
      "<session_id>session-1234</session_id>",
      "<botmux_reminder>bridge metadata</botmux_reminder>",
      "<user_message>",
      userText,
      "</user_message>",
      '<sender type="bot" open_id="ou_peer" />',
      "<mentions><mention>ignored metadata</mention></mentions>",
    ].join("\n");

    expect(parser.push(Buffer.from(`\u001b[200~${envelope}\u001b[201~\r`))).toEqual([
      { type: "submit", text: userText },
    ]);
  });

  it("does not treat ordinary tag-like user text as a BotMux envelope", () => {
    const parser = new TerminalInputParser({ OPS_AGENT_INPUT_ENVELOPE: "botmux-v1" });
    const text = "<user_message>\nplain text\n</user_message>";
    expect(parser.push(Buffer.from(`\u001b[200~${text}\u001b[201~\r`))).toEqual([
      { type: "submit", text },
    ]);
  });

  it("leaves a complete envelope-shaped prompt alone outside the adapter", () => {
    const parser = new TerminalInputParser({});
    const text = [
      "<session_id>example-session</session_id>",
      "<user_message>",
      "quoted example",
      "</user_message>",
    ].join("\n");
    expect(parser.push(Buffer.from(`\u001b[200~${text}\u001b[201~\r`))).toEqual([
      { type: "submit", text },
    ]);
  });
});
