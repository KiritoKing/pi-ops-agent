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
});
