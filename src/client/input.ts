import { TextDecoder } from "node:util";
import { unwrapBotMuxInput } from "./botmux-envelope.js";
import { isForbiddenTextControl } from "../shared/terminal-safety.js";

const BRACKETED_PASTE_START = "\u001b[200~";
const BRACKETED_PASTE_END = "\u001b[201~";
const MAX_INPUT_BYTES = 64 * 1024;

export type InputEvent =
  | { type: "submit"; text: string }
  | { type: "abort" }
  | { type: "eof" };

export class TerminalInputParser {
  readonly #decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
  readonly #unwrapBotMux: boolean;
  #pending = "";
  #current = "";
  #currentBytes = 0;
  #inPaste = false;
  #skipLineFeed = false;

  constructor(environment: NodeJS.ProcessEnv = process.env) {
    this.#unwrapBotMux = environment.OPS_AGENT_INPUT_ENVELOPE === "botmux-v1";
  }

  push(chunk: Buffer): InputEvent[] {
    this.#pending += this.#decoder.decode(chunk, { stream: true });
    return this.#drain(false);
  }

  end(chunk?: Buffer): InputEvent[] {
    this.#pending += this.#decoder.decode(chunk);
    const events = this.#drain(true);
    if (this.#current.length > 0) {
      events.push({ type: "submit", text: this.#takeCurrent() });
    }
    events.push({ type: "eof" });
    return events;
  }

  #drain(final: boolean): InputEvent[] {
    const events: InputEvent[] = [];
    while (this.#pending.length > 0) {
      const marker = this.#inPaste ? BRACKETED_PASTE_END : BRACKETED_PASTE_START;
      if (this.#pending.startsWith(marker)) {
        this.#pending = this.#pending.slice(marker.length);
        this.#inPaste = !this.#inPaste;
        continue;
      }
      if (!final && marker.startsWith(this.#pending)) break;

      const codePoint = this.#pending.codePointAt(0);
      if (codePoint === undefined) break;
      const character = String.fromCodePoint(codePoint);
      this.#pending = this.#pending.slice(character.length);

      if (this.#inPaste) {
        this.#append(character);
        continue;
      }
      if (character === "\u0003") {
        this.#current = "";
        this.#currentBytes = 0;
        events.push({ type: "abort" });
        continue;
      }
      if (character === "\u0004") {
        if (this.#current.length > 0) {
          events.push({ type: "submit", text: this.#takeCurrent() });
        }
        events.push({ type: "eof" });
        continue;
      }
      if (character === "\u007f" || character === "\b") {
        const characters = Array.from(this.#current);
        const removed = characters.pop();
        this.#current = characters.join("");
        if (removed !== undefined) this.#currentBytes -= Buffer.byteLength(removed, "utf8");
        continue;
      }
      if (character === "\r") {
        events.push({ type: "submit", text: this.#takeCurrent() });
        this.#skipLineFeed = true;
        continue;
      }
      if (character === "\n") {
        if (this.#skipLineFeed) {
          this.#skipLineFeed = false;
          continue;
        }
        events.push({ type: "submit", text: this.#takeCurrent() });
        continue;
      }
      this.#skipLineFeed = false;
      this.#append(character);
    }
    return events;
  }

  #append(value: string): void {
    if (isForbiddenTextControl(value.codePointAt(0) ?? 0, true)) {
      this.#current = "";
      this.#currentBytes = 0;
      throw new Error("input contains a forbidden control character");
    }
    const bytes = Buffer.byteLength(value, "utf8");
    if (this.#currentBytes + bytes > MAX_INPUT_BYTES) {
      this.#current = "";
      this.#currentBytes = 0;
      throw new Error(`input exceeds ${MAX_INPUT_BYTES} UTF-8 bytes`);
    }
    this.#current += value;
    this.#currentBytes += bytes;
  }

  #takeCurrent(): string {
    const value = this.#current;
    this.#current = "";
    this.#currentBytes = 0;
    return this.#unwrapBotMux ? unwrapBotMuxInput(value).text : value;
  }
}
