import { StringDecoder } from "node:string_decoder";

const BRACKETED_PASTE_START = "\u001b[200~";
const BRACKETED_PASTE_END = "\u001b[201~";
const MAX_INPUT_CHARACTERS = 64 * 1024;

export type InputEvent =
  | { type: "submit"; text: string }
  | { type: "abort" }
  | { type: "eof" };

export class TerminalInputParser {
  readonly #decoder = new StringDecoder("utf8");
  #pending = "";
  #current = "";
  #inPaste = false;
  #skipLineFeed = false;

  push(chunk: Buffer): InputEvent[] {
    this.#pending += this.#decoder.write(chunk);
    return this.#drain(false);
  }

  end(chunk?: Buffer): InputEvent[] {
    if (chunk) this.#pending += this.#decoder.end(chunk);
    else this.#pending += this.#decoder.end();
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

      const character = this.#pending[0];
      if (character === undefined) break;
      this.#pending = this.#pending.slice(1);

      if (this.#inPaste) {
        this.#append(character);
        continue;
      }
      if (character === "\u0003") {
        this.#current = "";
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
        this.#current = Array.from(this.#current).slice(0, -1).join("");
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
    this.#current += value;
    if (this.#current.length > MAX_INPUT_CHARACTERS) {
      this.#current = "";
      throw new Error(`input exceeds ${MAX_INPUT_CHARACTERS} characters`);
    }
  }

  #takeCurrent(): string {
    const value = this.#current;
    this.#current = "";
    return value;
  }
}
