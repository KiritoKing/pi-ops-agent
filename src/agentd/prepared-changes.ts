import type { ChangeRef } from "../shared/approval.js";
import { encodeChangeRef } from "../shared/approval.js";

const MAX_TOOL_CALL_ID_CHARS = 512;
const MAX_PREPARED_CHANGES_PER_TOOL = 32;
const MAX_TRACKED_TOOL_CALLS = 256;

/**
 * Records only successful trusted-provider preparations. Source workload output is never
 * parsed for this signal, so an untrusted plugin cannot forge a client approval binding.
 */
export class PreparedChangeTracker {
  readonly #byToolCall = new Map<string, string[]>();

  record(toolCallId: string, changeRef: ChangeRef): void {
    if (toolCallId.length < 1 || toolCallId.length > MAX_TOOL_CALL_ID_CHARS
      || toolCallId.includes("\0") || toolCallId.includes("\n")) {
      throw new Error("prepared change has an invalid tool-call correlation");
    }
    let references = this.#byToolCall.get(toolCallId);
    if (references === undefined) {
      if (this.#byToolCall.size >= MAX_TRACKED_TOOL_CALLS) {
        throw new Error("too many unconsumed prepared-change correlations");
      }
      references = [];
      this.#byToolCall.set(toolCallId, references);
    }
    const encoded = encodeChangeRef(changeRef);
    if (references.includes(encoded)) return;
    if (references.length >= MAX_PREPARED_CHANGES_PER_TOOL) {
      throw new Error("one tool call prepared too many changes to bind safely");
    }
    references.push(encoded);
  }

  consume(toolCallId: string): readonly string[] {
    const references = this.#byToolCall.get(toolCallId);
    this.#byToolCall.delete(toolCallId);
    return references === undefined ? [] : [...references];
  }

  clear(): void {
    this.#byToolCall.clear();
  }
}
