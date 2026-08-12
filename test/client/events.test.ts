import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";
import {
  boundClientEventContent,
  eventSinkFromEnvironment,
  MAX_CLIENT_EVENT_CONTENT_BYTES,
  NdjsonEventSink,
} from "../../src/client/events.js";

describe("client completion events", () => {
  it("serializes a versioned, redacted NDJSON event", async () => {
    const output = new PassThrough();
    let saved = "";
    output.on("data", (chunk: Buffer | string) => {
      saved += chunk.toString();
    });
    const secret = `sk-${"x".repeat(32)}`;

    await new NdjsonEventSink(output).publish({
      version: 1,
      type: "completion",
      eventId: "event-12345678",
      outcome: "success",
      content: `done ${secret}`,
    });

    expect(JSON.parse(saved)).toEqual({
      version: 1,
      type: "completion",
      eventId: "event-12345678",
      outcome: "success",
      content: "done [REDACTED]",
    });
  });

  it("bounds large UTF-8 content without leaving a partial character", () => {
    const bounded = boundClientEventContent("界".repeat(30_000));
    expect(Buffer.byteLength(bounded.text, "utf8"))
      .toBeLessThanOrEqual(MAX_CLIENT_EVENT_CONTENT_BYTES);
    expect(bounded.text).toMatch(/\[TRUNCATED\]$/u);
    expect(bounded.text).not.toContain("�");
    expect(bounded.truncated).toBe(true);
  });

  it("keeps the event channel disabled unless an inherited fd is explicit", () => {
    expect(eventSinkFromEnvironment({})).toBeUndefined();
    expect(() => eventSinkFromEnvironment({ OPS_AGENT_EVENT_FD: "shell command" }))
      .toThrow("must be an integer");
    expect(() => eventSinkFromEnvironment({ OPS_AGENT_EVENT_FD: "2" }))
      .toThrow("between 3 and 1024");
  });
});
