import { PassThrough } from "node:stream";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  parseAdapterDescriptorJson,
  type AdapterDescriptor,
  type AdapterInboundText,
  type AdapterSessionControl,
} from "../../src/shared/adapter-runtime.js";
import {
  DeclaredAdapterInputParser,
  readAdapterClientContext,
} from "../../src/client/adapter-channel.js";

const SESSION_ID = "agent-session-channel-1234";
const EXTERNAL_SESSION_ID = "botmux-session-channel-1234";

function descriptor(): AdapterDescriptor {
  return parseAdapterDescriptorJson(
    readFileSync(join(process.cwd(), "plugins/adapter-tui/profile.json"), "utf8"),
  );
}

function bind(): AdapterSessionControl {
  return {
    apiVersion: "agentd.adapter-session-control/v1",
    schemaVersion: 1,
    type: "bind",
    controlId: "control:channel:00000001",
    externalSessionId: EXTERNAL_SESSION_ID,
    sessionId: SESSION_ID,
  };
}

function inbound(text = "检查主机状态"): AdapterInboundText {
  return {
    apiVersion: "agentd.adapter-inbound/v1",
    schemaVersion: 1,
    type: "text",
    ingressId: "ingress:channel:00000001",
    externalSessionId: EXTERNAL_SESSION_ID,
    conversationType: "direct",
    text,
    source: { authentication: "unverified", principalId: "botmux:user" },
    observedAt: "2026-08-08T08:00:00Z",
  };
}

function line(value: unknown): Buffer {
  return Buffer.from(`${JSON.stringify(value)}\n`);
}

describe("trusted Adapter Client channels", () => {
  it("reassembles split bind/text NDJSON and preserves UTF-8 text", () => {
    const parser = new DeclaredAdapterInputParser(descriptor(), SESSION_ID);
    const bytes = Buffer.concat([line(bind()), line(inbound())]);
    expect(parser.push(bytes.subarray(0, 7))).toEqual([]);
    expect(parser.push(bytes.subarray(7, bytes.length - 2))).toEqual([]);
    expect(parser.push(bytes.subarray(bytes.length - 2))).toEqual([inbound()]);
    expect(parser.end()).toEqual([]);
  });

  it("rejects invalid UTF-8, duplicate/trailing JSON, raw whitespace overflow, and action confusion", () => {
    const invalid = new DeclaredAdapterInputParser(descriptor(), SESSION_ID);
    expect(() => invalid.push(Buffer.from([0xff, 0x0a]))).toThrow("valid UTF-8");

    const duplicate = new DeclaredAdapterInputParser(descriptor(), SESSION_ID);
    expect(() => duplicate.push(Buffer.from(
      '{"apiVersion":"agentd.adapter-session-control/v1","apiVersion":"agentd.adapter-session-control/v1"}\n',
    ))).toThrow("duplicate field");

    const trailing = new DeclaredAdapterInputParser(descriptor(), SESSION_ID);
    expect(() => trailing.push(Buffer.from(`${JSON.stringify(bind())}{}\n`)))
      .toThrow("trailing value");

    const profile = descriptor();
    const whitespace = new DeclaredAdapterInputParser(profile, SESSION_ID);
    expect(() => whitespace.push(Buffer.concat([
      Buffer.alloc(profile.inbound.maxFrameBytes + 1, 0x20),
      Buffer.from("\n"),
    ]))).toThrow("raw inbound frame");

    const confused = new DeclaredAdapterInputParser(profile, SESSION_ID);
    expect(() => confused.push(Buffer.from(`${JSON.stringify({
      apiVersion: "agentd.adapter-outbound-action/v1",
      schemaVersion: 1,
      type: "send",
      actionId: "action:confused:00000001",
      externalSessionId: EXTERNAL_SESSION_ID,
      content: "unsafe",
    })}\n`))).toThrow("unsupported API version");
  });

  it("requires exact bind ordering and correlation", () => {
    expect(() => new DeclaredAdapterInputParser(descriptor(), SESSION_ID).push(line(inbound())))
      .toThrow("before the required session bind");
    const wrong = new DeclaredAdapterInputParser(descriptor(), SESSION_ID);
    expect(() => wrong.push(line({ ...bind(), sessionId: "agent-session-wrong-1234" })))
      .toThrow("does not match");
    const duplicate = new DeclaredAdapterInputParser(descriptor(), SESSION_ID);
    duplicate.push(line(bind()));
    expect(() => duplicate.push(line(bind()))).toThrow("only once");
  });

  it("rejects every hidden-directional control after typed Client decoding", () => {
    for (const control of ["\u061c", "\u200e", "\u200f", "\ufeff"]) {
      const parser = new DeclaredAdapterInputParser(descriptor(), SESSION_ID);
      parser.push(line(bind()));
      expect(() => parser.push(line(inbound(`safe${control}unsafe`))))
        .toThrow("forbidden control character");
    }
  });

  it("fatal-decodes one runner-owned descriptor/digest context frame", async () => {
    const profile = descriptor();
    const context = {
      apiVersion: "agentd.adapter-client-context/v1",
      schemaVersion: 1,
      pluginId: profile.adapterId,
      digest: `sha256:${"a".repeat(64)}`,
      descriptor: profile,
    };
    const input = new PassThrough();
    const reading = readAdapterClientContext(
      { OPS_AGENT_ADAPTER_CONTEXT_FD: "5" },
      input,
    );
    const bytes = line(context);
    input.write(bytes.subarray(0, 9));
    input.end(bytes.subarray(9));
    await expect(reading).resolves.toEqual(context);

    const invalid = new PassThrough();
    const rejected = readAdapterClientContext(
      { OPS_AGENT_ADAPTER_CONTEXT_FD: "5" },
      invalid,
    );
    invalid.end(Buffer.from([0xff, 0x0a]));
    await expect(rejected).rejects.toThrow("valid UTF-8");
  });
});
