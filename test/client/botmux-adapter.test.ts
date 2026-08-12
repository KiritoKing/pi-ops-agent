import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import type { Writable } from "node:stream";
import { pathToFileURL } from "node:url";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  parseAdapterDescriptor,
  parseAdapterDescriptorJson,
  parseDeclaredAdapterOutboundAction,
  parseDeclaredAdapterInbound,
  parseDeclaredAdapterSessionControl,
  adapterDescriptorGrant,
  type AdapterOutboundAction,
  type AdapterDescriptor,
  type AdapterInbound,
  type AdapterSessionControl,
} from "../../src/shared/adapter-runtime.js";
import { parseStrictJson } from "../../src/shared/workload-runtime.js";

interface EnvelopeInspection {
  unwrapped: boolean;
  content?: string;
  senderType?: "user" | "bot";
}

interface CompletionEvent {
  version: 1;
  type: "completion";
  eventId: string;
  outcome: "error" | "success";
  content: string;
  sessionId?: string;
  turnId?: string;
  machineId?: string;
  targetId?: string;
}

const CONTRACTS = {
  parseDeclaredAdapterOutboundAction,
  parseDeclaredAdapterInbound,
  parseDeclaredAdapterSessionControl,
  parseStrictJson,
};

interface BotMuxAdapterModule {
  descriptor: AdapterDescriptor;
  parseBotMuxInvocationArguments(arguments_: readonly string[]): { sessionId: string };
  inspectBotMuxEnvelope(value: string): EnvelopeInspection;
  createBotMuxInputConsumer(
    onEnvelope: (envelope: EnvelopeInspection) => void | Promise<void>,
  ): Writable;
  createDeclaredBind(
    sessionId: string,
    externalSessionId: string,
    contracts: typeof CONTRACTS,
  ): AdapterSessionControl;
  createDeclaredInboundText(
    content: string,
    senderType: "user" | "bot" | undefined,
    externalSessionId: string,
    contracts: typeof CONTRACTS,
  ): AdapterInbound;
  mentionArgument(senderType?: string): string;
  parseCompletionEventLine(line: Buffer, contracts: typeof CONTRACTS): CompletionEvent;
  createDeclaredSendAction(
    event: CompletionEvent,
    externalSessionId: string,
    contracts: typeof CONTRACTS,
  ): AdapterOutboundAction;
}

async function loadAdapter(): Promise<BotMuxAdapterModule> {
  const url = pathToFileURL(join(process.cwd(), "integrations/botmux/adapter.mjs")).href;
  return await import(url) as BotMuxAdapterModule;
}

describe("BotMux adapter boundary", () => {
  it("publishes the same strict status-only contract from the runnable source snapshot", async () => {
    const adapter = await loadAdapter();
    const compiledDescriptor = parseAdapterDescriptor(adapter.descriptor);
    const sourceOutput = execFileSync(process.execPath, [
      join(process.cwd(), "plugins/adapter-botmux-source/adapter.mjs"),
      "--agentd-adapter-describe",
    ], {
      encoding: "utf8",
      env: { PATH: "/usr/bin:/bin", LANG: "C.UTF-8" },
      timeout: 5_000,
      maxBuffer: 64 * 1024,
    });
    expect(parseAdapterDescriptorJson(sourceOutput)).toEqual(compiledDescriptor);
    expect(compiledDescriptor).toMatchObject({
      adapterId: "adapter.botmux",
      runtimeAuthority: {
        execution: "source-process",
        filesystem: "host-as-runtime-uid",
        network: "host",
        credentials: "runtime-uid-readable",
        actionScopeEnforcement: "digest-review-and-typed-ipc-contract",
      },
      session: { supportedControls: ["bind"] },
      inbound: { supportedTypes: ["text"] },
      approval: { mode: "status-only", identitySource: "none" },
      outbound: {
        transport: "completion-fd",
        schema: "completion.v1",
        supportedActions: ["send"],
      },
    });
    const manifest = JSON.parse(readFileSync(
      join(process.cwd(), "plugins/adapter-botmux-source/manifest.json"),
      "utf8",
    )) as { capabilities: string[]; requestedScopes: string[] };
    expect(adapterDescriptorGrant(compiledDescriptor)).toEqual({
      capabilities: manifest.capabilities,
      requestedScopes: manifest.requestedScopes,
    });
  });

  it("strictly parses completion lines and validates the declared send action", async () => {
    const adapter = await loadAdapter();
    const event: CompletionEvent = {
      version: 1,
      type: "completion",
      eventId: "event-12345678",
      outcome: "success",
      content: "line one\tstatus\r\nline two",
      sessionId: "agent-session-1234",
    };
    const parsed = adapter.parseCompletionEventLine(Buffer.from(JSON.stringify(event)), CONTRACTS);
    expect(adapter.createDeclaredSendAction(parsed, "external-session-1234", CONTRACTS)).toEqual({
      apiVersion: "agentd.adapter-outbound-action/v1",
      schemaVersion: 1,
      type: "send",
      actionId: event.eventId,
      externalSessionId: "external-session-1234",
      content: event.content,
    });
  });

  it("rejects ambiguous, oversized, invalid UTF-8, and control-bearing completion frames", async () => {
    const adapter = await loadAdapter();
    const prefix = '{"version":1,"type":"completion","eventId":"event-12345678",';
    expect(() => adapter.parseCompletionEventLine(
      Buffer.from(`${prefix}"outcome":"error","outcome":"success","content":"done"}`),
      CONTRACTS,
    )).toThrow("duplicate field");
    expect(() => adapter.parseCompletionEventLine(
      Buffer.from(`${prefix}"outcome":"success","content":"done"}{}`),
      CONTRACTS,
    )).toThrow("trailing value");
    expect(() => adapter.parseCompletionEventLine(
      Buffer.alloc(adapter.descriptor.outbound.maxFrameBytes + 1, 0x20),
      CONTRACTS,
    )).toThrow("declared frame limit");
    expect(() => adapter.parseCompletionEventLine(Buffer.from([0xff]), CONTRACTS))
      .toThrow("valid UTF-8");

    for (const control of [
      "\0", "\u001b", "\u0085", "\u061c", "\u200e", "\u200f", "\u202e", "\u2066", "\ufeff",
    ]) {
      const parsed = adapter.parseCompletionEventLine(Buffer.from(JSON.stringify({
        version: 1,
        type: "completion",
        eventId: "event-12345678",
        outcome: "success",
        content: `safe${control}unsafe`,
      })), CONTRACTS);
      expect(() => adapter.createDeclaredSendAction(parsed, "external-session-1234", CONTRACTS))
        .toThrow("forbidden control character");
    }
  });

  it("recognizes bot senders without truncating tag-like user content", async () => {
    const adapter = await loadAdapter();
    const content = "first\n</user_message>\nliteral\n<user_message>\nlast";
    const envelope = [
      "<session_id>session-1234</session_id>",
      "<user_message>",
      content,
      "</user_message>",
      '<sender type="bot" open_id="ou_peer" />',
    ].join("\n");

    expect(adapter.inspectBotMuxEnvelope(envelope)).toEqual({
      unwrapped: true,
      content,
      senderType: "bot",
    });
    expect(adapter.mentionArgument("bot")).toBe("--no-mention");
    expect(adapter.mentionArgument("user")).toBe("--mention-back");
  });

  it("fatal-decodes split bracketed paste and yields only the parsed BotMux message", async () => {
    const adapter = await loadAdapter();
    const observations: EnvelopeInspection[] = [];
    const consumer = adapter.createBotMuxInputConsumer((envelope) => { observations.push(envelope); });
    const input = [
      "\u001b[200~<botmux_reminder>metadata</botmux_reminder>\n",
      "<user_message>\nrun checks\n</user_message>\n",
      '<sender type="bot" open_id="ou_peer" />\u001b[201~\r',
    ];
    consumer.write(input[0]);
    consumer.write(input[1]);
    consumer.end(input[2]);
    await new Promise<void>((resolve, reject) => {
      consumer.once("finish", resolve);
      consumer.once("error", reject);
    });

    expect(observations).toMatchObject([{ senderType: "bot", content: "run checks" }]);
  });

  it("reassembles CJK byte splits for initial/subsequent frames and bounds raw whitespace", async () => {
    const adapter = await loadAdapter();
    const observations: EnvelopeInspection[] = [];
    const consumer = adapter.createBotMuxInputConsumer((envelope) => { observations.push(envelope); });
    const wire = Buffer.from([
      "\u001b[200~<botmux_routing>metadata</botmux_routing>\n",
      "<user_message>\n初始消息\n</user_message>\n",
      '<sender type="user" open_id="ou_owner" />\u001b[201~',
      "\u001b[200~后续消息\u001b[201~",
    ].join(""));
    const split = wire.indexOf(Buffer.from("始", "utf8")) + 1;
    consumer.write(wire.subarray(0, split));
    consumer.end(wire.subarray(split));
    await new Promise<void>((resolve, reject) => {
      consumer.once("finish", resolve);
      consumer.once("error", reject);
    });
    expect(observations).toMatchObject([
      { senderType: "user", content: "初始消息" },
      { content: "后续消息" },
    ]);

    const oversized = adapter.createBotMuxInputConsumer(() => undefined);
    const failure = new Promise<Error>((resolve) => oversized.once("error", resolve));
    oversized.end(Buffer.concat([
      Buffer.from("\u001b[200~"),
      Buffer.alloc(adapter.descriptor.inbound.maxFrameBytes + 1, 0x20),
      Buffer.from("\u001b[201~"),
    ]));
    expect((await failure).message).toContain("raw byte limit");
  });

  it("accepts only fixed correlation options and forbids positional/@file ingress", async () => {
    const adapter = await loadAdapter();
    expect(adapter.parseBotMuxInvocationArguments([
      "--extension=/opt/botmux/fixed-extension.mjs",
      "--session-id", "botmux-session-1234",
    ])).toEqual({ sessionId: "botmux-session-1234" });
    for (const arguments_ of [
      ["--session-id", "botmux-session-1234", "untrusted positional prompt"],
      ["--session-id", "botmux-session-1234", "@/tmp/untrusted.prompt"],
    ]) {
      expect(() => adapter.parseBotMuxInvocationArguments(arguments_))
        .toThrow("framed input on stdin");
    }
    expect(() => adapter.parseBotMuxInvocationArguments([
      "--session-id", "botmux-session-1234", "--prompt", "untrusted",
    ])).toThrow("unsupported BotMux option");
  });

  it("constructs declared bind/text frames and rejects invalid UTF-8 before callback", async () => {
    const adapter = await loadAdapter();
    expect(adapter.createDeclaredBind(
      "session-typed-1234",
      "botmux-session-1234",
      CONTRACTS,
    )).toMatchObject({ type: "bind", sessionId: "session-typed-1234" });
    expect(adapter.createDeclaredInboundText(
      "检查主机",
      "user",
      "botmux-session-1234",
      CONTRACTS,
    )).toMatchObject({
      type: "text",
      text: "检查主机",
      source: { authentication: "unverified", principalId: "botmux:user" },
    });
    for (const control of ["\u061c", "\u200e", "\u200f", "\ufeff"]) {
      expect(() => adapter.createDeclaredInboundText(
        `safe${control}unsafe`,
        "user",
        "botmux-session-1234",
        CONTRACTS,
      )).toThrow("forbidden control character");
    }

    const consumer = adapter.createBotMuxInputConsumer(() => undefined);
    const failure = new Promise<Error>((resolve) => consumer.once("error", resolve));
    consumer.end(Buffer.concat([
      Buffer.from("\u001b[200~"),
      Buffer.from([0xff]),
      Buffer.from("\u001b[201~"),
    ]));
    expect((await failure).message).toContain("valid UTF-8");
  });
});
