import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  ADAPTER_INBOUND_API_VERSION,
  ADAPTER_OUTBOUND_ACTION_API_VERSION,
  ADAPTER_RUNNER_CONTROL_API_VERSION,
  ADAPTER_SESSION_CONTROL_API_VERSION,
  MAX_ADAPTER_CONTRACT_FRAME_BYTES,
  adapterDescriptorGrant,
  parseAdapterDescriptor,
  parseAdapterDescriptorJson,
  parseAdapterInbound,
  parseAdapterInboundJson,
  parseAdapterOutboundAction,
  parseAdapterOutboundActionJson,
  parseAdapterRunnerControlRequest,
  parseAdapterRunnerControlResponse,
  parseAdapterSessionControl,
  parseAdapterSessionControlJson,
  parseDeclaredAdapterInbound,
  parseDeclaredAdapterOutboundAction,
  parseDeclaredAdapterSessionControl,
  parseDeclaredAdapterToClientFrame,
} from "../src/shared/adapter-runtime.js";

const FIXTURE_ROOT = join(process.cwd(), "test/fixtures/adapter-contracts");

function fixture(name: string): string {
  return readFileSync(join(FIXTURE_ROOT, name), "utf8");
}

function loadProfile() {
  return parseAdapterDescriptorJson(
    readFileSync(join(process.cwd(), "plugins/adapter-tui/profile.json"), "utf8"),
  );
}

function action(type: "display" | "mark" | "quote" | "reply" | "send"): unknown {
  const base = {
    apiVersion: ADAPTER_OUTBOUND_ACTION_API_VERSION,
    schemaVersion: 1,
    type,
    actionId: `action:${type}:00000001`,
  };
  switch (type) {
    case "display":
      return { ...base, content: "Working...", level: "status" };
    case "mark":
      return {
        ...base,
        externalSessionId: "external-session-00000001",
        messageId: "message:00000001",
        mark: "resolved",
      };
    case "quote":
      return {
        ...base,
        externalSessionId: "external-session-00000001",
        quoteMessageId: "message:00000001",
        content: "Quoted response",
      };
    case "reply":
      return {
        ...base,
        externalSessionId: "external-session-00000001",
        replyToMessageId: "message:00000001",
        content: "Direct response",
      };
    case "send":
      return {
        ...base,
        externalSessionId: "external-session-00000001",
        content: "New message",
      };
  }
}

function control(type: "bind" | "clear-request" | "compact-request" | "handoff"): unknown {
  const base = {
    apiVersion: ADAPTER_SESSION_CONTROL_API_VERSION,
    schemaVersion: 1,
    type,
    controlId: `control:${type}:00000001`,
    externalSessionId: "external-session-00000001",
    sessionId: "agent-session-00000001",
  };
  if (type === "handoff") {
    return { ...base, fromWriterId: "writer:00000001", toWriterId: "writer:00000002" };
  }
  if (type === "bind") return base;
  return { ...base, reason: `${type} requested by the authenticated operator` };
}

describe("versioned Adapter behavioral contracts", () => {
  it("keeps the runner lease handoff fixed to one exact adapter.tui digest", () => {
    const request = {
      apiVersion: ADAPTER_RUNNER_CONTROL_API_VERSION,
      action: "release-tui-self-update-lease",
      pluginId: "adapter.tui",
      digest: `sha256:${"a".repeat(64)}`,
    };
    expect(parseAdapterRunnerControlRequest(request)).toEqual(request);
    expect(() => parseAdapterRunnerControlRequest({ ...request, pluginId: "adapter.botmux" }))
      .toThrow("fixed TUI self-update handoff");
    expect(() => parseAdapterRunnerControlRequest({ ...request, digest: `sha256:${"A".repeat(64)}` }))
      .toThrow("invalid format");
    expect(() => parseAdapterRunnerControlRequest({ ...request, hiddenAction: true }))
      .toThrow("not supported");
    expect(parseAdapterRunnerControlResponse({
      apiVersion: ADAPTER_RUNNER_CONTROL_API_VERSION,
      ok: true,
      state: "RELEASED",
    })).toMatchObject({ ok: true, state: "RELEASED" });
    expect(() => parseAdapterRunnerControlResponse({
      apiVersion: ADAPTER_RUNNER_CONTROL_API_VERSION,
      ok: true,
      state: "RELEASED",
      error: "ambiguous",
    })).toThrow("did not acknowledge");
  });

  it("accepts strict fixtures and every bounded tagged-union variant", () => {
    expect(parseAdapterInboundJson(fixture("inbound-text.json"))).toMatchObject({
      type: "text",
      source: { authentication: "authenticated" },
    });
    expect(parseAdapterOutboundActionJson(fixture("outbound-send.json")).type).toBe("send");
    expect(parseAdapterSessionControlJson(fixture("session-bind.json")).type).toBe("bind");

    for (const type of ["display", "mark", "quote", "reply", "send"] as const) {
      expect(parseAdapterOutboundAction(action(type)).type).toBe(type);
    }
    for (const type of ["bind", "clear-request", "compact-request", "handoff"] as const) {
      expect(parseAdapterSessionControl(control(type)).type).toBe(type);
    }
  });

  it("binds the real TUI manifest grant to only text, bind, and display", () => {
    const descriptor = loadProfile();
    const manifest = JSON.parse(
      readFileSync(join(process.cwd(), "plugins/adapter-tui/manifest.json"), "utf8"),
    ) as { capabilities: string[]; requestedScopes: string[] };
    expect(adapterDescriptorGrant(descriptor)).toEqual({
      capabilities: manifest.capabilities,
      requestedScopes: manifest.requestedScopes,
    });
    expect(descriptor.inbound.supportedTypes).toEqual(["text"]);
    expect(descriptor.session.supportedControls).toEqual(["bind"]);
    expect(descriptor.outbound.supportedActions).toEqual(["display"]);
    expect(descriptor.runtimeAuthority).toEqual({
      execution: "compiled-client",
      filesystem: "host-as-runtime-uid",
      network: "host",
      credentials: "runtime-uid-readable",
      actionScopeEnforcement: "digest-review-and-typed-ipc-contract",
    });
    expect(() => parseAdapterDescriptor({
      ...descriptor,
      runtimeAuthority: { ...descriptor.runtimeAuthority, execution: "source-process" },
    })).toThrow("only adapter.tui may use the compiled Client");
    expect(() => parseAdapterDescriptor({
      ...descriptor,
      runtimeAuthority: { ...descriptor.runtimeAuthority, hiddenAuthority: true },
    })).toThrow("not supported");
  });

  it("rejects unknown and duplicate fields at top-level and trusted-evidence boundaries", () => {
    const inbound = parseAdapterInboundJson(fixture("inbound-text.json"));
    expect(() => parseAdapterInbound({ ...inbound, injected: true })).toThrow("not supported");
    expect(() => parseAdapterInbound({
      ...inbound,
      source: {
        ...inbound.source,
        evidence: {
          ...(inbound.source.authentication === "authenticated" ? inbound.source.evidence : {}),
          injected: true,
        },
      },
    })).toThrow("not supported");
    expect(() => parseAdapterOutboundActionJson(
      '{"apiVersion":"agentd.adapter-outbound-action/v1","apiVersion":"agentd.adapter-outbound-action/v1"}',
    )).toThrow("duplicate field");
  });

  it("enforces UTF-8 and total frame bounds instead of JavaScript character counts", () => {
    const inbound = parseAdapterInboundJson(fixture("inbound-text.json"));
    expect(() => parseAdapterInbound({ ...inbound, text: "界".repeat(21_846) }))
      .toThrow("UTF-8 size limit");
    expect(() => parseAdapterOutboundAction({
      ...action("display") as object,
      content: "x".repeat(65_537),
    })).toThrow("length must be between");
    expect(() => parseAdapterInboundJson(" ".repeat(MAX_ADAPTER_CONTRACT_FRAME_BYTES + 1)))
      .toThrow("size limit");
  });

  it("rejects terminal escapes, hidden controls, and malformed source evidence", () => {
    const inbound = parseAdapterInboundJson(fixture("inbound-text.json"));
    for (const controlCharacter of [
      "\0", "\u001b", "\u0085", "\u061c", "\u200e", "\u200f", "\u202e", "\u2066", "\ufeff",
    ]) {
      expect(() => parseAdapterInbound({
        ...inbound,
        text: `safe${controlCharacter}unsafe`,
      })).toThrow("forbidden control character");
      expect(() => parseAdapterOutboundAction({
        ...(action("display") as object),
        content: `safe${controlCharacter}unsafe`,
      })).toThrow("forbidden control character");
      expect(() => parseAdapterSessionControl({
        ...(control("compact-request") as object),
        reason: `safe${controlCharacter}unsafe`,
      })).toThrow("forbidden control character");
    }
    expect(() => parseAdapterInbound({
      ...inbound,
      source: { authentication: "unverified", principalId: "principal:00000001\nforged" },
    })).toThrow();
    expect(() => parseAdapterInbound({
      ...inbound,
      source: { authentication: "authenticated", principalId: "principal:00000001" },
    })).toThrow("must be an object");
  });

  it("checks raw Adapter-to-Client NDJSON bytes before strict parsing and declaration", () => {
    const descriptor = loadProfile();
    const inbound = parseAdapterInboundJson(fixture("inbound-text.json"));
    const encoded = Buffer.from(JSON.stringify(inbound));
    expect(parseDeclaredAdapterToClientFrame(descriptor, encoded)).toEqual(inbound);
    expect(() => parseDeclaredAdapterToClientFrame(descriptor, Buffer.from([0xff])))
      .toThrow("valid UTF-8");
    expect(() => parseDeclaredAdapterToClientFrame(
      descriptor,
      Buffer.from(`${JSON.stringify(inbound)}{}`),
    )).toThrow("trailing value");
    expect(() => parseDeclaredAdapterToClientFrame(
      descriptor,
      Buffer.from(JSON.stringify({ ...inbound, text: "first", type: "text" })
        .replace('"type":"text"', '"type":"text","type":"text"')),
    )).toThrow("duplicate field");
    expect(() => parseDeclaredAdapterToClientFrame(
      descriptor,
      Buffer.concat([
        Buffer.alloc(descriptor.inbound.maxFrameBytes - encoded.length + 1, 0x20),
        encoded,
      ]),
    )).toThrow("raw inbound frame");
  });

  it("rejects valid but undeclared actions, controls, and inbound types", () => {
    const descriptor = loadProfile();
    expect(() => parseDeclaredAdapterOutboundAction(descriptor, action("send")))
      .toThrow("did not declare outbound action send");
    expect(() => parseDeclaredAdapterSessionControl(descriptor, control("handoff")))
      .toThrow("did not declare session control handoff");
    const noInbound = {
      ...descriptor,
      inbound: { ...descriptor.inbound, supportedTypes: [] },
    };
    expect(() => parseDeclaredAdapterInbound(
      noInbound,
      parseAdapterInboundJson(fixture("inbound-text.json")),
    )).toThrow("did not declare inbound type text");
  });

  it("enforces descriptor-specific canonical UTF-8 frame limits", () => {
    const descriptor = loadProfile();
    const inbound = {
      ...parseAdapterInboundJson(fixture("inbound-text.json")),
      text: "界".repeat(64),
    };
    const inboundBytes = Buffer.byteLength(JSON.stringify(inbound), "utf8");
    expect(parseDeclaredAdapterInbound({
      ...descriptor,
      inbound: { ...descriptor.inbound, maxFrameBytes: inboundBytes },
    }, inbound)).toEqual(inbound);
    expect(() => parseDeclaredAdapterInbound({
      ...descriptor,
      inbound: { ...descriptor.inbound, maxFrameBytes: inboundBytes - 1 },
    }, inbound)).toThrow(`descriptor maxFrameBytes ${inboundBytes - 1}`);

    const outbound = action("display");
    const outboundBytes = Buffer.byteLength(JSON.stringify(outbound), "utf8");
    expect(parseDeclaredAdapterOutboundAction({
      ...descriptor,
      outbound: { ...descriptor.outbound, maxFrameBytes: outboundBytes },
    }, outbound)).toEqual(outbound);
    expect(() => parseDeclaredAdapterOutboundAction({
      ...descriptor,
      outbound: { ...descriptor.outbound, maxFrameBytes: outboundBytes - 1 },
    }, outbound)).toThrow(`descriptor maxFrameBytes ${outboundBytes - 1}`);

    const sessionControl = control("bind");
    const sessionBytes = Buffer.byteLength(JSON.stringify(sessionControl), "utf8");
    expect(parseDeclaredAdapterSessionControl({
      ...descriptor,
      inbound: { ...descriptor.inbound, maxFrameBytes: sessionBytes },
    }, sessionControl)).toEqual(sessionControl);
    expect(() => parseDeclaredAdapterSessionControl({
      ...descriptor,
      inbound: { ...descriptor.inbound, maxFrameBytes: sessionBytes - 1 },
    }, sessionControl)).toThrow(`descriptor maxFrameBytes ${sessionBytes - 1}`);
  });

  it("keeps authenticated evidence as bounded metadata, not an approval intent", () => {
    const inbound = parseAdapterInboundJson(fixture("inbound-text.json"));
    expect(inbound.apiVersion).toBe(ADAPTER_INBOUND_API_VERSION);
    expect(inbound).not.toHaveProperty("approval");
    expect(inbound).not.toHaveProperty("changeRef");
    expect(inbound).not.toHaveProperty("planHash");
  });
});
