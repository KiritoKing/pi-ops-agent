import { requireInteger, requireRecord, requireString } from "./guards.js";
import { requireExactRecord } from "./strict.js";
import { parseStrictJson } from "./workload-runtime.js";
import { hasForbiddenTextControl } from "./terminal-safety.js";

export const ADAPTER_ABI_VERSION = "agentd.adapter/v1" as const;
export const ADAPTER_INBOUND_API_VERSION = "agentd.adapter-inbound/v1" as const;
export const ADAPTER_OUTBOUND_ACTION_API_VERSION = "agentd.adapter-outbound-action/v1" as const;
export const ADAPTER_SESSION_CONTROL_API_VERSION = "agentd.adapter-session-control/v1" as const;
export const ADAPTER_CLIENT_CONTEXT_API_VERSION = "agentd.adapter-client-context/v1" as const;
export const ADAPTER_RUNNER_CONTROL_API_VERSION = "agentd.adapter-runner-control/v1" as const;
export const ADAPTER_DESCRIBE_ARGUMENT = "--agentd-adapter-describe" as const;
export const ADAPTER_COMPLETION_FD = 3;
export const ADAPTER_INPUT_FD = 4;
export const ADAPTER_CONTEXT_FD = 5;
export const ADAPTER_RUNNER_CONTROL_REQUEST_FD = 6;
export const ADAPTER_RUNNER_CONTROL_RESPONSE_FD = 7;
export const MAX_ADAPTER_DESCRIPTOR_BYTES = 32 * 1024;
export const MAX_ADAPTER_CONTRACT_FRAME_BYTES = 128 * 1024;
export const MAX_ADAPTER_TEXT_BYTES = 64 * 1024;
export const MAX_ADAPTER_CLIENT_CONTEXT_BYTES = 64 * 1024;

const MAX_ADAPTER_IDENTIFIER_BYTES = 512;
const MAX_ADAPTER_REASON_BYTES = 4 * 1024;
const ADAPTER_ID_PATTERN = /^adapter\.[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?$/u;
const IDENTIFIER_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9._:@/-]{0,510}[A-Za-z0-9])?$/u;
const RFC3339_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/u;

export type AdapterApprovalMode = "local-tty" | "status-only";
export type AdapterInboundType = "text";
export type AdapterOutboundActionType = "display" | "mark" | "quote" | "reply" | "send";
export type AdapterSessionControlType =
  | "bind"
  | "clear-request"
  | "compact-request"
  | "handoff";

export interface AdapterDescriptor {
  apiVersion: typeof ADAPTER_ABI_VERSION;
  schemaVersion: 1;
  adapterId: string;
  runtimeAuthority: {
    execution: "compiled-client" | "source-process";
    filesystem: "host-as-runtime-uid";
    network: "host";
    credentials: "runtime-uid-readable";
    actionScopeEnforcement: "digest-review-and-typed-ipc-contract";
  };
  session: {
    mapping: "adapter-owned" | "local-terminal";
    writerLease: "gateway-global";
    controlApiVersion: typeof ADAPTER_SESSION_CONTROL_API_VERSION;
    supportedControls: readonly AdapterSessionControlType[];
  };
  inbound: {
    transport: "stdin" | "tty";
    framing: "adapter-defined" | "botmux-v1" | "terminal-text";
    contractApiVersion: typeof ADAPTER_INBOUND_API_VERSION;
    supportedTypes: readonly AdapterInboundType[];
    maxFrameBytes: number;
  };
  outbound: {
    transport: "completion-fd" | "stdout";
    framing: "ndjson" | "terminal-text";
    schema: "completion.v1" | "terminal.text/v1";
    actionApiVersion: typeof ADAPTER_OUTBOUND_ACTION_API_VERSION;
    supportedActions: readonly AdapterOutboundActionType[];
    maxFrameBytes: number;
  };
  approval: {
    mode: AdapterApprovalMode;
    identitySource: "none" | "os-user+tty+sudo-pam";
    replayProtection: "none" | "local-command";
  };
}

export interface AdapterClientContext {
  apiVersion: typeof ADAPTER_CLIENT_CONTEXT_API_VERSION;
  schemaVersion: 1;
  pluginId: string;
  digest: string;
  descriptor: AdapterDescriptor;
}

export interface AdapterRunnerControlRequest {
  apiVersion: typeof ADAPTER_RUNNER_CONTROL_API_VERSION;
  action: "release-tui-self-update-lease";
  pluginId: "adapter.tui";
  digest: string;
}

export interface AdapterRunnerControlResponse {
  apiVersion: typeof ADAPTER_RUNNER_CONTROL_API_VERSION;
  ok: boolean;
  state?: "RELEASED";
  error?: string;
}

export function parseAdapterRunnerControlRequest(value: unknown): AdapterRunnerControlRequest {
  const input = requireExactRecord(value, "Adapter runner control request", [
    "apiVersion", "action", "pluginId", "digest",
  ]);
  if (input.apiVersion !== ADAPTER_RUNNER_CONTROL_API_VERSION
    || input.action !== "release-tui-self-update-lease"
    || input.pluginId !== "adapter.tui") {
    throw new Error("Adapter runner control request is not the fixed TUI self-update handoff");
  }
  return {
    apiVersion: ADAPTER_RUNNER_CONTROL_API_VERSION,
    action: "release-tui-self-update-lease",
    pluginId: "adapter.tui",
    digest: requireString(input.digest, "Adapter runner control request.digest", {
      pattern: /^sha256:[a-f0-9]{64}$/u,
    }),
  };
}

export function parseAdapterRunnerControlResponse(value: unknown): AdapterRunnerControlResponse {
  const input = requireExactRecord(value, "Adapter runner control response", [
    "apiVersion", "ok", "state", "error",
  ]);
  if (input.apiVersion !== ADAPTER_RUNNER_CONTROL_API_VERSION || typeof input.ok !== "boolean") {
    throw new Error("Adapter runner control response has an unsupported version or status");
  }
  if (input.ok) {
    if (input.state !== "RELEASED" || input.error !== undefined) {
      throw new Error("Adapter runner did not acknowledge the TUI lease release");
    }
    return {
      apiVersion: ADAPTER_RUNNER_CONTROL_API_VERSION,
      ok: true,
      state: "RELEASED",
    };
  }
  if (input.state !== undefined) {
    throw new Error("failed Adapter runner control response included a release state");
  }
  return {
    apiVersion: ADAPTER_RUNNER_CONTROL_API_VERSION,
    ok: false,
    error: requireString(input.error, "Adapter runner control response.error", { max: 512 }),
  };
}

export interface AdapterAuthenticatedSourceEvidence {
  kind: "adapter-authentication" | "os-peer-credential";
  issuer: string;
  subject: string;
  evidenceId: string;
  observedAt: string;
}

export type AdapterInboundSource =
  | {
      authentication: "unverified";
      principalId: string;
      displayName?: string;
    }
  | {
      authentication: "authenticated";
      principalId: string;
      displayName?: string;
      evidence: AdapterAuthenticatedSourceEvidence;
    };

export interface AdapterInboundText {
  apiVersion: typeof ADAPTER_INBOUND_API_VERSION;
  schemaVersion: 1;
  type: "text";
  ingressId: string;
  externalSessionId: string;
  conversationType: "direct" | "group" | "terminal" | "thread";
  text: string;
  source: AdapterInboundSource;
  observedAt: string;
  replyToMessageId?: string;
}

export type AdapterInbound = AdapterInboundText;

interface AdapterOutboundBase {
  apiVersion: typeof ADAPTER_OUTBOUND_ACTION_API_VERSION;
  schemaVersion: 1;
  actionId: string;
}

export type AdapterOutboundAction =
  | AdapterOutboundBase & {
      type: "send";
      externalSessionId: string;
      content: string;
    }
  | AdapterOutboundBase & {
      type: "reply";
      externalSessionId: string;
      replyToMessageId: string;
      content: string;
    }
  | AdapterOutboundBase & {
      type: "quote";
      externalSessionId: string;
      quoteMessageId: string;
      content: string;
    }
  | AdapterOutboundBase & {
      type: "mark";
      externalSessionId: string;
      messageId: string;
      mark: "acknowledged" | "failed" | "resolved";
    }
  | AdapterOutboundBase & {
      type: "display";
      content: string;
      level: "error" | "info" | "status";
    };

interface AdapterSessionControlBase {
  apiVersion: typeof ADAPTER_SESSION_CONTROL_API_VERSION;
  schemaVersion: 1;
  controlId: string;
  externalSessionId: string;
  sessionId: string;
}

export type AdapterSessionControl =
  | AdapterSessionControlBase & { type: "bind" }
  | AdapterSessionControlBase & {
      type: "handoff";
      fromWriterId: string;
      toWriterId: string;
    }
  | AdapterSessionControlBase & {
      type: "compact-request";
      reason: string;
    }
  | AdapterSessionControlBase & {
      type: "clear-request";
      reason: string;
    };

export interface AdapterDescriptorGrant {
  capabilities: readonly string[];
  requestedScopes: readonly string[];
}

function requireEnum<Value extends string>(
  value: unknown,
  label: string,
  allowed: readonly Value[],
): Value {
  const parsed = requireString(value, label, { max: 96 });
  if (!allowed.includes(parsed as Value)) throw new Error(`${label} is not supported`);
  return parsed as Value;
}

function requireEnumArray<Value extends string>(
  value: unknown,
  label: string,
  allowed: readonly Value[],
): Value[] {
  if (!Array.isArray(value) || value.length > allowed.length) {
    throw new Error(`${label} must be a bounded array`);
  }
  const parsed = value.map((item, index) => requireEnum(item, `${label}[${index}]`, allowed));
  if (parsed.some((item, index) => index > 0 && (parsed[index - 1] ?? "") >= item)) {
    throw new Error(`${label} must be sorted and unique`);
  }
  return parsed;
}

function requireEncodedLimit(value: unknown, label: string, maximumBytes: number): void {
  let encoded: unknown;
  try {
    encoded = JSON.stringify(value);
  } catch {
    throw new Error(`${label} must be JSON serializable`);
  }
  if (typeof encoded !== "string" || Buffer.byteLength(encoded, "utf8") > maximumBytes) {
    throw new Error(`${label} exceeds its size limit`);
  }
}

function requireBoundedText(
  value: unknown,
  label: string,
  maximumBytes: number,
  options: { pattern?: RegExp; messageWhitespace?: boolean } = {},
): string {
  const parsed = requireString(value, label, {
    max: maximumBytes,
    ...(options.pattern === undefined ? {} : { pattern: options.pattern }),
  });
  if (Buffer.byteLength(parsed, "utf8") > maximumBytes) {
    throw new Error(`${label} exceeds its UTF-8 size limit`);
  }
  if (hasForbiddenTextControl(parsed, options.messageWhitespace ?? false)) {
    throw new Error(`${label} contains a forbidden control character`);
  }
  return parsed;
}

function requireIdentifier(value: unknown, label: string): string {
  return requireBoundedText(value, label, MAX_ADAPTER_IDENTIFIER_BYTES, {
    pattern: IDENTIFIER_PATTERN,
  });
}

function requireTimestamp(value: unknown, label: string): string {
  const parsed = requireBoundedText(value, label, 64, { pattern: RFC3339_PATTERN });
  if (!Number.isFinite(Date.parse(parsed))) throw new Error(`${label} is not a valid timestamp`);
  return parsed;
}

function optionalDisplayName(value: unknown, label: string): string | undefined {
  if (value === undefined) return undefined;
  return requireBoundedText(value, label, 512);
}

function parseInboundSource(value: unknown): AdapterInboundSource {
  const base = requireRecord(value, "adapter inbound.source");
  const authentication = requireEnum(
    base.authentication,
    "adapter inbound.source.authentication",
    ["authenticated", "unverified"] as const,
  );
  if (authentication === "unverified") {
    const input = requireExactRecord(base, "adapter inbound.source", [
      "authentication", "principalId", "displayName",
    ]);
    const displayName = optionalDisplayName(input.displayName, "adapter inbound.source.displayName");
    return {
      authentication: "unverified",
      principalId: requireIdentifier(input.principalId, "adapter inbound.source.principalId"),
      ...(displayName === undefined ? {} : { displayName }),
    };
  }
  const input = requireExactRecord(base, "adapter inbound.source", [
    "authentication", "principalId", "displayName", "evidence",
  ]);
  const evidence = requireExactRecord(input.evidence, "adapter inbound.source.evidence", [
    "kind", "issuer", "subject", "evidenceId", "observedAt",
  ]);
  const displayName = optionalDisplayName(input.displayName, "adapter inbound.source.displayName");
  return {
    authentication: "authenticated",
    principalId: requireIdentifier(input.principalId, "adapter inbound.source.principalId"),
    ...(displayName === undefined ? {} : { displayName }),
    evidence: {
      kind: requireEnum(evidence.kind, "adapter inbound.source.evidence.kind", [
        "adapter-authentication", "os-peer-credential",
      ] as const),
      issuer: requireIdentifier(evidence.issuer, "adapter inbound.source.evidence.issuer"),
      subject: requireIdentifier(evidence.subject, "adapter inbound.source.evidence.subject"),
      evidenceId: requireIdentifier(evidence.evidenceId, "adapter inbound.source.evidence.evidenceId"),
      observedAt: requireTimestamp(
        evidence.observedAt,
        "adapter inbound.source.evidence.observedAt",
      ),
    },
  };
}

function requireContractHeader(
  input: Record<string, unknown>,
  label: string,
  apiVersion: string,
): void {
  if (input.apiVersion !== apiVersion || input.schemaVersion !== 1) {
    throw new Error(`${label} has an unsupported API or schema version`);
  }
}

export function parseAdapterInbound(value: unknown): AdapterInbound {
  requireEncodedLimit(value, "adapter inbound", MAX_ADAPTER_CONTRACT_FRAME_BYTES);
  const input = requireExactRecord(value, "adapter inbound", [
    "apiVersion", "schemaVersion", "type", "ingressId", "externalSessionId",
    "conversationType", "text", "source", "observedAt", "replyToMessageId",
  ]);
  requireContractHeader(input, "adapter inbound", ADAPTER_INBOUND_API_VERSION);
  if (input.type !== "text") throw new Error("adapter inbound.type is not supported");
  const replyToMessageId = input.replyToMessageId === undefined
    ? undefined
    : requireIdentifier(input.replyToMessageId, "adapter inbound.replyToMessageId");
  return {
    apiVersion: ADAPTER_INBOUND_API_VERSION,
    schemaVersion: 1,
    type: "text",
    ingressId: requireIdentifier(input.ingressId, "adapter inbound.ingressId"),
    externalSessionId: requireIdentifier(
      input.externalSessionId,
      "adapter inbound.externalSessionId",
    ),
    conversationType: requireEnum(input.conversationType, "adapter inbound.conversationType", [
      "direct", "group", "terminal", "thread",
    ] as const),
    text: requireBoundedText(input.text, "adapter inbound.text", MAX_ADAPTER_TEXT_BYTES, {
      messageWhitespace: true,
    }),
    source: parseInboundSource(input.source),
    observedAt: requireTimestamp(input.observedAt, "adapter inbound.observedAt"),
    ...(replyToMessageId === undefined ? {} : { replyToMessageId }),
  };
}

export function parseAdapterInboundJson(text: string): AdapterInbound {
  return parseAdapterInbound(parseStrictJson(text, MAX_ADAPTER_CONTRACT_FRAME_BYTES));
}

function parseOutboundBase(
  input: Record<string, unknown>,
): Pick<AdapterOutboundBase, "apiVersion" | "schemaVersion" | "actionId"> {
  requireContractHeader(input, "adapter outbound action", ADAPTER_OUTBOUND_ACTION_API_VERSION);
  return {
    apiVersion: ADAPTER_OUTBOUND_ACTION_API_VERSION,
    schemaVersion: 1,
    actionId: requireIdentifier(input.actionId, "adapter outbound action.actionId"),
  };
}

export function parseAdapterOutboundAction(value: unknown): AdapterOutboundAction {
  requireEncodedLimit(value, "adapter outbound action", MAX_ADAPTER_CONTRACT_FRAME_BYTES);
  const base = requireRecord(value, "adapter outbound action");
  const type = requireEnum(base.type, "adapter outbound action.type", [
    "display", "mark", "quote", "reply", "send",
  ] as const);
  if (type === "display") {
    const input = requireExactRecord(base, "adapter outbound action", [
      "apiVersion", "schemaVersion", "type", "actionId", "content", "level",
    ]);
    return {
      ...parseOutboundBase(input),
      type,
      content: requireBoundedText(
        input.content,
        "adapter outbound action.content",
        MAX_ADAPTER_TEXT_BYTES,
        { messageWhitespace: true },
      ),
      level: requireEnum(input.level, "adapter outbound action.level", [
        "error", "info", "status",
      ] as const),
    };
  }
  if (type === "mark") {
    const input = requireExactRecord(base, "adapter outbound action", [
      "apiVersion", "schemaVersion", "type", "actionId", "externalSessionId",
      "messageId", "mark",
    ]);
    return {
      ...parseOutboundBase(input),
      type,
      externalSessionId: requireIdentifier(
        input.externalSessionId,
        "adapter outbound action.externalSessionId",
      ),
      messageId: requireIdentifier(input.messageId, "adapter outbound action.messageId"),
      mark: requireEnum(input.mark, "adapter outbound action.mark", [
        "acknowledged", "failed", "resolved",
      ] as const),
    };
  }
  const targetField = type === "reply" ? "replyToMessageId" : "quoteMessageId";
  const allowed = [
    "apiVersion", "schemaVersion", "type", "actionId", "externalSessionId", "content",
    ...(type === "send" ? [] : [targetField]),
  ];
  const input = requireExactRecord(base, "adapter outbound action", allowed);
  const common = {
    ...parseOutboundBase(input),
    externalSessionId: requireIdentifier(
      input.externalSessionId,
      "adapter outbound action.externalSessionId",
    ),
    content: requireBoundedText(
      input.content,
      "adapter outbound action.content",
      MAX_ADAPTER_TEXT_BYTES,
      { messageWhitespace: true },
    ),
  };
  if (type === "send") return { ...common, type };
  const target = requireIdentifier(input[targetField], `adapter outbound action.${targetField}`);
  return type === "reply"
    ? { ...common, type, replyToMessageId: target }
    : { ...common, type, quoteMessageId: target };
}

export function parseAdapterOutboundActionJson(text: string): AdapterOutboundAction {
  return parseAdapterOutboundAction(parseStrictJson(text, MAX_ADAPTER_CONTRACT_FRAME_BYTES));
}

function parseSessionControlBase(
  input: Record<string, unknown>,
): Omit<AdapterSessionControlBase, never> {
  requireContractHeader(input, "adapter session control", ADAPTER_SESSION_CONTROL_API_VERSION);
  return {
    apiVersion: ADAPTER_SESSION_CONTROL_API_VERSION,
    schemaVersion: 1,
    controlId: requireIdentifier(input.controlId, "adapter session control.controlId"),
    externalSessionId: requireIdentifier(
      input.externalSessionId,
      "adapter session control.externalSessionId",
    ),
    sessionId: requireIdentifier(input.sessionId, "adapter session control.sessionId"),
  };
}

export function parseAdapterSessionControl(value: unknown): AdapterSessionControl {
  requireEncodedLimit(value, "adapter session control", MAX_ADAPTER_CONTRACT_FRAME_BYTES);
  const base = requireRecord(value, "adapter session control");
  const type = requireEnum(base.type, "adapter session control.type", [
    "bind", "clear-request", "compact-request", "handoff",
  ] as const);
  const commonFields = [
    "apiVersion", "schemaVersion", "type", "controlId", "externalSessionId", "sessionId",
  ];
  if (type === "bind") {
    const input = requireExactRecord(base, "adapter session control", commonFields);
    return { ...parseSessionControlBase(input), type };
  }
  if (type === "handoff") {
    const input = requireExactRecord(base, "adapter session control", [
      ...commonFields, "fromWriterId", "toWriterId",
    ]);
    const fromWriterId = requireIdentifier(
      input.fromWriterId,
      "adapter session control.fromWriterId",
    );
    const toWriterId = requireIdentifier(input.toWriterId, "adapter session control.toWriterId");
    if (fromWriterId === toWriterId) {
      throw new Error("adapter session handoff requires different writer IDs");
    }
    return { ...parseSessionControlBase(input), type, fromWriterId, toWriterId };
  }
  const input = requireExactRecord(base, "adapter session control", [...commonFields, "reason"]);
  const reason = requireBoundedText(
    input.reason,
    "adapter session control.reason",
    MAX_ADAPTER_REASON_BYTES,
    { messageWhitespace: true },
  );
  return { ...parseSessionControlBase(input), type, reason };
}

export function parseAdapterSessionControlJson(text: string): AdapterSessionControl {
  return parseAdapterSessionControl(parseStrictJson(text, MAX_ADAPTER_CONTRACT_FRAME_BYTES));
}

export function parseAdapterDescriptor(value: unknown): AdapterDescriptor {
  requireEncodedLimit(value, "adapter descriptor", MAX_ADAPTER_DESCRIPTOR_BYTES);
  const input = requireExactRecord(value, "adapter descriptor", [
    "apiVersion", "schemaVersion", "adapterId", "runtimeAuthority", "session", "inbound",
    "outbound", "approval",
  ]);
  if (input.apiVersion !== ADAPTER_ABI_VERSION || input.schemaVersion !== 1) {
    throw new Error("adapter descriptor has an unsupported API or schema version");
  }
  const session = requireExactRecord(input.session, "adapter descriptor.session", [
    "mapping", "writerLease", "controlApiVersion", "supportedControls",
  ]);
  const runtimeAuthority = requireExactRecord(
    input.runtimeAuthority,
    "adapter descriptor.runtimeAuthority",
    ["execution", "filesystem", "network", "credentials", "actionScopeEnforcement"],
  );
  const inbound = requireExactRecord(input.inbound, "adapter descriptor.inbound", [
    "transport", "framing", "contractApiVersion", "supportedTypes", "maxFrameBytes",
  ]);
  const outbound = requireExactRecord(input.outbound, "adapter descriptor.outbound", [
    "transport", "framing", "schema", "actionApiVersion", "supportedActions", "maxFrameBytes",
  ]);
  const approval = requireExactRecord(input.approval, "adapter descriptor.approval", [
    "mode", "identitySource", "replayProtection",
  ]);
  if (session.controlApiVersion !== ADAPTER_SESSION_CONTROL_API_VERSION
    || inbound.contractApiVersion !== ADAPTER_INBOUND_API_VERSION
    || outbound.actionApiVersion !== ADAPTER_OUTBOUND_ACTION_API_VERSION) {
    throw new Error("adapter descriptor references an unsupported behavioral contract version");
  }
  const descriptor: AdapterDescriptor = {
    apiVersion: ADAPTER_ABI_VERSION,
    schemaVersion: 1,
    adapterId: requireString(input.adapterId, "adapter descriptor.adapterId", {
      max: 72,
      pattern: ADAPTER_ID_PATTERN,
    }),
    runtimeAuthority: {
      execution: requireEnum(
        runtimeAuthority.execution,
        "adapter descriptor.runtimeAuthority.execution",
        ["compiled-client", "source-process"],
      ),
      filesystem: requireEnum(
        runtimeAuthority.filesystem,
        "adapter descriptor.runtimeAuthority.filesystem",
        ["host-as-runtime-uid"],
      ),
      network: requireEnum(
        runtimeAuthority.network,
        "adapter descriptor.runtimeAuthority.network",
        ["host"],
      ),
      credentials: requireEnum(
        runtimeAuthority.credentials,
        "adapter descriptor.runtimeAuthority.credentials",
        ["runtime-uid-readable"],
      ),
      actionScopeEnforcement: requireEnum(
        runtimeAuthority.actionScopeEnforcement,
        "adapter descriptor.runtimeAuthority.actionScopeEnforcement",
        ["digest-review-and-typed-ipc-contract"],
      ),
    },
    session: {
      mapping: requireEnum(session.mapping, "adapter descriptor.session.mapping", [
        "adapter-owned", "local-terminal",
      ]),
      writerLease: requireEnum(
        session.writerLease,
        "adapter descriptor.session.writerLease",
        ["gateway-global"],
      ),
      controlApiVersion: ADAPTER_SESSION_CONTROL_API_VERSION,
      supportedControls: requireEnumArray(
        session.supportedControls,
        "adapter descriptor.session.supportedControls",
        ["bind", "clear-request", "compact-request", "handoff"],
      ),
    },
    inbound: {
      transport: requireEnum(inbound.transport, "adapter descriptor.inbound.transport", [
        "stdin", "tty",
      ]),
      framing: requireEnum(inbound.framing, "adapter descriptor.inbound.framing", [
        "adapter-defined", "botmux-v1", "terminal-text",
      ]),
      contractApiVersion: ADAPTER_INBOUND_API_VERSION,
      supportedTypes: requireEnumArray(
        inbound.supportedTypes,
        "adapter descriptor.inbound.supportedTypes",
        ["text"],
      ),
      maxFrameBytes: requireInteger(
        inbound.maxFrameBytes,
        "adapter descriptor.inbound.maxFrameBytes",
        1,
        MAX_ADAPTER_CONTRACT_FRAME_BYTES,
      ),
    },
    outbound: {
      transport: requireEnum(outbound.transport, "adapter descriptor.outbound.transport", [
        "completion-fd", "stdout",
      ]),
      framing: requireEnum(outbound.framing, "adapter descriptor.outbound.framing", [
        "ndjson", "terminal-text",
      ]),
      schema: requireEnum(outbound.schema, "adapter descriptor.outbound.schema", [
        "completion.v1", "terminal.text/v1",
      ]),
      actionApiVersion: ADAPTER_OUTBOUND_ACTION_API_VERSION,
      supportedActions: requireEnumArray(
        outbound.supportedActions,
        "adapter descriptor.outbound.supportedActions",
        ["display", "mark", "quote", "reply", "send"],
      ),
      maxFrameBytes: requireInteger(
        outbound.maxFrameBytes,
        "adapter descriptor.outbound.maxFrameBytes",
        1,
        MAX_ADAPTER_CONTRACT_FRAME_BYTES,
      ),
    },
    approval: {
      mode: requireEnum(approval.mode, "adapter descriptor.approval.mode", [
        "local-tty", "status-only",
      ]),
      identitySource: requireEnum(
        approval.identitySource,
        "adapter descriptor.approval.identitySource",
        ["none", "os-user+tty+sudo-pam"],
      ),
      replayProtection: requireEnum(
        approval.replayProtection,
        "adapter descriptor.approval.replayProtection",
        ["none", "local-command"],
      ),
    },
  };
  if ((descriptor.adapterId === "adapter.tui")
    !== (descriptor.runtimeAuthority.execution === "compiled-client")) {
    throw new Error(
      "only adapter.tui may use the compiled Client; executable adapters must declare source-process authority",
    );
  }
  if (descriptor.approval.mode === "local-tty") {
    if (descriptor.adapterId !== "adapter.tui"
      || descriptor.session.mapping !== "local-terminal"
      || descriptor.inbound.transport !== "tty"
      || descriptor.outbound.transport !== "stdout"
      || descriptor.approval.identitySource !== "os-user+tty+sudo-pam"
      || descriptor.approval.replayProtection !== "local-command") {
      throw new Error("only adapter.tui may declare the complete local TTY approval contract");
    }
  } else if (descriptor.approval.identitySource !== "none"
    || descriptor.approval.replayProtection !== "none") {
    throw new Error("status-only adapters must not claim an approval identity or replay authority");
  }
  return descriptor;
}

export function parseAdapterDescriptorJson(text: string): AdapterDescriptor {
  return parseAdapterDescriptor(parseStrictJson(text, MAX_ADAPTER_DESCRIPTOR_BYTES));
}

export function parseAdapterClientContext(value: unknown): AdapterClientContext {
  requireEncodedLimit(value, "adapter client context", MAX_ADAPTER_CLIENT_CONTEXT_BYTES);
  const input = requireExactRecord(value, "adapter client context", [
    "apiVersion", "schemaVersion", "pluginId", "digest", "descriptor",
  ]);
  if (input.apiVersion !== ADAPTER_CLIENT_CONTEXT_API_VERSION || input.schemaVersion !== 1) {
    throw new Error("adapter client context has an unsupported API or schema version");
  }
  const pluginId = requireBoundedText(input.pluginId, "adapter client context.pluginId", 72, {
    pattern: ADAPTER_ID_PATTERN,
  });
  const digest = requireBoundedText(input.digest, "adapter client context.digest", 71, {
    pattern: /^sha256:[a-f0-9]{64}$/u,
  });
  const descriptor = parseAdapterDescriptor(input.descriptor);
  if (descriptor.adapterId !== pluginId) {
    throw new Error("adapter client context descriptor identity does not match its plugin ID");
  }
  return {
    apiVersion: ADAPTER_CLIENT_CONTEXT_API_VERSION,
    schemaVersion: 1,
    pluginId,
    digest,
    descriptor,
  };
}

export function parseAdapterClientContextJson(text: string): AdapterClientContext {
  return parseAdapterClientContext(parseStrictJson(text, MAX_ADAPTER_CLIENT_CONTEXT_BYTES));
}

export type AdapterToClientFrame = AdapterInbound | AdapterSessionControl;

/**
 * Parse one raw NDJSON frame before any canonicalization. This is the
 * authoritative external Adapter -> compiled Client boundary.
 */
export function parseDeclaredAdapterToClientFrame(
  descriptor: AdapterDescriptor,
  rawFrame: Buffer,
): AdapterToClientFrame {
  if (rawFrame.length === 0 || rawFrame.length > descriptor.inbound.maxFrameBytes) {
    throw new Error(
      `adapter ${descriptor.adapterId} raw inbound frame exceeds descriptor maxFrameBytes ${descriptor.inbound.maxFrameBytes}`,
    );
  }
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(rawFrame);
  } catch {
    throw new Error(`adapter ${descriptor.adapterId} raw inbound frame is not valid UTF-8`);
  }
  const value = parseStrictJson(text, descriptor.inbound.maxFrameBytes);
  const input = requireRecord(value, "adapter-to-client frame");
  if (input.apiVersion === ADAPTER_INBOUND_API_VERSION) {
    return parseDeclaredAdapterInbound(descriptor, value);
  }
  if (input.apiVersion === ADAPTER_SESSION_CONTROL_API_VERSION) {
    return parseDeclaredAdapterSessionControl(descriptor, value);
  }
  throw new Error("adapter-to-client frame has an unsupported API version");
}

function adapterScopeNamespace(adapterId: string): string {
  return adapterId === "adapter.tui" ? "local" : adapterId.slice("adapter.".length);
}

export function adapterDescriptorGrant(descriptor: AdapterDescriptor): AdapterDescriptorGrant {
  const namespace = adapterScopeNamespace(descriptor.adapterId);
  const capabilities = [
    ...descriptor.inbound.supportedTypes.map((type) => `adapter.inbound.${type}`),
    ...descriptor.outbound.supportedActions.map((action) => `adapter.outbound.${action}`),
    ...descriptor.session.supportedControls.map((control) => `adapter.session.${control}`),
    descriptor.approval.mode === "local-tty" ? "approval.local" : "approval.status",
  ].sort();
  const requestedScopes = [
    ...capabilities
      .filter((capability) => capability.startsWith("adapter."))
      .map((capability) => `${capability}.${namespace}`),
    descriptor.approval.mode === "local-tty"
      ? "approval.submit.local"
      : "approval.status.remote",
  ].sort();
  return { capabilities, requestedScopes };
}

function requireDeclaredFrameLimit(
  value: AdapterInbound | AdapterOutboundAction | AdapterSessionControl,
  label: string,
  maximumBytes: number,
): void {
  const encoded = JSON.stringify(value);
  if (Buffer.byteLength(encoded, "utf8") > maximumBytes) {
    throw new Error(`${label} exceeds descriptor maxFrameBytes ${maximumBytes}`);
  }
}

export function parseDeclaredAdapterInbound(
  descriptor: AdapterDescriptor,
  value: unknown,
): AdapterInbound {
  const inbound = parseAdapterInbound(value);
  if (!descriptor.inbound.supportedTypes.includes(inbound.type)) {
    throw new Error(`adapter ${descriptor.adapterId} did not declare inbound type ${inbound.type}`);
  }
  requireDeclaredFrameLimit(
    inbound,
    `adapter ${descriptor.adapterId} inbound canonical frame`,
    descriptor.inbound.maxFrameBytes,
  );
  return inbound;
}

export function parseDeclaredAdapterOutboundAction(
  descriptor: AdapterDescriptor,
  value: unknown,
): AdapterOutboundAction {
  const action = parseAdapterOutboundAction(value);
  if (!descriptor.outbound.supportedActions.includes(action.type)) {
    throw new Error(`adapter ${descriptor.adapterId} did not declare outbound action ${action.type}`);
  }
  requireDeclaredFrameLimit(
    action,
    `adapter ${descriptor.adapterId} outbound canonical frame`,
    descriptor.outbound.maxFrameBytes,
  );
  return action;
}

export function parseDeclaredAdapterSessionControl(
  descriptor: AdapterDescriptor,
  value: unknown,
): AdapterSessionControl {
  const control = parseAdapterSessionControl(value);
  if (!descriptor.session.supportedControls.includes(control.type)) {
    throw new Error(`adapter ${descriptor.adapterId} did not declare session control ${control.type}`);
  }
  // Session controls travel from the Adapter toward Core, so the descriptor's
  // inbound frame ceiling is the applicable wire budget until a distinct
  // session-control transport is introduced.
  requireDeclaredFrameLimit(
    control,
    `adapter ${descriptor.adapterId} session-control canonical frame`,
    descriptor.inbound.maxFrameBytes,
  );
  return control;
}
