import { generateKeyPairSync, sign } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  brokerReceiptSigningPayload,
  canonicalBrokerResultDigest,
  parseBrokerReceipt,
  verifyBrokerResponse,
  type BrokerReceipt,
} from "../src/shared/broker-receipt.js";
import { parseChangeId } from "../src/shared/domain.js";
import type { RemoteResponse } from "../src/shared/server-protocol.js";

function signedStatus(): {
  response: RemoteResponse;
  publicKey: Buffer;
} {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const planHash = `sha256:${"a".repeat(64)}`;
  const response: RemoteResponse = {
    version: 1,
    requestId: "status-request-0001",
    ok: true,
    auditId: "audit-0123456789abcdef0123456789abcdef",
    changeId: parseChangeId("change-0123456789abcdef0123456789abcdef"),
    state: "COMMITTED",
    summary: "change committed",
    data: {
      planHash,
      plan: { version: 1, steps: ["one", "two"] },
      rollbackAvailable: true,
    },
  };
  const receipt: BrokerReceipt = {
    version: 1,
    keyId: "core-receipt-v1",
    domain: "core",
    requestId: response.requestId,
    method: "change.status",
    action: "status",
    serverId: "server-12345678",
    machineId: "machine-12345678",
    targetId: "target-12345678",
    changeId: response.changeId ?? "",
    planHash,
    state: response.state ?? "",
    auditId: response.auditId ?? "",
    resultDigest: canonicalBrokerResultDigest(response),
    issuedAt: "2026-08-08T10:00:00.123456Z",
    signature: "",
  };
  receipt.signature = sign(null, brokerReceiptSigningPayload(receipt), privateKey)
    .toString("base64").replace(/=+$/u, "");
  response.brokerReceipt = parseBrokerReceipt(receipt);
  return {
    response,
    publicKey: Buffer.from(publicKey.export({ type: "spki", format: "pem" })),
  };
}

function signedCommandInspection(): {
  response: RemoteResponse;
  publicKey: Buffer;
} {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const pluginDigest = `sha256:${"b".repeat(64)}`;
  const response: RemoteResponse = {
    version: 1,
    requestId: "command-inspect-0001",
    ok: true,
    auditId: "audit-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    data: {
      kind: "workload.command.inspect-result/v1",
      pluginId: "workload.example-command",
      pluginDigest,
      profileKey: "example.status",
      output: "ok\n",
    },
  };
  const receipt: BrokerReceipt = {
    version: 1,
    keyId: "core-receipt-v1",
    domain: "core",
    requestId: response.requestId,
    method: "workload.command.inspect",
    action: "inspect",
    serverId: "server-12345678",
    machineId: "machine-12345678",
    targetId: "target-12345678",
    changeId: "",
    planHash: "",
    state: "",
    pluginId: "workload.example-command",
    pluginDigest,
    profileKey: "example.status",
    auditId: response.auditId ?? "",
    resultDigest: canonicalBrokerResultDigest(response),
    issuedAt: "2026-08-08T10:20:00Z",
    signature: "",
  };
  receipt.signature = sign(null, brokerReceiptSigningPayload(receipt), privateKey)
    .toString("base64").replace(/=+$/u, "");
  response.brokerReceipt = parseBrokerReceipt(receipt);
  return {
    response,
    publicKey: Buffer.from(publicKey.export({ type: "spki", format: "pem" })),
  };
}

describe("broker receipt verification", () => {
  it("binds a relayed status to the pinned key, request, scope, plan and result", () => {
    const { response, publicKey } = signedStatus();
    const expected = {
      keyId: "core-receipt-v1",
      domain: "core" as const,
      requestId: "status-request-0001",
      method: "change.status" as const,
      serverId: "server-12345678",
      machineId: "machine-12345678",
      targetId: "target-12345678",
      changeId: "change-0123456789abcdef0123456789abcdef",
    };
    expect(() => verifyBrokerResponse(
      response,
      expected,
      publicKey,
      new Date("2026-08-08T10:00:01Z"),
    )).not.toThrow();

    expect(() => verifyBrokerResponse(
      { ...response, summary: "fabricated committed result" },
      expected,
      publicKey,
      new Date("2026-08-08T10:00:01Z"),
    )).toThrow("result digest");
    expect(() => verifyBrokerResponse(
      response,
      { ...expected, requestId: "status-request-0002" },
      publicKey,
      new Date("2026-08-08T10:00:01Z"),
    )).toThrow("request scope");
    expect(() => verifyBrokerResponse(
      { ...response, data: { ...(response.data as object), planHash: `sha256:${"b".repeat(64)}` } },
      expected,
      publicKey,
      new Date("2026-08-08T10:00:01Z"),
    )).toThrow("plan hash");
  });

  it("rejects ambiguous receipt shape and non-safe response numbers", () => {
    const { response } = signedStatus();
    expect(() => parseBrokerReceipt({ ...response.brokerReceipt, command: "sh" }))
      .toThrow("command is not supported");
    expect(() => canonicalBrokerResultDigest({
      ...response,
      data: { fraction: 1.5 },
    })).toThrow("safe integers");
  });

  it("binds a command inspection to the business plugin digest and semantic profile", () => {
    const { response, publicKey } = signedCommandInspection();
    const expected = {
      keyId: "core-receipt-v1",
      domain: "core" as const,
      requestId: "command-inspect-0001",
      method: "workload.command.inspect" as const,
      serverId: "server-12345678",
      machineId: "machine-12345678",
      targetId: "target-12345678",
      changeId: "",
      pluginId: "workload.example-command",
      pluginDigest: `sha256:${"b".repeat(64)}`,
      profileKey: "example.status",
    };
    expect(() => verifyBrokerResponse(
      response,
      expected,
      publicKey,
      new Date("2026-08-08T10:20:01Z"),
    )).not.toThrow();
    expect(() => verifyBrokerResponse(
      response,
      { ...expected, profileKey: "example.other" },
      publicKey,
      new Date("2026-08-08T10:20:01Z"),
    )).toThrow("request scope");
    expect(() => verifyBrokerResponse(
      { ...response, data: { output: "fabricated" } },
      expected,
      publicKey,
      new Date("2026-08-08T10:20:01Z"),
    )).toThrow("result digest");
    expect(() => parseBrokerReceipt({ ...response.brokerReceipt, pluginId: "workload.base" }))
      .toThrow("invalid digest-bound profile scope");
  });

  it("matches the Go canonical result vector", () => {
    expect(canonicalBrokerResultDigest({
      version: 1,
      requestId: "status-request-0001",
      ok: true,
      auditId: "audit-0123456789abcdef0123456789abcdef",
      changeId: parseChangeId("change-0123456789abcdef0123456789abcdef"),
      state: "COMMITTED",
      summary: "change committed",
      data: {
        plan: { version: 1, steps: ["one", "two"] },
        rollbackAvailable: true,
      },
    })).toBe("sha256:592c0d9bc3006a0d3c2238c1e5d3a7689a94404f47a36ccdc4a0ab42603a61e7");
  });
});
