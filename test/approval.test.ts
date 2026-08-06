import { generateKeyPairSync, verify } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  approvalPayload,
  encodeChangeRef,
  parseChangeRef,
  signApprovalGrant,
} from "../src/shared/approval.js";
import {
  parseChangeId,
  parseMachineId,
  parseServerId,
  parseTargetId,
} from "../src/shared/domain.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, {
    recursive: true,
    force: true,
  })));
});

describe("remote approval grants", () => {
  it("round-trips opaque change references and rejects extra authority fields", () => {
    const changeRef = {
      version: 1 as const,
      serverId: parseServerId("server-12345678"),
      machineId: parseMachineId("machine-12345678"),
      targetId: parseTargetId("target-local-system"),
      changeId: parseChangeId("change-12345678"),
    };
    expect(parseChangeRef(encodeChangeRef(changeRef))).toEqual(changeRef);

    const encoded = Buffer.from(JSON.stringify({
      ...changeRef,
      privileged: true,
    })).toString("base64url");
    expect(() => parseChangeRef(`opschg1_${encoded}`)).toThrow(/not supported/u);
  });

  it("signs a plan- and policy-bound Ed25519 approval grant", async () => {
    const directory = await mkdtemp(join(tmpdir(), "ops-agent-approval-"));
    temporaryDirectories.push(directory);
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const keyPath = join(directory, "approval.key.pem");
    await writeFile(keyPath, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
    const grant = await signApprovalGrant({
      keyId: "operator-key-v1",
      privateKeyPath: keyPath,
      action: "approve",
      changeRef: {
        version: 1,
        serverId: parseServerId("server-12345678"),
        machineId: parseMachineId("machine-12345678"),
        targetId: parseTargetId("target-local-system"),
        changeId: parseChangeId("change-12345678"),
      },
      planHash: `sha256:${"a".repeat(64)}`,
      policyRevision: "policy-local-v1",
      now: new Date("2026-08-06T00:00:00.000Z"),
    });
    const { signature, ...unsigned } = grant;
    expect(grant.expiresAt).toBe("2026-08-06T00:02:00.000Z");
    expect(signature).not.toContain("=");
    expect(verify(
      null,
      approvalPayload(unsigned),
      publicKey,
      Buffer.from(signature, "base64"),
    )).toBe(true);
    expect(verify(
      null,
      approvalPayload({ ...unsigned, action: "rollback" }),
      publicKey,
      Buffer.from(signature, "base64"),
    )).toBe(false);
  });
});
