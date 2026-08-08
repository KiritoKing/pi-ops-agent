import { generateKeyPairSync, verify } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  approvalPayload,
  encodeChangeRef,
  parseChangeMetadata,
  parseChangeRef,
  signApprovalGrant,
} from "../src/shared/approval.js";
import { buildApprovalPlan } from "../src/shared/approval-review.js";
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
  it("accepts bounded standing and human authorization metadata without weakening strict fields", () => {
    const base = {
      serverId: "server-12345678",
      machineId: "machine-12345678",
      targetId: "target-local-system",
      policyRevision: "policy-local-v1",
      capabilityRevision: "capability-local-v1",
      planHash: `sha256:${"a".repeat(64)}`,
      kind: "service.action",
      backupRefs: [],
      verification: "active",
      rollbackAvailable: true,
      lastError: "",
      recoveryOnly: false,
    };
    expect(parseChangeMetadata({
      ...base,
      authorizationBasis: "standing-policy:policy-local-v1:service.action",
      authorizationScope: "service.action",
      authorizedAt: "2026-08-08T00:00:00Z",
    })).toMatchObject({ authorizationScope: "service.action" });
    expect(parseChangeMetadata({
      ...base,
      authorizationBasis: "approval-key:local-approver-v1",
      authorizedAt: "2026-08-08T00:00:00Z",
    })).toMatchObject({ authorizationBasis: "approval-key:local-approver-v1" });
    expect(() => parseChangeMetadata({
      ...base,
      authorizationScope: "service.action",
    })).toThrow(/authorizationBasis/u);
    expect(parseChangeMetadata({
      ...base,
      recoveryOnly: true,
      recoveryDescriptor: {
        version: 1,
        compatibilityVersion: "legacy-plan-v0.1-v0.2",
        originalKind: "service.action",
        originalTarget: "demo.service",
        originalAction: "service.restart",
        compensationTarget: "demo.service",
        compensationAction: "service.stop",
        rollbackDataDigest: `sha256:${"b".repeat(64)}`,
        backupObjects: [],
        rollbackCompatible: true,
      },
    })).toMatchObject({ recoveryOnly: true, kind: "service.action" });
    const { recoveryOnly: _recoveryOnly, ...withoutRecoveryMarker } = base;
    void _recoveryOnly;
    expect(() => parseChangeMetadata(withoutRecoveryMarker)).toThrow(/recoveryOnly/u);
    expect(() => parseChangeMetadata({
      ...base,
      recoveryOnly: true,
      plan: {},
    })).toThrow(/must not contain/u);
  });

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

  it("strictly binds PVE recovery parents, terminal evidence, and local unknown clearance", async () => {
    const parentChangeId = parseChangeId("pve-change-0123456789abcdef0123456789abcdef");
    const childOperation = {
      kind: "pve.guest.action" as const,
      pluginId: "workload.pve" as const,
      pluginDigest: `sha256:${"a".repeat(64)}`,
      recoveryOfChangeId: parentChangeId,
      node: "pve1",
      guestType: "qemu" as const,
      vmid: 100,
      action: "start" as const,
    };
    const childPlan = buildApprovalPlan({
      operation: childOperation,
      policyRevision: "policy-pve-12345678",
      capabilityRevision: "capability-pve-12345678",
      preconditionDigest: `sha256:${"b".repeat(64)}`,
      preconditionFields: [
        { name: "currentStatus", value: "stopped" },
        { name: "currentLock", value: "unlocked" },
      ],
    });
    const common = {
      serverId: "server-pve-12345678",
      machineId: "machine-pve-12345678",
      targetId: "target-pve-root",
      policyRevision: "policy-pve-12345678",
      capabilityRevision: "capability-pve-12345678",
      backupRefs: [],
      verification: "",
      rollbackAvailable: false,
      lastError: "",
      recoveryOnly: false,
      pveMutationVersion: 1,
    };
    expect(parseChangeMetadata({
      ...common,
      planHash: childPlan.planHash,
      kind: childOperation.kind,
      recoveryOfChangeId: parentChangeId,
      plan: childPlan,
    })).toMatchObject({ recoveryOfChangeId: parentChangeId, pveMutationVersion: 1 });

    const { recoveryOfChangeId: _parentReference, ...parentOperation } = childOperation;
    void _parentReference;
    const parentPlan = buildApprovalPlan({
      operation: parentOperation,
      policyRevision: common.policyRevision,
      capabilityRevision: common.capabilityRevision,
    });
    const terminalUPID = "UPID:pve1:00000001:00000002:00000003:qmstart:100:root@pam:";
    const resolved = {
      ...common,
      planHash: parentPlan.planHash,
      kind: parentOperation.kind,
      backupRefs: [`pve:task:${terminalUPID}`],
      mutationDisposition: "TASKS_TERMINAL",
      resolution: {
        kind: "pve.recovery-transfer/v1",
        childChangeId: parseChangeId("pve-change-fedcba9876543210fedcba9876543210"),
        childPlanHash: childPlan.planHash,
        transferredAt: "2026-08-08T00:00:00Z",
        parentMutationDisposition: "TASKS_TERMINAL",
        parentTaskEvidence: [{
          role: "primary",
          node: "pve1",
          upid: terminalUPID,
          status: "stopped",
          exitStatus: "OK",
          observedAt: "2026-08-08T00:00:00Z",
        }],
      },
      plan: parentPlan,
    };
    expect(parseChangeMetadata(resolved)).toMatchObject({
      mutationDisposition: "TASKS_TERMINAL",
      resolution: { parentTaskEvidence: [{ exitStatus: "OK" }] },
    });
    const localResolution = JSON.parse(await readFile(
      join(process.cwd(), "test/fixtures/pve-local-unknown-clearance-resolution.json"),
      "utf8",
    )) as Record<string, unknown>;
    const localResolved = {
      ...resolved,
      backupRefs: [],
      mutationDisposition: "STARTED_OR_UNKNOWN",
      resolution: localResolution,
    };
    expect(parseChangeMetadata(localResolved)).toMatchObject({
      mutationDisposition: "STARTED_OR_UNKNOWN",
      resolution: {
        basis: "local-unknown-clearance",
        parentChangeId,
        resourceKey: "pve/vmid/100",
      },
    });
    expect(() => parseChangeMetadata({
      ...localResolved,
      resolution: { ...localResolution, basis: "operator-said-safe" },
    })).toThrow(/unsupported basis/u);
    const { clusterStateDigest: _clusterStateDigest, ...missingClusterDigest } = localResolution;
    void _clusterStateDigest;
    expect(() => parseChangeMetadata({
      ...localResolved,
      resolution: missingClusterDigest,
    })).toThrow(/clusterStateDigest/u);
    expect(() => parseChangeMetadata({
      ...localResolved,
      resolution: { ...localResolution, trusted: true },
    })).toThrow(/not supported/u);
    expect(() => parseChangeMetadata({
      ...resolved,
      mutationDisposition: "STARTED_OR_UNKNOWN",
    })).toThrow(/does not bind/u);
    expect(() => parseChangeMetadata({
      ...resolved,
      backupRefs: [],
    })).toThrow(/absent from authoritative backupRefs/u);
    expect(() => parseChangeMetadata({
      ...common,
      kind: "service.action",
      planHash: `sha256:${"c".repeat(64)}`,
      mutationDisposition: "NO_MUTATION_STARTED",
    })).toThrow(/only a PVE change/u);
  });

  it("parses canonical Go Store recovery status fixtures with non-null empty evidence", async () => {
    for (const [filename, disposition, basis] of [
      ["pve-recovery-status-no-mutation.json", "NO_MUTATION_STARTED", undefined],
      ["pve-recovery-status-local-unknown.json", "STARTED_OR_UNKNOWN", "local-unknown-clearance"],
    ] as const) {
      const metadata = JSON.parse(await readFile(
        join(process.cwd(), "test/fixtures", filename),
        "utf8",
      )) as Record<string, unknown>;
      const parsed = parseChangeMetadata(metadata);
      expect(parsed.mutationDisposition).toBe(disposition);
      expect(parsed.resolution?.parentTaskEvidence).toEqual([]);
      expect(parsed.resolution?.basis).toBe(basis);
      const resolution = metadata.resolution as Record<string, unknown>;
      expect(() => parseChangeMetadata({
        ...metadata,
        resolution: { ...resolution, parentTaskEvidence: null },
      })).toThrow(/parent task evidence/u);
    }
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
      capabilityRevision: "capability-local-v1",
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
