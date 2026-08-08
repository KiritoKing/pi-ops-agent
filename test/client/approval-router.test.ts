import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { ServerRegistry } from "../../src/agentd/server-registry.js";
import { ApprovalRouter } from "../../src/client/approval-router.js";
import type { ApprovalIntentBinding } from "../../src/client/approval-intent.js";
import type { ApprovalSubmission } from "../../src/client/approval-submitter.js";
import { encodeChangeRef, type ChangeRef } from "../../src/shared/approval.js";
import {
  buildApprovalPlan,
  canonicalApprovalPlanHash,
  finalizeApprovalReview,
  type ApprovalPlan,
  type ApprovalReview,
  type ApprovalReviewRequest,
} from "../../src/shared/approval-review.js";
import {
  parseChangeId,
  parseMachineId,
  parseServerId,
  parseSessionId,
  parseTargetId,
  parseTurnId,
} from "../../src/shared/domain.js";
import { deterministicApprovalReview } from "../../src/reviewer/reviewer.js";
import type { ActiveSourcePlugin } from "../../src/shared/source-plugin.js";
import type { RootOperation } from "../../src/shared/messages.js";

const temporaryDirectories: string[] = [];

function sourcePlugin(pluginId: string, digest: string): ActiveSourcePlugin {
  return {
    apiVersion: "agentd.plugin-registration/v1",
    schemaVersion: 1,
    pluginId,
    kind: "workload",
    version: "0.3.0",
    publisher: "KiritoKing/pi-ops-agent",
    digest,
    capabilities: ["service.manage"],
    requestedScopes: ["service.manage.explicit"],
    approvedBy: "local-admin:1000",
    approvedAt: "2026-08-08T00:00:00Z",
  };
}

function intentBinding(
  changeRef: ChangeRef,
  userIntent = "restart demo after checking health",
): ApprovalIntentBinding {
  return {
    version: 1,
    sessionId: parseSessionId("session-approval-12345678"),
    turnId: parseTurnId("turn-approval-12345678"),
    changeRef,
    userIntent,
  };
}

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map(async (directory) =>
    await rm(directory, { recursive: true, force: true })));
});

describe("ApprovalRouter review boundary", () => {
  it("requires a stable independent review before delegating to the root-owned submitter", async () => {
    const directory = await mkdtemp(join(tmpdir(), "ops-approval-router-"));
    temporaryDirectories.push(directory);
    const serverId = parseServerId("server-12345678");
    const machineId = parseMachineId("machine-12345678");
    const targetId = parseTargetId("target-12345678");
    const changeId = parseChangeId("change-12345678");
    const registry = new ServerRegistry(join(directory, "servers.json"));
    await registry.initialize();
    await registry.register({
      serverId,
      machineId,
      baseUrl: "https://127.0.0.1:9443",
      caPath: "/unused/ca.pem",
      certPath: "/unused/agent.pem",
      keyPath: "/unused/agent.key",
      approverCertPath: "/unused/approver.pem",
      approverKeyPath: "/unused/approver.key",
      approvalSigningKeyPath: "/unused/approval.key",
      approvalKeyId: "approver-test-v1",
      enabled: true,
    });
    const plan = buildApprovalPlan({
      operation: {
        kind: "service.action",
        pluginId: "workload.base",
        pluginDigest: `sha256:${"d".repeat(64)}`,
        unit: "demo.service",
        action: "restart",
      },
      policyRevision: "policy-12345678",
      capabilityRevision: "capability-12345678",
    });
    const actions: ApprovalSubmission[] = [];
    const submitStarted = Promise.withResolvers<undefined>();
    const submitFinish = Promise.withResolvers<undefined>();
    let leaseHeld = false;
    const now = new Date("2026-08-08T00:00:00.000Z");
    const router = new ApprovalRouter(registry, {
      now: () => now,
      reviewer: { review: (request) => Promise.resolve(deterministicApprovalReview(request)) },
      submitter: {
        submit: async (request) => {
          actions.push(request);
          submitStarted.resolve(undefined);
          await submitFinish.promise;
          return {
            version: 1,
            requestId: "approval-submit-0001",
            ok: true,
            changeId,
            state: "COMMITTED",
          };
        },
      },
      clientFactory: () => Promise.resolve({
        changeStatus: (request) => Promise.resolve({
          version: 1,
          requestId: request.requestId,
          ok: true,
          changeId,
          state: "PENDING_APPROVAL",
          data: {
            serverId,
            machineId,
            targetId,
            policyRevision: plan.policyRevision,
            capabilityRevision: plan.capabilityRevision,
            planHash: plan.planHash,
            kind: "service.action",
            backupRefs: [],
            verification: "",
            rollbackAvailable: true,
            recoveryOnly: false,
            plan,
          },
        }),
      }),
      sourcePluginLoader: () => Promise.resolve(sourcePlugin(
        "workload.base",
        `sha256:${"d".repeat(64)}`,
      )),
      sourcePluginLease: (expected) => {
        leaseHeld = true;
        return Promise.resolve({
          registration: sourcePlugin(expected.pluginId, expected.digest),
          release: () => {
            leaseHeld = false;
            return Promise.resolve();
          },
        });
      },
    });
    const command = {
      kind: "approve" as const,
      changeRef: {
        version: 1 as const,
        serverId,
        machineId,
        targetId,
        changeId,
      },
    };
    expect(encodeChangeRef(command.changeRef)).toMatch(/^opschg1_/u);

    await expect(router.execute(command, { localConsole: true }))
      .rejects.toThrow("approval intent unavailable");
    await expect(router.execute(command, {
      intentBinding: intentBinding({
        ...command.changeRef,
        changeId: parseChangeId("change-other-12345678"),
      }),
      localConsole: true,
    })).rejects.toThrow("does not match the exact change reference");
    expect(actions).toHaveLength(0);

    const preview = await router.execute(command, {
      intentBinding: intentBinding(command.changeRef),
      localConsole: true,
    });
    expect(preview.state).toBe("REVIEW_REQUIRED");
    expect(actions).toHaveLength(0);

    const committing = router.execute(command, {
      intentBinding: intentBinding(command.changeRef),
      localConsole: true,
    });
    await submitStarted.promise;
    expect(leaseHeld).toBe(true);
    submitFinish.resolve(undefined);
    const committed = await committing;
    expect(committed.state).toBe("COMMITTED");
    expect(leaseHeld).toBe(false);
    expect(actions).toHaveLength(1);
    expect(actions[0]).toEqual({
      action: "approve",
      changeRef: command.changeRef,
      userIntent: "restart demo after checking health",
    });
  });

  it("rejects reviewer output bound to another request, intent, or plan step", async () => {
    const directory = await mkdtemp(join(tmpdir(), "ops-approval-router-"));
    temporaryDirectories.push(directory);
    const serverId = parseServerId("server-12345678");
    const machineId = parseMachineId("machine-12345678");
    const targetId = parseTargetId("target-12345678");
    const changeId = parseChangeId("change-review-binding-1234");
    const registry = new ServerRegistry(join(directory, "servers.json"));
    await registry.initialize();
    await registry.register({
      serverId,
      machineId,
      baseUrl: "https://127.0.0.1:9443",
      caPath: "/unused/ca.pem",
      certPath: "/unused/agent.pem",
      keyPath: "/unused/agent.key",
      approverCertPath: "/unused/approver.pem",
      approverKeyPath: "/unused/approver.key",
      approvalSigningKeyPath: "/unused/approval.key",
      approvalKeyId: "approver-test-v1",
      enabled: true,
    });
    const pluginDigest = `sha256:${"d".repeat(64)}`;
    const plan = buildApprovalPlan({
      operation: {
        kind: "service.action",
        pluginId: "workload.base",
        pluginDigest,
        unit: "demo.service",
        action: "restart",
      },
      policyRevision: "policy-12345678",
      capabilityRevision: "capability-12345678",
    });
    const command = {
      kind: "approve" as const,
      changeRef: { version: 1 as const, serverId, machineId, targetId, changeId },
    };
    let submissions = 0;
    for (const test of [
      { mode: "reviewId", message: "another review request" },
      { mode: "intent", message: "another user intent" },
      { mode: "stepId", message: "unknown canonical plan step" },
    ] as const) {
      const router = new ApprovalRouter(registry, {
        reviewer: {
          review: (request) => {
            const reviewed = deterministicApprovalReview(request);
            const { reviewDigest, ...unsigned } = reviewed;
            void reviewDigest;
            if (test.mode === "reviewId") {
              return Promise.resolve(finalizeApprovalReview({
                ...unsigned,
                reviewId: "review-attacker-12345678",
              }));
            }
            if (test.mode === "intent") {
              return Promise.resolve(finalizeApprovalReview({
                ...unsigned,
                userIntentDigest: `sha256:${"f".repeat(64)}`,
              }));
            }
            return Promise.resolve(finalizeApprovalReview({
              ...unsigned,
              risk: "high",
              findings: [...unsigned.findings, {
                code: "review.unknown-step",
                risk: "high",
                stepId: "step-attacker",
                summary: "attacker-controlled finding correlation",
              }],
            }));
          },
        },
        submitter: {
          submit: () => {
            submissions += 1;
            return Promise.resolve({ version: 1, requestId: "submit-review-binding", ok: true });
          },
        },
        clientFactory: () => Promise.resolve({
          changeStatus: (request) => Promise.resolve({
            version: 1,
            requestId: request.requestId,
            ok: true,
            changeId,
            state: "PENDING_APPROVAL",
            data: {
              serverId,
              machineId,
              targetId,
              policyRevision: plan.policyRevision,
              capabilityRevision: plan.capabilityRevision,
              planHash: plan.planHash,
              kind: "service.action",
              backupRefs: [],
              verification: "",
              rollbackAvailable: true,
              recoveryOnly: false,
              plan,
            },
          }),
        }),
        sourcePluginLoader: () => Promise.resolve(sourcePlugin("workload.base", pluginDigest)),
      });
      await expect(router.execute(command, {
        intentBinding: intentBinding(command.changeRef),
        localConsole: true,
      })).rejects.toThrow(test.message);
    }
    expect(submissions).toBe(0);
  });

  it("refuses reviewer reject and returns split-required as structured non-authorization", async () => {
    const directory = await mkdtemp(join(tmpdir(), "ops-approval-router-"));
    temporaryDirectories.push(directory);
    const serverId = parseServerId("server-12345678");
    const machineId = parseMachineId("machine-12345678");
    const targetId = parseTargetId("target-12345678");
    const changeId = parseChangeId("change-12345678");
    const registry = new ServerRegistry(join(directory, "servers.json"));
    await registry.initialize();
    await registry.register({
      serverId,
      machineId,
      baseUrl: "https://127.0.0.1:9443",
      caPath: "/unused/ca.pem",
      certPath: "/unused/agent.pem",
      keyPath: "/unused/agent.key",
      approverCertPath: "/unused/approver.pem",
      approverKeyPath: "/unused/approver.key",
      approvalSigningKeyPath: "/unused/approval.key",
      approvalKeyId: "approver-test-v1",
      enabled: true,
    });
    const plan = buildApprovalPlan({
      operation: {
        kind: "service.action",
        pluginId: "workload.base",
        pluginDigest: `sha256:${"d".repeat(64)}`,
        unit: "demo.service",
        action: "restart",
      },
      policyRevision: "policy-12345678",
      capabilityRevision: "capability-12345678",
    });
    const command = {
      kind: "approve" as const,
      changeRef: { version: 1 as const, serverId, machineId, targetId, changeId },
    };
    let submissions = 0;

    for (const recommendation of ["reject", "split-required"] as const) {
      const router = new ApprovalRouter(registry, {
        reviewer: {
          review: (request: ApprovalReviewRequest) => {
            const reviewed = deterministicApprovalReview(request);
            const { reviewDigest, ...unsigned } = reviewed;
            void reviewDigest;
            return Promise.resolve(finalizeApprovalReview({ ...unsigned, recommendation }));
          },
        },
        submitter: {
          submit: () => {
            submissions += 1;
            return Promise.resolve({ version: 1, requestId: "submit-12345678", ok: true });
          },
        },
        clientFactory: () => Promise.resolve({
          changeStatus: (request) => Promise.resolve({
            version: 1,
            requestId: request.requestId,
            ok: true,
            changeId,
            state: "PENDING_APPROVAL",
            data: {
              serverId,
              machineId,
              targetId,
              policyRevision: plan.policyRevision,
              capabilityRevision: plan.capabilityRevision,
              planHash: plan.planHash,
              kind: "service.action",
              backupRefs: [],
              verification: "",
              rollbackAvailable: true,
              recoveryOnly: false,
              plan,
            },
          }),
        }),
        sourcePluginLoader: () => Promise.resolve(sourcePlugin(
          "workload.base",
          `sha256:${"d".repeat(64)}`,
        )),
      });
      const context = {
        intentBinding: intentBinding(command.changeRef),
        localConsole: true,
      };
      if (recommendation === "reject") {
        await expect(router.execute(command, context)).rejects.toThrow("rejected");
      } else {
        const first = await router.execute(command, context);
        expect(first).toMatchObject({
          ok: true,
          changeId,
          state: "SPLIT_REQUIRED",
          data: {
            recommendation: "split-required",
            canAuthorize: false,
            planHash: plan.planHash,
          },
        });
        expect(first.summary).toContain("No approval was submitted");
        expect((first.data as ApprovalReview).findings).toEqual(expect.any(Array));
        expect((first.data as ApprovalReview).reviewDigest).toMatch(/^sha256:[a-f0-9]{64}$/u);

        const repeated = await router.execute(command, context);
        expect(repeated).toMatchObject({
          ok: true,
          state: "SPLIT_REQUIRED",
          data: { recommendation: "split-required", canAuthorize: false },
        });
        expect(submissions).toBe(0);
      }
    }
    expect(submissions).toBe(0);
  });

  it("revalidates a custom PVE source digest before review and again before submit", async () => {
    const directory = await mkdtemp(join(tmpdir(), "ops-approval-router-"));
    temporaryDirectories.push(directory);
    const serverId = parseServerId("server-12345678");
    const machineId = parseMachineId("machine-12345678");
    const targetId = parseTargetId("target-12345678");
    const changeId = parseChangeId("change-12345678");
    const pluginDigest = `sha256:${"a".repeat(64)}`;
    const registry = new ServerRegistry(join(directory, "servers.json"));
    await registry.initialize();
    await registry.register({
      serverId,
      machineId,
      baseUrl: "https://127.0.0.1:9443",
      caPath: "/unused/ca.pem",
      certPath: "/unused/agent.pem",
      keyPath: "/unused/agent.key",
      approverCertPath: "/unused/approver.pem",
      approverKeyPath: "/unused/approver.key",
      approvalSigningKeyPath: "/unused/approval.key",
      approvalKeyId: "approver-test-v1",
      enabled: true,
    });
    const plan = buildApprovalPlan({
      operation: {
        kind: "pve.snapshot.rollback",
        pluginId: "workload.example-pve",
        pluginDigest,
        node: "pve1",
        guestType: "qemu",
        vmid: 100,
        snapshot: "before-upgrade",
        backupStorage: "backup-store",
      },
      policyRevision: "policy-12345678",
      capabilityRevision: "capability-12345678",
    });
    const plugin = (digest: string): ActiveSourcePlugin => ({
      apiVersion: "agentd.plugin-registration/v1",
      schemaVersion: 1,
      pluginId: "workload.example-pve",
      kind: "workload",
      version: "0.3.0",
      publisher: "KiritoKing/pi-ops-agent",
      digest,
      capabilities: ["example.pve.snapshot"],
      requestedScopes: ["pve.snapshot.manage"],
      approvedBy: "local-admin:1000",
      approvedAt: "2026-08-08T00:00:00Z",
    });
    const currentSequence: ActiveSourcePlugin[] = [];
    const leaseSequence: ActiveSourcePlugin[] = [];
    let submissions = 0;
    const router = new ApprovalRouter(registry, {
      reviewer: { review: (request) => Promise.resolve(deterministicApprovalReview(request)) },
      sourcePluginLoader: () => {
        const current = currentSequence.shift();
        if (current === undefined) throw new Error("custom PVE workload is inactive");
        return Promise.resolve(current);
      },
      sourcePluginLease: () => {
        const current = leaseSequence.shift();
        if (current === undefined) throw new Error("custom PVE workload lease unavailable");
        return Promise.resolve({
          registration: current,
          release: async () => await Promise.resolve(),
        });
      },
      submitter: {
        submit: () => {
          submissions += 1;
          return Promise.resolve({ version: 1, requestId: "submit-12345678", ok: true });
        },
      },
      clientFactory: () => Promise.resolve({
        changeStatus: (request) => Promise.resolve({
          version: 1,
          requestId: request.requestId,
          ok: true,
          changeId,
          state: "PENDING_APPROVAL",
          data: {
            serverId,
            machineId,
            targetId,
            policyRevision: plan.policyRevision,
            capabilityRevision: plan.capabilityRevision,
            planHash: plan.planHash,
            kind: "pve.snapshot.rollback",
            backupRefs: [],
            verification: "",
            rollbackAvailable: true,
            recoveryOnly: false,
            plan,
          },
        }),
      }),
    });
    const command = {
      kind: "approve" as const,
      changeRef: { version: 1 as const, serverId, machineId, targetId, changeId },
    };

    currentSequence.push(plugin(pluginDigest));
    const context = { intentBinding: intentBinding(command.changeRef), localConsole: true };
    expect((await router.execute(command, context)).state).toBe("REVIEW_REQUIRED");

    currentSequence.push(plugin(`sha256:${"b".repeat(64)}`));
    await expect(router.execute(command, context))
      .rejects.toThrow("no longer matches");
    expect(submissions).toBe(0);

    currentSequence.push(plugin(pluginDigest));
    leaseSequence.push(plugin(`sha256:${"b".repeat(64)}`));
    await expect(router.execute(command, context))
      .rejects.toThrow("no longer matches");
    expect(submissions).toBe(0);

    currentSequence.push(plugin(pluginDigest));
    expect((await router.execute(command, context)).state).toBe("REVIEW_REQUIRED");

    currentSequence.push(plugin(pluginDigest));
    leaseSequence.push(plugin(pluginDigest));
    await expect(router.execute(command, context))
      .resolves.toMatchObject({ ok: true });
    expect(submissions).toBe(1);

    const malformedUnsigned = {
      ...plan,
      steps: plan.steps.map((step, index) => index === 0
        ? {
            ...step,
            fields: step.fields.map((field) => field.name === "storage"
              ? { ...field, value: "different-store" }
              : field),
          }
        : step),
    };
    const malformedPlan = {
      ...malformedUnsigned,
      planHash: canonicalApprovalPlanHash(malformedUnsigned),
    };
    const malformedRouter = new ApprovalRouter(registry, {
      reviewer: { review: (request) => Promise.resolve(deterministicApprovalReview(request)) },
      sourcePluginLoader: () => Promise.resolve(plugin(pluginDigest)),
      submitter: {
        submit: () => {
          submissions += 1;
          return Promise.resolve({ version: 1, requestId: "submit-12345678", ok: true });
        },
      },
      clientFactory: () => Promise.resolve({
        changeStatus: (request) => Promise.resolve({
          version: 1,
          requestId: request.requestId,
          ok: true,
          changeId,
          state: "PENDING_APPROVAL",
          data: {
            serverId,
            machineId,
            targetId,
            policyRevision: malformedPlan.policyRevision,
            capabilityRevision: malformedPlan.capabilityRevision,
            planHash: malformedPlan.planHash,
            kind: "pve.snapshot.rollback",
            backupRefs: [],
            verification: "",
            rollbackAvailable: true,
            recoveryOnly: false,
            plan: malformedPlan,
          },
        }),
      }),
    });
    await expect(malformedRouter.execute(command, context))
      .rejects.toThrow("invalid safety-backup sequence");
    expect(submissions).toBe(1);
  });

  it("rejects old base and arbitrary source-workload plans after their current digest changes", async () => {
    const directory = await mkdtemp(join(tmpdir(), "ops-approval-router-"));
    temporaryDirectories.push(directory);
    const serverId = parseServerId("server-12345678");
    const machineId = parseMachineId("machine-12345678");
    const targetId = parseTargetId("target-12345678");
    const changeId = parseChangeId("change-12345678");
    const registry = new ServerRegistry(join(directory, "servers.json"));
    await registry.initialize();
    await registry.register({
      serverId,
      machineId,
      baseUrl: "https://127.0.0.1:9443",
      caPath: "/unused/ca.pem",
      certPath: "/unused/agent.pem",
      keyPath: "/unused/agent.key",
      approverCertPath: "/unused/approver.pem",
      approverKeyPath: "/unused/approver.key",
      approvalSigningKeyPath: "/unused/approval.key",
      approvalKeyId: "approver-test-v1",
      enabled: true,
    });
    const digestA = `sha256:${"a".repeat(64)}`;
    const digestB = `sha256:${"b".repeat(64)}`;
    const operations: RootOperation[] = [
      {
        kind: "service.action",
        pluginId: "workload.base",
        pluginDigest: digestA,
        unit: "demo.service",
        action: "restart",
      },
      {
        kind: "workload.service.action",
        pluginId: "workload.example-service",
        pluginDigest: digestA,
        account: "example",
        manager: "user",
        unit: "example.service",
        action: "restart",
      },
      {
        kind: "workload.service.action",
        pluginId: "workload.other-service",
        pluginDigest: digestA,
        account: "other",
        manager: "user",
        unit: "other.service",
        action: "restart",
      },
    ];
    const command = {
      kind: "approve" as const,
      changeRef: { version: 1 as const, serverId, machineId, targetId, changeId },
    };
    const context = { intentBinding: intentBinding(command.changeRef), localConsole: true };

    for (const operation of operations) {
      const plan = buildApprovalPlan({
        operation,
        policyRevision: "policy-12345678",
        capabilityRevision: "capability-12345678",
      });
      let currentDigest = digestA;
      let submissions = 0;
      const router = new ApprovalRouter(registry, {
        reviewer: { review: (request) => Promise.resolve(deterministicApprovalReview(request)) },
        sourcePluginLoader: (pluginId) => Promise.resolve(sourcePlugin(pluginId, currentDigest)),
        sourcePluginLease: () => {
          throw new Error("stale pending plan unexpectedly reached its submit lease");
        },
        submitter: {
          submit: () => {
            submissions += 1;
            return Promise.resolve({ version: 1, requestId: "submit-12345678", ok: true });
          },
        },
        clientFactory: () => Promise.resolve({
          changeStatus: (request) => Promise.resolve({
            version: 1,
            requestId: request.requestId,
            ok: true,
            changeId,
            state: "PENDING_APPROVAL",
            data: {
              serverId,
              machineId,
              targetId,
              policyRevision: plan.policyRevision,
              capabilityRevision: plan.capabilityRevision,
              planHash: plan.planHash,
              kind: operation.kind,
              backupRefs: [],
              verification: "",
              rollbackAvailable: true,
              recoveryOnly: false,
              plan,
            },
          }),
        }),
      });
      await expect(router.execute(command, context)).resolves.toMatchObject({
        state: "REVIEW_REQUIRED",
      });
      currentDigest = digestB;
      await expect(router.execute(command, context)).rejects.toThrow("no longer matches");
      expect(submissions).toBe(0);
    }
  });

  it("pins JSON config approval to current source digest, local confirmation, and its submit lease", async () => {
    const directory = await mkdtemp(join(tmpdir(), "ops-approval-router-"));
    temporaryDirectories.push(directory);
    const serverId = parseServerId("server-12345678");
    const machineId = parseMachineId("machine-12345678");
    const targetId = parseTargetId("target-12345678");
    const changeId = parseChangeId("change-json-config-12345678");
    const registry = new ServerRegistry(join(directory, "servers.json"));
    await registry.initialize();
    await registry.register({
      serverId,
      machineId,
      baseUrl: "https://127.0.0.1:9443",
      caPath: "/unused/ca.pem",
      certPath: "/unused/agent.pem",
      keyPath: "/unused/agent.key",
      approverCertPath: "/unused/approver.pem",
      approverKeyPath: "/unused/approver.key",
      approvalSigningKeyPath: "/unused/approval.key",
      approvalKeyId: "approver-test-v1",
      enabled: true,
    });
    const digestA = `sha256:${"a".repeat(64)}`;
    const digestB = `sha256:${"b".repeat(64)}`;
    const preconditionFields = [
      { name: "targetAccount", value: "botmux" },
      { name: "accountUid", value: "1000" },
      { name: "configPath", value: "/home/botmux/.botmux/bots.json" },
      { name: "profileKey", value: "botmux.bots" },
      { name: "selectorKey", value: "name" },
      { name: "selectorValue", value: "ops-agent" },
      { name: "fieldKey", value: "model" },
      { name: "jsonField", value: "model" },
      { name: "beforeKind", value: "string" },
      { name: "before", value: "openai/gpt-4.1" },
      { name: "afterKind", value: "string" },
      { name: "after", value: "openai/gpt-5" },
      { name: "configDigest", value: `sha256:${"c".repeat(64)}` },
      { name: "configIdentity", value: "dev=1;ino=2;mode=0600;bytes=128" },
      { name: "documentRewrite", value: "whole-document-semantic-rewrite" },
      {
        name: "sameUidRaceBoundary",
        value: "digest-cas-detects-but-cannot-prevent-later-same-uid-replacement",
      },
    ];
    const plan = buildApprovalPlan({
      operation: {
        kind: "workload.json-config.edit",
        pluginId: "workload.botmux-ops",
        sourceDigest: digestA,
        profileKey: "botmux.bots",
        selectorValue: "ops-agent",
        fieldKey: "model",
        value: { kind: "string", stringValue: "openai/gpt-5" },
      },
      policyRevision: "policy-json-config-v1",
      capabilityRevision: "capability-remote-v0.3-v8",
      preconditionDigest: `sha256:${"d".repeat(64)}`,
      preconditionFields,
    });
    let currentDigest = digestB;
    let leaseHeld = false;
    let submissions = 0;
    const submitStarted = Promise.withResolvers<undefined>();
    const submitFinish = Promise.withResolvers<undefined>();
    const tryRegisterUpdate = (): boolean => {
      if (leaseHeld) return false;
      currentDigest = digestB;
      return true;
    };
    const router = new ApprovalRouter(registry, {
      reviewer: { review: (request) => Promise.resolve(deterministicApprovalReview(request)) },
      sourcePluginLoader: (pluginId) => Promise.resolve(sourcePlugin(pluginId, currentDigest)),
      sourcePluginLease: (expected) => {
        expect(expected).toEqual({ pluginId: "workload.botmux-ops", digest: digestA });
        leaseHeld = true;
        return Promise.resolve({
          registration: sourcePlugin(expected.pluginId, expected.digest),
          release: () => {
            leaseHeld = false;
            return Promise.resolve();
          },
        });
      },
      submitter: {
        submit: async () => {
          submissions += 1;
          expect(tryRegisterUpdate()).toBe(false);
          submitStarted.resolve(undefined);
          await submitFinish.promise;
          return { version: 1, requestId: "submit-json-config", ok: true };
        },
      },
      clientFactory: () => Promise.resolve({
        changeStatus: (request) => Promise.resolve({
          version: 1,
          requestId: request.requestId,
          ok: true,
          changeId,
          state: "PENDING_APPROVAL",
          data: {
            serverId,
            machineId,
            targetId,
            policyRevision: plan.policyRevision,
            capabilityRevision: plan.capabilityRevision,
            planHash: plan.planHash,
            kind: "workload.json-config.edit",
            backupRefs: [],
            verification: "",
            rollbackAvailable: true,
            recoveryOnly: false,
            plan,
          },
        }),
      }),
    });
    const command = {
      kind: "approve" as const,
      changeRef: { version: 1 as const, serverId, machineId, targetId, changeId },
    };
    const intent = { intentBinding: intentBinding(command.changeRef), localConsole: true };

    await expect(router.execute(command, intent)).rejects.toThrow("no longer matches");
    currentDigest = digestA;
    await expect(router.execute(command, intent)).resolves.toMatchObject({ state: "REVIEW_REQUIRED" });
    await expect(router.execute(command, { ...intent, localConsole: false }))
      .rejects.toThrow("local interactive console");

    const approving = router.execute(command, intent);
    await submitStarted.promise;
    expect(leaseHeld).toBe(true);
    expect(currentDigest).toBe(digestA);
    submitFinish.resolve(undefined);
    await expect(approving).resolves.toMatchObject({ ok: true });
    expect(leaseHeld).toBe(false);
    expect(submissions).toBe(1);
    expect(tryRegisterUpdate()).toBe(true);
  });

  it("rejects a JSON config plan whose tagged request disagrees with root preconditions", async () => {
    const directory = await mkdtemp(join(tmpdir(), "ops-approval-router-"));
    temporaryDirectories.push(directory);
    const serverId = parseServerId("server-12345678");
    const machineId = parseMachineId("machine-12345678");
    const targetId = parseTargetId("target-12345678");
    const changeId = parseChangeId("change-json-config-bad-1234");
    const registry = new ServerRegistry(join(directory, "servers.json"));
    await registry.initialize();
    await registry.register({
      serverId,
      machineId,
      baseUrl: "https://127.0.0.1:9443",
      caPath: "/unused/ca.pem",
      certPath: "/unused/agent.pem",
      keyPath: "/unused/agent.key",
      approverCertPath: "/unused/approver.pem",
      approverKeyPath: "/unused/approver.key",
      approvalSigningKeyPath: "/unused/approval.key",
      approvalKeyId: "approver-test-v1",
      enabled: true,
    });
    const digest = `sha256:${"a".repeat(64)}`;
    const valid = buildApprovalPlan({
      operation: {
        kind: "workload.json-config.edit",
        pluginId: "workload.botmux-ops",
        sourceDigest: digest,
        profileKey: "botmux.bots",
        selectorValue: "ops-agent",
        fieldKey: "showInTeam",
        value: { kind: "boolean", booleanValue: true },
      },
      policyRevision: "policy-json-config-v1",
      capabilityRevision: "capability-remote-v0.3-v8",
      preconditionDigest: `sha256:${"d".repeat(64)}`,
      preconditionFields: [
        { name: "targetAccount", value: "botmux" },
        { name: "accountUid", value: "1000" },
        { name: "configPath", value: "/home/botmux/.botmux/bots.json" },
        { name: "profileKey", value: "botmux.bots" },
        { name: "selectorKey", value: "name" },
        { name: "selectorValue", value: "ops-agent" },
        { name: "fieldKey", value: "showInTeam" },
        { name: "jsonField", value: "showInTeam" },
        { name: "beforeKind", value: "boolean" },
        { name: "before", value: "false" },
        { name: "afterKind", value: "boolean" },
        { name: "after", value: "false" },
        { name: "configDigest", value: `sha256:${"c".repeat(64)}` },
        { name: "configIdentity", value: "dev=1;ino=2;mode=0600;bytes=128" },
        { name: "documentRewrite", value: "whole-document-semantic-rewrite" },
        {
          name: "sameUidRaceBoundary",
          value: "digest-cas-detects-but-cannot-prevent-later-same-uid-replacement",
        },
      ],
    });
    let submissions = 0;
    const router = new ApprovalRouter(registry, {
      reviewer: { review: (request) => Promise.resolve(deterministicApprovalReview(request)) },
      sourcePluginLoader: () => Promise.resolve(sourcePlugin("workload.botmux-ops", digest)),
      submitter: {
        submit: () => {
          submissions += 1;
          return Promise.resolve({ version: 1, requestId: "submit-bad-json-config", ok: true });
        },
      },
      clientFactory: () => Promise.resolve({
        changeStatus: (request) => Promise.resolve({
          version: 1,
          requestId: request.requestId,
          ok: true,
          changeId,
          state: "PENDING_APPROVAL",
          data: {
            serverId,
            machineId,
            targetId,
            policyRevision: valid.policyRevision,
            capabilityRevision: valid.capabilityRevision,
            planHash: valid.planHash,
            kind: "workload.json-config.edit",
            backupRefs: [],
            verification: "",
            rollbackAvailable: true,
            recoveryOnly: false,
            plan: valid,
          },
        }),
      }),
    });
    const command = {
      kind: "approve" as const,
      changeRef: { version: 1 as const, serverId, machineId, targetId, changeId },
    };
    await expect(router.execute(command, {
      intentBinding: intentBinding(command.changeRef),
      localConsole: true,
    })).rejects.toThrow("does not match its authoritative preconditions");
    expect(submissions).toBe(0);
  });

  it("quiesces only after the second local review of one canonical adapter.tui self-update", async () => {
    const directory = await mkdtemp(join(tmpdir(), "ops-approval-router-"));
    temporaryDirectories.push(directory);
    const serverId = parseServerId("server-12345678");
    const machineId = parseMachineId("machine-12345678");
    const targetId = parseTargetId("target-12345678");
    const changeId = parseChangeId("change-tui-self-update-1234");
    const registry = new ServerRegistry(join(directory, "servers.json"));
    await registry.initialize();
    await registry.register({
      serverId,
      machineId,
      baseUrl: "https://127.0.0.1:9443",
      caPath: "/unused/ca.pem",
      certPath: "/unused/agent.pem",
      keyPath: "/unused/agent.key",
      approverCertPath: "/unused/approver.pem",
      approverKeyPath: "/unused/approver.key",
      approvalSigningKeyPath: "/unused/approval.key",
      approvalKeyId: "approver-test-v1",
      enabled: true,
    });
    const plan = buildApprovalPlan({
      operation: {
        kind: "plugin.register",
        pluginId: "adapter.tui",
        pluginKind: "adapter",
        version: "0.3.1",
        publisher: "example/plugin",
        digest: `sha256:${"b".repeat(64)}`,
        capabilities: [
          "adapter.inbound.text", "adapter.outbound.display",
          "adapter.session.bind", "approval.local",
        ],
        requestedScopes: [
          "adapter.inbound.text.local", "adapter.outbound.display.local",
          "adapter.session.bind.local", "approval.submit.local",
        ],
      },
      policyRevision: "policy-12345678",
      capabilityRevision: "capability-12345678",
    });
    const order: string[] = [];
    let failSubmit = false;
    const router = new ApprovalRouter(registry, {
      reviewer: { review: (request) => Promise.resolve(deterministicApprovalReview(request)) },
      selfAdapterRuntime: {
        pluginId: "adapter.tui",
        digest: `sha256:${"a".repeat(64)}`,
        quiesceForUpdate: () => {
          order.push("quiesce");
          return Promise.resolve();
        },
      },
      submitter: {
        submit: () => {
          order.push("submit");
          return failSubmit
            ? Promise.reject(new Error("simulated submit failure"))
            : Promise.resolve({ version: 1, requestId: "submit-tui-1234", ok: true });
        },
      },
      clientFactory: () => Promise.resolve({
        changeStatus: (request) => Promise.resolve({
          version: 1,
          requestId: request.requestId,
          ok: true,
          changeId,
          state: "PENDING_APPROVAL",
          data: {
            serverId,
            machineId,
            targetId,
            policyRevision: plan.policyRevision,
            capabilityRevision: plan.capabilityRevision,
            planHash: plan.planHash,
            kind: "plugin.register",
            backupRefs: [],
            verification: "",
            rollbackAvailable: true,
            recoveryOnly: false,
            plan,
          },
        }),
      }),
    });
    const command = {
      kind: "approve" as const,
      changeRef: { version: 1 as const, serverId, machineId, targetId, changeId },
    };
    const context = { intentBinding: intentBinding(command.changeRef), localConsole: true };

    await expect(router.execute(command, context)).resolves.toMatchObject({
      state: "REVIEW_REQUIRED",
    });
    expect(order).toEqual([]);
    await expect(router.execute(command, { ...context, localConsole: false }))
      .rejects.toThrow("second local TUI confirmation");
    expect(order).toEqual([]);

    await expect(router.execute(command, context)).resolves.toMatchObject({ ok: true });
    expect(order).toEqual(["quiesce", "submit"]);

    const failingRouter = new ApprovalRouter(registry, {
      reviewer: { review: (request) => Promise.resolve(deterministicApprovalReview(request)) },
      selfAdapterRuntime: {
        pluginId: "adapter.tui",
        digest: `sha256:${"a".repeat(64)}`,
        quiesceForUpdate: () => {
          order.push("quiesce-failure");
          return Promise.resolve();
        },
      },
      submitter: {
        submit: () => Promise.reject(new Error("simulated submit failure")),
      },
      clientFactory: () => Promise.resolve({
        changeStatus: (request) => Promise.resolve({
          version: 1,
          requestId: request.requestId,
          ok: true,
          changeId,
          state: "PENDING_APPROVAL",
          data: {
            serverId,
            machineId,
            targetId,
            policyRevision: plan.policyRevision,
            capabilityRevision: plan.capabilityRevision,
            planHash: plan.planHash,
            kind: "plugin.register",
            backupRefs: [],
            verification: "",
            rollbackAvailable: true,
            recoveryOnly: false,
            plan,
          },
        }),
      }),
    });
    failSubmit = true;
    await expect(failingRouter.execute(command, context)).resolves.toMatchObject({
      state: "REVIEW_REQUIRED",
    });
    await expect(failingRouter.execute(command, context)).rejects.toThrow("simulated submit failure");
    expect(order).toContain("quiesce-failure");
  });

  it("approves a plugin A-to-B registration without requiring inactive B to be current", async () => {
    const directory = await mkdtemp(join(tmpdir(), "ops-approval-router-"));
    temporaryDirectories.push(directory);
    const serverId = parseServerId("server-12345678");
    const machineId = parseMachineId("machine-12345678");
    const targetId = parseTargetId("target-12345678");
    const changeId = parseChangeId("change-12345678");
    const registry = new ServerRegistry(join(directory, "servers.json"));
    await registry.initialize();
    await registry.register({
      serverId,
      machineId,
      baseUrl: "https://127.0.0.1:9443",
      caPath: "/unused/ca.pem",
      certPath: "/unused/agent.pem",
      keyPath: "/unused/agent.key",
      approverCertPath: "/unused/approver.pem",
      approverKeyPath: "/unused/approver.key",
      approvalSigningKeyPath: "/unused/approval.key",
      approvalKeyId: "approver-test-v1",
      enabled: true,
    });
    const digestB = `sha256:${"b".repeat(64)}`;
    const plan = buildApprovalPlan({
      operation: {
        kind: "plugin.register",
        pluginId: "workload.example",
        pluginKind: "workload",
        version: "2.0.0",
        publisher: "example/plugin",
        digest: digestB,
        capabilities: ["demo.echo"],
        requestedScopes: [],
      },
      policyRevision: "policy-12345678",
      capabilityRevision: "capability-12345678",
    });
    let submissions = 0;
    let selfUpdateHandoffs = 0;
    const router = new ApprovalRouter(registry, {
      reviewer: { review: (request) => Promise.resolve(deterministicApprovalReview(request)) },
      sourcePluginLoader: () => {
        throw new Error("inactive update digest B must not be read as current");
      },
      sourcePluginLease: () => {
        throw new Error("inactive update digest B must not acquire a runtime lease");
      },
      submitter: {
        submit: () => {
          submissions += 1;
          return Promise.resolve({ version: 1, requestId: "submit-12345678", ok: true });
        },
      },
      selfAdapterRuntime: {
        pluginId: "adapter.tui",
        digest: `sha256:${"a".repeat(64)}`,
        quiesceForUpdate: () => {
          selfUpdateHandoffs += 1;
          return Promise.resolve();
        },
      },
      clientFactory: () => Promise.resolve({
        changeStatus: (request) => Promise.resolve({
          version: 1,
          requestId: request.requestId,
          ok: true,
          changeId,
          state: "PENDING_APPROVAL",
          data: {
            serverId,
            machineId,
            targetId,
            policyRevision: plan.policyRevision,
            capabilityRevision: plan.capabilityRevision,
            planHash: plan.planHash,
            kind: "plugin.register",
            backupRefs: [],
            verification: "",
            rollbackAvailable: true,
            recoveryOnly: false,
            plan,
          },
        }),
      }),
    });
    const command = {
      kind: "approve" as const,
      changeRef: { version: 1 as const, serverId, machineId, targetId, changeId },
    };
    const context = { intentBinding: intentBinding(command.changeRef), localConsole: true };

    await expect(router.execute(command, context)).resolves.toMatchObject({
      state: "REVIEW_REQUIRED",
    });
    await expect(router.execute(command, context)).resolves.toMatchObject({ ok: true });
    expect(submissions).toBe(1);
    expect(selfUpdateHandoffs).toBe(0);
  });

  it("fails closed on missing or mixed source-plugin provenance in a pending plan", async () => {
    const directory = await mkdtemp(join(tmpdir(), "ops-approval-router-"));
    temporaryDirectories.push(directory);
    const serverId = parseServerId("server-12345678");
    const machineId = parseMachineId("machine-12345678");
    const targetId = parseTargetId("target-12345678");
    const changeId = parseChangeId("change-12345678");
    const registry = new ServerRegistry(join(directory, "servers.json"));
    await registry.initialize();
    await registry.register({
      serverId,
      machineId,
      baseUrl: "https://127.0.0.1:9443",
      caPath: "/unused/ca.pem",
      certPath: "/unused/agent.pem",
      keyPath: "/unused/agent.key",
      approverCertPath: "/unused/approver.pem",
      approverKeyPath: "/unused/approver.key",
      approvalSigningKeyPath: "/unused/approval.key",
      approvalKeyId: "approver-test-v1",
      enabled: true,
    });
    const digestA = `sha256:${"a".repeat(64)}`;
    const digestB = `sha256:${"b".repeat(64)}`;
    const valid = buildApprovalPlan({
      operation: {
        kind: "service.action",
        pluginId: "workload.base",
        pluginDigest: digestA,
        unit: "demo.service",
        action: "restart",
      },
      policyRevision: "policy-12345678",
      capabilityRevision: "capability-12345678",
    });
    const missingUnsigned = {
      ...valid,
      steps: valid.steps.map((step) => ({
        ...step,
        fields: step.fields.filter((field) => field.name !== "pluginDigest"),
      })),
    };
    const missing: ApprovalPlan = {
      ...missingUnsigned,
      planHash: canonicalApprovalPlanHash(missingUnsigned),
    };
    const mixedUnsigned = {
      ...valid,
      steps: [
        ...valid.steps,
        {
          id: "step-2",
          operation: "workload.service.action" as const,
          fields: [
            { name: "pluginId", value: "workload.example-service" },
            { name: "pluginDigest", value: digestB },
            { name: "account", value: "example" },
            { name: "manager", value: "user" },
            { name: "unit", value: "example.service" },
            { name: "action", value: "restart" },
          ],
          reversible: false,
        },
      ],
    };
    const mixed: ApprovalPlan = {
      ...mixedUnsigned,
      planHash: canonicalApprovalPlanHash(mixedUnsigned),
    };
    const command = {
      kind: "approve" as const,
      changeRef: { version: 1 as const, serverId, machineId, targetId, changeId },
    };
    let submissions = 0;

    for (const [plan, expectedError] of [
      [missing, "missing or invalid provenance"],
      [mixed, "one canonical source plugin"],
    ] as const) {
      const router = new ApprovalRouter(registry, {
        reviewer: { review: (request) => Promise.resolve(deterministicApprovalReview(request)) },
        sourcePluginLoader: () => Promise.resolve(sourcePlugin("workload.base", digestA)),
        sourcePluginLease: () => {
          throw new Error("malformed plan unexpectedly reached its submit lease");
        },
        submitter: {
          submit: () => {
            submissions += 1;
            return Promise.resolve({ version: 1, requestId: "submit-12345678", ok: true });
          },
        },
        clientFactory: () => Promise.resolve({
          changeStatus: (request) => Promise.resolve({
            version: 1,
            requestId: request.requestId,
            ok: true,
            changeId,
            state: "PENDING_APPROVAL",
            data: {
              serverId,
              machineId,
              targetId,
              policyRevision: plan.policyRevision,
              capabilityRevision: plan.capabilityRevision,
              planHash: plan.planHash,
              kind: "service.action",
              backupRefs: [],
              verification: "",
              rollbackAvailable: true,
              recoveryOnly: false,
              plan,
            },
          }),
        }),
      });
      await expect(router.execute(command, {
        intentBinding: intentBinding(command.changeRef),
        localConsole: true,
      })).rejects.toThrow(expectedError);
    }
    expect(submissions).toBe(0);
  });

  it("recovers legacy planless changes only through reject or a critical local two-step rollback", async () => {
    const directory = await mkdtemp(join(tmpdir(), "ops-approval-router-"));
    temporaryDirectories.push(directory);
    const serverId = parseServerId("server-12345678");
    const machineId = parseMachineId("machine-12345678");
    const targetId = parseTargetId("target-12345678");
    const changeId = parseChangeId("change-legacy-12345678");
    const registry = new ServerRegistry(join(directory, "servers.json"));
    await registry.initialize();
    await registry.register({
      serverId,
      machineId,
      baseUrl: "https://127.0.0.1:9443",
      caPath: "/unused/ca.pem",
      certPath: "/unused/agent.pem",
      keyPath: "/unused/agent.key",
      approverCertPath: "/unused/approver.pem",
      approverKeyPath: "/unused/approver.key",
      approvalSigningKeyPath: "/unused/approval.key",
      approvalKeyId: "approver-test-v1",
      enabled: true,
    });
    const submissions: ApprovalSubmission[] = [];
    let reviewerCalls = 0;
    let state = "PENDING_APPROVAL";
    let rollbackAvailable = false;
    const router = new ApprovalRouter(registry, {
      now: () => new Date("2026-08-08T00:00:00.000Z"),
      reviewer: {
        review: () => {
          reviewerCalls += 1;
          throw new Error("recovery-only status must not be converted into a canonical plan");
        },
      },
      submitter: {
        submit: (submission) => {
          submissions.push(submission);
          return Promise.resolve({
            version: 1,
            requestId: "approval-submit-legacy",
            ok: true,
            changeId,
            state: submission.action === "reject" ? "REJECTED" : "ROLLED_BACK",
          });
        },
      },
      clientFactory: () => Promise.resolve({
        changeStatus: (request) => Promise.resolve({
          version: 1,
          requestId: request.requestId,
          ok: true,
          changeId,
          state,
          data: {
            serverId,
            machineId,
            targetId,
            policyRevision: "policy-legacy-v2",
            capabilityRevision: "capability-legacy-v2",
            planHash: `sha256:${"c".repeat(64)}`,
            kind: "service.action",
            backupRefs: ["/var/lib/ops-agent/backups/change-legacy-12345678"],
            verification: "legacy verification was interrupted",
            rollbackAvailable,
            ...(rollbackAvailable
              ? {}
              : { rollbackUnavailableReason: "the persisted change has no durable rollback evidence" }),
            lastError: "broker restarted during verification",
            recoveryOnly: true,
            recoveryDescriptor: {
              version: 1,
              compatibilityVersion: "legacy-plan-v0.1-v0.2",
              originalKind: "service.action",
              originalTarget: "demo.service",
              originalAction: "service.restart",
              compensationTarget: "demo.service",
              compensationAction: "service.stop",
              rollbackDataDigest: `sha256:${"d".repeat(64)}`,
              backupObjects: [{
                reference: "/var/lib/ops-agent/backups/change-legacy-12345678",
                ...(rollbackAvailable ? { digest: `sha256:${"e".repeat(64)}` } : {}),
              }],
              rollbackCompatible: rollbackAvailable,
              ...(rollbackAvailable
                ? {}
                : { unavailableReason: "the persisted change has no durable rollback evidence" }),
            },
          },
        }),
      }),
    });
    const reference = { version: 1 as const, serverId, machineId, targetId, changeId };

    await expect(router.execute({ kind: "approve", changeRef: reference }, {
      localConsole: true,
    })).rejects.toThrow("cannot be approved");
    await expect(router.execute({ kind: "reject", changeRef: reference }))
      .resolves.toMatchObject({ state: "REJECTED" });
    expect(submissions[0]?.userIntent).toContain("exact model-external /reject");

    state = "RECOVERY_REQUIRED";
    rollbackAvailable = true;
    await expect(router.execute({ kind: "rollback", changeRef: reference }))
      .rejects.toThrow("local interactive console");
    const preview = await router.execute({ kind: "rollback", changeRef: reference }, {
      localConsole: true,
    });
    expect(preview).toMatchObject({
      state: "REVIEW_REQUIRED",
      data: {
        risk: "critical",
        summary: "",
        recoveryDescriptor: {
          compatibilityVersion: "legacy-plan-v0.1-v0.2",
          originalTarget: "demo.service",
          compensationAction: "service.stop",
          rollbackCompatible: true,
        },
      },
    });
    expect(submissions).toHaveLength(1);
    await expect(router.execute({ kind: "rollback", changeRef: reference }, {
      localConsole: true,
    })).resolves.toMatchObject({ state: "ROLLED_BACK" });
    expect(submissions[1]?.userIntent).toContain("signed legacy recovery-only");
    expect(reviewerCalls).toBe(0);
  });

  it("validates a signed local unknown-clearance resolution before returning status", async () => {
    const directory = await mkdtemp(join(tmpdir(), "ops-approval-router-"));
    temporaryDirectories.push(directory);
    const serverId = parseServerId("server-pve-12345678");
    const machineId = parseMachineId("machine-pve-12345678");
    const targetId = parseTargetId("target-pve-root");
    const parentChangeId = parseChangeId("pve-change-parent-12345678");
    const childChangeId = parseChangeId("pve-change-child-123456789");
    const registry = new ServerRegistry(join(directory, "servers.json"));
    await registry.initialize();
    await registry.register({
      serverId,
      machineId,
      baseUrl: "https://127.0.0.1:9443",
      caPath: "/unused/ca.pem",
      certPath: "/unused/agent.pem",
      keyPath: "/unused/agent.key",
      enabled: true,
    });
    const plan = buildApprovalPlan({
      operation: {
        kind: "pve.guest.action",
        pluginId: "workload.pve",
        pluginDigest: `sha256:${"a".repeat(64)}`,
        node: "pve1",
        guestType: "qemu",
        vmid: 100,
        action: "start",
      },
      policyRevision: "policy-pve-12345678",
      capabilityRevision: "capability-pve-12345678",
    });
    let resolutionParent = parseChangeId("pve-change-other-12345678");
    const router = new ApprovalRouter(registry, {
      clientFactory: () => Promise.resolve({
        changeStatus: (request) => Promise.resolve({
          version: 1,
          requestId: request.requestId,
          ok: true,
          changeId: parentChangeId,
          state: "SUPERSEDED",
          data: {
            serverId,
            machineId,
            targetId,
            policyRevision: plan.policyRevision,
            capabilityRevision: plan.capabilityRevision,
            planHash: plan.planHash,
            kind: "pve.guest.action",
            backupRefs: [],
            verification: "",
            rollbackAvailable: false,
            lastError: "lost UPID",
            recoveryOnly: false,
            pveMutationVersion: 1,
            mutationDisposition: "STARTED_OR_UNKNOWN",
            resolution: {
              kind: "pve.recovery-transfer/v1",
              basis: "local-unknown-clearance",
              parentChangeId: resolutionParent,
              childChangeId,
              childPlanHash: `sha256:${"b".repeat(64)}`,
              resourceKey: "pve/vmid/100",
              transferredAt: "2026-08-08T00:00:00Z",
              parentMutationDisposition: "STARTED_OR_UNKNOWN",
              parentTaskEvidence: [],
              clearanceObservationDigest: `sha256:${"c".repeat(64)}`,
              activeTaskDigest: `sha256:${"d".repeat(64)}`,
              guestStateDigest: `sha256:${"e".repeat(64)}`,
              clusterStateDigest: `sha256:${"f".repeat(64)}`,
            },
            plan,
          },
        }),
      }),
    });
    const command = {
      kind: "status" as const,
      changeRef: { version: 1 as const, serverId, machineId, targetId, changeId: parentChangeId },
    };

    await expect(router.execute(command)).rejects.toThrow("does not bind this parent change");
    resolutionParent = parentChangeId;
    await expect(router.execute(command)).resolves.toMatchObject({
      ok: true,
      state: "SUPERSEDED",
    });
  });
});
