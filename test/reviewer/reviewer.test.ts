import { describe, expect, it } from "vitest";
import {
  buildApprovalPlan,
  canonicalApprovalPlanHash,
  digestCanonical,
  parseApprovalReview,
  parseApprovalReviewRequest,
  type ApprovalFinding,
  type ApprovalPlan,
} from "../../src/shared/approval-review.js";
import {
  deterministicApprovalReview,
  mergeAdvisoryRisk,
} from "../../src/reviewer/reviewer.js";

describe("approval reviewer", () => {
  it("builds stable plans that show the exact bounded file content", () => {
    const input = {
      operation: {
        kind: "file.write" as const,
        pluginId: "workload.base" as const,
        pluginDigest: `sha256:${"d".repeat(64)}`,
        path: "/etc/example.conf",
        content: "token=must-not-appear",
        mode: "0640",
      },
      policyRevision: "policy-12345678",
      capabilityRevision: "capability-12345678",
    };
    const first = buildApprovalPlan(input);
    const second = buildApprovalPlan(input);
    expect(first).toEqual(second);
    expect(JSON.stringify(first)).toContain("must-not-appear");
    expect(first.steps[0]?.fields.find((field) => field.name === "contentDigest")?.value)
      .toMatch(/^sha256:/u);
    expect(first.steps[0]?.fields.find((field) => field.name === "contentText")?.value)
      .toBe("token=must-not-appear");
    const review = deterministicApprovalReview({
      version: 1,
      reviewId: "review-file-write",
      userIntent: "write the exact configuration",
      plan: first,
    });
    expect(review.findings.map((finding) => finding.code))
      .toContain("file.write.secret-like-content");
    expect(review.risk).toBe("critical");
  });

  it("keeps breakglass critical and non-authorizing", () => {
    const plan = buildApprovalPlan({
      operation: {
        kind: "breakglass.script",
        script: "systemctl stop demo.service && rm -rf /danger",
        backupPaths: [],
        network: true,
      },
      policyRevision: "policy-12345678",
      capabilityRevision: "capability-12345678",
    });
    const review = deterministicApprovalReview({
      version: 1,
      reviewId: "review-12345678",
      userIntent: "repair the service",
      plan,
    });
    expect(review.minimumRisk).toBe("critical");
    expect(review.risk).toBe("critical");
    expect(review.canAuthorize).toBe(false);
    expect(review.findings.map((item) => item.code)).toEqual(expect.arrayContaining([
      "breakglass.local-only",
      "breakglass.network-boundary",
      "breakglass.no-backup",
      "breakglass.no-verification",
      "breakglass.network",
      "breakglass.command-batch",
      "breakglass.destructive-command",
    ]));
    const destructiveFinding = review.findings.find((item) => item.code === "breakglass.destructive-command");
    expect(typeof destructiveFinding?.sourceStart).toBe("number");
    expect(typeof destructiveFinding?.sourceEnd).toBe("number");
    expect(review.findings.find((item) => item.code === "breakglass.network")?.summary)
      .toContain("host-network access");
    expect(review.findings.find((item) => item.code === "breakglass.no-verification")?.summary)
      .toContain("caller-provided privileged postcondition");
  });

  it("treats network=false as best-effort for every full-root capsule", () => {
    const plan = buildApprovalPlan({
      operation: {
        kind: "breakglass.script",
        script: "true",
        backupPaths: ["/etc/hosts"],
        verifyScript: "true",
        network: false,
      },
      policyRevision: "policy-12345678",
      capabilityRevision: "capability-12345678",
    });
    const review = deterministicApprovalReview({
      version: 1,
      reviewId: "review-breakglass-private-network",
      userIntent: "run a manually approved root repair without requesting host networking",
      plan,
    });
    const networkBoundary = review.findings.find((item) =>
      item.code === "breakglass.network-boundary");
    expect(review.minimumRisk).toBe("critical");
    expect(review.canAuthorize).toBe(false);
    expect(networkBoundary?.risk).toBe("critical");
    expect(networkBoundary?.summary).toContain("best-effort PrivateNetwork");
    expect(networkBoundary?.summary).toContain("not a no-network boundary");
    expect(review.findings.map((item) => item.code)).not.toContain("breakglass.network");
  });

  it("matches the Go plugin.register canonical plan-hash vector", () => {
    const plan = buildApprovalPlan({
      operation: {
        kind: "plugin.register",
        pluginId: "workload.example",
        pluginKind: "workload",
        version: "1.2.3",
        publisher: "example/ops",
        digest: `sha256:${"b".repeat(64)}`,
        capabilities: ["demo.echo", "target.inspect"],
        requestedScopes: ["control.target.inspect", "control.target.prepare"],
      },
      policyRevision: "policy-12345678",
      capabilityRevision: "capability-12345678",
    });
    expect(plan.planHash)
      .toBe("sha256:a865c0c3d1601ef7feb51fbe30d213337ee731a4af85c4ae45dc2a7e71c29418");
  });

  it("shows and explains an executable Adapter's full runtime authority", () => {
    const plan = buildApprovalPlan({
      operation: {
        kind: "plugin.register",
        pluginId: "adapter.example",
        pluginKind: "adapter",
        version: "1.2.3",
        publisher: "example/ops",
        digest: `sha256:${"c".repeat(64)}`,
        capabilities: [
          "adapter.inbound.text",
          "adapter.outbound.send",
          "adapter.session.bind",
          "approval.status",
        ],
        requestedScopes: [
          "adapter.inbound.text.example",
          "adapter.outbound.send.example",
          "adapter.session.bind.example",
          "approval.status.remote",
        ],
      },
      policyRevision: "policy-12345678",
      capabilityRevision: "capability-12345678",
    });
    expect(Object.fromEntries(plan.steps[0]?.fields.map((field) => [field.name, field.value]) ?? []))
      .toMatchObject({
        adapterRuntimeIdentity: "ops-adapter-example",
        adapterExecution: "source-process",
        adapterFilesystemAuthority: "host-as-runtime-uid",
        adapterNetworkAuthority: "host",
        adapterCredentialAuthority: "runtime-uid-readable",
        adapterActionScopeEnforcement: "digest-review-and-typed-ipc-contract",
        adapterDirectPlatformAuthority: "full-runtime-uid-authority;not-os-action-sandboxed",
      });
    const review = deterministicApprovalReview({
      version: 1,
      reviewId: "review-adapter-authority",
      userIntent: "register the reviewed Adapter source",
      plan,
    });
    expect(review.findings).toContainEqual(expect.objectContaining({
      code: "plugin.adapter-runtime-authority",
      risk: "high",
    }));
    expect(review.findings.find((finding) =>
      finding.code === "plugin.adapter-runtime-authority")?.summary)
      .toContain("not-os-action-sandboxed");
  });

  it("does not let advisory output lower the deterministic floor", () => {
    const plan = buildApprovalPlan({
      operation: {
        kind: "plugin.install",
        pluginId: "adapter.example",
        version: "1.0.0",
        publisher: "example",
        digest: `sha256:${"a".repeat(64)}`,
        artifactRef: `builtin:sha256:${"a".repeat(64)}`,
      },
      policyRevision: "policy-12345678",
      capabilityRevision: "capability-12345678",
    });
    const deterministic = deterministicApprovalReview({
      version: 1,
      reviewId: "review-12345678",
      userIntent: "install the adapter",
      plan,
    });
    const forgedLow: ApprovalFinding = {
      code: "model.safe",
      risk: "low",
      stepId: "step-1",
      summary: "Looks safe",
    };
    const merged = mergeAdvisoryRisk(deterministic, "low", [forgedLow]);
    expect(merged.minimumRisk).toBe("high");
    expect(merged.risk).toBe("high");
    expect(merged.canAuthorize).toBe(false);
  });

  it("keeps exactly 128 findings and replaces 129-plus with a critical bound marker", () => {
    const plan = buildApprovalPlan({
      operation: {
        kind: "file.write",
        pluginId: "workload.base",
        pluginDigest: `sha256:${"d".repeat(64)}`,
        path: "/etc/example.conf",
        content: "enabled=true\n",
        mode: "0640",
      },
      policyRevision: "policy-12345678",
      capabilityRevision: "capability-12345678",
    });
    const deterministic = deterministicApprovalReview({
      version: 1,
      reviewId: "review-finding-boundary",
      userIntent: "write the exact non-secret configuration",
      plan,
    });
    expect(deterministic.findings).toHaveLength(0);
    const advisory = (count: number): ApprovalFinding[] => Array.from(
      { length: count },
      (_, index) => ({
        code: `advisory.item-${index}`,
        risk: "low",
        stepId: "step-1",
        summary: `Advisory finding ${index}.`,
      }),
    );

    const exact = mergeAdvisoryRisk(deterministic, "low", advisory(128));
    expect(exact.findings).toHaveLength(128);
    expect(exact.findings.map((finding) => finding.code))
      .not.toContain("review.findings-truncated");
    expect(parseApprovalReview(exact)).toEqual(exact);

    const overflow = mergeAdvisoryRisk(deterministic, "low", advisory(129));
    expect(overflow.findings).toHaveLength(128);
    expect(overflow.findings.at(-1)).toMatchObject({
      code: "review.findings-truncated",
      risk: "critical",
    });
    expect(overflow.findings.at(-1)?.summary).toContain("omitted 2 finding(s)");
    expect(overflow.risk).toBe("critical");
    expect(parseApprovalReview(overflow)).toEqual(overflow);
  });

  it("bounds two 64-segment breakglass steps without changing split-required", () => {
    const script = Array.from({ length: 64 }, () => "true").join(";");
    const steps: ApprovalPlan["steps"] = [1, 2].map((index) => ({
      id: `step-${index}`,
      operation: "breakglass.script" as const,
      reversible: false,
      fields: [
        { name: "scriptText", value: script },
        { name: "network", value: "false" },
        { name: "backupPaths", value: "" },
        { name: "verifyDigest", value: "none" },
      ],
    }));
    const unsigned: Omit<ApprovalPlan, "planHash"> = {
      version: 1,
      policyRevision: "policy-12345678",
      capabilityRevision: "capability-12345678",
      steps,
    };
    const plan: ApprovalPlan = {
      ...unsigned,
      planHash: canonicalApprovalPlanHash(unsigned),
    };
    const request = parseApprovalReviewRequest({
      version: 1,
      reviewId: "review-two-breakglass-batches",
      userIntent: "run two explicitly displayed repair batches",
      plan,
    });
    const review = deterministicApprovalReview(request);
    expect(review.findings).toHaveLength(128);
    expect(review.findings.at(-1)).toMatchObject({
      code: "review.findings-truncated",
      risk: "critical",
    });
    expect(review.recommendation).toBe("split-required");
    expect(review.canAuthorize).toBe(false);
    expect(parseApprovalReview(review)).toEqual(review);
  });

  it("keeps a PVE safety backup and destructive action in one manual review", () => {
    const plan = buildApprovalPlan({
      operation: {
        kind: "pve.snapshot.rollback",
        pluginId: "workload.pve",
        pluginDigest: `sha256:${"a".repeat(64)}`,
        node: "pve1",
        guestType: "qemu",
        vmid: 100,
        snapshot: "known-good",
        backupStorage: "local",
      },
      policyRevision: "policy-12345678",
      capabilityRevision: "capability-12345678",
      preconditionFields: [
        { name: "currentStatus", value: "running" },
        { name: "snapshotState", value: "present" },
      ],
    });
    const review = deterministicApprovalReview({
      version: 1,
      reviewId: "review-pve-snapshot",
      userIntent: "roll back VM 100 after taking a safety backup",
      plan,
    });
    expect(plan.steps.map((step) => step.operation)).toEqual([
      "pve.guest.backup",
      "pve.snapshot.rollback",
    ]);
    expect(plan.steps[1]?.fields).toContainEqual({
      name: "precondition.currentStatus",
      value: "running",
    });
    expect(review.minimumRisk).toBe("critical");
    expect(review.recommendation).toBe("manual-review");
  });

  it("treats a PVE hard stop as critical and non-reversible", () => {
    const plan = buildApprovalPlan({
      operation: {
        kind: "pve.guest.action",
        pluginId: "workload.pve",
        pluginDigest: `sha256:${"b".repeat(64)}`,
        node: "pve1",
        guestType: "qemu",
        vmid: 100,
        action: "stop",
      },
      policyRevision: "policy-12345678",
      capabilityRevision: "capability-12345678",
    });
    const review = deterministicApprovalReview({
      version: 1,
      reviewId: "review-pve-hard-stop",
      userIntent: "hard stop VM 100",
      plan,
    });
    expect(plan.steps[0]?.reversible).toBe(false);
    expect(review.minimumRisk).toBe("critical");
    expect(review.findings.map((item) => item.code)).toContain("pve.guest.hard-stop");
  });

  it("matches Go's PVE recovery plan hash and raises a critical lock-transfer finding", () => {
    const parent = "pve-change-0123456789abcdef0123456789abcdef";
    const plan = buildApprovalPlan({
      operation: {
        kind: "pve.snapshot.rollback",
        pluginId: "workload.pve",
        pluginDigest: `sha256:${"e".repeat(64)}`,
        recoveryOfChangeId: parent,
        node: "pve1",
        guestType: "qemu",
        vmid: 100,
        snapshot: "known-good",
        backupStorage: "local",
      },
      policyRevision: "policy-12345678",
      capabilityRevision: "capability-12345678",
    });
    expect(plan.planHash)
      .toBe("sha256:f32dc23be1dde4655eb7dadc4366eac241c33d563428fc5a30617eab207e445f");
    expect(plan.steps.every((step) => step.fields.some((field) =>
      field.name === "recoveryOfChangeId" && field.value === parent))).toBe(true);
    const review = deterministicApprovalReview({
      version: 1,
      reviewId: "review-pve-recovery-chain",
      userIntent: "recover VMID 100 from the unresolved parent change",
      plan,
    });
    expect(review.minimumRisk).toBe("critical");
    expect(review.findings.map((item) => item.code)).toContain("pve.recovery-chain");
    expect(review.findings.find((item) => item.code === "pve.recovery-chain")?.summary)
      .toContain(parent);
  });

  it("round-trips a digest-bound workload service action through the strict parser", () => {
    const plan = buildApprovalPlan({
      operation: {
        kind: "workload.service.action",
        pluginId: "workload.hermes-ops",
        pluginDigest: `sha256:${"c".repeat(64)}`,
        account: "hermes",
        manager: "user",
        unit: "hermes-gateway.service",
        action: "restart",
      },
      policyRevision: "policy-12345678",
      capabilityRevision: "capability-12345678",
    });
    const request = parseApprovalReviewRequest({
      version: 1,
      reviewId: "review-workload-service",
      userIntent: "restart the Hermes gateway for the hermes account",
      plan,
    });
    expect(request.plan).toEqual(plan);
    expect(request.plan.steps[0]?.operation).toBe("workload.service.action");
    expect(request.plan.steps[0]?.reversible).toBe(false);
  });

  it("matches Go's precondition-bound JSON config plan and keeps a high local floor", () => {
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
      { name: "configDigest", value: `sha256:${"b".repeat(64)}` },
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
        sourceDigest: `sha256:${"a".repeat(64)}`,
        profileKey: "botmux.bots",
        selectorValue: "ops-agent",
        fieldKey: "model",
        value: { kind: "string", stringValue: "openai/gpt-5" },
      },
      policyRevision: "policy-json-config-v1",
      capabilityRevision: "capability-remote-v0.3-v8",
      preconditionDigest: "sha256:3bdcbaa2cd90ff432fc91468a7b54b2f6a93ca94778189f4c31c1e6cf3c3b7c4",
      preconditionFields,
    });
    expect(plan.planHash)
      .toBe("sha256:ea6fc7e091c926e7ec9bb42a5a4a327a6bc7b53817199f40afd9623531570e40");
    expect(plan.pluginDigest).toBe(`sha256:${"a".repeat(64)}`);
    expect(Object.fromEntries(plan.steps[0]?.fields.map((field) => [field.name, field.value]) ?? []))
      .toMatchObject({
        sourceDigest: `sha256:${"a".repeat(64)}`,
        valueKind: "string",
        requestedValue: "openai/gpt-5",
        "precondition.configDigest": `sha256:${"b".repeat(64)}`,
        "precondition.before": "openai/gpt-4.1",
        "precondition.after": "openai/gpt-5",
      });
    const request = parseApprovalReviewRequest({
      version: 1,
      reviewId: "review-json-config-golden",
      userIntent: "change only the ops-agent BotMux model",
      plan,
    });
    const review = deterministicApprovalReview(request);
    expect(review.minimumRisk).toBe("high");
    expect(review.canAuthorize).toBe(false);
    expect(review.findings).toContainEqual(expect.objectContaining({
      code: "workload.json-config.local-per-change",
      risk: "high",
    }));
  });

  it("strictly rejects unknown request fields", () => {
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
    expect(() => parseApprovalReviewRequest({
      version: 1,
      reviewId: "review-12345678",
      userIntent: "restart demo",
      plan,
      injected: true,
    })).toThrow(/not supported/u);
  });

  it("uses canonical key ordering for hashes", () => {
    expect(digestCanonical({ b: 2, a: 1 })).toBe(digestCanonical({ a: 1, b: 2 }));
  });
});
