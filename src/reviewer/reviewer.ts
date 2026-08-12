import {
  compareRisk,
  digestCanonical,
  finalizeApprovalReview,
  maxRisk,
  type ApprovalFinding,
  type ApprovalPlanStep,
  type ApprovalReview,
  type ApprovalReviewRequest,
  type ApprovalRisk,
} from "../shared/approval-review.js";
import {
  analyzeShellCommands,
  type ShellSegmentAnalysis,
} from "./shell-analysis.js";

const DYNAMIC_SHELL = /(?:`|\$\(|\beval\b|\bsource\b|\b(?:bash|sh)\s+-c\b)/u;
const DESTRUCTIVE_SHELL = /\b(?:rm|mkfs|wipefs|dd|shutdown|reboot|poweroff)\b/u;
const PRIVILEGE_SHELL = /\b(?:sudo|su|setpriv|runuser|nsenter)\b/u;
const NETWORK_SHELL = /\b(?:curl|wget|nc|ncat|ssh|scp|rsync)\b/u;
const SECRET_ASSIGNMENT = /\b(?:api[_-]?key|password|private[_-]?key|secret|token)\s*[:=]/iu;
const MAX_REVIEW_FINDINGS = 128;

interface BoundedFindings {
  findings: readonly ApprovalFinding[];
  truncated: boolean;
}

function boundFindings(
  findings: readonly ApprovalFinding[],
  fallbackStepId: string,
): BoundedFindings {
  if (findings.length <= MAX_REVIEW_FINDINGS) return { findings, truncated: false };
  const retained = findings.slice(0, MAX_REVIEW_FINDINGS - 1);
  const dropped = findings.length - retained.length;
  return {
    findings: [...retained, {
      code: "review.findings-truncated",
      risk: "critical",
      stepId: retained[0]?.stepId ?? fallbackStepId,
      summary: `The deterministic reviewer omitted ${dropped} finding(s) after reaching its ${MAX_REVIEW_FINDINGS}-entry response bound; no omitted finding can lower risk or authorize this plan.`,
    }],
    truncated: true,
  };
}

function fieldValue(step: ApprovalPlanStep, name: string): string | undefined {
  return step.fields.find((field) => field.name === name)?.value;
}

function stepRisk(step: ApprovalPlanStep): ApprovalRisk {
  switch (step.operation) {
    case "file.write":
    case "service.action":
      return step.reversible ? "medium" : "high";
    case "workload.service.action":
      return "high";
    case "workload.json-config.edit":
      // A root-owned policy maps the semantic request to an account and JSON
      // field, but this still rewrites another account's configuration and is
      // deliberately eligible only for local, per-change approval.
      return "high";
    case "package.install":
    case "plugin.install":
    case "plugin.register":
    case "workload.deploy":
      return "high";
    case "breakglass.script":
      return "critical";
    case "pve.guest.action": {
      const action = step.fields.find((field) => field.name === "action")?.value;
      return action === "stop" || action === "reboot" ? "critical" : "high";
    }
    case "pve.snapshot.create":
    case "pve.guest.backup":
      return "high";
    case "pve.snapshot.delete":
    case "pve.snapshot.rollback":
    case "pve.guest.restore":
    case "pve.guest.migrate":
      return "critical";
  }
}

function inspectPVE(step: ApprovalPlanStep): ApprovalFinding[] {
  if (!step.operation.startsWith("pve.")) return [];
  const findings: ApprovalFinding[] = [];
  const recoveryOfChangeId = fieldValue(step, "recoveryOfChangeId");
  if (recoveryOfChangeId !== undefined) {
    findings.push(finding(
      "pve.recovery-chain",
      "critical",
      step,
      `This is a separately approved recovery child of ${recoveryOfChangeId}; only terminal or proven-not-started parent tasks permit the atomic cluster-global VMID lock transfer, and child failure retains that lock.`,
    ));
  }
  if (step.operation !== "pve.guest.action") return findings;
  const action = step.fields.find((field) => field.name === "action")?.value;
  if (action === "stop") {
    findings.push(finding(
      "pve.guest.hard-stop",
      "critical",
      step,
      "A hard stop can discard in-memory state and interrupt guest I/O; a later start is not a rollback.",
    ));
    return findings;
  }
  if (action === "shutdown" || action === "reboot") {
    findings.push(finding(
      "pve.guest.availability-impact",
      action === "reboot" ? "critical" : "high",
      step,
      `The ${action} action interrupts guest availability and cannot restore in-flight work.`,
    ));
  }
  return findings;
}

function inspectFileWrite(step: ApprovalPlanStep): ApprovalFinding[] {
  if (step.operation !== "file.write") return [];
  const content = fieldValue(step, "contentText");
  if (content === undefined) {
    return [finding(
      "file.write.opaque-content",
      "critical",
      step,
      "The exact file content is missing; an opaque digest is not meaningful human approval.",
    )];
  }
  const findings: ApprovalFinding[] = [];
  if (Buffer.byteLength(content) > 16 * 1024 || content.split(/\r?\n/u).length > 200) {
    findings.push(finding(
      "file.write.large-content",
      "high",
      step,
      "The write is large; inspect the complete bounded content and consider a narrower typed workflow.",
    ));
  }
  if (SECRET_ASSIGNMENT.test(content)) {
    findings.push(finding(
      "file.write.secret-like-content",
      "critical",
      step,
      "The content resembles secret material. Generic file.write is audit-visible; use a dedicated credential flow.",
    ));
  }
  return findings;
}

function inspectJSONConfigEdit(step: ApprovalPlanStep): ApprovalFinding[] {
  if (step.operation !== "workload.json-config.edit") return [];
  const findings = [finding(
    "workload.json-config.local-per-change",
    "high",
    step,
    "This source-workload request rewrites another account's JSON configuration through a root-owned semantic mapping. It requires local per-change approval; reviewer output and standing policy cannot authorize it.",
  )];
  const required = [
    "pluginId",
    "sourceDigest",
    "profileKey",
    "selectorValue",
    "fieldKey",
    "valueKind",
    "requestedValue",
    "precondition.targetAccount",
    "precondition.accountUid",
    "precondition.configPath",
    "precondition.beforeKind",
    "precondition.before",
    "precondition.afterKind",
    "precondition.after",
    "precondition.configDigest",
    "precondition.configIdentity",
    "precondition.documentRewrite",
    "precondition.sameUidRaceBoundary",
  ];
  const missing = required.filter((name) => fieldValue(step, name) === undefined);
  if (missing.length > 0) {
    findings.push(finding(
      "workload.json-config.missing-authoritative-context",
      "critical",
      step,
      `The signed plan omits authoritative JSON edit context: ${missing.join(", ")}.`,
    ));
  }
  return findings;
}

function finding(
  code: string,
  risk: ApprovalRisk,
  step: ApprovalPlanStep,
  summary: string,
  sourceStart?: number,
  sourceEnd?: number,
): ApprovalFinding {
  return {
    code, risk, stepId: step.id, summary,
    ...(sourceStart === undefined ? {} : { sourceStart }),
    ...(sourceEnd === undefined ? {} : { sourceEnd }),
  };
}

function breakglassSegmentCode(segment: ShellSegmentAnalysis): string {
  if (segment.classifications.includes("dynamic")) return "breakglass.dynamic-shell";
  if (segment.classifications.includes("destructive")) return "breakglass.destructive-command";
  if (segment.classifications.includes("privilege-transition")) {
    return "breakglass.identity-transition";
  }
  if (segment.classifications.includes("network")) return "breakglass.network-command";
  if (segment.classifications.includes("filesystem-write")) {
    return "breakglass.filesystem-write";
  }
  if (segment.classifications.includes("redirection")) return "breakglass.redirection";
  if (segment.classifications.includes("opaque")) return "breakglass.shell-opaque";
  return "breakglass.command-segment";
}

function breakglassSegmentSummary(segment: ShellSegmentAnalysis): string {
  const classifications = segment.classifications.length === 0
    ? "recognized-read-only"
    : segment.classifications.join(",");
  const opaque = segment.opaqueReasons.length === 0
    ? "none"
    : segment.opaqueReasons.join(",");
  return [
    `Command segment ${segment.index + 1} (${segment.executable}) has deterministic floor ${segment.riskFloor}.`,
    `operator=${segment.operatorBefore}; dependency=${segment.dependency}; classifications=${classifications}; opaque=${opaque}.`,
    `bounded command=${segment.display}`,
  ].join(" ");
}

function inspectBreakglass(step: ApprovalPlanStep): ApprovalFinding[] {
  const findings: ApprovalFinding[] = [];
  const fieldValue = (name: string): string | undefined =>
    step.fields.find((field) => field.name === name)?.value;
  const network = fieldValue("network") === "true";
  const backups = fieldValue("backupPaths") ?? "";
  const verifyDigest = fieldValue("verifyDigest");
  const script = fieldValue("scriptText") ?? "";
  findings.push(finding(
    "breakglass.local-only",
    "critical",
    step,
    "Arbitrary privileged work must remain local-console-only and cannot be auto-approved.",
  ));
  findings.push(finding(
    "breakglass.network-boundary",
    "critical",
    step,
    network
      ? "This full-root capsule explicitly requests the host network; network and external-system effects are in scope."
      : "network=false adds only a best-effort PrivateNetwork namespace; full-root code can escape or delegate through PID 1, so it is not a no-network boundary.",
  ));
  if (backups.length === 0) {
    findings.push(finding(
      "breakglass.no-backup",
      "critical",
      step,
      "The capsule declares no backup path; recovery must be justified before approval.",
    ));
  }
  if (verifyDigest === "none") {
    findings.push(finding(
      "breakglass.no-verification",
      "critical",
      step,
      "The capsule has no caller-provided privileged postcondition script.",
    ));
  }
  if (network) {
    findings.push(finding(
      "breakglass.network",
      "critical",
      step,
      "The full-root capsule explicitly requests host-network access and may affect external systems.",
    ));
  }
  const analysis = analyzeShellCommands(script);
  if (analysis.segments.length > 1) {
    findings.push(finding(
      "breakglass.command-batch",
      "critical",
      step,
      `The capsule contains ${analysis.segments.length} top-level command segments. ${analysis.splitReason} Any suggested split is advisory, must preserve order, and must be prepared and approved as separate canonical changes.`,
    ));
  }
  for (const segment of analysis.segments) {
    findings.push(finding(
      breakglassSegmentCode(segment),
      segment.riskFloor,
      step,
      breakglassSegmentSummary(segment),
      segment.sourceStart,
      segment.sourceEnd,
    ));
  }
  return findings;
}

function inspectIntent(step: ApprovalPlanStep, intent: string): ApprovalFinding[] {
  const findings: ApprovalFinding[] = [];
  if (DYNAMIC_SHELL.test(intent)) {
    findings.push(finding(
      "intent.dynamic-shell",
      "high",
      step,
      "The user input contains dynamic shell evaluation; compare only against the canonical plan.",
    ));
  }
  if (DESTRUCTIVE_SHELL.test(intent)) {
    findings.push(finding(
      "intent.destructive-token",
      "critical",
      step,
      "The user input mentions a destructive or availability-impacting command.",
    ));
  }
  if (PRIVILEGE_SHELL.test(intent)) {
    findings.push(finding(
      "intent.privilege-token",
      "high",
      step,
      "The user input mentions an identity or privilege transition.",
    ));
  }
  if (NETWORK_SHELL.test(intent)) {
    findings.push(finding(
      "intent.network-token",
      "high",
      step,
      "The user input mentions a network-capable executable.",
    ));
  }
  return findings;
}

function inspectAdapterRegistration(step: ApprovalPlanStep): ApprovalFinding[] {
  if (step.operation !== "plugin.register"
    || fieldValue(step, "pluginKind") !== "adapter") return [];
  const identity = fieldValue(step, "adapterRuntimeIdentity") ?? "unknown-runtime-identity";
  const execution = fieldValue(step, "adapterExecution");
  const directAuthority = fieldValue(step, "adapterDirectPlatformAuthority")
    ?? "missing-authority-evidence";
  return [finding(
    "plugin.adapter-runtime-authority",
    "high",
    step,
    execution === "compiled-client"
      ? `This declarative Adapter starts the fixed compiled Client as ${identity} with host network and runtime-UID-readable filesystem/credentials; plugin source execution is forbidden (${directAuthority}).`
      : `This Adapter source runs as ${identity} with host network and runtime-UID-readable filesystem/credentials. Action capabilities and scopes bind digest review and typed IPC only; source can still make direct platform calls under ${directAuthority}.`,
  )];
}

export function deterministicApprovalReview(request: ApprovalReviewRequest): ApprovalReview {
  const findings: ApprovalFinding[] = [];
  const stepRisks = request.plan.steps.map(stepRisk);
  for (const step of request.plan.steps) {
    if (step.operation === "breakglass.script") findings.push(...inspectBreakglass(step));
    findings.push(...inspectAdapterRegistration(step));
    findings.push(...inspectFileWrite(step));
    findings.push(...inspectJSONConfigEdit(step));
    findings.push(...inspectPVE(step));
    findings.push(...inspectIntent(step, request.userIntent));
    if (!step.reversible) {
      findings.push(finding(
        "plan.rollback-limited",
        "high",
        step,
        "This step does not declare a complete automatic rollback.",
      ));
    }
  }
  const unboundedMinimumRisk = maxRisk(...stepRisks, ...findings.map((item) => item.risk));
  const recommendation = findings.some((item) =>
    item.code === "intent.dynamic-shell" || item.code === "breakglass.command-batch")
    ? "split-required"
    : unboundedMinimumRisk === "critical"
      ? "manual-review"
      : "manual-review";
  const bounded = boundFindings(findings, request.plan.steps[0]?.id ?? "review");
  const minimumRisk = bounded.truncated
    ? maxRisk(unboundedMinimumRisk, "critical")
    : unboundedMinimumRisk;
  const explanation = [
    `${request.plan.steps.length} canonical step(s); deterministic floor=${minimumRisk}.`,
    findings.length === 0
      ? "No additional deterministic finding was raised."
      : `${findings.length} finding(s) require attention.`,
    "This reviewer is advisory and cannot sign, approve, or lower the policy risk floor.",
  ].join(" ");
  return finalizeApprovalReview({
    version: 1,
    reviewId: request.reviewId,
    planHash: request.plan.planHash,
    userIntentDigest: digestCanonical({ userIntent: request.userIntent }),
    minimumRisk,
    risk: minimumRisk,
    recommendation,
    canAuthorize: false,
    findings: bounded.findings,
    explanation,
  });
}

export function mergeAdvisoryRisk(
  deterministic: ApprovalReview,
  advisoryRisk: ApprovalRisk,
  advisoryFindings: readonly ApprovalFinding[],
): ApprovalReview {
  const { reviewDigest: previousReviewDigest, ...unsignedDeterministic } = deterministic;
  void previousReviewDigest;
  const validFindings = advisoryFindings.filter((item) =>
    deterministic.planHash.length > 0 && item.stepId.length > 0);
  const combinedFindings = [...deterministic.findings, ...validFindings];
  const bounded = boundFindings(
    combinedFindings,
    deterministic.findings[0]?.stepId ?? validFindings[0]?.stepId ?? "review",
  );
  const risk = maxRisk(
    deterministic.minimumRisk,
    deterministic.risk,
    advisoryRisk,
    ...validFindings.map((item) => item.risk),
    ...(bounded.truncated ? ["critical" as const] : []),
  );
  return finalizeApprovalReview({
    ...unsignedDeterministic,
    risk,
    recommendation: compareRisk(risk, "high") >= 0
      ? deterministic.recommendation
      : "manual-review",
    canAuthorize: false,
    findings: bounded.findings,
    explanation: `${deterministic.explanation} Advisory analysis raised the final risk to ${risk}.`,
  });
}
