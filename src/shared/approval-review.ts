import { createHash } from "node:crypto";
import type { RootOperation } from "./messages.js";
import { requireString } from "./guards.js";
import { requireExactRecord } from "./strict.js";

const SHA256 = /^sha256:[a-f0-9]{64}$/u;
const RISK_LEVELS = ["low", "medium", "high", "critical"] as const;

export type ApprovalRisk = (typeof RISK_LEVELS)[number];

export interface ApprovalPlanField {
  name: string;
  value: string;
}

export interface ApprovalPlanStep {
  id: string;
  operation: RootOperation["kind"];
  fields: readonly ApprovalPlanField[];
  reversible: boolean;
}

export interface ApprovalPlan {
  version: 1;
  planHash: string;
  policyRevision: string;
  capabilityRevision: string;
  preconditionDigest?: string;
  pluginDigest?: string;
  steps: readonly ApprovalPlanStep[];
}

export interface ApprovalReviewRequest {
  version: 1;
  reviewId: string;
  userIntent: string;
  plan: ApprovalPlan;
}

export interface ApprovalFinding {
  code: string;
  risk: ApprovalRisk;
  stepId: string;
  summary: string;
  sourceStart?: number;
  sourceEnd?: number;
}

export interface ApprovalReview {
  version: 1;
  reviewId: string;
  planHash: string;
  userIntentDigest: string;
  minimumRisk: ApprovalRisk;
  risk: ApprovalRisk;
  recommendation: "manual-review" | "split-required" | "reject";
  canAuthorize: false;
  findings: readonly ApprovalFinding[];
  explanation: string;
  reviewDigest: string;
}

function sha256(value: string | Buffer): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function canonicalize(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "number") {
    return JSON.stringify(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (typeof value !== "object") throw new Error("canonical value contains an unsupported type");
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).filter((key) => record[key] !== undefined).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalize(record[key])}`).join(",")}}`;
}

export function digestCanonical(value: unknown): string {
  return sha256(canonicalize(value));
}

export function requireApprovalReviewBinding(
  request: ApprovalReviewRequest,
  review: ApprovalReview,
): void {
  if (review.reviewId !== request.reviewId) {
    throw new Error("approval reviewer returned a result for another review request");
  }
  if (review.planHash !== request.plan.planHash) {
    throw new Error("approval reviewer returned a result for another plan");
  }
  if (review.userIntentDigest !== digestCanonical({ userIntent: request.userIntent })) {
    throw new Error("approval reviewer returned a result for another user intent");
  }
  const stepIds = new Set(request.plan.steps.map((step) => step.id));
  if (review.findings.some((finding) => !stepIds.has(finding.stepId))) {
    throw new Error("approval reviewer finding references an unknown canonical plan step");
  }
}

function updatePlanHashFrame(hash: ReturnType<typeof createHash>, value: string): void {
  const payload = Buffer.from(value, "utf8");
  hash.update(String(payload.length), "ascii");
  hash.update(":", "ascii");
  hash.update(payload);
}

// This framing is shared with internal/protocol.CanonicalApprovalPlanHash.
// It binds exactly what the reviewer and human see without depending on
// language-specific JSON escaping rules.
export function canonicalApprovalPlanHash(
  plan: Omit<ApprovalPlan, "planHash"> | ApprovalPlan,
): string {
  const hash = createHash("sha256");
  hash.update("agentd-approval-plan-v1\0", "utf8");
  updatePlanHashFrame(hash, String(plan.version));
  updatePlanHashFrame(hash, plan.policyRevision);
  updatePlanHashFrame(hash, plan.capabilityRevision);
  updatePlanHashFrame(hash, plan.preconditionDigest ?? "");
  updatePlanHashFrame(hash, plan.pluginDigest ?? "");
  updatePlanHashFrame(hash, String(plan.steps.length));
  for (const step of plan.steps) {
    updatePlanHashFrame(hash, step.id);
    updatePlanHashFrame(hash, step.operation);
    updatePlanHashFrame(hash, String(step.reversible));
    updatePlanHashFrame(hash, String(step.fields.length));
    for (const field of step.fields) {
      updatePlanHashFrame(hash, field.name);
      updatePlanHashFrame(hash, field.value);
    }
  }
  return `sha256:${hash.digest("hex")}`;
}

function contentDigest(content: string): string {
  return sha256(Buffer.from(content, "utf8"));
}

function adapterRuntimeIdentity(pluginId: string): string {
  if (pluginId === "adapter.tui") return "enrolled-local-administrator";
  if (pluginId === "adapter.botmux") return "ops-agent-botmux";
  const suffix = pluginId.slice("adapter.".length).replaceAll(".", "-");
  if (suffix.length <= 20) return `ops-adapter-${suffix}`;
  const shortHash = createHash("sha256").update(pluginId, "utf8").digest("hex").slice(0, 16);
  return `ops-adapter-${shortHash}`;
}

function adapterAuthorityPlanFields(pluginId: string): ApprovalPlanField[] {
  const tui = pluginId === "adapter.tui";
  return [
    { name: "adapterRuntimeIdentity", value: adapterRuntimeIdentity(pluginId) },
    { name: "adapterExecution", value: tui ? "compiled-client" : "source-process" },
    { name: "adapterFilesystemAuthority", value: "host-as-runtime-uid" },
    { name: "adapterNetworkAuthority", value: "host" },
    { name: "adapterCredentialAuthority", value: "runtime-uid-readable" },
    {
      name: "adapterActionScopeEnforcement",
      value: "digest-review-and-typed-ipc-contract",
    },
    {
      name: "adapterDirectPlatformAuthority",
      value: tui
        ? "plugin-source-forbidden;fixed-compiled-client-profile"
        : "full-runtime-uid-authority;not-os-action-sandboxed",
    },
  ];
}

export function planStepForOperation(operation: RootOperation): ApprovalPlanStep {
  switch (operation.kind) {
    case "package.install":
      return {
        id: "step-1",
        operation: operation.kind,
        fields: [
          { name: "package", value: operation.package },
          ...(operation.version === undefined ? [] : [{ name: "version", value: operation.version }]),
        ],
        reversible: false,
      };
    case "service.action":
      return {
        id: "step-1",
        operation: operation.kind,
        fields: [
          { name: "pluginId", value: operation.pluginId },
          { name: "pluginDigest", value: operation.pluginDigest },
          { name: "unit", value: operation.unit },
          { name: "action", value: operation.action },
        ],
        reversible: operation.action !== "stop",
      };
    case "workload.service.action":
      return {
        id: "step-1",
        operation: operation.kind,
        fields: [
          { name: "pluginId", value: operation.pluginId },
          { name: "pluginDigest", value: operation.pluginDigest },
          { name: "account", value: operation.account },
          { name: "manager", value: operation.manager },
          { name: "unit", value: operation.unit },
          { name: "action", value: operation.action },
        ],
        reversible: false,
      };
    case "workload.json-config.edit": {
      const requestedValue = operation.value.kind === "string"
        ? operation.value.stringValue
        : operation.value.kind === "boolean"
          ? String(operation.value.booleanValue)
          : "<absent>";
      return {
        id: "step-1",
        operation: operation.kind,
        fields: [
          { name: "pluginId", value: operation.pluginId },
          { name: "sourceDigest", value: operation.sourceDigest },
          { name: "profileKey", value: operation.profileKey },
          { name: "selectorValue", value: operation.selectorValue },
          { name: "fieldKey", value: operation.fieldKey },
          { name: "valueKind", value: operation.value.kind },
          { name: "requestedValue", value: requestedValue },
        ],
        reversible: true,
      };
    }
    case "file.write":
      return {
        id: "step-1",
        operation: operation.kind,
        fields: [
          { name: "pluginId", value: operation.pluginId },
          { name: "pluginDigest", value: operation.pluginDigest },
          { name: "path", value: operation.path },
          { name: "contentDigest", value: contentDigest(operation.content) },
          { name: "contentBytes", value: String(Buffer.byteLength(operation.content)) },
          { name: "contentText", value: operation.content },
          ...(operation.mode === undefined ? [] : [{ name: "mode", value: operation.mode }]),
        ],
        reversible: true,
      };
    case "plugin.install":
    case "workload.deploy":
      return {
        id: "step-1",
        operation: operation.kind,
        fields: [
          { name: "pluginId", value: operation.pluginId },
          { name: "version", value: operation.version },
          { name: "publisher", value: operation.publisher },
          { name: "digest", value: operation.digest },
          { name: "artifactRef", value: operation.artifactRef },
        ],
        reversible: true,
      };
    case "plugin.register":
      return {
        id: "step-1",
        operation: operation.kind,
        fields: [
          { name: "pluginId", value: operation.pluginId },
          { name: "pluginKind", value: operation.pluginKind },
          { name: "version", value: operation.version },
          { name: "publisher", value: operation.publisher },
          { name: "digest", value: operation.digest },
          { name: "capabilities", value: operation.capabilities.join("\n") },
          { name: "requestedScopes", value: operation.requestedScopes.join("\n") },
          ...(operation.pluginKind === "adapter"
            ? adapterAuthorityPlanFields(operation.pluginId)
            : []),
        ],
        reversible: true,
      };
    case "breakglass.script":
      return {
        id: "step-1",
        operation: operation.kind,
        fields: [
          { name: "scriptDigest", value: contentDigest(operation.script) },
          { name: "scriptBytes", value: String(Buffer.byteLength(operation.script)) },
          { name: "scriptText", value: operation.script },
          { name: "backupPaths", value: operation.backupPaths.join("\n") },
          {
            name: "verifyDigest",
            value: operation.verifyScript === undefined
              ? "none"
              : contentDigest(operation.verifyScript),
          },
          { name: "verifyText", value: operation.verifyScript ?? "" },
          { name: "network", value: String(operation.network) },
        ],
        reversible: false,
      };
    case "pve.guest.action":
      return {
        id: "step-1",
        operation: operation.kind,
        fields: [
          ...pveGuestFields(operation),
          { name: "action", value: operation.action },
        ],
        reversible: false,
      };
    case "pve.snapshot.create":
      return {
        id: "step-1",
        operation: operation.kind,
        fields: [
          ...pveGuestFields(operation),
          { name: "snapshot", value: operation.snapshot },
          ...(operation.description === undefined
            ? []
            : [{ name: "description", value: operation.description }]),
        ],
        // Snapshot deletion is a separate destructive plan with a required
        // safety backup, not an implicit rollback of this step.
        reversible: false,
      };
    case "pve.snapshot.delete":
    case "pve.snapshot.rollback":
      return {
        id: "step-1",
        operation: operation.kind,
        fields: [
          ...pveGuestFields(operation),
          { name: "snapshot", value: operation.snapshot },
          { name: "backupStorage", value: operation.backupStorage },
        ],
        reversible: false,
      };
    case "pve.guest.backup":
      return {
        id: "step-1",
        operation: operation.kind,
        fields: [...pveGuestFields(operation), { name: "storage", value: operation.storage }],
        reversible: false,
      };
    case "pve.guest.restore":
      return {
        id: "step-1",
        operation: operation.kind,
        fields: [
          ...pveGuestFields(operation),
          { name: "backupVolume", value: operation.backupVolume },
          { name: "storage", value: operation.storage },
        ],
        reversible: false,
      };
    case "pve.guest.migrate":
      return {
        id: "step-1",
        operation: operation.kind,
        fields: [
          ...pveGuestFields(operation),
          { name: "targetNode", value: operation.targetNode },
          { name: "online", value: String(operation.online) },
          { name: "restart", value: String(operation.restart) },
          { name: "withLocalDisks", value: String(operation.withLocalDisks) },
        ],
        reversible: false,
      };
  }
}

type PVEGuestOperation = Extract<RootOperation, {
  kind:
    | "pve.guest.action"
    | "pve.snapshot.create"
    | "pve.snapshot.delete"
    | "pve.snapshot.rollback"
    | "pve.guest.backup"
    | "pve.guest.restore"
    | "pve.guest.migrate";
}>;

function pveGuestFields(operation: PVEGuestOperation): ApprovalPlanField[] {
  return [
    { name: "pluginId", value: operation.pluginId },
    { name: "pluginDigest", value: operation.pluginDigest },
    ...(operation.recoveryOfChangeId === undefined
      ? []
      : [{ name: "recoveryOfChangeId", value: operation.recoveryOfChangeId }]),
    { name: "node", value: operation.node },
    { name: "guestType", value: operation.guestType },
    { name: "vmid", value: String(operation.vmid) },
  ];
}

function operationPluginDigest(operation: RootOperation): string | undefined {
  switch (operation.kind) {
    case "package.install":
    case "breakglass.script":
      return undefined;
    case "service.action":
    case "file.write":
    case "workload.service.action":
      return operation.pluginDigest;
    case "workload.json-config.edit":
      return operation.sourceDigest;
    case "plugin.install":
    case "workload.deploy":
      return operation.digest;
    case "plugin.register":
      return operation.digest;
    case "pve.guest.action":
    case "pve.snapshot.create":
    case "pve.snapshot.delete":
    case "pve.snapshot.rollback":
    case "pve.guest.backup":
    case "pve.guest.restore":
    case "pve.guest.migrate":
      return operation.pluginDigest;
  }
}

export function buildApprovalPlan(input: {
  operation: RootOperation;
  policyRevision: string;
  capabilityRevision: string;
  preconditionDigest?: string;
  preconditionFields?: readonly ApprovalPlanField[];
}): ApprovalPlan {
  const primary = planStepForOperation(input.operation);
  const preconditionFields = (input.preconditionFields ?? []).map((field) => ({
    name: `precondition.${field.name}`,
    value: field.value,
  }));
  const primaryWithPreconditions: ApprovalPlanStep = {
    ...primary,
    fields: [...primary.fields, ...preconditionFields],
  };
  const steps: ApprovalPlanStep[] = input.operation.kind === "pve.snapshot.delete"
    || input.operation.kind === "pve.snapshot.rollback"
    ? [
        {
          id: "step-1",
          operation: "pve.guest.backup",
          fields: [
            ...pveGuestFields(input.operation),
            { name: "storage", value: input.operation.backupStorage },
            { name: "purpose", value: "safety-backup-before-destructive-snapshot-action" },
          ],
          reversible: false,
        },
        { ...primaryWithPreconditions, id: "step-2" },
      ]
    : [primaryWithPreconditions];
  const pluginDigest = operationPluginDigest(input.operation);
  const unsigned = {
    version: 1 as const,
    policyRevision: input.policyRevision,
    capabilityRevision: input.capabilityRevision,
    ...(input.preconditionDigest === undefined
      ? {}
      : { preconditionDigest: input.preconditionDigest }),
    ...(pluginDigest === undefined ? {} : { pluginDigest }),
    steps,
  };
  return { ...unsigned, planHash: canonicalApprovalPlanHash(unsigned) };
}

function parseRisk(value: unknown, label: string): ApprovalRisk {
  const risk = requireString(value, label, { max: 16 });
  if (!(RISK_LEVELS as readonly string[]).includes(risk)) {
    throw new Error(`${label} is not a supported risk`);
  }
  return risk as ApprovalRisk;
}

function parsePlanStep(value: unknown, index: number): ApprovalPlanStep {
  const input = requireExactRecord(value, `approval plan.steps[${index}]`, [
    "id", "operation", "fields", "reversible",
  ]);
  const operation = requireString(input.operation, `approval plan.steps[${index}].operation`, {
    max: 64,
  });
  const operations: RootOperation["kind"][] = [
    "package.install", "service.action", "workload.service.action", "workload.json-config.edit",
    "file.write", "plugin.install", "plugin.register", "workload.deploy", "breakglass.script", "pve.guest.action",
    "pve.snapshot.create", "pve.snapshot.delete", "pve.snapshot.rollback", "pve.guest.backup",
    "pve.guest.restore", "pve.guest.migrate",
  ];
  if (!operations.includes(operation as RootOperation["kind"])) {
    throw new Error(`approval plan.steps[${index}].operation is unsupported`);
  }
  if (!Array.isArray(input.fields) || input.fields.length > 64) {
    throw new Error("approval plan step fields must be an array with at most 64 entries");
  }
  const fields = input.fields.map((value, fieldIndex): ApprovalPlanField => {
    const field = requireExactRecord(value, `approval plan.steps[${index}].fields[${fieldIndex}]`, [
      "name", "value",
    ]);
    return {
      name: requireString(field.name, `approval plan.steps[${index}].fields[${fieldIndex}].name`, {
        pattern: /^[a-zA-Z][a-zA-Z0-9._-]{0,63}$/u,
      }),
      value: requireString(field.value, `approval plan.steps[${index}].fields[${fieldIndex}].value`, {
        min: 0, max: 128 * 1024,
      }),
    };
  });
  if (new Set(fields.map((field) => field.name)).size !== fields.length) {
    throw new Error("approval plan step fields contain duplicate names");
  }
  if (typeof input.reversible !== "boolean") {
    throw new Error(`approval plan.steps[${index}].reversible must be a boolean`);
  }
  return {
    id: requireString(input.id, `approval plan.steps[${index}].id`, {
      pattern: /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$/u,
    }),
    operation: operation as RootOperation["kind"],
    fields,
    reversible: input.reversible,
  };
}

export function parseApprovalPlan(value: unknown): ApprovalPlan {
  const input = requireExactRecord(value, "approval plan", [
    "version", "planHash", "policyRevision", "capabilityRevision", "preconditionDigest",
    "pluginDigest", "steps",
  ]);
  if (input.version !== 1) throw new Error("approval plan has an unsupported version");
  if (!Array.isArray(input.steps) || input.steps.length === 0 || input.steps.length > 64) {
    throw new Error("approval plan.steps must contain between 1 and 64 steps");
  }
  const plan: ApprovalPlan = {
    version: 1,
    planHash: requireString(input.planHash, "approval plan.planHash", { pattern: SHA256 }),
    policyRevision: requireString(input.policyRevision, "approval plan.policyRevision", {
      min: 1, max: 160,
    }),
    capabilityRevision: requireString(
      input.capabilityRevision,
      "approval plan.capabilityRevision",
      { min: 1, max: 160 },
    ),
    steps: input.steps.map(parsePlanStep),
    ...(input.preconditionDigest === undefined
      ? {}
      : {
          preconditionDigest: requireString(
            input.preconditionDigest,
            "approval plan.preconditionDigest",
            { pattern: SHA256 },
          ),
        }),
    ...(input.pluginDigest === undefined
      ? {}
      : { pluginDigest: requireString(input.pluginDigest, "approval plan.pluginDigest", { pattern: SHA256 }) }),
  };
  if (canonicalApprovalPlanHash(plan) !== plan.planHash) {
    throw new Error("approval plan displayed fields do not match planHash");
  }
  return plan;
}

export function parseApprovalReviewRequest(value: unknown): ApprovalReviewRequest {
  const input = requireExactRecord(value, "approval review request", [
    "version", "reviewId", "userIntent", "plan",
  ]);
  if (input.version !== 1) throw new Error("approval review request has an unsupported version");
  return {
    version: 1,
    reviewId: requireString(input.reviewId, "approval review request.reviewId", {
      pattern: /^[a-zA-Z0-9][a-zA-Z0-9._:-]{7,159}$/u,
    }),
    userIntent: requireString(input.userIntent, "approval review request.userIntent", {
      min: 1, max: 64 * 1024,
    }),
    plan: parseApprovalPlan(input.plan),
  };
}

export function compareRisk(left: ApprovalRisk, right: ApprovalRisk): number {
  return RISK_LEVELS.indexOf(left) - RISK_LEVELS.indexOf(right);
}

export function maxRisk(...values: ApprovalRisk[]): ApprovalRisk {
  return values.reduce((current, next) => compareRisk(next, current) > 0 ? next : current, "low");
}

export function finalizeApprovalReview(
  review: Omit<ApprovalReview, "reviewDigest">,
): ApprovalReview {
  const normalized = {
    ...review,
    risk: maxRisk(review.minimumRisk, review.risk),
    canAuthorize: false as const,
  };
  return { ...normalized, reviewDigest: digestCanonical(normalized) };
}

export function parseApprovalFinding(value: unknown, index: number): ApprovalFinding {
  const input = requireExactRecord(value, `approval finding[${index}]`, [
    "code", "risk", "stepId", "summary", "sourceStart", "sourceEnd",
  ]);
  const finding: ApprovalFinding = {
    code: requireString(input.code, `approval finding[${index}].code`, {
      pattern: /^[a-z0-9][a-z0-9._-]{1,63}$/u,
    }),
    risk: parseRisk(input.risk, `approval finding[${index}].risk`),
    stepId: requireString(input.stepId, `approval finding[${index}].stepId`, { max: 64 }),
    summary: requireString(input.summary, `approval finding[${index}].summary`, { max: 1024 }),
  };
  if (input.sourceStart !== undefined || input.sourceEnd !== undefined) {
    if (!Number.isInteger(input.sourceStart) || !Number.isInteger(input.sourceEnd)
      || Number(input.sourceStart) < 0 || Number(input.sourceEnd) < Number(input.sourceStart)) {
      throw new Error(`approval finding[${index}] has an invalid source span`);
    }
    finding.sourceStart = Number(input.sourceStart);
    finding.sourceEnd = Number(input.sourceEnd);
  }
  return finding;
}

export function parseApprovalReview(value: unknown): ApprovalReview {
  const input = requireExactRecord(value, "approval review", [
    "version", "reviewId", "planHash", "userIntentDigest", "minimumRisk", "risk",
    "recommendation", "canAuthorize", "findings", "explanation", "reviewDigest",
  ]);
  if (input.version !== 1 || input.canAuthorize !== false) {
    throw new Error("approval review has an unsupported version or authority claim");
  }
  const recommendation = requireString(input.recommendation, "approval review.recommendation", {
    max: 32,
  });
  if (recommendation !== "manual-review" && recommendation !== "split-required"
    && recommendation !== "reject") {
    throw new Error("approval review has an unsupported recommendation");
  }
  if (!Array.isArray(input.findings) || input.findings.length > 128) {
    throw new Error("approval review.findings must contain at most 128 entries");
  }
  const review: ApprovalReview = {
    version: 1,
    reviewId: requireString(input.reviewId, "approval review.reviewId", {
      pattern: /^[a-zA-Z0-9][a-zA-Z0-9._:-]{7,159}$/u,
    }),
    planHash: requireString(input.planHash, "approval review.planHash", { pattern: SHA256 }),
    userIntentDigest: requireString(input.userIntentDigest, "approval review.userIntentDigest", {
      pattern: SHA256,
    }),
    minimumRisk: parseRisk(input.minimumRisk, "approval review.minimumRisk"),
    risk: parseRisk(input.risk, "approval review.risk"),
    recommendation,
    canAuthorize: false,
    findings: input.findings.map(parseApprovalFinding),
    explanation: requireString(input.explanation, "approval review.explanation", {
      min: 1, max: 16 * 1024,
    }),
    reviewDigest: requireString(input.reviewDigest, "approval review.reviewDigest", { pattern: SHA256 }),
  };
  const { reviewDigest, ...unsigned } = review;
  if (digestCanonical(unsigned) !== reviewDigest) {
    throw new Error("approval review digest does not match its canonical content");
  }
  if (compareRisk(review.risk, review.minimumRisk) < 0) {
    throw new Error("approval review risk is below the deterministic minimum");
  }
  return review;
}
