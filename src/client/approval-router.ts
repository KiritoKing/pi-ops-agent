import { randomUUID } from "node:crypto";
import {
  encodeChangeRef,
  parseChangeMetadata,
  type ApprovalAction,
} from "../shared/approval.js";
import {
  digestCanonical,
  requireApprovalReviewBinding,
  type ApprovalPlan,
  type ApprovalReview,
  type ApprovalReviewRequest,
} from "../shared/approval-review.js";
import type { HelperResponse } from "../shared/messages.js";
import { deadline } from "../shared/rpc.js";
import { HttpsOpsServerClient } from "../agentd/ops-server-client.js";
import type { ServerRegistry } from "../agentd/server-registry.js";
import type { DirectCommand } from "./commands.js";
import {
  UnixSocketApprovalReviewer,
  type ApprovalReviewProvider,
} from "./reviewer-client.js";
import type { ServerRegistration } from "../agentd/server-registry.js";
import type { OpsServerClient } from "../agentd/ops-server-client.js";
import {
  SudoApprovalSubmitter,
  type ApprovalSubmitter,
} from "./approval-submitter.js";
import type { ActiveSourcePlugin } from "../shared/source-plugin.js";
import {
  MAX_BOUND_APPROVAL_INTENT_BYTES,
  type ApprovalIntentBinding,
} from "./approval-intent.js";
import { parseSessionId, parseTurnId } from "../shared/domain.js";

export interface ApprovalExecutionContext {
  intentBinding?: ApprovalIntentBinding;
  localConsole?: boolean;
}

export interface ApprovalRouterOptions {
  reviewer?: ApprovalReviewProvider;
  clientFactory?: (registration: ServerRegistration) => Promise<Pick<
    OpsServerClient,
    "changeStatus"
  >>;
  submitter?: ApprovalSubmitter;
  sourcePluginLoader?: (pluginId: string) => Promise<ActiveSourcePlugin>;
  sourcePluginLease?: (expected: {
    pluginId: string;
    digest: string;
  }) => Promise<{
    registration: ActiveSourcePlugin;
    release(): Promise<void>;
  }>;
  selfAdapterRuntime?: {
    pluginId: string;
    digest: string;
    quiesceForUpdate(): Promise<void>;
  };
  now?: () => Date;
}

interface PendingReview {
  review: ApprovalReview;
  expiresAt: number;
}

interface PendingRecoveryConfirmation {
  evidenceDigest: string;
  expiresAt: number;
}

const PVE_PLAN_OPERATIONS = new Set<ApprovalPlan["steps"][number]["operation"]>([
  "pve.guest.action",
  "pve.snapshot.create",
  "pve.snapshot.delete",
  "pve.snapshot.rollback",
  "pve.guest.backup",
  "pve.guest.restore",
  "pve.guest.migrate",
]);
const PLUGIN_BOUND_PLAN_OPERATIONS = new Set<ApprovalPlan["steps"][number]["operation"]>([
  "service.action",
  "file.write",
  "workload.service.action",
  "workload.json-config.edit",
  ...PVE_PLAN_OPERATIONS,
]);
const WORKLOAD_PLUGIN_ID_PATTERN =
  /^workload\.[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?$/u;

const EXPLICIT_REJECT_INTENT =
  "The user entered the exact model-external /reject command for this change reference.";
const EXPLICIT_RECOVERY_ROLLBACK_INTENT =
  "The user entered the exact model-external /rollback command for this signed legacy recovery-only change reference.";

type ApprovalPlanStep = ApprovalPlan["steps"][number];
interface PluginPlanBinding {
  pluginId: string;
  pluginDigest: string;
}

const TUI_REGISTER_FIELD_NAMES = [
  "pluginId",
  "pluginKind",
  "version",
  "publisher",
  "digest",
  "capabilities",
  "requestedScopes",
  "adapterRuntimeIdentity",
  "adapterExecution",
  "adapterFilesystemAuthority",
  "adapterNetworkAuthority",
  "adapterCredentialAuthority",
  "adapterActionScopeEnforcement",
  "adapterDirectPlatformAuthority",
] as const;

function isTUISelfRegistrationPlan(
  plan: ApprovalPlan,
  selfAdapterRuntime: ApprovalRouterOptions["selfAdapterRuntime"],
): boolean {
  const targetsTUI = plan.steps.some((step) =>
    step.operation === "plugin.register" && stepField(step, "pluginId") === "adapter.tui");
  if (!targetsTUI) return false;
  const step = plan.steps[0];
  if (selfAdapterRuntime === undefined || selfAdapterRuntime.pluginId !== "adapter.tui") {
    throw new Error("adapter.tui registration must be confirmed by the running local TUI");
  }
  if (plan.steps.length !== 1 || step === undefined || step.id !== "step-1"
    || step.operation !== "plugin.register" || !step.reversible
    || step.fields.length !== TUI_REGISTER_FIELD_NAMES.length
    || step.fields.some((field, index) => field.name !== TUI_REGISTER_FIELD_NAMES[index])
    || stepField(step, "pluginKind") !== "adapter"
    || !/^sha256:[a-f0-9]{64}$/u.test(stepField(step, "digest") ?? "")
    || stepField(step, "adapterRuntimeIdentity") !== "enrolled-local-administrator"
    || stepField(step, "adapterExecution") !== "compiled-client"
    || stepField(step, "adapterFilesystemAuthority") !== "host-as-runtime-uid"
    || stepField(step, "adapterNetworkAuthority") !== "host"
    || stepField(step, "adapterCredentialAuthority") !== "runtime-uid-readable"
    || stepField(step, "adapterActionScopeEnforcement")
      !== "digest-review-and-typed-ipc-contract"
    || stepField(step, "adapterDirectPlatformAuthority")
      !== "plugin-source-forbidden;fixed-compiled-client-profile") {
    throw new Error("adapter.tui self-registration is not one canonical declarative update step");
  }
  return true;
}

function stepField(step: ApprovalPlanStep, name: string): string | undefined {
  return step.fields.find((field) => field.name === name)?.value;
}

function samePVEGuest(left: ApprovalPlanStep, right: ApprovalPlanStep): boolean {
  return ["pluginId", "pluginDigest", "node", "guestType", "vmid"]
    .every((name) => stepField(left, name) === stepField(right, name));
}

function requirePVEPlanShape(plan: ApprovalPlan): void {
  const pluginId = plan.steps[0] === undefined
    ? undefined
    : stepField(plan.steps[0], "pluginId");
  if (plan.pluginDigest === undefined || plan.steps.length < 1 || plan.steps.length > 2
    || plan.steps.some((step) => !PVE_PLAN_OPERATIONS.has(step.operation))
    || pluginId === undefined
    || !WORKLOAD_PLUGIN_ID_PATTERN.test(pluginId)
    || plan.steps.some((step) => stepField(step, "pluginId") !== pluginId
      || stepField(step, "pluginDigest") !== plan.pluginDigest)) {
    throw new Error("PVE approval plan does not bind one canonical source-workload identity and digest");
  }
  if (plan.steps.length === 1) return;
  const backup = plan.steps[0];
  const mutation = plan.steps[1];
  if (backup === undefined || mutation === undefined
    || backup.id !== "step-1" || mutation.id !== "step-2"
    || backup.operation !== "pve.guest.backup"
    || (mutation.operation !== "pve.snapshot.delete"
      && mutation.operation !== "pve.snapshot.rollback")
    || backup.reversible || mutation.reversible
    || stepField(backup, "purpose") !== "safety-backup-before-destructive-snapshot-action"
    || stepField(backup, "storage") === undefined
    || stepField(backup, "storage") !== stepField(mutation, "backupStorage")
    || !samePVEGuest(backup, mutation)) {
    throw new Error("PVE destructive snapshot plan has an invalid safety-backup sequence");
  }
}

const JSON_CONFIG_REQUEST_FIELDS = [
  "pluginId",
  "sourceDigest",
  "profileKey",
  "selectorValue",
  "fieldKey",
  "valueKind",
  "requestedValue",
] as const;
const JSON_CONFIG_PRECONDITION_FIELDS = [
  "targetAccount",
  "accountUid",
  "configPath",
  "profileKey",
  "selectorKey",
  "selectorValue",
  "fieldKey",
  "jsonField",
  "beforeKind",
  "before",
  "afterKind",
  "after",
  "configDigest",
  "configIdentity",
  "documentRewrite",
  "sameUidRaceBoundary",
] as const;
const JSON_CONFIG_DIRECTORY_PRECONDITION_FIELDS = [
  "workingDirectoryRoot",
  "workingDirectoryPath",
  "workingDirectoryRootIdentity",
  "workingDirectoryIdentity",
  "workingDirectoryResidualRisk",
] as const;

function requireJSONConfigPlanShape(plan: ApprovalPlan): void {
  const step = plan.steps[0];
  if (plan.steps.length !== 1 || step === undefined
    || step.operation !== "workload.json-config.edit" || !step.reversible
    || plan.preconditionDigest === undefined || plan.pluginDigest === undefined) {
    throw new Error("JSON config approval plan is not one reversible precondition-bound edit");
  }
  const request = new Map(JSON_CONFIG_REQUEST_FIELDS.map((name) => [name, stepField(step, name)]));
  const precondition = new Map(JSON_CONFIG_PRECONDITION_FIELDS.map((name) => [
    name,
    stepField(step, `precondition.${name}`),
  ]));
  if ([...request.values(), ...precondition.values()].some((value) => value === undefined)) {
    throw new Error("JSON config approval plan omits request or authoritative precondition fields");
  }
  if (request.get("sourceDigest") !== plan.pluginDigest
    || request.get("profileKey") !== precondition.get("profileKey")
    || request.get("selectorValue") !== precondition.get("selectorValue")
    || request.get("fieldKey") !== precondition.get("fieldKey")
    || request.get("requestedValue") !== precondition.get("after")
    || precondition.get("documentRewrite") !== "whole-document-semantic-rewrite"
    || precondition.get("sameUidRaceBoundary")
      !== "digest-cas-detects-but-cannot-prevent-later-same-uid-replacement"
    || !/^sha256:[a-f0-9]{64}$/u.test(precondition.get("configDigest") ?? "")) {
    throw new Error("JSON config approval plan request does not match its authoritative preconditions");
  }
  const kind = request.get("valueKind");
  const expectedAfterKind = kind === "clear" ? "absent" : kind;
  const requestedValue = request.get("requestedValue");
  if ((kind !== "string" && kind !== "boolean" && kind !== "clear")
    || precondition.get("afterKind") !== expectedAfterKind
    || (kind === "boolean" && requestedValue !== "true" && requestedValue !== "false")
    || (kind === "clear" && requestedValue !== "<absent>")) {
    throw new Error("JSON config approval plan has a confused tagged requested value");
  }
  const directoryValues = JSON_CONFIG_DIRECTORY_PRECONDITION_FIELDS.map((name) =>
    stepField(step, `precondition.${name}`));
  if (directoryValues.some((value) => value !== undefined)
    && directoryValues.some((value) => value === undefined)) {
    throw new Error("JSON config approval plan has an incomplete working-directory proof");
  }
  if (directoryValues.every((value) => value !== undefined)
    && stepField(step, "precondition.workingDirectoryResidualRisk")
      !== "pathname_may_be_replaced_after_verification") {
    throw new Error("JSON config approval plan has an invalid working-directory residual risk");
  }
}

function requireCanonicalPluginPlanBinding(plan: ApprovalPlan): PluginPlanBinding | undefined {
  const boundSteps = plan.steps.filter((step) => PLUGIN_BOUND_PLAN_OPERATIONS.has(step.operation));
  if (boundSteps.length === 0) return undefined;
  if (boundSteps.length !== plan.steps.length || plan.pluginDigest === undefined) {
    throw new Error("approval plan mixes plugin-bound and unbound operations or omits its plugin digest");
  }
  const bindings = boundSteps.map((step) => {
    const pluginId = stepField(step, "pluginId");
    const pluginDigest = step.operation === "workload.json-config.edit"
      ? stepField(step, "sourceDigest")
      : stepField(step, "pluginDigest");
    if (pluginId === undefined || pluginDigest === undefined
      || !WORKLOAD_PLUGIN_ID_PATTERN.test(pluginId)
      || !/^sha256:[a-f0-9]{64}$/u.test(pluginDigest)) {
      throw new Error("plugin-bound approval plan step has missing or invalid provenance");
    }
    if ((step.operation === "service.action" || step.operation === "file.write")
      && pluginId !== "workload.base") {
      throw new Error("generic file/service approval plan is not bound to workload.base");
    }
    return { pluginId, pluginDigest };
  });
  const first = bindings[0];
  if (first === undefined || first.pluginDigest !== plan.pluginDigest
    || bindings.some((binding) => binding.pluginId !== first.pluginId
      || binding.pluginDigest !== first.pluginDigest)) {
    throw new Error("approval plan does not bind one canonical source plugin identity and digest");
  }
  if (boundSteps.some((step) => PVE_PLAN_OPERATIONS.has(step.operation))) {
    requirePVEPlanShape(plan);
  }
  if (boundSteps.some((step) => step.operation === "workload.json-config.edit")) {
    requireJSONConfigPlanShape(plan);
  }
  return first;
}

function requireApprovalIntentBinding(
  context: ApprovalExecutionContext,
  reference: Parameters<typeof encodeChangeRef>[0],
): ApprovalIntentBinding {
  const binding = context.intentBinding;
  if (binding === undefined) {
    throw new Error(
      "approval intent unavailable for this change; prepare it again from this live client session",
    );
  }
  if (encodeChangeRef(binding.changeRef) !== encodeChangeRef(reference)) {
    throw new Error("approval intent binding does not match the exact change reference");
  }
  parseSessionId(binding.sessionId, "approval intent sessionId");
  parseTurnId(binding.turnId, "approval intent turnId");
  const bytes = Buffer.from(binding.userIntent, "utf8");
  if (binding.userIntent.trim().length === 0
    || bytes.length > MAX_BOUND_APPROVAL_INTENT_BYTES
    || bytes.toString("utf8") !== binding.userIntent) {
    throw new Error("approval intent binding contains unavailable or invalid user input");
  }
  return binding;
}

export class ApprovalRouter {
  readonly #servers: ServerRegistry;
  readonly #reviewer: ApprovalReviewProvider;
  readonly #clientFactory: NonNullable<ApprovalRouterOptions["clientFactory"]>;
  readonly #submitter: ApprovalSubmitter;
  readonly #sourcePluginLoader: ApprovalRouterOptions["sourcePluginLoader"];
  readonly #sourcePluginLease: ApprovalRouterOptions["sourcePluginLease"];
  readonly #selfAdapterRuntime: ApprovalRouterOptions["selfAdapterRuntime"];
  readonly #now: () => Date;
  readonly #pendingReviews = new Map<string, PendingReview>();
  readonly #pendingRecoveryConfirmations = new Map<string, PendingRecoveryConfirmation>();

  constructor(servers: ServerRegistry, options: ApprovalRouterOptions = {}) {
    this.#servers = servers;
    this.#reviewer = options.reviewer ?? new UnixSocketApprovalReviewer();
    this.#clientFactory = options.clientFactory ?? (async (registration) =>
      await HttpsOpsServerClient.createObserver(registration));
    this.#submitter = options.submitter ?? new SudoApprovalSubmitter();
    this.#sourcePluginLoader = options.sourcePluginLoader;
    this.#sourcePluginLease = options.sourcePluginLease;
    this.#selfAdapterRuntime = options.selfAdapterRuntime;
    if (this.#selfAdapterRuntime !== undefined
      && (this.#selfAdapterRuntime.pluginId !== "adapter.tui"
        || !/^sha256:[a-f0-9]{64}$/u.test(this.#selfAdapterRuntime.digest))) {
      throw new Error("approval self-update handoff is reserved for an exact adapter.tui runtime");
    }
    this.#now = options.now ?? (() => new Date());
  }

  async execute(
    command: DirectCommand,
    context: ApprovalExecutionContext = {},
  ): Promise<HelperResponse> {
    const reference = command.changeRef;
    const registration = await this.#servers.getByServer(reference.serverId);
    if (!registration || !registration.enabled || registration.machineId !== reference.machineId) {
      throw new Error("changeRef does not resolve to an enabled pinned server");
    }
    const inspectionClient = await this.#clientFactory(registration);
    const status = await inspectionClient.changeStatus({
      version: 1,
      requestId: randomUUID(),
      deadline: deadline(30),
      machineId: reference.machineId,
      targetId: reference.targetId,
      method: "change.status",
      changeId: reference.changeId,
    });
    if (!status.ok) return status;
    const metadata = parseChangeMetadata(status.data);
    if ((status.state === "SUPERSEDED") !== (metadata.resolution !== undefined)) {
      throw new Error("signed PVE recovery resolution does not match the authoritative state");
    }
    if (metadata.resolution?.basis === "local-unknown-clearance"
      && metadata.resolution.parentChangeId !== reference.changeId) {
      throw new Error("signed PVE unknown-clearance resolution does not bind this parent change");
    }
    if (metadata.kind.startsWith("pve.")
      && (status.state === "RECOVERY_REQUIRED" || status.state === "SUPERSEDED")
      && metadata.mutationDisposition === undefined) {
      throw new Error("unresolved signed PVE status has no mutation disposition");
    }
    if (command.kind === "status") return status;
    if (!registration.approverCertPath || !registration.approverKeyPath
      || !registration.approvalSigningKeyPath || !registration.approvalKeyId) {
      throw new Error("server registration has no model-external approver credentials");
    }
    const action: ApprovalAction = command.kind;
    if (metadata.recoveryOnly) {
      if (action === "approve") {
        throw new Error("legacy recovery-only changes cannot be approved or executed");
      }
      if (action === "reject") {
        if (status.state !== "PENDING_APPROVAL") {
          throw new Error(`recovery-only change state ${String(status.state)} is not eligible for reject`);
        }
        return await this.#submitter.submit({
          action,
          changeRef: reference,
          userIntent: EXPLICIT_REJECT_INTENT,
        });
      }
      if ((status.state !== "COMMITTED" && status.state !== "RECOVERY_REQUIRED")
        || !metadata.rollbackAvailable) {
        throw new Error(
          `recovery-only change state ${String(status.state)} is not eligible for rollback`
            + (metadata.rollbackUnavailableReason === undefined
              ? ""
              : `: ${metadata.rollbackUnavailableReason}`),
        );
      }
      if (context.localConsole !== true) {
        throw new Error("legacy recovery-only rollback requires a local interactive console");
      }
      const evidence = {
        version: 1 as const,
        recoveryOnly: true as const,
        risk: "critical" as const,
        canAuthorize: false as const,
        action,
        serverId: reference.serverId,
        machineId: reference.machineId,
        targetId: reference.targetId,
        changeId: reference.changeId,
        state: status.state,
        kind: metadata.kind,
        summary: status.summary ?? "",
        planHash: metadata.planHash,
        policyRevision: metadata.policyRevision,
        capabilityRevision: metadata.capabilityRevision,
        backupRefs: metadata.backupRefs,
        verification: metadata.verification,
        rollbackAvailable: metadata.rollbackAvailable,
        rollbackUnavailableReason: metadata.rollbackUnavailableReason,
        recoveryDescriptor: metadata.recoveryDescriptor,
        lastError: metadata.lastError,
        authorizationBasis: metadata.authorizationBasis,
        authorizationScope: metadata.authorizationScope,
        authorizedAt: metadata.authorizedAt,
        explanation: "This persisted legacy change has no current canonical ApprovalPlan. "
          + "Rollback can only use its broker-stored recovery metadata and requires a second "
          + "local confirmation followed by PASSWD sudo and exact /dev/tty confirmation.",
      };
      const evidenceDigest = digestCanonical(evidence);
      const recoveryKey = `${action}\0${reference.serverId}\0${reference.machineId}`
        + `\0${reference.targetId}\0${reference.changeId}`;
      const previous = this.#pendingRecoveryConfirmations.get(recoveryKey);
      const now = this.#now().getTime();
      if (!previous || previous.expiresAt <= now
        || previous.evidenceDigest !== evidenceDigest) {
        this.#pendingRecoveryConfirmations.set(recoveryKey, {
          evidenceDigest,
          expiresAt: now + 2 * 60_000,
        });
        return {
          version: 1,
          requestId: status.requestId,
          ok: true,
          changeId: reference.changeId,
          state: "REVIEW_REQUIRED",
          summary: `${evidence.explanation} Repeat the same /rollback command to continue.`,
          data: { ...evidence, evidenceDigest },
        };
      }
      this.#pendingRecoveryConfirmations.delete(recoveryKey);
      return await this.#submitter.submit({
        action,
        changeRef: reference,
        userIntent: EXPLICIT_RECOVERY_ROLLBACK_INTENT,
      });
    }
    const intentBinding = action === "approve" || action === "rollback"
      ? requireApprovalIntentBinding(context, reference)
      : undefined;
    const userIntent = intentBinding?.userIntent ?? EXPLICIT_REJECT_INTENT;
    let pluginBinding: PluginPlanBinding | undefined;
    let tuiSelfRegistration = false;
    if (action === "approve" || action === "rollback") {
      if (intentBinding === undefined) {
        throw new Error("approval intent binding disappeared before review");
      }
      if (!metadata.plan) {
        throw new Error("change has no reviewable live plan; it is recovery-only");
      }
      if (metadata.plan.planHash !== metadata.planHash
        || metadata.plan.policyRevision !== metadata.policyRevision
        || metadata.plan.capabilityRevision !== metadata.capabilityRevision) {
        throw new Error("review plan does not match authoritative change metadata");
      }
      pluginBinding = requireCanonicalPluginPlanBinding(metadata.plan);
      if (action === "approve") {
        tuiSelfRegistration = isTUISelfRegistrationPlan(
          metadata.plan,
          this.#selfAdapterRuntime,
        );
      }
      if (action === "approve" && pluginBinding !== undefined) {
        await this.#requireCurrentPluginBinding(pluginBinding);
      }
      const reviewId = `review-${digestCanonical({
        action,
        planHash: metadata.planHash,
        changeId: reference.changeId,
        sessionId: intentBinding.sessionId,
        turnId: intentBinding.turnId,
        userIntent,
      }).slice("sha256:".length, "sha256:".length + 32)}`;
      const request: ApprovalReviewRequest = {
        version: 1,
        reviewId,
        userIntent,
        plan: metadata.plan,
      };
      const review = await this.#reviewer.review(request);
      requireApprovalReviewBinding(request, review);
      if (review.recommendation === "reject") {
        throw new Error("approval reviewer rejected the canonical plan");
      }
      if (review.recommendation === "split-required") {
        return {
          version: 1,
          requestId: status.requestId,
          ok: true,
          changeId: reference.changeId,
          state: "SPLIT_REQUIRED",
          summary: `${review.explanation} No approval was submitted. Prepare and approve separate canonical changes that preserve the displayed dependencies and order.`,
          data: review,
        };
      }
      const reviewKey = `${action}\0${reference.serverId}\0${reference.changeId}`
        + `\0${intentBinding.sessionId}\0${intentBinding.turnId}`;
      const previous = this.#pendingReviews.get(reviewKey);
      const now = this.#now();
      if (!previous || previous.expiresAt <= now.getTime()
        || previous.review.reviewDigest !== review.reviewDigest) {
        this.#pendingReviews.set(reviewKey, { review, expiresAt: now.getTime() + 2 * 60_000 });
        return {
          version: 1,
          requestId: status.requestId,
          ok: true,
          changeId: reference.changeId,
          state: "REVIEW_REQUIRED",
          summary: `${review.explanation} Repeat the same /${action} command to confirm this review.`,
          data: review,
        };
      }
      if (review.risk === "critical" && context.localConsole !== true) {
        throw new Error("critical changes require confirmation from a local interactive console");
      }
      if (metadata.plan.steps.some((step) => step.operation === "workload.json-config.edit")
        && context.localConsole !== true) {
        throw new Error("JSON config changes require confirmation from a local interactive console");
      }
      if (tuiSelfRegistration && context.localConsole !== true) {
        throw new Error("adapter.tui self-update requires a second local TUI confirmation");
      }
      this.#pendingReviews.delete(reviewKey);
    }
    if (action === "approve" && pluginBinding !== undefined) {
      if (this.#sourcePluginLease === undefined) {
        throw new Error("plugin-bound approval requires a source-plugin registry lease");
      }
      const lease = await this.#sourcePluginLease({
        pluginId: pluginBinding.pluginId,
        digest: pluginBinding.pluginDigest,
      });
      try {
        this.#requireLeasedPluginBinding(pluginBinding, lease.registration);
        return await this.#submitter.submit({ action, changeRef: reference, userIntent });
      } finally {
        await lease.release();
      }
    }
    if (action === "approve" && tuiSelfRegistration) {
      if (this.#selfAdapterRuntime === undefined) {
        throw new Error("adapter.tui self-update requires a second local TUI confirmation");
      }
      await this.#selfAdapterRuntime.quiesceForUpdate();
    }
    return await this.#submitter.submit({ action, changeRef: reference, userIntent });
  }

  async #requireCurrentPluginBinding(binding: PluginPlanBinding): Promise<void> {
    if (this.#sourcePluginLoader === undefined) {
      throw new Error("plugin-bound approval requires a current source-plugin registry reader");
    }
    const current = await this.#sourcePluginLoader(binding.pluginId);
    this.#requireLeasedPluginBinding(binding, current);
  }

  #requireLeasedPluginBinding(binding: PluginPlanBinding, current: ActiveSourcePlugin): void {
    if (current.kind !== "workload" || current.pluginId !== binding.pluginId
      || current.digest !== binding.pluginDigest) {
      throw new Error(
        `approval plan no longer matches the current ${binding.pluginId} source registration`,
      );
    }
  }
}

export type ApprovalCommandHandler = (
  command: DirectCommand,
  context?: ApprovalExecutionContext,
) => Promise<HelperResponse>;
