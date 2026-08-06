import { randomUUID } from "node:crypto";
import {
  parseChangeMetadata,
  type ApprovalAction,
  signApprovalGrant,
} from "../shared/approval.js";
import type { HelperResponse } from "../shared/messages.js";
import { deadline } from "../shared/rpc.js";
import { HttpsOpsServerClient } from "../agentd/ops-server-client.js";
import type { ServerRegistry } from "../agentd/server-registry.js";
import type { DirectCommand } from "./commands.js";

export class ApprovalRouter {
  readonly #servers: ServerRegistry;

  constructor(servers: ServerRegistry) {
    this.#servers = servers;
  }

  async execute(command: DirectCommand): Promise<HelperResponse> {
    const reference = command.changeRef;
    const registration = await this.#servers.getByServer(reference.serverId);
    if (!registration || !registration.enabled || registration.machineId !== reference.machineId) {
      throw new Error("changeRef does not resolve to an enabled pinned server");
    }
    const actionRegistration = {
      ...registration,
      certPath: registration.approverCertPath ?? "",
      keyPath: registration.approverKeyPath ?? "",
    };
    if (!registration.approverCertPath || !registration.approverKeyPath
      || !registration.approvalSigningKeyPath || !registration.approvalKeyId) {
      throw new Error("server registration has no model-external approver credentials");
    }
    const client = await HttpsOpsServerClient.create(actionRegistration);
    const status = await client.changeStatus({
      version: 1,
      requestId: randomUUID(),
      deadline: deadline(30),
      machineId: reference.machineId,
      targetId: reference.targetId,
      method: "change.status",
      changeId: reference.changeId,
    });
    if (!status.ok) return status;
    if (command.kind === "status") return status;
    const metadata = parseChangeMetadata(status.data);
    const action: ApprovalAction = command.kind;
    const approval = await signApprovalGrant({
      keyId: registration.approvalKeyId,
      privateKeyPath: registration.approvalSigningKeyPath,
      action,
      changeRef: reference,
      planHash: metadata.planHash,
      policyRevision: metadata.policyRevision,
    });
    return await client.changeAction({
      version: 1,
      requestId: randomUUID(),
      deadline: deadline(action === "reject" ? 30 : 9 * 60),
      machineId: reference.machineId,
      targetId: reference.targetId,
      action,
      changeId: reference.changeId,
      approval,
    });
  }
}

export type ApprovalCommandHandler = (command: DirectCommand) => Promise<HelperResponse>;
