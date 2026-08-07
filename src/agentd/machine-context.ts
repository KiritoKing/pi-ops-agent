import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import {
  parseMachineId,
  parseServerId,
  type MachineId,
  type ServerId,
  type TargetId,
} from "../shared/domain.js";
import { requireString } from "../shared/guards.js";
import {
  parseCapabilityDescriptor,
  parseTargetDescriptors,
  type CapabilityDescriptor,
  type TargetDescriptor,
} from "../shared/server-protocol.js";
import { requireExactRecord } from "../shared/strict.js";
import type { OpsServerClient } from "./ops-server-client.js";
import type { ServerRegistration } from "./server-registry.js";

export interface MachineContext {
  version: 1;
  serverId: ServerId;
  machineId: MachineId;
  machineName: string;
  serverAccount: string;
  capabilities: CapabilityDescriptor;
  targets: TargetDescriptor[];
  refreshedAt: string;
}

function parseMachineContext(value: unknown): MachineContext {
  const input = requireExactRecord(value, "machine context", [
    "version", "serverId", "machineId", "machineName", "serverAccount",
    "capabilities", "targets", "refreshedAt",
  ]);
  if (input.version !== 1) throw new Error("unsupported machine context version");
  const refreshedAt = requireString(input.refreshedAt, "machine context.refreshedAt", { max: 64 });
  if (!Number.isFinite(Date.parse(refreshedAt))) {
    throw new Error("machine context.refreshedAt must be an ISO date");
  }
  return {
    version: 1,
    serverId: parseServerId(input.serverId, "machine context.serverId"),
    machineId: parseMachineId(input.machineId, "machine context.machineId"),
    machineName: requireString(input.machineName, "machine context.machineName", { max: 256 }),
    serverAccount: requireString(input.serverAccount, "machine context.serverAccount", { max: 128 }),
    capabilities: parseCapabilityDescriptor(input.capabilities),
    targets: parseTargetDescriptors(input.targets),
    refreshedAt,
  };
}

export class MachineContextStore {
  readonly #directory: string;

  constructor(directory: string) {
    this.#directory = directory;
  }

  async initialize(): Promise<void> {
    await mkdir(this.#directory, { recursive: true, mode: 0o750 });
  }

  async read(machineId: MachineId): Promise<MachineContext | undefined> {
    try {
      const value = JSON.parse(await readFile(this.#path(machineId), "utf8")) as unknown;
      const context = parseMachineContext(value);
      if (context.machineId !== machineId) throw new Error("machine context path/id mismatch");
      return context;
    } catch (error) {
      if (error instanceof Error && "code" in error && error.code === "ENOENT") return undefined;
      throw error;
    }
  }

  async require(machineId: MachineId): Promise<MachineContext> {
    const context = await this.read(machineId);
    if (!context) throw new Error(`machine context is unavailable: ${machineId}`);
    return context;
  }

  async refresh(
    registration: ServerRegistration,
    client: OpsServerClient,
    signal?: AbortSignal,
  ): Promise<MachineContext> {
    const identity = await client.identity(signal);
    if (identity.serverId !== registration.serverId || identity.machineId !== registration.machineId) {
      throw new Error("server identity does not match its pinned registration");
    }
    const [capabilities, targets] = await Promise.all([
      client.capabilities(signal),
      client.targets(signal),
    ]);
    const context: MachineContext = {
      version: 1,
      serverId: identity.serverId,
      machineId: identity.machineId,
      machineName: identity.machineName,
      serverAccount: identity.account,
      capabilities,
      targets,
      refreshedAt: new Date().toISOString(),
    };
    await this.#write(context);
    return context;
  }

  requireTarget(context: MachineContext, targetId: TargetId): TargetDescriptor {
    const target = context.targets.find((item) => item.targetId === targetId);
    if (!target) throw new Error(`target is not registered for machine ${context.machineId}: ${targetId}`);
    return target;
  }

  #path(machineId: MachineId): string {
    return join(this.#directory, machineId, "context.json");
  }

  async #write(context: MachineContext): Promise<void> {
    const directory = join(this.#directory, context.machineId);
    const path = join(directory, "context.json");
    const temporary = `${path}.tmp-${process.pid}-${randomUUID()}`;
    await mkdir(directory, { recursive: true, mode: 0o750 });
    await writeFile(temporary, `${JSON.stringify(context, undefined, 2)}\n`, {
      encoding: "utf8",
      mode: 0o600,
    });
    await rename(temporary, path);
  }
}
