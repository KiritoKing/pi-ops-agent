import { readFile } from "node:fs/promises";
import { Agent as HttpsAgent, request as httpsRequest } from "node:https";
import {
  parseCapabilityDescriptor,
  parseRemoteResponse,
  parseArtifactCatalog,
  parseServerIdentity,
  parseTargetDescriptors,
  type CapabilityDescriptor,
  type ChangeActionRequest,
  type ChangeStatusRequest,
  type InspectionRequest,
  type PrepareChangeRequest,
  type ArtifactDescriptor,
  type RemoteResponse,
  type ServerIdentity,
  type TargetDescriptor,
  type WorkloadCommandInspectionRequest,
} from "../shared/server-protocol.js";
import type { TargetId } from "../shared/domain.js";
import type { ServerRegistration } from "./server-registry.js";
import { verifyBrokerResponse, type BrokerDomain } from "../shared/broker-receipt.js";

const MAX_RESPONSE_BYTES = 1024 * 1024;
const DEFAULT_TRANSPORT_TIMEOUT_MS = 30_000;
const MAX_TRANSPORT_TIMEOUT_MS = 10 * 60_000;
const TRANSPORT_DEADLINE_GRACE_MS = 5_000;

export function transportTimeoutForDeadline(deadline: string, now = Date.now()): number {
  const deadlineMs = Date.parse(deadline);
  if (!Number.isFinite(deadlineMs)) return DEFAULT_TRANSPORT_TIMEOUT_MS;
  return Math.min(
    MAX_TRANSPORT_TIMEOUT_MS,
    Math.max(DEFAULT_TRANSPORT_TIMEOUT_MS, deadlineMs - now + TRANSPORT_DEADLINE_GRACE_MS),
  );
}

export interface OpsServerClient {
  identity(signal?: AbortSignal): Promise<ServerIdentity>;
  capabilities(signal?: AbortSignal): Promise<CapabilityDescriptor>;
  targets(signal?: AbortSignal): Promise<TargetDescriptor[]>;
  artifacts(targetId: TargetId, signal?: AbortSignal): Promise<ArtifactDescriptor[]>;
  inspect(request: InspectionRequest, signal?: AbortSignal): Promise<RemoteResponse>;
  workloadCommandInspect(
    request: WorkloadCommandInspectionRequest,
    signal?: AbortSignal,
  ): Promise<RemoteResponse>;
  prepareChange(request: PrepareChangeRequest, signal?: AbortSignal): Promise<RemoteResponse>;
  changeStatus(request: ChangeStatusRequest, signal?: AbortSignal): Promise<RemoteResponse>;
  changeAction(request: ChangeActionRequest, signal?: AbortSignal): Promise<RemoteResponse>;
}

interface TlsMaterial {
  ca: Buffer;
  cert: Buffer;
  key: Buffer;
}

interface ReceiptMaterial {
  core?: { keyId: string; publicKey: Buffer };
  pve?: { keyId: string; publicKey: Buffer };
}

export class HttpsOpsServerClient implements OpsServerClient {
  readonly #registration: ServerRegistration;
  readonly #tls: TlsMaterial;
  readonly #agent: HttpsAgent;
  readonly #receipts: ReceiptMaterial;

  private constructor(
    registration: ServerRegistration,
    tls: TlsMaterial,
    receipts: ReceiptMaterial,
  ) {
    this.#registration = registration;
    this.#tls = tls;
    this.#receipts = receipts;
    this.#agent = new HttpsAgent({
      keepAlive: true,
      keepAliveMsecs: 15_000,
      maxSockets: 8,
      maxFreeSockets: 2,
      timeout: MAX_TRANSPORT_TIMEOUT_MS,
    });
  }

  static async create(registration: ServerRegistration): Promise<HttpsOpsServerClient> {
    return await HttpsOpsServerClient.#createWithCredential(
      registration,
      registration.certPath,
      registration.keyPath,
    );
  }

  static async createObserver(registration: ServerRegistration): Promise<HttpsOpsServerClient> {
    if (registration.observerCertPath === undefined
      || registration.observerKeyPath === undefined) {
      throw new Error("server registration has no complete observer credentials");
    }
    return await HttpsOpsServerClient.#createWithCredential(
      registration,
      registration.observerCertPath,
      registration.observerKeyPath,
    );
  }

  static async #createWithCredential(
    registration: ServerRegistration,
    certPath: string,
    keyPath: string,
  ): Promise<HttpsOpsServerClient> {
    const [ca, cert, key, coreReceiptKey, pveReceiptKey] = await Promise.all([
      readFile(registration.caPath),
      readFile(certPath),
      readFile(keyPath),
      registration.coreReceiptPublicKeyPath === undefined
        ? Promise.resolve(undefined)
        : readFile(registration.coreReceiptPublicKeyPath),
      registration.pveReceiptPublicKeyPath === undefined
        ? Promise.resolve(undefined)
        : readFile(registration.pveReceiptPublicKeyPath),
    ]);
    return new HttpsOpsServerClient(registration, { ca, cert, key }, {
      ...(coreReceiptKey === undefined || registration.coreReceiptKeyId === undefined
        ? {}
        : { core: { keyId: registration.coreReceiptKeyId, publicKey: coreReceiptKey } }),
      ...(pveReceiptKey === undefined || registration.pveReceiptKeyId === undefined
        ? {}
        : { pve: { keyId: registration.pveReceiptKeyId, publicKey: pveReceiptKey } }),
    });
  }

  async identity(signal?: AbortSignal): Promise<ServerIdentity> {
    return parseServerIdentity(await this.#request("GET", "/v1/identity", undefined, signal));
  }

  async capabilities(signal?: AbortSignal): Promise<CapabilityDescriptor> {
    return parseCapabilityDescriptor(
      await this.#request("GET", "/v1/capabilities", undefined, signal),
    );
  }

  async targets(signal?: AbortSignal): Promise<TargetDescriptor[]> {
    return parseTargetDescriptors(await this.#request("GET", "/v1/targets", undefined, signal));
  }

  async artifacts(targetId: TargetId, signal?: AbortSignal): Promise<ArtifactDescriptor[]> {
    return parseArtifactCatalog(await this.#request(
      "GET",
      `/v1/artifacts?targetId=${encodeURIComponent(targetId)}`,
      undefined,
      signal,
    ));
  }

  async inspect(request: InspectionRequest, signal?: AbortSignal): Promise<RemoteResponse> {
    const response = parseRemoteResponse(await this.#request(
      "POST",
      "/v1/inspect",
      request,
      signal,
      transportTimeoutForDeadline(request.deadline),
    ));
    if (response.requestId !== request.requestId) {
      throw new Error("inspection response request ID does not match");
    }
    return response;
  }

  async workloadCommandInspect(
    request: WorkloadCommandInspectionRequest,
    signal?: AbortSignal,
  ): Promise<RemoteResponse> {
    const response = parseRemoteResponse(await this.#request(
      "POST",
      "/v1/workload-command-inspections",
      request,
      signal,
      transportTimeoutForDeadline(request.deadline),
    ));
    if (response.requestId !== request.requestId) {
      throw new Error("workload command inspection response request ID does not match");
    }
    const receipt = this.#receipts.core;
    if (receipt === undefined) {
      throw new Error("server registration has no pinned core broker receipt key");
    }
    verifyBrokerResponse(response, {
      keyId: receipt.keyId,
      domain: "core",
      requestId: request.requestId,
      method: "workload.command.inspect",
      serverId: this.#registration.serverId,
      machineId: request.machineId,
      targetId: request.targetId,
      changeId: "",
      pluginId: request.pluginId,
      pluginDigest: request.pluginDigest,
      profileKey: request.profileKey,
    }, receipt.publicKey);
    return response;
  }

  async prepareChange(request: PrepareChangeRequest, signal?: AbortSignal): Promise<RemoteResponse> {
    const response = parseRemoteResponse(await this.#request(
      "POST",
      "/v1/changes",
      request,
      signal,
      transportTimeoutForDeadline(request.deadline),
    ));
    if (response.requestId !== request.requestId) {
      throw new Error("prepare response request ID does not match");
    }
    return response;
  }

  async changeStatus(request: ChangeStatusRequest, signal?: AbortSignal): Promise<RemoteResponse> {
    const response = parseRemoteResponse(await this.#request(
      "GET",
      `/v1/changes/${encodeURIComponent(request.changeId)}?requestId=${encodeURIComponent(request.requestId)}&deadline=${encodeURIComponent(request.deadline)}&machineId=${encodeURIComponent(request.machineId)}&targetId=${encodeURIComponent(request.targetId)}`,
      undefined,
      signal,
      transportTimeoutForDeadline(request.deadline),
    ));
    const domain: BrokerDomain = request.changeId.startsWith("pve-change-") ? "pve" : "core";
    const receipt = this.#receipts[domain];
    if (receipt === undefined) {
      throw new Error(`server registration has no pinned ${domain} broker receipt key`);
    }
    verifyBrokerResponse(response, {
      keyId: receipt.keyId,
      domain,
      requestId: request.requestId,
      method: "change.status",
      serverId: this.#registration.serverId,
      machineId: request.machineId,
      targetId: request.targetId,
      changeId: request.changeId,
    }, receipt.publicKey);
    return response;
  }

  async changeAction(request: ChangeActionRequest, signal?: AbortSignal): Promise<RemoteResponse> {
    const body = {
      version: request.version,
      requestId: request.requestId,
      deadline: request.deadline,
      machineId: request.machineId,
      targetId: request.targetId,
      approval: request.approval,
    };
    const response = parseRemoteResponse(await this.#request(
      "POST",
      `/v1/changes/${encodeURIComponent(request.changeId)}/${request.action}`,
      body,
      signal,
      transportTimeoutForDeadline(request.deadline),
    ));
    const domain: BrokerDomain = request.changeId.startsWith("pve-change-") ? "pve" : "core";
    const receipt = this.#receipts[domain];
    if (receipt === undefined) {
      throw new Error(`server registration has no pinned ${domain} broker receipt key`);
    }
    const method = request.action === "approve"
      ? "change.approve" as const
      : request.action === "reject"
        ? "change.reject" as const
        : "change.rollback" as const;
    verifyBrokerResponse(response, {
      keyId: receipt.keyId,
      domain,
      requestId: request.requestId,
      method,
      serverId: this.#registration.serverId,
      machineId: request.machineId,
      targetId: request.targetId,
      changeId: request.changeId,
      planHash: request.approval.planHash,
    }, receipt.publicKey);
    return response;
  }

  close(): void {
    this.#agent.destroy();
  }

  async #request(
    method: "GET" | "POST",
    path: string,
    body: unknown,
    signal: AbortSignal | undefined,
    timeoutMs = DEFAULT_TRANSPORT_TIMEOUT_MS,
  ): Promise<unknown> {
    const url = new URL(path, this.#registration.baseUrl);
    const encoded = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
    return await new Promise<unknown>((resolve, reject) => {
      const request = httpsRequest(url, {
        method,
        agent: this.#agent,
        ca: this.#tls.ca,
        cert: this.#tls.cert,
        key: this.#tls.key,
        rejectUnauthorized: true,
        ...(this.#registration.serverName === undefined
          ? {}
          : { servername: this.#registration.serverName }),
        headers: encoded === undefined ? { accept: "application/json" } : {
          accept: "application/json",
          "content-type": "application/json",
          "content-length": String(encoded.length),
        },
        signal,
      }, (response) => {
        const chunks: Buffer[] = [];
        let received = 0;
        response.on("data", (chunk: Buffer | string) => {
          const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
          received += bytes.length;
          if (received > MAX_RESPONSE_BYTES) {
            request.destroy(new Error("server response exceeds 1 MiB"));
            return;
          }
          chunks.push(bytes);
        });
        response.once("end", () => {
          const status = response.statusCode ?? 0;
          if (status < 200 || status >= 300) {
            reject(new Error(`server returned HTTP ${status}`));
            return;
          }
          const contentType = response.headers["content-type"] ?? "";
          if (!contentType.toLowerCase().startsWith("application/json")) {
            reject(new Error("server response is not application/json"));
            return;
          }
          try {
            resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown);
          } catch {
            reject(new Error("server returned invalid JSON"));
          }
        });
      });
      request.setTimeout(timeoutMs, () => request.destroy(new Error("server request timed out")));
      request.once("error", reject);
      if (encoded !== undefined) request.end(encoded);
      else request.end();
    });
  }
}

export type OpsServerClientFactory = (registration: ServerRegistration) => Promise<OpsServerClient>;

export const createHttpsOpsServerClient: OpsServerClientFactory = async (registration) =>
  await HttpsOpsServerClient.create(registration);

interface PooledClient {
  fingerprint: string;
  client: HttpsOpsServerClient;
}

export class ManagedOpsServerPool {
  readonly #clients = new Map<string, Promise<PooledClient>>();

  async get(registration: ServerRegistration): Promise<OpsServerClient> {
    const fingerprint = JSON.stringify(registration);
    const existing = this.#clients.get(registration.serverId);
    if (existing) {
      const pooled = await existing;
      if (pooled.fingerprint === fingerprint) return pooled.client;
      pooled.client.close();
      this.#clients.delete(registration.serverId);
    }
    const created = HttpsOpsServerClient.create(registration).then((client) => ({
      fingerprint,
      client,
    }));
    this.#clients.set(registration.serverId, created);
    try {
      return (await created).client;
    } catch (error) {
      this.#clients.delete(registration.serverId);
      throw error;
    }
  }

  close(): void {
    for (const pending of this.#clients.values()) {
      void pending.then(({ client }) => client.close(), () => undefined);
    }
    this.#clients.clear();
  }
}
