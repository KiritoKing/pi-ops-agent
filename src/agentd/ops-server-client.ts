import { readFile } from "node:fs/promises";
import { Agent as HttpsAgent, request as httpsRequest } from "node:https";
import {
  parseCapabilityDescriptor,
  parseRemoteResponse,
  parsePluginCatalog,
  parseServerIdentity,
  parseTargetDescriptors,
  type CapabilityDescriptor,
  type ChangeActionRequest,
  type ChangeStatusRequest,
  type InspectionRequest,
  type PrepareChangeRequest,
  type PluginCatalogEntry,
  type RemoteResponse,
  type ServerIdentity,
  type TargetDescriptor,
} from "../shared/server-protocol.js";
import type { ServerRegistration } from "./server-registry.js";

const MAX_RESPONSE_BYTES = 1024 * 1024;

export interface OpsServerClient {
  identity(signal?: AbortSignal): Promise<ServerIdentity>;
  capabilities(signal?: AbortSignal): Promise<CapabilityDescriptor>;
  targets(signal?: AbortSignal): Promise<TargetDescriptor[]>;
  plugins(signal?: AbortSignal): Promise<PluginCatalogEntry[]>;
  inspect(request: InspectionRequest, signal?: AbortSignal): Promise<RemoteResponse>;
  prepareChange(request: PrepareChangeRequest, signal?: AbortSignal): Promise<RemoteResponse>;
  changeStatus(request: ChangeStatusRequest, signal?: AbortSignal): Promise<RemoteResponse>;
  changeAction(request: ChangeActionRequest, signal?: AbortSignal): Promise<RemoteResponse>;
}

interface TlsMaterial {
  ca: Buffer;
  cert: Buffer;
  key: Buffer;
}

export class HttpsOpsServerClient implements OpsServerClient {
  readonly #registration: ServerRegistration;
  readonly #tls: TlsMaterial;
  readonly #agent: HttpsAgent;

  private constructor(registration: ServerRegistration, tls: TlsMaterial) {
    this.#registration = registration;
    this.#tls = tls;
    this.#agent = new HttpsAgent({
      keepAlive: true,
      keepAliveMsecs: 15_000,
      maxSockets: 8,
      maxFreeSockets: 2,
      timeout: 90_000,
    });
  }

  static async create(registration: ServerRegistration): Promise<HttpsOpsServerClient> {
    const [ca, cert, key] = await Promise.all([
      readFile(registration.caPath),
      readFile(registration.certPath),
      readFile(registration.keyPath),
    ]);
    return new HttpsOpsServerClient(registration, { ca, cert, key });
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

  async plugins(signal?: AbortSignal): Promise<PluginCatalogEntry[]> {
    return parsePluginCatalog(await this.#request("GET", "/v1/plugins", undefined, signal));
  }

  async inspect(request: InspectionRequest, signal?: AbortSignal): Promise<RemoteResponse> {
    return parseRemoteResponse(await this.#request("POST", "/v1/inspect", request, signal));
  }

  async prepareChange(request: PrepareChangeRequest, signal?: AbortSignal): Promise<RemoteResponse> {
    return parseRemoteResponse(await this.#request("POST", "/v1/changes", request, signal));
  }

  async changeStatus(request: ChangeStatusRequest, signal?: AbortSignal): Promise<RemoteResponse> {
    return parseRemoteResponse(await this.#request(
      "GET",
      `/v1/changes/${encodeURIComponent(request.changeId)}?requestId=${encodeURIComponent(request.requestId)}&deadline=${encodeURIComponent(request.deadline)}&machineId=${encodeURIComponent(request.machineId)}&targetId=${encodeURIComponent(request.targetId)}`,
      undefined,
      signal,
    ));
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
    return parseRemoteResponse(await this.#request(
      "POST",
      `/v1/changes/${encodeURIComponent(request.changeId)}/${request.action}`,
      body,
      signal,
    ));
  }

  close(): void {
    this.#agent.destroy();
  }

  async #request(
    method: "GET" | "POST",
    path: string,
    body: unknown,
    signal: AbortSignal | undefined,
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
      request.setTimeout(30_000, () => request.destroy(new Error("server request timed out")));
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
