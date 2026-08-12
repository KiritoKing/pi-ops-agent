import { isAbsolute, normalize } from "node:path";
import {
  parseMachineId,
  parseServerId,
  type MachineId,
  type ServerId,
} from "../shared/domain.js";
import { requireString } from "../shared/guards.js";
import { requireExactRecord } from "../shared/strict.js";
import { JsonFileStore } from "./json-store.js";

export interface ServerRegistration {
  serverId: ServerId;
  machineId: MachineId;
  baseUrl: string;
  caPath: string;
  certPath: string;
  keyPath: string;
  observerCertPath?: string;
  observerKeyPath?: string;
  coreReceiptKeyId?: string;
  coreReceiptPublicKeyPath?: string;
  pveReceiptKeyId?: string;
  pveReceiptPublicKeyPath?: string;
  approverCertPath?: string;
  approverKeyPath?: string;
  approvalSigningKeyPath?: string;
  approvalKeyId?: string;
  serverName?: string;
  enabled: boolean;
}

interface ServerRegistryDocument {
  version: 1;
  servers: ServerRegistration[];
}

function parseBaseUrl(value: unknown, label: string): string {
  const raw = requireString(value, label, { max: 2048 });
  const url = new URL(raw);
  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash) {
    throw new Error(`${label} must be an HTTPS origin without credentials, query, or fragment`);
  }
  if (url.pathname !== "/") throw new Error(`${label} must not contain a path`);
  return url.origin;
}

function parseAbsolutePath(value: unknown, label: string): string {
  const path = requireString(value, label, { max: 4096 });
  if (!isAbsolute(path) || normalize(path) !== path || path.includes("\0")
    || path.includes("\n") || path.includes("\r")) {
    throw new Error(`${label} must be a clean absolute path`);
  }
  return path;
}

export function parseServerRegistration(value: unknown, label = "server registration"): ServerRegistration {
  const input = requireExactRecord(value, label, [
    "serverId", "machineId", "baseUrl", "caPath", "certPath", "keyPath",
    "observerCertPath", "observerKeyPath",
    "coreReceiptKeyId", "coreReceiptPublicKeyPath", "pveReceiptKeyId", "pveReceiptPublicKeyPath",
    "approverCertPath", "approverKeyPath", "approvalSigningKeyPath", "approvalKeyId",
    "serverName", "enabled",
  ]);
  if (typeof input.enabled !== "boolean") throw new Error(`${label}.enabled must be a boolean`);
  const registration: ServerRegistration = {
    serverId: parseServerId(input.serverId, `${label}.serverId`),
    machineId: parseMachineId(input.machineId, `${label}.machineId`),
    baseUrl: parseBaseUrl(input.baseUrl, `${label}.baseUrl`),
    caPath: parseAbsolutePath(input.caPath, `${label}.caPath`),
    certPath: parseAbsolutePath(input.certPath, `${label}.certPath`),
    keyPath: parseAbsolutePath(input.keyPath, `${label}.keyPath`),
    enabled: input.enabled,
  };
  if (input.serverName !== undefined) {
    registration.serverName = requireString(input.serverName, `${label}.serverName`, { max: 253 });
  }
  if (input.observerCertPath !== undefined) {
    registration.observerCertPath = parseAbsolutePath(
      input.observerCertPath,
      `${label}.observerCertPath`,
    );
  }
  if (input.observerKeyPath !== undefined) {
    registration.observerKeyPath = parseAbsolutePath(
      input.observerKeyPath,
      `${label}.observerKeyPath`,
    );
  }
  if ((registration.observerCertPath === undefined)
    !== (registration.observerKeyPath === undefined)) {
    throw new Error(`${label} must configure both observer credential fields together`);
  }
  for (const [keyName, pathName] of [
    ["coreReceiptKeyId", "coreReceiptPublicKeyPath"],
    ["pveReceiptKeyId", "pveReceiptPublicKeyPath"],
  ] as const) {
    const keyValue = input[keyName];
    const pathValue = input[pathName];
    if ((keyValue === undefined) !== (pathValue === undefined)) {
      throw new Error(`${label} must configure ${keyName} and ${pathName} together`);
    }
    if (keyValue !== undefined && pathValue !== undefined) {
      registration[keyName] = requireString(keyValue, `${label}.${keyName}`, {
        min: 8,
        max: 160,
        pattern: /^[a-zA-Z0-9][a-zA-Z0-9._:-]{7,159}$/u,
      });
      registration[pathName] = parseAbsolutePath(pathValue, `${label}.${pathName}`);
    }
  }
  if (registration.coreReceiptKeyId !== undefined
    && registration.pveReceiptKeyId === registration.coreReceiptKeyId) {
    throw new Error(`${label} must use distinct core and PVE receipt key IDs`);
  }
  if (registration.coreReceiptPublicKeyPath !== undefined
    && registration.pveReceiptPublicKeyPath === registration.coreReceiptPublicKeyPath) {
    throw new Error(`${label} must use distinct core and PVE receipt public keys`);
  }
  if (input.approverCertPath !== undefined) {
    registration.approverCertPath = parseAbsolutePath(input.approverCertPath, `${label}.approverCertPath`);
  }
  if (input.approverKeyPath !== undefined) {
    registration.approverKeyPath = parseAbsolutePath(input.approverKeyPath, `${label}.approverKeyPath`);
  }
  if (input.approvalSigningKeyPath !== undefined) {
    registration.approvalSigningKeyPath = parseAbsolutePath(
      input.approvalSigningKeyPath,
      `${label}.approvalSigningKeyPath`,
    );
  }
  if (input.approvalKeyId !== undefined) {
    registration.approvalKeyId = requireString(input.approvalKeyId, `${label}.approvalKeyId`, {
      min: 8,
      max: 160,
      pattern: /^[a-zA-Z0-9][a-zA-Z0-9._:-]{7,159}$/u,
    });
  }
  const approvalValues = [
    registration.approverCertPath,
    registration.approverKeyPath,
    registration.approvalSigningKeyPath,
    registration.approvalKeyId,
  ];
  if (approvalValues.some((item) => item !== undefined)
    && approvalValues.some((item) => item === undefined)) {
    throw new Error(`${label} must configure all approver credential fields together`);
  }
  return registration;
}

function parseDocument(value: unknown): ServerRegistryDocument {
  const input = requireExactRecord(value, "server registry", ["version", "servers"]);
  if (input.version !== 1) throw new Error("unsupported server registry version");
  if (!Array.isArray(input.servers) || input.servers.length > 1024) {
    throw new Error("server registry.servers must contain at most 1024 entries");
  }
  const servers = input.servers.map((item, index) =>
    parseServerRegistration(item, `server registry.servers[${index}]`));
  const serverIds = new Set<string>();
  const machineIds = new Set<string>();
  for (const server of servers) {
    if (serverIds.has(server.serverId)) throw new Error(`duplicate serverId: ${server.serverId}`);
    if (machineIds.has(server.machineId)) throw new Error(`duplicate machineId: ${server.machineId}`);
    serverIds.add(server.serverId);
    machineIds.add(server.machineId);
  }
  return { version: 1, servers };
}

export class ServerRegistry {
  readonly #store: JsonFileStore<ServerRegistryDocument>;

  constructor(path: string) {
    this.#store = new JsonFileStore(path, parseDocument, () => ({ version: 1, servers: [] }));
  }

  async initialize(): Promise<void> {
    await this.#store.initialize();
  }

  async list(): Promise<ServerRegistration[]> {
    return (await this.#store.read()).servers;
  }

  async getByMachine(machineId: MachineId): Promise<ServerRegistration | undefined> {
    return (await this.list()).find((item) => item.machineId === machineId);
  }

  async getByServer(serverId: ServerId): Promise<ServerRegistration | undefined> {
    return (await this.list()).find((item) => item.serverId === serverId);
  }

  async register(registration: ServerRegistration): Promise<void> {
    const normalized = parseServerRegistration(registration);
    await this.#store.update((current) => {
      const conflict = current.servers.find((item) =>
        item.serverId === normalized.serverId || item.machineId === normalized.machineId);
      if (conflict && (conflict.serverId !== normalized.serverId
        || conflict.machineId !== normalized.machineId)) {
        throw new Error("serverId or machineId is already bound to a different registration");
      }
      return {
        version: 1,
        servers: [...current.servers.filter((item) => item.serverId !== normalized.serverId), normalized],
      };
    });
  }
}
