import { isAbsolute, normalize, posix } from "node:path";
import { isRecord, requireRecord, requireString } from "./guards.js";

const PLUGIN_ID = /^adapter\.[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?$/;
const VERSION = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$/;
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const SECRET_NAME = /^[a-z][a-zA-Z0-9]{0,63}$/;

export type AdapterSetupOperation =
  | "serviceAccount.create"
  | "systemdUnit.install"
  | "credential.install"
  | "supplementaryGroup.add"
  | "config.write"
  | "service.start";

export interface AdapterCapabilities {
  inboundText: boolean;
  verifiedSender: boolean;
  privateConversation: boolean;
  proactiveDelivery: boolean;
  approvalIntent: boolean;
  streaming: boolean;
}

export interface AdapterPluginManifest {
  schemaVersion: 1;
  id: string;
  kind: "im-adapter";
  version: string;
  publisher: string;
  coreProtocol: 1;
  entrypoint: string;
  description: string;
  capabilities: AdapterCapabilities;
  secrets: readonly string[];
  setupOperations: readonly AdapterSetupOperation[];
}

export interface PluginCatalogEntry {
  manifest: AdapterPluginManifest;
  packagePath: string;
  digest: string;
  signaturePath: string;
}

function requireExactKeys(
  input: Record<string, unknown>,
  label: string,
  allowed: readonly string[],
): void {
  const allowedSet = new Set(allowed);
  const unknown = Object.keys(input).filter((key) => !allowedSet.has(key));
  if (unknown.length > 0) throw new Error(`${label} contains unknown fields: ${unknown.join(", ")}`);
}

function requireBoolean(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") throw new Error(`${label} must be a boolean`);
  return value;
}

function requireRelativePackagePath(value: unknown, label: string): string {
  const path = requireString(value, label, { min: 1, max: 512 });
  const normalized = normalize(path).replaceAll("\\", "/");
  if (isAbsolute(path) || normalized === ".." || normalized.startsWith("../")) {
    throw new Error(`${label} must stay inside the plugin package`);
  }
  if (normalized !== posix.normalize(normalized) || normalized.includes("\0")) {
    throw new Error(`${label} must be a clean relative path`);
  }
  return normalized;
}

function parseCapabilities(value: unknown): AdapterCapabilities {
  const input = requireRecord(value, "plugin capabilities");
  const keys = [
    "inboundText",
    "verifiedSender",
    "privateConversation",
    "proactiveDelivery",
    "approvalIntent",
    "streaming",
  ] as const;
  requireExactKeys(input, "plugin capabilities", keys);
  return {
    inboundText: requireBoolean(input.inboundText, "capabilities.inboundText"),
    verifiedSender: requireBoolean(input.verifiedSender, "capabilities.verifiedSender"),
    privateConversation: requireBoolean(
      input.privateConversation,
      "capabilities.privateConversation",
    ),
    proactiveDelivery: requireBoolean(
      input.proactiveDelivery,
      "capabilities.proactiveDelivery",
    ),
    approvalIntent: requireBoolean(input.approvalIntent, "capabilities.approvalIntent"),
    streaming: requireBoolean(input.streaming, "capabilities.streaming"),
  };
}

function parseStringArray(
  value: unknown,
  label: string,
  validate: (entry: string) => boolean,
  maxItems: number,
): string[] {
  if (!Array.isArray(value) || value.length > maxItems) {
    throw new Error(`${label} must be an array with at most ${maxItems} items`);
  }
  const result = value.map((entry, index) => {
    const text = requireString(entry, `${label}[${index}]`, { min: 1, max: 128 });
    if (!validate(text)) throw new Error(`${label}[${index}] is unsupported`);
    return text;
  });
  if (new Set(result).size !== result.length) throw new Error(`${label} contains duplicates`);
  return result;
}

const SETUP_OPERATIONS = new Set<AdapterSetupOperation>([
  "serviceAccount.create",
  "systemdUnit.install",
  "credential.install",
  "supplementaryGroup.add",
  "config.write",
  "service.start",
]);

export function parseAdapterPluginManifest(value: unknown): AdapterPluginManifest {
  const input = requireRecord(value, "plugin manifest");
  requireExactKeys(input, "plugin manifest", [
    "schemaVersion",
    "id",
    "kind",
    "version",
    "publisher",
    "coreProtocol",
    "entrypoint",
    "description",
    "capabilities",
    "secrets",
    "setupOperations",
  ]);
  if (input.schemaVersion !== 1 || input.kind !== "im-adapter" || input.coreProtocol !== 1) {
    throw new Error("plugin manifest has an unsupported schema, kind, or core protocol");
  }
  const id = requireString(input.id, "plugin id", { max: 72, pattern: PLUGIN_ID });
  const version = requireString(input.version, "plugin version", { max: 96, pattern: VERSION });
  const secrets = parseStringArray(input.secrets, "plugin secrets", (item) => SECRET_NAME.test(item), 16);
  const setupOperations = parseStringArray(
    input.setupOperations,
    "plugin setupOperations",
    (item) => SETUP_OPERATIONS.has(item as AdapterSetupOperation),
    SETUP_OPERATIONS.size,
  ) as AdapterSetupOperation[];
  if (secrets.length > 0 && !setupOperations.includes("credential.install")) {
    throw new Error("plugins declaring secrets must request credential.install");
  }
  return {
    schemaVersion: 1,
    id,
    kind: "im-adapter",
    version,
    publisher: requireString(input.publisher, "plugin publisher", { min: 1, max: 160 }),
    coreProtocol: 1,
    entrypoint: requireRelativePackagePath(input.entrypoint, "plugin entrypoint"),
    description: requireString(input.description, "plugin description", { min: 1, max: 2048 }),
    capabilities: parseCapabilities(input.capabilities),
    secrets,
    setupOperations,
  };
}

export function parsePluginCatalogEntry(value: unknown): PluginCatalogEntry {
  const input = requireRecord(value, "plugin catalog entry");
  requireExactKeys(input, "plugin catalog entry", [
    "manifest",
    "packagePath",
    "digest",
    "signaturePath",
  ]);
  const packagePath = requireString(input.packagePath, "plugin packagePath", { min: 1, max: 4096 });
  const signaturePath = requireString(input.signaturePath, "plugin signaturePath", {
    min: 1,
    max: 4096,
  });
  if (!isAbsolute(packagePath) || !isAbsolute(signaturePath)) {
    throw new Error("plugin package and signature paths must be absolute trusted catalog paths");
  }
  return {
    manifest: parseAdapterPluginManifest(input.manifest),
    packagePath,
    digest: requireString(input.digest, "plugin digest", { pattern: SHA256 }),
    signaturePath,
  };
}

export function isAdapterPluginManifest(value: unknown): value is AdapterPluginManifest {
  if (!isRecord(value)) return false;
  try {
    parseAdapterPluginManifest(value);
    return true;
  } catch {
    return false;
  }
}
