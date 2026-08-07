import { isAbsolute, normalize, posix } from "node:path";
import { isRecord, requireInteger, requireRecord, requireString } from "./guards.js";

const ADAPTER_ID = /^adapter\.[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?$/;
const WORKLOAD_ID = /^workload\.[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?$/;
const VERSION = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$/;
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const SECRET_NAME = /^[a-z][a-zA-Z0-9]{0,63}$/;
const ADAPTER_ENTRYPOINT = /^[A-Za-z0-9._/-]+\.mjs$/;
const IMAGE_REPOSITORY = /^[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]{1,5})?(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)+$/;
const CONTAINER_NAME = /^ops-agent-[a-z0-9][a-z0-9_.-]{0,53}$/;
const CONTAINER_USER = /^[1-9][0-9]{0,9}:[1-9][0-9]{0,9}$/;
const PROCESS_COMMAND = /^[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}$/;
const ENVIRONMENT_NAME = /^[A-Z_][A-Z0-9_]{0,63}$/;
const FILE_MODE = /^0[0-7]{3}$/;

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

export interface WorkloadResources {
  memoryBytes: number;
  nanoCpus: number;
  pidsLimit: number;
  shmBytes: number;
}

export interface WorkloadDirectory {
  path: string;
  mode: string;
}

export interface WorkloadFile {
  source: string;
  path: string;
  mode: string;
}

export interface ContainerExecCheck {
  argv: readonly string[];
  outputContains: string;
}

export interface WorkloadProcessPolicy {
  runtimeUser: string;
  allowedRuntimeCommands: readonly string[];
  requiredRuntimeCommands: readonly string[];
  allowedRootCommands: readonly string[];
}

export interface ManagedWorkload {
  runtime: "docker";
  imageRepository: string;
  imageDigest: string;
  containerName: string;
  containerCommand: readonly string[];
  expectedEntrypoint: readonly string[];
  expectedUser: string;
  processPolicy: WorkloadProcessPolicy;
  containerPort: number;
  hostPort: number;
  dataMountTarget: string;
  uid: number;
  gid: number;
  resources: WorkloadResources;
  capAdd: readonly string[];
  literalEnvironment: Readonly<Record<string, string>>;
  credentialEnvironment: Readonly<Record<string, string>>;
  directories: readonly WorkloadDirectory[];
  files: readonly WorkloadFile[];
  containerExecChecks: readonly ContainerExecCheck[];
}

export interface ManagedWorkloadPluginManifest {
  schemaVersion: 2;
  id: string;
  kind: "managed-workload";
  version: string;
  publisher: string;
  coreProtocol: 1;
  description: string;
  workload: ManagedWorkload;
}

export type PluginManifest = AdapterPluginManifest | ManagedWorkloadPluginManifest;

export interface PluginCatalogEntry {
  manifest: PluginManifest;
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
  const missing = allowed.filter((key) => !Object.hasOwn(input, key) || input[key] === null);
  if (missing.length > 0) throw new Error(`${label} is missing required fields: ${missing.join(", ")}`);
}

function requireBoolean(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") throw new Error(`${label} must be a boolean`);
  return value;
}

function requireRelativePackagePath(value: unknown, label: string): string {
  const packagePath = requireString(value, label, { min: 1, max: 512 });
  const portable = packagePath.replaceAll("\\", "/");
  const normalized = normalize(packagePath).replaceAll("\\", "/");
  if (isAbsolute(packagePath) || normalized === ".." || normalized.startsWith("../")) {
    throw new Error(`${label} must stay inside the plugin package`);
  }
  if (packagePath.includes("\\") || portable !== normalized || normalized !== posix.normalize(normalized) || normalized.includes("\0")) {
    throw new Error(`${label} must be a clean relative path`);
  }
  return normalized;
}

function requireAdapterEntrypoint(value: unknown): string {
  const entrypoint = requireRelativePackagePath(value, "plugin entrypoint");
  if (!ADAPTER_ENTRYPOINT.test(entrypoint) || entrypoint.split("/").some((segment) =>
    segment === "" || segment === "." || segment === "..")) {
    throw new Error("plugin entrypoint must be a normalized .mjs archive path");
  }
  return entrypoint;
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
    privateConversation: requireBoolean(input.privateConversation, "capabilities.privateConversation"),
    proactiveDelivery: requireBoolean(input.proactiveDelivery, "capabilities.proactiveDelivery"),
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
    const text = requireString(entry, `${label}[${index}]`, { min: 1, max: 512 });
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

const SAFE_CONTAINER_CAPABILITIES = new Set([
  "CHOWN",
  "DAC_OVERRIDE",
  "FOWNER",
  "FSETID",
  "KILL",
  "NET_BIND_SERVICE",
  "SETGID",
  "SETUID",
]);

export function parseAdapterPluginManifest(value: unknown): AdapterPluginManifest {
  const input = requireRecord(value, "plugin manifest");
  requireExactKeys(input, "plugin manifest", [
    "schemaVersion", "id", "kind", "version", "publisher", "coreProtocol", "entrypoint",
    "description", "capabilities", "secrets", "setupOperations",
  ]);
  if (input.schemaVersion !== 1 || input.kind !== "im-adapter" || input.coreProtocol !== 1) {
    throw new Error("plugin manifest has an unsupported schema, kind, or core protocol");
  }
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
    id: requireString(input.id, "plugin id", { max: 72, pattern: ADAPTER_ID }),
    kind: "im-adapter",
    version: requireString(input.version, "plugin version", { max: 96, pattern: VERSION }),
    publisher: requireString(input.publisher, "plugin publisher", { min: 1, max: 160 }),
    coreProtocol: 1,
    entrypoint: requireAdapterEntrypoint(input.entrypoint),
    description: requireString(input.description, "plugin description", { min: 1, max: 2048 }),
    capabilities: parseCapabilities(input.capabilities),
    secrets,
    setupOperations,
  };
}

export function parseManagedWorkloadPluginManifest(value: unknown): ManagedWorkloadPluginManifest {
  const input = requireRecord(value, "plugin manifest");
  requireExactKeys(input, "plugin manifest", [
    "schemaVersion", "id", "kind", "version", "publisher", "coreProtocol", "description", "workload",
  ]);
  if (input.schemaVersion !== 2 || input.kind !== "managed-workload" || input.coreProtocol !== 1) {
    throw new Error("plugin manifest has an unsupported schema, kind, or core protocol");
  }
  return {
    schemaVersion: 2,
    id: requireString(input.id, "plugin id", { max: 72, pattern: WORKLOAD_ID }),
    kind: "managed-workload",
    version: requireString(input.version, "plugin version", { max: 96, pattern: VERSION }),
    publisher: requireString(input.publisher, "plugin publisher", { min: 1, max: 160 }),
    coreProtocol: 1,
    description: requireString(input.description, "plugin description", { min: 1, max: 2048 }),
    workload: parseManagedWorkload(input.workload),
  };
}

export function parsePluginManifest(value: unknown): PluginManifest {
  const input = requireRecord(value, "plugin manifest");
  if (input.schemaVersion === 1) return parseAdapterPluginManifest(input);
  if (input.schemaVersion === 2) return parseManagedWorkloadPluginManifest(input);
  throw new Error("plugin manifest has an unsupported schema version");
}

function parseManagedWorkload(value: unknown): ManagedWorkload {
  const input = requireRecord(value, "managed workload");
  requireExactKeys(input, "managed workload", [
    "runtime", "imageRepository", "imageDigest", "containerName", "containerCommand", "expectedEntrypoint",
    "expectedUser", "processPolicy", "containerPort", "hostPort", "dataMountTarget", "uid", "gid", "resources", "capAdd",
    "literalEnvironment", "credentialEnvironment", "directories", "files", "containerExecChecks",
  ]);
  if (input.runtime !== "docker") throw new Error("managed workload runtime must be docker");
  const dataMountTarget = requireContainerPath(input.dataMountTarget, "workload.dataMountTarget");
  if (dataMountTarget === "/") throw new Error("workload.dataMountTarget cannot be the container root");
  const literalEnvironment = parseEnvironmentMap(input.literalEnvironment, "workload.literalEnvironment", 32);
  for (const name of Object.keys(literalEnvironment)) {
    if (looksSensitiveEnvironment(name)) {
      throw new Error("literal environment cannot contain secret-like names");
    }
  }
  const credentialEnvironment = parseEnvironmentMap(
    input.credentialEnvironment,
    "workload.credentialEnvironment",
    16,
    SECRET_NAME,
  );
  const environmentTargets = [...Object.keys(literalEnvironment), ...Object.values(credentialEnvironment)];
  if (new Set(environmentTargets).size !== environmentTargets.length) {
    throw new Error("managed workload environment targets must be unique");
  }
  const capAdd = parseStringArray(
    input.capAdd,
    "workload.capAdd",
    (item) => SAFE_CONTAINER_CAPABILITIES.has(item),
    SAFE_CONTAINER_CAPABILITIES.size,
  );
  const directories = parseDirectories(input.directories, dataMountTarget);
  const files = parseFiles(input.files, dataMountTarget);
  const targets = [...directories.map((entry) => entry.path), ...files.map((entry) => entry.path)];
  if (new Set(targets).size !== targets.length) throw new Error("managed workload contains duplicate static paths");
  const uid = requireInteger(input.uid, "workload.uid", 1, 65535);
  const gid = requireInteger(input.gid, "workload.gid", 1, 65535);
  const expectedUser = requireString(input.expectedUser, "workload.expectedUser", { max: 64 });
  if (expectedUser !== "root" && !CONTAINER_USER.test(expectedUser)) {
    throw new Error("workload.expectedUser must be root or a numeric uid:gid");
  }
  if (expectedUser !== "root" && expectedUser !== `${uid}:${gid}`) {
    throw new Error("workload.expectedUser must be root or match uid:gid");
  }
  const processPolicy = parseProcessPolicy(input.processPolicy, expectedUser, `${uid}:${gid}`);
  return {
    runtime: "docker",
    imageRepository: requireString(input.imageRepository, "workload.imageRepository", {
      min: 1, max: 255, pattern: IMAGE_REPOSITORY,
    }),
    imageDigest: requireString(input.imageDigest, "workload.imageDigest", { pattern: SHA256 }),
    containerName: requireString(input.containerName, "workload.containerName", {
      pattern: CONTAINER_NAME,
    }),
    containerCommand: parseArgv(input.containerCommand, "workload.containerCommand", 32),
    expectedEntrypoint: parseExpectedEntrypoint(input.expectedEntrypoint),
    expectedUser,
    processPolicy,
    containerPort: requireInteger(input.containerPort, "workload.containerPort", 1, 65535),
    hostPort: requireInteger(input.hostPort, "workload.hostPort", 1, 65535),
    dataMountTarget,
    uid,
    gid,
    resources: parseResources(input.resources),
    capAdd,
    literalEnvironment,
    credentialEnvironment,
    directories,
    files,
    containerExecChecks: parseContainerExecChecks(input.containerExecChecks),
  };
}

function parseProcessPolicy(
  value: unknown,
  expectedUser: string,
  runtimeUser: string,
): WorkloadProcessPolicy {
  const input = requireRecord(value, "managed workload process policy");
  requireExactKeys(input, "managed workload process policy", [
    "runtimeUser", "allowedRuntimeCommands", "requiredRuntimeCommands", "allowedRootCommands",
  ]);
  const parsedRuntimeUser = requireString(input.runtimeUser, "processPolicy.runtimeUser", {
    max: 64, pattern: CONTAINER_USER,
  });
  if (parsedRuntimeUser !== runtimeUser) throw new Error("processPolicy.runtimeUser must match uid:gid");
  const allowedRuntimeCommands = parseStringArray(
    input.allowedRuntimeCommands,
    "processPolicy.allowedRuntimeCommands",
    (item) => PROCESS_COMMAND.test(item),
    32,
  );
  const requiredRuntimeCommands = parseStringArray(
    input.requiredRuntimeCommands,
    "processPolicy.requiredRuntimeCommands",
    (item) => PROCESS_COMMAND.test(item),
    16,
  );
  const allowedRootCommands = parseStringArray(
    input.allowedRootCommands,
    "processPolicy.allowedRootCommands",
    (item) => PROCESS_COMMAND.test(item),
    32,
  );
  if (allowedRuntimeCommands.length === 0 || requiredRuntimeCommands.length === 0 ||
    requiredRuntimeCommands.some((command) => !allowedRuntimeCommands.includes(command))) {
    throw new Error("required runtime commands must be a non-empty subset of allowed runtime commands");
  }
  if (expectedUser === "root" && allowedRootCommands.length === 0) {
    throw new Error("root-initialized workloads must allow bounded root supervisor commands");
  }
  if (expectedUser !== "root" && allowedRootCommands.length !== 0) {
    throw new Error("non-root workloads cannot allow root processes");
  }
  return { runtimeUser: parsedRuntimeUser, allowedRuntimeCommands, requiredRuntimeCommands, allowedRootCommands };
}

function parseResources(value: unknown): WorkloadResources {
  const input = requireRecord(value, "managed workload resources");
  requireExactKeys(input, "managed workload resources", ["memoryBytes", "nanoCpus", "pidsLimit", "shmBytes"]);
  const memoryBytes = requireInteger(input.memoryBytes, "resources.memoryBytes", 64 * 1024 * 1024, 128 * 1024 * 1024 * 1024);
  const shmBytes = requireInteger(input.shmBytes, "resources.shmBytes", 1024 * 1024, 16 * 1024 * 1024 * 1024);
  if (shmBytes > memoryBytes) throw new Error("resources.shmBytes cannot exceed memoryBytes");
  return {
    memoryBytes,
    nanoCpus: requireInteger(input.nanoCpus, "resources.nanoCpus", 100_000_000, 64_000_000_000),
    pidsLimit: requireInteger(input.pidsLimit, "resources.pidsLimit", 16, 65536),
    shmBytes,
  };
}

function parseEnvironmentMap(
  value: unknown,
  label: string,
  maximum: number,
  keyPattern: RegExp = ENVIRONMENT_NAME,
): Record<string, string> {
  const input = requireRecord(value, label);
  const entries = Object.entries(input);
  if (entries.length > maximum) throw new Error(`${label} contains too many entries`);
  return Object.fromEntries(entries.map(([key, rawValue]) => {
    if (!keyPattern.test(key)) throw new Error(`${label} contains an invalid key`);
    const text = requireString(rawValue, `${label}.${key}`, { max: 512 });
    if (containsForbiddenTextCharacter(text)) throw new Error(`${label}.${key} contains a forbidden character`);
    if (keyPattern === SECRET_NAME && !ENVIRONMENT_NAME.test(text)) {
      throw new Error(`${label}.${key} must target a valid environment name`);
    }
    return [key, text];
  }));
}

function parseDirectories(value: unknown, mount: string): WorkloadDirectory[] {
  if (!Array.isArray(value) || value.length > 64) throw new Error("workload.directories must contain at most 64 entries");
  return value.map((entry, index) => {
    const input = requireRecord(entry, `workload.directories[${index}]`);
    requireExactKeys(input, `workload.directories[${index}]`, ["path", "mode"]);
    return {
      path: requirePathWithinMount(input.path, `workload.directories[${index}].path`, mount),
      mode: requireMode(input.mode, `workload.directories[${index}].mode`, true),
    };
  });
}

function parseFiles(value: unknown, mount: string): WorkloadFile[] {
  if (!Array.isArray(value) || value.length > 64) throw new Error("workload.files must contain at most 64 entries");
  return value.map((entry, index) => {
    const input = requireRecord(entry, `workload.files[${index}]`);
    requireExactKeys(input, `workload.files[${index}]`, ["source", "path", "mode"]);
    const source = requireRelativePackagePath(input.source, `workload.files[${index}].source`);
    if (source === "manifest.json") throw new Error("managed workload cannot install its manifest as a static file");
    return {
      source,
      path: requirePathWithinMount(input.path, `workload.files[${index}].path`, mount),
      mode: requireMode(input.mode, `workload.files[${index}].mode`, false),
    };
  });
}

function parseContainerExecChecks(value: unknown): ContainerExecCheck[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > 16) {
    throw new Error("workload.containerExecChecks must contain between 1 and 16 entries");
  }
  return value.map((entry, index) => {
    const input = requireRecord(entry, `workload.containerExecChecks[${index}]`);
    requireExactKeys(input, `workload.containerExecChecks[${index}]`, ["argv", "outputContains"]);
    const argv = parseArgv(input.argv, `workload.containerExecChecks[${index}].argv`, 32);
    const executable = posix.basename(argv[0] ?? "");
    if (["sh", "bash", "dash", "zsh", "env"].includes(executable)) {
      throw new Error("managed workload checks cannot invoke a shell or env launcher");
    }
    const outputContains = requireString(input.outputContains, `workload.containerExecChecks[${index}].outputContains`, {
      min: 1, max: 1024,
    });
    if (containsForbiddenTextCharacter(outputContains)) throw new Error("check outputContains contains a forbidden character");
    return { argv, outputContains };
  });
}

function parseArgv(value: unknown, label: string, maximum: number): string[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > maximum) {
    throw new Error(`${label} must contain between 1 and ${maximum} arguments`);
  }
  const values = value.map((entry, index) => {
    const argument = requireString(entry, `${label}[${index}]`, { min: 1, max: 512 });
    if (containsForbiddenTextCharacter(argument)) throw new Error(`${label}[${index}] contains a forbidden character`);
    return argument;
  });
  if (values.reduce((total, argument) => total + Buffer.byteLength(argument), 0) > 4096) {
    throw new Error(`${label} exceeds its total size limit`);
  }
  return values;
}

function parseExpectedEntrypoint(value: unknown): string[] {
  const entrypoint = parseArgv(value, "workload.expectedEntrypoint", 16);
  requireContainerPath(entrypoint[0], "workload.expectedEntrypoint[0]");
  return entrypoint;
}

function requireContainerPath(value: unknown, label: string): string {
  const containerPath = requireString(value, label, { min: 2, max: 512 });
  if (!posix.isAbsolute(containerPath) || posix.normalize(containerPath) !== containerPath ||
      containerPath.includes("\\") || containsForbiddenTextCharacter(containerPath)) {
    throw new Error(`${label} must be a clean absolute container path`);
  }
  return containerPath;
}

function containsForbiddenTextCharacter(value: string): boolean {
  return value.includes("\0") || value.includes("\r") || value.includes("\n");
}

function requirePathWithinMount(value: unknown, label: string, mount: string): string {
  const containerPath = requireContainerPath(value, label);
  if (containerPath === mount || !containerPath.startsWith(`${mount}/`)) {
    throw new Error(`${label} must stay below the managed data mount`);
  }
  return containerPath;
}

function requireMode(value: unknown, label: string, directory: boolean): string {
  const mode = requireString(value, label, { pattern: FILE_MODE });
  const numeric = Number.parseInt(mode, 8);
  const hasOwnerAccess = directory ? (numeric & 0o500) === 0o500 : (numeric & 0o400) === 0o400;
  if ((numeric & 0o022) !== 0 || !hasOwnerAccess) throw new Error(`${label} is not a safe static mode`);
  return mode;
}

function looksSensitiveEnvironment(name: string): boolean {
  return ["KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL"].some((marker) => name.includes(marker));
}

export function parsePluginCatalogEntry(value: unknown): PluginCatalogEntry {
  const input = requireRecord(value, "plugin catalog entry");
  requireExactKeys(input, "plugin catalog entry", ["manifest", "packagePath", "digest", "signaturePath"]);
  const packagePath = requireString(input.packagePath, "plugin packagePath", { min: 1, max: 4096 });
  const signaturePath = requireString(input.signaturePath, "plugin signaturePath", { min: 1, max: 4096 });
  if (!isAbsolute(packagePath) || !isAbsolute(signaturePath)) {
    throw new Error("plugin package and signature paths must be absolute trusted catalog paths");
  }
  return {
    manifest: parsePluginManifest(input.manifest),
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

export function isManagedWorkloadPluginManifest(value: unknown): value is ManagedWorkloadPluginManifest {
  if (!isRecord(value)) return false;
  try {
    parseManagedWorkloadPluginManifest(value);
    return true;
  } catch {
    return false;
  }
}
