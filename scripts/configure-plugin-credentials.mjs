import { createHash } from "node:crypto";
import {
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

const args = process.argv.slice(2);
const options = new Map();
let replace = false;
for (let index = 0; index < args.length;) {
  if (args[index] === "--replace") {
    if (replace) fail("Duplicate --replace option.");
    replace = true;
    index += 1;
    continue;
  }
  const key = args[index];
  const value = args[index + 1];
  if (!key?.startsWith("--") || value === undefined || options.has(key)) fail("Invalid plugin credential arguments.");
  options.set(key, value);
  index += 2;
}
const pluginId = options.get("--plugin-id");
const targetId = options.get("--target-id");
const credentialFDText = options.get("--credential-fd");
const policyPath = options.get("--policy");
const pluginRoot = options.get("--plugin-root");
const credentialRoot = options.get("--credential-root");
const stateRoot = options.get("--state-root");
if (!/^workload\.[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?$/u.test(pluginId ?? "") ||
  !/^[a-zA-Z0-9][a-zA-Z0-9._-]{7,127}$/u.test(targetId ?? "") ||
  !/^[0-9]+$/u.test(credentialFDText ?? "") ||
  [policyPath, pluginRoot, credentialRoot, stateRoot].some((path) => !path || resolve(path) !== path)) {
  fail("Plugin credential configuration arguments are invalid.");
}
const credentialFD = Number(credentialFDText);
if (!Number.isSafeInteger(credentialFD) || credentialFD < 3 || credentialFD > 1024) fail("--credential-fd must be between 3 and 1024.");
if (existsSync(join(stateRoot, "managed", pluginId))) fail("Credential replacement is disabled after managed workload deployment.");

const current = join(pluginRoot, pluginId, "current");
let currentInfo;
try {
  currentInfo = lstatSync(current);
} catch {
  fail("Managed workload plugin is not installed.");
}
if (!currentInfo.isSymbolicLink()) fail("Managed workload current pointer is not a symbolic link.");
const installed = realpathSync(current);
const pluginDirectory = realpathSync(join(pluginRoot, pluginId));
if (!installed.startsWith(`${pluginDirectory}/`)) fail("Managed workload current pointer escapes the plugin root.");
const manifest = JSON.parse(readFileSync(join(installed, "manifest.json"), "utf8"));
const artifactDigest = readFileSync(join(installed, ".artifact-digest"), "utf8").trim();
if (manifest.schemaVersion !== 2 || manifest.kind !== "managed-workload" || manifest.id !== pluginId ||
  manifest.workload === null || typeof manifest.workload !== "object" || Array.isArray(manifest.workload) ||
  manifest.workload.credentialEnvironment === null || typeof manifest.workload.credentialEnvironment !== "object" || Array.isArray(manifest.workload.credentialEnvironment) ||
  !/^sha256:[a-f0-9]{64}$/u.test(artifactDigest)) {
  fail("Installed managed workload manifest or artifact marker is invalid.");
}

let credentialPayload;
try {
  credentialPayload = readFileSync(credentialFD);
} catch {
  fail("Cannot read credential bundle from the supplied descriptor.");
}
if (credentialPayload.length < 1 || credentialPayload.length > 64 * 1024) fail("Credential bundle is outside its size limit.");
let bundle;
try {
  bundle = JSON.parse(credentialPayload.toString("utf8"));
} catch {
  fail("Credential bundle is not valid JSON.");
}
const bundleKeys = bundle && typeof bundle === "object" && !Array.isArray(bundle) ? Object.keys(bundle).sort() : [];
if (bundleKeys.join(",") !== "pluginId,values,version" || bundle.version !== 1 || bundle.pluginId !== pluginId || !Array.isArray(bundle.values)) {
  fail("Credential bundle has an invalid schema or plugin identity.");
}
const slots = Object.keys(manifest.workload.credentialEnvironment).sort();
const supplied = [];
for (const item of bundle.values) {
  const keys = item && typeof item === "object" && !Array.isArray(item) ? Object.keys(item).sort() : [];
  if (keys.join(",") !== "name,value" || typeof item.name !== "string" || typeof item.value !== "string" || item.value.length < 1 || item.value.length > 4096 || /[\u0000\r\n]/u.test(item.value)) {
    fail("Credential bundle contains an invalid slot value.");
  }
  supplied.push(item.name);
}
if (supplied.sort().join("\0") !== slots.join("\0") || new Set(supplied).size !== supplied.length) fail("Credential bundle slots do not exactly match the plugin manifest.");

const policy = JSON.parse(readFileSync(policyPath, "utf8"));
const target = Array.isArray(policy.targets) ? policy.targets.find((candidate) => candidate?.id === targetId) : undefined;
const artifact = Array.isArray(target?.changes?.plugins) ? target.changes.plugins.find((candidate) =>
  candidate?.id === pluginId && candidate.kind === "managed-workload" && candidate.version === manifest.version &&
  candidate.publisher === manifest.publisher && candidate.digest === artifactDigest) : undefined;
if (!artifact) fail("Target policy does not pin the installed managed workload artifact.");

const credentialDigest = `sha256:${createHash("sha256").update(credentialPayload).digest("hex")}`;
const credentialDirectory = join(credentialRoot, pluginId);
const credentialPath = join(credentialDirectory, "credentials.json");
if (existsSync(credentialPath)) {
  const currentDigest = `sha256:${createHash("sha256").update(readFileSync(credentialPath)).digest("hex")}`;
  if (currentDigest === credentialDigest && artifact.credentialBundleDigest === credentialDigest) {
    process.stdout.write(`${policy.revision}\n`);
    process.exit(0);
  }
  if (!replace) fail("Credential bundle already exists; use --replace only before first workload deployment.");
}

function atomicWrite(path, payload, mode) {
  const temporary = `${path}.new.${process.pid}`;
  try {
    writeFileSync(temporary, payload, { flag: "wx", mode });
    chmodSync(temporary, mode);
    const file = openSync(temporary, "r");
    fsyncSync(file);
    closeSync(file);
    renameSync(temporary, path);
    const directory = openSync(dirname(path), "r");
    fsyncSync(directory);
    closeSync(directory);
  } catch (error) {
    try { unlinkSync(temporary); } catch {}
    fail(`Atomic credential configuration failed: ${error instanceof Error ? error.message : "unknown error"}`);
  }
}

atomicWrite(credentialPath, credentialPayload, 0o600);
artifact.credentialBundleDigest = credentialDigest;
policy.revision = "policy-pending-revision";
const revision = createHash("sha256").update(`${targetId}\0${pluginId}\0${credentialDigest}\0${JSON.stringify(policy)}`).digest("hex").slice(0, 24);
policy.revision = `policy-local-${revision}`;
atomicWrite(policyPath, Buffer.from(`${JSON.stringify(policy)}\n`), 0o640);
process.stdout.write(`${policy.revision}\n`);
