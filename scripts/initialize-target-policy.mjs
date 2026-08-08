import { createHash } from "node:crypto";
import {
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, resolve } from "node:path";

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

const args = process.argv.slice(2);
const options = new Map();
const enabledArtifactIds = [];
let validateOnly = false;
const supportedOptions = new Set(["--catalog-index", "--policy", "--output"]);
for (let index = 0; index < args.length; index += 1) {
  const key = args[index];
  if (key === "--validate-only") {
    if (validateOnly) fail("--validate-only was provided more than once.");
    validateOnly = true;
    continue;
  }
  const value = args[index + 1];
  if (!key?.startsWith("--") || value === undefined || value.startsWith("--")) fail("Invalid target policy initializer arguments.");
  if (key === "--enable-artifact") {
    if (enabledArtifactIds.includes(value)) fail(`Artifact ${value} was enabled more than once.`);
    enabledArtifactIds.push(value);
  } else {
    if (!supportedOptions.has(key) || options.has(key)) fail("Invalid target policy initializer arguments.");
    options.set(key, value);
  }
  index += 1;
}
const catalogPath = options.get("--catalog-index");
const policyPath = options.get("--policy");
const outputPath = options.get("--output") ?? policyPath;
if (!catalogPath || resolve(catalogPath) !== catalogPath || (!validateOnly && (!policyPath || !outputPath || resolve(policyPath) !== policyPath || resolve(outputPath) !== outputPath))) {
  fail("Usage: initialize-target-policy.mjs --catalog-index ABSOLUTE_PATH [--validate-only] [--policy ABSOLUTE_PATH] [--output ABSOLUTE_PATH] [--enable-artifact ID ...]");
}

function parseObject(path, label) {
  let value;
  try {
    value = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    fail(`${label} is not valid JSON: ${path}`);
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail(`${label} must be a JSON object.`);
  return value;
}

const catalog = parseObject(catalogPath, "Artifact catalog index");
if (catalog.schemaVersion !== 1 || !Array.isArray(catalog.artifacts) || catalog.artifacts.length > 256) {
  fail("Artifact catalog index has an unsupported schema.");
}
const artifactById = new Map();
for (const artifact of catalog.artifacts) {
  if (artifact === null || typeof artifact !== "object" || Array.isArray(artifact) || typeof artifact.id !== "string") {
    fail("Artifact catalog contains an invalid entry.");
  }
  const existing = artifactById.get(artifact.id);
  if (existing) fail(`Artifact catalog has multiple versions of ${artifact.id}; automatic policy initialization is ambiguous.`);
  artifactById.set(artifact.id, artifact);
}

const zeroDigest = `sha256:${"0".repeat(64)}`;
const canonicalDigest = /^sha256:[a-f0-9]{64}$/u;
const enabledArtifacts = enabledArtifactIds.map((id) => {
  const artifact = artifactById.get(id);
  if (!artifact) fail(`Enabled artifact ${id} is not present in the trusted catalog.`);
  return artifact;
});
if (validateOnly) {
  process.stdout.write(`${enabledArtifactIds.sort().join("\n")}${enabledArtifactIds.length > 0 ? "\n" : ""}`);
  process.exit(0);
}

const safeDefaultReadPaths = [];

function policyArtifact(artifact, credentialBundleDigest) {
  const result = {
    id: artifact.id,
    kind: artifact.kind,
    version: artifact.version,
    publisher: artifact.publisher,
    digest: artifact.digest,
  };
  if (artifact.kind === "managed-workload") result.credentialBundleDigest = credentialBundleDigest ?? zeroDigest;
  return result;
}

function freshPolicy() {
  const artifacts = enabledArtifacts.map((artifact) => policyArtifact(artifact));
  const hasDockerWorkload = artifacts.some((artifact) => artifact.kind === "managed-workload");
  return {
    version: 1,
    revision: "policy-initializing-v3",
    targets: [{
      id: "target-local-system",
      account: "root",
      displayName: "Local system",
      inspect: {
        hostSnapshot: true,
        processList: true,
        units: hasDockerWorkload ? ["docker.service", "ops-agent-server.service", "ops-agentd.service"] : ["ops-agent-server.service", "ops-agentd.service"],
        readPaths: safeDefaultReadPaths,
      },
      changes: {
        writePaths: [],
        units: hasDockerWorkload ? ["docker.service"] : [],
        packages: hasDockerWorkload ? ["docker.io"] : [],
        plugins: artifacts,
      },
      authorization: { standingScopes: [] },
    }],
  };
}

function migratePolicy(policy) {
  if (policy.version !== 1 || !Array.isArray(policy.targets) || policy.targets.length === 0) fail("Existing target policy has an unsupported schema.");
  for (const target of policy.targets) {
    if (target === null || typeof target !== "object" || Array.isArray(target) || target.changes === null || typeof target.changes !== "object" || Array.isArray(target.changes)) {
      fail("Existing target policy contains an invalid target.");
    }
    const changeKeys = Object.keys(target.changes).sort();
    const supportedChangeKeys = ["packages", "plugins", "units", "writePaths"];
    if (changeKeys.some((key) => !supportedChangeKeys.includes(key))) {
      fail(`Existing target ${target.id ?? "unknown"} contains an unsupported legacy change policy; migrate it explicitly before upgrading.`);
    }
    const migrated = [];
    const plugins = Array.isArray(target.changes.plugins) ? target.changes.plugins : [];
    for (const plugin of plugins) {
      if (typeof plugin === "string") {
        const artifact = artifactById.get(plugin);
        if (!artifact) fail(`Legacy plugin ${plugin} is not present in the trusted catalog.`);
        migrated.push(policyArtifact(artifact));
      } else if (plugin !== null && typeof plugin === "object" && !Array.isArray(plugin)) {
        migrated.push(plugin);
      } else {
        fail("Existing target policy contains an invalid plugin allowlist entry.");
      }
    }
    target.changes.plugins = migrated;
    if (!Array.isArray(target.changes.writePaths)) {
      fail("Existing target policy contains an invalid write path allowlist.");
    }
    // v0.2 initialized this broad root so generic file.write could update the
    // agent itself. v0.3 makes the control plane a permanent typed-only
    // boundary; remove the obsolete grant while preserving unrelated roots.
    target.changes.writePaths = target.changes.writePaths.filter(
      (path) => path !== "/etc/ops-agent",
    );
    if (target.authorization === undefined) {
      // Legacy allowlists meant "eligible for a separately approved change".
      // Never reinterpret them as standing authorization during an upgrade.
      target.authorization = { standingScopes: [] };
    } else {
      if (target.authorization === null || typeof target.authorization !== "object" ||
          Array.isArray(target.authorization) ||
          Object.keys(target.authorization).some(
            (key) => key !== "standingScopes" && key !== "baseWorkloadDigest",
          ) ||
          !Array.isArray(target.authorization.standingScopes) ||
          target.authorization.standingScopes.some((scope) => typeof scope !== "string") ||
          (target.authorization.baseWorkloadDigest !== undefined &&
            (typeof target.authorization.baseWorkloadDigest !== "string" ||
              !canonicalDigest.test(target.authorization.baseWorkloadDigest)))) {
        fail(`Existing target ${target.id ?? "unknown"} contains an invalid authorization policy.`);
      }
      if ((target.authorization.standingScopes.includes("file.write") ||
          target.authorization.standingScopes.includes("service.action")) &&
          !canonicalDigest.test(target.authorization.baseWorkloadDigest ?? "")) {
        fail(`Existing target ${target.id ?? "unknown"} must bind standing base operations to baseWorkloadDigest.`);
      }
    }
  }
  return policy;
}

const policyExists = existsSync(policyPath);
if (policyExists && enabledArtifactIds.length > 0) {
  fail("--enable-artifact is only valid while creating a fresh target policy; review existing policy changes explicitly.");
}
const policy = policyExists ? migratePolicy(parseObject(policyPath, "Existing target policy")) : freshPolicy();
for (const target of policy.targets) {
  target.changes.plugins.sort((left, right) => `${left.kind}\0${left.id}`.localeCompare(`${right.kind}\0${right.id}`, "en"));
  for (const key of ["units", "packages", "writePaths"]) {
    if (Array.isArray(target.changes[key])) target.changes[key].sort();
  }
  for (const key of ["units", "readPaths"]) {
    if (Array.isArray(target.inspect?.[key])) target.inspect[key].sort();
  }
  target.authorization.standingScopes.sort();
}
policy.revision = "policy-pending-revision";
const revisionDigest = createHash("sha256").update(JSON.stringify(policy)).digest("hex").slice(0, 24);
policy.revision = `policy-local-${revisionDigest}`;
const payload = `${JSON.stringify(policy)}\n`;
const temporary = `${outputPath}.new.${process.pid}`;
try {
  writeFileSync(temporary, payload, { flag: "wx", mode: 0o640 });
  chmodSync(temporary, 0o640);
  const file = openSync(temporary, "r");
  fsyncSync(file);
  closeSync(file);
  renameSync(temporary, outputPath);
  const directory = openSync(dirname(outputPath), "r");
  fsyncSync(directory);
  closeSync(directory);
} catch (error) {
  try {
    if (existsSync(temporary)) unlinkSync(temporary);
  } catch {
    // Preserve the original atomic-write failure as the actionable error.
  }
  fail(`Cannot atomically initialize target policy: ${error instanceof Error ? error.message : "unknown error"}`);
}
process.stdout.write(`${policy.revision}\n`);
