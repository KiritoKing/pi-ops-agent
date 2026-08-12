#!/usr/bin/env bash
set -euo pipefail

DIRECTORY="${1:-}"
OUTPUT="${2:-}"
if [[ -z "${DIRECTORY}" || -z "${OUTPUT}" ]]; then
  printf 'Usage: packaging/create-catalog-index.sh DIRECTORY OUTPUT\n' >&2
  exit 2
fi
for command_name in node tar; do
  command -v "${command_name}" >/dev/null 2>&1 || {
    printf 'Missing catalog index dependency: %s\n' "${command_name}" >&2
    exit 1
  }
done
if [[ ! -d "${DIRECTORY}" ]]; then
  printf 'Catalog directory does not exist: %s\n' "${DIRECTORY}" >&2
  exit 1
fi
if [[ -e "${OUTPUT}" ]]; then
  printf 'Refusing to overwrite catalog index: %s\n' "${OUTPUT}" >&2
  exit 1
fi

node - "${DIRECTORY}" "${OUTPUT}" <<'NODE'
const { createHash } = require("node:crypto");
const { readdirSync, readFileSync, realpathSync, statSync, writeFileSync } = require("node:fs");
const { join, resolve } = require("node:path");
const { spawnSync } = require("node:child_process");

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

const directoryArg = process.argv[2];
const outputArg = process.argv[3];
const directory = realpathSync(resolve(directoryArg));
const output = resolve(outputArg);
const packages = [];
for (const entry of readdirSync(directory, { withFileTypes: true })) {
  if (!entry.name.endsWith(".opspkg")) continue;
  if (!entry.isFile()) fail(`Catalog package must be a regular non-symlink file: ${entry.name}`);
  packages.push(entry.name);
}
packages.sort();
if (packages.length > 256) fail("Catalog contains more than 256 packages.");

const adapterId = /^adapter\.[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?$/u;
const workloadId = /^workload\.[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?$/u;
const versionPattern = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$/u;
const artifacts = packages.map((name) => {
  const packagePath = join(directory, name);
  const info = statSync(packagePath);
  if (!info.isFile() || (info.mode & 0o022) !== 0 || info.size < 1 || info.size > 16 * 1024 * 1024) {
    fail(`Catalog package is not a bounded non-writable regular file: ${name}`);
  }
  const listing = spawnSync("tar", ["-tzf", packagePath], {
    encoding: "utf8",
    maxBuffer: 1024 * 1024,
  });
  if (listing.status !== 0) fail(`Cannot list catalog package: ${name}`);
  const manifestNames = listing.stdout.split("\n")
    .filter(Boolean)
    .filter((entry) => entry.replace(/^\.\//u, "") === "manifest.json");
  if (manifestNames.length !== 1) fail(`Catalog package must contain one root manifest.json: ${name}`);
  const extracted = spawnSync("tar", ["-xOzf", packagePath, manifestNames[0]], {
    encoding: "utf8",
    maxBuffer: 256 * 1024,
  });
  if (extracted.status !== 0) fail(`Cannot read catalog manifest: ${name}`);
  let manifest;
  try {
    manifest = JSON.parse(extracted.stdout);
  } catch {
    fail(`Catalog manifest is not valid JSON: ${name}`);
  }
  if (manifest === null || typeof manifest !== "object" || Array.isArray(manifest)) {
    fail(`Catalog manifest is not an object: ${name}`);
  }
  const allowedFields = manifest.schemaVersion === 1
    ? ["schemaVersion", "id", "kind", "version", "publisher", "coreProtocol", "entrypoint", "description", "capabilities", "secrets", "setupOperations"]
    : ["schemaVersion", "id", "kind", "version", "publisher", "coreProtocol", "description", "workload"];
  const manifestFields = Object.keys(manifest);
  if (manifestFields.length !== allowedFields.length || allowedFields.some((field) => !Object.hasOwn(manifest, field))) {
    fail(`Catalog manifest has missing or unknown top-level fields: ${name}`);
  }
  const validIdentity = manifest.coreProtocol === 1 &&
    versionPattern.test(manifest.version) &&
    typeof manifest.publisher === "string" && manifest.publisher.length > 0 && manifest.publisher.length <= 160 &&
    typeof manifest.description === "string" && manifest.description.length > 0 && manifest.description.length <= 2048;
  const validKind = (manifest.schemaVersion === 1 && manifest.kind === "im-adapter" && adapterId.test(manifest.id)) ||
    (manifest.schemaVersion === 2 && manifest.kind === "managed-workload" && workloadId.test(manifest.id));
  if (!validIdentity || !validKind) fail(`Catalog manifest identity is invalid: ${name}`);
  const digest = `sha256:${createHash("sha256").update(readFileSync(packagePath)).digest("hex")}`;
  return {
    artifactRef: `builtin:${digest}`,
    id: manifest.id,
    kind: manifest.kind,
    version: manifest.version,
    publisher: manifest.publisher,
    digest,
    description: manifest.description,
  };
});
function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}
artifacts.sort((left, right) =>
  compareText(left.id, right.id) || compareText(left.version, right.version) || compareText(left.digest, right.digest));
if (new Set(artifacts.map((artifact) => artifact.artifactRef)).size !== artifacts.length) {
  fail("Catalog contains duplicate artifact references.");
}
writeFileSync(output, `${JSON.stringify({ schemaVersion: 1, artifacts }, null, 2)}\n`, { flag: "wx", mode: 0o644 });
NODE
