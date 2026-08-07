#!/usr/bin/env bash
set -euo pipefail

REPOSITORY_ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
VERSION="${1:-}"
OUTPUT_DIR="${2:-}"

if [[ ! "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || [[ -z "${OUTPUT_DIR}" ]]; then
  printf 'Usage: packaging/build-hermes-workload-plugin.sh VERSION OUTPUT_DIR\n' >&2
  exit 2
fi
for command_name in node tar install mktemp; do
  command -v "${command_name}" >/dev/null 2>&1 || {
    printf 'Missing build dependency: %s\n' "${command_name}" >&2
    exit 1
  }
done

plugin_root="${REPOSITORY_ROOT}/plugins/workload-hermes"
package_files=(manifest.json config.yaml ops-healthcheck.py prepare-credentials.mjs)
for package_file in "${package_files[@]}"; do
  [[ -f "${plugin_root}/${package_file}" ]] || {
    printf 'Missing Hermes workload plugin input: %s\n' "${plugin_root}/${package_file}" >&2
    exit 1
  }
done

manifest_version="$(node -e '
  const fs = require("node:fs");
  const value = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  if (value.schemaVersion !== 2 || value.kind !== "managed-workload" || value.id !== "workload.hermes") process.exit(1);
  process.stdout.write(value.version);
' "${plugin_root}/manifest.json")"
if [[ "${manifest_version}" != "${VERSION}" ]]; then
  printf 'Hermes workload manifest version %s does not match build version %s.\n' \
    "${manifest_version}" "${VERSION}" >&2
  exit 1
fi

mkdir -p "${OUTPUT_DIR}"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/ops-agent-hermes-workload.XXXXXX")"
cleanup() {
  find "${work_dir}" -mindepth 1 -depth -delete 2>/dev/null || true
  rmdir "${work_dir}" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

for package_file in "${package_files[@]}"; do
  install -m 0644 "${plugin_root}/${package_file}" "${work_dir}/${package_file}"
done
if tar --version 2>&1 | grep -q 'GNU tar'; then
  tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
    -czf "${OUTPUT_DIR}/workload-hermes_${VERSION}.opspkg" -C "${work_dir}" \
    "${package_files[@]}"
else
  COPYFILE_DISABLE=1 tar --format ustar -czf \
    "${OUTPUT_DIR}/workload-hermes_${VERSION}.opspkg" -C "${work_dir}" \
    "${package_files[@]}"
fi
