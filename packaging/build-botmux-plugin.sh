#!/usr/bin/env bash
set -euo pipefail

REPOSITORY_ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
VERSION="${1:-}"
OUTPUT_DIR="${2:-}"

if [[ ! "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] || [[ -z "${OUTPUT_DIR}" ]]; then
  printf 'Usage: packaging/build-botmux-plugin.sh VERSION OUTPUT_DIR\n' >&2
  exit 2
fi

manifest="${REPOSITORY_ROOT}/plugins/adapter-botmux/manifest.json"
adapter="${REPOSITORY_ROOT}/integrations/botmux/adapter.mjs"
setup="${REPOSITORY_ROOT}/scripts/configure-botmux.mjs"
for required_path in "${manifest}" "${adapter}" "${setup}"; do
  [[ -f "${required_path}" ]] || { printf 'Missing BotMux plugin input: %s\n' "${required_path}" >&2; exit 1; }
done

manifest_version="$(node -e 'const fs=require("node:fs"); const p=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); process.stdout.write(p.version)' "${manifest}")"
if [[ "${manifest_version}" != "${VERSION}" ]]; then
  printf 'BotMux manifest version %s does not match release %s.\n' "${manifest_version}" "${VERSION}" >&2
  exit 1
fi

mkdir -p "${OUTPUT_DIR}"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/ops-agent-botmux-plugin.XXXXXX")"
cleanup() {
  find "${work_dir}" -mindepth 1 -depth -delete 2>/dev/null || true
  rmdir "${work_dir}" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

install -m 0644 "${manifest}" "${work_dir}/manifest.json"
install -m 0755 "${adapter}" "${work_dir}/adapter.mjs"
install -m 0755 "${setup}" "${work_dir}/configure-botmux.mjs"
package_files=(manifest.json adapter.mjs configure-botmux.mjs)
if [[ -f "${REPOSITORY_ROOT}/config/botmux.bots.json.example" ]]; then
  install -m 0644 "${REPOSITORY_ROOT}/config/botmux.bots.json.example" \
    "${work_dir}/botmux.bots.json.example"
  package_files+=(botmux.bots.json.example)
fi
if [[ -f "${REPOSITORY_ROOT}/config/botmux-systemd-dropin.conf" ]]; then
  install -m 0644 "${REPOSITORY_ROOT}/config/botmux-systemd-dropin.conf" \
    "${work_dir}/botmux-systemd-dropin.conf"
  package_files+=(botmux-systemd-dropin.conf)
fi

if tar --version 2>&1 | grep -q 'GNU tar'; then
  tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
    -czf "${OUTPUT_DIR}/adapter-botmux_${VERSION}.opspkg" -C "${work_dir}" \
    "${package_files[@]}"
else
  COPYFILE_DISABLE=1 tar --format ustar -czf \
    "${OUTPUT_DIR}/adapter-botmux_${VERSION}.opspkg" -C "${work_dir}" \
    "${package_files[@]}"
fi
