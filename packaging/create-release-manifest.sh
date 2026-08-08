#!/usr/bin/env bash
set -euo pipefail

directory="${1:-}"
version="${2:-}"
repository="${3:-}"
commit="${4:-}"
if [[ -z "${directory}" ]] || [[ -z "${version}" ]] || [[ -z "${repository}" ]] \
  || [[ ! "${commit}" =~ ^[0-9a-f]{40}$ ]]; then
  printf 'Usage: create-release-manifest.sh DIRECTORY VERSION REPOSITORY COMMIT_SHA\n' >&2
  exit 2
fi
if [[ ! "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  printf 'Release manifest version is invalid: %s\n' "${version}" >&2
  exit 2
fi
command -v jq >/dev/null 2>&1 || { printf 'jq is required.\n' >&2; exit 1; }

directory="$(CDPATH= cd -- "${directory}" && pwd -P)"
[[ ! -e "${directory}/manifest.json" ]] || {
  printf 'Refusing to overwrite existing manifest.json.\n' >&2
  exit 1
}

required_assets=(
  "ops-agent-linux-amd64.tar.gz"
  "ops-agent-linux-arm64.tar.gz"
  "ops-agent-all_${version}_amd64.deb"
  "ops-agent-all_${version}_arm64.deb"
  "ops-agent-linux-amd64.spdx.json"
  "ops-agent-linux-arm64.spdx.json"
  "adapter-botmux_${version}.opspkg"
  "workload-hermes_${version}.opspkg"
)
for required_asset in "${required_assets[@]}"; do
  [[ -f "${directory}/${required_asset}" && ! -L "${directory}/${required_asset}" ]] || {
    printf 'Release asset set is incomplete: %s\n' "${required_asset}" >&2
    exit 1
  }
done

assets_file="$(mktemp "${TMPDIR:-/tmp}/ops-agent-assets.XXXXXX")"
trap 'rm -f -- "${assets_file:-}"' EXIT HUP INT TERM
for path in "${directory}"/*; do
  [[ -f "${path}" && ! -L "${path}" ]] || {
    printf 'Release directory contains a non-regular or symlink entry: %s\n' "${path}" >&2
    exit 1
  }
  name="$(basename "${path}")"
  [[ "${name}" != checksums.txt ]] || continue
  case "${name}" in
    *.deb) kind=debian-package ;;
    *.tar.gz) kind=native-archive ;;
    workload-*.opspkg) kind=managed-workload-plugin ;;
    adapter-*.opspkg) kind=adapter-plugin ;;
    *.opspkg) kind=plugin ;;
    *.spdx.json) kind=sbom ;;
    *) kind=artifact ;;
  esac
  jq -cn \
    --arg name "${name}" \
    --arg kind "${kind}" \
    --arg sha256 "$(sha256sum "${path}" | awk '{ print $1 }')" \
    --argjson bytes "$(stat -c '%s' "${path}")" \
    '{name: $name, kind: $kind, bytes: $bytes, sha256: $sha256}' >>"${assets_file}"
done

jq -s \
  --arg version "${version}" \
  --arg repository "${repository}" \
  --arg commit "${commit}" \
  '{
    schemaVersion: 1,
    product: "pi-ops-agent",
    version: $version,
    repository: $repository,
    commit: $commit,
    platforms: ["linux-systemd"],
    architectures: ["amd64", "arm64"],
    deployment: "native-only",
    assets: .
  }' "${assets_file}" >"${directory}/manifest.json"
