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
command -v jq >/dev/null 2>&1 || { printf 'jq is required.\n' >&2; exit 1; }

directory="$(CDPATH= cd -- "${directory}" && pwd -P)"
[[ ! -e "${directory}/manifest.json" ]] || {
  printf 'Refusing to overwrite existing manifest.json.\n' >&2
  exit 1
}

assets_file="$(mktemp "${TMPDIR:-/tmp}/ops-agent-assets.XXXXXX")"
trap 'rm -f -- "${assets_file:-}"' EXIT HUP INT TERM
for path in "${directory}"/*; do
  [[ -f "${path}" ]] || continue
  name="$(basename "${path}")"
  [[ "${name}" != checksums.txt ]] || continue
  case "${name}" in
    *.deb) kind=debian-package ;;
    *.tar.gz) kind=native-archive ;;
    *.opspkg) kind=adapter-plugin ;;
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
