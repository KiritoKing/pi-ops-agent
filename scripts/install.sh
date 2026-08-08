#!/bin/sh
set -eu

# This file is intentionally a small network bootstrap. The release payload owns
# all host mutations so a tagged copy of this script always installs the matching
# versioned, checksummed artifact.

readonly REPOSITORY="${OPS_AGENT_GITHUB_REPOSITORY:-KiritoKing/pi-ops-agent}"
readonly RELEASE_VERSION="${OPS_AGENT_VERSION:-latest}"

usage() {
  cat <<'EOF'
Usage:
  curl -fsSL https://raw.githubusercontent.com/KiritoKing/pi-ops-agent/main/scripts/install.sh \
    | sudo sh -s -- init [--admin-user USER] [--enable-artifact ID ...] [--no-start]

  curl -fsSL https://raw.githubusercontent.com/KiritoKing/pi-ops-agent/main/scripts/install.sh \
    | sudo sh -s -- join --controller URL --controller-ca-sha256 FINGERPRINT \
      --token-file PATH [--no-start]

  # Existing endpoint release upgrade: validate and reuse its enrollment.
  curl -fsSL https://raw.githubusercontent.com/KiritoKing/pi-ops-agent/main/scripts/install.sh \
    | sudo sh -s -- join --controller URL --controller-ca-sha256 FINGERPRINT \
      [--no-start]

Environment:
  OPS_AGENT_VERSION=v1.2.3            install a specific GitHub release
  OPS_AGENT_GITHUB_REPOSITORY=owner/repo
  OPS_AGENT_RELEASE_BASE=https://...   override the GitHub release base for mirrors/tests
EOF
}

if [ "$#" -eq 0 ]; then
  usage >&2
  exit 2
fi
case "$1" in
  init|join) ;;
  -h|--help) usage; exit 0 ;;
  *) printf 'Unknown mode: %s\n' "$1" >&2; usage >&2; exit 2 ;;
esac

if [ "$(id -u)" -ne 0 ]; then
  printf 'Run the bootstrap as root (normally through sudo).\n' >&2
  exit 1
fi
if [ "$(uname -s)" != Linux ] || [ ! -d /run/systemd/system ]; then
  printf 'Pi Ops Agent supports only Linux with systemd as PID 1.\n' >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64) release_arch=amd64 ;;
  aarch64|arm64) release_arch=arm64 ;;
  *) printf 'Unsupported architecture: %s\n' "$(uname -m)" >&2; exit 1 ;;
esac

for required_command in curl sha256sum tar mktemp; do
  if ! command -v "$required_command" >/dev/null 2>&1; then
    printf 'Missing bootstrap dependency: %s\n' "$required_command" >&2
    exit 1
  fi
done

if [ -n "${OPS_AGENT_RELEASE_BASE:-}" ]; then
  release_base=${OPS_AGENT_RELEASE_BASE%/}
elif [ "$RELEASE_VERSION" = latest ]; then
  release_base="https://github.com/${REPOSITORY}/releases/latest/download"
else
  case "$RELEASE_VERSION" in
    v*) release_tag=$RELEASE_VERSION ;;
    *) release_tag="v${RELEASE_VERSION}" ;;
  esac
  release_base="https://github.com/${REPOSITORY}/releases/download/${release_tag}"
fi

asset="ops-agent-linux-${release_arch}.tar.gz"
bootstrap_tmp=$(mktemp -d "${TMPDIR:-/tmp}/ops-agent-bootstrap.XXXXXX")
cleanup() {
  find "$bootstrap_tmp" -mindepth 1 -depth -delete 2>/dev/null || true
  rmdir "$bootstrap_tmp" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

curl -fL --proto '=https' --tlsv1.2 \
  "${release_base}/checksums.txt" -o "${bootstrap_tmp}/checksums.txt"
curl -fL --proto '=https' --tlsv1.2 \
  "${release_base}/${asset}" -o "${bootstrap_tmp}/${asset}"

expected_checksum=$(awk -v name="$asset" '$2 == name { print $1 }' "${bootstrap_tmp}/checksums.txt")
case "$expected_checksum" in
  ''|*[!0-9a-fA-F]*)
    printf 'Release checksum is missing or malformed for %s.\n' "$asset" >&2
    exit 1
    ;;
esac
if [ "${#expected_checksum}" -ne 64 ]; then
  printf 'Release checksum has an invalid length for %s.\n' "$asset" >&2
  exit 1
fi
actual_checksum=$(sha256sum "${bootstrap_tmp}/${asset}" | awk '{ print $1 }')
if [ "$actual_checksum" != "$expected_checksum" ]; then
  printf 'Checksum verification failed for %s.\n' "$asset" >&2
  exit 1
fi
if command -v gh >/dev/null 2>&1; then
  gh attestation verify "${bootstrap_tmp}/${asset}" --repo "$REPOSITORY"
else
  printf '%s\n' \
    'NOTICE: gh is unavailable; bootstrap verified GitHub HTTPS plus the release checksum,' \
    'but did not verify the GitHub artifact attestation. See docs/deployment.md.' >&2
fi

mkdir "${bootstrap_tmp}/release"
tar -xzf "${bootstrap_tmp}/${asset}" -C "${bootstrap_tmp}/release"
installer="${bootstrap_tmp}/release/install-release.sh"
payload="${bootstrap_tmp}/release/payload"
if [ ! -x "$installer" ] || [ ! -d "$payload" ]; then
  printf 'Release payload is incomplete.\n' >&2
  exit 1
fi

OPS_AGENT_PAYLOAD_DIR="$payload" "$installer" "$@"
