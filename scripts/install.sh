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
  # Ubuntu 24.04 restricted-userns host policy is a separate, model-external stage.
  curl -fsSL https://raw.githubusercontent.com/KiritoKing/pi-ops-agent/vX.Y.Z/scripts/install.sh \
    | sudo OPS_AGENT_VERSION=vX.Y.Z sh -s -- host-policy ACTION

  ACTION is one of:
    inspect
    install [--approve-digest sha256:...]
    status

  curl -fsSL https://raw.githubusercontent.com/KiritoKing/pi-ops-agent/vX.Y.Z/scripts/install.sh \
    | sudo OPS_AGENT_VERSION=vX.Y.Z sh -s -- init \
      [--admin-user USER] [--enable-artifact ID ...] [--no-start]

  curl -fsSL https://raw.githubusercontent.com/KiritoKing/pi-ops-agent/vX.Y.Z/scripts/install.sh \
    | sudo OPS_AGENT_VERSION=vX.Y.Z sh -s -- join \
      --controller URL --controller-ca-sha256 FINGERPRINT \
      --token-file PATH [--no-start]

  # Existing endpoint release upgrade: validate and reuse its enrollment.
  curl -fsSL https://raw.githubusercontent.com/KiritoKing/pi-ops-agent/vX.Y.Z/scripts/install.sh \
    | sudo OPS_AGENT_VERSION=vX.Y.Z sh -s -- join \
      --controller URL --controller-ca-sha256 FINGERPRINT \
      [--no-start]

Environment:
  OPS_AGENT_VERSION=v1.2.3            required explicit GitHub release pin
  OPS_AGENT_GITHUB_REPOSITORY=owner/repo
  OPS_AGENT_RELEASE_BASE=https://...   override the GitHub release base for mirrors/tests
EOF
}

if [ "$#" -eq 0 ]; then
  usage >&2
  exit 2
fi
mode=$1
shift
readonly mode
case "$mode" in
  init|join) ;;
  host-policy)
    if [ "$#" -eq 0 ]; then
      printf 'host-policy requires inspect, install, or status.\n' >&2
      usage >&2
      exit 2
    fi
    case "$1" in
      inspect|install|status) ;;
      *) printf 'Unknown host-policy action: %s\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
    ;;
  -h|--help) usage; exit 0 ;;
  *) printf 'Unknown mode: %s\n' "$mode" >&2; usage >&2; exit 2 ;;
esac

if [ "$RELEASE_VERSION" = latest ]; then
  printf '%s\n' \
    'The Raw bootstrap requires an explicit OPS_AGENT_VERSION=vX.Y.Z.' \
    'This binds host-policy, init, or join to one reviewed Release.' >&2
  exit 2
fi
for required_command in awk cat curl grep sha256sum tar mktemp; do
  if ! command -v "$required_command" >/dev/null 2>&1; then
    printf 'Missing bootstrap dependency: %s\n' "$required_command" >&2
    exit 1
  fi
done
if ! printf '%s\n' "$RELEASE_VERSION" \
    | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$'; then
  printf 'OPS_AGENT_VERSION must be an explicit v-prefixed semantic version.\n' >&2
  exit 2
fi

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

if [ -n "${OPS_AGENT_RELEASE_BASE:-}" ]; then
  release_base=${OPS_AGENT_RELEASE_BASE%/}
else
  release_tag=$RELEASE_VERSION
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
release_bootstrap="${bootstrap_tmp}/release/ops-agent-bootstrap"
payload_version_file="${bootstrap_tmp}/release/payload/VERSION"
if [ ! -f "$release_bootstrap" ] || [ -L "$release_bootstrap" ] || [ ! -x "$release_bootstrap" ] \
    || [ ! -f "$payload_version_file" ] || [ -L "$payload_version_file" ]; then
  printf 'Release payload is incomplete.\n' >&2
  exit 1
fi
if [ "$(cat "$payload_version_file")" != "${RELEASE_VERSION#v}" ]; then
  printf 'Release payload VERSION does not match OPS_AGENT_VERSION.\n' >&2
  exit 1
fi
"$release_bootstrap" "$mode" "$@"
