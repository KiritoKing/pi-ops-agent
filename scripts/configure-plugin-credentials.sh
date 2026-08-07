#!/usr/bin/env bash
set -euo pipefail

readonly CURRENT_ROOT="/opt/pi-ops-agent/current"
readonly POLICY_PATH="/etc/ops-agent/targets.json"
readonly PLUGIN_ROOT="/opt/pi-ops-agent/plugins"
readonly CREDENTIAL_ROOT="/etc/ops-agent/workloads"
readonly STATE_ROOT="/var/lib/ops-agent/root-helper"

PLUGIN_ID=""
TARGET_ID=""
CREDENTIAL_FD=""
REPLACE=false

usage() {
  printf 'Usage: sudo configure-plugin-credentials.sh --plugin-id workload.NAME --target-id TARGET --credential-fd N [--replace]\n'
}

while (($# > 0)); do
  case "$1" in
    --plugin-id) (($# >= 2)) || { usage >&2; exit 2; }; PLUGIN_ID="$2"; shift 2 ;;
    --target-id) (($# >= 2)) || { usage >&2; exit 2; }; TARGET_ID="$2"; shift 2 ;;
    --credential-fd) (($# >= 2)) || { usage >&2; exit 2; }; CREDENTIAL_FD="$2"; shift 2 ;;
    --replace) REPLACE=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done

if [[ ${EUID} -ne 0 ]]; then
  printf 'Run plugin credential configuration as root.\n' >&2
  exit 1
fi
if [[ ! "${PLUGIN_ID}" =~ ^workload\.[a-z0-9][a-z0-9.-]{0,63}$ ]] ||
  [[ ! "${TARGET_ID}" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]{7,127}$ ]] ||
  [[ ! "${CREDENTIAL_FD}" =~ ^[0-9]+$ ]] || ((CREDENTIAL_FD < 3 || CREDENTIAL_FD > 1024)); then
  usage >&2
  exit 2
fi
for path in "${CURRENT_ROOT}/runtime/node" "${CURRENT_ROOT}/scripts/configure-plugin-credentials.mjs" "${POLICY_PATH}"; do
  [[ -f "${path}" && ! -L "${path}" ]] || { printf 'Required trusted file is missing or is a symlink: %s\n' "${path}" >&2; exit 1; }
done
install -d -o root -g root -m 0700 "${CREDENTIAL_ROOT}" "${CREDENTIAL_ROOT}/${PLUGIN_ID}"

arguments=(
  --plugin-id "${PLUGIN_ID}"
  --target-id "${TARGET_ID}"
  --credential-fd "${CREDENTIAL_FD}"
  --policy "${POLICY_PATH}"
  --plugin-root "${PLUGIN_ROOT}"
  --credential-root "${CREDENTIAL_ROOT}"
  --state-root "${STATE_ROOT}"
)
if [[ "${REPLACE}" == true ]]; then
  arguments+=(--replace)
fi
revision="$("${CURRENT_ROOT}/runtime/node" "${CURRENT_ROOT}/scripts/configure-plugin-credentials.mjs" "${arguments[@]}")"
chown root:root "${CREDENTIAL_ROOT}/${PLUGIN_ID}/credentials.json"
chown root:ops-agent-server "${POLICY_PATH}"
chmod 0600 "${CREDENTIAL_ROOT}/${PLUGIN_ID}/credentials.json"
chmod 0640 "${POLICY_PATH}"
systemctl restart ops-root-helper.service ops-agent-server.service
printf 'Plugin credential bundle installed and bound to policy revision %s.\n' "${revision}"
