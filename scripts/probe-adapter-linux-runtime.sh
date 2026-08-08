#!/usr/bin/env bash
set -euo pipefail

readonly PROBE_USER="ops-agent-botmux"
readonly PROBE_PRIMARY_GROUP="ops-agent-botmux"
readonly PROBE_CLIENT_GROUP="ops-agent-client"
readonly SKIP_STATUS=77
readonly REPOSITORY_ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"

cd "${REPOSITORY_ROOT}"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "SKIP: Adapter supplementary-group/PID containment probe requires a real Linux kernel" >&2
  exit "${SKIP_STATUS}"
fi
if [[ "${EUID}" -ne 0 ]]; then
  echo "SKIP: run this probe as root so it can create root:ops-agent-client fixtures and drop to ${PROBE_USER}" >&2
  exit "${SKIP_STATUS}"
fi
for command in /usr/bin/bwrap /usr/bin/systemd-run /usr/bin/getent /usr/bin/id; do
  if [[ ! -x "${command}" ]]; then
    echo "SKIP: required Linux probe command is unavailable: ${command}" >&2
    exit "${SKIP_STATUS}"
  fi
done
if ! /usr/bin/getent passwd "${PROBE_USER}" >/dev/null \
  || ! /usr/bin/getent group "${PROBE_PRIMARY_GROUP}" >/dev/null \
  || ! /usr/bin/getent group "${PROBE_CLIENT_GROUP}" >/dev/null; then
  echo "SKIP: install the dedicated ${PROBE_USER} account and both required groups first" >&2
  exit "${SKIP_STATUS}"
fi
if [[ ! -d /run/systemd/system ]]; then
  echo "SKIP: Adapter hardening probe requires systemd as PID 1" >&2
  exit "${SKIP_STATUS}"
fi
if [[ ! -d /var/lib/ops-agent/adapters/botmux ]]; then
  echo "SKIP: initialize the BotMux Adapter working directory before this probe" >&2
  exit "${SKIP_STATUS}"
fi
if ! /usr/bin/id -nG "${PROBE_USER}" | tr ' ' '\n' | grep -Fxq "${PROBE_CLIENT_GROUP}"; then
  echo "FAIL: ${PROBE_USER} is not a member of ${PROBE_CLIENT_GROUP}" >&2
  exit 1
fi
if [[ ! -f dist/runtime/adapter-run.js ]]; then
  echo "FAIL: dist/runtime/adapter-run.js is missing; run npm run build before this probe" >&2
  exit 1
fi

if [[ -x "${REPOSITORY_ROOT}/runtime/node" ]]; then
  node_path="${REPOSITORY_ROOT}/runtime/node"
else
  node_path="$(command -v node)"
fi
node_path="$(readlink -f "${node_path}")"
if [[ ! -x "${node_path}" ]]; then
  echo "FAIL: fixed Node runtime is unavailable" >&2
  exit 1
fi
client_gid="$(/usr/bin/getent group "${PROBE_CLIENT_GROUP}" | cut -d: -f3)"
primary_gid="$(/usr/bin/getent group "${PROBE_PRIMARY_GROUP}" | cut -d: -f3)"
probe_uid="$(/usr/bin/id -u "${PROBE_USER}")"
probe_root="$(mktemp -d /tmp/agentd-adapter-linux-probe.XXXXXX)"
chown root:"${PROBE_CLIENT_GROUP}" "${probe_root}"
chmod 0750 "${probe_root}"
server_pid=""
cleanup() {
  if [[ -n "${server_pid}" ]]; then
    kill "${server_pid}" 2>/dev/null || true
    wait "${server_pid}" 2>/dev/null || true
  fi
  rm -rf -- "${probe_root}"
}
trap cleanup EXIT INT TERM

digest="$(printf 'a%.0s' {1..64})"
registry_path="${probe_root}/registry"
snapshot_path="${registry_path}/snapshots/sha256/${digest}"
fixture_path="${probe_root}/root-group-readable"
socket_directory="${probe_root}/socket"
socket_path="${socket_directory}/agentd-client.sock"
ready_path="${probe_root}/socket-ready"
result_directory="${probe_root}/result"
probe_client_path="${probe_root}/probe-client.mjs"
probe_runtime_root="${probe_root}/probe-runtime"
probe_driver_path="${probe_runtime_root}/probe-adapter-linux-runtime.mjs"

install -d -o root -g "${PROBE_CLIENT_GROUP}" -m 0750 \
  "${registry_path}" "${registry_path}/snapshots" "${registry_path}/snapshots/sha256" \
  "${snapshot_path}" "${socket_directory}" "${probe_runtime_root}"
install -d -o "${probe_uid}" -g "${primary_gid}" -m 0700 "${result_directory}"
install -o root -g "${PROBE_CLIENT_GROUP}" -m 0550 \
  scripts/probe-adapter-linux-fixture.mjs "${snapshot_path}/adapter.mjs"
install -o root -g "${PROBE_CLIENT_GROUP}" -m 0440 \
  scripts/probe-adapter-linux-client.mjs "${probe_client_path}"
cp -a dist "${probe_runtime_root}/dist"
chown -R root:"${PROBE_CLIENT_GROUP}" "${probe_runtime_root}/dist"
find "${probe_runtime_root}/dist" -type d -exec chmod 0750 {} +
find "${probe_runtime_root}/dist" -type f -exec chmod 0440 {} +
install -o root -g "${PROBE_CLIENT_GROUP}" -m 0440 \
  scripts/probe-adapter-linux-runtime.mjs "${probe_driver_path}"
printf '%s\n' "root-group-readable" > "${fixture_path}"
chown root:"${PROBE_CLIENT_GROUP}" "${fixture_path}"
chmod 0640 "${fixture_path}"

"${node_path}" scripts/probe-adapter-linux-socket.mjs \
  "${socket_path}" "${ready_path}" "${client_gid}" &
server_pid="$!"
for _ in {1..100}; do
  [[ -f "${ready_path}" ]] && break
  sleep 0.02
done
if [[ ! -f "${ready_path}" ]]; then
  echo "FAIL: root-owned group socket server did not become ready" >&2
  exit 1
fi

probe_unit="ops-agent-adapter-probe-${BASHPID}"
/usr/bin/systemd-run --quiet --wait --collect --pipe --unit="${probe_unit}" \
  --working-directory=/var/lib/ops-agent/adapters/botmux \
  --setenv=HOME=/var/lib/ops-agent/adapters/botmux \
  --setenv=PATH=/opt/pi-ops-agent/botmux-bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  --property="User=${PROBE_USER}" \
  --property="Group=${PROBE_PRIMARY_GROUP}" \
  --property="SupplementaryGroups=${PROBE_CLIENT_GROUP}" \
  --property=UMask=0077 \
  --property=NoNewPrivileges=yes \
  --property=ProtectSystem=strict \
  --property=ProtectHome=yes \
  --property=ProtectKernelTunables=yes \
  --property=ProtectKernelModules=yes \
  --property=ProtectControlGroups=yes \
  --property=PrivateDevices=yes \
  --property=RestrictSUIDSGID=yes \
  --property="RestrictNamespaces=user pid mnt" \
  --property="ReadOnlyPaths=/opt/pi-ops-agent ${probe_runtime_root} ${registry_path} ${fixture_path} ${socket_directory}" \
  --property="ReadWritePaths=/var/lib/ops-agent/adapters/botmux /tmp /proc/sys/user/max_user_namespaces" \
  "${node_path}" "${probe_driver_path}" \
  "${registry_path}" "${snapshot_path}" "${fixture_path}" "${socket_path}" \
  "${result_directory}" "${node_path}" /usr/bin/bwrap "${probe_client_path}"
