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
for command in /usr/bin/bwrap /usr/bin/busctl /usr/bin/systemd-run /usr/bin/systemctl /usr/bin/getent /usr/bin/id /usr/bin/sleep; do
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
probe_unit="ops-agent-adapter-probe-${BASHPID}"
probe_dropin_directory="/run/systemd/system/${probe_unit}.service.d"
probe_dropin_path="${probe_dropin_directory}/zzzzzz-ops-agent-probe-security.conf"
probe_dropin_owned=0
probe_unit_owned=0
cleanup() {
  if [[ "${probe_unit_owned}" -eq 1 ]]; then
    /usr/bin/systemctl stop "${probe_unit}.service" >/dev/null 2>&1 || true
  fi
  if [[ -n "${server_pid}" ]]; then
    kill "${server_pid}" 2>/dev/null || true
    wait "${server_pid}" 2>/dev/null || true
  fi
  if [[ "${probe_dropin_owned}" -eq 1 ]]; then
    rm -f -- "${probe_dropin_path}"
    rmdir -- "${probe_dropin_directory}" 2>/dev/null || true
    /usr/bin/systemctl daemon-reload >/dev/null 2>&1 || true
  fi
  rm -rf -- "${probe_root}"
}
trap cleanup EXIT INT TERM
if [[ -e "${probe_dropin_directory}" ]]; then
  echo "FAIL: refusing to reuse stale probe drop-in directory: ${probe_dropin_directory}" >&2
  exit 1
fi

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
probe_driver_directory="${probe_runtime_root}/scripts"
probe_driver_path="${probe_driver_directory}/probe-adapter-linux-runtime.mjs"

install -d -o root -g "${PROBE_CLIENT_GROUP}" -m 0750 \
  "${registry_path}" "${registry_path}/snapshots" "${registry_path}/snapshots/sha256" \
  "${snapshot_path}" "${socket_directory}" "${probe_runtime_root}" "${probe_driver_directory}"
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

# A host-wide service.d drop-in is allowed to reset list-valued properties after
# systemd-run constructs a transient service. Install a unit-specific, later
# drop-in and inspect the manager's effective values before running the probe so
# the test cannot pass under a silently weakened boundary.
install -d -o root -g root -m 0755 "${probe_dropin_directory}"
probe_dropin_owned=1
{
  printf '%s\n' \
    '[Service]' \
    "User=${PROBE_USER}" \
    "Group=${PROBE_PRIMARY_GROUP}" \
    'SupplementaryGroups=' \
    "SupplementaryGroups=${PROBE_CLIENT_GROUP}" \
    'WorkingDirectory=/var/lib/ops-agent/adapters/botmux' \
    'Environment=' \
    'Environment=HOME=/var/lib/ops-agent/adapters/botmux' \
    'Environment=PATH=/opt/pi-ops-agent/botmux-bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' \
    'UMask=0077' \
    'NoNewPrivileges=yes' \
    'AppArmorProfile=-bwrap' \
    'ProtectSystem=strict' \
    'ProtectHome=yes' \
    'ProtectKernelTunables=yes' \
    'ProtectKernelModules=yes' \
    'ProtectControlGroups=yes' \
    'PrivateDevices=yes' \
    'ProtectProc=invisible' \
    'ProcSubset=all' \
    'RestrictSUIDSGID=yes' \
    'RestrictNamespaces=user pid mnt' \
    'ReadOnlyPaths=' \
    "ReadOnlyPaths=/opt/pi-ops-agent ${probe_runtime_root} ${registry_path} ${fixture_path} ${socket_directory}" \
    'ReadWritePaths=' \
    'ReadWritePaths=/var/lib/ops-agent/adapters/botmux /tmp /proc/sys/user/max_user_namespaces'
} >"${probe_dropin_path}"
chown root:root "${probe_dropin_path}"
chmod 0644 "${probe_dropin_path}"
/usr/bin/systemctl daemon-reload

require_effective_property() {
  local property="$1"
  local expected="$2"
  local actual
  actual="$(/usr/bin/systemctl show "${probe_unit}.service" --property="${property}" --value)"
  if [[ "${actual}" != "${expected}" ]]; then
    echo "FAIL: effective ${property}=${actual@Q}, expected ${expected@Q}" >&2
    exit 1
  fi
}

require_effective_word_set() {
  local property="$1"
  shift
  local actual
  local expected_word
  local actual_word
  local found
  local -a actual_words=()
  actual="$(/usr/bin/systemctl show "${probe_unit}.service" --property="${property}" --value)"
  read -r -a actual_words <<<"${actual}"
  if [[ "${#actual_words[@]}" -ne "$#" ]]; then
    echo "FAIL: effective ${property}=${actual@Q}, expected exactly: $*" >&2
    exit 1
  fi
  for expected_word in "$@"; do
    found=0
    for actual_word in "${actual_words[@]}"; do
      if [[ "${actual_word}" == "${expected_word}" ]]; then
        found=1
        break
      fi
    done
    if [[ "${found}" -ne 1 ]]; then
      echo "FAIL: effective ${property}=${actual@Q}, missing ${expected_word@Q}" >&2
      exit 1
    fi
  done
}

require_effective_word_member() {
  local property="$1"
  local expected="$2"
  local actual
  local actual_word
  actual="$(/usr/bin/systemctl show "${probe_unit}.service" --property="${property}" --value)"
  for actual_word in ${actual}; do
    if [[ "${actual_word}" == "${expected}" ]]; then
      return 0
    fi
  done
  echo "FAIL: effective ${property}=${actual@Q}, missing ${expected@Q}" >&2
  exit 1
}

require_effective_apparmor_profile() {
  local object_payload object_path profile_payload
  object_payload="$(/usr/bin/busctl --json=short call org.freedesktop.systemd1 \
    /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager \
    LoadUnit s "${probe_unit}.service")"
  object_path="$("${node_path}" -e '
    const value = JSON.parse(process.argv[1]);
    if (value?.type !== "o" || !Array.isArray(value.data)
        || value.data.length !== 1 || typeof value.data[0] !== "string"
        || !/^\/org\/freedesktop\/systemd1\/unit\/[A-Za-z0-9_]+$/u.test(value.data[0])) {
      throw new Error("systemd LoadUnit returned an invalid object path");
    }
    process.stdout.write(value.data[0]);
  ' "${object_payload}")"
  profile_payload="$(/usr/bin/busctl --json=short get-property \
    org.freedesktop.systemd1 "${object_path}" \
    org.freedesktop.systemd1.Service AppArmorProfile)"
  "${node_path}" -e '
    const value = JSON.parse(process.argv[1]);
    if (value?.type !== "(bs)" || !Array.isArray(value.data)
        || value.data.length !== 2 || value.data[0] !== true
        || value.data[1] !== "bwrap") {
      throw new Error("effective AppArmorProfile is not exact ignore-missing bwrap");
    }
  ' "${profile_payload}"
}

# Keep one instance alive long enough to inspect the effective manager state.
# The same name-specific drop-in remains in force for the real invocation below.
probe_unit_owned=1
/usr/bin/systemd-run --quiet --collect --unit="${probe_unit}" \
  --working-directory=/var/lib/ops-agent/adapters/botmux \
  --setenv=HOME=/var/lib/ops-agent/adapters/botmux \
  --setenv=PATH=/opt/pi-ops-agent/botmux-bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  --property="User=${PROBE_USER}" \
  --property="Group=${PROBE_PRIMARY_GROUP}" \
  --property="SupplementaryGroups=${PROBE_CLIENT_GROUP}" \
  --property=UMask=0077 \
  --property=NoNewPrivileges=yes \
  --property=AppArmorProfile=-bwrap \
  --property=ProtectSystem=strict \
  --property=ProtectHome=yes \
  --property=ProtectKernelTunables=yes \
  --property=ProtectKernelModules=yes \
  --property=ProtectControlGroups=yes \
  --property=PrivateDevices=yes \
  --property=ProtectProc=invisible \
  --property=ProcSubset=all \
  --property=RestrictSUIDSGID=yes \
  --property="RestrictNamespaces=user pid mnt" \
  --property="ReadOnlyPaths=/opt/pi-ops-agent ${probe_runtime_root} ${registry_path} ${fixture_path} ${socket_directory}" \
  --property="ReadWritePaths=/var/lib/ops-agent/adapters/botmux /tmp /proc/sys/user/max_user_namespaces" \
  /usr/bin/sleep 30

require_effective_property LoadState loaded
require_effective_property ActiveState active
require_effective_property NeedDaemonReload no
require_effective_word_member DropInPaths "${probe_dropin_path}"
require_effective_property User "${PROBE_USER}"
require_effective_property Group "${PROBE_PRIMARY_GROUP}"
require_effective_word_set SupplementaryGroups "${PROBE_CLIENT_GROUP}"
require_effective_property WorkingDirectory /var/lib/ops-agent/adapters/botmux
require_effective_word_set Environment \
  HOME=/var/lib/ops-agent/adapters/botmux \
  PATH=/opt/pi-ops-agent/botmux-bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
require_effective_property UMask 0077
require_effective_property NoNewPrivileges yes
require_effective_apparmor_profile
require_effective_property ProtectSystem strict
require_effective_property ProtectHome yes
require_effective_property ProtectKernelTunables yes
require_effective_property ProtectKernelModules yes
require_effective_property ProtectControlGroups yes
require_effective_property PrivateDevices yes
require_effective_property ProtectProc invisible
require_effective_property ProcSubset all
require_effective_property RestrictSUIDSGID yes
require_effective_word_set RestrictNamespaces user pid mnt
require_effective_word_set ReadOnlyPaths \
  /opt/pi-ops-agent "${probe_runtime_root}" "${registry_path}" "${fixture_path}" "${socket_directory}"
require_effective_word_set ReadWritePaths \
  /var/lib/ops-agent/adapters/botmux /tmp /proc/sys/user/max_user_namespaces

/usr/bin/systemctl stop "${probe_unit}.service"
for _ in {1..100}; do
  if [[ "$(/usr/bin/systemctl show "${probe_unit}.service" --property=LoadState --value 2>/dev/null || true)" == "not-found" ]]; then
    break
  fi
  sleep 0.02
done
if [[ "$(/usr/bin/systemctl show "${probe_unit}.service" --property=LoadState --value 2>/dev/null || true)" != "not-found" ]]; then
  echo "FAIL: effective-vector probe unit did not unload before runtime probe" >&2
  exit 1
fi

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

/usr/bin/systemd-run --quiet --wait --collect --pipe --unit="${probe_unit}" \
  --working-directory=/var/lib/ops-agent/adapters/botmux \
  --setenv=HOME=/var/lib/ops-agent/adapters/botmux \
  --setenv=PATH=/opt/pi-ops-agent/botmux-bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  --property="User=${PROBE_USER}" \
  --property="Group=${PROBE_PRIMARY_GROUP}" \
  --property="SupplementaryGroups=${PROBE_CLIENT_GROUP}" \
  --property=UMask=0077 \
  --property=NoNewPrivileges=yes \
  --property=AppArmorProfile=-bwrap \
  --property=ProtectSystem=strict \
  --property=ProtectHome=yes \
  --property=ProtectKernelTunables=yes \
  --property=ProtectKernelModules=yes \
  --property=ProtectControlGroups=yes \
  --property=PrivateDevices=yes \
  --property=ProtectProc=invisible \
  --property=ProcSubset=all \
  --property=RestrictSUIDSGID=yes \
  --property="RestrictNamespaces=user pid mnt" \
  --property="ReadOnlyPaths=/opt/pi-ops-agent ${probe_runtime_root} ${registry_path} ${fixture_path} ${socket_directory}" \
  --property="ReadWritePaths=/var/lib/ops-agent/adapters/botmux /tmp /proc/sys/user/max_user_namespaces" \
  "${node_path}" "${probe_driver_path}" \
  "${registry_path}" "${snapshot_path}" "${fixture_path}" "${socket_path}" \
  "${result_directory}" "${node_path}" /usr/bin/bwrap "${probe_client_path}"
