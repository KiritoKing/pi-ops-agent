#!/usr/bin/env bash
set -euo pipefail

readonly BOTMUX_USER="ops-agent-botmux"
readonly BOTMUX_GROUP="ops-agent-botmux"
readonly CLIENT_GROUP="ops-agent-client"
readonly BOTMUX_HOME="/var/lib/ops-agent/adapters/botmux"
readonly SOURCE_REGISTRY="/var/lib/ops-agent/plugins"
readonly SOURCE_PLUGINCTL="/opt/pi-ops-agent/current/bin/agentd-pluginctl"
readonly CORE_NODE="/opt/pi-ops-agent/current/runtime/node"
readonly ADAPTER_RUNNER="/opt/pi-ops-agent/current/dist/runtime/adapter-run.js"
readonly BOTMUX_SETUP_RUNNER="/opt/pi-ops-agent/current/dist/runtime/botmux-setup-run.js"
readonly BOTMUX_PATH="/opt/pi-ops-agent/botmux-bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
PATH="/usr/sbin:/usr/bin:/sbin:/bin"
export PATH

if (($# != 0)); then
  printf 'setup-botmux does not accept arguments.\n' >&2
  exit 2
fi
if [[ ${EUID} -ne 0 ]]; then
  printf 'setup-botmux must run as root through its command-specific PASSWD sudo rule.\n' >&2
  exit 1
fi
if [[ ! -t 0 ]] || [[ ! -t 1 ]]; then
  printf 'BotMux setup requires an interactive local TTY.\n' >&2
  exit 1
fi

assert_root_owned_tree() {
  local target="$1"
  local resolved owner mode cursor
  resolved="$(readlink -f -- "${target}")"
  [[ -n "${resolved}" ]] && [[ -e "${resolved}" ]] || {
    printf 'Required path cannot be resolved: %s\n' "${target}" >&2
    return 1
  }
  cursor="${resolved}"
  while :; do
    owner="$(stat -Lc '%u' -- "${cursor}")"
    mode="$(stat -Lc '%a' -- "${cursor}")"
    [[ "${owner}" == 0 ]] || {
      printf 'Trusted executable tree is not root-owned: %s\n' "${cursor}" >&2
      return 1
    }
    (( (8#${mode} & 0022) == 0 )) || {
      printf 'Trusted executable tree is group/world writable: %s\n' "${cursor}" >&2
      return 1
    }
    [[ "${cursor}" != / ]] || break
    cursor="$(dirname -- "${cursor}")"
  done
  printf '%s\n' "${resolved}"
}

find_fixed_command() {
  local candidate resolved
  for candidate in "$@"; do
    [[ -e "${candidate}" ]] || [[ -L "${candidate}" ]] || continue
    [[ "$(stat -c '%u' -- "${candidate}")" == 0 ]] || {
      printf 'Command entry is not root-owned: %s\n' "${candidate}" >&2
      return 1
    }
    resolved="$(assert_root_owned_tree "${candidate}")"
    [[ -f "${resolved}" ]] && [[ -x "${resolved}" ]] || {
      printf 'Command is not a regular executable: %s\n' "${candidate}" >&2
      return 1
    }
    printf '%s\n' "${resolved}"
    return 0
  done
  printf 'Required command is not installed in the fixed allowlist.\n' >&2
  return 1
}

runuser_command="$(find_fixed_command /usr/sbin/runuser /usr/bin/runuser)"
env_command="$(find_fixed_command /usr/bin/env)"
node_command="$(assert_root_owned_tree "${CORE_NODE}")"
[[ -f "${node_command}" ]] && [[ -x "${node_command}" ]] || {
  printf 'Bundled Node runtime is not a regular executable.\n' >&2
  exit 1
}
adapter_runner="$(assert_root_owned_tree "${ADAPTER_RUNNER}")"
[[ -f "${adapter_runner}" ]] || {
  printf 'Fixed digest-validating Adapter runner is missing.\n' >&2
  exit 1
}
botmux_setup_runner="$(assert_root_owned_tree "${BOTMUX_SETUP_RUNNER}")"
[[ -f "${botmux_setup_runner}" ]] || {
  printf 'Fixed exact-digest BotMux setup runner is missing.\n' >&2
  exit 1
}

id "${BOTMUX_USER}" >/dev/null 2>&1 || {
  printf 'Dedicated BotMux account is missing. Re-run the release installer.\n' >&2
  exit 1
}
botmux_uid="$(id -u "${BOTMUX_USER}")"
botmux_gid="$(getent group "${BOTMUX_GROUP}" | cut -d: -f3)"
[[ "${botmux_uid}" =~ ^[0-9]+$ ]] && ((botmux_uid > 0)) || {
  printf 'Dedicated BotMux account must be non-root.\n' >&2
  exit 1
}
[[ "$(id -g "${BOTMUX_USER}")" == "${botmux_gid}" ]] || {
  printf 'Dedicated BotMux account has the wrong primary group.\n' >&2
  exit 1
}
primary_group="$(id -gn "${BOTMUX_USER}")"
supplementary=""
while IFS= read -r group; do
  [[ -n "${group}" ]] || continue
  [[ "${group}" == "${primary_group}" ]] && continue
  if [[ -n "${supplementary}" ]]; then
    supplementary+=","
  fi
  supplementary+="${group}"
done < <(id -nG "${BOTMUX_USER}" | tr ' ' '\n')
[[ "${supplementary}" == "${CLIENT_GROUP}" ]] || {
  printf 'Dedicated BotMux account must belong only to the agent socket group.\n' >&2
  exit 1
}

[[ -d "${BOTMUX_HOME}" ]] && [[ ! -L "${BOTMUX_HOME}" ]] || {
  printf 'Dedicated BotMux home is missing or unsafe.\n' >&2
  exit 1
}
[[ "$(stat -c '%u:%g:%a' -- "${BOTMUX_HOME}")" == "${botmux_uid}:${botmux_gid}:700" ]] || {
  printf 'Dedicated BotMux home must be owned by its service identity with mode 0700.\n' >&2
  exit 1
}

pluginctl_command="$(assert_root_owned_tree "${SOURCE_PLUGINCTL}")"
[[ -f "${pluginctl_command}" ]] && [[ -x "${pluginctl_command}" ]] || {
  printf 'Source plugin registry validator is missing.\n' >&2
  exit 1
}
setup_scratch="$(mktemp -d /run/ops-agent-botmux-setup.XXXXXX)"
chmod 0700 "${setup_scratch}"
cleanup_setup_scratch() {
  find "${setup_scratch}" -mindepth 1 -depth -delete 2>/dev/null || true
  rmdir "${setup_scratch}" 2>/dev/null || true
}
trap cleanup_setup_scratch EXIT HUP INT TERM

runtime_json="${setup_scratch}/runtime.json"
runtime_error="${setup_scratch}/runtime.err"
if ! "${pluginctl_command}" current --root "${SOURCE_REGISTRY}" \
    --plugin-id adapter.botmux --runtime >"${runtime_json}" 2>"${runtime_error}"; then
  printf '%s\n' \
    'Active Source adapter.botmux registration is required; legacy .opspkg artifacts are recovery evidence only.' \
    'Review and register plugins/adapter-botmux-source, then rerun /botmux-setup.' >&2
  sed -n '1,10p' "${runtime_error}" >&2
  exit 1
fi

runtime_entrypoint=""
hardener=""
runtime_fields="${setup_scratch}/runtime.fields"
"${node_command}" -e '
    const fs = require("node:fs");
    const path = require("node:path");
    const [input, registry] = process.argv.slice(1);
    const value = JSON.parse(fs.readFileSync(input, "utf8"));
    const expectedKeys = [
      "apiVersion", "schemaVersion", "pluginId", "kind", "version", "publisher",
      "digest", "capabilities", "requestedScopes", "approvedBy", "approvedAt",
      "entrypoint", "snapshotPath",
    ].sort();
    const exact = (left, right) => Array.isArray(left) && Array.isArray(right)
      && left.length === right.length && left.every((item, index) => item === right[index]);
    const capabilities = [
      "adapter.inbound.text", "adapter.outbound.send", "adapter.session.bind", "approval.status",
    ];
    const scopes = [
      "adapter.inbound.text.botmux", "adapter.outbound.send.botmux",
      "adapter.session.bind.botmux", "approval.status.remote",
    ];
    if (!exact(Object.keys(value).sort(), expectedKeys)
        || value.apiVersion !== "agentd.plugin-registration/v1"
        || value.schemaVersion !== 1 || value.pluginId !== "adapter.botmux"
        || value.kind !== "adapter"
        || !exact(value.capabilities, capabilities) || !exact(value.requestedScopes, scopes)
        || !/^sha256:[0-9a-f]{64}$/u.test(value.digest)
        || typeof value.snapshotPath !== "string"
        || value.entrypoint !== "adapter.mjs") {
      throw new Error("active source adapter runtime registration is invalid");
    }
    const digest = value.digest.slice("sha256:".length);
    const expectedSnapshot = path.join(registry, "snapshots", "sha256", digest);
    if (value.snapshotPath !== expectedSnapshot) {
      throw new Error("active source adapter snapshot path does not match its digest");
    }
    const entrypoint = path.join(expectedSnapshot, value.entrypoint);
    const hardener = path.join(expectedSnapshot, "configure-botmux.mjs");
    process.stdout.write(value.digest + "\n" + expectedSnapshot + "\n" + entrypoint + "\n" + hardener + "\n");
  ' "${runtime_json}" "${SOURCE_REGISTRY}" >"${runtime_fields}"
mapfile -t source_fields <"${runtime_fields}"
[[ "${#source_fields[@]}" == 4 ]] || {
  printf 'Source adapter runtime validator returned an incomplete result.\n' >&2
  exit 1
}
artifact_digest="${source_fields[0]}"
snapshot_root="${source_fields[1]}"
runtime_entrypoint="$(assert_root_owned_tree "${source_fields[2]}")"
hardener="$(assert_root_owned_tree "${source_fields[3]}")"
[[ "${runtime_entrypoint}" == "${snapshot_root}/"* ]] \
  && [[ "${hardener}" == "${snapshot_root}/configure-botmux.mjs" ]] \
  && [[ -f "${runtime_entrypoint}" ]] && [[ -f "${hardener}" ]] || {
  printf 'Active source adapter runtime files are missing or escape the approved snapshot.\n' >&2
  exit 1
}

if [[ -L /opt/pi-ops-agent/botmux-bin ]] \
    || { [[ -e /opt/pi-ops-agent/botmux-bin ]] && [[ ! -d /opt/pi-ops-agent/botmux-bin ]]; }; then
  printf 'BotMux resume wrapper directory is unsafe.\n' >&2
  exit 1
fi
install -d -o root -g root -m 0755 /opt/pi-ops-agent/botmux-bin
pi_wrapper_tmp="/opt/pi-ops-agent/botmux-bin/.pi-new-$$"
rm -f -- "${pi_wrapper_tmp}"
{
  printf '%s\n' '#!/bin/sh' 'set -eu'
  printf 'exec %s %s adapter.botmux -- "$@"\n' \
    "${CORE_NODE}" "${ADAPTER_RUNNER}"
} >"${pi_wrapper_tmp}"
chown root:root "${pi_wrapper_tmp}"
chmod 0755 "${pi_wrapper_tmp}"
mv -Tf -- "${pi_wrapper_tmp}" /opt/pi-ops-agent/botmux-bin/pi
chown -h root:root /opt/pi-ops-agent/botmux-bin/pi

for trusted_directory in \
  /opt/pi-ops-agent/botmux-bin /usr/local/sbin /usr/local/bin \
  /usr/sbin /usr/bin /sbin /bin; do
  [[ -d "${trusted_directory}" ]] || continue
  assert_root_owned_tree "${trusted_directory}" >/dev/null
done

run_as_botmux() {
  "${runuser_command}" -u "${BOTMUX_USER}" -- "${env_command}" -i \
    "HOME=${BOTMUX_HOME}" "USER=${BOTMUX_USER}" "LOGNAME=${BOTMUX_USER}" \
    "SHELL=/bin/bash" "PATH=${BOTMUX_PATH}" "$@"
}

# The dedicated BotMux UID, not this root wrapper, obtains the exact digest
# lease through the peer-authenticated fixed socket. The runner retains it
# across setup, approved hardener execution, and restart; any broker loss or
# concurrent update attempt therefore fails closed before current can move.
run_as_botmux "${node_command}" "${botmux_setup_runner}" \
  --digest "${artifact_digest}"
printf 'BotMux initialized under %s with Source adapter snapshot %s.\n' \
  "${BOTMUX_USER}" "${artifact_digest}"
