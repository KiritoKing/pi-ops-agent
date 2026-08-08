#!/usr/bin/env bash
set -euo pipefail

readonly APP_ROOT="/opt/pi-ops-agent"
readonly RELEASE_ROOT="${APP_ROOT}/releases"
readonly CURRENT_LINK="${APP_ROOT}/current"
readonly CONFIG_ROOT="/etc/ops-agent"
readonly UNIT_ROOT="/etc/systemd/system"
readonly TMPFILES_ROOT="/etc/tmpfiles.d"
readonly OPS_AGENT_TARGET_WANTS_DIR="${UNIT_ROOT}/ops-agent.target.wants"
readonly PVE_CONTROLLER_TARGET_WANT="${OPS_AGENT_TARGET_WANTS_DIR}/ops-pve-root-helper.service"
readonly SERVICE_USER="ops-agent"
readonly SERVICE_GROUP="ops-agent"
readonly CLIENT_GROUP="ops-agent-client"
readonly SERVER_USER="ops-agent-server"
readonly SERVER_GROUP="ops-agent-server"
readonly REVIEWER_USER="ops-agent-reviewer"
readonly REVIEWER_GROUP="ops-agent-reviewer"
readonly BOTMUX_USER="ops-agent-botmux"
readonly BOTMUX_GROUP="ops-agent-botmux"
readonly LEASE_USER="ops-agent-lease"
readonly LEASE_GROUP="ops-agent-lease"
readonly BOTMUX_HOME="/var/lib/ops-agent/adapters/botmux"
readonly APPROVAL_SUDOERS="/etc/sudoers.d/zzzz-ops-agent-approval"
readonly JSON_CONFIG_HELPER="/usr/lib/ops-agent/agentd-json-config-helper"
readonly RECEIPT_ROOT="${CONFIG_ROOT}/broker-receipts"
readonly RECEIPT_PRIVATE_ROOT="${RECEIPT_ROOT}/private"
readonly CORE_RECEIPT_KEY_ID="local-core-receipt-v1"
readonly PVE_RECEIPT_KEY_ID="local-pve-receipt-v1"

PAYLOAD_DIR="${OPS_AGENT_PAYLOAD_DIR:-}"
MODE=""
ADMIN_USER="${SUDO_USER:-}"
ENROLLMENT_FILE=""
CONTROLLER_URL=""
CONTROLLER_CA_SHA256=""
START_NOW=true
POLICY_CANDIDATE=""
POLICY_BACKUP=""
ENABLED_ARTIFACTS=()
APPROVE_REQUIRED_PLUGINS=false
RECEIPT_PUBLIC_GROUP=""
PVE_ENDPOINT=false
EXISTING_ENDPOINT_ENROLLMENT=false
INSTALL_TRANSACTION_DIR=""
INSTALL_TRANSACTION_ACTIVE=false
INSTALL_TRANSACTION_ROLLING_BACK=false
INSTALL_TRANSACTION_ROLLBACK_FAILED=false
INSTALL_QUIESCE_ACTIVE=false
RELEASE_CREATED=false
APP_ROOT_CREATED=false
RELEASE_ROOT_CREATED=false
RELEASE_STAGING=""
OPS_AGENT_TARGET_WANTS_SNAPSHOT_INDEX=-1
declare -a TRANSACTION_PATHS=()
declare -a TRANSACTION_PATH_STATES=()
declare -a TRANSACTION_UNITS=(
  ops-agent.target
  ops-agentd.service
  agentd-client-gateway.service
  agentd-guardian.service
  agentd-approval-reviewer.service
  agentd-plugin-lease-broker.service
  ops-agent-server.service
  ops-root-helper.service
  ops-pve-root-helper.service
  ops-systemd-helper.service
  ops-agent-healthcheck.service
  ops-agent-healthcheck.timer
)
declare -a TRANSACTION_INGRESS_UNITS=(
  agentd-client-gateway.service
  ops-agentd.service
  ops-agent-server.service
)
declare -A TRANSACTION_UNIT_ACTIVE=()
declare -A TRANSACTION_UNIT_ENABLED=()
declare -a TRANSACTION_USERS=(
  "${SERVICE_USER}"
  "${SERVER_USER}"
  "${REVIEWER_USER}"
  "${BOTMUX_USER}"
  "${LEASE_USER}"
)
declare -a TRANSACTION_GROUPS=(
  "${SERVICE_GROUP}"
  "${CLIENT_GROUP}"
  "${SERVER_GROUP}"
  "${REVIEWER_GROUP}"
  "${BOTMUX_GROUP}"
  "${LEASE_GROUP}"
)
declare -A TRANSACTION_USER_EXISTED=()
declare -A TRANSACTION_USER_GROUPS=()
declare -A TRANSACTION_GROUP_EXISTED=()
declare -a TRANSACTION_DIRECTORY_CANDIDATES=(
  /usr/lib/ops-agent
  /run/ops-agent/agentd
  /run/ops-agent/helper
  /run/ops-agent/reviewer
  /run/ops-agent/plugin-lease
  /run/ops-agent
  /var/lib/ops-agent/workspaces
  /var/lib/ops-agent/sessions
  /var/lib/ops-agent/registry
  /var/lib/ops-agent/machines
  /var/lib/ops-agent/pi
  /var/lib/ops-agent/root-helper
  /var/lib/ops-agent/pve-root-helper
  /var/lib/ops-agent/adapters/botmux
  /var/lib/ops-agent/adapters
  /var/lib/ops-agent
  /var/log/ops-agent/agentd
  /var/log/ops-agent/root-helper
  /var/log/ops-agent/pve-root-helper
  /var/log/ops-agent
)
declare -A TRANSACTION_DIRECTORY_EXISTED=()
declare -A TRANSACTION_DIRECTORY_UID=()
declare -A TRANSACTION_DIRECTORY_GID=()
declare -A TRANSACTION_DIRECTORY_MODE=()

remove_managed_path() {
  local path="$1"
  case "${path}" in
    "${CONFIG_ROOT}"|\
    /var/lib/ops-agent/plugin-sources|\
    /var/lib/ops-agent/plugins|\
    /var/lib/ops-agent/adapters|\
    "${CURRENT_LINK}"|\
    /usr/local/bin/ops-agent|\
    /usr/libexec/pi-ops-agent|\
    "${JSON_CONFIG_HELPER}"|\
    "${TMPFILES_ROOT}/ops-agent.conf"|\
    "${APPROVAL_SUDOERS}"|\
    "${UNIT_ROOT}"/ops-*|\
    "${UNIT_ROOT}"/agentd-*) ;;
    *)
      printf 'Refusing to remove an unmanaged rollback path: %s\n' "${path}" >&2
      return 1
      ;;
  esac
  if [[ -L "${path}" ]] || [[ -f "${path}" ]]; then
    rm -f -- "${path}"
  elif [[ -d "${path}" ]]; then
    find "${path}" -mindepth 1 -depth -delete
    rmdir -- "${path}"
  elif [[ -e "${path}" ]]; then
    printf 'Refusing to remove unsupported rollback path type: %s\n' "${path}" >&2
    return 1
  fi
}

snapshot_managed_path() {
  local path="$1"
  local index="${#TRANSACTION_PATHS[@]}"
  local snapshot="${INSTALL_TRANSACTION_DIR}/paths/${index}"
  TRANSACTION_PATHS+=("${path}")
  install -d -o root -g root -m 0700 "${snapshot}"
  if [[ -e "${path}" ]] || [[ -L "${path}" ]]; then
    TRANSACTION_PATH_STATES+=(present)
    cp -a --no-dereference "${path}" "${snapshot}/value"
  else
    TRANSACTION_PATH_STATES+=(absent)
  fi
}

restore_managed_path_snapshot() {
  local index="$1"
  local path="${TRANSACTION_PATHS[${index}]}"
  local state="${TRANSACTION_PATH_STATES[${index}]}"
  local snapshot="${INSTALL_TRANSACTION_DIR}/paths/${index}/value"
  remove_managed_path "${path}" \
    || { record_rollback_error "could not clear ${path}"; return; }
  if [[ "${state}" == present ]]; then
    mkdir -p "$(dirname "${path}")"
    cp -a --no-dereference "${snapshot}" "${path}" \
      || record_rollback_error "could not restore ${path}"
  fi
}

snapshot_account_state() {
  local user group primary supplementary item
  for group in "${TRANSACTION_GROUPS[@]}"; do
    if getent group "${group}" >/dev/null; then
      TRANSACTION_GROUP_EXISTED["${group}"]=true
    else
      TRANSACTION_GROUP_EXISTED["${group}"]=false
    fi
  done
  for user in "${TRANSACTION_USERS[@]}"; do
    if id "${user}" >/dev/null 2>&1; then
      TRANSACTION_USER_EXISTED["${user}"]=true
      primary="$(id -gn "${user}")"
      supplementary=""
      while IFS= read -r item; do
        [[ -n "${item}" ]] || continue
        [[ "${item}" == "${primary}" ]] && continue
        if [[ -n "${supplementary}" ]]; then
          supplementary+=","
        fi
        supplementary+="${item}"
      done < <(id -nG "${user}" | tr ' ' '\n')
      TRANSACTION_USER_GROUPS["${user}"]="${supplementary}"
    else
      TRANSACTION_USER_EXISTED["${user}"]=false
      TRANSACTION_USER_GROUPS["${user}"]=""
    fi
  done
}

snapshot_directory_state() {
  local directory
  for directory in "${TRANSACTION_DIRECTORY_CANDIDATES[@]}"; do
    if [[ -d "${directory}" ]] && [[ ! -L "${directory}" ]]; then
      TRANSACTION_DIRECTORY_EXISTED["${directory}"]=true
      TRANSACTION_DIRECTORY_UID["${directory}"]="$(stat -c '%u' "${directory}")"
      TRANSACTION_DIRECTORY_GID["${directory}"]="$(stat -c '%g' "${directory}")"
      TRANSACTION_DIRECTORY_MODE["${directory}"]="$(stat -c '%a' "${directory}")"
    elif [[ -e "${directory}" ]] || [[ -L "${directory}" ]]; then
      printf 'Managed runtime/state path is not a real directory: %s\n' "${directory}" >&2
      return 1
    else
      TRANSACTION_DIRECTORY_EXISTED["${directory}"]=false
    fi
  done
}

restore_existing_directory_metadata() {
  local directory
  for directory in "${TRANSACTION_DIRECTORY_CANDIDATES[@]}"; do
    [[ "${TRANSACTION_DIRECTORY_EXISTED["${directory}"]}" == true ]] || continue
    if [[ ! -d "${directory}" ]] || [[ -L "${directory}" ]]; then
      record_rollback_error "pre-existing directory has an unsafe type: ${directory}"
      continue
    fi
    chown "${TRANSACTION_DIRECTORY_UID["${directory}"]}:${TRANSACTION_DIRECTORY_GID["${directory}"]}" \
      "${directory}" \
      || record_rollback_error "could not restore ownership for ${directory}"
    chmod "${TRANSACTION_DIRECTORY_MODE["${directory}"]}" "${directory}" \
      || record_rollback_error "could not restore mode for ${directory}"
  done
}

snapshot_unit_state() {
  local unit
  for unit in "${TRANSACTION_UNITS[@]}"; do
    TRANSACTION_UNIT_ACTIVE["${unit}"]="$(systemctl is-active "${unit}" 2>/dev/null || true)"
    TRANSACTION_UNIT_ENABLED["${unit}"]="$(systemctl is-enabled "${unit}" 2>/dev/null || true)"
  done
}

snapshot_managed_units() {
  local path unit dropin_dir existing_dropin
  declare -A seen=()
  if [[ "${MODE}" == join ]]; then
    for unit in ops-agent-server.service ops-root-helper.service ops-pve-root-helper.service; do
      snapshot_managed_path "${UNIT_ROOT}/${unit}"
    done
    return
  fi
  for path in "${PAYLOAD_DIR}"/app/systemd/*.service \
      "${PAYLOAD_DIR}"/app/systemd/*.timer \
      "${PAYLOAD_DIR}"/app/systemd/*.target; do
    [[ -f "${path}" ]] || continue
    unit="${UNIT_ROOT}/$(basename "${path}")"
    [[ -n "${seen["${unit}"]:-}" ]] || snapshot_managed_path "${unit}"
    seen["${unit}"]=true
  done
  for dropin_dir in "${PAYLOAD_DIR}"/app/systemd/*.service.d; do
    [[ -d "${dropin_dir}" ]] || continue
    path="${UNIT_ROOT}/$(basename "${dropin_dir}")"
    [[ -n "${seen["${path}"]:-}" ]] || snapshot_managed_path "${path}"
    seen["${path}"]=true
  done
  for existing_dropin in "${UNIT_ROOT}"/ops-*.service.d/zzzz-ops-agent-*.conf; do
    [[ -e "${existing_dropin}" ]] || continue
    path="$(dirname "${existing_dropin}")"
    [[ -n "${seen["${path}"]:-}" ]] || snapshot_managed_path "${path}"
    seen["${path}"]=true
  done
  path="${UNIT_ROOT}/ops-agentd.service.d"
  [[ -n "${seen["${path}"]:-}" ]] || snapshot_managed_path "${path}"
  path="${UNIT_ROOT}/ops-systemd-helper.service"
  [[ -n "${seen["${path}"]:-}" ]] || snapshot_managed_path "${path}"
}

pve_controller_target_want_is_exact() {
  local resolved
  [[ -L "${PVE_CONTROLLER_TARGET_WANT}" ]] || return 1
  resolved="$(readlink -f -- "${PVE_CONTROLLER_TARGET_WANT}" 2>/dev/null || true)"
  [[ "${resolved}" == "${UNIT_ROOT}/ops-pve-root-helper.service" ]]
}

validate_endpoint_controller_target_wants() {
  local entry
  if [[ ! -e "${OPS_AGENT_TARGET_WANTS_DIR}" ]] \
      && [[ ! -L "${OPS_AGENT_TARGET_WANTS_DIR}" ]]; then
    return 0
  fi
  if [[ ! -d "${OPS_AGENT_TARGET_WANTS_DIR}" ]] \
      || [[ -L "${OPS_AGENT_TARGET_WANTS_DIR}" ]]; then
    printf 'join refuses unsafe controller target wants path: %s\n' \
      "${OPS_AGENT_TARGET_WANTS_DIR}" >&2
    return 1
  fi
  while IFS= read -r -d '' entry; do
    if [[ "${entry}" != "${PVE_CONTROLLER_TARGET_WANT}" ]] \
        || ! pve_controller_target_want_is_exact; then
      printf 'join refuses controller-only target dependency: %s\n' "${entry}" >&2
      return 1
    fi
  done < <(find "${OPS_AGENT_TARGET_WANTS_DIR}" -mindepth 1 -maxdepth 1 -print0)
}

cleanup_pve_controller_target_want() {
  if [[ ! -e "${OPS_AGENT_TARGET_WANTS_DIR}" ]] \
      && [[ ! -L "${OPS_AGENT_TARGET_WANTS_DIR}" ]]; then
    return 0
  fi
  if [[ ! -d "${OPS_AGENT_TARGET_WANTS_DIR}" ]] \
      || [[ -L "${OPS_AGENT_TARGET_WANTS_DIR}" ]]; then
    printf 'Refusing unsafe controller target wants path: %s\n' \
      "${OPS_AGENT_TARGET_WANTS_DIR}" >&2
    return 1
  fi
  if [[ -e "${PVE_CONTROLLER_TARGET_WANT}" ]] \
      || [[ -L "${PVE_CONTROLLER_TARGET_WANT}" ]]; then
    if ! pve_controller_target_want_is_exact; then
      printf 'Refusing unsafe PVE controller target dependency: %s\n' \
        "${PVE_CONTROLLER_TARGET_WANT}" >&2
      return 1
    fi
    rm -f -- "${PVE_CONTROLLER_TARGET_WANT}"
  fi
  if [[ -z "$(find "${OPS_AGENT_TARGET_WANTS_DIR}" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    rmdir -- "${OPS_AGENT_TARGET_WANTS_DIR}"
  fi
}

restore_quiesced_ingress() {
  local unit
  for unit in "${TRANSACTION_INGRESS_UNITS[@]}"; do
    case "${TRANSACTION_UNIT_ACTIVE["${unit}"]:-}" in
      active|reloading|activating)
        systemctl start "${unit}" >/dev/null 2>&1 \
          || printf 'Could not restore quiesced ingress unit %s.\n' "${unit}" >&2
        ;;
    esac
  done
}

abort_install_quiesce() {
  local status=$?
  [[ "${INSTALL_QUIESCE_ACTIVE}" == true ]] || exit "${status}"
  trap - EXIT HUP INT TERM
  set +e
  restore_quiesced_ingress
  find "${INSTALL_TRANSACTION_DIR}" -mindepth 1 -depth -delete 2>/dev/null || true
  rmdir "${INSTALL_TRANSACTION_DIR}" 2>/dev/null || true
  ((status != 0)) || status=1
  exit "${status}"
}

verify_root_stores_idle() {
  local checker="${PAYLOAD_DIR}/app/scripts/check-root-stores-idle.mjs"
  local node="${PAYLOAD_DIR}/app/runtime/node"
  [[ -f "${checker}" ]] && [[ -x "${node}" ]] || {
    printf 'Verified payload is missing the root-store quiescence checker.\n' >&2
    return 1
  }
  "${node}" "${checker}" \
    /var/lib/ops-agent/root-helper/state.json \
    /var/lib/ops-agent/pve-root-helper/state.json
}

quiesce_install_ingress() {
  local unit state
  for unit in "${TRANSACTION_INGRESS_UNITS[@]}"; do
    state="$(systemctl is-active "${unit}" 2>/dev/null || true)"
    case "${state}" in
      ""|inactive|failed|unknown) ;;
      *)
        systemctl stop "${unit}"
        ;;
    esac
  done
  for unit in "${TRANSACTION_INGRESS_UNITS[@]}"; do
    state="$(systemctl is-active "${unit}" 2>/dev/null || true)"
    case "${state}" in
      ""|inactive|failed|unknown) ;;
      *)
        printf 'Could not quiesce ingress unit %s (state=%s).\n' "${unit}" "${state}" >&2
        return 1
        ;;
    esac
  done
  verify_root_stores_idle
  for unit in ops-root-helper.service ops-pve-root-helper.service; do
    state="$(systemctl is-active "${unit}" 2>/dev/null || true)"
    case "${state}" in
      ""|inactive|failed|unknown) ;;
      *)
        printf '%s\n' \
          "Refusing an online upgrade while ${unit} is ${state}." \
          "Stop ops-agent.target and both root broker units after all changes are terminal, then retry." >&2
        return 1
        ;;
    esac
  done
}

stop_transaction_units() {
  local unit state
  for unit in "${TRANSACTION_UNITS[@]}"; do
    state="$(systemctl is-active "${unit}" 2>/dev/null || true)"
    case "${state}" in
      ""|inactive|failed|unknown) ;;
      *) systemctl stop "${unit}" ;;
    esac
  done
}

begin_install_transaction() {
  INSTALL_TRANSACTION_DIR="$(mktemp -d /var/tmp/ops-agent-install.XXXXXX)"
  chown root:root "${INSTALL_TRANSACTION_DIR}"
  chmod 0700 "${INSTALL_TRANSACTION_DIR}"
  if [[ "${MODE}" == init ]]; then
    TRANSACTION_USERS+=("${ADMIN_USER}")
  fi
  snapshot_account_state
  snapshot_directory_state
  snapshot_unit_state
  INSTALL_QUIESCE_ACTIVE=true
  trap abort_install_quiesce EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  quiesce_install_ingress
  snapshot_managed_path "${CONFIG_ROOT}"
  snapshot_managed_path "${CURRENT_LINK}"
  snapshot_managed_path "${JSON_CONFIG_HELPER}"
  snapshot_managed_path "${TMPFILES_ROOT}/ops-agent.conf"
  if [[ "${MODE}" == init ]]; then
    snapshot_managed_path /var/lib/ops-agent/plugin-sources
    snapshot_managed_path /var/lib/ops-agent/plugins
    snapshot_managed_path /usr/local/bin/ops-agent
    snapshot_managed_path /usr/libexec/pi-ops-agent
    snapshot_managed_path "${APPROVAL_SUDOERS}"
  fi
  snapshot_managed_units
  # Older PVE units installed themselves into ops-agent.target even on a
  # server-only join endpoint. Snapshot the complete wants directory so
  # cleanup and controller-only add-wants remain rollback-safe.
  OPS_AGENT_TARGET_WANTS_SNAPSHOT_INDEX="${#TRANSACTION_PATHS[@]}"
  snapshot_managed_path "${OPS_AGENT_TARGET_WANTS_DIR}"
  INSTALL_TRANSACTION_ACTIVE=true
  trap rollback_install_transaction EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  INSTALL_QUIESCE_ACTIVE=false
  stop_transaction_units
}

record_rollback_error() {
  local message="$1"
  printf 'Rollback warning: %s\n' "${message}" >&2
  INSTALL_TRANSACTION_ROLLBACK_FAILED=true
}

restore_account_state() {
  local index user group
  for user in "${TRANSACTION_USERS[@]}"; do
    if [[ "${TRANSACTION_USER_EXISTED["${user}"]}" == true ]]; then
      if id "${user}" >/dev/null 2>&1; then
        usermod --groups "${TRANSACTION_USER_GROUPS["${user}"]}" "${user}" \
          || record_rollback_error "could not restore supplementary groups for ${user}"
      else
        record_rollback_error "pre-existing user disappeared: ${user}"
      fi
    elif id "${user}" >/dev/null 2>&1; then
      userdel "${user}" || record_rollback_error "could not remove transaction-created user ${user}"
    fi
  done
  for ((index=${#TRANSACTION_GROUPS[@]} - 1; index >= 0; index--)); do
    group="${TRANSACTION_GROUPS[${index}]}"
    if [[ "${TRANSACTION_GROUP_EXISTED["${group}"]}" == false ]] \
        && getent group "${group}" >/dev/null; then
      groupdel "${group}" || record_rollback_error "could not remove transaction-created group ${group}"
    fi
  done
}

remove_transaction_created_directories() {
  local directory
  for directory in "${TRANSACTION_DIRECTORY_CANDIDATES[@]}"; do
    [[ "${TRANSACTION_DIRECTORY_EXISTED["${directory}"]}" == false ]] || continue
    case "${directory}" in
      /run/ops-agent|/run/ops-agent/*|\
      /var/lib/ops-agent|/var/lib/ops-agent/*|\
      /var/log/ops-agent|/var/log/ops-agent/*|\
      /usr/lib/ops-agent) ;;
      *)
        record_rollback_error "refused unmanaged transaction directory ${directory}"
        continue
        ;;
    esac
    if [[ -L "${directory}" ]]; then
      record_rollback_error "transaction-created directory became a symlink: ${directory}"
    elif [[ -d "${directory}" ]]; then
      case "${directory}" in
        /usr/lib/ops-agent|\
        /var/lib/ops-agent|/var/lib/ops-agent/adapters|/var/lib/ops-agent/adapters/*|\
        /var/log/ops-agent)
          if ! rmdir "${directory}" 2>/dev/null; then
            printf 'Rollback preserved non-empty third-party state: %s\n' \
              "${directory}" >&2
          fi
          continue
          ;;
      esac
      find "${directory}" -mindepth 1 -depth -delete \
        && rmdir "${directory}" \
        || record_rollback_error "could not remove transaction-created directory ${directory}"
    elif [[ -e "${directory}" ]]; then
      record_rollback_error "transaction-created path has an unsafe type: ${directory}"
    fi
  done
}

restore_unit_state() {
  local unit enabled active current_enabled current_active
  systemctl daemon-reload >/dev/null 2>&1 \
    || record_rollback_error "systemd daemon-reload failed"
  for unit in "${TRANSACTION_UNITS[@]}"; do
    enabled="${TRANSACTION_UNIT_ENABLED["${unit}"]}"
    active="${TRANSACTION_UNIT_ACTIVE["${unit}"]}"
    current_enabled="$(systemctl is-enabled "${unit}" 2>/dev/null || true)"
    case "${enabled}" in
      enabled)
        if [[ "${current_enabled}" == enabled-runtime ]] \
            || [[ "${current_enabled}" == linked-runtime ]]; then
          systemctl disable --runtime "${unit}" >/dev/null 2>&1 \
            || record_rollback_error "could not clear runtime-only enablement for ${unit}"
        fi
        systemctl enable "${unit}" >/dev/null 2>&1 \
          || record_rollback_error "could not re-enable ${unit}"
        ;;
      enabled-runtime)
        if [[ "${current_enabled}" == enabled ]] || [[ "${current_enabled}" == linked ]] \
            || [[ "${current_enabled}" == alias ]]; then
          systemctl disable "${unit}" >/dev/null 2>&1 \
            || record_rollback_error "could not clear persistent enablement for ${unit}"
        fi
        systemctl enable --runtime "${unit}" >/dev/null 2>&1 \
          || record_rollback_error "could not restore runtime enablement for ${unit}"
        ;;
      *)
        case "${current_enabled}" in
          enabled|linked|alias)
            systemctl disable "${unit}" >/dev/null 2>&1 \
              || record_rollback_error "could not restore disabled state for ${unit}"
            ;;
          enabled-runtime|linked-runtime)
            systemctl disable --runtime "${unit}" >/dev/null 2>&1 \
              || record_rollback_error "could not restore disabled runtime state for ${unit}"
            ;;
        esac
        ;;
    esac
    current_active="$(systemctl is-active "${unit}" 2>/dev/null || true)"
    case "${active}" in
      active|reloading|activating)
        systemctl start "${unit}" >/dev/null 2>&1 \
          || record_rollback_error "could not restart ${unit}"
        ;;
      *)
        case "${current_active}" in
          active|reloading|activating|deactivating)
            systemctl stop "${unit}" >/dev/null 2>&1 \
              || record_rollback_error "could not restore stopped state for ${unit}"
            ;;
        esac
        ;;
    esac
  done
}

rollback_install_transaction() {
  local status=$?
  local index unit
  [[ "${INSTALL_TRANSACTION_ACTIVE}" == true ]] || exit "${status}"
  [[ "${INSTALL_TRANSACTION_ROLLING_BACK}" == false ]] || exit "${status}"
  INSTALL_TRANSACTION_ROLLING_BACK=true
  INSTALL_TRANSACTION_ROLLBACK_FAILED=false
  trap - EXIT HUP INT TERM
  set +e
  for unit in "${TRANSACTION_UNITS[@]}"; do
    systemctl stop "${unit}" >/dev/null 2>&1 || true
  done
  for ((index=${#TRANSACTION_PATHS[@]} - 1; index >= 0; index--)); do
    restore_managed_path_snapshot "${index}"
  done
  remove_transaction_created_directories
  restore_existing_directory_metadata
  if [[ "${RELEASE_CREATED}" == true ]] && [[ -n "${release_dir:-}" ]] \
      && [[ "${release_dir}" == "${RELEASE_ROOT}/${release_version}" ]] \
      && [[ -d "${release_dir}" ]] && [[ ! -L "${release_dir}" ]]; then
    find "${release_dir}" -mindepth 1 -depth -delete \
      && rmdir "${release_dir}" \
      || record_rollback_error "could not remove transaction-created release ${release_dir}"
  fi
  if [[ -n "${RELEASE_STAGING}" ]] && [[ "${RELEASE_STAGING}" == "${RELEASE_ROOT}/."*".new."* ]] \
      && [[ -d "${RELEASE_STAGING}" ]] && [[ ! -L "${RELEASE_STAGING}" ]]; then
    find "${RELEASE_STAGING}" -mindepth 1 -depth -delete \
      && rmdir "${RELEASE_STAGING}" \
      || record_rollback_error "could not remove release staging ${RELEASE_STAGING}"
  fi
  if [[ "${RELEASE_ROOT_CREATED}" == true ]] && [[ -d "${RELEASE_ROOT}" ]] \
      && [[ ! -L "${RELEASE_ROOT}" ]]; then
    rmdir "${RELEASE_ROOT}" 2>/dev/null \
      || record_rollback_error "transaction-created release root is not empty: ${RELEASE_ROOT}"
  fi
  if [[ "${APP_ROOT_CREATED}" == true ]] && [[ -d "${APP_ROOT}" ]] \
      && [[ ! -L "${APP_ROOT}" ]]; then
    rmdir "${APP_ROOT}" 2>/dev/null \
      || record_rollback_error "transaction-created application root is not empty: ${APP_ROOT}"
  fi
  restore_account_state
  restore_unit_state
  # systemctl enable may recreate dependencies from the restored historical
  # unit's [Install] section. Reapply this one root-owned directory snapshot
  # after unit-state restoration so pre-existing third-party entries survive
  # exactly and a link absent before the transaction remains absent.
  if ((OPS_AGENT_TARGET_WANTS_SNAPSHOT_INDEX >= 0)); then
    restore_managed_path_snapshot "${OPS_AGENT_TARGET_WANTS_SNAPSHOT_INDEX}"
  fi
  if [[ "${INSTALL_TRANSACTION_ROLLBACK_FAILED}" == false ]]; then
    find "${INSTALL_TRANSACTION_DIR}" -mindepth 1 -depth -delete 2>/dev/null || true
    rmdir "${INSTALL_TRANSACTION_DIR}" 2>/dev/null || true
    printf 'Installation failed; all managed paths, identities and unit state were restored.\n' >&2
  else
    printf 'Installation failed and rollback was incomplete; root-only evidence remains at %s\n' \
      "${INSTALL_TRANSACTION_DIR}" >&2
  fi
  ((status != 0)) || status=1
  exit "${status}"
}

commit_install_transaction() {
  INSTALL_TRANSACTION_ACTIVE=false
  trap - EXIT HUP INT TERM
  if find "${INSTALL_TRANSACTION_DIR}" -mindepth 1 -depth -delete \
      && rmdir "${INSTALL_TRANSACTION_DIR}"; then
    INSTALL_TRANSACTION_DIR=""
  else
    printf 'Installation committed, but root-only transaction scratch could not be removed: %s\n' \
      "${INSTALL_TRANSACTION_DIR}" >&2
  fi
}

maybe_inject_install_failure() {
  local stage="$1"
  [[ "${OPS_AGENT_TEST_FAIL_AT:-}" != "${stage}" ]] || {
    printf 'Injected install failure after stage %s.\n' "${stage}" >&2
    return 97
  }
}

usage() {
  cat <<'EOF'
Usage:
  install-release.sh init [--admin-user USER] [--approve-required-plugins] [--enable-artifact ID ...] [--no-start]
  install-release.sh join --controller URL --controller-ca-sha256 FINGERPRINT [--token-file PATH] [--no-start]

This is the host-mutating half of the GitHub Release installer. It consumes an
already verified OPS_AGENT_PAYLOAD_DIR and never downloads or builds source.
`init` installs the core controller, local endpoint and TUI only. It never
installs or initializes BotMux or another external adapter.
The TUI adapter and base workload are required source plugins. Interactive
initialization displays and approves their exact source digest and scopes;
automation must pass --approve-required-plugins explicitly.
Fresh policies authorize no business artifact unless its exact catalog ID is
passed with --enable-artifact. Existing policies must be edited and reviewed
explicitly instead of being widened by the installer.
Fresh join requires --token-file. An existing server-only endpoint must omit
that flag so the new release validates and reuses its installed enrollment
without overwriting identity, policy, TLS, or broker receipt keys.
EOF
}

if (($# == 0)); then
  usage >&2
  exit 2
fi
MODE="$1"
shift
case "${MODE}" in
  init)
    while (($# > 0)); do
      case "$1" in
        --admin-user)
          (($# >= 2)) || { printf 'Missing --admin-user value.\n' >&2; exit 2; }
          ADMIN_USER="$2"
          shift 2
          ;;
        --enable-artifact)
          (($# >= 2)) || { printf 'Missing --enable-artifact value.\n' >&2; exit 2; }
          [[ "$2" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$ ]] || {
            printf 'Invalid --enable-artifact ID: %s\n' "$2" >&2
            exit 2
          }
          for enabled_artifact in "${ENABLED_ARTIFACTS[@]}"; do
            [[ "${enabled_artifact}" != "$2" ]] || {
              printf 'Artifact enabled more than once: %s\n' "$2" >&2
              exit 2
            }
          done
          ENABLED_ARTIFACTS+=("$2")
          shift 2
          ;;
        --approve-required-plugins) APPROVE_REQUIRED_PLUGINS=true; shift ;;
        --no-start) START_NOW=false; shift ;;
        -h|--help) usage; exit 0 ;;
        *) printf 'Unknown init argument: %s\n' "$1" >&2; exit 2 ;;
      esac
    done
    ;;
  join)
    while (($# > 0)); do
      case "$1" in
        --controller)
          (($# >= 2)) || { printf 'Missing --controller value.\n' >&2; exit 2; }
          CONTROLLER_URL="$2"
          shift 2
          ;;
        --controller-ca-sha256)
          (($# >= 2)) || { printf 'Missing --controller-ca-sha256 value.\n' >&2; exit 2; }
          CONTROLLER_CA_SHA256="$2"
          shift 2
          ;;
        --token-file)
          (($# >= 2)) || { printf 'Missing --token-file value.\n' >&2; exit 2; }
          ENROLLMENT_FILE="$2"
          shift 2
          ;;
        --no-start) START_NOW=false; shift ;;
        -h|--help) usage; exit 0 ;;
        *) printf 'Unknown join argument: %s\n' "$1" >&2; exit 2 ;;
      esac
    done
    [[ -n "${CONTROLLER_URL}" ]] || { printf 'join requires --controller URL.\n' >&2; exit 2; }
    [[ -n "${CONTROLLER_CA_SHA256}" ]] || { printf 'join requires --controller-ca-sha256 FINGERPRINT.\n' >&2; exit 2; }
    if [[ -n "${ENROLLMENT_FILE}" ]] \
        && { [[ ! -f "${ENROLLMENT_FILE}" ]] || [[ -L "${ENROLLMENT_FILE}" ]]; }; then
      printf 'Enrollment token must be a regular, non-symlink file.\n' >&2
      exit 2
    fi
    ;;
  -h|--help) usage; exit 0 ;;
  *) printf 'Unknown mode: %s\n' "${MODE}" >&2; usage >&2; exit 2 ;;
esac

if [[ "${MODE}" == init ]]; then
  RECEIPT_PUBLIC_GROUP="${CLIENT_GROUP}"
else
  RECEIPT_PUBLIC_GROUP="${SERVER_GROUP}"
fi

if [[ ${EUID} -ne 0 ]]; then
  printf 'Run the release installer as root.\n' >&2
  exit 1
fi
if [[ "$(uname -s)" != Linux ]] || [[ ! -d /run/systemd/system ]]; then
  printf 'Pi Ops Agent supports only Linux with systemd as PID 1.\n' >&2
  exit 1
fi
if [[ -z "${PAYLOAD_DIR}" ]] || [[ ! -d "${PAYLOAD_DIR}/app" ]]; then
  printf 'OPS_AGENT_PAYLOAD_DIR does not contain a release payload.\n' >&2
  exit 1
fi
if [[ "${MODE}" == init ]]; then
  botmux_setup_runner="${PAYLOAD_DIR}/app/dist/runtime/botmux-setup-run.js"
  if [[ ! -f "${botmux_setup_runner}" ]] || [[ -L "${botmux_setup_runner}" ]]; then
    printf 'Verified payload is missing the fixed exact-digest BotMux setup runner.\n' >&2
    exit 1
  fi
fi
if [[ "${MODE}" == init ]] && ((${#ENABLED_ARTIFACTS[@]} > 0)); then
  if [[ -f "${CONFIG_ROOT}/targets.json" ]]; then
    printf '%s\n' '--enable-artifact is only valid for a fresh target policy; review existing policy changes explicitly.' >&2
    exit 2
  fi
  preflight_node="${PAYLOAD_DIR}/app/runtime/node"
  preflight_initializer="${PAYLOAD_DIR}/app/scripts/initialize-target-policy.mjs"
  preflight_catalog="${PAYLOAD_DIR}/app/catalog/index.json"
  [[ -x "${preflight_node}" && -f "${preflight_initializer}" && -f "${preflight_catalog}" ]] || {
    printf 'Verified payload is missing artifact policy preflight files.\n' >&2
    exit 1
  }
  preflight_args=(--catalog-index "${preflight_catalog}" --validate-only)
  for enabled_artifact in "${ENABLED_ARTIFACTS[@]}"; do
    preflight_args+=(--enable-artifact "${enabled_artifact}")
  done
  "${preflight_node}" "${preflight_initializer}" "${preflight_args[@]}" >/dev/null
fi

install_native_dependencies() {
  local -a packages=(openssl ca-certificates diffutils)
  if [[ "${MODE}" == init ]]; then
    packages+=(bubblewrap sudo)
  fi
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${packages[@]}"
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y "${packages[@]}"
  elif command -v yum >/dev/null 2>&1; then
    yum install -y "${packages[@]}"
  elif command -v zypper >/dev/null 2>&1; then
    zypper --non-interactive install "${packages[@]}"
  elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --needed --noconfirm "${packages[@]}"
  else
    printf 'Install OpenSSL, CA certificates and diffutils, then retry.\n' >&2
    return 1
  fi
}

if ! command -v openssl >/dev/null 2>&1 || ! command -v diff >/dev/null 2>&1 \
    || { [[ "${MODE}" == init ]] && { ! command -v bwrap >/dev/null 2>&1 \
      || ! command -v sudo >/dev/null 2>&1 || ! command -v visudo >/dev/null 2>&1; }; }; then
  install_native_dependencies
fi

required_commands=(systemctl systemd-tmpfiles getent groupadd groupdel useradd userdel usermod install cp cmp mv ln readlink mktemp stat wc openssl sed tr cut grep find sleep diff dirname)
if [[ "${MODE}" == init ]]; then
  required_commands+=(gpasswd bwrap sha256sum hostname runuser sudo visudo)
fi
for required_command in "${required_commands[@]}"; do
  command -v "${required_command}" >/dev/null 2>&1 || {
    printf 'Missing installation dependency: %s\n' "${required_command}" >&2
    exit 1
  }
done
if [[ "${MODE}" == init ]] \
    && { [[ ! -x /usr/bin/env ]] || [[ ! -x /usr/bin/sudo ]] || [[ ! -x /usr/bin/bwrap ]]; }; then
  printf 'Pi Ops Agent requires fixed /usr/bin/env, /usr/bin/sudo, and /usr/bin/bwrap paths.\n' >&2
  exit 1
fi
SANDBOX_PRLIMIT=""
if [[ "${MODE}" == init ]]; then
  if [[ -x /usr/bin/prlimit ]]; then
    SANDBOX_PRLIMIT=/usr/bin/prlimit
  elif [[ -x /bin/prlimit ]]; then
    SANDBOX_PRLIMIT=/bin/prlimit
  else
    printf 'Pi Ops Agent requires the fixed util-linux prlimit boundary for Source Workloads.\n' >&2
    exit 1
  fi
fi

version_file="${PAYLOAD_DIR}/VERSION"
[[ -f "${version_file}" ]] || { printf 'Release VERSION is missing.\n' >&2; exit 1; }
IFS= read -r release_version <"${version_file}"
if [[ ! "${release_version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  printf 'Invalid release VERSION: %s\n' "${release_version}" >&2
  exit 1
fi

if [[ "${MODE}" == join ]]; then
  if [[ ! "${CONTROLLER_URL}" =~ ^https://[^[:space:]]+$ ]]; then
    printf 'The enrollment controller must be an https:// URL.\n' >&2
    exit 2
  fi
  if [[ ! "${CONTROLLER_CA_SHA256}" =~ ^sha256:[a-f0-9]{64}$ ]]; then
    printf 'The controller CA fingerprint must be canonical sha256:<64 lowercase hex>.\n' >&2
    exit 2
  fi
  if id "${SERVER_USER}" >/dev/null 2>&1 \
      || getent group "${SERVER_GROUP}" >/dev/null 2>&1 \
      || [[ -e "${CONFIG_ROOT}" ]] || [[ -L "${CONFIG_ROOT}" ]] \
      || [[ -e "${APP_ROOT}" ]] || [[ -L "${APP_ROOT}" ]] \
      || [[ -e /var/lib/ops-agent ]] || [[ -L /var/lib/ops-agent ]] \
      || [[ -e /var/log/ops-agent ]] || [[ -L /var/log/ops-agent ]] \
      || [[ -e "${UNIT_ROOT}/ops-agent-server.service" ]] \
      || [[ -e "${UNIT_ROOT}/ops-root-helper.service" ]] \
      || [[ -e "${UNIT_ROOT}/ops-pve-root-helper.service" ]] \
      || [[ -e "${OPS_AGENT_TARGET_WANTS_DIR}" ]] \
      || [[ -L "${OPS_AGENT_TARGET_WANTS_DIR}" ]]; then
    EXISTING_ENDPOINT_ENROLLMENT=true
  fi
  if [[ "${EXISTING_ENDPOINT_ENROLLMENT}" == true ]]; then
    if [[ -n "${ENROLLMENT_FILE}" ]]; then
      printf '%s\n' \
        'join found existing endpoint state and refuses to apply another enrollment bundle.' \
        'Retry without --token-file to validate and reuse the installed identity, policy, TLS, and receipt keys.' >&2
      exit 2
    fi
  else
    [[ -n "${ENROLLMENT_FILE}" ]] || {
      printf 'Fresh join requires --token-file PATH.\n' >&2
      exit 2
    }
    token_mode="$(stat -c '%a' "${ENROLLMENT_FILE}")"
    token_bytes="$(wc -c <"${ENROLLMENT_FILE}")"
    if ((10#${token_mode} % 100 > 0)); then
      printf 'Enrollment token file must not be group/world accessible (mode=%s).\n' "${token_mode}" >&2
      exit 2
    fi
    if ((token_bytes < 16 || token_bytes > 131072)); then
      printf 'Enrollment token file length is outside the supported range.\n' >&2
      exit 2
    fi
  fi
fi

if [[ "${MODE}" == init ]]; then
  if [[ -z "${ADMIN_USER}" ]] || ! id "${ADMIN_USER}" >/dev/null 2>&1; then
    printf 'init requires an existing non-root --admin-user (sudo normally supplies SUDO_USER).\n' >&2
    exit 1
  fi
  if [[ ! "${ADMIN_USER}" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
    printf 'The local administrator account name is not safe for generated policy files.\n' >&2
    exit 1
  fi
  if [[ "${ADMIN_USER}" == ops-agent* ]] || [[ "${ADMIN_USER}" == ops-adapter-* ]]; then
    printf 'The local administrator cannot use a reserved ops-agent or ops-adapter namespace.\n' >&2
    exit 1
  fi
  if [[ "$(id -u "${ADMIN_USER}")" == 0 ]] \
      || [[ "${ADMIN_USER}" == "${SERVICE_USER}" ]] \
      || [[ "${ADMIN_USER}" == "${SERVER_USER}" ]] \
      || [[ "${ADMIN_USER}" == "${REVIEWER_USER}" ]] \
      || [[ "${ADMIN_USER}" == "${BOTMUX_USER}" ]]; then
    printf 'The local administrator cannot be root or a Pi Ops Agent service account.\n' >&2
    exit 1
  fi
fi

if [[ "${MODE}" == join ]]; then
  # An endpoint has no model, TUI, reviewer, Adapter, client group, or related
  # mutable state. Keep the transaction inventory equally narrow so rollback
  # neither creates nor touches controller-only identities and directories.
  TRANSACTION_USERS=("${SERVER_USER}")
  TRANSACTION_GROUPS=("${SERVER_GROUP}")
  TRANSACTION_UNITS=(
    ops-agent-server.service
    ops-root-helper.service
    ops-pve-root-helper.service
  )
  TRANSACTION_INGRESS_UNITS=(ops-agent-server.service)
  TRANSACTION_DIRECTORY_CANDIDATES=(
    /usr/lib/ops-agent
    /run/ops-agent/helper
    /run/ops-agent
    /var/lib/ops-agent/root-helper
    /var/lib/ops-agent/pve-root-helper
    /var/lib/ops-agent
    /var/log/ops-agent/root-helper
    /var/log/ops-agent/pve-root-helper
    /var/log/ops-agent
  )
  for forbidden_user in "${SERVICE_USER}" "${REVIEWER_USER}" "${BOTMUX_USER}" "${LEASE_USER}"; do
    if id "${forbidden_user}" >/dev/null 2>&1; then
      printf 'join refuses a host with controller-only account %s; recover or uninstall that topology first.\n' \
        "${forbidden_user}" >&2
      exit 1
    fi
  done
  for forbidden_group in "${SERVICE_GROUP}" "${CLIENT_GROUP}" "${REVIEWER_GROUP}" "${BOTMUX_GROUP}" "${LEASE_GROUP}"; do
    if getent group "${forbidden_group}" >/dev/null; then
      printf 'join refuses a host with controller-only group %s; recover or uninstall that topology first.\n' \
        "${forbidden_group}" >&2
      exit 1
    fi
  done
  # Accept only the one stale dependency produced by older PVE endpoint
  # releases. It is removed transactionally below; every other target-wants
  # entry proves that this is not a server-only endpoint.
  validate_endpoint_controller_target_wants
  for forbidden_path in \
      "${CONFIG_ROOT}/agentd.json" "${CONFIG_ROOT}/models.json" \
      "${CONFIG_ROOT}/local-administrator.json" \
      "${CONFIG_ROOT}/agentd-guardian.json" "${CONFIG_ROOT}/credentials" \
      "${CONFIG_ROOT}/servers.json" "${CONFIG_ROOT}/approver" \
      "${CONFIG_ROOT}/tls/ca.key" "${CONFIG_ROOT}/tls/agent.crt" \
      "${CONFIG_ROOT}/tls/agent.key" "${CONFIG_ROOT}/tls/observer.crt" \
      "${CONFIG_ROOT}/tls/observer.key" \
      /var/lib/ops-agent/plugin-sources /var/lib/ops-agent/plugins \
      /var/lib/ops-agent/adapters /run/ops-agent/agentd /run/ops-agent/reviewer \
      /run/ops-agent/plugin-lease \
      "${UNIT_ROOT}/ops-agentd.service" "${UNIT_ROOT}/agentd-guardian.service" \
      "${UNIT_ROOT}/agentd-client-gateway.service" \
      "${UNIT_ROOT}/agentd-approval-reviewer.service" \
      "${UNIT_ROOT}/agentd-plugin-lease-broker.service" "${UNIT_ROOT}/ops-agent.target" \
      "${UNIT_ROOT}/ops-agent-healthcheck.service" "${UNIT_ROOT}/ops-agent-healthcheck.timer" \
      /usr/local/bin/ops-agent /usr/libexec/pi-ops-agent; do
    if [[ -e "${forbidden_path}" ]] || [[ -L "${forbidden_path}" ]]; then
      printf 'join refuses controller-only surface: %s\n' "${forbidden_path}" >&2
      exit 1
    fi
  done
fi

begin_install_transaction

validate_existing_group_members() {
  local group="$1"
  shift
  local member allowed permitted
  local -a existing_members=()
  [[ -n "$(getent group "${group}" 2>/dev/null || true)" ]] || return 0
  IFS=',' read -r -a existing_members <<<"$(getent group "${group}" | cut -d: -f4)"
  for member in "${existing_members[@]}"; do
    [[ -n "${member}" ]] || continue
    allowed=false
    for permitted in "$@"; do
      if [[ "${member}" == "${permitted}" ]]; then
        allowed=true
        break
      fi
    done
    [[ "${allowed}" == true ]] || {
      printf 'Sensitive group %s contains an unexpected account: %s\n' "${group}" "${member}" >&2
      return 1
    }
  done
}

ensure_service_identity() {
  local group="$1"
  local user="$2"
  local home="$3"
  local comment="$4"
  if ! getent group "${group}" >/dev/null; then
    groupadd --system "${group}"
  fi
  if ! id "${user}" >/dev/null 2>&1; then
    useradd --system --gid "${group}" --home-dir "${home}" \
      --shell /usr/sbin/nologin --comment "${comment}" "${user}"
  fi
  local uid gid primary_gid actual_home actual_shell
  IFS=: read -r _ _ uid primary_gid _ actual_home actual_shell < <(getent passwd "${user}")
  gid="$(getent group "${group}" | cut -d: -f3)"
  [[ "${uid}" =~ ^[0-9]+$ ]] && ((uid > 0)) || {
    printf 'Service account %s must have a non-root numeric UID.\n' "${user}" >&2
    return 1
  }
  [[ "${gid}" =~ ^[0-9]+$ ]] && ((gid > 0)) || {
    printf 'Service group %s must have a non-root numeric GID.\n' "${group}" >&2
    return 1
  }
  [[ "${primary_gid}" == "${gid}" ]] || {
    printf 'Service account %s must use %s as its primary group.\n' "${user}" "${group}" >&2
    return 1
  }
  [[ "${actual_home}" == "${home}" ]] || {
    printf 'Service account %s has unexpected home %s (expected %s).\n' \
      "${user}" "${actual_home}" "${home}" >&2
    return 1
  }
  case "${actual_shell}" in
    /usr/sbin/nologin|/sbin/nologin) ;;
    *)
      printf 'Service account %s must use a nologin shell.\n' "${user}" >&2
      return 1
      ;;
  esac
}

verify_unique_numeric_identity() {
  local kind="$1"
  local number="$2"
  local expected="$3"
  local records names
  if [[ "${kind}" == user ]]; then
    records="$(getent passwd "${number}")"
  else
    records="$(getent group "${number}")"
  fi
  names="$(printf '%s\n' "${records}" | cut -d: -f1)"
  [[ "${names}" == "${expected}" ]] || {
    printf '%s numeric ID %s is ambiguous or belongs to another identity: %s\n' \
      "${kind}" "${number}" "${names}" >&2
    return 1
  }
}

verify_supplementary_groups() {
  local user="$1"
  local expected_csv="$2"
  local primary actual item
  primary="$(id -gn "${user}")"
  actual=""
  while IFS= read -r item; do
    [[ -n "${item}" ]] || continue
    [[ "${item}" == "${primary}" ]] && continue
    if [[ -n "${actual}" ]]; then
      actual+=","
    fi
    actual+="${item}"
  done < <(id -nG "${user}" | tr ' ' '\n')
  [[ "${actual}" == "${expected_csv}" ]] || {
    printf 'Account %s has unexpected supplementary groups: %s (expected %s).\n' \
      "${user}" "${actual:-none}" "${expected_csv:-none}" >&2
    return 1
  }
}

if [[ "${MODE}" == join ]]; then
  validate_existing_group_members "${SERVER_GROUP}" "${SERVER_USER}"
  ensure_service_identity "${SERVER_GROUP}" "${SERVER_USER}" /var/lib/ops-agent/server \
    "Pi Ops Agent network server"
  server_uid="$(id -u "${SERVER_USER}")"
  server_gid="$(getent group "${SERVER_GROUP}" | cut -d: -f3)"
  verify_unique_numeric_identity user "${server_uid}" "${SERVER_USER}"
  verify_unique_numeric_identity group "${server_gid}" "${SERVER_GROUP}"
  usermod --groups "" "${SERVER_USER}"
  verify_supplementary_groups "${SERVER_USER}" ""
  validate_existing_group_members "${SERVER_GROUP}" "${SERVER_USER}"
else
validate_existing_group_members "${SERVICE_GROUP}" \
  "${SERVICE_USER}" "${SERVER_USER}" "${REVIEWER_USER}" "${BOTMUX_USER}" "${LEASE_USER}" "${ADMIN_USER:-}"
validate_existing_group_members "${CLIENT_GROUP}" \
  "${SERVICE_USER}" "${BOTMUX_USER}" "${LEASE_USER}" "${ADMIN_USER:-}"
validate_existing_group_members "${SERVER_GROUP}" \
  "${SERVICE_USER}" "${SERVER_USER}" "${REVIEWER_USER}" "${BOTMUX_USER}" "${LEASE_USER}" "${ADMIN_USER:-}"
validate_existing_group_members "${REVIEWER_GROUP}" \
  "${SERVICE_USER}" "${SERVER_USER}" "${REVIEWER_USER}" "${BOTMUX_USER}" "${LEASE_USER}" "${ADMIN_USER:-}"
validate_existing_group_members "${BOTMUX_GROUP}" \
  "${SERVICE_USER}" "${SERVER_USER}" "${REVIEWER_USER}" "${BOTMUX_USER}" "${LEASE_USER}" "${ADMIN_USER:-}"
validate_existing_group_members "${LEASE_GROUP}" \
  "${SERVICE_USER}" "${SERVER_USER}" "${REVIEWER_USER}" "${BOTMUX_USER}" "${LEASE_USER}" "${ADMIN_USER:-}"

ensure_service_identity "${SERVICE_GROUP}" "${SERVICE_USER}" /var/lib/ops-agent "Pi Ops Agent"
ensure_service_identity "${SERVER_GROUP}" "${SERVER_USER}" /var/lib/ops-agent/server \
  "Pi Ops Agent network server"
ensure_service_identity "${REVIEWER_GROUP}" "${REVIEWER_USER}" /var/empty \
  "Pi Ops Agent approval reviewer"
ensure_service_identity "${LEASE_GROUP}" "${LEASE_USER}" /var/empty \
  "Pi Ops Agent plugin lease broker"
if ! getent group "${CLIENT_GROUP}" >/dev/null; then
  groupadd --system "${CLIENT_GROUP}"
fi
if [[ "${MODE}" == init ]]; then
  ensure_service_identity "${BOTMUX_GROUP}" "${BOTMUX_USER}" "${BOTMUX_HOME}" \
    "Pi Ops Agent BotMux adapter"
fi

service_uids=(
  "$(id -u "${SERVICE_USER}")"
  "$(id -u "${SERVER_USER}")"
  "$(id -u "${REVIEWER_USER}")"
  "$(id -u "${LEASE_USER}")"
)
service_gids=(
  "$(getent group "${SERVICE_GROUP}" | cut -d: -f3)"
  "$(getent group "${SERVER_GROUP}" | cut -d: -f3)"
  "$(getent group "${REVIEWER_GROUP}" | cut -d: -f3)"
  "$(getent group "${LEASE_GROUP}" | cut -d: -f3)"
)
service_names=("${SERVICE_USER}" "${SERVER_USER}" "${REVIEWER_USER}" "${LEASE_USER}")
service_group_names=("${SERVICE_GROUP}" "${SERVER_GROUP}" "${REVIEWER_GROUP}" "${LEASE_GROUP}")
if [[ "${MODE}" == init ]]; then
  service_uids+=("$(id -u "${BOTMUX_USER}")")
  service_gids+=("$(getent group "${BOTMUX_GROUP}" | cut -d: -f3)")
  service_names+=("${BOTMUX_USER}")
  service_group_names+=("${BOTMUX_GROUP}")
fi
for index in "${!service_uids[@]}"; do
  verify_unique_numeric_identity user "${service_uids[${index}]}" "${service_names[${index}]}"
  verify_unique_numeric_identity group "${service_gids[${index}]}" "${service_group_names[${index}]}"
  for other_index in "${!service_uids[@]}"; do
    ((other_index <= index)) && continue
    [[ "${service_uids[${index}]}" != "${service_uids[${other_index}]}" ]] || {
      printf 'Service accounts %s and %s share UID %s.\n' \
        "${service_names[${index}]}" "${service_names[${other_index}]}" \
        "${service_uids[${index}]}" >&2
      exit 1
    }
    [[ "${service_gids[${index}]}" != "${service_gids[${other_index}]}" ]] || {
      printf 'Service groups %s and %s share GID %s.\n' \
        "${service_group_names[${index}]}" "${service_group_names[${other_index}]}" \
        "${service_gids[${index}]}" >&2
      exit 1
    }
  done
done

client_gid="$(getent group "${CLIENT_GROUP}" | cut -d: -f3)"
[[ "${client_gid}" =~ ^[0-9]+$ ]] && ((client_gid > 0)) || {
  printf 'Client group %s must have a non-root numeric GID.\n' "${CLIENT_GROUP}" >&2
  exit 1
}
verify_unique_numeric_identity group "${client_gid}" "${CLIENT_GROUP}"
for index in "${!service_gids[@]}"; do
  [[ "${client_gid}" != "${service_gids[${index}]}" ]] || {
    printf 'Client group and sensitive service group %s share GID %s.\n' \
      "${service_group_names[${index}]}" "${client_gid}" >&2
    exit 1
  }
done

usermod --groups "${CLIENT_GROUP}" "${SERVICE_USER}"
usermod --groups "" "${SERVER_USER}"
usermod --groups "" "${REVIEWER_USER}"
usermod --groups "" "${LEASE_USER}"
verify_supplementary_groups "${SERVICE_USER}" "${CLIENT_GROUP}"
verify_supplementary_groups "${SERVER_USER}" ""
verify_supplementary_groups "${REVIEWER_USER}" ""
verify_supplementary_groups "${LEASE_USER}" ""
if [[ "${MODE}" == init ]]; then
  usermod --groups "${CLIENT_GROUP}" "${BOTMUX_USER}"
  usermod --append --groups "${CLIENT_GROUP},${REVIEWER_GROUP}" "${ADMIN_USER}"
  for forbidden_group in "${SERVICE_GROUP}" "${SERVER_GROUP}" "${BOTMUX_GROUP}" "${LEASE_GROUP}"; do
    if id -nG "${ADMIN_USER}" | tr ' ' '\n' | grep -Fxq "${forbidden_group}"; then
      gpasswd --delete "${ADMIN_USER}" "${forbidden_group}" >/dev/null
    fi
  done
  admin_uid="$(id -u "${ADMIN_USER}")"
  admin_primary_gid="$(id -g "${ADMIN_USER}")"
  ((admin_uid > 0)) || { printf 'Administrator UID 0 is forbidden.\n' >&2; exit 1; }
  for index in "${!service_uids[@]}"; do
    [[ "${admin_uid}" != "${service_uids[${index}]}" ]] || {
      printf 'Administrator and service account %s share UID %s.\n' \
        "${service_names[${index}]}" "${admin_uid}" >&2
      exit 1
    }
    [[ "${admin_primary_gid}" != "${service_gids[${index}]}" ]] || {
      printf 'Administrator primary GID collides with sensitive group %s.\n' \
        "${service_group_names[${index}]}" >&2
      exit 1
    }
  done
  [[ "${admin_primary_gid}" != "${client_gid}" ]] || {
    printf 'Administrator primary GID collides with sensitive client group %s.\n' \
      "${CLIENT_GROUP}" >&2
    exit 1
  }
  verify_supplementary_groups "${BOTMUX_USER}" "${CLIENT_GROUP}"
  id -nG "${ADMIN_USER}" | tr ' ' '\n' | grep -Fxq "${CLIENT_GROUP}" || {
    printf 'Administrator did not acquire the agent client group.\n' >&2
    exit 1
  }
  id -nG "${ADMIN_USER}" | tr ' ' '\n' | grep -Fxq "${REVIEWER_GROUP}" || {
    printf 'Administrator did not acquire the approval reviewer group.\n' >&2
    exit 1
  }
  validate_existing_group_members "${SERVICE_GROUP}" "${SERVICE_USER}"
  validate_existing_group_members "${CLIENT_GROUP}" \
    "${SERVICE_USER}" "${ADMIN_USER}" "${BOTMUX_USER}"
  validate_existing_group_members "${REVIEWER_GROUP}" \
    "${REVIEWER_USER}" "${ADMIN_USER}"
  validate_existing_group_members "${BOTMUX_GROUP}" "${BOTMUX_USER}"
  validate_existing_group_members "${LEASE_GROUP}" "${LEASE_USER}"
fi
validate_existing_group_members "${SERVER_GROUP}" "${SERVER_USER}"
validate_existing_group_members "${SERVICE_GROUP}" "${SERVICE_USER}"
validate_existing_group_members "${LEASE_GROUP}" "${LEASE_USER}"
if [[ "${MODE}" != init ]]; then
  validate_existing_group_members "${CLIENT_GROUP}" "${SERVICE_USER}"
fi
fi
maybe_inject_install_failure accounts

if [[ "${MODE}" == init ]]; then
  for managed_plugin_directory in \
      /var/lib/ops-agent/plugin-sources \
      /var/lib/ops-agent/plugins \
      /var/lib/ops-agent/plugins/invocation-leases; do
    if [[ -e "${managed_plugin_directory}" ]] || [[ -L "${managed_plugin_directory}" ]]; then
      if [[ ! -d "${managed_plugin_directory}" ]] || [[ -L "${managed_plugin_directory}" ]]; then
        printf 'Managed plugin path must be a real directory: %s\n' \
          "${managed_plugin_directory}" >&2
        exit 1
      fi
    fi
  done
  install -d -o root -g root -m 0755 /var/lib/ops-agent/adapters
  install -d -o "${BOTMUX_USER}" -g "${BOTMUX_GROUP}" -m 0700 "${BOTMUX_HOME}"
  # Editable source belongs to the real administrator, not the client-plane
  # group. The broker runs as root and re-hashes it before registration;
  # agentd and adapters only read the approved immutable registry below.
  install -d -o "${ADMIN_USER}" -g "$(id -gn "${ADMIN_USER}")" -m 0750 \
    /var/lib/ops-agent/plugin-sources
  install -d -o root -g "${CLIENT_GROUP}" -m 2750 /var/lib/ops-agent/plugins
  install -d -o root -g "${LEASE_GROUP}" -m 0750 \
    /var/lib/ops-agent/plugins/invocation-leases
  [[ "$(stat -c '%U:%G:%a' /var/lib/ops-agent/plugins/invocation-leases)" \
      == "root:${LEASE_GROUP}:750" ]] || {
    printf 'Plugin invocation lease directory has unsafe ownership or mode.\n' >&2
    exit 1
  }
  while IFS= read -r -d '' lease_path; do
    lease_name="$(basename "${lease_path}")"
    if [[ ! -f "${lease_path}" ]] || [[ -L "${lease_path}" ]] \
        || [[ "$(stat -c '%h' "${lease_path}")" != 1 ]] \
        || [[ ! "${lease_name}" =~ ^(adapter|workload)\.[a-z0-9][a-z0-9.-]{0,63}\.lock$ ]]; then
      printf 'Unsafe legacy plugin invocation lease entry: %s\n' "${lease_path}" >&2
      exit 1
    fi
    chown root:"${LEASE_GROUP}" "${lease_path}"
    chmod 0640 "${lease_path}"
  done < <(find /var/lib/ops-agent/plugins/invocation-leases \
    -mindepth 1 -maxdepth 1 -print0)
fi

if [[ -L "${APP_ROOT}" ]] || { [[ -e "${APP_ROOT}" ]] && [[ ! -d "${APP_ROOT}" ]]; }; then
  printf 'Application root must be a real directory: %s\n' "${APP_ROOT}" >&2
  exit 1
fi
if [[ ! -d "${APP_ROOT}" ]]; then
  install -d -o root -g root -m 0755 "${APP_ROOT}"
  APP_ROOT_CREATED=true
fi
if [[ -L "${RELEASE_ROOT}" ]] || { [[ -e "${RELEASE_ROOT}" ]] && [[ ! -d "${RELEASE_ROOT}" ]]; }; then
  printf 'Release root must be a real directory: %s\n' "${RELEASE_ROOT}" >&2
  exit 1
fi
if [[ ! -d "${RELEASE_ROOT}" ]]; then
  install -d -o root -g root -m 0755 "${RELEASE_ROOT}"
  RELEASE_ROOT_CREATED=true
fi
release_dir="${RELEASE_ROOT}/${release_version}"
if [[ -e "${release_dir}" ]] || [[ -L "${release_dir}" ]]; then
  if [[ ! -d "${release_dir}" ]] || [[ -L "${release_dir}" ]]; then
    printf 'Existing release path is not a real directory: %s\n' "${release_dir}" >&2
    exit 1
  fi
  if ! diff --brief --recursive --no-dereference "${PAYLOAD_DIR}/app" "${release_dir}" >/dev/null; then
    printf 'Existing release %s does not match the verified payload; refusing same-version reuse.\n' "${release_version}" >&2
    exit 1
  fi
else
  RELEASE_STAGING="${RELEASE_ROOT}/.${release_version}.new.$$"
  install -d -o root -g root -m 0755 "${RELEASE_STAGING}"
  if ! cp -a "${PAYLOAD_DIR}/app/." "${RELEASE_STAGING}/"; then
    printf 'Could not stage verified release payload.\n' >&2
    exit 1
  fi
  chown -R root:root "${RELEASE_STAGING}"
  mv -- "${RELEASE_STAGING}" "${release_dir}"
  RELEASE_STAGING=""
  RELEASE_CREATED=true
fi
maybe_inject_install_failure release

json_config_helper_source="${release_dir}/bin/agentd-json-config-helper"
if [[ ! -f "${json_config_helper_source}" ]] || [[ -L "${json_config_helper_source}" ]] \
    || [[ ! -x "${json_config_helper_source}" ]]; then
  printf 'This release does not contain the fixed JSON config helper.\n' >&2
  exit 1
fi
install -d -o root -g root -m 0755 "$(dirname "${JSON_CONFIG_HELPER}")"
if [[ -e "${JSON_CONFIG_HELPER}" ]] || [[ -L "${JSON_CONFIG_HELPER}" ]]; then
  if [[ -d "${JSON_CONFIG_HELPER}" ]] && [[ ! -L "${JSON_CONFIG_HELPER}" ]]; then
    printf 'Fixed JSON config helper path is unexpectedly a directory.\n' >&2
    exit 1
  fi
  rm -f -- "${JSON_CONFIG_HELPER}"
fi
install -o root -g root -m 0755 "${json_config_helper_source}" "${JSON_CONFIG_HELPER}"
[[ "$(stat -c '%U:%G:%a' "${JSON_CONFIG_HELPER}")" == "root:root:755" ]] || {
  printf 'Fixed JSON config helper has unsafe ownership or mode.\n' >&2
  exit 1
}
cmp -s "${json_config_helper_source}" "${JSON_CONFIG_HELPER}" || {
  printf 'Fixed JSON config helper differs from the verified release binary.\n' >&2
  exit 1
}

if [[ "${MODE}" == join ]] && [[ "${EXISTING_ENDPOINT_ENROLLMENT}" == true ]]; then
  server_binary="${release_dir}/bin/ops-agent-server"
  [[ -x "${server_binary}" ]] || {
    printf 'This release does not contain ops-agent-server; refusing endpoint upgrade.\n' >&2
    exit 1
  }
  # Run before install -d/chown/chmod touches the config tree. A damaged or
  # partial trust topology must be rejected and restored, not repaired into a
  # shape that only appears valid to a later check.
  "${server_binary}" validate-enrollment --controller "${CONTROLLER_URL}" \
    --controller-ca-sha256 "${CONTROLLER_CA_SHA256}"
fi

install -d -o root -g root -m 0755 "${CONFIG_ROOT}"
if [[ "${MODE}" == init ]]; then
  install -d -o root -g root -m 0700 "${CONFIG_ROOT}/credentials"
  for config_name in agentd.json models.json; do
    source_config="${release_dir}/config/${config_name}"
    [[ -f "${source_config}" ]] || continue
    config_group="${SERVICE_GROUP}"
    if [[ "${config_name}" == agentd.json ]]; then
      config_group="${CLIENT_GROUP}"
    fi
    if [[ ! -e "${CONFIG_ROOT}/${config_name}" ]]; then
      install -o root -g "${config_group}" -m 0640 \
        "${source_config}" "${CONFIG_ROOT}/${config_name}"
    else
      [[ -f "${CONFIG_ROOT}/${config_name}" ]] && [[ ! -L "${CONFIG_ROOT}/${config_name}" ]] || {
        printf 'Managed config is not a regular non-symlink file: %s\n' \
          "${CONFIG_ROOT}/${config_name}" >&2
        exit 1
      }
      chown root:"${config_group}" "${CONFIG_ROOT}/${config_name}"
      chmod 0640 "${CONFIG_ROOT}/${config_name}"
      install -o root -g "${config_group}" -m 0640 \
        "${source_config}" "${CONFIG_ROOT}/${config_name}.dist"
    fi
  done

  agent_uid="$(id -u "${SERVICE_USER}")"
  agent_gid="$(getent group "${SERVICE_GROUP}" | cut -d: -f3)"
  client_gid="$(getent group "${CLIENT_GROUP}" | cut -d: -f3)"
  lease_uid="$(id -u "${LEASE_USER}")"
  lease_gid="$(getent group "${LEASE_GROUP}" | cut -d: -f3)"
  botmux_uid="$(id -u "${BOTMUX_USER}")"

  [[ "$(stat -c '%U:%G:%a' "${CONFIG_ROOT}")" == "root:root:755" ]] || {
    printf 'Config root must remain root-owned 0755 before administrator enrollment.\n' >&2
    exit 1
  }
  administrator_identity="${CONFIG_ROOT}/local-administrator.json"
  if [[ -e "${administrator_identity}" ]] || [[ -L "${administrator_identity}" ]]; then
    [[ -f "${administrator_identity}" ]] && [[ ! -L "${administrator_identity}" ]] \
        && [[ "$(stat -c '%h' "${administrator_identity}")" == 1 ]] \
        && [[ "$(stat -c '%U:%G:%a' "${administrator_identity}")" \
          == "root:${CLIENT_GROUP}:640" ]] || {
      printf 'Existing local administrator enrollment is not a root-owned client-plane record.\n' >&2
      exit 1
    }
    if ! "${release_dir}/runtime/node" - "${administrator_identity}" \
        "${admin_uid}" "${ADMIN_USER}" <<'NODE'
const fs = require("node:fs");
const [path, expectedUidText, expectedUsername] = process.argv.slice(2);
const payload = fs.readFileSync(path, "utf8");
if (Buffer.byteLength(payload) > 4096) process.exit(1);
const value = JSON.parse(payload);
if (value === null || Array.isArray(value) || typeof value !== "object"
    || Object.keys(value).sort().join(",") !== "uid,username,version"
    || value.version !== 1 || value.uid !== Number(expectedUidText)
    || value.username !== expectedUsername) process.exit(1);
NODE
    then
      printf '%s\n' \
        'The enrolled local administrator differs from --admin-user.' \
        'Ordinary upgrades cannot rotate the approval principal; use a dedicated reinitialization/rotation flow.' >&2
      exit 1
    fi
  else
    administrator_identity_tmp="$(mktemp "${CONFIG_ROOT}/.local-administrator.json.XXXXXX")"
    printf '{"version":1,"uid":%s,"username":"%s"}\n' \
      "${admin_uid}" "${ADMIN_USER}" >"${administrator_identity_tmp}"
    chown root:"${CLIENT_GROUP}" "${administrator_identity_tmp}"
    chmod 0640 "${administrator_identity_tmp}"
    mv -- "${administrator_identity_tmp}" "${administrator_identity}"
  fi
  [[ "$(stat -c '%U:%G:%a:%h' "${administrator_identity}")" \
      == "root:${CLIENT_GROUP}:640:1" ]] || {
    printf 'Local administrator enrollment has unsafe ownership, mode, or link count.\n' >&2
    exit 1
  }
fi
server_uid="$(id -u "${SERVER_USER}")"
server_gid="$(getent group "${SERVER_GROUP}" | cut -d: -f3)"
# Only root retains the local Unix-socket emergency identity. Normal TUI
# approvals always traverse HTTPS/mTLS and carry the separately signed grant;
# the human account is intentionally not a member of SERVER_GROUP.
approver_uid=0
runtime_tmp="$(mktemp "${CONFIG_ROOT}/.runtime.env.XXXXXX")"
if [[ "${MODE}" == init ]]; then
  printf 'OPS_AGENT_UID=%s\nOPS_AGENT_GID=%s\nOPS_CLIENT_GID=%s\nOPS_SERVER_UID=%s\nOPS_SERVER_GID=%s\nOPS_APPROVER_UID=%s\nOPS_ADMIN_UID=%s\nOPS_BOTMUX_UID=%s\nOPS_LEASE_UID=%s\nOPS_LEASE_GID=%s\n' \
    "${agent_uid}" "${agent_gid}" "${client_gid}" "${server_uid}" "${server_gid}" \
    "${approver_uid}" "${admin_uid}" "${botmux_uid}" "${lease_uid}" "${lease_gid}" \
    >"${runtime_tmp}"
else
  printf 'OPS_SERVER_UID=%s\nOPS_SERVER_GID=%s\nOPS_APPROVER_UID=%s\n' \
    "${server_uid}" "${server_gid}" "${approver_uid}" >"${runtime_tmp}"
fi
chown root:root "${runtime_tmp}"
chmod 0600 "${runtime_tmp}"
mv -f -- "${runtime_tmp}" "${CONFIG_ROOT}/runtime.env"

if [[ "${MODE}" == init ]]; then
  guardian_config_tmp="$(mktemp "${CONFIG_ROOT}/.agentd-guardian.json.XXXXXX")"
  cat >"${guardian_config_tmp}" <<EOF
{"version":1,"heartbeatPath":"/run/ops-agent/agentd/heartbeat.json","expectedUid":${agent_uid},"expectedExecutable":"${CURRENT_LINK}/runtime/node","expectedCgroup":"/system.slice/ops-agentd.service","heartbeatTimeout":"15s","checkInterval":"2s","operationTimeout":"1s","startupGrace":"20s","termGrace":"5s","maxClockSkew":"5s"}
EOF
  chown root:"${SERVICE_GROUP}" "${guardian_config_tmp}"
  chmod 0640 "${guardian_config_tmp}"
  mv -f -- "${guardian_config_tmp}" "${CONFIG_ROOT}/agentd-guardian.json"
fi

prepare_receipt_directories() {
  for directory in "${RECEIPT_ROOT}" "${RECEIPT_PRIVATE_ROOT}"; do
    if [[ -L "${directory}" ]] || { [[ -e "${directory}" ]] && [[ ! -d "${directory}" ]]; }; then
      printf 'Broker receipt credential path must be a real directory: %s\n' "${directory}" >&2
      return 1
    fi
  done
  install -d -o root -g root -m 0755 "${RECEIPT_ROOT}"
  install -d -o root -g root -m 0700 "${RECEIPT_PRIVATE_ROOT}"
  [[ -z "$(find "${RECEIPT_ROOT}" -type l -print -quit)" ]] || {
    printf 'Broker receipt credential tree must not contain symlinks.\n' >&2
    return 1
  }
}

secure_receipt_pair() {
  local domain="$1"
  local generate="$2"
  local private_key="${RECEIPT_PRIVATE_ROOT}/${domain}.key.pem"
  local public_key="${RECEIPT_ROOT}/${domain}-public.pem"
  local staging derived normalized
  if [[ "${generate}" == true ]] && [[ ! -e "${private_key}" ]] && [[ ! -e "${public_key}" ]]; then
    staging="$(mktemp -d "${INSTALL_TRANSACTION_DIR}/receipt-${domain}.XXXXXX")"
    openssl genpkey -algorithm ED25519 -out "${staging}/private.pem"
    openssl pkey -in "${staging}/private.pem" -pubout -out "${staging}/public.pem"
    install -o root -g root -m 0600 "${staging}/private.pem" "${private_key}"
    install -o root -g "${RECEIPT_PUBLIC_GROUP}" -m 0640 "${staging}/public.pem" "${public_key}"
    find "${staging}" -mindepth 1 -depth -delete
    rmdir "${staging}"
  fi
  if [[ ! -f "${private_key}" ]] || [[ -L "${private_key}" ]] \
      || [[ ! -f "${public_key}" ]] || [[ -L "${public_key}" ]]; then
    printf 'Broker receipt keypair is incomplete or unsafe for domain %s.\n' "${domain}" >&2
    return 1
  fi
  chown root:root "${private_key}"
  chmod 0600 "${private_key}"
  chown root:"${RECEIPT_PUBLIC_GROUP}" "${public_key}"
  chmod 0640 "${public_key}"
  [[ "$(stat -c '%U:%G:%a' "${private_key}")" == "root:root:600" ]] \
    && [[ "$(stat -c '%U:%G:%a' "${public_key}")" == "root:${RECEIPT_PUBLIC_GROUP}:640" ]] || {
      printf 'Broker receipt keypair has unsafe DAC for domain %s.\n' "${domain}" >&2
      return 1
    }
  derived="${INSTALL_TRANSACTION_DIR}/receipt-${domain}-derived.pem"
  normalized="${INSTALL_TRANSACTION_DIR}/receipt-${domain}-normalized.pem"
  openssl pkey -in "${private_key}" -pubout -out "${derived}"
  openssl pkey -pubin -in "${public_key}" -pubout -out "${normalized}"
  diff --brief "${derived}" "${normalized}" >/dev/null || {
    printf 'Broker receipt public key does not match its private key for domain %s.\n' \
      "${domain}" >&2
    return 1
  }
  rm -f -- "${derived}" "${normalized}"
}

initialize_local_broker_receipts() {
  prepare_receipt_directories
  secure_receipt_pair core true
  if [[ -x /usr/bin/pvesh ]]; then
    secure_receipt_pair pve true
  elif [[ -e "${RECEIPT_PRIVATE_ROOT}/pve.key.pem" ]] \
      || [[ -e "${RECEIPT_ROOT}/pve-public.pem" ]]; then
    # Preserve and validate historical PVE verification material if a host is
    # temporarily no longer advertising PVE. This keeps old receipts usable.
    secure_receipt_pair pve false
  fi
}

validate_enrolled_broker_receipts() {
  local has_pve=false
  prepare_receipt_directories
  secure_receipt_pair core false
  if [[ -e "${RECEIPT_PRIVATE_ROOT}/pve.key.pem" ]] \
      || [[ -e "${RECEIPT_ROOT}/pve-public.pem" ]]; then
    has_pve=true
    secure_receipt_pair pve false
  fi
  if [[ -x /usr/bin/pvesh ]] && [[ "${has_pve}" != true ]]; then
    printf 'PVE endpoint enrollment requires a bundle issued with --pve.\n' >&2
    return 1
  fi
  if [[ ! -x /usr/bin/pvesh ]] && [[ "${has_pve}" == true ]]; then
    printf 'A --pve enrollment bundle cannot be installed on a non-PVE endpoint.\n' >&2
    return 1
  fi
  PVE_ENDPOINT="${has_pve}"
}

initialize_local_endpoint() {
  local tls_root="${CONFIG_ROOT}/tls"
  local approver_root="${CONFIG_ROOT}/approver/root"
  local machine_raw machine_id server_hash server_id machine_name
  local observer_key_public observer_cert_public
  machine_raw="$(tr -cd 'a-fA-F0-9' </etc/machine-id 2>/dev/null || true)"
  if [[ ${#machine_raw} -lt 16 ]]; then
    machine_raw="$(hostname | sha256sum | cut -c1-32)"
  fi
  machine_id="machine-${machine_raw:0:32}"
  server_hash="$(printf '%s' "${machine_id}" | sha256sum | cut -c1-32)"
  server_id="server-${server_hash}"
  machine_name="$(hostname | tr -cd 'a-zA-Z0-9._-')"
  [[ -n "${machine_name}" ]] || machine_name="local-machine"

  if [[ -L "${CONFIG_ROOT}/approver" ]] || {
      [[ -e "${CONFIG_ROOT}/approver" ]] && [[ ! -d "${CONFIG_ROOT}/approver" ]]
    }; then
    printf 'Approver parent must be a real directory.\n' >&2
    return 1
  fi
  install -d -o root -g root -m 0700 "${CONFIG_ROOT}/approver"
  if [[ -L "${tls_root}" ]] || { [[ -e "${tls_root}" ]] && [[ ! -d "${tls_root}" ]]; }; then
    printf 'TLS credential root must be a real directory.\n' >&2
    return 1
  fi
  install -d -o root -g root -m 0755 "${tls_root}"
  install -d -o root -g root -m 0700 "${approver_root}"
  if [[ -n "$(find "${CONFIG_ROOT}/approver" -type l -print -quit)" ]]; then
    printf 'Approver credential tree must not contain symlinks.\n' >&2
    return 1
  fi
  if [[ -n "$(find "${tls_root}" -type l -print -quit)" ]]; then
    printf 'TLS credential tree must not contain symlinks.\n' >&2
    return 1
  fi

  if [[ -L "${CONFIG_ROOT}/servers.json" ]] \
      || { [[ -e "${CONFIG_ROOT}/servers.json" ]] && [[ ! -f "${CONFIG_ROOT}/servers.json" ]]; }; then
    printf 'Server registry must be a regular non-symlink file.\n' >&2
    return 1
  fi
  if [[ -f "${CONFIG_ROOT}/servers.json" ]]; then
    local migrated_servers
    migrated_servers="$(mktemp "${CONFIG_ROOT}/.servers-migrated.XXXXXX")"
    "${release_dir}/runtime/node" - \
      "${CONFIG_ROOT}/servers.json" "${migrated_servers}" "${server_id}" \
      "${CONFIG_ROOT}/approver" "${approver_root}" <<'NODE'
const fs = require("node:fs");
const path = require("node:path");
const [input, output, localServerId, approverParent, approverRoot] = process.argv.slice(2);
const document = JSON.parse(fs.readFileSync(input, "utf8"));
if (document.version !== 1 || !Array.isArray(document.servers) || document.servers.length > 1024) {
  throw new Error("existing server registry has an unsupported shape");
}
const fields = [
  ["approverCertPath", "approver.crt"],
  ["approverKeyPath", "approver.key"],
  ["approvalSigningKeyPath", "approval.key.pem"],
];
const cleanParent = path.resolve(approverParent);
const cleanRoot = path.resolve(approverRoot);
const within = (candidate, parent) => candidate.startsWith(parent + path.sep);
const safeServerId = (value) =>
  typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(value);
const ensureRealDirectory = (directory) => {
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error("approver destination is not a real directory: " + directory);
  }
  fs.chownSync(directory, 0, 0);
  fs.chmodSync(directory, 0o700);
};
ensureRealDirectory(cleanRoot);
for (const server of document.servers) {
  if (typeof server !== "object" || server === null || Array.isArray(server)
      || !safeServerId(server.serverId)) {
    throw new Error("server registry contains an invalid server identity");
  }
  const present = fields.map(([field]) => typeof server[field] === "string");
  if (present.every((value) => !value)) continue;
  if (!present.every(Boolean)) {
    throw new Error("server " + server.serverId + " has incomplete approver paths");
  }
  const destination = server.serverId === localServerId
    ? cleanRoot
    : path.join(cleanRoot, "servers", server.serverId);
  ensureRealDirectory(destination);
  for (const [field, basename] of fields) {
    const source = server[field];
    const cleanSource = path.resolve(source);
    if (source !== cleanSource || !within(cleanSource, cleanParent)
        || path.basename(cleanSource) !== basename) {
      throw new Error("server " + server.serverId + " has an unsafe " + field);
    }
    const sourceStat = fs.lstatSync(cleanSource);
    if (!sourceStat.isFile() || sourceStat.isSymbolicLink()
        || sourceStat.size < 1 || sourceStat.size > 131072) {
      throw new Error("server " + server.serverId + " has unsafe approver material");
    }
    const target = path.join(destination, basename);
    if (cleanSource !== target) {
      const temporary = target + ".new-" + process.pid;
      fs.copyFileSync(cleanSource, temporary, fs.constants.COPYFILE_EXCL);
      fs.chownSync(temporary, 0, 0);
      fs.chmodSync(temporary, 0o600);
      fs.renameSync(temporary, target);
    }
    fs.chownSync(target, 0, 0);
    fs.chmodSync(target, 0o600);
    const targetStat = fs.lstatSync(target);
    if (!targetStat.isFile() || targetStat.isSymbolicLink()
        || targetStat.uid !== 0 || (targetStat.mode & 0o777) !== 0o600) {
      throw new Error("server " + server.serverId + " approver destination is not root-only");
    }
    server[field] = target;
  }
}
fs.writeFileSync(output, JSON.stringify(document) + "\n", { mode: 0o600 });
NODE
    chown root:"${CLIENT_GROUP}" "${migrated_servers}"
    chmod 0640 "${migrated_servers}"
    mv -f -- "${migrated_servers}" "${CONFIG_ROOT}/servers.json"
  fi

  if [[ ! -f "${tls_root}/ca.crt" ]]; then
    local certificate_staging
    certificate_staging="$(mktemp -d "${CONFIG_ROOT}/.tls-init.XXXXXX")"
    cleanup_certificate_staging() {
      find "${certificate_staging}" -mindepth 1 -depth -delete 2>/dev/null || true
      rmdir "${certificate_staging}" 2>/dev/null || true
    }
    openssl req -x509 -newkey ed25519 -nodes -days 3650 \
      -subj '/CN=Pi Ops Agent Local CA' \
      -addext 'basicConstraints=critical,CA:TRUE' \
      -addext 'keyUsage=critical,keyCertSign,cRLSign' \
      -keyout "${certificate_staging}/ca.key" -out "${certificate_staging}/ca.crt"

    openssl genpkey -algorithm ED25519 -out "${certificate_staging}/server.key"
    openssl req -new -key "${certificate_staging}/server.key" -subj '/CN=localhost' \
      -out "${certificate_staging}/server.csr"
    cat >"${certificate_staging}/server.ext" <<'EOF'
[leaf]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF
    openssl x509 -req -days 825 -in "${certificate_staging}/server.csr" \
      -CA "${certificate_staging}/ca.crt" -CAkey "${certificate_staging}/ca.key" \
      -CAcreateserial -extfile "${certificate_staging}/server.ext" -extensions leaf \
      -out "${certificate_staging}/server.crt"

    for role in agent approver observer; do
      openssl genpkey -algorithm ED25519 -out "${certificate_staging}/${role}.key"
      openssl req -new -key "${certificate_staging}/${role}.key" \
        -subj "/CN=ops-agent-${role}" -out "${certificate_staging}/${role}.csr"
      cat >"${certificate_staging}/${role}.ext" <<EOF
[leaf]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectAltName=URI:spiffe://ops-agent/role/${role}
EOF
      openssl x509 -req -days 825 -in "${certificate_staging}/${role}.csr" \
        -CA "${certificate_staging}/ca.crt" -CAkey "${certificate_staging}/ca.key" \
        -CAserial "${certificate_staging}/ca.srl" \
        -extfile "${certificate_staging}/${role}.ext" -extensions leaf \
        -out "${certificate_staging}/${role}.crt"
    done
    openssl genpkey -algorithm ED25519 -out "${certificate_staging}/approval.key.pem"
    openssl pkey -in "${certificate_staging}/approval.key.pem" -pubout \
      -out "${certificate_staging}/approval.pub.pem"

    install -o root -g root -m 0600 "${certificate_staging}/ca.key" "${tls_root}/ca.key"
    install -o root -g "${CLIENT_GROUP}" -m 0640 "${certificate_staging}/ca.crt" "${tls_root}/ca.crt"
    install -o root -g "${SERVER_GROUP}" -m 0640 "${certificate_staging}/ca.crt" "${tls_root}/client-ca.crt"
    install -o root -g "${SERVER_GROUP}" -m 0640 "${certificate_staging}/server.key" "${tls_root}/server.key"
    install -o root -g "${SERVER_GROUP}" -m 0640 "${certificate_staging}/server.crt" "${tls_root}/server.crt"
    install -o "${SERVICE_USER}" -g "${SERVICE_GROUP}" -m 0600 \
      "${certificate_staging}/agent.key" "${tls_root}/agent.key"
    install -o root -g "${CLIENT_GROUP}" -m 0640 \
      "${certificate_staging}/agent.crt" "${tls_root}/agent.crt"
    install -o root -g "${CLIENT_GROUP}" -m 0640 \
      "${certificate_staging}/observer.key" "${tls_root}/observer.key"
    install -o root -g "${CLIENT_GROUP}" -m 0640 \
      "${certificate_staging}/observer.crt" "${tls_root}/observer.crt"
    install -o root -g root -m 0644 "${certificate_staging}/approval.pub.pem" "${tls_root}/approval.pub.pem"
    install -o root -g root -m 0600 \
      "${certificate_staging}/approver.key" "${approver_root}/approver.key"
    install -o root -g root -m 0600 \
      "${certificate_staging}/approver.crt" "${approver_root}/approver.crt"
    install -o root -g root -m 0600 \
      "${certificate_staging}/approval.key.pem" "${approver_root}/approval.key.pem"
    cleanup_certificate_staging
  fi
  if [[ ! -f "${tls_root}/observer.crt" ]] || [[ ! -f "${tls_root}/observer.key" ]]; then
    local observer_staging observer_serial
    [[ -f "${tls_root}/ca.crt" ]] && [[ ! -L "${tls_root}/ca.crt" ]] \
      && [[ -f "${tls_root}/ca.key" ]] && [[ ! -L "${tls_root}/ca.key" ]] || {
      printf 'Cannot create the observer identity without the local CA key.\n' >&2
      return 1
    }
    observer_staging="$(mktemp -d "${CONFIG_ROOT}/.observer-init.XXXXXX")"
    openssl genpkey -algorithm ED25519 -out "${observer_staging}/observer.key"
    openssl req -new -key "${observer_staging}/observer.key" \
      -subj '/CN=ops-agent-observer' -out "${observer_staging}/observer.csr"
    cat >"${observer_staging}/observer.ext" <<'EOF'
[leaf]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectAltName=URI:spiffe://ops-agent/role/observer
EOF
    observer_serial="$(openssl rand -hex 16)"
    openssl x509 -req -days 825 -in "${observer_staging}/observer.csr" \
      -CA "${tls_root}/ca.crt" -CAkey "${tls_root}/ca.key" \
      -set_serial "0x${observer_serial}" \
      -extfile "${observer_staging}/observer.ext" -extensions leaf \
      -out "${observer_staging}/observer.crt"
    install -o root -g "${CLIENT_GROUP}" -m 0640 \
      "${observer_staging}/observer.key" "${tls_root}/observer.key"
    install -o root -g "${CLIENT_GROUP}" -m 0640 \
      "${observer_staging}/observer.crt" "${tls_root}/observer.crt"
    find "${observer_staging}" -mindepth 1 -depth -delete
    rmdir "${observer_staging}"
  fi
  for required_security_file in \
    "${tls_root}/ca.crt" "${tls_root}/client-ca.crt" \
    "${tls_root}/server.crt" "${tls_root}/server.key" \
    "${tls_root}/agent.crt" "${tls_root}/agent.key" \
    "${tls_root}/observer.crt" "${tls_root}/observer.key" \
    "${tls_root}/approval.pub.pem" \
    "${approver_root}/approver.crt" "${approver_root}/approver.key" \
    "${approver_root}/approval.key.pem"; do
    [[ -f "${required_security_file}" ]] && [[ ! -L "${required_security_file}" ]] || {
      printf 'Local endpoint security material is incomplete: %s\n' "${required_security_file}" >&2
      return 1
    }
  done
  # Keep server, agent-role and observer-client credential sets disjoint even
  # on upgrades from releases that exposed agent.key through a shared group.
  chown root:root "${tls_root}" "${tls_root}/ca.key" "${tls_root}/approval.pub.pem"
  chmod 0755 "${tls_root}"
  chmod 0600 "${tls_root}/ca.key"
  chmod 0644 "${tls_root}/approval.pub.pem"
  chown root:"${CLIENT_GROUP}" \
    "${tls_root}/ca.crt" "${tls_root}/agent.crt" \
    "${tls_root}/observer.crt" "${tls_root}/observer.key"
  chmod 0640 \
    "${tls_root}/ca.crt" "${tls_root}/agent.crt" \
    "${tls_root}/observer.crt" "${tls_root}/observer.key"
  chown "${SERVICE_USER}:${SERVICE_GROUP}" "${tls_root}/agent.key"
  chmod 0600 "${tls_root}/agent.key"
  chown root:"${SERVER_GROUP}" \
    "${tls_root}/client-ca.crt" "${tls_root}/server.crt" "${tls_root}/server.key"
  chmod 0640 "${tls_root}/client-ca.crt" "${tls_root}/server.crt" "${tls_root}/server.key"
  [[ "$(stat -c '%U:%G:%a' "${tls_root}/agent.key")" \
      == "${SERVICE_USER}:${SERVICE_GROUP}:600" ]] || {
    printf 'Agent TLS private key is not restricted to the agent service UID.\n' >&2
    return 1
  }
  [[ "$(stat -c '%U:%G:%a' "${tls_root}/observer.key")" \
      == "root:${CLIENT_GROUP}:640" ]] || {
    printf 'Observer TLS private key does not have the expected client-group DAC.\n' >&2
    return 1
  }
  openssl verify -CAfile "${tls_root}/ca.crt" "${tls_root}/observer.crt" >/dev/null
  openssl x509 -in "${tls_root}/observer.crt" -noout -ext subjectAltName \
    | grep -Fq 'URI:spiffe://ops-agent/role/observer' || {
    printf 'Observer TLS certificate does not carry the fixed observer SPIFFE role.\n' >&2
    return 1
  }
  observer_key_public="${INSTALL_TRANSACTION_DIR}/observer-key.pub.pem"
  observer_cert_public="${INSTALL_TRANSACTION_DIR}/observer-cert.pub.pem"
  openssl pkey -in "${tls_root}/observer.key" -pubout -out "${observer_key_public}"
  openssl x509 -in "${tls_root}/observer.crt" -pubkey -noout >"${observer_cert_public}"
  diff --brief "${observer_key_public}" "${observer_cert_public}" >/dev/null || {
    printf 'Observer TLS certificate and private key do not match.\n' >&2
    return 1
  }
  for approver_security_file in \
    "${approver_root}/approver.crt" "${approver_root}/approver.key" \
    "${approver_root}/approval.key.pem"; do
    [[ ! -L "${approver_security_file}" ]] || {
      printf 'Approver security material must not be a symlink: %s\n' "${approver_security_file}" >&2
      return 1
    }
    chown root:root "${approver_security_file}"
    chmod 0600 "${approver_security_file}"
  done

  if [[ -L "${CONFIG_ROOT}/server-identity.json" ]] \
      || { [[ -e "${CONFIG_ROOT}/server-identity.json" ]] \
        && [[ ! -f "${CONFIG_ROOT}/server-identity.json" ]]; }; then
    printf 'Server identity must be a regular non-symlink file.\n' >&2
    return 1
  fi
  if [[ ! -e "${CONFIG_ROOT}/server-identity.json" ]]; then
    cat >"${CONFIG_ROOT}/server-identity.json" <<EOF
{"version":1,"serverId":"${server_id}","machineId":"${machine_id}","machineName":"${machine_name}","account":"${SERVER_USER}"}
EOF
    chown root:"${SERVER_GROUP}" "${CONFIG_ROOT}/server-identity.json"
    chmod 0640 "${CONFIG_ROOT}/server-identity.json"
  else
    "${release_dir}/runtime/node" -e '
      const fs = require("node:fs");
      const [file, serverId, machineId, account] = process.argv.slice(1);
      const value = JSON.parse(fs.readFileSync(file, "utf8"));
      if (value.version !== 1 || value.serverId !== serverId
          || value.machineId !== machineId || value.account !== account) {
        throw new Error("existing server identity does not match this machine");
      }
    ' "${CONFIG_ROOT}/server-identity.json" "${server_id}" "${machine_id}" "${SERVER_USER}"
    chown root:"${SERVER_GROUP}" "${CONFIG_ROOT}/server-identity.json"
    chmod 0640 "${CONFIG_ROOT}/server-identity.json"
  fi
  POLICY_CANDIDATE="${CONFIG_ROOT}/.targets.json.candidate.${release_version}.$$"
  [[ ! -e "${POLICY_CANDIDATE}" ]] || {
    printf 'Refusing to overwrite an existing policy candidate: %s\n' "${POLICY_CANDIDATE}" >&2
    return 1
  }
  local -a policy_initializer_args=(
    --catalog-index "${release_dir}/catalog/index.json"
    --policy "${CONFIG_ROOT}/targets.json"
    --output "${POLICY_CANDIDATE}"
  )
  local enabled_artifact
  for enabled_artifact in "${ENABLED_ARTIFACTS[@]}"; do
    policy_initializer_args+=(--enable-artifact "${enabled_artifact}")
  done
  "${release_dir}/runtime/node" "${release_dir}/scripts/initialize-target-policy.mjs" \
    "${policy_initializer_args[@]}" >/dev/null
  chown root:"${SERVER_GROUP}" "${POLICY_CANDIDATE}"
  chmod 0640 "${POLICY_CANDIDATE}"
  local servers_candidate
  servers_candidate="$(mktemp "${CONFIG_ROOT}/.servers.json.XXXXXX")"
  "${release_dir}/runtime/node" - \
    "${CONFIG_ROOT}/servers.json" "${servers_candidate}" \
    "${server_id}" "${machine_id}" "${tls_root}" \
    "${approver_root}" "${RECEIPT_ROOT}" \
    "${CORE_RECEIPT_KEY_ID}" "${PVE_RECEIPT_KEY_ID}" <<'NODE'
const fs = require("node:fs");
const [input, output, serverId, machineId, tlsRoot, approverRoot,
  receiptRoot, coreReceiptKeyId, pveReceiptKeyId] = process.argv.slice(2);
let document = { version: 1, servers: [] };
if (fs.existsSync(input)) document = JSON.parse(fs.readFileSync(input, "utf8"));
if (document.version !== 1 || !Array.isArray(document.servers) || document.servers.length > 1024) {
  throw new Error("existing server registry has an unsupported shape");
}
if (document.servers.some((server) => server.machineId === machineId && server.serverId !== serverId)) {
  throw new Error("existing server registry binds this machine to a different server identity");
}
const desired = {
  serverId,
  machineId,
  baseUrl: "https://127.0.0.1:7443",
  caPath: `${tlsRoot}/ca.crt`,
  certPath: `${tlsRoot}/agent.crt`,
  keyPath: `${tlsRoot}/agent.key`,
  observerCertPath: `${tlsRoot}/observer.crt`,
  observerKeyPath: `${tlsRoot}/observer.key`,
  approverCertPath: `${approverRoot}/approver.crt`,
  approverKeyPath: `${approverRoot}/approver.key`,
  approvalSigningKeyPath: `${approverRoot}/approval.key.pem`,
  approvalKeyId: "local-approver-v1",
  coreReceiptKeyId,
  coreReceiptPublicKeyPath: `${receiptRoot}/core-public.pem`,
  serverName: "localhost",
  enabled: true,
};
if (fs.existsSync(`${receiptRoot}/pve-public.pem`)) {
  desired.pveReceiptKeyId = pveReceiptKeyId;
  desired.pveReceiptPublicKeyPath = `${receiptRoot}/pve-public.pem`;
}
const existing = document.servers.find((server) => server.serverId === serverId);
if (existing === undefined) {
  document.servers.push(desired);
} else {
  if (existing.machineId !== machineId) throw new Error("local serverId is bound to a different machineId");
  existing.caPath = desired.caPath;
  existing.certPath = desired.certPath;
  existing.keyPath = desired.keyPath;
  existing.observerCertPath = desired.observerCertPath;
  existing.observerKeyPath = desired.observerKeyPath;
  existing.approverCertPath = desired.approverCertPath;
  existing.approverKeyPath = desired.approverKeyPath;
  existing.approvalSigningKeyPath = desired.approvalSigningKeyPath;
  existing.approvalKeyId = desired.approvalKeyId;
  existing.coreReceiptKeyId = desired.coreReceiptKeyId;
  existing.coreReceiptPublicKeyPath = desired.coreReceiptPublicKeyPath;
  if (desired.pveReceiptKeyId === undefined) {
    delete existing.pveReceiptKeyId;
    delete existing.pveReceiptPublicKeyPath;
  } else {
    existing.pveReceiptKeyId = desired.pveReceiptKeyId;
    existing.pveReceiptPublicKeyPath = desired.pveReceiptPublicKeyPath;
  }
}
fs.writeFileSync(output, `${JSON.stringify(document)}\n`, { mode: 0o600 });
NODE
  chown root:"${CLIENT_GROUP}" "${servers_candidate}"
  chmod 0640 "${servers_candidate}"
  mv -f -- "${servers_candidate}" "${CONFIG_ROOT}/servers.json"
  [[ "$(stat -c '%U:%G:%a' "${CONFIG_ROOT}/servers.json")" \
      == "root:${CLIENT_GROUP}:640" ]] || {
    printf 'Server registry does not have the expected client-group DAC.\n' >&2
    return 1
  }
  servers_candidate=""
}

install_approval_sudoers() {
  local sudoers_candidate="${INSTALL_TRANSACTION_DIR}/ops-agent-approval.sudoers"
  cat >"${sudoers_candidate}" <<EOF
Defaults!${CURRENT_LINK}/bin/agentd-approval-submit timestamp_timeout=0
Defaults!/usr/libexec/pi-ops-agent/setup-botmux timestamp_timeout=0
${ADMIN_USER} ALL=(root) PASSWD: ${CURRENT_LINK}/bin/agentd-approval-submit *
${ADMIN_USER} ALL=(root) PASSWD: /usr/libexec/pi-ops-agent/setup-botmux ""
EOF
  chown root:root "${sudoers_candidate}"
  chmod 0440 "${sudoers_candidate}"
  visudo -cf "${sudoers_candidate}" >/dev/null
  install -o root -g root -m 0440 "${sudoers_candidate}" "${APPROVAL_SUDOERS}"
  visudo -cf /etc/sudoers >/dev/null
}

verify_effective_sudo_policy() {
  local output admin_policy botmux_policy
  [[ -x /usr/bin/sudo ]] || {
    printf 'Effective sudo policy probe requires /usr/bin/sudo.\n' >&2
    return 1
  }
  runuser -u "${ADMIN_USER}" -- /usr/bin/sudo -k

  admin_policy="${INSTALL_TRANSACTION_DIR}/sudo-policy-${ADMIN_USER}.log"
  /usr/bin/sudo -U "${ADMIN_USER}" -l >"${admin_policy}" 2>&1 || {
    printf 'Cannot inspect the effective administrator sudo policy.\n' >&2
    sed -n '1,10p' "${admin_policy}" >&2
    return 1
  }
  if grep -F 'NOPASSWD:' "${admin_policy}" \
      | grep -Fq "${CURRENT_LINK}/bin/agentd-approval-submit"; then
    printf 'Unsafe sudo policy: an administrator NOPASSWD rule names agentd-approval-submit.\n' >&2
    return 1
  fi

  probe_requires_password() {
    local probe_name="$1"
    shift
    output="${INSTALL_TRANSACTION_DIR}/sudo-probe-${probe_name}.log"
    if runuser -u "${ADMIN_USER}" -- /usr/bin/env LC_ALL=C \
        /usr/bin/sudo -n -- "$@" >"${output}" 2>&1; then
      printf 'Unsafe sudo policy: %s ran non-interactively without a password.\n' \
        "${probe_name}" >&2
      return 1
    fi
    if ! grep -Fq 'a password is required' "${output}"; then
      # A correctly shaped helper probe deliberately references a nonexistent
      # server and exits without side effects if sudo actually launches it.
      # Any helper diagnostic therefore proves an argument-specific NOPASSWD
      # rule matched, even when the helper itself returned a non-zero status.
      printf 'Cannot prove PASSWD enforcement for %s; sudo said:\n' "${probe_name}" >&2
      sed -n '1,5p' "${output}" >&2
      return 1
    fi
  }

  # The approval rule contains an argv wildcard. A bare-command probe alone
  # misses site policy such as NOPASSWD rules restricted to `--action approve`.
  # Exercise one complete, syntactically valid, non-mutating argv shape for
  # every supported action; the random-looking identities are intentionally
  # absent from the installed server registry.
  local action change_prefix
  for action in approve reject rollback; do
    for change_prefix in change pve-change; do
      probe_requires_password "agentd-approval-submit-${change_prefix}-${action}" \
        "${CURRENT_LINK}/bin/agentd-approval-submit" \
        --action "${action}" \
        --server-id sudo-policy-probe-server \
        --machine-id sudo-policy-probe-machine \
        --target-id sudo-policy-probe-target \
        --change-id "${change_prefix}-sudo-policy-probe" \
        --user-intent-b64 c3Vkby1wb2xpY3ktcHJvYmU
    done
  done
  probe_requires_password setup-botmux /usr/libexec/pi-ops-agent/setup-botmux

  botmux_policy="${INSTALL_TRANSACTION_DIR}/sudo-probe-${BOTMUX_USER}.log"
  if /usr/bin/sudo -U "${BOTMUX_USER}" -l >"${botmux_policy}" 2>&1; then
    printf 'Unsafe sudo policy: dedicated BotMux account has at least one sudo rule:\n' >&2
    sed -n '1,10p' "${botmux_policy}" >&2
    return 1
  fi
}

secure_registered_approver_material() {
  local approver_parent="${CONFIG_ROOT}/approver"
  local approver_root="${approver_parent}/root"
  [[ -d "${approver_parent}" ]] && [[ ! -L "${approver_parent}" ]] || {
    printf 'Approver directory is missing or unsafe.\n' >&2
    return 1
  }
  [[ -z "$(find "${approver_parent}" -type l -print -quit)" ]] || {
    printf 'Approver directory contains a symlink.\n' >&2
    return 1
  }
  while IFS= read -r -d '' key; do
    chown root:root "${key}"
    chmod 0600 "${key}"
  done < <(find "${approver_parent}" -type f \
    \( -name approver.crt -o -name approver.key -o -name approval.key.pem \) -print0)
  while IFS= read -r -d '' directory; do
    chown root:root "${directory}"
    chmod 0700 "${directory}"
  done < <(find "${approver_parent}" -depth -type d -print0)
  "${release_dir}/runtime/node" - "${CONFIG_ROOT}/servers.json" "${approver_root}" <<'NODE'
const fs = require("node:fs");
const path = require("node:path");
const [registryPath, approverRoot] = process.argv.slice(2);
const document = JSON.parse(fs.readFileSync(registryPath, "utf8"));
if (document.version !== 1 || !Array.isArray(document.servers)) {
  throw new Error("server registry has an unsupported shape");
}
const root = path.resolve(approverRoot);
for (const server of document.servers) {
  const values = [
    server.approverCertPath,
    server.approverKeyPath,
    server.approvalSigningKeyPath,
  ];
  const present = values.map((value) => typeof value === "string");
  if (present.every((value) => !value)) continue;
  if (!present.every(Boolean)) throw new Error("server registry has incomplete approver paths");
  for (const value of values) {
    const clean = path.resolve(value);
    if (value !== clean || !clean.startsWith(root + path.sep)) {
      throw new Error("server registry retains a non-root approver path");
    }
    const stat = fs.lstatSync(clean);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== 0
        || (stat.mode & 0o777) !== 0o600) {
      throw new Error("registered approver material is not root-only");
    }
  }
}
NODE
}

if [[ "${MODE}" == init ]]; then
  initialize_local_broker_receipts
  initialize_local_endpoint
else
  server_binary="${release_dir}/bin/ops-agent-server"
  if [[ ! -x "${server_binary}" ]]; then
    printf 'This release does not contain ops-agent-server; refusing partial join.\n' >&2
    exit 1
  fi
  if [[ "${EXISTING_ENDPOINT_ENROLLMENT}" != true ]]; then
    enrollment_file="$(mktemp "${INSTALL_TRANSACTION_DIR}/enrollment.XXXXXX")"
    install -o root -g root -m 0600 "${ENROLLMENT_FILE}" "${enrollment_file}"
    "${server_binary}" enroll --controller "${CONTROLLER_URL}" \
      --controller-ca-sha256 "${CONTROLLER_CA_SHA256}" --token-file "${enrollment_file}"
    rm -f -- "${enrollment_file}"
  fi
  # A fresh signed bundle is the only source of endpoint receipt identities;
  # an upgrade only revalidates and reuses the already installed keys. The
  # exact PVE/non-PVE match is checked before unit selection and neither path
  # may generate a controller-unknown fallback key.
  validate_enrolled_broker_receipts
fi
maybe_inject_install_failure config

disable_managed_unit_for_cleanup() {
  local unit="$1"
  local enablement
  enablement="$(systemctl is-enabled "${unit}" 2>/dev/null || true)"
  case "${enablement}" in
    enabled|linked|alias) systemctl disable "${unit}" ;;
    enabled-runtime|linked-runtime) systemctl disable --runtime "${unit}" ;;
  esac
}

for unit in "${release_dir}"/systemd/*.service "${release_dir}"/systemd/*.timer "${release_dir}"/systemd/*.target; do
  [[ -f "${unit}" ]] || continue
  unit_name="$(basename "${unit}")"
  if [[ "${MODE}" == join ]]; then
    case "${unit_name}" in
      ops-agent-server.service|ops-root-helper.service) ;;
      ops-pve-root-helper.service)
        [[ "${PVE_ENDPOINT}" == true ]] || continue
        ;;
      *) continue ;;
    esac
  elif [[ "${unit_name}" == ops-pve-root-helper.service ]] && [[ ! -x /usr/bin/pvesh ]]; then
    # The PVE broker is not part of a non-PVE host's installed unit set. Keep
    # any historical state/audit, but remove a stale managed unit on upgrade.
    disable_managed_unit_for_cleanup "${unit_name}"
    rm -f -- "${UNIT_ROOT}/${unit_name}"
    continue
  fi
  install -o root -g root -m 0644 "${unit}" "${UNIT_ROOT}/${unit_name}"
done
cleanup_pve_controller_target_want
if [[ "${MODE}" == init ]] && [[ ! -f "${release_dir}/systemd/ops-systemd-helper.service" ]]; then
  # v0.2 compatibility cleanup. State and audit are deliberately preserved;
  # rollback still has the old unit/drop-in snapshot and its prior unit state.
  disable_managed_unit_for_cleanup ops-systemd-helper.service
  rm -f -- "${UNIT_ROOT}/ops-systemd-helper.service"
fi
if [[ "${MODE}" == init ]]; then
for existing_dropin in "${UNIT_ROOT}"/ops-*.service.d/zzzz-ops-agent-*.conf; do
  [[ -f "${existing_dropin}" ]] || continue
  dropin_directory="$(basename "$(dirname "${existing_dropin}")")"
  dropin_name="$(basename "${existing_dropin}")"
  if [[ "${dropin_directory}/${dropin_name}" == "ops-agentd.service.d/zzzz-ops-agent-credential.conf" ]]; then
    continue
  fi
  if [[ ! -f "${release_dir}/systemd/${dropin_directory}/${dropin_name}" ]]; then
    rm -f -- "${existing_dropin}"
  fi
done
for dropin_dir in "${release_dir}"/systemd/*.service.d; do
  [[ -d "${dropin_dir}" ]] || continue
  destination_dropin="${UNIT_ROOT}/$(basename "${dropin_dir}")"
  install -d -o root -g root -m 0755 "${destination_dropin}"
  for dropin in "${dropin_dir}"/*.conf; do
    [[ -f "${dropin}" ]] || continue
    install -o root -g root -m 0644 "${dropin}" "${destination_dropin}/$(basename "${dropin}")"
  done
done
install -d -o root -g root -m 0755 "${UNIT_ROOT}/ops-agentd.service.d"
cat >"${UNIT_ROOT}/ops-agentd.service.d/zzzz-ops-agent-credential.conf" <<'EOF'
[Service]
LoadCredentialEncrypted=deepseek_api_key:/etc/ops-agent/credentials/deepseek_api_key.cred
EOF
chown root:root "${UNIT_ROOT}/ops-agentd.service.d/zzzz-ops-agent-credential.conf"
chmod 0644 "${UNIT_ROOT}/ops-agentd.service.d/zzzz-ops-agent-credential.conf"
fi
tmpfiles_source="${release_dir}/systemd/ops-agent.tmpfiles.conf"
if [[ "${MODE}" == join ]]; then
  tmpfiles_source="${release_dir}/systemd/ops-agent-endpoint.tmpfiles.conf"
fi
if [[ -f "${tmpfiles_source}" ]]; then
  install -o root -g root -m 0644 "${tmpfiles_source}" "${TMPFILES_ROOT}/ops-agent.conf"
  if [[ "${PVE_ENDPOINT}" != true ]] && [[ ! -x /usr/bin/pvesh ]]; then
    sed -i '/pve-root-helper/d' "${TMPFILES_ROOT}/ops-agent.conf"
  fi
fi
maybe_inject_install_failure units

previous_current_present=false
previous_current_target=""
if [[ -L "${CURRENT_LINK}" ]]; then
  previous_current_present=true
  previous_current_target="$(readlink "${CURRENT_LINK}")"
elif [[ -e "${CURRENT_LINK}" ]]; then
  printf 'Refusing to replace non-symlink current path: %s\n' "${CURRENT_LINK}" >&2
  exit 1
fi

if [[ "${MODE}" == init ]] && [[ -f "${CONFIG_ROOT}/targets.json" ]]; then
  POLICY_BACKUP="$(mktemp "${CONFIG_ROOT}/targets.json.backup.${release_version}.XXXXXX")"
  install -o root -g "${SERVER_GROUP}" -m 0640 "${CONFIG_ROOT}/targets.json" "${POLICY_BACKUP}"
fi

if [[ "${MODE}" == init ]]; then
  mv -f -- "${POLICY_CANDIDATE}" "${CONFIG_ROOT}/targets.json"
  POLICY_CANDIDATE=""
fi
current_tmp="${APP_ROOT}/.current.${release_version}.$$"
ln -s "releases/${release_version}" "${current_tmp}"
mv -Tf -- "${current_tmp}" "${CURRENT_LINK}"
if [[ "${MODE}" == init ]]; then
  ln -sfn "${CURRENT_LINK}/bin/ops-agent" /usr/local/bin/ops-agent
  [[ -f "${CURRENT_LINK}/scripts/setup-botmux.sh" ]] || {
    printf 'Release is missing the fixed BotMux setup wrapper.\n' >&2
    exit 1
  }
  install -d -o root -g root -m 0755 /usr/libexec/pi-ops-agent
  install -o root -g root -m 0755 "${CURRENT_LINK}/scripts/setup-botmux.sh" \
    /usr/libexec/pi-ops-agent/setup-botmux
fi
maybe_inject_install_failure activation

systemd-tmpfiles --create "${TMPFILES_ROOT}/ops-agent.conf"
systemctl daemon-reload

stage_bundled_source_plugin() {
  local source_name="$1"
  local plugin_id="$2"
  local bundled_source="${CURRENT_LINK}/plugins/${source_name}"
  local source_root="/var/lib/ops-agent/plugin-sources/${plugin_id}"
  local previous_bundled_source=""
  local bundled_inspection="${INSTALL_TRANSACTION_DIR}/bundled-${source_name}.json"
  local refresh_source=false
  [[ -d "${bundled_source}" ]] || {
    printf 'Bundled source plugin is missing from the release: %s\n' "${source_name}" >&2
    return 1
  }
  "${CURRENT_LINK}/bin/agentd-pluginctl" inspect \
    --root /var/lib/ops-agent/plugins --source "${bundled_source}" >"${bundled_inspection}"
  "${CURRENT_LINK}/runtime/node" -e '
    const fs = require("node:fs");
    const [inspectionPath, expectedId] = process.argv.slice(1);
    const value = JSON.parse(fs.readFileSync(inspectionPath, "utf8"));
    if (value?.manifest?.id !== expectedId) {
      throw new Error("bundled source plugin identity does not match its staging slot");
    }
  ' "${bundled_inspection}" "${plugin_id}"
  if [[ "${previous_current_present}" == true ]] \
      && [[ "${previous_current_target}" =~ ^releases/[0-9A-Za-z.-]+$ ]]; then
    previous_bundled_source="${APP_ROOT}/${previous_current_target}/plugins/${source_name}"
  fi
  if [[ ! -e "${source_root}" ]]; then
    install -d -o "${ADMIN_USER}" -g "$(id -gn "${ADMIN_USER}")" -m 0755 "${source_root}"
    cp -a "${bundled_source}/." "${source_root}/"
    refresh_source=true
  elif [[ ! -d "${source_root}" ]] || [[ -L "${source_root}" ]]; then
    printf 'Source plugin path is unsafe: %s\n' "${source_root}" >&2
    return 1
  elif [[ -d "${previous_bundled_source}" ]] \
      && diff --brief --recursive --no-dereference \
        "${source_root}" "${previous_bundled_source}" >/dev/null; then
    # Advance an unmodified first-party working tree to the new release. The
    # active registry snapshot stays on the old digest until the normal plugin
    # approval below (required plugins) or a later typed registration.
    find "${source_root}" -mindepth 1 -depth -delete
    cp -a "${bundled_source}/." "${source_root}/"
    refresh_source=true
  else
    printf 'Preserving locally modified source plugin tree: %s\n' "${source_root}" >&2
  fi
  if [[ "${refresh_source}" == true ]]; then
    chown -R "${ADMIN_USER}:$(id -gn "${ADMIN_USER}")" "${source_root}"
    find "${source_root}" -type d -exec chmod 0755 {} +
    find "${source_root}" -type f -exec chmod u+rw,go+r,go-w {} +
  fi
}

register_required_source_plugin() {
  local source_name="$1"
  local plugin_id="$2"
  local source_root="/var/lib/ops-agent/plugin-sources/${plugin_id}"
  local inspection_file current_file current_digest bundled_digest answer expected_answer
  local -a fields register_args
  stage_bundled_source_plugin "${source_name}" "${plugin_id}"
  inspection_file="$(mktemp "${CONFIG_ROOT}/.plugin-inspection.XXXXXX")"
  current_file="$(mktemp "${CONFIG_ROOT}/.plugin-current.XXXXXX")"
  "${CURRENT_LINK}/bin/agentd-pluginctl" inspect \
    --root /var/lib/ops-agent/plugins --source "${source_root}" >"${inspection_file}"
  mapfile -t fields < <("${CURRENT_LINK}/runtime/node" -e '
    const fs = require("node:fs");
    const value = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    console.log(value.manifest.id);
    console.log(value.manifest.kind);
    console.log(value.digest);
    for (const scope of value.manifest.requestedScopes) console.log(`scope=${scope}`);
  ' "${inspection_file}")
  if [[ "${fields[0]:-}" != "${plugin_id}" ]] || [[ -z "${fields[1]:-}" ]] || [[ -z "${fields[2]:-}" ]]; then
    rm -f -- "${inspection_file}" "${current_file}"
    printf 'Required source plugin inspection returned an unexpected identity.\n' >&2
    return 1
  fi
  bundled_digest="$("${CURRENT_LINK}/runtime/node" -e '
    const fs = require("node:fs");
    const value = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    process.stdout.write(value.digest);
  ' "${INSTALL_TRANSACTION_DIR}/bundled-${source_name}.json")"
  if "${CURRENT_LINK}/bin/agentd-pluginctl" current \
      --root /var/lib/ops-agent/plugins --plugin-id "${plugin_id}" >"${current_file}" 2>/dev/null; then
    current_digest="$("${CURRENT_LINK}/runtime/node" -e '
      const fs = require("node:fs");
      process.stdout.write(JSON.parse(fs.readFileSync(process.argv[1], "utf8")).digest);
    ' "${current_file}")"
    if [[ "${current_digest}" == "${fields[2]}" ]]; then
      rm -f -- "${inspection_file}" "${current_file}"
      return 0
    fi
  fi
  printf 'Required plugin approval:\n' >&2
  "${CURRENT_LINK}/runtime/node" -e '
    const crypto = require("node:crypto");
    const fs = require("node:fs");
    const value = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    const adapterIdentity = (id) => {
      if (id === "adapter.tui") return "enrolled-local-administrator";
      if (id === "adapter.botmux") return "ops-agent-botmux";
      const suffix = id.slice("adapter.".length).replaceAll(".", "-");
      if (suffix.length <= 20) return `ops-adapter-${suffix}`;
      return `ops-adapter-${crypto.createHash("sha256").update(id).digest("hex").slice(0, 16)}`;
    };
    const runtimeAuthority = value.manifest.kind === "adapter" ? {
      runtimeIdentity: adapterIdentity(value.manifest.id),
      execution: value.manifest.id === "adapter.tui" ? "compiled-client" : "source-process",
      filesystem: "host-as-runtime-uid",
      network: "host",
      credentials: "runtime-uid-readable",
      actionScopeEnforcement: "digest-review-and-typed-ipc-contract",
      directPlatformAuthority: value.manifest.id === "adapter.tui"
        ? "plugin-source-forbidden;fixed-compiled-client-profile"
        : "full-runtime-uid-authority;not-os-action-sandboxed",
    } : undefined;
    process.stderr.write(JSON.stringify({
      id: value.manifest.id,
      kind: value.manifest.kind,
      version: value.manifest.version,
      publisher: value.manifest.publisher,
      digest: value.digest,
      capabilities: value.manifest.capabilities,
      requestedScopes: value.manifest.requestedScopes,
      ...(runtimeAuthority === undefined ? {} : { runtimeAuthority }),
    }, null, 2) + "\n");
  ' "${inspection_file}"
  expected_answer="APPROVE ${plugin_id} ${fields[2]}"
  if [[ "${APPROVE_REQUIRED_PLUGINS}" == true ]] \
      && [[ "${fields[2]}" != "${bundled_digest}" ]]; then
    rm -f -- "${inspection_file}" "${current_file}"
    printf '%s\n' \
      "--approve-required-plugins covers only the exact bundled ${plugin_id} source digest." \
      "The local source tree differs; rerun interactively and approve its displayed digest." >&2
    return 1
  fi
  if [[ "${APPROVE_REQUIRED_PLUGINS}" != true ]]; then
    [[ -c /dev/tty ]] || {
      rm -f -- "${inspection_file}" "${current_file}"
      printf 'No controlling TTY; pass --approve-required-plugins after reviewing bundled source.\n' >&2
      return 1
    }
    printf 'Type exactly: %s\n> ' "${expected_answer}" >/dev/tty
    IFS= read -r answer </dev/tty
    if [[ "${answer}" != "${expected_answer}" ]]; then
      rm -f -- "${inspection_file}" "${current_file}"
      printf 'Required plugin approval was not granted.\n' >&2
      return 1
    fi
  fi
  register_args=(register --root /var/lib/ops-agent/plugins --source "${source_root}" \
    --plugin-id "${plugin_id}" --kind "${fields[1]}" --digest "${fields[2]}" \
    --approved-by "bootstrap:${ADMIN_USER}")
  for field in "${fields[@]:3}"; do
    [[ "${field}" == scope=* ]] || continue
    register_args+=(--scope "${field#scope=}")
  done
  "${CURRENT_LINK}/bin/agentd-pluginctl" "${register_args[@]}" >/dev/null
  rm -f -- "${inspection_file}" "${current_file}"
}

if [[ "${MODE}" == init ]]; then
  register_required_source_plugin adapter-tui adapter.tui
  register_required_source_plugin workload-base workload.base
  stage_bundled_source_plugin adapter-botmux-source adapter.botmux
  stage_bundled_source_plugin workload-pve workload.pve
  stage_bundled_source_plugin workload-hermes-ops workload.hermes-ops
  stage_bundled_source_plugin workload-botmux-ops workload.botmux-ops
fi
maybe_inject_install_failure plugins

if [[ "${MODE}" == init ]]; then
  # Probe the real service boundary, not merely the service UID. The workload
  # sandbox needs a narrowly allow-listed set of namespaces and a writable
  # namespaced user.max_user_namespaces knob so bwrap can deny nesting without
  # making any host kernel tunable writable to the unprivileged service.
  bwrap_probe_unit="ops-agent-bwrap-probe-${BASHPID}"
  if ! systemd-run --quiet --wait --collect --unit="${bwrap_probe_unit}" \
    --property="User=${SERVICE_USER}" --property="Group=${SERVICE_GROUP}" \
    --property=NoNewPrivileges=yes --property=PrivateTmp=yes --property=PrivateDevices=yes \
    --property=ProtectSystem=strict --property=ProtectHome=yes \
    --property=ProtectKernelTunables=yes --property=ProtectKernelModules=yes \
    --property=ProtectKernelLogs=yes --property=ProtectControlGroups=yes \
    --property=ProtectClock=yes --property=ProtectHostname=yes \
    --property=ProtectProc=invisible --property=ProcSubset=pid \
    --property=RestrictRealtime=yes --property=RestrictSUIDSGID=yes \
    --property=LockPersonality=yes --property=SystemCallArchitectures=native \
    --property="RestrictNamespaces=user ipc net mnt pid" \
    --property="RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK" \
    --property=ReadWritePaths=/proc/sys/user/max_user_namespaces \
    /usr/bin/bwrap --die-with-parent --new-session \
    --unshare-user --unshare-ipc --unshare-pid --unshare-net \
    --as-pid-1 --disable-userns --cap-drop ALL --ro-bind / / --proc /proc --dev /dev \
    "${SANDBOX_PRLIMIT}" --as=1073741824:1073741824 --core=0:0 --cpu=5:5 \
    --fsize=67108864:67108864 --nofile=128:128 --nproc=64:64 -- /bin/true \
    >/dev/null 2>&1; then
    printf '%s\n' \
      'bubblewrap cannot run inside the effective ops-agentd systemd boundary; required Source Workloads cannot run.' \
      'Initialization is rolling back instead of starting without workload.base isolation.' >&2
    exit 1
  fi
  sed -i 's/"sandboxEnabled": false/"sandboxEnabled": true/' "${CONFIG_ROOT}/agentd.json"
fi

if [[ "${MODE}" == join ]]; then
  join_units=(ops-root-helper.service ops-agent-server.service)
  if [[ "${PVE_ENDPOINT}" == true ]]; then
    join_units+=(ops-pve-root-helper.service)
  fi
  systemctl enable "${join_units[@]}"
  maybe_inject_install_failure services
  commit_install_transaction
  if [[ "${START_NOW}" == true ]]; then
    if ! systemctl restart "${join_units[@]}"; then
      printf 'Endpoint install committed, but its services did not start; inspect systemd before retrying.\n' >&2
      exit 1
    fi
    if [[ "${PVE_ENDPOINT}" == true ]]; then
      socket_attempt=0
      while [[ ! -S /run/ops-agent/helper/pve-root-helper.sock ]] \
          && ((socket_attempt < 100)); do
        sleep 0.1
        socket_attempt=$((socket_attempt + 1))
      done
      if [[ ! -S /run/ops-agent/helper/pve-root-helper.sock ]] \
          || ! systemctl is-active --quiet ops-pve-root-helper.service; then
        printf 'Endpoint install committed, but the PVE broker did not become ready.\n' >&2
        exit 1
      fi
    fi
    "${CURRENT_LINK}/scripts/healthcheck.sh" --endpoint
  fi
  if [[ "${EXISTING_ENDPOINT_ENROLLMENT}" == true ]]; then
    printf 'Pi Ops Agent endpoint %s upgraded with its validated enrollment unchanged.\n' \
      "${release_version}"
  else
    printf 'Pi Ops Agent endpoint %s installed and enrolled.\n' "${release_version}"
  fi
  exit 0
fi

systemctl enable ops-agent.target ops-agent-healthcheck.timer
if [[ -x /usr/bin/pvesh ]]; then
  systemctl enable ops-pve-root-helper.service
  systemctl add-wants ops-agent.target ops-pve-root-helper.service
fi
credential_path="${CONFIG_ROOT}/credentials/deepseek_api_key.cred"
if [[ ! -f "${credential_path}" ]] && [[ "${START_NOW}" == true ]]; then
  if [[ ! -c /dev/tty ]]; then
    printf 'No controlling TTY is available for model credential input. Re-run with --no-start, then run %s/scripts/encrypt-credential.sh.\n' "${CURRENT_LINK}" >&2
    exit 1
  fi
  "${CURRENT_LINK}/scripts/encrypt-credential.sh" </dev/tty
fi
install_approval_sudoers
verify_effective_sudo_policy
secure_registered_approver_material

maybe_inject_install_failure security
maybe_inject_install_failure services
commit_install_transaction

if [[ "${START_NOW}" == true ]]; then
  if ! systemctl restart ops-agent.target ops-agent-healthcheck.timer; then
    printf 'Installation committed, but services did not start; inspect systemd before retrying.\n' >&2
    exit 1
  fi
  required_sockets=(
    /run/ops-agent/helper/root-helper.sock
    /run/ops-agent/reviewer/reviewer.sock
    /run/ops-agent/plugin-lease/lease.sock
    /run/ops-agent/agentd/agentd.sock
  )
  if [[ -x /usr/bin/pvesh ]]; then
    required_sockets+=(/run/ops-agent/helper/pve-root-helper.sock)
  fi
  for required_socket in "${required_sockets[@]}"; do
    socket_attempt=0
    while [[ ! -S "${required_socket}" ]] && ((socket_attempt < 100)); do
      sleep 0.1
      socket_attempt=$((socket_attempt + 1))
    done
    if [[ ! -S "${required_socket}" ]]; then
      printf 'Installation committed, but runtime socket did not appear: %s\n' \
        "${required_socket}" >&2
      exit 1
    fi
  done
  "${CURRENT_LINK}/scripts/healthcheck.sh"
fi

printf '%s\n' \
  "Pi Ops Agent ${release_version} initialized without external IM adapters." \
  "Re-login as ${ADMIN_USER} to refresh group membership, then run: ops-agent tui" \
  "Managed workload plugins require model-external credential provisioning with configure-plugin-credentials.sh before deployment." \
  "Install an adapter later by asking the Agent from TUI; BotMux setup uses the dedicated ${BOTMUX_USER} account through /usr/libexec/pi-ops-agent/setup-botmux."
if [[ ! -f "${credential_path}" ]]; then
  printf 'Before starting, create the model credential with: sudo %s/scripts/encrypt-credential.sh\n' \
    "${CURRENT_LINK}"
fi
if [[ -n "${POLICY_BACKUP}" ]]; then
  printf 'Previous target policy backup retained at: %s\n' "${POLICY_BACKUP}"
fi
