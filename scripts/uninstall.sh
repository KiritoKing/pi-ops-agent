#!/usr/bin/env bash
set -euo pipefail

readonly APP_ROOT="/opt/pi-ops-agent"
readonly CONFIG_ROOT="/etc/ops-agent"
readonly STATE_ROOT="/var/lib/ops-agent"
readonly LOG_ROOT="/var/log/ops-agent"
readonly RUNTIME_ROOT="/run/ops-agent"
readonly OPS_AGENT_TARGET_WANTS_DIR="/etc/systemd/system/ops-agent.target.wants"
readonly PVE_CONTROLLER_TARGET_WANT="${OPS_AGENT_TARGET_WANTS_DIR}/ops-pve-root-helper.service"
readonly PVE_UNIT_PATH="/etc/systemd/system/ops-pve-root-helper.service"
readonly JSON_CONFIG_HELPER="/usr/lib/ops-agent/agentd-json-config-helper"

PURGE_STATE=false
REMOVE_USER=false
CONFIRMED=false

usage() {
  printf '%s\n' \
    "用法: sudo scripts/uninstall.sh [--purge-state --yes [--remove-user]]" \
    "默认保留配置、encrypted credential、会话、备份、审计日志和 legacy plugin 恢复目录。"
}

while (($# > 0)); do
  case "$1" in
    --purge-state) PURGE_STATE=true ;;
    --remove-user) REMOVE_USER=true ;;
    --yes) CONFIRMED=true ;;
    -h|--help) usage; exit 0 ;;
    *) printf '未知参数: %s\n' "$1" >&2; exit 2 ;;
  esac
  shift
done
if [[ ${EUID} -ne 0 ]]; then
  printf '请用 root 运行。\n' >&2
  exit 1
fi
if [[ "${PURGE_STATE}" == true ]] && [[ "${CONFIRMED}" != true ]]; then
  printf '--purge-state 会永久删除 credential、会话、备份和审计日志；必须同时传 --yes。\n' >&2
  exit 1
fi
if [[ "${REMOVE_USER}" == true ]] && [[ "${PURGE_STATE}" != true ]]; then
  printf '--remove-user is only valid with --purge-state --yes; preserved state may still contain numeric ownership.\n' >&2
  exit 1
fi

declare -a ingress_units=(agentd-client-gateway.service ops-agentd.service ops-agent-server.service)
declare -A ingress_was_active=()
declare -a managed_units=(
  ops-agent-healthcheck.service
  ops-agent-healthcheck.timer
  ops-agent.target
  ops-agentd.service
  agentd-client-gateway.service
  agentd-guardian.service
  agentd-approval-reviewer.service
  agentd-plugin-lease-broker.service
  ops-agent-server.service
  ops-systemd-helper.service
  ops-pve-root-helper.service
  ops-root-helper.service
)
declare -A managed_was_active=()
declare -A managed_was_enabled=()
UNINSTALL_QUIESCE_ACTIVE=false
UNINSTALL_UNIT_TRANSACTION_ACTIVE=false
UNINSTALL_UNIT_ROLLBACK_FAILED=false
PVE_CONTROLLER_TARGET_WANT_WAS_PRESENT=false

if [[ -e "${OPS_AGENT_TARGET_WANTS_DIR}" ]] \
    || [[ -L "${OPS_AGENT_TARGET_WANTS_DIR}" ]]; then
  if [[ ! -d "${OPS_AGENT_TARGET_WANTS_DIR}" ]] \
      || [[ -L "${OPS_AGENT_TARGET_WANTS_DIR}" ]]; then
    printf 'Refusing unsafe controller target wants path: %s\n' \
      "${OPS_AGENT_TARGET_WANTS_DIR}" >&2
    exit 1
  fi
fi
if [[ -e "${PVE_CONTROLLER_TARGET_WANT}" ]] \
    || [[ -L "${PVE_CONTROLLER_TARGET_WANT}" ]]; then
  if [[ ! -L "${PVE_CONTROLLER_TARGET_WANT}" ]] \
      || [[ "$(readlink -f -- "${PVE_CONTROLLER_TARGET_WANT}" 2>/dev/null || true)" \
        != "${PVE_UNIT_PATH}" ]]; then
    printf 'Refusing unsafe PVE controller target dependency: %s\n' \
      "${PVE_CONTROLLER_TARGET_WANT}" >&2
    exit 1
  fi
  PVE_CONTROLLER_TARGET_WANT_WAS_PRESENT=true
fi

restore_uninstall_ingress() {
  local unit
  for unit in "${ingress_units[@]}"; do
    case "${ingress_was_active["${unit}"]:-}" in
      active|reloading|activating)
        systemctl start "${unit}" >/dev/null 2>&1 \
          || printf 'Could not restore quiesced ingress unit %s.\n' "${unit}" >&2
        ;;
    esac
  done
}

abort_uninstall_quiesce() {
  local status=$?
  [[ "${UNINSTALL_QUIESCE_ACTIVE}" == true ]] || exit "${status}"
  trap - EXIT HUP INT TERM
  set +e
  restore_uninstall_ingress
  ((status != 0)) || status=1
  exit "${status}"
}

restore_uninstall_unit_states() {
  local unit enabled current_enabled active
  systemctl daemon-reload >/dev/null 2>&1 || UNINSTALL_UNIT_ROLLBACK_FAILED=true
  for unit in "${managed_units[@]}"; do
    enabled="${managed_was_enabled["${unit}"]:-}"
    current_enabled="$(systemctl is-enabled "${unit}" 2>/dev/null || true)"
    case "${enabled}" in
      enabled)
        if [[ "${current_enabled}" == enabled-runtime ]] \
            || [[ "${current_enabled}" == linked-runtime ]]; then
          systemctl disable --runtime "${unit}" >/dev/null 2>&1 \
            || UNINSTALL_UNIT_ROLLBACK_FAILED=true
        fi
        systemctl enable "${unit}" >/dev/null 2>&1 || UNINSTALL_UNIT_ROLLBACK_FAILED=true
        ;;
      enabled-runtime)
        case "${current_enabled}" in
          enabled|linked|alias)
            systemctl disable "${unit}" >/dev/null 2>&1 || UNINSTALL_UNIT_ROLLBACK_FAILED=true
            ;;
        esac
        systemctl enable --runtime "${unit}" >/dev/null 2>&1 \
          || UNINSTALL_UNIT_ROLLBACK_FAILED=true
        ;;
      *)
        case "${current_enabled}" in
          enabled|linked|alias)
            systemctl disable "${unit}" >/dev/null 2>&1 || UNINSTALL_UNIT_ROLLBACK_FAILED=true
            ;;
          enabled-runtime|linked-runtime)
            systemctl disable --runtime "${unit}" >/dev/null 2>&1 \
              || UNINSTALL_UNIT_ROLLBACK_FAILED=true
            ;;
        esac
        ;;
    esac
  done
  for unit in "${managed_units[@]}"; do
    active="${managed_was_active["${unit}"]:-}"
    case "${active}" in
      active|reloading|activating)
        systemctl start "${unit}" >/dev/null 2>&1 || UNINSTALL_UNIT_ROLLBACK_FAILED=true
        ;;
    esac
  done
  for unit in "${managed_units[@]}"; do
    active="${managed_was_active["${unit}"]:-}"
    case "${active}" in
      active|reloading|activating) continue ;;
    esac
    case "$(systemctl is-active "${unit}" 2>/dev/null || true)" in
      active|reloading|activating|deactivating)
        systemctl stop "${unit}" >/dev/null 2>&1 || UNINSTALL_UNIT_ROLLBACK_FAILED=true
        ;;
    esac
  done
}

restore_pve_controller_target_want() {
  [[ "${PVE_CONTROLLER_TARGET_WANT_WAS_PRESENT}" == true ]] || return 0
  if [[ -e "${OPS_AGENT_TARGET_WANTS_DIR}" ]] \
      || [[ -L "${OPS_AGENT_TARGET_WANTS_DIR}" ]]; then
    if [[ ! -d "${OPS_AGENT_TARGET_WANTS_DIR}" ]] \
        || [[ -L "${OPS_AGENT_TARGET_WANTS_DIR}" ]]; then
      UNINSTALL_UNIT_ROLLBACK_FAILED=true
      return
    fi
  else
    install -d -o root -g root -m 0755 "${OPS_AGENT_TARGET_WANTS_DIR}" \
      || { UNINSTALL_UNIT_ROLLBACK_FAILED=true; return; }
  fi
  if [[ -L "${PVE_CONTROLLER_TARGET_WANT}" ]]; then
    if [[ "$(readlink -f -- "${PVE_CONTROLLER_TARGET_WANT}" 2>/dev/null || true)" \
        == "${PVE_UNIT_PATH}" ]]; then
      return 0
    fi
    UNINSTALL_UNIT_ROLLBACK_FAILED=true
    return
  fi
  if [[ -e "${PVE_CONTROLLER_TARGET_WANT}" ]]; then
    UNINSTALL_UNIT_ROLLBACK_FAILED=true
    return
  fi
  ln -s "${PVE_UNIT_PATH}" "${PVE_CONTROLLER_TARGET_WANT}" \
    || UNINSTALL_UNIT_ROLLBACK_FAILED=true
}

rollback_uninstall_unit_transaction() {
  local status=$?
  [[ "${UNINSTALL_UNIT_TRANSACTION_ACTIVE}" == true ]] || exit "${status}"
  trap - EXIT HUP INT TERM
  set +e
  UNINSTALL_UNIT_ROLLBACK_FAILED=false
  restore_uninstall_unit_states
  restore_pve_controller_target_want
  ((status != 0)) || status=1
  if [[ "${UNINSTALL_UNIT_ROLLBACK_FAILED}" == false ]]; then
    printf 'Uninstall stopped before file removal; prior managed unit state was restored.\n' >&2
  else
    printf 'Uninstall stopped before file removal, but managed unit-state rollback was incomplete.\n' >&2
  fi
  exit "${status}"
}

for unit in "${ingress_units[@]}"; do
  ingress_was_active["${unit}"]="$(systemctl is-active "${unit}" 2>/dev/null || true)"
done
UNINSTALL_QUIESCE_ACTIVE=true
trap abort_uninstall_quiesce EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
for unit in "${ingress_units[@]}"; do
  case "${ingress_was_active["${unit}"]}" in
    ""|inactive|failed|unknown) ;;
    *) systemctl stop "${unit}" ;;
  esac
done
for unit in "${ingress_units[@]}"; do
  ingress_state="$(systemctl is-active "${unit}" 2>/dev/null || true)"
  case "${ingress_state}" in
    ""|inactive|failed|unknown) ;;
    *)
      printf 'Refusing to uninstall because ingress unit %s is still %s.\n' \
        "${unit}" "${ingress_state}" >&2
      exit 1
      ;;
  esac
done
store_checker="${APP_ROOT}/current/scripts/check-root-stores-idle.mjs"
store_node="${APP_ROOT}/current/runtime/node"
[[ -f "${store_checker}" ]] && [[ -x "${store_node}" ]] || {
  printf 'Refusing to uninstall without the root-store quiescence checker.\n' >&2
  exit 1
}
"${store_node}" "${store_checker}" \
  "${STATE_ROOT}/root-helper/state.json" \
  "${STATE_ROOT}/pve-root-helper/state.json"
UNINSTALL_QUIESCE_ACTIVE=false
trap - EXIT HUP INT TERM

for unit in "${managed_units[@]}"; do
  case "${unit}" in
    ops-agentd.service|ops-agent-server.service)
      managed_was_active["${unit}"]="${ingress_was_active["${unit}"]}"
      ;;
    *)
      managed_was_active["${unit}"]="$(systemctl is-active "${unit}" 2>/dev/null || true)"
      ;;
  esac
  managed_was_enabled["${unit}"]="$(systemctl is-enabled "${unit}" 2>/dev/null || true)"
done
UNINSTALL_UNIT_TRANSACTION_ACTIVE=true
trap rollback_uninstall_unit_transaction EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

for unit in "${managed_units[@]}"; do
  unit_state="$(systemctl is-active "${unit}" 2>/dev/null || true)"
  case "${unit_state}" in
    ""|inactive|failed|unknown) ;;
    *)
      systemctl stop "${unit}" || {
        printf 'Refusing to uninstall because %s could not be stopped.\n' "${unit}" >&2
        exit 1
      }
      ;;
  esac
  unit_state="$(systemctl is-active "${unit}" 2>/dev/null || true)"
  case "${unit_state}" in
    ""|inactive|failed|unknown) ;;
    *)
      printf 'Refusing to uninstall because %s remains %s.\n' "${unit}" "${unit_state}" >&2
      exit 1
      ;;
  esac
done
if id ops-agent-botmux >/dev/null 2>&1; then
  botmux_processes="$(ps -u ops-agent-botmux -o pid= 2>/dev/null | tr -d '[:space:]')"
  if [[ -n "${botmux_processes}" ]]; then
    printf 'Refusing to uninstall while the dedicated BotMux account still owns processes; stop BotMux and retry.\n' >&2
    exit 1
  fi
fi
for unit in "${managed_units[@]}"; do
  unit_enablement="$(systemctl is-enabled "${unit}" 2>/dev/null || true)"
  case "${unit_enablement}" in
    enabled|linked|alias)
      systemctl disable "${unit}" || {
        printf 'Refusing to uninstall because %s could not be disabled.\n' "${unit}" >&2
        exit 1
      }
      ;;
    enabled-runtime|linked-runtime)
      systemctl disable --runtime "${unit}" || {
        printf 'Refusing to uninstall because runtime enablement for %s could not be disabled.\n' \
          "${unit}" >&2
        exit 1
      }
      ;;
  esac
done
if [[ "${PVE_CONTROLLER_TARGET_WANT_WAS_PRESENT}" == true ]]; then
  rm -f -- "${PVE_CONTROLLER_TARGET_WANT}"
  rmdir -- "${OPS_AGENT_TARGET_WANTS_DIR}" 2>/dev/null || true
fi
UNINSTALL_UNIT_TRANSACTION_ACTIVE=false
trap - EXIT HUP INT TERM

for file in \
  ops-agent.target \
  ops-agentd.service \
  agentd-client-gateway.service \
  agentd-guardian.service \
  agentd-approval-reviewer.service \
  agentd-plugin-lease-broker.service \
  ops-agent-server.service \
  ops-root-helper.service \
  ops-pve-root-helper.service \
  ops-systemd-helper.service \
  ops-agent-healthcheck.service \
  ops-agent-healthcheck.timer; do
  rm -f -- "/etc/systemd/system/${file}"
done
for dropin in \
  ops-agentd.service.d/zzzz-ops-agent-security.conf \
  ops-agentd.service.d/zzzz-ops-agent-credential.conf \
  agentd-guardian.service.d/zzzz-ops-agent-security.conf \
  ops-agent-server.service.d/zzzz-ops-agent-security.conf \
  ops-root-helper.service.d/zzzz-ops-agent-security.conf \
  ops-pve-root-helper.service.d/zzzz-ops-agent-security.conf \
  ops-systemd-helper.service.d/zzzz-ops-agent-security.conf \
  ops-agent-healthcheck.service.d/zzzz-ops-agent-security.conf; do
  rm -f -- "/etc/systemd/system/${dropin}"
  rmdir -- "/etc/systemd/system/$(dirname "${dropin}")" 2>/dev/null || true
done
rm -f -- /etc/tmpfiles.d/ops-agent.conf
rm -f -- /etc/sudoers.d/zzzz-ops-agent-approval
rm -f -- /usr/libexec/pi-ops-agent/setup-botmux
rmdir -- /usr/libexec/pi-ops-agent 2>/dev/null || true
rm -f -- "${JSON_CONFIG_HELPER}"
rmdir -- "$(dirname "${JSON_CONFIG_HELPER}")" 2>/dev/null || true
if [[ -L /usr/local/bin/ops-agent ]] \
  && [[ "$(readlink /usr/local/bin/ops-agent)" == "/opt/pi-ops-agent/current/bin/ops-agent" ]]; then
  rm -f -- /usr/local/bin/ops-agent
fi

remove_exact_tree() {
  local target="$1"
  case "${target}" in
    "${APP_ROOT}"|"${APP_ROOT}"/*|"${RUNTIME_ROOT}"|"${CONFIG_ROOT}"|"${STATE_ROOT}"|"${LOG_ROOT}") ;;
    *) printf 'Refusing unsafe uninstall target: %s\n' "${target}" >&2; return 1 ;;
  esac
  if [[ -L "${target}" ]] || [[ -f "${target}" ]]; then
    rm -f -- "${target}"
  elif [[ -d "${target}" ]]; then
    find "${target}" -mindepth 1 -depth -delete
    rmdir -- "${target}"
  elif [[ -e "${target}" ]]; then
    printf 'Refusing unsupported uninstall target type: %s\n' "${target}" >&2
    return 1
  fi
}

if [[ -L "${APP_ROOT}" ]] || { [[ -e "${APP_ROOT}" ]] && [[ ! -d "${APP_ROOT}" ]]; }; then
  printf 'Refusing unsafe application root during uninstall: %s\n' "${APP_ROOT}" >&2
  exit 1
fi
if [[ -d "${APP_ROOT}" ]]; then
  if [[ "${PURGE_STATE}" == true ]]; then
    remove_exact_tree "${APP_ROOT}"
  else
    while IFS= read -r -d '' application_entry; do
      [[ "${application_entry}" == "${APP_ROOT}/plugins" ]] && continue
      remove_exact_tree "${application_entry}"
    done < <(find "${APP_ROOT}" -mindepth 1 -maxdepth 1 -print0)
    rmdir -- "${APP_ROOT}" 2>/dev/null || true
  fi
fi
if [[ -d "${RUNTIME_ROOT}" ]]; then
  remove_exact_tree "${RUNTIME_ROOT}"
fi

if [[ "${PURGE_STATE}" == true ]]; then
  for directory in "${CONFIG_ROOT}" "${STATE_ROOT}" "${LOG_ROOT}"; do
    if [[ -d "${directory}" ]]; then
      remove_exact_tree "${directory}"
    fi
  done
fi

if [[ "${REMOVE_USER}" == true ]]; then
  for account in ops-agent-botmux ops-agent-reviewer ops-agent-lease ops-agent-server ops-agent; do
    if id "${account}" >/dev/null 2>&1; then
      userdel "${account}" || {
        printf 'Could not remove %s (check for remaining processes); account cleanup aborted.\n' \
          "${account}" >&2
        exit 1
      }
    fi
  done
  for group in ops-agent-botmux ops-agent-reviewer ops-agent-lease ops-agent-server ops-agent-client ops-agent; do
    if getent group "${group}" >/dev/null; then
      IFS=',' read -r -a remaining_members <<<"$(getent group "${group}" | cut -d: -f4)"
      for member in "${remaining_members[@]}"; do
        [[ -n "${member}" ]] || continue
        gpasswd --delete "${member}" "${group}" >/dev/null
      done
      groupdel "${group}" || {
        printf 'Could not remove service group %s; group cleanup aborted.\n' "${group}" >&2
        exit 1
      }
    fi
  done
fi

systemctl daemon-reload
systemctl reset-failed >/dev/null 2>&1 || true
printf '程序与 unit 已卸载。\n'
if [[ "${PURGE_STATE}" != true ]]; then
  printf '已保留 %s、%s、%s；需要永久删除时使用 --purge-state --yes。\n' \
    "${CONFIG_ROOT}" "${STATE_ROOT}" "${LOG_ROOT}"
  if [[ -d "${APP_ROOT}/plugins" ]]; then
    printf '已保留 legacy plugin 恢复目录 %s。\n' "${APP_ROOT}/plugins"
  fi
fi
