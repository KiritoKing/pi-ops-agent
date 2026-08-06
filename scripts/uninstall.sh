#!/usr/bin/env bash
set -euo pipefail

readonly APP_ROOT="/opt/pi-ops-agent"
readonly CONFIG_ROOT="/etc/ops-agent"
readonly STATE_ROOT="/var/lib/ops-agent"
readonly LOG_ROOT="/var/log/ops-agent"
readonly RUNTIME_ROOT="/run/ops-agent"

PURGE_STATE=false
REMOVE_USER=false
CONFIRMED=false

usage() {
  printf '%s\n' \
    "用法: sudo scripts/uninstall.sh [--purge-state --yes] [--remove-user]" \
    "默认保留配置、encrypted credential、会话、备份和审计日志。"
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

systemctl disable --now ops-agent-healthcheck.timer ops-agent.target >/dev/null 2>&1 || true
systemctl stop ops-agentd.service ops-agent-server.service ops-systemd-helper.service ops-root-helper.service >/dev/null 2>&1 || true

for file in \
  ops-agent.target \
  ops-agentd.service \
  ops-agent-server.service \
  ops-root-helper.service \
  ops-systemd-helper.service \
  ops-agent-healthcheck.service \
  ops-agent-healthcheck.timer; do
  rm -f -- "/etc/systemd/system/${file}"
done
rm -f -- /etc/tmpfiles.d/ops-agent.conf
if [[ -L /usr/local/bin/ops-agent ]] \
  && [[ "$(readlink /usr/local/bin/ops-agent)" == "/opt/pi-ops-agent/current/bin/ops-agent" ]]; then
  rm -f -- /usr/local/bin/ops-agent
fi

if [[ -d "${APP_ROOT}" ]]; then
  find "${APP_ROOT}" -mindepth 1 -depth -delete
  rmdir -- "${APP_ROOT}" 2>/dev/null || true
fi
if [[ -d "${RUNTIME_ROOT}" ]]; then
  find "${RUNTIME_ROOT}" -mindepth 1 -depth -delete
  rmdir -- "${RUNTIME_ROOT}" 2>/dev/null || true
fi

if [[ "${PURGE_STATE}" == true ]]; then
  for directory in "${CONFIG_ROOT}" "${STATE_ROOT}" "${LOG_ROOT}"; do
    if [[ -d "${directory}" ]]; then
      find "${directory}" -mindepth 1 -depth -delete
      rmdir -- "${directory}" 2>/dev/null || true
    fi
  done
fi

if [[ "${REMOVE_USER}" == true ]]; then
  id ops-agent >/dev/null 2>&1 && userdel ops-agent || true
  getent group ops-agent >/dev/null 2>&1 && groupdel ops-agent || true
fi

systemctl daemon-reload
systemctl reset-failed >/dev/null 2>&1 || true
printf '程序与 unit 已卸载。\n'
if [[ "${PURGE_STATE}" != true ]]; then
  printf '已保留 %s、%s、%s；需要永久删除时使用 --purge-state --yes。\n' \
    "${CONFIG_ROOT}" "${STATE_ROOT}" "${LOG_ROOT}"
fi
