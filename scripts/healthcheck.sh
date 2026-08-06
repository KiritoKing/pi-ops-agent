#!/usr/bin/env bash
set -u -o pipefail

STRICT=false
if [[ ${1:-} == "--strict" ]]; then
  STRICT=true
  shift
fi
if (($# > 0)); then
  printf '用法: scripts/healthcheck.sh [--strict]\n' >&2
  exit 2
fi

failures=0
warnings=0

report() {
  local level="$1"
  local name="$2"
  local detail="$3"
  printf '%-5s %-28s %s\n' "${level}" "${name}" "${detail}"
  case "${level}" in
    FAIL) failures=$((failures + 1)) ;;
    WARN) warnings=$((warnings + 1)) ;;
  esac
}

check_unit() {
  local unit="$1"
  local state
  state="$(systemctl is-active "${unit}" 2>/dev/null || true)"
  if [[ "${state}" == "active" ]]; then
    report PASS "unit:${unit}" "active"
  else
    report FAIL "unit:${unit}" "${state:-unknown}"
  fi
}

check_socket() {
  local name="$1"
  local path="$2"
  local expected_group="$3"
  if [[ ! -S "${path}" ]]; then
    report FAIL "socket:${name}" "missing: ${path}"
    return
  fi
  local owner group mode
  owner="$(stat -c '%U' "${path}" 2>/dev/null || printf '?')"
  group="$(stat -c '%G' "${path}" 2>/dev/null || printf '?')"
  mode="$(stat -c '%a' "${path}" 2>/dev/null || printf '?')"
  if [[ "${group}" != "${expected_group}" ]] || [[ "${mode}" != "660" ]]; then
    report FAIL "socket:${name}" "owner=${owner}:${group} mode=${mode}, expected group=${expected_group} mode=660"
  else
    report PASS "socket:${name}" "owner=${owner}:${group} mode=${mode}"
  fi
}

printf 'Pi Ops Agent health report\ntime=%s host=%s\n' "$(date --iso-8601=seconds)" "$(hostname)"
printf 'kernel=%s load=%s\n' "$(uname -r)" "$(cut -d ' ' -f 1-3 /proc/loadavg 2>/dev/null || printf unknown)"
printf 'memory=%s\n' "$(awk '/MemTotal:/ {total=$2} /MemAvailable:/ {available=$2} END {if (total > 0) printf "available=%dMiB total=%dMiB", available/1024, total/1024; else print "unknown"}' /proc/meminfo 2>/dev/null || printf unknown)"
printf 'rootfs=%s\n\n' "$(df -hP / 2>/dev/null | awk 'NR==2 {print $3 "/" $2 " used=" $5}' || printf unknown)"

if [[ "$(uname -s)" != "Linux" ]] || [[ ! -d /run/systemd/system ]]; then
  report FAIL platform "systemd Linux required"
else
  report PASS platform "systemd Linux"
fi
command -v bwrap >/dev/null 2>&1 \
  && report PASS bubblewrap "$(command -v bwrap)" \
  || report FAIL bubblewrap "not found"
[[ -x /opt/pi-ops-agent/current/runtime/node ]] \
  && report PASS node "$(/opt/pi-ops-agent/current/runtime/node --version 2>/dev/null || printf broken)" \
  || report FAIL node "runtime missing"

check_unit ops-root-helper.service
check_unit ops-systemd-helper.service
check_unit ops-agentd.service
check_unit ops-agent-server.service
check_unit ops-agent-healthcheck.timer

failed_units="$(systemctl --failed --no-legend --plain 2>/dev/null | awk 'NF {count++} END {print count+0}')"
if [[ "${failed_units}" == "0" ]]; then
  report PASS failed-units "none"
else
  report WARN failed-units "count=${failed_units}; inspect with systemctl --failed"
fi
check_socket root-helper /run/ops-agent/helper/root-helper.sock ops-agent-server
check_socket systemd-helper /run/ops-agent/helper/systemd-helper.sock ops-agent
check_socket agentd /run/ops-agent/agentd/agentd.sock ops-agent

credential=/etc/ops-agent/credentials/deepseek_api_key.cred
if [[ -f "${credential}" ]]; then
  credential_owner="$(stat -c '%U:%G' "${credential}" 2>/dev/null || printf '?')"
  credential_mode="$(stat -c '%a' "${credential}" 2>/dev/null || printf '?')"
  if [[ "${credential_owner}" == "root:root" ]] && [[ "${credential_mode}" == "600" ]]; then
    report PASS credential "encrypted file present; content not read"
  else
    report FAIL credential "owner=${credential_owner} mode=${credential_mode}"
  fi
else
  report FAIL credential "encrypted credential missing"
fi

for audit in \
  /var/log/ops-agent/agentd/audit.jsonl \
  /var/log/ops-agent/root-helper/audit.jsonl \
  /var/log/ops-agent/systemd-helper/audit.jsonl; do
  if [[ -s "${audit}" ]]; then
    report PASS "audit:$(basename "$(dirname "${audit}")")" "present"
  else
    report WARN "audit:$(basename "$(dirname "${audit}")")" "missing or empty"
  fi
done

printf '\nsummary failures=%d warnings=%d\n' "${failures}" "${warnings}"
if ((failures > 0)); then
  exit 1
fi
if [[ "${STRICT}" == true ]] && ((warnings > 0)); then
  exit 2
fi
exit 0
