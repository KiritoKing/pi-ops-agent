#!/usr/bin/env bash
set -u -o pipefail

STRICT=false
ENDPOINT=false
while (($# > 0)); do
  case "$1" in
    --strict) STRICT=true ;;
    --endpoint) ENDPOINT=true ;;
    *)
      printf '用法: scripts/healthcheck.sh [--strict] [--endpoint]\n' >&2
      exit 2
      ;;
  esac
  shift
done

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
  local expected_owner="$3"
  local expected_group="$4"
  if [[ ! -S "${path}" ]]; then
    report FAIL "socket:${name}" "missing: ${path}"
    return
  fi
  local owner group mode
  owner="$(stat -c '%U' "${path}" 2>/dev/null || printf '?')"
  group="$(stat -c '%G' "${path}" 2>/dev/null || printf '?')"
  mode="$(stat -c '%a' "${path}" 2>/dev/null || printf '?')"
  if [[ "${owner}" != "${expected_owner}" ]] || [[ "${group}" != "${expected_group}" ]] \
      || [[ "${mode}" != "660" ]]; then
    report FAIL "socket:${name}" "owner=${owner}:${group} mode=${mode}, expected ${expected_owner}:${expected_group} mode=660"
  else
    report PASS "socket:${name}" "owner=${owner}:${group} mode=${mode}"
  fi
}

check_private_socket() {
  local name="$1"
  local path="$2"
  local expected_owner="$3"
  local expected_group="$4"
  if [[ ! -S "${path}" ]]; then
    report FAIL "socket:${name}" "missing: ${path}"
    return
  fi
  local owner group mode
  owner="$(stat -c '%U' "${path}" 2>/dev/null || printf '?')"
  group="$(stat -c '%G' "${path}" 2>/dev/null || printf '?')"
  mode="$(stat -c '%a' "${path}" 2>/dev/null || printf '?')"
  if [[ "${owner}" != "${expected_owner}" ]] || [[ "${group}" != "${expected_group}" ]] \
      || [[ "${mode}" != "600" ]]; then
    report FAIL "socket:${name}" "owner=${owner}:${group} mode=${mode}, expected ${expected_owner}:${expected_group} mode=600"
  else
    report PASS "socket:${name}" "owner=${owner}:${group} mode=${mode}"
  fi
}

check_metadata() {
  local name="$1"
  local path="$2"
  local expected="$3"
  local actual
  if [[ ! -e "${path}" ]] || [[ -L "${path}" ]]; then
    report FAIL "dac:${name}" "missing or symlink: ${path}"
    return
  fi
  actual="$(stat -c '%U:%G:%a' "${path}" 2>/dev/null || printf '?')"
  if [[ "${actual}" == "${expected}" ]]; then
    report PASS "dac:${name}" "${actual}"
  else
    report FAIL "dac:${name}" "${actual}, expected ${expected}"
  fi
}

check_absent_path() {
  local name="$1"
  local path="$2"
  if [[ -e "${path}" ]] || [[ -L "${path}" ]]; then
    report FAIL "${name}" "non-PVE endpoint retains managed surface: ${path}"
  else
    report PASS "${name}" "absent"
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
if [[ "${ENDPOINT}" == true ]]; then
  if [[ -e /etc/systemd/system/ops-agent.target ]] \
      || [[ -L /etc/systemd/system/ops-agent.target ]] \
      || [[ -e /etc/systemd/system/ops-agent.target.wants ]] \
      || [[ -L /etc/systemd/system/ops-agent.target.wants ]]; then
    report FAIL endpoint-topology "controller target or wants dependency is present"
  else
    report PASS endpoint-topology "no controller target surface"
  fi
  endpoint_pve_receipt=false
  if [[ -e /etc/ops-agent/broker-receipts/private/pve.key.pem ]] \
      || [[ -e /etc/ops-agent/broker-receipts/pve-public.pem ]]; then
    endpoint_pve_receipt=true
  fi
  if [[ -x /usr/bin/pvesh ]] && [[ "${endpoint_pve_receipt}" != true ]]; then
    report FAIL pve-enrollment "PVE host has no --pve receipt identity"
  elif [[ ! -x /usr/bin/pvesh ]] && [[ "${endpoint_pve_receipt}" == true ]]; then
    report FAIL pve-enrollment "non-PVE host retains a --pve receipt identity"
  else
    report PASS pve-enrollment "bundle and host mode match"
  fi
  [[ -x /opt/pi-ops-agent/current/bin/ops-agent-server ]] \
    && report PASS endpoint-server-binary "present" \
    || report FAIL endpoint-server-binary "missing"
  [[ -x /opt/pi-ops-agent/current/bin/ops-root-helper ]] \
    && report PASS endpoint-broker-binary "present" \
    || report FAIL endpoint-broker-binary "missing"
  check_unit ops-root-helper.service
  check_unit ops-agent-server.service
  if [[ -x /usr/bin/pvesh ]]; then
    check_unit ops-pve-root-helper.service
  else
    check_absent_path pve-broker-unit \
      /etc/systemd/system/ops-pve-root-helper.service
    check_absent_path pve-broker-security-dropin \
      /etc/systemd/system/ops-pve-root-helper.service.d/zzzz-ops-agent-security.conf
  fi
  check_socket root-helper /run/ops-agent/helper/root-helper.sock root ops-agent-server
  if [[ -x /usr/bin/pvesh ]]; then
    check_socket pve-root-helper /run/ops-agent/helper/pve-root-helper.sock root ops-agent-server
  fi
  check_metadata runtime-config /etc/ops-agent/runtime.env root:root:600
  check_metadata endpoint-enrollment /etc/ops-agent/endpoint-enrollment.json root:ops-agent-server:640
  check_metadata server-identity /etc/ops-agent/server-identity.json root:ops-agent-server:640
  check_metadata target-policy /etc/ops-agent/targets.json root:ops-agent-server:640
  check_metadata json-config-helper /usr/lib/ops-agent/agentd-json-config-helper root:root:755
  if cmp -s /usr/lib/ops-agent/agentd-json-config-helper \
      /opt/pi-ops-agent/current/bin/agentd-json-config-helper; then
    report PASS json-config-helper-version "matches current verified release"
  else
    report FAIL json-config-helper-version "fixed helper differs from current verified release"
  fi
  check_metadata server-tls-key /etc/ops-agent/tls/server.key root:ops-agent-server:640
  check_metadata core-receipt-private /etc/ops-agent/broker-receipts/private/core.key.pem root:root:600
  check_metadata core-receipt-public /etc/ops-agent/broker-receipts/core-public.pem root:ops-agent-server:640
  if [[ -x /usr/bin/pvesh ]]; then
    check_metadata pve-receipt-private /etc/ops-agent/broker-receipts/private/pve.key.pem root:root:600
    check_metadata pve-receipt-public /etc/ops-agent/broker-receipts/pve-public.pem root:ops-agent-server:640
  fi
  for audit in /var/log/ops-agent/root-helper/audit.jsonl; do
    if [[ -s "${audit}" ]]; then
      report PASS "audit:$(basename "$(dirname "${audit}")")" "present"
    else
      report WARN "audit:$(basename "$(dirname "${audit}")")" "missing or empty"
    fi
  done
  if [[ -x /usr/bin/pvesh ]]; then
    if [[ -s /var/log/ops-agent/pve-root-helper/audit.jsonl ]]; then
      report PASS audit:pve-root-helper "present"
    else
      report WARN audit:pve-root-helper "missing or empty"
    fi
  fi
  printf '\nsummary failures=%d warnings=%d\n' "${failures}" "${warnings}"
  if ((failures > 0)); then
    exit 1
  fi
  if [[ "${STRICT}" == true ]] && ((warnings > 0)); then
    exit 2
  fi
  exit 0
fi
command -v bwrap >/dev/null 2>&1 \
  && report PASS bubblewrap "$(command -v bwrap)" \
  || report FAIL bubblewrap "not found"
[[ -x /opt/pi-ops-agent/current/runtime/node ]] \
  && report PASS node "$(/opt/pi-ops-agent/current/runtime/node --version 2>/dev/null || printf broken)" \
  || report FAIL node "runtime missing"

check_unit ops-root-helper.service
if [[ -x /usr/bin/pvesh ]]; then
  check_unit ops-pve-root-helper.service
else
  report PASS pve-broker "not a PVE host; unit condition intentionally skipped"
fi
check_unit agentd-approval-reviewer.service
check_unit agentd-plugin-lease-broker.service
check_unit agentd-guardian.service
check_unit ops-agentd.service
check_unit agentd-client-gateway.service
check_unit ops-agent-server.service
check_unit ops-agent-healthcheck.timer

failed_units="$(systemctl --failed --no-legend --plain 2>/dev/null | awk 'NF {count++} END {print count+0}')"
if [[ "${failed_units}" == "0" ]]; then
  report PASS failed-units "none"
else
  report WARN failed-units "count=${failed_units}; inspect with systemctl --failed"
fi
check_socket root-helper /run/ops-agent/helper/root-helper.sock root ops-agent-server
if [[ -x /usr/bin/pvesh ]]; then
  check_socket pve-root-helper /run/ops-agent/helper/pve-root-helper.sock root ops-agent-server
fi
check_socket approval-reviewer /run/ops-agent/reviewer/reviewer.sock ops-agent-reviewer ops-agent-reviewer
check_socket plugin-lease /run/ops-agent/plugin-lease/lease.sock ops-agent-lease ops-agent-client
check_socket agentd /run/ops-agent/agentd/agentd.sock ops-agent ops-agent-client
check_private_socket agentd-backend /run/ops-agent/agentd/backend.sock ops-agent ops-agent-client
check_metadata agentd-runtime /run/ops-agent/agentd ops-agent:ops-agent-client:2750
check_metadata plugin-registry /var/lib/ops-agent/plugins root:ops-agent-client:2750
check_metadata plugin-invocation-leases /var/lib/ops-agent/plugins/invocation-leases root:ops-agent-lease:750
check_metadata agent-tls-key /etc/ops-agent/tls/agent.key ops-agent:ops-agent:600
check_metadata observer-tls-key /etc/ops-agent/tls/observer.key root:ops-agent-client:640
check_metadata server-registry /etc/ops-agent/servers.json root:ops-agent-client:640
check_metadata local-administrator /etc/ops-agent/local-administrator.json root:ops-agent-client:640
check_metadata core-receipt-private /etc/ops-agent/broker-receipts/private/core.key.pem root:root:600
check_metadata core-receipt-public /etc/ops-agent/broker-receipts/core-public.pem root:ops-agent-client:640
if [[ -x /usr/bin/pvesh ]] \
    || [[ -e /etc/ops-agent/broker-receipts/private/pve.key.pem ]] \
    || [[ -e /etc/ops-agent/broker-receipts/pve-public.pem ]]; then
  check_metadata pve-receipt-private /etc/ops-agent/broker-receipts/private/pve.key.pem root:root:600
  check_metadata pve-receipt-public /etc/ops-agent/broker-receipts/pve-public.pem root:ops-agent-client:640
fi
check_metadata guardian-heartbeat /run/ops-agent/agentd/heartbeat.json ops-agent:ops-agent-client:600
check_metadata json-config-helper /usr/lib/ops-agent/agentd-json-config-helper root:root:755
if cmp -s /usr/lib/ops-agent/agentd-json-config-helper \
    /opt/pi-ops-agent/current/bin/agentd-json-config-helper; then
  report PASS json-config-helper-version "matches current verified release"
else
  report FAIL json-config-helper-version "fixed helper differs from current verified release"
fi

heartbeat=/run/ops-agent/agentd/heartbeat.json
if [[ -f "${heartbeat}" ]] && [[ ! -L "${heartbeat}" ]]; then
  heartbeat_age=$(( $(date +%s) - $(stat -c '%Y' "${heartbeat}" 2>/dev/null || printf 0) ))
  if ((heartbeat_age >= 0 && heartbeat_age <= 15)); then
    report PASS guardian-heartbeat "fresh age=${heartbeat_age}s"
  else
    report FAIL guardian-heartbeat "stale age=${heartbeat_age}s"
  fi
else
  report FAIL guardian-heartbeat "missing or unsafe"
fi

for required_plugin in adapter.tui workload.base; do
  if /opt/pi-ops-agent/current/bin/agentd-pluginctl current \
      --root /var/lib/ops-agent/plugins --plugin-id "${required_plugin}" >/dev/null 2>&1; then
    report PASS "plugin:${required_plugin}" "digest snapshot active"
  else
    report FAIL "plugin:${required_plugin}" "missing, unapproved, or tampered"
  fi
  check_metadata "plugin-lease:${required_plugin}" \
    "/var/lib/ops-agent/plugins/invocation-leases/${required_plugin}.lock" \
    root:ops-agent-lease:640
done

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
  /var/log/ops-agent/root-helper/audit.jsonl; do
  if [[ -s "${audit}" ]]; then
    report PASS "audit:$(basename "$(dirname "${audit}")")" "present"
  else
    report WARN "audit:$(basename "$(dirname "${audit}")")" "missing or empty"
  fi
done
if [[ -x /usr/bin/pvesh ]]; then
  if [[ -s /var/log/ops-agent/pve-root-helper/audit.jsonl ]]; then
    report PASS audit:pve-root-helper "present"
  else
    report WARN audit:pve-root-helper "missing or empty"
  fi
fi

printf '\nsummary failures=%d warnings=%d\n' "${failures}" "${warnings}"
if ((failures > 0)); then
  exit 1
fi
if [[ "${STRICT}" == true ]] && ((warnings > 0)); then
  exit 2
fi
exit 0
