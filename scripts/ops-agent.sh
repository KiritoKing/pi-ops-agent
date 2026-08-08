#!/usr/bin/env bash
set -euo pipefail

readonly APP_ROOT="/opt/pi-ops-agent"
readonly CURRENT_ROOT="${APP_ROOT}/current"
readonly NODE="${CURRENT_ROOT}/runtime/node"
readonly ADAPTER_RUNNER="${CURRENT_ROOT}/dist/runtime/adapter-run.js"

if [[ "${1:-}" == endpoint-token ]]; then
  shift
  exec "${CURRENT_ROOT}/bin/ops-agent-server" issue-enrollment "$@"
fi

if [[ "${1:-tui}" == tui ]]; then
  shift || true
  has_session_id=false
  for argument in "$@"; do
    if [[ "${argument}" == "--session-id" ]] || [[ "${argument}" == --session-id=* ]]; then
      has_session_id=true
      break
    fi
  done
  if [[ "${has_session_id}" == false ]]; then
    set -- --session-id "${OPS_AGENT_SESSION_ID:-session-tui-$(id -u)-default}" "$@"
  fi
fi

[[ -x "${NODE}" ]] && [[ -f "${ADAPTER_RUNNER}" ]] || {
  printf 'The fixed digest-validating Adapter runner is missing.\n' >&2
  exit 1
}
exec "${NODE}" "${ADAPTER_RUNNER}" adapter.tui -- "$@"
