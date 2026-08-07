#!/usr/bin/env bash
set -euo pipefail

readonly APP_ROOT="/opt/pi-ops-agent"
readonly CURRENT_ROOT="${APP_ROOT}/current"

case "${1:-tui}" in
  tui)
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
    ;;
  endpoint-token)
    shift
    exec "${CURRENT_ROOT}/bin/ops-agent-server" issue-enrollment "$@"
    ;;
esac

exec "${CURRENT_ROOT}/runtime/node" "${CURRENT_ROOT}/dist/client/index.js" "$@"
