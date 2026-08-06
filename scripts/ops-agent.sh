#!/usr/bin/env bash
set -euo pipefail

readonly APP_ROOT="/opt/pi-ops-agent"
readonly CURRENT_ROOT="${APP_ROOT}/current"

case "${1:-tui}" in
  tui)
    shift || true
    ;;
  endpoint-token)
    shift
    exec "${CURRENT_ROOT}/bin/ops-agent-server" issue-enrollment "$@"
    ;;
esac

exec "${CURRENT_ROOT}/runtime/node" "${CURRENT_ROOT}/dist/client/index.js" "$@"
