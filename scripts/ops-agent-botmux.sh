#!/usr/bin/env bash
set -euo pipefail

readonly APP_ROOT="/opt/pi-ops-agent"
exec "${APP_ROOT}/runtime/node" "${APP_ROOT}/integrations/botmux/adapter.mjs" "$@"
