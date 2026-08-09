#!/usr/bin/env bash
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

readonly release_root="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly installer="${release_root}/install-release.sh"
readonly host_policy_helper="${release_root}/configure-noble-bwrap-apparmor.sh"
readonly payload="${release_root}/payload"

verify_root_release_tree() {
  local current uid mode mode_value unsafe_entry
  [[ ! -L "${BASH_SOURCE[0]}" ]] || {
    printf 'Release bootstrap must not be invoked through a symlink.\n' >&2
    return 1
  }
  for required_command in stat find dirname; do
    command -v "${required_command}" >/dev/null 2>&1 || {
      printf 'Missing release bootstrap dependency: %s\n' "${required_command}" >&2
      return 1
    }
  done
  current="${release_root}"
  while true; do
    uid="$(stat -c '%u' -- "${current}")" || return 1
    mode="$(stat -c '%a' -- "${current}")" || return 1
    [[ "${uid}" == 0 && "${mode}" =~ ^[0-7]{3,4}$ ]] || {
      printf 'Release path ownership or mode is unsafe: %s\n' "${current}" >&2
      return 1
    }
    mode_value=$((8#${mode}))
    if (((mode_value & 0022) != 0 && (mode_value & 01000) == 0)); then
      printf 'Release path ancestor is writable without the sticky bit: %s\n' "${current}" >&2
      return 1
    fi
    [[ "${current}" != / ]] || break
    current="$(dirname -- "${current}")" || return 1
  done
  unsafe_entry="$(find "${release_root}" -xdev \
    \( ! -user root -o \( \( -type f -o -type d \) -perm /022 \) \) \
    -print -quit)" || return 1
  [[ -z "${unsafe_entry}" ]] || {
    printf 'Release tree contains a non-root-owned or writable entry: %s\n' "${unsafe_entry}" >&2
    return 1
  }
}

usage() {
  cat <<'EOF'
Usage:
  sudo ./ops-agent-bootstrap host-policy inspect
  sudo ./ops-agent-bootstrap host-policy install [--approve-digest sha256:...]
  sudo ./ops-agent-bootstrap host-policy status
  sudo ./ops-agent-bootstrap init [INSTALLER OPTIONS]
  sudo ./ops-agent-bootstrap join [INSTALLER OPTIONS]

The host-policy stage is explicit and never runs as part of init or join.
EOF
}

if (($# == 0)); then
  usage >&2
  exit 2
fi

mode="$1"
shift
case "${mode}" in
  host-policy)
    if (($# == 0)); then
      printf 'host-policy requires inspect, install, or status.\n' >&2
      usage >&2
      exit 2
    fi
    case "$1" in
      inspect|install|status) ;;
      *)
        printf 'Unknown host-policy action: %s\n' "$1" >&2
        usage >&2
        exit 2
        ;;
    esac
    ;;
  init|join) ;;
  -h|--help)
    usage
    exit 0
    ;;
  *)
    printf 'Unknown mode: %s\n' "${mode}" >&2
    usage >&2
    exit 2
    ;;
esac

if ((EUID == 0)); then
  verify_root_release_tree
fi

for required_file in "${installer}" "${host_policy_helper}"; do
  [[ -f "${required_file}" && ! -L "${required_file}" && -x "${required_file}" ]] || {
    printf 'Release entry is missing or unsafe: %s\n' "${required_file}" >&2
    exit 1
  }
done
[[ -d "${payload}" && ! -L "${payload}" ]] || {
  printf 'Release payload directory is missing or unsafe.\n' >&2
  exit 1
}

if [[ "${mode}" == host-policy ]]; then
  exec "${host_policy_helper}" "$@"
fi

export OPS_AGENT_PAYLOAD_DIR="${payload}"
exec "${installer}" "${mode}" "$@"
