#!/bin/bash
set -euo pipefail

export PATH="/usr/sbin:/usr/bin:/sbin:/bin"
readonly PATH
export LC_ALL=C
unset BASH_ENV CDPATH ENV
umask 077

readonly EXPECTED_PACKAGE="apparmor-profiles"
readonly EXPECTED_PACKAGE_VERSION="4.0.1really4.0.1-0ubuntu0.24.04.7"
readonly EXPECTED_PROFILE_SHA256="11d39094f044f0cda0febb3ad517b830301da6b2ce929664af09ee9e4dd264f9"
readonly LOCAL_RULE="/usr/bin/bwrap ix,"
readonly AUTHORITY_SUMMARY_SHA256="c745e2eb341efc1a26b017e63cc03b284f63f51298036ce58e9e6661d7f7015c"
readonly APPROVAL_DIGEST="sha256:d2b2928681d31e9430a9a2a1949ead607580311cba35b776e6a651e1d67254ef"
readonly MANAGED_PROFILE="/etc/apparmor.d/bwrap-userns-restrict"
readonly MANAGED_LOCAL_RULE="/etc/apparmor.d/local/bwrap-userns-restrict"
readonly DISABLE_PROFILE="/etc/apparmor.d/disable/bwrap-userns-restrict"
readonly COMPLAIN_PROFILE="/etc/apparmor.d/force-complain/bwrap-userns-restrict"
readonly RESTRICTION_PATH="/proc/sys/kernel/apparmor_restrict_unprivileged_userns"
readonly LOADED_PROFILES_PATH="/sys/kernel/security/apparmor/profiles"
readonly LOCK_DIRECTORY="/etc/apparmor.d"
readonly STATUS_ABSENT=3

ACTION=""
APPROVE_DIGEST=""
PROFILE_SOURCE=""
TARGET_STATE="unknown"
KERNEL_STATE="unknown"
CREATED_LOCAL_DIRECTORY=false
FRESH_MUTATION=false
STAGED_PATH=""
LOCK_HELD=false

print_authority_summary() {
  /bin/cat <<'EOF'
AUTHORITY SUMMARY (non-secret)
- This installs a host-wide, argv-blind AppArmor rule: /usr/bin/bwrap ix,
  The rule matches only the executable path; it cannot distinguish or constrain
  bwrap arguments for a process already running in the bwrap setup profile.
- ops-agentd's direct bundled Node process stays in the bwrap setup profile for
  its service lifetime, before and despite NoNewPrivileges=yes. If Core is
  compromised, it can attempt the user-namespace, mount, and network-namespace
  setup authority granted to that profile. Source code is expected to transition
  to unpriv_bwrap, but the setup window is intentional residual authority.
- This does not support the BotMux main -> pi wrapper -> Node launch chain on a
  restricted Ubuntu 24.04 host. BotMux remains unsupported and fail-closed.
- Automatic profile removal is unavailable. Failure cleanup and uninstall never
  unload kernel profiles; loaded/inconclusive state retains managed files and
  requires a separately audited host-maintenance procedure.
EOF
}

usage() {
  /bin/cat <<'EOF'
Usage: configure-noble-bwrap-apparmor.sh inspect|status
       configure-noble-bwrap-apparmor.sh install [--approve-digest sha256:...]
       configure-noble-bwrap-apparmor.sh remove

Installs only the pinned Ubuntu 24.04 apparmor-profiles bwrap policy and the
exact /usr/bin/bwrap ix compatibility rule required by Pi Ops Agent's fixed
outer-to-inner bubblewrap transition. It never installs packages, changes a
sysctl, enables SUID bubblewrap, or loads an unconfined profile.

The approval digest binds the package name, exact package version, reviewed
source digest, exact local-rule bytes, and the complete authority summary shown
before confirmation. Automatic removal is deliberately unavailable in this
release because a process can acquire the setup label between userspace scans;
uninstall therefore preserves the host policy. Failure handling never unloads a
kernel profile and deletes fresh files only when both managed profile names are
proven absent from kernel state.

status returns 0 only after exact managed files, both expected enforcing profile
identities, and a newly completed-and-cleaned static NNP authority smoke all pass.
It returns 3 for a safely absent policy and 1 for drift, partial state, smoke
failure, or inaccessible evidence. Kernel name/mode evidence alone is not a
policy digest or completion proof.
EOF
}

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  return 1
}

require_root() {
  [[ "${EUID}" -eq 0 ]] || fail "run ${ACTION} as root"
}

require_fixed_commands() {
  local command_path
  for command_path in \
      /bin/bash /bin/sh \
      /usr/bin/awk /usr/bin/busctl /usr/bin/bwrap /bin/cat \
      /usr/bin/chmod /usr/bin/chown /usr/bin/cmp /usr/bin/dpkg \
      /usr/bin/dpkg-query /usr/bin/getent \
      /usr/bin/flock /usr/bin/grep /usr/bin/id /usr/bin/install /usr/bin/ln \
      /usr/bin/journalctl /usr/bin/mktemp /usr/bin/readlink /usr/bin/realpath /usr/bin/rm \
      /usr/bin/rmdir /usr/bin/sha256sum /usr/bin/sleep /usr/bin/stat /usr/bin/systemctl \
      /usr/bin/unshare /usr/sbin/apparmor_parser /usr/sbin/getcap; do
    [[ -x "${command_path}" ]] || fail "required fixed command is unavailable: ${command_path}"
  done
}

acquire_helper_lock() {
  local fd_identity path_identity
  [[ -d "${LOCK_DIRECTORY}" && ! -L "${LOCK_DIRECTORY}" \
      && "$(/usr/bin/stat -c '%u:%g:%a' "${LOCK_DIRECTORY}")" == 0:0:755 ]] \
    || fail "AppArmor helper lock directory is unsafe"
  exec 8<"${LOCK_DIRECTORY}"
  path_identity="$(/usr/bin/stat -c '%d:%i' "${LOCK_DIRECTORY}")"
  fd_identity="$(/usr/bin/stat -Lc '%d:%i' /proc/self/fd/8)"
  [[ "${fd_identity}" == "${path_identity}" ]] \
    || fail "AppArmor helper lock descriptor identity is inconsistent"
  /usr/bin/flock --exclusive --nonblock 8 \
    || fail "another AppArmor compatibility helper action is already running"
  LOCK_HELD=true
}

validate_noble_host() {
  local os_release_source os_release_metadata os_release_uid os_release_gid
  local os_release_mode os_release_links os_release_size line
  local os_id_count=0 os_version_count=0
  local -a os_release_lines=()
  if [[ -L /etc/os-release ]]; then
    [[ "$(/usr/bin/readlink -- /etc/os-release)" == ../usr/lib/os-release ]] \
      || fail "/etc/os-release is not the standard Ubuntu os-release symlink"
    os_release_source="/usr/lib/os-release"
    [[ "$(/usr/bin/realpath -e -- /etc/os-release)" == "${os_release_source}" ]] \
      || fail "/etc/os-release does not resolve to canonical /usr/lib/os-release"
  else
    os_release_source="/etc/os-release"
    [[ "$(/usr/bin/realpath -e -- /etc/os-release)" == "${os_release_source}" ]] \
      || fail "/etc/os-release is not a canonical regular file"
  fi
  [[ -f "${os_release_source}" && ! -L "${os_release_source}" ]] \
    || fail "resolved os-release is not a regular non-symlink file"
  os_release_metadata="$(/usr/bin/stat -c '%u:%g:%a:%h:%s' "${os_release_source}")"
  IFS=: read -r os_release_uid os_release_gid os_release_mode \
    os_release_links os_release_size <<<"${os_release_metadata}"
  [[ "${os_release_uid}" == 0 && "${os_release_gid}" == 0 \
      && "${os_release_links}" =~ ^[1-9][0-9]*$ \
      && "${os_release_size}" =~ ^[0-9]+$ ]] \
    || fail "resolved os-release has unsafe metadata"
  if (( (8#${os_release_mode} & 0022) != 0 )); then
    fail "resolved os-release is group/world writable"
  fi
  ((os_release_size > 0 && os_release_size <= 16384)) \
    || fail "resolved os-release size is outside the reviewed bound"
  if ! mapfile -t os_release_lines <"${os_release_source}"; then
    fail "resolved os-release could not be read completely"
    return 1
  fi
  for line in "${os_release_lines[@]}"; do
    [[ "${line}" != *$'\r'* ]] || fail "resolved os-release contains a carriage return"
    case "${line}" in
      ID=ubuntu|ID='"ubuntu"') os_id_count=$((os_id_count + 1)) ;;
      ID=*) fail "this compatibility helper supports only Ubuntu" ;;
      VERSION_ID=24.04|VERSION_ID='"24.04"')
        os_version_count=$((os_version_count + 1))
        ;;
      VERSION_ID=*) fail "this compatibility helper supports only Ubuntu 24.04" ;;
    esac
  done
  [[ "${os_id_count}" -eq 1 && "${os_version_count}" -eq 1 ]] \
    || fail "os-release must contain unique Ubuntu 24.04 identity fields"
  [[ -r "${RESTRICTION_PATH}" ]] \
    || fail "restricted-userns sysctl is unavailable"
  [[ "$(<"${RESTRICTION_PATH}")" == 1 ]] \
    || fail "kernel.apparmor_restrict_unprivileged_userns must remain 1"
  [[ -r /sys/module/apparmor/parameters/enabled ]] \
    || fail "AppArmor is not enabled"
  case "$(</sys/module/apparmor/parameters/enabled)" in
    Y|y) ;;
    *) fail "AppArmor is not enabled in enforcing-capable mode" ;;
  esac
  [[ -r "${LOADED_PROFILES_PATH}" ]] \
    || fail "loaded AppArmor profile evidence is unreadable"
  [[ -d /run/systemd/system && ! -L /run/systemd/system ]] \
    || fail "systemd is not the usable PID 1 manager"
}

validate_bwrap_binary() {
  local canonical capabilities metadata mode
  [[ -f /usr/bin/bwrap && ! -L /usr/bin/bwrap ]] \
    || fail "/usr/bin/bwrap is not a regular non-symlink file"
  canonical="$(/usr/bin/realpath -e -- /usr/bin/bwrap)"
  [[ "${canonical}" == /usr/bin/bwrap ]] \
    || fail "/usr/bin/bwrap does not resolve to its fixed path"
  metadata="$(/usr/bin/stat -c '%u:%g:%a:%h' /usr/bin/bwrap)"
  IFS=: read -r _ _ mode _ <<<"${metadata}"
  [[ "${metadata%%:*}" == 0 && "${metadata#*:}" == 0:* ]] \
    || fail "/usr/bin/bwrap is not root:root"
  if (( (8#${mode} & 06022) != 0 )); then
    fail "/usr/bin/bwrap is writable outside root or has SUID/SGID bits"
  fi
  if ! capabilities="$(/usr/sbin/getcap -n /usr/bin/bwrap)"; then
    fail "could not inspect /usr/bin/bwrap file capabilities"
    return 1
  fi
  [[ -z "${capabilities}" ]] \
    || fail "/usr/bin/bwrap must not carry file capabilities"
}

validate_approval_digest_binding() {
  local computed summary_sha
  summary_sha="$(print_authority_summary | /usr/bin/sha256sum)"
  summary_sha="${summary_sha%% *}"
  [[ "${summary_sha}" == "${AUTHORITY_SUMMARY_SHA256}" ]] \
    || fail "internal AppArmor authority summary binding is inconsistent"
  computed="$({ printf '%s\0%s\0%s\0%s\0%s\0%s\n' \
    'ops-agent-noble-bwrap-apparmor/v1' \
    "package=${EXPECTED_PACKAGE}" \
    "version=${EXPECTED_PACKAGE_VERSION}" \
    "source-sha256=${EXPECTED_PROFILE_SHA256}" \
    "local-rule=${LOCAL_RULE}" \
    "authority-summary-sha256=${AUTHORITY_SUMMARY_SHA256}"; } \
    | /usr/bin/sha256sum)"
  computed="sha256:${computed%% *}"
  [[ "${computed}" == "${APPROVAL_DIGEST}" ]] \
    || fail "internal AppArmor approval digest binding is inconsistent"
}

inspect_pinned_package() {
  local package_status package_version package_drift source_sha source_metadata
  local source_uid source_gid source_mode source_links
  local -a profile_sources=() owners=()
  package_status="$(/usr/bin/dpkg-query --show \
    --showformat='${db:Status-Abbrev}' "${EXPECTED_PACKAGE}" 2>/dev/null || true)"
  [[ "${package_status}" == ii\  ]] \
    || fail "${EXPECTED_PACKAGE} is not installed in an exact installed state"
  package_version="$(/usr/bin/dpkg-query --show \
    --showformat='${Version}' "${EXPECTED_PACKAGE}")"
  [[ "${package_version}" == "${EXPECTED_PACKAGE_VERSION}" ]] \
    || fail "unsupported ${EXPECTED_PACKAGE} version: ${package_version}"
  package_drift="$(/usr/bin/dpkg --verify "${EXPECTED_PACKAGE}")"
  [[ -z "${package_drift}" ]] \
    || fail "dpkg reports drift in ${EXPECTED_PACKAGE}"

  mapfile -t profile_sources < <(
    /usr/bin/dpkg-query --listfiles "${EXPECTED_PACKAGE}" \
      | /usr/bin/awk -F/ '$NF == "bwrap-userns-restrict" { print }'
  )
  [[ "${#profile_sources[@]}" -eq 1 ]] \
    || fail "expected one package bwrap profile, found ${#profile_sources[@]}"
  PROFILE_SOURCE="${profile_sources[0]}"
  [[ "${PROFILE_SOURCE}" == /* && -f "${PROFILE_SOURCE}" && ! -L "${PROFILE_SOURCE}" ]] \
    || fail "package bwrap profile is not an absolute regular non-symlink file"
  [[ "$(/usr/bin/realpath -e -- "${PROFILE_SOURCE}")" == "${PROFILE_SOURCE}" ]] \
    || fail "package bwrap profile path is not canonical"
  mapfile -t owners < <(/usr/bin/dpkg-query --search "${PROFILE_SOURCE}")
  [[ "${#owners[@]}" -eq 1 \
      && "${owners[0]}" == "${EXPECTED_PACKAGE}: ${PROFILE_SOURCE}" ]] \
    || fail "package bwrap profile does not have unique dpkg ownership"
  source_metadata="$(/usr/bin/stat -c '%u:%g:%a:%h' "${PROFILE_SOURCE}")"
  IFS=: read -r source_uid source_gid source_mode source_links <<<"${source_metadata}"
  [[ "${source_uid}" == 0 && "${source_gid}" == 0 && "${source_links}" -ge 1 ]] \
    || fail "package bwrap profile has unsafe ownership"
  if (( (8#${source_mode} & 0022) != 0 )); then
    fail "package bwrap profile is group/world writable"
  fi
  source_sha="$(/usr/bin/sha256sum "${PROFILE_SOURCE}")"
  source_sha="${source_sha%% *}"
  [[ "${source_sha}" == "${EXPECTED_PROFILE_SHA256}" ]] \
    || fail "package bwrap profile digest is not the reviewed digest"
  /usr/bin/grep -Fq 'include if exists <local/bwrap-userns-restrict>' \
    "${PROFILE_SOURCE}" || fail "package profile omits its reviewed local include"
  /usr/bin/grep -Eq '^profile bwrap /usr/bin/bwrap ' "${PROFILE_SOURCE}" \
    || fail "package profile omits the fixed bwrap attachment"
  /usr/bin/grep -Eq '^profile unpriv_bwrap ' "${PROFILE_SOURCE}" \
    || fail "package profile omits the unprivileged child profile"

  printf 'apparmor-profile-package-version=%s\n' "${package_version}"
  printf 'apparmor-profile-source=%s\n' "${PROFILE_SOURCE}"
  printf 'apparmor-profile-source-sha256=%s\n' "${source_sha}"
  printf 'apparmor-policy-approval-digest=%s\n' "${APPROVAL_DIGEST}"
}

validate_policy_directory() {
  local path="$1"
  [[ -d "${path}" && ! -L "${path}" ]] \
    || fail "policy directory is not a real directory: ${path}"
  [[ "$(/usr/bin/stat -c '%u:%g:%a' "${path}")" == 0:0:755 ]] \
    || fail "policy directory must be root:root 0755: ${path}"
}

managed_profile_is_exact() {
  local destination_sha
  [[ -f "${MANAGED_PROFILE}" && ! -L "${MANAGED_PROFILE}" ]] || return 1
  [[ "$(/usr/bin/stat -c '%u:%g:%a:%h' "${MANAGED_PROFILE}")" == 0:0:644:1 ]] \
    || return 1
  destination_sha="$(/usr/bin/sha256sum "${MANAGED_PROFILE}")"
  destination_sha="${destination_sha%% *}"
  [[ "${destination_sha}" == "${EXPECTED_PROFILE_SHA256}" ]] || return 1
  /usr/bin/cmp --silent "${PROFILE_SOURCE}" "${MANAGED_PROFILE}"
}

managed_local_rule_is_exact() {
  [[ -f "${MANAGED_LOCAL_RULE}" && ! -L "${MANAGED_LOCAL_RULE}" ]] || return 1
  [[ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' "${MANAGED_LOCAL_RULE}")" \
      == "0:0:644:1:$(( ${#LOCAL_RULE} + 1 ))" ]] || return 1
  [[ "$(<"${MANAGED_LOCAL_RULE}")" == "${LOCAL_RULE}" ]]
}

inspect_target_state() {
  local main_present=false local_present=false
  validate_policy_directory /etc/apparmor.d
  for policy_path in "${DISABLE_PROFILE}" "${COMPLAIN_PROFILE}"; do
    if [[ -e "${policy_path}" || -L "${policy_path}" ]]; then
      fail "disable/force-complain policy path must be absent: ${policy_path}"
    fi
  done
  [[ -e "${MANAGED_PROFILE}" || -L "${MANAGED_PROFILE}" ]] && main_present=true
  [[ -e "${MANAGED_LOCAL_RULE}" || -L "${MANAGED_LOCAL_RULE}" ]] && local_present=true
  if [[ "${main_present}" == false && "${local_present}" == false ]]; then
    if [[ -e /etc/apparmor.d/local || -L /etc/apparmor.d/local ]]; then
      validate_policy_directory /etc/apparmor.d/local
    fi
    TARGET_STATE="absent"
    return 0
  fi
  [[ "${main_present}" == true && "${local_present}" == true ]] \
    || fail "managed AppArmor policy is partial/asymmetric"
  validate_policy_directory /etc/apparmor.d/local
  managed_profile_is_exact \
    || fail "managed bwrap profile is not the exact reviewed copy"
  managed_local_rule_is_exact \
    || fail "managed local bwrap rule is not the exact reviewed rule"
  TARGET_STATE="managed"
}

inspect_kernel_state() {
  local bwrap_line profile_line unpriv_line
  local -a bwrap_lines=() profile_lines=() unpriv_lines=()
  if ! mapfile -t profile_lines <"${LOADED_PROFILES_PATH}"; then
    fail "loaded AppArmor profile evidence could not be read completely"
    return 1
  fi
  for profile_line in "${profile_lines[@]}"; do
    case "${profile_line}" in
      "bwrap ("*) bwrap_lines+=("${profile_line}") ;;
      "unpriv_bwrap ("*) unpriv_lines+=("${profile_line}") ;;
    esac
  done
  [[ "${#bwrap_lines[@]}" -le 1 && "${#unpriv_lines[@]}" -le 1 ]] \
    || fail "kernel exposes duplicate bwrap profile identities"
  bwrap_line="${bwrap_lines[0]:-}"
  unpriv_line="${unpriv_lines[0]:-}"
  if [[ -z "${bwrap_line}" && -z "${unpriv_line}" ]]; then
    KERNEL_STATE="absent"
    return 0
  fi
  [[ -n "${bwrap_line}" && -n "${unpriv_line}" ]] \
    || fail "kernel bwrap profiles are partial/asymmetric"
  [[ "${bwrap_line}" == 'bwrap (enforce)' \
      && "${unpriv_line}" == 'unpriv_bwrap (enforce)' ]] \
    || fail "kernel bwrap profiles are not both in exact enforce mode"
  KERNEL_STATE="enforce"
}

print_state() {
  printf 'apparmor-managed-file-state=%s\n' "${TARGET_STATE}"
  printf 'apparmor-kernel-profile-state=%s\n' "${KERNEL_STATE}"
  printf 'kernel.apparmor_restrict_unprivileged_userns=%s\n' \
    "$(<"${RESTRICTION_PATH}")"
}

validate_consistent_state() {
  case "${TARGET_STATE}:${KERNEL_STATE}" in
    absent:absent|managed:absent|managed:enforce) ;;
    *) fail "managed files and kernel profile state are inconsistent" ;;
  esac
}

confirm_action() {
  local verb="$1"
  local confirmation="${verb} NOBLE BWRAP APPARMOR ${APPROVAL_DIGEST}"
  local answer
  if [[ -n "${APPROVE_DIGEST}" ]]; then
    print_authority_summary >&2
    [[ "${APPROVE_DIGEST}" == "${APPROVAL_DIGEST}" ]] \
      || fail "non-interactive approval digest does not match the reviewed profile"
    return 0
  fi
  [[ -c /dev/tty ]] || fail "interactive approval requires /dev/tty"
  exec 9<>/dev/tty
  [[ -t 9 ]] || fail "interactive approval requires a real TTY"
  print_authority_summary >&9
  printf 'Type exactly: %s\n> ' "${confirmation}" >&9
  IFS= read -r answer <&9 || fail "approval input failed"
  [[ "${answer}" == "${confirmation}" ]] || fail "exact approval phrase did not match"
  exec 9>&-
}

atomic_install_copy() {
  local source="$1" destination="$2" directory temporary
  directory="${destination%/*}"
  temporary="$(/usr/bin/mktemp "${directory}/.ops-agent-apparmor.XXXXXX")"
  STAGED_PATH="${temporary}"
  /usr/bin/install -o root -g root -m 0644 "${source}" "${temporary}"
  if ! /usr/bin/ln -- "${temporary}" "${destination}"; then
    /usr/bin/rm -- "${temporary}"
    return 1
  fi
  /usr/bin/rm -- "${temporary}"
  STAGED_PATH=""
}

atomic_install_local_rule() {
  local temporary
  temporary="$(/usr/bin/mktemp /etc/apparmor.d/local/.ops-agent-apparmor.XXXXXX)"
  STAGED_PATH="${temporary}"
  printf '%s\n' "${LOCAL_RULE}" >"${temporary}"
  /usr/bin/chown root:root "${temporary}"
  /usr/bin/chmod 0644 "${temporary}"
  if ! /usr/bin/ln -- "${temporary}" "${MANAGED_LOCAL_RULE}"; then
    /usr/bin/rm -- "${temporary}"
    return 1
  fi
  /usr/bin/rm -- "${temporary}"
  STAGED_PATH=""
}

kernel_profiles_are_proven_absent() {
  local matches grep_status=0
  [[ -r "${LOADED_PROFILES_PATH}" ]] || {
    printf 'INCOMPLETE: loaded AppArmor profile evidence became unreadable.\n' >&2
    return 1
  }
  matches="$(/usr/bin/grep -E '^(bwrap|unpriv_bwrap) \(' \
    "${LOADED_PROFILES_PATH}" 2>/dev/null)" || grep_status=$?
  case "${grep_status}" in
    0)
      printf 'INCOMPLETE: kernel still exposes managed AppArmor profiles: %s\n' \
        "${matches//$'\n'/, }" >&2
      return 1
      ;;
    1) return 0 ;;
    *)
      printf 'INCOMPLETE: loaded AppArmor profile absence could not be proven.\n' >&2
      return 1
      ;;
  esac
}

probe_unit_property() {
  local unit="$1" property="$2" value
  if ! value="$(/usr/bin/systemctl show \
      "${unit}" --property="${property}" --value)"; then
    fail "PID 1 did not return ${property} for AppArmor probe unit ${unit}"
    return 1
  fi
  if [[ "${value}" == *$'\n'* ]]; then
    fail "PID 1 returned a multi-line ${property} for AppArmor probe unit ${unit}"
    return 1
  fi
  printf '%s' "${value}"
}

require_probe_unit_property() {
  local unit="$1" property="$2" expected="$3" actual
  actual="$(probe_unit_property "${unit}" "${property}")" || return 1
  if [[ "${actual}" != "${expected}" ]]; then
    printf 'Unsafe effective %s for AppArmor probe unit %s: expected %q, got %q.\n' \
      "${property}" "${unit}" "${expected}" "${actual}" >&2
    return 1
  fi
}

probe_word_sets_equal() (
  set -f
  local left="$1" right="$2" left_word right_word matches
  local -a left_words=() right_words=()
  read -r -a left_words <<<"${left}"
  read -r -a right_words <<<"${right}"
  ((${#left_words[@]} == ${#right_words[@]})) || return 1
  for left_word in "${left_words[@]}"; do
    matches=0
    for right_word in "${right_words[@]}"; do
      if [[ "${left_word}" == "${right_word}" ]]; then
        matches=$((matches + 1))
      fi
    done
    [[ "${matches}" -eq 1 ]] || return 1
  done
)

require_probe_unit_word_set() {
  local unit="$1" property="$2" expected="$3" actual
  actual="$(probe_unit_property "${unit}" "${property}")" || return 1
  if ! probe_word_sets_equal "${actual}" "${expected}"; then
    printf 'Unsafe effective %s set for AppArmor probe unit %s: expected %q, got %q.\n' \
      "${property}" "${unit}" "${expected}" "${actual}" >&2
    return 1
  fi
}

verify_probe_system_default_dropin() {
  local path="$1" line section="" directive_seen=false
  case "${path}" in
    /usr/lib/systemd/system/service.d/10-timeout-abort.conf|\
    /lib/systemd/system/service.d/10-timeout-abort.conf|\
    /run/systemd/system/service.d/10-timeout-abort.conf) ;;
    *)
      fail "AppArmor probe loaded an unrecognized system service drop-in: ${path}"
      return 1
      ;;
  esac
  [[ -f "${path}" && ! -L "${path}" \
      && "$(/usr/bin/stat -c '%u:%g:%a:%h' "${path}")" == 0:0:644:1 ]] || {
    fail "system timeout compatibility drop-in is not exact root-owned 0644: ${path}"
    return 1
  }
  while IFS= read -r line || [[ -n "${line}" ]]; do
    [[ "${line}" != *$'\r'* ]] || {
      fail "system timeout compatibility drop-in contains a carriage return: ${path}"
      return 1
    }
    case "${line}" in
      ''|'#'*|';'*) continue ;;
      '[Service]')
        [[ -z "${section}" ]] || {
          fail "system timeout compatibility drop-in repeats its section: ${path}"
          return 1
        }
        section=service
        ;;
      'TimeoutStopFailureMode=abort')
        [[ "${section}" == service && "${directive_seen}" == false ]] || {
          fail "system timeout compatibility drop-in has unsafe structure: ${path}"
          return 1
        }
        directive_seen=true
        ;;
      *)
        fail "system timeout compatibility drop-in contains unreviewed authority: ${path}"
        return 1
        ;;
    esac
  done <"${path}"
  [[ "${section}" == service && "${directive_seen}" == true ]] || {
    fail "system timeout compatibility drop-in omits its exact reset: ${path}"
    return 1
  }
}

verify_probe_dropin_closure() {
  local unit="$1" security_dropin="$2" lifecycle_dropin="$3"
  local raw path security_seen=false lifecycle_seen=false system_default_count=0
  local -a paths=()
  raw="$(probe_unit_property "${unit}" DropInPaths)" || return 1
  read -r -a paths <<<"${raw}"
  for path in "${paths[@]}"; do
    case "${path}" in
      "${security_dropin}")
        [[ "${security_seen}" == false ]] || {
          fail "AppArmor probe loaded its security drop-in more than once"
          return 1
        }
        security_seen=true
        ;;
      "${lifecycle_dropin}")
        [[ "${lifecycle_seen}" == false ]] || {
          fail "AppArmor probe loaded its lifecycle drop-in more than once"
          return 1
        }
        lifecycle_seen=true
        ;;
      *)
        verify_probe_system_default_dropin "${path}" || return 1
        system_default_count=$((system_default_count + 1))
        [[ "${system_default_count}" -eq 1 ]] || {
          fail "AppArmor probe loaded multiple system-wide compatibility drop-ins"
          return 1
        }
        ;;
    esac
  done
  [[ "${security_seen}" == true && "${lifecycle_seen}" == true ]] || {
    fail "PID 1 did not load both exact AppArmor probe drop-ins"
    return 1
  }
}

require_probe_unit_exec_start() {
  local unit="$1" executable="$2" actual extended
  actual="$(probe_unit_property "${unit}" ExecStart)" || return 1
  case "${actual}" in
    "{ path=${executable} ; argv[]=${executable} ; ignore_errors=no ; "*) ;;
    *)
      printf 'Unsafe effective ExecStart for AppArmor probe unit %s: %q.\n' \
        "${unit}" "${actual}" >&2
      return 1
      ;;
  esac
  if [[ "${actual}" == *'} {'* ]]; then
    fail "AppArmor probe ExecStart contains more than one command"
    return 1
  fi
  extended="$(probe_unit_property "${unit}" ExecStartEx)" || return 1
  case "${extended}" in
    "{ path=${executable} ; argv[]=${executable} ; flags= ; "*) ;;
    *)
      printf 'Unsafe effective ExecStartEx for AppArmor probe unit %s: %q.\n' \
        "${unit}" "${extended}" >&2
      return 1
      ;;
  esac
  if [[ "${extended}" == *'} {'* ]]; then
    fail "AppArmor probe ExecStartEx contains more than one command"
    return 1
  fi
}

verify_probe_effective_vector() {
  local unit="$1" unit_path="$2" security_dropin="$3" lifecycle_dropin="$4"
  local driver="$5" nonce="$6" expectation property expected
  local -a scalar_expectations=(
    "LoadState=loaded"
    "FragmentPath=${unit_path}"
    "NeedDaemonReload=no"
    "User=nobody"
    "Group=nogroup"
    "Type=exec"
    "ExitType=cgroup"
    "UMask=0077"
    "RemainAfterExit=no"
    "Restart=no"
    "TimeoutStartUSec=10s"
    "RuntimeMaxUSec=30s"
    "TimeoutStopUSec=10s"
    "TimeoutStopFailureMode=terminate"
    "KillMode=control-group"
    "NoNewPrivileges=yes"
    "PrivateTmp=yes"
    "PrivateDevices=yes"
    "ProtectSystem=strict"
    "ProtectHome=yes"
    "ProtectKernelTunables=yes"
    "ProtectKernelModules=yes"
    "ProtectKernelLogs=yes"
    "ProtectControlGroups=yes"
    "ProtectClock=yes"
    "ProtectHostname=yes"
    "ProtectProc=invisible"
    "ProcSubset=all"
    "RestrictRealtime=yes"
    "RestrictSUIDSGID=yes"
    "LockPersonality=yes"
    "SystemCallArchitectures=native"
    "ExecCondition="
    "ExecStartPre="
    "ExecStartPost="
    "ExecReload="
    "ExecStop="
    "ExecStopPost="
    "Environment="
    "EnvironmentFiles="
  )
  for expectation in "${scalar_expectations[@]}"; do
    property="${expectation%%=*}"
    expected="${expectation#*=}"
    require_probe_unit_property "${unit}" "${property}" "${expected}" || return 1
  done
  require_probe_unit_word_set "${unit}" SupplementaryGroups '' || return 1
  require_probe_unit_word_set "${unit}" CapabilityBoundingSet '' || return 1
  require_probe_unit_word_set "${unit}" RestrictNamespaces \
    'user ipc pid net mnt' || return 1
  require_probe_unit_word_set "${unit}" RestrictAddressFamilies \
    'AF_UNIX AF_INET AF_INET6 AF_NETLINK' || return 1
  require_probe_unit_word_set "${unit}" ReadWritePaths \
    "${nonce} /proc/sys/user/max_user_namespaces" || return 1
  require_probe_unit_exec_start "${unit}" "${driver}" || return 1
  verify_probe_dropin_closure \
    "${unit}" "${security_dropin}" "${lifecycle_dropin}" || return 1
}

cleanup_probe_artifacts() {
  local unit="$1" unit_path="$2" dropin_directory="$3" security_dropin="$4"
  local lifecycle_dropin="$5" driver="$6" source_script="$7" nonce="$8"
  local active_state manager_units="" artifact attempt failed=false
  if ! /usr/bin/systemctl stop "${unit}" >/dev/null 2>&1; then
    printf 'Probe unit stop failed; preserving its artifacts: %s\n' "${unit}" >&2
    return 1
  fi
  if ! active_state="$(/usr/bin/systemctl show \
      "${unit}" -p ActiveState --value 2>/dev/null)"; then
    printf 'Probe unit state became unreadable; preserving its artifacts: %s\n' \
      "${unit}" >&2
    return 1
  fi
  case "${active_state}" in
    inactive|failed) ;;
    *)
      printf 'Probe unit did not reach a proven stopped state (%s); preserving its artifacts: %s\n' \
        "${active_state:-empty}" "${unit}" >&2
      return 1
      ;;
  esac
  /usr/bin/systemctl reset-failed "${unit}" >/dev/null 2>&1 || failed=true
  for artifact in "${lifecycle_dropin}" "${security_dropin}" "${unit_path}" \
      "${driver}" "${source_script}" "${nonce}"; do
    if [[ -e "${artifact}" || -L "${artifact}" ]]; then
      /usr/bin/rm -- "${artifact}" || failed=true
    fi
  done
  if [[ -d "${dropin_directory}" ]]; then
    /usr/bin/rmdir -- "${dropin_directory}" || failed=true
  fi
  /usr/bin/systemctl daemon-reload >/dev/null 2>&1 || failed=true
  for artifact in "${lifecycle_dropin}" "${security_dropin}" "${unit_path}" \
      "${driver}" "${source_script}" "${nonce}" "${dropin_directory}"; do
    if [[ -e "${artifact}" || -L "${artifact}" ]]; then
      printf 'Probe cleanup left an exact artifact path behind: %s\n' "${artifact}" >&2
      failed=true
    fi
  done
  for ((attempt=0; attempt<100; attempt++)); do
    if ! manager_units="$(/usr/bin/systemctl list-units --all --plain \
        --no-legend -- "${unit}" 2>/dev/null)"; then
      printf 'Probe unit garbage-collection evidence became unreadable: %s\n' \
        "${unit}" >&2
      failed=true
      break
    fi
    [[ -z "${manager_units}" ]] && break
    /usr/bin/sleep 0.02
  done
  if [[ -n "${manager_units}" ]]; then
    printf 'Probe unit remained loaded after exact cleanup: %s\n' "${unit}" >&2
    failed=true
  fi
  [[ "${failed}" == false ]]
}

run_authoritative_systemd_smoke() (
  set -euo pipefail
  local unit_path unit dropin_directory security_dropin lifecycle_dropin
  local driver source_script nonce nonce_value object_reply object_path profile_reply
  local conditions_reply asserts_reply
  local result active attempt
  unit_path="$(/usr/bin/mktemp /run/systemd/system/ops-agent-apparmor-probe-XXXXXX.service)"
  unit="${unit_path##*/}"
  [[ "${unit}" =~ ^ops-agent-apparmor-probe-[A-Za-z0-9]+\.service$ ]] \
    || fail "unsafe systemd probe unit name"
  dropin_directory="/run/systemd/system/${unit}.d"
  security_dropin="${dropin_directory}/zzzz-ops-agent-security.conf"
  lifecycle_dropin="${dropin_directory}/zzzz-ops-agent-zz-preflight.conf"
  driver="/run/systemd/system/${unit%.service}-driver"
  source_script="/run/systemd/system/${unit%.service}-source"
  nonce="/run/systemd/system/${unit%.service}-nonce"
  nonce_value="ops-agent-apparmor:${unit}"
  trap 'cleanup_probe_artifacts "${unit}" "${unit_path}" "${dropin_directory}" \
    "${security_dropin}" "${lifecycle_dropin}" "${driver}" "${source_script}" \
    "${nonce}" || exit 1' EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM

  [[ "$(/usr/bin/getent passwd nobody | /usr/bin/awk -F: '{ print $1 ":" $3 ":" $4 }')" \
      == nobody:65534:65534 ]] || fail "nobody probe identity is not the Ubuntu fixed identity"
  [[ "$(/usr/bin/getent group nogroup | /usr/bin/awk -F: '{ print $1 ":" $3 }')" \
      == nogroup:65534 ]] || fail "nogroup probe identity is not the Ubuntu fixed identity"
  /usr/bin/install -d -o root -g root -m 0755 "${dropin_directory}"
  /usr/bin/install -o root -g nogroup -m 0620 /dev/null "${nonce}"

  /bin/cat >"${source_script}" <<'SOURCE'
#!/bin/bash
set -euo pipefail
test "$$" -eq 1
current_label="$(</proc/self/attr/current)"
[[ "${current_label}" == *unpriv_bwrap* ]]
no_new_privileges=""
declare -A capability_values=()
while read -r status_key status_value _; do
  status_key="${status_key%:}"
  case "${status_key}" in
    NoNewPrivs) no_new_privileges="${status_value}" ;;
    CapInh|CapPrm|CapEff|CapBnd|CapAmb)
      capability_values["${status_key}"]="${status_value}"
      ;;
  esac
done </proc/self/status
[[ "${no_new_privileges}" == 1 ]]
for capability_set in CapInh CapPrm CapEff CapBnd CapAmb; do
  capability_value="${capability_values["${capability_set}"]:-}"
  [[ -n "${capability_value}" && "${capability_value}" =~ ^0+$ ]]
done
if /usr/bin/unshare --user --map-root-user /bin/true >/dev/null 2>&1; then
  echo 'Source created a further user namespace' >&2
  exit 1
fi
if /usr/bin/bwrap --die-with-parent --unshare-user --uid 0 --gid 0 \
    --ro-bind / / -- /bin/true >/dev/null 2>&1; then
  echo 'Source obtained nested bubblewrap authority' >&2
  exit 1
fi
printf '%s' "${OPS_AGENT_APPARMOR_NONCE_VALUE}" >"${OPS_AGENT_APPARMOR_NONCE_PATH}"
SOURCE
  /usr/bin/chown root:root "${source_script}"
  /usr/bin/chmod 0755 "${source_script}"

  /bin/cat >"${driver}" <<EOF
#!/bin/sh
set -eu
IFS= read -r current_label </proc/self/attr/current
case "\${current_label}" in bwrap*) ;; *) exit 81 ;; esac
no_new_privileges=
while read -r status_key status_value rest; do
  case "\${status_key}" in NoNewPrivs:) no_new_privileges="\${status_value}" ;; esac
done </proc/self/status
[ "\${no_new_privileges}" = 1 ]
exec /usr/bin/bwrap --die-with-parent --sync-fd 1 --unshare-user --unshare-ipc --unshare-pid --unshare-net --cap-drop ALL --bind / / --proc /proc --dev /dev -- /usr/bin/bwrap --die-with-parent --new-session --unshare-user --unshare-ipc --unshare-pid --unshare-net --as-pid-1 --disable-userns --cap-drop ALL --ro-bind / / --bind ${nonce} ${nonce} --proc /proc --dev /dev --clearenv --setenv OPS_AGENT_APPARMOR_NONCE_PATH ${nonce} --setenv OPS_AGENT_APPARMOR_NONCE_VALUE ${nonce_value} -- /bin/bash ${source_script}
EOF
  /usr/bin/chown root:root "${driver}"
  /usr/bin/chmod 0755 "${driver}"
  /bin/cat >"${unit_path}" <<'EOF'
[Unit]
Description=Pi Ops Agent AppArmor nested-bwrap compatibility probe

[Service]
EOF
  /bin/cat >"${security_dropin}" <<EOF
[Service]
NoNewPrivileges=yes
AppArmorProfile=-bwrap
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=all
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native
CapabilityBoundingSet=
RestrictNamespaces=user ipc net mnt pid
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
ReadWritePaths=${nonce} /proc/sys/user/max_user_namespaces
EOF
  /bin/cat >"${lifecycle_dropin}" <<EOF
[Unit]
ConditionPathExists=
AssertPathExists=

[Service]
Type=exec
ExitType=cgroup
User=nobody
Group=nogroup
SupplementaryGroups=
UMask=0077
RemainAfterExit=no
Restart=no
TimeoutStartSec=10s
RuntimeMaxSec=30s
TimeoutStopSec=10s
TimeoutStopFailureMode=terminate
KillMode=control-group
ExecCondition=
ExecStartPre=
ExecStart=
ExecStart=${driver}
ExecStartPost=
EOF
  /usr/bin/chown root:root "${unit_path}" "${security_dropin}" "${lifecycle_dropin}"
  /usr/bin/chmod 0644 "${unit_path}" "${security_dropin}" "${lifecycle_dropin}"
  [[ "$(/usr/bin/stat -c '%u:%g:%a' "${dropin_directory}")" == 0:0:755 ]]
  [[ "$(/usr/bin/stat -c '%u:%g:%a:%h' "${unit_path}")" == 0:0:644:1 ]]
  [[ "$(/usr/bin/stat -c '%u:%g:%a:%h' "${security_dropin}")" == 0:0:644:1 ]]
  [[ "$(/usr/bin/stat -c '%u:%g:%a:%h' "${lifecycle_dropin}")" == 0:0:644:1 ]]
  [[ "$(/usr/bin/stat -c '%u:%g:%a:%h' "${driver}")" == 0:0:755:1 ]]
  [[ "$(/usr/bin/stat -c '%u:%g:%a:%h' "${source_script}")" == 0:0:755:1 ]]
  [[ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' "${nonce}")" == 0:65534:620:1:0 ]]

  /usr/bin/systemctl daemon-reload
  verify_probe_effective_vector "${unit}" "${unit_path}" \
    "${security_dropin}" "${lifecycle_dropin}" "${driver}" "${nonce}"
  object_reply="$(/usr/bin/busctl call org.freedesktop.systemd1 \
    /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager LoadUnit s "${unit}")"
  [[ "${object_reply}" =~ ^o\ \"(/org/freedesktop/systemd1/unit/[A-Za-z0-9_]+)\"$ ]] \
    || fail "PID 1 returned an invalid AppArmor probe object path"
  object_path="${BASH_REMATCH[1]}"
  conditions_reply="$(/usr/bin/busctl get-property org.freedesktop.systemd1 \
    "${object_path}" org.freedesktop.systemd1.Unit Conditions)"
  [[ "${conditions_reply}" == 'a(sbbsi) 0' ]] \
    || fail "PID 1 retained unexpected AppArmor probe conditions"
  asserts_reply="$(/usr/bin/busctl get-property org.freedesktop.systemd1 \
    "${object_path}" org.freedesktop.systemd1.Unit Asserts)"
  [[ "${asserts_reply}" == 'a(sbbsi) 0' ]] \
    || fail "PID 1 retained unexpected AppArmor probe asserts"
  profile_reply="$(/usr/bin/busctl get-property org.freedesktop.systemd1 \
    "${object_path}" org.freedesktop.systemd1.Service AppArmorProfile)"
  [[ "${profile_reply}" == '(bs) true "bwrap"' ]] \
    || fail "PID 1 did not preserve exact ignore-missing bwrap profile semantics"

  if ! /usr/bin/systemctl start "${unit}"; then
    /usr/bin/systemctl status "${unit}" --no-pager >&2 || true
    fail "AppArmor compatibility smoke could not start"
  fi
  active="$(/usr/bin/systemctl show "${unit}" -p ActiveState --value)"
  for ((attempt=0; attempt<300; attempt++)); do
    case "${active}" in
      inactive|failed) break ;;
      activating|active|deactivating)
        /usr/bin/sleep 0.1
        active="$(/usr/bin/systemctl show "${unit}" -p ActiveState --value)"
        ;;
      *) fail "AppArmor compatibility smoke entered unexpected state ${active}" ;;
    esac
  done
  ((attempt < 300)) || fail "AppArmor compatibility smoke exceeded its deadline"
  result="$(/usr/bin/systemctl show "${unit}" -p Result --value)"
  if [[ "${active}" != inactive || "${result}" != success \
      || "$(/usr/bin/systemctl show "${unit}" -p ExecMainStatus --value)" != 0 ]]; then
    /usr/bin/systemctl status "${unit}" --no-pager >&2 || true
    /usr/bin/journalctl --boot -u "${unit}" --no-pager -n 64 -o cat >&2 || true
    /usr/bin/journalctl --boot -k \
      --grep='apparmor="DENIED"|apparmor=DENIED' --no-pager -n 64 -o cat >&2 || true
    fail "AppArmor compatibility smoke did not finish successfully"
  fi
  [[ "$(/usr/bin/stat -c '%u:%g:%a:%h:%s' "${nonce}")" \
      == "0:65534:620:1:${#nonce_value}" ]] \
    || fail "AppArmor compatibility smoke nonce metadata is invalid"
  [[ "$(<"${nonce}")" == "${nonce_value}" ]] \
    || fail "AppArmor compatibility smoke nonce is invalid"
  [[ "$(<"${RESTRICTION_PATH}")" == 1 ]] \
    || fail "restricted-userns sysctl changed during the smoke"
  cleanup_probe_artifacts "${unit}" "${unit_path}" "${dropin_directory}" \
    "${security_dropin}" "${lifecycle_dropin}" "${driver}" "${source_script}" \
    "${nonce}"
  trap - EXIT HUP INT TERM
)

rollback_fresh_install() {
  [[ "${FRESH_MUTATION}" == true ]] || return 0
  if ! kernel_profiles_are_proven_absent; then
    printf '%s\n' \
      'INCOMPLETE: fresh AppArmor install failed after a profile may have loaded.' \
      'No profile was unloaded; managed files and kernel state were retained as recovery evidence.' >&2
    return 1
  fi
  if [[ -e "${MANAGED_PROFILE}" || -L "${MANAGED_PROFILE}" ]]; then
    if ! managed_profile_is_exact; then
      printf '%s\n' \
        'INCOMPLETE: fresh AppArmor profile drifted during rollback.' \
        'Files were retained as recovery evidence.' >&2
      return 1
    fi
  fi
  if [[ -e "${MANAGED_LOCAL_RULE}" || -L "${MANAGED_LOCAL_RULE}" ]]; then
    if ! managed_local_rule_is_exact; then
      printf '%s\n' \
        'INCOMPLETE: fresh AppArmor local rule drifted during rollback.' \
        'Files were retained as recovery evidence.' >&2
      return 1
    fi
  fi
  for managed_path in "${MANAGED_LOCAL_RULE}" "${MANAGED_PROFILE}"; do
    if [[ -e "${managed_path}" || -L "${managed_path}" ]]; then
      /usr/bin/rm -- "${managed_path}" || return 1
    fi
  done
  if [[ "${CREATED_LOCAL_DIRECTORY}" == true ]]; then
    /usr/bin/rmdir -- /etc/apparmor.d/local || return 1
  fi
  printf 'Fresh AppArmor compatibility install rolled back completely.\n' >&2
}

cleanup_staged_path() {
  local expected_destination="" staged_links staged_identity destination_identity
  [[ -n "${STAGED_PATH}" ]] || return 0
  case "${STAGED_PATH}" in
    /etc/apparmor.d/.ops-agent-apparmor.*)
      expected_destination="${MANAGED_PROFILE}"
      ;;
    /etc/apparmor.d/local/.ops-agent-apparmor.*)
      expected_destination="${MANAGED_LOCAL_RULE}"
      ;;
    *)
      printf 'INCOMPLETE: refusing unsafe staged AppArmor cleanup path: %s\n' \
        "${STAGED_PATH}" >&2
      return 1
      ;;
  esac
  if [[ -e "${STAGED_PATH}" || -L "${STAGED_PATH}" ]]; then
    if [[ ! -f "${STAGED_PATH}" || -L "${STAGED_PATH}" ]]; then
      printf 'INCOMPLETE: staged AppArmor file has unsafe metadata: %s\n' \
        "${STAGED_PATH}" >&2
      return 1
    fi
    staged_links="$(/usr/bin/stat -c '%u:%g:%h' "${STAGED_PATH}" 2>/dev/null || true)"
    case "${staged_links}" in
      0:0:1) ;;
      0:0:2)
        if [[ ! -f "${expected_destination}" || -L "${expected_destination}" ]]; then
          fail "staged AppArmor hard link has no exact destination peer"
          return 1
        fi
        staged_identity="$(/usr/bin/stat -c '%d:%i' "${STAGED_PATH}")"
        destination_identity="$(/usr/bin/stat -c '%d:%i' "${expected_destination}")"
        if [[ "${staged_identity}" != "${destination_identity}" ]]; then
          fail "staged AppArmor hard link identity is inconsistent"
          return 1
        fi
        ;;
      *)
        fail "staged AppArmor file has an unsafe hard-link count"
        return 1
        ;;
    esac
    /usr/bin/rm -- "${STAGED_PATH}" || return 1
  fi
  STAGED_PATH=""
}

handle_exit() {
  local status=$?
  trap - EXIT HUP INT TERM
  if [[ "${FRESH_MUTATION}" == true ]]; then
    cleanup_staged_path || status=1
    rollback_fresh_install || status=1
  fi
  exit "${status}"
}

do_install() {
  require_root
  require_fixed_commands
  validate_noble_host
  validate_bwrap_binary
  validate_approval_digest_binding
  acquire_helper_lock
  [[ "${LOCK_HELD}" == true ]] || fail "AppArmor helper lock was not retained"
  inspect_pinned_package
  inspect_target_state
  inspect_kernel_state
  validate_consistent_state
  print_state
  confirm_action INSTALL

  if [[ "${TARGET_STATE}" == absent ]]; then
    FRESH_MUTATION=true
    trap handle_exit EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    if [[ ! -e /etc/apparmor.d/local && ! -L /etc/apparmor.d/local ]]; then
      /usr/bin/install -d -o root -g root -m 0755 /etc/apparmor.d/local
      CREATED_LOCAL_DIRECTORY=true
    fi
    validate_policy_directory /etc/apparmor.d/local
    atomic_install_copy "${PROFILE_SOURCE}" "${MANAGED_PROFILE}"
    atomic_install_local_rule
    managed_profile_is_exact && managed_local_rule_is_exact \
      || fail "fresh managed AppArmor files failed exact verification"
  fi

  # Approval is not a lease on package or destination bytes. Re-observe every
  # digest-bound input immediately before asking the kernel to load policy.
  inspect_pinned_package
  inspect_target_state
  inspect_kernel_state
  [[ "${TARGET_STATE}" == managed ]] \
    || fail "managed policy disappeared before kernel load"
  validate_consistent_state
  /usr/sbin/apparmor_parser --config-file /dev/null \
    --skip-read-cache --skip-cache --replace "${MANAGED_PROFILE}"
  inspect_kernel_state
  [[ "${KERNEL_STATE}" == enforce ]] \
    || fail "AppArmor parser did not load both profiles in enforce mode"
  [[ "$(<"${RESTRICTION_PATH}")" == 1 ]] \
    || fail "restricted-userns sysctl changed during profile load"
  run_authoritative_systemd_smoke
  inspect_pinned_package
  inspect_target_state
  inspect_kernel_state
  [[ "${TARGET_STATE}" == managed && "${KERNEL_STATE}" == enforce ]] \
    || fail "AppArmor profiles changed after the authoritative smoke"
  FRESH_MUTATION=false
  trap - EXIT HUP INT TERM
  printf 'apparmor-managed-state=installed-and-verified\n'
}

do_remove() {
  fail "automatic AppArmor policy removal is unavailable; preserve the managed policy"
}

do_inspect() {
  require_root
  require_fixed_commands
  validate_noble_host
  validate_bwrap_binary
  validate_approval_digest_binding
  acquire_helper_lock
  [[ "${LOCK_HELD}" == true ]] || fail "AppArmor helper lock was not retained"
  inspect_pinned_package
  inspect_target_state
  inspect_kernel_state
  validate_consistent_state
  print_state
  printf 'apparmor-inspect=eligible\n'
}

do_status() {
  require_root
  require_fixed_commands
  validate_noble_host
  validate_bwrap_binary
  validate_approval_digest_binding
  acquire_helper_lock
  [[ "${LOCK_HELD}" == true ]] || fail "AppArmor helper lock was not retained"
  inspect_pinned_package
  inspect_target_state
  inspect_kernel_state
  print_state
  case "${TARGET_STATE}:${KERNEL_STATE}" in
    managed:enforce)
      run_authoritative_systemd_smoke
      inspect_pinned_package
      inspect_target_state
      inspect_kernel_state
      [[ "${TARGET_STATE}" == managed && "${KERNEL_STATE}" == enforce ]] \
        || fail "AppArmor profiles changed after the status smoke"
      [[ "$(<"${RESTRICTION_PATH}")" == 1 ]] \
        || fail "restricted-userns sysctl changed during the status smoke"
      printf 'apparmor-managed-state=verified-now\n'
      return 0
      ;;
    absent:absent)
      printf 'apparmor-managed-state=absent\n'
      return "${STATUS_ABSENT}"
      ;;
    *) fail "managed files and kernel profiles are inconsistent" ;;
  esac
}

if (($# == 0)); then
  usage >&2
  exit 2
fi
ACTION="$1"
shift
case "${ACTION}" in
  inspect|status|install|remove) ;;
  -h|--help) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
esac
while (($# > 0)); do
  case "$1" in
    --approve-digest)
      [[ -z "${APPROVE_DIGEST}" && -n "${2:-}" ]] || { usage >&2; exit 2; }
      APPROVE_DIGEST="$2"
      shift 2
      ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
if [[ "${ACTION}" != install && "${ACTION}" != remove \
    && -n "${APPROVE_DIGEST}" ]]; then
  fail "--approve-digest is valid only for install/remove"
fi
case "${ACTION}" in
  inspect) do_inspect ;;
  status) do_status ;;
  install) do_install ;;
  remove) do_remove ;;
esac
