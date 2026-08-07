#!/usr/bin/env bash
set -euo pipefail

readonly APP_ROOT="/opt/pi-ops-agent"
readonly RELEASE_ROOT="${APP_ROOT}/releases"
readonly CURRENT_LINK="${APP_ROOT}/current"
readonly CONFIG_ROOT="/etc/ops-agent"
readonly UNIT_ROOT="/etc/systemd/system"
readonly TMPFILES_ROOT="/etc/tmpfiles.d"
readonly SERVICE_USER="ops-agent"
readonly SERVICE_GROUP="ops-agent"
readonly SERVER_USER="ops-agent-server"
readonly SERVER_GROUP="ops-agent-server"

PAYLOAD_DIR="${OPS_AGENT_PAYLOAD_DIR:-}"
MODE=""
ADMIN_USER="${SUDO_USER:-}"
ENROLLMENT_FILE=""
CONTROLLER_URL=""
START_NOW=true
POLICY_CANDIDATE=""
POLICY_BACKUP=""

usage() {
  cat <<'EOF'
Usage:
  install-release.sh init [--admin-user USER] [--no-start]
  install-release.sh join --controller URL --token-file PATH [--no-start]

This is the host-mutating half of the GitHub Release installer. It consumes an
already verified OPS_AGENT_PAYLOAD_DIR and never downloads or builds source.
`init` installs the core controller, local endpoint and TUI only. It never
installs or initializes BotMux or another external adapter.
EOF
}

if (($# == 0)); then
  usage >&2
  exit 2
fi
MODE="$1"
shift
case "${MODE}" in
  init)
    while (($# > 0)); do
      case "$1" in
        --admin-user)
          (($# >= 2)) || { printf 'Missing --admin-user value.\n' >&2; exit 2; }
          ADMIN_USER="$2"
          shift 2
          ;;
        --no-start) START_NOW=false; shift ;;
        -h|--help) usage; exit 0 ;;
        *) printf 'Unknown init argument: %s\n' "$1" >&2; exit 2 ;;
      esac
    done
    ;;
  join)
    while (($# > 0)); do
      case "$1" in
        --controller)
          (($# >= 2)) || { printf 'Missing --controller value.\n' >&2; exit 2; }
          CONTROLLER_URL="$2"
          shift 2
          ;;
        --token-file)
          (($# >= 2)) || { printf 'Missing --token-file value.\n' >&2; exit 2; }
          ENROLLMENT_FILE="$2"
          shift 2
          ;;
        --no-start) START_NOW=false; shift ;;
        -h|--help) usage; exit 0 ;;
        *) printf 'Unknown join argument: %s\n' "$1" >&2; exit 2 ;;
      esac
    done
    [[ -n "${CONTROLLER_URL}" ]] || { printf 'join requires --controller URL.\n' >&2; exit 2; }
    [[ -n "${ENROLLMENT_FILE}" ]] || { printf 'join requires --token-file PATH.\n' >&2; exit 2; }
    if [[ ! -f "${ENROLLMENT_FILE}" ]] || [[ -L "${ENROLLMENT_FILE}" ]]; then
      printf 'Enrollment token must be a regular, non-symlink file.\n' >&2
      exit 2
    fi
    ;;
  -h|--help) usage; exit 0 ;;
  *) printf 'Unknown mode: %s\n' "${MODE}" >&2; usage >&2; exit 2 ;;
esac

if [[ ${EUID} -ne 0 ]]; then
  printf 'Run the release installer as root.\n' >&2
  exit 1
fi
if [[ "$(uname -s)" != Linux ]] || [[ ! -d /run/systemd/system ]]; then
  printf 'Pi Ops Agent supports only Linux with systemd as PID 1.\n' >&2
  exit 1
fi
if [[ -z "${PAYLOAD_DIR}" ]] || [[ ! -d "${PAYLOAD_DIR}/app" ]]; then
  printf 'OPS_AGENT_PAYLOAD_DIR does not contain a release payload.\n' >&2
  exit 1
fi

install_native_dependencies() {
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends bubblewrap openssl ca-certificates diffutils
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y bubblewrap openssl ca-certificates diffutils
  elif command -v yum >/dev/null 2>&1; then
    yum install -y bubblewrap openssl ca-certificates diffutils
  elif command -v zypper >/dev/null 2>&1; then
    zypper --non-interactive install bubblewrap openssl ca-certificates diffutils
  elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --needed --noconfirm bubblewrap openssl ca-certificates diffutils
  else
    printf 'Install bubblewrap, OpenSSL, CA certificates and diffutils, then retry.\n' >&2
    return 1
  fi
}

if ! command -v bwrap >/dev/null 2>&1 || ! command -v openssl >/dev/null 2>&1 || ! command -v diff >/dev/null 2>&1; then
  install_native_dependencies
fi

for required_command in systemctl systemd-tmpfiles getent groupadd useradd usermod install cp mv ln readlink mktemp stat wc openssl bwrap sha256sum hostname sed tr cut runuser sleep diff; do
  command -v "${required_command}" >/dev/null 2>&1 || {
    printf 'Missing installation dependency: %s\n' "${required_command}" >&2
    exit 1
  }
done

version_file="${PAYLOAD_DIR}/VERSION"
[[ -f "${version_file}" ]] || { printf 'Release VERSION is missing.\n' >&2; exit 1; }
IFS= read -r release_version <"${version_file}"
if [[ ! "${release_version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  printf 'Invalid release VERSION: %s\n' "${release_version}" >&2
  exit 1
fi

if [[ "${MODE}" == join ]]; then
  if [[ ! "${CONTROLLER_URL}" =~ ^https://[^[:space:]]+$ ]]; then
    printf 'The enrollment controller must be an https:// URL.\n' >&2
    exit 2
  fi
  token_mode="$(stat -c '%a' "${ENROLLMENT_FILE}")"
  token_bytes="$(wc -c <"${ENROLLMENT_FILE}")"
  if ((10#${token_mode} % 100 > 0)); then
    printf 'Enrollment token file must not be group/world accessible (mode=%s).\n' "${token_mode}" >&2
    exit 2
  fi
  if ((token_bytes < 16 || token_bytes > 131072)); then
    printf 'Enrollment token file length is outside the supported range.\n' >&2
    exit 2
  fi
fi

if [[ "${MODE}" == init ]]; then
  if [[ -z "${ADMIN_USER}" ]] || ! id "${ADMIN_USER}" >/dev/null 2>&1; then
    printf 'init requires an existing non-root --admin-user (sudo normally supplies SUDO_USER).\n' >&2
    exit 1
  fi
  if [[ "${ADMIN_USER}" == root ]] || [[ "${ADMIN_USER}" == "${SERVICE_USER}" ]] || [[ "${ADMIN_USER}" == "${SERVER_USER}" ]]; then
    printf 'The local administrator cannot be root or a Pi Ops Agent service account.\n' >&2
    exit 1
  fi
fi

if ! getent group "${SERVICE_GROUP}" >/dev/null; then
  groupadd --system "${SERVICE_GROUP}"
fi
if ! id "${SERVICE_USER}" >/dev/null 2>&1; then
  useradd --system --gid "${SERVICE_GROUP}" --home-dir /var/lib/ops-agent \
    --shell /usr/sbin/nologin --comment "Pi Ops Agent" "${SERVICE_USER}"
fi
if ! getent group "${SERVER_GROUP}" >/dev/null; then
  groupadd --system "${SERVER_GROUP}"
fi
if ! id "${SERVER_USER}" >/dev/null 2>&1; then
  useradd --system --gid "${SERVER_GROUP}" --home-dir /var/lib/ops-agent/server \
    --shell /usr/sbin/nologin --comment "Pi Ops Agent network server" "${SERVER_USER}"
fi
usermod --append --groups "${SERVICE_GROUP}" "${SERVER_USER}"
if [[ "${MODE}" == init ]]; then
  usermod --append --groups "${SERVICE_GROUP},${SERVER_GROUP}" "${ADMIN_USER}"
fi

install -d -o root -g root -m 0755 "${APP_ROOT}" "${RELEASE_ROOT}"
release_dir="${RELEASE_ROOT}/${release_version}"
if [[ -e "${release_dir}" ]] || [[ -L "${release_dir}" ]]; then
  if [[ ! -d "${release_dir}" ]] || [[ -L "${release_dir}" ]]; then
    printf 'Existing release path is not a real directory: %s\n' "${release_dir}" >&2
    exit 1
  fi
  if ! diff --brief --recursive --no-dereference "${PAYLOAD_DIR}/app" "${release_dir}" >/dev/null; then
    printf 'Existing release %s does not match the verified payload; refusing same-version reuse.\n' "${release_version}" >&2
    exit 1
  fi
else
  release_staging="${RELEASE_ROOT}/.${release_version}.new.$$"
  install -d -o root -g root -m 0755 "${release_staging}"
  cleanup_release_staging() {
    if [[ -n "${release_staging:-}" ]] && [[ -d "${release_staging}" ]]; then
      find "${release_staging}" -mindepth 1 -depth -delete
      rmdir "${release_staging}"
    fi
  }
  trap cleanup_release_staging EXIT HUP INT TERM
  cp -a "${PAYLOAD_DIR}/app/." "${release_staging}/"
  chown -R root:root "${release_staging}"
  mv -- "${release_staging}" "${release_dir}"
  release_staging=""
  trap - EXIT HUP INT TERM
fi

install -d -o root -g "${SERVICE_GROUP}" -m 0750 "${CONFIG_ROOT}"
install -d -o root -g root -m 0700 "${CONFIG_ROOT}/credentials"
for config_name in agentd.json models.json; do
  source_config="${release_dir}/config/${config_name}"
  [[ -f "${source_config}" ]] || continue
  if [[ ! -e "${CONFIG_ROOT}/${config_name}" ]]; then
    install -o root -g "${SERVICE_GROUP}" -m 0640 "${source_config}" "${CONFIG_ROOT}/${config_name}"
  else
    install -o root -g "${SERVICE_GROUP}" -m 0640 "${source_config}" "${CONFIG_ROOT}/${config_name}.dist"
  fi
done

agent_uid="$(id -u "${SERVICE_USER}")"
agent_gid="$(getent group "${SERVICE_GROUP}" | cut -d: -f3)"
server_uid="$(id -u "${SERVER_USER}")"
server_gid="$(getent group "${SERVER_GROUP}" | cut -d: -f3)"
if [[ "${MODE}" == init ]]; then
  approver_uid="$(id -u "${ADMIN_USER}")"
else
  approver_uid=0
fi
runtime_tmp="$(mktemp "${CONFIG_ROOT}/.runtime.env.XXXXXX")"
trap 'rm -f -- "${runtime_tmp:-}"' EXIT HUP INT TERM
printf 'OPS_AGENT_UID=%s\nOPS_AGENT_GID=%s\nOPS_SERVER_UID=%s\nOPS_SERVER_GID=%s\nOPS_APPROVER_UID=%s\n' \
  "${agent_uid}" "${agent_gid}" "${server_uid}" "${server_gid}" "${approver_uid}" >"${runtime_tmp}"
chown root:root "${runtime_tmp}"
chmod 0600 "${runtime_tmp}"
mv -f -- "${runtime_tmp}" "${CONFIG_ROOT}/runtime.env"
trap - EXIT HUP INT TERM

initialize_local_endpoint() {
  local tls_root="${CONFIG_ROOT}/tls"
  local approver_root="${CONFIG_ROOT}/approver/${ADMIN_USER}"
  local admin_group
  admin_group="$(id -gn "${ADMIN_USER}")"
  install -d -o root -g "${SERVICE_GROUP}" -m 0750 "${tls_root}"
  install -d -o "${ADMIN_USER}" -g "${admin_group}" -m 0700 "${approver_root}"

  if [[ ! -f "${tls_root}/ca.crt" ]]; then
    local certificate_staging
    certificate_staging="$(mktemp -d "${CONFIG_ROOT}/.tls-init.XXXXXX")"
    cleanup_certificate_staging() {
      find "${certificate_staging}" -mindepth 1 -depth -delete 2>/dev/null || true
      rmdir "${certificate_staging}" 2>/dev/null || true
    }
    trap cleanup_certificate_staging EXIT HUP INT TERM

    openssl req -x509 -newkey ed25519 -nodes -days 3650 \
      -subj '/CN=Pi Ops Agent Local CA' \
      -addext 'basicConstraints=critical,CA:TRUE' \
      -addext 'keyUsage=critical,keyCertSign,cRLSign' \
      -keyout "${certificate_staging}/ca.key" -out "${certificate_staging}/ca.crt"

    openssl genpkey -algorithm ED25519 -out "${certificate_staging}/server.key"
    openssl req -new -key "${certificate_staging}/server.key" -subj '/CN=localhost' \
      -out "${certificate_staging}/server.csr"
    cat >"${certificate_staging}/server.ext" <<'EOF'
[leaf]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF
    openssl x509 -req -days 825 -in "${certificate_staging}/server.csr" \
      -CA "${certificate_staging}/ca.crt" -CAkey "${certificate_staging}/ca.key" \
      -CAcreateserial -extfile "${certificate_staging}/server.ext" -extensions leaf \
      -out "${certificate_staging}/server.crt"

    for role in agent approver; do
      openssl genpkey -algorithm ED25519 -out "${certificate_staging}/${role}.key"
      openssl req -new -key "${certificate_staging}/${role}.key" \
        -subj "/CN=ops-agent-${role}" -out "${certificate_staging}/${role}.csr"
      cat >"${certificate_staging}/${role}.ext" <<EOF
[leaf]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectAltName=URI:spiffe://ops-agent/role/${role}
EOF
      openssl x509 -req -days 825 -in "${certificate_staging}/${role}.csr" \
        -CA "${certificate_staging}/ca.crt" -CAkey "${certificate_staging}/ca.key" \
        -CAserial "${certificate_staging}/ca.srl" \
        -extfile "${certificate_staging}/${role}.ext" -extensions leaf \
        -out "${certificate_staging}/${role}.crt"
    done
    openssl genpkey -algorithm ED25519 -out "${certificate_staging}/approval.key.pem"
    openssl pkey -in "${certificate_staging}/approval.key.pem" -pubout \
      -out "${certificate_staging}/approval.pub.pem"

    install -o root -g root -m 0600 "${certificate_staging}/ca.key" "${tls_root}/ca.key"
    install -o root -g "${SERVICE_GROUP}" -m 0640 "${certificate_staging}/ca.crt" "${tls_root}/ca.crt"
    install -o root -g "${SERVICE_GROUP}" -m 0640 "${certificate_staging}/ca.crt" "${tls_root}/client-ca.crt"
    install -o root -g "${SERVER_GROUP}" -m 0640 "${certificate_staging}/server.key" "${tls_root}/server.key"
    install -o root -g "${SERVER_GROUP}" -m 0640 "${certificate_staging}/server.crt" "${tls_root}/server.crt"
    install -o root -g "${SERVICE_GROUP}" -m 0640 "${certificate_staging}/agent.key" "${tls_root}/agent.key"
    install -o root -g "${SERVICE_GROUP}" -m 0640 "${certificate_staging}/agent.crt" "${tls_root}/agent.crt"
    install -o root -g root -m 0644 "${certificate_staging}/approval.pub.pem" "${tls_root}/approval.pub.pem"
    install -o "${ADMIN_USER}" -g "${admin_group}" -m 0600 \
      "${certificate_staging}/approver.key" "${approver_root}/approver.key"
    install -o "${ADMIN_USER}" -g "${admin_group}" -m 0600 \
      "${certificate_staging}/approver.crt" "${approver_root}/approver.crt"
    install -o "${ADMIN_USER}" -g "${admin_group}" -m 0600 \
      "${certificate_staging}/approval.key.pem" "${approver_root}/approval.key.pem"
    cleanup_certificate_staging
    trap - EXIT HUP INT TERM
  fi
  for required_security_file in \
    "${tls_root}/ca.crt" "${tls_root}/client-ca.crt" \
    "${tls_root}/server.crt" "${tls_root}/server.key" \
    "${tls_root}/agent.crt" "${tls_root}/agent.key" \
    "${tls_root}/approval.pub.pem" \
    "${approver_root}/approver.crt" "${approver_root}/approver.key" \
    "${approver_root}/approval.key.pem"; do
    [[ -f "${required_security_file}" ]] || {
      printf 'Local endpoint security material is incomplete: %s\n' "${required_security_file}" >&2
      return 1
    }
  done

  local machine_raw machine_id server_hash server_id machine_name
  machine_raw="$(tr -cd 'a-fA-F0-9' </etc/machine-id 2>/dev/null || true)"
  if [[ ${#machine_raw} -lt 16 ]]; then
    machine_raw="$(hostname | sha256sum | cut -c1-32)"
  fi
  machine_id="machine-${machine_raw:0:32}"
  server_hash="$(printf '%s' "${machine_id}" | sha256sum | cut -c1-32)"
  server_id="server-${server_hash}"
  machine_name="$(hostname | tr -cd 'a-zA-Z0-9._-')"
  [[ -n "${machine_name}" ]] || machine_name="local-machine"

  if [[ ! -f "${CONFIG_ROOT}/server-identity.json" ]]; then
    cat >"${CONFIG_ROOT}/server-identity.json" <<EOF
{"version":1,"serverId":"${server_id}","machineId":"${machine_id}","machineName":"${machine_name}","account":"${SERVER_USER}"}
EOF
    chown root:"${SERVER_GROUP}" "${CONFIG_ROOT}/server-identity.json"
    chmod 0640 "${CONFIG_ROOT}/server-identity.json"
  fi
  POLICY_CANDIDATE="${CONFIG_ROOT}/.targets.json.candidate.${release_version}.$$"
  [[ ! -e "${POLICY_CANDIDATE}" ]] || {
    printf 'Refusing to overwrite an existing policy candidate: %s\n' "${POLICY_CANDIDATE}" >&2
    return 1
  }
  "${release_dir}/runtime/node" "${release_dir}/scripts/initialize-target-policy.mjs" \
    --catalog-index "${release_dir}/catalog/index.json" \
    --policy "${CONFIG_ROOT}/targets.json" \
    --output "${POLICY_CANDIDATE}" >/dev/null
  chown root:"${SERVER_GROUP}" "${POLICY_CANDIDATE}"
  chmod 0640 "${POLICY_CANDIDATE}"
  if [[ ! -f "${CONFIG_ROOT}/servers.json" ]]; then
    cat >"${CONFIG_ROOT}/servers.json" <<EOF
{"version":1,"servers":[{"serverId":"${server_id}","machineId":"${machine_id}","baseUrl":"https://127.0.0.1:7443","caPath":"${tls_root}/ca.crt","certPath":"${tls_root}/agent.crt","keyPath":"${tls_root}/agent.key","approverCertPath":"${approver_root}/approver.crt","approverKeyPath":"${approver_root}/approver.key","approvalSigningKeyPath":"${approver_root}/approval.key.pem","approvalKeyId":"local-approver-v1","serverName":"localhost","enabled":true}]}
EOF
    chown root:"${SERVICE_GROUP}" "${CONFIG_ROOT}/servers.json"
    chmod 0640 "${CONFIG_ROOT}/servers.json"
  fi
}

cleanup_policy_candidate() {
  if [[ -n "${POLICY_CANDIDATE:-}" ]] && [[ -f "${POLICY_CANDIDATE}" ]]; then
    rm -f -- "${POLICY_CANDIDATE}"
  fi
}

if [[ "${MODE}" == init ]]; then
  initialize_local_endpoint
  trap cleanup_policy_candidate EXIT HUP INT TERM
fi

for unit in "${release_dir}"/systemd/*.service "${release_dir}"/systemd/*.timer "${release_dir}"/systemd/*.target; do
  [[ -f "${unit}" ]] || continue
  install -o root -g root -m 0644 "${unit}" "${UNIT_ROOT}/$(basename "${unit}")"
done
for existing_dropin in "${UNIT_ROOT}"/ops-*.service.d/zzzz-ops-agent-*.conf; do
  [[ -f "${existing_dropin}" ]] || continue
  dropin_directory="$(basename "$(dirname "${existing_dropin}")")"
  dropin_name="$(basename "${existing_dropin}")"
  if [[ "${dropin_directory}/${dropin_name}" == "ops-agentd.service.d/zzzz-ops-agent-credential.conf" ]]; then
    continue
  fi
  if [[ ! -f "${release_dir}/systemd/${dropin_directory}/${dropin_name}" ]]; then
    rm -f -- "${existing_dropin}"
  fi
done
for dropin_dir in "${release_dir}"/systemd/*.service.d; do
  [[ -d "${dropin_dir}" ]] || continue
  destination_dropin="${UNIT_ROOT}/$(basename "${dropin_dir}")"
  install -d -o root -g root -m 0755 "${destination_dropin}"
  for dropin in "${dropin_dir}"/*.conf; do
    [[ -f "${dropin}" ]] || continue
    install -o root -g root -m 0644 "${dropin}" "${destination_dropin}/$(basename "${dropin}")"
  done
done
install -d -o root -g root -m 0755 "${UNIT_ROOT}/ops-agentd.service.d"
cat >"${UNIT_ROOT}/ops-agentd.service.d/zzzz-ops-agent-credential.conf" <<'EOF'
[Service]
LoadCredentialEncrypted=deepseek_api_key:/etc/ops-agent/credentials/deepseek_api_key.cred
EOF
chown root:root "${UNIT_ROOT}/ops-agentd.service.d/zzzz-ops-agent-credential.conf"
chmod 0644 "${UNIT_ROOT}/ops-agentd.service.d/zzzz-ops-agent-credential.conf"
if [[ -f "${release_dir}/systemd/ops-agent.tmpfiles.conf" ]]; then
  install -o root -g root -m 0644 "${release_dir}/systemd/ops-agent.tmpfiles.conf" \
    "${TMPFILES_ROOT}/ops-agent.conf"
fi

previous_current_present=false
previous_current_target=""
if [[ -L "${CURRENT_LINK}" ]]; then
  previous_current_present=true
  previous_current_target="$(readlink "${CURRENT_LINK}")"
elif [[ -e "${CURRENT_LINK}" ]]; then
  printf 'Refusing to replace non-symlink current path: %s\n' "${CURRENT_LINK}" >&2
  exit 1
fi

policy_was_present=false
if [[ "${MODE}" == init ]] && [[ -f "${CONFIG_ROOT}/targets.json" ]]; then
  policy_was_present=true
  POLICY_BACKUP="$(mktemp "${CONFIG_ROOT}/targets.json.backup.${release_version}.XXXXXX")"
  install -o root -g "${SERVER_GROUP}" -m 0640 "${CONFIG_ROOT}/targets.json" "${POLICY_BACKUP}"
fi

rollback_activation() {
  local activation_status=$?
  local restore_tmp=""
  ((activation_status != 0)) || activation_status=1
  trap - ERR EXIT HUP INT TERM
  set +e
  if [[ "${previous_current_present}" == true ]]; then
    current_tmp="${APP_ROOT}/.current.rollback.${release_version}.$$"
    rm -f -- "${current_tmp}"
    ln -s "${previous_current_target}" "${current_tmp}"
    mv -Tf -- "${current_tmp}" "${CURRENT_LINK}"
  elif [[ -L "${CURRENT_LINK}" ]] && [[ "$(readlink "${CURRENT_LINK}")" == "releases/${release_version}" ]]; then
    rm -f -- "${CURRENT_LINK}"
  fi
  if [[ "${MODE}" == init ]]; then
    if [[ "${policy_was_present}" == true ]] && [[ -f "${POLICY_BACKUP}" ]]; then
      restore_tmp="${CONFIG_ROOT}/.targets.json.restore.${release_version}.$$"
      install -o root -g "${SERVER_GROUP}" -m 0640 "${POLICY_BACKUP}" "${restore_tmp}"
      mv -f -- "${restore_tmp}" "${CONFIG_ROOT}/targets.json"
    elif [[ "${policy_was_present}" == false ]]; then
      rm -f -- "${CONFIG_ROOT}/targets.json"
    fi
  fi
  cleanup_policy_candidate
  systemctl daemon-reload >/dev/null 2>&1 || true
  if [[ "${START_NOW}" == true ]] && [[ "${previous_current_present}" == true ]]; then
    if [[ "${MODE}" == init ]]; then
      systemctl try-restart ops-agent.target ops-agent-healthcheck.timer >/dev/null 2>&1 || true
    else
      systemctl try-restart ops-root-helper.service ops-agent-server.service >/dev/null 2>&1 || true
    fi
  fi
  printf 'Release activation failed; restored the previous current link and target policy. Policy backup: %s\n' "${POLICY_BACKUP:-none}" >&2
  exit "${activation_status}"
}

trap - EXIT HUP INT TERM
trap rollback_activation ERR EXIT HUP INT TERM
if [[ "${MODE}" == init ]]; then
  mv -f -- "${POLICY_CANDIDATE}" "${CONFIG_ROOT}/targets.json"
  POLICY_CANDIDATE=""
fi
current_tmp="${APP_ROOT}/.current.${release_version}.$$"
ln -s "releases/${release_version}" "${current_tmp}"
mv -Tf -- "${current_tmp}" "${CURRENT_LINK}"
ln -sfn "${CURRENT_LINK}/bin/ops-agent" /usr/local/bin/ops-agent

systemd-tmpfiles --create "${TMPFILES_ROOT}/ops-agent.conf"
systemctl daemon-reload

if [[ "${MODE}" == init ]]; then
  if runuser -u "${SERVICE_USER}" -- bwrap --unshare-all --die-with-parent \
    --new-session --ro-bind / / --proc /proc --dev /dev /bin/true >/dev/null 2>&1; then
    sed -i 's/"sandboxEnabled": false/"sandboxEnabled": true/' "${CONFIG_ROOT}/agentd.json"
  else
    sed -i 's/"sandboxEnabled": true/"sandboxEnabled": false/' "${CONFIG_ROOT}/agentd.json"
    printf 'bubblewrap user namespaces are unavailable; ops_bash is disabled fail-closed.\n' >&2
  fi
fi

if [[ "${MODE}" == join ]]; then
  server_binary="${CURRENT_LINK}/bin/ops-agent-server"
  if [[ ! -x "${server_binary}" ]]; then
    printf 'This release does not contain ops-agent-server; refusing partial join.\n' >&2
    exit 1
  fi
  enrollment_file="$(mktemp "${CONFIG_ROOT}/.enrollment.XXXXXX")"
  trap 'rm -f -- "${enrollment_file:-}"' EXIT HUP INT TERM
  install -o root -g root -m 0600 "${ENROLLMENT_FILE}" "${enrollment_file}"
  "${server_binary}" enroll --controller "${CONTROLLER_URL}" --token-file "${enrollment_file}"
  rm -f -- "${enrollment_file}"
  trap - EXIT HUP INT TERM
  systemctl enable ops-root-helper.service ops-agent-server.service
  if [[ "${START_NOW}" == true ]]; then
    systemctl restart ops-root-helper.service ops-agent-server.service
  fi
  trap - ERR EXIT HUP INT TERM
  printf 'Pi Ops Agent endpoint %s installed and enrolled.\n' "${release_version}"
  exit 0
fi

systemctl enable ops-agent.target ops-agent-healthcheck.timer
credential_path="${CONFIG_ROOT}/credentials/deepseek_api_key.cred"
if [[ ! -f "${credential_path}" ]] && [[ "${START_NOW}" == true ]]; then
  if [[ ! -c /dev/tty ]]; then
    printf 'No controlling TTY is available for model credential input. Re-run with --no-start, then run %s/scripts/encrypt-credential.sh.\n' "${CURRENT_LINK}" >&2
    exit 1
  fi
  "${CURRENT_LINK}/scripts/encrypt-credential.sh" </dev/tty
fi
if [[ "${START_NOW}" == true ]]; then
  systemctl restart ops-agent.target ops-agent-healthcheck.timer
  for required_socket in \
    /run/ops-agent/helper/root-helper.sock \
    /run/ops-agent/helper/systemd-helper.sock \
    /run/ops-agent/agentd/agentd.sock; do
    socket_attempt=0
    while [[ ! -S "${required_socket}" ]] && ((socket_attempt < 100)); do
      sleep 0.1
      socket_attempt=$((socket_attempt + 1))
    done
    if [[ ! -S "${required_socket}" ]]; then
      printf 'Timed out waiting for runtime socket: %s\n' "${required_socket}" >&2
      exit 1
    fi
  done
  "${CURRENT_LINK}/scripts/healthcheck.sh"
fi

trap - ERR EXIT HUP INT TERM

printf '%s\n' \
  "Pi Ops Agent ${release_version} initialized without external IM adapters." \
  "Re-login as ${ADMIN_USER} to refresh group membership, then run: ops-agent tui" \
  "Managed workload plugins require model-external credential provisioning with configure-plugin-credentials.sh before deployment." \
  "Install an adapter later by asking the Agent from TUI; BotMux itself remains an external dependency."
if [[ ! -f "${credential_path}" ]]; then
  printf 'Before starting, create the model credential with: sudo %s/scripts/encrypt-credential.sh\n' \
    "${CURRENT_LINK}"
fi
if [[ -n "${POLICY_BACKUP}" ]]; then
  printf 'Previous target policy backup retained at: %s\n' "${POLICY_BACKUP}"
fi
