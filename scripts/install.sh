#!/usr/bin/env bash
set -euo pipefail

readonly APP_ROOT="/opt/pi-ops-agent"
readonly CONFIG_ROOT="/etc/ops-agent"
readonly UNIT_ROOT="/etc/systemd/system"
readonly TMPFILES_ROOT="/etc/tmpfiles.d"
readonly SERVICE_USER="ops-agent"
readonly SERVICE_GROUP="ops-agent"

SOURCE_ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
APPROVER_USER="${SUDO_USER:-}"
START_NOW=false

usage() {
  printf '%s\n' \
    "用法: sudo scripts/install.sh --approver-user <消息桥审批账户> [--start]" \
    "" \
    "--approver-user  唯一允许向 root-helper 提交审批命令的本机消息桥账户" \
    "--start          安装后立即启动；要求 encrypted credential 已存在"
}

while (($# > 0)); do
  case "$1" in
    --approver-user)
      (($# >= 2)) || { printf '缺少 --approver-user 参数\n' >&2; exit 2; }
      APPROVER_USER="$2"
      shift 2
      ;;
    --start)
      START_NOW=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf '未知参数: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ ${EUID} -ne 0 ]]; then
  printf '请用 root 运行安装脚本。\n' >&2
  exit 1
fi
if [[ "$(uname -s)" != "Linux" ]] || [[ ! -d /run/systemd/system ]]; then
  printf '仅支持以 systemd 为 PID 1 的 Linux。\n' >&2
  exit 1
fi
if [[ -z "${APPROVER_USER}" ]] || ! id "${APPROVER_USER}" >/dev/null 2>&1; then
  printf '必须通过 --approver-user 指定已存在的消息桥审批账户。\n' >&2
  exit 1
fi
if [[ "${APPROVER_USER}" == "${SERVICE_USER}" ]] || [[ "${APPROVER_USER}" == "root" ]]; then
  printf '审批账户不能是 root 或 %s。\n' "${SERVICE_USER}" >&2
  exit 1
fi

for command in systemctl systemd-tmpfiles systemd-creds getent groupadd useradd usermod install node file; do
  command -v "${command}" >/dev/null 2>&1 || {
    printf '缺少依赖: %s\n' "${command}" >&2
    exit 1
  }
done
command -v bwrap >/dev/null 2>&1 || {
  printf '缺少 bubblewrap（bwrap），请先用系统包管理器安装。\n' >&2
  exit 1
}

node -e 'const [major, minor] = process.versions.node.split(".").map(Number); if (major < 22 || (major === 22 && minor < 19)) process.exit(1)' || {
  printf '需要 Node.js >= 22.19.0。\n' >&2
  exit 1
}

required_paths=(
  "dist/agentd/index.js"
  "dist/client/index.js"
  "integrations/botmux/adapter.mjs"
  "bin/ops-root-helper"
  "bin/ops-systemd-helper"
  "node_modules/@earendil-works/pi-coding-agent/package.json"
  "config/agentd.json"
  "config/models.json"
)
for path in "${required_paths[@]}"; do
  [[ -e "${SOURCE_ROOT}/${path}" ]] || {
    printf '缺少构建产物 %s；请先按 README 执行构建与检查。\n' "${path}" >&2
    exit 1
  }
done

case "$(uname -m)" in
  x86_64) expected_binary_arch="x86-64" ;;
  aarch64|arm64) expected_binary_arch="ARM aarch64" ;;
  *)
    printf '当前安装器仅验证 x86_64/aarch64 helper，检测到 %s。\n' "$(uname -m)" >&2
    exit 1
    ;;
esac
for helper in ops-root-helper ops-systemd-helper; do
  helper_info="$(file -b -- "${SOURCE_ROOT}/bin/${helper}")"
  if [[ "${helper_info}" != ELF* ]] || [[ "${helper_info}" != *"${expected_binary_arch}"* ]]; then
    printf '拒绝安装 %s：目标需要 Linux ELF %s，实际为 %s。请在目标 Linux 构建或正确交叉编译。\n' \
      "${helper}" "${expected_binary_arch}" "${helper_info}" >&2
    exit 1
  fi
done

if ! getent group "${SERVICE_GROUP}" >/dev/null; then
  groupadd --system "${SERVICE_GROUP}"
fi
if ! id "${SERVICE_USER}" >/dev/null 2>&1; then
  useradd --system --gid "${SERVICE_GROUP}" --home-dir /var/lib/ops-agent \
    --shell /usr/sbin/nologin --comment "Pi Ops Agent" "${SERVICE_USER}"
fi
usermod --append --groups "${SERVICE_GROUP}" "${APPROVER_USER}"

install -d -o root -g root -m 0755 \
  "${APP_ROOT}" "${APP_ROOT}/bin" "${APP_ROOT}/botmux-bin" "${APP_ROOT}/runtime"
for directory in config dist node_modules docs scripts integrations; do
  install -d -o root -g root -m 0755 "${APP_ROOT}/${directory}"
  cp -a "${SOURCE_ROOT}/${directory}/." "${APP_ROOT}/${directory}/"
done
install -o root -g root -m 0755 "$(command -v node)" "${APP_ROOT}/runtime/node"
install -o root -g root -m 0755 "${SOURCE_ROOT}/bin/ops-root-helper" "${APP_ROOT}/bin/ops-root-helper"
install -o root -g root -m 0755 "${SOURCE_ROOT}/bin/ops-systemd-helper" "${APP_ROOT}/bin/ops-systemd-helper"
install -o root -g root -m 0755 "${SOURCE_ROOT}/scripts/ops-agent.sh" "${APP_ROOT}/bin/ops-agent"
install -o root -g root -m 0755 "${SOURCE_ROOT}/scripts/ops-agent-botmux.sh" "${APP_ROOT}/bin/ops-agent-botmux"
install -o root -g root -m 0755 "${SOURCE_ROOT}/scripts/ops-agent-botmux.sh" "${APP_ROOT}/botmux-bin/pi"
chmod 0755 "${APP_ROOT}/integrations/botmux/adapter.mjs"
install -o root -g root -m 0644 "${SOURCE_ROOT}/package.json" "${APP_ROOT}/package.json"
install -o root -g root -m 0644 "${SOURCE_ROOT}/package-lock.json" "${APP_ROOT}/package-lock.json"
install -o root -g root -m 0644 "${SOURCE_ROOT}/README.md" "${APP_ROOT}/README.md"
install -o root -g root -m 0644 "${SOURCE_ROOT}/LICENSE" "${APP_ROOT}/LICENSE"
chown -R root:root "${APP_ROOT}"
find "${APP_ROOT}/scripts" -maxdepth 1 -type f -name '*.sh' -exec chmod 0755 {} +

install -d -o root -g "${SERVICE_GROUP}" -m 0750 "${CONFIG_ROOT}"
install -d -o root -g root -m 0700 "${CONFIG_ROOT}/credentials"
for config in agentd.json models.json; do
  if [[ ! -e "${CONFIG_ROOT}/${config}" ]]; then
    install -o root -g "${SERVICE_GROUP}" -m 0640 "${SOURCE_ROOT}/config/${config}" "${CONFIG_ROOT}/${config}"
  else
    install -o root -g "${SERVICE_GROUP}" -m 0640 "${SOURCE_ROOT}/config/${config}" "${CONFIG_ROOT}/${config}.dist"
    printf '保留已有 %s；新默认值写入 %s.dist。\n' "${CONFIG_ROOT}/${config}" "${CONFIG_ROOT}/${config}"
  fi
done

agent_uid="$(id -u "${SERVICE_USER}")"
agent_gid="$(getent group "${SERVICE_GROUP}" | cut -d: -f3)"
approver_uid="$(id -u "${APPROVER_USER}")"
runtime_tmp="$(mktemp "${CONFIG_ROOT}/.runtime.env.XXXXXX")"
trap 'rm -f -- "${runtime_tmp:-}"' EXIT
printf 'OPS_AGENT_UID=%s\nOPS_AGENT_GID=%s\nOPS_APPROVER_UID=%s\n' \
  "${agent_uid}" "${agent_gid}" "${approver_uid}" >"${runtime_tmp}"
chown root:root "${runtime_tmp}"
chmod 0600 "${runtime_tmp}"
mv -f -- "${runtime_tmp}" "${CONFIG_ROOT}/runtime.env"
trap - EXIT

for unit in "${SOURCE_ROOT}"/systemd/*.service "${SOURCE_ROOT}"/systemd/*.timer "${SOURCE_ROOT}"/systemd/*.target; do
  install -o root -g root -m 0644 "${unit}" "${UNIT_ROOT}/$(basename "${unit}")"
done
install -o root -g root -m 0644 "${SOURCE_ROOT}/systemd/ops-agent.tmpfiles.conf" \
  "${TMPFILES_ROOT}/ops-agent.conf"
systemd-tmpfiles --create "${TMPFILES_ROOT}/ops-agent.conf"
systemctl daemon-reload
systemctl enable ops-agent.target ops-agent-healthcheck.timer

if [[ "${START_NOW}" == true ]]; then
  if [[ ! -f "${CONFIG_ROOT}/credentials/deepseek_api_key.cred" ]]; then
    printf '尚未创建 encrypted credential；拒绝启动。请先运行 scripts/encrypt-credential.sh。\n' >&2
    exit 1
  fi
  systemctl restart ops-agent.target
  systemctl restart ops-agent-healthcheck.timer
fi

printf '%s\n' \
  "安装完成。审批 UID=${approver_uid}，agent UID=${agent_uid}。" \
  "重新登录 ${APPROVER_USER} 后，新增的 ${SERVICE_GROUP} 组成员关系才会进入会话。" \
  "下一步：sudo ${APP_ROOT}/scripts/encrypt-credential.sh，然后 sudo systemctl start ops-agent.target。"
