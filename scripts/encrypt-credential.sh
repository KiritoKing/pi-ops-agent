#!/usr/bin/env bash
set -euo pipefail

readonly CREDENTIAL_DIR="/etc/ops-agent/credentials"
readonly CREDENTIAL_PATH="${CREDENTIAL_DIR}/deepseek_api_key.cred"
FORCE=false

if [[ ${1:-} == "--force" ]]; then
  FORCE=true
  shift
fi
if (($# > 0)); then
  printf '用法: sudo scripts/encrypt-credential.sh [--force]\n' >&2
  exit 2
fi
if [[ ${EUID} -ne 0 ]]; then
  printf '请用 root 运行。\n' >&2
  exit 1
fi
command -v systemd-creds >/dev/null 2>&1 || {
  printf '缺少 systemd-creds。\n' >&2
  exit 1
}
if [[ -e "${CREDENTIAL_PATH}" ]] && [[ "${FORCE}" != true ]]; then
  printf '%s 已存在；使用 --force 明确轮换。\n' "${CREDENTIAL_PATH}" >&2
  exit 1
fi

install -d -o root -g root -m 0700 "${CREDENTIAL_DIR}"
IFS= read -r -s -p 'DeepSeek API key: ' api_key
printf '\n'
IFS= read -r -s -p '再次输入: ' api_key_confirm
printf '\n'
if [[ "${api_key}" != "${api_key_confirm}" ]]; then
  unset api_key api_key_confirm
  printf '两次输入不一致。\n' >&2
  exit 1
fi
if ((${#api_key} < 16)); then
  unset api_key api_key_confirm
  printf 'credential 长度异常。\n' >&2
  exit 1
fi

encrypted_tmp="$(mktemp "${CREDENTIAL_DIR}/.deepseek_api_key.XXXXXX")"
trap 'rm -f -- "${encrypted_tmp:-}"' EXIT
printf '%s' "${api_key}" | systemd-creds encrypt --name=deepseek_api_key - "${encrypted_tmp}"
unset api_key api_key_confirm
chown root:root "${encrypted_tmp}"
chmod 0600 "${encrypted_tmp}"
mv -f -- "${encrypted_tmp}" "${CREDENTIAL_PATH}"
trap - EXIT

printf '已写入 systemd encrypted credential：%s\n' "${CREDENTIAL_PATH}"
printf '可执行：sudo systemctl restart ops-agentd.service\n'
