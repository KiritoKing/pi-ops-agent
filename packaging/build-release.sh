#!/usr/bin/env bash
set -euo pipefail

REPOSITORY_ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
VERSION=""
ARCH=""
NODE_RUNTIME_DIR=""
BIN_DIR=""
OUTPUT_DIR=""

usage() {
  cat <<'EOF'
Usage: packaging/build-release.sh \
  --version 1.2.3 --arch amd64|arm64 \
  --node-runtime-dir PATH --bin-dir PATH --output-dir PATH

Builds a source-free native release archive and Debian package. TypeScript,
node_modules, Go binaries and the Node runtime must already exist; this command
does not fetch dependencies or compile source.
EOF
}

while (($# > 0)); do
  case "$1" in
    --version) VERSION="${2:-}"; shift 2 ;;
    --arch) ARCH="${2:-}"; shift 2 ;;
    --node-runtime-dir) NODE_RUNTIME_DIR="${2:-}"; shift 2 ;;
    --bin-dir) BIN_DIR="${2:-}"; shift 2 ;;
    --output-dir) OUTPUT_DIR="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'Unknown argument: %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ ! "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  printf 'Invalid --version: %s\n' "${VERSION}" >&2
  exit 2
fi
case "${ARCH}" in
  amd64|arm64) ;;
  *) printf 'Invalid --arch: %s\n' "${ARCH}" >&2; exit 2 ;;
esac
for directory in "${NODE_RUNTIME_DIR}" "${BIN_DIR}" "${OUTPUT_DIR}"; do
  [[ -n "${directory}" ]] || { printf 'All path arguments are required.\n' >&2; exit 2; }
done

required_paths=(
  "${REPOSITORY_ROOT}/dist/agentd/index.js"
  "${REPOSITORY_ROOT}/dist/client/index.js"
  "${REPOSITORY_ROOT}/node_modules/@earendil-works/pi-coding-agent/package.json"
  "${REPOSITORY_ROOT}/scripts/install-release.sh"
  "${REPOSITORY_ROOT}/scripts/ops-agent.sh"
  "${NODE_RUNTIME_DIR}/bin/node"
)
for required_path in "${required_paths[@]}"; do
  [[ -e "${required_path}" ]] || {
    printf 'Missing release input: %s\n' "${required_path}" >&2
    exit 1
  }
done
if ! compgen -G "${BIN_DIR}/ops-*" >/dev/null; then
  printf 'No prebuilt Go binaries found in %s.\n' "${BIN_DIR}" >&2
  exit 1
fi

mkdir -p "${OUTPUT_DIR}"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/ops-agent-release.XXXXXX")"
cleanup() {
  find "${work_dir}" -mindepth 1 -depth -delete 2>/dev/null || true
  rmdir "${work_dir}" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

archive_root="${work_dir}/archive"
app_root="${archive_root}/payload/app"
install -d -m 0755 \
  "${app_root}/bin" "${app_root}/runtime" "${app_root}/config" \
  "${app_root}/dist" "${app_root}/node_modules" "${app_root}/docs" \
  "${app_root}/scripts" "${app_root}/systemd" "${app_root}/catalog"

cp -a "${REPOSITORY_ROOT}/dist/." "${app_root}/dist/"
cp -a "${REPOSITORY_ROOT}/node_modules/." "${app_root}/node_modules/"
if [[ -d "${app_root}/node_modules/.vite" ]]; then
  find "${app_root}/node_modules/.vite" -mindepth 1 -depth -delete
  rmdir "${app_root}/node_modules/.vite"
fi
if find "${app_root}/node_modules" -path '*/.vite/*' -print -quit | grep -q .; then
  printf 'Refusing to package generated Vite test caches.\n' >&2
  exit 1
fi
for config_path in "${REPOSITORY_ROOT}"/config/*; do
  [[ -f "${config_path}" ]] || continue
  case "$(basename "${config_path}")" in
    botmux*) continue ;;
  esac
  install -m 0644 "${config_path}" "${app_root}/config/$(basename "${config_path}")"
done
cp -a "${REPOSITORY_ROOT}/docs/." "${app_root}/docs/"
cp -a "${REPOSITORY_ROOT}/systemd/." "${app_root}/systemd/"
"${REPOSITORY_ROOT}/packaging/build-botmux-plugin.sh" "${VERSION}" "${app_root}/catalog"
"${REPOSITORY_ROOT}/packaging/build-hermes-workload-plugin.sh" "${VERSION}" "${app_root}/catalog"
"${REPOSITORY_ROOT}/packaging/create-catalog-index.sh" "${app_root}/catalog" "${app_root}/catalog/index.json"
for script_name in configure-plugin-credentials.sh encrypt-credential.sh healthcheck.sh install-release.sh ops-agent.sh uninstall.sh; do
  install -m 0755 "${REPOSITORY_ROOT}/scripts/${script_name}" "${app_root}/scripts/${script_name}"
done
for script_name in configure-plugin-credentials.mjs initialize-target-policy.mjs; do
  install -m 0644 "${REPOSITORY_ROOT}/scripts/${script_name}" "${app_root}/scripts/${script_name}"
done
cp -a "${BIN_DIR}"/ops-* "${app_root}/bin/"
install -m 0755 "${NODE_RUNTIME_DIR}/bin/node" "${app_root}/runtime/node"
install -m 0755 "${REPOSITORY_ROOT}/scripts/ops-agent.sh" "${app_root}/bin/ops-agent"
install -m 0755 "${REPOSITORY_ROOT}/scripts/install-release.sh" "${archive_root}/install-release.sh"
install -m 0644 "${REPOSITORY_ROOT}/package.json" "${app_root}/package.json"
install -m 0644 "${REPOSITORY_ROOT}/package-lock.json" "${app_root}/package-lock.json"
install -m 0644 "${REPOSITORY_ROOT}/README.md" "${app_root}/README.md"
install -m 0644 "${REPOSITORY_ROOT}/LICENSE" "${app_root}/LICENSE"
printf '%s\n' "${VERSION}" >"${archive_root}/payload/VERSION"

find "${archive_root}" -type d -exec chmod 0755 {} +
find "${archive_root}" -type f -exec chmod go-w {} +
find "${app_root}/scripts" -maxdepth 1 -type f -name '*.sh' -exec chmod 0755 {} +
find "${app_root}/bin" -maxdepth 1 -type f -exec chmod 0755 {} +

archive_name="ops-agent-linux-${ARCH}.tar.gz"
tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
  -czf "${OUTPUT_DIR}/${archive_name}" -C "${archive_root}" .

deb_root="${work_dir}/deb"
deb_payload_root="${deb_root}/usr/lib/ops-agent-payload/${VERSION}"
install -d -m 0755 "${deb_root}/DEBIAN" "${deb_payload_root}" "${deb_root}/usr/sbin"
cp -a "${archive_root}/." "${deb_payload_root}/"

cat >"${deb_root}/DEBIAN/control" <<EOF
Package: ops-agent-all
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: Pi Ops Agent maintainers
Depends: bash, ca-certificates, systemd, bubblewrap, openssl, diffutils
Section: admin
Priority: optional
Description: Least-privilege Pi operations agent native release payload
 Installs a verified, prebuilt payload. Run ops-agent-bootstrap init after dpkg.
EOF

cat >"${deb_root}/usr/sbin/ops-agent-bootstrap" <<EOF
#!/usr/bin/env bash
set -euo pipefail
readonly payload="/usr/lib/ops-agent-payload/${VERSION}/payload"
export OPS_AGENT_PAYLOAD_DIR="\${payload}"
exec "/usr/lib/ops-agent-payload/${VERSION}/install-release.sh" "\$@"
EOF
chmod 0755 "${deb_root}/usr/sbin/ops-agent-bootstrap"

cat >"${deb_root}/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
printf '%s\n' \
  'Pi Ops Agent payload installed but not initialized.' \
  'Run: sudo ops-agent-bootstrap init --admin-user <non-root-user>'
exit 0
EOF
chmod 0755 "${deb_root}/DEBIAN/postinst"

dpkg-deb --root-owner-group --build "${deb_root}" \
  "${OUTPUT_DIR}/ops-agent-all_${VERSION}_${ARCH}.deb"

printf 'Built %s and ops-agent-all_%s_%s.deb\n' \
  "${OUTPUT_DIR}/${archive_name}" "${VERSION}" "${ARCH}"
