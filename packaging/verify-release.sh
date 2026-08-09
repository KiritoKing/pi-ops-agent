#!/usr/bin/env bash
set -euo pipefail

VERSION=""
ARCH=""
NODE_VERSION=""
ARCHIVE=""
DEBIAN_PACKAGE=""
NO_PAYLOAD_EXECUTION=false

usage() {
  cat <<'EOF'
Usage: packaging/verify-release.sh \
  --version 1.2.3 --arch amd64|arm64 --node-version 22.0.0 \
  --archive PATH --deb PATH [--no-payload-execution]

Verifies that the native archive and Debian package contain the same complete
release payload, that all shipped Go commands are static binaries for the
declared architecture, and that the pinned Node runtime can load the compiled
entrypoints. By default the verifier requires a native host and executes the
bundled runtime smoke tests. --no-payload-execution keeps all structural,
parity, ELF, manifest and host-Node syntax checks without executing downloaded
payload code; a native build job must already have completed the default full
verification before this mode is used by a privileged publisher. This command
is Linux-only and does not mutate the host.
EOF
}

while (($# > 0)); do
  case "$1" in
    --version) VERSION="${2:-}"; shift 2 ;;
    --arch) ARCH="${2:-}"; shift 2 ;;
    --node-version) NODE_VERSION="${2:-}"; shift 2 ;;
    --archive) ARCHIVE="${2:-}"; shift 2 ;;
    --deb) DEBIAN_PACKAGE="${2:-}"; shift 2 ;;
    --no-payload-execution) NO_PAYLOAD_EXECUTION=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'Unknown argument: %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ ! "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  printf 'Invalid --version: %s\n' "${VERSION}" >&2
  exit 2
fi
if [[ ! "${NODE_VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  printf 'Invalid --node-version: %s\n' "${NODE_VERSION}" >&2
  exit 2
fi
case "${ARCH}" in
  amd64) expected_machine='Advanced Micro Devices X86-64' ;;
  arm64) expected_machine='AArch64' ;;
  *) printf 'Invalid --arch: %s\n' "${ARCH}" >&2; exit 2 ;;
esac

for command_name in tar dpkg-deb diff find readelf grep cmp mktemp mkdir uname; do
  command -v "${command_name}" >/dev/null 2>&1 || {
    printf 'Missing release verification dependency: %s\n' "${command_name}" >&2
    exit 1
  }
done
for input_path in "${ARCHIVE}" "${DEBIAN_PACKAGE}"; do
  [[ -n "${input_path}" && -f "${input_path}" && ! -L "${input_path}" ]] || {
    printf 'Release input is not a regular non-symlink file: %s\n' "${input_path}" >&2
    exit 1
  }
done

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/ops-agent-release-verify.XXXXXX")"
cleanup() {
  find "${work_dir}" -mindepth 1 -depth -delete 2>/dev/null || true
  rmdir "${work_dir}" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

archive_root="${work_dir}/archive"
deb_root="${work_dir}/deb"
mkdir -p "${archive_root}" "${deb_root}"
tar -xzf "${ARCHIVE}" -C "${archive_root}"
dpkg-deb -x "${DEBIAN_PACKAGE}" "${deb_root}"

app_root="${archive_root}/payload/app"
deb_payload_root="${deb_root}/usr/lib/ops-agent-payload/${VERSION}"
[[ -d "${app_root}" && ! -L "${app_root}" ]] || {
  printf 'Archive has no real payload/app directory.\n' >&2
  exit 1
}
[[ -d "${deb_payload_root}" && ! -L "${deb_payload_root}" ]] || {
  printf 'Debian package has no versioned payload directory.\n' >&2
  exit 1
}
diff --brief --recursive --no-dereference "${archive_root}" "${deb_payload_root}" >/dev/null || {
  printf 'Debian and native archive payloads differ.\n' >&2
  exit 1
}

[[ "$(dpkg-deb -f "${DEBIAN_PACKAGE}" Package)" == ops-agent-all ]] || {
  printf 'Debian package name is not ops-agent-all.\n' >&2
  exit 1
}
[[ "$(dpkg-deb -f "${DEBIAN_PACKAGE}" Version)" == "${VERSION}" ]] || {
  printf 'Debian package version does not match the release.\n' >&2
  exit 1
}
[[ "$(dpkg-deb -f "${DEBIAN_PACKAGE}" Architecture)" == "${ARCH}" ]] || {
  printf 'Debian package architecture does not match the release.\n' >&2
  exit 1
}
[[ -x "${deb_root}/usr/sbin/ops-agent-bootstrap" ]] || {
  printf 'Debian package is missing its executable bootstrap.\n' >&2
  exit 1
}

[[ "$(<"${archive_root}/payload/VERSION")" == "${VERSION}" ]] || {
  printf 'Archive VERSION does not match the release.\n' >&2
  exit 1
}
cmp -s "${archive_root}/install-release.sh" "${app_root}/scripts/install-release.sh" || {
  printf 'Outer and installed release installers differ.\n' >&2
  exit 1
}

required_files=(
  config/agentd.json
  config/models.json
  dist/agentd/index.js
  dist/client/index.js
  dist/reviewer/index.js
  dist/runtime/adapter-run.js
  dist/runtime/botmux-setup-run.js
  dist/runtime/workload-host.js
  dist/shared/bubblewrap-containment.js
  plugins/adapter-tui/manifest.json
  plugins/adapter-tui/profile.json
  plugins/adapter-botmux-source/manifest.json
  plugins/adapter-botmux-source/adapter.mjs
  plugins/workload-base/manifest.json
  plugins/workload-base/workload.mjs
  plugins/workload-botmux-ops/manifest.json
  plugins/workload-botmux-ops/workload.mjs
  plugins/workload-hermes-ops/manifest.json
  plugins/workload-hermes-ops/workload.mjs
  plugins/workload-pve/manifest.json
  plugins/workload-pve/workload.mjs
  plugins/workload-example/manifest.json
  plugins/workload-example/workload.mjs
  scripts/probe-adapter-linux-client.mjs
  scripts/probe-adapter-linux-fixture.mjs
  scripts/probe-adapter-linux-runtime.mjs
  scripts/probe-adapter-linux-socket.mjs
  skills/agentd-init/SKILL.md
  skills/agentd-init/agents/openai.yaml
  skills/agentd-adapter-dev/SKILL.md
  skills/agentd-adapter-dev/agents/openai.yaml
  skills/agentd-workload-dev/SKILL.md
  skills/agentd-workload-dev/agents/openai.yaml
  systemd/agentd-guardian.service
  systemd/agentd-guardian.service.d/zzzz-ops-agent-security.conf
  systemd/agentd-client-gateway.service
  systemd/agentd-client-gateway.service.d/zzzz-ops-agent-security.conf
  systemd/agentd-approval-reviewer.service
  systemd/agentd-approval-reviewer.service.d/zzzz-ops-agent-security.conf
  systemd/agentd-plugin-lease-broker.service
  systemd/agentd-plugin-lease-broker.service.d/zzzz-ops-agent-security.conf
  systemd/ops-agent-server.service
  systemd/ops-agent-server.service.d/zzzz-ops-agent-security.conf
  systemd/ops-agentd.service
  systemd/ops-agentd.service.d/zzzz-ops-agent-security.conf
  systemd/ops-root-helper.service
  systemd/ops-root-helper.service.d/zzzz-ops-agent-security.conf
  systemd/ops-agent-healthcheck.service
  systemd/ops-agent-healthcheck.service.d/zzzz-ops-agent-security.conf
  systemd/ops-agent-healthcheck.timer
  systemd/ops-agent.target
  systemd/ops-agent.tmpfiles.conf
  systemd/ops-pve-root-helper.service
  systemd/ops-pve-root-helper.service.d/zzzz-ops-agent-security.conf
  systemd/ops-agent-endpoint.tmpfiles.conf
  docs/architecture.md
  docs/security-model.md
  docs/deployment.md
  docs/operations.md
  docs/plugins.md
  docs/adapters.md
  docs/workloads/pve.md
)
for relative_path in "${required_files[@]}"; do
  [[ -f "${app_root}/${relative_path}" && ! -L "${app_root}/${relative_path}" ]] || {
    printf 'Release payload is missing a required regular file: %s\n' "${relative_path}" >&2
    exit 1
  }
done

unit_grants_read_write_path() {
  local unit_path="$1"
  local expected_path="$2"
  local line=""
  local token=""
  while IFS= read -r line; do
    [[ "${line}" == ReadWritePaths=* ]] || continue
    line="${line#ReadWritePaths=}"
    for token in ${line}; do
      [[ "${token}" == "${expected_path}" ]] && return 0
    done
  done <"${unit_path}"
  return 1
}

pve_broker_unit="${app_root}/systemd/ops-pve-root-helper.service"
pve_broker_dropin="${app_root}/systemd/ops-pve-root-helper.service.d/zzzz-ops-agent-security.conf"
for pve_broker_surface in "${pve_broker_unit}" "${pve_broker_dropin}"; do
  grep -Fxq 'ProtectSystem=full' "${pve_broker_surface}" || {
    printf 'Release PVE broker must retain ProtectSystem=full: %s.\n' \
      "${pve_broker_surface}" >&2
    exit 1
  }
  unit_grants_read_write_path "${pve_broker_surface}" /etc/pve || {
    printf 'Release PVE broker is missing the exact /etc/pve pmxcfs write exception: %s.\n' \
      "${pve_broker_surface}" >&2
    exit 1
  }
  while IFS= read -r read_write_path; do
    case "${read_write_path}" in
      /etc/pve) ;;
      /etc|/etc/*)
        printf 'Release PVE broker opens a wider /etc path: %s\n' "${read_write_path}" >&2
        exit 1
        ;;
    esac
  done < <(awk '/^ReadWritePaths=/ { sub(/^ReadWritePaths=/, ""); for (field = 1; field <= NF; field++) print $field }' "${pve_broker_surface}")
done
core_broker_unit="${app_root}/systemd/ops-root-helper.service"
grep -Eq '(^InaccessiblePaths=|[[:space:]])-/etc/pve([[:space:]]|$)' "${core_broker_unit}" || {
  printf 'Release core broker must keep /etc/pve inaccessible.\n' >&2
  exit 1
}
for isolated_unit in \
    "${app_root}/systemd/ops-agent-server.service" \
    "${app_root}/systemd/ops-agent-server.service.d/zzzz-ops-agent-security.conf" \
    "${app_root}/systemd/ops-agentd.service" \
    "${app_root}/systemd/ops-agentd.service.d/zzzz-ops-agent-security.conf"; do
  grep -Eq '(^InaccessiblePaths=|[[:space:]])-/etc/pve([[:space:]]|$)' "${isolated_unit}" || {
    printf 'Release non-PVE runtime must keep /etc/pve inaccessible: %s\n' "${isolated_unit}" >&2
    exit 1
  }
done
while IFS= read -r other_unit; do
  if [[ "${other_unit}" == "${pve_broker_unit}" \
      || "${other_unit}" == "${pve_broker_dropin}" ]]; then
    continue
  fi
  if unit_grants_read_write_path "${other_unit}" /etc/pve; then
    printf 'Only the PVE broker may receive the /etc/pve write exception: %s\n' "${other_unit}" >&2
    exit 1
  fi
done < <(find "${app_root}/systemd" -type f -print)

required_executables=(
  bin/ops-agent
  bin/ops-agent-server
  bin/ops-root-helper
  bin/agentd-guardian
  bin/agentd-client-gateway
  bin/agentd-pluginctl
  bin/agentd-approval-submit
  bin/agentd-json-config-helper
  runtime/node
  scripts/healthcheck.sh
  scripts/install-release.sh
  scripts/probe-adapter-linux-runtime.sh
  scripts/setup-botmux.sh
  scripts/uninstall.sh
)
for relative_path in "${required_executables[@]}"; do
  [[ -f "${app_root}/${relative_path}" && ! -L "${app_root}/${relative_path}" \
      && -x "${app_root}/${relative_path}" ]] || {
    printf 'Release payload is missing a required executable: %s\n' "${relative_path}" >&2
    exit 1
  }
done

if find "${archive_root}" -type f -name '._*' -print -quit | grep -q .; then
  printf 'Release archive contains forbidden AppleDouble metadata.\n' >&2
  exit 1
fi
for retired_path in \
    "${app_root}/bin/ops-systemd-helper" \
    "${app_root}/systemd/ops-systemd-helper.service" \
    "${app_root}/systemd/ops-systemd-helper.service.d"; do
  [[ ! -e "${retired_path}" && ! -L "${retired_path}" ]] || {
    printf 'Release payload contains retired privileged artifact: %s\n' "${retired_path}" >&2
    exit 1
  }
done
for dev_path in \
    "${app_root}/node_modules/typescript" \
    "${app_root}/node_modules/vitest" \
    "${app_root}/node_modules/eslint"; do
  [[ ! -e "${dev_path}" && ! -L "${dev_path}" ]] || {
    printf 'Release payload contains a pruned development dependency: %s\n' "${dev_path}" >&2
    exit 1
  }
done

node_runtime="${app_root}/runtime/node"
case "$(uname -m)" in
  x86_64) host_arch=amd64 ;;
  aarch64|arm64) host_arch=arm64 ;;
  *) host_arch=unknown ;;
esac
javascript_runtime="${node_runtime}"
runtime_execution_skipped=false
if [[ "${NO_PAYLOAD_EXECUTION}" == true ]]; then
  javascript_runtime="$(command -v node || true)"
  [[ -n "${javascript_runtime}" && -x "${javascript_runtime}" ]] || {
    printf 'Non-executing publish verification requires a host Node runtime for JavaScript syntax checks.\n' >&2
    exit 1
  }
  runtime_execution_skipped=true
else
  if [[ "${host_arch}" != "${ARCH}" ]]; then
    printf 'Refusing to execute %s payload on %s host; use the matching native runner.\n' \
      "${ARCH}" "${host_arch}" >&2
    exit 1
  fi
  [[ "$("${node_runtime}" -p 'process.versions.node')" == "${NODE_VERSION}" ]] || {
    printf 'Bundled Node runtime does not match the pinned release version.\n' >&2
    exit 1
  }
fi
"${javascript_runtime}" - "${app_root}" "${VERSION}" <<'NODE'
const fs = require("node:fs");
const path = require("node:path");
const appRoot = process.argv[2];
const expectedVersion = process.argv[3];
const packageDocument = JSON.parse(fs.readFileSync(path.join(appRoot, "package.json"), "utf8"));
const lockDocument = JSON.parse(fs.readFileSync(path.join(appRoot, "package-lock.json"), "utf8"));
if (packageDocument.version !== expectedVersion || lockDocument.packages?.[""]?.version !== expectedVersion) {
  throw new Error("package and lockfile versions do not match the release");
}
for (const directory of fs.readdirSync(path.join(appRoot, "plugins"), { withFileTypes: true })) {
  if (!directory.isDirectory()) continue;
  const manifestPath = path.join(appRoot, "plugins", directory.name, "manifest.json");
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  if (manifest.version !== expectedVersion) {
    throw new Error(`plugin manifest version mismatch: ${directory.name}`);
  }
}
NODE

while IFS= read -r -d '' javascript_path; do
  "${javascript_runtime}" --check "${javascript_path}" >/dev/null
done < <(find "${app_root}/dist" -type f -name '*.js' -print0)
if [[ "${runtime_execution_skipped}" != true ]]; then
  [[ "$("${javascript_runtime}" "${app_root}/dist/client/index.js" --version)" \
      == "pi-ops-agent ${VERSION}" ]] || {
    printf 'Compiled client version smoke failed under the bundled Node runtime.\n' >&2
    exit 1
  }
  "${javascript_runtime}" "${app_root}/dist/reviewer/index.js" </dev/null
fi

assert_elf_architecture() {
  local binary_path="$1"
  local elf_header
  elf_header="$(readelf -h "${binary_path}")"
  [[ "${elf_header}" == *"Machine:"*"${expected_machine}"* ]] || {
    printf 'ELF architecture mismatch: %s\n' "${binary_path}" >&2
    return 1
  }
}

assert_elf_architecture "${node_runtime}"
for binary_name in ops-agent-server ops-root-helper agentd-guardian agentd-client-gateway agentd-pluginctl agentd-approval-submit agentd-json-config-helper; do
  binary_path="${app_root}/bin/${binary_name}"
  assert_elf_architecture "${binary_path}"
  program_headers="$(readelf -l "${binary_path}")"
  if grep -Eq '(^|[[:space:]])INTERP([[:space:]]|$)' <<<"${program_headers}"; then
    printf 'Go release binary has a dynamic interpreter: %s\n' "${binary_name}" >&2
    exit 1
  fi
done

if [[ "${runtime_execution_skipped}" == true ]]; then
  printf 'Verified release %s for %s without executing downloaded payload code on %s; bundled Node %s execution was left to the completed native build verification.\n' \
    "${VERSION}" "${ARCH}" "${host_arch}" "${NODE_VERSION}"
else
  printf 'Verified release %s for %s with bundled Node %s.\n' \
    "${VERSION}" "${ARCH}" "${NODE_VERSION}"
fi
