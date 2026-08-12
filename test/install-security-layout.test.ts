import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readlinkSync,
  realpathSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

function repositoryFile(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

describe("installed client-plane isolation", () => {
  it("reasserts every managed service hardening directive in its final drop-in", () => {
    const lifecycleProperties = new Set([
      "Type", "User", "Group", "WorkingDirectory", "Environment", "EnvironmentFile",
      "LoadCredentialEncrypted", "ExecStart", "Restart", "RestartSec", "TimeoutStopSec",
      "TasksMax", "LimitNOFILE", "MemoryMax", "UMask", "SuccessExitStatus",
    ]);
    const serviceLines = (source: string): string[] => {
      let inService = false;
      const lines: string[] = [];
      for (const line of source.split("\n")) {
        if (line === "[Service]") {
          inService = true;
          continue;
        }
        if (/^\[[^\]]+\]$/u.test(line)) {
          inService = false;
          continue;
        }
        if (!inService || !/^[A-Za-z][A-Za-z0-9]*=/u.test(line)) continue;
        lines.push(line);
      }
      return lines;
    };

    for (const unit of [
      "agentd-approval-reviewer",
      "agentd-client-gateway",
      "agentd-guardian",
      "agentd-plugin-lease-broker",
      "ops-agentd",
      "ops-agent-server",
      "ops-root-helper",
      "ops-agent-healthcheck",
      "ops-pve-root-helper",
    ]) {
      const baseLines = serviceLines(repositoryFile(`systemd/${unit}.service`));
      const finalLines = new Set(serviceLines(repositoryFile(
        `systemd/${unit}.service.d/zzzz-ops-agent-security.conf`,
      )));
      for (const line of baseLines) {
        const property = line.slice(0, line.indexOf("="));
        if (lifecycleProperties.has(property)) continue;
        expect(finalLines.has(line), `${unit} final policy omitted ${line}`).toBe(true);
      }
    }
  });

  it("closes typed PID 1 policy and unknown service drop-in authority", () => {
    const installer = repositoryFile("scripts/install-release.sh");
    const busPathStart = installer.indexOf("installed_unit_bus_path() {");
    const busPathEnd = installer.indexOf("installed_unit_bus_property() {", busPathStart);
    const typedVerifierStart = installer.indexOf("verify_installed_unit_typed_vectors() {");
    const hostVerifierStart = installer.indexOf("verify_allowed_host_service_dropin() {");
    const hostVerifierEnd = installer.indexOf(
      "verify_installed_unit_dropin_closure() {",
      hostVerifierStart,
    );
    expect(busPathStart).toBeGreaterThanOrEqual(0);
    expect(busPathEnd).toBeGreaterThan(busPathStart);
    expect(typedVerifierStart).toBeGreaterThan(busPathEnd);
    expect(hostVerifierStart).toBeGreaterThan(typedVerifierStart);
    expect(hostVerifierEnd).toBeGreaterThan(hostVerifierStart);
    const busPathVerifier = installer.slice(busPathStart, busPathEnd);
    const typedVerifier = installer.slice(typedVerifierStart, hostVerifierStart);
    const hostVerifier = installer.slice(hostVerifierStart, hostVerifierEnd);

    expect(installer).toContain("required_commands=(systemctl systemd-tmpfiles busctl");
    expect(busPathVerifier).toContain("org.freedesktop.systemd1.Manager LoadUnit");
    expect(busPathVerifier).not.toContain("org.freedesktop.systemd1.Manager GetUnit");
    expect(installer).toContain("verify_installed_unit_typed_vectors \\");
    expect(installer).toContain(
      '"${unit}" "${UNIT_ROOT}/${unit}" "${dropin}" "${credential_dropin}"',
    );
    for (const property of [
      "Conditions",
      "Asserts",
      "LoadCredential",
      "LoadCredentialEncrypted",
      "SetCredential",
      "SetCredentialEncrypted",
      "ImportCredential",
    ]) {
      expect(typedVerifier).toContain(property);
    }
    for (const signature of ['"a(sbbsi)"', '"a(ss)"', '"a(say)"', '"as"']) {
      expect(typedVerifier).toContain(signature);
    }
    expect(installer).toContain(
      'require_installed_unit_word_set "${unit}" SuccessExitStatus "${expected}"',
    );
    expect(installer).toContain(
      'credential_dropin="${dropin_dir}/zzzz-ops-agent-credential.conf"',
    );
    expect(installer).toContain(
      "LoadCredentialEncrypted=deepseek_api_key:/etc/ops-agent/credentials/deepseek_api_key.cred",
    );
    expect(installer).toContain(
      'verify_installed_unit_dropin_closure "${unit}" "${dropin}" "${credential_dropin}"',
    );
    expect(installer).toContain('read -r -a paths <<<"${raw}"');
    expect(installer).toContain('for path in "${paths[@]}"; do');
    expect(installer).not.toContain(
      'for path in $(installed_unit_property "${unit}" DropInPaths)',
    );

    expect(hostVerifier).toContain("Host-wide service drop-in has unsafe metadata");
    expect(hostVerifier).toContain("NoNewPrivileges=no");
    expect(hostVerifier).toContain("ReadWritePaths=");
    expect(hostVerifier).toContain("SupplementaryGroups=");
    expect(hostVerifier).not.toContain("RootDirectory=");
    expect(hostVerifier).not.toContain("BindPaths=");
    expect(hostVerifier).not.toContain("BindReadOnlyPaths=");
    expect(hostVerifier).not.toContain("StateDirectory=");
    expect(hostVerifier).not.toContain("ConditionPathExists=");
    expect(hostVerifier).not.toContain("ExecStart=");
    expect(hostVerifier).not.toContain("Environment=");
    expect(hostVerifier).not.toContain("CapabilityBoundingSet=");
    expect(hostVerifier).not.toContain("LoadCredentialEncrypted=");
  });

  it("canonicalizes missing pre-v254 ImportCredential only with three exact proofs", () => {
    const installer = repositoryFile("scripts/install-release.sh");
    const compatibilityStart = installer.indexOf("installed_systemd_major_version() {");
    const compatibilityEnd = installer.indexOf(
      "require_installed_unit_apparmor_profile() {",
      compatibilityStart,
    );
    const closureStart = installer.indexOf("verify_installed_unit_dropin_closure() {");
    const closureEnd = installer.indexOf("require_installed_unit_property() {", closureStart);
    const typedStart = installer.indexOf("verify_installed_unit_typed_vectors() {");
    const typedEnd = installer.indexOf("verify_allowed_host_service_dropin() {", typedStart);
    const effectiveStart = installer.indexOf("verify_effective_security_dropin() {");
    const effectiveEnd = installer.indexOf("\nfor unit in ", effectiveStart);
    expect(compatibilityStart).toBeGreaterThanOrEqual(0);
    expect(compatibilityEnd).toBeGreaterThan(compatibilityStart);
    expect(closureStart).toBeGreaterThan(compatibilityEnd);
    expect(closureEnd).toBeGreaterThan(closureStart);
    expect(typedStart).toBeGreaterThan(compatibilityEnd);
    expect(typedEnd).toBeGreaterThan(typedStart);
    expect(effectiveStart).toBeGreaterThan(closureEnd);
    expect(effectiveEnd).toBeGreaterThan(effectiveStart);
    const compatibility = installer.slice(compatibilityStart, compatibilityEnd);
    const closure = installer.slice(closureStart, closureEnd);
    const typedFunction = installer.slice(typedStart, typedEnd);
    const effective = installer.slice(effectiveStart, effectiveEnd);

    expect(compatibility).toContain("org.freedesktop.systemd1.Manager Version");
    expect(compatibility).toContain('value?.type !== "s" || typeof value.data !== "string"');
    expect(compatibility).toContain("org.freedesktop.DBus.Introspectable Introspect");
    expect(compatibility).toContain("if ((10#${major} >= 254)); then");
    expect(compatibility).toContain("verify_no_import_credential_file_authority");
    expect(compatibility).toContain("verify_installed_unit_dropin_closure");
    expect(compatibility).toContain("printf '{\"type\":\"as\",\"data\":[]}'");
    expect(closure).toContain(
      'verify_no_import_credential_file_authority "${security_dropin}" || return 1',
    );
    expect(closure).toContain(
      'verify_no_import_credential_file_authority "${credential_dropin}" || return 1',
    );
    expect(closure).toContain(
      'raw="$(installed_unit_property "${unit}" DropInPaths)" || return 1',
    );
    expect(closure).toContain('verify_allowed_host_service_dropin "${path}" || return 1');
    expect(closure).toContain(
      'verify_no_import_credential_file_authority "${path}" || return 1',
    );
    expect(effective.indexOf("verify_installed_unit_dropin_closure")).toBeLessThan(
      effective.indexOf("verify_installed_unit_typed_vectors"),
    );

    const root = mkdtempSync(join(tmpdir(), "ops-agent-systemd-compat-"));
    try {
      mkdirSync(join(root, "runtime"));
      symlinkSync(process.execPath, join(root, "runtime", "node"));
      const safeUnit = join(root, "safe.service");
      const emptyReset = join(root, "empty-reset.conf");
      const nonempty = join(root, "nonempty.conf");
      const continuation = join(root, "continuation.conf");
      writeFileSync(safeUnit, "[Service]\nExecStart=/bin/true\n", "utf8");
      writeFileSync(emptyReset, "[Service]\nImportCredential=\n", "utf8");
      writeFileSync(nonempty, "[Service]\nImportCredential=host.*\n", "utf8");
      writeFileSync(continuation, "[Service]\nImportCrede\\\nntial=host.*\n", "utf8");
      const absentXml = [
        "<node>",
        '<interface name="org.freedesktop.systemd1.Service">',
        '<property name="LoadCredential" type="a(ss)" access="read"/>',
        '<property name="LoadCredentialEncrypted" type="a(ss)" access="read"/>',
        '<property name="SetCredential" type="a(say)" access="read"/>',
        '<property name="SetCredentialEncrypted" type="a(say)" access="read"/>',
        "</interface>",
        "</node>",
      ].join("");
      const presentXml = absentXml.replace(
        "</interface>",
        '<property name="ImportCredential" type="as" access="read"/></interface>',
      );
      const serviceInterface = absentXml.slice("<node>".length, -"</node>".length);
      const duplicateInterfaceXml = `<node>${serviceInterface}${serviceInterface}</node>`;
      const wrongTypeDuplicateXml = absentXml.replace(
        "</interface>",
        '<property name="LoadCredential" type="as" access="read"/></interface>',
      );
      const commentAnchorXml = [
        "<node>",
        '<interface name="org.freedesktop.systemd1.Service">',
        "<!-- LoadCredential LoadCredentialEncrypted SetCredential SetCredentialEncrypted -->",
        "</interface>",
        "</node>",
      ].join("");
      const script = [
        "set -euo pipefail",
        `release_dir=${JSON.stringify(root)}`,
        compatibility,
        closure,
        typedFunction,
        "installed_unit_bus_property() {",
        "  if [[ ${VECTOR_MODE:-0} == 1 ]]; then",
        "    case \"$3\" in",
        "      Conditions|Asserts) printf '%s' '{\"type\":\"a(sbbsi)\",\"data\":[]}' ; return 0 ;;",
        "      LoadCredential|LoadCredentialEncrypted) printf '%s' '{\"type\":\"a(ss)\",\"data\":[]}' ; return 0 ;;",
        "      SetCredential|SetCredentialEncrypted) printf '%s' '{\"type\":\"a(say)\",\"data\":[]}' ; return 0 ;;",
        "    esac",
        "  fi",
        "  if [[ ${IMPORT_MODE} == success ]]; then printf '%s' \"${IMPORT_PAYLOAD}\"; return 0; fi",
        "  printf '%s' 'simulated bus failure' >&2",
        "  return 23",
        "}",
        "busctl() {",
        "  case \"$*\" in",
        "    *'Manager Version') printf '%s' \"${VERSION_PAYLOAD}\" ; return ${VERSION_STATUS:-0} ;;",
        "    *'Introspect') printf '%s' \"${INTROSPECT_PAYLOAD}\" ; return ${INTROSPECT_STATUS:-0} ;;",
        "  esac",
        "  return 97",
        "}",
        "installed_unit_property() { printf '%s' \"${DROPIN_PATHS}\"; return ${DROPIN_STATUS:-0}; }",
        "installed_unit_bus_path() { printf '%s' /unit; }",
        "verify_allowed_host_service_dropin() { [[ ${HOST_OK} == 1 ]]; }",
        "call_import() {",
        "  installed_unit_import_credential_property test.service /unit \"$1\" \"$2\" \"${3:-}\"",
        "}",
        "expect_failure() {",
        "  local status",
        "  set +e",
        "  \"$@\" >/dev/null 2>&1",
        "  status=$?",
        "  set -e",
        "  ((status != 0))",
        "}",
        "IMPORT_MODE=success",
        "IMPORT_PAYLOAD='{" + "\"type\":\"as\",\"data\":[]}" + "'",
        "VERSION_PAYLOAD=invalid",
        "INTROSPECT_PAYLOAD=invalid",
        "DROPIN_PATHS=\"$2\"",
        "DROPIN_STATUS=0",
        "HOST_OK=1",
        "[[ $(call_import \"$1\" \"$2\") == \"${IMPORT_PAYLOAD}\" ]]",
        "IMPORT_MODE=fail",
        "VERSION_PAYLOAD=\"$5\"",
        "INTROSPECT_PAYLOAD=\"$6\"",
        "[[ $(call_import \"$1\" \"$2\") == '{\"type\":\"as\",\"data\":[]}' ]]",
        "VERSION_PAYLOAD=\"$7\"",
        "expect_failure call_import \"$1\" \"$2\"",
        "VERSION_PAYLOAD=\"$8\"",
        "expect_failure call_import \"$1\" \"$2\"",
        "VERSION_PAYLOAD=\"${12}\"",
        "expect_failure call_import \"$1\" \"$2\"",
        "VERSION_PAYLOAD=\"${13}\"",
        "expect_failure call_import \"$1\" \"$2\"",
        "VERSION_PAYLOAD=\"$5\"",
        "INTROSPECT_PAYLOAD=\"$9\"",
        "expect_failure call_import \"$1\" \"$2\"",
        "INTROSPECT_PAYLOAD=\"${10}\"",
        "expect_failure call_import \"$1\" \"$2\"",
        "INTROSPECT_PAYLOAD=\"${11}\"",
        "expect_failure call_import \"$1\" \"$2\"",
        "INTROSPECT_PAYLOAD=\"${14}\"",
        "expect_failure call_import \"$1\" \"$2\"",
        "INTROSPECT_PAYLOAD=\"${15}\"",
        "expect_failure call_import \"$1\" \"$2\"",
        "INTROSPECT_PAYLOAD=\"$6\"",
        "expect_failure call_import \"$3\" \"$2\"",
        "expect_failure call_import \"$1\" \"$3\"",
        "expect_failure call_import \"$1\" \"$2\" \"$3\"",
        "expect_failure call_import \"$1\" \"$4\"",
        "DROPIN_STATUS=7",
        "expect_failure call_import \"$1\" \"$2\"",
        "DROPIN_STATUS=0",
        "DROPIN_PATHS=\"$2 /run/systemd/system/service.d/test.conf\"",
        "HOST_OK=0",
        "expect_failure call_import \"$1\" \"$2\"",
        "HOST_OK=1",
        "expect_failure call_import \"$1\" \"$2\"",
        "DROPIN_PATHS=\"$2\"",
        "VERSION_STATUS=7",
        "expect_failure call_import \"$1\" \"$2\"",
        "VERSION_STATUS=0",
        "INTROSPECT_STATUS=7",
        "expect_failure call_import \"$1\" \"$2\"",
        "INTROSPECT_STATUS=0",
        "VECTOR_MODE=1",
        "IMPORT_MODE=success",
        "IMPORT_PAYLOAD='{\"type\":\"as\",\"data\":[]}'",
        "verify_installed_unit_typed_vectors test.service \"$1\" \"$2\" ''",
        "IMPORT_PAYLOAD='{\"type\":\"as\",\"data\":[\"unexpected\"]}'",
        "expect_failure verify_installed_unit_typed_vectors test.service \"$1\" \"$2\" ''",
        "IMPORT_PAYLOAD='{\"type\":\"a(ss)\",\"data\":[]}'",
        "expect_failure verify_installed_unit_typed_vectors test.service \"$1\" \"$2\" ''",
        "VECTOR_MODE=0",
        "verify_no_import_credential_file_authority \"$2\"",
        "expect_failure verify_no_import_credential_file_authority \"$3\"",
        "expect_failure verify_no_import_credential_file_authority \"$4\"",
      ].join("\n");
      const verification = spawnSync(
        "/bin/bash",
        [
          "-c",
          script,
          "--",
          safeUnit,
          emptyReset,
          nonempty,
          continuation,
          JSON.stringify({ type: "s", data: "252.39-1~deb12u2" }),
          JSON.stringify({ type: "s", data: [absentXml] }),
          JSON.stringify({ type: "s", data: "254.1-1" }),
          JSON.stringify({ type: "s", data: ["252.39-1"] }),
          JSON.stringify({ type: "s", data: [presentXml] }),
          JSON.stringify({ type: "s", data: absentXml }),
          JSON.stringify({ type: "s", data: [commentAnchorXml] }),
          JSON.stringify({ type: "s", data: "0252.39-1" }),
          JSON.stringify({ type: "s", data: "252evil" }),
          JSON.stringify({ type: "s", data: [duplicateInterfaceXml] }),
          JSON.stringify({ type: "s", data: [wrongTypeDuplicateXml] }),
        ],
        { encoding: "utf8" },
      );
      expect(verification.status, `${verification.stdout}${verification.stderr}`).toBe(0);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("keeps service, BotMux, and administrator identities out of the service group", () => {
    const installer = repositoryFile("scripts/install-release.sh");
    const botmuxSetup = repositoryFile("scripts/setup-botmux.sh");
    const botmuxDropIn = repositoryFile("config/botmux-systemd-dropin.conf");

    expect(installer).toContain('readonly CLIENT_GROUP="ops-agent-client"');
    expect(installer).toContain('usermod --groups "${CLIENT_GROUP}" "${SERVICE_USER}"');
    expect(installer).toContain('usermod --groups "${CLIENT_GROUP}" "${BOTMUX_USER}"');
    expect(installer).toContain(
      'usermod --append --groups "${CLIENT_GROUP},${REVIEWER_GROUP}" "${ADMIN_USER}"',
    );
    expect(installer).toContain(
      'for forbidden_group in "${SERVICE_GROUP}" "${SERVER_GROUP}" "${BOTMUX_GROUP}" "${LEASE_GROUP}"; do',
    );
    expect(botmuxSetup).toContain('readonly CLIENT_GROUP="ops-agent-client"');
    expect(botmuxDropIn).toContain("SupplementaryGroups=ops-agent-client");
    expect(botmuxDropIn).not.toContain("SupplementaryGroups=ops-agent\n");
  });

  it("binds local TUI approval to one immutable administrator enrollment", () => {
    const installer = repositoryFile("scripts/install-release.sh");
    const identity = repositoryFile("src/shared/local-administrator.ts");
    const authorization = repositoryFile("src/client/adapter-authorization.ts");

    expect(installer).toContain('if [[ "${ADMIN_USER}" == ops-agent* ]]');
    expect(installer).toContain('[[ "${ADMIN_USER}" == ops-adapter-* ]]');
    expect(installer).toContain('administrator_identity="${CONFIG_ROOT}/local-administrator.json"');
    expect(installer).toContain('Object.keys(value).sort().join(",") !== "uid,username,version"');
    expect(installer).toContain('value.uid !== Number(expectedUidText)');
    expect(installer).toContain('value.username !== expectedUsername');
    expect(installer).toContain("Ordinary upgrades cannot rotate the approval principal");
    expect(installer).toContain("root:${CLIENT_GROUP}:640:1");
    expect(identity).toContain(
      'ENROLLED_LOCAL_ADMINISTRATOR_PATH = "/etc/ops-agent/local-administrator.json"',
    );
    expect(identity).toContain("constants.O_RDONLY | constants.O_NOFOLLOW");
    expect(identity).toContain("info.uid !== expectedOwnerUid");
    expect(identity).toContain("info.nlink !== 1");
    expect(authorization).toContain('username.startsWith("ops-adapter-")');
    expect(authorization).toContain("options.effectiveUid !== enrolled.uid");
    expect(authorization).toContain("options.username !== enrolled.username");
    expect(installer).toContain('runtimeIdentity: adapterIdentity(value.manifest.id)');
    expect(installer).toContain('filesystem: "host-as-runtime-uid"');
    expect(installer).toContain('network: "host"');
    expect(installer).toContain('credentials: "runtime-uid-readable"');
    expect(installer).toContain(
      'actionScopeEnforcement: "digest-review-and-typed-ipc-contract"',
    );
    expect(installer).toContain(
      '"full-runtime-uid-authority;not-os-action-sandboxed"',
    );
  });

  it("probes PASSWD enforcement with every real approval argv shape", () => {
    const installer = repositoryFile("scripts/install-release.sh");

    expect(installer).toContain("probe_requires_password()");
    expect(installer).toContain("for action in approve reject rollback; do");
    expect(installer).toContain("for change_prefix in change pve-change; do");
    expect(installer).toContain('--action "${action}"');
    expect(installer).toContain("--server-id sudo-policy-probe-server");
    expect(installer).toContain("--machine-id sudo-policy-probe-machine");
    expect(installer).toContain("--target-id sudo-policy-probe-target");
    expect(installer).toContain('--change-id "${change_prefix}-sudo-policy-probe"');
    expect(installer).toContain("--user-intent-b64 c3Vkby1wb2xpY3ktcHJvYmU");
    expect(installer).toContain("grep -F 'NOPASSWD:'");
    expect(installer).toContain(
      "probe_requires_password setup-botmux /usr/libexec/pi-ops-agent/setup-botmux",
    );
  });

  it("accepts only bounded canonical BotMux no-sudo results across sudo 1.9 wrapping", () => {
    const installer = repositoryFile("scripts/install-release.sh");
    const verifierStart = installer.indexOf("verify_botmux_no_sudo_result() {");
    const verifierEnd = installer.indexOf("verify_effective_sudo_policy() {", verifierStart);
    const policyEnd = installer.indexOf("secure_registered_approver_material() {", verifierEnd);
    expect(verifierStart).toBeGreaterThanOrEqual(0);
    expect(verifierEnd).toBeGreaterThan(verifierStart);
    expect(policyEnd).toBeGreaterThan(verifierEnd);
    const verifier = installer.slice(verifierStart, verifierEnd);
    const policyProbe = installer.slice(verifierEnd, policyEnd);
    expect(policyProbe).toContain(
      'if LC_ALL=C /usr/bin/sudo -U "${BOTMUX_USER}" -l >"${botmux_policy}" 2>&1; then',
    );
    expect(policyProbe).toContain("botmux_status=$?");
    expect(policyProbe).toContain(
      'verify_botmux_no_sudo_result "${botmux_policy}" "${botmux_status}"',
    );
    expect(policyProbe).not.toContain(
      'LC_ALL=C /usr/bin/sudo -U "${BOTMUX_USER}" -l >"${botmux_policy}" 2>&1 || true',
    );

    const root = mkdtempSync(join(tmpdir(), "ops-agent-sudo-policy-"));
    try {
      mkdirSync(join(root, "runtime"));
      symlinkSync(process.execPath, join(root, "runtime", "node"));
      const canonical = join(root, "canonical.log");
      const wrapped = join(root, "wrapped.log");
      const listing = join(root, "listing.log");
      const warning = join(root, "warning.log");
      const badHost = join(root, "bad-host.log");
      const carriageReturn = join(root, "carriage-return.log");
      const nul = join(root, "nul.log");
      const oversized = join(root, "oversized.log");
      const sentence = "User ops-agent-botmux is not allowed to run sudo on node-1.\n";
      writeFileSync(canonical, sentence, "utf8");
      writeFileSync(
        wrapped,
        "User ops-agent-botmux is not allowed to run sudo on\n" +
          "        opsagent-e2e-bookworm-controller.\n",
        "utf8",
      );
      writeFileSync(listing, sentence + "    (ALL : ALL) ALL\n", "utf8");
      writeFileSync(warning, "sudo: policy plugin warning\n" + sentence, "utf8");
      writeFileSync(
        badHost,
        "User ops-agent-botmux is not allowed to run sudo on bad_host.\n",
        "utf8",
      );
      writeFileSync(carriageReturn, sentence.replace("\n", "\r\n"), "utf8");
      writeFileSync(nul, Buffer.concat([Buffer.from(sentence), Buffer.from([0])]));
      writeFileSync(oversized, sentence.trimEnd() + " ".repeat(1100) + "\n", "utf8");

      const script = [
        "set -euo pipefail",
        `release_dir=${JSON.stringify(root)}`,
        "readonly BOTMUX_USER=ops-agent-botmux",
        verifier,
        "expect_failure() {",
        "  if verify_botmux_no_sudo_result \"$1\" \"$2\" >/dev/null 2>&1; then",
        "    return 1",
        "  fi",
        "}",
        "verify_botmux_no_sudo_result \"$1\" 0",
        "verify_botmux_no_sudo_result \"$2\" 0",
        "expect_failure \"$1\" 1",
        "expect_failure \"$1\" 2",
        "expect_failure \"$3\" 0",
        "expect_failure \"$4\" 0",
        "expect_failure \"$5\" 0",
        "expect_failure \"$6\" 0",
        "expect_failure \"$7\" 0",
        "expect_failure \"$8\" 0",
      ].join("\n");
      const verification = spawnSync(
        "/bin/bash",
        [
          "-c",
          script,
          "--",
          canonical,
          wrapped,
          listing,
          warning,
          badHost,
          carriageReturn,
          nul,
          oversized,
        ],
        { encoding: "utf8" },
      );
      expect(verification.status, `${verification.stdout}${verification.stderr}`).toBe(0);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("lets the isolated reviewer create only its runtime socket", () => {
    const reviewerUnit = repositoryFile("systemd/agentd-approval-reviewer.service");
    const writablePaths = reviewerUnit
      .split("\n")
      .filter((line) => line.startsWith("ReadWritePaths="))
      .flatMap((line) => line.slice("ReadWritePaths=".length).trim().split(/\s+/u));

    expect(reviewerUnit).toContain("ProtectSystem=strict");
    expect(writablePaths).toEqual(["/run/ops-agent/reviewer"]);
    expect(reviewerUnit).toContain(
      "--socket=/run/ops-agent/reviewer/reviewer.sock",
    );
  });

  it("uses a peer-authenticated dedicated lease broker instead of client-readable lock files", () => {
    const installer = repositoryFile("scripts/install-release.sh");
    const leaseUnit = repositoryFile("systemd/agentd-plugin-lease-broker.service");
    const tmpfiles = repositoryFile("systemd/ops-agent.tmpfiles.conf");
    const target = repositoryFile("systemd/ops-agent.target");
    const agentUnit = repositoryFile("systemd/ops-agentd.service");
    const command = repositoryFile("cmd/agentd-pluginctl/main.go");
    const healthcheck = repositoryFile("scripts/healthcheck.sh");

    expect(installer).toContain('readonly LEASE_USER="ops-agent-lease"');
    expect(installer).toContain('readonly LEASE_GROUP="ops-agent-lease"');
    expect(installer).toContain('usermod --groups "" "${LEASE_USER}"');
    expect(installer).toContain(
      'install -d -o root -g "${LEASE_GROUP}" -m 0750',
    );
    expect(installer).toContain(
      "chmod 00750 /var/lib/ops-agent/plugins/invocation-leases",
    );
    expect(installer).toContain(
      'LC_ALL=C /usr/bin/sudo -U "${BOTMUX_USER}" -l',
    );
    expect(installer).toContain("verify_botmux_no_sudo_result()");
    expect(installer).toContain("const maximumBytes = 1024");
    expect(installer).toContain('.replace(/[ \\t\\n]+/gu, " ")');
    expect(installer).not.toContain(
      'LC_ALL=C /usr/bin/sudo -U "${BOTMUX_USER}" -l >"${botmux_policy}" 2>&1 || true',
    );
    expect(installer).toContain('stat -c \'%h\' "${lease_path}"');
    expect(installer).toContain('chown root:"${LEASE_GROUP}" "${lease_path}"');
    expect(installer).toContain('chmod 0640 "${lease_path}"');
    expect(installer).toContain("Managed plugin path must be a real directory");
    expect(tmpfiles).toContain(
      "d /var/lib/ops-agent/plugins/invocation-leases 0750 root ops-agent-lease -",
    );
    expect(tmpfiles).toContain(
      "d /run/ops-agent/plugin-lease 2750 ops-agent-lease ops-agent-client -",
    );

    expect(leaseUnit).toContain("User=ops-agent-lease");
    expect(leaseUnit).toContain("Group=ops-agent-lease");
    expect(leaseUnit).toContain("SupplementaryGroups=ops-agent-client");
    expect(leaseUnit).toContain("NoNewPrivileges=yes");
    expect(leaseUnit).toContain("CapabilityBoundingSet=");
    expect(leaseUnit).toContain("RestrictAddressFamilies=AF_UNIX");
    expect(leaseUnit).toContain("ReadOnlyPaths=/opt/pi-ops-agent /var/lib/ops-agent/plugins");
    expect(leaseUnit).not.toContain("User=root");
    expect(leaseUnit).not.toContain("User=ops-agent-server");
    expect(command).toContain("pluginlease.FixedRegistryRoot");
    expect(command).toContain("pluginlease.FixedSocketPath");
    expect(command).not.toContain('flags.String("root", pluginlease.FixedRegistryRoot');
    expect(target).toContain("agentd-plugin-lease-broker.service");
    expect(agentUnit).toContain("Requires=agentd-approval-reviewer.service agentd-plugin-lease-broker.service");
    expect(healthcheck).toContain(
      "check_socket plugin-lease /run/ops-agent/plugin-lease/lease.sock ops-agent-lease ops-agent-client",
    );
  });

  it("holds the BotMux source digest lease across its complete privileged setup workflow", () => {
    const setup = repositoryFile("scripts/setup-botmux.sh");
    const runner = repositoryFile("src/runtime/botmux-setup-run.ts");
    const pluginDocs = repositoryFile("docs/plugins.md");
    const securityDocs = repositoryFile("docs/security-model.md");
    const initSkill = repositoryFile("skills/agentd-init/SKILL.md");

    expect(setup).toContain(
      'readonly BOTMUX_SETUP_RUNNER="/opt/pi-ops-agent/current/dist/runtime/botmux-setup-run.js"',
    );
    expect(repositoryFile("scripts/install-release.sh")).toContain(
      'botmux_setup_runner="${PAYLOAD_DIR}/app/dist/runtime/botmux-setup-run.js"',
    );
    expect(setup).toContain('run_as_botmux "${node_command}" "${botmux_setup_runner}"');
    expect(setup).toContain('--digest "${artifact_digest}"');
    expect(runner).toContain('PLUGIN_LEASE_SOCKET = "/run/ops-agent/plugin-lease/lease.sock"');
    expect(runner).toContain('pluginId: BOTMUX_PLUGIN_ID, digest');
    expect(runner).toContain('["setup"]');
    expect(runner).toContain('join(lease.registration.snapshotPath, "configure-botmux.mjs")');
    expect(runner).toContain('const BWRAP = "/usr/bin/bwrap"');
    expect(runner).toContain('"--unshare-user"');
    expect(runner).toContain('"--unshare-pid"');
    expect(runner).toContain('"--as-pid-1"');
    expect(runner).toContain('"--die-with-parent"');
    expect(runner).toContain('"--dev", "/dev"');
    expect(runner).toContain('["restart"]');
    expect(runner).toContain("await workflow.catch(() => undefined)");
    expect(pluginDocs).not.toContain("从 runtime 继承的 fd 3");
    expect(securityDocs).not.toContain("作为 fd 3 交给短生命周期");
    expect(initSkill).toContain("root:ops-agent-lease 0750");
    expect(initSkill).not.toContain(
      "`/var/lib/ops-agent/plugins/invocation-leases` is `root:ops-agent-client 2750`",
    );
  });

  it("fails closed when the BotMux Source adapter is absent instead of running a legacy package", () => {
    const setup = repositoryFile("scripts/setup-botmux.sh");
    const pluginDocs = repositoryFile("docs/plugins.md");
    const deploymentDocs = repositoryFile("docs/deployment.md");
    const operationsDocs = repositoryFile("docs/operations.md");

    expect(setup).toContain(
      "Active Source adapter.botmux registration is required; legacy .opspkg artifacts are recovery evidence only.",
    );
    expect(setup).toContain("Review and register plugins/adapter-botmux-source");
    expect(setup).not.toContain("LEGACY_PLUGIN_ROOT");
    expect(setup).not.toContain("LEGACY_PLUGIN_CURRENT");
    expect(setup).not.toContain("using the legacy .opspkg compatibility snapshot");
    expect(setup).not.toContain("/opt/pi-ops-agent/bin/ops-agent-botmux");
    expect(setup).not.toContain("adapter_mode");
    expect(pluginDocs).toMatch(/不再作为可执行\s+runtime fallback/u);
    expect(deploymentDocs).toMatch(
      /legacy `adapter\.botmux` 只保留 artifact\/change\/rollback 证据/u,
    );
    expect(operationsDocs).toMatch(/不能\s+作为新版 Client 的 runtime fallback/u);
  });

  it("keeps the client gateway available across an automatic agentd restart", () => {
    const gatewayUnit = repositoryFile("systemd/agentd-client-gateway.service");
    const targetUnit = repositoryFile("systemd/ops-agent.target");
    const installer = repositoryFile("scripts/install-release.sh");
    const gatewaySource = repositoryFile("internal/clientgateway/gateway.go");

    expect(gatewayUnit).toContain("PartOf=ops-agent.target");
    expect(gatewayUnit).toContain("Wants=ops-agentd.service");
    expect(gatewayUnit).toContain("After=ops-agentd.service");
    expect(gatewayUnit).not.toContain("BindsTo=ops-agentd.service");
    expect(gatewayUnit).not.toContain("Requires=ops-agentd.service");
    expect(targetUnit).toMatch(
      /^Wants=.*\bops-agentd\.service\b.*\bagentd-client-gateway\.service\b/mu,
    );

    expect(installer).toContain("verify_effective_controller_restart_topology() {");
    expect(installer).toContain('value?.type !== "as"');
    expect(installer).toContain("value.data.includes(expectedMember)");
    expect(installer).toContain("PrivateTmp may add portable mount dependencies");
    expect(installer).toContain(
      '"${target_unit}" "${target_object}" Wants "${target_wants}"',
    );
    expect(installer).toContain(
      '"${gateway_unit}" "${gateway_object}" Wants ops-agentd.service true',
    );
    expect(installer).toContain(
      '"${gateway_unit}" "${gateway_object}" PartOf ops-agent.target',
    );
    expect(installer).toContain(
      '"${gateway_unit}" "${gateway_object}" BindsTo \'\'',
    );
    expect(installer).toContain(
      '"${gateway_unit}" "${gateway_object}" Requires ops-agentd.service false',
    );
    expect(installer).toContain(
      '"${gateway_unit}" "${gateway_object}" After ops-agentd.service true',
    );
    const effectiveLoop = installer.indexOf(
      'for effective_unit in "${effective_units[@]}"; do',
    );
    const topologyGate = installer.indexOf(
      "  verify_effective_controller_restart_topology",
      effectiveLoop,
    );
    expect(effectiveLoop).toBeGreaterThan(0);
    expect(topologyGate).toBeGreaterThan(effectiveLoop);

    const listenStart = gatewaySource.indexOf("func (s *Server) ListenAndServe");
    const dialStart = gatewaySource.indexOf("func (s *Server) dialBackend", listenStart);
    const proxyStart = gatewaySource.indexOf("func proxyBackendFrames", dialStart);
    expect(listenStart).toBeGreaterThan(0);
    expect(dialStart).toBeGreaterThan(listenStart);
    expect(gatewaySource.slice(listenStart, dialStart)).not.toContain(
      "inspectBackendSocket",
    );
    expect(gatewaySource.slice(dialStart, proxyStart)).toContain(
      "dialValidatedBackend",
    );
    expect(gatewaySource).toContain("after != before");
  });

  it("assigns the client socket and immutable plugin registry to the client group", () => {
    const tmpfiles = repositoryFile("systemd/ops-agent.tmpfiles.conf");
    const agentUnit = repositoryFile("systemd/ops-agentd.service");
    const guardianUnit = repositoryFile("systemd/agentd-guardian.service");
    const gatewayUnit = repositoryFile("systemd/agentd-client-gateway.service");
    const gatewayDropIn = repositoryFile(
      "systemd/agentd-client-gateway.service.d/zzzz-ops-agent-security.conf",
    );
    const agentConfig = repositoryFile("config/agentd.json");
    const healthcheck = repositoryFile("scripts/healthcheck.sh");

    expect(tmpfiles).toContain("d /run/ops-agent/agentd 2750 ops-agent ops-agent-client -");
    expect(tmpfiles).toContain(
      "d /var/lib/ops-agent/plugins 2750 root ops-agent-client -",
    );
    expect(tmpfiles).not.toContain("/var/lib/ops-agent/plugin-sources");
    expect(repositoryFile("scripts/install-release.sh")).toContain(
      'install -d -o "${ADMIN_USER}" -g "$(id -gn "${ADMIN_USER}")" -m 0750',
    );
    expect(agentUnit).toContain("SupplementaryGroups=ops-agent-client");
    expect(guardianUnit).toContain("SupplementaryGroups=ops-agent-client");
    expect(gatewayUnit).toContain("User=ops-agent");
    expect(gatewayUnit).toContain("Group=ops-agent");
    expect(gatewayUnit).toContain("SupplementaryGroups=ops-agent-client");
    expect(gatewayUnit).toContain("RestrictAddressFamilies=AF_UNIX");
    expect(gatewayUnit).toContain("ReadWritePaths=/run/ops-agent/agentd");
    expect(gatewayUnit).toContain("InaccessiblePaths=-/etc/ops-agent/credentials");
    for (const gatewayPolicy of [gatewayUnit, gatewayDropIn]) {
      expect(gatewayPolicy).toContain("TasksMax=128");
      expect(gatewayPolicy).toContain("LimitNOFILE=512");
      expect(gatewayPolicy).toContain("MemoryMax=256M");
    }
    const installer = repositoryFile("scripts/install-release.sh");
    expect(installer).toContain('require_installed_unit_property "${unit}" TasksMax');
    expect(installer).toContain('require_installed_unit_property "${unit}" LimitNOFILE');
    expect(installer).toContain('require_installed_unit_property "${unit}" LimitNOFILESoft');
    expect(installer).toContain('require_installed_unit_property "${unit}" MemoryMax');
    expect(installer).toContain('installed_unit_property "${unit}" ExecStartEx');
    expect(installer).toContain('flags= ;');
    expect(installer).toContain('seen[ReadWritePaths]');
    expect(installer).toContain('seen[SupplementaryGroups]');
    expect(installer).toContain(
      'require_installed_unit_word_set "${unit}" ReadWritePaths',
    );
    expect(agentConfig).toContain('"socketPath": "/run/ops-agent/agentd/agentd.sock"');
    expect(agentConfig).toContain('"backendSocketPath": "/run/ops-agent/agentd/backend.sock"');
    expect(healthcheck).toContain(
      "guardian-heartbeat /run/ops-agent/agentd/heartbeat.json ops-agent:ops-agent-client:600",
    );
    expect(healthcheck).toContain(
      "check_socket agentd /run/ops-agent/agentd/agentd.sock ops-agent ops-agent-client",
    );
    expect(healthcheck).toContain(
      "check_private_socket agentd-backend /run/ops-agent/agentd/backend.sock ops-agent ops-agent-client",
    );
  });

  it("keeps the workload namespace sandbox compatible with agentd hardening", () => {
    const agentUnit = repositoryFile("systemd/ops-agentd.service");
    const agentDropIn = repositoryFile(
      "systemd/ops-agentd.service.d/zzzz-ops-agent-security.conf",
    );
    const runner = repositoryFile("src/agentd/workload-host-runner.ts");
    const baseSandbox = repositoryFile("src/agentd/sandbox.ts");
    const containment = repositoryFile("src/shared/bubblewrap-containment.ts");

    for (const unit of [agentUnit, agentDropIn]) {
      expect(unit).toContain("RestrictNamespaces=user ipc net mnt pid");
      expect(unit).toContain("/proc/sys/user/max_user_namespaces");
      expect(unit).not.toContain("RestrictNamespaces=yes");
    }
    for (const sandbox of [runner, baseSandbox]) {
      for (const namespace of ["user", "ipc", "pid", "net"]) {
        expect(sandbox).toContain(`"--unshare-${namespace}"`);
      }
      expect(sandbox).toContain('"--as-pid-1"');
      expect(sandbox).toContain('"--disable-userns"');
      expect(sandbox).not.toContain('"--unshare-all"');
      expect(sandbox).not.toContain('"--unshare-cgroup"');
      expect(sandbox).not.toContain('"--unshare-uts"');
      expect(sandbox).not.toContain('"--hostname"');
      expect(sandbox).toContain("WithProcessReaper(bwrap");
      expect(sandbox).toContain("unshareIpc: true");
      expect(sandbox).toContain("unshareNetwork: true");
    }
    expect(containment).toContain('"--unshare-user"');
    expect(containment).toContain('outerArguments.push("--unshare-pid")');
    expect(containment).toContain('"--bind", "/", "/"');
    expect(containment).toContain('"--dev", "/dev"');
    expect(containment).toContain('"--proc", "/proc"');
    expect(containment).not.toContain('"--as-pid-1"');
    expect(containment).not.toContain('"--disable-userns"');
    expect(containment).not.toContain('"--new-session"');
  });

  it("rejects restricted-userns controller setup before mutation and forbids profile attachment", () => {
    const helper = repositoryFile("scripts/configure-noble-bwrap-apparmor.sh");
    const installer = repositoryFile("scripts/install-release.sh");
    const agentdUnit = repositoryFile("systemd/ops-agentd.service");
    const agentdDropIn = repositoryFile(
      "systemd/ops-agentd.service.d/zzzz-ops-agent-security.conf",
    );
    const adapterProbe = repositoryFile("scripts/probe-adapter-linux-runtime.sh");
    const ciWorkflow = repositoryFile(".github/workflows/ci.yml");
    const releaseWorkflow = repositoryFile(".github/workflows/release.yml");

    const installStart = helper.indexOf("do_install() {");
    const installEnd = helper.indexOf("\ndo_remove() {", installStart);
    const inspectStart = helper.indexOf("do_inspect() {");
    const inspectEnd = helper.indexOf("\ndo_status() {", inspectStart);
    expect(installStart).toBeGreaterThan(0);
    expect(installEnd).toBeGreaterThan(installStart);
    expect(inspectStart).toBeGreaterThan(installEnd);
    expect(inspectEnd).toBeGreaterThan(inspectStart);
    const installAction = helper.slice(installStart, installEnd);
    const inspectAction = helper.slice(inspectStart, inspectEnd);
    expect(installAction).toContain(
      "host-policy install is unsupported; no AppArmor policy was changed",
    );
    expect(inspectAction).toContain(
      "host-policy inspect is unsupported; no AppArmor policy was changed",
    );
    for (const mutation of [
      "atomic_install_copy", "atomic_install_local_rule", "apparmor_parser",
      "run_authoritative_systemd_smoke", "confirm_action",
    ]) {
      expect(installAction).not.toContain(mutation);
      expect(inspectAction).not.toContain(mutation);
    }
    expect(helper).toContain(
      "--cap-drop ALL --bind / / --dev /dev --proc /proc -- /usr/bin/bwrap",
    );

    const guardCall = installer.indexOf(
      "reject_unsupported_restricted_userns_controller_host\n",
    );
    const artifactValidateOnly = installer.indexOf(
      'preflight_args=(--catalog-index "${preflight_catalog}" --validate-only)',
    );
    const beginTransaction = installer.indexOf("\nbegin_install_transaction\n");
    expect(guardCall).toBeGreaterThan(0);
    expect(artifactValidateOnly).toBeGreaterThan(guardCall);
    expect(beginTransaction).toBeGreaterThan(artifactValidateOnly);
    expect(installer).toContain(
      "/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
    );
    expect(installer).toContain("/sys/module/apparmor/parameters/enabled");
    expect(installer).toContain("os_lines > 256 || os_bytes > 16384");
    expect(installer).toContain("os_id_count == 1 && os_version_count == 1");
    expect(installer).toContain(
      "Controller init is unsupported while AppArmor restricted unprivileged user namespaces are enabled.",
    );
    expect(installer).toContain(
      "No controller account, unit, plugin, release, or host AppArmor policy was changed.",
    );

    expect(agentdUnit).not.toContain("AppArmorProfile=");
    expect(agentdDropIn).not.toContain("AppArmorProfile=");
    expect(installer).toContain("require_installed_unit_apparmor_profile()");
    expect(installer).toContain('value?.type !== "(bs)"');
    expect(installer).toContain(
      'require_installed_unit_apparmor_profile "${unit}" false \'\'',
    );
    expect(installer).toContain(
      "require_installed_unit_apparmor_profile ops-agentd.service false ''",
    );
    expect(installer).toContain(
      'require_installed_unit_apparmor_profile "${bwrap_probe_unit}" false \'\'',
    );

    expect(adapterProbe).not.toContain("AppArmorProfile=-bwrap");
    expect(adapterProbe).not.toContain("--property=AppArmorProfile=");
    expect(adapterProbe).toContain("require_effective_empty_apparmor_profile");
    expect(adapterProbe).toContain("value.data[0] !== false");
    expect(adapterProbe).toContain('value.data[1] !== ""');

    const installerStart = ciWorkflow.indexOf("  installer-runtime:\n");
    const joinStart = ciWorkflow.indexOf("  join-installer-runtime:\n");
    const installerJob = ciWorkflow.slice(installerStart, joinStart);
    expect(installerJob).toContain(
      "name: Reject host policy and controller init before persistent mutation",
    );
    expect(installerJob).toContain("host-policy inspect");
    expect(installerJob).toContain("host-policy install");
    expect(installerJob).toContain("ops-agent-bwrap-profiles-before");
    expect(installerJob).toContain("ops-agent-bwrap-profiles-after");
    expect(installerJob).toContain("Early rejection created managed path");
    expect(installerJob).not.toContain(
      "Install and verify the pinned nested-bubblewrap AppArmor policy",
    );
    expect(installerJob).not.toContain(
      "Install successfully under the restored effective policy",
    );

    expect(releaseWorkflow).not.toContain(
      "Install and verify the pinned nested-bubblewrap AppArmor policy",
    );
    expect(releaseWorkflow).toContain(
      "name: Run the release-blocking real Linux Adapter probe",
    );
    expect(releaseWorkflow).toContain("npm run test:adapter-linux-runtime");
    expect(releaseWorkflow).toContain(
      "status 77 is unverified and blocks release",
    );
  });

  it("runs the BotMux Adapter probe inside its exact systemd namespace boundary", () => {
    const botmuxDropIn = repositoryFile("config/botmux-systemd-dropin.conf");
    const probe = repositoryFile("scripts/probe-adapter-linux-runtime.sh");
    const releaseWorkflow = repositoryFile(".github/workflows/release.yml");
    const writablePaths = botmuxDropIn
      .split("\n")
      .filter((line) => line.startsWith("ReadWritePaths="))
      .flatMap((line) => line.slice("ReadWritePaths=".length).trim().split(/\s+/u));

    expect(botmuxDropIn).toContain("ProtectKernelTunables=yes");
    expect(botmuxDropIn).toContain("RestrictNamespaces=user pid mnt");
    expect(writablePaths).toEqual([
      "/var/lib/ops-agent/adapters/botmux",
      "/tmp",
      "/proc/sys/user/max_user_namespaces",
    ]);
    expect(probe).toContain("/usr/bin/systemd-run --quiet --wait --collect --pipe");
    expect(probe).toContain(
      'probe_driver_directory="${probe_runtime_root}/scripts"',
    );
    expect(probe).toContain(
      'probe_driver_path="${probe_driver_directory}/probe-adapter-linux-runtime.mjs"',
    );
    expect(probe).toContain('cp -a dist "${probe_runtime_root}/dist"');
    expect(repositoryFile("src/runtime/adapter-run.ts")).toContain('"--unshare-user"');
    expect(repositoryFile("src/runtime/adapter-run.ts")).toContain('"--dev", "/dev"');
    expect(repositoryFile("scripts/probe-adapter-linux-fixture.mjs")).toContain(
      'writerLease: "gateway-global"',
    );
    expect(probe).toContain(
      "--working-directory=/var/lib/ops-agent/adapters/botmux",
    );
    expect(probe).toContain("--setenv=HOME=/var/lib/ops-agent/adapters/botmux");
    expect(probe).toContain(
      "--setenv=PATH=/opt/pi-ops-agent/botmux-bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    );
    for (const property of [
      "NoNewPrivileges=yes",
      "ProtectSystem=strict",
      "ProtectHome=yes",
      "ProtectKernelTunables=yes",
      "ProtectKernelModules=yes",
      "ProtectControlGroups=yes",
      "PrivateDevices=yes",
      "RestrictSUIDSGID=yes",
    ]) {
      expect(probe).toContain(`--property=${property}`);
    }
    expect(probe).toContain('--property="RestrictNamespaces=user pid mnt"');
    expect(probe).toContain(
      "/var/lib/ops-agent/adapters/botmux /tmp /proc/sys/user/max_user_namespaces",
    );
    expect(probe).not.toContain("/usr/sbin/runuser -u");

    const fixtureStart = releaseWorkflow.indexOf(
      "name: Create the disposable Adapter identity fixture",
    );
    const probeStart = releaseWorkflow.indexOf(
      "name: Run the release-blocking real Linux Adapter probe",
      fixtureStart,
    );
    expect(fixtureStart).toBeGreaterThan(0);
    expect(probeStart).toBeGreaterThan(fixtureStart);
    const fixture = releaseWorkflow.slice(fixtureStart, probeStart);
    expect(fixture).toContain("groupadd --system ops-agent-client");
    expect(fixture).toContain("groupadd --system ops-agent-botmux");
    expect(fixture).toContain("useradd --system");
    expect(fixture).toContain("--gid ops-agent-botmux");
    expect(fixture).toContain("--groups ops-agent-client");
    expect(fixture).toContain("-o ops-agent-botmux -g ops-agent-botmux -m 0700");
    expect(fixture).toContain('test "$(id -a)" = "${runner_identity}"');
    expect(fixture).not.toContain("usermod");
    expect(fixture).not.toContain("runner ALL=");
  });

  it("keeps the agent key owner-only and provisions a distinct status observer", () => {
    const installer = repositoryFile("scripts/install-release.sh");

    expect(installer).toContain("URI:spiffe://ops-agent/role/observer");
    expect(installer).toContain('chown "${SERVICE_USER}:${SERVICE_GROUP}" "${tls_root}/agent.key"');
    expect(installer).toContain('chmod 0600 "${tls_root}/agent.key"');
    expect(installer).toContain('chown root:"${CLIENT_GROUP}"');
    expect(installer).toContain('"${tls_root}/observer.crt" "${tls_root}/observer.key"');
    expect(installer).toContain('== "root:${CLIENT_GROUP}:640"');
    expect(installer).toContain("observerCertPath: `${tlsRoot}/observer.crt`");
    expect(installer).toContain("observerKeyPath: `${tlsRoot}/observer.key`");
    expect(installer).toContain(
      'chown root:"${CLIENT_GROUP}" "${servers_candidate}"',
    );
    expect(installer).toContain('chmod 0640 "${servers_candidate}"');
  });

  it("keeps the core and PVE broker stores and private identities mutually isolated", () => {
    const coreBroker = repositoryFile("systemd/ops-root-helper.service");
    const pveBroker = repositoryFile("systemd/ops-pve-root-helper.service");

    expect(coreBroker).toContain("-/var/lib/ops-agent/pve-root-helper");
    expect(coreBroker).toContain("-/var/log/ops-agent/pve-root-helper");
    expect(pveBroker).toContain("-/var/lib/ops-agent/root-helper");
    expect(pveBroker).toContain("-/var/log/ops-agent/root-helper");
    expect(coreBroker).toContain("--receipt-key-id=local-core-receipt-v1");
    expect(coreBroker).toContain(
      "--receipt-private-key=/etc/ops-agent/broker-receipts/private/core.key.pem",
    );
    expect(pveBroker).toContain("--receipt-key-id=local-pve-receipt-v1");
    expect(pveBroker).toContain(
      "--receipt-private-key=/etc/ops-agent/broker-receipts/private/pve.key.pem",
    );
    expect(coreBroker).toContain(
      "-/etc/ops-agent/broker-receipts/private/pve.key.pem",
    );
    expect(pveBroker).toContain(
      "-/etc/ops-agent/broker-receipts/private/core.key.pem",
    );
    for (const unit of [coreBroker, pveBroker]) {
      expect(unit).toContain("-/etc/ops-agent/approver");
      expect(unit).toContain("-/etc/ops-agent/tls/agent.key");
      expect(unit).toContain("-/etc/ops-agent/tls/observer.key");
      expect(unit).toContain("-/etc/ops-agent/tls/server.key");
    }
  });

  it("opens only the exact pmxcfs mount to the PVE broker", () => {
    const pveUnitName = "ops-pve-root-helper.service";
    const pveBroker = repositoryFile(`systemd/${pveUnitName}`);
    const pveBrokerDropIn = repositoryFile(
      "systemd/ops-pve-root-helper.service.d/zzzz-ops-agent-security.conf",
    );
    const coreBroker = repositoryFile("systemd/ops-root-helper.service");
    const readWritePaths = (unit: string): string[] =>
      unit
        .split("\n")
        .filter((line) => line.startsWith("ReadWritePaths="))
        .flatMap((line) => line.slice("ReadWritePaths=".length).trim().split(/\s+/u));

    for (const pveSurface of [pveBroker, pveBrokerDropIn]) {
      expect(pveSurface).toContain("ProtectSystem=full");
      expect(readWritePaths(pveSurface).filter((path) => path.startsWith("/etc"))).toEqual([
        "/etc/pve",
      ]);
    }
    expect(coreBroker).toContain("InaccessiblePaths=");
    expect(coreBroker).toMatch(/(?:^InaccessiblePaths=|\s)-\/etc\/pve(?:\s|$)/mu);
    for (const unitName of [
      "ops-agent-server.service",
      "ops-agent-server.service.d/zzzz-ops-agent-security.conf",
      "ops-agentd.service",
      "ops-agentd.service.d/zzzz-ops-agent-security.conf",
    ]) {
      expect(repositoryFile(`systemd/${unitName}`), unitName).toMatch(
        /(?:^InaccessiblePaths=|\s)-\/etc\/pve(?:\s|$)/mu,
      );
    }

    for (const entry of readdirSync(new URL("../systemd/", import.meta.url), {
      withFileTypes: true,
    })) {
      if (!entry.isFile()) continue;
      const unitName = entry.name;
      if (unitName === pveUnitName) continue;
      const unit = repositoryFile(`systemd/${unitName}`);
      expect(readWritePaths(unit), unitName).not.toContain("/etc/pve");
    }
  });

  it("keeps the PVE broker out of the controller target on join endpoints", () => {
    const installer = repositoryFile("scripts/install-release.sh");
    const pveBroker = repositoryFile("systemd/ops-pve-root-helper.service");
    const healthcheck = repositoryFile("scripts/healthcheck.sh");
    const uninstaller = repositoryFile("scripts/uninstall.sh");

    expect(pveBroker).toContain("WantedBy=multi-user.target");
    expect(pveBroker).not.toContain("WantedBy=ops-agent.target");
    expect(installer).toContain(
      'readonly OPS_AGENT_TARGET_WANTS_DIR="${UNIT_ROOT}/ops-agent.target.wants"',
    );
    expect(installer).toContain(
      'snapshot_managed_path "${OPS_AGENT_TARGET_WANTS_DIR}"',
    );
    expect(installer).toContain(
      'restore_managed_path_snapshot "${OPS_AGENT_TARGET_WANTS_SNAPSHOT_INDEX}"',
    );
    expect(installer).toContain("validate_endpoint_controller_target_wants");
    expect(installer).toContain("cleanup_pve_controller_target_want");
    expect(healthcheck).toContain("/etc/systemd/system/ops-agent.target.wants");
    expect(healthcheck).toContain(
      'report FAIL endpoint-topology "controller target or wants dependency is present"',
    );
    expect(uninstaller).toContain(
      'readonly PVE_CONTROLLER_TARGET_WANT="${OPS_AGENT_TARGET_WANTS_DIR}/ops-pve-root-helper.service"',
    );
    expect(uninstaller).toContain("restore_pve_controller_target_want");
    expect(uninstaller).toContain('rm -f -- "${PVE_CONTROLLER_TARGET_WANT}"');

    const snapshot = installer.indexOf(
      'snapshot_managed_path "${OPS_AGENT_TARGET_WANTS_DIR}"',
    );
    const rollbackStart = installer.indexOf("rollback_install_transaction() {");
    const restoreUnits = installer.indexOf("\n  restore_unit_state\n", rollbackStart);
    const restoreTopology = installer.indexOf(
      "\n  restore_managed_enablement_topology\n",
      restoreUnits,
    );
    const topologyFunctionStart = installer.indexOf(
      "restore_managed_enablement_topology() {",
    );
    const topologyFunctionEnd = installer.indexOf(
      "\nrollback_install_transaction() {",
      topologyFunctionStart,
    );
    const topologyFunction = installer.slice(topologyFunctionStart, topologyFunctionEnd);
    const cleanup = installer.lastIndexOf("\ncleanup_pve_controller_target_want\n");
    const unitFailure = installer.indexOf("maybe_inject_install_failure units");
    const joinActivation = installer.indexOf(
      'if [[ "${MODE}" == join ]]; then\n  join_units=',
    );
    const initActivation = installer.indexOf(
      "\nsystemctl enable ops-agent.target ops-agent-healthcheck.timer",
      joinActivation,
    );
    const addWants = installer.indexOf(
      "systemctl add-wants ops-agent.target ops-pve-root-helper.service",
    );
    const serviceFailure = installer.lastIndexOf("maybe_inject_install_failure services");

    expect(snapshot).toBeGreaterThan(0);
    expect(restoreTopology).toBeGreaterThan(restoreUnits);
    expect(topologyFunction).toContain(
      'for index in "${TRANSACTION_ENABLEMENT_LINK_SNAPSHOT_INDICES[@]}"; do',
    );
    expect(topologyFunction).toContain(
      'restore_managed_path_snapshot "${OPS_AGENT_TARGET_WANTS_SNAPSHOT_INDEX}"',
    );
    expect(topologyFunction.indexOf("systemctl daemon-reload")).toBeGreaterThan(
      topologyFunction.indexOf(
        'restore_managed_path_snapshot "${OPS_AGENT_TARGET_WANTS_SNAPSHOT_INDEX}"',
      ),
    );
    expect(cleanup).toBeGreaterThan(snapshot);
    expect(unitFailure).toBeGreaterThan(cleanup);
    expect(joinActivation).toBeGreaterThan(0);
    expect(initActivation).toBeGreaterThan(joinActivation);
    expect(installer.slice(joinActivation, initActivation)).not.toContain("add-wants");
    expect(addWants).toBeGreaterThan(initActivation);
    expect(serviceFailure).toBeGreaterThan(addWants);
  });

  it("snapshots only exact managed persistent and cleanup-time runtime links", () => {
    const installer = repositoryFile("scripts/install-release.sh");
    const snapshotStart = installer.indexOf("snapshot_managed_enablement_link() {");
    const snapshotEnd = installer.indexOf("pve_controller_target_want_is_exact() {", snapshotStart);
    const snapshotFunction = installer.slice(snapshotStart, snapshotEnd);
    const beginStart = installer.indexOf("begin_install_transaction() {");
    const beginEnd = installer.indexOf("record_rollback_error() {", beginStart);
    const begin = installer.slice(beginStart, beginEnd);
    const restoreStart = installer.indexOf("restore_unit_state() {");
    const restoreEnd = installer.indexOf(
      "restore_managed_enablement_topology() {",
      restoreStart,
    );
    const restore = installer.slice(restoreStart, restoreEnd);

    for (const path of [
      "multi-user.target.wants/ops-agent.target",
      "multi-user.target.wants/ops-agent-server.service",
      "multi-user.target.wants/ops-root-helper.service",
      "multi-user.target.wants/ops-pve-root-helper.service",
      "timers.target.wants/ops-agent-healthcheck.timer",
      "ops-agent.target.wants/ops-pve-root-helper.service",
      "ops-agent.target.wants/ops-systemd-helper.service",
    ]) {
      expect(snapshotFunction).toContain(path);
    }
    expect(snapshotFunction).toContain("Unit enablement path is not a symlink");
    expect(snapshotFunction).toContain("Unit enablement parent is group/world writable");
    expect(begin.indexOf("snapshot_managed_units")).toBeLessThan(
      begin.indexOf("snapshot_managed_enablement_links"),
    );
    expect(begin.indexOf("snapshot_managed_enablement_links")).toBeLessThan(
      begin.indexOf('snapshot_managed_path "${OPS_AGENT_TARGET_WANTS_DIR}"'),
    );
    expect(snapshotFunction).toContain(
      '${RUNTIME_UNIT_ROOT}/multi-user.target.wants/ops-pve-root-helper.service',
    );
    expect(snapshotFunction).toContain(
      '${RUNTIME_UNIT_ROOT}/ops-agent.target.wants/ops-systemd-helper.service',
    );
    expect(restore).not.toMatch(/^\s*systemctl disable(?:\s|$)/mu);
    expect(restore).toContain('if [[ "${current_enabled}" != "${enabled}" ]]');
    expect(restore).toContain("any remaining state mismatch is therefore an incomplete rollback");

    const installLinks = new Map([
      ["ops-agent.target", "multi-user.target"],
      ["ops-agent-healthcheck.timer", "timers.target"],
      ["ops-agent-server.service", "multi-user.target"],
      ["ops-root-helper.service", "multi-user.target"],
      ["ops-pve-root-helper.service", "multi-user.target"],
    ]);
    for (const [unit, wantedBy] of installLinks) {
      const source = repositoryFile(`systemd/${unit}`);
      expect(source).toContain("[Install]");
      expect(source).toContain(`WantedBy=${wantedBy}`);
      expect(snapshotFunction).toContain(`${wantedBy}.wants/${unit}`);
    }
  });

  it("removes only fixed stale-unit enablement links and preserves custom aliases", () => {
    const installer = repositoryFile("scripts/install-release.sh");
    const cleanupStart = installer.indexOf("cleanup_managed_unit_enablement_link() {");
    const cleanupEnd = installer.indexOf(
      "# Controller init follows the local PVE host fact",
      cleanupStart,
    );
    expect(cleanupStart).toBeGreaterThanOrEqual(0);
    expect(cleanupEnd).toBeGreaterThan(cleanupStart);
    const cleanupFunctions = installer.slice(cleanupStart, cleanupEnd);
    expect(cleanupFunctions).not.toContain("systemctl disable");

    const root = mkdtempSync(join(realpathSync(tmpdir()), "ops-agent-enable-cleanup-"));
    const unitRoot = join(root, "etc-systemd-system");
    const runtimeUnitRoot = join(root, "run-systemd-system");
    const pveUnit = join(unitRoot, "ops-pve-root-helper.service");
    const legacyUnit = join(unitRoot, "ops-systemd-helper.service");
    const exactLinks = [
      join(unitRoot, "multi-user.target.wants", "ops-pve-root-helper.service"),
      join(unitRoot, "ops-agent.target.wants", "ops-pve-root-helper.service"),
      join(runtimeUnitRoot, "multi-user.target.wants", "ops-pve-root-helper.service"),
      join(runtimeUnitRoot, "ops-agent.target.wants", "ops-pve-root-helper.service"),
      join(unitRoot, "ops-agent.target.wants", "ops-systemd-helper.service"),
      join(runtimeUnitRoot, "ops-agent.target.wants", "ops-systemd-helper.service"),
    ];
    const customPve = join(unitRoot, "custom.target.wants", "ops-pve-root-helper.service");
    const customLegacy = join(unitRoot, "custom.target.wants", "ops-systemd-helper.service");
    const pveAlias = join(unitRoot, "administrator-pve-alias.service");
    const legacyAlias = join(unitRoot, "administrator-systemd-alias.service");
    try {
      for (const directory of [
        join(unitRoot, "multi-user.target.wants"),
        join(unitRoot, "ops-agent.target.wants"),
        join(unitRoot, "custom.target.wants"),
        join(runtimeUnitRoot, "multi-user.target.wants"),
        join(runtimeUnitRoot, "ops-agent.target.wants"),
      ]) {
        mkdirSync(directory, { recursive: true });
      }
      writeFileSync(pveUnit, "pve fixture\n", "utf8");
      writeFileSync(legacyUnit, "legacy fixture\n", "utf8");
      for (const path of exactLinks.slice(0, 4)) symlinkSync(pveUnit, path);
      for (const path of exactLinks.slice(4)) symlinkSync(legacyUnit, path);
      for (const path of [customPve, pveAlias]) symlinkSync(pveUnit, path);
      for (const path of [customLegacy, legacyAlias]) symlinkSync(legacyUnit, path);

      const verification = spawnSync(
        "/bin/bash",
        [
          "-c",
          [
            "set -euo pipefail",
            'UNIT_ROOT="$1"',
            'RUNTIME_UNIT_ROOT="$2"',
            'TEST_NODE="$3"',
            "readlink() {",
            '  if [[ "$#" -eq 3 && "$1" == -f && "$2" == -- ]]; then',
            '    "${TEST_NODE}" -e \'process.stdout.write(require("node:fs").realpathSync(process.argv[1]))\' "$3"',
            "  else",
            '    command readlink "$@"',
            "  fi",
            "}",
            cleanupFunctions,
            "cleanup_managed_unit_enablement_links ops-pve-root-helper.service",
            "cleanup_managed_unit_enablement_links ops-systemd-helper.service",
            'unsafe="${RUNTIME_UNIT_ROOT}/ops-agent.target.wants/ops-systemd-helper.service"',
            'ln -s "${UNIT_ROOT}/ops-pve-root-helper.service" "${unsafe}"',
            "if cleanup_managed_unit_enablement_links ops-systemd-helper.service >/dev/null 2>&1; then exit 91; fi",
            '[[ -L "${unsafe}" ]]',
            'rm -f -- "${unsafe}"',
            'printf "%s\\n" unsafe >"${unsafe}"',
            "if cleanup_managed_unit_enablement_links ops-systemd-helper.service >/dev/null 2>&1; then exit 92; fi",
            '[[ -f "${unsafe}" ]]',
            'rm -f -- "${unsafe}"',
            "if cleanup_managed_unit_enablement_links unrelated.service >/dev/null 2>&1; then exit 93; fi",
          ].join("\n"),
          "--",
          unitRoot,
          runtimeUnitRoot,
          process.execPath,
        ],
        { encoding: "utf8" },
      );
      expect(verification.status, `${verification.stdout}${verification.stderr}`).toBe(0);
      for (const path of exactLinks) {
        expect(existsSync(path)).toBe(false);
        expect(() => lstatSync(path)).toThrow();
      }
      for (const [path, target] of [
        [customPve, pveUnit],
        [customLegacy, legacyUnit],
        [pveAlias, pveUnit],
        [legacyAlias, legacyUnit],
      ] as const) {
        expect(lstatSync(path).isSymbolicLink()).toBe(true);
        expect(readlinkSync(path)).toBe(target);
      }
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("transactionally removes only managed PVE systemd surfaces from non-PVE endpoints", () => {
    const installer = repositoryFile("scripts/install-release.sh");
    const healthcheck = repositoryFile("scripts/healthcheck.sh");
    const selection = installer.indexOf("selected_pve_broker=false");
    const enrollmentValidation = installer.lastIndexOf(
      "\n  validate_enrolled_broker_receipts\n",
      selection,
    );
    const unitCleanup = installer.indexOf(
      '[[ "${unit_name}" == ops-pve-root-helper.service ]]',
      selection,
    );
    const dropInCleanup = installer.indexOf(
      'pve_managed_dropin="${UNIT_ROOT}/ops-pve-root-helper.service.d/zzzz-ops-agent-security.conf"',
      unitCleanup,
    );
    const unitFailure = installer.indexOf("maybe_inject_install_failure units", dropInCleanup);

    expect(enrollmentValidation).toBeGreaterThan(0);
    expect(selection).toBeGreaterThan(enrollmentValidation);
    expect(installer).toContain(
      'snapshot_managed_path "${UNIT_ROOT}/ops-pve-root-helper.service.d"',
    );
    expect(unitCleanup).toBeGreaterThan(selection);
    expect(dropInCleanup).toBeGreaterThan(unitCleanup);
    expect(unitFailure).toBeGreaterThan(dropInCleanup);
    expect(installer.slice(unitCleanup, unitFailure)).toContain(
      'cleanup_managed_unit_enablement_links "${unit_name}"',
    );
    expect(installer).not.toContain("disable_managed_unit_for_cleanup");
    expect(installer).not.toMatch(/^\s*systemctl disable(?:\s|$)/mu);
    expect(installer.slice(selection, unitFailure)).toContain(
      "validate_stale_pve_unit_for_cleanup",
    );
    expect(installer.slice(selection, unitFailure)).toContain(
      "validate_stale_pve_dropin_for_cleanup",
    );
    expect(installer).toContain(
      '[[ ! -d "${directory}" ]] || [[ -L "${directory}" ]]',
    );
    expect(installer).toContain(
      'stat -c \'%U:%G:%a:%h\' "${managed}"',
    );
    expect(installer.slice(unitCleanup, unitFailure)).toContain(
      'rm -f -- "${UNIT_ROOT}/${unit_name}"',
    );
    expect(installer.slice(dropInCleanup, unitFailure)).toContain(
      'rm -f -- "${pve_managed_dropin}"',
    );
    expect(installer.slice(dropInCleanup, unitFailure)).toContain(
      'rmdir -- "${UNIT_ROOT}/ops-pve-root-helper.service.d" 2>/dev/null || true',
    );
    expect(installer.slice(unitCleanup, unitFailure)).not.toMatch(
      /(?:\/var\/lib\/ops-agent\/pve-root-helper|\/var\/log\/ops-agent\/pve-root-helper)/u,
    );
    expect(healthcheck).toContain(
      "check_absent_path pve-broker-unit",
    );
    expect(healthcheck).toContain(
      "check_absent_path pve-broker-security-dropin",
    );
    expect(healthcheck).toContain(
      "/etc/systemd/system/ops-pve-root-helper.service.d/zzzz-ops-agent-security.conf",
    );
    expect(healthcheck).toContain('[[ -e "${path}" ]] || [[ -L "${path}" ]]');
  });

  it("installs domain-separated broker receipt keys with pinned public verifiers", () => {
    const installer = repositoryFile("scripts/install-release.sh");
    const healthcheck = repositoryFile("scripts/healthcheck.sh");
    const serverCommand = repositoryFile("cmd/ops-agent-server/main.go");
    const enrollment = repositoryFile("internal/enrollment/enrollment.go");

    expect(installer).toContain('readonly CORE_RECEIPT_KEY_ID="local-core-receipt-v1"');
    expect(installer).toContain('readonly PVE_RECEIPT_KEY_ID="local-pve-receipt-v1"');
    expect(installer).toContain('install -o root -g root -m 0600 "${staging}/private.pem"');
    expect(installer).toContain(
      'install -o root -g "${RECEIPT_PUBLIC_GROUP}" -m 0640 "${staging}/public.pem"',
    );
    expect(installer).toContain("coreReceiptKeyId");
    expect(installer).toContain("coreReceiptPublicKeyPath");
    expect(installer).toContain("pveReceiptKeyId");
    expect(installer).toContain("pveReceiptPublicKeyPath");
    expect(healthcheck).toContain(
      "core-receipt-private /etc/ops-agent/broker-receipts/private/core.key.pem root:root:600",
    );
    expect(healthcheck).toContain(
      "core-receipt-public /etc/ops-agent/broker-receipts/core-public.pem root:ops-agent-client:640",
    );
    expect(serverCommand).toContain(
      'flags.Bool("pve", false, "issue a separate PVE broker receipt identity for a PVE endpoint")',
    );
    expect(serverCommand).toContain('flags.String("controller-ca-sha256"');
    expect(installer).toContain("--controller-ca-sha256");
    expect(enrollment).toContain("verifyControllerCAFingerprint");
    expect(enrollment).toContain('json:"coreReceiptPrivateKeyPem"');
    expect(enrollment).toContain('json:"pveReceiptPrivateKeyPem,omitempty"');
    expect(enrollment).toContain('remoteReceiptFolder = "remotes"');
  });

  it("migrates only the exact unmodified legacy default model catalog", () => {
    const installer = repositoryFile("scripts/install-release.sh");
    const legacyDefault = `{
  "providers": {
    "deepseek": {
      "baseUrl": "https://api.deepseek.com",
      "api": "openai-completions",
      "models": [
        {
          "id": "deepseek-v4-flash",
          "name": "DeepSeek V4 Flash",
          "reasoning": true,
          "input": ["text"]
        }
      ]
    }
  }
}
`;
    const legacyDigest = createHash("sha256").update(legacyDefault).digest("hex");
    expect(legacyDigest).toBe(
      "e7be604cd6cf42eb40ab6734332b63a7aaad191b2b3d2c2f1a74212e654e3891",
    );
    expect(installer).toContain(
      `readonly LEGACY_DEFAULT_MODELS_SHA256="${legacyDigest}"`,
    );

    const bashFunction = (name: string): string => {
      const match = installer.match(new RegExp(
        `^${name}\\(\\) \\{\\n[\\s\\S]*?^\\}\\n`,
        "mu",
      ));
      expect(match?.[0], `${name} must be a top-level executable helper`).toBeDefined();
      if (match?.[0] === undefined) throw new Error(`missing ${name}`);
      return match[0];
    };
    const productionFunctions = [
      "is_unmodified_legacy_default_models_config",
      "ensure_managed_directory",
      "install_verified_config_copy",
      "install_controller_configs",
      "refuse_mounts_at_or_below_managed_path",
      "remove_managed_path",
      "snapshot_managed_path",
      "restore_managed_path_snapshot",
      "maybe_inject_install_failure",
    ].map(bashFunction).join("\n");
    const configStart = installer.indexOf("install_controller_configs() {");
    const configEnd = installer.indexOf("\n}\n", configStart) + 3;
    const configInstall = installer.slice(configStart, configEnd);
    expect(configInstall).toContain(
      `== "root:\${config_group}:640:1"`,
    );
    expect(configInstall).toContain("is_unmodified_legacy_default_models_config");
    expect(configInstall).toContain('"${destination_config}.dist" "${config_group}"');
    expect(installer).toContain('sync -- "${temporary_path}"');
    expect(installer).toContain('sync -- "${destination_parent}"');
    expect(installer).not.toMatch(/^\s*sync\s+-f(?:\s|$)/mu);
    expect(installer.indexOf('snapshot_managed_path "${CONFIG_ROOT}"')).toBeLessThan(
      installer.indexOf('install_controller_configs "${release_dir}"'),
    );
    expect(installer.indexOf('install_controller_configs "${release_dir}"')).toBeLessThan(
      installer.indexOf("maybe_inject_install_failure config"),
    );

    const harness = [
      "set -euo pipefail",
      'CONFIG_ROOT="$1"',
      'release_dir="$2"',
      'TEST_UNSAFE_PATH="$3"',
      'SYNC_LOG="$4"',
      'ACTION="$5"',
      'INSTALL_TRANSACTION_DIR="$6"',
      'FINDMNT_BIN="$7"',
      'readonly SERVICE_GROUP="ops-agent"',
      'readonly CLIENT_GROUP="ops-agent-client"',
      `readonly LEGACY_DEFAULT_MODELS_SHA256="${legacyDigest}"`,
      'readonly CURRENT_LINK="/test/current"',
      'readonly JSON_CONFIG_HELPER="/test/json-config-helper"',
      'readonly TMPFILES_ROOT="/test/tmpfiles"',
      'readonly APPROVAL_SUDOERS="/test/sudoers"',
      'readonly UNIT_ROOT="/test/systemd"',
      'readonly RUNTIME_UNIT_ROOT="/test/run-systemd"',
      "install() {",
      "  local make_directory=false mode=0755 value",
      "  local -a operands=()",
      "  while (( $# > 0 )); do",
      "    case \"$1\" in",
      "      -d) make_directory=true; shift ;;",
      "      -o|-g) shift 2 ;;",
      "      -m) mode=\"$2\"; shift 2 ;;",
      "      --) shift ;;",
      "      *) operands+=(\"$1\"); shift ;;",
      "    esac",
      "  done",
      "  if [[ \"${make_directory}\" == true ]]; then",
      "    for value in \"${operands[@]}\"; do /bin/mkdir -p \"${value}\"; /bin/chmod \"${mode}\" \"${value}\"; done",
      "  else",
      "    /usr/bin/install -m \"${mode}\" \"${operands[0]}\" \"${operands[1]}\"",
      "  fi",
      "}",
      "stat() {",
      "  local format= path= value",
      "  while (( $# > 0 )); do",
      "    case \"$1\" in -c) format=\"$2\"; shift 2 ;; --) shift ;; *) path=\"$1\"; shift ;; esac",
      "  done",
      "  case \"${format}\" in",
      "    %U:%G:%a)",
      "      if [[ -n \"${TEST_UNSAFE_PATH}\" && \"${path}\" == \"${TEST_UNSAFE_PATH}\" ]]; then",
      "        if [[ \"${path}\" == */credentials ]]; then value=nobody:root:700; else value=root:root:777; fi;",
      "      elif [[ \"${path}\" == \"${CONFIG_ROOT}\" ]]; then value=root:root:755;",
      "      elif [[ \"${path}\" == \"${CONFIG_ROOT}/credentials\" ]]; then value=root:root:700;",
      "      else value=root:root:755; fi ;;",
      "    %U:%G:%a:%h)",
      "      if [[ -n \"${TEST_UNSAFE_PATH}\" && \"${path}\" == \"${TEST_UNSAFE_PATH}\" ]]; then value=root:ops-agent:640:2;",
      "      elif [[ \"${path##*/}\" == *agentd.json* ]]; then value=root:ops-agent-client:640:1;",
      "      else value=root:ops-agent:640:1; fi ;;",
      "    *) printf 'unexpected stat format: %s\\n' \"${format}\" >&2; return 1 ;;",
      "  esac",
      "  printf '%s\\n' \"${value}\"",
      "}",
      "sha256sum() { while (( $# > 1 )); do shift; done; /usr/bin/shasum -a 256 \"$1\"; }",
      "sync() { printf '%s\\n' \"$*\" >>\"${SYNC_LOG}\"; }",
      "mv() { while (( $# > 2 )); do shift; done; /bin/mv -f \"$1\" \"$2\"; }",
      "cp() { while (( $# > 2 )); do shift; done; /bin/cp -a \"$1\" \"$2\"; }",
      "record_rollback_error() { printf 'rollback error: %s\\n' \"$1\" >&2; return 1; }",
      productionFunctions,
      "case \"${ACTION}\" in",
      "  run)",
      "    ensure_managed_directory \"${CONFIG_ROOT}\" root root 755",
      "    ensure_managed_directory \"${CONFIG_ROOT}/credentials\" root root 700",
      "    install_controller_configs \"${release_dir}\" ;;",
      "  ensure-root) ensure_managed_directory \"${CONFIG_ROOT}\" root root 755 ;;",
      "  rollback)",
      "    TRANSACTION_PATHS=()",
      "    TRANSACTION_PATH_STATES=()",
      "    snapshot_managed_path \"${CONFIG_ROOT}\"",
      "    ensure_managed_directory \"${CONFIG_ROOT}\" root root 755",
      "    ensure_managed_directory \"${CONFIG_ROOT}/credentials\" root root 700",
      "    install_controller_configs \"${release_dir}\"",
      "    if OPS_AGENT_TEST_FAIL_AT=config maybe_inject_install_failure config; then exit 98; else injected_status=$?; fi",
      "    [[ \"${injected_status}\" == 97 ]]",
      "    restore_managed_path_snapshot 0 ;;",
      "  *) exit 99 ;;",
      "esac",
    ].join("\n");

    const root = mkdtempSync(join(realpathSync(tmpdir()), "ops-agent-model-migration-"));
    const releaseDir = join(root, "release");
    const currentModels = repositoryFile("config/models.json");
    const currentAgentd = repositoryFile("config/agentd.json");
    const findmntFixture = join(root, "findmnt-fixture");
    mkdirSync(join(releaseDir, "config"), { recursive: true });
    writeFileSync(join(releaseDir, "config", "models.json"), currentModels, { mode: 0o640 });
    writeFileSync(join(releaseDir, "config", "agentd.json"), currentAgentd, { mode: 0o640 });
    writeFileSync(findmntFixture, [
      "#!/bin/bash",
      "[[ \"$*\" == \"--kernel --noheadings --raw --output TARGET\" ]] || exit 64",
      "printf '/\\n'",
    ].join("\n"), { mode: 0o755 });
    chmodSync(findmntFixture, 0o755);
    const run = (
      configRoot: string,
      action = "run",
      unsafePath = "",
    ): SpawnSyncReturns<string> => {
      const syncLog = join(root, `sync-${Math.random().toString(16).slice(2)}.log`);
      writeFileSync(syncLog, "");
      const transaction = join(root, `transaction-${Math.random().toString(16).slice(2)}`);
      return spawnSync(
        "/bin/bash",
        [
          "-c", harness, "config-loop", configRoot, releaseDir, unsafePath, syncLog,
          action, transaction, findmntFixture,
        ],
        { encoding: "utf8" },
      );
    };
    try {
      const freshRoot = join(root, "fresh");
      const fresh = run(freshRoot);
      expect(fresh.status, `${fresh.stdout}${fresh.stderr}`).toBe(0);
      expect(readFileSync(join(freshRoot, "models.json"), "utf8")).toBe(currentModels);
      expect(readFileSync(join(freshRoot, "agentd.json"), "utf8")).toBe(currentAgentd);
      expect(existsSync(join(freshRoot, "models.json.dist"))).toBe(false);
      expect(lstatSync(freshRoot).mode & 0o777).toBe(0o755);
      expect(lstatSync(join(freshRoot, "credentials")).mode & 0o777).toBe(0o700);

      const legacyRoot = join(root, "legacy");
      mkdirSync(join(legacyRoot, "credentials"), { recursive: true, mode: 0o700 });
      chmodSync(legacyRoot, 0o755);
      writeFileSync(join(legacyRoot, "models.json"), legacyDefault, { mode: 0o640 });
      const legacy = run(legacyRoot);
      expect(legacy.status, `${legacy.stdout}${legacy.stderr}`).toBe(0);
      expect(legacy.stdout).toContain("Migrated the unmodified legacy default models.json");
      expect(readFileSync(join(legacyRoot, "models.json"), "utf8")).toBe(currentModels);
      expect(readFileSync(join(legacyRoot, "models.json.dist"), "utf8")).toBe(currentModels);

      const customRoot = join(root, "custom");
      const customModels = `${legacyDefault} `;
      mkdirSync(join(customRoot, "credentials"), { recursive: true, mode: 0o700 });
      chmodSync(customRoot, 0o755);
      writeFileSync(join(customRoot, "models.json"), customModels, { mode: 0o640 });
      const custom = run(customRoot);
      expect(custom.status, `${custom.stdout}${custom.stderr}`).toBe(0);
      expect(readFileSync(join(customRoot, "models.json"), "utf8")).toBe(customModels);
      expect(readFileSync(join(customRoot, "models.json.dist"), "utf8")).toBe(currentModels);

      const hardlinkRoot = join(root, "hardlink");
      mkdirSync(join(hardlinkRoot, "credentials"), { recursive: true, mode: 0o700 });
      chmodSync(hardlinkRoot, 0o755);
      const hardlinkModels = join(hardlinkRoot, "models.json");
      writeFileSync(hardlinkModels, legacyDefault, { mode: 0o640 });
      linkSync(hardlinkModels, join(hardlinkRoot, "models-hardlink.json"));
      const hardlink = run(hardlinkRoot, "run", hardlinkModels);
      expect(hardlink.status).not.toBe(0);
      expect(hardlink.stderr).toContain("unsafe ownership, mode, or link count");
      expect(readFileSync(hardlinkModels, "utf8")).toBe(legacyDefault);
      expect(existsSync(join(hardlinkRoot, "models.json.dist"))).toBe(false);

      const symlinkRoot = join(root, "symlink-config");
      const symlinkReferent = join(root, "symlink-config-referent.json");
      mkdirSync(join(symlinkRoot, "credentials"), { recursive: true, mode: 0o700 });
      chmodSync(symlinkRoot, 0o755);
      writeFileSync(symlinkReferent, legacyDefault, { mode: 0o640 });
      symlinkSync(symlinkReferent, join(symlinkRoot, "models.json"));
      const symlinkConfig = run(symlinkRoot);
      expect(symlinkConfig.status).not.toBe(0);
      expect(symlinkConfig.stderr).toContain("regular non-symlink file");
      expect(readFileSync(symlinkReferent, "utf8")).toBe(legacyDefault);
      expect(existsSync(join(symlinkRoot, "models.json.dist"))).toBe(false);

      const rootReferent = join(root, "config-root-referent");
      const rootSymlink = join(root, "config-root-link");
      mkdirSync(rootReferent, { mode: 0o755 });
      writeFileSync(join(rootReferent, "sentinel"), "unchanged\n");
      const rootReferentMode = lstatSync(rootReferent).mode & 0o777;
      symlinkSync(rootReferent, rootSymlink);
      const unsafeRoot = run(rootSymlink, "ensure-root");
      expect(unsafeRoot.status).not.toBe(0);
      expect(unsafeRoot.stderr).toContain("not a real directory");
      expect(readdirSync(rootReferent)).toEqual(["sentinel"]);
      expect(readFileSync(join(rootReferent, "sentinel"), "utf8")).toBe("unchanged\n");
      expect(lstatSync(rootReferent).mode & 0o777).toBe(rootReferentMode);

      const wrongModeRoot = join(root, "wrong-mode-root");
      mkdirSync(wrongModeRoot, { mode: 0o755 });
      writeFileSync(join(wrongModeRoot, "sentinel"), "unchanged\n");
      const wrongMode = run(wrongModeRoot, "ensure-root", wrongModeRoot);
      expect(wrongMode.status).not.toBe(0);
      expect(wrongMode.stderr).toContain("unsafe ownership or mode");
      expect(readFileSync(join(wrongModeRoot, "sentinel"), "utf8")).toBe("unchanged\n");
      expect(existsSync(join(wrongModeRoot, "credentials"))).toBe(false);

      const credentialRoot = join(root, "credential-link-root");
      const credentialReferent = join(root, "credential-referent");
      mkdirSync(credentialRoot, { mode: 0o755 });
      mkdirSync(credentialReferent, { mode: 0o700 });
      writeFileSync(join(credentialReferent, "sentinel"), "unchanged\n");
      const credentialReferentMode = lstatSync(credentialReferent).mode & 0o777;
      symlinkSync(credentialReferent, join(credentialRoot, "credentials"));
      const unsafeCredentials = run(credentialRoot);
      expect(unsafeCredentials.status).not.toBe(0);
      expect(unsafeCredentials.stderr).toContain("not a real directory");
      expect(readdirSync(credentialReferent)).toEqual(["sentinel"]);
      expect(readFileSync(join(credentialReferent, "sentinel"), "utf8")).toBe("unchanged\n");
      expect(lstatSync(credentialReferent).mode & 0o777).toBe(credentialReferentMode);
      expect(existsSync(join(credentialRoot, "models.json"))).toBe(false);

      const wrongCredentialRoot = join(root, "wrong-credential-owner");
      const wrongCredentialPath = join(wrongCredentialRoot, "credentials");
      mkdirSync(wrongCredentialPath, { recursive: true, mode: 0o700 });
      chmodSync(wrongCredentialRoot, 0o755);
      writeFileSync(join(wrongCredentialPath, "sentinel"), "unchanged\n");
      const wrongCredential = run(wrongCredentialRoot, "run", wrongCredentialPath);
      expect(wrongCredential.status).not.toBe(0);
      expect(wrongCredential.stderr).toContain("unsafe ownership or mode");
      expect(readFileSync(join(wrongCredentialPath, "sentinel"), "utf8"))
        .toBe("unchanged\n");
      expect(existsSync(join(wrongCredentialRoot, "models.json"))).toBe(false);

      const rollbackRoot = join(root, "rollback");
      const oldAgentd = '{"custom":true}\n';
      mkdirSync(join(rollbackRoot, "credentials"), { recursive: true, mode: 0o700 });
      chmodSync(rollbackRoot, 0o755);
      writeFileSync(join(rollbackRoot, "credentials", "sentinel"), "secret-state\n", { mode: 0o600 });
      writeFileSync(join(rollbackRoot, "agentd.json"), oldAgentd, { mode: 0o640 });
      writeFileSync(join(rollbackRoot, "models.json"), legacyDefault, { mode: 0o640 });
      const beforeRoot = lstatSync(rollbackRoot);
      const beforeModels = lstatSync(join(rollbackRoot, "models.json"));
      const rollback = run(rollbackRoot, "rollback");
      expect(rollback.status, `${rollback.stdout}${rollback.stderr}`).toBe(0);
      expect(rollback.stderr).toContain("Injected install failure after stage config");
      expect(readFileSync(join(rollbackRoot, "agentd.json"), "utf8")).toBe(oldAgentd);
      expect(readFileSync(join(rollbackRoot, "models.json"), "utf8")).toBe(legacyDefault);
      expect(readFileSync(join(rollbackRoot, "credentials", "sentinel"), "utf8"))
        .toBe("secret-state\n");
      expect(existsSync(join(rollbackRoot, "agentd.json.dist"))).toBe(false);
      expect(existsSync(join(rollbackRoot, "models.json.dist"))).toBe(false);
      const afterRoot = lstatSync(rollbackRoot);
      const afterModels = lstatSync(join(rollbackRoot, "models.json"));
      expect([afterRoot.uid, afterRoot.gid, afterRoot.mode & 0o777])
        .toEqual([beforeRoot.uid, beforeRoot.gid, beforeRoot.mode & 0o777]);
      expect([afterModels.uid, afterModels.gid, afterModels.mode & 0o777])
        .toEqual([beforeModels.uid, beforeModels.gid, beforeModels.mode & 0o777]);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("refuses mounts below every snapshotted path before copy and rollback deletion", () => {
    const installer = repositoryFile("scripts/install-release.sh");
    const bashFunction = (name: string): string => {
      const match = installer.match(new RegExp(
        `^${name}\\(\\) \\{\\n[\\s\\S]*?^\\}\\n`,
        "mu",
      ));
      expect(match?.[0], `${name} must be a top-level executable helper`).toBeDefined();
      if (match?.[0] === undefined) throw new Error(`missing ${name}`);
      return match[0];
    };
    const mountGuard = bashFunction("refuse_mounts_at_or_below_managed_path");
    const snapshot = bashFunction("snapshot_managed_path");
    const restore = bashFunction("restore_managed_path_snapshot");
    const begin = bashFunction("begin_install_transaction");
    expect(installer).toContain('readonly FINDMNT_BIN="/bin/findmnt"');
    expect(installer).toContain(
      `[[ "$(stat -c '%U:%G:%a:%h' "\${FINDMNT_BIN}")" != "root:root:755:1" ]]`,
    );
    expect(mountGuard).toContain(
      '"${FINDMNT_BIN}" \\\n      --kernel --noheadings --raw --output TARGET',
    );
    expect(mountGuard).not.toContain("--list");
    expect(mountGuard).toContain('[[ "${target}" == / ]]');
    expect(mountGuard).toContain('"${path}"|"${path}/"*');
    expect(snapshot.indexOf("refuse_mounts_at_or_below_managed_path"))
      .toBeLessThan(snapshot.indexOf("cp -a --no-dereference"));
    expect(snapshot).not.toContain('"${path}" == "${CONFIG_ROOT}"');
    expect(restore.indexOf("refuse_mounts_at_or_below_managed_path"))
      .toBeLessThan(restore.indexOf('remove_managed_path "${path}"'));
    expect(restore).not.toContain('"${path}" == "${CONFIG_ROOT}"');
    expect(begin.indexOf('refuse_mounts_at_or_below_managed_path "${CONFIG_ROOT}"'))
      .toBeLessThan(begin.indexOf('snapshot_managed_path "${CONFIG_ROOT}"'));
    const beginCall = installer.indexOf("\nbegin_install_transaction\n");
    const preflightCall = installer.lastIndexOf(
      '\nrefuse_mounts_at_or_below_managed_path "${CONFIG_ROOT}"\n',
      beginCall,
    );
    expect(preflightCall).toBeGreaterThan(0);
    expect(preflightCall).toBeLessThan(beginCall);

    const root = mkdtempSync(join(realpathSync(tmpdir()), "ops-agent-mount-guard-"));
    const findmntFixture = join(root, "findmnt-fixture");
    writeFileSync(findmntFixture, [
      "#!/bin/bash",
      "[[ \"$*\" == \"--kernel --noheadings --raw --output TARGET\" ]] || exit 64",
      "[[ \"${FINDMNT_TEST_MODE:-ok}\" != fail ]] || exit 42",
      "printf '%s' \"${FINDMNT_TEST_INVENTORY:-}\"",
    ].join("\n"), { mode: 0o755 });
    chmodSync(findmntFixture, 0o755);
    const managedPath = "/etc/ops-agent";
    const runGuard = (
      inventory: string,
      mode = "ok",
      path = managedPath,
    ): SpawnSyncReturns<string> => spawnSync(
      "/bin/bash",
      [
        "-c",
        [
          "set -euo pipefail",
          'CONFIG_ROOT="$1"',
          'FINDMNT_BIN="$2"',
          mountGuard,
          'refuse_mounts_at_or_below_managed_path "${CONFIG_ROOT}"',
        ].join("\n"),
        "mount-guard",
        path,
        findmntFixture,
      ],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          FINDMNT_TEST_INVENTORY: inventory,
          FINDMNT_TEST_MODE: mode,
        },
      },
    );
    try {
      for (const inventory of [
        "/\n",
        "/\n/etc\n",
        "/\n/etc/ops-agent-old\n",
      ]) {
        const allowed = runGuard(inventory);
        expect(allowed.status, `${allowed.stdout}${allowed.stderr}`).toBe(0);
      }
      for (const target of [
        managedPath,
        `${managedPath}/credentials`,
        `${managedPath}/models.json`,
      ]) {
        const refused = runGuard(`/\n${target}\n`);
        expect(refused.status).not.toBe(0);
        expect(refused.stderr).toContain("is at or below it");
      }
      const queryFailure = runGuard("/\n", "fail");
      expect(queryFailure.status).not.toBe(0);
      expect(queryFailure.stderr).toContain("Could not query kernel mount targets");
      const empty = runGuard("");
      expect(empty.status).not.toBe(0);
      expect(empty.stderr).toContain("inventory is empty");
      const noNamespaceRoot = runGuard("/proc\n/sys\n");
      expect(noNamespaceRoot.status).not.toBe(0);
      expect(noNamespaceRoot.stderr).toContain("inventory is incomplete");

      const pluginRegistry = "/var/lib/ops-agent/plugins";
      const unrelatedPluginPrefix = runGuard(
        "/\n/var/lib/ops-agent/plugins-old\n",
        "ok",
        pluginRegistry,
      );
      expect(
        unrelatedPluginPrefix.status,
        `${unrelatedPluginPrefix.stdout}${unrelatedPluginPrefix.stderr}`,
      ).toBe(0);
      for (const target of [pluginRegistry, `${pluginRegistry}/sha256/deadbeef`]) {
        const refusedPluginMount = runGuard(`/\n${target}\n`, "ok", pluginRegistry);
        expect(refusedPluginMount.status).not.toBe(0);
        expect(refusedPluginMount.stderr).toContain("is at or below it");
      }

      const snapshotMarker = join(root, "snapshot-write-called");
      const guardedSnapshot = spawnSync(
        "/bin/bash",
        [
          "-c",
          [
            "set -euo pipefail",
            'CONFIG_ROOT="$1"',
            'FINDMNT_BIN="$2"',
            'INSTALL_TRANSACTION_DIR="$3"',
            'SNAPSHOT_MARKER="$4"',
            "TRANSACTION_PATHS=()",
            "TRANSACTION_PATH_STATES=()",
            'install() { : >"${SNAPSHOT_MARKER}"; }',
            'cp() { : >"${SNAPSHOT_MARKER}"; }',
            mountGuard,
            snapshot,
            'snapshot_managed_path "${CONFIG_ROOT}"',
          ].join("\n"),
          "mount-snapshot",
          managedPath,
          findmntFixture,
          join(root, "snapshot-scratch"),
          snapshotMarker,
        ],
        {
          encoding: "utf8",
          env: {
            ...process.env,
            FINDMNT_TEST_INVENTORY: `/\n${managedPath}/models.json\n`,
          },
        },
      );
      expect(guardedSnapshot.status).not.toBe(0);
      expect(guardedSnapshot.stderr).toContain("is at or below it");
      expect(existsSync(snapshotMarker)).toBe(false);

      const rollbackScratch = join(root, "rollback-scratch");
      const runGuardedRestore = (
        path: string,
        inventory: string,
        deleteMarker: string,
      ): SpawnSyncReturns<string> => spawnSync(
        "/bin/bash",
        [
          "-c",
          [
            "set -euo pipefail",
            'CONFIG_ROOT="$1"',
            'FINDMNT_BIN="$2"',
            'INSTALL_TRANSACTION_DIR="$3"',
            'DELETE_MARKER="$4"',
            'TRANSACTION_PATHS=("${CONFIG_ROOT}")',
            "TRANSACTION_PATH_STATES=(present)",
            "INSTALL_TRANSACTION_ROLLBACK_FAILED=false",
            "record_rollback_error() {",
            "  printf 'Rollback warning: %s\\n' \"$1\" >&2",
            "  INSTALL_TRANSACTION_ROLLBACK_FAILED=true",
            "}",
            'remove_managed_path() { : >"${DELETE_MARKER}"; }',
            mountGuard,
            restore,
            "restore_managed_path_snapshot 0",
            '[[ "${INSTALL_TRANSACTION_ROLLBACK_FAILED}" == true ]]',
            '[[ ! -e "${DELETE_MARKER}" ]]',
          ].join("\n"),
          "mount-restore",
          path,
          findmntFixture,
          rollbackScratch,
          deleteMarker,
        ],
        {
          encoding: "utf8",
          env: {
            ...process.env,
            FINDMNT_TEST_INVENTORY: inventory,
          },
        },
      );
      const configDeleteMarker = join(root, "config-delete-called");
      const guardedConfigRestore = runGuardedRestore(
        managedPath,
        `/\n${managedPath}/credentials\n`,
        configDeleteMarker,
      );
      expect(
        guardedConfigRestore.status,
        `${guardedConfigRestore.stdout}${guardedConfigRestore.stderr}`,
      ).toBe(0);
      expect(guardedConfigRestore.stderr).toContain("Rollback warning");
      expect(existsSync(configDeleteMarker)).toBe(false);

      const pluginDeleteMarker = join(root, "plugin-delete-called");
      const guardedPluginRestore = runGuardedRestore(
        pluginRegistry,
        `/\n${pluginRegistry}/sha256/deadbeef\n`,
        pluginDeleteMarker,
      );
      expect(
        guardedPluginRestore.status,
        `${guardedPluginRestore.stdout}${guardedPluginRestore.stderr}`,
      ).toBe(0);
      expect(guardedPluginRestore.stderr).toContain("Rollback warning");
      expect(existsSync(pluginDeleteMarker)).toBe(false);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("keeps join endpoints server-and-broker-only", () => {
    const installer = repositoryFile("scripts/install-release.sh");
    const packager = repositoryFile("packaging/build-release.sh");
    const endpointTmpfiles = repositoryFile("systemd/ops-agent-endpoint.tmpfiles.conf");
    const healthcheck = repositoryFile("scripts/healthcheck.sh");
    const enrollment = repositoryFile("internal/enrollment/enrollment.go");

    expect(installer).toContain('TRANSACTION_USERS=("${SERVER_USER}")');
    expect(installer).toContain('TRANSACTION_GROUPS=("${SERVER_GROUP}")');
    expect(installer).not.toMatch(
      /\b(?:apt-get|dnf|yum|zypper|pacman)\b/u,
    );
    expect(installer).toContain("Missing installation dependency");
    expect(packager).toContain(
      "Depends: bash, ca-certificates, systemd, openssl, diffutils",
    );
    expect(packager).not.toMatch(/^Depends:.*(?:bubblewrap|sudo)/mu);
    expect(installer).toContain(
      'ops-agent-server.service|ops-root-helper.service) ;;',
    );
    expect(installer).toContain(
      'tmpfiles_source="${release_dir}/systemd/ops-agent-endpoint.tmpfiles.conf"',
    );
    expect(installer).toContain('"${CURRENT_LINK}/scripts/healthcheck.sh" --endpoint');
    expect(installer).toContain('snapshot_managed_path "${CONFIG_ROOT}"');
    expect(installer).toContain("maybe_inject_install_failure config");
    expect(endpointTmpfiles).toContain("/var/lib/ops-agent/root-helper");
    expect(endpointTmpfiles).not.toMatch(/agentd|reviewer|plugin|adapter|credential/u);
    expect(healthcheck).toContain('if [[ "${ENDPOINT}" == true ]]; then');
    expect(healthcheck).toContain(
      "endpoint-enrollment /etc/ops-agent/endpoint-enrollment.json root:ops-agent-server:640",
    );
    expect(healthcheck).toContain(
      "core-receipt-public /etc/ops-agent/broker-receipts/core-public.pem root:ops-agent-server:640",
    );
    expect(enrollment).toContain(
      'options.ReceiptPublicGroup = "ops-agent-server"',
    );
  });

  it("waits for every committed join broker to become active and publish its socket", () => {
    const installer = repositoryFile("scripts/install-release.sh");
    const helperMatch = installer.match(
      /wait_for_committed_endpoint_socket\(\) \{\n(?<body>[\s\S]*?)\n\}\n\nusage\(\)/u,
    );
    const helperBody = helperMatch?.groups?.body;
    expect(helperBody).toBeDefined();
    if (helperBody === undefined) throw new Error("endpoint readiness helper is missing");

    expect(helperBody).toContain('while [[ ! -S "${socket_path}" ]] && ((socket_attempt < 100)); do');
    expect(helperBody).toContain('systemctl is-active --quiet "${unit}"');
    expect(helperBody).toContain("sleep 0.1");
    expect(helperBody).toContain("Endpoint install committed");

    const joinStart = installer.indexOf(
      'if [[ "${MODE}" == join ]]; then\n  join_units=(',
    );
    const joinEnd = installer.indexOf(
      "\nsystemctl enable ops-agent.target ops-agent-healthcheck.timer",
      joinStart,
    );
    expect(joinStart).toBeGreaterThan(0);
    expect(joinEnd).toBeGreaterThan(joinStart);
    const joinActivation = installer.slice(joinStart, joinEnd);
    const coreReadiness = joinActivation.indexOf(
      'wait_for_committed_endpoint_socket \\\n      "core broker" ops-root-helper.service /run/ops-agent/helper/root-helper.sock',
    );
    const pveGuard = joinActivation.indexOf(
      'if [[ "${PVE_ENDPOINT}" == true ]]; then',
      coreReadiness,
    );
    const pveReadiness = joinActivation.indexOf(
      'wait_for_committed_endpoint_socket \\\n        "PVE broker" ops-pve-root-helper.service /run/ops-agent/helper/pve-root-helper.sock',
      pveGuard,
    );
    const serverReadiness = joinActivation.indexOf(
      "systemctl is-active --quiet ops-agent-server.service",
      pveReadiness,
    );
    const healthcheck = joinActivation.indexOf(
      '"${CURRENT_LINK}/scripts/healthcheck.sh" --endpoint',
      serverReadiness,
    );
    expect(coreReadiness).toBeGreaterThan(0);
    expect(pveGuard).toBeGreaterThan(coreReadiness);
    expect(pveReadiness).toBeGreaterThan(pveGuard);
    expect(serverReadiness).toBeGreaterThan(pveReadiness);
    expect(healthcheck).toBeGreaterThan(serverReadiness);
    expect(joinActivation).not.toContain("socket_attempt=");

    const verification = spawnSync(
      "/bin/bash",
      [
        "-c",
        [
          "set -euo pipefail",
          "wait_for_committed_endpoint_socket() {",
          helperBody,
          "}",
          'socket_path="${TMPDIR:-/tmp}/ops-agent-readiness-$$.sock"',
          '[[ ! -e "${socket_path}" ]]',
          "sleep_calls=0",
          "systemctl() { [[ \"$1\" == is-active && \"$2\" == --quiet && \"$3\" == ops-root-helper.service ]]; }",
          "sleep() { sleep_calls=$((sleep_calls + 1)); }",
          'diagnostic_file="$(mktemp)"',
          'trap \'rm -f -- "${diagnostic_file}"\' EXIT',
          "set +e",
          'wait_for_committed_endpoint_socket "core broker" ops-root-helper.service "${socket_path}" 2>"${diagnostic_file}"',
          "status=$?",
          "set -e",
          '[[ "${status}" -eq 1 ]]',
          '[[ "${sleep_calls}" -eq 100 ]]',
          "grep -F 'Endpoint install committed, but the core broker did not become ready' \"${diagnostic_file}\"",
          "sleep_calls=0",
          "systemctl() { return 1; }",
          ": >\"${diagnostic_file}\"",
          "set +e",
          'wait_for_committed_endpoint_socket "core broker" ops-root-helper.service "${socket_path}" 2>"${diagnostic_file}"',
          "status=$?",
          "set -e",
          '[[ "${status}" -eq 1 ]]',
          '[[ "${sleep_calls}" -eq 0 ]]',
          "grep -F 'ops-root-helper.service is not active while waiting for its runtime socket' \"${diagnostic_file}\"",
        ].join("\n"),
      ],
      { encoding: "utf8" },
    );
    expect(verification.status, `${verification.stdout}${verification.stderr}`).toBe(0);
  });

  it("waits for the private agent backend and a new heartbeat generation", () => {
    const installer = repositoryFile("scripts/install-release.sh");
    const verifierMatch = installer.match(
      /verify_committed_agentd_generation\(\) \{\n(?<body>[\s\S]*?)\n\}\n\nwait_for_committed_controller_generation/u,
    );
    const verifierBody = verifierMatch?.groups?.body;
    expect(verifierBody).toBeDefined();
    if (verifierBody === undefined) throw new Error("agentd generation verifier is missing");
    const helperMatch = installer.match(
      /wait_for_committed_controller_generation\(\) \{\n(?<body>[\s\S]*?)\n\}\n\nwait_for_committed_endpoint_socket/u,
    );
    const helperBody = helperMatch?.groups?.body;
    expect(helperBody).toBeDefined();
    if (helperBody === undefined) throw new Error("controller readiness helper is missing");

    expect(installer).toContain('readonly READINESS_TIMEOUT_BIN="/usr/bin/timeout"');
    expect(helperBody).toContain('while ((readiness_attempt < 100)); do');
    expect(verifierBody).toContain('"${READINESS_TIMEOUT_BIN}" --kill-after=1s 2s');
    expect(verifierBody).toContain(
      "systemctl show --property=MainPID --value ops-agentd.service",
    );
    expect(helperBody.match(/verify_committed_agentd_generation/gu)).toHaveLength(2);
    expect(helperBody).toContain("current_heartbeat_identity");
    expect(helperBody).toContain("baseline_heartbeat_identity");
    expect(helperBody).toContain("sleep 0.1");
    expect(helperBody).toContain("heartbeat for the new process generation");
    expect(helperBody).not.toContain("healthcheck.sh");

    const activationStart = installer.indexOf(
      '\nif [[ "${START_NOW}" == true ]]; then\n  if ! systemctl restart ops-agent.target',
    );
    const actualActivationStart = installer.indexOf(
      '\nif [[ "${START_NOW}" == true ]]; then\n  controller_heartbeat=',
    );
    const activationEnd = installer.indexOf(
      '\nprintf \'%s\\n\' \\\n  "Pi Ops Agent ${release_version}',
      actualActivationStart,
    );
    expect(activationStart).toBe(-1);
    expect(actualActivationStart).toBeGreaterThan(0);
    expect(activationEnd).toBeGreaterThan(actualActivationStart);
    const activation = installer.slice(actualActivationStart, activationEnd);
    const restart = activation.indexOf("systemctl restart ops-agent.target");
    const mainPid = activation.indexOf("agentd_main_pid=", restart);
    const baseline = activation.indexOf("controller_heartbeat_baseline=absent", mainPid);
    const publicSocket = activation.indexOf("/run/ops-agent/agentd/agentd.sock");
    const backendSocket = activation.indexOf("/run/ops-agent/agentd/backend.sock");
    const readiness = activation.indexOf("wait_for_committed_controller_generation");
    const finalHealth = activation.indexOf('"${CURRENT_LINK}/scripts/healthcheck.sh"');
    const finalGeneration = activation.indexOf(
      'verify_committed_agentd_generation "${agentd_main_pid}"',
      finalHealth,
    );
    expect(restart).toBeGreaterThan(0);
    expect(mainPid).toBeGreaterThan(restart);
    expect(baseline).toBeGreaterThan(mainPid);
    expect(publicSocket).toBeGreaterThan(0);
    expect(backendSocket).toBeGreaterThan(publicSocket);
    expect(readiness).toBeGreaterThan(backendSocket);
    expect(finalHealth).toBeGreaterThan(readiness);
    expect(finalGeneration).toBeGreaterThan(finalHealth);
    expect(activation.match(/scripts\/healthcheck\.sh/gu)).toHaveLength(1);
    expect(activation.slice(readiness, finalHealth)).not.toContain("healthcheck.sh");
    expect(activation).toContain(
      '"${READINESS_TIMEOUT_BIN}" --kill-after=5s 60s \\\n      systemctl restart ops-agent.target ops-agent-healthcheck.timer',
    );
    expect(activation).toContain(
      '"${READINESS_TIMEOUT_BIN}" --kill-after=5s 60s \\\n    "${CURRENT_LINK}/scripts/healthcheck.sh"',
    );

    const root = mkdtempSync(join(tmpdir(), "ops-agent-controller-readiness-"));
    try {
      const binaryRoot = join(root, "bin");
      const timeout = join(binaryRoot, "timeout");
      const systemctl = join(binaryRoot, "systemctl");
      const heartbeat = join(root, "heartbeat.json");
      const pidState = join(root, "pid-state");
      mkdirSync(binaryRoot, { recursive: true });
      writeFileSync(
        timeout,
        [
          "#!/bin/sh",
          'test "$1" = --kill-after=1s',
          'test "$2" = 2s',
          "shift 2",
          'exec "$@"',
        ].join("\n") + "\n",
        "utf8",
      );
      writeFileSync(
        systemctl,
        [
          "#!/bin/sh",
          'test "${OPS_AGENT_SYSTEMCTL_FAIL:-0}" = 0 || exit 1',
          'test "$1" = show',
          'test "$2" = --property=MainPID',
          'test "$3" = --value',
          'test "$4" = ops-agentd.service',
          'exec /bin/cat "${OPS_AGENT_PID_STATE}"',
        ].join("\n") + "\n",
        "utf8",
      );
      chmodSync(timeout, 0o755);
      chmodSync(systemctl, 0o755);
      writeFileSync(heartbeat, "old heartbeat\n", "utf8");
      writeFileSync(pidState, "1234\n", "utf8");
      const verification = spawnSync(
        "/bin/bash",
        [
          "-c",
          [
            "set -euo pipefail",
            "verify_committed_agentd_generation() {",
            verifierBody,
            "}",
            "wait_for_committed_controller_generation() {",
            helperBody,
            "}",
            'READINESS_TIMEOUT_BIN="$1/bin/timeout"',
            'PATH="$1/bin:${PATH}"',
            'heartbeat_path="$2"',
            'export OPS_AGENT_PID_STATE="$3"',
            "identity=old",
            "drift_on_new=0",
            "sleep_calls=0",
            'diagnostic_file="$(mktemp)"',
            'trap \'rm -f -- "${diagnostic_file}"\' EXIT',
            'stat() { if [[ "${identity}" == new && "${drift_on_new}" -eq 1 ]]; then printf \'5678\\n\' >"${OPS_AGENT_PID_STATE}"; fi; printf \'%s\\n\' "${identity}"; }',
            'sleep() { sleep_calls=$((sleep_calls + 1)); if [[ "${sleep_calls}" -eq 2 ]]; then identity=new; fi; }',
            'wait_for_committed_controller_generation 1234 old "${heartbeat_path}"',
            '[[ "${sleep_calls}" -eq 2 ]]',
            'printf \'1234\\n\' >"${OPS_AGENT_PID_STATE}"',
            "identity=old",
            "drift_on_new=1",
            "sleep_calls=0",
            ': >"${diagnostic_file}"',
            "set +e",
            'wait_for_committed_controller_generation 1234 old "${heartbeat_path}" 2>"${diagnostic_file}"',
            "status=$?",
            "set -e",
            '[[ "${status}" -eq 1 ]]',
            '[[ "${sleep_calls}" -eq 2 ]]',
            "grep -F 'changed generation while becoming ready' \"${diagnostic_file}\"",
            "drift_on_new=0",
            'printf \'5678\\n\' >"${OPS_AGENT_PID_STATE}"',
            "sleep_calls=0",
            ': >"${diagnostic_file}"',
            "set +e",
            'wait_for_committed_controller_generation 1234 old "${heartbeat_path}" 2>"${diagnostic_file}"',
            "status=$?",
            "set -e",
            '[[ "${status}" -eq 1 ]]',
            '[[ "${sleep_calls}" -eq 0 ]]',
            "grep -F 'changed generation while becoming ready' \"${diagnostic_file}\"",
            'printf \'1234\\n\' >"${OPS_AGENT_PID_STATE}"',
            "identity=old",
            "sleep_calls=0",
            'sleep() { sleep_calls=$((sleep_calls + 1)); }',
            ': >"${diagnostic_file}"',
            "set +e",
            'wait_for_committed_controller_generation 1234 old "${heartbeat_path}" 2>"${diagnostic_file}"',
            "status=$?",
            "set -e",
            '[[ "${status}" -eq 1 ]]',
            '[[ "${sleep_calls}" -eq 100 ]]',
            "grep -F 'heartbeat for the new process generation' \"${diagnostic_file}\"",
            "export OPS_AGENT_SYSTEMCTL_FAIL=1",
            "sleep_calls=0",
            ': >"${diagnostic_file}"',
            "set +e",
            'wait_for_committed_controller_generation 1234 old "${heartbeat_path}" 2>"${diagnostic_file}"',
            "status=$?",
            "set -e",
            '[[ "${status}" -eq 1 ]]',
            '[[ "${sleep_calls}" -eq 0 ]]',
            "grep -F 'PID 1 did not answer the bounded agentd readiness query' \"${diagnostic_file}\"",
          ].join("\n"),
          "controller-readiness",
          root,
          heartbeat,
          pidState,
        ],
        { encoding: "utf8" },
      );
      expect(verification.status, `${verification.stdout}${verification.stderr}`).toBe(0);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("installs the JSON config helper as one transactionally managed root-owned executable", () => {
    const installer = repositoryFile("scripts/install-release.sh");
    const uninstaller = repositoryFile("scripts/uninstall.sh");
    const healthcheck = repositoryFile("scripts/healthcheck.sh");

    expect(installer).toContain(
      'readonly JSON_CONFIG_HELPER="/usr/lib/ops-agent/agentd-json-config-helper"',
    );
    expect(installer).toContain('snapshot_managed_path "${JSON_CONFIG_HELPER}"');
    expect(installer).toContain(
      'install -o root -g root -m 0755 "${json_config_helper_source}" "${JSON_CONFIG_HELPER}"',
    );
    expect(installer).toContain(
      'cmp -s "${json_config_helper_source}" "${JSON_CONFIG_HELPER}"',
    );
    expect(uninstaller).toContain('rm -f -- "${JSON_CONFIG_HELPER}"');
    expect(healthcheck).toContain(
      "check_metadata json-config-helper /usr/lib/ops-agent/agentd-json-config-helper root:root:755",
    );
  });

  it("rolls init back when the mandatory Source Workload sandbox is unavailable", () => {
    const installer = repositoryFile("scripts/install-release.sh");
    const sandbox = repositoryFile("src/agentd/sandbox.ts");
    const preflightStart = installer.indexOf("run_bwrap_service_preflight() (");
    const preflightEnd = installer.indexOf(
      '\nif [[ "${MODE}" == init ]]; then',
      preflightStart,
    );
    const preflight = installer.slice(preflightStart, preflightEnd);

    expect(preflightStart).toBeGreaterThan(0);
    expect(preflightEnd).toBeGreaterThan(preflightStart);
    expect(preflight).toContain(
      "mktemp /run/systemd/system/ops-agent-bwrap-probe-XXXXXX.service",
    );
    expect(preflight).toContain(
      'bwrap_probe_security_dropin="${bwrap_probe_dropin_dir}/zzzz-ops-agent-security.conf"',
    );
    expect(preflight).toContain(
      'bwrap_probe_lifecycle_dropin="${bwrap_probe_dropin_dir}/zzzz-ops-agent-zz-preflight.conf"',
    );
    expect(preflight).toContain(
      '"${bwrap_probe_security_dropin}"',
    );
    expect(preflight).toContain(
      'cmp -s "${agentd_security_dropin}" "${bwrap_probe_security_dropin}"',
    );
    expect(preflight).toContain(
      'bwrap_probe_driver="/run/systemd/system/${bwrap_probe_unit%.service}-driver"',
    );
    expect(preflight).toContain(
      "mktemp /run/ops-agent/agentd/.install-bwrap-probe-XXXXXX.nonce",
    );
    expect(preflight).not.toContain("systemd-run");
    expect(preflight).not.toContain('--property="User=');
    expect(preflight).toContain("Type=exec");
    expect(preflight).toContain("ExitType=cgroup");
    expect(preflight).toContain("RemainAfterExit=no");
    expect(preflight).toContain("Restart=no");
    expect(preflight).toContain("TimeoutStartSec=10s");
    expect(preflight).toContain("RuntimeMaxSec=30s");
    expect(preflight).toContain("TimeoutStopSec=10s");
    expect(preflight).toContain("KillMode=control-group");
    expect(preflight).toContain(
      "--unshare-user --unshare-ipc --unshare-pid --unshare-net",
    );
    expect(preflight).toContain("--die-with-parent --sync-fd 1");
    expect(preflight).toContain("--cap-drop ALL --bind / / --dev /dev --proc /proc");
    expect(preflight).toContain("--as-pid-1 --disable-userns --cap-drop ALL");
    expect(preflight).toContain(
      "--ro-bind / / --bind ${bwrap_probe_nonce} ${bwrap_probe_nonce} --proc /proc --dev /dev --clearenv",
    );
    expect(preflight).not.toContain("--unshare-uts");
    expect(preflight).not.toContain("--unshare-cgroup");
    expect(preflight).toContain('[ "\\$\\$" -eq 1 ]');
    expect(preflight).toContain("no systemd dollar");
    expect(installer).not.toContain("userns_limit");
    expect(installer).toContain("--disable-userns performs the authoritative postcondition");
    expect(installer).toContain("CLONE_NEWUSER");
    expect(preflight).toContain("/bin/sleep 300 &");
    expect(installer).toContain(
      'agentd_security_dropin="${UNIT_ROOT}/ops-agentd.service.d/zzzz-ops-agent-security.conf"',
    );
    expect(installer).toContain("grep -Fxc 'ProcSubset=all'");
    expect(installer).not.toContain("sed -i 's/^ProcSubset=pid$/ProcSubset=all/'");
    expect(installer).toContain("type-wide service drop-ins");
    expect(installer).toContain("zzz-lxc-service.conf");
    expect(preflight).toContain('"ProcSubset=all"');
    for (const hardening of [
      "NoNewPrivileges=yes",
      "PrivateDevices=yes",
      "ProtectKernelTunables=yes",
      "ProtectKernelModules=yes",
      "ProtectKernelLogs=yes",
      "ProtectControlGroups=yes",
      "ProtectClock=yes",
      "ProtectHostname=yes",
      "ProtectProc=invisible",
      "CapabilityBoundingSet=",
    ]) {
      expect(preflight).toContain(`"${hardening}"`);
    }
    expect(preflight).toContain(
      'require_pid1_unit_property ops-agentd.service "${property}" "${expected}"',
    );
    expect(preflight).toContain(
      'require_pid1_unit_property "${bwrap_probe_unit}" "${property}" "${expected}"',
    );
    expect(preflight).toContain("equivalent_effective_properties");
    expect(preflight).toContain("fixed_effective_word_sets");
    expect(preflight).toContain('"RestrictNamespaces=user ipc net mnt pid"');
    expect(preflight).toContain(
      '"SupplementaryGroups=ops-agent-client"',
    );
    expect(preflight).toContain('"CapabilityBoundingSet="');
    expect(preflight).toContain('"ReadWritePaths=/run/ops-agent/agentd');
    expect(preflight).toContain('"ReadOnlyPaths=/opt/pi-ops-agent /etc/ops-agent"');
    expect(preflight).toContain(
      '"InaccessiblePaths=-/run/ops-agent/helper -/etc/ops-agent/workloads',
    );
    expect(preflight).toContain(
      'require_pid1_unit_word_sets_equal ops-agentd.service "${bwrap_probe_unit}"',
    );
    for (const [property, value] of [
      ["Type", "exec"],
      ["ExitType", "cgroup"],
      ["KillMode", "control-group"],
      ["RemainAfterExit", "no"],
      ["Restart", "no"],
      ["TimeoutStartUSec", "10s"],
      ["RuntimeMaxUSec", "30s"],
      ["TimeoutStopUSec", "10s"],
    ]) {
      expect(preflight).toContain(
        `require_pid1_unit_property "\${bwrap_probe_unit}" ${property} ${value}`,
      );
    }
    for (const emptyProperty of [
      "ExecCondition",
      "ExecStartPre",
      "ExecStartPost",
    ]) {
      expect(preflight).toContain(
        `require_pid1_unit_property "\${bwrap_probe_unit}" ${emptyProperty} ''`,
      );
    }
    expect(preflight).toContain(
      'require_pid1_unit_exec_start "${bwrap_probe_unit}" "${bwrap_probe_driver}"',
    );
    expect(preflight).toContain('pid1_unit_property "${unit}" ExecStartEx');
    expect(preflight).toContain('flags= ;');
    expect(preflight).toContain(
      'require_pid1_unit_property ops-agentd.service FragmentPath',
    );
    for (const finalProperty of [
      "Type simple",
      "ExitType main",
      "KillMode control-group",
      "Restart always",
      "TimeoutStopUSec 20s",
      "WorkingDirectory /var/lib/ops-agent",
      "ExecCondition ''",
      "ExecStartPre ''",
      "ExecStartPost ''",
      "EnvironmentFiles ''",
    ]) {
      expect(preflight).toContain(
        `require_pid1_unit_property ops-agentd.service ${finalProperty}`,
      );
    }
    expect(preflight).toContain(
      "'NODE_ENV=production OPS_AGENT_CONFIG=/etc/ops-agent/agentd.json'",
    );
    expect(preflight).toContain(
      "'/opt/pi-ops-agent/current/runtime/node /opt/pi-ops-agent/current/dist/agentd/index.js'",
    );
    expect(preflight).toContain('systemctl start "${bwrap_probe_unit}"');
    expect(preflight).toContain("print_bwrap_probe_diagnostics()");
    expect(preflight).toContain(
      "kernel.apparmor_restrict_unprivileged_userns",
    );
    expect(preflight).toContain("--lines=32 --output=cat");
    expect(preflight).toContain("[probe journal truncated at 8192 bytes]");
    expect(preflight).toContain(
      'require_pid1_unit_property "${bwrap_probe_unit}" Result success',
    );
    expect(preflight).toContain(
      'require_pid1_unit_property "${bwrap_probe_unit}" ExecMainStatus 0',
    );
    expect(preflight).toContain("local terminal_state_valid=true");
    expect(preflight).toContain('if [[ "${terminal_state_valid}" != true ]]');
    expect(installer).toContain("bwrap_preflight_status=0");
    expect(installer).toContain("set +e\n  run_bwrap_service_preflight");
    expect(installer).not.toContain("if ! run_bwrap_service_preflight");
    expect(preflight).toContain('systemctl stop "${bwrap_probe_unit}"');
    expect(preflight).toContain('systemctl reset-failed "${bwrap_probe_unit}"');
    expect(preflight).toContain('rm -f -- "${bwrap_probe_lifecycle_dropin}"');
    expect(preflight).toContain('rm -f -- "${bwrap_probe_security_dropin}"');
    expect(preflight).toContain('rmdir -- "${bwrap_probe_dropin_dir}"');
    expect(preflight).toContain('rm -f -- "${bwrap_probe_unit_path}"');
    expect(preflight).toContain('rm -f -- "${bwrap_probe_driver}"');
    expect(preflight).toContain('rm -f -- "${bwrap_probe_nonce}"');
    expect(preflight).toContain('load_state_status=$?');
    expect(preflight).toContain(
      'if ((load_state_status != 0)) || [[ "${load_state}" != not-found ]]; then',
    );
    expect(preflight).not.toContain(
      '"${bwrap_probe_unit}" 2>/dev/null || true)',
    );
    expect(preflight).toContain(
      "Static bubblewrap preflight did not produce its exact root-owned nonce.",
    );
    expect(preflight).toContain('literal "[unprintable]"');
    expect(preflight).not.toContain(
      "require_pid1_unit_property ops-agentd.service Conditions",
    );
    expect(preflight).not.toContain(
      "require_pid1_unit_property ops-agentd.service Asserts",
    );
    expect(preflight).not.toContain(
      'require_pid1_unit_property "${bwrap_probe_unit}" Conditions',
    );
    expect(preflight).not.toContain(
      'require_pid1_unit_property "${bwrap_probe_unit}" Asserts',
    );

    const lifecycle = preflight.match(
      /cat >"\$\{bwrap_probe_lifecycle_dropin\}" <<EOF\n(?<body>[\s\S]*?)\nEOF/u,
    )?.groups?.body;
    expect(lifecycle).toBeDefined();
    const inheritedGlobal = [
      "[Unit]",
      "ConditionPathExists=/definitely-missing",
      "[Service]",
      "Type=oneshot",
      "ExitType=main",
      "RemainAfterExit=yes",
      "Restart=always",
      "TimeoutStartSec=infinity",
      "RuntimeMaxSec=infinity",
      "TimeoutStopSec=infinity",
      "KillMode=process",
      "ExecCondition=/bin/false",
      "ExecStartPre=/bin/true",
      "ExecStart=",
      "ExecStart=/bin/true",
      "ExecStartPost=/bin/true",
    ].join("\n");
    const scalar = new Map<string, string>();
    const execLists = new Map<string, string[]>();
    for (const line of `${inheritedGlobal}\n${lifecycle ?? ""}`.split("\n")) {
      const separator = line.indexOf("=");
      if (separator < 0) continue;
      const key = line.slice(0, separator);
      const value = line.slice(separator + 1);
      if (["ExecCondition", "ExecStartPre", "ExecStart", "ExecStartPost"].includes(key)) {
        const commands = execLists.get(key) ?? [];
        if (value === "") commands.length = 0;
        else commands.push(value);
        execLists.set(key, commands);
      } else {
        scalar.set(key, value);
      }
    }
    expect(execLists.get("ExecCondition")).toEqual([]);
    expect(execLists.get("ExecStartPre")).toEqual([]);
    expect(execLists.get("ExecStart")).toEqual(["${bwrap_probe_driver}"]);
    expect(execLists.get("ExecStartPost")).toEqual([]);
    expect(scalar.get("ConditionPathExists")).toBe("");
    expect(scalar.get("Type")).toBe("exec");
    expect(scalar.get("ExitType")).toBe("cgroup");
    expect(scalar.get("RemainAfterExit")).toBe("no");
    expect(scalar.get("Restart")).toBe("no");
    expect(scalar.get("TimeoutStartSec")).toBe("10s");
    expect(scalar.get("RuntimeMaxSec")).toBe("30s");
    expect(scalar.get("TimeoutStopSec")).toBe("10s");
    expect(scalar.get("KillMode")).toBe("control-group");
    const detachedSleepSeconds = Number(
      preflight.match(/\/bin\/sleep (?<seconds>\d+) &/u)?.groups?.seconds,
    );
    const runtimeMaxSeconds = Number(scalar.get("RuntimeMaxSec")?.replace(/s$/u, ""));
    expect(detachedSleepSeconds).toBeGreaterThan(runtimeMaxSeconds * 2);
    expect(installer).toContain("requires the fixed util-linux prlimit boundary");
    expect(installer).toContain(
      "bubblewrap cannot run inside the effective ops-agentd systemd boundary; required Source Workloads cannot run.",
    );
    expect(installer).toContain(
      "Nested containment requires an outer bubblewrap PID 1 lifecycle barrier and an inner Source PID 1 with further user namespaces disabled.",
    );
    expect(installer).toContain(
      "Initialization is rolling back instead of starting without workload.base isolation.",
    );
    expect(installer).not.toContain(
      "bubblewrap user namespaces are unavailable; ops_bash is disabled fail-closed.",
    );
    expect(installer).not.toContain(
      "sed -i 's/\"sandboxEnabled\": true/\"sandboxEnabled\": false/'",
    );
    expect(sandbox).toContain('"--disable-userns"');
    expect(sandbox).toContain('"--cap-drop"');
    expect(sandbox).toContain('"--nproc=64:64"');
    expect(sandbox).toContain("must be a root-owned, non-writable executable file");
  });

  it("uses final PID 1 absence, not stop/reset status, as preflight cleanup authority", () => {
    const installer = repositoryFile("scripts/install-release.sh");
    const preflightStart = installer.indexOf("run_bwrap_service_preflight() (");
    const preflightEnd = installer.indexOf(
      '\nif [[ "${MODE}" == init ]]; then',
      preflightStart,
    );
    const preflight = installer.slice(preflightStart, preflightEnd);
    const cleanupMatch = preflight.match(
      / {2}cleanup_bwrap_service_preflight\(\) \{\n(?<body>[\s\S]*?)\n {2}\}\n\n {2}pid1_unit_property\(\)/u,
    );
    const cleanupBody = cleanupMatch?.groups?.body;
    expect(cleanupBody).toBeDefined();
    if (cleanupBody === undefined) throw new Error("preflight cleanup helper is missing");

    const runCleanup = (
      finalLoadState: string,
      stopStatus: number,
      daemonReloadStatus = 0,
      showStatus = 0,
    ) => {
      const root = mkdtempSync(join(tmpdir(), "ops-agent-probe-cleanup-"));
      const unit = "ops-agent-bwrap-probe-test.service";
      const unitPath = join(root, unit);
      const dropinDirectory = join(root, `${unit}.d`);
      const lifecycleDropin = join(
        dropinDirectory,
        "zzzz-ops-agent-zz-preflight.conf",
      );
      const securityDropin = join(dropinDirectory, "zzzz-ops-agent-security.conf");
      const driver = join(root, "ops-agent-bwrap-probe-test-driver");
      const nonce = join(root, "ops-agent-bwrap-probe-test.nonce");
      const callLog = join(root, "calls.log");
      mkdirSync(dropinDirectory);
      for (const path of [unitPath, lifecycleDropin, securityDropin, driver, nonce]) {
        writeFileSync(path, "fixture\n", "utf8");
      }
      const script = [
        "set -euo pipefail",
        "cleanup_bwrap_service_preflight() {",
        cleanupBody,
        "}",
        `bwrap_probe_unit=${JSON.stringify(unit)}`,
        `bwrap_probe_unit_path=${JSON.stringify(unitPath)}`,
        `bwrap_probe_dropin_dir=${JSON.stringify(dropinDirectory)}`,
        `bwrap_probe_lifecycle_dropin=${JSON.stringify(lifecycleDropin)}`,
        `bwrap_probe_security_dropin=${JSON.stringify(securityDropin)}`,
        `bwrap_probe_driver=${JSON.stringify(driver)}`,
        `bwrap_probe_nonce=${JSON.stringify(nonce)}`,
        "bwrap_probe_loaded=true",
        'FINAL_LOAD_STATE="$1"',
        'STOP_STATUS="$2"',
        'DAEMON_RELOAD_STATUS="$3"',
        'SHOW_STATUS="$4"',
        'CALL_LOG="$5"',
        "systemctl() {",
        "  printf '%s\\n' \"$*\" >>\"${CALL_LOG}\"",
        '  case "$1" in',
        '    stop) return "${STOP_STATUS}" ;;',
        "    reset-failed) return 1 ;;",
        '    daemon-reload) return "${DAEMON_RELOAD_STATUS}" ;;',
        "    show)",
        "      printf '%s\\n' \"${FINAL_LOAD_STATE}\"",
        '      return "${SHOW_STATUS}"',
        "      ;;",
        "    *) return 97 ;;",
        "  esac",
        "}",
        "cleanup_bwrap_service_preflight 0",
      ].join("\n");
      const verification = spawnSync(
        "/bin/bash",
        [
          "-c",
          script,
          "--",
          finalLoadState,
          String(stopStatus),
          String(daemonReloadStatus),
          String(showStatus),
          callLog,
        ],
        { encoding: "utf8" },
      );
      const calls = readFileSync(callLog, "utf8").trim().split("\n");
      const remaining = readdirSync(root).sort();
      rmSync(root, { recursive: true, force: true });
      return { verification, calls, remaining };
    };

    const expectedCalls = [
      "stop ops-agent-bwrap-probe-test.service",
      "reset-failed ops-agent-bwrap-probe-test.service",
      "daemon-reload",
      "show --no-pager --property=LoadState --value ops-agent-bwrap-probe-test.service",
    ];
    for (const stopStatus of [0, 1]) {
      const unloaded = runCleanup("not-found", stopStatus);
      expect(
        unloaded.verification.status,
        `${unloaded.verification.stdout}${unloaded.verification.stderr}`,
      ).toBe(0);
      expect(unloaded.calls).toEqual(expectedCalls);
      expect(unloaded.remaining).toEqual(["calls.log"]);
    }

    const stillLoaded = runCleanup("loaded", 0);
    expect(stillLoaded.verification.status).toBe(1);
    expect(stillLoaded.verification.stderr).toContain(
      "Could not completely remove the static bubblewrap preflight unit.",
    );
    expect(stillLoaded.calls).toEqual(expectedCalls);
    expect(stillLoaded.remaining).toEqual(["calls.log"]);

    const reloadFailed = runCleanup("not-found", 0, 1);
    expect(reloadFailed.verification.status).toBe(1);
    const showFailed = runCleanup("not-found", 0, 0, 1);
    expect(showFailed.verification.status).toBe(1);
  });

  it("compares PID 1 list properties as exact unique sets", () => {
    const installer = repositoryFile("scripts/install-release.sh");
    const functionMatch = installer.match(
      / {2}pid1_word_sets_equal\(\) \{\n(?<body>[\s\S]*?)\n {2}\}\n\n {2}require_pid1_unit_word_set\(\)/u,
    );
    const functionBody = functionMatch?.groups?.body;
    expect(functionBody).toBeDefined();
    if (functionBody === undefined) throw new Error("word-set helper is missing");

    const verification = spawnSync(
      "/bin/bash",
      [
        "-c",
        [
          "set -euo pipefail",
          "pid1_word_sets_equal() {",
          functionBody,
          "}",
          "pid1_word_sets_equal 'alpha beta alpha gamma' 'gamma alpha beta'",
          "pid1_word_sets_equal 'alpha alpha' 'alpha'",
          "pid1_word_sets_equal '' ''",
          "! pid1_word_sets_equal 'alpha beta alpha' 'alpha gamma'",
          "! pid1_word_sets_equal 'alpha beta' 'alpha beta gamma'",
          "! pid1_word_sets_equal '' 'alpha'",
        ].join("\n"),
      ],
      { encoding: "utf8" },
    );
    expect(verification.status, `${verification.stdout}${verification.stderr}`).toBe(0);
  });

  it("enrolls only fresh endpoints and read-only validates existing endpoint upgrades", () => {
    const installer = repositoryFile("scripts/install-release.sh");
    const serverCommand = repositoryFile("cmd/ops-agent-server/main.go");
    const enrollment = repositoryFile("internal/enrollment/enrollment.go");

    expect(installer).toContain("Fresh join requires --token-file PATH.");
    expect(installer).toContain(
      "join found existing endpoint state and refuses to apply another enrollment bundle.",
    );
    expect(installer).toContain(
      '"${server_binary}" enroll --controller "${CONTROLLER_URL}"',
    );
    expect(installer).toContain(
      '"${server_binary}" validate-enrollment --controller "${CONTROLLER_URL}"',
    );
    expect(installer).toContain('"${CONFIG_ROOT}/tls/ca.key"');
    expect(serverCommand).toContain('case "validate-enrollment":');
    expect(enrollment).toContain('filepath.Join(options.ConfigRoot, "endpoint-enrollment.json")');
    expect(enrollment).toContain("Validation never rewrites endpoint identity, policy, TLS material");

    const transaction = installer.indexOf("\nbegin_install_transaction\n");
    const validation = installer.indexOf('"${server_binary}" validate-enrollment');
    const configMutation = installer.indexOf(
      'ensure_managed_directory "${CONFIG_ROOT}" root root 755',
      validation,
    );
    const failureInjection = installer.indexOf("maybe_inject_install_failure config");
    expect(transaction).toBeGreaterThan(0);
    expect(validation).toBeGreaterThan(transaction);
    expect(configMutation).toBeGreaterThan(validation);
    expect(failureInjection).toBeGreaterThan(validation);
    expect(installer).toContain("trap rollback_install_transaction EXIT");
  });
});
