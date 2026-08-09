import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
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
    expect(installer).toContain(
      'verify_installed_unit_typed_vectors "${unit}" "${unit_path}"',
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
    expect(installer).toContain(
      "is not allowed to run sudo on [A-Za-z0-9][A-Za-z0-9.-]",
    );
    expect(installer).not.toContain(
      'if /usr/bin/sudo -U "${BOTMUX_USER}" -l',
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
    expect(containment).not.toContain('"--proc", "/proc"');
    expect(containment).not.toContain('"--as-pid-1"');
    expect(containment).not.toContain('"--disable-userns"');
    expect(containment).not.toContain('"--new-session"');
  });

  it("uses one pinned Noble AppArmor helper and an NNP-equivalent static smoke", () => {
    const helper = repositoryFile("scripts/configure-noble-bwrap-apparmor.sh");
    const installer = repositoryFile("scripts/install-release.sh");
    const agentdUnit = repositoryFile("systemd/ops-agentd.service");
    const agentdDropIn = repositoryFile(
      "systemd/ops-agentd.service.d/zzzz-ops-agent-security.conf",
    );
    const botmuxDropIn = repositoryFile("config/botmux-systemd-dropin.conf");
    const adapterProbe = repositoryFile("scripts/probe-adapter-linux-runtime.sh");
    const workflows = [
      {
        source: repositoryFile(".github/workflows/ci.yml"),
        after: "name: Build the native amd64 release payload",
      },
      {
        source: repositoryFile(".github/workflows/release.yml"),
        after: "name: Create the disposable Adapter identity fixture",
      },
    ];
    const summaryMatch = /print_authority_summary\(\) \{\n {2}\/bin\/cat <<'EOF'\n(?<summary>[\s\S]*?)\nEOF\n\}/u.exec(
      helper,
    );
    if (summaryMatch?.groups?.summary === undefined) {
      throw new Error("AppArmor helper authority summary is not canonical");
    }
    const summarySha256 = createHash("sha256")
      .update(`${summaryMatch.groups.summary}\n`)
      .digest("hex");
    expect(summarySha256).toBe(
      "c745e2eb341efc1a26b017e63cc03b284f63f51298036ce58e9e6661d7f7015c",
    );
    const approvalFields = [
      "ops-agent-noble-bwrap-apparmor/v1",
      "package=apparmor-profiles",
      "version=4.0.1really4.0.1-0ubuntu0.24.04.7",
      "source-sha256=11d39094f044f0cda0febb3ad517b830301da6b2ce929664af09ee9e4dd264f9",
      "local-rule=/usr/bin/bwrap ix,",
      `authority-summary-sha256=${summarySha256}`,
    ];
    const approvalBytes = Buffer.concat(
      approvalFields.flatMap((field, index) => [
        Buffer.from(field),
        Buffer.from(index === approvalFields.length - 1 ? "\n" : "\0"),
      ]),
    );
    expect(`sha256:${createHash("sha256").update(approvalBytes).digest("hex")}`).toBe(
      "sha256:d2b2928681d31e9430a9a2a1949ead607580311cba35b776e6a651e1d67254ef",
    );
    const vectorStart = helper.indexOf("verify_probe_effective_vector() {");
    const vectorEnd = helper.indexOf("cleanup_probe_artifacts() {", vectorStart);
    expect(vectorStart).toBeGreaterThan(0);
    expect(vectorEnd).toBeGreaterThan(vectorStart);
    const effectiveVector = helper.slice(vectorStart, vectorEnd);
    for (const property of [
      "User", "Group", "Type", "ExitType", "UMask", "RemainAfterExit", "Restart",
      "TimeoutStartUSec", "RuntimeMaxUSec", "TimeoutStopUSec",
      "TimeoutStopFailureMode", "KillMode", "NoNewPrivileges", "PrivateTmp",
      "PrivateDevices", "ProtectSystem", "ProtectHome", "ProtectKernelTunables",
      "ProtectKernelModules", "ProtectKernelLogs", "ProtectControlGroups",
      "ProtectClock", "ProtectHostname", "ProtectProc", "ProcSubset",
      "RestrictRealtime", "RestrictSUIDSGID", "LockPersonality",
      "SystemCallArchitectures", "SupplementaryGroups", "CapabilityBoundingSet",
      "RestrictNamespaces", "RestrictAddressFamilies", "ReadWritePaths",
      "ExecCondition", "ExecStartPre", "ExecStartPost", "ExecReload", "ExecStop",
      "ExecStopPost", "Environment", "EnvironmentFiles",
    ]) {
      expect(effectiveVector).toContain(property);
    }
    expect(effectiveVector).toContain("require_probe_unit_exec_start");
    expect(effectiveVector).toContain("verify_probe_dropin_closure");

    expect(helper).toContain(
      'EXPECTED_PACKAGE_VERSION="4.0.1really4.0.1-0ubuntu0.24.04.7"',
    );
    expect(helper).toContain(
      'EXPECTED_PROFILE_SHA256="11d39094f044f0cda0febb3ad517b830301da6b2ce929664af09ee9e4dd264f9"',
    );
    expect(helper).toContain(
      'APPROVAL_DIGEST="sha256:d2b2928681d31e9430a9a2a1949ead607580311cba35b776e6a651e1d67254ef"',
    );
    expect(helper).toContain(
      'AUTHORITY_SUMMARY_SHA256="c745e2eb341efc1a26b017e63cc03b284f63f51298036ce58e9e6661d7f7015c"',
    );
    expect(helper).toContain("ops-agent-noble-bwrap-apparmor/v1");
    expect(helper).toContain('"package=${EXPECTED_PACKAGE}"');
    expect(helper).toContain('"version=${EXPECTED_PACKAGE_VERSION}"');
    expect(helper).toContain('"source-sha256=${EXPECTED_PROFILE_SHA256}"');
    expect(helper).toContain('"local-rule=${LOCAL_RULE}"');
    expect(helper).toContain(
      '"authority-summary-sha256=${AUTHORITY_SUMMARY_SHA256}"',
    );
    expect(helper).toContain('LOCAL_RULE="/usr/bin/bwrap ix,"');
    expect(helper).toContain('MANAGED_PROFILE="/etc/apparmor.d/bwrap-userns-restrict"');
    expect(helper).toContain(
      'MANAGED_LOCAL_RULE="/etc/apparmor.d/local/bwrap-userns-restrict"',
    );
    expect(helper).toContain('DISABLE_PROFILE="/etc/apparmor.d/disable/bwrap-userns-restrict"');
    expect(helper).toContain(
      'COMPLAIN_PROFILE="/etc/apparmor.d/force-complain/bwrap-userns-restrict"',
    );
    expect(helper).toContain("dpkg --verify");
    expect(helper).toContain("unique dpkg ownership");
    expect(helper).toContain(
      '"$(/usr/bin/readlink -- /etc/os-release)" == ../usr/lib/os-release',
    );
    expect(helper).toContain(
      '"$(/usr/bin/realpath -e -- /etc/os-release)" == "${os_release_source}"',
    );
    expect(helper).toContain("os_release_size <= 16384");
    expect(helper).toContain(
      '"${os_id_count}" -eq 1 && "${os_version_count}" -eq 1',
    );
    expect(helper).toContain("/usr/sbin/getcap -n /usr/bin/bwrap");
    expect(helper).toContain(
      '[[ "${destination_sha}" == "${EXPECTED_PROFILE_SHA256}" ]]',
    );
    expect(helper).toContain(
      "/usr/sbin/apparmor_parser --config-file /dev/null",
    );
    expect(helper).toContain("--skip-read-cache --skip-cache --replace");
    expect(helper).not.toContain("apparmor_parser --remove");
    expect(helper).toContain("kernel_profiles_are_proven_absent");
    expect(helper).toContain(
      "No profile was unloaded; managed files and kernel state were retained",
    );
    expect(helper).toContain("AppArmorProfile=-bwrap");
    expect(helper).toContain("verify_probe_effective_vector");
    expect(helper).toContain("verify_probe_dropin_closure");
    expect(helper).toContain(
      "/usr/lib/systemd/system/service.d/10-timeout-abort.conf",
    );
    expect(helper).toContain("require_probe_unit_exec_start");
    expect(helper).toContain('"ExitType=cgroup"');
    expect(helper).toContain('"TimeoutStopFailureMode=terminate"');
    expect(helper).toContain("CapabilityBoundingSet ''");
    expect(helper).toContain("'user ipc pid net mnt'");
    expect(helper).toContain("'AF_UNIX AF_INET AF_INET6 AF_NETLINK'");
    expect(helper).toContain("flags= ;");
    expect(helper).toContain("'a(sbbsi) 0'");
    expect(helper).toContain("NoNewPrivileges=yes");
    expect(helper).toContain("PrivateDevices=yes");
    expect(helper).toContain("ProtectKernelTunables=yes");
    expect(helper).toContain("ProtectProc=invisible");
    expect(helper).toContain("ProcSubset=all");
    expect(helper).toContain("CapInh CapPrm CapEff CapBnd CapAmb");
    expect(helper).toContain("[ \"\\${current_label}\" = 'bwrap (enforce)' ]");
    expect(helper).toContain("declare -A capability_values=()");
    expect(helper).toContain('[[ "${current_label}" == *unpriv_bwrap* ]]');
    expect(helper).toContain("--as-pid-1 --disable-userns --cap-drop ALL");
    expect(helper).toContain("unshare --user --map-root-user");
    expect(helper).toContain("Source obtained nested bubblewrap authority");
    expect(helper).toContain('profile_reply}" == \'(bs) true "bwrap"\'');
    expect(helper).toContain("AUTHORITY SUMMARY (non-secret)");
    expect(helper).toContain("host-wide, argv-blind AppArmor rule");
    expect(helper).toContain("If Core is");
    expect(helper).toContain("user-namespace, mount, and network-namespace");
    expect(helper).toContain("BotMux remains unsupported and fail-closed");
    expect(helper).toContain("print_authority_summary >&9");
    expect(helper).toContain(
      'local verb="$1"\n  local confirmation="${verb} NOBLE BWRAP APPARMOR ${APPROVAL_DIGEST}"',
    );
    expect(helper).not.toContain(
      'local verb="$1" confirmation="${verb} NOBLE BWRAP APPARMOR ${APPROVAL_DIGEST}"',
    );
    expect(helper).toContain("automatic AppArmor policy removal is unavailable");
    expect(helper).toContain("/usr/bin/flock --exclusive --nonblock 8");
    expect(helper).toContain("systemctl list-units --all --plain");
    expect(helper).toContain(
      '/usr/bin/journalctl --boot -u "${unit}" --no-pager -n 64 -o cat',
    );
    expect(helper).toContain(
      "--grep='apparmor=\"DENIED\"|apparmor=DENIED' --no-pager -n 64 -o cat",
    );
    expect(helper).toContain("Probe cleanup left an exact artifact path behind");
    expect(helper).toContain('LOCK_DIRECTORY="/etc/apparmor.d"');
    expect(helper.match(/ {2}acquire_helper_lock\n/g)).toHaveLength(3);
    expect(helper.match(/ {6}run_authoritative_systemd_smoke\n/g)).toHaveLength(1);
    expect(helper).toContain("apparmor-managed-state=verified-now");
    expect(helper).not.toContain("/run/ops-agent-apparmor");
    expect(helper).not.toContain("active_bwrap_labels_absent");
    expect(helper).toContain("status returns 0");
    expect(helper).toContain("and 1 for drift");
    expect(helper).not.toContain("apt-get");
    expect(helper).not.toContain("/usr/sbin/sysctl");
    expect(helper).not.toContain("sysctl -w");
    expect(helper).not.toContain("AppArmorProfile=unconfined");
    expect(helper).not.toContain("flags=(unconfined)");
    expect(helper).not.toContain("chmod u+s");

    for (const { source: workflow, after } of workflows) {
      const start = workflow.indexOf(
        "name: Install and verify the pinned nested-bubblewrap AppArmor policy",
      );
      const end = workflow.indexOf(after, start);
      expect(start).toBeGreaterThan(0);
      expect(end).toBeGreaterThan(start);
      const gate = workflow.slice(start, end);
      expect(gate).toContain("configure-noble-bwrap-apparmor.sh inspect");
      expect(gate).toContain("configure-noble-bwrap-apparmor.sh install");
      expect(gate).toContain("--approve-digest");
      expect(gate).toContain("configure-noble-bwrap-apparmor.sh status");
      expect(gate).not.toContain("apparmor_parser");
      expect(gate).not.toContain("bwrap-userns-restrict.local");
    }

    expect(agentdUnit).toContain("AppArmorProfile=-bwrap");
    expect(agentdDropIn).toContain("AppArmorProfile=-bwrap");
    expect(botmuxDropIn).not.toContain("AppArmorProfile=");
    expect(installer).toContain("require_installed_unit_apparmor_profile");
    expect(installer).toContain('value?.type !== "(bs)"');
    expect(installer).toContain(
      "require_installed_unit_apparmor_profile ops-agentd.service true bwrap",
    );
    expect(adapterProbe).toContain("--property=AppArmorProfile=-bwrap");
    expect(adapterProbe).toContain("require_effective_apparmor_profile");
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
    const restoreUnits = installer.indexOf("\n  restore_unit_state\n");
    const lateWantsRestore = installer.indexOf(
      'restore_managed_path_snapshot "${OPS_AGENT_TARGET_WANTS_SNAPSHOT_INDEX}"',
    );
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
    expect(lateWantsRestore).toBeGreaterThan(restoreUnits);
    expect(cleanup).toBeGreaterThan(snapshot);
    expect(unitFailure).toBeGreaterThan(cleanup);
    expect(joinActivation).toBeGreaterThan(0);
    expect(initActivation).toBeGreaterThan(joinActivation);
    expect(installer.slice(joinActivation, initActivation)).not.toContain("add-wants");
    expect(addWants).toBeGreaterThan(initActivation);
    expect(serviceFailure).toBeGreaterThan(addWants);
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
      'disable_managed_unit_for_cleanup "${unit_name}"',
    );
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
    expect(preflight).toContain("--cap-drop ALL --bind / / --dev /dev");
    expect(preflight).not.toContain("--cap-drop ALL --bind / / --proc /proc --dev /dev");
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
    expect(preflight).toContain('[[ "${load_state}" == not-found ]]');
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
      'install -d -o root -g root -m 0755 "${CONFIG_ROOT}"',
    );
    const failureInjection = installer.indexOf("maybe_inject_install_failure config");
    expect(transaction).toBeGreaterThan(0);
    expect(validation).toBeGreaterThan(transaction);
    expect(configMutation).toBeGreaterThan(validation);
    expect(failureInjection).toBeGreaterThan(validation);
    expect(installer).toContain("trap rollback_install_transaction EXIT");
  });
});
