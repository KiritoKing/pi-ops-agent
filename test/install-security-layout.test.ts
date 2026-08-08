import { readFileSync, readdirSync } from "node:fs";
import { describe, expect, it } from "vitest";

function repositoryFile(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

describe("installed client-plane isolation", () => {
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
    expect(runner).toContain('"--unshare-pid"');
    expect(runner).toContain('"--as-pid-1"');
    expect(runner).toContain('"--die-with-parent"');
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
    expect(gatewayUnit).toContain("TasksMax=128");
    expect(gatewayUnit).toContain("LimitNOFILE=512");
    expect(gatewayUnit).toContain("MemoryMax=256M");
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
    }
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
    const coreBroker = repositoryFile("systemd/ops-root-helper.service");
    const readWritePaths = (unit: string): string[] =>
      unit
        .split("\n")
        .filter((line) => line.startsWith("ReadWritePaths="))
        .flatMap((line) => line.slice("ReadWritePaths=".length).trim().split(/\s+/u));

    expect(pveBroker).toContain("ProtectSystem=full");
    expect(readWritePaths(pveBroker).filter((path) => path.startsWith("/etc"))).toEqual([
      "/etc/pve",
    ]);
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
    expect(installer).toContain("packages+=(bubblewrap sudo)");
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

    expect(installer).toContain('systemd-run --quiet --wait --collect --unit="${bwrap_probe_unit}"');
    expect(installer).toContain('--property="RestrictNamespaces=user ipc net mnt pid"');
    expect(installer).toContain("--unshare-user --unshare-ipc --unshare-pid --unshare-net");
    expect(installer).toContain("--as-pid-1 --disable-userns --cap-drop ALL");
    expect(installer).toContain("requires the fixed util-linux prlimit boundary");
    expect(installer).toContain(
      "bubblewrap cannot run inside the effective ops-agentd systemd boundary; required Source Workloads cannot run.",
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
