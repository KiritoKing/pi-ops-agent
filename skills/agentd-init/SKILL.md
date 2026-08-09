---
name: agentd-init
description: Initialize, join, upgrade, or recover a Pi Ops Agent deployment on systemd Linux, either directly on the host or through an existing agent's SSH administration path. Use for first-controller setup, endpoint enrollment, release verification, deployment smoke tests, or diagnosing an incomplete installation without bypassing model-external approval.
---

# Initialize Agentd

Treat installation as a privileged, auditable change. Keep the model, `agentd`, SSH material,
approver credentials, and `agentd-root-broker` authority separated throughout the workflow.

## Establish the deployment mode

Read the repository-root `AGENTS.md` and these documents before changing a host:

- [architecture](../../docs/architecture.md)
- [security model](../../docs/security-model.md)
- [deployment](../../docs/deployment.md)
- [operations and recovery](../../docs/operations.md)

Choose exactly one mode:

- Use `init` for the first controller. Install `agentd`, same-UID guardian, local
  `agentd-server`, local `agentd-root-broker`, and the TUI recovery path. Install the
  PVE broker only when this same host has executable `/usr/bin/pvesh`.
- Use `join` for another managed machine. Install only `agentd-server` and
  the core `agentd-root-broker`. Install the separately scoped PVE broker only when the
  controller signed the enrollment with `issue-enrollment --pve` and the endpoint has
  executable `/usr/bin/pvesh`; require the signed flag and host fact to match in both
  directions. Do not copy the model, sessions, or controller credentials.
- Treat an existing controller as an `init` upgrade or recovery. Treat an existing server-only
  endpoint as a `join` upgrade: pass the authenticated controller origin and CA pin again but
  omit `--token-file`, so the new binary read-only validates and reuses the installed enrollment.
  Inspect active release, policy, state, and units first; do not run a fresh enrollment over them.
- Treat SSH as an administrator transport only. An agent controlling a target over SSH does
  not gain approval authority, and SSH keys must never enter model context or target config.

## Follow the safe workflow

1. Collect read-only evidence: Linux distribution, architecture, systemd PID 1, available
   disk space, current `/opt/pi-ops-agent/current`, existing `/etc/ops-agent`, unit states,
   target identity, and controller reachability. Redact credentials and enrollment bundles.
2. Select and pin an explicit release tag for production. Verify the release checksum before
   extraction. If `gh` is present, verify the GitHub artifact attestation; otherwise report
   that only HTTPS plus checksum was verified.
3. For `init`, resolve an existing non-root administrator. For a fresh `join`, generate the short-lived
   enrollment bundle on the controller, store and transfer it as a non-symlink `0600` file,
   and bind it to the exact HTTPS controller and endpoint identities. Independently convey and
   authenticate the `controller-ca-sha256` value printed by `issue-enrollment`, then pass that
   exact canonical fingerprint to `join`; never derive the trust pin from the bearer bundle or
   its transfer message. Use `issue-enrollment --pve` if and only if the endpoint has executable
   `/usr/bin/pvesh`; either mismatch must fail
   instead of generating an endpoint-local receipt key.
   For an existing endpoint upgrade, never issue or pass another bundle: omit `--token-file` and
   require read-only validation of `endpoint-enrollment.json`, controller/CA, identity, current
   policy schema, TLS/DAC and domain-separated receipt keypairs. Partial or damaged state must
   roll the installation transaction back instead of being repaired or overwritten.
   The `init` administrator must have a real local password/TTY path and no later effective broad
   `NOPASSWD` match overriding the two fixed-helper `PASSWD` rules; cloud images commonly add
   `NOPASSWD: ALL`, and the installer must trust the negative probe rather than filename assumptions.
   In a disposable test VM create a dedicated password-bearing admin;
   on production hosts preserve a separate recovery path before reviewing existing sudo policy.
4. Present the target, mode, release, identities, units, policy changes, and rollback path to
   the user before invoking `sudo` or changing the host. Never infer approval from model text.
5. Run the version-matched bootstrap described in [deployment](../../docs/deployment.md).
   Prefer `--no-start` when credentials or maintenance timing are not ready. Do not place
   secrets in argv, environment logs, chat, or transcript.
6. If initialization bootstraps the required `adapter.tui` and `workload.base` source plugins,
   show their exact manifests, source digests, capabilities, and requested scopes first. Record the user's
   explicit bootstrap approval and bind it to those digests. Do not silently approve another
   plugin or treat a first-party publisher as trusted. For every regular `plugin.register`, require
   the canonical plan to display and bind ID, kind, version, publisher, digest, complete capabilities,
   and complete sorted requested scopes; the broker must rescan and match all fields before activation.
   Every changed digest requires approval.
7. When enabling `workload.hermes-ops` or `workload.botmux-ops`, approve and register its exact
   source digest, then add a root-owned `serviceWorkloads` policy entry for one Target account,
   one `system|user` manager, explicit unit names, and only the needed
   `reload|reset-failed|restart|start|stop` actions. Discover actual units read-only; do not guess a
   unit or add a wildcard. Treat `reload`/`reset-failed` as per-change-only even when another service
   action has standing authorization. Use a
   separate Target for each Linux account. Verify a prepared plan shows the same plugin digest,
   account, manager, unit, action, UID, and authoritative systemd state before approval.
   For Hermes/BotMux CLI diagnostics, separately add exact `commandWorkloads` entries. Bind the same
   current plugin digest, Target/run-as account and home, semantic profileKey, complete fixed argv,
   timeout/output bound, and a root-owned executable whose original and resolved path trees are not
   group/world writable. Never point at `~/.local/bin`, npm/pnpm user bins, a checkout, or any
   user-writable symlink. Do not weaken the core broker's `ProtectHome=yes`; its fixed `systemd-run`
   transient unit supplies `ProtectHome=read-only` and `PrivateNetwork=yes`. Smoke-test through the
   dedicated command-inspection route, verify the pinned core receipt, confirm both audits omit raw
   output, and for BotMux verify setup summaries contain no `env`, `cliRuntime`, `update`, command/path,
   or credential fields.
   To enable BotMux config mutation, add a separate root-owned `jsonConfigWorkloads` entry copied
   from the repository example and replace its digest/UID/home/selectors/path roots with observed
   exact values. Do not expose config path, selector key, actual JSON field, helper or argv to the
   Source. Confirm the plan shows before/after, config digest/identity and whole-document rewrite;
   absolute working-directory edits must also show root/directory identity plus the
   post-verification pathname-replacement residual (a same-UID or other authorized parent writer
   may replace it). Every edit remains local per-change, never standing, and service restart
   is a second typed change.
8. For a PVE endpoint, treat `join --pve` as transport/broker enrollment only; it does not grant
   any PVE resource authority. On the controller, inspect and explicitly approve/register the exact
   `plugins/workload-pve` source tree as `workload.pve`, then record its current SHA-256 digest.
   Read-only discover the cluster nodes, storage IDs, QEMU/LXC VMIDs, migration destinations and
   enabled operations from PVE itself. Have the user review a root-owned endpoint Target policy
   whose `pve.pluginId`/`pve.pluginDigest` exactly match that registration and whose arrays list only
   those observed, intentionally managed resources; do not synthesize a wildcard, copy a sample
   unchanged, or derive `standingScopes` from the operation allowlist. Configure exactly one mutation
   endpoint for each PVE cluster because the VMID lock is broker-local; route other nodes through it
   or keep them read-only. After installing the reviewed policy, restart only the PVE broker/server
   during an approved maintenance window, refresh controller capabilities, and prove the PVE receipt
   verifies against the separately pinned PVE public key. Run all five read operations, then prepare
   and reject one nonstanding mutation before any approved mutation. Confirm wrong digest, unlisted
   node/storage/VMID, a second mutation endpoint and a core-broker PVE request all fail closed. Do not
   call the workload usable merely because the PVE unit is healthy.
9. Delete all enrollment-bundle copies after successful `join`; if enrollment fails or a copy
   may have leaked, disable the pending registration, wait for expiry, and rotate the affected
   endpoint credential before retrying.
10. When enabling BotMux, install and approve `adapter.botmux` first, then use only the fixed local
   TUI command. It must invoke `sudo -k -- /usr/libexec/pi-ops-agent/setup-botmux`; do not run
   BotMux setup as the administrator or pass a script/path argument to root. Verify the daemon,
   tmux backend, config and secret belong to `ops-agent-botmux`, whose only supplementary group
   is `ops-agent-client` and which has no sudo path or access to the agent service credential.

Do not weaken bubblewrap, systemd hardening, mTLS, peer-UID checks, or root policy to make an
installation pass. If non-privileged user namespaces are unavailable, the required
`workload.base` Source Workload cannot load safely: require `init` to fail closed and roll back
the complete installation transaction. Do not start a restricted controller or substitute a host
shell, in-process loader, Docker, sudo, or extra container privileges.

Treat every installer-managed service, not only `ops-agentd`, as a PID 1 effective-policy boundary.
For `init`, require exact release units plus unit-name-specific final security drop-ins for reviewer,
client gateway, guardian, plugin lease broker, agentd, server, core broker, and healthcheck; add the
PVE broker only when `/usr/bin/pvesh` is executable. For `join`, require only server and core broker,
adding PVE only when the signed enrollment bit and fixed local entrypoint match in both directions.
Reject controller-only units/drop-ins on join and stale managed PVE units/drop-ins on non-PVE hosts.
After `daemon-reload`, verify through `systemctl show` that PID 1 loaded the exact root-owned release
unit/final drop-in and that identity, lifecycle, single ExecStart/argv with empty `ExecStartEx.flags`,
environment, declared resource limits, scalar/list/path hardening, and capability bounds are exact;
undeclared `ReadWritePaths` and `SupplementaryGroups` vectors must remain empty. Query typed PID 1
D-Bus properties for exact Conditions/Asserts and Load/Set/Import credential vectors, verify the
healthcheck `SuccessExitStatus` and exact agentd credential drop-in, and reject every extra loaded
drop-in except a root-owned host-wide compatibility reset whose complete syntax is in the fixed
narrow allowlist. Host-wide `service.d` drift or later unit overrides must fail the transaction;
`cmp`, `systemctl cat`, and `systemd-analyze verify` alone are not sufficient.
Keep the mode-applicable unit and drop-in directories inside the same rollback snapshot, including
the PVE candidates before the conditional enrollment decision.

The preflight must execute the real nested bwrap structure inside a unique, root-owned,
short-lived static unit under `/run/systemd/system` that copies the final `ops-agentd` security
drop-in and verifies PID 1's effective configuration, not only under the same UID. It must prove the outer default PID 1
reaper can create only the exact `user/ipc/pid/net/mnt` set and start the fixed inner bwrap, the
inner Source is PID 1 and denies later userns, and `ProtectHostname=yes` plus the narrowly writable
namespaced `/proc/sys/user/max_user_namespaces` path work together. Require
`PrivateDevices=yes`, `ProtectKernelTunables=yes`, `ProtectProc=invisible`, and `ProcSubset=all` in
the effective service vector. `ProcSubset=all` is required for that sysctl path and exposes the
otherwise-unmasked, read-only non-PID procfs metadata; `ProtectProc=invisible` hides only foreign-UID
PID directories, not same-UID PIDs or that metadata. Treat bubblewrap's own failed
post-setup `CLONE_NEWUSER` attempt as the deny proof; do not infer it from the numeric value visible
through the final namespace's procfs. Runtime probes must additionally
observe the outer PID 1-owned `--sync-fd` EOF and the bounded `--info-fd`-bound exact init process
identity disappear before treating the process tree as drained. Sync failure must not bypass the
identity wait; unreadable initial stat evidence requires later PID ENOENT, and missing authoritative
info must remain fail-stop. Record that the current socket-backed registry lease is not yet
crash-persistent across broker restart, forced disconnect, hard deadline, or runtime SIGKILL.
Install a unit-name-specific late drop-in and verify the manager's effective scalar and list-valued
properties with `systemctl show`; host-wide `service.d` resets must not turn a weakened probe into a
pass. Remove the exact probe unit, drop-ins, driver, nonce, and manager state before the installation
transaction completes or rolls back.

Do not derive standing grants during initialization. If an administrator explicitly enables
standing `file.write` or `service.action`, require `authorization.baseWorkloadDigest` to equal the
current approved `workload.base` registration digest. A plugin update must leave the old Target
value ineffective until both the new source grant and Target policy are reviewed again.

Every root Target may prepare a per-change manual root capsule; the deprecated
`--allow-breakglass` flags are compatibility no-ops, not kill switches, and a legacy `full-root`
policy grants no extra authority. Never make a capsule standing. Require the local TUI,
independent reviewer, repeated `/approve`, PASSWD sudo submitter, and exact confirmation on the
real `/dev/tty` for every change; external adapters, non-root Targets and the PVE broker cannot
approve or execute this surface. `backupPaths` may be explicitly empty and `verifyScript` may be
absent. Treat it only as a caller-provided privileged postcondition, never an independent verifier.
Keep every capsule critical and expose missing recovery/postcondition evidence. Require an explicit
network declaration, but treat `network=false` plus `PrivateNetwork` as best-effort intent: full-root
code can escape or delegate through PID 1, so never present it as an inescapable no-network boundary.
Verify `RollbackAvailable=false`.

## Verify before declaring success

Use the current artifact names from the architecture document. Verify all applicable items:

- Before tagging, run the Linux release verifier for both amd64 and arm64. It must prove the tar
  and Debian versioned payload trees match, all seven current Go commands are static ELF binaries
  for the declared architecture, the pinned Node 22 LTS runtime syntax-checks every compiled
  JavaScript file and actually executes the Client/Reviewer smoke paths,
  and the payload includes Reviewer/Guardian, Adapter/Workload hosts, PVE, every bundled Source
  Plugin, all three Skills, systemd units and required docs while excluding the retired
  `ops-systemd-helper`. Require the complete two-architecture tar/deb/SBOM and compatibility
  `.opspkg` asset set before manifest/checksum generation, then attest every asset class including
  `checksums.txt`; do not treat the package-oriented SBOM as a replacement for asset integrity.
- After `init` has created the real `ops-agent-botmux` account and `ops-agent-client` supplementary
  group, run `npm run build` and then run `npm run test:adapter-linux-runtime` as root on Linux (or
  invoke the packaged `/opt/pi-ops-agent/current/scripts/probe-adapter-linux-runtime.sh`). Treat exit
  status `77` as unverified, never as pass. The release is blocked until real `/usr/bin/bwrap`
  preserves the group-readable fixture and group socket, uses an outer default bwrap reaper around
  the inner Source PID 1, observes its dedicated lifecycle FD reach EOF and exact init identity disappear, confirms the detached child
  has disappeared from the host-side driver's `/proc` by exact PID/starttime (never by trusting the
  inner procfs `NSpid`), and only then permits the exact-digest lease to release. For an installed artifact, verify the wrapper is
  self-contained and carries its fixture, socket, client and runtime driver scripts; a source-tree
  probe cannot substitute for that packaged-payload check. The Release workflow must enforce the
  same probe in a disposable Ubuntu job that creates only the dedicated system identity fixture,
  leaves the runner's default user unchanged, and is an explicit dependency of `publish`; never use
  `continue-on-error`. In the temporary read-only runtime, preserve the release module topology:
  place the driver under `scripts/` and the compiled runner under sibling `dist/runtime/`, so its
  `../dist/...` import cannot resolve outside the copied artifact or to a nonexistent path.
- Exercise `file.write` with a root-owned allowed root that is itself a dedicated filesystem or bind
  mount. The exact policy root may cross that mount boundary, but a symlink root, a nested mount below
  it, a writable parent, or parent/target device-and-inode drift must still fail closed.
- Prove the installer validated the complete mode-specific managed service set against PID 1 after
  daemon reload. Check exact `FragmentPath` and final security `DropInPaths`, one release ExecStart,
  empty pre/post/reload/stop hooks, exact typed Conditions/Asserts/credential vectors,
  SuccessExitStatus, identity/environment/lifecycle, and exact scalar/list/path/capability hardening;
  reject unrecognized extra loaded drop-ins. Do not accept the init union on join, the join intersection
  on init, or a managed PVE service/drop-in on a non-PVE host.
- The active release points to the intended immutable version; config and state remain outside
  the release directory.
- `/usr/lib/ops-agent/agentd-json-config-helper` is a non-symlink `root:root 0755` executable and
  byte-identical to the current verified release binary. Exercise strict inspect/snapshot/mutate,
  digest-CAS refusal, rollback and interrupted recovery on Linux; a non-Linux result is expected to
  fail closed, not count as deployment validation.
- Each process runs under its designated account; only the core/PVE brokers are root, and neither
  has a network listener.
- Service UID/GID values are nonzero and pairwise distinct; server/reviewer/lease static accounts
  have no supplementary groups; only the lease broker unit receives runtime-only
  `ops-agent-client` membership to read registrations; agentd and BotMux have only
  `ops-agent-client`; the administrator is not in the `ops-agent` service group.
- `/run/ops-agent/agentd` is `ops-agent:ops-agent-client 2750`; public `agentd.sock` is group `0660`
  and owned by active `agentd-client-gateway.service`, while agentd listens only on owner-mode
  `backend.sock 0600`. Prove the gateway uses kernel `SO_PEERCRED`, rejects the agent UID/stale or
  foreign Adapter digest, maps the same external Session ID into distinct UID+Adapter+digest
  namespaces, and rejects a second live writer before backend dial. Saturate concurrent unique
  sessions and prove fixed process-total/per-UID admission rejects overflow before spawning a
  handler; retain `TasksMax`, `LimitNOFILE`, and `MemoryMax` in the gateway unit. The CAS
  root is `root:ops-agent-client 2750`, `agent.key` is `ops-agent:ops-agent 0600`, and the observer
  key plus `servers.json` are `root:ops-agent-client 0640`.
- On `init`, editable `plugin-sources` is `ADMIN_USER`-owned `0750`; it is not part of the client
  group read surface. Only the digest-approved immutable CAS is client-readable.
- `/var/lib/ops-agent/plugins/invocation-leases` is `root:ops-agent-lease 0750`; every active
  plugin has a `root:ops-agent-lease 0640` lock file. Client-group runtimes must never open these
  locks. Verify the directory is exactly `0750`, not an inherited `2750` from its setgid registry
  parent; GNU `chmod 0750` preserves directory setgid, so initialization must use an explicit
  special-bit-clearing mode such as `00750`. They connect as their real UID to
  `/run/ops-agent/plugin-lease/lease.sock`, and the
  peer-authenticated `ops-agent-lease` broker alone opens the lock and returns the exact active
  registration under a shared lease. Prove a Workload holds that connection through
  its provider call and a concurrent register fails before switching `current`, then succeeds only
  after the invocation drains. Also prove executable Adapter runner holds the exact digest lease
  until the outer PID 1-owned sync FD and exact init identity prove its complete nested bubblewrap PID namespace has drained
  (including a detached-child probe), and the
  compiled TUI Client holds its own lease if the runner exits. An old-digest pending plan must not
  be approved after a new digest is current. Also exercise the root submitter directly: after its
  first signed status it must extract one canonical runtime workload ID/digest and hold a separate
  fixed-registry shared lease through reviewer, TTY, second status, and final action. Close the
  Client/lease-broker connection while approval is in flight and prove register/activate still fail
  until the action settles; prove old A/current B, mixed/missing provenance, and non-workload
  registration fail closed, while candidate registration/install/deploy and rollback do not
  incorrectly require runtime current.
  Exercise TUI self-update separately: only the second local confirmation of one canonical
  declarative `adapter.tui plugin.register` may stop input/session and release the Client lease,
  then request and await the outer runner lease release before submit. The old Client must exit on
  both submit success and failure; a second TUI lease must still block the exclusive update.
  Also prove BotMux setup holds the exact `adapter.botmux` digest lease across setup, the approved
  snapshot hardener, and restart; run the hardener as inner bubblewrap PID 1 with an outer default
  reaper plus lifecycle-FD barrier so detached descendants are gone before release, and prove lease
  loss aborts the current command and skips all later steps.
  Never loosen the lock directory DAC, delete a lease file, or stop isolation to force an update.
- The complete sudo policy passes `visudo -cf`; after invalidating the timestamp, non-interactive
  probes for both fixed root helpers fail specifically because a password is required. A fragment-
  only syntax check is not sufficient. A root-side `sudo -U ops-agent-botmux -l` probe must also
  confirm that the dedicated Adapter account has no sudo rule at all. Do not infer this from sudo's
  exit status: sudo 1.9 can return zero for the canonical negative result. Require exactly one
  C-locale `is not allowed to run sudo` line and reject warnings, Defaults or command listings.
- `agentd-server` requires HTTPS/mTLS and exposes only current policy capabilities.
- The TUI creates an isolated session; model-visible input cannot approve, reject, or roll back.
- A legacy status is marked `recoveryOnly=true` with no live plan only when the broker can strictly
  parse the stored operation and reproduce its exact v0.1/v0.2 NUL-prefixed plan hash. Verify an
  arbitrary canonical-plan mismatch fails closed and approve is always refused; pending changes can
  only be locally rejected. The signed `recoveryDescriptor` must bind original/compensation targets
  and actions, rollbackData digest, backup object digests, and compatibility version. Confirm
  `rollbackAvailable` is persisted evidence AND current compatibility, with a reason when false.
- Exercise both legacy file cases with the real executor: an existing target restores only when the
  post-write content/uid/gid/mode/dev/ino and exact root:root 0600 backup digest still match; a newly
  created target removes only while it remains root:root with the approved mode/content and the same
  inode. Drift must make rollback unavailable without mutation. Recovery still requires the critical
  two-step local preview plus PASSWD sudo and exact `/dev/tty` confirmation.
- Start approval only while agentd is ready and idle. Inject concurrent ANSI/control output during
  reviewer and the second submitter/sudo/TTY phase; it must remain hidden in a 256 KiB bounded buffer,
  then appear escaped under the delayed-untrusted separator after approval completes.
- Tamper reviewer output independently in `reviewId`, canonical user-intent digest, and finding
  `stepId`; Client must reject all three before preview, quiesce, or submit even when planHash and
  the review's own content digest are otherwise valid.
- `join` did not install a second model/session controller.
- `join` created only `ops-agent-server`, core broker, minimal endpoint tmpfiles/config and,
  when exactly matched by `--pve`, the PVE broker. It did not create agentd/reviewer/BotMux/client
  identities, plugin trees, approval sudoers, a controller health timer, `ops-agent.target.wants`,
  or an `ops-agent` CLI link. The PVE unit is enabled only under `multi-user.target` on an endpoint;
  only controller `init` adds it to `ops-agent.target`.
- Fresh `join` wrote `endpoint-enrollment.json`; an existing endpoint upgrade omitted the bearer
  bundle and only reused the enrollment after the new binary verified its controller/CA/identity,
  current policy schema, TLS/DAC and core/PVE receipt pairs. A partial/damaged topology failed and
  restored the previous release/config/unit state instead of generating replacement credentials.
- Core/PVE broker responses verify against the public keys pinned for that exact server;
  receipt private keys are root-only and domain-separated. Run `healthcheck.sh --endpoint` on join.
- On `init`, only a host with executable `/usr/bin/pvesh` has the PVE broker unit, state/audit
  tmpfiles, runtime socket, and health checks. On `join`, require that fact and the signed `--pve`
  enrollment to match exactly. Historical PVE state/audit remains preserved on cleanup. Verify the
  PVE unit retains `ProtectSystem=full` and opens only exact `ReadWritePaths=/etc/pve` for local
  pmxcfs mutation; the core broker must keep `/etc/pve` inaccessible.
- For each PVE endpoint, prove the controller's active `workload.pve` registration digest equals the
  endpoint policy pin; the policy lists only observed nodes/storages/VMIDs/migration targets and
  intentionally enabled operations, has no derived standing grants, and the cluster has exactly one
  mutation endpoint. Refresh capabilities after policy activation, verify a domain-separated signed
  PVE receipt for all five read methods, and prove wrong-digest/unlisted-resource/core-domain requests
  fail before any approved mutation.
- For an upgraded PVE endpoint, verify legacy `pve/qemu/<vmid>` and `pve/lxc/<vmid>` locks migrate
  to one cluster-global `pve/vmid/<vmid>` owner; any collision must stop initialization. Exercise a
  recovery child with `recoveryOfChangeId` and confirm running/lost-UPID parents retain their lock,
  a terminal/no-start parent transfers atomically to a locally approved child, restart does not
  revive the parent, child failure retains the lock, and commit releases it. Also verify PVE
  `Prepare` is read-only, primary intent precedes every API, and restore finishes stopped/unlocked.
  For a real long-running mutation, require the initial approval response to be a valid PVE-domain
  signed `EXECUTING` receipt only after the UPID is present in both the root-only task artifact and
  Change evidence. Stop issuing status requests and prove the broker-owned worker still reaches
  signed `COMMITTED`; separately cancel the client request and prove it does not cancel the task.
  Restart the broker while the task is running and prove it resumes the same UPID exactly once.
  A terminal task error or fresh broker poll/verification timeout must enter `RECOVERY_REQUIRED`
  with the VMID lock retained, while orderly daemon shutdown alone must preserve
  `EXECUTING`/`VERIFYING` for restart rather than fabricate failure.
  Treat the v0.3 lock as broker-local, not distributed: configure exactly one mutation endpoint per
  PVE cluster and route other nodes to it or keep them read-only; cluster fingerprint enforcement is
  not implemented.
- Healthcheck, service restart, and an interrupted-change status query preserve authoritative
  broker state and do not replay mutation.
- Generate controller and Unix-RPC request deadlines from the active server clock. Verify an expired
  deadline, or a clock retreat that would extend the window beyond ten minutes, fails before backend
  dispatch; the transport must derive its monotonic execution timeout from that same clock.
- Approval smoke must show that prepare binds the real bounded/redacted user input to the exact
  Session, turn, and change. Multiple pending changes must keep separate intent; later prompts,
  wrong-turn events, Client restart, or Session resume must not substitute a global last input.
  If that ephemeral binding is unavailable, require a fresh concise request and prepare instead
  of approving or rolling back the old change reference with a synthetic fallback.
- A missing optional adapter does not break core/TUI operation.
- A failed bubblewrap/user-namespace preflight rolls back the complete `init` transaction and
  does not leave a controller that cannot load the mandatory `workload.base` Source Workload.

Run the repository verification commands from `AGENTS.md` for implementation changes. For a
real deployment, also run the deployment smoke and recovery checks on the target Linux host.
On failure, require the installer transaction to restore identities/groups, runtime/server/TLS
configuration, units/drop-ins and prior enabled/active state, Source trees/registry, wrappers,
sudoers, `current`, and policy. Never snapshot or rewind Adapter secrets or broker state/audit.
Before upgrade/uninstall, stop ingress and reject every PREPARING/EXECUTING/VERIFYING/ROLLING_BACK
store; the installer must refuse an active broker rather than interrupt it. Use the root-only
failure-injection stages on an isolated systemd test host for upgrade smoke; if rollback reports
incomplete recovery, preserve its transaction evidence and never call the partial deployment
successful. Service activation happens after commit, so a post-commit start/health failure is a
degraded installed release to diagnose, not permission to overwrite live state with the old tree.
