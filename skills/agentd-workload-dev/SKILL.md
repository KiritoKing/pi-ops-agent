---
name: agentd-workload-dev
description: Design, implement, test, and optionally contribute a source-form Pi Ops Agent workload that adds sandboxed tools or tightly typed operational recipes. Use when creating a workload, moving tools out of core, grouping a safe operational workflow, adding a typed privileged operation, or updating a workload whose source digest and persistent approval must be renewed.
---

# Develop an Agentd Workload

Treat a workload as untrusted code plus a reviewable authority request. A workload may improve
ergonomics, but it cannot create a generic root, shell, argv, filesystem, container, or policy API.
Core registers no agent-visible business tools. A usable controller requires locally approved
`adapter.tui` and `workload.base`; initialization must fail closed and roll back when the real
bubblewrap/user-namespace host is unavailable.

## Load the contract

Read the repository-root `AGENTS.md`, then read:

- [architecture](../../docs/architecture.md), [security model](../../docs/security-model.md),
  [deployment](../../docs/deployment.md), and [operations](../../docs/operations.md)
- [`workload.base` source demo](../../plugins/workload-base/workload.mjs) and its
  [`manifest.json`](../../plugins/workload-base/manifest.json)
- [`internal/pluginregistry`](../../internal/pluginregistry/manifest.go) for source validation,
  digest binding, immutable snapshots, activation, and rollback
- [`src/shared/workload-runtime.ts`](../../src/shared/workload-runtime.ts),
  [`src/agentd/workload-host-runner.ts`](../../src/agentd/workload-host-runner.ts), and
  [`src/agentd/workload-providers.ts`](../../src/agentd/workload-providers.ts) for the isolated ABI
  and trusted-provider boundary
- [`src/shared/messages.ts`](../../src/shared/messages.ts) and
  [`internal/protocol/messages.go`](../../internal/protocol/messages.go) before changing a
  privileged tagged union
- [`internal/roothelper`](../../internal/roothelper/service.go) for authoritative state,
  execution, verification, rollback, and audit behavior

The source manifest is `agentd.plugin/v1`, schema `1`, with exact fields `apiVersion`,
`schemaVersion`, `id`, `kind`, `version`, `publisher`, `description`, `entrypoint`,
`capabilities`, and `requestedScopes`. Use `kind: "workload"`, a `workload.*` ID, a normalized
package-relative entrypoint, and sorted unique capability/scope arrays.

In v0.3 the source entrypoint is an executable extension point, but never an in-process one. The
fixed workload host runs `workload.mjs` from the immutable CAS in a fresh no-network, nested
bubblewrap. The outer fixed bwrap retains its default PID 1 reaper and executes only the same fixed
root-owned inner bwrap; the inner makes Source PID 1 and disables further user namespaces. A dedicated
`--sync-fd` remains open only in the outer PID 1 after launch, while bounded `--info-fd` output binds
that init's exact process identity. Both the sync EOF and identity disappearance are required before
the invocation and digest lease may settle. Sync failure must still wait for identity disappearance;
an unreadable initial stat accepts only later ENOENT, and missing authoritative info remains
fail-stop. This covers managed settlement, not broker restart, forced disconnect, hard-deadline, or
runtime-SIGKILL crash persistence. This still uses root-owned
fixed runtimes, empty namespace capabilities, nested-userns denial, and bounded
CPU/address-space/process/file/fd limits. It has read-only source, bounded framed IPC, and no host
credentials. Source may
declare tool schemas, business validation rules, perform pure computation, and orchestrate only the trusted providers it
listed. Tool capability and provider name are independent: descriptor capabilities must exactly match the
active manifest, while provider authority comes only from manifest `requestedScopes` covering every scope
required by the provider-name policy. A matching capability name or first-party ID grants nothing. New
host/root behavior therefore needs a narrow reviewed typed provider and, when
privileged, a broker tagged-union arm; never add in-process import/eval, a shell callback, or an
arbitrary command provider.
Every invocation must connect as its real UID to the fixed peer-authenticated lease broker socket,
acquire the registry's shared per-plugin lease for the exact active digest without opening the
broker-only lock directory, and retain it through provider calls, signed status handling, and local
audit. Registration, activation, and deactivation use the exclusive side of the same lock. A
current A-to-B test must prove the update fails before activation while A is in flight, succeeds
after A drains, and no new A provider request can start after B is current. Pre-existing signed
pending plans retain exact-A recovery and rejection evidence, but Client approval must fail once B
is current and require a newly prepared B plan. On the second confirmation, the Client/lease-broker
A lease is only a defense-in-depth precheck. After the first signed status, the root submitter must
independently extract one canonical workload ID/digest, reject mixed/missing/conflicting provenance,
and directly hold its own exact-current shared lease from the fixed registry through reviewer, TTY,
the second status, and the final broker action. Prove Client/broker lease loss cannot release this
root lease or let B activate. Candidate registration/install/deploy and rollback do not require the
candidate/old digest to remain runtime current.
Never add a host-shell, in-process loader, Docker, or reduced-isolation fallback for systems without
bubblewrap/user namespaces. Because `workload.base` is mandatory, that condition fails the whole
initialization transaction rather than merely hiding `ops_bash`.

Keep Ubuntu Noble AppArmor compatibility outside Workload authority. Under
`kernel.apparmor_restrict_unprivileged_userns=1`, only the version/hash-pinned
`configure-noble-bwrap-apparmor.sh` and exact host-wide `/usr/bin/bwrap ix,` may prepare the host;
the rule is path-wide, cannot bind project argv, and requires model-external local approval before
`init`. The canonical approval digest binds the exact package/version/source/rule and the complete
pre-confirm authority-summary hash; this Release pins
`sha256:d2b2928681d31e9430a9a2a1949ead607580311cba35b776e6a651e1d67254ef` and summary SHA-256
`c745e2eb341efc1a26b017e63cc03b284f63f51298036ce58e9e6661d7f7015c`. The disclosure must cover
the argv-blind host rule, long-lived Core setup-profile authority, BotMux unsupported state, and no
automatic removal. `ops-agentd` then uses typed `AppArmorProfile=-bwrap`. Require the helper's
root-owned, closed-world `NoNewPrivileges=yes` static smoke plus the installer preflight to prove
outer→fixed inner, final Source PID 1 under `unpriv_bwrap`, all capability sets zero, and no further
userns/nested bwrap.
The hosted helper-bound gate is still pending for this candidate, so keep `init` fail closed unless
those exact checks succeed; local/static validation is not production evidence.

This Noble-only compatibility covers direct Node `ops-agentd` and mandatory `workload.base`; it does
not authorize a workload, provider, or Adapter to manage host policy. BotMux guard decisions are
fact-first: every host with readable restricted-userns=`1` and AppArmor=`Y/y` refuses before setup
mutation; Noble also refuses missing/unreadable restriction evidence, while another host may continue
only when that sysctl is safely absent. A direct Adapter probe does not override this. Never
compensate in a workload descriptor/provider/source, requested scope, install hook, broker arm,
sysctl, SUID/unconfined setting, or single-layer fallback. Host-policy helper invocation never runs on
`join`, requires reapproval after distribution profile version/hash/rule/authority-summary drift, and
preserves policy on default uninstall.

Keep the runtime and unit contract synchronized: both Workload bwrap layers use only
`user/ipc/pid/net/mnt`,
while `ops-agentd.service` allow-lists exactly those namespace types. Do not add cgroup, UTS, or time
namespaces. Preserve `ProtectHostname=yes`, nested-userns denial, and the narrow
`ReadWritePaths=/proc/sys/user/max_user_namespaces` exception that the fixed outer uses to create the
inner namespace and the inner uses to deny later nesting. Bubblewrap must verify that denial by its
own post-setup `CLONE_NEWUSER` attempt; the numeric value visible in final procfs is not equivalent
evidence. Keep `PrivateDevices=yes`, `ProtectKernelTunables=yes`, `ProtectProc=invisible`, and
`ProcSubset=all` in the effective unit vector. `all` intentionally retains otherwise-unmasked,
read-only non-PID procfs metadata so the namespaced sysctl exists; `invisible` hides only foreign-UID
PID directories, not same-UID PIDs or that metadata. Update the unique, root-owned, short-lived
static install probe under `/run/systemd/system` whenever these arguments or hardening properties
change, and keep its exact cleanup contract synchronized.

The `ops-agentd` drop-in is one member of the installer-wide managed service contract, not a special
file whose presence alone proves safety. If a workload/provider change alters any managed service
unit or hardening, update its unit-name-specific final `zzzz-ops-agent-security.conf`, Release
packaging, transaction snapshot/rollback, PID 1 lifecycle/security effective verification, docs,
and tests in the same change. Preserve topology: `init` owns controller services plus local
server/core (and host-fact PVE); `join` owns only server/core plus enrollment-and-host-matched PVE.
Never add controller service/drop-in surfaces to join or leave managed PVE surfaces on non-PVE hosts.

## Choose the least authority

- Keep diagnostics and workspace file operations inside the non-networked agent sandbox when
  possible. Bound command duration, output, paths, and redaction.
- Use an existing typed broker operation when it fully expresses the change. Otherwise add a
  new minimal tagged-union variant across TypeScript and Go; never pass generic executable,
  `argv`, shell text, `pvesh`/`qm`/`pct` arguments, host path, UID, or `runAs` from the model.
- Do not disguise an untyped administrator script as a workload provider. The separate core manual
  root capsule may be prepared for any root Target, but it has no standing scope and is always
  locally, per-change PASSWD-sudo and `/dev/tty` approved. Script text/digest and network intent are
  mandatory. Keep every capsule critical. Treat `network=false` plus `PrivateNetwork` as best-effort
  intent, not an inescapable boundary for full-root code. Backup paths and a verify script may be
  empty; describe that script only as a caller-provided privileged postcondition, never an independent
  verifier, and require critical missing-evidence findings. It advertises no automatic rollback, and
  the PVE broker never accepts it; a workload must not weaken or duplicate that boundary.
- Resolve Target identity and resource allowlists from root-owned policy. Bind prepare and
  approval to server, machine, Target, plugin digest, requested scopes, plan hash, policy and
  capability revisions, preconditions, expiry, and nonce.
- Treat Target resource allowlists and standing authorization as separate gates. Only an exact
  ordinary scope explicitly present in `authorization.standingScopes` may execute during prepare;
  a missing/empty field and legacy policy require per-change human approval. Intersect that scope
  with the active plugin ID/kind/digest, exact descriptor/manifest capabilities, provider-name scope grant,
  and every resource constraint.
  Generic `file.write` and `service.action` are reserved to the actual `workload.base` caller: Core
  injects its current ID/digest, and standing use additionally requires the exact same
  `authorization.baseWorkloadDigest`. Never accept provenance supplied by plugin input or lend the
  base digest to another workload.
  For PVE, only exact guest start/shutdown, snapshot create, and guest backup scopes are eligible for
  standing authorization. Package/artifact installation, `plugin.register`, `plugin.install`,
  `workload.deploy`, manual root capsules, rollback, and critical PVE stop/reboot/snapshot delete/
  snapshot rollback/restore/migrate are never standing-authorized.
- Model each privileged recipe with typed parameters, resource locks, risk, write-before backup,
  fixed execution, authoritative verification, and deterministic rollback or explicit
  `RECOVERY_REQUIRED` evidence.
- Group related substeps into one typed recipe only when they share a target, invariant, and
  recovery boundary. Keep the approval plan explicit about every substep and risk.
- Keep credentials outside model context and source. Accept administrator-provisioned secret
  slots only through the documented model-external channel.

For a PVE workload, define separate node, VM, LXC, snapshot, backup, restore, and migration
operations. Use fixed broker-side commands or API paths and wait for the authoritative PVE task
terminal state identified by its bounded, node-bound UPID; never expose generic PVE CLI arguments
as a shortcut. Elevate guest stop/reboot, snapshot delete/rollback, restore, and migration to
critical review, reject them as standing scopes, and show resource IDs, source/target nodes,
storage, impact, and irreversible risk. A fake `pvesh` runner can
validate protocol, argv, UPID, and failure handling but is not real PVE validation; record the real
PVE lab scope separately. Never describe an inverse PVE action as automatic rollback: every
compensation must observe current state and become a new typed change with a new approval and UPID
evidence.

Local `pvesh` mutation handlers write pmxcfs. Keep `ops-pve-root-helper.service` at
`ProtectSystem=full` with only exact `ReadWritePaths=/etc/pve`; do not give that exception to the
core broker, Agent, server, or Source runtime. Never return or audit `/etc/pve/priv` paths, content,
or derived secrets.

Use `pve/vmid/<vmid>` as the cluster-global mutation identity; never split locks by node or
`qemu|lxc`. “Cluster-global” describes only the resource key shape: the v0.3 durable lock is local
to one broker and has no cluster fingerprint enforcement. Require exactly one mutation endpoint per
PVE cluster, route other writers through it or keep them read-only, and never claim distributed
locking. A compensation operation may expose the optional canonical-plan field
`recoveryOfChangeId`, but it must remain a normal typed operation for the same endpoint, Target,
and VMID. It is never standing-authorized. Before atomically transferring the parent lock to the
approved child, the broker must reconcile every durable safety/primary intent and known UPID:
running, query failure, unsupported status, or intent without a UPID all fail closed. Persist
`NO_MUTATION_STARTED` or terminal `stopped` task evidence in the parent resolution; a failed child
retains the VMID lock, a committed child releases it, and pruning must retain the complete selected
resolution chain.

Do not expose the broker's PVE unknown-result clearance as a workload provider, capability, tool,
or manifest scope. It is a separate model-external recovery escape hatch only for a
`STARTED_OR_UNKNOWN` parent with no known UPID. Any known UPID that is running or unqueryable must
remain denied; a known terminal UPID must use normal task reconciliation. The root-owned approval
submitter must require PASSWD sudo, a real `/dev/tty`, and a second exact confirmation independent
of the child plan approval. Bind a short-lived in-memory one-shot grant to the exact parent, child,
child plan hash, `pve/vmid/<vmid>`, and canonical active-task/guest/cluster observation digests.
Query active tasks only through `/nodes/<node>/tasks --source active --vmid N --limit 1`, including
both source and target for migration, and repeat the complete observation before confirmation and
atomic transfer. Expiry, restart, reject, drift, or persistence failure must leave the parent and
lock unchanged. A successful resolution uses `basis=local-unknown-clearance` and retains
`STARTED_OR_UNKNOWN`; never describe it as proof that no mutation occurred.

Keep PVE `Prepare` read-only. Fsync a primary intent before every primary API call, then perform the
full approved precondition recheck immediately before that call. Destructive snapshot safety
backup runs only after the durable execution barrier/audit and must persist its intent, UPID, and
unique volume before the primary phase. After it runs, the final check must still bind
`PreviousStatus` and permit exactly that one backup-set delta. Test lost-UPID, running task,
query failure, intent-write failure, restart, qemu/lxc same-VMID collision, precondition drift,
and TTL/quota pruning. An empty active-task inventory is not terminal proof for a known UPID.

For every long-running PVE mutation, persist the node-bound UPID in both the root-only task artifact
and Change evidence before returning a signed `EXECUTING` receipt. That receipt means durable
handoff, not success. Continue through a broker-owned, per-change singleflight worker with a fresh
bounded context for each poll and verification step; never couple it to the approval HTTP/CLI
context or require later status requests to drive progress. Daemon shutdown must preserve
`EXECUTING`/`VERIFYING` plus the VMID lock, and startup must resume from the journal without starting
the API twice. A fresh poll timeout/query error, terminal task failure, lost UPID, or verification
failure fails closed with evidence and lock retained. Tests must cover convergence without another
HTTP request, canceled client context, running-to-terminal restart, duplicate scheduling, terminal
failure, and daemon cancellation versus a real per-step timeout.

Deploy a PVE endpoint as the non-root server plus separate core and PVE brokers. Keep PVE on its own
socket/state/audit/receipt domain and fixed `/usr/bin/pvesh` paths; use the core broker, never the PVE
broker, for the separately approved manual root capsule.

For a systemd-backed service workload, use `workload.hermes-ops` or `workload.botmux-ops` as the
reference. Put the business unit/path profile in the source schema using only the ABI's anchored,
bounded safe-pattern subset. Read tools may call `target.inspect`; lifecycle tools call the generic
`workload.service.manage` provider and request `control.workload.service.manage`. That provider rejects
`workload.base`, revalidates the actual caller, and prepares `workload.service.action` with its active
plugin ID/digest plus a validated account, `system|user` manager, unit, and
`reload|reset-failed|restart|start|stop`.
Do not encode a negated control-character class in a descriptor pattern: it is outside the safe
pattern subset. Keep the descriptor length-bounded and reject C0/C1, bidi controls, directional
isolates, and BOM explicitly in digest-covered `invoke` code before any provider call; provider and
Go validation remain independent mandatory boundaries.
Core and the broker must not hardcode the reference plugin IDs or business profile. Root-owned Target policy must
match every field and bind the workload account to the Target account. The broker must inspect and
bind current UID/load/active/sub state before approval, use fixed no-shell `systemctl`/`runuser`
argv, and verify the terminal service state. Do not infer that an inverse service verb restores
lost in-memory or external work: advertise no automatic rollback and require any compensation to
be a newly prepared typed change with current preconditions and separate approval. `reload` requires
an active start/end state and `reset-failed` requires failed → non-failed; both are always per-change
approval even if the Target names `workload.service.action` as a standing scope.

For one policy-mapped scalar in an account-owned JSON document, use
`workload.json-config.edit` and request `control.workload.json-config.edit`; never compose JSON
through `file.write`, a shell, raw patch, or user-selected helper. Source input is limited to
machine/Target, a semantic profile and selector, a semantic field key, and an exact
`string|boolean|clear` tagged value. Reject controls/bidi text in digest-covered source before the
provider call. The trusted provider must reject `workload.base`, revalidate and inject the actual
caller ID/source digest, and accept only a signed `PENDING_APPROVAL`; this operation is always local
per-change and never standing. Define account/UID/home-relative config, selector key/allowlist,
actual JSON fields, types, enum/model/path constraints and path roots only in root-owned
`jsonConfigWorkloads` policy. Preserve the fixed root-owned helper, target-UID hardened transient
unit, strict JSON/openat2 checks, root-sealed before/after evidence, whole-document rewrite notice,
digest CAS, exact-digest approval lease, and `RECOVERY_REQUIRED` on unknown exchange outcome. For
absolute-path fields, bind and recheck root/directory identity while documenting that the same UID
or another locally authorized parent-directory writer may replace the pathname after verification.
Use `plugins/workload-botmux-ops` as the reference and
keep service restart as a separately prepared operation.

For a fixed read-only business CLI, use `workload.command.inspect`; never add raw command/argv to
`target.inspect` or `change.prepare`. Source input may contain only machine/Target plus a bounded semantic
`profileKey`. The trusted provider must reject `workload.base`, revalidate current caller, inject its exact
ID/digest, call the dedicated HTTPS route, and verify the pinned core broker receipt over
server/machine/Target/method/plugin/digest/profile/result digest. The root-owned Target profile holds the
non-root run-as account/home, executable, complete argv, timeout, and output bound. At invocation, resolve
symlinks and require both original and resolved path trees to be root-owned and group/world non-writable;
reject user-owned CLI installs. Execute only through fixed `systemd-run --wait --pipe --collect --uid=...`
with `ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateNetwork=yes`, clean env, RuntimeMaxSec, and
control-group kill. Keep the broker unit itself at `ProtectHome=yes`.

Neither Root nor Agent audit may store command output; record only SHA-256, UTF-8 byte count, truncated,
profile identity, and receipt metadata. Core redaction is only a floor. The source workload must rebuild
the model-facing result from a business allowlist. For setup/config JSON, use a digest-covered, source-local
bounded parser that rejects duplicate keys after escape decoding, trailing values, excessive depth/size,
truncation, and invalid controls; do not rely on native `JSON.parse` last-key-wins behavior. Copy only exact,
case-sensitive allowlisted fields, never object-map keys, and discard unknown or Unicode-confusable fields and
entire secret-bearing subtrees such as `env`; never trust an upstream mask. The standard BotMux sanitizer also
drops `cliRuntime`, `update`, command/args/cwd/path, and credential-shaped fields. Add negative tests proving
raw output, duplicate/trailing/deep/oversized inputs, confusable keys, controls, fallback keys, and marker
secrets are absent from audit and sanitized results or fail closed.

## Implement and verify

1. Write a capability table: operation, input type, target, read/write effect, required scope,
   approval class, backup, verification, rollback, timeout, and output bound.
2. Copy `plugins/workload-base` as the minimal source layout. Implement the bounded workload
   descriptor/invocation ABI and declare only the business capabilities and requested provider scopes in that table.
   Keep provider names sorted in each tool. Prove that an unrelated capability can use an approved provider scope,
   and that spoofing a provider name as a capability without its required scope is rejected.
   Reuse existing narrow trusted providers; if none exists, implementing and reviewing a typed
   provider (and any broker arm it needs) is part of the workload change.
3. Implement non-privileged tools with strict schemas. For every new root operation, update the
   TS and Go tagged unions, boundary decoders, policy, prepare plan, executor, store/recovery,
   audit, and docs in one change.
4. Test unknown/extra fields, scope denial, wrong peer UID, stale policy/capability/plugin digest,
   expired or replayed approval, concurrent mutation, timeout, partial failure, verification
   failure, rollback failure, bounded output, secret redaction, shared-lease loss, and exclusive
   update rejection while an old-digest provider call is in flight.
5. Inspect the final source tree through the registry. Present and bind ID, kind, version,
   publisher, canonical digest, complete capabilities, and complete sorted requested scopes in the
   typed `plugin.register` plan; register and activate only after an exact model-external local
   approval. Treat first-party and third-party source identically. Every install or changed digest
   requires a new local approval, and registration itself is never a standing operation.
6. Preserve the prior immutable snapshot and recovery evidence. Do not call success until the
   controller performs a fresh `change.status` request and validates a `COMMITTED` receipt with the
   pinned key for that broker domain. Only signed `PENDING_APPROVAL` may expose an approval side
   channel; signed `COMMITTED` after prepare identifies standing execution.

Keep approval review independent of workload output and agent narration. The current reviewer sees
only the user's original bounded input and broker-authoritative plan, applies deterministic risk
floors, and cannot approve. Its bounded quote/nesting-aware lexical structure can display shell
segments and dependencies, but opaque wrappers, argv, or expansion must become critical and it is
not a full Shell AST or semantic verifier. A `split-required` result must remain a structured
non-authorization and must not reach the submitter. Do not claim LLM review, AST splitting, or
risk-based auto-approval is implemented.

Run `npm run check`, `npm run build`, `go vet ./cmd/... ./internal/...`,
`go test -race ./internal/...`, and `git diff --check`. Add Linux/systemd integration tests and
failure-injection coverage for privileged or host-specific recipes.

## Optionally contribute

Only if `command -v gh` succeeds, offer an optional pull-request workflow. Proceed only after
the user agrees: inspect the diff, create a focused branch and conventional commit, push it,
then use `gh` to open a draft PR with the capability table, manifest digest/scopes, threat tests,
backup/verification/rollback evidence, and verification results. If `gh` is absent, do not
mention or block on a PR.
