---
name: agentd-adapter-dev
description: Design, implement, test, and optionally contribute a source-form Pi Ops Agent adapter that connects an external chat or automation system to core sessions, inbound messages, outbound events, and status-only approval fallback. Use when adding a new adapter, extending adapter capabilities, reviewing adapter trust boundaries, designing a future authenticated ApprovalIntent contract, or updating an adapter after its source digest changes.
---

# Develop an Agentd Adapter

Build the adapter as untrusted source. First-party and third-party adapters use the same
review, digest, scope, and per-install local approval rules. Core has no agent-visible business
tools; a usable controller requires the separately approved `adapter.tui` and `workload.base`.
Initialization must fail closed if the real bubblewrap/user-namespace host for the mandatory base
workload is unavailable.

## Load the contract

Read the repository-root `AGENTS.md`, then read:

- [architecture](../../docs/architecture.md), especially compiled Client, local session gateway,
  and Adapter routing
- [security model](../../docs/security-model.md), especially approval and secret boundaries
- [deployment](../../docs/deployment.md) and [operations](../../docs/operations.md)
- [`adapter.tui` declarative profile](../../plugins/adapter-tui/profile.json) and its
  [`manifest.json`](../../plugins/adapter-tui/manifest.json)
- [`internal/pluginregistry`](../../internal/pluginregistry/manifest.go) for the authoritative
  source manifest and snapshot rules
- [`src/client/events.ts`](../../src/client/events.ts) for bounded outbound completion events
- [`src/shared/adapter-runtime.ts`](../../src/shared/adapter-runtime.ts) for the strict descriptor and behavioral ABIs
- [`src/runtime/adapter-run.ts`](../../src/runtime/adapter-run.ts) for the fixed non-root host

The source manifest is `agentd.plugin/v1`, schema `1`, with exact fields `apiVersion`,
`schemaVersion`, `id`, `kind`, `version`, `publisher`, `description`, `entrypoint`,
`capabilities`, and `requestedScopes`. Use `kind: "adapter"`, an `adapter.*` ID, a normalized
package-relative entrypoint, and sorted unique capability/scope arrays.

The core never imports or evaluates untrusted adapter source in the `agentd` process. The fixed
runner supports approved executable `.mjs` entrypoints: it revalidates the root-owned CAS, captures
a strict descriptor, revalidates current against digest drift, then spawns Source and the release
compiled Client as sibling processes without a shell under
the caller's non-root UID and a sanitized environment. The runner must connect as that real UID to
the fixed peer-authenticated lease broker socket and retain an exact-digest shared registry lease
for the complete runtime; it must never open the broker-only lock directory. Both the descriptor probe and the main source
entrypoint must launch through their own fixed, nested bubblewrap PID namespaces. The outer fixed
bwrap keeps its default PID 1 reaper and may execute only the same fixed root-owned inner bwrap. It
must retain `--proc /proc` so its procfs matches the outer PID namespace; the fixed inner also
retains `--proc /proc`, so untrusted Source sees only the inner PID namespace's private procfs.
Omitting outer `--proc` breaks the inner namespace-FD lookup and is not a supported fallback. The
outer must not use
`--as-pid-1` or `--disable-userns`. The inner bwrap uses
`--unshare-user --unshare-pid --as-pid-1 --die-with-parent --disable-userns`, makes Source PID 1,
and denies further nesting. Outer bwrap must also retain a runner-observed `--sync-fd` that only its
PID 1 owns after launch and emit one bounded `--info-fd` `child-pid`; bind that PID's start identity.
Do not release the digest lease until the sync FD reaches EOF and the exact init identity disappears
from `/proc` (or is proven reused) after every detached/unref descendant is reaped. A sync error must
not short-circuit the identity wait; an unreadable initial stat requires later ENOENT, and missing
authoritative info keeps the invocation fail-stop. This managed-settlement guarantee is not yet a
crash-persistent broker guarantee across broker restart, forced disconnect, or runtime SIGKILL.
This preserves the Adapter's business network, host-user
permissions, and controlling TTY; do not describe it as the no-network Workload sandbox. Bubblewrap
itself must use `--dev /dev` to construct a minimal synthetic device view such as `/dev/null`;
never replace it with `--dev-bind /dev /dev` or otherwise re-bind the host device tree.
Do not infer supplementary-group preservation from those bwrap arguments. After `npm run build`,
run `npm run test:adapter-linux-runtime` as root on the target Linux host. It drops to the real
`ops-agent-botmux` account with primary `ops-agent-botmux` and supplementary `ops-agent-client`,
inside a transient systemd service that reproduces the BotMux hardening drop-in. The boundary permits
only `user/pid/mnt` namespaces in both layers and keeps `PrivateDevices=yes`,
`ProtectKernelTunables=yes`, `ProtectProc=invisible`, and `ProcSubset=all`; its sole sysctl write
exception is `/proc/sys/user/max_user_namespaces`, which the fixed outer needs to create the inner
namespace and the inner then uses to deny any further nesting. The probe must use a unit-specific
late drop-in and verify the effective scalar/list/path vector with `systemctl show`, so a host-wide
`service.d` reset cannot produce a false pass. Be explicit that `ProcSubset=all` leaves otherwise
unmasked read-only non-PID procfs metadata visible and `ProtectProc=invisible` hides only foreign-UID
PID directories, not same-UID PIDs or that metadata.
Do not confuse this transient probe drop-in with the installer-wide service contract. Every managed
daemon ships its own unit-name-specific final `zzzz-ops-agent-security.conf`, and installation must
verify PID 1's exact lifecycle/command/environment plus security effective vector after reload.
Adapter work that changes a controller service or its hardening must update that final drop-in,
packaging, the mode-specific installer check, docs, and tests together; it must not make the service
or its drop-in appear on a server-only `join` endpoint.
The probe then proves access to a `root:ops-agent-client 0640` fixture and group `0660` Unix socket, PID
namespace cleanup of a detached child using a host-side exact PID/starttime capture (never inner
`NSpid` self-reporting), fragmented FD4 input plus reverse FD3 completion through real
bwrap, and release ordering for the exact-digest lease. Source Adapter messages must use this bounded
typed channel; positional argv and `@file` prompts are forbidden. Exit status
`77` means the Linux/root/systemd/account/bwrap prerequisites were absent and is not a passing result. Never
replace this check with a fake bwrap or a mocked effective UID/GID.

Do not hide Ubuntu Noble AppArmor failures inside an Adapter change. When
`kernel.apparmor_restrict_unprivileged_userns=1` and AppArmor is enabled, this Release does not
support controller `init`; it must fail before any persistent mutation. The hardened hosted unit
proved the required outer `--proc /proc` returns `EPERM`, while GitHub Actions run `31319405888`
(commit `7091ecfbc28ae6410f06d4e2b64462c96dd83726`, job `93259846767`) proved that omitting it makes
the fixed inner fail with `open /proc/3/ns/ns failed`. Do not recommend `host-policy install`, cite
old managed state as support, modify the sysctl, use SUID/unconfined bwrap, remove a layer, or lower
`ProtectProc`/systemd hardening. Real support needs an independent typed short-lived spawn
supervisor. Preserve any existing managed files/kernel profiles as evidence; automatic removal is
not safe. BotMux remains fact-first fail closed on observed restricted-userns + AppArmor. A
server/core/PVE-only `join` endpoint does not run Source plugins and is outside this controller
restriction; Adapter code must never manage host policy.

`adapter.tui` is instead a non-executable profile: the runner starts the compiled Client directly
to preserve host sudo/PAM, and that Client independently holds the exact TUI digest lease until it
exits so runner failure cannot leave an unleased approver. Do not use the TUI exception for source.
`profile.json` is the only declarative Adapter; only its exact fixed grant may request
`approval.submit.local`, and the runner
launches the compiled Client after validating the local-TTY profile. Every other adapter is forced
to `status-only`.
This is real user-level code execution authority: approval of the digest authorizes everything the
Adapter UID can read or write. Never add an in-process import/eval, arbitrary callback command, or
root execution of source.

Except for the declarative TUI profile, on the exact sole argument
`--agentd-adapter-describe`, an entrypoint must print one bounded JSON
object matching `agentd.adapter/v1`, schema `1`, then exit `0` without reading secrets or changing
state. Declare adapter ID, fixed `runtimeAuthority` (execution, host filesystem/network,
runtime-UID-readable credentials, and digest-review/typed-IPC action enforcement), session
mapping/writer lease, inbound/outbound transport/framing/limits,
supported inbound types, session controls, outbound actions, and approval mode/identity/replay
semantics. Use `plugins/adapter-botmux-source` as the executable
`.mjs` example; `adapter.tui` is a privileged local-recovery exception, not a template.

Use the behavioral contracts in `src/shared/adapter-runtime.ts`:

- `agentd.adapter-inbound/v1`: bounded `text` with stable ingress/session IDs, conversation type,
  source and observation time. Authenticated source evidence carries only bounded issuer, subject,
  evidence ID and time; it is not an ApprovalIntent and must not authorize any change.
- `agentd.adapter-session-control/v1`: `bind`, `handoff`, `compact-request`, `clear-request`.
- `agentd.adapter-outbound-action/v1`: `send`, `reply`, `quote`, `mark`, `display`.

Declare only variants the integration really implements. The runner maps each declaration to
`adapter.inbound.<type>`, `adapter.session.<control>`, or `adapter.outbound.<action>` and the same
scope with the Adapter namespace appended. The complete sorted derived capability/scope arrays must
equal the manifest arrays. Never replace them with broad `message.inbound`, `message.outbound`, or
`session.manage` grants. Current TUI is exactly `text + bind + display`; current BotMux is exactly
`text + bind + send`. BotMux fixed `send` is not message-ID reply or quote.

This exact grant is review metadata and a typed IPC contract, not an OS action sandbox for executable
source. A credential-bearing Adapter can directly call platform APIs/CLIs with every permission of
its dedicated runtime UID. Registration review must therefore show the exact runtime identity,
host filesystem/network access, runtime-UID-readable credentials, and the fact that direct platform
calls are not action-scope-enforced. Never claim that a `send` declaration alone prevents source
from performing `quote`; only a future mediator that exclusively owns the platform credential can
make that guarantee.

The shipped external-Adapter boundary uses fixed FD 4 for strict NDJSON inbound `text` and session
`bind`, and FD 3 for `completion.v1`. The runner alone gives the compiled Client FD 5 containing the
captured descriptor, active plugin ID, and digest; Source must never spawn the formal Client or pass
initial input through its argv/`@file`. Client enforces raw wire bytes before fatal UTF-8, strict
duplicate/trailing JSON parsing, the declared union, bind correlation, and process-local ingress
replay checks. There is still no consumer for the other session controls, generic outbound action
mediator, persistent outbox, or remote ApprovalIntent. Cross-client writer ownership is instead a
Core transport invariant: every descriptor must declare `session.writerLease: "gateway-global"`.
The fixed `agentd-client-gateway` derives its backend Session namespace from kernel-observed UID,
exact active Adapter ID/digest, and external Session ID, and rejects a second live writer. Adapter
source cannot choose or bypass that namespace merely by guessing another Adapter's Session ID.

## Preserve the behavioral boundaries

- Session management: map stable external conversation/thread identity to an Agent session;
  preserve one active writer through the mandatory gateway-global lease; make session switch/handoff explicit; let core own context
  compaction and cleanup policy. Do not declare `handoff`, `compact-request`, or `clear-request`
  until an actual transport consumer and behavior exist.
- Inbound messages: authenticate sender and conversation type before normalization; retain a
  bounded stable ingress/message ID; persist deduplication; mark all content untrusted; remove
  credentials; never forward exact approval commands into the model.
- Outbound events: consume the versioned bounded event contract; expose only implemented typed
  platform actions; provide a final-text fallback; keep fixed executable/argv structure and never
  interpolate message text through a shell. A generic `send` implementation does not justify
  declaring `reply`, `quote`, or `mark`.
- Completion: deliver one completion for the authoritative settled turn. A disconnect or retry
  must not produce a duplicate or declare a retrying turn complete.
- Approval: the current runtime forces every non-TUI adapter to `status-only`; no released
  `ApprovalIntent` ingestion contract lets adapter source approve, reject, or roll back. A future
  versioned contract may accept an intent only when the adapter independently proves the sender,
  private-conversation semantics, ingress identity, and replay state. Even then, adapter source
  must not read an ApprovalGrant signing key or authorize itself; a future model-external approval gateway
  must bind the authenticated principal, change reference, plan hash, and current revisions.
  Until that contract exists, always fall back to local CLI/TUI approval.
- Change state: after every prepare, the controller must fetch `change.status` with a fresh request
  ID and verify the receipt with the pinned key for that broker domain. Only a signed
  `PENDING_APPROVAL` result may enter an approval side channel. A signed `COMMITTED` result means an
  exact root-owned Target `authorization.standingScopes` grant was consumed; it is not an adapter
  approval. Never infer a terminal state from the adapter, agent explanation, or unsigned server
  response.
- Review: the independent reviewer consumes only the user's original bounded input and the
  broker-authoritative plan. The current reviewer is deterministic; do not claim it is an LLM,
  performs command-AST splitting, or risk-approves operations.
- Secrets: keep platform credentials in the adapter's administrator-owned boundary, strip them
  before launching core, and never include them in transcript, argv, completion text, or audit.

An `allowedUsers` string supplied by adapter configuration is not by itself proof of identity.
Group chat, forwarded messages, bots, ambiguous sender metadata, or failed deduplication must
not retain approval capability.

## Implement and review

1. Copy the manifest shape and executable/descriptor pattern from `plugins/adapter-botmux-source`;
   choose a new `adapter.*` ID and declare only required capabilities/scopes. Never copy TUI's
   `approval.local` / `approval.submit.local`; the runner rejects them for every other ID.
2. Reuse the shared inbound/outbound/session tagged unions at the core boundary. Write bind then
   text as newline-terminated frames only to inherited FD 4; never spawn Client or forward raw
   terminal bytes/initial argv into it. The Client treats each raw frame as unknown, applies the
   descriptor byte ceiling before fatal UTF-8, rejects unknown/duplicate/trailing fields and hidden
   controls, then verifies the declared variant and session binding. Add a new union version instead
   of silently widening v1.
3. Keep vendor SDKs and credentials outside `src/`; put integration-specific code under
   `integrations/<adapter>/` and run it behind the documented client/event boundary. Never load
   vendor source into the core process merely because its digest was approved.
4. Add fixtures and tests for valid private messages, group/forward/bot rejection, spoofed sender,
   replay, duplicate completion, reconnect, timeout, unknown/duplicate fields, oversized UTF-8,
   control characters, descriptor/manifest capability confusion, undeclared actions, secret
   redaction, and approval fallback.
5. Inspect the final source tree through the registry. Reject symlinks, devices, sockets, and
   oversized files. Present and bind ID, kind, version, publisher, canonical digest, complete
   capabilities, and complete sorted requested scopes in the typed `plugin.register` plan. For an
   Adapter, also verify the canonical plan/reviewer shows runtime identity,
   filesystem/network/credential authority and the direct-call limitation.
   Register the immutable snapshot only after model-external local human approval matches every
   field. `plugin.register`, legacy `plugin.install`, and `workload.deploy` are never eligible for
   standing authorization.
6. Treat every installation or source update as a new digest that requires a new local approval;
   preserve the prior
   immutable snapshot for rollback.
   Source Adapters must never use the private TUI self-update control FDs 6/7. That handoff is
   reserved for the fixed compiled Client after a second local confirmation of one canonical
   `adapter.tui plugin.register`; another TUI lease continues to block activation.

Run `npm run check`, `npm run build`, relevant adapter tests, the real Linux Adapter runtime probe,
Go tests when a protocol or registry boundary changed, and `git diff --check`. Exercise the adapter against a local fake
platform before any real credential or production conversation.

## Optionally contribute

Only if `command -v gh` succeeds, offer an optional pull-request workflow. Proceed only after
the user agrees: inspect the diff, create a focused branch and conventional commit, push it,
then use `gh` to open a draft PR describing capabilities, requested scopes, threat tests, and
verification. If `gh` is absent, do not mention or block on a PR.
