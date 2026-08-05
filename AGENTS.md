# Repository instructions

- Keep `agentd` unprivileged. It must never invoke `sudo`, read host credentials,
  or execute root commands directly.
- Root changes must use the tagged-union protocol implemented by `root-helper`.
- Only the real client peer may approve or reject a pending change. The model and
  `agentd` UID must never gain that capability.
- Do not add a raw root command RPC. Generic privileged work belongs in a
  digest-bound break-glass capsule with an explicit backup and verification plan.
- Never commit API keys, Feishu credentials, SSH material, runtime audit logs, or
  generated systemd credentials.
- Core code under `src/` must not depend on BotMux, Feishu, or any IM bridge.
  Bridges consume the versioned inherited-FD event protocol from `integrations/`;
  never replace it with an environment-configured callback command.
- Do not weaken the systemd units or bubblewrap profile to make a test pass.
- TypeScript must remain strict and may not use `any`. Run `npm run check` and
  `go test ./...` before publishing.
