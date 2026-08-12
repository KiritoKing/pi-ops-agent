#!/usr/bin/env node
import { mkdir } from "node:fs/promises";
import { AuditLog } from "./audit.js";
import { loadAgentConfig, readCredential } from "../shared/config.js";
import { AgentServer } from "./server.js";
import { SessionFactory } from "./session.js";
import { GuardianHeartbeat } from "./guardian-heartbeat.js";

async function main(): Promise<void> {
  const configPath = process.env.OPS_AGENT_CONFIG ?? "/etc/ops-agent/agentd.json";
  const config = await loadAgentConfig(configPath);
  await Promise.all([
    mkdir(config.stateDir, { recursive: true, mode: 0o750 }),
    mkdir(config.workspaceRoot, { recursive: true, mode: 0o750 }),
    mkdir(config.sessionDir, { recursive: true, mode: 0o750 }),
    mkdir(config.agentDir, { recursive: true, mode: 0o700 }),
  ]);
  const audit = new AuditLog(config.auditPath);
  await audit.initialize();
  const sessions = await SessionFactory.create(
    config,
    audit,
    await readCredential(config.apiKeyCredential),
  );
  const server = new AgentServer(config, sessions, audit);
  await server.start();
  const guardianHeartbeat = new GuardianHeartbeat(
    config.guardianHeartbeatPath,
    (error) => { void audit.append({ type: "guardian_heartbeat_failed", message: error.message }); },
  );
  await guardianHeartbeat.start();

  let stopping = false;
  const stop = (): void => {
    if (stopping) return;
    stopping = true;
    void guardianHeartbeat.stop()
      .then(async () => await server.stop())
      .finally(() => process.exit(0));
  };
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
}

main().catch((error: unknown) => {
  process.stderr.write(`ops-agentd: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
