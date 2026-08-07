#!/usr/bin/env node
import { loadAgentConfig } from "../shared/config.js";
import { runClient } from "./app.js";
import { parseClientArguments } from "./args.js";

const VERSION = "0.2.0";

async function main(): Promise<void> {
  const invocation = parseClientArguments(process.argv.slice(2));
  if (invocation.kind === "version") {
    process.stdout.write(`pi-ops-agent ${VERSION}\n`);
    return;
  }
  const configPath = process.env.OPS_AGENT_CONFIG ?? "/etc/ops-agent/agentd.json";
  await runClient({
    arguments: invocation.arguments,
    config: await loadAgentConfig(configPath),
  });
}

main().catch((error: unknown) => {
  process.stderr.write(`ops-agent: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
