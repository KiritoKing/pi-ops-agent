#!/usr/bin/env node
import { loadAgentConfig } from "../shared/config.js";
import { runClient } from "./app.js";
import { parseClientArguments } from "./args.js";
import { readAdapterClientContext } from "./adapter-channel.js";
import { escapeUntrustedTerminalText } from "../shared/terminal-safety.js";

const VERSION = "0.3.0";

async function main(): Promise<void> {
  const arguments_ = process.argv.slice(2);
  if (arguments_.length === 1 && (arguments_[0] === "--version" || arguments_[0] === "-v")) {
    process.stdout.write(`pi-ops-agent ${VERSION}\n`);
    return;
  }
  const adapterContext = await readAdapterClientContext();
  const invocation = parseClientArguments(arguments_, process.env, {
    allowInitialPrompt: adapterContext.descriptor.runtimeAuthority.execution === "compiled-client",
  });
  if (invocation.kind === "version") {
    process.stdout.write(`pi-ops-agent ${VERSION}\n`);
    return;
  }
  const configPath = process.env.OPS_AGENT_CONFIG ?? "/etc/ops-agent/agentd.json";
  await runClient({
    arguments: invocation.arguments,
    config: await loadAgentConfig(configPath),
    adapterContext,
  });
}

main().catch((error: unknown) => {
  process.stderr.write(
    `ops-agent: ${escapeUntrustedTerminalText(error instanceof Error ? error.message : String(error))}\n`,
  );
  process.exitCode = 1;
});
