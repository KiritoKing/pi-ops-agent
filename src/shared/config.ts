import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { optionalString, requireRecord, requireString } from "./guards.js";

export interface AgentConfig {
  socketPath: string;
  rootHelperSocket: string;
  systemdHelperSocket: string;
  stateDir: string;
  workspaceRoot: string;
  sessionDir: string;
  sessionRegistryPath: string;
  serverRegistryPath: string;
  machineContextDir: string;
  agentDir: string;
  modelsPath: string;
  provider: string;
  model: string;
  apiKeyCredential: string;
  auditPath: string;
  bwrapPath: string;
  bashPath: string;
  sandboxEnabled: boolean;
}

const DEFAULTS: AgentConfig = {
  socketPath: "/run/ops-agent/agentd.sock",
  rootHelperSocket: "/run/ops-agent/root-helper.sock",
  systemdHelperSocket: "/run/ops-agent/systemd-helper.sock",
  stateDir: "/var/lib/ops-agent",
  workspaceRoot: "/var/lib/ops-agent/workspaces",
  sessionDir: "/var/lib/ops-agent/sessions",
  sessionRegistryPath: "/var/lib/ops-agent/registry/sessions.json",
  serverRegistryPath: "/etc/ops-agent/servers.json",
  machineContextDir: "/var/lib/ops-agent/machines",
  agentDir: "/var/lib/ops-agent/pi",
  modelsPath: "/etc/ops-agent/models.json",
  provider: "deepseek",
  model: "deepseek-v4-flash",
  apiKeyCredential: "deepseek_api_key",
  auditPath: "/var/log/ops-agent/agentd-audit.jsonl",
  bwrapPath: "/usr/bin/bwrap",
  bashPath: "/bin/bash",
  sandboxEnabled: true,
};

export async function loadAgentConfig(path: string): Promise<AgentConfig> {
  const raw = JSON.parse(await readFile(path, "utf8")) as unknown;
  const input = requireRecord(raw, "agent config");
  const config = { ...DEFAULTS };
  const stringKeys = (Object.keys(DEFAULTS) as Array<keyof AgentConfig>)
    .filter((key): key is Exclude<keyof AgentConfig, "sandboxEnabled"> => key !== "sandboxEnabled");
  for (const key of stringKeys) {
    const next = optionalString(input[key], `config.${key}`, { max: 4096 });
    if (next !== undefined) {
      config[key] = next;
    }
  }
  if (input.sandboxEnabled !== undefined) {
    if (typeof input.sandboxEnabled !== "boolean") {
      throw new Error("config.sandboxEnabled must be a boolean");
    }
    config.sandboxEnabled = input.sandboxEnabled;
  }
  return config;
}

export async function readCredential(name: string): Promise<string> {
  const directory = process.env.CREDENTIALS_DIRECTORY;
  if (!directory) {
    throw new Error("CREDENTIALS_DIRECTORY is not set");
  }
  const value = (await readFile(join(directory, name), "utf8")).trim();
  return requireString(value, `credential ${name}`, { min: 16, max: 16 * 1024 });
}
