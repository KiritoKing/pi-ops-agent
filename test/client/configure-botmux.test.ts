import { execFileSync } from "node:child_process";
import { chmodSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

describe("BotMux configuration hardener", () => {
  it("preserves the BotMux-owned secret while binding the ops-agent wrapper", () => {
    const directory = mkdtempSync(join(tmpdir(), "ops-agent-botmux-config-"));
    temporaryDirectories.push(directory);
    const configPath = join(directory, "bots.json");
    const secret = "not-a-real-lark-secret";
    const original = [{
      larkAppId: "cli_test",
      larkAppSecret: secret,
      cliId: "codex",
      allowedUsers: ["owner@example.com"],
      allowedChatGroups: [],
      p2pOpen: true,
      sandbox: true,
      sandboxHidePaths: ["/private"],
      sandboxNetwork: false,
    }];
    writeFileSync(configPath, `${JSON.stringify(original)}\n`, { encoding: "utf8", mode: 0o600 });
    chmodSync(configPath, 0o600);

    const output = execFileSync(
      process.execPath,
      [join(process.cwd(), "scripts/configure-botmux.mjs"), configPath],
      { encoding: "utf8" },
    );
    const configured = JSON.parse(readFileSync(configPath, "utf8")) as unknown;
    if (!Array.isArray(configured)) throw new Error("expected a BotMux config array");
    const first: unknown = configured[0];
    if (!isRecord(first)) throw new Error("expected a BotMux bot object");
    const bot = first;
    expect(bot).toMatchObject({
      larkAppSecret: secret,
      cliId: "pi",
      cliPathOverride: "/opt/pi-ops-agent/bin/ops-agent-botmux",
      p2pOpen: false,
      disableCliBypass: true,
      sandbox: false,
      writableTerminalLinkInCard: false,
    });
    expect(bot).not.toHaveProperty("sandboxHidePaths");
    expect(bot).not.toHaveProperty("sandboxNetwork");
    expect(output).not.toContain(secret);
    const summary = JSON.parse(output) as unknown;
    if (!isRecord(summary) || typeof summary.backupPath !== "string") {
      throw new Error("expected a configuration backup path");
    }
    expect(readFileSync(summary.backupPath, "utf8")).toContain(secret);
    expect(statSync(summary.backupPath).mode & 0o777).toBe(0o600);
    expect(statSync(configPath).mode & 0o777).toBe(0o600);
  });
});
