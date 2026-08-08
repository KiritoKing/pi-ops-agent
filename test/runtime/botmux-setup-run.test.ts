import { describe, expect, it } from "vitest";
import {
  runBotMuxSourceSetup,
  type BotMuxSetupCommand,
  type BotMuxSetupDependencies,
} from "../../src/runtime/botmux-setup-run.js";
import type {
  ActiveRuntimeSourcePlugin,
  ActiveRuntimeSourcePluginLease,
} from "../../src/shared/source-plugin.js";

const DIGEST = `sha256:${"a".repeat(64)}`;
const SNAPSHOT = `/var/lib/ops-agent/plugins/snapshots/sha256/${"a".repeat(64)}`;

function registration(overrides: Partial<ActiveRuntimeSourcePlugin> = {}): ActiveRuntimeSourcePlugin {
  return {
    apiVersion: "agentd.plugin-registration/v1",
    schemaVersion: 1,
    pluginId: "adapter.botmux",
    kind: "adapter",
    version: "0.3.0",
    publisher: "example/botmux",
    digest: DIGEST,
    capabilities: [
      "adapter.inbound.text", "adapter.outbound.send", "adapter.session.bind", "approval.status",
    ],
    requestedScopes: [
      "adapter.inbound.text.botmux",
      "adapter.outbound.send.botmux",
      "adapter.session.bind.botmux",
      "approval.status.remote",
    ],
    approvedBy: "local-admin:1000",
    approvedAt: "2026-08-08T00:00:00Z",
    entrypoint: "adapter.mjs",
    snapshotPath: SNAPSHOT,
    ...overrides,
  };
}

function fixture(options: {
  active?: ActiveRuntimeSourcePlugin;
  lost?: Promise<never>;
  execute?: (command: BotMuxSetupCommand, signal: AbortSignal) => Promise<number>;
} = {}): {
  dependencies: BotMuxSetupDependencies;
  events: string[];
} {
  const events: string[] = [];
  const active = options.active ?? registration();
  const lease: ActiveRuntimeSourcePluginLease = {
    registration: active,
    lost: options.lost ?? new Promise<never>(() => undefined),
    release: () => {
      events.push("release");
      return Promise.resolve();
    },
  };
  const dependencies: BotMuxSetupDependencies = {
    effectiveUid: 997,
    username: "ops-agent-botmux",
    homeDirectory: "/var/lib/ops-agent/adapters/botmux",
    nodePath: "/opt/pi-ops-agent/releases/0.3.0/runtime/node",
    bwrapPath: "/usr/bin/bwrap",
    botmuxPath: "/usr/bin/botmux",
    configPath: "/var/lib/ops-agent/adapters/botmux/.botmux/bots.json",
    environment: {},
    acquireLease: async (expected) => {
      events.push(`lease:${expected.pluginId}:${expected.digest}`);
      return await Promise.resolve(lease);
    },
    validateHardener: async (path) => {
      events.push(`validate:${path}`);
      return await Promise.resolve(path);
    },
    execute: options.execute ?? (async (command) => {
      events.push(`${command.label}:${command.executable}:${command.arguments.join("|")}`);
      return await Promise.resolve(0);
    }),
  };
  return { dependencies, events };
}

describe("exact-digest BotMux setup runner", () => {
  it("holds one lease across setup, approved hardener, and restart", async () => {
    const { dependencies, events } = fixture();

    await runBotMuxSourceSetup(DIGEST, dependencies);

    expect(events).toEqual([
      `lease:adapter.botmux:${DIGEST}`,
      `validate:${SNAPSHOT}/configure-botmux.mjs`,
      "BotMux setup:/usr/bin/botmux:setup",
      "approved BotMux configuration hardener:/usr/bin/bwrap:" + [
        "--die-with-parent", "--unshare-pid", "--as-pid-1", "--disable-userns",
        "--cap-drop", "ALL", "--bind", "/", "/", "--proc", "/proc",
        "--chdir", SNAPSHOT, "--", dependencies.nodePath,
        `${SNAPSHOT}/configure-botmux.mjs`, dependencies.configPath, "0",
      ].join("|"),
      "BotMux restart:/usr/bin/botmux:restart",
      "release",
    ]);
  });

  it("waits for the active command to stop and skips restart when the lease is lost", async () => {
    const lost = Promise.withResolvers<never>();
    let commandCount = 0;
    const { dependencies, events } = fixture({
      lost: lost.promise,
      execute: async (command, signal) => {
        commandCount += 1;
        events.push(`start:${command.label}`);
        if (commandCount === 1) return 0;
        lost.reject(new Error("lease broker restarted"));
        return await new Promise<number>((resolve) => {
          signal.addEventListener("abort", () => {
            events.push(`stopped:${command.label}`);
            resolve(143);
          }, { once: true });
        });
      },
    });

    await expect(runBotMuxSourceSetup(DIGEST, dependencies)).rejects.toThrow(
      "lease broker restarted",
    );
    expect(events).toContain("stopped:approved BotMux configuration hardener");
    expect(events).not.toContain("start:BotMux restart");
    expect(events.at(-1)).toBe("release");
  });

  it("does not execute any command when the broker returns a mismatched registration", async () => {
    const { dependencies, events } = fixture({
      active: registration({ entrypoint: "different.mjs" }),
    });

    await expect(runBotMuxSourceSetup(DIGEST, dependencies)).rejects.toThrow(
      "invalid adapter.botmux registration",
    );
    expect(events).toEqual([`lease:adapter.botmux:${DIGEST}`, "release"]);
  });
});
