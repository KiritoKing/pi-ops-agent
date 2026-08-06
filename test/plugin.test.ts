import { describe, expect, it } from "vitest";
import {
  isAdapterPluginManifest,
  parseAdapterPluginManifest,
  parsePluginCatalogEntry,
} from "../src/shared/plugin.js";

const manifest = {
  schemaVersion: 1,
  id: "adapter.botmux",
  kind: "im-adapter",
  version: "0.1.0",
  publisher: "KiritoKing/pi-ops-agent",
  coreProtocol: 1,
  entrypoint: "adapter.mjs",
  description: "BotMux adapter",
  capabilities: {
    inboundText: true,
    verifiedSender: true,
    privateConversation: true,
    proactiveDelivery: true,
    approvalIntent: true,
    streaming: false,
  },
  secrets: ["larkAppSecret"],
  setupOperations: ["credential.install", "config.write", "service.start"],
};

describe("adapter plugin manifest", () => {
  it("accepts a bounded declarative adapter manifest", () => {
    expect(parseAdapterPluginManifest(manifest)).toMatchObject({
      id: "adapter.botmux",
      entrypoint: "adapter.mjs",
    });
    expect(isAdapterPluginManifest(manifest)).toBe(true);
  });

  it("rejects executable escape hatches and unknown fields", () => {
    expect(() => parseAdapterPluginManifest({ ...manifest, installCommand: "sudo sh" })).toThrow(
      /unknown fields/u,
    );
    expect(() => parseAdapterPluginManifest({ ...manifest, entrypoint: "../escape.mjs" })).toThrow(
      /inside the plugin package/u,
    );
    expect(() =>
      parseAdapterPluginManifest({ ...manifest, setupOperations: ["root.shell"] }),
    ).toThrow(/unsupported/u);
  });

  it("requires signed absolute catalog locations", () => {
    expect(
      parsePluginCatalogEntry({
        manifest,
        packagePath: "/usr/lib/ops-agent/plugins/adapter-botmux.opspkg",
        digest: `sha256:${"a".repeat(64)}`,
        signaturePath: "/usr/lib/ops-agent/plugins/adapter-botmux.opspkg.sig",
      }),
    ).toMatchObject({ digest: `sha256:${"a".repeat(64)}` });
    expect(() =>
      parsePluginCatalogEntry({
        manifest,
        packagePath: "./plugin.opspkg",
        digest: `sha256:${"a".repeat(64)}`,
        signaturePath: "./plugin.sig",
      }),
    ).toThrow(/absolute/u);
  });
});
