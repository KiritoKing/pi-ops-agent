import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parseAdapterDescriptorJson } from "../../src/shared/adapter-runtime.js";

describe("TUI source adapter", () => {
  it("declares the sole local approval contract as a non-executable profile", () => {
      const directory = join(process.cwd(), "plugins/adapter-tui");
      const manifest = JSON.parse(readFileSync(join(directory, "manifest.json"), "utf8")) as {
        entrypoint: string;
      };
      expect(manifest.entrypoint).toBe("profile.json");
      const profile = join(directory, manifest.entrypoint);
      expect(parseAdapterDescriptorJson(readFileSync(profile, "utf8"))).toMatchObject({
        adapterId: "adapter.tui",
        session: { mapping: "local-terminal", supportedControls: ["bind"] },
        inbound: { supportedTypes: ["text"] },
        outbound: { supportedActions: ["display"] },
        approval: {
          mode: "local-tty",
          identitySource: "os-user+tty+sudo-pam",
          replayProtection: "local-command",
        },
      });
  });
});
