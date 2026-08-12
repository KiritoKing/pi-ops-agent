import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { afterEach, describe, expect, it } from "vitest";

const checker = new URL("../scripts/check-root-stores-idle.mjs", import.meta.url);
const directories: string[] = [];

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "ops-agent-store-check-"));
  directories.push(directory);
  return directory;
}

function check(path: string): ReturnType<typeof spawnSync> {
  return spawnSync(process.execPath, [checker.pathname, path], { encoding: "utf8" });
}

afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

describe("root broker store quiescence checker", () => {
  it("accepts a missing store and terminal changes", () => {
    const directory = temporaryDirectory();
    expect(check(join(directory, "missing.json")).status).toBe(0);
    const path = join(directory, "state.json");
    writeFileSync(path, JSON.stringify({
      changes: {
        done: { state: "COMMITTED" },
        recovery: { state: "RECOVERY_REQUIRED" },
      },
    }));
    expect(check(path).status).toBe(0);
  });

  it.each(["PREPARING", "EXECUTING", "VERIFYING", "ROLLING_BACK"])(
    "rejects an in-flight %s change",
    (state) => {
      const directory = temporaryDirectory();
      const path = join(directory, "state.json");
      writeFileSync(path, JSON.stringify({ changes: { "change-1": { state } } }));
      const result = check(path);
      expect(result.status).toBe(4);
      expect(result.stderr).toContain(`change-1 is ${state}`);
    },
  );

  it("fails closed for malformed or symlinked stores", () => {
    const directory = temporaryDirectory();
    const malformed = join(directory, "malformed.json");
    writeFileSync(malformed, "{}");
    expect(check(malformed).status).toBe(1);
    const real = join(directory, "real.json");
    const link = join(directory, "link.json");
    writeFileSync(real, JSON.stringify({ changes: {} }));
    symlinkSync(real, link);
    expect(check(link).status).toBe(1);
  });

  it("fails closed for an unknown state", () => {
    const directory = temporaryDirectory();
    const path = join(directory, "state.json");
    writeFileSync(path, JSON.stringify({ changes: { future: { state: "NEW_TRANSIENT_STATE" } } }));
    const result = check(path);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("unknown change state");
  });
});
