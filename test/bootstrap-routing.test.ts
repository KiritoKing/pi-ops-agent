import { spawnSync } from "node:child_process";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

const sourceBootstrap = fileURLToPath(
  new URL("../scripts/ops-agent-bootstrap.sh", import.meta.url),
);
const sourceNetworkBootstrap = fileURLToPath(
  new URL("../scripts/install.sh", import.meta.url),
);
const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

interface FakeReleaseRoot {
  readonly bootstrap: string;
  readonly helperArgs: string;
  readonly helperStarted: string;
  readonly installerArgs: string;
  readonly installerPayload: string;
  readonly installerStarted: string;
  readonly payload: string;
}

function makeFakeReleaseRoot(): FakeReleaseRoot {
  const root = mkdtempSync(join(tmpdir(), "ops-agent-bootstrap-routing-"));
  temporaryDirectories.push(root);

  const helperArgs = join(root, "helper-args");
  const helperStarted = join(root, "helper-started");
  const installerArgs = join(root, "installer-args");
  const installerPayload = join(root, "installer-payload");
  const installerStarted = join(root, "installer-started");
  const payload = join(root, "payload");
  const bootstrap = join(root, "ops-agent-bootstrap");

  copyFileSync(sourceBootstrap, bootstrap);
  chmodSync(bootstrap, 0o755);
  writeFileSync(join(root, "configure-noble-bwrap-apparmor.sh"), `#!/bin/sh
set -eu
printf '%s\\n' started > "$OPS_AGENT_TEST_HELPER_STARTED"
printf '%s\\n' "$@" > "$OPS_AGENT_TEST_HELPER_ARGS"
`, { mode: 0o755 });
  writeFileSync(join(root, "install-release.sh"), `#!/bin/sh
set -eu
printf '%s\\n' started > "$OPS_AGENT_TEST_INSTALLER_STARTED"
printf '%s\\n' "$@" > "$OPS_AGENT_TEST_INSTALLER_ARGS"
printf '%s\\n' "$OPS_AGENT_PAYLOAD_DIR" > "$OPS_AGENT_TEST_INSTALLER_PAYLOAD"
`, { mode: 0o755 });
  chmodSync(join(root, "configure-noble-bwrap-apparmor.sh"), 0o755);
  chmodSync(join(root, "install-release.sh"), 0o755);
  mkdirSync(payload);
  writeFileSync(join(payload, ".keep"), "");

  return {
    bootstrap,
    helperArgs,
    helperStarted,
    installerArgs,
    installerPayload,
    installerStarted,
    payload,
  };
}

function runBootstrap(release: FakeReleaseRoot, args: readonly string[]) {
  return spawnSync(release.bootstrap, args, {
    encoding: "utf8",
    env: {
      ...process.env,
      OPS_AGENT_TEST_HELPER_ARGS: release.helperArgs,
      OPS_AGENT_TEST_HELPER_STARTED: release.helperStarted,
      OPS_AGENT_TEST_INSTALLER_ARGS: release.installerArgs,
      OPS_AGENT_TEST_INSTALLER_PAYLOAD: release.installerPayload,
      OPS_AGENT_TEST_INSTALLER_STARTED: release.installerStarted,
    },
  });
}

function readArguments(path: string): string[] {
  return readFileSync(path, "utf8").trimEnd().split("\n");
}

describe("release-root ops-agent-bootstrap routing", () => {
  it("rejects an unpinned Raw init before platform or network access", () => {
    const environment = { ...process.env };
    delete environment.OPS_AGENT_VERSION;
    const result = spawnSync("/bin/sh", [sourceNetworkBootstrap, "init"], {
      encoding: "utf8",
      env: environment,
    });

    expect(result.status).toBe(2);
    expect(result.stderr).toContain(
      "requires an explicit OPS_AGENT_VERSION=vX.Y.Z",
    );
  });

  it("rejects a non-semantic Raw release pin before platform or network access", () => {
    const result = spawnSync("/bin/sh", [sourceNetworkBootstrap, "join"], {
      encoding: "utf8",
      env: { ...process.env, OPS_AGENT_VERSION: "v1.2" },
    });

    expect(result.status).toBe(2);
    expect(result.stderr).toContain("v-prefixed semantic version");
  });

  it.each([
    ["inspect", ["--approve-digest", "sha256:inspect"]],
    ["install", ["--approve-digest", "sha256:install"]],
    ["status", []],
  ] as const)("routes host-policy %s only to the helper", (action, options) => {
    const release = makeFakeReleaseRoot();
    const result = runBootstrap(release, ["host-policy", action, ...options]);

    expect(result.status).toBe(0);
    expect(readArguments(release.helperArgs)).toEqual([action, ...options]);
    expect(existsSync(release.helperStarted)).toBe(true);
    expect(existsSync(release.installerStarted)).toBe(false);
    expect(existsSync(release.installerArgs)).toBe(false);
  });

  it.each([
    ["missing action", ["host-policy"]],
    ["unknown action", ["host-policy", "unsupported"]],
    ["unsupported action", ["host-policy", "remove"]],
  ])("rejects %s without starting either release program", (_description, args) => {
    const release = makeFakeReleaseRoot();
    const result = runBootstrap(release, args);

    expect(result.status).toBe(2);
    expect(existsSync(release.helperStarted)).toBe(false);
    expect(existsSync(release.installerStarted)).toBe(false);
  });

  it.each([
    ["init", ["--admin-user", "alice", "--no-start"]],
    [
      "join",
      [
        "--controller",
        "https://controller.example.test",
        "--controller-ca-sha256",
        "sha256:controller",
        "--token-file",
        "/tmp/enrollment-token",
        "--no-start",
      ],
    ],
  ])("routes %s only to the installer with its payload", (mode, options) => {
    const release = makeFakeReleaseRoot();
    const result = runBootstrap(release, [mode, ...options]);

    expect(result.status).toBe(0);
    expect(readArguments(release.installerArgs)).toEqual([mode, ...options]);
    expect(readFileSync(release.installerPayload, "utf8").trim()).toBe(realpathSync(release.payload));
    expect(existsSync(release.installerStarted)).toBe(true);
    expect(existsSync(release.helperStarted)).toBe(false);
    expect(existsSync(release.helperArgs)).toBe(false);
  });
});
