import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

function repositoryFile(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

const expectedActionPins = new Map<string, { sha: string; version: string }>([
  [
    "actions/checkout",
    { sha: "3d3c42e5aac5ba805825da76410c181273ba90b1", version: "v7.0.1" },
  ],
  [
    "actions/setup-node",
    { sha: "820762786026740c76f36085b0efc47a31fe5020", version: "v7.0.0" },
  ],
  [
    "actions/setup-go",
    { sha: "b7ad1dad31e06c5925ef5d2fc7ad053ef454303e", version: "v7.0.0" },
  ],
  [
    "actions/upload-artifact",
    { sha: "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a", version: "v7.0.1" },
  ],
  [
    "actions/download-artifact",
    { sha: "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c", version: "v8.0.1" },
  ],
  [
    "actions/attest",
    { sha: "1e69f48acb82d1966a394da916b4c1698aa569d6", version: "v4.2.2" },
  ],
  [
    "anchore/sbom-action",
    { sha: "e22c389904149dbc22b58101806040fa8d37a610", version: "v0.24.0" },
  ],
]);

function expectAuditableActionPins(workflow: string): void {
  const usesLines = workflow
    .split("\n")
    .map((line) =>
      /^\s*(?:-\s+)?uses:\s+(\S+)(?:\s+#\s+(\S+))?\s*$/u.exec(line),
    )
    .filter((match): match is RegExpExecArray => match !== null);

  expect(usesLines.length).toBeGreaterThan(0);
  for (const match of usesLines) {
    const target = match[1];
    if (target === undefined) throw new Error("workflow action match omitted its target");
    if (target.startsWith("./")) continue;
    const separator = target.lastIndexOf("@");
    expect(separator, `remote action is missing an immutable ref: ${target}`).toBeGreaterThan(0);
    const action = target.slice(0, separator);
    const revision = target.slice(separator + 1);
    const expected = expectedActionPins.get(action);
    expect(expected, `unreviewed remote action in workflow: ${action}`).toBeDefined();
    expect(revision).toMatch(/^[0-9a-f]{40}$/u);
    expect(revision).toBe(expected?.sha);
    expect(match[2]).toBe(expected?.version);
  }
}

describe("native release layout", () => {
  it("builds only the current static Go command set", () => {
    const workflow = repositoryFile(".github/workflows/release.yml");
    const packager = repositoryFile("packaging/build-release.sh");
    const verifier = repositoryFile("packaging/verify-release.sh");

    expect(workflow).not.toContain("for command_dir in cmd/*");
    for (const command of [
      "ops-agent-server",
      "ops-root-helper",
      "agentd-guardian",
      "agentd-client-gateway",
      "agentd-pluginctl",
      "agentd-approval-submit",
      "agentd-json-config-helper",
    ]) {
      expect(workflow).toContain(command);
      expect(packager).toContain(command);
      expect(verifier).toContain(command);
    }
    expect(workflow).toContain("CGO_ENABLED=0 GOOS=linux");
    expect(verifier).toContain("readelf -l");
    expect(verifier).toContain("INTERP");
    expect(packager).not.toContain('install -m 0755 "${BIN_DIR}/ops-systemd-helper"');
    expect(verifier).toContain("bin/ops-systemd-helper");
  });

  it("ships and checks every v0.3 runtime plane and source extension surface", () => {
    const packager = repositoryFile("packaging/build-release.sh");
    const verifier = repositoryFile("packaging/verify-release.sh");

    for (const path of [
      "dist/agentd/index.js",
      "dist/client/index.js",
      "dist/reviewer/index.js",
      "dist/runtime/adapter-run.js",
      "dist/runtime/botmux-setup-run.js",
      "dist/runtime/workload-host.js",
      "plugins/adapter-tui/manifest.json",
      "plugins/adapter-tui/profile.json",
      "plugins/adapter-botmux-source/manifest.json",
      "plugins/adapter-botmux-source/adapter.mjs",
      "plugins/workload-base/manifest.json",
      "plugins/workload-base/workload.mjs",
      "plugins/workload-botmux-ops/manifest.json",
      "plugins/workload-botmux-ops/workload.mjs",
      "plugins/workload-hermes-ops/manifest.json",
      "plugins/workload-hermes-ops/workload.mjs",
      "plugins/workload-pve/manifest.json",
      "plugins/workload-pve/workload.mjs",
      "plugins/workload-example/manifest.json",
      "plugins/workload-example/workload.mjs",
      "scripts/probe-adapter-linux-fixture.mjs",
      "scripts/probe-adapter-linux-runtime.mjs",
      "scripts/probe-adapter-linux-runtime.sh",
      "scripts/probe-adapter-linux-socket.mjs",
      "skills/agentd-init/SKILL.md",
      "skills/agentd-init/agents/openai.yaml",
      "skills/agentd-adapter-dev/SKILL.md",
      "skills/agentd-adapter-dev/agents/openai.yaml",
      "skills/agentd-workload-dev/SKILL.md",
      "skills/agentd-workload-dev/agents/openai.yaml",
      "systemd/agentd-approval-reviewer.service",
      "systemd/agentd-plugin-lease-broker.service",
      "systemd/agentd-guardian.service",
      "systemd/agentd-client-gateway.service",
      "systemd/ops-pve-root-helper.service",
      "docs/workloads/pve.md",
    ]) {
      expect(packager).toContain(path);
      expect(verifier).toContain(path);
    }
    expect(packager).toContain('cp -a "${REPOSITORY_ROOT}/plugins/."');
    expect(packager).toContain('cp -a "${REPOSITORY_ROOT}/skills/."');
    expect(packager).toContain("Refusing to package symlinks from Source Plugin or Skill trees");
    expect(verifier).toContain("Release PVE broker must retain ProtectSystem=full");
    expect(verifier).toContain(
      "Release PVE broker is missing the exact /etc/pve pmxcfs write exception",
    );
    expect(verifier).toContain("Release core broker must keep /etc/pve inaccessible");
    expect(verifier).toContain(
      "Release non-PVE runtime must keep /etc/pve inaccessible",
    );
    expect(verifier).toContain("Release PVE broker opens a wider /etc path");
    expect(verifier).toContain(
      "Only the PVE broker may receive the /etc/pve write exception",
    );
    expect(repositoryFile("scripts/probe-adapter-linux-runtime.mjs")).toContain(
      "lost: new Promise(() => {}),",
    );
  });

  it("checks archive/deb parity and the pinned production runtime before SBOM generation", () => {
    const workflow = repositoryFile(".github/workflows/release.yml");
    const verifier = repositoryFile("packaging/verify-release.sh");

    expect(workflow).toMatch(/NODE_VERSION: 22\.\d+\.\d+/u);
    expect(workflow).toMatch(/GO_VERSION: 1\.\d+\.\d+/u);
    expect(workflow).toContain("packaging/verify-release.sh");
    expect(workflow).toContain(
      "anchore/sbom-action@e22c389904149dbc22b58101806040fa8d37a610 # v0.24.0",
    );
    expect(workflow).toContain("upload-release-assets: false");
    expect(workflow.indexOf("packaging/verify-release.sh")).toBeLessThan(
      workflow.indexOf("Generate installed-payload SPDX SBOM"),
    );
    expect(verifier).toContain("Debian and native archive payloads differ");
    expect(verifier).toContain("process.versions.node");
    expect(verifier).toContain('dist/client/index.js" --version');
    expect(verifier).toContain('dist/reviewer/index.js" </dev/null');
    expect(verifier).toContain("--no-payload-execution");
    expect(verifier).toContain("without executing downloaded payload code");
  });

  it("blocks publish on the real Linux Adapter runtime probe", () => {
    const workflow = repositoryFile(".github/workflows/release.yml");
    const probeJobStart = workflow.indexOf("  adapter-linux-runtime:\n");
    const buildJobStart = workflow.indexOf("\n  build:\n", probeJobStart);
    const publishJobStart = workflow.indexOf("\n  publish:\n", buildJobStart);

    expect(probeJobStart).toBeGreaterThan(0);
    expect(buildJobStart).toBeGreaterThan(probeJobStart);
    expect(publishJobStart).toBeGreaterThan(buildJobStart);
    const probeJob = workflow.slice(probeJobStart, buildJobStart);
    expect(probeJob).toContain("needs: validate");
    expect(probeJob).toContain("runs-on: ubuntu-24.04");
    expect(probeJob).toContain("npm run build");
    expect(probeJob).toContain("npm run test:adapter-linux-runtime");
    expect(probeJob).toContain('probe_status="$?"');
    expect(probeJob).toContain("status 77 is unverified and blocks release");
    expect(probeJob).not.toContain("continue-on-error");

    const publishJob = workflow.slice(publishJobStart);
    expect(publishJob).toMatch(
      /needs:\n\s+- build\n\s+- adapter-linux-runtime\n/u,
    );
  });

  it("pins every remote workflow action to a reviewed full commit", () => {
    expectAuditableActionPins(repositoryFile(".github/workflows/ci.yml"));
    expectAuditableActionPins(repositoryFile(".github/workflows/release.yml"));
  });

  it("isolates verified packages before third-party SBOM code and re-verifies downloads", () => {
    const workflow = repositoryFile(".github/workflows/release.yml");
    const nativeVerify = workflow.indexOf("packaging/verify-release.sh");
    const packageUpload = workflow.indexOf(
      "name: Isolate verified native packages before SBOM generation",
    );
    const sbom = workflow.indexOf("name: Generate installed-payload SPDX SBOM");
    const sbomUpload = workflow.indexOf("name: Upload generated SBOM separately");
    expect(nativeVerify).toBeGreaterThan(0);
    expect(nativeVerify).toBeLessThan(packageUpload);
    expect(packageUpload).toBeLessThan(sbom);
    expect(sbom).toBeLessThan(sbomUpload);

    const packageUploadBlock = workflow.slice(packageUpload, sbom);
    expect(packageUploadBlock).toContain("name: native-packages-${{ matrix.arch }}");
    expect(packageUploadBlock).toContain("ops-agent-linux-${{ matrix.arch }}.tar.gz");
    expect(packageUploadBlock).toContain("ops-agent-all_${{ steps.native_package.outputs.version }}");
    expect(packageUploadBlock).not.toContain("spdx");
    expect(packageUploadBlock).not.toContain("release/*");

    const sbomUploadBlock = workflow.slice(sbomUpload, workflow.indexOf("publish:"));
    expect(sbomUploadBlock).toContain("name: native-sbom-${{ matrix.arch }}");
    expect(sbomUploadBlock).toContain(
      "path: release/ops-agent-linux-${{ matrix.arch }}.spdx.json",
    );
    expect(sbomUploadBlock).not.toContain(".tar.gz");
    expect(sbomUploadBlock).not.toContain(".deb");

    const publishDownload = workflow.indexOf("actions/download-artifact@");
    const publishVerify = workflow.indexOf("name: Re-verify downloaded native packages");
    const manifest = workflow.indexOf("name: Generate release manifest and checksums");
    const attest = workflow.indexOf("name: Attest release artifacts");
    const publish = workflow.indexOf("name: Publish GitHub Release");
    expect(publishDownload).toBeGreaterThan(sbomUpload);
    expect(publishDownload).toBeLessThan(publishVerify);
    expect(workflow.slice(publishDownload, publishVerify)).toContain(
      "pattern: native-*",
    );
    expect(workflow.slice(publishDownload, publishVerify)).toContain(
      "merge-multiple: true",
    );
    expect(publishVerify).toBeLessThan(manifest);
    expect(manifest).toBeLessThan(attest);
    expect(attest).toBeLessThan(publish);
    const publishVerifyBlock = workflow.slice(publishVerify, manifest);
    expect(publishVerifyBlock).toContain("for arch in amd64 arm64");
    expect(publishVerifyBlock).toContain("packaging/verify-release.sh");
    expect(publishVerifyBlock).toContain("--no-payload-execution");
  });

  it("attests every published executable/package class and rejects version drift", () => {
    const workflow = repositoryFile(".github/workflows/release.yml");

    expect(workflow).toContain(
      "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1",
    );
    expect(workflow).toContain(
      "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1",
    );
    expect(workflow).toContain(
      "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 # v4.2.2",
    );
    expect(workflow).toContain("artifact-metadata: write");
    expect(workflow).not.toContain("actions/attest-build-provenance");
    for (const pattern of [
      "release/*.deb",
      "release/*.tar.gz",
      "release/*.opspkg",
      "release/*.spdx.json",
      "release/manifest.json",
      "release/checksums.txt",
    ]) {
      expect(workflow).toContain(pattern);
    }
    expect(workflow).toContain('require("./package-lock.json").packages[""].version');
    expect(workflow).toContain("pinned runtime is below engines.node");
    expect(workflow).toContain("--verify-tag");
    const manifestBuilder = repositoryFile("packaging/create-release-manifest.sh");
    for (const required of [
      "ops-agent-linux-amd64.tar.gz",
      "ops-agent-linux-arm64.tar.gz",
      'ops-agent-all_${version}_amd64.deb',
      'ops-agent-all_${version}_arm64.deb',
      "ops-agent-linux-amd64.spdx.json",
      "ops-agent-linux-arm64.spdx.json",
      'adapter-botmux_${version}.opspkg',
      'workload-hermes_${version}.opspkg',
    ]) {
      expect(manifestBuilder).toContain(required);
    }
    expect(manifestBuilder).toContain("Release asset set is incomplete");
  });
});
