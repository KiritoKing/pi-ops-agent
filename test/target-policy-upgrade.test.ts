import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

const temporaryDirectories: string[] = [];
const digest = (character: string): string => `sha256:${character.repeat(64)}`;

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function runInitializer(
  existingPolicy: unknown,
  enabledArtifactIds: string[] = [],
): { inputPath: string; outputPath: string; policy: Record<string, unknown> } {
  const directory = mkdtempSync(join(tmpdir(), "ops-policy-upgrade-"));
  temporaryDirectories.push(directory);
  const catalogPath = join(directory, "index.json");
  const inputPath = join(directory, "targets.json");
  const outputPath = join(directory, "targets.candidate.json");
  writeFileSync(catalogPath, `${JSON.stringify({
    schemaVersion: 1,
    artifacts: [
      { id: "adapter.botmux", kind: "im-adapter", version: "1.0.0", publisher: "example/ops", digest: digest("a") },
      { id: "workload.hermes", kind: "managed-workload", version: "1.0.0", publisher: "example/ops", digest: digest("b") },
    ],
  })}\n`);
  if (existingPolicy !== undefined) writeFileSync(inputPath, `${JSON.stringify(existingPolicy)}\n`);
  const initializerArgs = [
    join(process.cwd(), "scripts/initialize-target-policy.mjs"),
    "--catalog-index", catalogPath,
    "--policy", inputPath,
    "--output", outputPath,
  ];
  for (const id of enabledArtifactIds) initializerArgs.push("--enable-artifact", id);
  execFileSync(process.execPath, initializerArgs);
  const parsed = JSON.parse(readFileSync(outputPath, "utf8")) as unknown;
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("expected policy object");
  return { inputPath, outputPath, policy: parsed as Record<string, unknown> };
}

function validateArtifacts(enabledArtifactIds: string[]): string {
  const directory = mkdtempSync(join(tmpdir(), "ops-policy-validate-"));
  temporaryDirectories.push(directory);
  const catalogPath = join(directory, "index.json");
  writeFileSync(catalogPath, `${JSON.stringify({
    schemaVersion: 1,
    artifacts: [
      { id: "adapter.botmux", kind: "im-adapter", version: "1.0.0", publisher: "example/ops", digest: digest("a") },
      { id: "workload.hermes", kind: "managed-workload", version: "1.0.0", publisher: "example/ops", digest: digest("b") },
    ],
  })}\n`);
  const args = [
    join(process.cwd(), "scripts/initialize-target-policy.mjs"),
    "--catalog-index", catalogPath,
    "--validate-only",
  ];
  for (const id of enabledArtifactIds) args.push("--enable-artifact", id);
  return execFileSync(process.execPath, args, { encoding: "utf8" });
}

function localTarget(policy: Record<string, unknown>): Record<string, unknown> {
  const targets = policy.targets;
  if (!Array.isArray(targets) || targets.length !== 1) throw new Error("expected one target");
  const target: unknown = targets[0];
  if (target === null || typeof target !== "object" || Array.isArray(target)) throw new Error("expected target object");
  return target as Record<string, unknown>;
}

function targetChanges(target: Record<string, unknown>): Record<string, unknown> {
  const changes = target.changes;
  if (changes === null || typeof changes !== "object" || Array.isArray(changes)) throw new Error("expected changes object");
  return changes as Record<string, unknown>;
}

function targetStandingScopes(target: Record<string, unknown>): unknown {
  const authorization = target.authorization;
  if (authorization === null || typeof authorization !== "object" || Array.isArray(authorization)) {
    throw new Error("expected authorization object");
  }
  return (authorization as Record<string, unknown>).standingScopes;
}

describe("target policy upgrades", () => {
  it("migrates only an existing legacy plugin grant and stages the result", () => {
    const original = {
      version: 1,
      revision: "policy-legacy-v1",
      targets: [{
        id: "target-local-system",
        account: "root",
        displayName: "Local system",
        inspect: { hostSnapshot: true, processList: true, units: ["ops-agentd.service"], readPaths: ["/etc"] },
        changes: { writePaths: ["/etc/ops-agent"], units: [], packages: [], plugins: ["adapter.botmux"] },
      }],
    };
    const { inputPath, policy } = runInitializer(original);
    expect(JSON.parse(readFileSync(inputPath, "utf8"))).toEqual(original);
    const target = localTarget(policy);
    const changes = targetChanges(target);
    expect(changes.packages).toEqual([]);
    expect(changes.units).toEqual([]);
    expect(changes.writePaths).toEqual([]);
    expect(changes.plugins).toEqual([{
      id: "adapter.botmux",
      kind: "im-adapter",
      version: "1.0.0",
      publisher: "example/ops",
      digest: digest("a"),
    }]);
    expect((target.inspect as Record<string, unknown>).units).toEqual(["ops-agentd.service"]);
    expect(targetStandingScopes(target)).toEqual([]);
  });

  it("does not refresh or widen an existing structured allowlist", () => {
    const pinned = {
      id: "adapter.botmux",
      kind: "im-adapter",
      version: "0.9.0",
      publisher: "previous/publisher",
      digest: digest("c"),
    };
    const original = {
      version: 1,
      revision: "policy-structured-v1",
      targets: [{
        id: "target-local-system",
        account: "root",
        displayName: "Local system",
        inspect: { hostSnapshot: true, processList: true, units: [], readPaths: ["/etc"] },
        changes: { writePaths: ["/etc/ops-agent"], units: [], packages: [], plugins: [pinned] },
      }],
    };
    const { policy } = runInitializer(original);
    const changes = targetChanges(localTarget(policy));
    expect(changes.plugins).toEqual([pinned]);
    expect(changes.packages).toEqual([]);
    expect(changes.units).toEqual([]);
    expect(changes.writePaths).toEqual([]);
    expect(targetStandingScopes(localTarget(policy))).toEqual([]);
  });

  it("creates a core-only policy without catalog artifacts or Docker", () => {
    const { policy } = runInitializer(undefined);
    const target = localTarget(policy);
    const changes = targetChanges(target);
    expect(changes.packages).toEqual([]);
    expect(changes.units).toEqual([]);
    expect(changes.plugins).toEqual([]);
    expect(changes.writePaths).toEqual([]);
    expect((target.inspect as Record<string, unknown>).units).toEqual([
      "ops-agent-server.service",
      "ops-agentd.service",
    ]);
    expect((target.inspect as Record<string, unknown>).readPaths).toEqual([]);
    expect(targetStandingScopes(target)).toEqual([]);
  });

  it("authorizes an explicit adapter without adding Docker permissions", () => {
    const { policy } = runInitializer(undefined, ["adapter.botmux"]);
    const changes = targetChanges(localTarget(policy));
    expect(changes.packages).toEqual([]);
    expect(changes.units).toEqual([]);
    expect(changes.plugins).toEqual([{
      id: "adapter.botmux",
      kind: "im-adapter",
      version: "1.0.0",
      publisher: "example/ops",
      digest: digest("a"),
    }]);
  });

  it("authorizes only an explicit managed workload and its Docker prerequisites", () => {
    const { policy } = runInitializer(undefined, ["workload.hermes"]);
    const target = localTarget(policy);
    const changes = targetChanges(target);
    expect(changes.packages).toEqual(["docker.io"]);
    expect(changes.units).toEqual(["docker.service"]);
    expect(changes.plugins).toEqual([{
      id: "workload.hermes",
      kind: "managed-workload",
      version: "1.0.0",
      publisher: "example/ops",
      digest: digest("b"),
      credentialBundleDigest: digest("0"),
    }]);
    expect((target.inspect as Record<string, unknown>).units).toContain("docker.service");
  });

  it("sorts multiple explicit artifacts deterministically", () => {
    const { policy } = runInitializer(undefined, ["workload.hermes", "adapter.botmux"]);
    const changes = targetChanges(localTarget(policy));
    expect((changes.plugins as Array<Record<string, unknown>>).map((artifact) => artifact.id))
      .toEqual(["adapter.botmux", "workload.hermes"]);
  });

  it("rejects unknown artifact IDs and attempts to widen an existing policy", () => {
    expect(() => runInitializer(undefined, ["workload.unknown"])).toThrow();
    expect(() => validateArtifacts(["workload.unknown"])).toThrow();
    expect(validateArtifacts(["workload.hermes", "adapter.botmux"]))
      .toBe("adapter.botmux\nworkload.hermes\n");
    const existing = {
      version: 1,
      revision: "policy-existing-v1",
      targets: [{
        id: "target-local-system",
        account: "root",
        displayName: "Local system",
        inspect: { hostSnapshot: true, processList: true, units: [], readPaths: [] },
        changes: { writePaths: ["/etc/ops-agent"], units: [], packages: [], plugins: [] },
      }],
    };
    expect(() => runInitializer(existing, ["adapter.botmux"])).toThrow();
  });

  it("preserves a custom target even when it uses the former broad read roots", () => {
    const existing = {
      version: 1,
      revision: "policy-existing-v1",
      targets: [{
        id: "target-custom-system",
        account: "custom_agent",
        displayName: "Custom system",
        inspect: {
          hostSnapshot: true,
          processList: true,
          units: [],
          readPaths: ["/var/log", "/etc", "/proc"],
        },
        changes: { writePaths: ["/etc/ops-agent"], units: [], packages: [], plugins: [] },
      }],
    };
    const { policy } = runInitializer(existing);
    expect((localTarget(policy).inspect as Record<string, unknown>).readPaths)
      .toEqual(["/etc", "/proc", "/var/log"]);
    expect(targetChanges(localTarget(policy)).writePaths).toEqual([]);
    expect(targetStandingScopes(localTarget(policy))).toEqual([]);
  });

  it("preserves explicit standing scopes but never derives them from legacy allowlists", () => {
    const baseWorkloadDigest = `sha256:${"b".repeat(64)}`;
    const original = {
      version: 1,
      revision: "policy-standing-v1",
      targets: [{
        id: "target-local-system",
        account: "root",
        displayName: "Local system",
        inspect: { hostSnapshot: true, processList: true, units: [], readPaths: [] },
        changes: { writePaths: [], units: ["example.service"], packages: ["curl"], plugins: [] },
        authorization: { standingScopes: ["service.action"], baseWorkloadDigest },
      }],
    };
    const { policy } = runInitializer(original);
    expect(targetStandingScopes(localTarget(policy))).toEqual(["service.action"]);
    expect((localTarget(policy).authorization as Record<string, unknown>).baseWorkloadDigest)
      .toBe(baseWorkloadDigest);
  });

  it("refuses to migrate standing base operations without an exact workload.base digest", () => {
    const original = {
      version: 1,
      revision: "policy-unsafe-standing-v1",
      targets: [{
        id: "target-local-system",
        account: "root",
        displayName: "Local system",
        inspect: { hostSnapshot: true, processList: true, units: [], readPaths: [] },
        changes: { writePaths: [], units: ["example.service"], packages: [], plugins: [] },
        authorization: { standingScopes: ["service.action"] },
      }],
    };
    expect(() => runInitializer(original)).toThrow();
  });
});
