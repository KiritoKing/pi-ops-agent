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

function runInitializer(existingPolicy: unknown): { inputPath: string; outputPath: string; policy: Record<string, unknown> } {
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
  execFileSync(process.execPath, [
    join(process.cwd(), "scripts/initialize-target-policy.mjs"),
    "--catalog-index", catalogPath,
    "--policy", inputPath,
    "--output", outputPath,
  ]);
  const parsed = JSON.parse(readFileSync(outputPath, "utf8")) as unknown;
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("expected policy object");
  return { inputPath, outputPath, policy: parsed as Record<string, unknown> };
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
    expect(changes.plugins).toEqual([{
      id: "adapter.botmux",
      kind: "im-adapter",
      version: "1.0.0",
      publisher: "example/ops",
      digest: digest("a"),
    }]);
    expect((target.inspect as Record<string, unknown>).units).toEqual(["ops-agentd.service"]);
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
  });

  it("authorizes catalog artifacts and Docker only for a fresh installation", () => {
    const { policy } = runInitializer(undefined);
    const changes = targetChanges(localTarget(policy));
    expect(changes.packages).toEqual(["docker.io"]);
    expect(changes.units).toEqual(["docker.service"]);
    expect(changes.plugins).toHaveLength(2);
  });
});
