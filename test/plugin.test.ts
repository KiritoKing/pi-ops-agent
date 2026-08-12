import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  isAdapterPluginManifest,
  isManagedWorkloadPluginManifest,
  parseAdapterPluginManifest,
  parseManagedWorkloadPluginManifest,
  parsePluginCatalogEntry,
  parsePluginManifest,
} from "../src/shared/plugin.js";

const manifest = {
  schemaVersion: 1,
  id: "adapter.botmux",
  kind: "im-adapter",
  version: "0.2.0",
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

const workloadManifest = {
  schemaVersion: 2,
  id: "workload.hermes",
  kind: "managed-workload",
  version: "0.2.0",
  publisher: "KiritoKing/pi-ops-agent",
  coreProtocol: 1,
  description: "Hermes managed workload",
  workload: {
    runtime: "docker",
    imageRepository: "nousresearch/hermes-agent",
    imageDigest: `sha256:${"a".repeat(64)}`,
    containerName: "ops-agent-hermes",
    containerCommand: ["gateway", "run"],
    expectedEntrypoint: ["/opt/hermes/docker/entrypoint-dispatch.sh"],
    expectedUser: "root",
    processPolicy: {
      runtimeUser: "10000:10000",
      allowedRuntimeCommands: ["hermes", "s6-log", "sleep"],
      requiredRuntimeCommands: ["hermes"],
      allowedRootCommands: ["s6-svscan", "s6-supervise", "sleep"],
    },
    containerPort: 9119,
    hostPort: 9119,
    dataMountTarget: "/opt/data",
    uid: 10000,
    gid: 10000,
    resources: {
      memoryBytes: 4 * 1024 * 1024 * 1024,
      nanoCpus: 2_000_000_000,
      pidsLimit: 512,
      shmBytes: 1024 * 1024 * 1024,
    },
    capAdd: ["CHOWN", "DAC_OVERRIDE", "FOWNER", "KILL", "SETGID", "SETUID"],
    literalEnvironment: {
      HERMES_UID: "10000",
      HERMES_GID: "10000",
      HERMES_DASHBOARD: "1",
    },
    credentialEnvironment: {
      deepseekApiKey: "DEEPSEEK_API_KEY",
      dashboardUsername: "HERMES_DASHBOARD_BASIC_AUTH_USERNAME",
      dashboardPasswordHash: "HERMES_DASHBOARD_BASIC_AUTH_PASSWORD_HASH",
      dashboardSessionSecret: "HERMES_DASHBOARD_BASIC_AUTH_SECRET",
    },
    directories: [{ path: "/opt/data/workspace", mode: "0750" }],
    files: [
      { source: "config.yaml", path: "/opt/data/config.yaml", mode: "0644" },
      { source: "ops-healthcheck.py", path: "/opt/data/ops-healthcheck.py", mode: "0555" },
    ],
    containerExecChecks: [{
      argv: ["/opt/hermes/.venv/bin/python", "/opt/data/ops-healthcheck.py"],
      outputContains: "ops-healthcheck: ok",
    }],
  },
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
    expect(() => parseAdapterPluginManifest({ ...manifest, entrypoint: "adapter.mjs;sh" })).toThrow(
      /normalized \.mjs/u,
    );
    expect(() => parseAdapterPluginManifest({ ...manifest, entrypoint: "nested//adapter.mjs" })).toThrow(
      /clean relative path/u,
    );
    expect(() =>
      parseAdapterPluginManifest({ ...manifest, setupOperations: ["root.shell"] }),
    ).toThrow(/unsupported/u);
    expect(() =>
      parseAdapterPluginManifest({ ...manifest, setupOperations: ["config.write", "config.write"] }),
    ).toThrow(/duplicates/u);
    expect(() =>
      parseAdapterPluginManifest({ ...manifest, setupOperations: ["config.write"] }),
    ).toThrow(/credential\.install/u);
    expect(() => parseAdapterPluginManifest({ ...manifest, secrets: ["Lark.App.Secret"] })).toThrow(
      /unsupported/u,
    );
    expect(() => parseAdapterPluginManifest({ ...manifest, version: `1.0.0-${"a".repeat(96)}` })).toThrow(
      /plugin version/u,
    );
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

describe("managed workload plugin manifest", () => {
  it("parses the first-party Hermes manifest from the repository", () => {
    const repositoryManifest = JSON.parse(readFileSync(
      new URL("../plugins/workload-hermes/manifest.json", import.meta.url),
      "utf8",
    )) as unknown;
    expect(parseManagedWorkloadPluginManifest(repositoryManifest)).toMatchObject({
      id: "workload.hermes",
      version: "0.3.0",
      workload: { containerName: "ops-agent-hermes", expectedUser: "root" },
    });
  });

  it("requires an absolute expected container entrypoint", () => {
    expect(() => parseManagedWorkloadPluginManifest({
      ...workloadManifest,
      workload: { ...workloadManifest.workload, expectedEntrypoint: ["entrypoint-dispatch.sh"] },
    })).toThrow(/clean absolute container path/u);
  });

  it("accepts a bounded declarative Docker workload", () => {
    expect(parseManagedWorkloadPluginManifest(workloadManifest)).toMatchObject({
      id: "workload.hermes",
      workload: {
        runtime: "docker",
        hostPort: 9119,
        dataMountTarget: "/opt/data",
      },
    });
    expect(parsePluginManifest(workloadManifest).kind).toBe("managed-workload");
    expect(isManagedWorkloadPluginManifest(workloadManifest)).toBe(true);
  });

  it("rejects host execution and raw Docker escape hatches", () => {
    expect(() => parseManagedWorkloadPluginManifest({
      ...workloadManifest,
      hostExecutable: "/bin/sh",
    })).toThrow(/unknown fields/u);
    expect(() => parseManagedWorkloadPluginManifest({
      ...workloadManifest,
      workload: { ...workloadManifest.workload, dockerArgs: ["--privileged"] },
    })).toThrow(/unknown fields/u);
    expect(() => parseManagedWorkloadPluginManifest({
      ...workloadManifest,
      workload: { ...workloadManifest.workload, capAdd: ["SYS_ADMIN"] },
    })).toThrow(/unsupported/u);
    expect(() => parseManagedWorkloadPluginManifest({
      ...workloadManifest,
      workload: { ...workloadManifest.workload, containerName: "hermes" },
    })).toThrow(/invalid format/u);
    expect(() => parseManagedWorkloadPluginManifest({
      ...workloadManifest,
      workload: {
        ...workloadManifest.workload,
        containerExecChecks: [{ argv: ["/bin/sh", "-c", "curl localhost"], outputContains: "ok" }],
      },
    })).toThrow(/cannot invoke a shell/u);
  });

  it("keeps static files inside the data mount and secrets out of literals", () => {
    expect(() => parseManagedWorkloadPluginManifest({
      ...workloadManifest,
      workload: {
        ...workloadManifest.workload,
        files: [{ source: "config.yaml", path: "/etc/shadow", mode: "0644" }],
      },
    })).toThrow(/managed data mount/u);
    expect(() => parseManagedWorkloadPluginManifest({
      ...workloadManifest,
      workload: {
        ...workloadManifest.workload,
        literalEnvironment: { DEEPSEEK_API_KEY: "secret" },
      },
    })).toThrow(/secret-like/u);
    expect(() => parseManagedWorkloadPluginManifest({
      ...workloadManifest,
      workload: {
        ...workloadManifest.workload,
        credentialEnvironment: { deepseekApiKey: "HERMES_UID" },
      },
    })).toThrow(/unique/u);
    expect(() => parseManagedWorkloadPluginManifest({
      ...workloadManifest,
      workload: {
        ...workloadManifest.workload,
        expectedUser: "10000:10000",
        processPolicy: { ...workloadManifest.workload.processPolicy, allowedRootCommands: ["s6-svscan"] },
      },
    })).toThrow(/non-root workloads/u);
    expect(() => parseManagedWorkloadPluginManifest({
      ...workloadManifest,
      workload: {
        ...workloadManifest.workload,
        processPolicy: { ...workloadManifest.workload.processPolicy, requiredRuntimeCommands: ["python"] },
      },
    })).toThrow(/subset/u);
  });

  it("parses workload catalog entries through the union parser", () => {
    expect(parsePluginCatalogEntry({
      manifest: workloadManifest,
      packagePath: "/opt/pi-ops-agent/current/catalog/workload-hermes.opspkg",
      digest: `sha256:${"b".repeat(64)}`,
      signaturePath: "/opt/pi-ops-agent/current/catalog/workload-hermes.opspkg.sig",
    }).manifest.kind).toBe("managed-workload");
    expect(isAdapterPluginManifest(workloadManifest)).toBe(false);
  });
});
