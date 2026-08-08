import { mkdtemp, rm } from "node:fs/promises";
import { createServer, type Server, type Socket } from "node:net";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { encodeFrame, FrameDecoder } from "../src/shared/framing.js";
import {
  acquireActiveRuntimeSourcePluginLease,
  type ActiveRuntimeSourcePlugin,
} from "../src/shared/source-plugin.js";

interface TestBroker {
  root: string;
  path: string;
  server: Server;
  sockets: Set<Socket>;
}

const brokers: TestBroker[] = [];

afterEach(async () => {
  await Promise.all(brokers.splice(0).map(async (broker) => {
    for (const socket of broker.sockets) socket.destroy();
    await new Promise<void>((resolve) => broker.server.close(() => resolve()));
    await rm(broker.root, { recursive: true, force: true });
  }));
});

function registration(registryRoot: string): ActiveRuntimeSourcePlugin {
  const digest = `sha256:${"a".repeat(64)}`;
  return {
    apiVersion: "agentd.plugin-registration/v1",
    schemaVersion: 1,
    pluginId: "workload.example",
    kind: "workload",
    version: "1.0.0",
    publisher: "test/lease-broker",
    digest,
    capabilities: ["demo.echo"],
    requestedScopes: [],
    approvedBy: "test:administrator",
    approvedAt: "2026-08-08T00:00:00Z",
    entrypoint: "workload.mjs",
    snapshotPath: join(registryRoot, "snapshots", "sha256", digest.slice(7)),
  };
}

async function listenBroker(
  handler: (socket: Socket, decoder: FrameDecoder) => void,
): Promise<TestBroker> {
  const root = await mkdtemp(join("/tmp", "agentd-plugin-lease-client-"));
  const path = join(root, "lease.sock");
  const sockets = new Set<Socket>();
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
    handler(socket, new FrameDecoder());
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(path, () => {
      server.off("error", reject);
      resolve();
    });
  });
  const broker = { root, path, server, sockets };
  brokers.push(broker);
  return broker;
}

describe("source plugin lease broker client", () => {
  it("waits for the broker release acknowledgement before returning", async () => {
    const releaseObserved = Promise.withResolvers<undefined>();
    const broker = await listenBroker((socket, decoder) => {
      socket.on("data", (chunk: Buffer) => {
        for (const value of decoder.push(chunk)) {
          const request = value as { version?: unknown; pluginId?: unknown; digest?: unknown; action?: unknown };
          if (request.action === "release") {
            releaseObserved.resolve(undefined);
            setTimeout(() => {
              socket.end(encodeFrame({ version: 1, ok: true, state: "RELEASED" }));
            }, 10);
            continue;
          }
          const plugin = registration(join(broker.root, "registry"));
          expect(request).toEqual({
            version: 1,
            pluginId: plugin.pluginId,
            digest: plugin.digest,
          });
          socket.write(encodeFrame({
            version: 1,
            ok: true,
            state: "LEASED",
            registration: plugin,
          }));
        }
      });
    });
    const plugin = registration(join(broker.root, "registry"));
    const lease = await acquireActiveRuntimeSourcePluginLease({
      pluginRegistryPath: join(broker.root, "registry"),
      pluginLeaseSocketPath: broker.path,
    }, plugin);
    const release = lease.release();
    let releaseSettled = false;
    void release.then(() => { releaseSettled = true; });
    await releaseObserved.promise;
    expect(releaseSettled).toBe(false);
    await release;
    expect(releaseSettled).toBe(true);
  });

  it("rejects the loss signal when the broker restarts or drops the peer", async () => {
    const broker = await listenBroker((socket, decoder) => {
      socket.on("data", (chunk: Buffer) => {
        for (const value of decoder.push(chunk)) {
          const request = value as { pluginId?: unknown; digest?: unknown };
          const plugin = registration(join(broker.root, "registry"));
          expect(request).toMatchObject({ pluginId: plugin.pluginId, digest: plugin.digest });
          socket.write(encodeFrame({
            version: 1,
            ok: true,
            state: "LEASED",
            registration: plugin,
          }), () => socket.destroy());
        }
      });
    });
    const plugin = registration(join(broker.root, "registry"));
    const lease = await acquireActiveRuntimeSourcePluginLease({
      pluginRegistryPath: join(broker.root, "registry"),
      pluginLeaseSocketPath: broker.path,
    }, plugin);
    await expect(lease.lost).rejects.toThrow("plugin lease broker connection was lost");
    await lease.release();
  });
});
