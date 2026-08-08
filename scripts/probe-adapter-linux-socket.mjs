#!/usr/bin/env node
import { chmod, chown, writeFile } from "node:fs/promises";
import { createServer } from "node:net";

const socketPath = process.argv[2];
const readyPath = process.argv[3];
const groupId = Number.parseInt(process.argv[4] ?? "", 10);
if (socketPath === undefined || readyPath === undefined || !Number.isSafeInteger(groupId)) {
  throw new Error("usage: adapter-linux-socket-server <socket> <ready> <gid>");
}

const server = createServer((socket) => {
  const chunks = [];
  socket.on("data", (chunk) => chunks.push(chunk));
  socket.once("data", () => {
    const request = Buffer.concat(chunks).toString("utf8");
    if (request === "adapter-probe\n") socket.end("root-group-socket-ok\n");
    else socket.destroy(new Error("invalid probe request"));
  });
});

server.listen(socketPath, async () => {
  await chown(socketPath, 0, groupId);
  await chmod(socketPath, 0o660);
  await writeFile(readyPath, "ready\n", { mode: 0o600 });
});

const timer = setTimeout(() => {
  process.stderr.write("adapter-linux-socket-server: timed out\n");
  server.close();
  process.exitCode = 1;
}, 15_000);

server.once("close", () => clearTimeout(timer));
server.once("connection", () => server.close());
