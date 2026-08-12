#!/usr/bin/env node
import fs from "node:fs";

const context = fs.readFileSync(5, "utf8");
const value = JSON.parse(context);
if (value?.apiVersion !== "agentd.adapter-client-context/v1"
  || value?.schemaVersion !== 1
  || value?.pluginId !== "adapter.botmux"
  || typeof value?.digest !== "string"
  || value?.descriptor?.adapterId !== "adapter.botmux") {
  throw new Error("Linux probe Client received an invalid runner context");
}

const input = fs.readFileSync(4, "utf8");
const lines = input.split("\n");
if (lines.at(-1) !== "") {
  throw new Error("Linux probe Client input is not newline-terminated");
}
lines.pop();
const frames = lines.map((line) => JSON.parse(line));
if (frames.length !== 2
  || frames[0]?.apiVersion !== "agentd.adapter-session-control/v1"
  || frames[0]?.schemaVersion !== 1
  || frames[0]?.type !== "bind"
  || frames[0]?.sessionId !== "adapter-probe-session-1234"
  || frames[0]?.externalSessionId !== "linux-probe-external-session"
  || frames[1]?.apiVersion !== "agentd.adapter-inbound/v1"
  || frames[1]?.schemaVersion !== 1
  || frames[1]?.type !== "text"
  || frames[1]?.externalSessionId !== frames[0].externalSessionId
  || frames[1]?.text !== "FD3/FD4 分片探针") {
  throw new Error("Linux probe Client received invalid typed Source Adapter input");
}
fs.writeSync(3, "probe-completion\n", undefined, "utf8");
fs.closeSync(3);
