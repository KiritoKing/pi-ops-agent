#!/usr/bin/env node
import {
  chmodSync,
  closeSync,
  constants as fsConstants,
  copyFileSync,
  fsyncSync,
  lstatSync,
  openSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join } from "node:path";

const configPath = process.argv[2] ?? process.env.BOTS_CONFIG ?? join(homedir(), ".botmux", "bots.json");
if (!isAbsolute(configPath)) {
  throw new Error("bots.json path must be absolute");
}
const botIndex = Number.parseInt(process.argv[3] ?? "0", 10);
if (!Number.isInteger(botIndex) || botIndex < 0) {
  throw new Error("bot index must be a non-negative integer");
}

const stat = lstatSync(configPath);
if (!stat.isFile() || stat.isSymbolicLink()) {
  throw new Error("bots.json must be a regular file, not a symlink");
}
if (typeof process.getuid === "function" && stat.uid !== process.getuid()) {
  throw new Error("bots.json must be owned by the current user");
}

const bots = JSON.parse(readFileSync(configPath, "utf8"));
if (!Array.isArray(bots) || botIndex >= bots.length) {
  throw new Error("configured bot index does not exist");
}
const bot = bots[botIndex];
if (typeof bot !== "object" || bot === null || Array.isArray(bot)) {
  throw new Error("configured bot must be an object");
}
if (!Array.isArray(bot.allowedUsers) || bot.allowedUsers.length !== 1) {
  throw new Error("ops bot must have exactly one allowed user");
}
if (Array.isArray(bot.allowedChatGroups) && bot.allowedChatGroups.length > 0) {
  throw new Error("ops bot must not allow chat groups");
}

const timestamp = new Date().toISOString().replaceAll(/[:.]/gu, "-");
const backupPath = `${configPath}.pre-ops-agent-${timestamp}`;
copyFileSync(configPath, backupPath);
chmodSync(backupPath, 0o600);

Object.assign(bot, {
  cliId: "pi",
  cliPathOverride: "/opt/pi-ops-agent/bin/ops-agent-botmux",
  p2pOpen: false,
  disableCliBypass: true,
  sandbox: false,
  writableTerminalLinkInCard: false,
});
delete bot.sandboxHidePaths;
delete bot.sandboxNetwork;

const temporaryPath = `${configPath}.ops-agent.tmp`;
const file = openSync(
  temporaryPath,
  fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
  0o600,
);
try {
  writeFileSync(file, `${JSON.stringify(bots, undefined, 2)}\n`);
  fsyncSync(file);
} finally {
  closeSync(file);
}
chmodSync(temporaryPath, 0o600);
renameSync(temporaryPath, configPath);
const directory = openSync(dirname(configPath), "r");
try {
  fsyncSync(directory);
} finally {
  closeSync(directory);
}

process.stdout.write(
  `${JSON.stringify(
    {
      cliId: bot.cliId,
      sandbox: bot.sandbox,
      p2pOpen: bot.p2pOpen,
      disableCliBypass: bot.disableCliBypass,
      writableTerminalLinkInCard: bot.writableTerminalLinkInCard,
      allowedUsersCount: bot.allowedUsers.length,
      allowedChatGroupsCount: Array.isArray(bot.allowedChatGroups)
        ? bot.allowedChatGroups.length
        : 0,
      backupPath,
    },
    undefined,
    2,
  )}\n`,
);
