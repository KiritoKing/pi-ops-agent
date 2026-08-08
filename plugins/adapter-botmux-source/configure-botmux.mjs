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
import { homedir, tmpdir } from "node:os";
import { dirname, isAbsolute, join, normalize } from "node:path";

const configPath = process.argv[2] ?? process.env.BOTS_CONFIG ?? join(homedir(), ".botmux", "bots.json");
if (!isAbsolute(configPath) || normalize(configPath) !== configPath) {
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
const currentUid = typeof process.getuid === "function" ? process.getuid() : undefined;
if (currentUid === 0) {
  throw new Error("BotMux configuration hardener must never run as root");
}
if (currentUid !== undefined && stat.uid !== currentUid) {
  throw new Error("bots.json must be owned by the current user");
}
if ((stat.mode & 0o077) !== 0) {
  throw new Error("bots.json must not be group/world accessible");
}
if (stat.size < 2 || stat.size > 1024 * 1024) {
  throw new Error("bots.json is outside the supported size range");
}

const expectedHome = "/var/lib/ops-agent/adapters/botmux";
const expectedPath = `${expectedHome}/.botmux/bots.json`;
const testOnlyPath = process.env.OPS_AGENT_BOTMUX_TEST_ONLY === "1"
  && configPath.startsWith(`${tmpdir()}/`);
if (!testOnlyPath && (homedir() !== expectedHome || configPath !== expectedPath)) {
  throw new Error("BotMux configuration must live under the dedicated adapter account");
}
const protectedDirectories = testOnlyPath
  ? [dirname(configPath)]
  : [dirname(configPath), homedir()];
for (const directoryPath of protectedDirectories) {
  const directoryStat = lstatSync(directoryPath);
  if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()) {
    throw new Error("BotMux configuration parent must be a real directory");
  }
  if (currentUid !== undefined && directoryStat.uid !== currentUid) {
    throw new Error("BotMux configuration parent must be owned by the adapter account");
  }
  if ((directoryStat.mode & 0o077) !== 0) {
    throw new Error("BotMux configuration parent must be owner-only");
  }
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
if (typeof bot.allowedUsers[0] !== "string"
    || bot.allowedUsers[0].length < 1 || bot.allowedUsers[0].length > 256) {
  throw new Error("ops bot allowed user must be a bounded string");
}
if (Array.isArray(bot.allowedChatGroups) && bot.allowedChatGroups.length > 0) {
  throw new Error("ops bot must not allow chat groups");
}
if (Array.isArray(bot.globalGrants) && bot.globalGrants.length > 0) {
  throw new Error("ops bot must not grant global talk access");
}
if (bot.chatGrants !== undefined
  && (typeof bot.chatGrants !== "object" || bot.chatGrants === null
    || Array.isArray(bot.chatGrants) || Object.keys(bot.chatGrants).length > 0)) {
  throw new Error("ops bot must not grant per-chat talk access");
}
if (bot.messageListeners !== undefined
  && (typeof bot.messageListeners !== "object" || bot.messageListeners === null
    || Array.isArray(bot.messageListeners)
    || Object.values(bot.messageListeners).some((listener) =>
      typeof listener === "object" && listener !== null && listener.enabled === true))) {
  throw new Error("ops bot must not enable non-mention message listeners");
}

const fixedPath = "/opt/pi-ops-agent/botmux-bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const existingEnvironment = typeof bot.env === "object" && bot.env !== null && !Array.isArray(bot.env)
  ? bot.env
  : {};

const timestamp = new Date().toISOString().replaceAll(/[:.]/gu, "-");
const backupPath = `${configPath}.pre-ops-agent-${timestamp}`;
copyFileSync(configPath, backupPath);
chmodSync(backupPath, 0o600);

Object.assign(bot, {
  cliId: "pi",
  cliPathOverride: "/opt/pi-ops-agent/botmux-bin/pi",
  p2pOpen: false,
  disableCliBypass: true,
  launchShell: "/bin/bash",
  env: { ...existingEnvironment, PATH: fixedPath },
  sandbox: false,
  autoGrantRequestCards: false,
  autoStartOnGroupJoin: false,
  autoStartOnNewTopic: false,
  disableStreamingCard: true,
  silentTurnReactions: true,
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
      launchShell: bot.launchShell,
      path: bot.env.PATH,
      autoGrantRequestCards: bot.autoGrantRequestCards,
      autoStartOnGroupJoin: bot.autoStartOnGroupJoin,
      autoStartOnNewTopic: bot.autoStartOnNewTopic,
      disableStreamingCard: bot.disableStreamingCard,
      silentTurnReactions: bot.silentTurnReactions,
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
