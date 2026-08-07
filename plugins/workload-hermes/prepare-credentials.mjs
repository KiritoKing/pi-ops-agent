import { randomBytes, scryptSync } from "node:crypto";
import { readFileSync } from "node:fs";

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

const args = process.argv.slice(2);
if (args.length !== 2 || args[0] !== "--input-fd" || !/^[0-9]+$/u.test(args[1] ?? "")) {
  fail("Usage: prepare-credentials.mjs --input-fd N");
}
const inputFD = Number(args[1]);
if (!Number.isSafeInteger(inputFD) || inputFD < 3 || inputFD > 1024) {
  fail("--input-fd must identify an explicitly opened descriptor between 3 and 1024.");
}

let input;
try {
  input = JSON.parse(readFileSync(inputFD, "utf8"));
} catch {
  fail("Credential input must be one JSON object read from the supplied descriptor.");
}
if (input === null || typeof input !== "object" || Array.isArray(input)) {
  fail("Credential input must be a JSON object.");
}
const keys = Object.keys(input);
const expectedKeys = ["dashboardPassword", "dashboardUsername", "deepseekApiKey"];
if (keys.length !== expectedKeys.length || expectedKeys.some((key) => !Object.hasOwn(input, key))) {
  fail("Credential input must contain exactly deepseekApiKey, dashboardUsername, and dashboardPassword.");
}

const { deepseekApiKey, dashboardUsername, dashboardPassword } = input;
if (typeof deepseekApiKey !== "string" || !/^[A-Za-z0-9+/=._:$-]{16,512}$/u.test(deepseekApiKey)) {
  fail("DeepSeek API key format is invalid.");
}
if (typeof dashboardUsername !== "string" || !/^[A-Za-z0-9._-]{1,64}$/u.test(dashboardUsername)) {
  fail("Dashboard username format is invalid.");
}
if (typeof dashboardPassword !== "string" || dashboardPassword.length < 16 || dashboardPassword.length > 256 || /[\u0000\r\n]/u.test(dashboardPassword)) {
  fail("Dashboard password must contain 16 to 256 characters without line breaks.");
}

const salt = randomBytes(16);
const derived = scryptSync(dashboardPassword, salt, 32, {
  N: 16384,
  r: 8,
  p: 1,
  maxmem: 64 * 1024 * 1024,
});
const dashboardPasswordHash = `scrypt$16384$8$1$${salt.toString("base64")}$${derived.toString("base64")}`;
const bundle = {
  version: 1,
  pluginId: "workload.hermes",
  values: [
    { name: "dashboardPasswordHash", value: dashboardPasswordHash },
    { name: "dashboardSessionSecret", value: randomBytes(32).toString("base64") },
    { name: "dashboardUsername", value: dashboardUsername },
    { name: "deepseekApiKey", value: deepseekApiKey },
  ],
};
process.stdout.write(`${JSON.stringify(bundle)}\n`);
