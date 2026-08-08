import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { isAbsolute, normalize } from "node:path";
import { requireInteger, requireString } from "./guards.js";
import { requireExactRecord } from "./strict.js";

export const ENROLLED_LOCAL_ADMINISTRATOR_PATH = "/etc/ops-agent/local-administrator.json";

const MAX_IDENTITY_BYTES = 4096;

export interface EnrolledLocalAdministrator {
  version: 1;
  uid: number;
  username: string;
}

function parseEnrolledLocalAdministrator(value: unknown): EnrolledLocalAdministrator {
  const input = requireExactRecord(value, "enrolled local administrator", [
    "version", "uid", "username",
  ]);
  if (input.version !== 1) {
    throw new Error("enrolled local administrator has an unsupported version");
  }
  return {
    version: 1,
    uid: requireInteger(input.uid, "enrolled local administrator.uid", 1, 2_147_483_647),
    username: requireString(input.username, "enrolled local administrator.username", {
      max: 32,
      pattern: /^[a-z_][a-z0-9_-]{0,31}$/u,
    }),
  };
}

/**
 * Read the fixed, root-owned enrollment record without following a final
 * symlink. This record is deliberately independent of OPS_AGENT_CONFIG: an
 * untrusted client-group process may choose its own config file, but it cannot
 * thereby nominate itself as the local approval principal.
 */
export async function loadEnrolledLocalAdministrator(
  path = ENROLLED_LOCAL_ADMINISTRATOR_PATH,
  expectedOwnerUid = 0,
): Promise<EnrolledLocalAdministrator> {
  if (!isAbsolute(path) || normalize(path) !== path || path.includes("\0")) {
    throw new Error("local administrator identity path must be a clean absolute path");
  }
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const info = await handle.stat();
    if (!info.isFile() || info.uid !== expectedOwnerUid || info.nlink !== 1
      || (info.mode & 0o777) !== 0o640) {
      throw new Error("local administrator identity must be a root-owned 0640 regular file");
    }
    if (info.size < 2 || info.size > MAX_IDENTITY_BYTES) {
      throw new Error("local administrator identity has an invalid bounded size");
    }
    const payload = await handle.readFile({ encoding: "utf8" });
    return parseEnrolledLocalAdministrator(JSON.parse(payload) as unknown);
  } finally {
    await handle.close();
  }
}
