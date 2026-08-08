import { chmod, mkdtemp, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { loadEnrolledLocalAdministrator } from "../src/shared/local-administrator.js";

describe("root-owned local administrator enrollment", () => {
  it("loads only the exact owner-controlled UID and username record", async () => {
    const root = await mkdtemp(join(tmpdir(), "ops-local-admin-"));
    const path = join(root, "local-administrator.json");
    const ownerUid = process.getuid?.() ?? 0;
    await writeFile(path, '{"version":1,"uid":1000,"username":"local-admin"}\n', { mode: 0o640 });
    await chmod(path, 0o640);
    await expect(loadEnrolledLocalAdministrator(path, ownerUid)).resolves.toEqual({
      version: 1,
      uid: 1000,
      username: "local-admin",
    });

    await chmod(path, 0o660);
    await expect(loadEnrolledLocalAdministrator(path, ownerUid)).rejects.toThrow("root-owned 0640");
  });

  it("rejects symlinks and unknown identity fields", async () => {
    const root = await mkdtemp(join(tmpdir(), "ops-local-admin-"));
    const target = join(root, "target.json");
    const link = join(root, "identity.json");
    const ownerUid = process.getuid?.() ?? 0;
    await writeFile(
      target,
      '{"version":1,"uid":1000,"username":"local-admin","trusted":true}\n',
      { mode: 0o640 },
    );
    await chmod(target, 0o640);
    await expect(loadEnrolledLocalAdministrator(target, ownerUid)).rejects.toThrow("trusted");
    await symlink(target, link);
    await expect(loadEnrolledLocalAdministrator(link, ownerUid)).rejects.toThrow();
  });
});
