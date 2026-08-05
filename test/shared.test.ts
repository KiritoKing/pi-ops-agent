import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { AuditLog } from "../src/agentd/audit.js";
import { encodeFrame, FrameDecoder, MAX_FRAME_BYTES } from "../src/shared/framing.js";
import { parseAgentClientMessage, parseHelperResponse } from "../src/shared/messages.js";
import { redact, redactText } from "../src/shared/redaction.js";
import { routePrompt } from "../src/shared/router.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map(async (path) => await rm(path, { recursive: true })));
});

describe("framing", () => {
  it("decodes a fragmented frame", () => {
    const frame = encodeFrame({ ok: true });
    const decoder = new FrameDecoder();
    expect(decoder.push(frame.subarray(0, 3))).toEqual([]);
    expect(decoder.push(frame.subarray(3))).toEqual([{ ok: true }]);
  });

  it("rejects oversized frames before allocating the payload", () => {
    const header = Buffer.alloc(4);
    header.writeUInt32BE(MAX_FRAME_BYTES + 1);
    expect(() => new FrameDecoder().push(header)).toThrow(/invalid frame length/);
  });
});

describe("message validation", () => {
  it("validates session identifiers and prompt bounds", () => {
    expect(parseAgentClientMessage({ type: "hello", sessionId: "session-123" })).toEqual({
      type: "hello",
      sessionId: "session-123",
    });
    expect(() => parseAgentClientMessage({ type: "hello", sessionId: "bad" })).toThrow();
  });

  it("does not trust a malformed helper response", () => {
    expect(() => parseHelperResponse({ version: 1, requestId: "x", ok: "yes" })).toThrow();
  });
});

describe("model routing", () => {
  it("uses low effort for bounded health checks", () => {
    expect(routePrompt("检查磁盘和内存状态")).toMatchObject({ risk: "R0", thinking: "low" });
  });

  it("uses high effort for mutations and diagnosis", () => {
    expect(routePrompt("安装 nginx 并重启服务")).toMatchObject({ risk: "R2", thinking: "high" });
    expect(routePrompt("诊断服务异常原因")).toMatchObject({ risk: "R1", thinking: "high" });
  });
});

describe("redaction", () => {
  it("redacts token-shaped values and secret keys", () => {
    const secret = `sk-${"a".repeat(32)}`;
    expect(redactText(`token=${secret}`)).not.toContain(secret);
    expect(redact({ nested: { apiKey: secret } })).toEqual({ nested: { apiKey: "[REDACTED]" } });
  });
});

describe("audit chain", () => {
  it("continues the verified chain across restarts and fails closed on tampering", async () => {
    const directory = await mkdtemp(join(tmpdir(), "ops-agent-audit-"));
    temporaryDirectories.push(directory);
    const path = join(directory, "audit.jsonl");
    const first = new AuditLog(path);
    await first.initialize();
    await first.append({ type: "one" });

    const second = new AuditLog(path);
    await second.initialize();
    await second.append({ type: "two" });
    const lines = (await readFile(path, "utf8")).trim().split("\n");
    expect(lines).toHaveLength(2);

    const changed = lines[0]?.replace('"one"', '"tampered"');
    if (!changed) throw new Error("missing audit fixture");
    await writeFile(path, `${changed}\n${lines[1] ?? ""}\n`);
    await expect(new AuditLog(path).initialize()).rejects.toThrow(/audit chain hash mismatch/);
  });
});
