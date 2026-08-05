import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { parseClientArguments } from "../../src/client/args.js";

describe("parseClientArguments", () => {
  it("accepts BotMux's Pi session invocation", () => {
    expect(parseClientArguments(["--session-id", "session-1234", "inspect host health"])).toEqual({
      kind: "run",
      arguments: {
        sessionId: "session-1234",
        initialPrompt: "inspect host health",
      },
    });
  });

  it("accepts a resume invocation without an initial prompt", () => {
    expect(parseClientArguments(["--session-id=session-1234"])).toEqual({
      kind: "run",
      arguments: { sessionId: "session-1234" },
    });
  });

  it("reads BotMux's constrained absolute @file initial prompt", () => {
    const directory = mkdtempSync(join(tmpdir(), "ops-agent-args-"));
    try {
      const promptPath = join(directory, "initial.prompt.md");
      writeFileSync(promptPath, "inspect from file", { mode: 0o600 });
      expect(parseClientArguments([
        "--extension",
        "/opt/botmux/pi-initial-prompt-extension.js",
        "--session-id",
        "session-1234",
        `@${promptPath}`,
      ])).toEqual({
        kind: "run",
        arguments: {
          sessionId: "session-1234",
          initialPrompt: "inspect from file",
        },
      });
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("rejects symlinked, non-regular, and oversized @file prompts", () => {
    const directory = mkdtempSync(join(tmpdir(), "ops-agent-args-"));
    try {
      const promptPath = join(directory, "initial.prompt.md");
      const linkPath = join(directory, "initial-link.md");
      const oversizedPath = join(directory, "oversized.prompt.md");
      writeFileSync(promptPath, "safe", { mode: 0o600 });
      symlinkSync(promptPath, linkPath);
      writeFileSync(oversizedPath, Buffer.alloc(64 * 1024 + 1), { mode: 0o600 });

      expect(() => parseClientArguments([
        "--session-id",
        "session-1234",
        `@${linkPath}`,
      ])).toThrow("symbolic link");
      expect(() => parseClientArguments([
        "--session-id",
        "session-1234",
        `@${directory}`,
      ])).toThrow("regular file");
      expect(() => parseClientArguments([
        "--session-id",
        "session-1234",
        `@${oversizedPath}`,
      ])).toThrow("65536 bytes");
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("rejects an @file not owned by the current UID", () => {
    const directory = mkdtempSync(join(tmpdir(), "ops-agent-args-"));
    const getuid = process.getuid;
    if (!getuid) throw new Error("test requires Unix user IDs");
    const actualUid = getuid.call(process);
    const uid = vi.spyOn(process, "getuid").mockReturnValue(actualUid + 1);
    try {
      const promptPath = join(directory, "initial.prompt.md");
      writeFileSync(promptPath, "safe", { mode: 0o600 });
      expect(() => parseClientArguments([
        "--session-id",
        "session-1234",
        `@${promptPath}`,
      ])).toThrow("owned by the current UID");
    } finally {
      uid.mockRestore();
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("accepts but does not load the BotMux extension", () => {
    expect(parseClientArguments([
      "--extension=/path/that/does/not/exist.js",
      "--session-id=session-1234",
      "inspect host health",
    ])).toEqual({
      kind: "run",
      arguments: {
        sessionId: "session-1234",
        initialPrompt: "inspect host health",
      },
    });
  });

  it("rejects missing and malformed session identifiers", () => {
    expect(() => parseClientArguments([])).toThrow("--session-id is required");
    expect(() => parseClientArguments(["--session-id", "short"])).toThrow("sessionId");
  });

  it("reports its version without requiring a session", () => {
    expect(parseClientArguments(["--version"])).toEqual({ kind: "version" });
  });
});
