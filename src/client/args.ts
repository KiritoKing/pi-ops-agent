import {
  closeSync,
  constants as fsConstants,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
} from "node:fs";
import { isAbsolute } from "node:path";
import { parseAgentClientMessage } from "../shared/messages.js";

const MAX_INITIAL_PROMPT_FILE_BYTES = 64 * 1024;

export interface ClientArguments {
  sessionId: string;
  initialPrompt?: string;
}

export interface ParsedClientArguments {
  kind: "run";
  arguments: ClientArguments;
}

export interface ClientVersionArguments {
  kind: "version";
}

export type ClientInvocation = ParsedClientArguments | ClientVersionArguments;

function readInitialPromptFile(argument: string): string {
  const path = argument.slice(1);
  if (!isAbsolute(path)) return argument;
  const uid = process.getuid?.();
  if (uid === undefined) {
    throw new Error("@file prompts require a platform with Unix user IDs");
  }

  const linkStat = lstatSync(path);
  if (linkStat.isSymbolicLink()) {
    throw new Error("@file prompt must not be a symbolic link");
  }

  const descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const stat = fstatSync(descriptor);
    if (!stat.isFile()) throw new Error("@file prompt must be a regular file");
    if (stat.uid !== uid) throw new Error("@file prompt must be owned by the current UID");
    if (stat.size > MAX_INITIAL_PROMPT_FILE_BYTES) {
      throw new Error(`@file prompt exceeds ${MAX_INITIAL_PROMPT_FILE_BYTES} bytes`);
    }
    const content = Buffer.alloc(stat.size);
    let offset = 0;
    while (offset < content.length) {
      const bytesRead = readSync(descriptor, content, offset, content.length - offset, offset);
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    return content.subarray(0, offset).toString("utf8");
  } finally {
    closeSync(descriptor);
  }
}

export function parseClientArguments(argv: readonly string[]): ClientInvocation {
  let sessionId: string | undefined;
  let ignoredExtension = false;
  const positional: string[] = [];

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === undefined) continue;
    if (argument === "--version" || argument === "-v") {
      if (argv.length !== 1) throw new Error("--version cannot be combined with other arguments");
      return { kind: "version" };
    }
    if (argument === "--session-id") {
      const value = argv[index + 1];
      if (!value) throw new Error("--session-id requires a value");
      if (sessionId !== undefined) throw new Error("--session-id may only be specified once");
      sessionId = value;
      index += 1;
      continue;
    }
    if (argument.startsWith("--session-id=")) {
      if (sessionId !== undefined) throw new Error("--session-id may only be specified once");
      sessionId = argument.slice("--session-id=".length);
      continue;
    }
    if (argument === "--extension") {
      const value = argv[index + 1];
      if (!value) throw new Error("--extension requires a value");
      if (ignoredExtension) throw new Error("--extension may only be specified once");
      if (!isAbsolute(value)) throw new Error("--extension requires an absolute path");
      ignoredExtension = true;
      index += 1;
      continue;
    }
    if (argument.startsWith("--extension=")) {
      if (ignoredExtension) throw new Error("--extension may only be specified once");
      const value = argument.slice("--extension=".length);
      if (!isAbsolute(value)) throw new Error("--extension requires an absolute path");
      ignoredExtension = true;
      continue;
    }
    if (argument.startsWith("-")) throw new Error(`unsupported option: ${argument}`);
    positional.push(argument);
  }

  if (!sessionId) throw new Error("--session-id is required");
  const initialPrompt = positional.length > 0
    ? positional.length === 1 && positional[0]?.startsWith("@")
      ? readInitialPromptFile(positional[0])
      : positional.join(" ")
    : undefined;
  const validated = parseAgentClientMessage({
    type: "hello",
    sessionId,
    ...(initialPrompt === undefined ? {} : { initialPrompt }),
  });
  if (validated.type !== "hello") throw new Error("unexpected client argument validation result");
  return {
    kind: "run",
    arguments:
      validated.initialPrompt === undefined
        ? { sessionId: validated.sessionId }
        : { sessionId: validated.sessionId, initialPrompt: validated.initialPrompt },
  };
}
