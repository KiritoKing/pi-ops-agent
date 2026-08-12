import type { ApprovalRisk } from "../shared/approval-review.js";

const MAX_SOURCE_BYTES = 128 * 1024;
const MAX_SEGMENTS = 64;
const MAX_ITEMS_PER_SEGMENT = 512;
const MAX_DISPLAY_BYTES = 512;
const MAX_NESTING = 32;

const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/u;
const SHELL_CONTROL_WORDS = new Set([
  "case", "coproc", "do", "done", "elif", "else", "esac", "fi", "for", "function",
  "if", "in", "select", "then", "time", "until", "while",
]);

export type ShellOperator = "start" | "sequence" | "and" | "or" | "pipe" | "background";

export type ShellDependency =
  | "none"
  | "after-completion"
  | "on-success"
  | "on-failure"
  | "pipeline-input"
  | "concurrent";

export type ShellClassification =
  | "destructive"
  | "dynamic"
  | "filesystem-write"
  | "network"
  | "opaque"
  | "privilege-transition"
  | "redirection";

export interface ShellRedirection {
  operator: string;
  target?: string;
}

export interface ShellSegmentAnalysis {
  index: number;
  sourceStart: number;
  sourceEnd: number;
  display: string;
  operatorBefore: ShellOperator;
  dependency: ShellDependency;
  dependsOn?: number;
  executable: string;
  wrappers: readonly string[];
  redirections: readonly ShellRedirection[];
  classifications: readonly ShellClassification[];
  opaqueReasons: readonly string[];
  riskFloor: ApprovalRisk;
}

export interface ShellCommandAnalysis {
  version: 1;
  segments: readonly ShellSegmentAnalysis[];
  riskFloor: ApprovalRisk;
  opaqueReasons: readonly string[];
  canSafelySuggestIndependentSplit: boolean;
  splitReason: string;
}

type Quote = "none" | "single" | "double";
type ContextKind = "root" | "command-substitution" | "parameter-expansion" | "process-substitution" | "subshell";

interface LexContext {
  kind: ContextKind;
  quote: Quote;
  depth: number;
  terminator: ")" | "}" | "";
}

interface LexWord {
  kind: "word";
  value: string;
  start: number;
  end: number;
  opaqueReasons: string[];
}

interface LexRedirection {
  kind: "redirection";
  value: string;
  start: number;
  end: number;
}

type LexItem = LexWord | LexRedirection;

interface LexSegment {
  items: LexItem[];
  sourceStart: number;
  sourceEnd: number;
  operatorBefore: ShellOperator;
  opaqueReasons: string[];
}

interface MutableWord {
  value: string;
  start: number;
  end: number;
  opaqueReasons: string[];
}

interface LexResult {
  segments: LexSegment[];
  fatalReasons: string[];
}

interface CommandClassification {
  executable: string;
  wrappers: string[];
  classifications: ShellClassification[];
  opaqueReasons: string[];
  riskFloor: ApprovalRisk;
}

function riskRank(risk: ApprovalRisk): number {
  switch (risk) {
    case "low": return 0;
    case "medium": return 1;
    case "high": return 2;
    case "critical": return 3;
  }
}

function maxRisk(...risks: readonly ApprovalRisk[]): ApprovalRisk {
  let result: ApprovalRisk = "low";
  for (const risk of risks) {
    if (riskRank(risk) > riskRank(result)) result = risk;
  }
  return result;
}

function pushUnique(target: string[], value: string): void {
  if (!target.includes(value)) target.push(value);
}

function addClassification(target: ShellClassification[], value: ShellClassification): void {
  if (!target.includes(value)) target.push(value);
}

function boundedDisplay(value: string): string {
  let escaped = "";
  for (const character of value) {
    switch (character) {
      case "\\": escaped += "\\\\"; break;
      case "\r": escaped += "\\r"; break;
      case "\n": escaped += "\\n"; break;
      case "\t": escaped += "\\t"; break;
      default: {
        const code = character.charCodeAt(0);
        escaped += code <= 0x1f || (code >= 0x7f && code <= 0x9f)
          ? `\\u${code.toString(16).padStart(4, "0")}`
          : character;
      }
    }
  }
  if (Buffer.byteLength(escaped) <= MAX_DISPLAY_BYTES) return escaped;
  let end = Math.min(escaped.length, MAX_DISPLAY_BYTES);
  while (end > 0 && Buffer.byteLength(escaped.slice(0, end)) > MAX_DISPLAY_BYTES - 16) end--;
  return `${escaped.slice(0, end)}...[truncated]`;
}

function containsUnsafeControl(value: string): boolean {
  for (const character of value) {
    const code = character.charCodeAt(0);
    if (code <= 0x08 || code === 0x0b || code === 0x0c ||
        (code >= 0x0e && code <= 0x1f) || (code >= 0x7f && code <= 0x9f)) {
      return true;
    }
  }
  return false;
}

function opaqueAnalysis(source: string, reasons: readonly string[]): ShellCommandAnalysis {
  const opaqueReasons: string[] = [];
  for (const reason of reasons) pushUnique(opaqueReasons, reason);
  return {
    version: 1,
    segments: [{
      index: 0,
      sourceStart: 0,
      sourceEnd: source.length,
      display: boundedDisplay(source),
      operatorBefore: "start",
      dependency: "none",
      executable: "unknown",
      wrappers: [],
      redirections: [],
      classifications: ["opaque"],
      opaqueReasons,
      riskFloor: "critical",
    }],
    riskFloor: "critical",
    opaqueReasons,
    canSafelySuggestIndependentSplit: false,
    splitReason: "The shell text is opaque and cannot be proposed as independent commands.",
  };
}

function relationFor(operator: ShellOperator): ShellDependency {
  switch (operator) {
    case "start": return "none";
    case "sequence": return "after-completion";
    case "and": return "on-success";
    case "or": return "on-failure";
    case "pipe": return "pipeline-input";
    case "background": return "concurrent";
  }
}

function lexShell(source: string): LexResult {
  const segments: LexSegment[] = [];
  const fatalReasons: string[] = [];
  let items: LexItem[] = [];
  let segmentReasons: string[] = [];
  let operatorBefore: ShellOperator = "start";
  let word: MutableWord | undefined;
  const contexts: LexContext[] = [{ kind: "root", quote: "none", depth: 0, terminator: "" }];

  const currentContext = (): LexContext => {
    const context = contexts.at(-1);
    if (context === undefined) throw new Error("shell lexer context stack is empty");
    return context;
  };
  const ensureWord = (index: number): MutableWord => {
    word ??= { value: "", start: index, end: index, opaqueReasons: [] };
    return word;
  };
  const append = (value: string, start: number, end: number): void => {
    const current = ensureWord(start);
    current.value += value;
    current.end = end;
  };
  const markWord = (reason: string, index: number): void => {
    const current = ensureWord(index);
    pushUnique(current.opaqueReasons, reason);
  };
  const pushItem = (item: LexItem): void => {
    if (items.length >= MAX_ITEMS_PER_SEGMENT) {
      pushUnique(fatalReasons, "token-limit-exceeded");
      return;
    }
    items.push(item);
  };
  const finishWord = (): void => {
    if (word === undefined) return;
    pushItem({
      kind: "word",
      value: word.value,
      start: word.start,
      end: word.end,
      opaqueReasons: [...word.opaqueReasons],
    });
    word = undefined;
  };
  const finishSegment = (nextOperator: ShellOperator, allowEmptySequence = false): void => {
    finishWord();
    let emitted = false;
    if (items.length > 0) {
      if (segments.length >= MAX_SEGMENTS) {
        pushUnique(fatalReasons, "segment-limit-exceeded");
        return;
      }
      const first = items[0];
      const last = items.at(-1);
      if (first === undefined || last === undefined) {
        pushUnique(fatalReasons, "empty-command-segment");
        return;
      }
      segments.push({
        items,
        sourceStart: first.start,
        sourceEnd: last.end,
        operatorBefore,
        opaqueReasons: segmentReasons,
      });
      emitted = true;
      items = [];
      segmentReasons = [];
    } else if (operatorBefore !== "start" && operatorBefore !== "sequence") {
      pushUnique(fatalReasons, "missing-control-operand");
    } else if (nextOperator !== "sequence") {
      pushUnique(fatalReasons, "empty-control-operand");
    } else if (!allowEmptySequence && segments.length === 0) {
      pushUnique(fatalReasons, "empty-command-segment");
    }
    if (emitted || segments.length > 0) operatorBefore = nextOperator;
  };
  const pushContext = (context: LexContext): boolean => {
    if (contexts.length >= MAX_NESTING) {
      pushUnique(fatalReasons, "nesting-limit-exceeded");
      return false;
    }
    contexts.push(context);
    return true;
  };

  for (let index = 0; index < source.length && fatalReasons.length === 0;) {
    const context = currentContext();
    const character = source.charAt(index);
    const next = source[index + 1] ?? "";

    if (context.quote === "single") {
      if (character === "'") {
        context.quote = "none";
        ensureWord(index).end = index + 1;
      } else {
        append(character, index, index + 1);
      }
      index++;
      continue;
    }
    if (context.quote === "double") {
      if (character === "\"") {
        context.quote = "none";
        ensureWord(index).end = index + 1;
        index++;
        continue;
      }
      if (character === "\\") {
        if (next === "") {
          markWord("dangling-escape", index);
          append(character, index, index + 1);
          index++;
          continue;
        }
        if (next === "\n") {
          ensureWord(index).end = index + 2;
        } else {
          append(next, index, index + 2);
        }
        index += 2;
        continue;
      }
      if (character === "`" ) {
        markWord("command-substitution", index);
        append(character, index, index + 1);
        let cursor = index + 1;
        let closed = false;
        for (; cursor < source.length; cursor++) {
          const nested = source.charAt(cursor);
          append(nested, cursor, cursor + 1);
          if (nested === "\\" && cursor + 1 < source.length) {
            cursor++;
            append(source.charAt(cursor), cursor, cursor + 1);
          } else if (nested === "`") {
            closed = true;
            cursor++;
            break;
          }
        }
        if (!closed) pushUnique(fatalReasons, "unterminated-backtick-substitution");
        index = cursor;
        continue;
      }
      if (character === "$" && next === "(" && source[index + 2] === "(") {
        return { segments: [], fatalReasons: ["arithmetic-expansion"] };
      }
      if (character === "$" && next === "[") {
        return { segments: [], fatalReasons: ["legacy-arithmetic-expansion"] };
      }
      if (character === "$" && next === "(") {
        markWord("command-substitution", index);
        append("$(", index, index + 2);
        if (!pushContext({ kind: "command-substitution", quote: "none", depth: 1, terminator: ")" })) break;
        index += 2;
        continue;
      }
      if (character === "$" && next === "{") {
        markWord("parameter-expansion", index);
        append("${", index, index + 2);
        if (!pushContext({ kind: "parameter-expansion", quote: "none", depth: 1, terminator: "}" })) break;
        index += 2;
        continue;
      }
      if (character === "$" && /[A-Za-z0-9_@*#?$!-]/u.test(next)) markWord("parameter-expansion", index);
      append(character, index, index + 1);
      index++;
      continue;
    }

    if (context.kind !== "root" && character === context.terminator) {
      append(character, index, index + 1);
      context.depth--;
      if (context.depth === 0) contexts.pop();
      index++;
      continue;
    }
    if (context.kind !== "root" && context.terminator === ")" && character === "(") {
      if (context.depth >= MAX_NESTING) {
        pushUnique(fatalReasons, "nesting-limit-exceeded");
        break;
      }
      context.depth++;
      append(character, index, index + 1);
      index++;
      continue;
    }
    if (context.kind !== "root" && context.terminator === "}" && character === "{" && source[index - 1] === "$") {
      if (context.depth >= MAX_NESTING) {
        pushUnique(fatalReasons, "nesting-limit-exceeded");
        break;
      }
      context.depth++;
      append(character, index, index + 1);
      index++;
      continue;
    }

    if (character === "$" && (next === "'" || next === "\"")) {
      markWord(next === "'" ? "ansi-c-quote" : "localized-quote", index);
      append(character, index, index + 1);
      index++;
      continue;
    }
    if (character === "'") {
      ensureWord(index).end = index + 1;
      context.quote = "single";
      index++;
      continue;
    }
    if (character === "\"") {
      ensureWord(index).end = index + 1;
      context.quote = "double";
      index++;
      continue;
    }
    if (character === "\\") {
      if (next === "") {
        markWord("dangling-escape", index);
        append(character, index, index + 1);
        index++;
        continue;
      }
      if (next === "\n") {
        ensureWord(index).end = index + 2;
      } else {
        append(next, index, index + 2);
      }
      index += 2;
      continue;
    }
    if (character === "`") {
      markWord("command-substitution", index);
      append(character, index, index + 1);
      let cursor = index + 1;
      let closed = false;
      for (; cursor < source.length; cursor++) {
        const nested = source.charAt(cursor);
        append(nested, cursor, cursor + 1);
        if (nested === "\\" && cursor + 1 < source.length) {
          cursor++;
          append(source.charAt(cursor), cursor, cursor + 1);
        } else if (nested === "`") {
          closed = true;
          cursor++;
          break;
        }
      }
      if (!closed) pushUnique(fatalReasons, "unterminated-backtick-substitution");
      index = cursor;
      continue;
    }
    if (character === "$" && next === "(" && source[index + 2] === "(") {
      return { segments: [], fatalReasons: ["arithmetic-expansion"] };
    }
    if (character === "$" && next === "[") {
      return { segments: [], fatalReasons: ["legacy-arithmetic-expansion"] };
    }
    if (character === "$" && next === "(") {
      markWord("command-substitution", index);
      append("$(", index, index + 2);
      if (!pushContext({ kind: "command-substitution", quote: "none", depth: 1, terminator: ")" })) break;
      index += 2;
      continue;
    }
    if (character === "$" && next === "{") {
      markWord("parameter-expansion", index);
      append("${", index, index + 2);
      if (!pushContext({ kind: "parameter-expansion", quote: "none", depth: 1, terminator: "}" })) break;
      index += 2;
      continue;
    }
    if ((character === "<" || character === ">") && next === "(" ) {
      markWord("process-substitution", index);
      append(`${character}(`, index, index + 2);
      if (!pushContext({ kind: "process-substitution", quote: "none", depth: 1, terminator: ")" })) break;
      index += 2;
      continue;
    }
    if (character === "(" && next === "(") return { segments: [], fatalReasons: ["arithmetic-command"] };
    if (character === "(" && contexts.length === 1) {
      markWord("subshell-group", index);
      append(character, index, index + 1);
      if (!pushContext({ kind: "subshell", quote: "none", depth: 1, terminator: ")" })) break;
      index++;
      continue;
    }
    if (character === ")" && contexts.length === 1) {
      return { segments: [], fatalReasons: ["unmatched-closing-parenthesis"] };
    }

    if (contexts.length > 1) {
      if (character === "$" && /[A-Za-z0-9_@*#?$!-]/u.test(next)) markWord("parameter-expansion", index);
      append(character, index, index + 1);
      index++;
      continue;
    }

    if (character === "#" && word === undefined) {
      while (index < source.length && source[index] !== "\n") index++;
      continue;
    }
    if (character === "[" && next === "[") return { segments: [], fatalReasons: ["compound-test-expression"] };
    if (character === "<" && next === "<") return { segments: [], fatalReasons: ["heredoc-or-here-string"] };

    if (character === "&" && next === ">") {
      finishWord();
      const length = source[index + 2] === ">" ? 3 : 2;
      pushItem({ kind: "redirection", value: source.slice(index, index + length), start: index, end: index + length });
      index += length;
      continue;
    }
    if (character === "<" || character === ">") {
      let descriptor = "";
      if (word !== undefined && /^\d+$/u.test(word.value) && word.end === index) {
        descriptor = word.value;
        const descriptorStart = word.start;
        if (index - word.start !== word.value.length) {
          pushUnique(segmentReasons, "quoted-or-escaped-io-number");
        }
        word = undefined;
        const pair = source.slice(index, index + 2);
        const operator = [">>", ">|", ">&", "<>", "<&"].includes(pair) ? pair : character;
        pushItem({
          kind: "redirection",
          value: descriptor + operator,
          start: descriptorStart,
          end: index + operator.length,
        });
        index += operator.length;
        continue;
      } else {
        finishWord();
      }
      const pair = source.slice(index, index + 2);
      const operator = [">>", ">|", ">&", "<>", "<&"].includes(pair) ? pair : character;
      pushItem({
        kind: "redirection",
        value: descriptor + operator,
        start: index,
        end: index + operator.length,
      });
      index += operator.length;
      continue;
    }

    const control = (() => {
      if (character === "&" && next === "&") return { length: 2, operator: "and" as const };
      if (character === "|" && next === "|") return { length: 2, operator: "or" as const };
      if (character === "|" && next === "&") return { length: 2, operator: "pipe" as const };
      if (character === "|") return { length: 1, operator: "pipe" as const };
      if (character === ";") return { length: 1, operator: "sequence" as const };
      if (character === "\n") return { length: 1, operator: "sequence" as const };
      if (character === "&") return { length: 1, operator: "background" as const };
      return undefined;
    })();
    if (control !== undefined) {
      if (character === ";" && next === ";") return { segments: [], fatalReasons: ["compound-control-operator"] };
      finishSegment(control.operator, character === "\n");
      index += control.length;
      continue;
    }

    if (/\s/u.test(character)) {
      finishWord();
      index++;
      continue;
    }
    if (character === "$" && /[A-Za-z0-9_@*#?$!-]/u.test(next)) markWord("parameter-expansion", index);
    if (character === "*" || character === "?") markWord("pathname-expansion", index);
    if (character === "[" || character === "]") markWord("pathname-or-test-bracket", index);
    if (character === "{" || character === "}") markWord("brace-expansion-or-group", index);
    if (character === "~" && word === undefined) markWord("tilde-expansion", index);
    append(character, index, index + 1);
    index++;
  }

  if (contexts.length !== 1) pushUnique(fatalReasons, `unterminated-${currentContext().kind}`);
  if (contexts[0]?.quote !== "none") pushUnique(fatalReasons, `unterminated-${contexts[0]?.quote ?? "quote"}-quote`);
  finishSegment("sequence", true);
  return { segments, fatalReasons };
}

function basename(value: string): string {
  const pieces = value.split("/");
  return pieces[pieces.length - 1] ?? value;
}

function staticOperands(arguments_: readonly string[]): readonly string[] | undefined {
  const operands: string[] = [];
  let optionsEnded = false;
  for (const argument of arguments_) {
    if (!optionsEnded && argument === "--") {
      optionsEnded = true;
      continue;
    }
    if (!optionsEnded && argument.startsWith("-") && argument !== "-") return undefined;
    operands.push(argument);
  }
  return operands;
}

function hasPrintfStateDirective(format: string): boolean {
  return /%(?:[1-9][0-9]*\$)?[-+# 0']*(?:[0-9]+|\*)?(?:\.(?:[0-9]+|\*))?n/u.test(format);
}

const SYSTEMCTL_READ_ONLY_ACTIONS = new Set([
  "cat", "get-default", "is-active", "is-enabled", "is-failed", "list-dependencies",
  "list-jobs", "list-unit-files", "list-units", "show", "show-environment", "status",
]);
const SYSTEMCTL_DESTRUCTIVE_ACTIONS = new Set([
  "cancel", "emergency", "freeze", "halt", "isolate", "kexec", "kill", "poweroff",
  "reboot", "reload", "reload-or-restart", "reload-or-try-restart", "rescue", "restart",
  "shutdown", "soft-reboot", "start", "stop", "thaw", "try-reload-or-restart",
  "try-restart",
]);
const SYSTEMCTL_FILESYSTEM_ACTIONS = new Set([
  "add-requires", "add-wants", "disable", "edit", "enable", "link", "mask", "preset",
  "preset-all", "reenable", "revert", "set-default", "set-property", "unmask",
]);
const SYSTEMCTL_READ_ONLY_FLAGS = new Set([
  "--all", "--failed", "--full", "--no-legend", "--no-pager", "--plain", "--quiet",
  "--system", "--user", "--value",
]);
const SYSTEMCTL_READ_ONLY_VALUE_FLAGS = [
  "--lines=", "--output=", "--property=", "--state=", "--timestamp=", "--type=",
];

function mergeClassification(base: CommandClassification, nested: CommandClassification): CommandClassification {
  for (const wrapper of nested.wrappers) pushUnique(base.wrappers, wrapper);
  for (const classification of nested.classifications) addClassification(base.classifications, classification);
  for (const reason of nested.opaqueReasons) pushUnique(base.opaqueReasons, reason);
  base.riskFloor = maxRisk(base.riskFloor, nested.riskFloor);
  if (nested.executable !== "unknown") base.executable = nested.executable;
  return base;
}

function classifyCommand(words: readonly string[], operatorBefore: ShellOperator, depth = 0): CommandClassification {
  const result: CommandClassification = {
    executable: "unknown",
    wrappers: [],
    classifications: [],
    opaqueReasons: [],
    riskFloor: "medium",
  };
  if (depth > 8) {
    addClassification(result.classifications, "opaque");
    pushUnique(result.opaqueReasons, "wrapper-depth-exceeded");
    result.riskFloor = "critical";
    return result;
  }
  let index = 0;
  while (index < words.length) {
    const candidate = words[index];
    if (candidate === undefined || !ASSIGNMENT.test(candidate)) break;
    index++;
  }
  const executableToken = words[index];
  if (executableToken === undefined || executableToken.length === 0) {
    addClassification(result.classifications, "opaque");
    pushUnique(result.opaqueReasons, "missing-executable");
    result.riskFloor = "critical";
    return result;
  }
  const executable = basename(executableToken);
  result.executable = executable;
  const arguments_ = words.slice(index + 1);

  const critical = (classification: ShellClassification, reason?: string): void => {
    addClassification(result.classifications, classification);
    if (reason !== undefined) {
      addClassification(result.classifications, "opaque");
      pushUnique(result.opaqueReasons, reason);
    }
    result.riskFloor = "critical";
  };
  const high = (classification: ShellClassification): void => {
    addClassification(result.classifications, classification);
    result.riskFloor = maxRisk(result.riskFloor, "high");
  };

  if (index > 0) critical("dynamic", "environment-assignment");

  if (["eval", "source", "."].includes(executable)) {
    critical("dynamic", "dynamic-shell-wrapper");
    return result;
  }
  if (["bash", "dash", "ksh", "sh", "zsh"].includes(executable)) {
    pushUnique(result.wrappers, executable);
    const commandIndex = arguments_.findIndex((argument) => /^-[A-Za-z]*c[A-Za-z]*$/u.test(argument));
    if (commandIndex >= 0) {
      critical("dynamic", "nested-shell-command-string");
    } else if (arguments_.length > 0) {
      critical("dynamic", "shell-script-file");
    } else if (operatorBefore === "pipe") {
      critical("dynamic", "shell-code-from-pipeline");
    } else {
      critical("dynamic", "interactive-or-stdin-shell");
    }
    return result;
  }
  if (/^(?:node|perl|python(?:\d+(?:\.\d+)*)?|ruby)$/u.test(executable)) {
    pushUnique(result.wrappers, executable);
    critical("dynamic", arguments_.some((argument) => ["-c", "-e", "-p", "--eval", "--print"].includes(argument))
      ? "interpreter-inline-code"
      : "interpreter-code-source");
    return result;
  }
  if (executable === "base64") {
    critical("dynamic", "encoded-payload-wrapper");
    return result;
  }
  if (executable === "xargs") {
    critical("dynamic", "stdin-derived-argv");
    return result;
  }
  if (executable === "find") {
    if (arguments_.some((argument) => ["-exec", "-execdir", "-ok", "-okdir"].includes(argument))) {
      critical("dynamic", "find-exec-wrapper");
      return result;
    }
    if (arguments_.includes("-delete")) {
      critical("destructive", "find-delete-action");
      return result;
    }
    if (arguments_.some((argument) => ["-fls", "-fprint", "-fprint0", "-fprintf"].includes(argument))) {
      critical("filesystem-write", "find-file-output-action");
      return result;
    }
    critical("opaque", "find-expression-not-proven-read-only");
    return result;
  }
  if (executable === "env") {
    pushUnique(result.wrappers, "env");
    critical("dynamic", "environment-wrapper");
    let nestedIndex = 0;
    while (nestedIndex < arguments_.length) {
      const argument = arguments_[nestedIndex];
      if (argument === undefined) break;
      if (argument === "--") {
        nestedIndex++;
        break;
      }
      if (ASSIGNMENT.test(argument) || argument === "-i" || argument === "--ignore-environment") {
        nestedIndex++;
        continue;
      }
      if (argument === "-u" || argument === "--unset") {
        nestedIndex += 2;
        continue;
      }
      if (argument.startsWith("--unset=") || !argument.startsWith("-")) break;
      critical("dynamic", "unsupported-env-option");
      return result;
    }
    if (nestedIndex >= arguments_.length) {
      critical("dynamic", "env-without-command");
      return result;
    }
    return mergeClassification(result, classifyCommand(arguments_.slice(nestedIndex), operatorBefore, depth + 1));
  }
  if (executable === "sudo") {
    pushUnique(result.wrappers, "sudo");
    critical("privilege-transition", "privilege-wrapper");
    const marker = arguments_.indexOf("--");
    if (marker >= 0 && marker + 1 < arguments_.length) {
      return mergeClassification(result, classifyCommand(arguments_.slice(marker + 1), operatorBefore, depth + 1));
    }
    return result;
  }
  if (["chroot", "nsenter", "runuser", "setpriv", "su"].includes(executable)) {
    critical("privilege-transition", "identity-or-namespace-wrapper");
    return result;
  }
  if (["cd", "export", "set", "shift", "trap", "umask", "unalias", "unset"].includes(executable)) {
    critical("dynamic", "stateful-shell-context");
    return result;
  }
  if (executable === "exec") {
    critical("dynamic", "process-replacement");
    return result;
  }
  if (["rm", "rmdir", "shred", "wipefs"].includes(executable) || executable.startsWith("mkfs")) {
    critical("destructive");
    return result;
  }
  if (["dd", "fdisk", "parted", "sfdisk"].includes(executable)) {
    critical("destructive", "raw-device-or-disk-tool");
    return result;
  }
  if (["halt", "poweroff", "reboot", "shutdown"].includes(executable)) {
    critical("destructive");
    return result;
  }
  if (["kill", "killall", "pkill"].includes(executable)) {
    critical("destructive");
    return result;
  }
  if (executable === "systemctl") {
    const positionals: string[] = [];
    let optionsEnded = false;
    for (const argument of arguments_) {
      if (!optionsEnded && argument === "--") {
        optionsEnded = true;
        continue;
      }
      if (!optionsEnded && argument.startsWith("-")) {
        if (SYSTEMCTL_READ_ONLY_FLAGS.has(argument)
          || SYSTEMCTL_READ_ONLY_VALUE_FLAGS.some((prefix) => argument.startsWith(prefix))) {
          continue;
        }
        critical("opaque", "unsupported-systemctl-option");
        return result;
      }
      positionals.push(argument);
    }
    const action = positionals[0];
    if (action === undefined || SYSTEMCTL_READ_ONLY_ACTIONS.has(action)) return result;
    if (SYSTEMCTL_DESTRUCTIVE_ACTIONS.has(action)) {
      critical("destructive", "systemctl-availability-or-state-change");
    } else if (SYSTEMCTL_FILESYSTEM_ACTIONS.has(action)) {
      critical("filesystem-write", "systemctl-filesystem-or-policy-change");
    } else {
      critical("opaque", "unsupported-or-mutating-systemctl-action");
    }
    return result;
  }
  if (["curl", "ftp", "nc", "ncat", "rsync", "scp", "sftp", "socat", "ssh", "wget"].includes(executable)) {
    high("network");
    return result;
  }
  if (["chmod", "chown", "chgrp", "cp", "install", "ln", "mkdir", "mv", "tee", "touch", "truncate"].includes(executable)) {
    high("filesystem-write");
    return result;
  }
  if (executable === "sed" && arguments_.some((argument) =>
    /^-[A-Za-z]*i/u.test(argument) || argument === "--in-place" || argument.startsWith("--in-place="))) {
    critical("filesystem-write", "sed-in-place-write");
    return result;
  }
  if (executable === "date") {
    if (arguments_.some((argument) => argument === "-s" || argument === "--set"
      || argument.startsWith("--set="))) {
      critical("destructive", "date-clock-set");
      return result;
    }
    const safe = arguments_.every((argument) => argument.startsWith("+") || [
      "-I", "-R", "-u", "--iso-8601", "--resolution", "--rfc-email", "--universal",
      "--utc",
    ].includes(argument) || argument.startsWith("--iso-8601=")
      || argument.startsWith("--rfc-3339="));
    if (!safe) critical("opaque", "unsupported-or-mutating-date-argument");
    return result;
  }
  if (executable === "printf") {
    const formatIndex = arguments_[0] === "--" ? 1 : 0;
    const format = arguments_[formatIndex];
    if (arguments_[0] === "-v" || arguments_[0]?.startsWith("-v") === true
      || (format !== undefined && hasPrintfStateDirective(format))) {
      critical("dynamic", "stateful-shell-printf");
    }
    return result;
  }
  if (executable === "sort") {
    if (arguments_.some((argument) => argument === "-o" || argument.startsWith("--output="))) {
      critical("filesystem-write", "sort-output-file");
      return result;
    }
    if (arguments_.some((argument) => argument === "--compress-program"
      || argument.startsWith("--compress-program="))) {
      critical("dynamic", "sort-compress-program");
      return result;
    }
    if (staticOperands(arguments_) === undefined) {
      critical("opaque", "unsupported-sort-option");
    }
    return result;
  }
  if (executable === "uniq") {
    const operands = staticOperands(arguments_);
    if (operands === undefined) {
      critical("opaque", "unsupported-uniq-option");
    } else if (operands.length > 1) {
      critical("filesystem-write", "uniq-output-file");
    }
    return result;
  }
  if (executable === "rg") {
    critical("dynamic", "ripgrep-config-or-preprocessor-not-proven-safe");
    return result;
  }
  if (["[", "echo", "false", "pwd", "test", "true"].includes(executable)) {
    return result;
  }
  if (["cat", "grep", "head", "id", "ls", "stat", "tail", "uname", "wc", "whoami"].includes(executable)) {
    if (staticOperands(arguments_) === undefined) {
      critical("opaque", `unsupported-${executable}-option`);
    }
    return result;
  }

  critical("opaque", "unclassified-executable");
  return result;
}

function analyzeLexSegment(source: string, segment: LexSegment, index: number): ShellSegmentAnalysis {
  const redirections: ShellRedirection[] = [];
  const words: string[] = [];
  const opaqueReasons = [...segment.opaqueReasons];
  let redirectionRisk: ApprovalRisk = "low";
  let hasNetworkRedirection = false;
  let hasFilesystemWriteRedirection = false;
  for (let itemIndex = 0; itemIndex < segment.items.length; itemIndex++) {
    const item = segment.items[itemIndex];
    if (item === undefined) break;
    if (item.kind === "word") {
      words.push(item.value);
      for (const reason of item.opaqueReasons) pushUnique(opaqueReasons, reason);
      continue;
    }
    const target = segment.items[itemIndex + 1];
    if (target?.kind === "word") {
      redirections.push({ operator: item.value, target: boundedDisplay(target.value) });
      for (const reason of target.opaqueReasons) pushUnique(opaqueReasons, reason);
      if (/^\/dev\/(?:tcp|udp)\//u.test(target.value)) {
        hasNetworkRedirection = true;
        pushUnique(opaqueReasons, "shell-network-redirection");
      }
      if (item.value.includes(">") && !item.value.includes(">&")) {
        hasFilesystemWriteRedirection = true;
      }
      itemIndex++;
    } else {
      redirections.push({ operator: item.value });
      pushUnique(opaqueReasons, "redirection-without-target");
    }
    redirectionRisk = maxRisk(redirectionRisk, item.value.includes(">") ? "high" : "medium");
  }
  const classification = classifyCommand(words, segment.operatorBefore);
  for (const reason of classification.opaqueReasons) pushUnique(opaqueReasons, reason);
  if (opaqueReasons.length > 0) addClassification(classification.classifications, "opaque");
  if (redirections.length > 0) addClassification(classification.classifications, "redirection");
  if (hasNetworkRedirection) addClassification(classification.classifications, "network");
  if (hasFilesystemWriteRedirection) {
    addClassification(classification.classifications, "filesystem-write");
  }
  const dependency = relationFor(segment.operatorBefore);
  const dependencyRisk: ApprovalRisk = dependency === "pipeline-input" || dependency === "concurrent" ? "high" : "low";
  const riskFloor = opaqueReasons.length > 0
    ? "critical"
    : maxRisk(classification.riskFloor, redirectionRisk, dependencyRisk);
  return {
    index,
    sourceStart: segment.sourceStart,
    sourceEnd: segment.sourceEnd,
    display: boundedDisplay(source.slice(segment.sourceStart, segment.sourceEnd)),
    operatorBefore: segment.operatorBefore,
    dependency,
    ...(index === 0 ? {} : { dependsOn: index - 1 }),
    executable: classification.executable,
    wrappers: classification.wrappers,
    redirections,
    classifications: classification.classifications,
    opaqueReasons,
    riskFloor,
  };
}

export function analyzeShellCommands(source: string): ShellCommandAnalysis {
  if (Buffer.byteLength(source) > MAX_SOURCE_BYTES) return opaqueAnalysis(source, ["source-size-limit-exceeded"]);
  if (containsUnsafeControl(source)) return opaqueAnalysis(source, ["unsafe-control-character"]);
  if (source.trim().length === 0) return opaqueAnalysis(source, ["empty-shell-text"]);
  const lexed = lexShell(source);
  if (lexed.fatalReasons.length > 0 || lexed.segments.length === 0) {
    return opaqueAnalysis(source, lexed.fatalReasons.length > 0 ? lexed.fatalReasons : ["no-command-segment"]);
  }
  const containsControlWord = lexed.segments.some((segment) => segment.items.some((item) =>
    item.kind === "word" && SHELL_CONTROL_WORDS.has(item.value)));
  if (containsControlWord) return opaqueAnalysis(source, ["shell-control-structure"]);

  const segments = lexed.segments.map((segment, index) => analyzeLexSegment(source, segment, index));
  const opaqueReasons: string[] = [];
  for (const segment of segments) {
    for (const reason of segment.opaqueReasons) pushUnique(opaqueReasons, reason);
  }
  const riskFloor = maxRisk(...segments.map((segment) => segment.riskFloor));
  const hasOnlyIndependentSeparators = segments.slice(1).every((segment) => segment.operatorBefore === "sequence");
  const hasCrossSegmentHazard = segments.some((segment) =>
    segment.opaqueReasons.length > 0 || segment.redirections.length > 0 ||
    segment.classifications.length > 0);
  const canSafelySuggestIndependentSplit = segments.length > 1 && hasOnlyIndependentSeparators && !hasCrossSegmentHazard;
  let splitReason = "The shell text contains one top-level command segment.";
  if (segments.length > 1) {
    if (canSafelySuggestIndependentSplit) {
      splitReason = "Top-level commands are separated only by sequence boundaries and every segment is a recognized read-only command; this is advisory and does not prove semantic independence.";
    } else if (!hasOnlyIndependentSeparators) {
      splitReason = "Pipeline, conditional, or background operators create dependencies between command segments.";
    } else {
      splitReason = "Opaque syntax, redirection, or shell-state behavior prevents an independent split suggestion.";
    }
  }
  return {
    version: 1,
    segments,
    riskFloor,
    opaqueReasons,
    canSafelySuggestIndependentSplit,
    splitReason,
  };
}
