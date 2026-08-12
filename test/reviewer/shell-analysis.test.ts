import { describe, expect, it } from "vitest";
import { analyzeShellCommands } from "../../src/reviewer/shell-analysis.js";

describe("conservative shell command analysis", () => {
  it.each([
    ["printf '%s' 'a;b'", "printf"],
    [String.raw`printf a\;b`, "printf"],
    ["printf '%s\\n' 'a && b || c | d'", "printf"],
  ])("does not split quoted or escaped separators in %s", (script, executable) => {
    const analysis = analyzeShellCommands(script);
    expect(analysis.segments).toHaveLength(1);
    expect(analysis.segments[0]?.executable).toBe(executable);
    expect(analysis.opaqueReasons).toEqual([]);
  });

  it("returns ordered top-level segments and exact source offsets", () => {
    const script = "true\nuname -a\nrm -rf /danger";
    const analysis = analyzeShellCommands(script);
    expect(analysis.segments.map((segment) => ({
      text: script.slice(segment.sourceStart, segment.sourceEnd),
      operator: segment.operatorBefore,
      dependency: segment.dependency,
    }))).toEqual([
      { text: "true", operator: "start", dependency: "none" },
      { text: "uname -a", operator: "sequence", dependency: "after-completion" },
      { text: "rm -rf /danger", operator: "sequence", dependency: "after-completion" },
    ]);
    expect(analysis.segments[2]?.classifications).toContain("destructive");
    expect(analysis.riskFloor).toBe("critical");
    expect(analysis.canSafelySuggestIndependentSplit).toBe(false);
  });

  it.each([
    ["true && rm -rf /danger", "and", "on-success"],
    ["false || shutdown -h now", "or", "on-failure"],
    ["printf x | sh", "pipe", "pipeline-input"],
    ["sleep 1 & touch /tmp/example", "background", "concurrent"],
  ] as const)("preserves dependency operators in %s", (script, operator, dependency) => {
    const analysis = analyzeShellCommands(script);
    expect(analysis.segments).toHaveLength(2);
    expect(analysis.segments[1]).toMatchObject({ operatorBefore: operator, dependency });
    expect(analysis.canSafelySuggestIndependentSplit).toBe(false);
    expect(analysis.riskFloor).toBe("critical");
  });

  it.each([
    ["bash -c 'rm -rf /danger'", "nested-shell-command-string"],
    ["python3 -c 'import os; os.remove(\"/tmp/x\")'", "interpreter-inline-code"],
    ["perl -e 'unlink q{/tmp/x}'", "interpreter-inline-code"],
    ["printf payload | base64 -d", "encoded-payload-wrapper"],
    ["printf x | xargs rm", "stdin-derived-argv"],
    ["find /tmp -type f -exec rm -- {} +", "find-exec-wrapper"],
    ["eval 'true'", "dynamic-shell-wrapper"],
    ["source /tmp/repair.sh", "dynamic-shell-wrapper"],
  ])("never lowers opaque wrapper risk for %s", (script, reason) => {
    const analysis = analyzeShellCommands(script);
    expect(analysis.riskFloor).toBe("critical");
    expect(analysis.segments.some((segment) => segment.opaqueReasons.includes(reason))).toBe(true);
    expect(analysis.canSafelySuggestIndependentSplit).toBe(false);
  });

  it.each([
    ["echo $(rm -rf /danger)", "command-substitution", "critical"],
    ["cat <<EOF\nsecret\nEOF", "heredoc-or-here-string", "critical"],
    ["if true; then rm -rf /danger; fi", "shell-control-structure", "critical"],
    ["printf x > /etc/example", "", "high"],
    ["printf '\u0001'", "unsafe-control-character", "critical"],
  ] as const)("fails closed for hard-to-prove shell text in %s", (
    script,
    expectedReason,
    expectedRisk,
  ) => {
    const analysis = analyzeShellCommands(script);
    expect(analysis.riskFloor).toBe(expectedRisk);
    if (expectedReason !== "") {
      expect([
        ...analysis.opaqueReasons,
        ...analysis.segments.flatMap((segment) => segment.opaqueReasons),
      ]).toContain(expectedReason);
    } else {
      expect(analysis.segments[0]?.classifications).toContain("redirection");
    }
  });

  it("only suggests an advisory split for recognized read-only sequence segments", () => {
    const analysis = analyzeShellCommands("true; uname; id");
    expect(analysis.canSafelySuggestIndependentSplit).toBe(true);
    expect(analysis.splitReason).toContain("advisory");
    expect(analysis.splitReason).toContain("does not prove semantic independence");
  });

  it("bounds display text and treats oversized input as opaque", () => {
    const bounded = analyzeShellCommands(`echo ${"x".repeat(4096)}`);
    expect(Buffer.byteLength(bounded.segments[0]?.display ?? "")).toBeLessThanOrEqual(512);
    expect(bounded.segments[0]?.display).toContain("[truncated]");

    const oversized = analyzeShellCommands(`echo ${"x".repeat(128 * 1024)}`);
    expect(oversized.riskFloor).toBe("critical");
    expect(oversized.opaqueReasons).toContain("source-size-limit-exceeded");
  });

  it.each([
    ["date -s @0; true", "date-clock-set"],
    ["sort -o /etc/shadow /tmp/in; true", "sort-output-file"],
    ["sort --compress-program=sh /tmp/in; true", "sort-compress-program"],
    ["uniq /tmp/in /etc/shadow; true", "uniq-output-file"],
    ["printf -v PATH /tmp; true", "stateful-shell-printf"],
    ["printf %n PATH; true", "stateful-shell-printf"],
    ["find /tmp -fprintf /etc/shadow x; true", "find-file-output-action"],
    ["systemctl isolate rescue.target; true", "systemctl-availability-or-state-change"],
    ["systemctl --machine guest stop demo; true", "unsupported-systemctl-option"],
    ["systemctl $'stop' demo; true", "ansi-c-quote"],
    ["PATH=/untrusted true; true", "environment-assignment"],
    ["env LD_PRELOAD=/tmp/x.so true; true", "environment-wrapper"],
    ["rg --pre sh pattern; true", "ripgrep-config-or-preprocessor-not-proven-safe"],
    ["cat </dev/tcp/example.com/443; true", "shell-network-redirection"],
  ])("never calls a stateful or argv-opaque sequence independently splittable: %s", (
    script,
    reason,
  ) => {
    const analysis = analyzeShellCommands(script);
    expect(analysis.riskFloor).toBe("critical");
    expect(analysis.canSafelySuggestIndependentSplit).toBe(false);
    expect(analysis.segments.flatMap((segment) => segment.opaqueReasons)).toContain(reason);
  });

  it.each([
    ["echo $[1 + 1]", "legacy-arithmetic-expansion"],
    ["echo \"$[1 + 1]\"", "legacy-arithmetic-expansion"],
    ["echo {one,two}", "brace-expansion-or-group"],
    ["echo file[0-9]", "pathname-or-test-bracket"],
  ])("marks additional shell expansion syntax opaque: %s", (script, reason) => {
    const analysis = analyzeShellCommands(script);
    expect(analysis.riskFloor).toBe("critical");
    expect([
      ...analysis.opaqueReasons,
      ...analysis.segments.flatMap((segment) => segment.opaqueReasons),
    ]).toContain(reason);
  });

  it("bounds redirection tokens before constructing an unbounded result", () => {
    const analysis = analyzeShellCommands(">".repeat(1026));
    expect(analysis.riskFloor).toBe("critical");
    expect(analysis.opaqueReasons).toContain("token-limit-exceeded");
    expect(analysis.segments[0]?.redirections).toEqual([]);
  });

  it("uses raw source positions for escaped numeric redirection candidates", () => {
    const script = String.raw`2\0>/tmp/x echo ok`;
    const analysis = analyzeShellCommands(script);
    expect(analysis.segments).toHaveLength(1);
    expect(analysis.segments[0]).toMatchObject({ sourceStart: 0, sourceEnd: script.length });
    expect(analysis.riskFloor).toBe("critical");
    expect(analysis.segments[0]?.opaqueReasons).toContain("quoted-or-escaped-io-number");
    expect(script.slice(
      analysis.segments[0]?.sourceStart,
      analysis.segments[0]?.sourceEnd,
    )).toBe(script);
  });

  it("keeps Unicode, CRLF, and comments aligned to exact source slices", () => {
    const script = "printf '%s' '雪;&&|'\r\n# ignored; rm -rf /\r\nrm -rf /danger";
    const analysis = analyzeShellCommands(script);
    expect(analysis.segments.map((segment) =>
      script.slice(segment.sourceStart, segment.sourceEnd))).toEqual([
      "printf '%s' '雪;&&|'",
      "rm -rf /danger",
    ]);
    expect(analysis.segments[1]).toMatchObject({
      operatorBefore: "sequence",
      dependency: "after-completion",
      riskFloor: "critical",
    });
  });

  it("keeps the first command independent of leading blank lines and comments", () => {
    const analysis = analyzeShellCommands("\r\n# context only\r\ntrue");
    expect(analysis.segments).toHaveLength(1);
    expect(analysis.segments[0]).toMatchObject({
      operatorBefore: "start",
      dependency: "none",
      display: "true",
    });
    const invalidLeadingSeparator = analyzeShellCommands("; true");
    expect(invalidLeadingSeparator.riskFloor).toBe("critical");
    expect(invalidLeadingSeparator.opaqueReasons).toContain("empty-command-segment");
  });
});
