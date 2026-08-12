import { describe, expect, it } from "vitest";
import { workloadStdoutWriteSucceeded } from "../../src/runtime/workload-host.js";

describe("workload host stdout framing", () => {
  it("accepts both successful Node writable callback shapes", () => {
    expect(workloadStdoutWriteSucceeded(undefined)).toBe(true);
    expect(workloadStdoutWriteSucceeded(null)).toBe(true);
    expect(workloadStdoutWriteSucceeded(new Error("pipe failed"))).toBe(false);
  });
});
