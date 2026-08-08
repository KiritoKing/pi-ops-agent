import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { UnixSocketApprovalReviewer } from "../../src/client/reviewer-client.js";
import { listenApprovalReviewer } from "../../src/reviewer/server.js";
import { buildApprovalPlan } from "../../src/shared/approval-review.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map(async (directory) =>
    await rm(directory, { recursive: true, force: true })));
});

describe("isolated approval reviewer protocol", () => {
  it("reviews exactly the framed canonical plan over a Unix socket", async () => {
    const directory = await mkdtemp(join(tmpdir(), "ops-reviewer-"));
    temporaryDirectories.push(directory);
    const socketPath = join(directory, "reviewer.sock");
    const server = await listenApprovalReviewer(socketPath);
    try {
      const plan = buildApprovalPlan({
        operation: {
          kind: "service.action",
          pluginId: "workload.base",
          pluginDigest: `sha256:${"d".repeat(64)}`,
          unit: "demo.service",
          action: "restart",
        },
        policyRevision: "policy-test",
        capabilityRevision: "capability-test",
      });
      const review = await new UnixSocketApprovalReviewer(socketPath, 2_000).review({
        version: 1,
        reviewId: "review-12345678",
        userIntent: "restart the demo service",
        plan,
      });
      expect(review).toMatchObject({
        planHash: plan.planHash,
        canAuthorize: false,
        recommendation: "manual-review",
      });
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => {
        if (error) reject(error);
        else resolve();
      }));
    }
  });
});
