import type { SessionRecord } from "./session-registry.js";

export const MAX_WORKSPACE_CONTEXT_BYTES = 4096;

export function trustedWorkspaceContext(record: SessionRecord): string {
  const content = JSON.stringify({
    version: 1,
    trust: "controller-generated",
    sessionId: record.sessionId,
    workspacePath: record.workspacePath,
    machineId: record.binding?.machineId ?? null,
    targetId: record.binding?.targetId ?? null,
    capabilityRevision: record.binding?.capabilityRevision ?? null,
    policyRevision: record.binding?.policyRevision ?? null,
  });
  if (Buffer.byteLength(content, "utf8") > MAX_WORKSPACE_CONTEXT_BYTES) {
    throw new Error("trusted workspace context exceeds its size limit");
  }
  return `[TRUSTED_WORKSPACE_CONTEXT_V1]\n${content}\n[/TRUSTED_WORKSPACE_CONTEXT_V1]`;
}

export function prependTrustedWorkspaceContext(
  systemPrompt: string,
  record: SessionRecord,
): string {
  return `${trustedWorkspaceContext(record)}\n\n${systemPrompt}`;
}
