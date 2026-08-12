import { spawn } from "node:child_process";
import { isAbsolute, normalize } from "node:path";
import type { ApprovalAction, ChangeRef } from "../shared/approval.js";
import { parseHelperResponse, type HelperResponse } from "../shared/messages.js";

const MAX_OUTPUT_BYTES = 1024 * 1024;
const MAX_RUNTIME_MS = 10 * 60_000;
export const MAX_APPROVAL_USER_INTENT_BYTES = 4096;

export interface ApprovalSubmission {
  action: ApprovalAction;
  changeRef: ChangeRef;
  userIntent: string;
}

export interface ApprovalSubmitter {
  submit(request: ApprovalSubmission): Promise<HelperResponse>;
}

export function approvalSubmitArguments(
  executable: string,
  request: ApprovalSubmission,
): string[] {
  const reference = request.changeRef;
  const userIntent = Buffer.from(request.userIntent, "utf8");
  if (userIntent.length < 1 || userIntent.length > MAX_APPROVAL_USER_INTENT_BYTES
    || userIntent.toString("utf8") !== request.userIntent
    || request.userIntent.trim().length === 0) {
    throw new Error(
      `approval user intent must be valid UTF-8 with 1 to ${MAX_APPROVAL_USER_INTENT_BYTES} bounded bytes`,
    );
  }
  return [
    "-k",
    "--",
    executable,
    "--action", request.action,
    "--server-id", reference.serverId,
    "--machine-id", reference.machineId,
    "--target-id", reference.targetId,
    "--change-id", reference.changeId,
    "--user-intent-b64", userIntent.toString("base64url"),
  ];
}

export class SudoApprovalSubmitter implements ApprovalSubmitter {
  readonly #executable: string;

  constructor(executable = "/opt/pi-ops-agent/current/bin/agentd-approval-submit") {
    if (!isAbsolute(executable) || normalize(executable) !== executable
      || executable.includes("\0") || executable.includes("\n")) {
      throw new Error("approval submit helper path must be absolute and normalized");
    }
    this.#executable = executable;
  }

  async submit(request: ApprovalSubmission): Promise<HelperResponse> {
    const arguments_ = approvalSubmitArguments(this.#executable, request);
    return await new Promise<HelperResponse>((resolve, reject) => {
      const child = spawn("/usr/bin/sudo", arguments_, {
        shell: false,
        stdio: ["inherit", "pipe", "inherit"],
      });
      const chunks: Buffer[] = [];
      let received = 0;
      let settled = false;
      const finish = (error?: Error, response?: HelperResponse): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (error) reject(error);
        else if (response === undefined) reject(new Error("approval submit helper returned no response"));
        else resolve(response);
      };
      const timer = setTimeout(() => {
        child.kill("SIGTERM");
        finish(new Error("approval submit helper timed out"));
      }, MAX_RUNTIME_MS);
      timer.unref();
      child.stdout.on("data", (chunk: Buffer | string) => {
        const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        received += bytes.length;
        if (received > MAX_OUTPUT_BYTES) {
          child.kill("SIGTERM");
          finish(new Error("approval submit helper output exceeds 1 MiB"));
          return;
        }
        chunks.push(bytes);
      });
      child.once("error", (error) => finish(error));
      child.once("close", (code, signal) => {
        if (settled) return;
        if (code !== 0) {
          finish(new Error(`approval submit helper failed (${signal ?? `exit ${String(code)}`})`));
          return;
        }
        try {
          const payload = Buffer.concat(chunks).toString("utf8").trim();
          finish(undefined, parseHelperResponse(JSON.parse(payload) as unknown));
        } catch {
          finish(new Error("approval submit helper returned invalid JSON"));
        }
      });
    });
  }
}
