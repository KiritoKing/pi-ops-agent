import { createReadStream, createWriteStream } from "node:fs";
import {
  ADAPTER_RUNNER_CONTROL_API_VERSION,
  ADAPTER_RUNNER_CONTROL_REQUEST_FD,
  ADAPTER_RUNNER_CONTROL_RESPONSE_FD,
  parseAdapterRunnerControlResponse,
} from "../shared/adapter-runtime.js";
import { encodeFrame, FrameDecoder } from "../shared/framing.js";

const HANDOFF_TIMEOUT_MILLISECONDS = 10_000;

function requireFixedDescriptor(environment: NodeJS.ProcessEnv, name: string, expected: number): number {
  if (environment[name] !== String(expected)) {
    throw new Error(`${name} must be the fixed descriptor ${expected}`);
  }
  return expected;
}

export async function releaseOuterTUIRuntimeLeaseForSelfUpdate(
  digest: string,
  environment: NodeJS.ProcessEnv = process.env,
): Promise<void> {
  if (!/^sha256:[a-f0-9]{64}$/u.test(digest)) {
    throw new Error("TUI self-update handoff requires the exact running Adapter digest");
  }
  const requestFD = requireFixedDescriptor(
    environment,
    "OPS_AGENT_ADAPTER_RUNNER_CONTROL_REQUEST_FD",
    ADAPTER_RUNNER_CONTROL_REQUEST_FD,
  );
  const responseFD = requireFixedDescriptor(
    environment,
    "OPS_AGENT_ADAPTER_RUNNER_CONTROL_RESPONSE_FD",
    ADAPTER_RUNNER_CONTROL_RESPONSE_FD,
  );
  const input = createReadStream("", { fd: responseFD, autoClose: false });
  const output = createWriteStream("", { fd: requestFD, autoClose: false });
  const decoder = new FrameDecoder(16 * 1024);
  await new Promise<void>((resolve, reject) => {
    let settled = false;
    const finish = (error?: Error): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      input.destroy();
      output.destroy();
      if (error === undefined) resolve();
      else reject(error);
    };
    const timer = setTimeout(() => {
      finish(new Error("Adapter runner TUI self-update handoff timed out"));
    }, HANDOFF_TIMEOUT_MILLISECONDS);
    timer.unref();
    input.on("data", (chunk: Buffer) => {
      try {
        const frames = decoder.push(chunk);
        if (frames.length !== 1) {
          if (frames.length === 0) return;
          throw new Error("Adapter runner returned multiple self-update handoff responses");
        }
        const response = parseAdapterRunnerControlResponse(frames[0]);
        if (!response.ok) throw new Error(response.error ?? "Adapter runner refused the handoff");
        finish();
      } catch (error) {
        finish(error instanceof Error ? error : new Error("Adapter runner handoff failed"));
      }
    });
    input.once("error", (error) => finish(error));
    input.once("close", () => finish(new Error("Adapter runner closed before the handoff response")));
    output.once("error", (error) => finish(error));
    output.end(encodeFrame({
      apiVersion: ADAPTER_RUNNER_CONTROL_API_VERSION,
      action: "release-tui-self-update-lease",
      pluginId: "adapter.tui",
      digest,
    }));
  });
}
