import type { AgentConfig } from "../shared/config.js";
import type { Readable } from "node:stream";
import { userInfo } from "node:os";
import { parseSessionId } from "../shared/domain.js";
import type { AgentServerMessage } from "../shared/messages.js";
import { AGENT_CLIENT_PEER_API_VERSION } from "../shared/messages.js";
import { AgentConnection } from "./agent-connection.js";
import type { ClientArguments } from "./args.js";
import { ClientController } from "./controller.js";
import { eventSinkFromEnvironment } from "./events.js";
import { TerminalInputParser } from "./input.js";
import {
  adapterInputFromEnvironment,
  DeclaredAdapterInputParser,
} from "./adapter-channel.js";
import type { AdapterClientContext } from "../shared/adapter-runtime.js";
import { ServerRegistry } from "../agentd/server-registry.js";
import { ApprovalRouter } from "./approval-router.js";
import { SudoApprovalSubmitter } from "./approval-submitter.js";
import { UnixSocketApprovalReviewer } from "./reviewer-client.js";
import {
  acquireActiveRuntimeSourcePluginLease,
  loadActiveRuntimeSourcePlugin,
  loadActiveSourcePlugin,
} from "../shared/source-plugin.js";
import { requireClientAdapterContext } from "./adapter-authorization.js";
import { loadEnrolledLocalAdministrator } from "../shared/local-administrator.js";
import {
  initializeBotMux,
  parseLocalClientCommand,
  type InitializeBotMuxOptions,
} from "./botmux-setup.js";
import { releaseOuterTUIRuntimeLeaseForSelfUpdate } from "./adapter-self-update.js";

export interface RunClientOptions {
  arguments: ClientArguments;
  config: AgentConfig;
  adapterContext: AdapterClientContext;
  input?: Readable;
  output?: NodeJS.WriteStream;
  initializeBotMux?: (options: InitializeBotMuxOptions) => Promise<void>;
}

export async function runClient(options: RunClientOptions): Promise<void> {
  const externalAdapter = options.adapterContext.descriptor.runtimeAuthority.execution
    === "source-process";
  if (externalAdapter && options.arguments.initialPrompt !== undefined) {
    throw new Error("source Adapter initial prompts must arrive through the typed FD channel");
  }
  const input = options.input
    ?? (externalAdapter ? adapterInputFromEnvironment() : process.stdin);
  const output = options.output ?? process.stdout;
  const adapterId = process.env.OPS_AGENT_ADAPTER_ID;
  if (adapterId === undefined) {
    throw new Error("compiled client cannot run outside the digest-validating adapter runner");
  }
  const activeAdapter = await loadActiveRuntimeSourcePlugin(options.config, adapterId);
  const adapterLease = await acquireActiveRuntimeSourcePluginLease(options.config, {
    pluginId: activeAdapter.pluginId,
    digest: activeAdapter.digest,
  });
  let adapterLeaseFailure: Error | undefined;
  let stopForAdapterLeaseLoss = (): void => undefined;
  void adapterLease.lost.catch((error: unknown) => {
    adapterLeaseFailure = error instanceof Error
      ? error
      : new Error("compiled client lost its exact adapter digest lease");
    stopForAdapterLeaseLoss();
  });
  const requireAdapterLease = (): void => {
    if (adapterLeaseFailure !== undefined) throw adapterLeaseFailure;
  };
  try {
  const servers = new ServerRegistry(options.config.serverRegistryPath);
  await servers.initialize();
  requireAdapterLease();
  const eventSink = eventSinkFromEnvironment();
  const enrolledAdministrator = adapterId === "adapter.tui"
    ? await loadEnrolledLocalAdministrator()
    : undefined;
  requireAdapterLease();
  const inputIsTTY = "isTTY" in input && input.isTTY;
  const setInputRawMode = (enabled: boolean): void => {
    if ("setRawMode" in input && typeof input.setRawMode === "function") {
      input.setRawMode(enabled);
    }
  };
  const adapter = requireClientAdapterContext(activeAdapter, options.adapterContext, {
    environment: process.env,
    username: userInfo().username,
    effectiveUid: process.geteuid?.() ?? -1,
    ...(enrolledAdministrator === undefined ? {} : { enrolledAdministrator }),
    inputIsTTY,
    outputIsTTY: output.isTTY,
    hasExternalEventSink: eventSink !== undefined,
  });
  const controllerHolder: { value?: ClientController } = {};
  const bufferedMessages: AgentServerMessage[] = [];
  const { promise: closed, resolve: resolveClosed } = Promise.withResolvers<undefined>();
  let agentClosed = false;
  let stopped = false;
  let detachInputNow = (): void => { input.pause(); };
  let attachInputNow = (): void => { input.resume(); };
  const connection = await AgentConnection.connect(
    options.config.socketPath,
    {
      type: "hello",
      sessionId: parseSessionId(options.arguments.sessionId),
      peer: {
        apiVersion: AGENT_CLIENT_PEER_API_VERSION,
        adapterId: adapter.adapterId,
        digest: adapter.digest,
      },
    },
    {
      onMessage: (message) => {
        if (controllerHolder.value) controllerHolder.value.handleAgentMessage(message);
        else bufferedMessages.push(message);
      },
      onError: (error) => controllerHolder.value?.handleAgentError(error),
      onClose: () => {
        agentClosed = true;
        detachInputNow();
        resolveClosed(undefined);
      },
    },
  );
  if (adapterLeaseFailure !== undefined) {
    connection.close();
    throw adapterLeaseFailure;
  }
  let selfUpdateQuiesced = false;
  const approvalRouter = new ApprovalRouter(servers, {
    reviewer: new UnixSocketApprovalReviewer(options.config.reviewerSocket),
    submitter: new SudoApprovalSubmitter(options.config.approvalSubmitPath),
    sourcePluginLoader: async (pluginId) =>
      await loadActiveSourcePlugin(options.config, pluginId),
    sourcePluginLease: async (expected) =>
      await acquireActiveRuntimeSourcePluginLease(options.config, expected),
    ...(adapter.adapterId === "adapter.tui"
      ? {
          selfAdapterRuntime: {
            pluginId: adapter.adapterId,
            digest: adapter.digest,
            quiesceForUpdate: async () => {
              if (selfUpdateQuiesced) {
                throw new Error("adapter.tui self-update handoff was already consumed");
              }
              selfUpdateQuiesced = true;
              stopped = true;
              detachInputNow();
              setInputRawMode(false);
              connection.close();
              await closed;
              await adapterLease.release();
              await releaseOuterTUIRuntimeLeaseForSelfUpdate(adapter.digest);
            },
          },
        }
      : {}),
  });
  const controller = new ClientController({
    agent: connection,
    output,
    directCommandHandler: async (command, context) => {
      if (!adapter.canSubmitApproval && command.kind !== "status") {
        throw new Error("this adapter cannot authenticate approval; use the local TUI");
      }
      const usesLocalApprovalConsole = command.kind !== "status"
        && eventSink === undefined && inputIsTTY && output.isTTY;
      if (usesLocalApprovalConsole) {
        detachInputNow();
        setInputRawMode(false);
      }
      try {
        return await approvalRouter.execute(command, context);
      } finally {
        if (usesLocalApprovalConsole && !stopped && !agentClosed) attachInputNow();
      }
    },
    eventSink,
    localConsole: eventSink === undefined && inputIsTTY && output.isTTY,
  });
  controllerHolder.value = controller;
  if (options.arguments.initialPrompt !== undefined) {
    controller.submit(options.arguments.initialPrompt);
  }
  for (const message of bufferedMessages) controller.handleAgentMessage(message);

  const terminalParser = externalAdapter ? undefined : new TerminalInputParser();
  const adapterParser = externalAdapter
    ? new DeclaredAdapterInputParser(options.adapterContext.descriptor, options.arguments.sessionId)
    : undefined;
  const botmuxSetup = options.initializeBotMux ?? initializeBotMux;
  let localCommandQueue: Promise<void> = Promise.resolve();
  const wasRaw = inputIsTTY && "isRaw" in input ? input.isRaw : false;
  const attachInput = (): void => {
    if (agentClosed || stopped) return;
    input.on("data", onData);
    input.once("end", onEnd);
    if (inputIsTTY) setInputRawMode(true);
    input.resume();
  };
  const detachInput = (): void => {
    input.off("data", onData);
    input.off("end", onEnd);
    input.pause();
  };
  detachInputNow = detachInput;
  attachInputNow = attachInput;
  stopForAdapterLeaseLoss = () => {
    stopped = true;
    detachInputNow();
    connection.close();
  };
  requireAdapterLease();
  const runLocalCommand = (): void => {
    localCommandQueue = localCommandQueue.then(async () => {
      await controller.waitForDirectCommands();
      if (!controller.isIdle()) {
        throw new Error("finish the active agent turn before running /botmux-setup");
      }
      if (!inputIsTTY || !output.isTTY) {
        throw new Error("/botmux-setup requires an interactive TTY");
      }
      detachInput();
      setInputRawMode(false);
      try {
        await botmuxSetup({ input, output });
      } finally {
        if (!stopped) attachInput();
      }
    }).catch((error: unknown) => {
      output.write(`[botmux setup error] ${error instanceof Error ? error.message : String(error)}\n`);
      if (!stopped && inputIsTTY && !input.readableFlowing) attachInput();
    });
  };
  const dispatch = (events: ReturnType<TerminalInputParser["push"]>): void => {
    for (const event of events) {
      if (event.type === "submit") {
        try {
          const localCommand = parseLocalClientCommand(event.text);
          if (localCommand?.kind === "botmux-setup") runLocalCommand();
          else controller.submit(event.text);
        } catch (error) {
          output.write(`[input error] ${error instanceof Error ? error.message : String(error)}\n`);
        }
      }
      else if (event.type === "abort") controller.abort();
      else connection.close();
    }
  };
  const onData = (chunk: Buffer | string): void => {
    try {
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      if (adapterParser !== undefined) {
        for (const message of adapterParser.push(bytes)) controller.submit(message.text);
      } else if (terminalParser !== undefined) {
        dispatch(terminalParser.push(bytes));
      }
    } catch (error) {
      controller.handleAgentError(error instanceof Error ? error : new Error(String(error)));
      if (adapterParser !== undefined) connection.close();
    }
  };
  const onEnd = (): void => {
    try {
      if (adapterParser !== undefined) {
        for (const message of adapterParser.end()) controller.submit(message.text);
        connection.close();
      } else if (terminalParser !== undefined) {
        dispatch(terminalParser.end());
      }
    } catch (error) {
      controller.handleAgentError(error instanceof Error ? error : new Error(String(error)));
      connection.close();
    }
  };
  attachInput();

  try {
    await closed;
    requireAdapterLease();
  } finally {
    stopped = true;
    detachInput();
    await localCommandQueue;
    if (inputIsTTY) setInputRawMode(wasRaw);
    if (output.isTTY) output.write("\n");
    await controller.waitForDirectCommands();
    await controller.waitForEvents();
  }
  } finally {
    await adapterLease.release();
  }
}
