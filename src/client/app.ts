import type { AgentConfig } from "../shared/config.js";
import { parseSessionId } from "../shared/domain.js";
import type { AgentServerMessage } from "../shared/messages.js";
import { AgentConnection } from "./agent-connection.js";
import type { ClientArguments } from "./args.js";
import { ClientController } from "./controller.js";
import { eventSinkFromEnvironment } from "./events.js";
import { TerminalInputParser } from "./input.js";
import { ServerRegistry } from "../agentd/server-registry.js";
import { ApprovalRouter } from "./approval-router.js";
import {
  initializeBotMux,
  parseLocalClientCommand,
  type InitializeBotMuxOptions,
} from "./botmux-setup.js";

export interface RunClientOptions {
  arguments: ClientArguments;
  config: AgentConfig;
  input?: NodeJS.ReadStream;
  output?: NodeJS.WriteStream;
  initializeBotMux?: (options: InitializeBotMuxOptions) => Promise<void>;
}

export async function runClient(options: RunClientOptions): Promise<void> {
  const input = options.input ?? process.stdin;
  const output = options.output ?? process.stdout;
  const servers = new ServerRegistry(options.config.serverRegistryPath);
  await servers.initialize();
  const approvalRouter = new ApprovalRouter(servers);
  const controllerHolder: { value?: ClientController } = {};
  const bufferedMessages: AgentServerMessage[] = [];
  const { promise: closed, resolve: resolveClosed } = Promise.withResolvers<undefined>();
  const connection = await AgentConnection.connect(
    options.config.socketPath,
    {
      type: "hello",
      sessionId: parseSessionId(options.arguments.sessionId),
    },
    {
      onMessage: (message) => {
        if (controllerHolder.value) controllerHolder.value.handleAgentMessage(message);
        else bufferedMessages.push(message);
      },
      onError: (error) => controllerHolder.value?.handleAgentError(error),
      onClose: () => resolveClosed(undefined),
    },
  );
  const controller = new ClientController({
    agent: connection,
    rootHelperSocket: options.config.rootHelperSocket,
    output,
    directCommandHandler: async (command) => await approvalRouter.execute(command),
    eventSink: eventSinkFromEnvironment(),
  });
  controllerHolder.value = controller;
  if (options.arguments.initialPrompt !== undefined) {
    controller.submit(options.arguments.initialPrompt);
  }
  for (const message of bufferedMessages) controller.handleAgentMessage(message);

  const parser = new TerminalInputParser();
  const botmuxSetup = options.initializeBotMux ?? initializeBotMux;
  let stopped = false;
  let localCommandQueue: Promise<void> = Promise.resolve();
  const wasRaw = input.isTTY ? input.isRaw : false;
  const attachInput = (): void => {
    input.on("data", onData);
    input.once("end", onEnd);
    if (input.isTTY) input.setRawMode(true);
    input.resume();
  };
  const detachInput = (): void => {
    input.off("data", onData);
    input.off("end", onEnd);
    input.pause();
  };
  const runLocalCommand = (): void => {
    localCommandQueue = localCommandQueue.then(async () => {
      await controller.waitForDirectCommands();
      if (!controller.isIdle()) {
        throw new Error("finish the active agent turn before running /botmux-setup");
      }
      if (!input.isTTY || !output.isTTY) {
        throw new Error("/botmux-setup requires an interactive TTY");
      }
      detachInput();
      input.setRawMode(false);
      try {
        await botmuxSetup({ input, output });
      } finally {
        if (!stopped) attachInput();
      }
    }).catch((error: unknown) => {
      output.write(`[botmux setup error] ${error instanceof Error ? error.message : String(error)}\n`);
      if (!stopped && input.isTTY && !input.readableFlowing) attachInput();
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
      dispatch(parser.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
    } catch (error) {
      controller.handleAgentError(error instanceof Error ? error : new Error(String(error)));
    }
  };
  const onEnd = (): void => dispatch(parser.end());
  attachInput();

  try {
    await closed;
  } finally {
    stopped = true;
    detachInput();
    await localCommandQueue;
    if (input.isTTY) input.setRawMode(wasRaw);
    if (output.isTTY) output.write("\n");
    await controller.waitForDirectCommands();
    await controller.waitForEvents();
  }
}
