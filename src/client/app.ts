import type { AgentConfig } from "../shared/config.js";
import type { AgentServerMessage } from "../shared/messages.js";
import { AgentConnection } from "./agent-connection.js";
import type { ClientArguments } from "./args.js";
import { ClientController } from "./controller.js";
import { eventSinkFromEnvironment } from "./events.js";
import { TerminalInputParser } from "./input.js";

export interface RunClientOptions {
  arguments: ClientArguments;
  config: AgentConfig;
  input?: NodeJS.ReadStream;
  output?: NodeJS.WriteStream;
}

export async function runClient(options: RunClientOptions): Promise<void> {
  const input = options.input ?? process.stdin;
  const output = options.output ?? process.stdout;
  const controllerHolder: { value?: ClientController } = {};
  const bufferedMessages: AgentServerMessage[] = [];
  const { promise: closed, resolve: resolveClosed } = Promise.withResolvers<undefined>();
  const connection = await AgentConnection.connect(
    options.config.socketPath,
    {
      type: "hello",
      sessionId: options.arguments.sessionId,
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
    eventSink: eventSinkFromEnvironment(),
  });
  controllerHolder.value = controller;
  if (options.arguments.initialPrompt !== undefined) {
    controller.submit(options.arguments.initialPrompt);
  }
  for (const message of bufferedMessages) controller.handleAgentMessage(message);

  const parser = new TerminalInputParser();
  const dispatch = (events: ReturnType<TerminalInputParser["push"]>): void => {
    for (const event of events) {
      if (event.type === "submit") controller.submit(event.text);
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
  input.on("data", onData);
  input.once("end", onEnd);

  const wasRaw = input.isTTY ? input.isRaw : false;
  if (input.isTTY) input.setRawMode(true);
  input.resume();

  try {
    await closed;
  } finally {
    input.off("data", onData);
    input.off("end", onEnd);
    if (input.isTTY) input.setRawMode(wasRaw);
    if (output.isTTY) output.write("\n");
    await controller.waitForDirectCommands();
    await controller.waitForEvents();
  }
}
