export const workload = Object.freeze({
  apiVersion: "agentd.workload/v1",
  tools: Object.freeze([
    Object.freeze({
      name: "ops_demo_echo",
      label: "Echo from editable workload source",
      description: "Return bounded text formatted entirely by this approved source snapshot.",
      capability: "demo.echo",
      parameters: Object.freeze({
        type: "object",
        properties: Object.freeze({
          message: Object.freeze({ type: "string", minLength: 1, maxLength: 4096 }),
          style: Object.freeze({ type: "string", enum: Object.freeze(["plain", "upper"]) }),
        }),
        required: Object.freeze(["message"]),
        additionalProperties: false,
      }),
      providers: Object.freeze([]),
      executionMode: "parallel",
    }),
  ]),
  invoke(request) {
    if (request.tool !== "ops_demo_echo") throw new Error("workload.example received an unknown tool");
    const message = request.input.style === "upper"
      ? request.input.message.toUpperCase()
      : request.input.message;
    return Object.freeze({
      content: Object.freeze([{ type: "text", text: `[workload.example] ${message}` }]),
      details: Object.freeze({ sourceDefined: true }),
    });
  },
});
