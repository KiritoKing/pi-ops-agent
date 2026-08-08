export type BotMuxSenderType = "user" | "bot";

export interface UnwrappedBotMuxInput {
  text: string;
  senderType?: BotMuxSenderType;
  unwrapped: boolean;
}

const BOTMUX_PREFIX_MARKER = /<(?:botmux_[a-z_]+|session_id|identity|role|whiteboard|chat_context)(?:\s|>)/u;
const USER_MESSAGE_OPEN = /(?:^|\r?\n)<user_message>\r?\n/gu;
const USER_MESSAGE_CLOSE = /\r?\n<\/user_message>(?=\r?\n|$)/gu;
const SENDER_TAG = /<sender\s+[^>]*\btype=(?:"(user|bot)"|'(user|bot)')[^>]*\/\s*>/gu;

function firstMatch(expression: RegExp, value: string): RegExpExecArray | undefined {
  expression.lastIndex = 0;
  return expression.exec(value) ?? undefined;
}

function lastMatch(expression: RegExp, value: string): RegExpExecArray | undefined {
  expression.lastIndex = 0;
  let result: RegExpExecArray | undefined;
  for (let match = expression.exec(value); match !== null; match = expression.exec(value)) {
    result = match;
  }
  return result;
}

/**
 * Remove BotMux's model-facing metadata envelope at the client boundary.
 *
 * BotMux currently leaves user text unescaped inside `<user_message>`. Using
 * the first opening delimiter and the final closing delimiter preserves text
 * that itself contains tag-like lines instead of letting it truncate or split
 * the user's message. Ordinary text is returned unchanged unless the complete
 * wrapper and an independent BotMux prefix marker are both present.
 */
export function unwrapBotMuxInput(value: string): UnwrappedBotMuxInput {
  const opening = firstMatch(USER_MESSAGE_OPEN, value);
  const closing = lastMatch(USER_MESSAGE_CLOSE, value);
  if (!opening || !closing) return { text: value, unwrapped: false };

  const contentStart = opening.index + opening[0].length;
  if (closing.index < contentStart) return { text: value, unwrapped: false };
  const prefix = value.slice(0, opening.index);
  if (!BOTMUX_PREFIX_MARKER.test(prefix)) return { text: value, unwrapped: false };

  const suffix = value.slice(closing.index + closing[0].length);
  const sender = lastMatch(SENDER_TAG, suffix);
  const rawSenderType = sender?.[1] ?? sender?.[2];
  const senderType: BotMuxSenderType | undefined =
    rawSenderType === "user" || rawSenderType === "bot" ? rawSenderType : undefined;
  return {
    text: value.slice(contentStart, closing.index),
    ...(senderType === undefined ? {} : { senderType }),
    unwrapped: true,
  };
}
