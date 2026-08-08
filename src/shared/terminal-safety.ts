const SAFE_MESSAGE_WHITESPACE = new Set([0x09, 0x0a, 0x0d]);

/**
 * Controls that may alter terminal presentation, text direction, framing, or
 * audit readability. Message contracts may opt in only to TAB/LF/CR.
 */
export function isForbiddenTextControl(
  codePoint: number,
  allowMessageWhitespace = false,
): boolean {
  if (allowMessageWhitespace && SAFE_MESSAGE_WHITESPACE.has(codePoint)) return false;
  return codePoint < 0x20
    || (codePoint >= 0x7f && codePoint <= 0x9f)
    || codePoint === 0x061c
    || codePoint === 0x200e
    || codePoint === 0x200f
    || (codePoint >= 0x2028 && codePoint <= 0x202e)
    || (codePoint >= 0x2066 && codePoint <= 0x2069)
    || codePoint === 0xfeff;
}

export function hasForbiddenTextControl(
  value: string,
  allowMessageWhitespace = false,
): boolean {
  return Array.from(value).some((character) =>
    isForbiddenTextControl(character.codePointAt(0) ?? 0, allowMessageWhitespace));
}

function escapedControl(codePoint: number): string {
  return codePoint <= 0xff
    ? `\\x${codePoint.toString(16).padStart(2, "0")}`
    : `\\u{${codePoint.toString(16)}}`;
}

/** Escape untrusted diagnostics without preserving terminal or bidi controls. */
export function escapeUntrustedTerminalText(value: string, maximumBytes = 8 * 1024): string {
  let escaped = "";
  let bytes = 0;
  for (const character of value) {
    const codePoint = character.codePointAt(0) ?? 0;
    const safe = character === "\n"
      ? character
      : isForbiddenTextControl(codePoint)
        ? escapedControl(codePoint)
        : character;
    const safeBytes = Buffer.byteLength(safe, "utf8");
    if (bytes + safeBytes > maximumBytes) break;
    escaped += safe;
    bytes += safeBytes;
  }
  return escaped;
}

export function terminalSafeTextFromBytes(value: Buffer, maximumBytes = 2 * 1024): string {
  const bounded = value.subarray(0, maximumBytes);
  return escapeUntrustedTerminalText(bounded.toString("utf8"), maximumBytes).trim();
}
