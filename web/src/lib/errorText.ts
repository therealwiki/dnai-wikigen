const INVISIBLE_OR_DIRECTIONAL_CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u061c\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]/gu;
const LONE_SURROGATE = /[\ud800-\udfff]/gu;

/**
 * Turn an untrusted service/provider error into one bounded, visually honest
 * line. Solid escapes markup, while this additionally removes terminal,
 * zero-width, and bidi controls that can spoof surrounding interface text.
 */
export function publicErrorText(value: unknown, fallback: string, maximum = 240): string {
  if (!Number.isInteger(maximum) || maximum < 1 || maximum > 1_024) return fallback;
  const normalized = String(value ?? "")
    .replace(INVISIBLE_OR_DIRECTIONAL_CONTROL, "")
    .replace(LONE_SURROGATE, "")
    .replace(/\s+/gu, " ")
    .trim();
  if (!normalized) return fallback;
  return Array.from(normalized).slice(0, maximum).join("");
}
