import { describe, expect, it } from "vitest";
import { publicErrorText } from "./errorText";

describe("publicErrorText", () => {
  it("flattens whitespace and removes invisible, terminal, and bidi controls", () => {
    expect(publicErrorText("  denied\n\u001b[31m\u202efake\u202c\u200b  ", "fallback"))
      .toBe("denied [31mfake");
  });

  it("uses a safe fallback for empty control-only text", () => {
    expect(publicErrorText("\u0000\u202e\u202c", "Request failed")).toBe("Request failed");
  });

  it("limits by rendered code points without splitting emoji", () => {
    expect(publicErrorText("A🧬BC", "fallback", 3)).toBe("A🧬B");
  });
});
