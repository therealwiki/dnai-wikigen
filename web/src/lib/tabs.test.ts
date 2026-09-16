import { describe, expect, it } from "vitest";
import { nextRovingTab } from "./tabs";

const TABS = ["first", "second", "third"] as const;

describe("roving tab navigation", () => {
  it("moves with both horizontal and vertical arrow keys and wraps", () => {
    expect(nextRovingTab(TABS, "first", "ArrowRight")).toBe("second");
    expect(nextRovingTab(TABS, "second", "ArrowDown")).toBe("third");
    expect(nextRovingTab(TABS, "first", "ArrowLeft")).toBe("third");
    expect(nextRovingTab(TABS, "third", "ArrowUp")).toBe("second");
  });

  it("supports Home and End without hijacking unrelated keys", () => {
    expect(nextRovingTab(TABS, "second", "Home")).toBe("first");
    expect(nextRovingTab(TABS, "second", "End")).toBe("third");
    expect(nextRovingTab(TABS, "second", "Tab")).toBeUndefined();
  });

  it("fails closed for an unknown current tab or an empty tab set", () => {
    expect(nextRovingTab(TABS, "missing" as (typeof TABS)[number], "ArrowRight")).toBeUndefined();
    expect(nextRovingTab([] as const, "missing", "Home")).toBeUndefined();
  });
});
