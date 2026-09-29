import { createComponent } from "solid-js";
import { renderToString } from "solid-js/web";
import { describe, expect, it, vi } from "vitest";
import { WalletBalanceSummary } from "./AppShell";
import type { WalletBalanceState } from "../lib/wallet";

function renderBalance(state: WalletBalanceState, balance = 5_000_000_000_000_000_000n) {
  const onRefresh = vi.fn();
  const html = renderToString(() => createComponent(WalletBalanceSummary, { state, balance, onRefresh }));
  return { html, onRefresh };
}

describe("wallet balance observation presentation", () => {
  it("shows a numeric amount only for a successful current balance read", () => {
    const { html, onRefresh } = renderBalance("ready");
    expect(html).toContain("5 ETH");
    expect(html).toContain("Refresh Base Sepolia balance");
    expect(html).toContain('role="status" aria-live="polite" aria-atomic="true"');
    expect(onRefresh).not.toHaveBeenCalled();
  });

  it("distinguishes a confirmed zero from an unavailable observation", () => {
    const { html } = renderBalance("ready", 0n);
    expect(html).toContain("0 ETH");
    expect(html).not.toContain("Unavailable");
  });

  it("hides the previous amount while loading and disables repeated refresh", () => {
    const { html, onRefresh } = renderBalance("loading");
    expect(html).toContain("Loading…");
    expect(html).toContain("Checking balance…");
    expect(html).toMatch(/<button[^>]* disabled/);
    expect(html).not.toMatch(/\d+(?:\.\d+)? ETH/);
    expect(onRefresh).not.toHaveBeenCalled();
  });

  it("reports a failed read without inventing a zero and offers an explicit retry", () => {
    const { html } = renderBalance("unavailable", 0n);
    expect(html).toContain("Unavailable");
    expect(html).toContain("The balance read failed. Retry to check this account.");
    expect(html).toContain("Retry Base Sepolia balance");
    expect(html).not.toMatch(/\d+(?:\.\d+)? ETH/);
    expect(html).not.toMatch(/<button[^>]* disabled/);
  });

  it("does not expose an amount or request a read while disconnected", () => {
    const { html, onRefresh } = renderBalance("idle");
    expect(html).toContain("Not checked");
    expect(html).not.toMatch(/\d+(?:\.\d+)? ETH/);
    expect(html).not.toContain("<button");
    expect(onRefresh).not.toHaveBeenCalled();
  });
});
