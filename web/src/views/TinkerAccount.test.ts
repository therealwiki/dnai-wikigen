import { createComponent } from "solid-js";
import { renderToString } from "solid-js/web";
import { describe, expect, it } from "vitest";
import { TinkerAccount } from "./TinkerAccount";
import tinkerAccountSource from "./TinkerAccount.tsx?raw";

function renderAccount(): string {
  return renderToString(() => createComponent(TinkerAccount, {
    requestWalletConnection: () => undefined,
    openCompute: () => undefined,
  }));
}

describe("Tinker delegated account console", () => {
  it("renders the complete customer lifecycle and keeps its evidence boundary explicit", () => {
    const html = renderAccount();

    expect(html).toContain("Delegated Tinker account");
    expect(html).toContain("Select owner wallet");
    expect(html).toContain("signed nonce challenge establishes service authorization");
    expect(html).toContain("Establish account");
    expect(html).toContain("Freeze policy");
    expect(html).toContain("Use capacity");
    expect(html).toContain("Create inside CVM");
    expect(html).toContain("Link attested commitment");
    expect(html).toContain("Custody + encumbrance");
    expect(html).toContain("Allowance and execution policy");
    expect(html).toContain("See exactly what the contract can authorize");
    expect(html).toContain("EXACT OPERATION LOOKUP");
    expect(html).toContain("Rotate or end delegation");
    expect(html).toContain("Inference and training spend");
    expect(html).toContain("not evidence that Wikigen's fresh Tinker account");
  });

  it("separates exact assets, noncash test credits, and future hosted card funding", () => {
    const html = renderAccount();

    expect(html).toContain("Exact-asset vault");
    expect(html).toContain("same-asset withdrawal claim");
    expect(html).toContain("No token minting");
    expect(html).toContain("Operator test credits");
    expect(html).toContain("non-transferable, non-redeemable");
    expect(html).toContain("Provider-hosted checkout");
    expect(html).toContain("does not collect, proxy, log, or store card details");
  });

  it("fails closed for every account, funding, authority, and spend mutation", () => {
    const html = renderAccount();
    const mutations = [...html.matchAll(/<button[^>]*data-tinker-mutation="[^"]+"[^>]*>[\s\S]*?<\/button>/g)];

    expect(mutations.length).toBeGreaterThanOrEqual(9);
    for (const [button] of mutations) {
      expect(button).toContain("disabled");
      expect(button).toMatch(/Release gated|Roadmap/);
    }

    expect(html).toContain('data-tinker-action="connect-wallet"');
    expect(html).toContain('data-tinker-action="open-compute"');
  });

  it("offers no field or network path for card, account, or raw secret intake", () => {
    expect(tinkerAccountSource).not.toMatch(/<input\b|<textarea\b|<select\b/);
    expect(tinkerAccountSource).not.toContain("fetch(");
    expect(tinkerAccountSource).not.toContain("tml-");
    expect(tinkerAccountSource).not.toContain("private-key");
    expect(tinkerAccountSource).toContain("Never paste an upstream API key");
    expect(tinkerAccountSource).toContain("Contract custody");
    expect(tinkerAccountSource).toContain("No keys, cards, provider balance, or user funds");
  });
});
