import { describe, expect, it } from "vitest";
import source from "./RoyaltyRail.tsx?raw";
import { royaltyUiContextIsCurrent, royaltyUiFingerprint } from "./RoyaltyRail";

describe("Royalty rail product boundary", () => {
  it("keeps allocation writes absent while exposing verified self-claims", () => {
    expect(source).toContain("allocation authority absent");
    expect(source).toContain("Live read · runtime verified");
    expect(source).toContain("does not establish ownership");
    expect(source).toContain("withdrawRoyaltyBalance(exactAsset)");
    expect(source).toContain("Only the connected owner can pull its recorded balance");
    expect(source).not.toContain("distributeNative");
    expect(source).not.toContain("distributeERC20");
  });

  it("binds async publication to wallet authorization and exact action fields", () => {
    const expected = royaltyUiFingerprint({
      action: "withdraw",
      account: `0x${"11".repeat(20)}`,
      authorizationVersion: 4,
      fields: ["native", "5", `0x${"22".repeat(20)}`, "100"],
    });
    const driftedAsset = royaltyUiFingerprint({
      action: "withdraw",
      account: `0x${"11".repeat(20)}`,
      authorizationVersion: 4,
      fields: ["usdc", "5", `0x${"22".repeat(20)}`, "100"],
    });
    const driftedWallet = royaltyUiFingerprint({
      action: "withdraw",
      account: `0x${"11".repeat(20)}`,
      authorizationVersion: 5,
      fields: ["native", "5", `0x${"22".repeat(20)}`, "100"],
    });
    expect(royaltyUiContextIsCurrent(expected, expected)).toBe(true);
    expect(royaltyUiContextIsCurrent(expected, driftedAsset)).toBe(false);
    expect(royaltyUiContextIsCurrent(expected, driftedWallet)).toBe(false);
  });
});
