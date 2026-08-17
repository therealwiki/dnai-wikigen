import { describe, expect, it } from "vitest";
import source from "./RoyaltyRail.tsx?raw";
import {
  royaltyUiAuthorityEpochIsCurrent,
  royaltyUiContextIsCurrent,
  royaltyUiFingerprint,
} from "./RoyaltyRail";

describe("Royalty rail product boundary", () => {
  it("exposes the asset picker as a pressed-button group, not a tab interface", () => {
    expect(source).toContain(
      'class="royalty-asset-tabs" role="group" aria-label="Royalty asset"',
    );
    expect(source).toContain('aria-pressed={assetKind() === "native"}');
    expect(source).toContain('aria-pressed={assetKind() === "usdc"}');
    expect(source).not.toContain(
      'class="royalty-asset-tabs" role="tablist"',
    );
    expect(source).not.toMatch(
      /class="royalty-asset-tabs"[\s\S]{0,500}\brole="tab"/,
    );
  });

  it("keeps allocation writes absent while exposing verified self-claims", () => {
    expect(source).toContain("Withdrawal runtime and settlement authority are separate gates");
    expect(source).toContain("Live read · runtime verified");
    expect(source).toContain("dual-signed, release-bound settlement");
    expect(source).toContain("broadcastRoyaltyWithdrawal");
    expect(source).toContain("confirmRoyaltyWithdrawal");
    expect(source).toContain("recoverRoyaltyWithdrawal");
    expect(source).toContain(
      "Only the connected owner can pull its recorded aggregate asset balance",
    );
    expect(source).toContain(
      "this withdrawal is not a single-settlement claim",
    );
    expect(source).not.toContain("distributeNative");
    expect(source).not.toContain("distributeERC20");
  });

  it("separates dual-RPC release evidence from the browser observation and reservation gate", () => {
    expect(source).toContain("Dual-RPC H bound");
    expect(source).toContain("One-RPC read · authority current");
    expect(source).toContain("One external RPC at block");
    expect(source).toContain("The browser cannot author allocations, prove TDX, or manufacture QVL evidence");
    expect(source).toContain("Authority readiness is not funding or authorization");
    expect(source).toContain("requires an exact active onchain reservation");
    expect(source).toContain("already-accrued owner withdrawals usable");
    expect(source).toContain("newSettlementsEnabled");
    expect(source).toMatch(
      /disabled=\{Boolean\(busy\(\)\) \|\| \(!pendingWithdrawal\(\) && \(!state\(\)\?\.runtimeVerified \|\| !selectedAmount\(\)\)\)\}/,
    );
  });

  it("binds async publication to wallet, chain, release, and exact action fields", () => {
    const expected = royaltyUiFingerprint({
      action: "withdraw",
      account: `0x${"11".repeat(20)}`,
      chainId: 84532,
      authorizationVersion: 4,
      releaseFingerprint: "release-a",
      fields: ["native", "5", `0x${"22".repeat(20)}`, "100"],
    });
    const driftedAsset = royaltyUiFingerprint({
      action: "withdraw",
      account: `0x${"11".repeat(20)}`,
      chainId: 84532,
      authorizationVersion: 4,
      releaseFingerprint: "release-a",
      fields: ["usdc", "5", `0x${"22".repeat(20)}`, "100"],
    });
    const driftedWallet = royaltyUiFingerprint({
      action: "withdraw",
      account: `0x${"11".repeat(20)}`,
      chainId: 84532,
      authorizationVersion: 5,
      releaseFingerprint: "release-a",
      fields: ["native", "5", `0x${"22".repeat(20)}`, "100"],
    });
    const driftedChain = royaltyUiFingerprint({
      action: "withdraw",
      account: `0x${"11".repeat(20)}`,
      chainId: 1,
      authorizationVersion: 4,
      releaseFingerprint: "release-a",
      fields: ["native", "5", `0x${"22".repeat(20)}`, "100"],
    });
    const driftedRelease = royaltyUiFingerprint({
      action: "withdraw",
      account: `0x${"11".repeat(20)}`,
      chainId: 84532,
      authorizationVersion: 4,
      releaseFingerprint: "release-b",
      fields: ["native", "5", `0x${"22".repeat(20)}`, "100"],
    });
    expect(royaltyUiContextIsCurrent(expected, expected)).toBe(true);
    expect(royaltyUiContextIsCurrent(expected, driftedAsset)).toBe(false);
    expect(royaltyUiContextIsCurrent(expected, driftedWallet)).toBe(false);
    expect(royaltyUiContextIsCurrent(expected, driftedChain)).toBe(false);
    expect(royaltyUiContextIsCurrent(expected, driftedRelease)).toBe(false);
    expect(royaltyUiAuthorityEpochIsCurrent({
      expectedEpoch: 3,
      currentEpoch: 3,
      expectedRevision: 7,
      currentRevision: 7,
      expectedFingerprint: expected,
      currentFingerprint: expected,
    })).toBe(true);
    expect(royaltyUiAuthorityEpochIsCurrent({
      expectedEpoch: 3,
      currentEpoch: 4,
      expectedRevision: 7,
      currentRevision: 7,
      expectedFingerprint: expected,
      currentFingerprint: expected,
    })).toBe(false);
  });

  it("retains one broadcast and blocks a second withdrawal until recovery resolves it", () => {
    expect(source).toMatch(
      /broadcastRoyaltyWithdrawal[\s\S]*?retainRoyaltyWithdrawal\(storage, broadcast\)[\s\S]*?setPendingWithdrawal\(broadcast\)[\s\S]*?setTransactionHash\(broadcast\.transactionHash\)[\s\S]*?confirmRoyaltyWithdrawal/,
    );
    expect(source).toContain("restoreRoyaltyWithdrawal");
    expect(source).toContain("clearFinalizedRoyaltyWithdrawal");
    expect(source).toContain(
      "Reload recovery stores public transaction metadata only",
    );
    expect(source).toContain("while finalized confirmation is checked");
    expect(source).toContain("Recheck exact withdrawal");
    expect(source).toContain("do not broadcast another withdrawal");
    expect(source).toContain("The exact transaction hash remains retained");
    expect(source).not.toContain("Royalty withdrawal failed");
    expect(source).toMatch(
      /disabled=\{Boolean\(busy\(\)\) \|\| Boolean\(pendingWithdrawal\(\)\)\}/,
    );
  });

  it("drops late success and failure publications after an authority epoch changes", async () => {
    let epoch = 5;
    let revision = 11;
    const fingerprint = "wallet-a/base-sepolia/release-a";
    let notice = "replacement authority is current";
    let error = "";
    let resolveRequest: ((value: string) => void) | undefined;
    const response = new Promise<string>((resolve) => {
      resolveRequest = resolve;
    });
    const pending = (async () => {
      try {
        const value = await response;
        if (!royaltyUiAuthorityEpochIsCurrent({
          expectedEpoch: 5,
          currentEpoch: epoch,
          expectedRevision: 11,
          currentRevision: revision,
          expectedFingerprint: fingerprint,
          currentFingerprint: fingerprint,
        })) return;
        notice = value;
      } catch {
        if (epoch === 5 && revision === 11) error = "stale failure";
      }
    })();

    epoch += 1;
    revision += 1;
    resolveRequest?.("stale payout success");
    await pending;
    expect(notice).toBe("replacement authority is current");
    expect(error).toBe("");
  });
});
