import { describe, expect, it } from "vitest";
import panelSource from "./ComputeVaultPanel.tsx?raw";
import {
  computeVaultUiOperationContextIsCurrent,
  computeVaultUiOperationFingerprint,
  computeVaultUiOperationGenerationIsCurrent,
} from "./ComputeVaultPanel";

function authorizationFingerprint(overrides: {
  account?: string;
  projectReference?: string;
  jobReference?: string;
  workloadCommitment?: string;
  assetKind?: string;
  amount?: string;
  decimals?: number;
  symbol?: string;
} = {}): string {
  return computeVaultUiOperationFingerprint({
    action: "authorize",
    account: overrides.account ?? `0x${"1".repeat(40)}`,
    projectReference: overrides.projectReference ?? "prj_0123456789abcdef01234567",
    fields: [
      overrides.jobReference ?? "challenge-run-001",
      overrides.amount ?? "0.005",
      "1",
      overrides.assetKind ?? "native",
      overrides.decimals ?? 18,
      overrides.symbol ?? "ETH",
      `0x${"2".repeat(40)}`,
      `0x${"3".repeat(64)}`,
      "",
      [
        `wrk_${"ab".repeat(16)}`,
        "dnai.compute.workload.inference.v1",
        overrides.workloadCommitment ?? `0x${"4".repeat(64)}`,
        `0x${"5".repeat(64)}`,
        "inference",
        "qwen3_8b",
        "qwen3_8b_bounded",
        "bounded_summary_receipt",
        4_096,
        512,
        0,
      ],
    ],
  });
}

describe("Compute vault async UI attribution", () => {
  it("exposes the capacity asset picker as a pressed-button group, not a tab interface", () => {
    expect(panelSource).toContain(
      'class="vault-asset-tabs" role="group" aria-label="Capacity asset"',
    );
    expect(panelSource).toContain(
      'aria-pressed={assetKind() === "native"}',
    );
    expect(panelSource).toContain(
      'aria-pressed={assetKind() === "erc20"}',
    );
    expect(panelSource).not.toContain(
      'class="vault-asset-tabs" role="tablist"',
    );
    expect(panelSource).not.toMatch(
      /class="vault-asset-tabs"[\s\S]{0,500}\brole="tab"/,
    );
  });

  it("exposes sponsor recipients, nonce invalidation, and role accrual claims without broadening assets", () => {
    expect(panelSource).toContain("Capacity beneficiary");
    expect(panelSource).toContain("PAYER · SIGNS &amp; SPENDS");
    expect(panelSource).toContain("BENEFICIARY · OWNS CAPACITY");
    expect(panelSource).toContain("Only the beneficiary can authorize jobs or withdraw this capacity");
    expect(panelSource).toContain("beneficiaryFundingConfirmed");
    expect(panelSource).toContain("fundVaultNative(reference, amount, beneficiary)");
    expect(panelSource).toContain("fundVaultErc20(reference, amount, beneficiary)");
    expect(panelSource).toContain("invalidateVaultAuthorizationNonce(reference, newNonce)");
    expect(panelSource).toContain("withdrawVaultAccrued(exactAssetKind)");
    expect(panelSource).toContain("Invalidate earlier signatures");
    expect(panelSource).toContain("Provider / developer accrual");
    expect(panelSource).toContain("wallet-scoped and remains available without a project");
    expect(panelSource).toContain("confirmed contract event supplies the exact amount withdrawn");
    expect(panelSource).toContain("uint256 maximum");
    expect(panelSource).toContain("never an unlimited allowance");
    expect(panelSource).toContain("An existing larger allowance is left unchanged");
    expect(panelSource).toContain("loadComputeVaultSafetyState(nextAccount, nextProject || undefined)");
    expect(panelSource).toContain("Code-pinned safety controls are evaluated separately below");
    expect(panelSource).toContain("Unverified token units");
    expect(panelSource).toContain("RAW BASE UNITS");
    expect(panelSource).toContain("configured symbol and decimals are intentionally not used");
  });

  it("drops a deferred authorization result after job, workload, asset, amount, or display drift", async () => {
    const expectedFingerprint = authorizationFingerprint();
    let currentFingerprint = expectedFingerprint;
    let releaseWalletApproval: (() => void) | undefined;
    const walletApprovalPaused = new Promise<void>((resolve) => {
      releaseWalletApproval = resolve;
    });
    const resultMayPublish = (async () => {
      await walletApprovalPaused;
      return computeVaultUiOperationContextIsCurrent({
        expectedAuthorizationVersion: 19,
        currentAuthorizationVersion: 19,
        expectedFingerprint,
        currentFingerprint,
      });
    })();

    currentFingerprint = authorizationFingerprint({
      jobReference: "challenge-run-002",
      workloadCommitment: `0x${"6".repeat(64)}`,
      assetKind: "erc20",
      amount: "17.25",
      decimals: 6,
      symbol: "USDC",
    });
    releaseWalletApproval?.();
    expect(await resultMayPublish).toBe(false);
  });

  it("drops deferred funding and pinned-job reads after wallet or exact-reference drift", async () => {
    const expectedFunding = computeVaultUiOperationFingerprint({
      action: "fund",
      account: `0x${"a".repeat(40)}`,
      projectReference: "prj_exact_asset",
      fields: ["native", 18, "ETH", "0.01", `0x${"b".repeat(40)}`],
    });
    let currentAuthorizationVersion = 4;
    let releaseFunding: (() => void) | undefined;
    const fundingPaused = new Promise<void>((resolve) => {
      releaseFunding = resolve;
    });
    const fundingMayPublish = (async () => {
      await fundingPaused;
      return computeVaultUiOperationContextIsCurrent({
        expectedAuthorizationVersion: 4,
        currentAuthorizationVersion,
        expectedFingerprint: expectedFunding,
        currentFingerprint: expectedFunding,
      });
    })();
    currentAuthorizationVersion += 1;
    releaseFunding?.();
    expect(await fundingMayPublish).toBe(false);

    const expectedRead = computeVaultUiOperationFingerprint({
      action: "inspect",
      account: `0x${"a".repeat(40)}`,
      projectReference: "prj_exact_asset",
      fields: ["challenge-run-001", "challenge-run-001", ""],
    });
    let currentRead = expectedRead;
    let releaseRead: (() => void) | undefined;
    const readPaused = new Promise<void>((resolve) => {
      releaseRead = resolve;
    });
    const readMayPublish = (async () => {
      await readPaused;
      return computeVaultUiOperationContextIsCurrent({
        expectedAuthorizationVersion: 5,
        currentAuthorizationVersion: 5,
        expectedFingerprint: expectedRead,
        currentFingerprint: currentRead,
      });
    })();
    currentRead = computeVaultUiOperationFingerprint({
      action: "inspect",
      account: `0x${"a".repeat(40)}`,
      projectReference: "prj_exact_asset",
      fields: ["challenge-run-002", "challenge-run-002", ""],
    });
    releaseRead?.();
    expect(await readMayPublish).toBe(false);

    expect(panelSource).toContain("const authorizedReference = jobReference().trim()");
    expect(panelSource).toContain("const decimals = releaseDecimals()");
    expect(panelSource).toContain("const symbol = releaseSymbol()");
    expect(panelSource).toContain("readPinnedJob(authorizedReference, actionContextIsCurrent)");
    expect(panelSource).toContain("shortHex(result.jobId)");
  });

  it("does not let stale tracked read A clear busy state owned by newer operation B", async () => {
    let activeUiGeneration = 31;
    const readAGeneration = activeUiGeneration;
    let releaseReadA: (() => void) | undefined;
    const readAPaused = new Promise<void>((resolve) => {
      releaseReadA = resolve;
    });
    const readAMayFinalize = (async () => {
      await readAPaused;
      return computeVaultUiOperationGenerationIsCurrent(
        readAGeneration,
        activeUiGeneration,
      );
    })();

    // Context churn cancels A and operation B acquires the busy indicator.
    activeUiGeneration += 1;
    const operationBGeneration = activeUiGeneration;
    releaseReadA?.();
    expect(await readAMayFinalize).toBe(false);
    expect(computeVaultUiOperationGenerationIsCurrent(
      operationBGeneration,
      activeUiGeneration,
    )).toBe(true);
    expect(panelSource.match(/computeVaultUiOperationGenerationIsCurrent\(/g)?.length).toBeGreaterThanOrEqual(7);
  });
});
