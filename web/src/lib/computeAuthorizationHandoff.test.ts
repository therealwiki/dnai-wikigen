import { describe, expect, it } from "vitest";
import { zeroAddress, zeroHash, type Address, type Hex } from "viem";
import {
  assertComputeAuthorizationHandoffCoreUnchanged,
  assertComputeAuthorizationHandoffMatchesIntent,
  computeAuthorizationHandoffFromPinnedRead,
  createComputeAuthorizationHandoff,
  dispatchFieldsFromComputeAuthorizationHandoff,
  parseComputeAuthorizationHandoff,
} from "./computeAuthorizationHandoff";
import type { ComputeDispatchIntentStatus } from "./compute";
import {
  computeVaultJobId,
  computeVaultProjectId,
  type ComputeVaultState,
  type VaultJobRead,
} from "./computeVault";
import { parseComputeVaultConfig } from "./computeVaultConfig";

const vault = "0x1111111111111111111111111111111111111111" as Address;
const owner = "0x2222222222222222222222222222222222222222" as Address;
const developer = "0x3333333333333333333333333333333333333333" as Address;
const verifier = "0x4444444444444444444444444444444444444444" as Address;
const qvlVerifier = "0x6666666666666666666666666666666666666666" as Address;
const tee = "0x5555555555555555555555555555555555555555" as Address;
const codeHash = `0x${"11".repeat(32)}` as Hex;
const composeHash = `0x${"22".repeat(32)}` as Hex;
const ratePolicy = `0x${"33".repeat(32)}` as Hex;
const policySet = `0x${"44".repeat(32)}` as Hex;
const transactionHash = `0x${"55".repeat(32)}` as Hex;
const workloadCommitment = `0x${"66".repeat(32)}` as Hex;
const manifestCommitment = `0x${"77".repeat(32)}` as Hex;
const dispatchIntentCommitment = `0x${"88".repeat(32)}` as Hex;
const projectReference = "prj_0123456789abcdef01234567";
const jobReference = "challenge-run-001";

function pinnedRead(): { state: ComputeVaultState; jobRead: VaultJobRead } {
  const config = parseComputeVaultConfig({
    VITE_ENABLE_COMPUTE_VAULT_FUNDING: "true",
    VITE_ENABLE_COMPUTE_VAULT_AUTHORIZATION: "true",
    VITE_COMPUTE_CREDIT_VAULT_ADDRESS: vault,
    VITE_COMPUTE_CREDIT_VAULT_CODE_HASH: codeHash,
    VITE_COMPUTE_VAULT_DEVELOPER: developer,
    VITE_COMPUTE_VAULT_METERING_VERIFIER: verifier,
    VITE_COMPUTE_VAULT_METERING_QVL_VERIFIER: qvlVerifier,
    VITE_COMPUTE_VAULT_METERING_POLICY_SET_HASH: policySet,
    VITE_COMPUTE_METERING_VERIFIED_QUOTE_SHA256: `sha256:${"66".repeat(32)}`,
    VITE_COMPUTE_VAULT_TEE_IDENTITY: tee,
    VITE_COMPUTE_VAULT_COMPOSE_HASH: composeHash,
    VITE_COMPUTE_VAULT_NATIVE_RATE_POLICY_COMMITMENT: ratePolicy,
  });
  const projectId = computeVaultProjectId(projectReference);
  const blockNumber = 12_345n;
  return {
    state: {
      config,
      checkedAt: 1_800_000_000_000,
      blockNumber,
      projectId,
      account: owner,
      snapshot: { runtimeCodeHash: codeHash },
      readiness: {
        deploymentVerified: true,
        withdrawalReady: true,
        nativeFundingReady: true,
        tokenFundingReady: false,
        nativeAuthorizationReady: true,
        tokenAuthorizationReady: false,
        deploymentReasons: [],
        fundingReasons: [],
        executionReasons: [],
        tokenReasons: ["no exact ERC20 asset is release configured"],
      },
    },
    jobRead: {
      jobId: computeVaultJobId(jobReference),
      blockNumber,
      blockTimestamp: 1_800_000_000n,
      job: {
        projectId,
        user: owner,
        asset: zeroAddress,
        authorizationNonce: 9_007_199_254_740_993n,
        maxAssetDebit: 5_000_000_000_000_000n,
        actualAssetDebit: 0n,
        authorizationExpiry: 1_800_003_600n,
        startedAt: 0n,
        usageEndedAt: 0n,
        receiptExpiry: 0n,
        ratePolicyCommitment: ratePolicy,
        workloadCommitment,
        manifestCommitment,
        dispatchIntentCommitment,
        composeHash: zeroHash,
        startCommitment: zeroHash,
        usageCommitment: zeroHash,
        attestationEvidenceHash: zeroHash,
        billableComputeUnits: 0n,
        teeIdentity: zeroAddress,
        state: 1,
      },
    },
  };
}

function receipt() {
  const { state, jobRead } = pinnedRead();
  return computeAuthorizationHandoffFromPinnedRead({
    source: "confirmed_transaction",
    projectReference,
    jobReference,
    state,
    jobRead,
    authorizationTransactionHash: transactionHash,
  });
}

describe("Compute vault authorization handoff", () => {
  it("normalizes one immutable exact-asset receipt without interpreting it as credits", () => {
    const value = receipt();
    expect(Object.isFrozen(value)).toBe(true);
    expect(value).toMatchObject({
      surface: "compute_vault_authorization_handoff",
      schemaVersion: 2,
      source: "confirmed_transaction",
      projectReference,
      jobReference,
      user: owner,
      asset: zeroAddress,
      authorizationNonce: "9007199254740993",
      maxAssetDebit: "5000000000000000",
      authorizationExpiry: 1_800_003_600,
      ratePolicyCommitment: ratePolicy,
      workloadCommitment,
      manifestCommitment,
      dispatchIntentCommitment,
      composeHash,
      vaultAddress: vault,
      vaultRuntimeCodeHash: codeHash,
      pinnedBlockNumber: "12345",
      pinnedBlockTimestamp: 1_800_000_000,
      authorizationTransactionHash: transactionHash,
    });
    expect(parseComputeAuthorizationHandoff(value, { projectReference, user: owner })).toEqual(value);
    expect(value).not.toHaveProperty("credits");
    expect(value).not.toHaveProperty("providerDispatch");
  });

  it("converts only the seven vault-bound dispatch fields and preserves uint256 precision", () => {
    expect(dispatchFieldsFromComputeAuthorizationHandoff(receipt())).toEqual({
      jobReference,
      asset: zeroAddress,
      authorizationNonce: 9_007_199_254_740_993n,
      maxAssetDebit: 5_000_000_000_000_000n,
      authorizationExpiry: 1_800_003_600,
      ratePolicyCommitment: ratePolicy,
      composeHash,
    });
  });

  it("rejects mutation, extra fields, mismatched references, and invented transaction provenance", () => {
    const value = receipt();
    expect(() => parseComputeAuthorizationHandoff({ ...value, maxAssetDebit: "6" })).toThrow(/commitment/);
    expect(() => parseComputeAuthorizationHandoff({ ...value, credits: 50 })).toThrow(/fields are not exact/);
    expect(() => parseComputeAuthorizationHandoff({ ...value, projectReference: "different-project" })).toThrow(/project ID/);
    expect(() => createComputeAuthorizationHandoff({
      ...value,
      source: "pinned_block_inspection",
      authorizationTransactionHash: transactionHash,
    })).toThrow(/must not imply a transaction provenance/);
    expect(() => createComputeAuthorizationHandoff({
      ...value,
      source: "pinned_block_inspection",
      pinnedBlockTimestamp: value.authorizationExpiry,
      authorizationTransactionHash: null,
    })).toThrow(/not open/);
  });

  it("rejects started, expired, cross-wallet, and release-drifted pinned reads", () => {
    const base = pinnedRead();
    const cases: Array<{ mutate: () => void; pattern: RegExp }> = [
      { mutate: () => { base.jobRead.blockNumber += 1n; }, pattern: /one block/ },
      { mutate: () => { base.jobRead.job.state = 2; }, pattern: /not-yet-started/ },
      { mutate: () => { base.jobRead.job.authorizationExpiry = base.jobRead.blockTimestamp; }, pattern: /expired/ },
      { mutate: () => { base.jobRead.job.user = developer; }, pattern: /different wallet/ },
      { mutate: () => { base.state.readiness.nativeAuthorizationReady = false; }, pattern: /release gates/ },
    ];
    for (const testCase of cases) {
      const current = pinnedRead();
      Object.assign(base.state, current.state);
      Object.assign(base.jobRead, current.jobRead);
      testCase.mutate();
      expect(() => computeAuthorizationHandoffFromPinnedRead({
        source: "pinned_block_inspection",
        projectReference,
        jobReference,
        state: base.state,
        jobRead: base.jobRead,
      })).toThrow(testCase.pattern);
    }
  });

  it("detects core authorization drift even when both receipts are internally valid", () => {
    const original = receipt();
    const changed = createComputeAuthorizationHandoff({
      ...original,
      source: "pinned_block_inspection",
      authorizationNonce: "9007199254740994",
      pinnedBlockNumber: "12346",
      authorizationTransactionHash: null,
    });
    expect(() => assertComputeAuthorizationHandoffCoreUnchanged(original, changed)).toThrow(/authorizationNonce/);
  });

  it("requires the authenticated journal record to preserve the complete vault tuple", () => {
    const value = receipt();
    const intent = {
      project_reference: value.projectReference,
      project_id: value.projectId,
      job_reference: value.jobReference,
      job_id: value.jobId,
      user: value.user,
      asset: value.asset,
      authorization_nonce: BigInt(value.authorizationNonce),
      max_asset_debit: BigInt(value.maxAssetDebit),
      authorization_expiry: value.authorizationExpiry,
      rate_policy_commitment: value.ratePolicyCommitment,
      workload_commitment: value.workloadCommitment,
      manifest_commitment: value.manifestCommitment,
      intent_commitment: value.dispatchIntentCommitment,
      compose_hash: value.composeHash,
    } as ComputeDispatchIntentStatus;
    expect(() => assertComputeAuthorizationHandoffMatchesIntent(value, intent)).not.toThrow();
    expect(() => assertComputeAuthorizationHandoffMatchesIntent(value, {
      ...intent,
      max_asset_debit: intent.max_asset_debit + 1n,
    })).toThrow(/does not match/);
  });
});
