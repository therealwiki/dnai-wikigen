import { describe, expect, it } from "vitest";
import type { ArenaExecutionProvenance } from "./arena";
import type { ComputeJob } from "./compute";
import type { ChainDeal } from "./contract";
import {
  createArenaRankingVerificationContext,
  createComputeJobVerificationContext,
  createDealResultVerificationContext,
} from "./verificationContext";

const notExecuted = {
  status: "not_executed",
  outcome: null,
  runtime: "dnai-safe-ir-v1",
  runtime_policy_commitment: null,
  challenge_manifest_hash: null,
  compose_hash: null,
  app_id: null,
  os_image_hash: null,
  quote_sha256: null,
  verifier_address: null,
  verdict_digest: null,
  tee_signer_address: null,
  chain_id: null,
  challenge_registry_address: null,
  evidence_classification: "none",
  independently_verified_by_client: false,
  raw_tdx_quote_egress: false,
  exact_score_egress: false,
  exact_timing_egress: false,
} as const satisfies ArenaExecutionProvenance;

const workerReported = {
  status: "worker_reported",
  outcome: "completed",
  runtime: "dnai-safe-ir-v1",
  runtime_policy_commitment: `sha256:${"1".repeat(64)}`,
  challenge_manifest_hash: "2".repeat(64),
  compose_hash: "3".repeat(64),
  app_id: "dnai-dnaseq-safe-ir",
  os_image_hash: "4".repeat(64),
  quote_sha256: `sha256:${"5".repeat(64)}`,
  verifier_address: `0x${"6".repeat(40)}`,
  verdict_digest: `0x${"7".repeat(64)}`,
  tee_signer_address: `0x${"8".repeat(40)}`,
  chain_id: 84532,
  challenge_registry_address: `0x${"9".repeat(40)}`,
  evidence_classification: "worker_reported_qvl_binding_not_independently_verified",
  independently_verified_by_client: false,
  raw_tdx_quote_egress: false,
  exact_score_egress: false,
  exact_timing_egress: false,
} as const satisfies ArenaExecutionProvenance;

const computeJob: ComputeJob = {
  job_id: "job_private_identity",
  project_id: "project_private_identity",
  name: "private experiment name",
  operation: "inference",
  model: "qwen3_8b",
  recipe: "qwen3_8b_bounded",
  max_credits: 500,
  actual_credits: null,
  released_credits: null,
  result_policy: "bounded_summary_receipt",
  environment_version: "v1",
  status: "succeeded",
  dispatch_status: "not_dispatched",
  backend_capability: "future_inference_proxy",
  credential_id: "credential_private_identity",
  created_at: 1,
  updated_at: 2,
  started_at: null,
  completed_at: null,
  metering_source: null,
  usage_receipt_hash: `sha256:${"a".repeat(64)}`,
  settlement_authority: null,
  provider_authoritative_settlement: false,
  raw_input_persisted: false,
  raw_output_persisted: false,
};

const dealResult: ChainDeal = {
  id: 17n,
  seller: `0x${"1".repeat(40)}`,
  buyer: `0x${"2".repeat(40)}`,
  reservePrice: 123n,
  budgetCap: 456n,
  expiry: 999n,
  state: "Evaluated",
  artifactHash: `0x${"3".repeat(64)}`,
  teeIdentity: `0x${"4".repeat(40)}`,
  scoreBand: "High",
  computeCost: 10n,
  fee: 1n,
  resultHash: `0x${"5".repeat(64)}`,
  resultComposeHash: `0x${"6".repeat(64)}`,
  paymentToken: `0x${"7".repeat(40)}`,
  evaluatorPolicyCommitment: `0x${"8".repeat(64)}`,
  attestationEvidenceHash: `0x${"9".repeat(64)}`,
  resultAuthorizationExpiry: 1_000n,
  attestationAuthorizationExpiry: 1_000n,
};

describe("bounded in-memory verification context", () => {
  it("reduces an illustrative Arena row to a non-identifying, non-executed sample", () => {
    const context = createArenaRankingVerificationContext({
      challengeId: "atlas-denoise-01",
      challengeVersion: "illustrative-preview",
      rank: 1,
      evidence: "illustrative",
      submissionId: "modeled_submission",
      candidateCommitment: `sha256:${"b".repeat(64)}`,
      ladder: { stepIndex: 19, denominator: 20, improvementSteps: 47 },
    });

    expect(context).toEqual({
      schema: "dnai.browser-evidence-selection.v1",
      source: "arena_ranking",
      classification: "illustrative_only",
      challengeId: "atlas-denoise-01",
      challengeVersion: null,
      rank: 1,
      submissionId: null,
      candidateCommitment: null,
      ladder: null,
      workerClaim: null,
    });
    expect(Object.isFrozen(context)).toBe(true);
    expect(JSON.stringify(context)).not.toMatch(/wallet|entrant|handle|timing|reward|modeled_submission|illustrative-preview/i);
  });

  it("retains only bounded public projection fields when no execution evidence exists", () => {
    const context = createArenaRankingVerificationContext({
      challengeId: "dnaseq-variant-qc-safe-ir",
      challengeVersion: "1.0.0",
      rank: 2,
      evidence: "none",
      submissionId: "sub_1234",
      candidateCommitment: `sha256:${"c".repeat(64)}`,
      ladder: { stepIndex: 4, denominator: 20, improvementSteps: 3 },
      provenance: notExecuted,
    });

    expect(context.classification).toBe("projection_only_no_execution_evidence");
    expect(context.workerClaim).toBeNull();
    expect(context.ladder).toEqual({ stepIndex: 4, denominator: 20, improvementSteps: 3 });
    expect(Object.isFrozen(context)).toBe(true);
    expect(Object.isFrozen(context.ladder)).toBe(true);
  });

  it("copies and freezes the complete bounded worker claim without accepting it as verified", () => {
    const context = createArenaRankingVerificationContext({
      challengeId: "dnaseq-variant-qc-safe-ir",
      challengeVersion: "1.0.0",
      rank: 1,
      evidence: "worker_reported",
      submissionId: "sub_5678",
      candidateCommitment: `sha256:${"d".repeat(64)}`,
      ladder: { stepIndex: 5, denominator: 20, improvementSteps: 4 },
      provenance: workerReported,
    });

    expect(context.classification).toBe("worker_reported_qvl_binding_not_independently_verified");
    expect(context.workerClaim?.quoteSha256).toBe(workerReported.quote_sha256);
    expect(context.workerClaim?.chainId).toBe(84532);
    expect(Object.isFrozen(context.workerClaim)).toBe(true);
    expect(JSON.stringify(context)).not.toContain(workerReported.app_id);
    expect(JSON.stringify(context)).not.toMatch(/raw_tdx_quote|independently_verified_by_client/);
  });

  it("fails closed on malformed Arena identifiers, hashes, bounds, and provenance", () => {
    expect(() => createArenaRankingVerificationContext({ challengeId: "bad\u202eid", rank: 1, evidence: "illustrative" })).toThrow();
    expect(() => createArenaRankingVerificationContext({ challengeId: "valid-id", rank: 0, evidence: "illustrative" })).toThrow();
    expect(() => createArenaRankingVerificationContext({
      challengeId: "valid-id",
      rank: 1,
      evidence: "none",
      candidateCommitment: "sha256:not-a-digest",
    })).toThrow();
    expect(() => createArenaRankingVerificationContext({
      challengeId: "valid-id",
      rank: 1,
      evidence: "none",
      ladder: { stepIndex: 21, denominator: 20, improvementSteps: 0 },
    })).toThrow();
    expect(() => createArenaRankingVerificationContext({
      challengeId: "valid-id",
      rank: 1,
      evidence: "worker_reported",
      provenance: { ...workerReported, chain_id: 1 } as unknown as ArenaExecutionProvenance,
    })).toThrow("Base Sepolia");
  });

  it("projects only bounded public Deal Room result fields without upgrading contract claims", () => {
    const context = createDealResultVerificationContext(dealResult, {
      modeled: false,
      contractAddress: `0x${"a".repeat(40)}`,
    });
    const serialized = JSON.stringify(context);

    expect(context).toEqual({
      schema: "dnai.browser-evidence-selection.v1",
      source: "deal_result",
      classification: "contract_reported_result_not_independently_verified",
      roomId: "17",
      state: "Evaluated",
      scoreBand: "High",
      resultCommitment: dealResult.resultHash,
      composeBinding: dealResult.resultComposeHash,
      evaluatorPolicyCommitment: dealResult.evaluatorPolicyCommitment,
      attestationEvidenceCommitment: dealResult.attestationEvidenceHash,
      chainId: 84532,
      contractAddress: `0x${"a".repeat(40)}`,
      independentlyVerifiedByBrowser: false,
      rawQuoteAvailable: false,
      intelCollateralVerifiedByBrowser: false,
    });
    expect(Object.isFrozen(context)).toBe(true);
    expect(serialized).not.toContain(dealResult.seller);
    expect(serialized).not.toContain(dealResult.buyer);
    expect(serialized).not.toContain(dealResult.artifactHash);
    expect(serialized).not.toMatch(/reservePrice|budgetCap|computeCost|paymentToken|teeIdentity/i);
  });

  it("keeps a modeled Deal Room result illustrative and rejects false source claims", () => {
    const context = createDealResultVerificationContext(dealResult, { modeled: true });

    expect(context.classification).toBe("illustrative_only");
    expect(context.contractAddress).toBeNull();
    expect(context.independentlyVerifiedByBrowser).toBe(false);
    expect(() => createDealResultVerificationContext(dealResult, {
      modeled: true,
      contractAddress: `0x${"a".repeat(40)}`,
    })).toThrow("cannot claim a contract source");
    expect(() => createDealResultVerificationContext(dealResult, { modeled: false })).toThrow("requires its public contract address");
    expect(() => createDealResultVerificationContext({ ...dealResult, state: "Created" }, { modeled: true })).toThrow("result-bearing room state");
    expect(() => createDealResultVerificationContext({ ...dealResult, resultHash: "0x1234" }, { modeled: true })).toThrow("result commitment");
    expect(() => createDealResultVerificationContext({ ...dealResult, id: -1n }, { modeled: true })).toThrow("uint256");
  });

  it("hands Verify only a service-reported receipt hash and fixed negative invariants", () => {
    const context = createComputeJobVerificationContext(computeJob);
    const serialized = JSON.stringify(context);

    expect(context).toEqual({
      schema: "dnai.browser-evidence-selection.v1",
      source: "compute_receipt_hash",
      classification: "service_reported_hash_only_not_receipt",
      receiptSha256: computeJob.usage_receipt_hash,
      operation: "inference",
      resultPolicy: "bounded_summary_receipt",
      dispatchStatus: "not_dispatched",
      providerAuthoritativeSettlement: false,
      rawInputPersisted: false,
      rawOutputPersisted: false,
    });
    expect(Object.isFrozen(context)).toBe(true);
    expect(serialized).not.toMatch(/job_private_identity|project_private_identity|private experiment|credential_private_identity|max_credits|actual_credits|token|prompt|dataset|raw_output/i);
  });

  it("rejects absent or malformed receipt hashes and weakened negative invariants", () => {
    expect(() => createComputeJobVerificationContext({ ...computeJob, usage_receipt_hash: null })).toThrow();
    expect(() => createComputeJobVerificationContext({ ...computeJob, usage_receipt_hash: "0x1234" })).toThrow();
    expect(() => createComputeJobVerificationContext({
      ...computeJob,
      result_policy: "raw_output" as ComputeJob["result_policy"],
    })).toThrow("result policy");
    expect(() => createComputeJobVerificationContext({
      ...computeJob,
      provider_authoritative_settlement: true,
    } as unknown as ComputeJob)).toThrow("invariants");
  });
});
