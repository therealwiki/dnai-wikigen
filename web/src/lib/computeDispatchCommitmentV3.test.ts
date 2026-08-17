import { describe, expect, it } from "vitest";

import {
  computeCollaborationOneShotAuthorizationContextCommitment,
  computeDispatchIntentV3Commitment,
  computeStandaloneAuthorizationContextCommitment,
} from "./computeDispatchCommitment";
import vectors from "./computeDispatchIntentV3Vectors.json";

describe("Compute dispatch intent v3 commitment", () => {
  it("matches the Python wallet-adoption KAT", () => {
    const vector = vectors.vectors[0];
    const intent = vector.intent;
    expect(computeStandaloneAuthorizationContextCommitment({
      projectId: vector.project_id as `0x${string}`,
      jobId: vector.job_id as `0x${string}`,
      user: intent.user as `0x${string}`,
      asset: intent.asset as `0x${string}`,
      authorizationNonce: BigInt(intent.authorization_nonce),
      maxAssetDebit: BigInt(intent.max_asset_debit),
      authorizationExpiry: intent.authorization_expiry,
      ratePolicyCommitment: intent.rate_policy_commitment as `0x${string}`,
      workloadCommitment: intent.workload_commitment as `0x${string}`,
      manifestCommitment: intent.manifest_commitment as `0x${string}`,
    })).toBe(intent.authorization_context_commitment);
    expect(computeDispatchIntentV3Commitment({
      projectReference: intent.project_reference,
      jobReference: intent.job_reference,
      projectId: vector.project_id as `0x${string}`,
      jobId: vector.job_id as `0x${string}`,
      user: intent.user as `0x${string}`,
      asset: intent.asset as `0x${string}`,
      authorizationNonce: BigInt(intent.authorization_nonce),
      maxAssetDebit: BigInt(intent.max_asset_debit),
      authorizationExpiry: intent.authorization_expiry,
      ratePolicyCommitment: intent.rate_policy_commitment as `0x${string}`,
      composeHash: intent.compose_hash as `0x${string}`,
      operation: intent.operation,
      model: intent.model,
      recipe: intent.recipe,
      resultPolicy: intent.result_policy,
      maxPrefillTokens: intent.max_prefill_tokens,
      maxSampleTokens: intent.max_sample_tokens,
      maxTrainTokens: intent.max_train_tokens,
      workloadId: intent.workload_id,
      workloadSchema: intent.workload_schema,
      manifestCommitment: intent.manifest_commitment as `0x${string}`,
      workloadCommitment: intent.workload_commitment as `0x${string}`,
      workloadSourceKind: intent.workload_source_kind as "wallet" | "credential",
      workloadExecutionBindingCommitment: (
        intent.workload_execution_binding_commitment as `sha256:${string}`
      ),
      workloadRecipientReleaseCommitment: (
        intent.workload_recipient_release_commitment as `sha256:${string}`
      ),
      authorizationKind: intent.authorization_kind as "standalone" | "collaboration_one_shot",
      authorizationContextCommitment: (
        intent.authorization_context_commitment as `sha256:${string}`
      ),
    })).toBe(vector.intent_commitment);
  });

  it("binds the source, ciphertext execution binding, and recipient release", () => {
    const vector = vectors.vectors[0];
    const intent = vector.intent;
    const base = {
      projectReference: intent.project_reference,
      jobReference: intent.job_reference,
      projectId: vector.project_id as `0x${string}`,
      jobId: vector.job_id as `0x${string}`,
      user: intent.user as `0x${string}`,
      asset: intent.asset as `0x${string}`,
      authorizationNonce: BigInt(intent.authorization_nonce),
      maxAssetDebit: BigInt(intent.max_asset_debit),
      authorizationExpiry: intent.authorization_expiry,
      ratePolicyCommitment: intent.rate_policy_commitment as `0x${string}`,
      composeHash: intent.compose_hash as `0x${string}`,
      operation: intent.operation,
      model: intent.model,
      recipe: intent.recipe,
      resultPolicy: intent.result_policy,
      maxPrefillTokens: intent.max_prefill_tokens,
      maxSampleTokens: intent.max_sample_tokens,
      maxTrainTokens: intent.max_train_tokens,
      workloadId: intent.workload_id,
      workloadSchema: intent.workload_schema,
      manifestCommitment: intent.manifest_commitment as `0x${string}`,
      workloadCommitment: intent.workload_commitment as `0x${string}`,
      workloadSourceKind: "wallet" as const,
      workloadExecutionBindingCommitment: (
        intent.workload_execution_binding_commitment as `sha256:${string}`
      ),
      workloadRecipientReleaseCommitment: (
        intent.workload_recipient_release_commitment as `sha256:${string}`
      ),
      authorizationKind: "standalone" as const,
      authorizationContextCommitment: (
        intent.authorization_context_commitment as `sha256:${string}`
      ),
    };
    const baseline = computeDispatchIntentV3Commitment(base);
    expect(computeDispatchIntentV3Commitment({
      ...base,
      workloadSourceKind: "credential",
    })).not.toBe(baseline);
    expect(computeDispatchIntentV3Commitment({
      ...base,
      workloadExecutionBindingCommitment: `sha256:${"a3".repeat(32)}`,
    })).not.toBe(baseline);
    expect(computeDispatchIntentV3Commitment({
      ...base,
      workloadRecipientReleaseCommitment: `sha256:${"a4".repeat(32)}`,
    })).not.toBe(baseline);
    expect(computeDispatchIntentV3Commitment({
      ...base,
      authorizationKind: "collaboration_one_shot",
    })).not.toBe(baseline);
    expect(computeDispatchIntentV3Commitment({
      ...base,
      authorizationContextCommitment: `sha256:${"a5".repeat(32)}`,
    })).not.toBe(baseline);
    expect(() => computeDispatchIntentV3Commitment({
      ...base,
      workloadExecutionBindingCommitment: `sha256:${"0".repeat(64)}`,
    })).toThrow(/authority/);
  });

  it("matches the non-circular Python collaboration one-shot KAT", () => {
    const fields = {
      collaborationExecutionBasisCommitment: `sha256:${"b1".repeat(32)}` as const,
      collaborationExecutionGrantSetCommitment: `sha256:${"b2".repeat(32)}` as const,
      projectId: `0x${"11".repeat(32)}` as `0x${string}`,
      jobId: `0x${"22".repeat(32)}` as `0x${string}`,
      user: `0x${"33".repeat(20)}` as `0x${string}`,
      asset: `0x${"00".repeat(20)}` as `0x${string}`,
      authorizationNonce: 7n,
      maxAssetDebit: 123_456n,
      authorizationExpiry: 1_800_003_600,
      ratePolicyCommitment: `0x${"44".repeat(32)}` as `0x${string}`,
      workloadCommitment: `0x${"55".repeat(32)}` as `0x${string}`,
      manifestCommitment: `0x${"66".repeat(32)}` as `0x${string}`,
    };
    const context = computeCollaborationOneShotAuthorizationContextCommitment(fields);
    expect(context).toBe(
      "sha256:e1e6a62d78894cccfee48f506b8bc658d498dd922c9a6c2c371784a597e21c4e",
    );
    const substitutions = [
      { collaborationExecutionBasisCommitment: `sha256:${"b3".repeat(32)}` },
      { collaborationExecutionGrantSetCommitment: `sha256:${"b4".repeat(32)}` },
      { projectId: `0x${"12".repeat(32)}` },
      { jobId: `0x${"23".repeat(32)}` },
      { user: `0x${"34".repeat(20)}` },
      { asset: `0x${"35".repeat(20)}` },
      { authorizationNonce: 8n },
      { maxAssetDebit: 123_457n },
      { authorizationExpiry: 1_800_003_601 },
      { ratePolicyCommitment: `0x${"45".repeat(32)}` },
      { workloadCommitment: `0x${"56".repeat(32)}` },
      { manifestCommitment: `0x${"67".repeat(32)}` },
    ] as const;
    for (const substitution of substitutions) {
      expect(computeCollaborationOneShotAuthorizationContextCommitment({
        ...fields,
        ...substitution,
      })).not.toBe(context);
    }
    expect(computeStandaloneAuthorizationContextCommitment(fields)).not.toBe(context);
    expect(() => computeCollaborationOneShotAuthorizationContextCommitment({
      ...fields,
      collaborationExecutionBasisCommitment: `sha256:${"0".repeat(64)}`,
    })).toThrow(/not canonical/);
  });
});
