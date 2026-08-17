import { sha256 } from "viem";

const ENCODER = new TextEncoder();
const MAX_UINT256 = (1n << 256n) - 1n;
const DISPATCH_INTENT_COMMITMENT_DOMAIN = "dnai-wikigen/compute-dispatch-intent/v1\0";
const STANDALONE_AUTHORIZATION_CONTEXT_DOMAIN =
  "dnai-wikigen/compute-standalone-authorization-context/v1\0";
const COLLABORATION_ONE_SHOT_AUTHORIZATION_CONTEXT_DOMAIN =
  "dnai-wikigen/compute-collaboration-one-shot-authorization-context/v1\0";

export interface ComputeDispatchIntentCommitmentFields {
  projectReference: string;
  jobReference: string;
  projectId: `0x${string}`;
  jobId: `0x${string}`;
  user: `0x${string}`;
  asset: `0x${string}`;
  authorizationNonce: bigint;
  maxAssetDebit: bigint;
  authorizationExpiry: number;
  ratePolicyCommitment: `0x${string}`;
  composeHash: `0x${string}`;
  operation: string;
  model: string;
  recipe: string;
  resultPolicy: string;
  maxPrefillTokens: number;
  maxSampleTokens: number;
  maxTrainTokens: number;
  workloadId: string;
  workloadSchema: string;
  manifestCommitment: `0x${string}`;
  workloadCommitment: `0x${string}`;
}

export interface ComputeDispatchIntentV3CommitmentFields
  extends ComputeDispatchIntentCommitmentFields {
  workloadSourceKind: "wallet" | "credential";
  workloadExecutionBindingCommitment: `sha256:${string}`;
  workloadRecipientReleaseCommitment: `sha256:${string}`;
  authorizationKind: "standalone" | "collaboration_one_shot";
  authorizationContextCommitment: `sha256:${string}`;
}

export interface ComputeStandaloneAuthorizationContextFields {
  projectId: `0x${string}`;
  jobId: `0x${string}`;
  user: `0x${string}`;
  asset: `0x${string}`;
  authorizationNonce: bigint;
  maxAssetDebit: bigint;
  authorizationExpiry: number;
  ratePolicyCommitment: `0x${string}`;
  workloadCommitment: `0x${string}`;
  manifestCommitment: `0x${string}`;
}

export interface ComputeCollaborationOneShotAuthorizationContextFields
  extends ComputeStandaloneAuthorizationContextFields {
  collaborationExecutionBasisCommitment: `sha256:${string}`;
  collaborationExecutionGrantSetCommitment: `sha256:${string}`;
}

export function canonicalComputeJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "bigint") {
    if (value < 0n || value > MAX_UINT256) {
      throw new Error("Dispatch commitment integer is outside uint256");
    }
    return value.toString();
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new Error("Dispatch commitment integer is not canonical");
    }
    return String(value);
  }
  if (typeof value === "boolean") return value ? "true" : "false";
  if (Array.isArray(value)) return `[${value.map(canonicalComputeJson).join(",")}]`;
  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0);
    return `{${entries.map(([key, nested]) => `${JSON.stringify(key)}:${canonicalComputeJson(nested)}`).join(",")}}`;
  }
  throw new Error("Dispatch commitment value is not canonical JSON");
}

export function computeDispatchIntentCommitment(
  fields: ComputeDispatchIntentCommitmentFields,
): `0x${string}` {
  const canonicalIntent = canonicalComputeJson({
    asset: fields.asset,
    authorization_expiry: fields.authorizationExpiry,
    authorization_nonce: fields.authorizationNonce,
    compose_hash: fields.composeHash,
    job_id: fields.jobId,
    job_reference: fields.jobReference,
    max_asset_debit: fields.maxAssetDebit,
    max_prefill_tokens: fields.maxPrefillTokens,
    max_sample_tokens: fields.maxSampleTokens,
    max_train_tokens: fields.maxTrainTokens,
    manifest_commitment: fields.manifestCommitment,
    model: fields.model,
    operation: fields.operation,
    project_id: fields.projectId,
    project_reference: fields.projectReference,
    rate_policy_commitment: fields.ratePolicyCommitment,
    recipe: fields.recipe,
    result_policy: fields.resultPolicy,
    schema: "dnai.compute.dispatch-intent.v2",
    user: fields.user,
    workload_commitment: fields.workloadCommitment,
    workload_id: fields.workloadId,
    workload_schema: fields.workloadSchema,
  });
  return sha256(ENCODER.encode(`${DISPATCH_INTENT_COMMITMENT_DOMAIN}${canonicalIntent}`));
}

export function computeStandaloneAuthorizationContextCommitment(
  fields: ComputeStandaloneAuthorizationContextFields,
): `sha256:${string}` {
  const bytes32 = /^0x(?!0{64}$)[0-9a-f]{64}$/;
  const address = /^0x[0-9a-f]{40}$/;
  if (
    !bytes32.test(fields.projectId)
    || !bytes32.test(fields.jobId)
    || !address.test(fields.user)
    || !address.test(fields.asset)
    || !bytes32.test(fields.ratePolicyCommitment)
    || !bytes32.test(fields.workloadCommitment)
    || !bytes32.test(fields.manifestCommitment)
    || fields.authorizationNonce < 0n
    || fields.authorizationNonce > MAX_UINT256
    || fields.maxAssetDebit < 1n
    || fields.maxAssetDebit > MAX_UINT256
    || !Number.isSafeInteger(fields.authorizationExpiry)
    || fields.authorizationExpiry < 1
    || fields.authorizationExpiry > 4_102_444_800
  ) {
    throw new Error("Standalone authorization context is not canonical");
  }
  const canonicalContext = canonicalComputeJson({
    asset: fields.asset,
    authorization_expiry: fields.authorizationExpiry,
    authorization_nonce: fields.authorizationNonce,
    authorization_scope: "compute_credit_vault_job",
    chain_id: 84_532,
    job_id: fields.jobId,
    manifest_commitment: fields.manifestCommitment,
    max_asset_debit: fields.maxAssetDebit,
    project_id: fields.projectId,
    rate_policy_commitment: fields.ratePolicyCommitment,
    schema: "dnai.compute.standalone-authorization-context.v1",
    user: fields.user,
    workload_commitment: fields.workloadCommitment,
  });
  const digest = sha256(
    ENCODER.encode(`${STANDALONE_AUTHORIZATION_CONTEXT_DOMAIN}${canonicalContext}`),
  );
  return `sha256:${digest.slice(2)}`;
}

export function computeCollaborationOneShotAuthorizationContextCommitment(
  fields: ComputeCollaborationOneShotAuthorizationContextFields,
): `sha256:${string}` {
  const bytes32 = /^0x(?!0{64}$)[0-9a-f]{64}$/;
  const address = /^0x[0-9a-f]{40}$/;
  const sha256Commitment = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
  if (
    !sha256Commitment.test(fields.collaborationExecutionBasisCommitment)
    || !sha256Commitment.test(fields.collaborationExecutionGrantSetCommitment)
    || !bytes32.test(fields.projectId)
    || !bytes32.test(fields.jobId)
    || !address.test(fields.user)
    || !address.test(fields.asset)
    || !bytes32.test(fields.ratePolicyCommitment)
    || !bytes32.test(fields.workloadCommitment)
    || !bytes32.test(fields.manifestCommitment)
    || fields.authorizationNonce < 0n
    || fields.authorizationNonce > MAX_UINT256
    || fields.maxAssetDebit < 1n
    || fields.maxAssetDebit > MAX_UINT256
    || !Number.isSafeInteger(fields.authorizationExpiry)
    || fields.authorizationExpiry < 1
    || fields.authorizationExpiry > 4_102_444_800
  ) {
    throw new Error("Collaboration one-shot authorization context is not canonical");
  }
  const canonicalContext = canonicalComputeJson({
    asset: fields.asset,
    authorization_expiry: fields.authorizationExpiry,
    authorization_nonce: fields.authorizationNonce,
    authorization_scope: "compute_credit_vault_job",
    chain_id: 84_532,
    collaboration_execution_basis_commitment: (
      fields.collaborationExecutionBasisCommitment
    ),
    collaboration_execution_grant_set_commitment: (
      fields.collaborationExecutionGrantSetCommitment
    ),
    job_id: fields.jobId,
    manifest_commitment: fields.manifestCommitment,
    max_asset_debit: fields.maxAssetDebit,
    project_id: fields.projectId,
    rate_policy_commitment: fields.ratePolicyCommitment,
    schema: "dnai.compute.collaboration-one-shot-authorization-context.v1",
    user: fields.user,
    workload_commitment: fields.workloadCommitment,
  });
  const digest = sha256(
    ENCODER.encode(
      `${COLLABORATION_ONE_SHOT_AUTHORIZATION_CONTEXT_DOMAIN}${canonicalContext}`,
    ),
  );
  return `sha256:${digest.slice(2)}`;
}

export function computeDispatchIntentV3Commitment(
  fields: ComputeDispatchIntentV3CommitmentFields,
): `0x${string}` {
  const sha256Commitment = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
  if (
    (fields.workloadSourceKind !== "wallet" && fields.workloadSourceKind !== "credential")
    || (fields.authorizationKind !== "standalone"
      && fields.authorizationKind !== "collaboration_one_shot")
    || !sha256Commitment.test(fields.workloadExecutionBindingCommitment)
    || !sha256Commitment.test(fields.workloadRecipientReleaseCommitment)
    || !sha256Commitment.test(fields.authorizationContextCommitment)
  ) {
    throw new Error("Dispatch workload authority is not canonical");
  }
  const canonicalIntent = canonicalComputeJson({
    asset: fields.asset,
    authorization_context_commitment: fields.authorizationContextCommitment,
    authorization_expiry: fields.authorizationExpiry,
    authorization_kind: fields.authorizationKind,
    authorization_nonce: fields.authorizationNonce,
    compose_hash: fields.composeHash,
    job_id: fields.jobId,
    job_reference: fields.jobReference,
    max_asset_debit: fields.maxAssetDebit,
    max_prefill_tokens: fields.maxPrefillTokens,
    max_sample_tokens: fields.maxSampleTokens,
    max_train_tokens: fields.maxTrainTokens,
    manifest_commitment: fields.manifestCommitment,
    model: fields.model,
    operation: fields.operation,
    project_id: fields.projectId,
    project_reference: fields.projectReference,
    rate_policy_commitment: fields.ratePolicyCommitment,
    recipe: fields.recipe,
    result_policy: fields.resultPolicy,
    schema: "dnai.compute.dispatch-intent.v3",
    user: fields.user,
    workload_commitment: fields.workloadCommitment,
    workload_execution_binding_commitment: fields.workloadExecutionBindingCommitment,
    workload_id: fields.workloadId,
    workload_recipient_release_commitment: fields.workloadRecipientReleaseCommitment,
    workload_schema: fields.workloadSchema,
    workload_source_kind: fields.workloadSourceKind,
  });
  return sha256(ENCODER.encode(`${DISPATCH_INTENT_COMMITMENT_DOMAIN}${canonicalIntent}`));
}
