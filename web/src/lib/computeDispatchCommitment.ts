import { sha256 } from "viem";

const ENCODER = new TextEncoder();
const MAX_UINT256 = (1n << 256n) - 1n;
const DISPATCH_INTENT_COMMITMENT_DOMAIN = "dnai-wikigen/compute-dispatch-intent/v1\0";

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
