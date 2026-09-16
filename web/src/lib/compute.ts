import { deployment } from "../config";
import {
  encodeAbiParameters,
  hashTypedData,
  keccak256,
  recoverAddress,
  recoverMessageAddress,
  sha256,
  stringToHex,
  type Address,
  type Hex,
} from "viem";
import { computeVaultJobId, computeVaultProjectId } from "./computeVault";
import {
  canonicalComputeJson,
  computeDispatchIntentV3Commitment,
  computeStandaloneAuthorizationContextCommitment,
} from "./computeDispatchCommitment";
import { publicErrorText } from "./errorText";

export {
  computeDispatchIntentCommitment,
  computeDispatchIntentV3Commitment,
  computeStandaloneAuthorizationContextCommitment,
  type ComputeDispatchIntentCommitmentFields,
  type ComputeDispatchIntentV3CommitmentFields,
} from "./computeDispatchCommitment";

const MAX_RESPONSE_BYTES = 512 * 1024;
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const RESOURCE_ID = /^[a-z][a-z0-9_]{2,63}$/;
const HEX_64 = /^[0-9a-f]{64}$/;
const COMPUTE_PROJECT_ID = /^prj_[0-9a-f]{24}$/;
const COMPUTE_JOB_ID = /^job_[0-9a-f]{24}$/;
const COMPUTE_LEDGER_TRANSACTION_ID = /^txn_[0-9a-f]{24}$/;
const COMPUTE_LEDGER_GENESIS_HASH = "0".repeat(64);
const COMPUTE_LEDGER_MAX_SEQUENCE = 40_000;
const COMPUTE_LEDGER_MAX_TIMESTAMP = 4_102_444_800;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const NONZERO_BYTES32 = /^0x(?!0{64}$)[0-9a-f]{64}$/;
const CANONICAL_SIGNATURE = /^0x[0-9a-f]{130}$/;
const COMPUTE_REFERENCE = /^(?:0x(?!0{64}$)[0-9a-fA-F]{64}|[A-Za-z0-9][A-Za-z0-9._:-]{0,127})$/;
const DECIMAL_UINT256 = /^(?:0|[1-9][0-9]{0,77})$/;
const MAX_UINT256 = (1n << 256n) - 1n;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/;
const COMPUTE_JOB_PUBLIC_LABEL = /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$/;
const WORKLOAD_ID = /^wrk_[0-9a-f]{32}$/;
const DISPATCH_MUTATION_ROUTE = "/compute/projects/{project_id}/dispatch-intents";
const DISPATCH_STATUS_ROUTE = "/compute/projects/{project_id}/dispatch-intents/{job_reference}";
const COMPUTE_USAGE_COMMITMENT_DOMAIN = "dnai-wikigen/compute-usage/v1\0";
const COMPUTE_CANCELLATION_CHECKPOINT_DOMAIN =
  "dnai-wikigen/compute-dispatch-cancellation/v1\0";
const COMPUTE_VAULT_EIP712_NAME = "DNAI Compute Credit Vault";
const COMPUTE_VAULT_EIP712_VERSION = "2";
const COMPUTE_VAULT_CHAIN_ID = 84_532;
const COMPUTE_METERED_USAGE_TYPE = "ComputeMeteredUsage(uint256 chainId,address verifyingContract,bytes32 projectId,bytes32 jobId,address user,address asset,uint256 authorizationNonce,uint256 maxAssetDebit,uint256 actualAssetDebit,uint256 authorizationExpiry,bytes32 ratePolicyCommitment,bytes32 workloadCommitment,bytes32 manifestCommitment,bytes32 dispatchIntentCommitment,address teeIdentity,bytes32 composeHash,bytes32 startCommitment,uint256 billableComputeUnits,uint256 usageStartedAt,uint256 usageEndedAt,bytes32 meteringPolicySetHash,bytes32 attestationEvidenceHash)";
const COMPUTE_METERING_RECEIPT_FIELDS = [
  { name: "projectId", type: "bytes32" },
  { name: "jobId", type: "bytes32" },
  { name: "user", type: "address" },
  { name: "asset", type: "address" },
  { name: "authorizationNonce", type: "uint256" },
  { name: "maxAssetDebit", type: "uint256" },
  { name: "actualAssetDebit", type: "uint256" },
  { name: "authorizationExpiry", type: "uint256" },
  { name: "ratePolicyCommitment", type: "bytes32" },
  { name: "workloadCommitment", type: "bytes32" },
  { name: "manifestCommitment", type: "bytes32" },
  { name: "dispatchIntentCommitment", type: "bytes32" },
  { name: "teeIdentity", type: "address" },
  { name: "composeHash", type: "bytes32" },
  { name: "startCommitment", type: "bytes32" },
  { name: "billableComputeUnits", type: "uint256" },
  { name: "usageStartedAt", type: "uint256" },
  { name: "usageEndedAt", type: "uint256" },
  { name: "usageCommitment", type: "bytes32" },
  { name: "meteringPolicySetHash", type: "bytes32" },
  { name: "attestationEvidenceHash", type: "bytes32" },
  { name: "receiptExpiry", type: "uint256" },
] as const;
const TINKER_PROVIDER_ADAPTER_ID = "tinker_sdk_0_22_7_at_most_once_v1";
const TINKER_PROVIDER_SDK_VERSION = "0.22.7";
const TINKER_PROVIDER_SDK_SOURCE_SHA256 = "sha256:3ab30e85f4d1ae21ab4a8b415d382e719decd3abb31e61f6e481e8e5296dac62";
const TINKER_PROVIDER_REQUEST_CONTRACT_SHA256 = "sha256:15f112c2e285ba2463d36fe32a47f78eda40f7ca81d7b49f6d51dc4378feef0d";
const TINKER_PROVIDER_BASE_URL_SHA256 = "sha256:e3ae09c22c856fa175bfbeded8819e1665f39c235869a15e3e0729bfb4f39533";
const TINKER_PROVIDER_RELEASE_SHA256 = "sha256:4264a2226ac9c850d8f053c98ac90d0f6dcbc58702919899384a9b2442b35631";
const TINKER_TOKENIZER_PATH = "/opt/dnai/qwen3-8b-tokenizer";
const TINKER_TOKENIZER_RELEASE_SHA256 = "sha256:d933156af48aa90a117025537b4291c2e72b62ad14ddcfa7d77f3258928cd2e0";
const COMPILED_RECIPE_POLICY_DOMAIN = "dnai-wikigen/compute-compiled-recipe/v1\0";
const EXECUTION_POLICY_CONTEXT_DOMAIN = "dnai-wikigen/compute-execution-policy-context/v1\0";
const SUPPORTED_SCOPES = new Set([
  "jobs:create",
  "jobs:read",
  "workloads:create",
  "workloads:delete",
  "challenge:submit",
  "submissions:read",
  "receipts:read",
]);

export type ProjectRole = "owner" | "admin" | "developer" | "viewer";
export type DeviceKind = "developer_device" | "ci_service" | "autonomous_agent";
export type ComputeScope = "jobs:create" | "jobs:read" | "workloads:create" | "workloads:delete" | "challenge:submit" | "submissions:read" | "receipts:read";
export const COMPUTE_PUBLIC_CREDENTIAL_SCOPES = ["jobs:create", "jobs:read", "workloads:create", "workloads:delete"] as const satisfies readonly ComputeScope[];
export type ComputeJobStatus = "queued" | "running" | "succeeded" | "failed" | "canceled";
export const COMPUTE_JOB_ENVIRONMENT_MARKER = "env_v1" as const;
export type ComputeDispatchStage =
  | "intent_created"
  | "start_prepared"
  | "start_broadcast"
  | "start_confirmed"
  | "provider_dispatching"
  | "provider_attempt_checkpointed"
  | "provider_outcome_ambiguous"
  | "usage_finalized"
  | "workload_released"
  | "metering_pending"
  | "metering_decided"
  | "settlement_prepared"
  | "settlement_broadcast"
  | "settled"
  | "blocked";

export interface ComputeProviderRuntimePresence {
  authenticated: true;
  fresh: true;
  process_presence_only: true;
  tdx_evidence: false;
  observed_at: number;
}

export interface ComputeProviderGuarantees {
  at_most_once_attempt_checkpoint: boolean;
  terminal_ambiguity_hold: boolean;
  ambiguous_outcome_ciphertext_retained: boolean;
}

export interface ComputeProviderCapabilityRelease {
  schema: "dnai.compute.provider-capability.v1";
  source_present: true;
  release_configured: boolean;
  provider_dispatch: boolean;
  allowed_operations: ["inference", "training"];
  allowed_result_policies: ["bounded_summary_receipt"];
  adapter_id: "tinker_sdk_0_22_7_at_most_once_v1";
  sdk_version: "0.22.7";
  sdk_source_sha256: string;
  request_contract_sha256: string;
  base_url_sha256: string;
  provider_release_sha256: string;
  idempotency_header_role: "request_commitment_only";
  idempotent_provider_replay_claimed: false;
  automatic_provider_redispatch: false;
  adapter_contract: ComputeProviderGuarantees;
  runtime_guarantees: ComputeProviderGuarantees;
  runtime?: ComputeProviderRuntimePresence;
  reason: string;
}

export interface ComputeProviderCapabilityUnavailable {
  schema: "dnai.compute.provider-capability.v1";
  source_present: true;
  release_configured: false;
  provider_dispatch: false;
  reason: "provider_capability_unavailable";
}

export type ComputeProviderCapability =
  | ComputeProviderCapabilityRelease
  | ComputeProviderCapabilityUnavailable;

export interface ComputeDispatchCapability {
  metadata_intent_creation: boolean;
  provider_dispatch: boolean;
  independent_metering: boolean;
  settlement: boolean;
  credential_workload_wallet_adoption: boolean;
  wallet_adoption_authority: "project_owner_admin_developer";
  wallet_source_transfer_supported: false;
  device_spending_authority: false;
  exact_asset_only: true;
  mutation_route: typeof DISPATCH_MUTATION_ROUTE | null;
  status_route_template: typeof DISPATCH_STATUS_ROUTE;
  status_recovery_by_job_reference: true;
  automatic_provider_redispatch: false;
  provider: ComputeProviderCapability;
  reason: string;
}

export interface ComputeFundingCapabilities {
  surface: "compute_funding_capabilities";
  schema_version: 1;
  card: { enabled: false; mutation_route: null; reason: string; card_data_accepted: false; distinct_from_exact_asset_capacity: true };
  usdc: { enabled: false; mutation_route: null; reason: string; capacity_model: "same_asset_nontransferable_vault_claim" };
  eth: { enabled: false; mutation_route: null; reason: string; capacity_model: "same_asset_nontransferable_vault_claim" };
  exact_asset_vault: {
    contract: "ComputeCreditVault";
    release_bound: true;
    review_status: "reviewed_and_extensively_tested_not_formally_audited";
    provider_dispatch_authoritative: false;
  };
  dispatch_intents: ComputeDispatchCapability;
  operator_testnet_grants: { enabled: boolean; auth: "configured_runtime_bearer"; cash_value: false };
  credits: {
    kind: "closed_loop_service_credit";
    transferable: false;
    redeemable: false;
    onchain_token: false;
    nominal_usd_cents_per_credit: 1;
    legacy_modeled_ledger: true;
    distinct_from_exact_asset_vault: true;
  };
}

export interface ComputeProject {
  project_id: string;
  name: string;
  role: ProjectRole;
  policy: {
    per_job_max_credits: number;
    daily_project_max_credits: number;
    credential_max_ttl_seconds: number;
    allowed_operations: ["inference", "training"] | string[];
  };
  members: { address: string; role: ProjectRole }[];
  created_at: number;
  updated_at: number;
  credit_instrument: "closed_loop_nontransferable_service_credit";
  provider_dispatch_enabled: boolean;
}

export interface ComputeDispatchIntentStatus {
  surface: "compute_dispatch_intent";
  schema_version: 3;
  project_reference: string;
  job_reference: string;
  project_id: `0x${string}`;
  job_id: `0x${string}`;
  user: `0x${string}`;
  asset: `0x${string}`;
  authorization_nonce: bigint;
  max_asset_debit: bigint;
  authorization_expiry: number;
  rate_policy_commitment: `0x${string}`;
  compose_hash: `0x${string}`;
  operation: "inference" | "training";
  model: "qwen3_8b";
  recipe: "qwen3_8b_bounded" | "qwen3_8b_lora_r32";
  result_policy: "bounded_summary_receipt" | "score_band_hash";
  resource_limits: {
    max_prefill_tokens: number;
    max_sample_tokens: number;
    max_train_tokens: number;
  };
  workload_id: string;
  workload_schema: "dnai.compute.workload.inference.v1" | "dnai.compute.workload.sft-jsonl.v1";
  manifest_commitment: `0x${string}`;
  workload_commitment: `0x${string}`;
  authorization: ComputeDispatchAuthorization;
  workload_authority: ComputeDispatchWorkloadAuthority;
  intent_commitment: `0x${string}`;
  execution_policy_context_hash: string;
  stage: ComputeDispatchStage;
  workload_claim_commitment: string;
  workload_claim_confirmed: true;
  provider_authoritative: false;
  legacy_credit_ledger_mutated: false;
  provider_dispatch_status:
    | "not_started"
    | "prepared"
    | "attempt_checkpointed"
    | "outcome_ambiguous"
    | "usage_finalized";
  provider_dispatch_may_have_occurred: boolean;
  provider_usage_finalized: boolean;
  idempotent_provider_replay_claimed: false;
  automatic_provider_redispatch: false;
  ambiguous_outcome_hold: boolean;
  bounded_result: ComputeBoundedResult | null;
  workload_ciphertext_released: boolean;
  workload_ciphertext_retained_for_reconciliation: boolean;
  raw_prompt_accepted: false;
  raw_examples_accepted: false;
  arbitrary_program_accepted: false;
  exact_timing_egress: false;
}

export interface ComputeDispatchAuthorization {
  kind: "standalone" | "collaboration_one_shot";
  context_commitment: string;
  server_derived: boolean;
}

export interface ComputeDispatchWorkloadAuthority {
  source_kind: "wallet" | "credential";
  execution_binding_commitment: string;
  recipient_release_commitment: string;
  funding_authority: "onchain_wallet_job";
  device_spending_authority: false;
}

export interface ComputeBoundedResult {
  schema: "dnai.compute.bounded-result.v1";
  result_policy: "bounded_summary_receipt" | "score_band_hash";
  operation: "inference" | "training";
  outcome: "succeeded" | "failed";
  result_class:
    | "completed_within_authorized_caps"
    | "provider_failed_without_raw_detail";
  result_commitment: `0x${string}`;
  commitment_scheme: "hmac-sha256-dstack-v1-over-dispatch-bound-private-result-and-canonical-bounded-projection";
  score_band_released: false;
  raw_prompt_egress: false;
  raw_examples_egress: false;
  raw_output_egress: false;
  provider_identifier_egress: false;
  exception_detail_egress: false;
}

export interface ComputeDispatchIntentInput {
  jobReference: string;
  workloadId: string;
  asset: string;
  authorizationNonce: bigint;
  maxAssetDebit: bigint;
  authorizationExpiry: number;
  ratePolicyCommitment: string;
  composeHash: string;
  operation: "inference" | "training";
  resultPolicy: "bounded_summary_receipt" | "score_band_hash";
  maxPrefillTokens: number;
  maxSampleTokens: number;
  maxTrainTokens: number;
}

export interface ComputeDispatchIntentResult {
  created: boolean;
  idempotentReplay: boolean;
  workloadClaimCreated: boolean;
  workloadClaimConfirmed: true;
  workloadClaimRecovered: boolean;
  workloadClaimCommitment: string;
  intent: ComputeDispatchIntentStatus;
}

export interface ComputeDispatchCancellationReceipt {
  surface: "compute_dispatch_cancellation";
  schema_version: 2;
  project_reference: string;
  job_reference: string;
  project_id: `0x${string}`;
  job_id: `0x${string}`;
  intent_commitment: `0x${string}`;
  authorization: Omit<ComputeDispatchAuthorization, "server_derived">;
  workload_authority: ComputeDispatchWorkloadAuthority & { funding_wallet: Address };
  workload_claim_commitment: string;
  workload_claim_confirmed: true;
  cancellation_checkpoint_commitment: string;
  canceled_at: number;
  journal_execution_prevented: true;
  provider_dispatch_performed: false;
  provider_dispatch_may_have_occurred: false;
  workload_ciphertext_released: true;
  vault_authorization_released: false;
  onchain_cancel_required: true;
  exact_asset_capacity_released: false;
  provider_authoritative: false;
  legacy_credit_ledger_mutated: false;
  raw_secret_egress: false;
  changed: boolean;
  idempotent_replay: boolean;
}

export interface ComputeDispatchCancellationAttempt {
  schema: "dnai.compute.browser-dispatch-cancellation-attempt.v1";
  schema_version: 1;
  project_reference: string;
  job_reference: string;
  project_id: `0x${string}`;
  job_id: `0x${string}`;
  user: Address;
  wallet_address: Address;
  intent_commitment: `0x${string}`;
  workload_id: string;
  workload_commitment: `0x${string}`;
  authorization: ComputeDispatchAuthorization;
  workload_authority: ComputeDispatchWorkloadAuthority;
  workload_claim_commitment: string;
  idempotency_key: string;
}

type ComputeDispatchCancellationBinding = Pick<
  ComputeDispatchCancellationAttempt,
  | "project_reference"
  | "job_reference"
  | "project_id"
  | "job_id"
  | "user"
  | "intent_commitment"
  | "workload_id"
  | "workload_commitment"
  | "authorization"
  | "workload_authority"
  | "workload_claim_commitment"
>;

export interface ComputeTinkerProviderRelease {
  schema: "dnai.compute.tinker-provider-release.v1";
  adapter_id: "tinker_sdk_0_22_7_at_most_once_v1";
  sdk_version: "0.22.7";
  sdk_source_sha256: string;
  request_contract_sha256: string;
  base_url_sha256: string;
  tokenizer_path: "/opt/dnai/qwen3-8b-tokenizer";
  tokenizer_release_sha256: string;
  idempotency_header_role: "request_commitment_only";
  idempotent_provider_replay_claimed: false;
  automatic_provider_redispatch: false;
  at_most_once_attempt_checkpoint: true;
  terminal_ambiguity_hold: true;
  ambiguous_outcome_ciphertext_retained: true;
  provider_authoritative_invoice: false;
  raw_secret_egress: false;
}

export interface ComputeProviderUsageEvidence {
  outcome: "succeeded" | "failed";
  prefill_tokens: number;
  sample_tokens: number;
  training_tokens: number;
  result_commitment: `0x${string}`;
  provider_authoritative_invoice: false;
}

export interface ComputeSignedUsageEvidence {
  schema: "dnai.compute-metering-request.v2";
  block: {
    number: number;
    hash: `0x${string}`;
  };
  usage: {
    schema: "dnai.compute-usage-envelope.v2";
    job_id: `0x${string}`;
    project_id: `0x${string}`;
    user: Address;
    asset: Address;
    authorization_nonce: string;
    max_asset_debit: string;
    authorization_expiry: number;
    rate_policy_commitment: `0x${string}`;
    workload_commitment: `0x${string}`;
    manifest_commitment: `0x${string}`;
    dispatch_intent_commitment: `0x${string}`;
    tee_identity: Address;
    compose_hash: `0x${string}`;
    start_commitment: `0x${string}`;
    model: "qwen3_8b";
    recipe: "qwen3_8b_bounded" | "qwen3_8b_lora_r32";
    outcome: "succeeded" | "failed";
    prefill_tokens: string;
    sample_tokens: string;
    training_tokens: string;
    usage_started_at: number;
    usage_observed_at: number;
    raw_secret_egress: false;
    usage_commitment: `0x${string}`;
    tee_signature: Hex;
  };
}

export interface ComputeIndependentMeteringEvidence {
  schema: "dnai.compute-metering-decision.v2";
  classification: "attested_dual_verified_metering";
  provider_authoritative_invoice: false;
  chain_id: 84_532;
  vault_address: Address;
  pinned_block_number: number;
  pinned_block_hash: `0x${string}`;
  policy_set_hash: `0x${string}`;
  rate_policy_commitment: `0x${string}`;
  workload_commitment: `0x${string}`;
  manifest_commitment: `0x${string}`;
  dispatch_intent_commitment: `0x${string}`;
  asset: Address;
  job_id: `0x${string}`;
  usage_commitment: `0x${string}`;
  onchain_usage_commitment: `0x${string}`;
  actual_asset_debit: bigint;
  billable_compute_units: bigint;
  usage_started_at: number;
  usage_ended_at: number;
  attestation_evidence_hash: `0x${string}`;
  receipt_expiry: number;
  metering_receipt_digest: `0x${string}`;
  metering_qvl_receipt_digest: `0x${string}`;
  metering_verifier: Address;
  metering_qvl_verifier: Address;
  tee_identity: Address;
  compose_hash: `0x${string}`;
  raw_secret_egress: false;
  verifier_signature: Hex;
  qvl_signature: Hex;
}

export interface ComputeExactAssetUsageReceipt {
  surface: "compute_exact_asset_usage_receipt";
  schema_version: 2;
  access: "wallet_authenticated_project_member";
  project_reference: string;
  job_reference: string;
  project_id: `0x${string}`;
  job_id: `0x${string}`;
  intent_commitment: `0x${string}`;
  authorization: Omit<ComputeDispatchAuthorization, "server_derived">;
  workload_authority: ComputeDispatchWorkloadAuthority & { funding_wallet: Address };
  workload_claim_commitment: string;
  workload_claim_confirmed: true;
  execution_policy_context_hash: string;
  provider_release_sha256: string;
  provider_release: ComputeTinkerProviderRelease;
  provider_usage: ComputeProviderUsageEvidence;
  bounded_result: ComputeBoundedResult;
  signed_usage: ComputeSignedUsageEvidence;
  independent_metering: ComputeIndependentMeteringEvidence;
  settlement: {
    confirmed: true;
    chain_id: 84_532;
    vault_address: Address;
    transaction_hash: `0x${string}`;
    onchain_usage_commitment: `0x${string}`;
    actual_asset_debit: bigint;
    billable_compute_units: bigint;
    attestation_evidence_hash: `0x${string}`;
    receipt_expiry: number;
  };
  provider_authoritative_invoice: false;
  exact_asset_only: true;
  legacy_credit_ledger_mutated: false;
  raw_prompt_egress: false;
  raw_examples_egress: false;
  raw_output_egress: false;
  provider_identifier_egress: false;
  raw_transaction_egress: false;
  browser_verification: {
    usage_commitment_rederived: true;
    tee_signature_recovered: true;
    onchain_usage_commitment_rederived: true;
    metering_receipt_digest_rederived: true;
    metering_qvl_receipt_digest_rederived: true;
    metering_eoa_signature_recovered: true;
    metering_qvl_eoa_signature_recovered: true;
    erc1271_contract_signature_checked: false;
    release_state_anchored_in_browser: false;
  };
}

export interface ComputeExecutionPolicyTarget {
  resourceId: `0x${string}`;
  executionContextHash: string;
  authorizedUser: `0x${string}`;
}

export interface ComputeDevice {
  device_id: string;
  project_id: string;
  label: string;
  kind: DeviceKind;
  public_key_hash: string;
  status: "active" | "revoked";
  registered_at: number;
  revoked_at: number | null;
  binding: "encrypted_delivery_only_not_hardware_attestation";
  public_key_returned: false;
}

export interface ComputeCredential {
  credential_id: string;
  project_id: string;
  device_id: string;
  name: string;
  prefix: string;
  scopes: ComputeScope[];
  daily_credit_cap: number;
  generation: number;
  status: "active" | "expired" | "revoked";
  issued_at: number;
  expires_at: number;
  last_used_at: number | null;
  rotated_at: number | null;
  revoked_at: number | null;
  plaintext_token_stored: false;
  upstream_tinker_key_exposed: false;
}

export interface ComputeBalance {
  surface: "compute_credit_balance";
  schema_version: 1;
  project_id: string;
  available_credits: number;
  reserved_credits: number;
  total_service_credits: number;
  unit: "service_credit";
  nominal_usd_cents_per_credit: 1;
  transferable: false;
  redeemable: false;
  onchain_token: false;
}

export type ComputeLedgerKind =
  | "testnet_grant"
  | "job_reserve"
  | "job_settle"
  | "job_release"
  | "job_cancel";

export type ComputeLedgerAuthority =
  | "operator_runtime"
  | "wallet"
  | "credential"
  | "project_wallet_owner"
  | "project_wallet_admin"
  | "project_wallet_developer";

export type ComputeLedgerSettlementStatus =
  | "operator_testnet_only"
  | "reserved"
  | "provisional_internal_metering"
  | "released_without_service_settlement"
  | "user_canceled_before_dispatch";

export interface ComputeLedgerTransaction {
  transaction_id: string;
  sequence: number;
  kind: ComputeLedgerKind;
  project_id: string;
  job_id: string | null;
  amount_credits: number;
  postings: { account: string; delta: number }[];
  authority: ComputeLedgerAuthority;
  created_at: number;
  settlement_status: ComputeLedgerSettlementStatus;
  transaction_hash: string;
  previous_hash: string;
}

export interface ComputeLedger {
  surface: "compute_ledger";
  schema_version: 1;
  project_id: string;
  balance: ComputeBalance;
  transactions: ComputeLedgerTransaction[];
  append_only: true;
  double_entry: true;
  currency: "service_credit";
  transferable: false;
  redeemable: false;
}

export type ComputeLedgerAdjacencyState =
  | "genesis"
  | "visible_link"
  | "interleaved_global"
  | "outside_view"
  | "invalid";

export function computeLedgerAdjacency(
  newer: ComputeLedgerTransaction,
  older?: ComputeLedgerTransaction,
): ComputeLedgerAdjacencyState {
  if (newer.sequence === 1) {
    return older === undefined && newer.previous_hash === COMPUTE_LEDGER_GENESIS_HASH
      ? "genesis"
      : "invalid";
  }
  if (newer.previous_hash === COMPUTE_LEDGER_GENESIS_HASH) return "invalid";
  if (older === undefined) return "outside_view";
  if (newer.sequence === older.sequence + 1) {
    return newer.previous_hash === older.transaction_hash ? "visible_link" : "invalid";
  }
  return newer.sequence > older.sequence + 1 ? "interleaved_global" : "invalid";
}

export interface ComputeJob {
  job_id: string;
  project_id: string;
  name: string;
  operation: "inference" | "training";
  model: "qwen3_8b";
  recipe: "qwen3_8b_bounded" | "qwen3_8b_lora_r32";
  max_credits: number;
  actual_credits: number | null;
  released_credits: number | null;
  result_policy: "bounded_summary_receipt" | "score_band_hash";
  environment_version: string;
  status: ComputeJobStatus;
  dispatch_status: "not_dispatched";
  backend_capability: "existing_tinker_training_proxy" | "future_inference_proxy";
  credential_id: string | null;
  created_at: number;
  updated_at: number;
  started_at: number | null;
  completed_at: number | null;
  metering_source: string | null;
  usage_receipt_hash: string | null;
  settlement_authority: string | null;
  provider_authoritative_settlement: false;
  raw_input_persisted: false;
  raw_output_persisted: false;
}

export interface ComputeJobCreateInput {
  name: string;
  operation: "inference" | "training";
  maxCredits: number;
  resultPolicy: "bounded_summary_receipt" | "score_band_hash";
  environmentVersion: typeof COMPUTE_JOB_ENVIRONMENT_MARKER;
}

export interface ComputeJobCreateResult {
  created: boolean;
  idempotentReplay: boolean;
  job: ComputeJob;
}

export interface ComputeJobCancellationReceipt {
  surface: "compute_job_cancellation";
  schema_version: 1;
  project_id: string;
  job_id: string;
  status: "canceled";
  changed: boolean;
  idempotent_replay: boolean;
  released_credits: number;
  credit_reversal: "reserved_to_available";
  ledger: {
    transaction_id: string;
    sequence: number;
    kind: "job_cancel";
    transaction_hash: string;
    previous_hash: string;
    settlement_status: "user_canceled_before_dispatch";
  };
  provider_dispatch_performed: false;
  service_settlement_performed: false;
}

export interface DeviceKeyMaterial {
  publicKeyHex: string;
  privateKey: CryptoKey;
}

interface ComputeCapsule {
  delivery: "x25519_aes_256_gcm_envelope";
  encrypted_token: {
    ephemeral_public_key: string;
    nonce: string;
    ciphertext: string;
  };
  associated_data: string;
  associated_data_hash: string;
  recipient_public_key_hash: string;
  plaintext_token_returned: false;
}

export interface ComputeCredentialDelivery {
  credential: ComputeCredential;
  capsule: ComputeCapsule;
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} is not an object`);
  return value as Record<string, unknown>;
}

function integer(value: unknown, label: string, minimum = 0, maximum = Number.MAX_SAFE_INTEGER): number {
  if (!Number.isSafeInteger(value) || Number(value) < minimum || Number(value) > maximum) {
    throw new Error(`${label} is outside the supported range`);
  }
  return Number(value);
}

function text(value: unknown, label: string, maximum = 256): string {
  if (typeof value !== "string" || value.length < 1 || encoder.encode(value).byteLength > maximum) {
    throw new Error(`${label} is malformed`);
  }
  return value;
}

function exactKeys(value: Record<string, unknown>, label: string, expected: readonly string[]): void {
  const actual = Object.keys(value).sort();
  const keys = [...expected].sort();
  if (actual.length !== keys.length || actual.some((key, index) => key !== keys[index])) {
    throw new Error(`${label} contains unsupported fields`);
  }
}

function boolean(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") throw new Error(`${label} is malformed`);
  return value;
}

export function parseDispatchUint256(value: unknown, label = "uint256"): bigint {
  const normalized = typeof value === "number"
    ? Number.isSafeInteger(value) && value >= 0 ? String(value) : ""
    : typeof value === "bigint"
      ? value >= 0n ? value.toString() : ""
      : typeof value === "string" ? value : "";
  if (!DECIMAL_UINT256.test(normalized)) throw new Error(`${label} is not a canonical uint256`);
  const parsed = BigInt(normalized);
  if (parsed > MAX_UINT256) throw new Error(`${label} exceeds uint256`);
  return parsed;
}

function computeCompiledRecipePolicyCommitment(
  operation: string,
  model: string,
  recipe: string,
): `0x${string}` {
  const policy = operation === "inference" && model === "qwen3_8b" && recipe === "qwen3_8b_bounded"
    ? {
        allowed_result_policies: ["bounded_summary_receipt", "score_band_hash"],
        arbitrary_program_api: false,
        max_prefill_tokens: 32_768,
        max_sample_tokens: 4_096,
        max_train_tokens: 0,
        model,
        operation,
        raw_examples_api: false,
        raw_prompt_api: false,
        recipe,
        schema: "dnai.compute.compiled-recipe-policy.v1",
      }
    : operation === "training" && model === "qwen3_8b" && recipe === "qwen3_8b_lora_r32"
      ? {
          allowed_result_policies: ["bounded_summary_receipt", "score_band_hash"],
          arbitrary_program_api: false,
          max_prefill_tokens: 0,
          max_sample_tokens: 0,
          max_train_tokens: 10_000_000,
          model,
          operation,
          raw_examples_api: false,
          raw_prompt_api: false,
          recipe,
          schema: "dnai.compute.compiled-recipe-policy.v1",
        }
      : undefined;
  if (!policy) throw new Error("Compute execution policy recipe is not release-pinned");
  return sha256(encoder.encode(
    `${COMPILED_RECIPE_POLICY_DOMAIN}${canonicalComputeJson(policy)}`,
  ));
}

export function computeExecutionPolicyContextHash(input: {
  jobId: `0x${string}`;
  intentCommitment: `0x${string}`;
  operation: string;
  model: string;
  recipe: string;
}): string {
  const payload = canonicalComputeJson({
    intent_commitment: input.intentCommitment,
    job_id: input.jobId,
    recipe_policy_commitment: computeCompiledRecipePolicyCommitment(
      input.operation,
      input.model,
      input.recipe,
    ),
    schema: "dnai.compute.execution-policy-context.v1",
  });
  return sha256(encoder.encode(`${EXECUTION_POLICY_CONTEXT_DOMAIN}${payload}`)).slice(2);
}

function parseJsonWithoutPrecisionLoss(raw: string): unknown {
  let index = 0;
  let transformed = "";
  while (index < raw.length) {
    if (raw[index] === '"') {
      const start = index;
      index += 1;
      let escaped = false;
      while (index < raw.length) {
        const character = raw[index];
        index += 1;
        if (escaped) {
          escaped = false;
        } else if (character === "\\") {
          escaped = true;
        } else if (character === '"') {
          break;
        }
      }
      transformed += raw.slice(start, index);
      continue;
    }
    const remainder = raw.slice(index);
    const numeric = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(remainder)?.[0];
    if (numeric) {
      if (!/[.eE]/.test(numeric)) {
        if (numeric.length > 80) {
          transformed += JSON.stringify(numeric);
          index += numeric.length;
          continue;
        }
        try {
          const candidate = BigInt(numeric);
          if (candidate > BigInt(Number.MAX_SAFE_INTEGER) || candidate < BigInt(Number.MIN_SAFE_INTEGER)) {
            transformed += JSON.stringify(numeric);
            index += numeric.length;
            continue;
          }
        } catch {
          throw new Error("Compute service returned malformed JSON");
        }
      }
      transformed += numeric;
      index += numeric.length;
      continue;
    }
    transformed += raw[index];
    index += 1;
  }
  return JSON.parse(transformed);
}

function assertNoSensitiveFields(value: unknown): void {
  const forbidden = new Set([
    "card_number", "cvc", "cvv", "prompt", "prompts", "training_examples",
    "raw_input", "raw_output", "upstream_api_key", "upstream_tinker_key", "private_key",
    "plaintext_token", "wallet_signing_key", "runtime_bearer",
  ]);
  const pending: unknown[] = [value];
  let containers = 0;
  while (pending.length > 0) {
    const current = pending.pop();
    if (!current || typeof current !== "object") continue;
    containers += 1;
    if (containers > 16_384) throw new Error("Compute response contains too many nested containers");
    if (Array.isArray(current)) {
      pending.push(...current);
      continue;
    }
    for (const [key, nested] of Object.entries(current as Record<string, unknown>)) {
      if (forbidden.has(key)) throw new Error(`Compute response contains forbidden field ${key}`);
      pending.push(nested);
    }
  }
}

async function readBoundedResponseText(response: Response): Promise<string> {
  const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
  if (!contentType.includes("application/json")) {
    throw new Error("Compute service did not return application/json");
  }
  const declared = Number(response.headers.get("content-length") ?? 0);
  if (Number.isFinite(declared) && declared > MAX_RESPONSE_BYTES) {
    throw new Error("Compute response exceeded the public size limit");
  }
  if (!response.body) throw new Error("Compute service returned an empty response");

  const reader = response.body.getReader();
  const streamDecoder = new TextDecoder("utf-8", { fatal: true });
  let body = "";
  let received = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      received += value.byteLength;
      if (received > MAX_RESPONSE_BYTES) {
        await reader.cancel();
        throw new Error("Compute response exceeded the public size limit");
      }
      body += streamDecoder.decode(value, { stream: true });
    }
    body += streamDecoder.decode();
    return body;
  } finally {
    reader.releaseLock();
  }
}

function baseUrl(): string {
  if (!deployment.delegateUrl) throw new Error("Fresh delegate endpoint is not configured");
  return deployment.delegateUrl.replace(/\/$/, "");
}

async function request(
  path: string,
  options: { method?: "GET" | "POST" | "DELETE"; token?: string; body?: unknown; idempotencyKey?: string; timeout?: number } = {},
): Promise<unknown> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (options.token) headers.Authorization = `Bearer ${options.token}`;
  if (options.body !== undefined) headers["Content-Type"] = "application/json";
  if (options.idempotencyKey) headers["Idempotency-Key"] = options.idempotencyKey;
  const response = await fetch(`${baseUrl()}${path}`, {
    method: options.method ?? "GET",
    credentials: "omit",
    cache: "no-store",
    redirect: "error",
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
    signal: AbortSignal.timeout(options.timeout ?? 12_000),
  });
  const raw = await readBoundedResponseText(response);
  let value: unknown;
  try {
    value = parseJsonWithoutPrecisionLoss(raw);
  } catch {
    throw new Error("Compute service returned malformed JSON");
  }
  if (!response.ok) {
    const body = value && typeof value === "object" && "detail" in value ? (value as { detail: unknown }).detail : undefined;
    const fallback = `Request failed with status ${response.status}`;
    throw new Error(publicErrorText(typeof body === "string" ? body : fallback, fallback));
  }
  assertNoSensitiveFields(value);
  return value;
}

function assertProject(value: unknown): asserts value is ComputeProject {
  const project = record(value, "Compute project");
  const policy = record(project.policy, "Compute project policy");
  if (
    !RESOURCE_ID.test(text(project.project_id, "project_id", 64))
    || !["owner", "admin", "developer", "viewer"].includes(String(project.role))
    || project.credit_instrument !== "closed_loop_nontransferable_service_credit"
    || typeof project.provider_dispatch_enabled !== "boolean"
    || !Array.isArray(project.members)
    || project.members.length > 64
    || !Array.isArray(policy.allowed_operations)
    || policy.allowed_operations.join(",") !== "inference,training"
  ) throw new Error("Compute project failed its bounded schema checks");
  integer(policy.per_job_max_credits, "per-job credit cap", 1, 500);
  integer(policy.daily_project_max_credits, "daily project cap", 1, 2_500);
  integer(policy.credential_max_ttl_seconds, "credential lifetime", 60, 604_800);
  for (const memberValue of project.members) {
    const member = record(memberValue, "project member");
    if (!/^0x[0-9a-fA-F]{40}$/.test(String(member.address)) || !["owner", "admin", "developer", "viewer"].includes(String(member.role))) {
      throw new Error("Compute project member is malformed");
    }
  }
}

function assertDevice(value: unknown): asserts value is ComputeDevice {
  const device = record(value, "Compute device");
  if (
    !RESOURCE_ID.test(String(device.device_id))
    || !RESOURCE_ID.test(String(device.project_id))
    || !["developer_device", "ci_service", "autonomous_agent"].includes(String(device.kind))
    || !["active", "revoked"].includes(String(device.status))
    || device.binding !== "encrypted_delivery_only_not_hardware_attestation"
    || device.public_key_returned !== false
    || !HEX_64.test(String(device.public_key_hash))
  ) throw new Error("Compute device failed its bounded schema checks");
}

function assertCredential(value: unknown): asserts value is ComputeCredential {
  const credential = record(value, "Compute credential");
  if (
    !RESOURCE_ID.test(String(credential.credential_id))
    || !RESOURCE_ID.test(String(credential.project_id))
    || !RESOURCE_ID.test(String(credential.device_id))
    || !Array.isArray(credential.scopes)
    || credential.scopes.length < 1
    || credential.scopes.length > 5
    || credential.scopes.some((scope) => typeof scope !== "string" || !SUPPORTED_SCOPES.has(scope))
    || !["active", "expired", "revoked"].includes(String(credential.status))
    || credential.plaintext_token_stored !== false
    || credential.upstream_tinker_key_exposed !== false
  ) throw new Error("Compute credential failed its bounded schema checks");
}

function assertBalance(value: unknown, projectId?: string): asserts value is ComputeBalance {
  const balance = record(value, "Compute balance");
  exactKeys(balance, "Compute balance", [
    "surface",
    "schema_version",
    "project_id",
    "available_credits",
    "reserved_credits",
    "total_service_credits",
    "unit",
    "nominal_usd_cents_per_credit",
    "transferable",
    "redeemable",
    "onchain_token",
  ]);
  if (
    balance.surface !== "compute_credit_balance"
    || balance.schema_version !== 1
    || typeof balance.project_id !== "string"
    || !COMPUTE_PROJECT_ID.test(balance.project_id)
    || (projectId !== undefined && balance.project_id !== projectId)
    || balance.unit !== "service_credit"
    || balance.nominal_usd_cents_per_credit !== 1
    || balance.transferable !== false
    || balance.redeemable !== false
    || balance.onchain_token !== false
  ) throw new Error("Compute balance failed its bounded schema checks");
  const available = integer(balance.available_credits, "available credits", 0, 10_000_000);
  const reserved = integer(balance.reserved_credits, "reserved credits", 0, 10_000_000);
  if (integer(balance.total_service_credits, "total credits", 0, 10_000_000) !== available + reserved) {
    throw new Error("Compute balance does not reconcile");
  }
}

function parseComputeLedgerPostings(
  value: unknown,
  projectId: string,
): { account: string; delta: number }[] {
  if (!Array.isArray(value) || value.length < 2 || value.length > 3) {
    throw new Error("Compute ledger postings are malformed");
  }
  const supportedAccounts = new Set([
    `project:${projectId}:available`,
    `project:${projectId}:reserved`,
    "system:testnet_grant_pool",
    "system:service_revenue",
  ]);
  const seenAccounts = new Set<string>();
  const postings = value.map((item) => {
    const posting = record(item, "Compute ledger posting");
    exactKeys(posting, "Compute ledger posting", ["account", "delta"]);
    const account = text(posting.account, "Compute ledger account", 96);
    if (!supportedAccounts.has(account) || seenAccounts.has(account)) {
      throw new Error("Compute ledger account is unsupported or duplicated");
    }
    seenAccounts.add(account);
    return {
      account,
      delta: integer(posting.delta, "Compute ledger posting delta", -10_000_000, 10_000_000),
    };
  });
  if (postings.reduce((sum, posting) => sum + posting.delta, 0) !== 0) {
    throw new Error("Compute ledger transaction does not balance");
  }
  return postings;
}

function ledgerPostingDelta(
  postings: readonly { account: string; delta: number }[],
  account: string,
): number | undefined {
  return postings.find((posting) => posting.account === account)?.delta;
}

function assertComputeLedgerTransactionSemantics(transaction: ComputeLedgerTransaction): void {
  const availableAccount = `project:${transaction.project_id}:available`;
  const reservedAccount = `project:${transaction.project_id}:reserved`;
  const available = ledgerPostingDelta(transaction.postings, availableAccount);
  const reserved = ledgerPostingDelta(transaction.postings, reservedAccount);
  const grantPool = ledgerPostingDelta(transaction.postings, "system:testnet_grant_pool");
  const serviceRevenue = ledgerPostingDelta(transaction.postings, "system:service_revenue");

  if (transaction.kind === "testnet_grant") {
    if (
      transaction.job_id !== null
      || transaction.authority !== "operator_runtime"
      || transaction.settlement_status !== "operator_testnet_only"
      || transaction.amount_credits < 1
      || transaction.amount_credits > 1_000_000
      || transaction.postings.length !== 2
      || available !== transaction.amount_credits
      || grantPool !== -transaction.amount_credits
    ) throw new Error("Compute testnet grant transaction is inconsistent");
    return;
  }

  if (transaction.job_id === null || !COMPUTE_JOB_ID.test(transaction.job_id)) {
    throw new Error("Compute ledger job reference is malformed");
  }

  if (transaction.kind === "job_reserve") {
    if (
      !["wallet", "credential"].includes(transaction.authority)
      || transaction.settlement_status !== "reserved"
      || transaction.amount_credits < 1
      || transaction.amount_credits > 500
      || transaction.postings.length !== 2
      || available !== -transaction.amount_credits
      || reserved !== transaction.amount_credits
    ) throw new Error("Compute reservation transaction is inconsistent");
    return;
  }

  if (transaction.kind === "job_settle") {
    const reservedDebit = reserved === undefined ? 0 : -reserved;
    if (
      transaction.authority !== "operator_runtime"
      || transaction.settlement_status !== "provisional_internal_metering"
      || transaction.amount_credits < 0
      || transaction.amount_credits > 500
      || transaction.postings.length !== 3
      || reservedDebit < 1
      || reservedDebit > 500
      || serviceRevenue !== transaction.amount_credits
      || available === undefined
      || available < 0
      || available > 500
      || reservedDebit !== transaction.amount_credits + available
    ) throw new Error("Compute settlement transaction is inconsistent");
    return;
  }

  const expectedStatus = transaction.kind === "job_release"
    ? "released_without_service_settlement"
    : "user_canceled_before_dispatch";
  const expectedAuthorities: readonly ComputeLedgerAuthority[] = transaction.kind === "job_release"
    ? ["operator_runtime"]
    : ["project_wallet_owner", "project_wallet_admin", "project_wallet_developer"];
  if (
    !expectedAuthorities.includes(transaction.authority)
    || transaction.settlement_status !== expectedStatus
    || transaction.amount_credits < 1
    || transaction.amount_credits > 500
    || transaction.postings.length !== 2
    || reserved !== -transaction.amount_credits
    || available !== transaction.amount_credits
  ) throw new Error("Compute release transaction is inconsistent");
}

function parseComputeLedgerTransaction(
  value: unknown,
  projectId: string,
): ComputeLedgerTransaction {
  const transaction = record(value, "Compute ledger transaction");
  exactKeys(transaction, "Compute ledger transaction", [
    "transaction_id",
    "sequence",
    "kind",
    "project_id",
    "job_id",
    "amount_credits",
    "postings",
    "authority",
    "created_at",
    "settlement_status",
    "transaction_hash",
    "previous_hash",
  ]);

  const transactionId = text(transaction.transaction_id, "Compute ledger transaction ID", 64);
  const kindValue = text(transaction.kind, "Compute ledger transaction kind", 64);
  const authorityValue = text(transaction.authority, "Compute ledger transaction authority", 64);
  const settlementStatusValue = text(transaction.settlement_status, "Compute ledger settlement status", 64);
  const transactionHash = text(transaction.transaction_hash, "Compute ledger transaction hash", 64);
  const previousHash = text(transaction.previous_hash, "Compute ledger previous hash", 64);
  const kinds: readonly ComputeLedgerKind[] = [
    "testnet_grant",
    "job_reserve",
    "job_settle",
    "job_release",
    "job_cancel",
  ];
  const authorities: readonly ComputeLedgerAuthority[] = [
    "operator_runtime",
    "wallet",
    "credential",
    "project_wallet_owner",
    "project_wallet_admin",
    "project_wallet_developer",
  ];
  const settlementStatuses: readonly ComputeLedgerSettlementStatus[] = [
    "operator_testnet_only",
    "reserved",
    "provisional_internal_metering",
    "released_without_service_settlement",
    "user_canceled_before_dispatch",
  ];
  if (
    !COMPUTE_LEDGER_TRANSACTION_ID.test(transactionId)
    || !kinds.includes(kindValue as ComputeLedgerKind)
    || transaction.project_id !== projectId
    || (transaction.job_id !== null && (
      typeof transaction.job_id !== "string"
      || !COMPUTE_JOB_ID.test(transaction.job_id)
    ))
    || !authorities.includes(authorityValue as ComputeLedgerAuthority)
    || !settlementStatuses.includes(settlementStatusValue as ComputeLedgerSettlementStatus)
    || !HEX_64.test(transactionHash)
    || !HEX_64.test(previousHash)
    || transactionHash === previousHash
  ) throw new Error("Compute ledger transaction failed its bounded schema checks");

  const parsed: ComputeLedgerTransaction = {
    transaction_id: transactionId,
    sequence: integer(
      transaction.sequence,
      "Compute ledger sequence",
      1,
      COMPUTE_LEDGER_MAX_SEQUENCE,
    ),
    kind: kindValue as ComputeLedgerKind,
    project_id: projectId,
    job_id: transaction.job_id,
    amount_credits: integer(transaction.amount_credits, "Compute ledger amount", 0, 1_000_000),
    postings: parseComputeLedgerPostings(transaction.postings, projectId),
    authority: authorityValue as ComputeLedgerAuthority,
    created_at: integer(
      transaction.created_at,
      "Compute ledger timestamp",
      0,
      COMPUTE_LEDGER_MAX_TIMESTAMP,
    ),
    settlement_status: settlementStatusValue as ComputeLedgerSettlementStatus,
    transaction_hash: transactionHash,
    previous_hash: previousHash,
  };
  assertComputeLedgerTransactionSemantics(parsed);
  return parsed;
}

export function parseComputeLedger(value: unknown, projectId: string): ComputeLedger {
  if (!COMPUTE_PROJECT_ID.test(projectId)) {
    throw new Error("Compute ledger project binding is malformed");
  }
  const result = record(value, "Compute ledger");
  exactKeys(result, "Compute ledger", [
    "surface",
    "schema_version",
    "project_id",
    "balance",
    "transactions",
    "append_only",
    "double_entry",
    "currency",
    "transferable",
    "redeemable",
  ]);
  if (
    result.surface !== "compute_ledger"
    || result.schema_version !== 1
    || result.project_id !== projectId
    || result.append_only !== true
    || result.double_entry !== true
    || result.currency !== "service_credit"
    || result.transferable !== false
    || result.redeemable !== false
    || !Array.isArray(result.transactions)
    || result.transactions.length > 100
  ) throw new Error("Compute ledger failed its bounded schema checks");

  const balanceValue = result.balance;
  assertBalance(balanceValue, projectId);
  const transactions = result.transactions.map((item) => parseComputeLedgerTransaction(item, projectId));
  const transactionIds = new Set<string>();
  const transactionHashes = new Set<string>();
  for (let index = 0; index < transactions.length; index += 1) {
    const transaction = transactions[index];
    const older = transactions[index + 1];
    if (
      transactionIds.has(transaction.transaction_id)
      || transactionHashes.has(transaction.transaction_hash)
      || (older !== undefined && transaction.sequence <= older.sequence)
      || computeLedgerAdjacency(transaction, older) === "invalid"
    ) throw new Error("Compute ledger ordering or visible hash chain is inconsistent");
    transactionIds.add(transaction.transaction_id);
    transactionHashes.add(transaction.transaction_hash);
  }

  return {
    surface: "compute_ledger",
    schema_version: 1,
    project_id: projectId,
    balance: balanceValue,
    transactions,
    append_only: true,
    double_entry: true,
    currency: "service_credit",
    transferable: false,
    redeemable: false,
  };
}

function assertJob(value: unknown, projectId?: string): asserts value is ComputeJob {
  const job = record(value, "Compute job");
  exactKeys(job, "Compute job", [
    "job_id", "project_id", "name", "operation", "model", "recipe",
    "max_credits", "actual_credits", "released_credits", "result_policy",
    "environment_version", "status", "dispatch_status", "backend_capability",
    "credential_id", "created_at", "updated_at", "started_at", "completed_at",
    "metering_source", "usage_receipt_hash", "settlement_authority",
    "provider_authoritative_settlement", "raw_input_persisted", "raw_output_persisted",
  ]);
  const operation = String(job.operation);
  if (
    !RESOURCE_ID.test(String(job.job_id))
    || !RESOURCE_ID.test(String(job.project_id))
    || (projectId !== undefined && job.project_id !== projectId)
    || !["inference", "training"].includes(operation)
    || !COMPUTE_JOB_PUBLIC_LABEL.test(String(job.name))
    || job.model !== "qwen3_8b"
    || job.recipe !== (operation === "training" ? "qwen3_8b_lora_r32" : "qwen3_8b_bounded")
    || !["bounded_summary_receipt", "score_band_hash"].includes(String(job.result_policy))
    || !COMPUTE_JOB_PUBLIC_LABEL.test(String(job.environment_version))
    || !["queued", "running", "succeeded", "failed", "canceled"].includes(String(job.status))
    || job.dispatch_status !== "not_dispatched"
    || job.backend_capability !== (operation === "training" ? "existing_tinker_training_proxy" : "future_inference_proxy")
    || job.provider_authoritative_settlement !== false
    || job.raw_input_persisted !== false
    || job.raw_output_persisted !== false
  ) throw new Error("Compute job failed its bounded schema checks");
  integer(job.max_credits, "job reservation", 1, 500);
  if (job.usage_receipt_hash !== null && !SHA256.test(String(job.usage_receipt_hash))) throw new Error("Compute receipt hash is malformed");
}

function assertProviderGuarantees(
  value: unknown,
  label: string,
  expected: boolean,
): asserts value is ComputeProviderGuarantees {
  const guarantees = record(value, label);
  exactKeys(guarantees, label, [
    "at_most_once_attempt_checkpoint",
    "terminal_ambiguity_hold",
    "ambiguous_outcome_ciphertext_retained",
  ]);
  if (
    boolean(guarantees.at_most_once_attempt_checkpoint, `${label} attempt checkpoint`) !== expected
    || boolean(guarantees.terminal_ambiguity_hold, `${label} ambiguity hold`) !== expected
    || boolean(
      guarantees.ambiguous_outcome_ciphertext_retained,
      `${label} ciphertext retention`,
    ) !== expected
  ) throw new Error(`${label} made an unsupported guarantee`);
}

function assertProviderCapability(value: unknown): asserts value is ComputeProviderCapability {
  const provider = record(value, "Compute provider capability");
  if (!Object.prototype.hasOwnProperty.call(provider, "allowed_operations")) {
    exactKeys(provider, "Compute provider capability fallback", [
      "schema",
      "source_present",
      "release_configured",
      "provider_dispatch",
      "reason",
    ]);
    if (
      provider.schema !== "dnai.compute.provider-capability.v1"
      || provider.source_present !== true
      || provider.release_configured !== false
      || provider.provider_dispatch !== false
      || provider.reason !== "provider_capability_unavailable"
    ) throw new Error("Compute provider capability fallback is contradictory");
    return;
  }

  const hasRuntime = Object.prototype.hasOwnProperty.call(provider, "runtime");
  exactKeys(provider, "Compute provider capability", [
    "schema",
    "source_present",
    "release_configured",
    "provider_dispatch",
    "allowed_operations",
    "allowed_result_policies",
    "adapter_id",
    "sdk_version",
    "sdk_source_sha256",
    "request_contract_sha256",
    "base_url_sha256",
    "provider_release_sha256",
    "idempotency_header_role",
    "idempotent_provider_replay_claimed",
    "automatic_provider_redispatch",
    "adapter_contract",
    "runtime_guarantees",
    ...(hasRuntime ? ["runtime"] : []),
    "reason",
  ]);
  const releaseConfigured = boolean(
    provider.release_configured,
    "provider release configuration",
  );
  const providerDispatch = boolean(
    provider.provider_dispatch,
    "provider dispatch capability",
  );
  const allowedOperations = provider.allowed_operations;
  const allowedResultPolicies = provider.allowed_result_policies;
  const reason = text(provider.reason, "provider capability reason", 96);
  assertProviderGuarantees(
    provider.adapter_contract,
    "Compute provider adapter contract",
    true,
  );
  assertProviderGuarantees(
    provider.runtime_guarantees,
    "Compute provider runtime guarantees",
    providerDispatch,
  );

  if (hasRuntime) {
    const runtime = record(provider.runtime, "Compute provider runtime presence");
    exactKeys(runtime, "Compute provider runtime presence", [
      "authenticated",
      "fresh",
      "process_presence_only",
      "tdx_evidence",
      "observed_at",
    ]);
    if (
      runtime.authenticated !== true
      || runtime.fresh !== true
      || runtime.process_presence_only !== true
      || runtime.tdx_evidence !== false
    ) throw new Error("Compute provider runtime presence is contradictory");
    integer(runtime.observed_at, "provider runtime observation", 1, 4_102_444_800);
  }

  if (
    provider.schema !== "dnai.compute.provider-capability.v1"
    || provider.source_present !== true
    || !Array.isArray(allowedOperations)
    || allowedOperations.length !== 2
    || allowedOperations[0] !== "inference"
    || allowedOperations[1] !== "training"
    || !Array.isArray(allowedResultPolicies)
    || allowedResultPolicies.length !== 1
    || allowedResultPolicies[0] !== "bounded_summary_receipt"
    || provider.adapter_id !== TINKER_PROVIDER_ADAPTER_ID
    || provider.sdk_version !== TINKER_PROVIDER_SDK_VERSION
    || provider.sdk_source_sha256 !== TINKER_PROVIDER_SDK_SOURCE_SHA256
    || provider.request_contract_sha256 !== TINKER_PROVIDER_REQUEST_CONTRACT_SHA256
    || provider.base_url_sha256 !== TINKER_PROVIDER_BASE_URL_SHA256
    || provider.provider_release_sha256 !== TINKER_PROVIDER_RELEASE_SHA256
    || provider.idempotency_header_role !== "request_commitment_only"
    || provider.idempotent_provider_replay_claimed !== false
    || provider.automatic_provider_redispatch !== false
    || !/^[a-z][a-z0-9_]{2,95}$/.test(reason)
    || (providerDispatch && !releaseConfigured)
    || hasRuntime !== providerDispatch
  ) throw new Error("Compute provider capability is contradictory");
}

function assertDispatchCapability(value: unknown): asserts value is ComputeDispatchCapability {
  const capability = record(value, "Compute dispatch-intent capability");
  exactKeys(capability, "Compute dispatch-intent capability", [
    "metadata_intent_creation",
    "provider_dispatch",
    "independent_metering",
    "settlement",
    "credential_workload_wallet_adoption",
    "wallet_adoption_authority",
    "wallet_source_transfer_supported",
    "device_spending_authority",
    "exact_asset_only",
    "mutation_route",
    "status_route_template",
    "status_recovery_by_job_reference",
    "automatic_provider_redispatch",
    "provider",
    "reason",
  ]);
  const metadata = boolean(capability.metadata_intent_creation, "metadata intent creation capability");
  const provider = boolean(capability.provider_dispatch, "provider dispatch capability");
  const metering = boolean(capability.independent_metering, "independent metering capability");
  const settlement = boolean(capability.settlement, "settlement capability");
  const credentialAdoption = boolean(
    capability.credential_workload_wallet_adoption,
    "credential workload wallet-adoption capability",
  );
  const reason = text(capability.reason, "dispatch capability reason", 96);
  assertProviderCapability(capability.provider);
  const providerCapability = capability.provider;
  if (
    capability.exact_asset_only !== true
    || capability.wallet_adoption_authority !== "project_owner_admin_developer"
    || capability.wallet_source_transfer_supported !== false
    || capability.device_spending_authority !== false
    || capability.status_route_template !== DISPATCH_STATUS_ROUTE
    || capability.status_recovery_by_job_reference !== true
    || capability.automatic_provider_redispatch !== false
    || !/^[a-z][a-z0-9_]{2,95}$/.test(reason)
    || (metadata ? capability.mutation_route !== DISPATCH_MUTATION_ROUTE : capability.mutation_route !== null)
    || (provider && !metadata)
    || (credentialAdoption && !provider)
    || (metering && !provider)
    || (settlement && !metering)
    || provider !== providerCapability.provider_dispatch
    || (
      provider
        ? reason !== "ready_at_most_once_terminal_ambiguity_hold"
        : reason !== providerCapability.reason
    )
  ) throw new Error("Compute dispatch-intent capability is contradictory");
}

export function parseComputeFundingCapabilities(value: unknown): ComputeFundingCapabilities {
  assertNoSensitiveFields(value);
  const capability = record(value, "Compute funding capabilities");
  exactKeys(capability, "Compute funding capabilities", [
    "surface",
    "schema_version",
    "card",
    "usdc",
    "eth",
    "exact_asset_vault",
    "dispatch_intents",
    "operator_testnet_grants",
    "credits",
  ]);
  const card = record(capability.card, "card capability");
  const usdc = record(capability.usdc, "USDC capability");
  const eth = record(capability.eth, "ETH capability");
  const vault = record(capability.exact_asset_vault, "exact-asset vault capability");
  const credits = record(capability.credits, "credit capability");
  const grants = record(capability.operator_testnet_grants, "testnet grant capability");
  exactKeys(card, "card capability", ["enabled", "mutation_route", "reason", "card_data_accepted", "distinct_from_exact_asset_capacity"]);
  exactKeys(usdc, "USDC capability", ["enabled", "mutation_route", "reason", "capacity_model"]);
  exactKeys(eth, "ETH capability", ["enabled", "mutation_route", "reason", "capacity_model"]);
  exactKeys(vault, "exact-asset vault capability", ["contract", "release_bound", "review_status", "provider_dispatch_authoritative"]);
  exactKeys(grants, "testnet grant capability", ["enabled", "auth", "cash_value"]);
  exactKeys(credits, "credit capability", [
    "kind", "transferable", "redeemable", "onchain_token",
    "nominal_usd_cents_per_credit", "legacy_modeled_ledger", "distinct_from_exact_asset_vault",
  ]);
  assertDispatchCapability(capability.dispatch_intents);
  if (
    capability.surface !== "compute_funding_capabilities"
    || capability.schema_version !== 1
    || card.enabled !== false
    || card.mutation_route !== null
    || card.card_data_accepted !== false
    || card.distinct_from_exact_asset_capacity !== true
    || usdc.enabled !== false
    || usdc.mutation_route !== null
    || usdc.capacity_model !== "same_asset_nontransferable_vault_claim"
    || eth.enabled !== false
    || eth.mutation_route !== null
    || eth.capacity_model !== "same_asset_nontransferable_vault_claim"
    || vault.contract !== "ComputeCreditVault"
    || vault.release_bound !== true
    || vault.review_status !== "reviewed_and_extensively_tested_not_formally_audited"
    || vault.provider_dispatch_authoritative !== false
    || credits.kind !== "closed_loop_service_credit"
    || credits.transferable !== false
    || credits.redeemable !== false
    || credits.onchain_token !== false
    || credits.nominal_usd_cents_per_credit !== 1
    || credits.legacy_modeled_ledger !== true
    || credits.distinct_from_exact_asset_vault !== true
    || typeof grants.enabled !== "boolean"
    || grants.auth !== "configured_runtime_bearer"
    || grants.cash_value !== false
  ) throw new Error("Compute funding capability made an unsupported claim");
  text(card.reason, "card capability reason", 128);
  text(usdc.reason, "USDC capability reason", 128);
  text(eth.reason, "ETH capability reason", 128);
  return capability as unknown as ComputeFundingCapabilities;
}

export async function fetchFundingCapabilities(): Promise<ComputeFundingCapabilities> {
  return parseComputeFundingCapabilities(await request("/compute/funding-capabilities"));
}

export async function listProjects(token: string): Promise<ComputeProject[]> {
  const result = record(await request("/compute/projects", { token }), "Compute projects");
  if (result.surface !== "compute_projects" || result.schema_version !== 1 || !Array.isArray(result.projects) || result.projects.length > 16) {
    throw new Error("Compute projects failed their bounded schema checks");
  }
  result.projects.forEach(assertProject);
  return result.projects as ComputeProject[];
}

export async function createProject(token: string, name: string, idempotencyKey: string): Promise<ComputeProject> {
  const result = record(await request("/compute/projects", { method: "POST", token, idempotencyKey, body: { name } }), "Compute project result");
  if (result.surface !== "compute_project_result" || typeof result.created !== "boolean" || typeof result.idempotent_replay !== "boolean") {
    throw new Error("Compute project result is malformed");
  }
  assertProject(result.project);
  return result.project;
}

export async function getProject(token: string, projectId: string): Promise<ComputeProject> {
  const result = await request(`/compute/projects/${encodeURIComponent(projectId)}`, { token });
  assertProject(result);
  return result;
}

export async function addProjectMember(token: string, projectId: string, address: string, role: Exclude<ProjectRole, "owner">): Promise<ComputeProject> {
  const result = await request(`/compute/projects/${encodeURIComponent(projectId)}/members`, { method: "POST", token, body: { address, role } });
  assertProject(result);
  return result;
}

export async function removeProjectMember(token: string, projectId: string, address: string): Promise<ComputeProject> {
  const result = await request(`/compute/projects/${encodeURIComponent(projectId)}/members/${encodeURIComponent(address)}`, { method: "DELETE", token });
  assertProject(result);
  return result;
}

export async function listDevices(token: string, projectId: string): Promise<ComputeDevice[]> {
  const result = record(await request(`/compute/projects/${encodeURIComponent(projectId)}/devices`, { token }), "Compute devices");
  if (result.surface !== "compute_devices" || !Array.isArray(result.devices) || result.devices.length > 128) throw new Error("Compute devices are malformed");
  result.devices.forEach(assertDevice);
  return result.devices as ComputeDevice[];
}

export async function registerDevice(token: string, projectId: string, label: string, kind: DeviceKind, publicKey: string): Promise<ComputeDevice> {
  const result = record(await request(`/compute/projects/${encodeURIComponent(projectId)}/devices`, { method: "POST", token, body: { label, kind, public_key: publicKey } }), "Compute device result");
  if (result.surface !== "compute_device") throw new Error("Compute device result is malformed");
  assertDevice(result.device);
  return result.device;
}

export async function revokeDevice(token: string, projectId: string, deviceId: string): Promise<ComputeDevice> {
  const result = record(await request(`/compute/projects/${encodeURIComponent(projectId)}/devices/${encodeURIComponent(deviceId)}/revoke`, { method: "POST", token }), "Compute device result");
  if (result.surface !== "compute_device") throw new Error("Compute device result is malformed");
  assertDevice(result.device);
  return result.device;
}

export async function listCredentials(token: string, projectId: string): Promise<ComputeCredential[]> {
  const result = record(await request(`/compute/projects/${encodeURIComponent(projectId)}/credentials`, { token }), "Compute credentials");
  if (result.surface !== "compute_credentials" || !Array.isArray(result.credentials) || result.credentials.length > 512) throw new Error("Compute credentials are malformed");
  result.credentials.forEach(assertCredential);
  return result.credentials as ComputeCredential[];
}

function parseCredentialDelivery(value: unknown, expectedSurface: "compute_credential_issuance" | "compute_credential_rotation"): ComputeCredentialDelivery {
  const result = record(value, "Compute credential delivery");
  const capsule = record(result.capsule, "Compute credential capsule");
  const encrypted = record(capsule.encrypted_token, "Compute encrypted token");
  assertCredential(result.credential);
  if (
    result.surface !== expectedSurface
    || capsule.delivery !== "x25519_aes_256_gcm_envelope"
    || capsule.plaintext_token_returned !== false
    || result.plaintext_token_returned !== false
    || (expectedSurface === "compute_credential_issuance" && result.upstream_tinker_key_exposed !== false)
    || !HEX_64.test(String(encrypted.ephemeral_public_key))
    || !/^[0-9a-f]{24}$/.test(String(encrypted.nonce))
    || !/^[0-9a-f]{32,16384}$/.test(String(encrypted.ciphertext))
    || !/^[0-9a-f]{2,8192}$/.test(String(capsule.associated_data))
    || !HEX_64.test(String(capsule.associated_data_hash))
    || !HEX_64.test(String(capsule.recipient_public_key_hash))
  ) throw new Error("Compute credential capsule failed its bounded schema checks");
  return { credential: result.credential, capsule: capsule as unknown as ComputeCapsule };
}

export async function issueCredential(
  token: string,
  projectId: string,
  input: { deviceId: string; name: string; scopes: ComputeScope[]; expiresInSeconds: number; dailyCreditCap: number },
): Promise<ComputeCredentialDelivery> {
  return parseCredentialDelivery(await request(`/compute/projects/${encodeURIComponent(projectId)}/credentials`, {
    method: "POST",
    token,
    body: {
      device_id: input.deviceId,
      name: input.name,
      scopes: input.scopes,
      expires_in_seconds: input.expiresInSeconds,
      daily_credit_cap: input.dailyCreditCap,
    },
  }), "compute_credential_issuance");
}

export async function rotateCredential(token: string, projectId: string, credentialId: string, expiresInSeconds: number): Promise<ComputeCredentialDelivery> {
  return parseCredentialDelivery(await request(`/compute/projects/${encodeURIComponent(projectId)}/credentials/${encodeURIComponent(credentialId)}/rotate`, {
    method: "POST", token, body: { expires_in_seconds: expiresInSeconds },
  }), "compute_credential_rotation");
}

export async function revokeCredential(token: string, projectId: string, credentialId: string): Promise<ComputeCredential> {
  const result = record(await request(`/compute/projects/${encodeURIComponent(projectId)}/credentials/${encodeURIComponent(credentialId)}/revoke`, { method: "POST", token }), "Compute credential result");
  if (result.surface !== "compute_credential") throw new Error("Compute credential result is malformed");
  assertCredential(result.credential);
  return result.credential;
}

export async function fetchBalance(token: string, projectId: string): Promise<ComputeBalance> {
  const result = await request(`/compute/projects/${encodeURIComponent(projectId)}/balance`, { token });
  assertBalance(result, projectId);
  return result;
}

export async function fetchLedger(token: string, projectId: string): Promise<ComputeLedger> {
  return parseComputeLedger(
    await request(`/compute/projects/${encodeURIComponent(projectId)}/ledger?limit=100`, { token }),
    projectId,
  );
}

export async function listJobs(token: string, projectId: string): Promise<ComputeJob[]> {
  const result = record(await request(`/compute/projects/${encodeURIComponent(projectId)}/jobs?limit=100`, { token }), "Compute jobs");
  if (result.surface !== "compute_jobs" || result.schema_version !== 1 || !Array.isArray(result.jobs) || result.jobs.length > 100) throw new Error("Compute jobs are malformed");
  result.jobs.forEach((job) => assertJob(job, projectId));
  return result.jobs as ComputeJob[];
}

const DISPATCH_STAGES = new Set<ComputeDispatchStage>([
  "intent_created",
  "start_prepared",
  "start_broadcast",
  "start_confirmed",
  "provider_dispatching",
  "provider_attempt_checkpointed",
  "provider_outcome_ambiguous",
  "usage_finalized",
  "workload_released",
  "metering_pending",
  "metering_decided",
  "settlement_prepared",
  "settlement_broadcast",
  "settled",
  "blocked",
]);
const PRE_PROVIDER_STAGES = new Set<ComputeDispatchStage>([
  "intent_created", "start_prepared", "start_broadcast", "start_confirmed",
]);
const USAGE_FINALIZED_STAGES = new Set<ComputeDispatchStage>([
  "usage_finalized", "workload_released", "metering_pending", "metering_decided",
  "settlement_prepared", "settlement_broadcast", "settled",
]);
const CIPHERTEXT_RELEASED_STAGES = new Set<ComputeDispatchStage>([
  "workload_released", "metering_pending", "metering_decided",
  "settlement_prepared", "settlement_broadcast", "settled",
]);

function boundedReference(value: unknown, label: string): string {
  const normalized = text(value, label, 128).trim();
  if (!COMPUTE_REFERENCE.test(normalized)) throw new Error(`${label} is malformed`);
  return normalized.startsWith("0x") ? normalized.toLowerCase() : normalized;
}

function lowerAddress(value: unknown, label: string, allowZero: boolean): `0x${string}` {
  const normalized = typeof value === "string" ? value.toLowerCase() : "";
  if (!ADDRESS.test(normalized) || (!allowZero && normalized === `0x${"0".repeat(40)}`)) {
    throw new Error(`${label} is malformed`);
  }
  return normalized as `0x${string}`;
}

function nonzeroBytes32(value: unknown, label: string): `0x${string}` {
  const normalized = typeof value === "string" ? value.toLowerCase() : "";
  if (!NONZERO_BYTES32.test(normalized)) throw new Error(`${label} is malformed`);
  return normalized as `0x${string}`;
}

function nonzeroSha256(value: unknown, label: string): string {
  const normalized = typeof value === "string" ? value.toLowerCase() : "";
  if (!/^sha256:(?!0{64}$)[0-9a-f]{64}$/.test(normalized)) {
    throw new Error(`${label} is malformed`);
  }
  return normalized;
}

function parseComputeDispatchAuthorization(
  value: unknown,
  includeServerDerived: true,
): ComputeDispatchAuthorization;
function parseComputeDispatchAuthorization(
  value: unknown,
  includeServerDerived: false,
): Omit<ComputeDispatchAuthorization, "server_derived">;
function parseComputeDispatchAuthorization(
  value: unknown,
  includeServerDerived: boolean,
): ComputeDispatchAuthorization | Omit<ComputeDispatchAuthorization, "server_derived"> {
  const authorization = record(value, "Compute dispatch authorization");
  exactKeys(
    authorization,
    "Compute dispatch authorization",
    includeServerDerived
      ? ["kind", "context_commitment", "server_derived"]
      : ["kind", "context_commitment"],
  );
  const kind = String(authorization.kind);
  if (kind !== "standalone" && kind !== "collaboration_one_shot") {
    throw new Error("Compute dispatch authorization kind is malformed");
  }
  const parsed = {
    kind,
    context_commitment: nonzeroSha256(
      authorization.context_commitment,
      "dispatch authorization context",
    ),
    ...(includeServerDerived
      ? {
        server_derived: boolean(
          authorization.server_derived,
          "dispatch authorization server-derived flag",
        ),
      }
      : {}),
  };
  if (
    includeServerDerived
    && "server_derived" in parsed
    && parsed.server_derived !== (kind === "standalone")
  ) {
    throw new Error("Compute dispatch authorization derivation is contradictory");
  }
  return parsed as ComputeDispatchAuthorization | Omit<ComputeDispatchAuthorization, "server_derived">;
}

function parseComputeDispatchWorkloadAuthority(
  value: unknown,
  includeFundingWallet: true,
): ComputeDispatchWorkloadAuthority & { funding_wallet: Address };
function parseComputeDispatchWorkloadAuthority(
  value: unknown,
  includeFundingWallet: false,
): ComputeDispatchWorkloadAuthority;
function parseComputeDispatchWorkloadAuthority(
  value: unknown,
  includeFundingWallet: boolean,
): ComputeDispatchWorkloadAuthority | (ComputeDispatchWorkloadAuthority & { funding_wallet: Address }) {
  const authority = record(value, "Compute dispatch workload authority");
  exactKeys(
    authority,
    "Compute dispatch workload authority",
    [
      "source_kind", "execution_binding_commitment",
      "recipient_release_commitment", "funding_authority",
      ...(includeFundingWallet ? ["funding_wallet"] : []),
      "device_spending_authority",
    ],
  );
  const sourceKind = String(authority.source_kind);
  if (sourceKind !== "wallet" && sourceKind !== "credential") {
    throw new Error("Compute workload source kind is malformed");
  }
  if (
    authority.funding_authority !== "onchain_wallet_job"
    || authority.device_spending_authority !== false
  ) {
    throw new Error("Compute workload funding authority is contradictory");
  }
  return {
    source_kind: sourceKind,
    execution_binding_commitment: nonzeroSha256(
      authority.execution_binding_commitment,
      "workload execution-binding commitment",
    ),
    recipient_release_commitment: nonzeroSha256(
      authority.recipient_release_commitment,
      "workload recipient release commitment",
    ),
    funding_authority: "onchain_wallet_job",
    ...(includeFundingWallet
      ? {
        funding_wallet: lowerAddress(
          authority.funding_wallet,
          "workload funding wallet",
          false,
        ),
      }
      : {}),
    device_spending_authority: false,
  } as ComputeDispatchWorkloadAuthority | (ComputeDispatchWorkloadAuthority & { funding_wallet: Address });
}

function canonicalSignature(value: unknown, label: string): Hex {
  const normalized = typeof value === "string" ? value.toLowerCase() : "";
  if (!CANONICAL_SIGNATURE.test(normalized)) throw new Error(`${label} is malformed`);
  return normalized as Hex;
}

function parseComputeBoundedResult(
  value: unknown,
  expected: {
    operation: string;
    resultPolicy: string;
  },
): ComputeBoundedResult {
  const result = record(value, "Compute bounded provider result");
  exactKeys(result, "Compute bounded provider result", [
    "schema",
    "result_policy",
    "operation",
    "outcome",
    "result_class",
    "result_commitment",
    "commitment_scheme",
    "score_band_released",
    "raw_prompt_egress",
    "raw_examples_egress",
    "raw_output_egress",
    "provider_identifier_egress",
    "exception_detail_egress",
  ]);
  const outcome = String(result.outcome);
  const expectedClass = outcome === "succeeded"
    ? "completed_within_authorized_caps"
    : "provider_failed_without_raw_detail";
  const parsed = {
    ...result,
    result_commitment: nonzeroBytes32(
      result.result_commitment,
      "bounded result commitment",
    ),
  };
  if (
    result.schema !== "dnai.compute.bounded-result.v1"
    || result.result_policy !== expected.resultPolicy
    || result.operation !== expected.operation
    || !["succeeded", "failed"].includes(outcome)
    || result.result_class !== expectedClass
    || result.commitment_scheme
      !== "hmac-sha256-dstack-v1-over-dispatch-bound-private-result-and-canonical-bounded-projection"
    || result.score_band_released !== false
    || result.raw_prompt_egress !== false
    || result.raw_examples_egress !== false
    || result.raw_output_egress !== false
    || result.provider_identifier_egress !== false
    || result.exception_detail_egress !== false
  ) throw new Error("Compute bounded provider result failed its bounded schema checks");
  return parsed as ComputeBoundedResult;
}

export function parseComputeDispatchIntent(
  value: unknown,
  expected?: { projectReference?: string; jobReference?: string },
): ComputeDispatchIntentStatus {
  assertNoSensitiveFields(value);
  const intent = record(value, "Compute dispatch intent");
  exactKeys(intent, "Compute dispatch intent", [
    "surface", "schema_version", "project_reference", "job_reference", "project_id", "job_id",
    "user", "asset", "authorization_nonce", "max_asset_debit", "authorization_expiry",
    "rate_policy_commitment", "compose_hash", "operation", "model", "recipe", "result_policy",
    "resource_limits", "workload_id", "workload_schema", "manifest_commitment", "workload_commitment",
    "authorization", "workload_authority", "intent_commitment",
    "execution_policy_context_hash", "stage", "workload_claim_commitment",
    "workload_claim_confirmed", "provider_authoritative",
    "legacy_credit_ledger_mutated", "provider_dispatch_status",
    "provider_dispatch_may_have_occurred", "provider_usage_finalized",
    "idempotent_provider_replay_claimed", "automatic_provider_redispatch",
    "ambiguous_outcome_hold", "bounded_result", "workload_ciphertext_released",
    "workload_ciphertext_retained_for_reconciliation", "raw_prompt_accepted",
    "raw_examples_accepted", "arbitrary_program_accepted", "exact_timing_egress",
  ]);
  const limits = record(intent.resource_limits, "Compute dispatch resource limits");
  exactKeys(limits, "Compute dispatch resource limits", [
    "max_prefill_tokens", "max_sample_tokens", "max_train_tokens",
  ]);
  const projectReference = boundedReference(intent.project_reference, "dispatch project reference");
  const jobReference = boundedReference(intent.job_reference, "dispatch job reference");
  const projectId = nonzeroBytes32(intent.project_id, "dispatch project ID");
  const jobId = nonzeroBytes32(intent.job_id, "dispatch job ID");
  const stage = String(intent.stage) as ComputeDispatchStage;
  const providerStatus = String(intent.provider_dispatch_status);
  const providerMayHaveStarted = boolean(intent.provider_dispatch_may_have_occurred, "provider dispatch ambiguity flag");
  const usageFinalized = boolean(intent.provider_usage_finalized, "provider usage finalization flag");
  const idempotentReplayClaimed = boolean(
    intent.idempotent_provider_replay_claimed,
    "provider replay claim",
  );
  const automaticRedispatch = boolean(
    intent.automatic_provider_redispatch,
    "automatic provider redispatch",
  );
  const ambiguousOutcomeHold = boolean(
    intent.ambiguous_outcome_hold,
    "provider ambiguity hold",
  );
  const workloadCiphertextReleased = boolean(
    intent.workload_ciphertext_released,
    "workload ciphertext release",
  );
  const workloadCiphertextRetained = boolean(
    intent.workload_ciphertext_retained_for_reconciliation,
    "workload ciphertext reconciliation retention",
  );
  const operation = String(intent.operation);
  const resultPolicy = String(intent.result_policy);
  const recipe = String(intent.recipe);
  const maxPrefill = integer(limits.max_prefill_tokens, "maximum prefill tokens", 0, 100_000_000);
  const maxSample = integer(limits.max_sample_tokens, "maximum sample tokens", 0, 100_000_000);
  const maxTrain = integer(limits.max_train_tokens, "maximum training tokens", 0, 100_000_000);
  const authorizationNonce = parseDispatchUint256(intent.authorization_nonce, "authorization nonce");
  const maxAssetDebit = parseDispatchUint256(intent.max_asset_debit, "maximum asset debit");
  const user = lowerAddress(intent.user, "dispatch user", false);
  const asset = lowerAddress(intent.asset, "dispatch asset", true);
  const authorizationExpiry = integer(intent.authorization_expiry, "authorization expiry", 1, 4_102_444_800);
  const ratePolicyCommitment = nonzeroBytes32(intent.rate_policy_commitment, "rate-policy commitment");
  const composeHash = nonzeroBytes32(intent.compose_hash, "compose hash");
  const workloadId = String(intent.workload_id);
  const workloadSchema = String(intent.workload_schema);
  const manifestCommitment = nonzeroBytes32(intent.manifest_commitment, "manifest commitment");
  const workloadCommitment = nonzeroBytes32(intent.workload_commitment, "workload commitment");
  const authorization = parseComputeDispatchAuthorization(intent.authorization, true);
  const workloadAuthority = parseComputeDispatchWorkloadAuthority(
    intent.workload_authority,
    false,
  );
  const workloadClaimCommitment = nonzeroSha256(
    intent.workload_claim_commitment,
    "workload dispatch-claim commitment",
  );
  const workloadClaimConfirmed = boolean(
    intent.workload_claim_confirmed,
    "workload dispatch-claim confirmation",
  );
  const intentCommitment = nonzeroBytes32(intent.intent_commitment, "intent commitment");
  const boundedResult = intent.bounded_result === null
    ? null
    : parseComputeBoundedResult(intent.bounded_result, { operation, resultPolicy });
  const executionPolicyContextHash = typeof intent.execution_policy_context_hash === "string"
    && HEX_64.test(intent.execution_policy_context_hash)
    ? intent.execution_policy_context_hash
    : "";
  const expectedProject = expected?.projectReference === undefined
    ? undefined
    : boundedReference(expected.projectReference, "expected project reference");
  const expectedJob = expected?.jobReference === undefined
    ? undefined
    : boundedReference(expected.jobReference, "expected job reference");

  if (
    intent.surface !== "compute_dispatch_intent"
    || intent.schema_version !== 3
    || projectId !== computeVaultProjectId(projectReference)
    || jobId !== computeVaultJobId(jobReference)
    || (expectedProject !== undefined && projectReference !== expectedProject)
    || (expectedJob !== undefined && jobReference !== expectedJob)
    || maxAssetDebit === 0n
    || !DISPATCH_STAGES.has(stage)
    || ![
      "not_started",
      "prepared",
      "attempt_checkpointed",
      "outcome_ambiguous",
      "usage_finalized",
    ].includes(providerStatus)
    || intent.provider_authoritative !== false
    || intent.legacy_credit_ledger_mutated !== false
    || !workloadClaimConfirmed
    || idempotentReplayClaimed
    || automaticRedispatch
    || intent.raw_prompt_accepted !== false
    || intent.raw_examples_accepted !== false
    || intent.arbitrary_program_accepted !== false
    || intent.exact_timing_egress !== false
    || (providerStatus === "not_started" && (providerMayHaveStarted || usageFinalized))
    || (providerStatus === "prepared" && (providerMayHaveStarted || usageFinalized))
    || (providerStatus === "attempt_checkpointed" && (!providerMayHaveStarted || usageFinalized))
    || (providerStatus === "outcome_ambiguous" && (!providerMayHaveStarted || usageFinalized))
    || (providerStatus === "usage_finalized" && (!providerMayHaveStarted || !usageFinalized))
    || (stage !== "blocked" && PRE_PROVIDER_STAGES.has(stage) && providerStatus !== "not_started")
    || (stage === "provider_dispatching" && providerStatus !== "prepared")
    || (stage === "provider_attempt_checkpointed" && providerStatus !== "attempt_checkpointed")
    || (stage === "provider_outcome_ambiguous" && providerStatus !== "outcome_ambiguous")
    || (stage !== "blocked" && USAGE_FINALIZED_STAGES.has(stage) && providerStatus !== "usage_finalized")
    || (
      stage === "blocked"
      && ["attempt_checkpointed", "outcome_ambiguous"].includes(providerStatus)
    )
    || ambiguousOutcomeHold !== (stage === "provider_outcome_ambiguous")
    || usageFinalized !== (boundedResult !== null)
    || workloadCiphertextRetained
      !== (stage === "provider_outcome_ambiguous" && !workloadCiphertextReleased)
    || (stage !== "blocked" && CIPHERTEXT_RELEASED_STAGES.has(stage) && !workloadCiphertextReleased)
    || (stage !== "blocked" && !CIPHERTEXT_RELEASED_STAGES.has(stage) && workloadCiphertextReleased)
    || !["inference", "training"].includes(operation)
    || !WORKLOAD_ID.test(workloadId)
    || workloadSchema !== (operation === "inference"
      ? "dnai.compute.workload.inference.v1"
      : "dnai.compute.workload.sft-jsonl.v1")
    || intent.model !== "qwen3_8b"
    || !["bounded_summary_receipt", "score_band_hash"].includes(resultPolicy)
    || (operation === "inference" && (
      recipe !== "qwen3_8b_bounded" || maxPrefill < 1 || maxPrefill > 32_768
      || maxSample < 1 || maxSample > 4_096 || maxTrain !== 0
    ))
    || (operation === "training" && (
      recipe !== "qwen3_8b_lora_r32" || maxPrefill !== 0 || maxSample !== 0
      || maxTrain < 1 || maxTrain > 10_000_000
    ))
  ) throw new Error("Compute dispatch intent failed its bounded schema checks");

  const expectedAuthorizationContext = authorization.kind === "standalone"
    ? computeStandaloneAuthorizationContextCommitment({
      projectId,
      jobId,
      user,
      asset,
      authorizationNonce,
      maxAssetDebit,
      authorizationExpiry,
      ratePolicyCommitment,
      workloadCommitment,
      manifestCommitment,
    })
    : authorization.context_commitment;
  if (authorization.context_commitment !== expectedAuthorizationContext) {
    throw new Error("Compute standalone authorization context does not match its canonical vault tuple");
  }
  const expectedCommitment = computeDispatchIntentV3Commitment({
    projectReference,
    jobReference,
    projectId,
    jobId,
    user,
    asset,
    authorizationNonce,
    maxAssetDebit,
    authorizationExpiry,
    ratePolicyCommitment,
    composeHash,
    operation,
    model: String(intent.model),
    recipe,
    resultPolicy,
    maxPrefillTokens: maxPrefill,
    maxSampleTokens: maxSample,
    maxTrainTokens: maxTrain,
    workloadId,
    workloadSchema,
    manifestCommitment,
    workloadCommitment,
    workloadSourceKind: workloadAuthority.source_kind,
    workloadExecutionBindingCommitment: (
      workloadAuthority.execution_binding_commitment as `sha256:${string}`
    ),
    workloadRecipientReleaseCommitment: (
      workloadAuthority.recipient_release_commitment as `sha256:${string}`
    ),
    authorizationKind: authorization.kind,
    authorizationContextCommitment: (
      authorization.context_commitment as `sha256:${string}`
    ),
  });
  if (intentCommitment !== expectedCommitment) {
    throw new Error("Compute dispatch intent commitment does not match its canonical metadata");
  }
  const expectedPolicyContextHash = computeExecutionPolicyContextHash({
    jobId,
    intentCommitment,
    operation,
    model: String(intent.model),
    recipe,
  });
  if (executionPolicyContextHash !== expectedPolicyContextHash) {
    throw new Error("Compute execution-policy context does not match intent and compiled recipe");
  }

  const parsed = {
    ...intent,
    project_reference: projectReference,
    job_reference: jobReference,
    project_id: projectId,
    job_id: jobId,
    user,
    asset,
    authorization_nonce: authorizationNonce,
    max_asset_debit: maxAssetDebit,
    authorization_expiry: authorizationExpiry,
    rate_policy_commitment: ratePolicyCommitment,
    compose_hash: composeHash,
    workload_id: workloadId,
    workload_schema: workloadSchema,
    manifest_commitment: manifestCommitment,
    workload_commitment: workloadCommitment,
    authorization,
    workload_authority: workloadAuthority,
    operation,
    recipe,
    resource_limits: {
      max_prefill_tokens: maxPrefill,
      max_sample_tokens: maxSample,
      max_train_tokens: maxTrain,
    },
    intent_commitment: intentCommitment,
    execution_policy_context_hash: executionPolicyContextHash,
    stage,
    workload_claim_commitment: workloadClaimCommitment,
    workload_claim_confirmed: true,
    provider_dispatch_status: providerStatus,
    bounded_result: boundedResult,
  };
  return parsed as ComputeDispatchIntentStatus;
}

export function canCreateComputeDispatchIntent(
  project: ComputeProject | undefined,
  capability: ComputeDispatchCapability | undefined,
): boolean {
  return Boolean(
    project
    && ["owner", "admin", "developer"].includes(project.role)
    && project.provider_dispatch_enabled === true
    && capability?.metadata_intent_creation === true
    && capability.provider_dispatch === true
    && capability.independent_metering === true
    && capability.settlement === true
    && capability.wallet_adoption_authority === "project_owner_admin_developer"
    && capability.wallet_source_transfer_supported === false
    && capability.device_spending_authority === false
    && capability.exact_asset_only === true
    && capability.mutation_route === DISPATCH_MUTATION_ROUTE
    && capability.status_route_template === DISPATCH_STATUS_ROUTE
    && capability.status_recovery_by_job_reference === true
    && capability.automatic_provider_redispatch === false
    && capability.provider.release_configured === true
    && capability.provider.provider_dispatch === true
    && "runtime_guarantees" in capability.provider
    && capability.provider.runtime_guarantees.at_most_once_attempt_checkpoint === true
    && capability.provider.runtime_guarantees.terminal_ambiguity_hold === true
    && capability.provider.runtime_guarantees.ambiguous_outcome_ciphertext_retained === true
    && capability.provider.idempotent_provider_replay_claimed === false
    && capability.provider.automatic_provider_redispatch === false
    && "runtime" in capability.provider
    && capability.provider.runtime?.authenticated === true
    && capability.provider.runtime.fresh === true
  );
}

function normalizeDispatchInput(input: ComputeDispatchIntentInput): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1_000);
  const jobReference = boundedReference(input.jobReference, "dispatch job reference");
  const workloadId = String(input.workloadId).trim();
  const authorizationNonce = parseDispatchUint256(input.authorizationNonce, "authorization nonce");
  const maxAssetDebit = parseDispatchUint256(input.maxAssetDebit, "maximum asset debit");
  const operation = input.operation;
  const prefill = integer(input.maxPrefillTokens, "maximum prefill tokens", 0, 100_000_000);
  const sample = integer(input.maxSampleTokens, "maximum sample tokens", 0, 100_000_000);
  const train = integer(input.maxTrainTokens, "maximum training tokens", 0, 100_000_000);
  if (
    maxAssetDebit === 0n
    || !WORKLOAD_ID.test(workloadId)
    || !Number.isSafeInteger(input.authorizationExpiry)
    || input.authorizationExpiry <= now
    || input.authorizationExpiry > now + 30 * 24 * 60 * 60
    || (operation === "inference" && (prefill < 1 || prefill > 32_768 || sample < 1 || sample > 4_096 || train !== 0))
    || (operation === "training" && (prefill !== 0 || sample !== 0 || train < 1 || train > 10_000_000))
  ) throw new Error("Compute dispatch intent exceeds its compiled public recipe");
  return {
    job_reference: jobReference,
    workload_id: workloadId,
    asset: lowerAddress(input.asset, "dispatch asset", true),
    authorization_nonce: authorizationNonce.toString(),
    max_asset_debit: maxAssetDebit.toString(),
    authorization_expiry: input.authorizationExpiry,
    rate_policy_commitment: nonzeroBytes32(input.ratePolicyCommitment, "rate-policy commitment"),
    compose_hash: nonzeroBytes32(input.composeHash, "compose hash"),
    operation,
    model: "qwen3_8b",
    recipe: operation === "training" ? "qwen3_8b_lora_r32" : "qwen3_8b_bounded",
    result_policy: input.resultPolicy,
    max_prefill_tokens: prefill,
    max_sample_tokens: sample,
    max_train_tokens: train,
  };
}

export async function fetchComputeDispatchIntent(
  token: string,
  projectReference: string,
  jobReference: string,
): Promise<ComputeDispatchIntentStatus> {
  const project = boundedReference(projectReference, "dispatch project reference");
  if (!RESOURCE_ID.test(project)) throw new Error("Dispatch project reference is not a Compute Console project ID");
  const job = boundedReference(jobReference, "dispatch job reference");
  const result = await request(
    `/compute/projects/${encodeURIComponent(project)}/dispatch-intents/${encodeURIComponent(job)}`,
    { token },
  );
  return parseComputeDispatchIntent(result, { projectReference: project, jobReference: job });
}

export function canCancelComputeDispatchIntent(
  status: ComputeDispatchIntentStatus | undefined,
  project?: ComputeProject,
  walletAddress?: string,
): boolean {
  if (!status) return false;
  const normalizedWallet = walletAddress?.toLowerCase();
  return status.stage === "intent_created"
    && status.provider_dispatch_status === "not_started"
    && status.provider_dispatch_may_have_occurred === false
    && status.provider_usage_finalized === false
    && status.bounded_result === null
    && status.workload_ciphertext_released === false
    && status.workload_ciphertext_retained_for_reconciliation === false
    && (
      project === undefined
      || (
        project.project_id === status.project_reference
        && ["owner", "admin", "developer"].includes(project.role)
      )
    )
    && (normalizedWallet === undefined || normalizedWallet === status.user);
}

function dispatchCancellationBindingMatches(
  attempt: ComputeDispatchCancellationAttempt,
  status: ComputeDispatchIntentStatus,
  project: ComputeProject,
  walletAddress: string,
): boolean {
  const wallet = walletAddress.toLowerCase();
  return ["owner", "admin", "developer"].includes(project.role)
    && project.project_id === status.project_reference
    && attempt.project_reference === status.project_reference
    && attempt.job_reference === status.job_reference
    && attempt.project_id === status.project_id
    && attempt.job_id === status.job_id
    && attempt.user === status.user
    && attempt.wallet_address === wallet
    && status.user === wallet
    && attempt.intent_commitment === status.intent_commitment
    && attempt.workload_id === status.workload_id
    && attempt.workload_commitment === status.workload_commitment
    && attempt.authorization.kind === status.authorization.kind
    && attempt.authorization.context_commitment
      === status.authorization.context_commitment
    && attempt.authorization.server_derived
      === status.authorization.server_derived
    && attempt.workload_authority.source_kind
      === status.workload_authority.source_kind
    && attempt.workload_authority.execution_binding_commitment
      === status.workload_authority.execution_binding_commitment
    && attempt.workload_authority.recipient_release_commitment
      === status.workload_authority.recipient_release_commitment
    && attempt.workload_claim_commitment
      === status.workload_claim_commitment;
}

export function createComputeDispatchCancellationAttempt(
  status: ComputeDispatchIntentStatus,
  project: ComputeProject,
  walletAddress: string,
  idempotencyKey: string,
): ComputeDispatchCancellationAttempt {
  if (!canCancelComputeDispatchIntent(status, project, walletAddress)) {
    throw new Error("Dispatch cancellation is available only before provider start");
  }
  if (!IDEMPOTENCY_KEY.test(idempotencyKey)) {
    throw new Error("Dispatch cancellation idempotency key is malformed");
  }
  return {
    schema: "dnai.compute.browser-dispatch-cancellation-attempt.v1",
    schema_version: 1,
    project_reference: status.project_reference,
    job_reference: status.job_reference,
    project_id: status.project_id,
    job_id: status.job_id,
    user: status.user,
    wallet_address: lowerAddress(walletAddress, "dispatch cancellation wallet", false),
    intent_commitment: status.intent_commitment,
    workload_id: status.workload_id,
    workload_commitment: status.workload_commitment,
    authorization: status.authorization,
    workload_authority: status.workload_authority,
    workload_claim_commitment: status.workload_claim_commitment,
    idempotency_key: idempotencyKey,
  };
}

export function parseComputeDispatchCancellationAttempt(
  value: unknown,
): ComputeDispatchCancellationAttempt {
  const attempt = record(value, "Persisted dispatch cancellation attempt");
  exactKeys(attempt, "Persisted dispatch cancellation attempt", [
    "schema", "schema_version", "project_reference", "job_reference",
    "project_id", "job_id", "user", "wallet_address", "intent_commitment",
    "workload_id", "workload_commitment", "authorization",
    "workload_authority", "workload_claim_commitment", "idempotency_key",
  ]);
  const parsed: ComputeDispatchCancellationAttempt = {
    schema: attempt.schema as ComputeDispatchCancellationAttempt["schema"],
    schema_version: attempt.schema_version as 1,
    project_reference: boundedReference(
      attempt.project_reference,
      "persisted cancellation project reference",
    ),
    job_reference: boundedReference(
      attempt.job_reference,
      "persisted cancellation job reference",
    ),
    project_id: nonzeroBytes32(
      attempt.project_id,
      "persisted cancellation project ID",
    ),
    job_id: nonzeroBytes32(attempt.job_id, "persisted cancellation job ID"),
    user: lowerAddress(attempt.user, "persisted cancellation user", false),
    wallet_address: lowerAddress(
      attempt.wallet_address,
      "persisted cancellation wallet",
      false,
    ),
    intent_commitment: nonzeroBytes32(
      attempt.intent_commitment,
      "persisted cancellation intent commitment",
    ),
    workload_id: text(attempt.workload_id, "persisted cancellation workload ID", 36),
    workload_commitment: nonzeroBytes32(
      attempt.workload_commitment,
      "persisted cancellation workload commitment",
    ),
    authorization: parseComputeDispatchAuthorization(
      attempt.authorization,
      true,
    ),
    workload_authority: parseComputeDispatchWorkloadAuthority(
      attempt.workload_authority,
      false,
    ),
    workload_claim_commitment: nonzeroSha256(
      attempt.workload_claim_commitment,
      "persisted cancellation workload-claim commitment",
    ),
    idempotency_key: text(
      attempt.idempotency_key,
      "persisted cancellation idempotency key",
      128,
    ),
  };
  if (
    parsed.schema !== "dnai.compute.browser-dispatch-cancellation-attempt.v1"
    || parsed.schema_version !== 1
    || !RESOURCE_ID.test(parsed.project_reference)
    || !WORKLOAD_ID.test(parsed.workload_id)
    || parsed.wallet_address !== parsed.user
    || !IDEMPOTENCY_KEY.test(parsed.idempotency_key)
  ) {
    throw new Error("Persisted dispatch cancellation attempt is malformed");
  }
  return parsed;
}

export function canReplayComputeDispatchCancellationAttempt(
  status: ComputeDispatchIntentStatus | undefined,
  project: ComputeProject | undefined,
  walletAddress: string | undefined,
  attempt: ComputeDispatchCancellationAttempt | undefined,
): boolean {
  if (!status || !project || !walletAddress || !attempt) return false;
  return status.stage === "blocked"
    && status.provider_dispatch_status === "not_started"
    && status.provider_dispatch_may_have_occurred === false
    && status.provider_usage_finalized === false
    && status.bounded_result === null
    && status.workload_ciphertext_retained_for_reconciliation === false
    && dispatchCancellationBindingMatches(attempt, status, project, walletAddress);
}

export function computeDispatchCancellationCheckpointCommitment(
  status: ComputeDispatchCancellationBinding,
  canceledAt: number,
): string {
  const timestamp = integer(
    canceledAt,
    "dispatch cancellation time",
    1,
    4_102_444_800,
  );
  const payload = {
    schema: "dnai.compute.dispatch-cancellation.v1",
    job_id: status.job_id,
    project_id: status.project_id,
    user: status.user,
    intent_commitment: status.intent_commitment,
    workload_id: status.workload_id,
    workload_commitment: status.workload_commitment,
    canceled_at: timestamp,
    provider_dispatch_performed: false,
    vault_authorization_released: false,
    raw_secret_egress: false,
  };
  return `sha256:${sha256(encoder.encode(
    `${COMPUTE_CANCELLATION_CHECKPOINT_DOMAIN}${canonicalComputeJson(payload)}`,
  )).slice(2)}`;
}

export function parseComputeDispatchCancellation(
  value: unknown,
  expected: ComputeDispatchCancellationBinding,
): ComputeDispatchCancellationReceipt {
  assertNoSensitiveFields(value);
  const receipt = record(value, "Compute dispatch cancellation");
  exactKeys(receipt, "Compute dispatch cancellation", [
    "surface", "schema_version", "project_reference", "job_reference",
    "project_id", "job_id", "intent_commitment", "authorization",
    "workload_authority", "workload_claim_commitment",
    "workload_claim_confirmed",
    "cancellation_checkpoint_commitment", "canceled_at",
    "journal_execution_prevented", "provider_dispatch_performed",
    "provider_dispatch_may_have_occurred", "workload_ciphertext_released",
    "vault_authorization_released", "onchain_cancel_required",
    "exact_asset_capacity_released", "provider_authoritative",
    "legacy_credit_ledger_mutated", "raw_secret_egress", "changed",
    "idempotent_replay",
  ]);
  const changed = boolean(receipt.changed, "dispatch cancellation changed state");
  const replay = boolean(receipt.idempotent_replay, "dispatch cancellation replay state");
  const authorization = parseComputeDispatchAuthorization(
    receipt.authorization,
    false,
  );
  const workloadAuthority = parseComputeDispatchWorkloadAuthority(
    receipt.workload_authority,
    true,
  );
  const parsed: ComputeDispatchCancellationReceipt = {
    surface: receipt.surface as ComputeDispatchCancellationReceipt["surface"],
    schema_version: receipt.schema_version as 2,
    project_reference: boundedReference(
      receipt.project_reference,
      "canceled dispatch project reference",
    ),
    job_reference: boundedReference(
      receipt.job_reference,
      "canceled dispatch job reference",
    ),
    project_id: nonzeroBytes32(receipt.project_id, "canceled dispatch project ID"),
    job_id: nonzeroBytes32(receipt.job_id, "canceled dispatch job ID"),
    intent_commitment: nonzeroBytes32(
      receipt.intent_commitment,
      "canceled dispatch intent commitment",
    ),
    authorization,
    workload_authority: workloadAuthority,
    workload_claim_commitment: nonzeroSha256(
      receipt.workload_claim_commitment,
      "canceled workload dispatch-claim commitment",
    ),
    workload_claim_confirmed: receipt.workload_claim_confirmed as true,
    cancellation_checkpoint_commitment: nonzeroSha256(
      receipt.cancellation_checkpoint_commitment,
      "dispatch cancellation checkpoint",
    ),
    canceled_at: integer(receipt.canceled_at, "dispatch cancellation time", 1, 4_102_444_800),
    journal_execution_prevented: receipt.journal_execution_prevented as true,
    provider_dispatch_performed: receipt.provider_dispatch_performed as false,
    provider_dispatch_may_have_occurred: receipt.provider_dispatch_may_have_occurred as false,
    workload_ciphertext_released: receipt.workload_ciphertext_released as true,
    vault_authorization_released: receipt.vault_authorization_released as false,
    onchain_cancel_required: receipt.onchain_cancel_required as true,
    exact_asset_capacity_released: receipt.exact_asset_capacity_released as false,
    provider_authoritative: receipt.provider_authoritative as false,
    legacy_credit_ledger_mutated: receipt.legacy_credit_ledger_mutated as false,
    raw_secret_egress: receipt.raw_secret_egress as false,
    changed,
    idempotent_replay: replay,
  };
  if (
    parsed.surface !== "compute_dispatch_cancellation"
    || parsed.schema_version !== 2
    || parsed.project_reference !== expected.project_reference
    || parsed.job_reference !== expected.job_reference
    || parsed.project_id !== expected.project_id
    || parsed.job_id !== expected.job_id
    || parsed.intent_commitment !== expected.intent_commitment
    || parsed.authorization.kind !== expected.authorization.kind
    || parsed.authorization.context_commitment
      !== expected.authorization.context_commitment
    || parsed.workload_authority.source_kind
      !== expected.workload_authority.source_kind
    || parsed.workload_authority.execution_binding_commitment
      !== expected.workload_authority.execution_binding_commitment
    || parsed.workload_authority.recipient_release_commitment
      !== expected.workload_authority.recipient_release_commitment
    || parsed.workload_authority.funding_wallet !== expected.user
    || parsed.workload_claim_commitment
      !== expected.workload_claim_commitment
    || parsed.workload_claim_confirmed !== true
    || parsed.cancellation_checkpoint_commitment
      !== computeDispatchCancellationCheckpointCommitment(expected, parsed.canceled_at)
    || parsed.journal_execution_prevented !== true
    || parsed.provider_dispatch_performed !== false
    || parsed.provider_dispatch_may_have_occurred !== false
    || parsed.workload_ciphertext_released !== true
    || parsed.vault_authorization_released !== false
    || parsed.onchain_cancel_required !== true
    || parsed.exact_asset_capacity_released !== false
    || parsed.provider_authoritative !== false
    || parsed.legacy_credit_ledger_mutated !== false
    || parsed.raw_secret_egress !== false
    || changed === replay
  ) throw new Error("Compute dispatch cancellation failed its bounded schema checks");
  return parsed;
}

export async function cancelComputeDispatchIntent(
  token: string,
  project: ComputeProject,
  status: ComputeDispatchIntentStatus,
  expectedWalletAddress: string,
  attempt: ComputeDispatchCancellationAttempt,
): Promise<ComputeDispatchCancellationReceipt> {
  const boundAttempt = parseComputeDispatchCancellationAttempt(attempt);
  const initial = canCancelComputeDispatchIntent(
    status,
    project,
    expectedWalletAddress,
  );
  const replay = canReplayComputeDispatchCancellationAttempt(
    status,
    project,
    expectedWalletAddress,
    boundAttempt,
  );
  if (
    (!initial && !replay)
    || !dispatchCancellationBindingMatches(
      boundAttempt,
      status,
      project,
      expectedWalletAddress,
    )
  ) {
    throw new Error("Dispatch cancellation is available only before provider start");
  }
  const result = await request(
    `/compute/projects/${encodeURIComponent(project.project_id)}/dispatch-intents/${encodeURIComponent(status.job_reference)}/cancel`,
    {
      method: "POST",
      token,
      idempotencyKey: boundAttempt.idempotency_key,
      body: { reason: "user_requested_before_provider_start" },
      timeout: 15_000,
    },
  );
  return parseComputeDispatchCancellation(result, boundAttempt);
}

function parseTinkerProviderRelease(value: unknown): ComputeTinkerProviderRelease {
  const release = record(value, "Compute provider release");
  exactKeys(release, "Compute provider release", [
    "schema", "adapter_id", "sdk_version", "sdk_source_sha256",
    "request_contract_sha256", "base_url_sha256", "tokenizer_path",
    "tokenizer_release_sha256", "idempotency_header_role",
    "idempotent_provider_replay_claimed", "automatic_provider_redispatch",
    "at_most_once_attempt_checkpoint", "terminal_ambiguity_hold",
    "ambiguous_outcome_ciphertext_retained", "provider_authoritative_invoice",
    "raw_secret_egress",
  ]);
  const parsed = {
    ...release,
    sdk_source_sha256: nonzeroSha256(release.sdk_source_sha256, "provider SDK source"),
    request_contract_sha256: nonzeroSha256(
      release.request_contract_sha256,
      "provider request contract",
    ),
    base_url_sha256: nonzeroSha256(release.base_url_sha256, "provider base URL"),
    tokenizer_release_sha256: nonzeroSha256(
      release.tokenizer_release_sha256,
      "provider tokenizer release",
    ),
  } as unknown as ComputeTinkerProviderRelease;
  if (
    parsed.schema !== "dnai.compute.tinker-provider-release.v1"
    || parsed.adapter_id !== TINKER_PROVIDER_ADAPTER_ID
    || parsed.sdk_version !== TINKER_PROVIDER_SDK_VERSION
    || parsed.sdk_source_sha256 !== TINKER_PROVIDER_SDK_SOURCE_SHA256
    || parsed.request_contract_sha256 !== TINKER_PROVIDER_REQUEST_CONTRACT_SHA256
    || parsed.base_url_sha256 !== TINKER_PROVIDER_BASE_URL_SHA256
    || parsed.tokenizer_path !== TINKER_TOKENIZER_PATH
    || parsed.tokenizer_release_sha256 !== TINKER_TOKENIZER_RELEASE_SHA256
    || parsed.idempotency_header_role !== "request_commitment_only"
    || parsed.idempotent_provider_replay_claimed !== false
    || parsed.automatic_provider_redispatch !== false
    || parsed.at_most_once_attempt_checkpoint !== true
    || parsed.terminal_ambiguity_hold !== true
    || parsed.ambiguous_outcome_ciphertext_retained !== true
    || parsed.provider_authoritative_invoice !== false
    || parsed.raw_secret_egress !== false
  ) throw new Error("Compute provider release failed its pinned schema checks");
  return parsed;
}

function parseProviderUsageEvidence(
  value: unknown,
  expected: ComputeDispatchIntentStatus,
): ComputeProviderUsageEvidence {
  const usage = record(value, "Compute provider usage");
  exactKeys(usage, "Compute provider usage", [
    "outcome", "prefill_tokens", "sample_tokens", "training_tokens",
    "result_commitment", "provider_authoritative_invoice",
  ]);
  const parsed: ComputeProviderUsageEvidence = {
    outcome: String(usage.outcome) as ComputeProviderUsageEvidence["outcome"],
    prefill_tokens: integer(usage.prefill_tokens, "provider prefill tokens", 0, 100_000_000),
    sample_tokens: integer(usage.sample_tokens, "provider sample tokens", 0, 100_000_000),
    training_tokens: integer(usage.training_tokens, "provider training tokens", 0, 100_000_000),
    result_commitment: nonzeroBytes32(usage.result_commitment, "provider result commitment"),
    provider_authoritative_invoice: usage.provider_authoritative_invoice as false,
  };
  if (
    !["succeeded", "failed"].includes(parsed.outcome)
    || parsed.prefill_tokens > expected.resource_limits.max_prefill_tokens
    || parsed.sample_tokens > expected.resource_limits.max_sample_tokens
    || parsed.training_tokens > expected.resource_limits.max_train_tokens
    || (parsed.outcome === "succeeded"
      && parsed.prefill_tokens + parsed.sample_tokens + parsed.training_tokens === 0)
    || parsed.provider_authoritative_invoice !== false
  ) throw new Error("Compute provider usage failed its bounded schema checks");
  return parsed;
}

function parseSignedUsageEvidence(
  value: unknown,
  expected: ComputeDispatchIntentStatus,
  providerUsage: ComputeProviderUsageEvidence,
): ComputeSignedUsageEvidence {
  const signed = record(value, "Compute signed usage request");
  exactKeys(signed, "Compute signed usage request", ["schema", "block", "usage"]);
  const block = record(signed.block, "Compute signed usage block");
  exactKeys(block, "Compute signed usage block", ["number", "hash"]);
  const usage = record(signed.usage, "Compute signed usage envelope");
  exactKeys(usage, "Compute signed usage envelope", [
    "schema", "job_id", "project_id", "user", "asset",
    "authorization_nonce", "max_asset_debit", "authorization_expiry",
    "rate_policy_commitment", "workload_commitment", "manifest_commitment",
    "dispatch_intent_commitment", "tee_identity", "compose_hash",
    "start_commitment", "model", "recipe", "outcome", "prefill_tokens",
    "sample_tokens", "training_tokens", "usage_started_at",
    "usage_observed_at", "raw_secret_egress", "usage_commitment",
    "tee_signature",
  ]);
  const authorizationNonce = parseDispatchUint256(
    usage.authorization_nonce,
    "signed usage authorization nonce",
  );
  const maxAssetDebit = parseDispatchUint256(
    usage.max_asset_debit,
    "signed usage maximum asset debit",
  );
  const prefill = parseDispatchUint256(usage.prefill_tokens, "signed usage prefill tokens");
  const sample = parseDispatchUint256(usage.sample_tokens, "signed usage sample tokens");
  const training = parseDispatchUint256(usage.training_tokens, "signed usage training tokens");
  const usageStartedAt = integer(usage.usage_started_at, "signed usage start time", 1, 4_102_444_800);
  const usageObservedAt = integer(usage.usage_observed_at, "signed usage observation time", 1, 4_102_444_800);
  const parsed: ComputeSignedUsageEvidence = {
    schema: signed.schema as ComputeSignedUsageEvidence["schema"],
    block: {
      number: integer(block.number, "signed usage block number", 1, Number.MAX_SAFE_INTEGER),
      hash: nonzeroBytes32(block.hash, "signed usage block hash"),
    },
    usage: {
      schema: usage.schema as ComputeSignedUsageEvidence["usage"]["schema"],
      job_id: nonzeroBytes32(usage.job_id, "signed usage job ID"),
      project_id: nonzeroBytes32(usage.project_id, "signed usage project ID"),
      user: lowerAddress(usage.user, "signed usage user", false),
      asset: lowerAddress(usage.asset, "signed usage asset", true),
      authorization_nonce: authorizationNonce.toString(),
      max_asset_debit: maxAssetDebit.toString(),
      authorization_expiry: integer(
        usage.authorization_expiry,
        "signed usage authorization expiry",
        1,
        4_102_444_800,
      ),
      rate_policy_commitment: nonzeroBytes32(
        usage.rate_policy_commitment,
        "signed usage rate-policy commitment",
      ),
      workload_commitment: nonzeroBytes32(
        usage.workload_commitment,
        "signed usage workload commitment",
      ),
      manifest_commitment: nonzeroBytes32(
        usage.manifest_commitment,
        "signed usage manifest commitment",
      ),
      dispatch_intent_commitment: nonzeroBytes32(
        usage.dispatch_intent_commitment,
        "signed usage dispatch intent commitment",
      ),
      tee_identity: lowerAddress(usage.tee_identity, "signed usage TEE identity", false),
      compose_hash: nonzeroBytes32(usage.compose_hash, "signed usage compose hash"),
      start_commitment: nonzeroBytes32(
        usage.start_commitment,
        "signed usage start commitment",
      ),
      model: usage.model as ComputeSignedUsageEvidence["usage"]["model"],
      recipe: usage.recipe as ComputeSignedUsageEvidence["usage"]["recipe"],
      outcome: usage.outcome as ComputeSignedUsageEvidence["usage"]["outcome"],
      prefill_tokens: prefill.toString(),
      sample_tokens: sample.toString(),
      training_tokens: training.toString(),
      usage_started_at: usageStartedAt,
      usage_observed_at: usageObservedAt,
      raw_secret_egress: usage.raw_secret_egress as false,
      usage_commitment: nonzeroBytes32(
        usage.usage_commitment,
        "signed usage commitment",
      ),
      tee_signature: canonicalSignature(usage.tee_signature, "signed usage TEE signature"),
    },
  };
  if (
    parsed.schema !== "dnai.compute-metering-request.v2"
    || parsed.usage.schema !== "dnai.compute-usage-envelope.v2"
    || parsed.usage.job_id !== expected.job_id
    || parsed.usage.project_id !== expected.project_id
    || parsed.usage.user !== expected.user
    || parsed.usage.asset !== expected.asset
    || authorizationNonce !== expected.authorization_nonce
    || maxAssetDebit !== expected.max_asset_debit
    || parsed.usage.authorization_expiry !== expected.authorization_expiry
    || parsed.usage.rate_policy_commitment !== expected.rate_policy_commitment
    || parsed.usage.workload_commitment !== expected.workload_commitment
    || parsed.usage.manifest_commitment !== expected.manifest_commitment
    || parsed.usage.dispatch_intent_commitment !== expected.intent_commitment
    || parsed.usage.compose_hash !== expected.compose_hash
    || parsed.usage.model !== expected.model
    || parsed.usage.recipe !== expected.recipe
    || parsed.usage.outcome !== providerUsage.outcome
    || prefill !== BigInt(providerUsage.prefill_tokens)
    || sample !== BigInt(providerUsage.sample_tokens)
    || training !== BigInt(providerUsage.training_tokens)
    || prefill > BigInt(expected.resource_limits.max_prefill_tokens)
    || sample > BigInt(expected.resource_limits.max_sample_tokens)
    || training > BigInt(expected.resource_limits.max_train_tokens)
    || usageObservedAt < usageStartedAt
    || usageObservedAt > expected.authorization_expiry
    || parsed.usage.raw_secret_egress !== false
  ) throw new Error("Compute signed usage failed its dispatch binding checks");
  const commitmentClaims = { ...parsed.usage } as Record<string, unknown>;
  delete commitmentClaims.usage_commitment;
  delete commitmentClaims.tee_signature;
  const derivedCommitment = sha256(encoder.encode(
    `${COMPUTE_USAGE_COMMITMENT_DOMAIN}${canonicalComputeJson(commitmentClaims)}`,
  ));
  if (derivedCommitment !== parsed.usage.usage_commitment) {
    throw new Error("Compute signed usage commitment does not match its canonical claims");
  }
  return parsed;
}

function parseIndependentMeteringEvidence(
  value: unknown,
  expected: ComputeDispatchIntentStatus,
  signedUsage: ComputeSignedUsageEvidence,
): ComputeIndependentMeteringEvidence {
  const decision = record(value, "Compute independent metering decision");
  exactKeys(decision, "Compute independent metering decision", [
    "schema", "classification", "provider_authoritative_invoice", "chain_id",
    "vault_address", "pinned_block_number", "pinned_block_hash",
    "policy_set_hash", "rate_policy_commitment", "workload_commitment",
    "manifest_commitment", "dispatch_intent_commitment", "asset", "job_id",
    "usage_commitment", "onchain_usage_commitment", "actual_asset_debit",
    "billable_compute_units", "usage_started_at", "usage_ended_at",
    "attestation_evidence_hash", "receipt_expiry", "metering_receipt_digest",
    "metering_qvl_receipt_digest", "metering_verifier",
    "metering_qvl_verifier", "tee_identity", "compose_hash",
    "raw_secret_egress", "verifier_signature", "qvl_signature",
  ]);
  const parsed: ComputeIndependentMeteringEvidence = {
    schema: decision.schema as ComputeIndependentMeteringEvidence["schema"],
    classification: decision.classification as ComputeIndependentMeteringEvidence["classification"],
    provider_authoritative_invoice: decision.provider_authoritative_invoice as false,
    chain_id: decision.chain_id as 84_532,
    vault_address: lowerAddress(decision.vault_address, "metering vault address", false),
    pinned_block_number: integer(
      decision.pinned_block_number,
      "metering pinned block number",
      1,
      Number.MAX_SAFE_INTEGER,
    ),
    pinned_block_hash: nonzeroBytes32(decision.pinned_block_hash, "metering pinned block hash"),
    policy_set_hash: nonzeroBytes32(decision.policy_set_hash, "metering policy-set hash"),
    rate_policy_commitment: nonzeroBytes32(
      decision.rate_policy_commitment,
      "metering rate-policy commitment",
    ),
    workload_commitment: nonzeroBytes32(
      decision.workload_commitment,
      "metering workload commitment",
    ),
    manifest_commitment: nonzeroBytes32(
      decision.manifest_commitment,
      "metering manifest commitment",
    ),
    dispatch_intent_commitment: nonzeroBytes32(
      decision.dispatch_intent_commitment,
      "metering dispatch intent commitment",
    ),
    asset: lowerAddress(decision.asset, "metering asset", true),
    job_id: nonzeroBytes32(decision.job_id, "metering job ID"),
    usage_commitment: nonzeroBytes32(decision.usage_commitment, "metering usage commitment"),
    onchain_usage_commitment: nonzeroBytes32(
      decision.onchain_usage_commitment,
      "onchain usage commitment",
    ),
    actual_asset_debit: parseDispatchUint256(
      decision.actual_asset_debit,
      "metered actual asset debit",
    ),
    billable_compute_units: parseDispatchUint256(
      decision.billable_compute_units,
      "metered billable compute units",
    ),
    usage_started_at: integer(decision.usage_started_at, "metering start time", 1, 4_102_444_800),
    usage_ended_at: integer(decision.usage_ended_at, "metering end time", 1, 4_102_444_800),
    attestation_evidence_hash: nonzeroBytes32(
      decision.attestation_evidence_hash,
      "metering attestation evidence hash",
    ),
    receipt_expiry: integer(decision.receipt_expiry, "metering receipt expiry", 1, 4_102_444_800),
    metering_receipt_digest: nonzeroBytes32(
      decision.metering_receipt_digest,
      "metering receipt digest",
    ),
    metering_qvl_receipt_digest: nonzeroBytes32(
      decision.metering_qvl_receipt_digest,
      "metering QVL receipt digest",
    ),
    metering_verifier: lowerAddress(decision.metering_verifier, "metering verifier", false),
    metering_qvl_verifier: lowerAddress(
      decision.metering_qvl_verifier,
      "metering QVL verifier",
      false,
    ),
    tee_identity: lowerAddress(decision.tee_identity, "metering TEE identity", false),
    compose_hash: nonzeroBytes32(decision.compose_hash, "metering compose hash"),
    raw_secret_egress: decision.raw_secret_egress as false,
    verifier_signature: canonicalSignature(
      decision.verifier_signature,
      "metering verifier signature",
    ),
    qvl_signature: canonicalSignature(decision.qvl_signature, "metering QVL signature"),
  };
  if (
    parsed.schema !== "dnai.compute-metering-decision.v2"
    || parsed.classification !== "attested_dual_verified_metering"
    || parsed.provider_authoritative_invoice !== false
    || parsed.chain_id !== 84_532
    || parsed.pinned_block_number !== signedUsage.block.number
    || parsed.pinned_block_hash !== signedUsage.block.hash
    || parsed.rate_policy_commitment !== expected.rate_policy_commitment
    || parsed.workload_commitment !== expected.workload_commitment
    || parsed.manifest_commitment !== expected.manifest_commitment
    || parsed.dispatch_intent_commitment !== expected.intent_commitment
    || parsed.asset !== expected.asset
    || parsed.job_id !== expected.job_id
    || parsed.usage_commitment !== signedUsage.usage.usage_commitment
    || parsed.actual_asset_debit > expected.max_asset_debit
    || parsed.billable_compute_units <= 0n
    || parsed.usage_started_at !== signedUsage.usage.usage_started_at
    || parsed.usage_ended_at !== signedUsage.usage.usage_observed_at
    || parsed.usage_ended_at < parsed.usage_started_at
    || parsed.receipt_expiry < parsed.usage_ended_at
    || parsed.receipt_expiry - parsed.usage_ended_at > 600
    || parsed.receipt_expiry > expected.authorization_expiry
    || parsed.tee_identity !== signedUsage.usage.tee_identity
    || parsed.compose_hash !== expected.compose_hash
    || parsed.metering_verifier === parsed.metering_qvl_verifier
    || parsed.metering_verifier === parsed.tee_identity
    || parsed.metering_qvl_verifier === parsed.tee_identity
    || parsed.raw_secret_egress !== false
  ) throw new Error("Compute independent metering failed its dispatch binding checks");
  return parsed;
}

function computeVaultUsageCommitment(
  expected: ComputeDispatchIntentStatus,
  signedUsage: ComputeSignedUsageEvidence,
  metering: ComputeIndependentMeteringEvidence,
): Hex {
  return keccak256(encodeAbiParameters(
    [
      { type: "bytes32" },
      { type: "uint256" },
      { type: "address" },
      { type: "bytes32" },
      { type: "bytes32" },
      { type: "address" },
      { type: "address" },
      { type: "uint256" },
      { type: "uint256" },
      { type: "uint256" },
      { type: "uint256" },
      { type: "bytes32" },
      { type: "bytes32" },
      { type: "bytes32" },
      { type: "bytes32" },
      { type: "address" },
      { type: "bytes32" },
      { type: "bytes32" },
      { type: "uint256" },
      { type: "uint256" },
      { type: "uint256" },
      { type: "bytes32" },
      { type: "bytes32" },
    ],
    [
      keccak256(stringToHex(COMPUTE_METERED_USAGE_TYPE)),
      BigInt(COMPUTE_VAULT_CHAIN_ID),
      metering.vault_address,
      expected.project_id,
      expected.job_id,
      expected.user,
      expected.asset,
      expected.authorization_nonce,
      expected.max_asset_debit,
      metering.actual_asset_debit,
      BigInt(expected.authorization_expiry),
      expected.rate_policy_commitment,
      expected.workload_commitment,
      expected.manifest_commitment,
      expected.intent_commitment,
      signedUsage.usage.tee_identity,
      expected.compose_hash,
      signedUsage.usage.start_commitment,
      metering.billable_compute_units,
      BigInt(metering.usage_started_at),
      BigInt(metering.usage_ended_at),
      metering.policy_set_hash,
      metering.attestation_evidence_hash,
    ],
  ));
}

function computeVaultMeteringReceiptDigest(
  kind: "meter" | "qvl",
  expected: ComputeDispatchIntentStatus,
  signedUsage: ComputeSignedUsageEvidence,
  metering: ComputeIndependentMeteringEvidence,
  onchainUsageCommitment: Hex,
): Hex {
  const domain = {
    name: COMPUTE_VAULT_EIP712_NAME,
    version: COMPUTE_VAULT_EIP712_VERSION,
    chainId: COMPUTE_VAULT_CHAIN_ID,
    verifyingContract: metering.vault_address,
  } as const;
  const message = {
    projectId: expected.project_id,
    jobId: expected.job_id,
    user: expected.user,
    asset: expected.asset,
    authorizationNonce: expected.authorization_nonce,
    maxAssetDebit: expected.max_asset_debit,
    actualAssetDebit: metering.actual_asset_debit,
    authorizationExpiry: BigInt(expected.authorization_expiry),
    ratePolicyCommitment: expected.rate_policy_commitment,
    workloadCommitment: expected.workload_commitment,
    manifestCommitment: expected.manifest_commitment,
    dispatchIntentCommitment: expected.intent_commitment,
    teeIdentity: signedUsage.usage.tee_identity,
    composeHash: expected.compose_hash,
    startCommitment: signedUsage.usage.start_commitment,
    billableComputeUnits: metering.billable_compute_units,
    usageStartedAt: BigInt(metering.usage_started_at),
    usageEndedAt: BigInt(metering.usage_ended_at),
    usageCommitment: onchainUsageCommitment,
    meteringPolicySetHash: metering.policy_set_hash,
    attestationEvidenceHash: metering.attestation_evidence_hash,
    receiptExpiry: BigInt(metering.receipt_expiry),
  } as const;
  if (kind === "meter") {
    return hashTypedData({
      domain,
      types: { ComputeMeteringReceipt: COMPUTE_METERING_RECEIPT_FIELDS },
      primaryType: "ComputeMeteringReceipt",
      message,
    });
  }
  return hashTypedData({
    domain,
    types: { ComputeMeteringQvlReceipt: COMPUTE_METERING_RECEIPT_FIELDS },
    primaryType: "ComputeMeteringQvlReceipt",
    message,
  });
}

export async function parseComputeExactAssetUsageReceipt(
  value: unknown,
  expected: ComputeDispatchIntentStatus,
): Promise<ComputeExactAssetUsageReceipt> {
  assertNoSensitiveFields(value);
  if (expected.stage !== "settled" || !expected.bounded_result) {
    throw new Error("Signed usage evidence is available only after settlement");
  }
  const receipt = record(value, "Compute exact-asset usage receipt");
  exactKeys(receipt, "Compute exact-asset usage receipt", [
    "surface", "schema_version", "access", "project_reference",
    "job_reference", "project_id", "job_id", "intent_commitment",
    "authorization", "workload_authority", "workload_claim_commitment",
    "workload_claim_confirmed",
    "execution_policy_context_hash", "provider_release_sha256",
    "provider_release", "provider_usage", "bounded_result", "signed_usage",
    "independent_metering", "settlement", "provider_authoritative_invoice",
    "exact_asset_only", "legacy_credit_ledger_mutated", "raw_prompt_egress",
    "raw_examples_egress", "raw_output_egress", "provider_identifier_egress",
    "raw_transaction_egress",
  ]);
  const providerRelease = parseTinkerProviderRelease(receipt.provider_release);
  const authorization = parseComputeDispatchAuthorization(
    receipt.authorization,
    false,
  );
  const workloadAuthority = parseComputeDispatchWorkloadAuthority(
    receipt.workload_authority,
    true,
  );
  const workloadClaimCommitment = nonzeroSha256(
    receipt.workload_claim_commitment,
    "usage receipt workload dispatch-claim commitment",
  );
  const providerReleaseSha = nonzeroSha256(
    receipt.provider_release_sha256,
    "provider release digest",
  );
  const rederivedReleaseSha = `sha256:${sha256(
    encoder.encode(canonicalComputeJson(providerRelease)),
  ).slice(2)}`;
  const providerUsage = parseProviderUsageEvidence(receipt.provider_usage, expected);
  const boundedResult = parseComputeBoundedResult(receipt.bounded_result, {
    operation: expected.operation,
    resultPolicy: expected.result_policy,
  });
  const signedUsage = parseSignedUsageEvidence(
    receipt.signed_usage,
    expected,
    providerUsage,
  );
  const metering = parseIndependentMeteringEvidence(
    receipt.independent_metering,
    expected,
    signedUsage,
  );
  const derivedOnchainUsageCommitment = computeVaultUsageCommitment(
    expected,
    signedUsage,
    metering,
  );
  const derivedMeteringReceiptDigest = computeVaultMeteringReceiptDigest(
    "meter",
    expected,
    signedUsage,
    metering,
    derivedOnchainUsageCommitment,
  );
  const derivedMeteringQvlReceiptDigest = computeVaultMeteringReceiptDigest(
    "qvl",
    expected,
    signedUsage,
    metering,
    derivedOnchainUsageCommitment,
  );
  if (
    metering.onchain_usage_commitment !== derivedOnchainUsageCommitment
    || metering.metering_receipt_digest !== derivedMeteringReceiptDigest
    || metering.metering_qvl_receipt_digest !== derivedMeteringQvlReceiptDigest
  ) {
    throw new Error(
      "Compute exact-asset usage receipt failed its local ComputeCreditVault digest derivation",
    );
  }
  const settlement = record(receipt.settlement, "Compute exact-asset settlement");
  exactKeys(settlement, "Compute exact-asset settlement", [
    "confirmed", "chain_id", "vault_address", "transaction_hash",
    "onchain_usage_commitment", "actual_asset_debit",
    "billable_compute_units", "attestation_evidence_hash", "receipt_expiry",
  ]);
  const parsedSettlement: ComputeExactAssetUsageReceipt["settlement"] = {
    confirmed: settlement.confirmed as true,
    chain_id: settlement.chain_id as 84_532,
    vault_address: lowerAddress(settlement.vault_address, "settlement vault address", false),
    transaction_hash: nonzeroBytes32(settlement.transaction_hash, "settlement transaction hash"),
    onchain_usage_commitment: nonzeroBytes32(
      settlement.onchain_usage_commitment,
      "settlement usage commitment",
    ),
    actual_asset_debit: parseDispatchUint256(
      settlement.actual_asset_debit,
      "settlement actual asset debit",
    ),
    billable_compute_units: parseDispatchUint256(
      settlement.billable_compute_units,
      "settlement billable compute units",
    ),
    attestation_evidence_hash: nonzeroBytes32(
      settlement.attestation_evidence_hash,
      "settlement attestation evidence hash",
    ),
    receipt_expiry: integer(
      settlement.receipt_expiry,
      "settlement receipt expiry",
      1,
      4_102_444_800,
    ),
  };
  const parsed: ComputeExactAssetUsageReceipt = {
    surface: receipt.surface as ComputeExactAssetUsageReceipt["surface"],
    schema_version: receipt.schema_version as 2,
    access: receipt.access as ComputeExactAssetUsageReceipt["access"],
    project_reference: boundedReference(
      receipt.project_reference,
      "usage receipt project reference",
    ),
    job_reference: boundedReference(receipt.job_reference, "usage receipt job reference"),
    project_id: nonzeroBytes32(receipt.project_id, "usage receipt project ID"),
    job_id: nonzeroBytes32(receipt.job_id, "usage receipt job ID"),
    intent_commitment: nonzeroBytes32(
      receipt.intent_commitment,
      "usage receipt intent commitment",
    ),
    authorization,
    workload_authority: workloadAuthority,
    workload_claim_commitment: workloadClaimCommitment,
    workload_claim_confirmed: receipt.workload_claim_confirmed as true,
    execution_policy_context_hash:
      typeof receipt.execution_policy_context_hash === "string"
      && HEX_64.test(receipt.execution_policy_context_hash)
        ? receipt.execution_policy_context_hash
        : "",
    provider_release_sha256: providerReleaseSha,
    provider_release: providerRelease,
    provider_usage: providerUsage,
    bounded_result: boundedResult,
    signed_usage: signedUsage,
    independent_metering: metering,
    settlement: parsedSettlement,
    provider_authoritative_invoice: receipt.provider_authoritative_invoice as false,
    exact_asset_only: receipt.exact_asset_only as true,
    legacy_credit_ledger_mutated: receipt.legacy_credit_ledger_mutated as false,
    raw_prompt_egress: receipt.raw_prompt_egress as false,
    raw_examples_egress: receipt.raw_examples_egress as false,
    raw_output_egress: receipt.raw_output_egress as false,
    provider_identifier_egress: receipt.provider_identifier_egress as false,
    raw_transaction_egress: receipt.raw_transaction_egress as false,
    browser_verification: {
      usage_commitment_rederived: true,
      tee_signature_recovered: true,
      onchain_usage_commitment_rederived: true,
      metering_receipt_digest_rederived: true,
      metering_qvl_receipt_digest_rederived: true,
      metering_eoa_signature_recovered: true,
      metering_qvl_eoa_signature_recovered: true,
      erc1271_contract_signature_checked: false,
      release_state_anchored_in_browser: false,
    },
  };
  if (
    parsed.surface !== "compute_exact_asset_usage_receipt"
    || parsed.schema_version !== 2
    || parsed.access !== "wallet_authenticated_project_member"
    || parsed.project_reference !== expected.project_reference
    || parsed.job_reference !== expected.job_reference
    || parsed.project_id !== expected.project_id
    || parsed.job_id !== expected.job_id
    || parsed.intent_commitment !== expected.intent_commitment
    || parsed.authorization.kind !== expected.authorization.kind
    || parsed.authorization.context_commitment
      !== expected.authorization.context_commitment
    || parsed.workload_authority.source_kind
      !== expected.workload_authority.source_kind
    || parsed.workload_authority.execution_binding_commitment
      !== expected.workload_authority.execution_binding_commitment
    || parsed.workload_authority.recipient_release_commitment
      !== expected.workload_authority.recipient_release_commitment
    || parsed.workload_authority.funding_wallet !== expected.user
    || parsed.workload_claim_commitment
      !== expected.workload_claim_commitment
    || parsed.workload_claim_confirmed !== true
    || parsed.execution_policy_context_hash !== expected.execution_policy_context_hash
    || providerReleaseSha !== TINKER_PROVIDER_RELEASE_SHA256
    || rederivedReleaseSha !== providerReleaseSha
    || providerUsage.outcome !== boundedResult.outcome
    || providerUsage.result_commitment !== boundedResult.result_commitment
    || boundedResult.result_commitment !== expected.bounded_result.result_commitment
    || boundedResult.outcome !== expected.bounded_result.outcome
    || parsedSettlement.confirmed !== true
    || parsedSettlement.chain_id !== 84_532
    || parsedSettlement.vault_address !== metering.vault_address
    || parsedSettlement.onchain_usage_commitment !== metering.onchain_usage_commitment
    || parsedSettlement.actual_asset_debit !== metering.actual_asset_debit
    || parsedSettlement.billable_compute_units !== metering.billable_compute_units
    || parsedSettlement.attestation_evidence_hash !== metering.attestation_evidence_hash
    || parsedSettlement.receipt_expiry !== metering.receipt_expiry
    || parsed.provider_authoritative_invoice !== false
    || parsed.exact_asset_only !== true
    || parsed.legacy_credit_ledger_mutated !== false
    || parsed.raw_prompt_egress !== false
    || parsed.raw_examples_egress !== false
    || parsed.raw_output_egress !== false
    || parsed.provider_identifier_egress !== false
    || parsed.raw_transaction_egress !== false
  ) throw new Error("Compute exact-asset usage receipt failed its settlement binding checks");
  try {
    const [teeSigner, meterSigner, qvlSigner] = await Promise.all([
      recoverMessageAddress({
        message: { raw: signedUsage.usage.usage_commitment },
        signature: signedUsage.usage.tee_signature,
      }),
      recoverAddress({
        hash: metering.metering_receipt_digest,
        signature: metering.verifier_signature,
      }),
      recoverAddress({
        hash: metering.metering_qvl_receipt_digest,
        signature: metering.qvl_signature,
      }),
    ]);
    if (
      teeSigner.toLowerCase() !== signedUsage.usage.tee_identity
      || meterSigner.toLowerCase() !== metering.metering_verifier
      || qvlSigner.toLowerCase() !== metering.metering_qvl_verifier
    ) throw new Error("signature signer mismatch");
  } catch {
    throw new Error(
      "Compute exact-asset usage signatures could not be authenticated by browser EOA recovery; ERC-1271 contract signatures require a pinned onchain check",
    );
  }
  return parsed;
}

export async function fetchComputeDispatchUsageReceipt(
  token: string,
  status: ComputeDispatchIntentStatus,
): Promise<ComputeExactAssetUsageReceipt> {
  if (status.stage !== "settled") {
    throw new Error("Signed usage evidence is available only after settlement");
  }
  const result = await request(
    `/compute/projects/${encodeURIComponent(status.project_reference)}/dispatch-intents/${encodeURIComponent(status.job_reference)}/usage-receipt`,
    { token, timeout: 15_000 },
  );
  return parseComputeExactAssetUsageReceipt(result, status);
}

/**
 * Resolve a public Compute policy target only through the authenticated exact-
 * asset status route. Legacy service-credit job IDs are intentionally not
 * accepted by this browser workflow.
 */
export async function fetchComputeExecutionPolicyTarget(
  token: string,
  projectReference: string,
  jobReference: string,
  expectedWalletAddress: string,
): Promise<ComputeExecutionPolicyTarget> {
  const intent = await fetchComputeDispatchIntent(
    token,
    projectReference,
    jobReference,
  );
  const recomputed = computeExecutionPolicyContextHash({
    jobId: intent.job_id,
    intentCommitment: intent.intent_commitment,
    operation: intent.operation,
    model: intent.model,
    recipe: intent.recipe,
  });
  if (recomputed !== intent.execution_policy_context_hash) {
    throw new Error(
      "Authenticated Compute intent drifted from its execution-policy context",
    );
  }
  const expectedUser = lowerAddress(
    expectedWalletAddress,
    "expected Compute policy wallet",
    false,
  );
  if (intent.user !== expectedUser) {
    throw new Error(
      "Authenticated Compute intent is owned by a different wallet",
    );
  }
  return {
    resourceId: intent.job_id,
    executionContextHash: recomputed,
    authorizedUser: intent.user,
  };
}

export async function createComputeDispatchIntent(
  token: string,
  project: ComputeProject,
  capability: ComputeDispatchCapability,
  input: ComputeDispatchIntentInput,
  idempotencyKey: string,
): Promise<ComputeDispatchIntentResult> {
  if (!canCreateComputeDispatchIntent(project, capability)) {
    throw new Error("Exact-asset dispatch-intent creation is not enabled by this release");
  }
  if (
    !("allowed_result_policies" in capability.provider)
    || !capability.provider.allowed_operations.includes(input.operation)
    || !capability.provider.allowed_result_policies.includes(
      input.resultPolicy as "bounded_summary_receipt",
    )
  ) {
    throw new Error(
      "Operation or result policy is not supported by the provider release",
    );
  }
  if (!IDEMPOTENCY_KEY.test(idempotencyKey)) throw new Error("Compute dispatch idempotency key is malformed");
  const body = normalizeDispatchInput(input);
  const result = record(await request(
    `/compute/projects/${encodeURIComponent(project.project_id)}/dispatch-intents`,
    { method: "POST", token, idempotencyKey, body },
  ), "Compute dispatch-intent result");
  exactKeys(result, "Compute dispatch-intent result", [
    "surface", "schema_version", "created", "idempotent_replay", "intent",
    "workload_claim_created", "workload_claim_confirmed",
    "workload_claim_recovered", "workload_claim_commitment",
    "legacy_credit_ledger_mutated", "provider_dispatch_status",
    "provider_dispatch_may_have_occurred", "provider_authoritative",
  ]);
  const created = boolean(result.created, "dispatch-intent created flag");
  const replay = boolean(result.idempotent_replay, "dispatch-intent replay flag");
  const claimCreated = boolean(
    result.workload_claim_created,
    "dispatch workload-claim created flag",
  );
  const claimConfirmed = boolean(
    result.workload_claim_confirmed,
    "dispatch workload-claim confirmation",
  );
  const claimRecovered = boolean(
    result.workload_claim_recovered,
    "dispatch workload-claim recovery flag",
  );
  const claimCommitment = nonzeroSha256(
    result.workload_claim_commitment,
    "dispatch workload-claim commitment",
  );
  const intent = parseComputeDispatchIntent(result.intent, {
    projectReference: project.project_id,
    jobReference: String(body.job_reference),
  });
  if (
    result.surface !== "compute_dispatch_intent_result"
    || result.schema_version !== 3
    || created === replay
    || !claimConfirmed
    || claimCommitment !== intent.workload_claim_commitment
    || (created && claimRecovered)
    || (claimRecovered && !replay)
    || result.legacy_credit_ledger_mutated !== false
    || result.provider_authoritative !== false
    || result.provider_dispatch_status !== intent.provider_dispatch_status
    || result.provider_dispatch_may_have_occurred !== intent.provider_dispatch_may_have_occurred
  ) throw new Error("Compute dispatch-intent result is contradictory");
  return {
    created,
    idempotentReplay: replay,
    workloadClaimCreated: claimCreated,
    workloadClaimConfirmed: true,
    workloadClaimRecovered: claimRecovered,
    workloadClaimCommitment: claimCommitment,
    intent,
  };
}

export function normalizeComputeJobCreateInput(
  project: ComputeProject,
  input: ComputeJobCreateInput,
): ComputeJobCreateInput {
  assertProject(project);
  const candidate = record(input, "Compute job create input");
  exactKeys(candidate, "Compute job create input", [
    "name", "operation", "maxCredits", "resultPolicy", "environmentVersion",
  ]);
  const name = text(candidate.name, "public job label", 64).trim();
  const operation = candidate.operation;
  const resultPolicy = candidate.resultPolicy;
  const maxCredits = integer(candidate.maxCredits, "job reservation", 1, 500);
  if (
    !COMPUTE_JOB_PUBLIC_LABEL.test(name)
    || !["owner", "admin", "developer"].includes(project.role)
    || !["inference", "training"].includes(String(operation))
    || !project.policy.allowed_operations.map(String).includes(String(operation))
    || !["bounded_summary_receipt", "score_band_hash"].includes(String(resultPolicy))
    || candidate.environmentVersion !== COMPUTE_JOB_ENVIRONMENT_MARKER
    || maxCredits > project.policy.per_job_max_credits
  ) throw new Error("Compute job request is outside the release-bounded project policy");
  return {
    name,
    operation: operation as ComputeJobCreateInput["operation"],
    maxCredits,
    resultPolicy: resultPolicy as ComputeJobCreateInput["resultPolicy"],
    environmentVersion: COMPUTE_JOB_ENVIRONMENT_MARKER,
  };
}

export function parseComputeJobCreateResult(
  value: unknown,
  projectId: string,
  expected: ComputeJobCreateInput,
): ComputeJobCreateResult {
  assertNoSensitiveFields(value);
  const result = record(value, "Compute job result");
  exactKeys(result, "Compute job result", [
    "surface", "created", "idempotent_replay", "job", "provider_dispatch_performed",
  ]);
  const created = boolean(result.created, "job created flag");
  const replay = boolean(result.idempotent_replay, "job replay flag");
  assertJob(result.job, projectId);
  const job = result.job;
  const expectedRecipe = expected.operation === "training" ? "qwen3_8b_lora_r32" : "qwen3_8b_bounded";
  if (
    result.surface !== "compute_job_result"
    || created === replay
    || result.provider_dispatch_performed !== false
    || job.name !== expected.name
    || job.operation !== expected.operation
    || job.recipe !== expectedRecipe
    || job.max_credits !== expected.maxCredits
    || job.result_policy !== expected.resultPolicy
    || job.environment_version !== expected.environmentVersion
    || (created && (
      job.status !== "queued"
      || job.actual_credits !== null
      || job.released_credits !== null
      || job.started_at !== null
      || job.completed_at !== null
      || job.metering_source !== null
      || job.usage_receipt_hash !== null
      || job.settlement_authority !== null
    ))
  ) throw new Error("Compute job result is contradictory or outside the requested reservation");
  return { created, idempotentReplay: replay, job };
}

export async function createJob(
  token: string,
  project: ComputeProject,
  input: ComputeJobCreateInput,
  idempotencyKey: string,
): Promise<ComputeJobCreateResult> {
  if (!IDEMPOTENCY_KEY.test(idempotencyKey)) throw new Error("Compute job idempotency key is malformed");
  const normalized = normalizeComputeJobCreateInput(project, input);
  const result = await request(`/compute/projects/${encodeURIComponent(project.project_id)}/jobs`, {
    method: "POST",
    token,
    idempotencyKey,
    body: {
      name: normalized.name,
      operation: normalized.operation,
      model: "qwen3_8b",
      recipe: normalized.operation === "training" ? "qwen3_8b_lora_r32" : "qwen3_8b_bounded",
      max_credits: normalized.maxCredits,
      result_policy: normalized.resultPolicy,
      environment_version: normalized.environmentVersion,
    },
  });
  return parseComputeJobCreateResult(result, project.project_id, normalized);
}

export function canCancelComputeJob(job: ComputeJob, role: ProjectRole | undefined): boolean {
  return (
    role !== undefined
    && ["owner", "admin", "developer"].includes(role)
    && job.status === "queued"
    && job.dispatch_status === "not_dispatched"
    && job.started_at === null
    && job.completed_at === null
    && job.actual_credits === null
    && job.released_credits === null
    && job.metering_source === null
    && job.usage_receipt_hash === null
    && job.settlement_authority === null
  );
}

export function parseComputeJobCancellation(
  value: unknown,
  expectedProjectId: string,
  expectedJobId: string,
): ComputeJobCancellationReceipt {
  assertNoSensitiveFields(value);
  const result = record(value, "Compute job cancellation");
  exactKeys(result, "Compute job cancellation", [
    "surface",
    "schema_version",
    "project_id",
    "job_id",
    "status",
    "changed",
    "idempotent_replay",
    "released_credits",
    "credit_reversal",
    "ledger",
    "provider_dispatch_performed",
    "service_settlement_performed",
  ]);
  const ledger = record(result.ledger, "Compute cancellation ledger receipt");
  exactKeys(ledger, "Compute cancellation ledger receipt", [
    "transaction_id",
    "sequence",
    "kind",
    "transaction_hash",
    "previous_hash",
    "settlement_status",
  ]);
  if (
    result.surface !== "compute_job_cancellation"
    || result.schema_version !== 1
    || result.project_id !== expectedProjectId
    || result.job_id !== expectedJobId
    || !RESOURCE_ID.test(expectedProjectId)
    || !RESOURCE_ID.test(expectedJobId)
    || result.status !== "canceled"
    || typeof result.changed !== "boolean"
    || typeof result.idempotent_replay !== "boolean"
    || result.changed === result.idempotent_replay
    || result.credit_reversal !== "reserved_to_available"
    || result.provider_dispatch_performed !== false
    || result.service_settlement_performed !== false
    || !RESOURCE_ID.test(String(ledger.transaction_id))
    || ledger.kind !== "job_cancel"
    || !HEX_64.test(String(ledger.transaction_hash))
    || !HEX_64.test(String(ledger.previous_hash))
    || ledger.settlement_status !== "user_canceled_before_dispatch"
  ) throw new Error("Compute job cancellation failed its bounded schema checks");
  integer(result.released_credits, "released credits", 1, 500);
  integer(ledger.sequence, "cancellation ledger sequence", 1, 40_000);
  return result as unknown as ComputeJobCancellationReceipt;
}

export async function cancelComputeJob(
  token: string,
  projectId: string,
  jobId: string,
  idempotencyKey: string,
): Promise<ComputeJobCancellationReceipt> {
  if (!RESOURCE_ID.test(projectId) || !RESOURCE_ID.test(jobId)) {
    throw new Error("Compute cancellation target is malformed");
  }
  if (!IDEMPOTENCY_KEY.test(idempotencyKey)) {
    throw new Error("Compute cancellation idempotency key is malformed");
  }
  const result = await request(
    `/compute/projects/${encodeURIComponent(projectId)}/jobs/${encodeURIComponent(jobId)}/cancel`,
    {
      method: "POST",
      token,
      idempotencyKey,
      body: { reason: "user_requested_before_dispatch" },
    },
  );
  return parseComputeJobCancellation(result, projectId, jobId);
}

function bytesFromHex(value: string, exactBytes?: number): Uint8Array {
  if (!/^[0-9a-f]+$/.test(value) || value.length % 2 !== 0) throw new Error("Credential capsule contains invalid hex");
  const bytes = new Uint8Array(value.length / 2);
  for (let index = 0; index < bytes.length; index += 1) bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  if (exactBytes !== undefined && bytes.length !== exactBytes) throw new Error("Credential capsule field has an invalid length");
  return bytes;
}

function hexFromBytes(value: ArrayBuffer | Uint8Array): string {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function buffer(value: Uint8Array): ArrayBuffer {
  return value.slice().buffer as ArrayBuffer;
}

export async function generateDeviceKey(): Promise<DeviceKeyMaterial> {
  if (!crypto?.subtle) throw new Error("This browser cannot create a device encryption key");
  const pair = await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]) as CryptoKeyPair;
  const publicKey = await crypto.subtle.exportKey("raw", pair.publicKey);
  return { publicKeyHex: hexFromBytes(publicKey), privateKey: pair.privateKey };
}

async function sha256Text(value: string): Promise<string> {
  return hexFromBytes(await crypto.subtle.digest("SHA-256", encoder.encode(value)));
}

export async function decryptCredentialCapsule(delivery: ComputeCredentialDelivery, deviceKey: DeviceKeyMaterial): Promise<string> {
  const { capsule, credential } = delivery;
  const ephemeralBytes = bytesFromHex(capsule.encrypted_token.ephemeral_public_key, 32);
  const nonce = bytesFromHex(capsule.encrypted_token.nonce, 12);
  const ciphertext = bytesFromHex(capsule.encrypted_token.ciphertext);
  const associatedData = bytesFromHex(capsule.associated_data);
  let shared = new Uint8Array();
  let plaintext = new Uint8Array();
  try {
    if (await sha256Text(`compute_credential_aad:${capsule.associated_data}`) !== capsule.associated_data_hash) {
      throw new Error("Credential token associated-data commitment is invalid");
    }
    if (await sha256Text(`compute_device_key:${deviceKey.publicKeyHex}`) !== capsule.recipient_public_key_hash) {
      throw new Error("Credential token recipient commitment is invalid");
    }
    const binding = record(JSON.parse(decoder.decode(associatedData)), "Credential token binding");
    if (
      Object.keys(binding).sort().join(",") !== "credential_id,device_id,expires_at,generation,jwt_id_hash,project_id,surface"
      || binding.surface !== "compute_credential"
      || binding.credential_id !== credential.credential_id
      || binding.project_id !== credential.project_id
      || binding.device_id !== credential.device_id
      || binding.generation !== credential.generation
      || binding.expires_at !== credential.expires_at
      || !HEX_64.test(String(binding.jwt_id_hash))
    ) throw new Error("Credential token binding does not match the issuance receipt");
    const ephemeral = await crypto.subtle.importKey("raw", buffer(ephemeralBytes), { name: "X25519" }, false, []);
    shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: ephemeral }, deviceKey.privateKey, 256));
    const hkdf = await crypto.subtle.importKey("raw", buffer(shared), "HKDF", false, ["deriveKey"]);
    const key = await crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(), info: encoder.encode("dnai-wikigen-compute-credential-v1") },
      hkdf,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"],
    );
    plaintext = new Uint8Array(await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: buffer(nonce), additionalData: buffer(associatedData), tagLength: 128 },
      key,
      buffer(ciphertext),
    ));
    const token = decoder.decode(plaintext);
    await validateCredentialTokenShape(token, credential, String(binding.jwt_id_hash));
    return token;
  } catch (cause) {
    if (cause instanceof Error && (cause.message.startsWith("Credential token") || cause.message.startsWith("Credential capsule"))) throw cause;
    throw new Error("Credential capsule could not be authenticated for this device");
  } finally {
    ephemeralBytes.fill(0);
    nonce.fill(0);
    ciphertext.fill(0);
    associatedData.fill(0);
    shared.fill(0);
    plaintext.fill(0);
  }
}

function decodeBase64UrlJson(value: string): Record<string, unknown> {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error("Credential token encoding is invalid");
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (value.length % 4)) % 4);
  const bytes = Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
  if (bytes.length > 8_192) throw new Error("Credential token segment exceeds its bound");
  return record(JSON.parse(decoder.decode(bytes)), "Credential token segment");
}

async function validateCredentialTokenShape(token: string, credential: ComputeCredential, expectedJwtIdHash: string): Promise<void> {
  if (token.length < 80 || token.length > 4096) throw new Error("Credential token length is invalid");
  const parts = token.split(".");
  if (parts.length !== 3 || parts.some((part) => !/^[A-Za-z0-9_-]+$/.test(part))) throw new Error("Credential token format is invalid");
  const header = decodeBase64UrlJson(parts[0]);
  const payload = decodeBase64UrlJson(parts[1]);
  const now = Math.floor(Date.now() / 1000);
  const jwtId = String(payload.jti ?? "");
  if (
    Object.keys(header).sort().join(",") !== "alg,kid,typ"
    || header.alg !== "HS256"
    || header.kid !== "dstack-compute-credential-v1"
    || header.typ !== "JWT"
    || payload.sub !== credential.credential_id
    || payload.project_id !== credential.project_id
    || payload.device_id !== credential.device_id
    || payload.generation !== credential.generation
    || payload.daily_credit_cap !== credential.daily_credit_cap
    || payload.iat !== credential.issued_at
    || payload.nbf !== payload.iat
    || payload.exp !== credential.expires_at
    || !Number.isInteger(payload.iat)
    || Number(payload.iat) > now + 30
    || !Number.isInteger(payload.exp)
    || Number(payload.exp) <= now
    || Number(payload.exp) <= Number(payload.iat)
    || Number(payload.exp) - Number(payload.iat) > 604_800
    || !/^[0-9a-f]{32}$/.test(jwtId)
    || String(payload.scope).split(" ").join(",") !== credential.scopes.join(",")
  ) throw new Error("Credential token claims do not match the issuance receipt");
  if (await sha256Text(`compute_credential_jti:${jwtId}`) !== expectedJwtIdHash) {
    throw new Error("Credential token id does not match the authenticated capsule binding");
  }
}

export function newIdempotencyKey(prefix: string): string {
  const normalized = prefix.toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 24) || "request";
  return `${normalized}:${crypto.randomUUID()}`;
}

export class UnresolvedIdempotencyAttempt {
  private attempt?: { fingerprint: string; key: string };

  keyFor(prefix: string, fingerprint: string): string {
    const requestFingerprint = `${prefix}\u0000${fingerprint}`;
    if (this.attempt?.fingerprint === requestFingerprint) return this.attempt.key;
    const key = newIdempotencyKey(prefix);
    this.attempt = { fingerprint: requestFingerprint, key };
    return key;
  }

  resolve(key: string): void {
    if (this.attempt?.key === key) this.attempt = undefined;
  }
}
