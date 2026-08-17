import { afterEach, describe, expect, it, vi } from "vitest";
import {
  encodeAbiParameters,
  hashTypedData,
  keccak256,
  sha256,
  stringToHex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { deployment } from "../config";
import {
  cancelComputeDispatchIntent,
  cancelComputeJob,
  canCancelComputeDispatchIntent,
  canReplayComputeDispatchCancellationAttempt,
  canCancelComputeJob,
  canCreateComputeDispatchIntent,
  computeDispatchCancellationCheckpointCommitment,
  computeDispatchIntentCommitment,
  computeDispatchIntentV3Commitment,
  computeStandaloneAuthorizationContextCommitment,
  computeExecutionPolicyContextHash,
  createComputeDispatchCancellationAttempt,
  createComputeDispatchIntent,
  createJob,
  decryptCredentialCapsule,
  fetchComputeExecutionPolicyTarget,
  fetchComputeDispatchIntent,
  fetchComputeDispatchUsageReceipt,
  generateDeviceKey,
  parseComputeDispatchCancellation,
  parseComputeDispatchCancellationAttempt,
  parseComputeDispatchIntent,
  parseComputeExactAssetUsageReceipt,
  parseComputeFundingCapabilities,
  parseDispatchUint256,
  parseComputeJobCancellation,
  parseComputeJobCreateResult,
  normalizeComputeJobCreateInput,
  UnresolvedIdempotencyAttempt,
  type ComputeDispatchCapability,
  type ComputeDispatchIntentStatus,
  type ComputeProviderCapabilityRelease,
  type ComputeCredential,
  type ComputeCredentialDelivery,
  type ComputeJob,
  type ComputeJobCreateInput,
  type ComputeJobCancellationReceipt,
  type ComputeProject,
  type DeviceKeyMaterial,
} from "./compute";
import { canonicalComputeJson } from "./computeDispatchCommitment";
import { computeVaultJobId, computeVaultProjectId } from "./computeVault";
import contextVectors from "./computeExecutionPolicyContextVectors.json";

const encoder = new TextEncoder();

function buffer(value: Uint8Array): ArrayBuffer {
  return value.slice().buffer as ArrayBuffer;
}

function hex(value: ArrayBuffer | Uint8Array): string {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function b64url(value: string): string {
  const bytes = encoder.encode(value);
  let binary = "";
  bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

async function digest(value: string): Promise<string> {
  return hex(await crypto.subtle.digest("SHA-256", encoder.encode(value)));
}

describe("Compute project idempotency attempts", () => {
  it("reuses one key only while the same create request is unresolved", () => {
    const attempt = new UnresolvedIdempotencyAttempt();
    const first = attempt.keyFor("project", "0xowner:atlas-research");

    expect(attempt.keyFor("project", "0xowner:atlas-research")).toBe(first);
    expect(attempt.keyFor("project", "0xowner:another-project")).not.toBe(first);
  });

  it("clears on authoritative create success before a downstream refresh failure", () => {
    const attempt = new UnresolvedIdempotencyAttempt();
    const committed = attempt.keyFor("project", "0xowner:atlas-research");
    attempt.resolve(committed);

    expect(() => {
      throw new Error("project list refresh failed");
    }).toThrow("project list refresh failed");
    expect(attempt.keyFor("project", "0xowner:atlas-research")).not.toBe(committed);
  });

  it("does not let a stale completion clear the current unresolved request", () => {
    const attempt = new UnresolvedIdempotencyAttempt();
    const stale = attempt.keyFor("project", "0xowner:first-project");
    const current = attempt.keyFor("project", "0xowner:second-project");

    attempt.resolve(stale);
    expect(attempt.keyFor("project", "0xowner:second-project")).toBe(current);
  });
});

const issuedAt = Math.floor(Date.now() / 1000) - 5;

const credential: ComputeCredential = {
  credential_id: "cred_0123456789abcdef01234567",
  project_id: "proj_0123456789abcdef01234567",
  device_id: "dev_0123456789abcdef01234567",
  name: "test-device",
  prefix: "wk_dev_234567",
  scopes: ["jobs:create", "jobs:read"],
  daily_credit_cap: 500,
  generation: 1,
  status: "active",
  issued_at: issuedAt,
  expires_at: issuedAt + 3_600,
  last_used_at: null,
  rotated_at: null,
  revoked_at: null,
  plaintext_token_stored: false,
  upstream_tinker_key_exposed: false,
};

const queuedJob: ComputeJob = {
  job_id: "job_0123456789abcdef01234567",
  project_id: credential.project_id,
  name: "bounded-sample",
  operation: "inference",
  model: "qwen3_8b",
  recipe: "qwen3_8b_bounded",
  max_credits: 125,
  actual_credits: null,
  released_credits: null,
  result_policy: "bounded_summary_receipt",
  environment_version: "env_v1",
  status: "queued",
  dispatch_status: "not_dispatched",
  backend_capability: "future_inference_proxy",
  credential_id: null,
  created_at: issuedAt,
  updated_at: issuedAt,
  started_at: null,
  completed_at: null,
  metering_source: null,
  usage_receipt_hash: null,
  settlement_authority: null,
  provider_authoritative_settlement: false,
  raw_input_persisted: false,
  raw_output_persisted: false,
};

const dispatchProject: ComputeProject = {
  project_id: "prj_0123456789abcdef01234567",
  name: "exact-asset-lab",
  role: "owner",
  policy: {
    per_job_max_credits: 500,
    daily_project_max_credits: 2_500,
    credential_max_ttl_seconds: 604_800,
    allowed_operations: ["inference", "training"],
  },
  members: [{ address: `0x${"1".repeat(40)}`, role: "owner" }],
  created_at: issuedAt,
  updated_at: issuedAt,
  credit_instrument: "closed_loop_nontransferable_service_credit",
  provider_dispatch_enabled: false,
};

function providerCapability(
  overrides: Partial<ComputeProviderCapabilityRelease> = {},
): ComputeProviderCapabilityRelease {
  return {
    schema: "dnai.compute.provider-capability.v1",
    source_present: true,
    release_configured: false,
    provider_dispatch: false,
    allowed_operations: ["inference", "training"],
    allowed_result_policies: ["bounded_summary_receipt"],
    adapter_id: "tinker_sdk_0_22_7_at_most_once_v1",
    sdk_version: "0.22.7",
    sdk_source_sha256: "sha256:3ab30e85f4d1ae21ab4a8b415d382e719decd3abb31e61f6e481e8e5296dac62",
    request_contract_sha256: "sha256:15f112c2e285ba2463d36fe32a47f78eda40f7ca81d7b49f6d51dc4378feef0d",
    base_url_sha256: "sha256:e3ae09c22c856fa175bfbeded8819e1665f39c235869a15e3e0729bfb4f39533",
    provider_release_sha256: "sha256:4264a2226ac9c850d8f053c98ac90d0f6dcbc58702919899384a9b2442b35631",
    idempotency_header_role: "request_commitment_only",
    idempotent_provider_replay_claimed: false,
    automatic_provider_redispatch: false,
    adapter_contract: {
      at_most_once_attempt_checkpoint: true,
      terminal_ambiguity_hold: true,
      ambiguous_outcome_ciphertext_retained: true,
    },
    runtime_guarantees: {
      at_most_once_attempt_checkpoint: false,
      terminal_ambiguity_hold: false,
      ambiguous_outcome_ciphertext_retained: false,
    },
    reason: "provider_execution_not_enabled",
    ...overrides,
  };
}

function readyProviderCapability(
  overrides: Partial<ComputeProviderCapabilityRelease> = {},
): ComputeProviderCapabilityRelease {
  return providerCapability({
    release_configured: true,
    provider_dispatch: true,
    runtime_guarantees: {
      at_most_once_attempt_checkpoint: true,
      terminal_ambiguity_hold: true,
      ambiguous_outcome_ciphertext_retained: true,
    },
    runtime: {
      authenticated: true,
      fresh: true,
      process_presence_only: true,
      tdx_evidence: false,
      observed_at: 1_900_000_000,
    },
    reason: "ready_at_most_once_ambiguity_hold",
    ...overrides,
  });
}

function dispatchCapability(overrides: Partial<ComputeDispatchCapability> = {}): ComputeDispatchCapability {
  return {
    metadata_intent_creation: false,
    provider_dispatch: false,
    independent_metering: false,
    settlement: false,
    credential_workload_wallet_adoption: false,
    wallet_adoption_authority: "project_owner_admin_developer",
    wallet_source_transfer_supported: false,
    device_spending_authority: false,
    exact_asset_only: true,
    mutation_route: null,
    status_route_template: "/compute/projects/{project_id}/dispatch-intents/{job_reference}",
    status_recovery_by_job_reference: true,
    automatic_provider_redispatch: false,
    provider: providerCapability(),
    reason: "provider_execution_not_enabled",
    ...overrides,
  } as ComputeDispatchCapability;
}

function fundingCapabilities(dispatch = dispatchCapability()): Record<string, unknown> {
  return {
    surface: "compute_funding_capabilities",
    schema_version: 1,
    card: {
      enabled: false,
      mutation_route: null,
      reason: "signed_webhook_and_hosted_checkout_not_configured",
      card_data_accepted: false,
      distinct_from_exact_asset_capacity: true,
    },
    usdc: {
      enabled: false,
      mutation_route: null,
      reason: "release_generated_base_sepolia_vault_evidence_required",
      capacity_model: "same_asset_nontransferable_vault_claim",
    },
    eth: {
      enabled: false,
      mutation_route: null,
      reason: "release_generated_base_sepolia_vault_evidence_required",
      capacity_model: "same_asset_nontransferable_vault_claim",
    },
    exact_asset_vault: {
      contract: "ComputeCreditVault",
      release_bound: true,
      review_status: "reviewed_and_extensively_tested_not_formally_audited",
      provider_dispatch_authoritative: false,
    },
    dispatch_intents: dispatch,
    operator_testnet_grants: {
      enabled: true,
      auth: "configured_runtime_bearer",
      cash_value: false,
    },
    credits: {
      kind: "closed_loop_service_credit",
      transferable: false,
      redeemable: false,
      onchain_token: false,
      nominal_usd_cents_per_credit: 1,
      legacy_modeled_ledger: true,
      distinct_from_exact_asset_vault: true,
    },
  };
}

function boundedResult(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schema: "dnai.compute.bounded-result.v1",
    result_policy: "bounded_summary_receipt",
    operation: "inference",
    outcome: "succeeded",
    result_class: "completed_within_authorized_caps",
    result_commitment: `0x${"6".repeat(64)}`,
    commitment_scheme: "hmac-sha256-dstack-v1-over-dispatch-bound-private-result-and-canonical-bounded-projection",
    score_band_released: false,
    raw_prompt_egress: false,
    raw_examples_egress: false,
    raw_output_egress: false,
    provider_identifier_egress: false,
    exception_detail_egress: false,
    ...overrides,
  };
}

function dispatchStatus(updates: Partial<ComputeDispatchIntentStatus> = {}): Record<string, unknown> {
  const projectReference = dispatchProject.project_id;
  const jobReference = "wallet-job-0001";
  const record: Record<string, unknown> = {
    surface: "compute_dispatch_intent",
    schema_version: 3,
    project_reference: projectReference,
    job_reference: jobReference,
    project_id: computeVaultProjectId(projectReference),
    job_id: computeVaultJobId(jobReference),
    user: `0x${"1".repeat(40)}`,
    asset: `0x${"0".repeat(40)}`,
    authorization_nonce: "9007199254740993",
    max_asset_debit: "1000000000000000000",
    authorization_expiry: Math.floor(Date.now() / 1_000) + 600,
    rate_policy_commitment: `0x${"3".repeat(64)}`,
    compose_hash: `0x${"4".repeat(64)}`,
    operation: "inference",
    model: "qwen3_8b",
    recipe: "qwen3_8b_bounded",
    result_policy: "bounded_summary_receipt",
    resource_limits: {
      max_prefill_tokens: 1_000,
      max_sample_tokens: 100,
      max_train_tokens: 0,
    },
    workload_id: `wrk_${"ab".repeat(16)}`,
    workload_schema: "dnai.compute.workload.inference.v1",
    manifest_commitment: `0x${"91".repeat(32)}`,
    workload_commitment: `0x${"92".repeat(32)}`,
    authorization: null,
    workload_authority: {
      source_kind: "credential",
      execution_binding_commitment: `sha256:${"93".repeat(32)}`,
      recipient_release_commitment: `sha256:${"94".repeat(32)}`,
      funding_authority: "onchain_wallet_job",
      device_spending_authority: false,
    },
    intent_commitment: `0x${"5".repeat(64)}`,
    execution_policy_context_hash: "5".repeat(64),
    stage: "intent_created",
    workload_claim_commitment: `sha256:${"95".repeat(32)}`,
    workload_claim_confirmed: true,
    provider_authoritative: false,
    legacy_credit_ledger_mutated: false,
    provider_dispatch_status: "not_started",
    provider_dispatch_may_have_occurred: false,
    provider_usage_finalized: false,
    idempotent_provider_replay_claimed: false,
    automatic_provider_redispatch: false,
    ambiguous_outcome_hold: false,
    bounded_result: null,
    workload_ciphertext_released: false,
    workload_ciphertext_retained_for_reconciliation: false,
    raw_prompt_accepted: false,
    raw_examples_accepted: false,
    arbitrary_program_accepted: false,
    exact_timing_egress: false,
    ...updates,
  };
  if (!Object.prototype.hasOwnProperty.call(updates, "authorization")) {
    record.authorization = {
      kind: "standalone",
      context_commitment: computeStandaloneAuthorizationContextCommitment({
        projectId: record.project_id as `0x${string}`,
        jobId: record.job_id as `0x${string}`,
        user: record.user as `0x${string}`,
        asset: record.asset as `0x${string}`,
        authorizationNonce: BigInt(record.authorization_nonce as string | number | bigint),
        maxAssetDebit: BigInt(record.max_asset_debit as string | number | bigint),
        authorizationExpiry: Number(record.authorization_expiry),
        ratePolicyCommitment: record.rate_policy_commitment as `0x${string}`,
        workloadCommitment: record.workload_commitment as `0x${string}`,
        manifestCommitment: record.manifest_commitment as `0x${string}`,
      }),
      server_derived: true,
    };
  }
  if (!Object.prototype.hasOwnProperty.call(updates, "intent_commitment")) {
    const limits = record.resource_limits as ComputeDispatchIntentStatus["resource_limits"];
    const authority = record.workload_authority as ComputeDispatchIntentStatus["workload_authority"];
    const authorization = record.authorization as ComputeDispatchIntentStatus["authorization"];
    record.intent_commitment = computeDispatchIntentV3Commitment({
      projectReference: String(record.project_reference),
      jobReference: String(record.job_reference),
      projectId: record.project_id as `0x${string}`,
      jobId: record.job_id as `0x${string}`,
      user: record.user as `0x${string}`,
      asset: record.asset as `0x${string}`,
      authorizationNonce: BigInt(record.authorization_nonce as string | number | bigint),
      maxAssetDebit: BigInt(record.max_asset_debit as string | number | bigint),
      authorizationExpiry: Number(record.authorization_expiry),
      ratePolicyCommitment: record.rate_policy_commitment as `0x${string}`,
      composeHash: record.compose_hash as `0x${string}`,
      operation: String(record.operation),
      model: String(record.model),
      recipe: String(record.recipe),
      resultPolicy: String(record.result_policy),
      maxPrefillTokens: Number(limits.max_prefill_tokens),
      maxSampleTokens: Number(limits.max_sample_tokens),
      maxTrainTokens: Number(limits.max_train_tokens),
      workloadId: String(record.workload_id),
      workloadSchema: String(record.workload_schema),
      manifestCommitment: record.manifest_commitment as `0x${string}`,
      workloadCommitment: record.workload_commitment as `0x${string}`,
      workloadSourceKind: authority.source_kind,
      workloadExecutionBindingCommitment: (
        authority.execution_binding_commitment as `sha256:${string}`
      ),
      workloadRecipientReleaseCommitment: (
        authority.recipient_release_commitment as `sha256:${string}`
      ),
      authorizationKind: authorization.kind,
      authorizationContextCommitment: (
        authorization.context_commitment as `sha256:${string}`
      ),
    });
  }
  if (!Object.prototype.hasOwnProperty.call(updates, "execution_policy_context_hash")) {
    record.execution_policy_context_hash = computeExecutionPolicyContextHash({
      jobId: record.job_id as `0x${string}`,
      intentCommitment: record.intent_commitment as `0x${string}`,
      operation: String(record.operation),
      model: String(record.model),
      recipe: String(record.recipe),
    });
  }
  return record;
}

function dispatchCancellationResponse(
  status: ComputeDispatchIntentStatus,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  const canceledAt = Math.floor(Date.now() / 1_000);
  return {
    surface: "compute_dispatch_cancellation",
    schema_version: 2,
    project_reference: status.project_reference,
    job_reference: status.job_reference,
    project_id: status.project_id,
    job_id: status.job_id,
    intent_commitment: status.intent_commitment,
    authorization: {
      kind: status.authorization.kind,
      context_commitment: status.authorization.context_commitment,
    },
    workload_authority: {
      ...status.workload_authority,
      funding_wallet: status.user,
    },
    workload_claim_commitment: status.workload_claim_commitment,
    workload_claim_confirmed: true,
    cancellation_checkpoint_commitment:
      computeDispatchCancellationCheckpointCommitment(status, canceledAt),
    canceled_at: canceledAt,
    journal_execution_prevented: true,
    provider_dispatch_performed: false,
    provider_dispatch_may_have_occurred: false,
    workload_ciphertext_released: true,
    vault_authorization_released: false,
    onchain_cancel_required: true,
    exact_asset_capacity_released: false,
    provider_authoritative: false,
    legacy_credit_ledger_mutated: false,
    raw_secret_egress: false,
    changed: true,
    idempotent_replay: false,
    ...overrides,
  };
}

async function settledUsageReceiptFixture(): Promise<{
  status: ComputeDispatchIntentStatus;
  receipt: Record<string, unknown>;
}> {
  const status = parseComputeDispatchIntent(dispatchStatus({
    stage: "settled",
    provider_dispatch_status: "usage_finalized",
    provider_dispatch_may_have_occurred: true,
    provider_usage_finalized: true,
    bounded_result: boundedResult() as unknown as ComputeDispatchIntentStatus["bounded_result"],
    workload_ciphertext_released: true,
  }));
  const tee = privateKeyToAccount(`0x${"71".repeat(32)}`);
  const meter = privateKeyToAccount(`0x${"72".repeat(32)}`);
  const qvl = privateKeyToAccount(`0x${"73".repeat(32)}`);
  const providerRelease = {
    schema: "dnai.compute.tinker-provider-release.v1",
    adapter_id: "tinker_sdk_0_22_7_at_most_once_v1",
    sdk_version: "0.22.7",
    sdk_source_sha256: "sha256:3ab30e85f4d1ae21ab4a8b415d382e719decd3abb31e61f6e481e8e5296dac62",
    request_contract_sha256: "sha256:15f112c2e285ba2463d36fe32a47f78eda40f7ca81d7b49f6d51dc4378feef0d",
    base_url_sha256: "sha256:e3ae09c22c856fa175bfbeded8819e1665f39c235869a15e3e0729bfb4f39533",
    tokenizer_path: "/opt/dnai/qwen3-8b-tokenizer",
    tokenizer_release_sha256: "sha256:d933156af48aa90a117025537b4291c2e72b62ad14ddcfa7d77f3258928cd2e0",
    idempotency_header_role: "request_commitment_only",
    idempotent_provider_replay_claimed: false,
    automatic_provider_redispatch: false,
    at_most_once_attempt_checkpoint: true,
    terminal_ambiguity_hold: true,
    ambiguous_outcome_ciphertext_retained: true,
    provider_authoritative_invoice: false,
    raw_secret_egress: false,
  };
  const providerUsage = {
    outcome: "succeeded",
    prefill_tokens: 10,
    sample_tokens: 2,
    training_tokens: 0,
    result_commitment: status.bounded_result!.result_commitment,
    provider_authoritative_invoice: false,
  };
  const usageStartedAt = status.authorization_expiry - 400;
  const usageObservedAt = usageStartedAt + 10;
  const usageClaims = {
    schema: "dnai.compute-usage-envelope.v2",
    job_id: status.job_id,
    project_id: status.project_id,
    user: status.user,
    asset: status.asset,
    authorization_nonce: status.authorization_nonce.toString(),
    max_asset_debit: status.max_asset_debit.toString(),
    authorization_expiry: status.authorization_expiry,
    rate_policy_commitment: status.rate_policy_commitment,
    workload_commitment: status.workload_commitment,
    manifest_commitment: status.manifest_commitment,
    dispatch_intent_commitment: status.intent_commitment,
    tee_identity: tee.address.toLowerCase() as `0x${string}`,
    compose_hash: status.compose_hash,
    start_commitment: `0x${"8".repeat(64)}` as `0x${string}`,
    model: status.model,
    recipe: status.recipe,
    outcome: providerUsage.outcome,
    prefill_tokens: String(providerUsage.prefill_tokens),
    sample_tokens: String(providerUsage.sample_tokens),
    training_tokens: String(providerUsage.training_tokens),
    usage_started_at: usageStartedAt,
    usage_observed_at: usageObservedAt,
    raw_secret_egress: false,
  };
  const usageCommitment = sha256(encoder.encode(
    `dnai-wikigen/compute-usage/v1\0${canonicalComputeJson(usageClaims)}`,
  ));
  const vaultAddress = `0x${"9".repeat(40)}` as `0x${string}`;
  const policySetHash = `0x${"e".repeat(64)}` as `0x${string}`;
  const attestationEvidenceHash = `0x${"c".repeat(64)}` as `0x${string}`;
  const receiptExpiry = usageObservedAt + 300;
  const onchainUsageCommitment = keccak256(encodeAbiParameters(
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
      keccak256(stringToHex(
        "ComputeMeteredUsage(uint256 chainId,address verifyingContract,bytes32 projectId,bytes32 jobId,address user,address asset,uint256 authorizationNonce,uint256 maxAssetDebit,uint256 actualAssetDebit,uint256 authorizationExpiry,bytes32 ratePolicyCommitment,bytes32 workloadCommitment,bytes32 manifestCommitment,bytes32 dispatchIntentCommitment,address teeIdentity,bytes32 composeHash,bytes32 startCommitment,uint256 billableComputeUnits,uint256 usageStartedAt,uint256 usageEndedAt,bytes32 meteringPolicySetHash,bytes32 attestationEvidenceHash)",
      )),
      84_532n,
      vaultAddress,
      status.project_id,
      status.job_id,
      status.user,
      status.asset,
      status.authorization_nonce,
      status.max_asset_debit,
      500n,
      BigInt(status.authorization_expiry),
      status.rate_policy_commitment,
      status.workload_commitment,
      status.manifest_commitment,
      status.intent_commitment,
      usageClaims.tee_identity,
      status.compose_hash,
      usageClaims.start_commitment,
      12n,
      BigInt(usageStartedAt),
      BigInt(usageObservedAt),
      policySetHash,
      attestationEvidenceHash,
    ],
  ));
  const meteringFields = [
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
  const meteringMessage = {
    projectId: status.project_id,
    jobId: status.job_id,
    user: status.user,
    asset: status.asset,
    authorizationNonce: status.authorization_nonce,
    maxAssetDebit: status.max_asset_debit,
    actualAssetDebit: 500n,
    authorizationExpiry: BigInt(status.authorization_expiry),
    ratePolicyCommitment: status.rate_policy_commitment,
    workloadCommitment: status.workload_commitment,
    manifestCommitment: status.manifest_commitment,
    dispatchIntentCommitment: status.intent_commitment,
    teeIdentity: usageClaims.tee_identity,
    composeHash: status.compose_hash,
    startCommitment: usageClaims.start_commitment,
    billableComputeUnits: 12n,
    usageStartedAt: BigInt(usageStartedAt),
    usageEndedAt: BigInt(usageObservedAt),
    usageCommitment: onchainUsageCommitment,
    meteringPolicySetHash: policySetHash,
    attestationEvidenceHash,
    receiptExpiry: BigInt(receiptExpiry),
  } as const;
  const meteringDomain = {
    name: "DNAI Compute Credit Vault",
    version: "2",
    chainId: 84_532,
    verifyingContract: vaultAddress,
  } as const;
  const meterDigest = hashTypedData({
    domain: meteringDomain,
    types: { ComputeMeteringReceipt: meteringFields },
    primaryType: "ComputeMeteringReceipt",
    message: meteringMessage,
  });
  const qvlDigest = hashTypedData({
    domain: meteringDomain,
    types: { ComputeMeteringQvlReceipt: meteringFields },
    primaryType: "ComputeMeteringQvlReceipt",
    message: meteringMessage,
  });
  const independentMetering = {
    schema: "dnai.compute-metering-decision.v2",
    classification: "attested_dual_verified_metering",
    provider_authoritative_invoice: false,
    chain_id: 84_532,
    vault_address: vaultAddress,
    pinned_block_number: 12_345,
    pinned_block_hash: `0x${"d".repeat(64)}`,
    policy_set_hash: policySetHash,
    rate_policy_commitment: status.rate_policy_commitment,
    workload_commitment: status.workload_commitment,
    manifest_commitment: status.manifest_commitment,
    dispatch_intent_commitment: status.intent_commitment,
    asset: status.asset,
    job_id: status.job_id,
    usage_commitment: usageCommitment,
    onchain_usage_commitment: onchainUsageCommitment,
    actual_asset_debit: "500",
    billable_compute_units: "12",
    usage_started_at: usageStartedAt,
    usage_ended_at: usageObservedAt,
    attestation_evidence_hash: attestationEvidenceHash,
    receipt_expiry: receiptExpiry,
    metering_receipt_digest: meterDigest,
    metering_qvl_receipt_digest: qvlDigest,
    metering_verifier: meter.address.toLowerCase(),
    metering_qvl_verifier: qvl.address.toLowerCase(),
    tee_identity: tee.address.toLowerCase(),
    compose_hash: status.compose_hash,
    raw_secret_egress: false,
    verifier_signature: (await meter.sign({ hash: meterDigest })).toLowerCase(),
    qvl_signature: (await qvl.sign({ hash: qvlDigest })).toLowerCase(),
  };
  return {
    status,
    receipt: {
      surface: "compute_exact_asset_usage_receipt",
      schema_version: 2,
      access: "wallet_authenticated_project_member",
      project_reference: status.project_reference,
      job_reference: status.job_reference,
      project_id: status.project_id,
      job_id: status.job_id,
      intent_commitment: status.intent_commitment,
      authorization: {
        kind: status.authorization.kind,
        context_commitment: status.authorization.context_commitment,
      },
      workload_authority: {
        ...status.workload_authority,
        funding_wallet: status.user,
      },
      workload_claim_commitment: status.workload_claim_commitment,
      workload_claim_confirmed: true,
      execution_policy_context_hash: status.execution_policy_context_hash,
      provider_release_sha256: "sha256:4264a2226ac9c850d8f053c98ac90d0f6dcbc58702919899384a9b2442b35631",
      provider_release: providerRelease,
      provider_usage: providerUsage,
      bounded_result: status.bounded_result,
      signed_usage: {
        schema: "dnai.compute-metering-request.v2",
        block: {
          number: independentMetering.pinned_block_number,
          hash: independentMetering.pinned_block_hash,
        },
        usage: {
          ...usageClaims,
          usage_commitment: usageCommitment,
          tee_signature: (await tee.signMessage({
            message: { raw: usageCommitment },
          })).toLowerCase(),
        },
      },
      independent_metering: independentMetering,
      settlement: {
        confirmed: true,
        chain_id: 84_532,
        vault_address: independentMetering.vault_address,
        transaction_hash: `0x${"f".repeat(64)}`,
        onchain_usage_commitment: onchainUsageCommitment,
        actual_asset_debit: independentMetering.actual_asset_debit,
        billable_compute_units: independentMetering.billable_compute_units,
        attestation_evidence_hash: attestationEvidenceHash,
        receipt_expiry: receiptExpiry,
      },
      provider_authoritative_invoice: false,
      exact_asset_only: true,
      legacy_credit_ledger_mutated: false,
      raw_prompt_egress: false,
      raw_examples_egress: false,
      raw_output_egress: false,
      provider_identifier_egress: false,
      raw_transaction_egress: false,
    },
  };
}

function cancellationReceipt(): ComputeJobCancellationReceipt {
  return {
    surface: "compute_job_cancellation",
    schema_version: 1,
    project_id: queuedJob.project_id,
    job_id: queuedJob.job_id,
    status: "canceled",
    changed: true,
    idempotent_replay: false,
    released_credits: queuedJob.max_credits,
    credit_reversal: "reserved_to_available",
    ledger: {
      transaction_id: "txn_0123456789abcdef01234567",
      sequence: 3,
      kind: "job_cancel",
      transaction_hash: "1".repeat(64),
      previous_hash: "2".repeat(64),
      settlement_status: "user_canceled_before_dispatch",
    },
    provider_dispatch_performed: false,
    service_settlement_performed: false,
  };
}

const jobCreateInput: ComputeJobCreateInput = {
  name: "bounded-sample",
  operation: "inference",
  maxCredits: 125,
  resultPolicy: "bounded_summary_receipt",
  environmentVersion: "env_v1",
};

function jobCreateResponse(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    surface: "compute_job_result",
    created: true,
    idempotent_replay: false,
    job: { ...queuedJob, project_id: dispatchProject.project_id },
    provider_dispatch_performed: false,
    ...overrides,
  };
}

async function deliveryFor(
  device: DeviceKeyMaterial,
  tokenJti = "0123456789abcdef0123456789abcdef",
  bindingJti = tokenJti,
): Promise<{ delivery: ComputeCredentialDelivery; token: string }> {
  const jwtIdHash = await digest(`compute_credential_jti:${bindingJti}`);
  const associatedObject = {
    credential_id: credential.credential_id,
    device_id: credential.device_id,
    expires_at: credential.expires_at,
    generation: credential.generation,
    jwt_id_hash: jwtIdHash,
    project_id: credential.project_id,
    surface: "compute_credential",
  };
  const associatedBytes = encoder.encode(JSON.stringify(associatedObject));
  const associatedHex = hex(associatedBytes);
  const header = { alg: "HS256", kid: "dstack-compute-credential-v1", typ: "JWT" };
  const payload = {
    sub: credential.credential_id,
    project_id: credential.project_id,
    device_id: credential.device_id,
    generation: credential.generation,
    scope: credential.scopes.join(" "),
    daily_credit_cap: credential.daily_credit_cap,
    iat: credential.issued_at,
    nbf: credential.issued_at,
    exp: credential.expires_at,
    jti: tokenJti,
  };
  const token = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}.${b64url("test-signature")}`;
  const recipient = await crypto.subtle.importKey("raw", buffer(Uint8Array.from(device.publicKeyHex.match(/../g)!.map((byte) => Number.parseInt(byte, 16)))), { name: "X25519" }, false, []);
  const ephemeral = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]) as CryptoKeyPair;
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: recipient }, ephemeral.privateKey, 256));
  const hkdf = await crypto.subtle.importKey("raw", buffer(shared), "HKDF", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(), info: encoder.encode("dnai-wikigen-compute-credential-v1") },
    hkdf,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
  const nonce = new Uint8Array(12).fill(7);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: associatedBytes, tagLength: 128 }, key, encoder.encode(token));
  const ephemeralPublic = await crypto.subtle.exportKey("raw", ephemeral.publicKey);
  shared.fill(0);
  return {
    token,
    delivery: {
      credential,
      capsule: {
        delivery: "x25519_aes_256_gcm_envelope",
        encrypted_token: {
          ephemeral_public_key: hex(ephemeralPublic),
          nonce: hex(nonce),
          ciphertext: hex(ciphertext),
        },
        associated_data: associatedHex,
        associated_data_hash: await digest(`compute_credential_aad:${associatedHex}`),
        recipient_public_key_hash: await digest(`compute_device_key:${device.publicKeyHex}`),
        plaintext_token_returned: false,
      },
    },
  };
}

describe("Compute metadata-only job creation client", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("posts only bounded public metadata with one replay key and parses the exact no-dispatch result", async () => {
    const mutableDeployment = deployment as unknown as { delegateUrl: string };
    const originalDelegateUrl = mutableDeployment.delegateUrl;
    mutableDeployment.delegateUrl = "https://delegate.example";
    const fetchMock = vi.fn(async () => new Response(
      JSON.stringify(jobCreateResponse()),
      { status: 200, headers: { "Content-Type": "application/json" } },
    ));
    vi.stubGlobal("fetch", fetchMock);
    try {
      await expect(createJob(
        "compute-wallet-token",
        dispatchProject,
        jobCreateInput,
        "jobcreate:12345678",
      )).resolves.toMatchObject({
        created: true,
        idempotentReplay: false,
        job: { name: jobCreateInput.name, dispatch_status: "not_dispatched" },
      });
      expect(fetchMock).toHaveBeenCalledTimes(1);
      const [url, options] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
      expect(url).toBe(`https://delegate.example/compute/projects/${dispatchProject.project_id}/jobs`);
      expect(options.method).toBe("POST");
      expect(options.credentials).toBe("omit");
      expect(options.cache).toBe("no-store");
      expect(options.redirect).toBe("error");
      expect(options.headers).toEqual({
        Accept: "application/json",
        Authorization: "Bearer compute-wallet-token",
        "Content-Type": "application/json",
        "Idempotency-Key": "jobcreate:12345678",
      });
      expect(JSON.parse(String(options.body))).toEqual({
        name: "bounded-sample",
        operation: "inference",
        model: "qwen3_8b",
        recipe: "qwen3_8b_bounded",
        max_credits: 125,
        result_policy: "bounded_summary_receipt",
        environment_version: "env_v1",
      });
      expect(String(options.body)).not.toMatch(/prompt|example|dataset|raw_input|credential|card/i);
    } finally {
      mutableDeployment.delegateUrl = originalDelegateUrl;
    }
  });

  it("rejects malformed keys, non-mutating roles, policy overages, and unexpected input before fetch", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(createJob(
      "token",
      dispatchProject,
      jobCreateInput,
      "short",
    )).rejects.toThrow(/idempotency key/);
    await expect(createJob(
      "token",
      { ...dispatchProject, role: "viewer" },
      jobCreateInput,
      "jobcreate:viewer-role",
    )).rejects.toThrow(/release-bounded project policy/);
    await expect(createJob(
      "token",
      { ...dispatchProject, policy: { ...dispatchProject.policy, per_job_max_credits: 100 } },
      jobCreateInput,
      "jobcreate:over-project-cap",
    )).rejects.toThrow(/release-bounded project policy/);
    await expect(createJob(
      "token",
      dispatchProject,
      { ...jobCreateInput, prompt: "forbidden" } as ComputeJobCreateInput,
      "jobcreate:extra-field",
    )).rejects.toThrow(/unsupported fields/);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("normalizes the public label and pins the inert environment marker", () => {
    expect(normalizeComputeJobCreateInput(dispatchProject, {
      ...jobCreateInput,
      name: "  bounded-sample  ",
    })).toEqual(jobCreateInput);
    expect(() => normalizeComputeJobCreateInput(dispatchProject, {
      ...jobCreateInput,
      environmentVersion: "private-dataset-v2" as "env_v1",
    })).toThrow(/release-bounded project policy/);
  });

  it("rejects response expansion, replay contradictions, request drift, dispatch claims, and non-pristine creates", () => {
    expect(() => parseComputeJobCreateResult(
      { ...jobCreateResponse(), request_commitment: "unreleased" },
      dispatchProject.project_id,
      jobCreateInput,
    )).toThrow(/unsupported fields/);

    expect(() => parseComputeJobCreateResult(
      jobCreateResponse({ idempotent_replay: true }),
      dispatchProject.project_id,
      jobCreateInput,
    )).toThrow(/contradictory/);

    expect(() => parseComputeJobCreateResult(
      jobCreateResponse({ provider_dispatch_performed: true }),
      dispatchProject.project_id,
      jobCreateInput,
    )).toThrow(/contradictory/);

    expect(() => parseComputeJobCreateResult(
      jobCreateResponse({ job: { ...queuedJob, project_id: dispatchProject.project_id, max_credits: 126 } }),
      dispatchProject.project_id,
      jobCreateInput,
    )).toThrow(/requested reservation/);

    expect(() => parseComputeJobCreateResult(
      jobCreateResponse({ job: { ...queuedJob, project_id: dispatchProject.project_id, status: "running", started_at: issuedAt } }),
      dispatchProject.project_id,
      jobCreateInput,
    )).toThrow(/contradictory/);

    expect(() => parseComputeJobCreateResult(
      jobCreateResponse({ job: { ...queuedJob, project_id: dispatchProject.project_id, raw_prompt: "forbidden" } }),
      dispatchProject.project_id,
      jobCreateInput,
    )).toThrow(/forbidden field|unsupported fields/);
  });

  it("accepts an exact idempotent replay without relabeling it as a new reservation", () => {
    expect(parseComputeJobCreateResult(
      jobCreateResponse({ created: false, idempotent_replay: true }),
      dispatchProject.project_id,
      jobCreateInput,
    )).toMatchObject({ created: false, idempotentReplay: true });
  });
});

describe("Compute device credential delivery", () => {
  it("keeps the registered browser device private key non-exportable", async () => {
    const device = await generateDeviceKey();
    expect(device.publicKeyHex).toMatch(/^[0-9a-f]{64}$/);
    expect(device.privateKey.type).toBe("private");
    expect(device.privateKey.extractable).toBe(false);
    await expect(crypto.subtle.exportKey("pkcs8", device.privateKey)).rejects.toThrow();
  });

  it("decrypts a capsule only for its registered X25519 device and validates every binding", async () => {
    const device = await generateDeviceKey();
    const { delivery, token } = await deliveryFor(device);
    await expect(decryptCredentialCapsule(delivery, device)).resolves.toBe(token);

    const otherDevice = await generateDeviceKey();
    await expect(decryptCredentialCapsule(delivery, otherDevice)).rejects.toThrow(/recipient commitment/);
  });

  it("rejects a capsule whose associated-data commitment was altered", async () => {
    const device = await generateDeviceKey();
    const { delivery } = await deliveryFor(device);
    const tampered = structuredClone(delivery);
    tampered.capsule.associated_data_hash = "0".repeat(64);
    await expect(decryptCredentialCapsule(tampered, device)).rejects.toThrow(/associated-data commitment/);
  });

  it("rejects a decrypted JWT whose jti is not the capsule-bound credential generation", async () => {
    const device = await generateDeviceKey();
    const { delivery } = await deliveryFor(
      device,
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );
    await expect(decryptCredentialCapsule(delivery, device)).rejects.toThrow(/token id does not match/);
  });
});

describe("Compute queued-job cancellation", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("accepts only the exact bounded cancellation and immutable ledger receipt", () => {
    const value = cancellationReceipt();
    expect(
      parseComputeJobCancellation(value, queuedJob.project_id, queuedJob.job_id),
    ).toEqual(value);

    const replay = cancellationReceipt();
    replay.changed = false;
    replay.idempotent_replay = true;
    expect(
      parseComputeJobCancellation(replay, queuedJob.project_id, queuedJob.job_id),
    ).toEqual(replay);
  });

  it("rejects extra fields, identity drift, contradictory replay claims, and malformed ledger evidence", () => {
    const extra = { ...cancellationReceipt(), wallet_address: "0x" + "1".repeat(40) };
    expect(() => parseComputeJobCancellation(extra, queuedJob.project_id, queuedJob.job_id)).toThrow(/unsupported fields/);

    const nestedExtra = cancellationReceipt() as ComputeJobCancellationReceipt & { ledger: ComputeJobCancellationReceipt["ledger"] & { authority?: string } };
    nestedExtra.ledger.authority = "project_wallet_owner";
    expect(() => parseComputeJobCancellation(nestedExtra, queuedJob.project_id, queuedJob.job_id)).toThrow(/unsupported fields/);

    const contradictory = cancellationReceipt();
    contradictory.idempotent_replay = true;
    expect(() => parseComputeJobCancellation(contradictory, queuedJob.project_id, queuedJob.job_id)).toThrow(/bounded schema/);

    const malformedHash = cancellationReceipt();
    malformedHash.ledger.transaction_hash = "A".repeat(64);
    expect(() => parseComputeJobCancellation(malformedHash, queuedJob.project_id, queuedJob.job_id)).toThrow(/bounded schema/);

    const excessiveRelease = cancellationReceipt();
    excessiveRelease.released_credits = 501;
    expect(() => parseComputeJobCancellation(excessiveRelease, queuedJob.project_id, queuedJob.job_id)).toThrow(/released credits/);

    expect(() => parseComputeJobCancellation(
      cancellationReceipt(),
      "proj_ffffffffffffffffffffffff",
      queuedJob.job_id,
    )).toThrow(/bounded schema/);
  });

  it("permits only current mutating roles and pristine queued, never-dispatched records", () => {
    expect(canCancelComputeJob(queuedJob, "owner")).toBe(true);
    expect(canCancelComputeJob(queuedJob, "admin")).toBe(true);
    expect(canCancelComputeJob(queuedJob, "developer")).toBe(true);
    expect(canCancelComputeJob(queuedJob, "viewer")).toBe(false);
    expect(canCancelComputeJob(queuedJob, undefined)).toBe(false);

    for (const mutation of [
      { status: "running" as const },
      { status: "succeeded" as const },
      { started_at: issuedAt },
      { completed_at: issuedAt },
      { actual_credits: 0 },
      { released_credits: 125 },
      { metering_source: "operator_bounded_receipt" },
      { usage_receipt_hash: `sha256:${"1".repeat(64)}` },
      { settlement_authority: "operator_runtime" },
    ]) {
      expect(canCancelComputeJob({ ...queuedJob, ...mutation }, "owner")).toBe(false);
    }
    const providerDispatched = {
      ...queuedJob,
      dispatch_status: "provider_dispatched",
    } as unknown as ComputeJob;
    expect(canCancelComputeJob(providerDispatched, "owner")).toBe(false);
  });

  it("posts the fixed cancellation intent with bearer and replay key, then parses the receipt", async () => {
    const mutableDeployment = deployment as unknown as { delegateUrl: string };
    const originalDelegateUrl = mutableDeployment.delegateUrl;
    mutableDeployment.delegateUrl = "https://delegate.example";
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => new Response(
      JSON.stringify(cancellationReceipt()),
      { status: 200, headers: { "Content-Type": "application/json" } },
    ));
    vi.stubGlobal("fetch", fetchMock);
    try {
      await expect(cancelComputeJob(
        "compute-wallet-token",
        queuedJob.project_id,
        queuedJob.job_id,
        "jobcancel:12345678",
      )).resolves.toEqual(cancellationReceipt());
      expect(fetchMock).toHaveBeenCalledTimes(1);
      const [url, options] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
      expect(url).toBe(`https://delegate.example/compute/projects/${queuedJob.project_id}/jobs/${queuedJob.job_id}/cancel`);
      expect(options.method).toBe("POST");
      expect(options.credentials).toBe("omit");
      expect(options.headers).toEqual({
        Accept: "application/json",
        Authorization: "Bearer compute-wallet-token",
        "Content-Type": "application/json",
        "Idempotency-Key": "jobcancel:12345678",
      });
      expect(options.body).toBe(JSON.stringify({ reason: "user_requested_before_dispatch" }));

      await expect(cancelComputeJob(
        "compute-wallet-token",
        queuedJob.project_id,
        queuedJob.job_id,
        "short",
      )).rejects.toThrow(/idempotency key/);
      expect(fetchMock).toHaveBeenCalledTimes(1);
    } finally {
      mutableDeployment.delegateUrl = originalDelegateUrl;
    }
  });

  it("cancels an undeclared oversized response stream before JSON parsing", async () => {
    const mutableDeployment = deployment as unknown as { delegateUrl: string };
    const originalDelegateUrl = mutableDeployment.delegateUrl;
    mutableDeployment.delegateUrl = "https://delegate.example";
    let canceled = false;
    const oversized = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(400 * 1024).fill(0x20));
        controller.enqueue(new Uint8Array(200 * 1024).fill(0x20));
      },
      cancel() {
        canceled = true;
      },
    });
    vi.stubGlobal("fetch", vi.fn(async () => new Response(oversized, {
      status: 200,
      headers: { "Content-Type": "application/json" },
    })));
    try {
      await expect(cancelComputeJob(
        "compute-wallet-token",
        queuedJob.project_id,
        queuedJob.job_id,
        "jobcancel:oversized-response",
      )).rejects.toThrow(/public size limit/);
      expect(canceled).toBe(true);
    } finally {
      mutableDeployment.delegateUrl = originalDelegateUrl;
    }
  });

  it("rejects non-JSON Compute responses before parsing them", async () => {
    const mutableDeployment = deployment as unknown as { delegateUrl: string };
    const originalDelegateUrl = mutableDeployment.delegateUrl;
    mutableDeployment.delegateUrl = "https://delegate.example";
    vi.stubGlobal("fetch", vi.fn(async () => new Response("not-json", {
      status: 200,
      headers: { "Content-Type": "text/plain" },
    })));
    try {
      await expect(cancelComputeJob(
        "compute-wallet-token",
        queuedJob.project_id,
        queuedJob.job_id,
        "jobcancel:wrong-content-type",
      )).rejects.toThrow(/application\/json/);
    } finally {
      mutableDeployment.delegateUrl = originalDelegateUrl;
    }
  });
});

describe("Compute exact-asset dispatch intents", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("parses the exact bounded journal schema and preserves uint256 precision", () => {
    const value = dispatchStatus();
    const parsed = parseComputeDispatchIntent(value, {
      projectReference: dispatchProject.project_id,
      jobReference: "wallet-job-0001",
    });
    expect(parsed.authorization_nonce).toBe(9_007_199_254_740_993n);
    expect(parsed.max_asset_debit).toBe(1_000_000_000_000_000_000n);
    expect(parsed.project_id).toBe(computeVaultProjectId(dispatchProject.project_id));
    expect(parsed.job_id).toBe(computeVaultJobId("wallet-job-0001"));
    expect(() => parseComputeDispatchIntent(value, {
      projectReference: "prj_wrong",
      jobReference: "wallet-job-0001",
    })).toThrow(/bounded schema/);
    expect(() => parseComputeDispatchIntent(value, {
      projectReference: dispatchProject.project_id,
      jobReference: "wallet-job-wrong",
    })).toThrow(/bounded schema/);
    expect(parseDispatchUint256((1n << 256n) - 1n)).toBe((1n << 256n) - 1n);
    expect(() => parseDispatchUint256(1n << 256n)).toThrow(/exceeds uint256/);
    expect(() => parseDispatchUint256("01")).toThrow(/canonical uint256/);
  });

  it("accepts each durable provider checkpoint without inventing replay guarantees", () => {
    const prepared = parseComputeDispatchIntent(dispatchStatus({
      stage: "provider_dispatching",
      provider_dispatch_status: "prepared",
    }));
    expect(prepared.provider_dispatch_may_have_occurred).toBe(false);
    expect(prepared.bounded_result).toBeNull();

    const checkpointed = parseComputeDispatchIntent(dispatchStatus({
      stage: "provider_attempt_checkpointed",
      provider_dispatch_status: "attempt_checkpointed",
      provider_dispatch_may_have_occurred: true,
    }));
    expect(checkpointed.provider_usage_finalized).toBe(false);
    expect(checkpointed.automatic_provider_redispatch).toBe(false);

    const ambiguous = parseComputeDispatchIntent(dispatchStatus({
      stage: "provider_outcome_ambiguous",
      provider_dispatch_status: "outcome_ambiguous",
      provider_dispatch_may_have_occurred: true,
      ambiguous_outcome_hold: true,
      workload_ciphertext_retained_for_reconciliation: true,
    }));
    expect(ambiguous.idempotent_provider_replay_claimed).toBe(false);
    expect(ambiguous.workload_ciphertext_released).toBe(false);

    const usage = {
      provider_dispatch_status: "usage_finalized" as const,
      provider_dispatch_may_have_occurred: true,
      provider_usage_finalized: true,
      bounded_result: boundedResult() as unknown as ComputeDispatchIntentStatus["bounded_result"],
    };
    const finalized = parseComputeDispatchIntent(dispatchStatus({
      ...usage,
      stage: "usage_finalized",
    }));
    expect(finalized.bounded_result?.result_class).toBe("completed_within_authorized_caps");
    expect(finalized.workload_ciphertext_released).toBe(false);

    for (const stage of [
      "workload_released",
      "metering_pending",
      "metering_decided",
      "settlement_prepared",
      "settlement_broadcast",
      "settled",
    ] as const) {
      const parsed = parseComputeDispatchIntent(dispatchStatus({
        ...usage,
        stage,
        workload_ciphertext_released: true,
      }));
      expect(parsed.stage).toBe(stage);
      expect(parsed.workload_ciphertext_released).toBe(true);
    }

    const canceled = parseComputeDispatchIntent(dispatchStatus({
      stage: "blocked",
      workload_ciphertext_released: true,
    }));
    expect(canceled.provider_dispatch_status).toBe("not_started");

    const postUsageBlocked = parseComputeDispatchIntent(dispatchStatus({
      ...usage,
      stage: "blocked",
    }));
    expect(postUsageBlocked.provider_dispatch_may_have_occurred).toBe(true);
  });

  it("rejects contradictory bounded-result, ambiguity, retention, and replay claims", () => {
    expect(() => parseComputeDispatchIntent(dispatchStatus({
      idempotent_provider_replay_claimed: true,
    } as unknown as Partial<ComputeDispatchIntentStatus>))).toThrow(/bounded schema/);
    expect(() => parseComputeDispatchIntent(dispatchStatus({
      automatic_provider_redispatch: true,
    } as unknown as Partial<ComputeDispatchIntentStatus>))).toThrow(/bounded schema/);
    expect(() => parseComputeDispatchIntent(dispatchStatus({
      stage: "provider_outcome_ambiguous",
      provider_dispatch_status: "outcome_ambiguous",
      provider_dispatch_may_have_occurred: true,
      ambiguous_outcome_hold: true,
      workload_ciphertext_retained_for_reconciliation: false,
    }))).toThrow(/bounded schema/);
    expect(() => parseComputeDispatchIntent(dispatchStatus({
      stage: "usage_finalized",
      provider_dispatch_status: "usage_finalized",
      provider_dispatch_may_have_occurred: true,
      provider_usage_finalized: true,
      bounded_result: boundedResult({ raw_output_egress: true }),
    } as unknown as Partial<ComputeDispatchIntentStatus>))).toThrow(/bounded provider result/);
    expect(() => parseComputeDispatchIntent(dispatchStatus({
      stage: "usage_finalized",
      provider_dispatch_status: "usage_finalized",
      provider_dispatch_may_have_occurred: true,
      provider_usage_finalized: true,
      bounded_result: {
        ...boundedResult(),
        future_provider_field: "forbidden",
      },
    } as unknown as Partial<ComputeDispatchIntentStatus>))).toThrow(/unsupported fields/);
    expect(() => parseComputeDispatchIntent(dispatchStatus({
      stage: "usage_finalized",
      provider_dispatch_status: "usage_finalized",
      provider_dispatch_may_have_occurred: true,
      provider_usage_finalized: true,
      bounded_result: null,
    }))).toThrow(/bounded schema/);
  });

  it("matches the Python runtime's canonical intent commitment vector", () => {
    expect(computeDispatchIntentCommitment({
      projectReference: dispatchProject.project_id,
      jobReference: "wallet-job-0001",
      projectId: computeVaultProjectId(dispatchProject.project_id),
      jobId: computeVaultJobId("wallet-job-0001"),
      user: `0x${"1".repeat(40)}`,
      asset: `0x${"0".repeat(40)}`,
      authorizationNonce: 9_007_199_254_740_993n,
      maxAssetDebit: 1_000_000_000_000_000_000n,
      authorizationExpiry: 2_000_000_000,
      ratePolicyCommitment: `0x${"3".repeat(64)}`,
      composeHash: `0x${"4".repeat(64)}`,
      operation: "inference",
      model: "qwen3_8b",
      recipe: "qwen3_8b_bounded",
      resultPolicy: "bounded_summary_receipt",
      maxPrefillTokens: 1_000,
      maxSampleTokens: 100,
      maxTrainTokens: 0,
      workloadId: `wrk_${"ab".repeat(16)}`,
      workloadSchema: "dnai.compute.workload.inference.v1",
      manifestCommitment: `0x${"91".repeat(32)}`,
      workloadCommitment: `0x${"92".repeat(32)}`,
    })).toBe("0x785edf5867fe64c8c566c010cfd5179a830e7c377e5ca86c46a0c43b2dd3a1ed");
  });

  it("matches Python's 0x-input to bare execution-context vector", () => {
    const vector = contextVectors.vectors[0];
    expect(vector.intent_commitment.startsWith("0x")).toBe(true);
    expect(vector.recipe_policy_commitment.startsWith("0x")).toBe(true);
    expect(vector.execution_context_hash.startsWith("0x")).toBe(false);
    expect(computeExecutionPolicyContextHash({
      jobId: vector.job_id as `0x${string}`,
      intentCommitment: vector.intent_commitment as `0x${string}`,
      operation: vector.intent.operation,
      model: vector.intent.model,
      recipe: vector.intent.recipe,
    })).toBe(vector.execution_context_hash);
  });

  it("derives the policy target only from wallet-authenticated exact-intent status", async () => {
    const mutableDeployment = deployment as unknown as { delegateUrl: string };
    const originalDelegateUrl = mutableDeployment.delegateUrl;
    mutableDeployment.delegateUrl = "https://delegate.example";
    const response = dispatchStatus();
    const fetchMock = vi.fn(async () => new Response(JSON.stringify(response), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }));
    vi.stubGlobal("fetch", fetchMock);
    try {
      const target = await fetchComputeExecutionPolicyTarget(
        "wallet-scoped-compute-token",
        dispatchProject.project_id,
        "wallet-job-0001",
        String(response.user),
      );
      expect(target).toEqual({
        resourceId: response.job_id,
        executionContextHash: response.execution_policy_context_hash,
        authorizedUser: response.user,
      });
      expect(fetchMock).toHaveBeenCalledOnce();
      const [url, options] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
      expect(url).toBe(
        `https://delegate.example/compute/projects/${dispatchProject.project_id}/dispatch-intents/wallet-job-0001`,
      );
      expect(options.headers).toMatchObject({
        Authorization: "Bearer wallet-scoped-compute-token",
      });
      expect(options.credentials).toBe("omit");
    } finally {
      mutableDeployment.delegateUrl = originalDelegateUrl;
      vi.unstubAllGlobals();
    }
  });

  it("rejects a Compute policy target owned by another wallet", async () => {
    const mutableDeployment = deployment as unknown as { delegateUrl: string };
    const originalDelegateUrl = mutableDeployment.delegateUrl;
    mutableDeployment.delegateUrl = "https://delegate.example";
    vi.stubGlobal("fetch", vi.fn(async () => new Response(
      JSON.stringify(dispatchStatus()),
      { status: 200, headers: { "Content-Type": "application/json" } },
    )));
    try {
      await expect(fetchComputeExecutionPolicyTarget(
        "wallet-scoped-compute-token",
        dispatchProject.project_id,
        "wallet-job-0001",
        `0x${"2".repeat(40)}`,
      )).rejects.toThrow(/different wallet/);
    } finally {
      mutableDeployment.delegateUrl = originalDelegateUrl;
      vi.unstubAllGlobals();
    }
  });

  it("keeps legacy service-credit job IDs outside the public policy target flow", async () => {
    const mutableDeployment = deployment as unknown as { delegateUrl: string };
    const originalDelegateUrl = mutableDeployment.delegateUrl;
    mutableDeployment.delegateUrl = "https://delegate.example";
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => new Response(
      JSON.stringify({ detail: "Exact-asset dispatch intent not found" }),
      { status: 404, headers: { "Content-Type": "application/json" } },
    ));
    vi.stubGlobal("fetch", fetchMock);
    try {
      await expect(fetchComputeExecutionPolicyTarget(
        "wallet-scoped-compute-token",
        dispatchProject.project_id,
        "job_legacy_service_credit",
        `0x${"1".repeat(40)}`,
      )).rejects.toThrow(/not found/);
      expect(String(fetchMock.mock.calls[0][0])).toContain(
        "/dispatch-intents/job_legacy_service_credit",
      );
    } finally {
      mutableDeployment.delegateUrl = originalDelegateUrl;
      vi.unstubAllGlobals();
    }
  });

  it("rejects unknown egress, canonical-ID drift, recipe drift, and contradictory lifecycle flags", () => {
    expect(() => parseComputeDispatchIntent({ ...dispatchStatus(), provider_id: "forbidden" })).toThrow(/unsupported fields/);
    expect(() => parseComputeDispatchIntent({ ...dispatchStatus(), job_id: `0x${"9".repeat(64)}` })).toThrow(/bounded schema/);
    expect(() => parseComputeDispatchIntent(dispatchStatus({
      intent_commitment: `0x${"5".repeat(64)}`,
    }))).toThrow(/commitment does not match/);
    expect(() => parseComputeDispatchIntent(dispatchStatus({
      execution_policy_context_hash: "5".repeat(64),
    }))).toThrow(/execution-policy context/);
    expect(() => parseComputeDispatchIntent({
      ...dispatchStatus(),
      resource_limits: { max_prefill_tokens: 32_769, max_sample_tokens: 100, max_train_tokens: 0 },
    })).toThrow(/bounded schema/);
    expect(() => parseComputeDispatchIntent({
      ...dispatchStatus(),
      stage: "provider_dispatching",
      provider_dispatch_status: "not_started",
    })).toThrow(/bounded schema/);
    expect(() => parseComputeDispatchIntent({
      ...dispatchStatus(),
      provider_dispatch_status: "usage_finalized",
      provider_dispatch_may_have_occurred: true,
      provider_usage_finalized: false,
    })).toThrow(/bounded schema/);
    expect(() => parseComputeDispatchIntent({ ...dispatchStatus(), prompt: "private" })).toThrow(/forbidden field prompt/);

    const authoritySubstitution = dispatchStatus();
    authoritySubstitution.workload_authority = {
      ...(authoritySubstitution.workload_authority as Record<string, unknown>),
      source_kind: "wallet",
    };
    expect(() => parseComputeDispatchIntent(authoritySubstitution))
      .toThrow(/commitment does not match/);
    const unconfirmedClaim = dispatchStatus() as unknown as Record<string, unknown>;
    unconfirmedClaim.workload_claim_confirmed = false;
    expect(() => parseComputeDispatchIntent(unconfirmedClaim)).toThrow(/bounded schema/);
    const authorizationDrift = dispatchStatus();
    authorizationDrift.authorization = {
      ...(authorizationDrift.authorization as Record<string, unknown>),
      server_derived: false,
    };
    expect(() => parseComputeDispatchIntent(authorizationDrift))
      .toThrow(/derivation is contradictory/);
  });

  it("strictly parses the disabled capability and rejects unknown or contradictory upgrades", () => {
    expect(parseComputeFundingCapabilities(fundingCapabilities()).dispatch_intents).toEqual(dispatchCapability());

    const unknown = fundingCapabilities();
    (unknown.dispatch_intents as Record<string, unknown>).future_override = true;
    expect(() => parseComputeFundingCapabilities(unknown)).toThrow(/unsupported fields/);

    expect(() => parseComputeFundingCapabilities(fundingCapabilities(dispatchCapability({
      provider_dispatch: true,
    })))).toThrow(/contradictory/);
    expect(() => parseComputeFundingCapabilities(fundingCapabilities(dispatchCapability({
      metadata_intent_creation: true,
      mutation_route: null,
    })))).toThrow(/contradictory/);
    expect(() => parseComputeFundingCapabilities(fundingCapabilities(dispatchCapability({
      independent_metering: true,
    })))).toThrow(/contradictory/);

    const releaseDrift = fundingCapabilities();
    ((releaseDrift.dispatch_intents as ComputeDispatchCapability)
      .provider as ComputeProviderCapabilityRelease).provider_release_sha256
      = `sha256:${"f".repeat(64)}`;
    expect(() => parseComputeFundingCapabilities(releaseDrift)).toThrow(/provider capability/);

    const nestedUpgrade = fundingCapabilities();
    (((nestedUpgrade.dispatch_intents as ComputeDispatchCapability)
      .provider as ComputeProviderCapabilityRelease)
      .runtime_guarantees as unknown as Record<string, unknown>).provider_replay = true;
    expect(() => parseComputeFundingCapabilities(nestedUpgrade)).toThrow(/unsupported fields/);
  });

  it("strictly parses a fresh at-most-once provider capability", () => {
    const ready = dispatchCapability({
      metadata_intent_creation: true,
      provider_dispatch: true,
      independent_metering: true,
      settlement: true,
      mutation_route: "/compute/projects/{project_id}/dispatch-intents",
      provider: readyProviderCapability(),
      reason: "ready_at_most_once_terminal_ambiguity_hold",
    });
    const parsed = parseComputeFundingCapabilities(fundingCapabilities(ready));
    expect(parsed.dispatch_intents.provider.provider_dispatch).toBe(true);
    expect(parsed.dispatch_intents.automatic_provider_redispatch).toBe(false);
    expect(
      "runtime" in parsed.dispatch_intents.provider
        ? parsed.dispatch_intents.provider.runtime?.tdx_evidence
        : undefined,
    ).toBe(false);

    const missingRuntime = fundingCapabilities(dispatchCapability({
      metadata_intent_creation: true,
      provider_dispatch: true,
      independent_metering: true,
      settlement: true,
      mutation_route: "/compute/projects/{project_id}/dispatch-intents",
      provider: providerCapability({
        release_configured: true,
        provider_dispatch: true,
        runtime_guarantees: {
          at_most_once_attempt_checkpoint: true,
          terminal_ambiguity_hold: true,
          ambiguous_outcome_ciphertext_retained: true,
        },
        reason: "ready_at_most_once_ambiguity_hold",
      }),
      reason: "ready_at_most_once_terminal_ambiguity_hold",
    }));
    expect(() => parseComputeFundingCapabilities(missingRuntime)).toThrow(/provider capability/);
  });

  it("keeps creation disabled until both project and every independent release capability agree", () => {
    const allEnabled = dispatchCapability({
      metadata_intent_creation: true,
      provider_dispatch: true,
      independent_metering: true,
      settlement: true,
      mutation_route: "/compute/projects/{project_id}/dispatch-intents",
      provider: readyProviderCapability(),
      reason: "ready_at_most_once_terminal_ambiguity_hold",
    });
    expect(canCreateComputeDispatchIntent(dispatchProject, allEnabled)).toBe(false);
    const enabledProject = { ...dispatchProject, provider_dispatch_enabled: true };
    expect(canCreateComputeDispatchIntent(enabledProject, allEnabled)).toBe(true);
    expect(canCreateComputeDispatchIntent({ ...enabledProject, role: "viewer" }, allEnabled)).toBe(false);
    expect(canCreateComputeDispatchIntent(enabledProject, { ...allEnabled, settlement: false })).toBe(false);
    expect(canCreateComputeDispatchIntent(enabledProject, {
      ...allEnabled,
      provider: readyProviderCapability({
        runtime_guarantees: {
          at_most_once_attempt_checkpoint: true,
          terminal_ambiguity_hold: false,
          ambiguous_outcome_ciphertext_retained: true,
        },
      }),
    })).toBe(false);
  });

  it("reads the status route with bearer auth and losslessly parses bare oversized JSON integers", async () => {
    const mutableDeployment = deployment as unknown as { delegateUrl: string };
    const originalDelegateUrl = mutableDeployment.delegateUrl;
    mutableDeployment.delegateUrl = "https://delegate.example";
    const serialized = JSON.stringify(dispatchStatus())
      .replace('"authorization_nonce":"9007199254740993"', '"authorization_nonce":9007199254740993')
      .replace('"max_asset_debit":"1000000000000000000"', '"max_asset_debit":1000000000000000000');
    const fetchMock = vi.fn(async () => new Response(serialized, {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }));
    vi.stubGlobal("fetch", fetchMock);
    try {
      const parsed = await fetchComputeDispatchIntent(
        "compute-wallet-token",
        dispatchProject.project_id,
        "wallet-job-0001",
      );
      expect(parsed.max_asset_debit).toBe(1_000_000_000_000_000_000n);
      const [url, options] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
      expect(url).toBe(`https://delegate.example/compute/projects/${dispatchProject.project_id}/dispatch-intents/wallet-job-0001`);
      expect(options.credentials).toBe("omit");
      expect(options.headers).toEqual({
        Accept: "application/json",
        Authorization: "Bearer compute-wallet-token",
      });
    } finally {
      mutableDeployment.delegateUrl = originalDelegateUrl;
    }
  });

  it("refuses disabled creation before fetch and posts only canonical metadata when fully enabled", async () => {
    const mutableDeployment = deployment as unknown as { delegateUrl: string };
    const originalDelegateUrl = mutableDeployment.delegateUrl;
    mutableDeployment.delegateUrl = "https://delegate.example";
    const allEnabled = dispatchCapability({
      metadata_intent_creation: true,
      provider_dispatch: true,
      independent_metering: true,
      settlement: true,
      mutation_route: "/compute/projects/{project_id}/dispatch-intents",
      provider: readyProviderCapability(),
      reason: "ready_at_most_once_terminal_ambiguity_hold",
    });
    const enabledProject = { ...dispatchProject, provider_dispatch_enabled: true };
    const input = {
      jobReference: "wallet-job-0001",
      workloadId: `wrk_${"ab".repeat(16)}`,
      asset: `0x${"0".repeat(40)}`,
      authorizationNonce: 9_007_199_254_740_993n,
      maxAssetDebit: 1_000_000_000_000_000_000n,
      authorizationExpiry: Math.floor(Date.now() / 1_000) + 600,
      ratePolicyCommitment: `0x${"3".repeat(64)}`,
      composeHash: `0x${"4".repeat(64)}`,
      operation: "inference" as const,
      resultPolicy: "bounded_summary_receipt" as const,
      maxPrefillTokens: 1_000,
      maxSampleTokens: 100,
      maxTrainTokens: 0,
    };
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({
      surface: "compute_dispatch_intent_result",
      schema_version: 3,
      created: true,
      idempotent_replay: false,
      workload_claim_created: true,
      workload_claim_confirmed: true,
      workload_claim_recovered: false,
      workload_claim_commitment: `sha256:${"95".repeat(32)}`,
      intent: dispatchStatus({ authorization_expiry: input.authorizationExpiry }),
      legacy_credit_ledger_mutated: false,
      provider_dispatch_status: "not_started",
      provider_dispatch_may_have_occurred: false,
      provider_authoritative: false,
    }), { status: 200, headers: { "Content-Type": "application/json" } }));
    vi.stubGlobal("fetch", fetchMock);
    try {
      await expect(createComputeDispatchIntent(
        "compute-wallet-token", dispatchProject, allEnabled, input, "dispatch:12345678",
      )).rejects.toThrow(/not enabled/);
      expect(fetchMock).not.toHaveBeenCalled();

      await expect(createComputeDispatchIntent(
        "compute-wallet-token",
        enabledProject,
        allEnabled,
        { ...input, resultPolicy: "score_band_hash" },
        "dispatch:unsupported-policy",
      )).rejects.toThrow(/not supported by the provider release/);
      expect(fetchMock).not.toHaveBeenCalled();

      await expect(createComputeDispatchIntent(
        "compute-wallet-token", enabledProject, allEnabled, input, "dispatch:12345678",
      )).resolves.toMatchObject({ created: true, idempotentReplay: false });
      expect(fetchMock).toHaveBeenCalledTimes(1);
      const [url, options] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
      expect(url).toBe(`https://delegate.example/compute/projects/${dispatchProject.project_id}/dispatch-intents`);
      expect(options.method).toBe("POST");
      expect(options.headers).toEqual({
        Accept: "application/json",
        Authorization: "Bearer compute-wallet-token",
        "Content-Type": "application/json",
        "Idempotency-Key": "dispatch:12345678",
      });
      expect(JSON.parse(String(options.body))).toEqual({
        job_reference: "wallet-job-0001",
        workload_id: `wrk_${"ab".repeat(16)}`,
        asset: `0x${"0".repeat(40)}`,
        authorization_nonce: "9007199254740993",
        max_asset_debit: "1000000000000000000",
        authorization_expiry: input.authorizationExpiry,
        rate_policy_commitment: `0x${"3".repeat(64)}`,
        compose_hash: `0x${"4".repeat(64)}`,
        operation: "inference",
        model: "qwen3_8b",
        recipe: "qwen3_8b_bounded",
        result_policy: "bounded_summary_receipt",
        max_prefill_tokens: 1_000,
        max_sample_tokens: 100,
        max_train_tokens: 0,
      });
    } finally {
      mutableDeployment.delegateUrl = originalDelegateUrl;
    }
  });

  it("permits cancellation only at the exact pre-start checkpoint and strictly binds its receipt", () => {
    const preStart = parseComputeDispatchIntent(dispatchStatus());
    expect(canCancelComputeDispatchIntent(
      preStart,
      dispatchProject,
      `0x${"1".repeat(40)}`,
    )).toBe(true);
    expect(canCancelComputeDispatchIntent(
      preStart,
      { ...dispatchProject, role: "viewer" },
      `0x${"1".repeat(40)}`,
    )).toBe(false);
    expect(canCancelComputeDispatchIntent(
      preStart,
      dispatchProject,
      `0x${"2".repeat(40)}`,
    )).toBe(false);
    expect(canCancelComputeDispatchIntent(parseComputeDispatchIntent(dispatchStatus({
      stage: "start_prepared",
      provider_dispatch_status: "not_started",
    })))).toBe(false);
    expect(canCancelComputeDispatchIntent(parseComputeDispatchIntent(dispatchStatus({
      stage: "provider_attempt_checkpointed",
      provider_dispatch_status: "attempt_checkpointed",
      provider_dispatch_may_have_occurred: true,
    })))).toBe(false);

    expect(parseComputeDispatchCancellation(
      dispatchCancellationResponse(preStart),
      preStart,
    )).toMatchObject({
      journal_execution_prevented: true,
      workload_ciphertext_released: true,
      onchain_cancel_required: true,
      exact_asset_capacity_released: false,
      changed: true,
      idempotent_replay: false,
    });
    expect(parseComputeDispatchCancellation(
      dispatchCancellationResponse(preStart, {
        changed: false,
        idempotent_replay: true,
      }),
      preStart,
    )).toMatchObject({ changed: false, idempotent_replay: true });
    expect(() => parseComputeDispatchCancellation(
      dispatchCancellationResponse(preStart, {
        workload_ciphertext_released: false,
      }),
      preStart,
    )).toThrow(/bounded schema/);
    expect(() => parseComputeDispatchCancellation(
      dispatchCancellationResponse(preStart, {
        job_id: `0x${"9".repeat(64)}`,
      }),
      preStart,
    )).toThrow(/bounded schema/);
    const checkpointDrift = dispatchCancellationResponse(preStart);
    checkpointDrift.cancellation_checkpoint_commitment = `sha256:${"f".repeat(64)}`;
    expect(() => parseComputeDispatchCancellation(
      checkpointDrift,
      preStart,
    )).toThrow(/bounded schema/);
    const cancellationTimeDrift = dispatchCancellationResponse(preStart);
    cancellationTimeDrift.canceled_at = Number(cancellationTimeDrift.canceled_at) + 1;
    expect(() => parseComputeDispatchCancellation(
      cancellationTimeDrift,
      preStart,
    )).toThrow(/bounded schema/);
    expect(() => parseComputeDispatchCancellation(
      {
        ...dispatchCancellationResponse(preStart),
        raw_transaction: "forbidden",
      },
      preStart,
    )).toThrow(/unsupported fields/);
  });

  it("posts the fixed cancellation grammar with one caller-supplied replay key", async () => {
    const mutableDeployment = deployment as unknown as { delegateUrl: string };
    const originalDelegateUrl = mutableDeployment.delegateUrl;
    mutableDeployment.delegateUrl = "https://delegate.example";
    const preStart = parseComputeDispatchIntent(dispatchStatus());
    const attempt = createComputeDispatchCancellationAttempt(
      preStart,
      dispatchProject,
      `0x${"1".repeat(40)}`,
      "dispatch-cancel:12345678",
    );
    const fetchMock = vi.fn(async () => new Response(
      JSON.stringify(dispatchCancellationResponse(preStart)),
      { status: 200, headers: { "Content-Type": "application/json" } },
    ));
    vi.stubGlobal("fetch", fetchMock);
    try {
      await expect(cancelComputeDispatchIntent(
        "compute-wallet-token",
        dispatchProject,
        preStart,
        `0x${"2".repeat(40)}`,
        attempt,
      )).rejects.toThrow(/only before provider start/);
      expect(fetchMock).not.toHaveBeenCalled();

      await expect(cancelComputeDispatchIntent(
        "compute-wallet-token",
        dispatchProject,
        preStart,
        `0x${"1".repeat(40)}`,
        attempt,
      )).resolves.toMatchObject({
        journal_execution_prevented: true,
        workload_ciphertext_released: true,
      });
      const [url, options] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
      expect(url).toBe(
        `https://delegate.example/compute/projects/${dispatchProject.project_id}/dispatch-intents/wallet-job-0001/cancel`,
      );
      expect(options.method).toBe("POST");
      expect(options.credentials).toBe("omit");
      expect(options.headers).toEqual({
        Accept: "application/json",
        Authorization: "Bearer compute-wallet-token",
        "Content-Type": "application/json",
        "Idempotency-Key": "dispatch-cancel:12345678",
      });
      expect(JSON.parse(String(options.body))).toEqual({
        reason: "user_requested_before_provider_start",
      });
    } finally {
      mutableDeployment.delegateUrl = originalDelegateUrl;
    }
  });

  it("recovers only an exact persisted cancellation replay after reload and fails closed on key loss", async () => {
    const mutableDeployment = deployment as unknown as { delegateUrl: string };
    const originalDelegateUrl = mutableDeployment.delegateUrl;
    mutableDeployment.delegateUrl = "https://delegate.example";
    const walletAddress = `0x${"1".repeat(40)}`;
    const preStart = parseComputeDispatchIntent(dispatchStatus());
    const originalAttempt = createComputeDispatchCancellationAttempt(
      preStart,
      dispatchProject,
      walletAddress,
      "dispatch-cancel:reload-0001",
    );
    const serialized = JSON.stringify(originalAttempt);
    expect(serialized).not.toContain("compute-wallet-token");
    expect(serialized).not.toContain("prompt");
    const recoveredAttempt = parseComputeDispatchCancellationAttempt(
      JSON.parse(serialized),
    );
    const blocked = parseComputeDispatchIntent(dispatchStatus({
      stage: "blocked",
      workload_ciphertext_released: false,
    }));
    expect(canReplayComputeDispatchCancellationAttempt(
      blocked,
      dispatchProject,
      walletAddress,
      recoveredAttempt,
    )).toBe(true);
    expect(canReplayComputeDispatchCancellationAttempt(
      blocked,
      dispatchProject,
      walletAddress,
      undefined,
    )).toBe(false);
    expect(canReplayComputeDispatchCancellationAttempt(
      blocked,
      dispatchProject,
      `0x${"2".repeat(40)}`,
      recoveredAttempt,
    )).toBe(false);
    expect(canReplayComputeDispatchCancellationAttempt(
      parseComputeDispatchIntent(dispatchStatus({
        stage: "blocked",
        provider_dispatch_status: "usage_finalized",
        provider_dispatch_may_have_occurred: true,
        provider_usage_finalized: true,
        bounded_result: boundedResult() as unknown as ComputeDispatchIntentStatus["bounded_result"],
      })),
      dispatchProject,
      walletAddress,
      recoveredAttempt,
    )).toBe(false);
    expect(() => parseComputeDispatchCancellationAttempt({
      ...recoveredAttempt,
      token: "must-not-persist",
    })).toThrow(/unsupported fields/);
    expect(() => parseComputeDispatchCancellationAttempt({
      ...recoveredAttempt,
      idempotency_key: "short",
    })).toThrow(/malformed/);

    const fetchMock = vi.fn(async () => new Response(JSON.stringify(
      dispatchCancellationResponse(preStart, {
        changed: false,
        idempotent_replay: true,
      }),
    ), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }));
    vi.stubGlobal("fetch", fetchMock);
    try {
      await expect(cancelComputeDispatchIntent(
        "compute-wallet-token",
        dispatchProject,
        blocked,
        walletAddress,
        recoveredAttempt,
      )).resolves.toMatchObject({
        changed: false,
        idempotent_replay: true,
        workload_ciphertext_released: true,
      });
      const [, options] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
      expect((options.headers as Record<string, string>)["Idempotency-Key"])
        .toBe("dispatch-cancel:reload-0001");
    } finally {
      mutableDeployment.delegateUrl = originalDelegateUrl;
    }
  });

  it("authenticates every settled usage signature and rejects binding or egress drift", async () => {
    const { status, receipt } = await settledUsageReceiptFixture();
    await expect(parseComputeExactAssetUsageReceipt(receipt, status)).resolves.toMatchObject({
      surface: "compute_exact_asset_usage_receipt",
      provider_authoritative_invoice: false,
      exact_asset_only: true,
      settlement: {
        confirmed: true,
        chain_id: 84_532,
        actual_asset_debit: 500n,
        billable_compute_units: 12n,
      },
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
    });

    const usageDrift = structuredClone(receipt);
    ((usageDrift.signed_usage as Record<string, unknown>).usage as Record<string, unknown>)
      .prefill_tokens = "11";
    await expect(parseComputeExactAssetUsageReceipt(usageDrift, status))
      .rejects.toThrow(/dispatch binding|commitment/);

    const signatureDrift = structuredClone(receipt);
    const signedUsage = (signatureDrift.signed_usage as Record<string, unknown>)
      .usage as Record<string, unknown>;
    signedUsage.tee_signature = `0x${"1".repeat(130)}`;
    await expect(parseComputeExactAssetUsageReceipt(signatureDrift, status))
      .rejects.toThrow(/signatures could not be authenticated/);

    const egressDrift = structuredClone(receipt);
    egressDrift.raw_output_egress = true;
    await expect(parseComputeExactAssetUsageReceipt(egressDrift, status))
      .rejects.toThrow(/settlement binding/);

    const debitDrift = structuredClone(receipt);
    (debitDrift.independent_metering as Record<string, unknown>)
      .actual_asset_debit = "501";
    (debitDrift.settlement as Record<string, unknown>).actual_asset_debit = "501";
    await expect(parseComputeExactAssetUsageReceipt(debitDrift, status))
      .rejects.toThrow(/local ComputeCreditVault digest derivation/);

    const digestDrift = structuredClone(receipt);
    (digestDrift.independent_metering as Record<string, unknown>)
      .metering_receipt_digest = `0x${"7".repeat(64)}`;
    await expect(parseComputeExactAssetUsageReceipt(digestDrift, status))
      .rejects.toThrow(/local ComputeCreditVault digest derivation/);

    const vaultDrift = structuredClone(receipt);
    (vaultDrift.independent_metering as Record<string, unknown>).vault_address =
      `0x${"a".repeat(40)}`;
    (vaultDrift.settlement as Record<string, unknown>).vault_address =
      `0x${"a".repeat(40)}`;
    await expect(parseComputeExactAssetUsageReceipt(vaultDrift, status))
      .rejects.toThrow(/local ComputeCreditVault digest derivation/);

    const wrongRelease = structuredClone(receipt);
    wrongRelease.provider_release_sha256 = `sha256:${"f".repeat(64)}`;
    await expect(parseComputeExactAssetUsageReceipt(wrongRelease, status))
      .rejects.toThrow(/settlement binding/);

    await expect(parseComputeExactAssetUsageReceipt(
      receipt,
      parseComputeDispatchIntent(dispatchStatus()),
    )).rejects.toThrow(/only after settlement/);
  });

  it("retrieves exact usage only for a settled status with wallet bearer auth", async () => {
    const mutableDeployment = deployment as unknown as { delegateUrl: string };
    const originalDelegateUrl = mutableDeployment.delegateUrl;
    mutableDeployment.delegateUrl = "https://delegate.example";
    const { status, receipt } = await settledUsageReceiptFixture();
    const fetchMock = vi.fn(async () => new Response(JSON.stringify(receipt), {
      status: 200,
      headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
    }));
    vi.stubGlobal("fetch", fetchMock);
    try {
      await expect(fetchComputeDispatchUsageReceipt(
        "compute-wallet-token",
        status,
      )).resolves.toMatchObject({
        job_reference: status.job_reference,
        settlement: { confirmed: true },
      });
      const [url, options] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
      expect(url).toBe(
        `https://delegate.example/compute/projects/${status.project_reference}/dispatch-intents/${status.job_reference}/usage-receipt`,
      );
      expect(options.method).toBe("GET");
      expect(options.credentials).toBe("omit");
      expect(options.cache).toBe("no-store");
      expect(options.redirect).toBe("error");
      expect(options.headers).toEqual({
        Accept: "application/json",
        Authorization: "Bearer compute-wallet-token",
      });

      await expect(fetchComputeDispatchUsageReceipt(
        "compute-wallet-token",
        parseComputeDispatchIntent(dispatchStatus()),
      )).rejects.toThrow(/only after settlement/);
      expect(fetchMock).toHaveBeenCalledTimes(1);
    } finally {
      mutableDeployment.delegateUrl = originalDelegateUrl;
    }
  });
});
