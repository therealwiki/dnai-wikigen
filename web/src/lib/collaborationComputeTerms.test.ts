import { describe, expect, it } from "vitest";
import { zeroAddress, type Hex } from "viem";
import {
  assertCollaborationComputeAuthorizationMatchesPlanRequest,
  parseCollaborationExecutionStatus,
  type CollaborationExecutionPlanProjection,
  type CollaborationExecutionPlanRequest,
  type CollaborationExecutionStatusProjection,
} from "./collaboration";
import { verifyCollaborationComputeAuthorizationTerms } from "./collaborationComputeAuthorization";
import {
  computeCollaborationOneShotAuthorizationContextCommitment,
  computeDispatchIntentV3Commitment,
} from "./computeDispatchCommitment";
import { collaborationFundingReservationId, type CollaborationFundingReservationRequest } from "./collaborationRoyaltyReservation";

const word = (digit: string) => `0x${digit.repeat(64)}` as Hex;
const pin = (digit: string) => `sha256:${digit.repeat(64)}` as `sha256:${string}`;
const USER = `0x${"1".repeat(40)}` as const;
const OTHER = `0x${"9".repeat(40)}` as const;
const VAULT = `0x${"2".repeat(40)}` as const;
const DISTRIBUTOR = `0x${"3".repeat(40)}` as const;
const EXECUTION = `exec_${"4".repeat(64)}`;
const ROOM = `room_${"5".repeat(32)}`;
const NOW = 1_900_000_000;

function request(sourceKind: "wallet" | "credential" = "wallet"): CollaborationExecutionPlanRequest {
  return {
    compute_project_id: word("1"), compute_job_id: word("2"),
    compute_workload_id: `wrk_${"3".repeat(32)}`, compute_workload_commitment: word("4"),
    compute_manifest_commitment: word("5"), compute_rate_policy_commitment: word("6"),
    compute_workload_schema: "dnai.compute.workload.inference.v1", compute_workload_source_kind: sourceKind,
    compute_workload_execution_binding_commitment: pin("7"), compute_workload_recipient_release_commitment: pin("8"),
    compute_user_address: USER, sponsor_address: USER, operation: "inference", model: "qwen3_8b",
    recipe: "qwen3_8b_bounded", result_policy: "bounded_summary_receipt",
    max_prefill_tokens: 2048, max_sample_tokens: 512, max_train_tokens: 0,
    asset: zeroAddress, max_total_asset_debit: 10_000, max_compute_asset_debit: 7000,
    royalty_total: 2000, authorization_nonce: 11, authorization_lifetime_seconds: 600,
  };
}

function plan(sourceKind: "wallet" | "credential" = "wallet"): CollaborationExecutionPlanProjection {
  return {
    surface: "collaboration_execution_plan", schema_version: 2, run_id: `run_${"a".repeat(32)}`,
    room_id: ROOM, requester_address: USER, release_git_sha: "b".repeat(40),
    release_verification_sha256: pin("c"), chain_id: 84532, cvm_id: "cvm-main-runtime-0001",
    compose_hash: word("d"), compute_workload_source_kind: sourceKind, sponsor_address: USER,
    asset: zeroAddress, room_commitment: pin("1"), room_generation: 1, room_state_commitment: pin("2"),
    query_ref: pin("3"), query_proposal_commitment: pin("4"), prospective_query_grant_set_commitment: pin("5"),
    joint_consent_snapshot_commitment: pin("6"), allocation_commitment: pin("7"),
    authorization_expiry: NOW + 600, royalty_total: "2000", basis_commitment: pin("8"), owner_addresses: [USER],
    royalty_owner_amounts_hash: word("9"), royalty_distributor_address: DISTRIBUTOR,
    royalty_release_policy_commitment: word("a"), royalty_release_binding_commitment: pin("b"),
    royalty_settlement_id: word("c"), royalty_settlement_nonce: "17", royalty_reservation_safety_seconds: 900,
    royalty_authority_server_derived: true, royalty_reservation_is_derived_after_fresh_owner_grants: true,
    royalty_reservation_must_be_deposited_onchain_after_authorization: true,
    plan_token: `${"a".repeat(40)}.${"b".repeat(40)}`, plan_token_contains_bounded_metadata_only: true,
    requires_fresh_execution_grant_from_every_owner: true, query_grants_are_not_execution_grants: true,
    provider_dispatch_performed: false, raw_signature_retained: false, raw_query_egress: false,
    raw_artifact_egress: false, clientProjectionIsExecutionEvidence: false,
  };
}

/** Exact API public_projection shape, including the independently parsed Royalty seam. */
function statusFixture(sourceKind: "wallet" | "credential" = "wallet") {
  const p = plan(sourceKind);
  const r = request(sourceKind);
  const grantSet = pin("d");
  const intentCommitment = pin("e");
  const context = computeCollaborationOneShotAuthorizationContextCommitment({
    collaborationExecutionBasisCommitment: p.basis_commitment as `sha256:${string}`,
    collaborationExecutionGrantSetCommitment: grantSet,
    projectId: r.compute_project_id as Hex, jobId: r.compute_job_id as Hex, user: USER, asset: zeroAddress,
    authorizationNonce: BigInt(r.authorization_nonce), maxAssetDebit: BigInt(r.max_compute_asset_debit),
    authorizationExpiry: p.authorization_expiry, ratePolicyCommitment: r.compute_rate_policy_commitment as Hex,
    workloadCommitment: r.compute_workload_commitment as Hex, manifestCommitment: r.compute_manifest_commitment as Hex,
  });
  const dispatch = computeDispatchIntentV3Commitment({
    projectReference: r.compute_project_id, jobReference: r.compute_job_id,
    projectId: r.compute_project_id as Hex, jobId: r.compute_job_id as Hex, user: USER, asset: zeroAddress,
    authorizationNonce: BigInt(r.authorization_nonce), maxAssetDebit: BigInt(r.max_compute_asset_debit),
    authorizationExpiry: p.authorization_expiry, ratePolicyCommitment: r.compute_rate_policy_commitment as Hex,
    composeHash: p.compose_hash as Hex, operation: r.operation, model: r.model, recipe: r.recipe,
    resultPolicy: r.result_policy, maxPrefillTokens: r.max_prefill_tokens,
    maxSampleTokens: r.max_sample_tokens, maxTrainTokens: r.max_train_tokens,
    workloadId: r.compute_workload_id, workloadSchema: r.compute_workload_schema,
    workloadCommitment: r.compute_workload_commitment as Hex, manifestCommitment: r.compute_manifest_commitment as Hex,
    workloadSourceKind: sourceKind,
    workloadExecutionBindingCommitment: r.compute_workload_execution_binding_commitment as `sha256:${string}`,
    workloadRecipientReleaseCommitment: r.compute_workload_recipient_release_commitment as `sha256:${string}`,
    authorizationKind: "collaboration_one_shot", authorizationContextCommitment: context,
  });
  const funding: CollaborationFundingReservationRequest = {
    settlementId: p.royalty_settlement_id as Hex, settlementNonce: 17n,
    releasePolicyCommitment: p.royalty_release_policy_commitment as Hex,
    roomCommitment: word("1"), roomStateCommitment: word("2"), queryCommitment: word("4"),
    grantSetCommitment: word("d"), allocationCommitment: word("7"), ownersAmountsHash: word("9"),
    asset: zeroAddress, total: 2000n, executionCommitment: word("e"), refundAfter: BigInt(NOW + 1500),
  };
  return {
    surface: "collaboration_one_shot_execution", schema_version: 1, execution_id: EXECUTION,
    intent_commitment: intentCommitment, authorization_commitment: pin("f"),
    execution_grant_set_commitment: grantSet, owner_execution_grant_count: 1,
    release: { git_sha: p.release_git_sha, verification_sha256: p.release_verification_sha256,
      chain_id: 84532, cvm_id: p.cvm_id, compose_hash: p.compose_hash },
    room_id: ROOM, room_commitment: p.room_commitment, room_generation: 1,
    room_state_commitment: p.room_state_commitment, query_ref: p.query_ref,
    query_proposal_commitment: p.query_proposal_commitment,
    prospective_query_grant_set_commitment: p.prospective_query_grant_set_commitment,
    joint_consent_snapshot_commitment: p.joint_consent_snapshot_commitment, allocation_commitment: p.allocation_commitment,
    compute_project_id: r.compute_project_id, compute_job_id: r.compute_job_id,
    compute_workload_id: r.compute_workload_id, compute_workload_commitment: r.compute_workload_commitment,
    compute_manifest_commitment: r.compute_manifest_commitment, compute_dispatch_intent_commitment: dispatch,
    compute_authorization: { kind: "collaboration_one_shot", context_commitment: context, standalone_path_used: false },
    compute_rate_policy_commitment: r.compute_rate_policy_commitment, compute_workload_schema: r.compute_workload_schema,
    compute_workload_source_kind: r.compute_workload_source_kind,
    compute_workload_execution_binding_commitment: r.compute_workload_execution_binding_commitment,
    compute_workload_recipient_release_commitment: r.compute_workload_recipient_release_commitment,
    compute_authority: { vault_address: VAULT, vault_runtime_code_hash: word("f"),
      finality_model: "single_rpc_reported_finalized", user_address: USER },
    operation: r.operation, model: r.model, recipe: r.recipe, result_policy: r.result_policy,
    resource_limits: { max_prefill_tokens: r.max_prefill_tokens, max_sample_tokens: r.max_sample_tokens, max_train_tokens: r.max_train_tokens },
    sponsor_address: USER, asset: zeroAddress, max_total_asset_debit: r.max_total_asset_debit,
    max_total_asset_debit_scope: "compute_usage_plus_reserved_royalty", max_compute_asset_debit: r.max_compute_asset_debit,
    max_compute_asset_debit_scope: "compute_usage_only", authorization_nonce: r.authorization_nonce,
    authorization_expiry: p.authorization_expiry,
    royalty: {
      asset: zeroAddress, total: "2000", owner_amounts_hash: word("9"),
      owner_amounts: [{ owner_address: USER, amount: "2000" }],
      distributor_address: DISTRIBUTOR, release_policy_commitment: word("a"), release_binding_commitment: pin("b"),
      settlement_id: word("c"), settlement_nonce: "17",
      funding_reservation: {
        schema: "dnai.collaboration.royalty-funding-reservation.v1", chain_id: 84532,
        distributor_address: DISTRIBUTOR, sponsor_address: USER,
        reservation_id: collaborationFundingReservationId({ chainId: 84532, distributor: DISTRIBUTOR, sponsor: USER, request: funding }),
        request: { settlement_id: funding.settlementId, settlement_nonce: "17",
          release_policy_commitment: funding.releasePolicyCommitment, room_commitment: funding.roomCommitment,
          room_state_commitment: funding.roomStateCommitment, query_commitment: funding.queryCommitment,
          grant_set_commitment: funding.grantSetCommitment, allocation_commitment: funding.allocationCommitment,
          owners_amounts_hash: funding.ownersAmountsHash, asset: zeroAddress, total: "2000",
          execution_commitment: funding.executionCommitment, refund_after: funding.refundAfter.toString() },
        transaction: { schema: "dnai.collaboration.royalty-funding-action-gated.v1", status: "gated_worker_presence_required",
          reason: "fresh_authenticated_worker_and_qvl_capability_required", executable: false,
          wallet_transaction_included: false, erc20_approval_included: false },
        derived_after_fresh_owner_grants: true, client_supplied_reservation_id: false,
        balance_or_allowance_is_not_authorization: true,
      },
      reservation_safety_seconds: 900, funding_reservation_finalization_proven: false,
      hash_semantics: "RoyaltyDistributor owner and amount array EIP-712 commitment",
      exact_payout_validation_proven: true, fresh_construction_requires_validated_owner_amounts: true,
    },
    state: "authorized", claim_count: 0, bounded_result: null,
    claim_vault_observation: null, claim_royalty_observation: null,
    compute_handoff: { handoff_id: `handoff_${"a".repeat(64)}`, handoff_commitment: pin("a"),
      planned_at: NOW, provider_call_performed_by_collaboration: false },
    compute_handoff_status: "planned_not_submitted", compute_journal_projection: null,
    provider_dispatch_may_have_occurred: null, provider_dispatch_flag_source: null,
    collaboration_provider_call_performed: false, journal_automatic_redispatch: false,
    idempotent_provider_replay_claimed: false, reconciliation_hold: false,
    reconciliation_was_required: false, reconciliation_hold_at: null, reconciliation_hold_projection_commitment: null,
    authority_invalidated_before_claim: false, source_capable_core_only: false, api_worker_wiring_claimed: false,
    live_deployment_claimed: false, tdx_attestation_claimed: false, qvl_verification_claimed: false,
    settlement_performed: false, compute_settlement_projected: false, royalty_distribution_performed: false,
    journal_raw_input_persisted: false, journal_raw_result_persisted: false,
    public_projection_raw_input_included: false, public_projection_raw_result_included: false,
    public_projection_provider_identifier_included: false, whole_system_non_egress_claimed: false,
    anti_rollback_provided: false, authorized_at: NOW, queued_at: null, claimed_at: null,
    handoff_pending_at: null, handoff_confirmed_at: null, terminal_at: null,
    api_worker_wiring_available: true, fresh_worker_presence_proven: false,
    client_supplied_vault_observation: false, client_supplied_compute_projection: false,
  };
}

function replacePath(value: unknown, path: string, replacement: unknown): void {
  const segments = path.split(".");
  let container = value as Record<string, unknown>;
  for (const segment of segments.slice(0, -1)) container = container[segment] as Record<string, unknown>;
  container[segments.at(-1)!] = replacement;
}

function verifyProjectedTerms(status: CollaborationExecutionStatusProjection, retainedPlan = plan()) {
  const { releaseSha: _sha, releaseVerificationSha256: _verification, cvmId: _cvm, ...terms } = status.computeAuthorization;
  return verifyCollaborationComputeAuthorizationTerms({ ...terms,
    basisCommitment: retainedPlan.basis_commitment as `sha256:${string}`, releaseFingerprint: "current-release-binding" });
}

describe("actual Collaboration status Compute-authorization projection", () => {
  it.each(["wallet", "credential"] as const)("parses the complete %s-origin public response without granting chain or TEE evidence", (source) => {
    const raw = statusFixture(source);
    const status = parseCollaborationExecutionStatus(raw);
    expect(status.computeAuthorization).toMatchObject({
      executionId: EXECUTION, grantSetCommitment: pin("d"), authorizationKind: "collaboration_one_shot",
      chainId: 84532, vaultAddress: VAULT, vaultRuntimeCodeHash: word("f"),
      finalityModel: "single_rpc_reported_finalized", authorizationNonce: 11n,
      maxAssetDebit: 7000n, authorizationExpiry: NOW + 600, user: USER, asset: zeroAddress,
      workload: { sourceKind: source, workloadId: raw.compute_workload_id, maxPrefillTokens: 2048,
        maxSampleTokens: 512, maxTrainTokens: 0, recipientReleaseCommitment: pin("8") },
    });
    expect(Object.isFrozen(status)).toBe(true);
    expect(Object.isFrozen(status.computeAuthorization)).toBe(true);
    expect(Object.isFrozen(status.computeAuthorization.workload)).toBe(true);
    expect(status.finalizedVaultFreshnessProvenInBrowser).toBe(false);
    expect(status.tdxAttestationVerifiedInBrowser).toBe(false);
    expect(status.qvlVerifiedInBrowser).toBe(false);
    expect(status.clientDtoMayUnlockExecutionControls).toBe(false);
    expect(status.royalty_reservation.walletActionReady).toBe(false);
    expect(() => assertCollaborationComputeAuthorizationMatchesPlanRequest(status, plan(source), request(source))).not.toThrow();
    expect(verifyProjectedTerms(status, plan(source)).dispatchIntentCommitment).toBe(raw.compute_dispatch_intent_commitment);
  });

  it.each([
    "release", "compute_authority", "compute_authorization", "resource_limits",
  ])("rejects unknown nested fields in %s", (path) => {
    const raw = statusFixture();
    replacePath(raw, `${path}.unexpected_authority`, true);
    expect(() => parseCollaborationExecutionStatus(raw)).toThrow();
  });

  it.each([
    { path: "compute_authorization.kind", value: "standalone" },
    { path: "compute_authorization.standalone_path_used", value: true },
    { path: "compute_authorization.context_commitment", value: word("a") },
    { path: "compute_authority.finality_model", value: "rpc_reported_finalized" },
    { path: "compute_authority.vault_runtime_code_hash", value: `0x${"0".repeat(64)}` },
    { path: "compute_authority.user_address", value: OTHER },
    { path: "sponsor_address", value: OTHER },
    { path: "release.chain_id", value: 1 },
    { path: "release.git_sha", value: "main" },
    { path: "release.verification_sha256", value: "sha256:invalid" },
    { path: "release.cvm_id", value: "bad" },
    { path: "release.compose_hash", value: pin("a") },
    { path: "authorization_nonce", value: "11" },
    { path: "authorization_nonce", value: -1 },
    { path: "authorization_nonce", value: Number.MAX_SAFE_INTEGER + 1 },
    { path: "max_compute_asset_debit", value: 0 },
    { path: "max_compute_asset_debit", value: Number.MAX_SAFE_INTEGER + 1 },
    { path: "authorization_expiry", value: 4_102_444_801 },
    { path: "resource_limits.max_prefill_tokens", value: 0 },
    { path: "resource_limits.max_sample_tokens", value: 4097 },
    { path: "resource_limits.max_train_tokens", value: 1 },
    { path: "resource_limits.max_prefill_tokens", value: 1.5 },
    { path: "compute_workload_source_kind", value: "standalone" },
    { path: "compute_workload_execution_binding_commitment", value: word("a") },
    { path: "compute_workload_recipient_release_commitment", value: `sha256:${"0".repeat(64)}` },
    { path: "compute_workload_id", value: "wrk_invalid" },
    { path: "compute_project_id", value: `0x${"0".repeat(64)}` },
    { path: "compute_dispatch_intent_commitment", value: pin("a") },
    { path: "recipe", value: "qwen3_8b_lora_r32" },
    { path: "model", value: "unapproved_model" },
    { path: "tdx_attestation_claimed", value: true },
  ])("rejects malformed or unsupported $path = $value", ({ path, value }) => {
    const raw = statusFixture();
    replacePath(raw, path, value);
    expect(() => parseCollaborationExecutionStatus(raw)).toThrow();
  });

  it("does not alias mutable response objects", () => {
    const raw = statusFixture();
    const status = parseCollaborationExecutionStatus(raw);
    raw.resource_limits.max_sample_tokens = 2;
    raw.compute_authority.user_address = OTHER as typeof USER;
    raw.compute_workload_source_kind = "credential";
    expect(status.computeAuthorization.user).toBe(USER);
    expect(status.computeAuthorization.workload.sourceKind).toBe("wallet");
    expect(status.computeAuthorization.workload.maxSampleTokens).toBe(512);
  });
});

describe("binding API Compute terms to the retained request and plan", () => {
  it.each([
    { path: "compute_project_id", value: word("b") }, { path: "compute_job_id", value: word("b") },
    { path: "compute_workload_id", value: `wrk_${"b".repeat(32)}` },
    { path: "compute_workload_commitment", value: word("b") }, { path: "compute_manifest_commitment", value: word("b") },
    { path: "compute_rate_policy_commitment", value: word("b") },
    { path: "compute_workload_source_kind", value: "credential" },
    { path: "compute_workload_execution_binding_commitment", value: pin("b") },
    { path: "compute_workload_recipient_release_commitment", value: pin("b") },
    { path: "resource_limits.max_prefill_tokens", value: 2049 }, { path: "resource_limits.max_sample_tokens", value: 513 },
    { path: "asset", value: OTHER }, { path: "max_compute_asset_debit", value: 7001 },
    { path: "authorization_nonce", value: 12 }, { path: "authorization_expiry", value: NOW + 601 },
    { path: "release.git_sha", value: "c".repeat(40) },
    { path: "release.verification_sha256", value: pin("d") }, { path: "release.cvm_id", value: "cvm-other-runtime-0002" },
    { path: "release.compose_hash", value: word("e") }, { path: "room_id", value: `room_${"6".repeat(32)}` },
  ])("rejects valid-shaped server substitution at $path", ({ path, value }) => {
    const raw = statusFixture();
    replacePath(raw, path, value);
    const status = parseCollaborationExecutionStatus(raw);
    expect(() => assertCollaborationComputeAuthorizationMatchesPlanRequest(status, plan(), request())).toThrow("differs");
  });

  it("rejects substituting both server sponsor and Compute wallet together", () => {
    const raw = statusFixture();
    replacePath(raw, "sponsor_address", OTHER);
    replacePath(raw, "compute_authority.user_address", OTHER);
    const status = parseCollaborationExecutionStatus(raw);
    expect(() => assertCollaborationComputeAuthorizationMatchesPlanRequest(status, plan(), request())).toThrow("differs");
  });

  it.each([
    { compute_project_id: word("b") }, { compute_job_id: word("b") },
    { compute_workload_id: `wrk_${"b".repeat(32)}` }, { compute_workload_commitment: word("b") },
    { compute_manifest_commitment: word("b") }, { compute_rate_policy_commitment: word("b") },
    { compute_workload_source_kind: "credential" }, { compute_workload_execution_binding_commitment: pin("b") },
    { compute_workload_recipient_release_commitment: pin("b") }, { max_compute_asset_debit: 7001 },
    { authorization_nonce: 12 }, { max_prefill_tokens: 2049 }, { max_sample_tokens: 513 },
    { asset: OTHER }, { compute_user_address: OTHER }, { sponsor_address: OTHER },
  ])("rejects a substituted retained request %o", (change) => {
    expect(() => assertCollaborationComputeAuthorizationMatchesPlanRequest(
      parseCollaborationExecutionStatus(statusFixture()), plan(), { ...request(), ...change } as CollaborationExecutionPlanRequest,
    )).toThrow();
  });

  it.each([
    { room_id: `room_${"6".repeat(32)}` }, { release_git_sha: "c".repeat(40) },
    { release_verification_sha256: pin("d") }, { cvm_id: "cvm-other-runtime-0002" },
    { compose_hash: word("e") }, { asset: OTHER }, { sponsor_address: OTHER },
    { authorization_expiry: NOW + 601 },
  ])("rejects a substituted retained plan %o", (change) => {
    expect(() => assertCollaborationComputeAuthorizationMatchesPlanRequest(
      parseCollaborationExecutionStatus(statusFixture()), { ...plan(), ...change }, request(),
    )).toThrow();
  });

  it("checks projection execution and grant-set consistency even for constructed local DTOs", () => {
    const status = parseCollaborationExecutionStatus(statusFixture());
    for (const change of [{ executionId: `exec_${"a".repeat(64)}` }, { grantSetCommitment: pin("a") }]) {
      expect(() => assertCollaborationComputeAuthorizationMatchesPlanRequest({ ...status,
        computeAuthorization: { ...status.computeAuthorization, ...change },
      }, plan(), request())).toThrow("differs");
    }
  });

  it.each([
    { path: "compute_authorization.context_commitment", value: pin("a") },
    { path: "compute_dispatch_intent_commitment", value: word("a") },
    { path: "execution_grant_set_commitment", value: pin("a") },
  ])("does not mistake parsing $path for independently recomputed spend authority", ({ path, value }) => {
    const raw = statusFixture();
    replacePath(raw, path, value);
    const status = parseCollaborationExecutionStatus(raw);
    expect(status.clientDtoMayUnlockExecutionControls).toBe(false);
    expect(() => verifyProjectedTerms(status)).toThrow();
  });

  it("rejects a different retained basis when independently verifying the one-shot context", () => {
    expect(() => verifyProjectedTerms(parseCollaborationExecutionStatus(statusFixture()), {
      ...plan(), basis_commitment: pin("a"),
    })).toThrow("context");
  });
});
