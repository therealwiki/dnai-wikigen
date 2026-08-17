import { sha256 } from "viem";
import {
  computeVaultDeployment,
  computeWorkloadDeployment,
  deployment,
} from "../config";
import { pythonCanonicalJson } from "./policyCommitments";
import {
  configuredExecutionPolicyAnchorRelease,
  parseRollbackAnchorStatus,
  type ExecutionPolicyAnchorRelease,
  type RollbackAnchorStatus,
} from "./executionPolicyAnchor";
import { publicErrorText } from "./errorText";
import { verifyCollaborationFundingReservationProjection } from "./collaborationRoyaltyReservation";

const MAX_RESPONSE_BYTES = 256 * 1024;
const MAX_RESPONSE_CONTAINERS = 16_384;
const MAX_ROOM_MEMBERS = 16;
const MAX_ROOM_OWNERS = 16;
const MAX_ROOM_PAGE_SIZE = 16;
const MAX_CURSOR_BYTES = 1_024;
const JWT = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const BARE_HASH = /^(?!0{64}$)[0-9a-f]{64}$/;
const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const APP_ID = /^(?!0{40}$)[0-9a-f]{40}$/;
const OCI_IMAGE_DIGEST = /@sha256:(?!0{64}$)[0-9a-f]{64}$/;
const ROOM_ID = /^room_[0-9a-f]{32}$/;
const CONSENT_ID = /^consent_[0-9a-f]{32}$/;
const QUERY_GRANT_ID = /^qgrant_[0-9a-f]{32}$/;
const RUN_ID = /^run_[0-9a-f]{32}$/;
const EXECUTION_GRANT_ID = /^xgrant_[0-9a-f]{32}$/;
const EXECUTION_ID = /^exec_[0-9a-f]{64}$/;
const WORKLOAD_ID = /^wrk_[0-9a-f]{32}$/;
const GIT_SHA = /^(?!0{40}$)[0-9a-f]{40}$/;
const CVM_ID = /^[a-z0-9][a-z0-9._:-]{7,127}$/;
const BYTES32 = /^0x(?!0{64}$)[0-9a-f]{64}$/;
const EXECUTION_TOKEN = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/;
const OPAQUE_CURSOR = /^[\x21-\x7e]+$/;
const EXECUTION_POLICY_RESOURCE_DOMAIN =
  "dnai-wikigen/execution-policy-resource/v1";

export type CollaborationMembershipStatus =
  | "invited"
  | "accepted"
  | "declined"
  | "cancelled";
export type CollaborationRoleConsentStatus = "pending" | "active" | "revoked";
export type CollaborationConsentStatus = CollaborationRoleConsentStatus;
export type CollaborationConsentDecision = "activate" | "revoke";
export type CollaborationQueryGrantDecision = "approve" | "revoke";
export type CollaborationQueryGrantStatus = "pending" | "approved" | "revoked";
export type CollaborationChallengeStatus =
  | "pending"
  | "consumed"
  | "superseded"
  | "expired";

export interface CollaborationSession {
  readonly accessToken: string;
  readonly address: string;
  readonly issuedAt: number;
  readonly expiresAt: number;
  readonly walletAuthorizationVersion: number;
}

export interface CollaborationReleaseConfiguration {
  readonly collaborationEnabled: boolean;
  readonly delegateUrl: string;
  readonly releaseIdentityStatus: string;
  readonly releaseSha: string | undefined;
  readonly verificationChainReleaseSha: string | undefined;
  readonly appId: string;
  readonly cvmId: string;
  readonly composeHash: string;
  readonly osImageHash: string;
  readonly imageDigest: string;
  readonly walletAuthDomain: string;
  readonly walletAuthUri: string;
  readonly executionPolicyAnchorRelease?: ExecutionPolicyAnchorRelease;
}

export interface CollaborationMembership {
  readonly member_address: string;
  readonly membership_status: CollaborationMembershipStatus;
  readonly membership_generation: number;
  readonly decision_recorded: boolean;
}

export interface CollaborationOwner {
  readonly owner_address: string;
  readonly allocation_bps: number;
  readonly corpus_policy_commitment: string;
  readonly membership_status: CollaborationMembershipStatus;
  readonly role_consent_status: CollaborationRoleConsentStatus;
  readonly role_consent_generation: number;
  readonly role_authorization_hash_recorded: boolean;
  readonly role_accepted: boolean;
}

export interface CollaborationOwnerQueryGrant {
  readonly owner_address: string;
  readonly grant_status: CollaborationQueryGrantStatus;
  readonly grant_generation: number;
  readonly authorization_hash_recorded: boolean;
}

interface CollaborationRollbackWitnessBoundary {
  readonly schema: "dnai.collaboration-rollback-witness.v1";
  readonly opaque_commitments_only: true;
  readonly raw_room_egress: false;
  readonly raw_member_egress: false;
  readonly raw_query_egress: false;
}

export interface CollaborationLocalRollbackWitness
  extends CollaborationRollbackWitnessBoundary {
  readonly mode: "local_hmac_current_state_non_monotonic";
  readonly monotonic: false;
  readonly authority_context_hash: null;
  readonly state_hash: null;
  readonly decision_hash: null;
  readonly anchor_sequence: null;
  readonly rollback_anchor: null;
}

export interface CollaborationReleaseBoundRollbackWitness
  extends CollaborationRollbackWitnessBoundary {
  readonly mode: "base_sepolia_execution_policy_anchor";
  readonly monotonic: true;
  readonly authority_context_hash: string;
  readonly state_hash: string;
  readonly decision_hash: string;
  readonly anchor_sequence: number;
  readonly rollback_anchor: RollbackAnchorStatus;
}

export type CollaborationRollbackWitness =
  | CollaborationLocalRollbackWitness
  | CollaborationReleaseBoundRollbackWitness;

export interface CollaborationRollbackProjection {
  readonly rollback_protection: boolean;
  readonly rollback_witness: CollaborationRollbackWitness;
  readonly tamper_evident_current_state: true;
}

export interface CollaborationQueryProposal
  extends CollaborationRollbackProjection {
  readonly surface: "collaboration_query_proposal";
  readonly schema_version: 2;
  readonly room_id: string;
  readonly query_ref: string;
  readonly proposer_address: string;
  readonly room_commitment: string;
  readonly room_generation: number;
  readonly proposal_commitment: string;
  readonly allocation_commitment: string;
  readonly proposed_at: number;
  readonly proposal_current: boolean;
  readonly owner_query_grants: readonly CollaborationOwnerQueryGrant[];
  readonly all_required_query_grants_current: boolean;
  readonly raw_query_egress: false;
  readonly raw_policy_egress: false;
  readonly raw_signature_egress: false;
}

export interface CollaborationRoom extends CollaborationRollbackProjection {
  readonly surface: "collaboration_room";
  readonly schema_version: 2;
  readonly room_id: string;
  readonly creator_address: string;
  readonly declared_member_addresses: readonly string[];
  readonly accepted_member_addresses: readonly string[];
  readonly pending_invitation_addresses: readonly string[];
  readonly declined_member_addresses: readonly string[];
  readonly cancelled_invitation_addresses: readonly string[];
  readonly memberships: readonly CollaborationMembership[];
  readonly requester_membership_status: "accepted" | "invited";
  readonly purpose_commitment: string;
  readonly pipeline_commitment: string;
  readonly room_commitment: string;
  readonly generation: number;
  readonly created_at: number;
  readonly updated_at: number;
  readonly lifecycle_status: "active" | "archived";
  readonly archived_at: number;
  readonly reclaimable_after: number;
  readonly room_retention_policy:
    | "active_not_pruned"
    | "explicit_archive_then_bounded_reclamation";
  readonly owners: readonly CollaborationOwner[];
  readonly all_required_memberships_accepted: boolean;
  readonly all_required_roles_active: boolean;
  readonly current_query: CollaborationQueryProposal | null;
  readonly all_required_query_grants_current: boolean;
  readonly membership_acceptance_mechanism:
    "wallet_authenticated_invitation_response";
  readonly role_acceptance_mechanism: "owner_role_consent_signature";
  readonly query_grant_mechanism:
    "owner_signature_bound_to_current_query_v2";
  readonly participant_authenticated_projection: true;
  readonly raw_purpose_egress: false;
  readonly raw_policy_egress: false;
  readonly raw_signature_egress: false;
  readonly raw_artifact_egress: false;
}

export interface CollaborationRoomList extends CollaborationRollbackProjection {
  readonly surface: "collaboration_rooms";
  readonly schema_version: 2;
  readonly rooms: readonly CollaborationRoom[];
  readonly room_count: number;
  readonly has_more: boolean;
  readonly next_cursor: string | null;
  readonly page_limit: number;
  readonly maximum_page_size: 16;
  readonly maximum_accepted_rooms_per_participant: 64;
  readonly maximum_pending_invitations_per_target: 32;
  readonly snapshot_bound_pagination: true;
  readonly participant_authenticated_projection: true;
  readonly raw_purpose_egress: false;
  readonly raw_policy_egress: false;
  readonly raw_signature_egress: false;
}

export interface CollaborationInvitationResult
  extends CollaborationRollbackProjection {
  readonly surface: "collaboration_invitation_result";
  readonly schema_version: 2;
  readonly room_id: string;
  readonly member_address: string;
  readonly membership_status: "accepted" | "declined" | "cancelled";
  readonly membership_generation: 1;
  readonly decision_recorded: true;
  readonly visible_after_response: boolean;
  readonly ordinary_participant_authority: boolean;
  readonly room_generation: number;
  readonly room_state_commitment: string;
  readonly raw_purpose_egress: false;
  readonly raw_policy_egress: false;
  readonly raw_signature_egress: false;
}

export interface CollaborationConsentChallenge
  extends CollaborationRollbackProjection {
  readonly surface: "collaboration_role_consent_challenge";
  readonly schema_version: 2;
  readonly challenge_id: string;
  readonly room_id: string;
  readonly owner_address: string;
  readonly decision: CollaborationConsentDecision;
  readonly room_commitment: string;
  readonly room_generation: number;
  readonly room_state_commitment: string;
  readonly challenge_commitment: string;
  readonly message: string;
  readonly issued_at: number;
  readonly expires_at: number;
  readonly status: CollaborationChallengeStatus;
  readonly authorization_hash_recorded: boolean;
  readonly reclaimable_after: number;
  readonly retention_policy: "bounded_reclaimable_after_terminal_or_expiry";
  readonly participant_authenticated_projection: true;
  readonly raw_signature_egress: false;
}

export interface CollaborationQueryGrantChallenge
  extends CollaborationRollbackProjection {
  readonly surface: "collaboration_query_grant_challenge";
  readonly schema_version: 2;
  readonly challenge_id: string;
  readonly room_id: string;
  readonly owner_address: string;
  readonly decision: CollaborationQueryGrantDecision;
  readonly room_commitment: string;
  readonly room_generation: number;
  readonly query_ref: string;
  readonly proposal_commitment: string;
  readonly allocation_commitment: string;
  readonly owner_policy_commitment: string;
  readonly challenge_commitment: string;
  readonly message: string;
  readonly issued_at: number;
  readonly expires_at: number;
  readonly status: CollaborationChallengeStatus;
  readonly authorization_hash_recorded: boolean;
  readonly reclaimable_after: number;
  readonly retention_policy: "bounded_reclaimable_after_terminal_or_expiry";
  readonly participant_authenticated_projection: true;
  readonly raw_signature_egress: false;
}

export interface CollaborationJointRun
  extends CollaborationRollbackProjection {
  readonly surface: "collaboration_joint_consent_snapshot";
  readonly schema_version: 2;
  readonly run_id: string;
  readonly room_id: string;
  readonly query_ref: string;
  readonly requester_address: string;
  readonly room_commitment: string;
  readonly room_generation: number;
  readonly room_state_commitment: string;
  readonly query_proposal_commitment: string;
  readonly query_grant_set_commitment: string;
  readonly allocation_commitment: string;
  readonly joint_consent_snapshot_commitment: string;
  readonly recorded_at: number;
  readonly execution_status: "joint_consent_snapshot_not_dispatched";
  readonly consent_snapshot_current: boolean;
  readonly query_grants_current: boolean;
  readonly execution_authority: false;
  readonly provider_dispatch_performed: false;
  readonly tdx_attestation: false;
  readonly settlement_performed: false;
  readonly royalty_distribution_performed: false;
  readonly reclaimable_after: number;
  readonly retention_policy: "bounded_non_dispatched_snapshot_retention";
  readonly raw_purpose_egress: false;
  readonly raw_policy_egress: false;
  readonly raw_signature_egress: false;
  readonly raw_artifact_egress: false;
}

export type CollaborationExecutionState =
  | "authorized"
  | "queued"
  | "claimed"
  | "compute_handoff_pending"
  | "compute_handoff_confirmed"
  | "bounded_result_ready"
  | "failed"
  | "reconciliation_hold"
  | "authority_invalidated";

export interface CollaborationExecutionPlanRequest {
  readonly compute_project_id: string;
  readonly compute_job_id: string;
  readonly compute_workload_id: string;
  readonly compute_workload_commitment: string;
  readonly compute_manifest_commitment: string;
  readonly compute_rate_policy_commitment: string;
  readonly compute_workload_schema:
    | "dnai.compute.workload.inference.v1"
    | "dnai.compute.workload.sft-jsonl.v1";
  readonly compute_workload_source_kind: "wallet" | "credential";
  readonly compute_workload_execution_binding_commitment: string;
  readonly compute_workload_recipient_release_commitment: string;
  readonly compute_user_address: string;
  readonly operation: "inference" | "training";
  readonly model: "qwen3_8b";
  readonly recipe: "qwen3_8b_bounded" | "qwen3_8b_lora_r32";
  readonly result_policy: "bounded_summary_receipt" | "score_band_hash";
  readonly max_prefill_tokens: number;
  readonly max_sample_tokens: number;
  readonly max_train_tokens: number;
  readonly sponsor_address: string;
  readonly asset: string;
  readonly max_total_asset_debit: number;
  readonly max_compute_asset_debit: number;
  readonly authorization_nonce: number;
  readonly authorization_lifetime_seconds: number;
  readonly royalty_total: number;
}

export interface CollaborationExecutionPlanProjection {
  readonly surface: "collaboration_execution_plan";
  readonly schema_version: 2;
  readonly run_id: string;
  readonly room_id: string;
  readonly requester_address: string;
  readonly release_git_sha: string;
  readonly release_verification_sha256: string;
  readonly chain_id: 84_532;
  readonly cvm_id: string;
  readonly compose_hash: string;
  readonly compute_workload_source_kind: "wallet" | "credential";
  readonly sponsor_address: string;
  readonly asset: string;
  readonly room_commitment: string;
  readonly room_generation: number;
  readonly room_state_commitment: string;
  readonly query_ref: string;
  readonly query_proposal_commitment: string;
  readonly prospective_query_grant_set_commitment: string;
  readonly joint_consent_snapshot_commitment: string;
  readonly allocation_commitment: string;
  readonly authorization_expiry: number;
  readonly royalty_total: string;
  readonly basis_commitment: string;
  readonly owner_addresses: readonly string[];
  readonly royalty_owner_amounts_hash: string;
  readonly royalty_distributor_address: string;
  readonly royalty_release_policy_commitment: string;
  readonly royalty_release_binding_commitment: string;
  readonly royalty_settlement_id: string;
  readonly royalty_settlement_nonce: string;
  readonly royalty_reservation_safety_seconds: number;
  readonly royalty_authority_server_derived: true;
  readonly royalty_reservation_is_derived_after_fresh_owner_grants: true;
  readonly royalty_reservation_must_be_deposited_onchain_after_authorization: true;
  readonly plan_token: string;
  readonly plan_token_contains_bounded_metadata_only: true;
  readonly requires_fresh_execution_grant_from_every_owner: true;
  readonly query_grants_are_not_execution_grants: true;
  readonly provider_dispatch_performed: false;
  readonly raw_signature_retained: false;
  readonly raw_query_egress: false;
  readonly raw_artifact_egress: false;
  readonly clientProjectionIsExecutionEvidence: false;
}

export interface CollaborationExecutionFundingReservationRequestProjection {
  readonly settlement_id: string;
  readonly settlement_nonce: string;
  readonly release_policy_commitment: string;
  readonly room_commitment: string;
  readonly room_state_commitment: string;
  readonly query_commitment: string;
  readonly grant_set_commitment: string;
  readonly allocation_commitment: string;
  readonly owners_amounts_hash: string;
  readonly asset: string;
  readonly total: string;
  readonly execution_commitment: string;
  readonly refund_after: string;
}

export interface CollaborationExecutionFundingReservationReadyTransactionProjection {
  readonly to: string;
  readonly function_name: "reserveNative" | "reserveERC20";
  readonly abi_signature: string;
  readonly calldata: string;
  readonly value: string;
  readonly erc20_approval_required: boolean;
  readonly erc20_approval: null | {
    readonly token_address: string;
    readonly spender: string;
    readonly minimum_amount: string;
  };
}

export interface CollaborationExecutionFundingReservationGatedTransactionProjection {
  readonly schema: "dnai.collaboration.royalty-funding-action-gated.v1";
  readonly status: "gated_worker_presence_required";
  readonly reason:
    "fresh_authenticated_worker_and_qvl_capability_required";
  readonly executable: false;
  readonly wallet_transaction_included: false;
  readonly erc20_approval_included: false;
}

export type CollaborationExecutionFundingReservationTransactionProjection =
  | CollaborationExecutionFundingReservationReadyTransactionProjection
  | CollaborationExecutionFundingReservationGatedTransactionProjection;

export interface CollaborationExecutionRoyaltyReservationProjection {
  readonly schema: "dnai.collaboration.royalty-funding-reservation.v1";
  readonly chain_id: 84_532;
  readonly distributor_address: string;
  readonly sponsor_address: string;
  readonly reservation_id: string;
  readonly request: CollaborationExecutionFundingReservationRequestProjection;
  readonly transaction: CollaborationExecutionFundingReservationTransactionProjection;
  readonly derived_after_fresh_owner_grants: true;
  readonly client_supplied_reservation_id: false;
  readonly balance_or_allowance_is_not_authorization: true;
  readonly walletActionReady: boolean;
  readonly finalizedReservationObservedInBrowser: false;
  readonly mayUnlockExecutionControls: false;
}

export interface CollaborationExecutionGrantChallenge {
  readonly surface: "collaboration_execution_grant_challenge";
  readonly schema_version: 2;
  readonly grant_id: string;
  readonly owner_address: string;
  readonly basis_commitment: string;
  readonly royalty_settlement_nonce: string;
  readonly message: string;
  readonly challenge_token: string;
  readonly issued_at: number;
  readonly expires_at: number;
  readonly scope: "one_shot_execution";
  readonly query_grants_are_not_execution_grants: true;
  readonly raw_signature_retained: false;
}

export interface CollaborationExecutionGrantSubmission {
  readonly challenge_token: string;
  readonly signature: string;
}

export interface CollaborationExecutionStatusProjection {
  readonly surface: "collaboration_one_shot_execution";
  readonly schema_version: 1;
  readonly execution_id: string;
  readonly room_id: string;
  readonly state: CollaborationExecutionState;
  readonly intent_commitment: string;
  readonly authorization_commitment: string;
  readonly execution_grant_set_commitment: string;
  readonly owner_execution_grant_count: number;
  readonly provider_dispatch_may_have_occurred: boolean | null;
  readonly reconciliation_hold: boolean;
  readonly authority_invalidated_before_claim: boolean;
  readonly bounded_result_present: boolean;
  readonly royalty_reservation: CollaborationExecutionRoyaltyReservationProjection;
  readonly royaltyReservationFinalizationProven: boolean;
  readonly participantAuthenticatedApiProjection: true;
  readonly apiWorkerWiringAvailable: boolean;
  readonly apiWorkerWiringClaimed: false;
  readonly freshWorkerPresenceProven: false;
  readonly apiReportsAuthenticatedLocalJournal: boolean;
  readonly independentJournalSourceAuthenticated: false;
  readonly finalizedVaultFreshnessProvenInBrowser: false;
  readonly tdxAttestationVerifiedInBrowser: false;
  readonly qvlVerifiedInBrowser: false;
  readonly settlementFinalizedInBrowser: false;
  readonly royaltyDistributionObservedInBrowser: false;
  readonly clientDtoMayUnlockExecutionControls: false;
}

export interface CollaborationExecutionWorkerReleaseBinding {
  readonly release_git_sha: string;
  readonly release_verification_sha256: string;
  readonly deployment_intent_sha256: string;
  readonly release_authority_sha256: string;
  readonly ceremony_nonce: string;
  readonly main_runtime_cvm_id: string;
  readonly main_runtime_compose_hash: string;
  readonly main_runtime_app_id: string;
  readonly main_runtime_os_image_hash: string;
  readonly royalty_release_binding_commitment: string;
  readonly royalty_distributor_address: string;
  readonly compute_vault_address: string;
  readonly compute_vault_runtime_code_hash: string;
  readonly chain_id: 84_532;
  readonly worker_service: "collaboration-execution-worker";
  readonly worker_profile: "collaboration-execution";
}

export interface CollaborationExecutionWorkerCapability {
  readonly surface: "collaboration_execution_worker_capability";
  readonly schema: "dnai.collaboration.execution-worker-capability.v1";
  readonly status: "live" | "unavailable";
  readonly gate_reason: string;
  readonly execution_enabled: boolean;
  readonly queue_control_plane_available: boolean;
  readonly queued_work_executable: boolean;
  readonly onchain_reservation_ready: boolean;
  readonly worker_connected: boolean;
  readonly freshness: "fresh" | "unavailable";
  readonly evidence_authenticity: "hmac_verified" | "unverified";
  readonly evidence_classification:
    "authenticated_worker_presence_not_job_attestation";
  readonly heartbeat_observed_at: number | null;
  readonly presence_binding_sha256: string | null;
  readonly release_binding_sha256: string | null;
  readonly release_binding: CollaborationExecutionWorkerReleaseBinding | null;
  readonly qvl_capability: {
    readonly configuration: "complete" | "unavailable";
    readonly reachability: "authenticated_exact_capability" | "unavailable";
    readonly observation_sha256: string | null;
    readonly observed_at: number | null;
    readonly expires_at: number | null;
    readonly profile: "royalty_settlement" | null;
    readonly royalty_authorization_schema:
      "dnai.royalty-settlement-qvl-authorization-request.v2" | null;
    readonly per_job_qvl_required: true;
    readonly per_job_qvl_verified: false;
  };
  readonly real_dstack: boolean;
  readonly simulator: false;
  readonly tdx_job_attestation_proven: false;
  readonly qvl_job_verdict_proven: false;
  readonly warning: string;
  /** Browser parsing authenticates shape and bindings, not a job attestation. */
  readonly clientProjectionIsJobAttestation: false;
}

export type CollaborationExecutionApiResourceKind =
  | "execution_plan"
  | "execution_authorization"
  | "execution_status";

export interface CollaborationExecutionQueueControlProjection {
  readonly queue_control_plane_available: boolean;
  readonly queued_not_executable: boolean;
  readonly onchain_reservation_ready: boolean;
  readonly fresh_worker_presence_proven: boolean;
  readonly api_worker_wiring_claimed: boolean;
  readonly clientProjectionIsJobAttestation: false;
}

export interface CollaborationExecutionApiEnvelope<T> {
  readonly surface: "collaboration_execution_api_envelope";
  readonly schema_version: 1;
  readonly resource_kind: CollaborationExecutionApiResourceKind;
  readonly payload: T;
  readonly worker_capability: CollaborationExecutionWorkerCapability;
  readonly queue_control: CollaborationExecutionQueueControlProjection;
}

export interface CollaborationExecutionAuthorizationResult {
  readonly surface: "collaboration_execution_authorization_result";
  readonly schema_version: 2;
  readonly created: boolean;
  readonly idempotent_replay: boolean;
  readonly verifier_kinds: readonly ("eoa" | "eip1271")[];
  readonly raw_signatures_retained: false;
  readonly query_grants_reused_as_execution_grants: false;
  readonly provider_dispatch_performed: false;
  readonly authorization_commitment: string;
  readonly royalty_reservation: CollaborationExecutionRoyaltyReservationProjection;
  readonly royaltyReservationFinalizedInBrowser: false;
  readonly royaltyReservationMayUnlockExecutionControls: false;
  readonly execution: CollaborationExecutionStatusProjection;
}

export interface CreateCollaborationRoomRequest {
  readonly room_id: string;
  readonly idempotency_key: string;
  readonly member_addresses: readonly string[];
  readonly purpose_commitment: string;
  readonly pipeline_commitment: string;
  readonly corpus_policy_commitments: Readonly<Record<string, string>>;
  readonly owner_allocations_bps: Readonly<Record<string, number>>;
}

export interface CollaborationRoomPageOptions {
  readonly limit?: number;
  readonly cursor?: string;
  readonly signal?: AbortSignal;
}

interface RequestOptions {
  readonly method?: "GET" | "POST";
  readonly token: string;
  readonly body?: Readonly<Record<string, unknown>>;
  readonly signal?: AbortSignal;
}

export class CollaborationRequestError extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "CollaborationRequestError";
    this.status = status;
  }

  get restartRequired(): boolean {
    return this.status === 409;
  }
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function exactKeys(
  value: Record<string, unknown>,
  keys: readonly string[],
  label: string,
): void {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])
  ) throw new Error(`${label} has an unexpected schema`);
}

function integer(
  value: unknown,
  label: string,
  minimum = 0,
  maximum = 4_102_444_800,
): number {
  if (
    typeof value !== "number"
    || !Number.isSafeInteger(value)
    || value < minimum
    || value > maximum
  ) throw new Error(`${label} is invalid`);
  return value;
}

function patterned(
  value: unknown,
  pattern: RegExp,
  label: string,
  maximum = 256,
): string {
  if (
    typeof value !== "string"
    || value.length > maximum
    || !pattern.test(value)
  ) throw new Error(`${label} is invalid`);
  return value;
}

function literal<T extends string | number | boolean | null>(
  value: unknown,
  expected: T,
  label: string,
): T {
  if (value !== expected) throw new Error(`${label} is invalid`);
  return expected;
}

function address(value: unknown, label: string): string {
  return patterned(value, ADDRESS, label, 42);
}

function commitment(value: unknown, label: string): string {
  return patterned(value, SHA256, label, 71);
}

function bool(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") throw new Error(`${label} is invalid`);
  return value;
}

function canonicalUintString(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^[1-9][0-9]*$/.test(value)) {
    throw new Error(`${label} is invalid`);
  }
  const parsed = BigInt(value);
  if (parsed > (1n << 256n) - 1n) throw new Error(`${label} is invalid`);
  return value;
}

function collaborationExecutionPolicyResourceHash(
  authorityContextHash: string,
): string {
  const encoder = new TextEncoder();
  const domain = encoder.encode(EXECUTION_POLICY_RESOURCE_DOMAIN);
  const surface = encoder.encode("collaboration_state");
  const resource = encoder.encode(authorityContextHash);
  const payload = new Uint8Array(
    domain.byteLength + surface.byteLength + resource.byteLength + 2,
  );
  let offset = 0;
  payload.set(domain, offset);
  offset += domain.byteLength + 1;
  payload.set(surface, offset);
  offset += surface.byteLength + 1;
  payload.set(resource, offset);
  return sha256(payload).slice(2);
}

function canonicalAddresses(
  value: unknown,
  label: string,
  maximum = MAX_ROOM_MEMBERS,
): readonly string[] {
  if (!Array.isArray(value) || value.length > maximum) {
    throw new Error(`${label} is invalid`);
  }
  const parsed = value.map((item) => address(item, label));
  if (
    new Set(parsed).size !== parsed.length
    || parsed.some((item, index) => index > 0 && parsed[index - 1] >= item)
  ) throw new Error(`${label} is not canonical`);
  return Object.freeze(parsed);
}

function opaqueCursor(value: unknown): string {
  if (
    typeof value !== "string"
    || value.length === 0
    || new TextEncoder().encode(value).length > MAX_CURSOR_BYTES
    || !OPAQUE_CURSOR.test(value)
  ) throw new Error("Collaboration room cursor is invalid");
  return value;
}

function assertNoSensitiveFields(value: unknown): void {
  const forbidden = new Set([
    "artifact",
    "artifact_content",
    "card_number",
    "corpus",
    "corpus_content",
    "cvv",
    "private_key",
    "purpose",
    "purpose_text",
    "raw_artifact",
    "raw_policy",
    "signature",
    "wallet_signature",
  ]);
  const pending: unknown[] = [value];
  let containers = 0;
  while (pending.length > 0) {
    const current = pending.pop();
    if (!current || typeof current !== "object") continue;
    containers += 1;
    if (containers > MAX_RESPONSE_CONTAINERS) {
      throw new Error("Collaboration response is too deeply nested");
    }
    if (Array.isArray(current)) {
      pending.push(...current);
      continue;
    }
    for (const [key, nested] of Object.entries(
      current as Record<string, unknown>,
    )) {
      if (forbidden.has(key)) {
        throw new Error(`Collaboration response contains forbidden field ${key}`);
      }
      pending.push(nested);
    }
  }
}

export function parseCollaborationRollbackWitness(
  value: unknown,
  releaseValue: ExecutionPolicyAnchorRelease | undefined =
    deployment.executionPolicyAnchorRelease,
  label = "Collaboration rollback witness",
): CollaborationRollbackWitness {
  const witness = record(value, label);
  exactKeys(witness, [
    "schema",
    "mode",
    "monotonic",
    "authority_context_hash",
    "state_hash",
    "decision_hash",
    "anchor_sequence",
    "rollback_anchor",
    "opaque_commitments_only",
    "raw_room_egress",
    "raw_member_egress",
    "raw_query_egress",
  ], label);
  literal(
    witness.schema,
    "dnai.collaboration-rollback-witness.v1",
    `${label} schema`,
  );
  literal(
    witness.opaque_commitments_only,
    true,
    `${label} commitment boundary`,
  );
  literal(witness.raw_room_egress, false, `${label} room egress`);
  literal(witness.raw_member_egress, false, `${label} member egress`);
  literal(witness.raw_query_egress, false, `${label} query egress`);

  if (witness.mode === "local_hmac_current_state_non_monotonic") {
    literal(witness.monotonic, false, `${label} monotonic marker`);
    literal(
      witness.authority_context_hash,
      null,
      `${label} authority context`,
    );
    literal(witness.state_hash, null, `${label} state commitment`);
    literal(witness.decision_hash, null, `${label} decision commitment`);
    literal(witness.anchor_sequence, null, `${label} anchor sequence`);
    literal(witness.rollback_anchor, null, `${label} rollback anchor`);
    return Object.freeze({
      schema: "dnai.collaboration-rollback-witness.v1",
      mode: "local_hmac_current_state_non_monotonic",
      monotonic: false,
      authority_context_hash: null,
      state_hash: null,
      decision_hash: null,
      anchor_sequence: null,
      rollback_anchor: null,
      opaque_commitments_only: true,
      raw_room_egress: false,
      raw_member_egress: false,
      raw_query_egress: false,
    });
  }

  literal(
    witness.mode,
    "base_sepolia_execution_policy_anchor",
    `${label} mode`,
  );
  literal(witness.monotonic, true, `${label} monotonic marker`);
  const authorityContextHash = patterned(
    witness.authority_context_hash,
    BARE_HASH,
    `${label} authority context`,
    64,
  );
  const stateHash = patterned(
    witness.state_hash,
    BARE_HASH,
    `${label} state commitment`,
    64,
  );
  const decisionHash = patterned(
    witness.decision_hash,
    BARE_HASH,
    `${label} decision commitment`,
    64,
  );
  const anchorSequence = integer(
    witness.anchor_sequence,
    `${label} anchor sequence`,
    1,
    Number.MAX_SAFE_INTEGER,
  );
  const rollbackAnchor = Object.freeze(
    parseRollbackAnchorStatus(witness.rollback_anchor),
  );
  if (!releaseValue) {
    throw new Error(
      `${label} cannot be promoted without a release-pinned anchor`,
    );
  }
  const release = configuredExecutionPolicyAnchorRelease(releaseValue);
  if (
    rollbackAnchor.contract_address !== release.address
    || rollbackAnchor.runtime_code_hash !== release.runtimeCodeHash
    || rollbackAnchor.writer !== release.writer
    || rollbackAnchor.writer_release_commitment
      !== release.writerReleaseCommitment
    || rollbackAnchor.minimum_confirmation_depth !== release.confirmations
  ) {
    throw new Error(`${label} does not match the frontend release`);
  }
  if (
    rollbackAnchor.resource_id_hash
      !== collaborationExecutionPolicyResourceHash(authorityContextHash)
    || rollbackAnchor.decision_hash !== decisionHash
    || rollbackAnchor.resource_decision_head !== `0x${decisionHash}`
    || rollbackAnchor.resource_sequence !== anchorSequence
    || rollbackAnchor.decision_sequence !== anchorSequence
    || rollbackAnchor.global_sequence < anchorSequence
  ) {
    throw new Error(`${label} anchor bindings are inconsistent`);
  }
  return Object.freeze({
    schema: "dnai.collaboration-rollback-witness.v1",
    mode: "base_sepolia_execution_policy_anchor",
    monotonic: true,
    authority_context_hash: authorityContextHash,
    state_hash: stateHash,
    decision_hash: decisionHash,
    anchor_sequence: anchorSequence,
    rollback_anchor: rollbackAnchor,
    opaque_commitments_only: true,
    raw_room_egress: false,
    raw_member_egress: false,
    raw_query_egress: false,
  });
}

function assertCurrentStateBoundary(
  value: Record<string, unknown>,
  label: string,
): CollaborationRollbackProjection {
  const rollbackProtection = bool(
    value.rollback_protection,
    `${label} rollback boundary`,
  );
  const rollbackWitness = parseCollaborationRollbackWitness(
    value.rollback_witness,
    deployment.executionPolicyAnchorRelease,
    `${label} rollback witness`,
  );
  const releaseBound = rollbackWitness.mode
    === "base_sepolia_execution_policy_anchor";
  if (rollbackProtection !== releaseBound) {
    throw new Error(`${label} rollback marker contradicts its witness`);
  }
  literal(
    value.tamper_evident_current_state,
    true,
    `${label} current-state integrity`,
  );
  return Object.freeze({
    rollback_protection: releaseBound,
    rollback_witness: rollbackWitness,
    tamper_evident_current_state: true,
  });
}

export function collaborationRollbackProtectionVerified(
  value: CollaborationRollbackProjection,
): value is CollaborationRollbackProjection & {
  readonly rollback_protection: true;
  readonly rollback_witness: CollaborationReleaseBoundRollbackWitness;
} {
  if (value.rollback_protection !== true) return false;
  try {
    const verified = parseCollaborationRollbackWitness(
      value.rollback_witness,
      deployment.executionPolicyAnchorRelease,
    );
    return verified.mode === "base_sepolia_execution_policy_anchor"
      && JSON.stringify(verified) === JSON.stringify(value.rollback_witness);
  } catch {
    return false;
  }
}

function assertSameRollbackWitness(
  parent: CollaborationRollbackProjection,
  child: CollaborationRollbackProjection,
  label: string,
): void {
  if (
    parent.rollback_protection !== child.rollback_protection
    || parent.tamper_evident_current_state
      !== child.tamper_evident_current_state
    || JSON.stringify(parent.rollback_witness)
      !== JSON.stringify(child.rollback_witness)
  ) {
    throw new Error(`${label} carries a conflicting rollback witness`);
  }
}

function parseMembership(value: unknown): CollaborationMembership {
  const membership = record(value, "Collaboration membership");
  exactKeys(membership, [
    "member_address",
    "membership_status",
    "membership_generation",
    "decision_recorded",
  ], "Collaboration membership");
  const status = String(membership.membership_status);
  if (!["invited", "accepted", "declined", "cancelled"].includes(status)) {
    throw new Error("Collaboration membership status is invalid");
  }
  const generation = integer(
    membership.membership_generation,
    "Collaboration membership generation",
    0,
    1,
  );
  const decided = bool(
    membership.decision_recorded,
    "Collaboration membership decision marker",
  );
  if (
    (status === "invited" && (generation !== 0 || decided))
    || (status !== "invited" && (generation !== 1 || !decided))
  ) throw new Error("Collaboration membership state is inconsistent");
  return Object.freeze({
    member_address: address(
      membership.member_address,
      "Collaboration member address",
    ),
    membership_status: status as CollaborationMembershipStatus,
    membership_generation: generation,
    decision_recorded: decided,
  });
}

function parseOwner(value: unknown): CollaborationOwner {
  const owner = record(value, "Collaboration owner");
  exactKeys(owner, [
    "owner_address",
    "allocation_bps",
    "corpus_policy_commitment",
    "membership_status",
    "role_consent_status",
    "role_consent_generation",
    "role_authorization_hash_recorded",
    "role_accepted",
  ], "Collaboration owner");
  const membershipStatus = String(owner.membership_status);
  if (!["invited", "accepted", "declined", "cancelled"].includes(
    membershipStatus,
  )) throw new Error("Collaboration owner membership status is invalid");
  const roleStatus = String(owner.role_consent_status);
  if (!["pending", "active", "revoked"].includes(roleStatus)) {
    throw new Error("Collaboration owner role status is invalid");
  }
  const generation = integer(
    owner.role_consent_generation,
    "Collaboration owner role generation",
    0,
    Number.MAX_SAFE_INTEGER,
  );
  const recorded = bool(
    owner.role_authorization_hash_recorded,
    "Collaboration owner authorization marker",
  );
  const accepted = bool(
    owner.role_accepted,
    "Collaboration owner role marker",
  );
  if (
    accepted !== (
      membershipStatus === "accepted"
      && roleStatus === "active"
      && generation > 0
      && recorded
    )
    || (generation === 0 && (roleStatus !== "pending" || recorded))
    || (generation > 0 && !recorded)
  ) throw new Error("Collaboration owner authority state is inconsistent");
  return Object.freeze({
    owner_address: address(owner.owner_address, "Collaboration owner address"),
    allocation_bps: integer(
      owner.allocation_bps,
      "Collaboration allocation",
      1,
      10_000,
    ),
    corpus_policy_commitment: commitment(
      owner.corpus_policy_commitment,
      "Collaboration policy commitment",
    ),
    membership_status: membershipStatus as CollaborationMembershipStatus,
    role_consent_status: roleStatus as CollaborationRoleConsentStatus,
    role_consent_generation: generation,
    role_authorization_hash_recorded: recorded,
    role_accepted: accepted,
  });
}

function parseOwnerQueryGrant(value: unknown): CollaborationOwnerQueryGrant {
  const grant = record(value, "Collaboration query grant");
  exactKeys(grant, [
    "owner_address",
    "grant_status",
    "grant_generation",
    "authorization_hash_recorded",
  ], "Collaboration query grant");
  const status = String(grant.grant_status);
  if (!["pending", "approved", "revoked"].includes(status)) {
    throw new Error("Collaboration query-grant status is invalid");
  }
  const generation = integer(
    grant.grant_generation,
    "Collaboration query-grant generation",
    0,
    Number.MAX_SAFE_INTEGER,
  );
  const recorded = bool(
    grant.authorization_hash_recorded,
    "Collaboration query-grant authorization marker",
  );
  if (
    (generation === 0 && (status !== "pending" || recorded))
    || (generation > 0 && !recorded)
  ) throw new Error("Collaboration query-grant state is inconsistent");
  return Object.freeze({
    owner_address: address(
      grant.owner_address,
      "Collaboration query-grant owner",
    ),
    grant_status: status as CollaborationQueryGrantStatus,
    grant_generation: generation,
    authorization_hash_recorded: recorded,
  });
}

export function parseCollaborationQueryProposal(
  value: unknown,
): CollaborationQueryProposal {
  assertNoSensitiveFields(value);
  const query = record(value, "Collaboration query proposal");
  exactKeys(query, [
    "surface",
    "schema_version",
    "room_id",
    "query_ref",
    "proposer_address",
    "room_commitment",
    "room_generation",
    "proposal_commitment",
    "allocation_commitment",
    "proposed_at",
    "proposal_current",
    "owner_query_grants",
    "all_required_query_grants_current",
    "raw_query_egress",
    "raw_policy_egress",
    "raw_signature_egress",
    "rollback_protection",
    "rollback_witness",
    "tamper_evident_current_state",
  ], "Collaboration query proposal");
  literal(
    query.surface,
    "collaboration_query_proposal",
    "Collaboration query surface",
  );
  literal(query.schema_version, 2, "Collaboration query schema");
  literal(query.raw_query_egress, false, "Collaboration query egress");
  literal(query.raw_policy_egress, false, "Collaboration policy egress");
  literal(query.raw_signature_egress, false, "Collaboration signature egress");
  const rollbackBoundary = assertCurrentStateBoundary(
    query,
    "Collaboration query proposal",
  );
  if (
    !Array.isArray(query.owner_query_grants)
    || query.owner_query_grants.length < 1
    || query.owner_query_grants.length > MAX_ROOM_OWNERS
  ) throw new Error("Collaboration query grants are invalid");
  const grants = query.owner_query_grants.map(parseOwnerQueryGrant);
  if (
    new Set(grants.map((grant) => grant.owner_address)).size !== grants.length
    || grants.some((grant, index) => (
      index > 0 && grants[index - 1].owner_address >= grant.owner_address
    ))
  ) throw new Error("Collaboration query grants are not canonical");
  const allRequired = grants.every((grant) => (
    grant.grant_status === "approved"
    && grant.grant_generation > 0
    && grant.authorization_hash_recorded
  ));
  const current = bool(
    query.proposal_current,
    "Collaboration query current marker",
  );
  if (
    query.all_required_query_grants_current
      !== (current && allRequired)
  ) throw new Error("Collaboration query grant summary is inconsistent");
  return Object.freeze({
    surface: "collaboration_query_proposal",
    schema_version: 2,
    room_id: patterned(query.room_id, ROOM_ID, "Collaboration room ID", 37),
    query_ref: commitment(query.query_ref, "Collaboration query commitment"),
    proposer_address: address(
      query.proposer_address,
      "Collaboration query proposer",
    ),
    room_commitment: commitment(
      query.room_commitment,
      "Collaboration room commitment",
    ),
    room_generation: integer(
      query.room_generation,
      "Collaboration query room generation",
      1,
      Number.MAX_SAFE_INTEGER,
    ),
    proposal_commitment: commitment(
      query.proposal_commitment,
      "Collaboration query proposal commitment",
    ),
    allocation_commitment: commitment(
      query.allocation_commitment,
      "Collaboration query allocation commitment",
    ),
    proposed_at: integer(
      query.proposed_at,
      "Collaboration query proposal time",
    ),
    proposal_current: current,
    owner_query_grants: Object.freeze(grants),
    all_required_query_grants_current: current && allRequired,
    raw_query_egress: false,
    raw_policy_egress: false,
    raw_signature_egress: false,
    ...rollbackBoundary,
  });
}

export function parseCollaborationRoom(value: unknown): CollaborationRoom {
  assertNoSensitiveFields(value);
  const room = record(value, "Collaboration room");
  exactKeys(room, [
    "surface",
    "schema_version",
    "room_id",
    "creator_address",
    "declared_member_addresses",
    "accepted_member_addresses",
    "pending_invitation_addresses",
    "declined_member_addresses",
    "cancelled_invitation_addresses",
    "memberships",
    "requester_membership_status",
    "purpose_commitment",
    "pipeline_commitment",
    "room_commitment",
    "generation",
    "created_at",
    "updated_at",
    "lifecycle_status",
    "archived_at",
    "reclaimable_after",
    "room_retention_policy",
    "owners",
    "all_required_memberships_accepted",
    "all_required_roles_active",
    "current_query",
    "all_required_query_grants_current",
    "membership_acceptance_mechanism",
    "role_acceptance_mechanism",
    "query_grant_mechanism",
    "participant_authenticated_projection",
    "raw_purpose_egress",
    "raw_policy_egress",
    "raw_signature_egress",
    "raw_artifact_egress",
    "rollback_protection",
    "rollback_witness",
    "tamper_evident_current_state",
  ], "Collaboration room");
  literal(room.surface, "collaboration_room", "Collaboration room surface");
  literal(room.schema_version, 2, "Collaboration room schema");
  literal(
    room.membership_acceptance_mechanism,
    "wallet_authenticated_invitation_response",
    "Collaboration membership mechanism",
  );
  literal(
    room.role_acceptance_mechanism,
    "owner_role_consent_signature",
    "Collaboration role mechanism",
  );
  literal(
    room.query_grant_mechanism,
    "owner_signature_bound_to_current_query_v2",
    "Collaboration query-grant mechanism",
  );
  literal(
    room.participant_authenticated_projection,
    true,
    "Collaboration participant projection",
  );
  literal(room.raw_purpose_egress, false, "Collaboration purpose egress");
  literal(room.raw_policy_egress, false, "Collaboration policy egress");
  literal(room.raw_signature_egress, false, "Collaboration signature egress");
  literal(room.raw_artifact_egress, false, "Collaboration artifact egress");
  const rollbackBoundary = assertCurrentStateBoundary(
    room,
    "Collaboration room",
  );

  const declared = canonicalAddresses(
    room.declared_member_addresses,
    "Collaboration declared members",
  );
  const accepted = canonicalAddresses(
    room.accepted_member_addresses,
    "Collaboration accepted members",
  );
  const invited = canonicalAddresses(
    room.pending_invitation_addresses,
    "Collaboration pending invitations",
  );
  const declined = canonicalAddresses(
    room.declined_member_addresses,
    "Collaboration declined members",
  );
  const cancelled = canonicalAddresses(
    room.cancelled_invitation_addresses,
    "Collaboration cancelled invitations",
  );
  if (
    !Array.isArray(room.memberships)
    || room.memberships.length !== declared.length
  ) throw new Error("Collaboration memberships are invalid");
  const memberships = room.memberships.map(parseMembership);
  if (
    memberships.some((item, index) => (
      item.member_address !== declared[index]
    ))
    || accepted.join("\0") !== memberships
      .filter((item) => item.membership_status === "accepted")
      .map((item) => item.member_address).join("\0")
    || invited.join("\0") !== memberships
      .filter((item) => item.membership_status === "invited")
      .map((item) => item.member_address).join("\0")
    || declined.join("\0") !== memberships
      .filter((item) => item.membership_status === "declined")
      .map((item) => item.member_address).join("\0")
    || cancelled.join("\0") !== memberships
      .filter((item) => item.membership_status === "cancelled")
      .map((item) => item.member_address).join("\0")
  ) throw new Error("Collaboration membership summaries are inconsistent");

  if (
    !Array.isArray(room.owners)
    || room.owners.length < 1
    || room.owners.length > MAX_ROOM_OWNERS
  ) throw new Error("Collaboration room owners are invalid");
  const owners = room.owners.map(parseOwner);
  if (
    new Set(owners.map((owner) => owner.owner_address)).size !== owners.length
    || owners.some((owner, index) => (
      index > 0 && owners[index - 1].owner_address >= owner.owner_address
    ))
    || owners.some((owner) => !declared.includes(owner.owner_address))
    || owners.reduce((total, owner) => total + owner.allocation_bps, 0) !== 10_000
  ) throw new Error("Collaboration room owner bindings are invalid");
  const allMemberships = owners.every(
    (owner) => owner.membership_status === "accepted",
  );
  const allRoles = owners.every((owner) => owner.role_accepted);
  if (
    room.all_required_memberships_accepted !== allMemberships
    || room.all_required_roles_active !== (allMemberships && allRoles)
  ) throw new Error("Collaboration role summary is inconsistent");

  const currentQuery = room.current_query === null
    ? null
    : parseCollaborationQueryProposal(room.current_query);
  if (currentQuery) {
    assertSameRollbackWitness(
      rollbackBoundary,
      currentQuery,
      "Collaboration room query",
    );
  }
  if (
    currentQuery
    && (
      currentQuery.room_id !== room.room_id
      || currentQuery.room_commitment !== room.room_commitment
      || currentQuery.room_generation !== room.generation
    )
  ) throw new Error("Collaboration query is bound to a different room state");
  const allQueryGrants = currentQuery?.all_required_query_grants_current ?? false;
  if (room.all_required_query_grants_current !== allQueryGrants) {
    throw new Error("Collaboration query summary is inconsistent");
  }

  const creator = address(
    room.creator_address,
    "Collaboration room creator",
  );
  if (!accepted.includes(creator)) {
    throw new Error("Collaboration room creator is not accepted");
  }
  const requesterStatus = String(room.requester_membership_status);
  if (!["accepted", "invited"].includes(requesterStatus)) {
    throw new Error("Collaboration requester membership is invalid");
  }
  const lifecycle = String(room.lifecycle_status);
  if (!["active", "archived"].includes(lifecycle)) {
    throw new Error("Collaboration lifecycle is invalid");
  }
  const createdAt = integer(room.created_at, "Collaboration room creation time");
  const updatedAt = integer(room.updated_at, "Collaboration room update time");
  const archivedAt = integer(room.archived_at, "Collaboration archive time");
  const reclaimableAfter = integer(
    room.reclaimable_after,
    "Collaboration room retention boundary",
  );
  if (updatedAt < createdAt) {
    throw new Error("Collaboration room timestamps are inconsistent");
  }
  if (lifecycle === "active") {
    literal(
      room.room_retention_policy,
      "active_not_pruned",
      "Collaboration room retention policy",
    );
    if (archivedAt !== 0 || reclaimableAfter !== 0) {
      throw new Error("Active collaboration room has a retention deadline");
    }
  } else {
    literal(
      room.room_retention_policy,
      "explicit_archive_then_bounded_reclamation",
      "Collaboration room retention policy",
    );
    if (
      archivedAt === 0
      || reclaimableAfter <= archivedAt
      || invited.length > 0
      || allRoles
      || currentQuery !== null
    ) throw new Error("Archived collaboration room retains live authority");
  }

  return Object.freeze({
    surface: "collaboration_room",
    schema_version: 2,
    room_id: patterned(room.room_id, ROOM_ID, "Collaboration room ID", 37),
    creator_address: creator,
    declared_member_addresses: declared,
    accepted_member_addresses: accepted,
    pending_invitation_addresses: invited,
    declined_member_addresses: declined,
    cancelled_invitation_addresses: cancelled,
    memberships: Object.freeze(memberships),
    requester_membership_status: requesterStatus as "accepted" | "invited",
    purpose_commitment: commitment(
      room.purpose_commitment,
      "Collaboration purpose commitment",
    ),
    pipeline_commitment: commitment(
      room.pipeline_commitment,
      "Collaboration pipeline commitment",
    ),
    room_commitment: commitment(
      room.room_commitment,
      "Collaboration room commitment",
    ),
    generation: integer(
      room.generation,
      "Collaboration room generation",
      1,
      Number.MAX_SAFE_INTEGER,
    ),
    created_at: createdAt,
    updated_at: updatedAt,
    lifecycle_status: lifecycle as "active" | "archived",
    archived_at: archivedAt,
    reclaimable_after: reclaimableAfter,
    room_retention_policy: room.room_retention_policy as
      CollaborationRoom["room_retention_policy"],
    owners: Object.freeze(owners),
    all_required_memberships_accepted: allMemberships,
    all_required_roles_active: allMemberships && allRoles,
    current_query: currentQuery,
    all_required_query_grants_current: allQueryGrants,
    membership_acceptance_mechanism:
      "wallet_authenticated_invitation_response",
    role_acceptance_mechanism: "owner_role_consent_signature",
    query_grant_mechanism: "owner_signature_bound_to_current_query_v2",
    participant_authenticated_projection: true,
    raw_purpose_egress: false,
    raw_policy_egress: false,
    raw_signature_egress: false,
    raw_artifact_egress: false,
    ...rollbackBoundary,
  });
}

export function parseCollaborationRoomList(
  value: unknown,
): CollaborationRoomList {
  assertNoSensitiveFields(value);
  const list = record(value, "Collaboration room list");
  exactKeys(list, [
    "surface",
    "schema_version",
    "rooms",
    "room_count",
    "has_more",
    "next_cursor",
    "page_limit",
    "maximum_page_size",
    "maximum_accepted_rooms_per_participant",
    "maximum_pending_invitations_per_target",
    "snapshot_bound_pagination",
    "participant_authenticated_projection",
    "raw_purpose_egress",
    "raw_policy_egress",
    "raw_signature_egress",
    "rollback_protection",
    "rollback_witness",
    "tamper_evident_current_state",
  ], "Collaboration room list");
  literal(list.surface, "collaboration_rooms", "Collaboration room-list surface");
  literal(list.schema_version, 2, "Collaboration room-list schema");
  literal(list.maximum_page_size, 16, "Collaboration maximum page size");
  literal(
    list.maximum_accepted_rooms_per_participant,
    64,
    "Collaboration accepted-room quota",
  );
  literal(
    list.maximum_pending_invitations_per_target,
    32,
    "Collaboration pending-invitation quota",
  );
  literal(
    list.snapshot_bound_pagination,
    true,
    "Collaboration cursor boundary",
  );
  literal(
    list.participant_authenticated_projection,
    true,
    "Collaboration participant room list",
  );
  literal(list.raw_purpose_egress, false, "Collaboration purpose egress");
  literal(list.raw_policy_egress, false, "Collaboration policy egress");
  literal(list.raw_signature_egress, false, "Collaboration signature egress");
  const rollbackBoundary = assertCurrentStateBoundary(
    list,
    "Collaboration room list",
  );
  const pageLimit = integer(
    list.page_limit,
    "Collaboration page limit",
    1,
    MAX_ROOM_PAGE_SIZE,
  );
  if (!Array.isArray(list.rooms) || list.rooms.length > pageLimit) {
    throw new Error("Collaboration room page is invalid");
  }
  const rooms = list.rooms.map(parseCollaborationRoom);
  for (const room of rooms) {
    assertSameRollbackWitness(
      rollbackBoundary,
      room,
      "Collaboration room list item",
    );
  }
  const hasMore = bool(list.has_more, "Collaboration continuation marker");
  const nextCursor = list.next_cursor === null
    ? null
    : opaqueCursor(list.next_cursor);
  if (
    integer(list.room_count, "Collaboration room count", 0, pageLimit)
      !== rooms.length
    || new Set(rooms.map((room) => room.room_id)).size !== rooms.length
    || hasMore !== Boolean(nextCursor)
    || (hasMore && rooms.length === 0)
  ) throw new Error("Collaboration room-list summary is inconsistent");
  return Object.freeze({
    surface: "collaboration_rooms",
    schema_version: 2,
    rooms: Object.freeze(rooms),
    room_count: rooms.length,
    has_more: hasMore,
    next_cursor: nextCursor,
    page_limit: pageLimit,
    maximum_page_size: 16,
    maximum_accepted_rooms_per_participant: 64,
    maximum_pending_invitations_per_target: 32,
    snapshot_bound_pagination: true,
    participant_authenticated_projection: true,
    raw_purpose_egress: false,
    raw_policy_egress: false,
    raw_signature_egress: false,
    ...rollbackBoundary,
  });
}

export function appendCollaborationRoomPage(
  current: readonly CollaborationRoom[],
  page: CollaborationRoomList,
): readonly CollaborationRoom[] {
  const known = new Set(current.map((room) => room.room_id));
  if (page.rooms.some((room) => known.has(room.room_id))) {
    throw new Error("Collaboration room continuation contains a duplicate");
  }
  return Object.freeze([...current, ...page.rooms]);
}

export function parseCollaborationRoomResult(
  value: unknown,
): CollaborationRoom {
  assertNoSensitiveFields(value);
  const result = record(value, "Collaboration room result");
  exactKeys(
    result,
    ["surface", "schema_version", "room"],
    "Collaboration room result",
  );
  literal(
    result.surface,
    "collaboration_room_result",
    "Collaboration room-result surface",
  );
  literal(result.schema_version, 2, "Collaboration room-result schema");
  return parseCollaborationRoom(result.room);
}

export function parseCollaborationInvitationResult(
  value: unknown,
): CollaborationInvitationResult {
  assertNoSensitiveFields(value);
  const result = record(value, "Collaboration invitation result");
  exactKeys(result, [
    "surface",
    "schema_version",
    "room_id",
    "member_address",
    "membership_status",
    "membership_generation",
    "decision_recorded",
    "visible_after_response",
    "ordinary_participant_authority",
    "room_generation",
    "room_state_commitment",
    "raw_purpose_egress",
    "raw_policy_egress",
    "raw_signature_egress",
    "rollback_protection",
    "rollback_witness",
    "tamper_evident_current_state",
  ], "Collaboration invitation result");
  literal(
    result.surface,
    "collaboration_invitation_result",
    "Collaboration invitation-result surface",
  );
  literal(result.schema_version, 2, "Collaboration invitation-result schema");
  literal(
    result.membership_generation,
    1,
    "Collaboration membership generation",
  );
  literal(
    result.decision_recorded,
    true,
    "Collaboration invitation decision marker",
  );
  literal(result.raw_purpose_egress, false, "Collaboration purpose egress");
  literal(result.raw_policy_egress, false, "Collaboration policy egress");
  literal(result.raw_signature_egress, false, "Collaboration signature egress");
  const rollbackBoundary = assertCurrentStateBoundary(
    result,
    "Collaboration invitation result",
  );
  const status = String(result.membership_status);
  if (!["accepted", "declined", "cancelled"].includes(status)) {
    throw new Error("Collaboration invitation result status is invalid");
  }
  const visible = bool(
    result.visible_after_response,
    "Collaboration invitation visibility marker",
  );
  const authority = bool(
    result.ordinary_participant_authority,
    "Collaboration participant-authority marker",
  );
  if (
    visible !== (status === "accepted")
    || authority !== (status === "accepted")
  ) throw new Error("Collaboration invitation result is inconsistent");
  return Object.freeze({
    surface: "collaboration_invitation_result",
    schema_version: 2,
    room_id: patterned(result.room_id, ROOM_ID, "Collaboration room ID", 37),
    member_address: address(
      result.member_address,
      "Collaboration invitation wallet",
    ),
    membership_status: status as
      CollaborationInvitationResult["membership_status"],
    membership_generation: 1,
    decision_recorded: true,
    visible_after_response: visible,
    ordinary_participant_authority: authority,
    room_generation: integer(
      result.room_generation,
      "Collaboration room generation",
      1,
      Number.MAX_SAFE_INTEGER,
    ),
    room_state_commitment: commitment(
      result.room_state_commitment,
      "Collaboration room-state commitment",
    ),
    raw_purpose_egress: false,
    raw_policy_egress: false,
    raw_signature_egress: false,
    ...rollbackBoundary,
  });
}

export function parseCollaborationConsentResult(
  value: unknown,
): CollaborationRoom {
  assertNoSensitiveFields(value);
  const result = record(value, "Collaboration role-consent result");
  exactKeys(result, [
    "surface",
    "schema_version",
    "verifier_kind",
    "room",
    "raw_signature_retained",
  ], "Collaboration role-consent result");
  literal(
    result.surface,
    "collaboration_role_consent_result",
    "Collaboration role-consent-result surface",
  );
  literal(result.schema_version, 2, "Collaboration role-consent-result schema");
  if (!["eoa", "eip1271"].includes(String(result.verifier_kind))) {
    throw new Error("Collaboration consent verifier kind is invalid");
  }
  literal(
    result.raw_signature_retained,
    false,
    "Collaboration signature retention",
  );
  return parseCollaborationRoom(result.room);
}

function parseChallengeCommon(
  value: Record<string, unknown>,
  label: string,
): {
  issuedAt: number;
  expiresAt: number;
  reclaimableAfter: number;
  status: CollaborationChallengeStatus;
  message: string;
  authorizationRecorded: boolean;
  rollbackBoundary: CollaborationRollbackProjection;
} {
  literal(
    value.retention_policy,
    "bounded_reclaimable_after_terminal_or_expiry",
    `${label} retention policy`,
  );
  literal(
    value.participant_authenticated_projection,
    true,
    `${label} participant projection`,
  );
  literal(value.raw_signature_egress, false, `${label} signature egress`);
  const rollbackBoundary = assertCurrentStateBoundary(value, label);
  const status = String(value.status);
  if (!["pending", "consumed", "superseded", "expired"].includes(status)) {
    throw new Error(`${label} status is invalid`);
  }
  const message = value.message;
  if (
    typeof message !== "string"
    || message.length < 128
    || new TextEncoder().encode(message).length > 4_096
    || message.includes("\0")
  ) throw new Error(`${label} message is invalid`);
  const issuedAt = integer(value.issued_at, `${label} issue time`);
  const expiresAt = integer(value.expires_at, `${label} expiry time`);
  const reclaimableAfter = integer(
    value.reclaimable_after,
    `${label} retention boundary`,
  );
  if (
    expiresAt <= issuedAt
    || expiresAt - issuedAt > 900
    || reclaimableAfter <= issuedAt
  ) throw new Error(`${label} lifetime is invalid`);
  return {
    issuedAt,
    expiresAt,
    reclaimableAfter,
    status: status as CollaborationChallengeStatus,
    message,
    authorizationRecorded: bool(
      value.authorization_hash_recorded,
      `${label} authorization marker`,
    ),
    rollbackBoundary,
  };
}

export function parseCollaborationConsentChallenge(
  value: unknown,
): CollaborationConsentChallenge {
  assertNoSensitiveFields(value);
  const challenge = record(value, "Collaboration role-consent challenge");
  exactKeys(challenge, [
    "surface",
    "schema_version",
    "challenge_id",
    "room_id",
    "owner_address",
    "decision",
    "room_commitment",
    "room_generation",
    "room_state_commitment",
    "challenge_commitment",
    "message",
    "issued_at",
    "expires_at",
    "status",
    "authorization_hash_recorded",
    "reclaimable_after",
    "retention_policy",
    "participant_authenticated_projection",
    "raw_signature_egress",
    "rollback_protection",
    "rollback_witness",
    "tamper_evident_current_state",
  ], "Collaboration role-consent challenge");
  literal(
    challenge.surface,
    "collaboration_role_consent_challenge",
    "Collaboration role-consent surface",
  );
  literal(challenge.schema_version, 2, "Collaboration challenge schema");
  const decision = String(challenge.decision);
  if (!["activate", "revoke"].includes(decision)) {
    throw new Error("Collaboration role-consent decision is invalid");
  }
  const common = parseChallengeCommon(
    challenge,
    "Collaboration role-consent challenge",
  );
  return Object.freeze({
    surface: "collaboration_role_consent_challenge",
    schema_version: 2,
    challenge_id: patterned(
      challenge.challenge_id,
      CONSENT_ID,
      "Collaboration role-consent challenge ID",
      40,
    ),
    room_id: patterned(challenge.room_id, ROOM_ID, "Collaboration room ID", 37),
    owner_address: address(
      challenge.owner_address,
      "Collaboration consent owner",
    ),
    decision: decision as CollaborationConsentDecision,
    room_commitment: commitment(
      challenge.room_commitment,
      "Collaboration room commitment",
    ),
    room_generation: integer(
      challenge.room_generation,
      "Collaboration challenge room generation",
      1,
      Number.MAX_SAFE_INTEGER,
    ),
    room_state_commitment: commitment(
      challenge.room_state_commitment,
      "Collaboration room-state commitment",
    ),
    challenge_commitment: commitment(
      challenge.challenge_commitment,
      "Collaboration challenge commitment",
    ),
    message: common.message,
    issued_at: common.issuedAt,
    expires_at: common.expiresAt,
    status: common.status,
    authorization_hash_recorded: common.authorizationRecorded,
    reclaimable_after: common.reclaimableAfter,
    retention_policy: "bounded_reclaimable_after_terminal_or_expiry",
    participant_authenticated_projection: true,
    raw_signature_egress: false,
    ...common.rollbackBoundary,
  });
}

export function parseCollaborationQueryGrantChallenge(
  value: unknown,
): CollaborationQueryGrantChallenge {
  assertNoSensitiveFields(value);
  const challenge = record(value, "Collaboration query-grant challenge");
  exactKeys(challenge, [
    "surface",
    "schema_version",
    "challenge_id",
    "room_id",
    "owner_address",
    "decision",
    "room_commitment",
    "room_generation",
    "query_ref",
    "proposal_commitment",
    "allocation_commitment",
    "owner_policy_commitment",
    "challenge_commitment",
    "message",
    "issued_at",
    "expires_at",
    "status",
    "authorization_hash_recorded",
    "reclaimable_after",
    "retention_policy",
    "participant_authenticated_projection",
    "raw_signature_egress",
    "rollback_protection",
    "rollback_witness",
    "tamper_evident_current_state",
  ], "Collaboration query-grant challenge");
  literal(
    challenge.surface,
    "collaboration_query_grant_challenge",
    "Collaboration query-grant surface",
  );
  literal(challenge.schema_version, 2, "Collaboration query-grant schema");
  const decision = String(challenge.decision);
  if (!["approve", "revoke"].includes(decision)) {
    throw new Error("Collaboration query-grant decision is invalid");
  }
  const common = parseChallengeCommon(
    challenge,
    "Collaboration query-grant challenge",
  );
  return Object.freeze({
    surface: "collaboration_query_grant_challenge",
    schema_version: 2,
    challenge_id: patterned(
      challenge.challenge_id,
      QUERY_GRANT_ID,
      "Collaboration query-grant challenge ID",
      39,
    ),
    room_id: patterned(challenge.room_id, ROOM_ID, "Collaboration room ID", 37),
    owner_address: address(
      challenge.owner_address,
      "Collaboration query-grant owner",
    ),
    decision: decision as CollaborationQueryGrantDecision,
    room_commitment: commitment(
      challenge.room_commitment,
      "Collaboration room commitment",
    ),
    room_generation: integer(
      challenge.room_generation,
      "Collaboration query-grant room generation",
      1,
      Number.MAX_SAFE_INTEGER,
    ),
    query_ref: commitment(
      challenge.query_ref,
      "Collaboration query commitment",
    ),
    proposal_commitment: commitment(
      challenge.proposal_commitment,
      "Collaboration proposal commitment",
    ),
    allocation_commitment: commitment(
      challenge.allocation_commitment,
      "Collaboration allocation commitment",
    ),
    owner_policy_commitment: commitment(
      challenge.owner_policy_commitment,
      "Collaboration owner policy commitment",
    ),
    challenge_commitment: commitment(
      challenge.challenge_commitment,
      "Collaboration query challenge commitment",
    ),
    message: common.message,
    issued_at: common.issuedAt,
    expires_at: common.expiresAt,
    status: common.status,
    authorization_hash_recorded: common.authorizationRecorded,
    reclaimable_after: common.reclaimableAfter,
    retention_policy: "bounded_reclaimable_after_terminal_or_expiry",
    participant_authenticated_projection: true,
    raw_signature_egress: false,
    ...common.rollbackBoundary,
  });
}

function expectedConsentMessage(
  challenge: CollaborationConsentChallenge,
): string {
  const verb = challenge.decision === "activate" ? "activate" : "revoke";
  const title = verb.charAt(0).toUpperCase() + verb.slice(1);
  return (
    "www.wikigen.me wants you to sign in with your Ethereum account:\n"
    + `${challenge.owner_address}\n\n`
    + `${title} this wallet's owner role for the specified `
    + "multi-owner collaboration room. This does not approve any query. "
    + "Each query requires a separate exact-query owner signature. This "
    + "signature does not dispatch execution, settle funds, or transfer "
    + "tokens.\n\n"
    + "URI: https://www.wikigen.me\n"
    + "Version: 2\n"
    + "Chain ID: 84532\n"
    + `Nonce: ${challenge.challenge_id.slice("consent_".length)}\n`
    + `Issued At: ${challenge.issued_at}\n`
    + `Expiration Time: ${challenge.expires_at}\n`
    + "Resources:\n"
    + `- urn:dnai:collaboration:room:${challenge.room_id}\n`
    + `- urn:dnai:collaboration:room-commitment:${challenge.room_commitment}\n`
    + `- urn:dnai:collaboration:room-generation:${challenge.room_generation}\n`
    + `- urn:dnai:collaboration:state:${challenge.room_state_commitment}\n`
    + `- urn:dnai:collaboration:owner-role:${challenge.decision}`
  );
}

function expectedQueryGrantMessage(
  challenge: CollaborationQueryGrantChallenge,
): string {
  const verb = challenge.decision === "approve" ? "approve" : "revoke";
  const title = verb.charAt(0).toUpperCase() + verb.slice(1);
  return (
    "www.wikigen.me wants you to sign in with your Ethereum account:\n"
    + `${challenge.owner_address}\n\n`
    + `${title} this wallet's grant for exactly the committed `
    + "current query below. It cannot be inherited by another query. This "
    + "signature records a prospective consent snapshot only; it does not "
    + "dispatch execution, settle funds, or transfer tokens.\n\n"
    + "URI: https://www.wikigen.me\n"
    + "Version: 2\n"
    + "Chain ID: 84532\n"
    + `Nonce: ${challenge.challenge_id.slice("qgrant_".length)}\n`
    + `Issued At: ${challenge.issued_at}\n`
    + `Expiration Time: ${challenge.expires_at}\n`
    + "Resources:\n"
    + `- urn:dnai:collaboration:room:${challenge.room_id}\n`
    + `- urn:dnai:collaboration:room-commitment:${challenge.room_commitment}\n`
    + `- urn:dnai:collaboration:room-generation:${challenge.room_generation}\n`
    + `- urn:dnai:collaboration:query:${challenge.query_ref}\n`
    + `- urn:dnai:collaboration:query-proposal:${challenge.proposal_commitment}\n`
    + `- urn:dnai:collaboration:owner-policy:${challenge.owner_policy_commitment}\n`
    + `- urn:dnai:collaboration:allocation:${challenge.allocation_commitment}\n`
    + `- urn:dnai:collaboration:query-grant:${challenge.decision}`
  );
}

export function assertConsentChallengeForSigning(
  challenge: CollaborationConsentChallenge,
  expected: {
    readonly room: CollaborationRoom;
    readonly ownerAddress: string;
    readonly decision: CollaborationConsentDecision;
    readonly nowSeconds?: number;
  },
): void {
  const now = expected.nowSeconds ?? Math.floor(Date.now() / 1_000);
  const owner = expected.ownerAddress.toLowerCase();
  if (
    !ADDRESS.test(owner)
    || challenge.status !== "pending"
    || expected.room.lifecycle_status !== "active"
    || expected.room.requester_membership_status !== "accepted"
    || challenge.room_id !== expected.room.room_id
    || challenge.room_commitment !== expected.room.room_commitment
    || challenge.room_generation !== expected.room.generation
    || challenge.owner_address !== owner
    || challenge.decision !== expected.decision
    || now < challenge.issued_at - 60
    || now >= challenge.expires_at
    || challenge.authorization_hash_recorded
  ) throw new Error("Consent challenge is stale or bound to a different action");
  if (challenge.message !== expectedConsentMessage(challenge)) {
    throw new Error("Consent challenge message does not match its exact bindings");
  }
}

export function assertQueryGrantChallengeForSigning(
  challenge: CollaborationQueryGrantChallenge,
  expected: {
    readonly room: CollaborationRoom;
    readonly ownerAddress: string;
    readonly decision: CollaborationQueryGrantDecision;
    readonly nowSeconds?: number;
  },
): void {
  const query = expected.room.current_query;
  const now = expected.nowSeconds ?? Math.floor(Date.now() / 1_000);
  const owner = expected.ownerAddress.toLowerCase();
  if (
    !query
    || !query.proposal_current
    || !ADDRESS.test(owner)
    || challenge.status !== "pending"
    || expected.room.lifecycle_status !== "active"
    || expected.room.requester_membership_status !== "accepted"
    || challenge.room_id !== expected.room.room_id
    || challenge.room_commitment !== expected.room.room_commitment
    || challenge.room_generation !== expected.room.generation
    || challenge.owner_address !== owner
    || challenge.decision !== expected.decision
    || challenge.query_ref !== query.query_ref
    || challenge.proposal_commitment !== query.proposal_commitment
    || challenge.allocation_commitment !== query.allocation_commitment
    || now < challenge.issued_at - 60
    || now >= challenge.expires_at
    || challenge.authorization_hash_recorded
  ) throw new Error(
    "Query-grant challenge is stale or bound to a different query",
  );
  const ownerRecord = expected.room.owners.find(
    (item) => item.owner_address === owner,
  );
  if (
    !ownerRecord?.role_accepted
    || challenge.owner_policy_commitment
      !== ownerRecord.corpus_policy_commitment
    || challenge.message !== expectedQueryGrantMessage(challenge)
  ) throw new Error(
    "Query-grant challenge message does not match its exact bindings",
  );
}

export function parseCollaborationQueryProposalResult(
  value: unknown,
): CollaborationQueryProposal {
  assertNoSensitiveFields(value);
  const result = record(value, "Collaboration query proposal result");
  exactKeys(
    result,
    ["surface", "schema_version", "query"],
    "Collaboration query proposal result",
  );
  literal(
    result.surface,
    "collaboration_query_proposal_result",
    "Collaboration query proposal-result surface",
  );
  literal(result.schema_version, 2, "Collaboration query proposal-result schema");
  return parseCollaborationQueryProposal(result.query);
}

export function parseCollaborationQueryGrantResult(
  value: unknown,
): CollaborationQueryProposal {
  assertNoSensitiveFields(value);
  const result = record(value, "Collaboration query-grant result");
  exactKeys(result, [
    "surface",
    "schema_version",
    "verifier_kind",
    "query",
    "raw_signature_retained",
  ], "Collaboration query-grant result");
  literal(
    result.surface,
    "collaboration_query_grant_result",
    "Collaboration query-grant-result surface",
  );
  literal(result.schema_version, 2, "Collaboration query-grant-result schema");
  if (!["eoa", "eip1271"].includes(String(result.verifier_kind))) {
    throw new Error("Collaboration query-grant verifier kind is invalid");
  }
  literal(
    result.raw_signature_retained,
    false,
    "Collaboration query signature retention",
  );
  return parseCollaborationQueryProposal(result.query);
}

export function parseCollaborationJointRun(
  value: unknown,
): CollaborationJointRun {
  assertNoSensitiveFields(value);
  const run = record(value, "Collaboration joint-consent snapshot");
  exactKeys(run, [
    "surface",
    "schema_version",
    "run_id",
    "room_id",
    "query_ref",
    "requester_address",
    "room_commitment",
    "room_generation",
    "room_state_commitment",
    "query_proposal_commitment",
    "query_grant_set_commitment",
    "allocation_commitment",
    "joint_consent_snapshot_commitment",
    "recorded_at",
    "execution_status",
    "consent_snapshot_current",
    "query_grants_current",
    "execution_authority",
    "provider_dispatch_performed",
    "tdx_attestation",
    "settlement_performed",
    "royalty_distribution_performed",
    "reclaimable_after",
    "retention_policy",
    "raw_purpose_egress",
    "raw_policy_egress",
    "raw_signature_egress",
    "raw_artifact_egress",
    "rollback_protection",
    "rollback_witness",
    "tamper_evident_current_state",
  ], "Collaboration joint-consent snapshot");
  literal(
    run.surface,
    "collaboration_joint_consent_snapshot",
    "Collaboration joint-consent surface",
  );
  literal(run.schema_version, 2, "Collaboration joint-consent schema");
  literal(
    run.execution_status,
    "joint_consent_snapshot_not_dispatched",
    "Collaboration execution status",
  );
  literal(
    run.retention_policy,
    "bounded_non_dispatched_snapshot_retention",
    "Collaboration snapshot retention",
  );
  const current = bool(
    run.consent_snapshot_current,
    "Collaboration current-consent marker",
  );
  if (run.query_grants_current !== current) {
    throw new Error("Collaboration query-grant marker is inconsistent");
  }
  for (const key of [
    "execution_authority",
    "provider_dispatch_performed",
    "tdx_attestation",
    "settlement_performed",
    "royalty_distribution_performed",
    "raw_purpose_egress",
    "raw_policy_egress",
    "raw_signature_egress",
    "raw_artifact_egress",
  ] as const) literal(run[key], false, `Collaboration ${key}`);
  const rollbackBoundary = assertCurrentStateBoundary(
    run,
    "Collaboration joint-consent snapshot",
  );
  const recordedAt = integer(run.recorded_at, "Collaboration snapshot time");
  const reclaimableAfter = integer(
    run.reclaimable_after,
    "Collaboration snapshot retention boundary",
  );
  if (reclaimableAfter <= recordedAt) {
    throw new Error("Collaboration snapshot retention is invalid");
  }
  return Object.freeze({
    surface: "collaboration_joint_consent_snapshot",
    schema_version: 2,
    run_id: patterned(run.run_id, RUN_ID, "Collaboration run ID", 36),
    room_id: patterned(run.room_id, ROOM_ID, "Collaboration room ID", 37),
    query_ref: commitment(run.query_ref, "Collaboration query commitment"),
    requester_address: address(
      run.requester_address,
      "Collaboration snapshot requester",
    ),
    room_commitment: commitment(
      run.room_commitment,
      "Collaboration room commitment",
    ),
    room_generation: integer(
      run.room_generation,
      "Collaboration snapshot room generation",
      1,
      Number.MAX_SAFE_INTEGER,
    ),
    room_state_commitment: commitment(
      run.room_state_commitment,
      "Collaboration room-state commitment",
    ),
    query_proposal_commitment: commitment(
      run.query_proposal_commitment,
      "Collaboration query proposal commitment",
    ),
    query_grant_set_commitment: commitment(
      run.query_grant_set_commitment,
      "Collaboration query grant-set commitment",
    ),
    allocation_commitment: commitment(
      run.allocation_commitment,
      "Collaboration allocation commitment",
    ),
    joint_consent_snapshot_commitment: commitment(
      run.joint_consent_snapshot_commitment,
      "Collaboration joint-consent snapshot commitment",
    ),
    recorded_at: recordedAt,
    execution_status: "joint_consent_snapshot_not_dispatched",
    consent_snapshot_current: current,
    query_grants_current: current,
    execution_authority: false,
    provider_dispatch_performed: false,
    tdx_attestation: false,
    settlement_performed: false,
    royalty_distribution_performed: false,
    reclaimable_after: reclaimableAfter,
    retention_policy: "bounded_non_dispatched_snapshot_retention",
    raw_purpose_egress: false,
    raw_policy_egress: false,
    raw_signature_egress: false,
    raw_artifact_egress: false,
    ...rollbackBoundary,
  });
}

export function collaborationSessionIsCurrent(
  session: CollaborationSession | undefined,
  context: {
    readonly address: string | undefined;
    readonly chainId: number | undefined;
    readonly walletAuthorizationVersion: number;
    readonly nowMs?: number;
  },
): session is CollaborationSession {
  return Boolean(
    session
    && context.address
    && context.chainId === 84532
    && session.address === context.address.toLowerCase()
    && session.walletAuthorizationVersion
      === context.walletAuthorizationVersion
    && session.expiresAt * 1_000 > (context.nowMs ?? Date.now()) + 5_000,
  );
}

function canonicalHttpsOrigin(value: string): boolean {
  try {
    const parsed = new URL(value);
    return parsed.protocol === "https:"
      && !parsed.username
      && !parsed.password
      && !parsed.search
      && !parsed.hash
      && parsed.pathname === "/"
      && parsed.origin === value.replace(/\/$/, "");
  } catch {
    return false;
  }
}

export function collaborationReleaseConfigured(
  configuration: CollaborationReleaseConfiguration = deployment,
): boolean {
  return configuration.collaborationEnabled === true
    && canonicalHttpsOrigin(configuration.delegateUrl)
    && configuration.releaseIdentityStatus === "release_bound"
    && /^[0-9a-f]{40}$/.test(configuration.releaseSha ?? "")
    && configuration.verificationChainReleaseSha === configuration.releaseSha
    && APP_ID.test(configuration.appId)
    && configuration.cvmId.length >= 1
    && configuration.cvmId.length <= 128
    && BARE_HASH.test(configuration.composeHash)
    && BARE_HASH.test(configuration.osImageHash)
    && OCI_IMAGE_DIGEST.test(configuration.imageDigest)
    && configuration.walletAuthDomain === "www.wikigen.me"
    && configuration.walletAuthUri === "https://www.wikigen.me"
    && configuration.executionPolicyAnchorRelease !== undefined;
}

export function collaborationJointRunCurrentForRoom(
  run: CollaborationJointRun,
  room: CollaborationRoom,
): boolean {
  return run.consent_snapshot_current
    && run.query_grants_current
    && run.room_id === room.room_id
    && run.room_commitment === room.room_commitment
    && run.room_generation === room.generation
    && room.lifecycle_status === "active"
    && room.all_required_query_grants_current
    && room.current_query?.query_ref === run.query_ref
    && room.current_query.proposal_commitment
      === run.query_proposal_commitment;
}

export function createCollaborationIdentifier(
  prefix: "room" | "idem",
): string {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  const hex = Array.from(
    bytes,
    (value) => value.toString(16).padStart(2, "0"),
  ).join("");
  return prefix === "room" ? `room_${hex}` : `collab.${hex}`;
}

function baseUrl(): string {
  if (!collaborationReleaseConfigured() || !deployment.delegateUrl) {
    throw new Error(
      "Collaboration control plane is not enabled by the frontend release",
    );
  }
  return deployment.delegateUrl.replace(/\/$/, "");
}

async function readBoundedJson(response: Response): Promise<unknown> {
  const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
  if (!contentType.includes("application/json")) {
    throw new Error("Collaboration service did not return application/json");
  }
  const declared = Number(response.headers.get("content-length") ?? 0);
  if (Number.isFinite(declared) && declared > MAX_RESPONSE_BYTES) {
    throw new Error("Collaboration response exceeded its public size limit");
  }
  if (!response.body) throw new Error("Collaboration service returned no body");
  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let text = "";
  let received = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      received += value.byteLength;
      if (received > MAX_RESPONSE_BYTES) {
        await reader.cancel();
        throw new Error(
          "Collaboration response exceeded its public size limit",
        );
      }
      text += decoder.decode(value, { stream: true });
    }
    text += decoder.decode();
  } finally {
    reader.releaseLock();
  }
  try {
    const value: unknown = JSON.parse(text);
    assertNoSensitiveFields(value);
    return value;
  } catch (cause) {
    if (cause instanceof Error
      && cause.message.startsWith("Collaboration response contains")) {
      throw cause;
    }
    throw new Error("Collaboration service returned malformed JSON");
  }
}

function validToken(token: string): boolean {
  return token.length >= 80 && token.length <= 4_096 && JWT.test(token);
}

async function request(
  path: string,
  options: RequestOptions,
): Promise<unknown> {
  if (!validToken(options.token)) {
    throw new Error("Collaboration wallet session is malformed");
  }
  const headers: Record<string, string> = {
    Accept: "application/json",
    Authorization: `Bearer ${options.token}`,
  };
  if (options.body) headers["Content-Type"] = "application/json";
  const signal = options.signal
    ? AbortSignal.any([options.signal, AbortSignal.timeout(12_000)])
    : AbortSignal.timeout(12_000);
  const response = await fetch(`${baseUrl()}${path}`, {
    method: options.method ?? "GET",
    credentials: "omit",
    cache: "no-store",
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined,
    signal,
  });
  const value = await readBoundedJson(response);
  if (!response.ok) {
    const object = value && typeof value === "object" && !Array.isArray(value)
      ? value as Record<string, unknown>
      : {};
    const fallback = `Collaboration request failed with status ${response.status}`;
    throw new CollaborationRequestError(publicErrorText(
      typeof object.detail === "string" ? object.detail : fallback,
      fallback,
    ), response.status);
  }
  return value;
}

/** Shared bounded, bearer-authenticated transport for adjacent Collaboration
 * subresources such as the sponsor-only Royalty settlement journal. */
export async function requestCollaborationAuthenticatedApi(
  path: string,
  options: RequestOptions,
): Promise<unknown> {
  return request(path, options);
}

function signalOptions(
  value?: AbortSignal | CollaborationRoomPageOptions,
): CollaborationRoomPageOptions {
  if (!value) return {};
  if (typeof AbortSignal !== "undefined" && value instanceof AbortSignal) {
    return { signal: value };
  }
  return value as CollaborationRoomPageOptions;
}

export async function listCollaborationRooms(
  token: string,
  optionsOrSignal?: AbortSignal | CollaborationRoomPageOptions,
): Promise<CollaborationRoomList> {
  const options = signalOptions(optionsOrSignal);
  const limit = options.limit ?? 8;
  integer(limit, "Collaboration room page limit", 1, MAX_ROOM_PAGE_SIZE);
  const params = new URLSearchParams({ limit: String(limit) });
  if (options.cursor !== undefined) {
    params.set("cursor", opaqueCursor(options.cursor));
  }
  return parseCollaborationRoomList(await request(
    `/collaboration/rooms?${params.toString()}`,
    { token, signal: options.signal },
  ));
}

export async function fetchCollaborationRoom(
  token: string,
  roomId: string,
  signal?: AbortSignal,
): Promise<CollaborationRoom> {
  patterned(roomId, ROOM_ID, "Collaboration room ID", 37);
  const room = parseCollaborationRoom(await request(
    `/collaboration/rooms/${encodeURIComponent(roomId)}`,
    { token, signal },
  ));
  if (room.room_id !== roomId) {
    throw new Error("Collaboration service returned a different room");
  }
  return room;
}

export async function createCollaborationRoom(
  token: string,
  input: CreateCollaborationRoomRequest,
  signal?: AbortSignal,
): Promise<CollaborationRoom> {
  patterned(input.room_id, ROOM_ID, "Collaboration room ID", 37);
  patterned(
    input.idempotency_key,
    IDEMPOTENCY_KEY,
    "Collaboration idempotency key",
    128,
  );
  if (
    !Array.isArray(input.member_addresses)
    || input.member_addresses.length < 1
    || input.member_addresses.length > MAX_ROOM_MEMBERS
  ) throw new Error("Collaboration room declarations are invalid");
  const members = input.member_addresses.map((member) => (
    address(member.toLowerCase(), "Collaboration room declaration")
  ));
  if (new Set(members).size !== members.length) {
    throw new Error("Collaboration room declarations contain a duplicate");
  }
  commitment(input.purpose_commitment, "Collaboration purpose commitment");
  commitment(input.pipeline_commitment, "Collaboration pipeline commitment");
  const rawPolicies = record(
    input.corpus_policy_commitments,
    "Collaboration owner policies",
  );
  const rawAllocations = record(
    input.owner_allocations_bps,
    "Collaboration owner allocations",
  );
  if (
    Object.keys(rawPolicies).length < 1
    || Object.keys(rawPolicies).length > MAX_ROOM_OWNERS
    || Object.keys(rawPolicies).length !== Object.keys(rawAllocations).length
  ) throw new Error("Collaboration owner maps are invalid");
  const policies: Record<string, string> = {};
  for (const [rawOwner, policy] of Object.entries(rawPolicies)) {
    const owner = address(rawOwner.toLowerCase(), "Collaboration owner");
    if (
      !members.includes(owner)
      || Object.prototype.hasOwnProperty.call(policies, owner)
    ) {
      throw new Error("Collaboration owner is not a declared invitee");
    }
    policies[owner] = commitment(
      policy,
      "Collaboration policy commitment",
    );
  }
  const allocations: Record<string, number> = {};
  let allocationTotal = 0;
  for (const [rawOwner, allocation] of Object.entries(rawAllocations)) {
    const owner = address(rawOwner.toLowerCase(), "Collaboration owner");
    if (
      !Object.prototype.hasOwnProperty.call(policies, owner)
      || Object.prototype.hasOwnProperty.call(allocations, owner)
    ) {
      throw new Error("Collaboration owner maps are invalid");
    }
    allocations[owner] = integer(
      allocation,
      "Collaboration allocation",
      1,
      10_000,
    );
    allocationTotal += allocations[owner];
  }
  if (
    allocationTotal !== 10_000
    || Object.keys(allocations).length !== Object.keys(policies).length
  ) throw new Error("Collaboration allocations must sum to 10,000 bps");
  const room = parseCollaborationRoomResult(await request(
    "/collaboration/rooms",
    {
      method: "POST",
      token,
      body: {
        room_id: input.room_id,
        idempotency_key: input.idempotency_key,
        member_addresses: members,
        purpose_commitment: input.purpose_commitment,
        pipeline_commitment: input.pipeline_commitment,
        corpus_policy_commitments: policies,
        owner_allocations_bps: allocations,
      },
      signal,
    },
  ));
  if (room.room_id !== input.room_id) {
    throw new Error("Collaboration service created a different room");
  }
  return room;
}

async function invitationDecision(
  token: string,
  roomId: string,
  action: "accept" | "decline",
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<CollaborationInvitationResult> {
  patterned(roomId, ROOM_ID, "Collaboration room ID", 37);
  patterned(
    idempotencyKey,
    IDEMPOTENCY_KEY,
    "Collaboration idempotency key",
    128,
  );
  const result = parseCollaborationInvitationResult(await request(
    `/collaboration/rooms/${encodeURIComponent(roomId)}/invitations/${action}`,
    {
      method: "POST",
      token,
      body: { idempotency_key: idempotencyKey },
      signal,
    },
  ));
  if (
    result.room_id !== roomId
    || result.membership_status
      !== (action === "accept" ? "accepted" : "declined")
  ) throw new Error("Collaboration service recorded a different invitation");
  return result;
}

export function acceptCollaborationInvitation(
  token: string,
  roomId: string,
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<CollaborationInvitationResult> {
  return invitationDecision(
    token,
    roomId,
    "accept",
    idempotencyKey,
    signal,
  );
}

export function declineCollaborationInvitation(
  token: string,
  roomId: string,
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<CollaborationInvitationResult> {
  return invitationDecision(
    token,
    roomId,
    "decline",
    idempotencyKey,
    signal,
  );
}

export async function cancelCollaborationInvitation(
  token: string,
  roomId: string,
  inviteeAddress: string,
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<CollaborationInvitationResult> {
  patterned(roomId, ROOM_ID, "Collaboration room ID", 37);
  const invitee = address(
    inviteeAddress.toLowerCase(),
    "Collaboration invitee",
  );
  patterned(
    idempotencyKey,
    IDEMPOTENCY_KEY,
    "Collaboration idempotency key",
    128,
  );
  const result = parseCollaborationInvitationResult(await request(
    `/collaboration/rooms/${encodeURIComponent(roomId)}/invitations/cancel`,
    {
      method: "POST",
      token,
      body: {
        invitee_address: invitee,
        idempotency_key: idempotencyKey,
      },
      signal,
    },
  ));
  if (
    result.room_id !== roomId
    || result.member_address !== invitee
    || result.membership_status !== "cancelled"
  ) throw new Error("Collaboration service cancelled a different invitation");
  return result;
}

export async function archiveCollaborationRoom(
  token: string,
  roomId: string,
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<CollaborationRoom> {
  patterned(roomId, ROOM_ID, "Collaboration room ID", 37);
  patterned(
    idempotencyKey,
    IDEMPOTENCY_KEY,
    "Collaboration idempotency key",
    128,
  );
  const room = parseCollaborationRoomResult(await request(
    `/collaboration/rooms/${encodeURIComponent(roomId)}/archive`,
    {
      method: "POST",
      token,
      body: { idempotency_key: idempotencyKey },
      signal,
    },
  ));
  if (room.room_id !== roomId || room.lifecycle_status !== "archived") {
    throw new Error("Collaboration service archived a different room");
  }
  return room;
}

export async function issueCollaborationConsentChallenge(
  token: string,
  roomId: string,
  decision: CollaborationConsentDecision,
  signal?: AbortSignal,
): Promise<CollaborationConsentChallenge> {
  patterned(roomId, ROOM_ID, "Collaboration room ID", 37);
  const challenge = parseCollaborationConsentChallenge(await request(
    `/collaboration/rooms/${encodeURIComponent(roomId)}/consent-challenges`,
    { method: "POST", token, body: { decision }, signal },
  ));
  if (challenge.room_id !== roomId || challenge.decision !== decision) {
    throw new Error("Collaboration service issued a different role action");
  }
  return challenge;
}

export async function fetchCollaborationConsentChallenge(
  token: string,
  challengeId: string,
  signal?: AbortSignal,
): Promise<CollaborationConsentChallenge> {
  patterned(
    challengeId,
    CONSENT_ID,
    "Collaboration role-consent challenge ID",
    40,
  );
  const challenge = parseCollaborationConsentChallenge(await request(
    `/collaboration/consent-challenges/${encodeURIComponent(challengeId)}`,
    { token, signal },
  ));
  if (challenge.challenge_id !== challengeId) {
    throw new Error(
      "Collaboration service returned a different role-consent challenge",
    );
  }
  return challenge;
}

function assertSignature(signature: string, label: string): void {
  if (
    typeof signature !== "string"
    || !/^0x[0-9a-fA-F]+$/.test(signature)
    || signature.length < 4
    || signature.length > 8_194
    || signature.length % 2 !== 0
  ) throw new Error(`${label} is malformed`);
}

export async function submitCollaborationConsent(
  token: string,
  roomId: string,
  input: {
    readonly challenge_id: string;
    readonly decision: CollaborationConsentDecision;
    readonly signature: string;
  },
  signal?: AbortSignal,
): Promise<CollaborationRoom> {
  patterned(roomId, ROOM_ID, "Collaboration room ID", 37);
  patterned(
    input.challenge_id,
    CONSENT_ID,
    "Collaboration role-consent challenge ID",
    40,
  );
  assertSignature(input.signature, "Collaboration role-consent signature");
  const room = parseCollaborationConsentResult(await request(
    `/collaboration/rooms/${encodeURIComponent(roomId)}/consents`,
    { method: "POST", token, body: { ...input }, signal },
  ));
  if (room.room_id !== roomId) {
    throw new Error("Collaboration service updated a different room");
  }
  return room;
}

export async function proposeCollaborationQuery(
  token: string,
  roomId: string,
  queryRef: string,
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<CollaborationQueryProposal> {
  patterned(roomId, ROOM_ID, "Collaboration room ID", 37);
  commitment(queryRef, "Collaboration query commitment");
  patterned(
    idempotencyKey,
    IDEMPOTENCY_KEY,
    "Collaboration idempotency key",
    128,
  );
  const query = parseCollaborationQueryProposalResult(await request(
    `/collaboration/rooms/${encodeURIComponent(roomId)}/query-proposals`,
    {
      method: "POST",
      token,
      body: {
        query_ref: queryRef,
        idempotency_key: idempotencyKey,
      },
      signal,
    },
  ));
  if (query.room_id !== roomId || query.query_ref !== queryRef) {
    throw new Error("Collaboration service proposed a different query");
  }
  return query;
}

export async function issueCollaborationQueryGrantChallenge(
  token: string,
  roomId: string,
  decision: CollaborationQueryGrantDecision,
  signal?: AbortSignal,
): Promise<CollaborationQueryGrantChallenge> {
  patterned(roomId, ROOM_ID, "Collaboration room ID", 37);
  const challenge = parseCollaborationQueryGrantChallenge(await request(
    `/collaboration/rooms/${encodeURIComponent(roomId)}/query-grant-challenges`,
    { method: "POST", token, body: { decision }, signal },
  ));
  if (challenge.room_id !== roomId || challenge.decision !== decision) {
    throw new Error("Collaboration service issued a different query action");
  }
  return challenge;
}

export async function fetchCollaborationQueryGrantChallenge(
  token: string,
  challengeId: string,
  signal?: AbortSignal,
): Promise<CollaborationQueryGrantChallenge> {
  patterned(
    challengeId,
    QUERY_GRANT_ID,
    "Collaboration query-grant challenge ID",
    39,
  );
  const challenge = parseCollaborationQueryGrantChallenge(await request(
    `/collaboration/query-grant-challenges/${encodeURIComponent(challengeId)}`,
    { token, signal },
  ));
  if (challenge.challenge_id !== challengeId) {
    throw new Error(
      "Collaboration service returned a different query-grant challenge",
    );
  }
  return challenge;
}

export async function submitCollaborationQueryGrant(
  token: string,
  roomId: string,
  input: {
    readonly challenge_id: string;
    readonly decision: CollaborationQueryGrantDecision;
    readonly signature: string;
  },
  signal?: AbortSignal,
): Promise<CollaborationQueryProposal> {
  patterned(roomId, ROOM_ID, "Collaboration room ID", 37);
  patterned(
    input.challenge_id,
    QUERY_GRANT_ID,
    "Collaboration query-grant challenge ID",
    39,
  );
  assertSignature(input.signature, "Collaboration query-grant signature");
  const query = parseCollaborationQueryGrantResult(await request(
    `/collaboration/rooms/${encodeURIComponent(roomId)}/query-grants`,
    { method: "POST", token, body: input, signal },
  ));
  if (query.room_id !== roomId) {
    throw new Error("Collaboration service updated a different query");
  }
  return query;
}

export async function authorizeCollaborationJointRun(
  token: string,
  roomId: string,
  queryRef: string,
  idempotencyKey: string,
  signal?: AbortSignal,
): Promise<CollaborationJointRun> {
  patterned(roomId, ROOM_ID, "Collaboration room ID", 37);
  commitment(queryRef, "Collaboration query commitment");
  patterned(
    idempotencyKey,
    IDEMPOTENCY_KEY,
    "Collaboration idempotency key",
    128,
  );
  const run = parseCollaborationJointRun(await request(
    `/collaboration/rooms/${encodeURIComponent(roomId)}/runs`,
    {
      method: "POST",
      token,
      body: { query_ref: queryRef, idempotency_key: idempotencyKey },
      signal,
    },
  ));
  if (run.room_id !== roomId || run.query_ref !== queryRef) {
    throw new Error(
      "Collaboration service recorded a different room or query snapshot",
    );
  }
  return run;
}

export async function fetchCollaborationJointRun(
  token: string,
  runId: string,
  signal?: AbortSignal,
): Promise<CollaborationJointRun> {
  patterned(runId, RUN_ID, "Collaboration run ID", 36);
  const run = parseCollaborationJointRun(await request(
    `/collaboration/runs/${encodeURIComponent(runId)}`,
    { token, signal },
  ));
  if (run.run_id !== runId) {
    throw new Error(
      "Collaboration service returned a different joint-consent snapshot",
    );
  }
  return run;
}

const COLLABORATION_EXECUTION_PLAN_REQUEST_KEYS = [
  "compute_project_id",
  "compute_job_id",
  "compute_workload_id",
  "compute_workload_commitment",
  "compute_manifest_commitment",
  "compute_rate_policy_commitment",
  "compute_workload_schema",
  "compute_workload_source_kind",
  "compute_workload_execution_binding_commitment",
  "compute_workload_recipient_release_commitment",
  "compute_user_address",
  "operation",
  "model",
  "recipe",
  "result_policy",
  "max_prefill_tokens",
  "max_sample_tokens",
  "max_train_tokens",
  "sponsor_address",
  "asset",
  "max_total_asset_debit",
  "max_compute_asset_debit",
  "authorization_nonce",
  "authorization_lifetime_seconds",
  "royalty_total",
] as const;

const COLLABORATION_EXECUTION_BASIS_DOMAIN =
  "dnai-wikigen/collaboration-execution-basis/v2\0";
const COLLABORATION_EXECUTION_AUTHORIZATION_DOMAIN =
  "dnai-wikigen/collaboration-execution-authorization/v1\0";
const COLLABORATION_EXECUTION_ID_DOMAIN =
  "dnai-wikigen/collaboration-execution-id/v1\0";

function collaborationExecutionCanonicalCommitment(
  domain: string,
  value: unknown,
): string {
  const encoder = new TextEncoder();
  const domainBytes = encoder.encode(domain);
  const valueBytes = encoder.encode(pythonCanonicalJson(value));
  const payload = new Uint8Array(domainBytes.length + valueBytes.length);
  payload.set(domainBytes, 0);
  payload.set(valueBytes, domainBytes.length);
  return `sha256:${sha256(payload).slice(2)}`;
}

const COLLABORATION_EXECUTION_BASIS_KEYS = [
  "schema",
  "release_git_sha",
  "release_verification_sha256",
  "chain_id",
  "cvm_id",
  "compose_hash",
  "room_id",
  "room_commitment",
  "room_generation",
  "room_state_commitment",
  "query_ref",
  "query_proposal_commitment",
  "prospective_query_grant_set_commitment",
  "joint_consent_snapshot_commitment",
  "allocation_commitment",
  "owner_addresses",
  "compute_project_id",
  "compute_job_id",
  "compute_workload_id",
  "compute_workload_commitment",
  "compute_manifest_commitment",
  "compute_rate_policy_commitment",
  "compute_workload_schema",
  "compute_workload_source_kind",
  "compute_workload_execution_binding_commitment",
  "compute_workload_recipient_release_commitment",
  "compute_vault_address",
  "compute_vault_runtime_code_hash",
  "compute_finality_model",
  "compute_user_address",
  "operation",
  "model",
  "recipe",
  "result_policy",
  "max_prefill_tokens",
  "max_sample_tokens",
  "max_train_tokens",
  "sponsor_address",
  "asset",
  "max_total_asset_debit",
  "max_compute_asset_debit",
  "authorization_nonce",
  "authorization_expiry",
  "royalty_asset",
  "royalty_total",
  "royalty_owner_amounts_hash",
  "royalty_distributor_address",
  "royalty_release_policy_commitment",
  "royalty_release_binding_commitment",
  "royalty_settlement_id",
  "royalty_settlement_nonce",
  "royalty_reservation_safety_seconds",
  "intent_created_at",
] as const;

const COLLABORATION_EXECUTION_CORE_STATUS_KEYS = [
  "surface",
  "schema_version",
  "execution_id",
  "intent_commitment",
  "authorization_commitment",
  "execution_grant_set_commitment",
  "owner_execution_grant_count",
  "release",
  "room_id",
  "room_commitment",
  "room_generation",
  "room_state_commitment",
  "query_ref",
  "query_proposal_commitment",
  "prospective_query_grant_set_commitment",
  "joint_consent_snapshot_commitment",
  "allocation_commitment",
  "compute_project_id",
  "compute_job_id",
  "compute_workload_id",
  "compute_workload_commitment",
  "compute_manifest_commitment",
  "compute_dispatch_intent_commitment",
  "compute_authorization",
  "compute_rate_policy_commitment",
  "compute_workload_schema",
  "compute_workload_source_kind",
  "compute_workload_execution_binding_commitment",
  "compute_workload_recipient_release_commitment",
  "compute_authority",
  "operation",
  "model",
  "recipe",
  "result_policy",
  "resource_limits",
  "sponsor_address",
  "asset",
  "max_total_asset_debit",
  "max_total_asset_debit_scope",
  "max_compute_asset_debit",
  "max_compute_asset_debit_scope",
  "authorization_nonce",
  "authorization_expiry",
  "royalty",
  "state",
  "claim_count",
  "bounded_result",
  "claim_vault_observation",
  "claim_royalty_observation",
  "compute_handoff",
  "compute_handoff_status",
  "compute_journal_projection",
  "provider_dispatch_may_have_occurred",
  "provider_dispatch_flag_source",
  "collaboration_provider_call_performed",
  "journal_automatic_redispatch",
  "idempotent_provider_replay_claimed",
  "reconciliation_hold",
  "reconciliation_was_required",
  "reconciliation_hold_at",
  "reconciliation_hold_projection_commitment",
  "authority_invalidated_before_claim",
  "source_capable_core_only",
  "api_worker_wiring_claimed",
  "live_deployment_claimed",
  "tdx_attestation_claimed",
  "qvl_verification_claimed",
  "settlement_performed",
  "compute_settlement_projected",
  "royalty_distribution_performed",
  "journal_raw_input_persisted",
  "journal_raw_result_persisted",
  "public_projection_raw_input_included",
  "public_projection_raw_result_included",
  "public_projection_provider_identifier_included",
  "whole_system_non_egress_claimed",
  "anti_rollback_provided",
  "authorized_at",
  "queued_at",
  "claimed_at",
  "handoff_pending_at",
  "handoff_confirmed_at",
  "terminal_at",
] as const;

const COLLABORATION_EXECUTION_STATES = new Set<CollaborationExecutionState>([
  "authorized",
  "queued",
  "claimed",
  "compute_handoff_pending",
  "compute_handoff_confirmed",
  "bounded_result_ready",
  "failed",
  "reconciliation_hold",
  "authority_invalidated",
]);

function boundedExecutionToken(value: unknown, label: string): string {
  const token = patterned(value, EXECUTION_TOKEN, label, 98_304);
  if (token.length < 80) throw new Error(`${label} is invalid`);
  return token;
}

function choice<T extends string>(
  value: unknown,
  choices: readonly T[],
  label: string,
): T {
  if (typeof value !== "string" || !choices.includes(value as T)) {
    throw new Error(`${label} is invalid`);
  }
  return value as T;
}

export function assertCollaborationExecutionPlanRequest(
  value: unknown,
  expectedRequesterAddress?: string,
): asserts value is CollaborationExecutionPlanRequest {
  const plan = record(value, "Collaboration execution plan request");
  exactKeys(
    plan,
    COLLABORATION_EXECUTION_PLAN_REQUEST_KEYS,
    "Collaboration execution plan request",
  );
  patterned(plan.compute_project_id, BYTES32, "Compute project ID", 66);
  patterned(plan.compute_job_id, BYTES32, "Compute job ID", 66);
  patterned(plan.compute_workload_id, WORKLOAD_ID, "Compute workload ID", 36);
  patterned(plan.compute_workload_commitment, BYTES32, "Compute workload commitment", 66);
  patterned(plan.compute_manifest_commitment, BYTES32, "Compute manifest commitment", 66);
  patterned(plan.compute_rate_policy_commitment, BYTES32, "Compute rate-policy commitment", 66);
  const workloadSchema = choice(plan.compute_workload_schema, [
    "dnai.compute.workload.inference.v1",
    "dnai.compute.workload.sft-jsonl.v1",
  ] as const, "Compute workload schema");
  choice(plan.compute_workload_source_kind, ["wallet", "credential"] as const, "Compute workload source");
  commitment(plan.compute_workload_execution_binding_commitment, "Compute workload execution binding");
  commitment(plan.compute_workload_recipient_release_commitment, "Compute workload recipient release");
  const computeUser = address(plan.compute_user_address, "Compute funding wallet");
  const operation = choice(plan.operation, ["inference", "training"] as const, "Compute operation");
  literal(plan.model, "qwen3_8b", "Compute model");
  const recipe = choice(plan.recipe, ["qwen3_8b_bounded", "qwen3_8b_lora_r32"] as const, "Compute recipe");
  choice(plan.result_policy, ["bounded_summary_receipt", "score_band_hash"] as const, "Compute result policy");
  integer(plan.max_prefill_tokens, "Maximum prefill tokens", 0, 32_768);
  integer(plan.max_sample_tokens, "Maximum sample tokens", 0, 4_096);
  integer(plan.max_train_tokens, "Maximum train tokens", 0, 10_000_000);
  const sponsor = address(plan.sponsor_address, "Execution sponsor");
  address(plan.asset, "Execution asset");
  const maximumTotal = integer(plan.max_total_asset_debit, "Maximum total debit", 1, Number.MAX_SAFE_INTEGER);
  const maximumCompute = integer(plan.max_compute_asset_debit, "Maximum Compute debit", 1, Number.MAX_SAFE_INTEGER);
  integer(plan.authorization_nonce, "Execution authorization nonce", 0, Number.MAX_SAFE_INTEGER);
  integer(plan.authorization_lifetime_seconds, "Execution authorization lifetime", 60, 3_600);
  const royaltyTotal = integer(plan.royalty_total, "Execution royalty total", 1, Number.MAX_SAFE_INTEGER);
  if (maximumCompute + royaltyTotal > maximumTotal) {
    throw new Error("Compute cap plus Royalty total exceeds the all-in cap");
  }
  if (computeUser !== sponsor) {
    throw new Error("Compute funding wallet and execution sponsor must match");
  }
  if (
    expectedRequesterAddress
    && computeUser !== address(
      expectedRequesterAddress.toLowerCase(),
      "Collaboration requester",
    )
  ) throw new Error("Execution plan belongs to a different funding wallet");
  if (
    (operation === "inference" && (
      workloadSchema !== "dnai.compute.workload.inference.v1"
      || recipe !== "qwen3_8b_bounded"
    ))
    || (operation === "training" && (
      workloadSchema !== "dnai.compute.workload.sft-jsonl.v1"
      || recipe !== "qwen3_8b_lora_r32"
    ))
  ) throw new Error("Compute workload schema or recipe does not match the operation");
}

export function parseCollaborationExecutionPlan(
  value: unknown,
  expectedRequest?: CollaborationExecutionPlanRequest,
): CollaborationExecutionPlanProjection {
  const plan = record(value, "Collaboration execution plan");
  exactKeys(plan, [
    "surface",
    "schema_version",
    "run_id",
    "room_id",
    "requester_address",
    "basis",
    "basis_commitment",
    "owner_addresses",
    "royalty_owner_amounts_hash",
    "royalty_distributor_address",
    "royalty_release_policy_commitment",
    "royalty_release_binding_commitment",
    "royalty_settlement_id",
    "royalty_settlement_nonce",
    "royalty_reservation_safety_seconds",
    "royalty_authority_server_derived",
    "royalty_reservation_is_derived_after_fresh_owner_grants",
    "royalty_reservation_must_be_deposited_onchain_after_authorization",
    "plan_token",
    "plan_token_contains_bounded_metadata_only",
    "requires_fresh_execution_grant_from_every_owner",
    "query_grants_are_not_execution_grants",
    "provider_dispatch_performed",
    "raw_signature_retained",
    "raw_query_egress",
    "raw_artifact_egress",
  ], "Collaboration execution plan");
  literal(plan.surface, "collaboration_execution_plan", "Collaboration execution plan surface");
  literal(plan.schema_version, 2, "Collaboration execution plan schema");
  const runId = patterned(plan.run_id, RUN_ID, "Collaboration run ID", 36);
  const roomId = patterned(plan.room_id, ROOM_ID, "Collaboration room ID", 37);
  const requester = address(plan.requester_address, "Collaboration execution requester");
  const basisCommitment = commitment(plan.basis_commitment, "Collaboration execution basis");
  const owners = canonicalAddresses(plan.owner_addresses, "Collaboration execution owners");
  if (owners.length < 1) {
    throw new Error("Collaboration execution owners are empty");
  }
  const royaltyHash = patterned(
    plan.royalty_owner_amounts_hash,
    BYTES32,
    "Royalty owner amounts hash",
    66,
  );
  const projectedRoyaltyReleaseBinding = commitment(
    plan.royalty_release_binding_commitment,
    "Projected Royalty release binding",
  );
  const projectedRoyaltyDistributor = address(
    plan.royalty_distributor_address,
    "Projected Royalty distributor",
  );
  const projectedRoyaltyReleasePolicy = patterned(
    plan.royalty_release_policy_commitment,
    BYTES32,
    "Projected Royalty release policy",
    66,
  );
  const projectedRoyaltySettlementId = patterned(
    plan.royalty_settlement_id,
    BYTES32,
    "Projected Royalty settlement ID",
    66,
  );
  const projectedRoyaltySettlementNonce = canonicalUintString(
    plan.royalty_settlement_nonce,
    "Projected Royalty settlement nonce",
  );
  const projectedRoyaltyReservationSafetySeconds = integer(
    plan.royalty_reservation_safety_seconds,
    "Projected Royalty reservation safety window",
    60,
    3_600,
  );
  const basis = record(plan.basis, "Collaboration execution basis projection");
  exactKeys(
    basis,
    COLLABORATION_EXECUTION_BASIS_KEYS,
    "Collaboration execution basis projection",
  );
  if (
    collaborationExecutionCanonicalCommitment(
      COLLABORATION_EXECUTION_BASIS_DOMAIN,
      basis,
    ) !== basisCommitment
  ) throw new Error(
    "Collaboration execution basis commitment does not recompute",
  );
  literal(
    basis.schema,
    "dnai.collaboration.execution-basis.v2",
    "Collaboration execution basis schema",
  );
  const releaseGitSha = patterned(
    basis.release_git_sha,
    GIT_SHA,
    "Collaboration execution release SHA",
    40,
  );
  const releaseVerificationSha256 = commitment(
    basis.release_verification_sha256,
    "Collaboration execution release verification",
  );
  const chainId = literal(
    basis.chain_id,
    84_532,
    "Collaboration execution chain",
  );
  const cvmId = patterned(
    basis.cvm_id,
    CVM_ID,
    "Collaboration execution CVM ID",
    128,
  );
  const composeHash = patterned(
    basis.compose_hash,
    BYTES32,
    "Collaboration execution compose hash",
    66,
  );
  const workloadSourceKind = choice(
    basis.compute_workload_source_kind,
    ["wallet", "credential"] as const,
    "Collaboration execution workload source",
  );
  const sponsorAddress = address(
    basis.sponsor_address,
    "Collaboration execution sponsor",
  );
  const executionAsset = address(
    basis.asset,
    "Collaboration execution asset",
  );
  const basisRoomId = patterned(
    basis.room_id,
    ROOM_ID,
    "Collaboration execution basis room ID",
    37,
  );
  const roomCommitment = commitment(
    basis.room_commitment,
    "Collaboration execution room commitment",
  );
  const roomGeneration = integer(
    basis.room_generation,
    "Collaboration execution room generation",
    1,
    Number.MAX_SAFE_INTEGER,
  );
  const roomStateCommitment = commitment(
    basis.room_state_commitment,
    "Collaboration execution room-state commitment",
  );
  const queryRef = commitment(
    basis.query_ref,
    "Collaboration execution query reference",
  );
  const queryProposalCommitment = commitment(
    basis.query_proposal_commitment,
    "Collaboration execution query proposal",
  );
  const prospectiveQueryGrantSetCommitment = commitment(
    basis.prospective_query_grant_set_commitment,
    "Collaboration execution prospective query-grant set",
  );
  const jointConsentSnapshotCommitment = commitment(
    basis.joint_consent_snapshot_commitment,
    "Collaboration execution joint snapshot",
  );
  const allocationCommitment = commitment(
    basis.allocation_commitment,
    "Collaboration execution allocation",
  );
  const basisOwners = canonicalAddresses(
    basis.owner_addresses,
    "Collaboration execution basis owners",
  );
  patterned(basis.compute_project_id, BYTES32, "Compute project ID", 66);
  patterned(basis.compute_job_id, BYTES32, "Compute job ID", 66);
  patterned(basis.compute_workload_id, WORKLOAD_ID, "Compute workload ID", 36);
  patterned(
    basis.compute_workload_commitment,
    BYTES32,
    "Compute workload commitment",
    66,
  );
  patterned(
    basis.compute_manifest_commitment,
    BYTES32,
    "Compute manifest commitment",
    66,
  );
  patterned(
    basis.compute_rate_policy_commitment,
    BYTES32,
    "Compute rate-policy commitment",
    66,
  );
  const computeWorkloadSchema = choice(
    basis.compute_workload_schema,
    [
      "dnai.compute.workload.inference.v1",
      "dnai.compute.workload.sft-jsonl.v1",
    ] as const,
    "Compute workload schema",
  );
  commitment(
    basis.compute_workload_execution_binding_commitment,
    "Compute workload execution binding",
  );
  commitment(
    basis.compute_workload_recipient_release_commitment,
    "Compute workload recipient release",
  );
  address(basis.compute_vault_address, "Compute vault");
  patterned(
    basis.compute_vault_runtime_code_hash,
    BYTES32,
    "Compute vault runtime",
    66,
  );
  literal(
    basis.compute_finality_model,
    "single_rpc_reported_finalized",
    "Compute finality model",
  );
  const computeUserAddress = address(
    basis.compute_user_address,
    "Compute funding wallet",
  );
  const operation = choice(
    basis.operation,
    ["inference", "training"] as const,
    "Compute operation",
  );
  literal(basis.model, "qwen3_8b", "Compute model");
  const recipe = choice(
    basis.recipe,
    ["qwen3_8b_bounded", "qwen3_8b_lora_r32"] as const,
    "Compute recipe",
  );
  choice(
    basis.result_policy,
    ["bounded_summary_receipt", "score_band_hash"] as const,
    "Compute result policy",
  );
  integer(basis.max_prefill_tokens, "Maximum prefill tokens", 0, 32_768);
  integer(basis.max_sample_tokens, "Maximum sample tokens", 0, 4_096);
  integer(basis.max_train_tokens, "Maximum train tokens", 0, 10_000_000);
  const maximumTotal = integer(
    basis.max_total_asset_debit,
    "Maximum total debit",
    1,
    Number.MAX_SAFE_INTEGER,
  );
  const maximumCompute = integer(
    basis.max_compute_asset_debit,
    "Maximum Compute debit",
    1,
    Number.MAX_SAFE_INTEGER,
  );
  integer(
    basis.authorization_nonce,
    "Execution authorization nonce",
    0,
    Number.MAX_SAFE_INTEGER,
  );
  const authorizationExpiry = integer(
    basis.authorization_expiry,
    "Execution authorization expiry",
    1,
    4_102_444_800,
  );
  const royaltyAsset = address(basis.royalty_asset, "Royalty asset");
  const royaltyTotal = integer(
    basis.royalty_total,
    "Royalty total",
    1,
    Number.MAX_SAFE_INTEGER,
  );
  const intentCreatedAt = integer(
    basis.intent_created_at,
    "Execution intent creation time",
    1,
    4_102_444_800,
  );
  if (
    authorizationExpiry <= intentCreatedAt
    || authorizationExpiry - intentCreatedAt > 3_600
    || computeUserAddress !== requester
    || sponsorAddress !== requester
    || royaltyAsset !== executionAsset
    || maximumCompute + royaltyTotal > maximumTotal
    || (operation === "inference" && (
      computeWorkloadSchema !== "dnai.compute.workload.inference.v1"
      || recipe !== "qwen3_8b_bounded"
    ))
    || (operation === "training" && (
      computeWorkloadSchema !== "dnai.compute.workload.sft-jsonl.v1"
      || recipe !== "qwen3_8b_lora_r32"
    ))
  ) throw new Error("Collaboration execution basis funding or workload changed");
  const royaltyReleaseBinding = commitment(
    basis.royalty_release_binding_commitment,
    "Royalty release binding",
  );
  const royaltyDistributor = address(
    basis.royalty_distributor_address,
    "Royalty distributor",
  );
  const royaltyReleasePolicy = patterned(
    basis.royalty_release_policy_commitment,
    BYTES32,
    "Royalty release policy",
    66,
  );
  const royaltySettlementId = patterned(
    basis.royalty_settlement_id,
    BYTES32,
    "Royalty settlement ID",
    66,
  );
  const royaltySettlementNonce = canonicalUintString(
    basis.royalty_settlement_nonce,
    "Royalty settlement nonce",
  );
  const royaltyReservationSafetySeconds = integer(
    basis.royalty_reservation_safety_seconds,
    "Royalty reservation safety window",
    60,
    3_600,
  );
  if (
    basisRoomId !== roomId
    || JSON.stringify(basisOwners) !== JSON.stringify(owners)
    || basis.royalty_owner_amounts_hash !== royaltyHash
    || royaltyDistributor !== projectedRoyaltyDistributor
    || royaltyReleasePolicy !== projectedRoyaltyReleasePolicy
    || royaltyReleaseBinding !== projectedRoyaltyReleaseBinding
    || royaltySettlementId !== projectedRoyaltySettlementId
    || royaltySettlementNonce !== projectedRoyaltySettlementNonce
    || royaltyReservationSafetySeconds
      !== projectedRoyaltyReservationSafetySeconds
  ) throw new Error("Collaboration execution basis projection changed");
  if (expectedRequest) {
    assertCollaborationExecutionPlanRequest(expectedRequest, requester);
    const projectedRequest: CollaborationExecutionPlanRequest = {
      compute_project_id: String(basis.compute_project_id),
      compute_job_id: String(basis.compute_job_id),
      compute_workload_id: String(basis.compute_workload_id),
      compute_workload_commitment: String(basis.compute_workload_commitment),
      compute_manifest_commitment: String(basis.compute_manifest_commitment),
      compute_rate_policy_commitment: String(basis.compute_rate_policy_commitment),
      compute_workload_schema: computeWorkloadSchema,
      compute_workload_source_kind: workloadSourceKind,
      compute_workload_execution_binding_commitment:
        String(basis.compute_workload_execution_binding_commitment),
      compute_workload_recipient_release_commitment:
        String(basis.compute_workload_recipient_release_commitment),
      compute_user_address: computeUserAddress,
      operation,
      model: "qwen3_8b",
      recipe,
      result_policy: basis.result_policy as CollaborationExecutionPlanRequest["result_policy"],
      max_prefill_tokens: basis.max_prefill_tokens as number,
      max_sample_tokens: basis.max_sample_tokens as number,
      max_train_tokens: basis.max_train_tokens as number,
      sponsor_address: sponsorAddress,
      asset: executionAsset,
      max_total_asset_debit: maximumTotal,
      max_compute_asset_debit: maximumCompute,
      authorization_nonce: basis.authorization_nonce as number,
      authorization_lifetime_seconds: authorizationExpiry - intentCreatedAt,
      royalty_total: royaltyTotal,
    };
    for (const key of COLLABORATION_EXECUTION_PLAN_REQUEST_KEYS) {
      if (projectedRequest[key] !== expectedRequest[key]) {
        throw new Error("Collaboration execution plan changed the requested terms");
      }
    }
  }
  return Object.freeze({
    surface: "collaboration_execution_plan" as const,
    schema_version: 2 as const,
    run_id: runId,
    room_id: roomId,
    requester_address: requester,
    release_git_sha: releaseGitSha,
    release_verification_sha256: releaseVerificationSha256,
    chain_id: chainId,
    cvm_id: cvmId,
    compose_hash: composeHash,
    compute_workload_source_kind: workloadSourceKind,
    sponsor_address: sponsorAddress,
    asset: executionAsset,
    room_commitment: roomCommitment,
    room_generation: roomGeneration,
    room_state_commitment: roomStateCommitment,
    query_ref: queryRef,
    query_proposal_commitment: queryProposalCommitment,
    prospective_query_grant_set_commitment:
      prospectiveQueryGrantSetCommitment,
    joint_consent_snapshot_commitment: jointConsentSnapshotCommitment,
    allocation_commitment: allocationCommitment,
    authorization_expiry: authorizationExpiry,
    royalty_total: String(royaltyTotal),
    basis_commitment: basisCommitment,
    owner_addresses: owners,
    royalty_owner_amounts_hash: royaltyHash,
    royalty_distributor_address: royaltyDistributor,
    royalty_release_policy_commitment: royaltyReleasePolicy,
    royalty_release_binding_commitment: royaltyReleaseBinding,
    royalty_settlement_id: royaltySettlementId,
    royalty_settlement_nonce: royaltySettlementNonce,
    royalty_reservation_safety_seconds: royaltyReservationSafetySeconds,
    royalty_authority_server_derived: literal(
      plan.royalty_authority_server_derived,
      true,
      "Collaboration Royalty authority source",
    ),
    royalty_reservation_is_derived_after_fresh_owner_grants: literal(
      plan.royalty_reservation_is_derived_after_fresh_owner_grants,
      true,
      "Collaboration Royalty reservation derivation boundary",
    ),
    royalty_reservation_must_be_deposited_onchain_after_authorization: literal(
      plan.royalty_reservation_must_be_deposited_onchain_after_authorization,
      true,
      "Collaboration Royalty reservation deposit order",
    ),
    plan_token: boundedExecutionToken(plan.plan_token, "Collaboration execution plan token"),
    plan_token_contains_bounded_metadata_only: literal(plan.plan_token_contains_bounded_metadata_only, true, "Collaboration plan-token content boundary"),
    requires_fresh_execution_grant_from_every_owner: literal(plan.requires_fresh_execution_grant_from_every_owner, true, "Collaboration execution grant requirement"),
    query_grants_are_not_execution_grants: literal(plan.query_grants_are_not_execution_grants, true, "Collaboration query-grant boundary"),
    provider_dispatch_performed: literal(plan.provider_dispatch_performed, false, "Collaboration plan dispatch state"),
    raw_signature_retained: literal(plan.raw_signature_retained, false, "Collaboration plan signature boundary"),
    raw_query_egress: literal(plan.raw_query_egress, false, "Collaboration plan query boundary"),
    raw_artifact_egress: literal(plan.raw_artifact_egress, false, "Collaboration plan artifact boundary"),
    clientProjectionIsExecutionEvidence: false as const,
  });
}

export function parseCollaborationExecutionGrantChallenge(
  value: unknown,
): CollaborationExecutionGrantChallenge {
  const challenge = record(value, "Collaboration execution grant challenge");
  exactKeys(challenge, [
    "surface",
    "schema_version",
    "grant_id",
    "owner_address",
    "basis_commitment",
    "royalty_settlement_nonce",
    "message",
    "challenge_token",
    "issued_at",
    "expires_at",
    "scope",
    "query_grants_are_not_execution_grants",
    "raw_signature_retained",
  ], "Collaboration execution grant challenge");
  literal(challenge.surface, "collaboration_execution_grant_challenge", "Collaboration execution challenge surface");
  literal(challenge.schema_version, 2, "Collaboration execution challenge schema");
  const grantId = patterned(challenge.grant_id, EXECUTION_GRANT_ID, "Collaboration execution grant ID", 39);
  const ownerAddress = address(challenge.owner_address, "Collaboration execution grant owner");
  const basisCommitment = commitment(challenge.basis_commitment, "Collaboration execution grant basis");
  const royaltySettlementNonce = canonicalUintString(
    challenge.royalty_settlement_nonce,
    "Collaboration execution grant Royalty settlement nonce",
  );
  const message = patterned(challenge.message, /^[\x20-\x7e]+$/, "Collaboration execution grant message", 65_536);
  const issuedAt = integer(challenge.issued_at, "Collaboration execution challenge issue time");
  const expiresAt = integer(challenge.expires_at, "Collaboration execution challenge expiry");
  if (expiresAt <= issuedAt) throw new Error("Collaboration execution challenge is already expired");
  const parsedMessage = record(JSON.parse(message) as unknown, "Collaboration execution grant message");
  exactKeys(parsedMessage, [
    "domain",
    "schema",
    "chain_id",
    "scope",
    "grant_id",
    "owner_address",
    "basis_commitment",
    "royalty_settlement_nonce",
    "prospective_query_grant_authorization_hash",
    "execution_grant_generation",
    "issued_at",
    "expires_at",
    "query_grants_are_not_execution_grants",
  ], "Collaboration execution grant message");
  literal(parsedMessage.domain, "wikigen collaboration one-shot execution grant v1", "Collaboration execution grant domain");
  literal(parsedMessage.schema, "dnai.collaboration.execution-grant-challenge.v1", "Collaboration execution grant message schema");
  literal(parsedMessage.chain_id, 84_532, "Collaboration execution grant chain");
  literal(parsedMessage.scope, "one_shot_execution", "Collaboration execution grant scope");
  commitment(parsedMessage.prospective_query_grant_authorization_hash, "Prospective query-grant authorization hash");
  const messageRoyaltySettlementNonce = canonicalUintString(
    parsedMessage.royalty_settlement_nonce,
    "Collaboration execution grant message Royalty settlement nonce",
  );
  integer(parsedMessage.execution_grant_generation, "Execution grant generation", 1);
  literal(parsedMessage.query_grants_are_not_execution_grants, true, "Collaboration query-grant boundary");
  if (
    parsedMessage.grant_id !== grantId
    || parsedMessage.owner_address !== ownerAddress
    || parsedMessage.basis_commitment !== basisCommitment
    || messageRoyaltySettlementNonce !== royaltySettlementNonce
    || parsedMessage.issued_at !== issuedAt
    || parsedMessage.expires_at !== expiresAt
  ) throw new Error("Collaboration execution grant message changed");
  return Object.freeze({
    surface: "collaboration_execution_grant_challenge" as const,
    schema_version: 2 as const,
    grant_id: grantId,
    owner_address: ownerAddress,
    basis_commitment: basisCommitment,
    royalty_settlement_nonce: royaltySettlementNonce,
    message,
    challenge_token: boundedExecutionToken(challenge.challenge_token, "Collaboration execution challenge token"),
    issued_at: issuedAt,
    expires_at: expiresAt,
    scope: literal(challenge.scope, "one_shot_execution", "Collaboration execution challenge scope"),
    query_grants_are_not_execution_grants: literal(challenge.query_grants_are_not_execution_grants, true, "Collaboration query-grant boundary"),
    raw_signature_retained: literal(challenge.raw_signature_retained, false, "Collaboration execution signature boundary"),
  });
}

export function assertCollaborationExecutionGrantChallengeForSigning(
  challenge: CollaborationExecutionGrantChallenge,
  expected: {
    readonly plan: CollaborationExecutionPlanProjection;
    readonly ownerAddress: string;
    readonly now?: number;
  },
): void {
  assertCollaborationExecutionPlanMatchesCurrentRelease(expected.plan);
  const owner = address(expected.ownerAddress.toLowerCase(), "Collaboration execution owner");
  const now = expected.now ?? Math.floor(Date.now() / 1_000);
  if (
    challenge.owner_address !== owner
    || !expected.plan.owner_addresses.includes(owner)
    || challenge.basis_commitment !== expected.plan.basis_commitment
    || challenge.royalty_settlement_nonce
      !== expected.plan.royalty_settlement_nonce
    || now < challenge.issued_at - 60
    || now >= challenge.expires_at
    || challenge.scope !== "one_shot_execution"
    || !challenge.query_grants_are_not_execution_grants
  ) throw new Error("Execution grant challenge is stale or bound to a different plan");
}

export interface CollaborationExecutionPlanReleaseExpectation {
  readonly releaseSha: string;
  readonly releaseVerificationSha256: string;
  readonly mainRuntimeCvmId: string;
  readonly composeHash: string;
  readonly royaltyDistributorAddress: string;
  readonly royaltyReleasePolicyCommitment: string;
  readonly walletAdoptionEnabled: boolean;
}

export function assertCollaborationExecutionPlanMatchesRelease(
  plan: CollaborationExecutionPlanProjection,
  expected: CollaborationExecutionPlanReleaseExpectation,
): void {
  if (
    plan.release_git_sha !== expected.releaseSha.toLowerCase()
    || plan.release_verification_sha256
      !== expected.releaseVerificationSha256.toLowerCase()
    || plan.chain_id !== 84_532
    || plan.cvm_id !== expected.mainRuntimeCvmId
    || plan.compose_hash.toLowerCase() !== expected.composeHash.toLowerCase()
    || plan.royalty_distributor_address
      !== expected.royaltyDistributorAddress.toLowerCase()
    || plan.royalty_release_policy_commitment
      !== expected.royaltyReleasePolicyCommitment.toLowerCase()
    || (plan.compute_workload_source_kind === "credential"
      && !expected.walletAdoptionEnabled)
  ) {
    throw new Error("Collaboration execution plan does not match the current v4 release");
  }
}

export function assertCollaborationExecutionPlanMatchesCurrentRelease(
  plan: CollaborationExecutionPlanProjection,
): void {
  const release = deployment.collaborationExecutionRelease;
  const royaltyAuthority = deployment.royaltyRelease.authority;
  if (
    !release.configured
    || !release.executionEnabled
    || !release.releaseSha
    || !release.releaseVerificationSha256
    || !release.mainRuntimeCvmId
    || !deployment.composeHash
    || !deployment.royaltyDistributorAddress
    || !royaltyAuthority
  ) {
    throw new Error("Current v4 Collaboration execution release is not configured");
  }
  assertCollaborationExecutionPlanMatchesRelease(plan, {
    releaseSha: release.releaseSha,
    releaseVerificationSha256: release.releaseVerificationSha256,
    mainRuntimeCvmId: release.mainRuntimeCvmId,
    composeHash: deployment.composeHash,
    royaltyDistributorAddress: deployment.royaltyDistributorAddress,
    royaltyReleasePolicyCommitment:
      royaltyAuthority.release_policy_commitment,
    walletAdoptionEnabled: release.walletAdoptionEnabled,
  });
}

export function assertCollaborationExecutionPlanMatchesJointRun(
  plan: CollaborationExecutionPlanProjection,
  jointRun: CollaborationJointRun,
  room: CollaborationRoom,
): void {
  const expectedOwners = room.owners
    .filter((owner) => (
      owner.membership_status === "accepted" && owner.role_accepted
    ))
    .map((owner) => owner.owner_address.toLowerCase())
    .sort();
  if (
    !collaborationJointRunCurrentForRoom(jointRun, room)
    || plan.run_id !== jointRun.run_id
    || plan.room_id !== jointRun.room_id
    || plan.requester_address !== jointRun.requester_address
    || plan.room_commitment !== jointRun.room_commitment
    || plan.room_generation !== jointRun.room_generation
    || plan.room_state_commitment !== jointRun.room_state_commitment
    || plan.query_ref !== jointRun.query_ref
    || plan.query_proposal_commitment
      !== jointRun.query_proposal_commitment
    || plan.prospective_query_grant_set_commitment
      !== jointRun.query_grant_set_commitment
    || plan.joint_consent_snapshot_commitment
      !== jointRun.joint_consent_snapshot_commitment
    || plan.allocation_commitment !== jointRun.allocation_commitment
    || JSON.stringify(plan.owner_addresses) !== JSON.stringify(expectedOwners)
  ) throw new Error(
    "Collaboration execution plan does not match the selected current joint snapshot",
  );
}

function commitmentBytes32(value: string): string {
  return `0x${value.slice(7)}`;
}

export function assertCollaborationExecutionAuthorizationMatchesPlan(
  result: CollaborationExecutionAuthorizationResult,
  plan: CollaborationExecutionPlanProjection,
): void {
  const execution = result.execution;
  const reservation = result.royalty_reservation;
  const request = reservation.request;
  const expectedExecutionId = `exec_${sha256(new TextEncoder().encode(
    `${COLLABORATION_EXECUTION_ID_DOMAIN}${execution.intent_commitment}`,
  )).slice(2)}`;
  const expectedAuthorizationCommitment =
    collaborationExecutionCanonicalCommitment(
      COLLABORATION_EXECUTION_AUTHORIZATION_DOMAIN,
      {
        schema: "dnai.collaboration.execution-authorization.v1",
        execution_id: execution.execution_id,
        intent_commitment: execution.intent_commitment,
        execution_basis_commitment: plan.basis_commitment,
        execution_grant_set_commitment:
          execution.execution_grant_set_commitment,
      },
    );
  if (
    execution.execution_id !== expectedExecutionId
    || result.authorization_commitment !== expectedAuthorizationCommitment
    || execution.authorization_commitment
      !== result.authorization_commitment
    || execution.room_id !== plan.room_id
    || execution.owner_execution_grant_count !== plan.owner_addresses.length
    || commitmentBytes32(execution.execution_grant_set_commitment)
      !== request.grant_set_commitment
    || commitmentBytes32(execution.intent_commitment)
      !== request.execution_commitment
    || reservation.chain_id !== 84_532
    || reservation.distributor_address
      !== plan.royalty_distributor_address
    || reservation.sponsor_address !== plan.sponsor_address
    || request.settlement_id !== plan.royalty_settlement_id
    || request.settlement_nonce !== plan.royalty_settlement_nonce
    || request.release_policy_commitment
      !== plan.royalty_release_policy_commitment
    || request.room_commitment !== commitmentBytes32(plan.room_commitment)
    || request.room_state_commitment
      !== commitmentBytes32(plan.room_state_commitment)
    || request.query_commitment
      !== commitmentBytes32(plan.query_proposal_commitment)
    || request.allocation_commitment
      !== commitmentBytes32(plan.allocation_commitment)
    || request.owners_amounts_hash !== plan.royalty_owner_amounts_hash
    || request.asset !== plan.asset
    || request.total !== plan.royalty_total
    || request.refund_after !== String(
      plan.authorization_expiry + plan.royalty_reservation_safety_seconds,
    )
  ) throw new Error(
    "Collaboration execution authorization does not match the retained plan",
  );
}

function parseCollaborationExecutionStatusRoyalty(value: unknown): {
  reservation: CollaborationExecutionRoyaltyReservationProjection;
  finalizationProven: boolean;
} {
  const royalty = record(value, "Collaboration execution Royalty state");
  exactKeys(royalty, [
    "asset",
    "total",
    "owner_amounts_hash",
    "owner_amounts",
    "distributor_address",
    "release_policy_commitment",
    "release_binding_commitment",
    "settlement_id",
    "settlement_nonce",
    "funding_reservation",
    "reservation_safety_seconds",
    "funding_reservation_finalization_proven",
    "hash_semantics",
    "exact_payout_validation_proven",
    "fresh_construction_requires_validated_owner_amounts",
  ], "Collaboration execution Royalty state");
  const asset = address(royalty.asset, "Collaboration Royalty asset");
  const total = canonicalUintString(
    royalty.total,
    "Collaboration Royalty total",
  );
  const ownerAmountsHash = patterned(
    royalty.owner_amounts_hash,
    BYTES32,
    "Collaboration Royalty owner amounts hash",
    66,
  );
  const distributor = address(
    royalty.distributor_address,
    "Collaboration Royalty distributor",
  );
  const releasePolicy = patterned(
    royalty.release_policy_commitment,
    BYTES32,
    "Collaboration Royalty release policy",
    66,
  );
  commitment(
    royalty.release_binding_commitment,
    "Collaboration Royalty release binding",
  );
  const settlementId = patterned(
    royalty.settlement_id,
    BYTES32,
    "Collaboration Royalty settlement ID",
    66,
  );
  const settlementNonce = canonicalUintString(
    royalty.settlement_nonce,
    "Collaboration Royalty settlement nonce",
  );
  integer(
    royalty.reservation_safety_seconds,
    "Collaboration Royalty reservation safety window",
    1,
    Number.MAX_SAFE_INTEGER,
  );
  literal(
    royalty.hash_semantics,
    "RoyaltyDistributor owner and amount array EIP-712 commitment",
    "Collaboration Royalty hash semantics",
  );
  if (royalty.owner_amounts === null) {
    literal(
      royalty.exact_payout_validation_proven,
      false,
      "Collaboration Royalty payout validation",
    );
  } else {
    if (
      !Array.isArray(royalty.owner_amounts)
      || royalty.owner_amounts.length < 1
      || royalty.owner_amounts.length > MAX_ROOM_OWNERS
    ) throw new Error("Collaboration Royalty owner amounts are invalid");
    const owners = new Set<string>();
    let summed = 0n;
    for (const item of royalty.owner_amounts) {
      const ownerAmount = record(item, "Collaboration Royalty owner amount");
      exactKeys(
        ownerAmount,
        ["owner_address", "amount"],
        "Collaboration Royalty owner amount",
      );
      const owner = address(
        ownerAmount.owner_address,
        "Collaboration Royalty owner",
      );
      if (owners.has(owner)) {
        throw new Error("Collaboration Royalty owner amounts are duplicated");
      }
      owners.add(owner);
      summed += BigInt(canonicalUintString(
        ownerAmount.amount,
        "Collaboration Royalty owner amount",
      ));
    }
    if (summed.toString() !== total) {
      throw new Error("Collaboration Royalty owner amounts do not sum to total");
    }
    literal(
      royalty.exact_payout_validation_proven,
      true,
      "Collaboration Royalty payout validation",
    );
  }
  literal(
    royalty.fresh_construction_requires_validated_owner_amounts,
    true,
    "Collaboration Royalty fresh-construction boundary",
  );
  const reservation = parseCollaborationExecutionRoyaltyReservation(
    royalty.funding_reservation,
  );
  if (
    reservation.request.asset !== asset
    || reservation.request.total !== total
    || reservation.request.owners_amounts_hash !== ownerAmountsHash
    || reservation.distributor_address !== distributor
    || reservation.request.release_policy_commitment !== releasePolicy
    || reservation.request.settlement_id !== settlementId
    || reservation.request.settlement_nonce !== settlementNonce
  ) throw new Error(
    "Collaboration Royalty reservation changed across execution status",
  );
  return {
    reservation,
    finalizationProven: bool(
      royalty.funding_reservation_finalization_proven,
      "Collaboration Royalty reservation finalization",
    ),
  };
}

function parseCollaborationExecutionStatusRecord(
  value: unknown,
  apiProjection: boolean,
): CollaborationExecutionStatusProjection {
  const status = record(value, "Collaboration execution status");
  exactKeys(status, [
    ...COLLABORATION_EXECUTION_CORE_STATUS_KEYS,
    ...(apiProjection
      ? [
          "api_worker_wiring_available",
          "fresh_worker_presence_proven",
          "client_supplied_vault_observation",
          "client_supplied_compute_projection",
        ]
      : []),
  ], "Collaboration execution status");
  literal(status.surface, "collaboration_one_shot_execution", "Collaboration execution status surface");
  literal(status.schema_version, 1, "Collaboration execution status schema");
  const state = choice(
    status.state,
    [...COLLABORATION_EXECUTION_STATES],
    "Collaboration execution state",
  );
  const dispatchMayHaveOccurred = status.provider_dispatch_may_have_occurred;
  if (dispatchMayHaveOccurred !== null && typeof dispatchMayHaveOccurred !== "boolean") {
    throw new Error("Collaboration provider-dispatch projection is invalid");
  }
  const projection = status.compute_journal_projection;
  let apiReportsAuthenticatedLocalJournal = false;
  if (projection !== null) {
    const projected = record(projection, "Collaboration Compute-journal projection");
    exactKeys(projected, [
      "projection_commitment",
      "source_journal_schema",
      "source_sequence",
      "source_record_commitment",
      "source_journal_mac_commitment",
      "source_authentication_receipt",
      "source_authentication_receipt_bound",
      "source_authentication_proven",
      "source_authentication_boundary",
      "compute_stage",
      "provider_dispatch_may_have_occurred",
      "automatic_provider_redispatch",
      "bounded_result_imported",
      "observed_at",
    ], "Collaboration Compute-journal projection");
    commitment(projected.projection_commitment, "Collaboration Compute projection");
    integer(projected.source_sequence, "Collaboration Compute source sequence", 1);
    commitment(projected.source_record_commitment, "Collaboration Compute source record");
    commitment(projected.source_journal_mac_commitment, "Collaboration Compute source journal MAC");
    commitment(projected.source_authentication_receipt, "Collaboration Compute source authentication receipt");
    literal(projected.source_authentication_receipt_bound, true, "Collaboration Compute receipt binding");
    literal(
      projected.source_authentication_proven,
      apiProjection,
      "Collaboration Compute-journal source authentication",
    );
    literal(
      projected.source_authentication_boundary,
      apiProjection
        ? "authenticated_local_compute_journal_reader"
        : "trusted_local_compute_journal_reader_required",
      "Collaboration Compute-journal source boundary",
    );
    literal(projected.automatic_provider_redispatch, false, "Collaboration provider redispatch boundary");
    apiReportsAuthenticatedLocalJournal = apiProjection;
  }
  literal(status.collaboration_provider_call_performed, false, "Collaboration provider-call boundary");
  literal(status.journal_automatic_redispatch, false, "Collaboration journal redispatch boundary");
  literal(status.idempotent_provider_replay_claimed, false, "Collaboration provider replay boundary");
  literal(status.live_deployment_claimed, false, "Collaboration live deployment boundary");
  literal(status.tdx_attestation_claimed, false, "Collaboration TDX boundary");
  literal(status.qvl_verification_claimed, false, "Collaboration QVL boundary");
  literal(status.settlement_performed, false, "Collaboration settlement boundary");
  literal(status.royalty_distribution_performed, false, "Collaboration Royalty boundary");
  literal(status.journal_raw_input_persisted, false, "Collaboration raw-input boundary");
  literal(status.journal_raw_result_persisted, false, "Collaboration raw-result boundary");
  literal(status.public_projection_raw_input_included, false, "Collaboration public input boundary");
  literal(status.public_projection_raw_result_included, false, "Collaboration public result boundary");
  literal(status.public_projection_provider_identifier_included, false, "Collaboration provider-identifier boundary");
  literal(status.whole_system_non_egress_claimed, false, "Collaboration non-egress boundary");
  literal(status.anti_rollback_provided, false, "Collaboration anti-rollback boundary");
  if (apiProjection) {
    literal(status.source_capable_core_only, false, "Collaboration execution API wiring");
    literal(status.api_worker_wiring_available, true, "Collaboration execution API routing");
    literal(status.api_worker_wiring_claimed, false, "Collaboration worker-presence boundary");
    literal(status.fresh_worker_presence_proven, false, "Collaboration worker-presence boundary");
    literal(status.client_supplied_vault_observation, false, "Collaboration vault-observation source");
    literal(status.client_supplied_compute_projection, false, "Collaboration Compute-projection source");
  } else {
    literal(status.source_capable_core_only, true, "Collaboration execution authorization projection");
    literal(status.api_worker_wiring_claimed, false, "Collaboration execution authorization projection");
  }
  const reconciliationHold = literal(
    status.reconciliation_hold,
    state === "reconciliation_hold",
    "Collaboration reconciliation state",
  );
  const authorityInvalidated = literal(
    status.authority_invalidated_before_claim,
    state === "authority_invalidated",
    "Collaboration authority-invalidated state",
  );
  const royalty = parseCollaborationExecutionStatusRoyalty(status.royalty);
  return Object.freeze({
    surface: "collaboration_one_shot_execution" as const,
    schema_version: 1 as const,
    execution_id: patterned(status.execution_id, EXECUTION_ID, "Collaboration execution ID", 69),
    room_id: patterned(status.room_id, ROOM_ID, "Collaboration room ID", 37),
    state,
    intent_commitment: commitment(status.intent_commitment, "Collaboration execution intent"),
    authorization_commitment: commitment(status.authorization_commitment, "Collaboration execution authorization"),
    execution_grant_set_commitment: commitment(status.execution_grant_set_commitment, "Collaboration execution grant set"),
    owner_execution_grant_count: integer(status.owner_execution_grant_count, "Collaboration execution grant count", 1, MAX_ROOM_OWNERS),
    provider_dispatch_may_have_occurred: dispatchMayHaveOccurred,
    reconciliation_hold: reconciliationHold,
    authority_invalidated_before_claim: authorityInvalidated,
    bounded_result_present: status.bounded_result !== null,
    royalty_reservation: royalty.reservation,
    royaltyReservationFinalizationProven: royalty.finalizationProven,
    participantAuthenticatedApiProjection: true as const,
    apiWorkerWiringAvailable: apiProjection,
    apiWorkerWiringClaimed: false as const,
    freshWorkerPresenceProven: false as const,
    apiReportsAuthenticatedLocalJournal,
    independentJournalSourceAuthenticated: false as const,
    finalizedVaultFreshnessProvenInBrowser: false as const,
    tdxAttestationVerifiedInBrowser: false as const,
    qvlVerifiedInBrowser: false as const,
    settlementFinalizedInBrowser: false as const,
    royaltyDistributionObservedInBrowser: false as const,
    clientDtoMayUnlockExecutionControls: false as const,
  });
}

export function parseCollaborationExecutionStatus(
  value: unknown,
): CollaborationExecutionStatusProjection {
  return parseCollaborationExecutionStatusRecord(value, true);
}

const COLLABORATION_EXECUTION_WORKER_RELEASE_BINDING_KEYS = [
  "release_git_sha",
  "release_verification_sha256",
  "deployment_intent_sha256",
  "release_authority_sha256",
  "ceremony_nonce",
  "main_runtime_cvm_id",
  "main_runtime_compose_hash",
  "main_runtime_app_id",
  "main_runtime_os_image_hash",
  "royalty_release_binding_commitment",
  "royalty_distributor_address",
  "compute_vault_address",
  "compute_vault_runtime_code_hash",
  "chain_id",
  "worker_service",
  "worker_profile",
] as const;

const COLLABORATION_EXECUTION_WORKER_CAPABILITY_KEYS = [
  "surface",
  "schema",
  "status",
  "gate_reason",
  "execution_enabled",
  "queue_control_plane_available",
  "queued_work_executable",
  "onchain_reservation_ready",
  "worker_connected",
  "freshness",
  "evidence_authenticity",
  "evidence_classification",
  "heartbeat_observed_at",
  "presence_binding_sha256",
  "release_binding_sha256",
  "release_binding",
  "qvl_capability",
  "real_dstack",
  "simulator",
  "tdx_job_attestation_proven",
  "qvl_job_verdict_proven",
  "warning",
] as const;

const COLLABORATION_EXECUTION_WORKER_RELEASE_BINDING_SCHEMA =
  "dnai.collaboration.execution-worker-release-binding.v1" as const;
const COLLABORATION_EXECUTION_WORKER_CAPABILITY_SCHEMA =
  "dnai.collaboration.execution-worker-capability.v1" as const;
const COLLABORATION_EXECUTION_WORKER_EVIDENCE_CLASSIFICATION =
  "authenticated_worker_presence_not_job_attestation" as const;
const COLLABORATION_EXECUTION_QVL_PROFILE = "royalty_settlement" as const;
const COLLABORATION_EXECUTION_QVL_AUTHORIZATION_SCHEMA =
  "dnai.royalty-settlement-qvl-authorization-request.v2" as const;
const COLLABORATION_EXECUTION_WORKER_RELEASE_DOMAIN =
  "dnai-wikigen/collaboration-execution-worker-release-binding/v1\0";
const COLLABORATION_EXECUTION_WORKER_PRESENCE_DOMAIN =
  "dnai-wikigen/collaboration-execution-worker-presence-binding/v1\0";

function collaborationExecutionWorkerCommitment(
  domain: string,
  value: unknown,
): string {
  return collaborationExecutionCanonicalCommitment(domain, value);
}

function parseCollaborationExecutionWorkerReleaseBinding(
  value: unknown,
): CollaborationExecutionWorkerReleaseBinding {
  const binding = record(
    value,
    "Collaboration execution worker release binding",
  );
  exactKeys(
    binding,
    COLLABORATION_EXECUTION_WORKER_RELEASE_BINDING_KEYS,
    "Collaboration execution worker release binding",
  );
  return Object.freeze({
    release_git_sha: patterned(
      binding.release_git_sha,
      GIT_SHA,
      "Worker release SHA",
      40,
    ),
    release_verification_sha256: commitment(
      binding.release_verification_sha256,
      "Worker release verification",
    ),
    deployment_intent_sha256: commitment(
      binding.deployment_intent_sha256,
      "Worker deployment intent",
    ),
    release_authority_sha256: commitment(
      binding.release_authority_sha256,
      "Worker release authority",
    ),
    ceremony_nonce: patterned(
      binding.ceremony_nonce,
      BYTES32,
      "Worker ceremony nonce",
      66,
    ),
    main_runtime_cvm_id: patterned(
      binding.main_runtime_cvm_id,
      CVM_ID,
      "Worker main-runtime CVM",
      128,
    ),
    main_runtime_compose_hash: patterned(
      binding.main_runtime_compose_hash,
      BYTES32,
      "Worker main-runtime compose hash",
      66,
    ),
    main_runtime_app_id: patterned(
      binding.main_runtime_app_id,
      APP_ID,
      "Worker main-runtime app ID",
      40,
    ),
    main_runtime_os_image_hash: patterned(
      binding.main_runtime_os_image_hash,
      BARE_HASH,
      "Worker main-runtime OS image hash",
      64,
    ),
    royalty_release_binding_commitment: commitment(
      binding.royalty_release_binding_commitment,
      "Worker Royalty release binding",
    ),
    royalty_distributor_address: address(
      binding.royalty_distributor_address,
      "Worker Royalty distributor",
    ),
    compute_vault_address: address(
      binding.compute_vault_address,
      "Worker Compute vault",
    ),
    compute_vault_runtime_code_hash: patterned(
      binding.compute_vault_runtime_code_hash,
      BYTES32,
      "Worker Compute vault runtime",
      66,
    ),
    chain_id: literal(
      binding.chain_id,
      84_532,
      "Worker execution chain",
    ),
    worker_service: literal(
      binding.worker_service,
      "collaboration-execution-worker",
      "Worker service",
    ),
    worker_profile: literal(
      binding.worker_profile,
      "collaboration-execution",
      "Worker profile",
    ),
  });
}

export function parseCollaborationExecutionWorkerCapability(
  value: unknown,
): CollaborationExecutionWorkerCapability {
  const capability = record(
    value,
    "Collaboration execution worker capability",
  );
  exactKeys(
    capability,
    COLLABORATION_EXECUTION_WORKER_CAPABILITY_KEYS,
    "Collaboration execution worker capability",
  );
  literal(
    capability.surface,
    "collaboration_execution_worker_capability",
    "Collaboration execution worker capability surface",
  );
  literal(
    capability.schema,
    COLLABORATION_EXECUTION_WORKER_CAPABILITY_SCHEMA,
    "Collaboration execution worker capability schema",
  );
  const status = choice(
    capability.status,
    ["live", "unavailable"] as const,
    "Collaboration execution worker status",
  );
  const live = status === "live";
  const gateReason = patterned(
    capability.gate_reason,
    /^[a-z][a-z0-9_]{1,63}$/,
    "Collaboration execution worker gate reason",
    64,
  );
  if ((live && gateReason !== "ready") || (!live && gateReason === "ready")) {
    throw new Error("Collaboration execution worker gate reason is contradictory");
  }
  const executionEnabled = bool(
    capability.execution_enabled,
    "Collaboration execution worker release decision",
  );
  const queueAvailable = bool(
    capability.queue_control_plane_available,
    "Collaboration execution queue availability",
  );
  if (queueAvailable !== executionEnabled || (live && !executionEnabled)) {
    throw new Error("Collaboration execution queue decision is contradictory");
  }
  literal(
    capability.queued_work_executable,
    live,
    "Collaboration queued-work capability",
  );
  literal(
    capability.onchain_reservation_ready,
    live,
    "Collaboration reservation capability",
  );
  literal(
    capability.worker_connected,
    live,
    "Collaboration worker connection state",
  );
  literal(
    capability.freshness,
    live ? "fresh" : "unavailable",
    "Collaboration worker freshness",
  );
  literal(
    capability.evidence_authenticity,
    live ? "hmac_verified" : "unverified",
    "Collaboration worker evidence authenticity",
  );
  literal(
    capability.evidence_classification,
    COLLABORATION_EXECUTION_WORKER_EVIDENCE_CLASSIFICATION,
    "Collaboration worker evidence classification",
  );

  let heartbeatObservedAt: number | null = null;
  let presenceBindingSha256: string | null = null;
  if (live) {
    heartbeatObservedAt = integer(
      capability.heartbeat_observed_at,
      "Collaboration worker heartbeat time",
      1,
      4_102_444_800,
    );
    presenceBindingSha256 = commitment(
      capability.presence_binding_sha256,
      "Collaboration worker presence binding",
    );
  } else {
    literal(
      capability.heartbeat_observed_at,
      null,
      "Unavailable Collaboration worker heartbeat",
    );
    literal(
      capability.presence_binding_sha256,
      null,
      "Unavailable Collaboration worker presence binding",
    );
  }

  let releaseBinding: CollaborationExecutionWorkerReleaseBinding | null = null;
  let releaseBindingSha256: string | null = null;
  if (capability.release_binding === null) {
    literal(
      capability.release_binding_sha256,
      null,
      "Unavailable Collaboration worker release binding",
    );
  } else {
    releaseBinding = parseCollaborationExecutionWorkerReleaseBinding(
      capability.release_binding,
    );
    releaseBindingSha256 = commitment(
      capability.release_binding_sha256,
      "Collaboration worker release-binding digest",
    );
    const expectedReleaseBinding = collaborationExecutionWorkerCommitment(
      COLLABORATION_EXECUTION_WORKER_RELEASE_DOMAIN,
      {
        schema: COLLABORATION_EXECUTION_WORKER_RELEASE_BINDING_SCHEMA,
        release_binding: releaseBinding,
      },
    );
    if (releaseBindingSha256 !== expectedReleaseBinding) {
      throw new Error("Collaboration worker release binding does not recompute");
    }
  }
  if (live && (!releaseBinding || !releaseBindingSha256)) {
    throw new Error("Live Collaboration worker release binding is unavailable");
  }
  const qvl = record(
    capability.qvl_capability,
    "Collaboration worker QVL capability",
  );
  exactKeys(qvl, [
    "configuration",
    "reachability",
    "observation_sha256",
    "observed_at",
    "expires_at",
    "profile",
    "royalty_authorization_schema",
    "per_job_qvl_required",
    "per_job_qvl_verified",
  ], "Collaboration worker QVL capability");
  const qvlConfiguration = literal(
    qvl.configuration,
    live ? "complete" : "unavailable",
    "Collaboration worker QVL configuration",
  );
  const qvlReachability = literal(
    qvl.reachability,
    live ? "authenticated_exact_capability" : "unavailable",
    "Collaboration worker QVL reachability",
  );
  let qvlObservationSha256: string | null = null;
  let qvlObservedAt: number | null = null;
  let qvlExpiresAt: number | null = null;
  let qvlProfile: typeof COLLABORATION_EXECUTION_QVL_PROFILE | null = null;
  let qvlAuthorizationSchema:
    typeof COLLABORATION_EXECUTION_QVL_AUTHORIZATION_SCHEMA | null = null;
  if (live) {
    qvlObservationSha256 = commitment(
      qvl.observation_sha256,
      "Collaboration worker QVL capability observation",
    );
    qvlObservedAt = integer(
      qvl.observed_at,
      "Collaboration worker QVL capability observation time",
      1,
      4_102_444_800,
    );
    qvlExpiresAt = integer(
      qvl.expires_at,
      "Collaboration worker QVL capability expiry",
      1,
      4_102_444_800,
    );
    qvlProfile = literal(
      qvl.profile,
      COLLABORATION_EXECUTION_QVL_PROFILE,
      "Collaboration worker QVL profile",
    );
    qvlAuthorizationSchema = literal(
      qvl.royalty_authorization_schema,
      COLLABORATION_EXECUTION_QVL_AUTHORIZATION_SCHEMA,
      "Collaboration worker QVL Royalty authorization schema",
    );
    if (
      qvlExpiresAt <= qvlObservedAt
      || heartbeatObservedAt === null
      || qvlObservedAt > heartbeatObservedAt
    ) throw new Error("Collaboration worker QVL capability timing is contradictory");
  } else {
    literal(qvl.observation_sha256, null, "Unavailable Collaboration QVL observation");
    literal(qvl.observed_at, null, "Unavailable Collaboration QVL observation time");
    literal(qvl.expires_at, null, "Unavailable Collaboration QVL expiry");
    literal(qvl.profile, null, "Unavailable Collaboration QVL profile");
    literal(
      qvl.royalty_authorization_schema,
      null,
      "Unavailable Collaboration QVL Royalty authorization schema",
    );
  }
  literal(qvl.per_job_qvl_required, true, "Collaboration per-job QVL requirement");
  literal(qvl.per_job_qvl_verified, false, "Collaboration per-job QVL verdict");
  if (live) {
    const expectedPresenceBinding = collaborationExecutionWorkerCommitment(
      COLLABORATION_EXECUTION_WORKER_PRESENCE_DOMAIN,
      {
        schema: COLLABORATION_EXECUTION_WORKER_CAPABILITY_SCHEMA,
        heartbeat_schema: "dnai.collaboration.execution-worker-heartbeat.v1",
        observed_at: heartbeatObservedAt,
        release_binding_sha256: releaseBindingSha256,
        evidence_classification:
          COLLABORATION_EXECUTION_WORKER_EVIDENCE_CLASSIFICATION,
        qvl_capability_observation_sha256: qvlObservationSha256,
      },
    );
    if (presenceBindingSha256 !== expectedPresenceBinding) {
      throw new Error("Collaboration worker presence binding does not recompute");
    }
  }
  literal(capability.real_dstack, live, "Collaboration real-dstack presence");
  literal(capability.simulator, false, "Collaboration simulator boundary");
  literal(
    capability.tdx_job_attestation_proven,
    false,
    "Collaboration TDX job-attestation boundary",
  );
  literal(
    capability.qvl_job_verdict_proven,
    false,
    "Collaboration QVL job-verdict boundary",
  );
  const warning = patterned(
    capability.warning,
    /^[\x20-\x7e]+$/,
    "Collaboration worker capability warning",
    2_048,
  );

  return Object.freeze({
    surface: "collaboration_execution_worker_capability" as const,
    schema: COLLABORATION_EXECUTION_WORKER_CAPABILITY_SCHEMA,
    status,
    gate_reason: gateReason,
    execution_enabled: executionEnabled,
    queue_control_plane_available: queueAvailable,
    queued_work_executable: live,
    onchain_reservation_ready: live,
    worker_connected: live,
    freshness: live ? "fresh" as const : "unavailable" as const,
    evidence_authenticity: live
      ? "hmac_verified" as const
      : "unverified" as const,
    evidence_classification:
      COLLABORATION_EXECUTION_WORKER_EVIDENCE_CLASSIFICATION,
    heartbeat_observed_at: heartbeatObservedAt,
    presence_binding_sha256: presenceBindingSha256,
    release_binding_sha256: releaseBindingSha256,
    release_binding: releaseBinding,
    qvl_capability: Object.freeze({
      configuration: qvlConfiguration,
      reachability: qvlReachability,
      observation_sha256: qvlObservationSha256,
      observed_at: qvlObservedAt,
      expires_at: qvlExpiresAt,
      profile: qvlProfile,
      royalty_authorization_schema: qvlAuthorizationSchema,
      per_job_qvl_required: true as const,
      per_job_qvl_verified: false as const,
    }),
    real_dstack: live,
    simulator: false as const,
    tdx_job_attestation_proven: false as const,
    qvl_job_verdict_proven: false as const,
    warning,
    clientProjectionIsJobAttestation: false as const,
  });
}

export function parseCollaborationExecutionApiEnvelope<T>(
  value: unknown,
  expectedResourceKind: CollaborationExecutionApiResourceKind,
  parsePayload: (payload: unknown) => T,
): CollaborationExecutionApiEnvelope<T> {
  const envelope = record(value, "Collaboration execution API envelope");
  exactKeys(envelope, [
    "surface",
    "schema_version",
    "resource_kind",
    "payload",
    "worker_capability",
    "queue_control",
  ], "Collaboration execution API envelope");
  literal(
    envelope.surface,
    "collaboration_execution_api_envelope",
    "Collaboration execution API envelope surface",
  );
  literal(
    envelope.schema_version,
    1,
    "Collaboration execution API envelope schema",
  );
  const resourceKind = literal(
    envelope.resource_kind,
    expectedResourceKind,
    "Collaboration execution API resource kind",
  );
  const workerCapability = parseCollaborationExecutionWorkerCapability(
    envelope.worker_capability,
  );
  const queue = record(
    envelope.queue_control,
    "Collaboration execution queue control",
  );
  exactKeys(queue, [
    "queue_control_plane_available",
    "queued_not_executable",
    "onchain_reservation_ready",
    "fresh_worker_presence_proven",
    "api_worker_wiring_claimed",
  ], "Collaboration execution queue control");
  const reservationReady = workerCapability.onchain_reservation_ready;
  const queueAvailable = literal(
    queue.queue_control_plane_available,
    workerCapability.queue_control_plane_available,
    "Collaboration execution queue availability",
  );
  const queuedNotExecutable = literal(
    queue.queued_not_executable,
    !reservationReady,
    "Collaboration execution queued-work gate",
  );
  const projectedReservationReady = literal(
    queue.onchain_reservation_ready,
    reservationReady,
    "Collaboration execution reservation gate",
  );
  const freshWorkerPresence = literal(
    queue.fresh_worker_presence_proven,
    reservationReady,
    "Collaboration execution worker-presence projection",
  );
  const apiWorkerWiringClaimed = literal(
    queue.api_worker_wiring_claimed,
    reservationReady,
    "Collaboration execution worker-wiring projection",
  );
  return Object.freeze({
    surface: "collaboration_execution_api_envelope" as const,
    schema_version: 1 as const,
    resource_kind: resourceKind,
    payload: parsePayload(envelope.payload),
    worker_capability: workerCapability,
    queue_control: Object.freeze({
      queue_control_plane_available: queueAvailable,
      queued_not_executable: queuedNotExecutable,
      onchain_reservation_ready: projectedReservationReady,
      fresh_worker_presence_proven: freshWorkerPresence,
      api_worker_wiring_claimed: apiWorkerWiringClaimed,
      // A capability envelope is authenticated worker/QVL reachability state,
      // never a per-job TDX quote or QVL verdict.
      clientProjectionIsJobAttestation: false as const,
    }),
  });
}

export interface CollaborationExecutionWorkerReleaseExpectation {
  readonly releaseSha: string;
  readonly releaseVerificationSha256: string;
  readonly deploymentIntentSha256: string;
  readonly releaseAuthoritySha256: string;
  readonly ceremonyNonce: string;
  readonly mainRuntimeCvmId: string;
  readonly mainRuntimeComposeHash: string;
  readonly mainRuntimeAppId: string;
  readonly mainRuntimeOsImageHash: string;
  readonly royaltyDistributorAddress: string;
  readonly computeVaultAddress: string;
  readonly computeVaultRuntimeCodeHash: string;
  readonly royaltyReleaseBindingCommitment?: string;
}

export function assertCollaborationExecutionWorkerCapabilityMatchesRelease(
  capability: CollaborationExecutionWorkerCapability,
  expected: CollaborationExecutionWorkerReleaseExpectation,
  nowMs = Date.now(),
): void {
  const binding = capability.release_binding;
  const observedAtMs = capability.heartbeat_observed_at === null
    ? undefined
    : capability.heartbeat_observed_at * 1_000;
  const qvlObservedAtMs = capability.qvl_capability.observed_at === null
    ? undefined
    : capability.qvl_capability.observed_at * 1_000;
  const qvlExpiresAtMs = capability.qvl_capability.expires_at === null
    ? undefined
    : capability.qvl_capability.expires_at * 1_000;
  if (
    capability.status !== "live"
    || capability.gate_reason !== "ready"
    || capability.execution_enabled !== true
    || capability.queue_control_plane_available !== true
    || capability.queued_work_executable !== true
    || capability.onchain_reservation_ready !== true
    || capability.worker_connected !== true
    || capability.freshness !== "fresh"
    || capability.evidence_authenticity !== "hmac_verified"
    || capability.evidence_classification
      !== COLLABORATION_EXECUTION_WORKER_EVIDENCE_CLASSIFICATION
    || capability.real_dstack !== true
    || capability.simulator !== false
    || capability.tdx_job_attestation_proven !== false
    || capability.qvl_job_verdict_proven !== false
    || capability.qvl_capability.configuration !== "complete"
    || capability.qvl_capability.reachability
      !== "authenticated_exact_capability"
    || capability.qvl_capability.observation_sha256 === null
    || capability.qvl_capability.profile
      !== COLLABORATION_EXECUTION_QVL_PROFILE
    || capability.qvl_capability.royalty_authorization_schema
      !== COLLABORATION_EXECUTION_QVL_AUTHORIZATION_SCHEMA
    || capability.qvl_capability.per_job_qvl_required !== true
    || capability.qvl_capability.per_job_qvl_verified !== false
    || !binding
    || observedAtMs === undefined
    || qvlObservedAtMs === undefined
    || qvlExpiresAtMs === undefined
    || !Number.isFinite(nowMs)
    || observedAtMs > nowMs + 5_000
    || nowMs - observedAtMs > 300_000
    || qvlObservedAtMs > nowMs + 5_000
    || nowMs - qvlObservedAtMs > 300_000
    || qvlExpiresAtMs <= nowMs
  ) throw new Error("Fresh authenticated Collaboration worker presence is unavailable");
  if (
    binding.release_git_sha !== expected.releaseSha.toLowerCase()
    || binding.release_verification_sha256
      !== expected.releaseVerificationSha256.toLowerCase()
    || binding.deployment_intent_sha256
      !== expected.deploymentIntentSha256.toLowerCase()
    || binding.release_authority_sha256
      !== expected.releaseAuthoritySha256.toLowerCase()
    || binding.ceremony_nonce !== expected.ceremonyNonce.toLowerCase()
    || binding.main_runtime_cvm_id !== expected.mainRuntimeCvmId
    || binding.main_runtime_compose_hash
      !== expected.mainRuntimeComposeHash.toLowerCase()
    || binding.main_runtime_app_id !== expected.mainRuntimeAppId.toLowerCase()
    || binding.main_runtime_os_image_hash
      !== expected.mainRuntimeOsImageHash.toLowerCase()
    || binding.royalty_distributor_address
      !== expected.royaltyDistributorAddress.toLowerCase()
    || binding.compute_vault_address
      !== expected.computeVaultAddress.toLowerCase()
    || binding.compute_vault_runtime_code_hash
      !== expected.computeVaultRuntimeCodeHash.toLowerCase()
    || (expected.royaltyReleaseBindingCommitment !== undefined
      && binding.royalty_release_binding_commitment
        !== expected.royaltyReleaseBindingCommitment.toLowerCase())
  ) throw new Error("Collaboration worker presence belongs to another release");
}

export function assertCollaborationExecutionWorkerCapabilityMatchesCurrentRelease(
  capability: CollaborationExecutionWorkerCapability,
  plan?: CollaborationExecutionPlanProjection,
  nowMs = Date.now(),
): void {
  const release = deployment.collaborationExecutionRelease;
  const trust = computeWorkloadDeployment.trustPolicy;
  if (
    !release.configured
    || !release.executionEnabled
    || !release.releaseSha
    || !release.releaseVerificationSha256
    || !release.mainRuntimeCvmId
    || !trust
    || !deployment.composeHash
    || !deployment.appId
    || !deployment.osImageHash
    || !deployment.royaltyDistributorAddress
    || !computeVaultDeployment.address
    || !computeVaultDeployment.codeHash
  ) throw new Error("Current Collaboration worker release is not configured");
  assertCollaborationExecutionWorkerCapabilityMatchesRelease(capability, {
    releaseSha: release.releaseSha,
    releaseVerificationSha256: release.releaseVerificationSha256,
    deploymentIntentSha256: trust.deploymentIntentSha256,
    releaseAuthoritySha256: trust.releaseAuthoritySha256,
    ceremonyNonce: trust.ceremonyNonce,
    mainRuntimeCvmId: release.mainRuntimeCvmId,
    mainRuntimeComposeHash: deployment.composeHash,
    mainRuntimeAppId: deployment.appId,
    mainRuntimeOsImageHash: deployment.osImageHash,
    royaltyDistributorAddress: deployment.royaltyDistributorAddress,
    computeVaultAddress: computeVaultDeployment.address,
    computeVaultRuntimeCodeHash: computeVaultDeployment.codeHash,
    royaltyReleaseBindingCommitment:
      plan?.royalty_release_binding_commitment,
  }, nowMs);
}

export function parseCollaborationExecutionRoyaltyReservation(
  value: unknown,
): CollaborationExecutionRoyaltyReservationProjection {
  const reservation = record(value, "Collaboration Royalty reservation");
  exactKeys(reservation, [
    "schema",
    "chain_id",
    "distributor_address",
    "sponsor_address",
    "reservation_id",
    "request",
    "transaction",
    "derived_after_fresh_owner_grants",
    "client_supplied_reservation_id",
    "balance_or_allowance_is_not_authorization",
  ], "Collaboration Royalty reservation");
  literal(
    reservation.schema,
    "dnai.collaboration.royalty-funding-reservation.v1",
    "Collaboration Royalty reservation schema",
  );
  literal(reservation.chain_id, 84_532, "Collaboration Royalty reservation chain");
  const distributor = address(
    reservation.distributor_address,
    "Collaboration Royalty reservation distributor",
  );
  const sponsor = address(
    reservation.sponsor_address,
    "Collaboration Royalty reservation sponsor",
  );
  const requestValue = record(
    reservation.request,
    "Collaboration Royalty funding request",
  );
  exactKeys(requestValue, [
    "settlement_id",
    "settlement_nonce",
    "release_policy_commitment",
    "room_commitment",
    "room_state_commitment",
    "query_commitment",
    "grant_set_commitment",
    "allocation_commitment",
    "owners_amounts_hash",
    "asset",
    "total",
    "execution_commitment",
    "refund_after",
  ], "Collaboration Royalty funding request");
  const request = Object.freeze({
    settlement_id: patterned(requestValue.settlement_id, BYTES32, "Royalty settlement ID", 66),
    settlement_nonce: canonicalUintString(requestValue.settlement_nonce, "Royalty settlement nonce"),
    release_policy_commitment: patterned(requestValue.release_policy_commitment, BYTES32, "Royalty release policy", 66),
    room_commitment: patterned(requestValue.room_commitment, BYTES32, "Royalty room commitment", 66),
    room_state_commitment: patterned(requestValue.room_state_commitment, BYTES32, "Royalty room-state commitment", 66),
    query_commitment: patterned(requestValue.query_commitment, BYTES32, "Royalty query commitment", 66),
    grant_set_commitment: patterned(requestValue.grant_set_commitment, BYTES32, "Royalty execution grant set", 66),
    allocation_commitment: patterned(requestValue.allocation_commitment, BYTES32, "Royalty allocation commitment", 66),
    owners_amounts_hash: patterned(requestValue.owners_amounts_hash, BYTES32, "Royalty owner amounts", 66),
    asset: address(requestValue.asset, "Royalty reservation asset"),
    total: canonicalUintString(requestValue.total, "Royalty reservation total"),
    execution_commitment: patterned(requestValue.execution_commitment, BYTES32, "Royalty execution commitment", 66),
    refund_after: canonicalUintString(
      requestValue.refund_after,
      "Royalty reservation refund time",
    ),
  });
  const transactionValue = record(
    reservation.transaction,
    "Collaboration Royalty reservation transaction",
  );
  const zeroAddress = `0x${"0".repeat(40)}`;
  const native = request.asset === zeroAddress;
  let walletActionReady = false;
  let transaction:
    CollaborationExecutionFundingReservationTransactionProjection;
  if ("schema" in transactionValue || "status" in transactionValue) {
    exactKeys(transactionValue, [
      "schema",
      "status",
      "reason",
      "executable",
      "wallet_transaction_included",
      "erc20_approval_included",
    ], "Collaboration Royalty gated wallet action");
    transaction = Object.freeze({
      schema: literal(
        transactionValue.schema,
        "dnai.collaboration.royalty-funding-action-gated.v1",
        "Collaboration Royalty gated action schema",
      ),
      status: literal(
        transactionValue.status,
        "gated_worker_presence_required",
        "Collaboration Royalty gated action status",
      ),
      reason: literal(
        transactionValue.reason,
        "fresh_authenticated_worker_and_qvl_capability_required",
        "Collaboration Royalty gated action reason",
      ),
      executable: literal(
        transactionValue.executable,
        false,
        "Collaboration Royalty gated action executable boundary",
      ),
      wallet_transaction_included: literal(
        transactionValue.wallet_transaction_included,
        false,
        "Collaboration Royalty gated action inclusion boundary",
      ),
      erc20_approval_included: literal(
        transactionValue.erc20_approval_included,
        false,
        "Collaboration Royalty gated approval boundary",
      ),
    });
  } else {
    exactKeys(transactionValue, [
      "to",
      "function_name",
      "abi_signature",
      "calldata",
      "value",
      "erc20_approval_required",
      "erc20_approval",
    ], "Collaboration Royalty reservation transaction");
    const functionName = choice(
      transactionValue.function_name,
      ["reserveNative", "reserveERC20"] as const,
      "Collaboration Royalty reservation function",
    );
    if ((native && functionName !== "reserveNative") || (!native && functionName !== "reserveERC20")) {
      throw new Error("Collaboration Royalty reservation function does not match its asset");
    }
    const transactionTo = address(
      transactionValue.to,
      "Collaboration Royalty reservation transaction target",
    );
    if (transactionTo !== distributor) {
      throw new Error("Collaboration Royalty reservation transaction target changed");
    }
    const calldata = patterned(
      transactionValue.calldata,
      /^0x[0-9a-f]+$/,
      "Collaboration Royalty reservation calldata",
      8_192,
    );
    if (calldata.length % 2 !== 0 || calldata.length < 10) {
      throw new Error("Collaboration Royalty reservation calldata is invalid");
    }
    const transactionAmount = transactionValue.value === "0"
      ? "0"
      : canonicalUintString(
          transactionValue.value,
          "Collaboration Royalty reservation transaction value",
        );
    const expectedAbiSignature = `${functionName}((bytes32,uint256,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,address,uint256,bytes32,uint64))`;
    literal(
      transactionValue.abi_signature,
      expectedAbiSignature,
      "Collaboration Royalty reservation ABI signature",
    );
    let approval:
      CollaborationExecutionFundingReservationReadyTransactionProjection["erc20_approval"] = null;
    if (native) {
      literal(transactionValue.erc20_approval_required, false, "Native Royalty approval boundary");
      literal(transactionValue.erc20_approval, null, "Native Royalty approval terms");
      if (transactionAmount !== request.total) {
        throw new Error("Native Royalty reservation value changed");
      }
    } else {
      literal(transactionValue.erc20_approval_required, true, "ERC20 Royalty approval requirement");
      const approvalValue = record(
        transactionValue.erc20_approval,
        "Collaboration Royalty ERC20 approval",
      );
      exactKeys(approvalValue, [
        "token_address",
        "spender",
        "minimum_amount",
      ], "Collaboration Royalty ERC20 approval");
      approval = Object.freeze({
        token_address: address(approvalValue.token_address, "Royalty approval token"),
        spender: address(approvalValue.spender, "Royalty approval spender"),
        minimum_amount: canonicalUintString(approvalValue.minimum_amount, "Royalty approval amount"),
      });
      if (
        transactionAmount !== "0"
        || approval.token_address !== request.asset
        || approval.spender !== distributor
        || approval.minimum_amount !== request.total
      ) throw new Error("Collaboration Royalty ERC20 approval terms changed");
    }
    transaction = Object.freeze({
      to: transactionTo,
      function_name: functionName,
      abi_signature: expectedAbiSignature,
      calldata,
      value: transactionAmount,
      erc20_approval_required: !native,
      erc20_approval: approval,
    });
    walletActionReady = true;
  }
  const parsedReservation = Object.freeze({
    schema: "dnai.collaboration.royalty-funding-reservation.v1" as const,
    chain_id: 84_532 as const,
    distributor_address: distributor,
    sponsor_address: sponsor,
    reservation_id: patterned(
      reservation.reservation_id,
      BYTES32,
      "Collaboration Royalty reservation ID",
      66,
    ),
    request,
    transaction,
    derived_after_fresh_owner_grants: literal(
      reservation.derived_after_fresh_owner_grants,
      true,
      "Collaboration Royalty reservation derivation order",
    ),
    client_supplied_reservation_id: literal(
      reservation.client_supplied_reservation_id,
      false,
      "Collaboration Royalty reservation ID source",
    ),
    balance_or_allowance_is_not_authorization: literal(
      reservation.balance_or_allowance_is_not_authorization,
      true,
      "Collaboration Royalty balance and allowance boundary",
    ),
    walletActionReady,
    finalizedReservationObservedInBrowser: false as const,
    mayUnlockExecutionControls: false as const,
  });
  verifyCollaborationFundingReservationProjection(parsedReservation);
  return parsedReservation;
}

export function parseCollaborationExecutionAuthorizationResult(
  value: unknown,
): CollaborationExecutionAuthorizationResult {
  const result = record(value, "Collaboration execution authorization result");
  exactKeys(result, [
    "surface",
    "schema_version",
    "created",
    "idempotent_replay",
    "verifier_kinds",
    "raw_signatures_retained",
    "query_grants_reused_as_execution_grants",
    "provider_dispatch_performed",
    "execution",
    "authorization_commitment",
    "royalty_reservation",
  ], "Collaboration execution authorization result");
  literal(result.surface, "collaboration_execution_authorization_result", "Collaboration execution authorization surface");
  literal(result.schema_version, 2, "Collaboration execution authorization schema");
  const created = bool(result.created, "Collaboration execution creation state");
  const replay = bool(result.idempotent_replay, "Collaboration execution replay state");
  if (created === replay) throw new Error("Collaboration execution creation state is contradictory");
  if (!Array.isArray(result.verifier_kinds) || result.verifier_kinds.length < 1) {
    throw new Error("Collaboration execution verifier kinds are invalid");
  }
  const verifierKinds = Object.freeze(result.verifier_kinds.map((item) => (
    choice(item, ["eoa", "eip1271"] as const, "Collaboration execution verifier kind")
  )));
  if (new Set(verifierKinds).size !== verifierKinds.length) {
    throw new Error("Collaboration execution verifier kinds are not canonical");
  }
  const execution = parseCollaborationExecutionStatusRecord(result.execution, false);
  const authorizationCommitment = commitment(result.authorization_commitment, "Collaboration execution authorization");
  const royaltyReservation = parseCollaborationExecutionRoyaltyReservation(
    result.royalty_reservation,
  );
  const executionIntentBytes32 = `0x${execution.intent_commitment.slice(7)}`;
  if (
    execution.authorization_commitment !== authorizationCommitment
    || executionIntentBytes32 !== royaltyReservation.request.execution_commitment
  ) {
    throw new Error("Collaboration execution authorization result changed");
  }
  return Object.freeze({
    surface: "collaboration_execution_authorization_result" as const,
    schema_version: 2 as const,
    created,
    idempotent_replay: replay,
    verifier_kinds: verifierKinds,
    raw_signatures_retained: literal(result.raw_signatures_retained, false, "Collaboration raw-signature boundary"),
    query_grants_reused_as_execution_grants: literal(result.query_grants_reused_as_execution_grants, false, "Collaboration execution-grant boundary"),
    provider_dispatch_performed: literal(result.provider_dispatch_performed, false, "Collaboration authorization dispatch state"),
    authorization_commitment: authorizationCommitment,
    royalty_reservation: royaltyReservation,
    royaltyReservationFinalizedInBrowser: false as const,
    royaltyReservationMayUnlockExecutionControls: false as const,
    execution,
  });
}

export async function createCollaborationExecutionPlan(
  token: string,
  runId: string,
  input: CollaborationExecutionPlanRequest,
  expectedRequesterAddress?: string,
  signal?: AbortSignal,
  expectedContext?: {
    readonly room: CollaborationRoom;
    readonly jointRun: CollaborationJointRun;
  },
): Promise<CollaborationExecutionPlanProjection> {
  patterned(runId, RUN_ID, "Collaboration run ID", 36);
  assertCollaborationExecutionPlanRequest(input, expectedRequesterAddress);
  const envelope = parseCollaborationExecutionApiEnvelope(await request(
    `/collaboration/runs/${encodeURIComponent(runId)}/execution-plans`,
    { method: "POST", token, body: { ...input }, signal },
  ), "execution_plan", (payload) => (
    parseCollaborationExecutionPlan(payload, input)
  ));
  const plan = envelope.payload;
  if (plan.run_id !== runId) {
    throw new Error("Collaboration service planned a different joint run");
  }
  assertCollaborationExecutionPlanMatchesCurrentRelease(plan);
  if (expectedContext) {
    assertCollaborationExecutionPlanMatchesJointRun(
      plan,
      expectedContext.jointRun,
      expectedContext.room,
    );
  }
  return plan;
}

export async function issueCollaborationExecutionGrantChallenge(
  token: string,
  planToken: string,
  signal?: AbortSignal,
): Promise<CollaborationExecutionGrantChallenge> {
  const normalizedToken = boundedExecutionToken(planToken, "Collaboration execution plan token");
  return parseCollaborationExecutionGrantChallenge(await request(
    "/collaboration/execution-plans/grant-challenges",
    { method: "POST", token, body: { plan_token: normalizedToken }, signal },
  ));
}

export async function authorizeCollaborationExecution(
  token: string,
  input: {
    readonly plan_token: string;
    readonly idempotency_key: string;
    readonly grants: readonly CollaborationExecutionGrantSubmission[];
  },
  signal?: AbortSignal,
  expectedPlan?: CollaborationExecutionPlanProjection,
): Promise<CollaborationExecutionAuthorizationResult> {
  const normalized = record(input, "Collaboration execution authorization request");
  exactKeys(normalized, ["plan_token", "idempotency_key", "grants"], "Collaboration execution authorization request");
  boundedExecutionToken(normalized.plan_token, "Collaboration execution plan token");
  patterned(normalized.idempotency_key, IDEMPOTENCY_KEY, "Collaboration execution idempotency key", 128);
  if (!Array.isArray(normalized.grants) || normalized.grants.length < 1 || normalized.grants.length > MAX_ROOM_OWNERS) {
    throw new Error("Collaboration execution grants are invalid");
  }
  for (const item of normalized.grants) {
    const grant = record(item, "Collaboration execution grant submission");
    exactKeys(grant, ["challenge_token", "signature"], "Collaboration execution grant submission");
    boundedExecutionToken(grant.challenge_token, "Collaboration execution challenge token");
    assertSignature(String(grant.signature), "Collaboration execution grant signature");
  }
  const envelope = parseCollaborationExecutionApiEnvelope(await request(
    "/collaboration/execution-plans/authorize",
    { method: "POST", token, body: input, signal },
  ), "execution_authorization", parseCollaborationExecutionAuthorizationResult);
  if (
    envelope.payload.royalty_reservation.walletActionReady
      !== envelope.queue_control.onchain_reservation_ready
  ) throw new Error(
    "Collaboration Royalty wallet action does not match the authenticated capability gate",
  );
  if (expectedPlan) {
    assertCollaborationExecutionAuthorizationMatchesPlan(
      envelope.payload,
      expectedPlan,
    );
  }
  return envelope.payload;
}

export async function fetchCollaborationExecutionWorkerCapability(
  token: string,
  signal?: AbortSignal,
): Promise<CollaborationExecutionWorkerCapability> {
  return parseCollaborationExecutionWorkerCapability(await request(
    "/collaboration/execution-capability",
    { token, signal },
  ));
}

export async function fetchCollaborationExecutionStatusEnvelope(
  token: string,
  executionId: string,
  signal?: AbortSignal,
): Promise<CollaborationExecutionApiEnvelope<CollaborationExecutionStatusProjection>> {
  patterned(executionId, EXECUTION_ID, "Collaboration execution ID", 69);
  const envelope = parseCollaborationExecutionApiEnvelope(await request(
    `/collaboration/executions/${encodeURIComponent(executionId)}`,
    { token, signal },
  ), "execution_status", parseCollaborationExecutionStatus);
  const execution = envelope.payload;
  if (execution.execution_id !== executionId) {
    throw new Error("Collaboration service returned a different execution");
  }
  if (
    execution.royalty_reservation.walletActionReady
      !== envelope.queue_control.onchain_reservation_ready
  ) throw new Error(
    "Collaboration status reservation does not match the authenticated capability gate",
  );
  return envelope;
}

export async function fetchCollaborationExecutionStatus(
  token: string,
  executionId: string,
  signal?: AbortSignal,
): Promise<CollaborationExecutionStatusProjection> {
  return (
    await fetchCollaborationExecutionStatusEnvelope(token, executionId, signal)
  ).payload;
}
