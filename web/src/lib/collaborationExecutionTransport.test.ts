import { sha256, zeroAddress, type Address, type Hex } from "viem";
import { describe, expect, it } from "vitest";

import {
  assertCollaborationExecutionAuthorizationMatchesPlan,
  assertCollaborationExecutionPlanMatchesJointRun,
  assertCollaborationExecutionPlanRequest,
  assertCollaborationExecutionPlanMatchesRelease,
  assertCollaborationExecutionWorkerCapabilityMatchesRelease,
  parseCollaborationExecutionApiEnvelope,
  parseCollaborationExecutionPlan,
  parseCollaborationExecutionRoyaltyReservation,
  parseCollaborationExecutionWorkerCapability,
  type CollaborationExecutionAuthorizationResult,
  type CollaborationExecutionPlanProjection,
  type CollaborationExecutionPlanRequest,
  type CollaborationJointRun,
  type CollaborationRoom,
  type CollaborationSession,
} from "./collaboration";
import {
  COLLABORATION_EXECUTION_API_CONTRACT,
  collaborationExecutionClientDtoEvidenceBoundary,
  collaborationExecutionTransportAdapter,
  collaborationExecutionTransportGate,
} from "./collaborationExecutionTransport";
import collaborationSource from "./collaboration.ts?raw";
import {
  collaborationFundingReservationCall,
  collaborationFundingReservationId,
  type CollaborationFundingReservationRequest,
} from "./collaborationRoyaltyReservation";
import { pythonCanonicalJson } from "./policyCommitments";

const WALLET = `0x${"1".repeat(40)}`;

function planRequest(): CollaborationExecutionPlanRequest {
  const projection: CollaborationExecutionPlanRequest = {
    compute_project_id: `0x${"1".repeat(64)}`,
    compute_job_id: `0x${"2".repeat(64)}`,
    compute_workload_id: `wrk_${"3".repeat(32)}`,
    compute_workload_commitment: `0x${"4".repeat(64)}`,
    compute_manifest_commitment: `0x${"5".repeat(64)}`,
    compute_rate_policy_commitment: `0x${"6".repeat(64)}`,
    compute_workload_schema: "dnai.compute.workload.inference.v1",
    compute_workload_source_kind: "wallet",
    compute_workload_execution_binding_commitment: `sha256:${"7".repeat(64)}`,
    compute_workload_recipient_release_commitment: `sha256:${"8".repeat(64)}`,
    compute_user_address: WALLET,
    operation: "inference",
    model: "qwen3_8b",
    recipe: "qwen3_8b_bounded",
    result_policy: "score_band_hash",
    max_prefill_tokens: 2_048,
    max_sample_tokens: 512,
    max_train_tokens: 0,
    sponsor_address: WALLET,
    asset: `0x${"9".repeat(40)}`,
    max_total_asset_debit: 10_000,
    max_compute_asset_debit: 7_000,
    authorization_nonce: 11,
    authorization_lifetime_seconds: 600,
    royalty_total: 2_000,
  };
  return projection;
}

function currentSession(): CollaborationSession {
  return {
    accessToken: `${"a".repeat(40)}.${"b".repeat(40)}.${"c".repeat(40)}`,
    address: WALLET,
    issuedAt: 1_900_000_000,
    expiresAt: 1_900_000_600,
    walletAuthorizationVersion: 4,
  };
}

function serverPlanProjection() {
  const sha = (character: string) => `sha256:${character.repeat(64)}`;
  const word = (character: string) => `0x${character.repeat(64)}`;
  const ownerAddresses = [WALLET];
  const royaltyRelease = sha("d");
  const royaltyDistributor = `0x${"8".repeat(40)}`;
  const royaltyReleasePolicy = word("e");
  const royaltySettlementId = word("f");
  const projection = {
    surface: "collaboration_execution_plan",
    schema_version: 2,
    run_id: `run_${"a".repeat(32)}`,
    room_id: `room_${"b".repeat(32)}`,
    requester_address: WALLET,
    basis: {
      schema: "dnai.collaboration.execution-basis.v2",
      release_git_sha: "a".repeat(40),
      release_verification_sha256: sha("1"),
      chain_id: 84_532,
      cvm_id: "cvm-main-runtime-0001",
      compose_hash: word("2"),
      room_id: `room_${"b".repeat(32)}`,
      room_commitment: sha("3"),
      room_generation: 4,
      room_state_commitment: sha("4"),
      query_ref: sha("5"),
      query_proposal_commitment: sha("6"),
      prospective_query_grant_set_commitment: sha("7"),
      joint_consent_snapshot_commitment: sha("8"),
      allocation_commitment: sha("9"),
      owner_addresses: ownerAddresses,
      compute_project_id: word("1"),
      compute_job_id: word("2"),
      compute_workload_id: `wrk_${"3".repeat(32)}`,
      compute_workload_commitment: word("4"),
      compute_manifest_commitment: word("5"),
      compute_rate_policy_commitment: word("6"),
      compute_workload_schema: "dnai.compute.workload.inference.v1",
      compute_workload_source_kind: "wallet",
      compute_workload_execution_binding_commitment: sha("7"),
      compute_workload_recipient_release_commitment: sha("8"),
      compute_vault_address: `0x${"2".repeat(40)}`,
      compute_vault_runtime_code_hash: word("7"),
      compute_finality_model: "single_rpc_reported_finalized",
      compute_user_address: WALLET,
      operation: "inference",
      model: "qwen3_8b",
      recipe: "qwen3_8b_bounded",
      result_policy: "score_band_hash",
      max_prefill_tokens: 2_048,
      max_sample_tokens: 512,
      max_train_tokens: 0,
      sponsor_address: WALLET,
      asset: `0x${"9".repeat(40)}`,
      max_total_asset_debit: 10_000,
      max_compute_asset_debit: 7_000,
      authorization_nonce: 11,
      authorization_expiry: 1_900_000_600,
      royalty_asset: `0x${"9".repeat(40)}`,
      royalty_total: 2_000,
      royalty_owner_amounts_hash: word("c"),
      royalty_distributor_address: royaltyDistributor,
      royalty_release_policy_commitment: royaltyReleasePolicy,
      royalty_release_binding_commitment: royaltyRelease,
      royalty_settlement_id: royaltySettlementId,
      royalty_settlement_nonce: "17",
      royalty_reservation_safety_seconds: 900,
      intent_created_at: 1_900_000_000,
    },
    basis_commitment: "",
    owner_addresses: ownerAddresses,
    royalty_owner_amounts_hash: word("c"),
    royalty_distributor_address: royaltyDistributor,
    royalty_release_policy_commitment: royaltyReleasePolicy,
    royalty_release_binding_commitment: royaltyRelease,
    royalty_settlement_id: royaltySettlementId,
    royalty_settlement_nonce: "17",
    royalty_reservation_safety_seconds: 900,
    royalty_authority_server_derived: true,
    royalty_reservation_is_derived_after_fresh_owner_grants: true,
    royalty_reservation_must_be_deposited_onchain_after_authorization: true,
    plan_token: `${"a".repeat(40)}.${"b".repeat(40)}`,
    plan_token_contains_bounded_metadata_only: true,
    requires_fresh_execution_grant_from_every_owner: true,
    query_grants_are_not_execution_grants: true,
    provider_dispatch_performed: false,
    raw_signature_retained: false,
    raw_query_egress: false,
    raw_artifact_egress: false,
  };
  projection.basis_commitment = workerCommitment(
    "dnai-wikigen/collaboration-execution-basis/v2\0",
    projection.basis,
  );
  return projection;
}

function workerCommitment(domain: string, value: unknown): string {
  const encoder = new TextEncoder();
  const domainBytes = encoder.encode(domain);
  const valueBytes = encoder.encode(pythonCanonicalJson(value));
  const payload = new Uint8Array(domainBytes.length + valueBytes.length);
  payload.set(domainBytes);
  payload.set(valueBytes, domainBytes.length);
  return `sha256:${sha256(payload).slice(2)}`;
}

function executionIdForIntent(intentCommitment: string): string {
  return `exec_${sha256(new TextEncoder().encode(
    `dnai-wikigen/collaboration-execution-id/v1\0${intentCommitment}`,
  )).slice(2)}`;
}

function authorizationForPlan(
  plan: CollaborationExecutionPlanProjection,
): CollaborationExecutionAuthorizationResult {
  const intentCommitment = `sha256:${"b".repeat(64)}`;
  const executionId = executionIdForIntent(intentCommitment);
  const grantSetCommitment = `sha256:${"a".repeat(64)}`;
  const authorizationCommitment = workerCommitment(
    "dnai-wikigen/collaboration-execution-authorization/v1\0",
    {
      schema: "dnai.collaboration.execution-authorization.v1",
      execution_id: executionId,
      intent_commitment: intentCommitment,
      execution_basis_commitment: plan.basis_commitment,
      execution_grant_set_commitment: grantSetCommitment,
    },
  );
  return {
    authorization_commitment: authorizationCommitment,
    execution: {
      execution_id: executionId,
      room_id: plan.room_id,
      intent_commitment: intentCommitment,
      authorization_commitment: authorizationCommitment,
      execution_grant_set_commitment: grantSetCommitment,
      owner_execution_grant_count: plan.owner_addresses.length,
    },
    royalty_reservation: {
      chain_id: 84_532,
      distributor_address: plan.royalty_distributor_address,
      sponsor_address: plan.sponsor_address,
      request: {
        settlement_id: plan.royalty_settlement_id,
        settlement_nonce: plan.royalty_settlement_nonce,
        release_policy_commitment:
          plan.royalty_release_policy_commitment,
        room_commitment: `0x${plan.room_commitment.slice(7)}`,
        room_state_commitment: `0x${plan.room_state_commitment.slice(7)}`,
        query_commitment: `0x${plan.query_proposal_commitment.slice(7)}`,
        grant_set_commitment: `0x${grantSetCommitment.slice(7)}`,
        allocation_commitment: `0x${plan.allocation_commitment.slice(7)}`,
        owners_amounts_hash: plan.royalty_owner_amounts_hash,
        asset: plan.asset,
        total: plan.royalty_total,
        execution_commitment: `0x${intentCommitment.slice(7)}`,
        refund_after: String(
          plan.authorization_expiry
            + plan.royalty_reservation_safety_seconds,
        ),
      },
    },
  } as unknown as CollaborationExecutionAuthorizationResult;
}

function liveWorkerCapability(observedAt = 1_900_000_000) {
  const qvlObservationSha256 = `sha256:${"c".repeat(64)}`;
  const releaseBinding = {
    release_git_sha: "a".repeat(40),
    release_verification_sha256: `sha256:${"1".repeat(64)}`,
    deployment_intent_sha256: `sha256:${"2".repeat(64)}`,
    release_authority_sha256: `sha256:${"3".repeat(64)}`,
    ceremony_nonce: `0x${"4".repeat(64)}`,
    main_runtime_cvm_id: "cvm-main-runtime-0001",
    main_runtime_compose_hash: `0x${"5".repeat(64)}`,
    main_runtime_app_id: "6".repeat(40),
    main_runtime_os_image_hash: "7".repeat(64),
    royalty_release_binding_commitment: `sha256:${"8".repeat(64)}`,
    royalty_distributor_address: `0x${"9".repeat(40)}`,
    compute_vault_address: `0x${"a".repeat(40)}`,
    compute_vault_runtime_code_hash: `0x${"b".repeat(64)}`,
    chain_id: 84_532,
    worker_service: "collaboration-execution-worker",
    worker_profile: "collaboration-execution",
  };
  const releaseBindingSha256 = workerCommitment(
    "dnai-wikigen/collaboration-execution-worker-release-binding/v1\0",
    {
      schema: "dnai.collaboration.execution-worker-release-binding.v1",
      release_binding: releaseBinding,
    },
  );
  const presenceBindingSha256 = workerCommitment(
    "dnai-wikigen/collaboration-execution-worker-presence-binding/v1\0",
    {
      schema: "dnai.collaboration.execution-worker-capability.v1",
      heartbeat_schema: "dnai.collaboration.execution-worker-heartbeat.v1",
      observed_at: observedAt,
      release_binding_sha256: releaseBindingSha256,
      evidence_classification:
        "authenticated_worker_presence_not_job_attestation",
      qvl_capability_observation_sha256: qvlObservationSha256,
    },
  );
  return {
    surface: "collaboration_execution_worker_capability",
    schema: "dnai.collaboration.execution-worker-capability.v1",
    status: "live",
    gate_reason: "ready",
    execution_enabled: true,
    queue_control_plane_available: true,
    queued_work_executable: true,
    onchain_reservation_ready: true,
    worker_connected: true,
    freshness: "fresh",
    evidence_authenticity: "hmac_verified",
    evidence_classification:
      "authenticated_worker_presence_not_job_attestation",
    heartbeat_observed_at: observedAt,
    presence_binding_sha256: presenceBindingSha256,
    release_binding_sha256: releaseBindingSha256,
    release_binding: releaseBinding,
    qvl_capability: {
      configuration: "complete",
      reachability: "authenticated_exact_capability",
      observation_sha256: qvlObservationSha256,
      observed_at: observedAt,
      expires_at: observedAt + 300,
      profile: "royalty_settlement",
      royalty_authorization_schema:
        "dnai.royalty-settlement-qvl-authorization-request.v2",
      per_job_qvl_required: true,
      per_job_qvl_verified: false,
    },
    real_dstack: true,
    simulator: false,
    tdx_job_attestation_proven: false,
    qvl_job_verdict_proven: false,
    warning: "Authenticated presence only; per-job TDX and QVL remain required.",
  };
}

function unavailableWorkerCapability() {
  return {
    ...liveWorkerCapability(),
    status: "unavailable",
    gate_reason: "heartbeat_stale",
    queued_work_executable: false,
    onchain_reservation_ready: false,
    worker_connected: false,
    freshness: "unavailable",
    evidence_authenticity: "unverified",
    heartbeat_observed_at: null,
    presence_binding_sha256: null,
    qvl_capability: {
      configuration: "unavailable",
      reachability: "unavailable",
      observation_sha256: null,
      observed_at: null,
      expires_at: null,
      profile: null,
      royalty_authorization_schema: null,
      per_job_qvl_required: true,
      per_job_qvl_verified: false,
    },
    real_dstack: false,
  };
}

describe("Collaboration execution transport", () => {
  it("exposes typed calls through the existing Collaboration API adapter", () => {
    expect(collaborationExecutionTransportAdapter.contract).toBe(
      COLLABORATION_EXECUTION_API_CONTRACT,
    );
    expect(collaborationExecutionTransportAdapter.createPlan).toBeTypeOf("function");
    expect(collaborationExecutionTransportAdapter.issueGrantChallenge).toBeTypeOf("function");
    expect(collaborationExecutionTransportAdapter.authorize).toBeTypeOf("function");
    expect(collaborationExecutionTransportAdapter.fetchWorkerCapability).toBeTypeOf("function");
    expect(collaborationExecutionTransportAdapter.fetchStatus).toBeTypeOf("function");
  });

  it("recomputes authenticated worker bindings while preserving the no-job-attestation boundary", () => {
    const capability = parseCollaborationExecutionWorkerCapability(
      liveWorkerCapability(),
    );
    expect(capability.status).toBe("live");
    expect(capability.evidence_classification).toBe(
      "authenticated_worker_presence_not_job_attestation",
    );
    expect(capability.clientProjectionIsJobAttestation).toBe(false);
    expect(capability.tdx_job_attestation_proven).toBe(false);
    expect(capability.qvl_job_verdict_proven).toBe(false);

    const binding = capability.release_binding!;
    expect(() => assertCollaborationExecutionWorkerCapabilityMatchesRelease(
      capability,
      {
        releaseSha: binding.release_git_sha,
        releaseVerificationSha256: binding.release_verification_sha256,
        deploymentIntentSha256: binding.deployment_intent_sha256,
        releaseAuthoritySha256: binding.release_authority_sha256,
        ceremonyNonce: binding.ceremony_nonce,
        mainRuntimeCvmId: binding.main_runtime_cvm_id,
        mainRuntimeComposeHash: binding.main_runtime_compose_hash,
        mainRuntimeAppId: binding.main_runtime_app_id,
        mainRuntimeOsImageHash: binding.main_runtime_os_image_hash,
        royaltyDistributorAddress: binding.royalty_distributor_address,
        computeVaultAddress: binding.compute_vault_address,
        computeVaultRuntimeCodeHash: binding.compute_vault_runtime_code_hash,
        royaltyReleaseBindingCommitment:
          binding.royalty_release_binding_commitment,
      },
      1_900_000_001_000,
    )).not.toThrow();
    expect(() => parseCollaborationExecutionWorkerCapability({
      ...liveWorkerCapability(),
      presence_binding_sha256: `sha256:${"f".repeat(64)}`,
    })).toThrow("does not recompute");
    expect(() => assertCollaborationExecutionWorkerCapabilityMatchesRelease(
      capability,
      {
        releaseSha: "f".repeat(40),
        releaseVerificationSha256: binding.release_verification_sha256,
        deploymentIntentSha256: binding.deployment_intent_sha256,
        releaseAuthoritySha256: binding.release_authority_sha256,
        ceremonyNonce: binding.ceremony_nonce,
        mainRuntimeCvmId: binding.main_runtime_cvm_id,
        mainRuntimeComposeHash: binding.main_runtime_compose_hash,
        mainRuntimeAppId: binding.main_runtime_app_id,
        mainRuntimeOsImageHash: binding.main_runtime_os_image_hash,
        royaltyDistributorAddress: binding.royalty_distributor_address,
        computeVaultAddress: binding.compute_vault_address,
        computeVaultRuntimeCodeHash: binding.compute_vault_runtime_code_hash,
      },
      1_900_000_001_000,
    )).toThrow("another release");
  });

  it("accepts only an exact capability-bound API envelope", () => {
    const value = {
      surface: "collaboration_execution_api_envelope",
      schema_version: 1,
      resource_kind: "execution_plan",
      payload: { marker: "strict" },
      worker_capability: unavailableWorkerCapability(),
      queue_control: {
        queue_control_plane_available: true,
        queued_not_executable: true,
        onchain_reservation_ready: false,
        fresh_worker_presence_proven: false,
        api_worker_wiring_claimed: false,
      },
    };
    const parsed = parseCollaborationExecutionApiEnvelope(
      value,
      "execution_plan",
      (payload) => payload as { marker: string },
    );
    expect(parsed.payload.marker).toBe("strict");
    expect(parsed.queue_control.queued_not_executable).toBe(true);
    expect(parsed.queue_control.clientProjectionIsJobAttestation).toBe(false);
    expect(() => parseCollaborationExecutionApiEnvelope(
      {
        ...value,
        queue_control: {
          ...value.queue_control,
          queued_not_executable: false,
        },
      },
      "execution_plan",
      (payload) => payload,
    )).toThrow("queued-work gate");
    expect(() => parseCollaborationExecutionApiEnvelope(
      value,
      "execution_status",
      (payload) => payload,
    )).toThrow("resource kind");
  });

  it("keeps calls closed when a live room, joint snapshot, or measured release is absent", () => {
    const gate = collaborationExecutionTransportGate({
      adapter: collaborationExecutionTransportAdapter,
      session: currentSession(),
      walletContext: {
        address: WALLET,
        chainId: 84_532,
        walletAuthorizationVersion: 4,
        nowMs: 1_899_999_000_000,
      },
    });

    expect(gate.apiContractWired).toBe(true);
    expect(gate.currentCollaborationSessionBound).toBe(true);
    expect(gate.selectedRoomBound).toBe(false);
    expect(gate.currentJointSnapshotBound).toBe(false);
    expect(gate.controlPlaneMutationCallsEnabled).toBe(false);
    expect(gate.reservationWriteEnabled).toBe(false);
    expect(gate.settlementWriteEnabled).toBe(false);
    expect(gate.modeledStateUsedForReadiness).toBe(false);
    expect(gate.blockers.join(" ")).toContain("participant-authenticated room");
  });

  it("rejects client-supplied room, owner, finality, and projection authority in a plan body", () => {
    const forbiddenFields = [
      "room_id",
      "owner_addresses",
      "finalized_vault_observation",
      "compute_journal_projection",
      "royalty_release_binding_commitment",
      "royalty_funding_authorization_commitment",
      "royalty_settlement_id",
      "royalty_settlement_nonce",
      "royalty_reservation_safety_seconds",
    ] as const;

    for (const field of forbiddenFields) {
      const forged: Record<string, unknown> = { ...planRequest() };
      forged[field] = field === "owner_addresses" ? [WALLET] : "forged";
      expect(
        () => assertCollaborationExecutionPlanRequest(forged, WALLET),
        field,
      ).toThrow("unexpected schema");
    }
  });

  it("accepts only matching server-derived Royalty reservation terms in a plan projection", () => {
    const parsed = parseCollaborationExecutionPlan(serverPlanProjection());

    expect(parsed.royalty_authority_server_derived).toBe(true);
    expect(
      parsed.royalty_reservation_must_be_deposited_onchain_after_authorization,
    ).toBe(true);
    expect(parsed.royalty_release_binding_commitment).toBe(
      serverPlanProjection().basis.royalty_release_binding_commitment,
    );
    expect(parsed.royalty_settlement_id).toBe(
      serverPlanProjection().basis.royalty_settlement_id,
    );
    expect(parsed.royalty_settlement_nonce).toBe("17");
    expect(parsed.royalty_reservation_safety_seconds).toBe(
      serverPlanProjection().basis.royalty_reservation_safety_seconds,
    );
    expect(() => parseCollaborationExecutionPlan({
      ...serverPlanProjection(),
      royalty_release_binding_commitment: `sha256:${"0".repeat(64)}`,
    })).toThrow();
    expect(() => parseCollaborationExecutionPlan({
      ...serverPlanProjection(),
      royalty_settlement_id: `0x${"0".repeat(64)}`,
    })).toThrow();
  });

  it("recomputes the exact canonical execution basis before accepting a plan", () => {
    const projection = serverPlanProjection();
    projection.basis.room_commitment = `sha256:${"0".repeat(64)}`;
    projection.room_id = projection.basis.room_id;
    expect(() => parseCollaborationExecutionPlan(projection)).toThrow(
      "basis commitment does not recompute",
    );
  });

  it("keeps uint256 settlement nonces exact beyond JavaScript's safe-integer range", () => {
    const hugeNonce = "340282366920938463463374607431768211457";
    const projection = serverPlanProjection();
    projection.basis.royalty_settlement_nonce = hugeNonce;
    projection.royalty_settlement_nonce = hugeNonce;
    projection.basis_commitment = workerCommitment(
      "dnai-wikigen/collaboration-execution-basis/v2\0",
      projection.basis,
    );
    expect(parseCollaborationExecutionPlan(projection).royalty_settlement_nonce)
      .toBe(hugeNonce);
    const invalidBasis = {
      ...projection.basis,
      royalty_settlement_nonce: 17,
    };
    expect(() => parseCollaborationExecutionPlan({
      ...projection,
      basis: invalidBasis,
      basis_commitment: workerCommitment(
        "dnai-wikigen/collaboration-execution-basis/v2\0",
        invalidBasis,
      ),
    })).toThrow("settlement nonce");
  });

  it("cross-checks requested terms and the current release before any owner signs", () => {
    const plan = parseCollaborationExecutionPlan(
      serverPlanProjection(),
      planRequest(),
    );
    expect(() => assertCollaborationExecutionPlanMatchesRelease(plan, {
      releaseSha: plan.release_git_sha,
      releaseVerificationSha256: plan.release_verification_sha256,
      mainRuntimeCvmId: plan.cvm_id,
      composeHash: plan.compose_hash,
      royaltyDistributorAddress: plan.royalty_distributor_address,
      royaltyReleasePolicyCommitment:
        plan.royalty_release_policy_commitment,
      walletAdoptionEnabled: false,
    })).not.toThrow();
    expect(() => parseCollaborationExecutionPlan(
      serverPlanProjection(),
      { ...planRequest(), max_compute_asset_debit: 6_999 },
    )).toThrow("changed the requested terms");
    expect(() => assertCollaborationExecutionPlanMatchesRelease(plan, {
      releaseSha: "f".repeat(40),
      releaseVerificationSha256: plan.release_verification_sha256,
      mainRuntimeCvmId: plan.cvm_id,
      composeHash: plan.compose_hash,
      royaltyDistributorAddress: plan.royalty_distributor_address,
      royaltyReleasePolicyCommitment:
        plan.royalty_release_policy_commitment,
      walletAdoptionEnabled: false,
    })).toThrow("current v4 release");
  });

  it("binds the selected joint snapshot and exact authorization commitment to one plan", () => {
    const plan = parseCollaborationExecutionPlan(serverPlanProjection());
    const room = {
      room_id: plan.room_id,
      room_commitment: plan.room_commitment,
      generation: plan.room_generation,
      lifecycle_status: "active",
      all_required_query_grants_current: true,
      current_query: {
        query_ref: plan.query_ref,
        proposal_commitment: plan.query_proposal_commitment,
      },
      owners: plan.owner_addresses.map((owner) => ({
        owner_address: owner,
        membership_status: "accepted",
        role_accepted: true,
      })),
    } as unknown as CollaborationRoom;
    const jointRun = {
      run_id: plan.run_id,
      room_id: plan.room_id,
      requester_address: plan.requester_address,
      room_commitment: plan.room_commitment,
      room_generation: plan.room_generation,
      room_state_commitment: plan.room_state_commitment,
      query_ref: plan.query_ref,
      query_proposal_commitment: plan.query_proposal_commitment,
      query_grant_set_commitment:
        plan.prospective_query_grant_set_commitment,
      allocation_commitment: plan.allocation_commitment,
      joint_consent_snapshot_commitment:
        plan.joint_consent_snapshot_commitment,
      consent_snapshot_current: true,
      query_grants_current: true,
    } as unknown as CollaborationJointRun;

    expect(() => assertCollaborationExecutionPlanMatchesJointRun(
      plan,
      jointRun,
      room,
    )).not.toThrow();
    expect(() => assertCollaborationExecutionPlanMatchesJointRun(
      plan,
      {
        ...jointRun,
        allocation_commitment: `sha256:${"0".repeat(64)}`,
      },
      room,
    )).toThrow("selected current joint snapshot");

    const authorization = authorizationForPlan(plan);
    expect(() => assertCollaborationExecutionAuthorizationMatchesPlan(
      authorization,
      plan,
    )).not.toThrow();
    expect(() => assertCollaborationExecutionAuthorizationMatchesPlan(
      authorization,
      {
        ...plan,
        basis_commitment: `sha256:${"f".repeat(64)}`,
      },
    )).toThrow("retained plan");
    expect(() => assertCollaborationExecutionAuthorizationMatchesPlan(
      {
        ...authorization,
        execution: {
          ...authorization.execution,
          execution_id: `exec_${"0".repeat(64)}`,
        },
      },
      plan,
    )).toThrow("retained plan");
  });

  it("renders exact reservation terms without promoting them into finalized funding evidence", () => {
    const distributor = `0x${"8".repeat(40)}` as Address;
    const bytes32 = (character: string) => `0x${character.repeat(64)}` as Hex;
    const fundingRequest: CollaborationFundingReservationRequest = {
      settlementId: bytes32("1"),
      settlementNonce: 11n,
      releasePolicyCommitment: bytes32("2"),
      roomCommitment: bytes32("3"),
      roomStateCommitment: bytes32("4"),
      queryCommitment: bytes32("5"),
      grantSetCommitment: bytes32("6"),
      allocationCommitment: bytes32("7"),
      ownersAmountsHash: bytes32("c"),
      asset: zeroAddress,
      total: 2_000n,
      executionCommitment: bytes32("b"),
      refundAfter: 1_900_001_500n,
    };
    const fundingCall = collaborationFundingReservationCall(fundingRequest);
    const reservation = {
      schema: "dnai.collaboration.royalty-funding-reservation.v1",
      chain_id: 84_532,
      distributor_address: distributor.toLowerCase(),
      sponsor_address: WALLET,
      reservation_id: collaborationFundingReservationId({
        chainId: 84_532,
        distributor,
        sponsor: WALLET as Address,
        request: fundingRequest,
      }),
      request: {
        settlement_id: fundingRequest.settlementId,
        settlement_nonce: "11",
        release_policy_commitment: fundingRequest.releasePolicyCommitment,
        room_commitment: fundingRequest.roomCommitment,
        room_state_commitment: fundingRequest.roomStateCommitment,
        query_commitment: fundingRequest.queryCommitment,
        grant_set_commitment: fundingRequest.grantSetCommitment,
        allocation_commitment: fundingRequest.allocationCommitment,
        owners_amounts_hash: fundingRequest.ownersAmountsHash,
        asset: zeroAddress,
        total: "2000",
        execution_commitment: fundingRequest.executionCommitment,
        refund_after: "1900001500",
      },
      transaction: {
        to: distributor.toLowerCase(),
        function_name: "reserveNative",
        abi_signature: "reserveNative((bytes32,uint256,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,address,uint256,bytes32,uint64))",
        calldata: fundingCall.expectedCalldata,
        value: "2000",
        erc20_approval_required: false,
        erc20_approval: null,
      },
      derived_after_fresh_owner_grants: true,
      client_supplied_reservation_id: false,
      balance_or_allowance_is_not_authorization: true,
    };

    expect(parseCollaborationExecutionRoyaltyReservation(reservation)).toMatchObject({
      reservation_id: reservation.reservation_id,
      request: { total: "2000" },
      client_supplied_reservation_id: false,
      balance_or_allowance_is_not_authorization: true,
      finalizedReservationObservedInBrowser: false,
      mayUnlockExecutionControls: false,
    });
    const gated = parseCollaborationExecutionRoyaltyReservation({
      ...reservation,
      transaction: {
        schema: "dnai.collaboration.royalty-funding-action-gated.v1",
        status: "gated_worker_presence_required",
        reason: "fresh_authenticated_worker_and_qvl_capability_required",
        executable: false,
        wallet_transaction_included: false,
        erc20_approval_included: false,
      },
    });
    expect(gated.walletActionReady).toBe(false);
    expect(gated.transaction).toEqual({
      schema: "dnai.collaboration.royalty-funding-action-gated.v1",
      status: "gated_worker_presence_required",
      reason: "fresh_authenticated_worker_and_qvl_capability_required",
      executable: false,
      wallet_transaction_included: false,
      erc20_approval_included: false,
    });
    expect(() => parseCollaborationExecutionRoyaltyReservation({
      ...reservation,
      balance_or_allowance_is_not_authorization: false,
    })).toThrow();
    expect(() => parseCollaborationExecutionRoyaltyReservation({
      ...reservation,
      request: { ...reservation.request, refund_after: 1_900_001_500 },
    })).toThrow("refund time");
    expect(collaborationSource).toContain(
      "!== royaltyReservation.request.execution_commitment",
    );
  });

  it("never promotes a forged client status DTO into journal, chain, TDX, QVL, or control evidence", () => {
    const forgedDto = {
      surface: "collaboration_one_shot_execution",
      state: "bounded_result_ready",
      source_authentication_proven: true,
      finalized_vault_freshness_proven: true,
      tdx_attestation_verified: true,
      qvl_verified: true,
      settlement_finalized: true,
      execution_controls_unlocked: true,
    };

    expect(collaborationExecutionClientDtoEvidenceBoundary(forgedDto)).toEqual({
      clientDtoAcceptedAsJournalEvidence: false,
      clientDtoAcceptedAsFinalizedVaultEvidence: false,
      clientDtoAcceptedAsTdxEvidence: false,
      clientDtoAcceptedAsQvlEvidence: false,
      clientDtoMayUnlockExecutionControls: false,
      requiredSource:
        "participant_api_plus_trusted_local_journal_and_fresh_chain_read",
    });
  });

  it("separates API route availability from unproven worker presence", () => {
    expect(collaborationSource).toContain(
      'literal(status.api_worker_wiring_available, true',
    );
    expect(collaborationSource).toContain(
      'literal(status.api_worker_wiring_claimed, false',
    );
    expect(collaborationSource).toContain(
      'literal(status.fresh_worker_presence_proven, false',
    );
    expect(collaborationSource).not.toContain(
      'literal(status.api_worker_wiring_claimed, true',
    );
  });

  it("validates the all-in cap and current funding wallet before transport", () => {
    expect(() => assertCollaborationExecutionPlanRequest(
      planRequest(),
      WALLET,
    )).not.toThrow();
    expect(() => assertCollaborationExecutionPlanRequest({
      ...planRequest(),
      max_total_asset_debit: 8_999,
    }, WALLET)).toThrow("exceeds the all-in cap");
    expect(() => assertCollaborationExecutionPlanRequest(
      planRequest(),
      `0x${"2".repeat(40)}`,
    )).toThrow("different funding wallet");
  });
});
