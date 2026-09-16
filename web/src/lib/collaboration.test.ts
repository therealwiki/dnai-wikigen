import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { deployment } from "../config";
import {
  acceptCollaborationInvitation,
  appendCollaborationRoomPage,
  archiveCollaborationRoom,
  assertConsentChallengeForSigning,
  assertQueryGrantChallengeForSigning,
  authorizeCollaborationJointRun,
  cancelCollaborationInvitation,
  collaborationJointRunCurrentForRoom,
  collaborationReleaseConfigured,
  collaborationRollbackProtectionVerified,
  collaborationSessionIsCurrent,
  createCollaborationRoom,
  declineCollaborationInvitation,
  fetchCollaborationQueryGrantChallenge,
  listCollaborationRooms,
  parseCollaborationConsentChallenge,
  parseCollaborationInvitationResult,
  parseCollaborationJointRun,
  parseCollaborationQueryGrantChallenge,
  parseCollaborationRollbackWitness,
  parseCollaborationRoom,
  parseCollaborationRoomList,
  proposeCollaborationQuery,
  submitCollaborationQueryGrant,
  type CollaborationQueryGrantChallenge,
  type CollaborationReleaseConfiguration,
  type CollaborationRoom,
} from "./collaboration";
import type { ExecutionPolicyAnchorRelease } from "./executionPolicyAnchor";

const CREATOR = `0x${"1".repeat(40)}`;
const OWNER = `0x${"2".repeat(40)}`;
const ROOM_ID = `room_${"a".repeat(32)}`;
const CONSENT_ID = `consent_${"b".repeat(32)}`;
const QUERY_CHALLENGE_ID = `qgrant_${"c".repeat(32)}`;
const RUN_ID = `run_${"d".repeat(32)}`;
const TOKEN = `${"a".repeat(40)}.${"b".repeat(40)}.${"c".repeat(40)}`;

function digest(character: string): string {
  return `sha256:${character.repeat(64)}`;
}

function localRollbackTruth() {
  return {
    rollback_protection: false as const,
    rollback_witness: {
      schema: "dnai.collaboration-rollback-witness.v1" as const,
      mode: "local_hmac_current_state_non_monotonic" as const,
      monotonic: false as const,
      authority_context_hash: null,
      state_hash: null,
      decision_hash: null,
      anchor_sequence: null,
      rollback_anchor: null,
      opaque_commitments_only: true as const,
      raw_room_egress: false as const,
      raw_member_egress: false as const,
      raw_query_egress: false as const,
    },
    tamper_evident_current_state: true as const,
  };
}

const LIVE_ANCHOR_RELEASE: ExecutionPolicyAnchorRelease = {
  address: `0x${"5".repeat(40)}`,
  runtimeCodeHash: `0x${"6".repeat(64)}`,
  writer: `0x${"7".repeat(40)}`,
  writerReleaseCommitment: `0x${"8".repeat(64)}`,
  confirmations: 2,
  maxBlockAgeSeconds: 600,
  maxFutureBlockSkewSeconds: 30,
};

function liveReleaseConfiguration(): CollaborationReleaseConfiguration {
  const releaseSha = "a".repeat(40);
  return {
    collaborationEnabled: true,
    delegateUrl: "https://delegate.example",
    releaseIdentityStatus: "release_bound",
    releaseSha,
    verificationChainReleaseSha: releaseSha,
    appId: "b".repeat(40),
    cvmId: "cvm-main-runtime-0001",
    composeHash: "c".repeat(64),
    osImageHash: "d".repeat(64),
    imageDigest: `ghcr.io/wikigen/delegate@sha256:${"e".repeat(64)}`,
    walletAuthDomain: "www.wikigen.me",
    walletAuthUri: "https://www.wikigen.me",
    executionPolicyAnchorRelease: LIVE_ANCHOR_RELEASE,
  };
}

function liveRollbackTruth() {
  const authorityContextHash = "a".repeat(64);
  const decisionHash = "c".repeat(64);
  return {
    rollback_protection: true as const,
    rollback_witness: {
      schema: "dnai.collaboration-rollback-witness.v1" as const,
      mode: "base_sepolia_execution_policy_anchor" as const,
      monotonic: true as const,
      authority_context_hash: authorityContextHash,
      state_hash: "b".repeat(64),
      decision_hash: decisionHash,
      anchor_sequence: 7,
      rollback_anchor: {
        schema: "dnai-wikigen/execution-policy-anchor-status/v1",
        status: "rpc_reported_finalized_release_match",
        verification_model:
          "single_rpc_reported_finalized_with_confirmation_depth",
        chain_id: 84_532,
        latest_block_number: 105,
        rpc_finalized_block_number: 104,
        rpc_finalized_block_hash: `0x${"9".repeat(64)}`,
        minimum_confirmation_depth: 2,
        observed_confirmation_depth: 2,
        block_number: 104,
        block_hash: `0x${"d".repeat(64)}`,
        block_timestamp: 1_900_000_000,
        contract_address: LIVE_ANCHOR_RELEASE.address,
        runtime_code_hash: LIVE_ANCHOR_RELEASE.runtimeCodeHash,
        writer: LIVE_ANCHOR_RELEASE.writer,
        writer_release_commitment:
          LIVE_ANCHOR_RELEASE.writerReleaseCommitment,
        writer_rotations_frozen: true,
        paused: false,
        global_sequence: 11,
        global_head: `0x${"e".repeat(64)}`,
        resource_id_hash:
          "125542999749ad85596e2d5c1479ae4c199bb1cca5ed150e663f39def93eaebb",
        resource_decision_head: `0x${decisionHash}`,
        resource_sequence: 7,
        decision_hash: decisionHash,
        decision_sequence: 7,
        opaque_commitments_only: true,
        independent_rpc_quorum_verified: false,
        consensus_proof_verified: false,
        raw_resource_id_egress: false,
        raw_policy_egress: false,
      },
      opaque_commitments_only: true as const,
      raw_room_egress: false as const,
      raw_member_egress: false as const,
      raw_query_egress: false as const,
    },
    tamper_evident_current_state: true as const,
  };
}

function queryFixture(approved = true): Record<string, unknown> {
  return {
    surface: "collaboration_query_proposal",
    schema_version: 2,
    room_id: ROOM_ID,
    query_ref: digest("7"),
    proposer_address: CREATOR,
    room_commitment: digest("3"),
    room_generation: 3,
    proposal_commitment: digest("8"),
    allocation_commitment: digest("9"),
    proposed_at: 120,
    proposal_current: true,
    owner_query_grants: [{
      owner_address: OWNER,
      grant_status: approved ? "approved" : "pending",
      grant_generation: approved ? 1 : 0,
      authorization_hash_recorded: approved,
    }],
    all_required_query_grants_current: approved,
    raw_query_egress: false,
    raw_policy_egress: false,
    raw_signature_egress: false,
    ...localRollbackTruth(),
  };
}

function roomFixture(
  options: {
    invited?: boolean;
    query?: boolean;
    archived?: boolean;
  } = {},
): Record<string, unknown> {
  const invited = options.invited === true;
  const archived = options.archived === true;
  const accepted = invited ? [CREATOR] : [CREATOR, OWNER].sort();
  const pending = invited ? [OWNER] : [];
  return {
    surface: "collaboration_room",
    schema_version: 2,
    room_id: ROOM_ID,
    creator_address: CREATOR,
    declared_member_addresses: [CREATOR, OWNER].sort(),
    accepted_member_addresses: accepted,
    pending_invitation_addresses: pending,
    declined_member_addresses: [],
    cancelled_invitation_addresses: [],
    memberships: [CREATOR, OWNER].sort().map((member) => ({
      member_address: member,
      membership_status: member === OWNER && invited ? "invited" : "accepted",
      membership_generation: member === OWNER && invited ? 0 : 1,
      decision_recorded: !(member === OWNER && invited),
    })),
    requester_membership_status: "accepted",
    purpose_commitment: digest("1"),
    pipeline_commitment: digest("2"),
    room_commitment: digest("3"),
    generation: 3,
    created_at: 100,
    updated_at: archived ? 200 : 120,
    lifecycle_status: archived ? "archived" : "active",
    archived_at: archived ? 200 : 0,
    reclaimable_after: archived ? 604_800 : 0,
    room_retention_policy: archived
      ? "explicit_archive_then_bounded_reclamation"
      : "active_not_pruned",
    owners: [{
      owner_address: OWNER,
      allocation_bps: 10_000,
      corpus_policy_commitment: digest("4"),
      membership_status: invited ? "invited" : "accepted",
      role_consent_status: archived || invited ? "pending" : "active",
      role_consent_generation: archived || invited ? 0 : 1,
      role_authorization_hash_recorded: !(archived || invited),
      role_accepted: !(archived || invited),
    }],
    all_required_memberships_accepted: !invited,
    all_required_roles_active: !(archived || invited),
    current_query: options.query && !archived ? queryFixture() : null,
    all_required_query_grants_current: options.query === true && !archived,
    membership_acceptance_mechanism:
      "wallet_authenticated_invitation_response",
    role_acceptance_mechanism: "owner_role_consent_signature",
    query_grant_mechanism: "owner_signature_bound_to_current_query_v2",
    participant_authenticated_projection: true,
    raw_purpose_egress: false,
    raw_policy_egress: false,
    raw_signature_egress: false,
    raw_artifact_egress: false,
    ...localRollbackTruth(),
  };
}

function listFixture(
  room = roomFixture(),
  options: { hasMore?: boolean; cursor?: string | null } = {},
): Record<string, unknown> {
  const hasMore = options.hasMore === true;
  return {
    surface: "collaboration_rooms",
    schema_version: 2,
    rooms: [room],
    room_count: 1,
    has_more: hasMore,
    next_cursor: hasMore
      ? (options.cursor ?? "opaque.cursor.value")
      : null,
    page_limit: 8,
    maximum_page_size: 16,
    maximum_accepted_rooms_per_participant: 64,
    maximum_pending_invitations_per_target: 32,
    snapshot_bound_pagination: true,
    participant_authenticated_projection: true,
    raw_purpose_egress: false,
    raw_policy_egress: false,
    raw_signature_egress: false,
    ...localRollbackTruth(),
  };
}

function roleMessage(
  room: CollaborationRoom,
  decision: "activate" | "revoke",
): string {
  const verb = decision === "activate" ? "Activate" : "Revoke";
  return (
    "www.wikigen.me wants you to sign in with your Ethereum account:\n"
    + `${OWNER}\n\n`
    + `${verb} this wallet's owner role for the specified `
    + "multi-owner collaboration room. This does not approve any query. "
    + "Each query requires a separate exact-query owner signature. This "
    + "signature does not dispatch execution, settle funds, or transfer "
    + "tokens.\n\n"
    + "URI: https://www.wikigen.me\n"
    + "Version: 2\n"
    + "Chain ID: 84532\n"
    + `Nonce: ${CONSENT_ID.slice("consent_".length)}\n`
    + "Issued At: 130\n"
    + "Expiration Time: 430\n"
    + "Resources:\n"
    + `- urn:dnai:collaboration:room:${ROOM_ID}\n`
    + `- urn:dnai:collaboration:room-commitment:${room.room_commitment}\n`
    + `- urn:dnai:collaboration:room-generation:${room.generation}\n`
    + `- urn:dnai:collaboration:state:${digest("5")}\n`
    + `- urn:dnai:collaboration:owner-role:${decision}`
  );
}

function roleChallengeFixture(room: CollaborationRoom): Record<string, unknown> {
  return {
    surface: "collaboration_role_consent_challenge",
    schema_version: 2,
    challenge_id: CONSENT_ID,
    room_id: ROOM_ID,
    owner_address: OWNER,
    decision: "activate",
    room_commitment: room.room_commitment,
    room_generation: room.generation,
    room_state_commitment: digest("5"),
    challenge_commitment: digest("6"),
    message: roleMessage(room, "activate"),
    issued_at: 130,
    expires_at: 430,
    status: "pending",
    authorization_hash_recorded: false,
    reclaimable_after: 86_830,
    retention_policy: "bounded_reclaimable_after_terminal_or_expiry",
    participant_authenticated_projection: true,
    raw_signature_egress: false,
    ...localRollbackTruth(),
  };
}

function queryMessage(
  challenge: Omit<CollaborationQueryGrantChallenge, "message">,
): string {
  return (
    "www.wikigen.me wants you to sign in with your Ethereum account:\n"
    + `${OWNER}\n\n`
    + "Approve this wallet's grant for exactly the committed "
    + "current query below. It cannot be inherited by another query. This "
    + "signature records a prospective consent snapshot only; it does not "
    + "dispatch execution, settle funds, or transfer tokens.\n\n"
    + "URI: https://www.wikigen.me\n"
    + "Version: 2\n"
    + "Chain ID: 84532\n"
    + `Nonce: ${QUERY_CHALLENGE_ID.slice("qgrant_".length)}\n`
    + "Issued At: 140\n"
    + "Expiration Time: 440\n"
    + "Resources:\n"
    + `- urn:dnai:collaboration:room:${ROOM_ID}\n`
    + `- urn:dnai:collaboration:room-commitment:${challenge.room_commitment}\n`
    + `- urn:dnai:collaboration:room-generation:${challenge.room_generation}\n`
    + `- urn:dnai:collaboration:query:${challenge.query_ref}\n`
    + `- urn:dnai:collaboration:query-proposal:${challenge.proposal_commitment}\n`
    + `- urn:dnai:collaboration:owner-policy:${challenge.owner_policy_commitment}\n`
    + `- urn:dnai:collaboration:allocation:${challenge.allocation_commitment}\n`
    + "- urn:dnai:collaboration:query-grant:approve"
  );
}

function queryChallengeFixture(): Record<string, unknown> {
  const fixture = {
    surface: "collaboration_query_grant_challenge" as const,
    schema_version: 2 as const,
    challenge_id: QUERY_CHALLENGE_ID,
    room_id: ROOM_ID,
    owner_address: OWNER,
    decision: "approve" as const,
    room_commitment: digest("3"),
    room_generation: 3,
    query_ref: digest("7"),
    proposal_commitment: digest("8"),
    allocation_commitment: digest("9"),
    owner_policy_commitment: digest("4"),
    challenge_commitment: digest("a"),
    issued_at: 140,
    expires_at: 440,
    status: "pending" as const,
    authorization_hash_recorded: false,
    reclaimable_after: 86_840,
    retention_policy:
      "bounded_reclaimable_after_terminal_or_expiry" as const,
    participant_authenticated_projection: true as const,
    raw_signature_egress: false as const,
    ...localRollbackTruth(),
  };
  return { ...fixture, message: queryMessage(fixture) };
}

function runFixture(): Record<string, unknown> {
  return {
    surface: "collaboration_joint_consent_snapshot",
    schema_version: 2,
    run_id: RUN_ID,
    room_id: ROOM_ID,
    query_ref: digest("7"),
    requester_address: CREATOR,
    room_commitment: digest("3"),
    room_generation: 3,
    room_state_commitment: digest("b"),
    query_proposal_commitment: digest("8"),
    query_grant_set_commitment: digest("c"),
    allocation_commitment: digest("9"),
    joint_consent_snapshot_commitment: digest("d"),
    recorded_at: 160,
    execution_status: "joint_consent_snapshot_not_dispatched",
    consent_snapshot_current: true,
    query_grants_current: true,
    execution_authority: false,
    provider_dispatch_performed: false,
    tdx_attestation: false,
    settlement_performed: false,
    royalty_distribution_performed: false,
    reclaimable_after: 604_960,
    retention_policy: "bounded_non_dispatched_snapshot_retention",
    raw_purpose_egress: false,
    raw_policy_egress: false,
    raw_signature_egress: false,
    raw_artifact_egress: false,
    ...localRollbackTruth(),
  };
}

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("Collaboration schema v2 parsing", () => {
  it("keeps local HMAC integrity explicit without inventing a monotonic witness", () => {
    const parsed = parseCollaborationRoom(roomFixture());
    expect(parsed.rollback_protection).toBe(false);
    expect(parsed.rollback_witness.mode).toBe(
      "local_hmac_current_state_non_monotonic",
    );
    expect(parsed.rollback_witness.monotonic).toBe(false);
    expect(collaborationRollbackProtectionVerified(parsed)).toBe(false);

    expect(() => parseCollaborationRoom({
      ...roomFixture(),
      rollback_protection: true,
    })).toThrow(/contradicts its witness/);

    const local = localRollbackTruth();
    expect(() => parseCollaborationRollbackWitness({
      ...local.rollback_witness,
      unsupported_claim: true,
    })).toThrow(/unexpected schema/);
    expect(() => parseCollaborationRollbackWitness({
      ...local.rollback_witness,
      monotonic: true,
    })).toThrow(/monotonic marker/);
  });

  it("promotes only an exact release-matched witness and rejects nested conflicts", () => {
    const truth = liveRollbackTruth();
    const witness = parseCollaborationRollbackWitness(
      truth.rollback_witness,
      LIVE_ANCHOR_RELEASE,
    );
    expect(witness.mode).toBe("base_sepolia_execution_policy_anchor");
    expect(witness.rollback_anchor?.independent_rpc_quorum_verified).toBe(false);
    expect(witness.rollback_anchor?.consensus_proof_verified).toBe(false);
    expect(collaborationRollbackProtectionVerified({
      rollback_protection: true,
      rollback_witness: witness,
      tamper_evident_current_state: true,
    })).toBe(false);

    expect(() => parseCollaborationRollbackWitness(
      truth.rollback_witness,
      {
        ...LIVE_ANCHOR_RELEASE,
        runtimeCodeHash: `0x${"f".repeat(64)}`,
      },
    )).toThrow(/does not match the frontend release/);
    expect(() => parseCollaborationRollbackWitness({
      ...truth.rollback_witness,
      decision_hash: "f".repeat(64),
    }, LIVE_ANCHOR_RELEASE)).toThrow(/anchor bindings/);
    expect(() => parseCollaborationRollbackWitness({
      ...truth.rollback_witness,
      rollback_anchor: {
        ...truth.rollback_witness.rollback_anchor,
        resource_id_hash: truth.rollback_witness.authority_context_hash,
      },
    }, LIVE_ANCHOR_RELEASE)).toThrow(/anchor bindings/);

    const mutableDeployment = deployment as unknown as {
      executionPolicyAnchorRelease?: ExecutionPolicyAnchorRelease;
    };
    const originalRelease = mutableDeployment.executionPolicyAnchorRelease;
    mutableDeployment.executionPolicyAnchorRelease = LIVE_ANCHOR_RELEASE;
    try {
      const liveRoom = parseCollaborationRoom({
        ...roomFixture(),
        ...truth,
      });
      expect(collaborationRollbackProtectionVerified(liveRoom)).toBe(true);
      expect(() => parseCollaborationRoom({
        ...roomFixture(),
        ...truth,
        rollback_protection: false,
      })).toThrow(/contradicts its witness/);
      expect(() => parseCollaborationRoom({
        ...roomFixture({ query: true }),
        ...truth,
      })).toThrow(/conflicting rollback witness/);
      expect(() => parseCollaborationRoomList({
        ...listFixture({
          ...roomFixture(),
          ...truth,
        }),
      })).toThrow(/conflicting rollback witness/);
    } finally {
      mutableDeployment.executionPolicyAnchorRelease = originalRelease;
    }
  });

  it("distinguishes invitations from accepted membership and role authority", () => {
    const invited = parseCollaborationRoom(roomFixture({ invited: true }));
    expect(invited.pending_invitation_addresses).toEqual([OWNER]);
    expect(invited.accepted_member_addresses).toEqual([CREATOR]);
    expect(invited.owners[0].membership_status).toBe("invited");
    expect(invited.owners[0].role_accepted).toBe(false);
    expect(invited.all_required_roles_active).toBe(false);

    const accepted = parseCollaborationRoom(roomFixture({ query: true }));
    expect(accepted.all_required_roles_active).toBe(true);
    expect(accepted.current_query?.query_ref).toBe(digest("7"));
    expect(accepted.all_required_query_grants_current).toBe(true);
  });

  it("rejects v1, declarations labeled accepted, and sensitive response fields", () => {
    expect(() => parseCollaborationRoom({
      ...roomFixture(),
      schema_version: 1,
    })).toThrow();
    const inconsistent = roomFixture({ invited: true });
    inconsistent.accepted_member_addresses = [CREATOR, OWNER].sort();
    expect(() => parseCollaborationRoom(inconsistent)).toThrow(
      /membership summaries/,
    );
    expect(() => parseCollaborationRoom({
      ...roomFixture(),
      purpose_text: "raw purpose",
    })).toThrow(/forbidden field/);
  });

  it("parses bounded cursor pages and rejects contradictory/cyclic append", () => {
    const first = parseCollaborationRoomList(listFixture(
      roomFixture(),
      { hasMore: true, cursor: "opaque.cursor.value" },
    ));
    expect(first.has_more).toBe(true);
    expect(first.next_cursor).toBe("opaque.cursor.value");
    expect(() => parseCollaborationRoomList({
      ...listFixture(),
      has_more: true,
      next_cursor: null,
    })).toThrow(/summary/);
    expect(() => appendCollaborationRoomPage(first.rooms, first)).toThrow(
      /duplicate/,
    );
  });

  it("verifies exact role and exact-query messages before signing", () => {
    const room = parseCollaborationRoom(roomFixture({ query: true }));
    const role = parseCollaborationConsentChallenge(
      roleChallengeFixture(room),
    );
    expect(() => assertConsentChallengeForSigning(role, {
      room,
      ownerAddress: OWNER,
      decision: "activate",
      nowSeconds: 140,
    })).not.toThrow();

    const query = parseCollaborationQueryGrantChallenge(
      queryChallengeFixture(),
    );
    expect(() => assertQueryGrantChallengeForSigning(query, {
      room,
      ownerAddress: OWNER,
      decision: "approve",
      nowSeconds: 150,
    })).not.toThrow();
    const otherRoom = parseCollaborationRoom({
      ...roomFixture({ query: true }),
      generation: 4,
      current_query: {
        ...queryFixture(),
        room_generation: 4,
      },
    });
    expect(() => assertQueryGrantChallengeForSigning(query, {
      room: otherRoom,
      ownerAddress: OWNER,
      decision: "approve",
      nowSeconds: 150,
    })).toThrow(/different query/);
  });

  it("parses honest bounded invitation, archive, and snapshot retention", () => {
    const invitation = parseCollaborationInvitationResult({
      surface: "collaboration_invitation_result",
      schema_version: 2,
      room_id: ROOM_ID,
      member_address: OWNER,
      membership_status: "declined",
      membership_generation: 1,
      decision_recorded: true,
      visible_after_response: false,
      ordinary_participant_authority: false,
      room_generation: 2,
      room_state_commitment: digest("e"),
      raw_purpose_egress: false,
      raw_policy_egress: false,
      raw_signature_egress: false,
      ...localRollbackTruth(),
    });
    expect(invitation.visible_after_response).toBe(false);
    expect(parseCollaborationRoom(roomFixture({ archived: true }))
      .room_retention_policy).toContain("bounded_reclamation");
    const run = parseCollaborationJointRun(runFixture());
    expect(run.execution_authority).toBe(false);
    expect(run.reclaimable_after).toBeGreaterThan(run.recorded_at);
    const currentRoom = parseCollaborationRoom(roomFixture({ query: true }));
    expect(collaborationJointRunCurrentForRoom(run, currentRoom)).toBe(true);
    expect(collaborationJointRunCurrentForRoom(run, parseCollaborationRoom({
      ...roomFixture({ query: true }),
      generation: 4,
      current_query: {
        ...queryFixture(),
        room_generation: 4,
      },
    }))).toBe(false);
  });
});

describe("Collaboration frontend release gate", () => {
  it("requires the complete release, CVM, wallet-auth, and rollback authority", () => {
    const release = liveReleaseConfiguration();
    expect(collaborationReleaseConfigured(release)).toBe(true);
    expect(collaborationReleaseConfigured({
      ...release,
      verificationChainReleaseSha: "f".repeat(40),
    })).toBe(false);
    expect(collaborationReleaseConfigured({
      ...release,
      composeHash: "",
    })).toBe(false);
    expect(collaborationReleaseConfigured({
      ...release,
      walletAuthUri: "https://attacker.example",
    })).toBe(false);
    expect(collaborationReleaseConfigured({
      ...release,
      executionPolicyAnchorRelease: undefined,
    })).toBe(false);
    expect(collaborationReleaseConfigured({
      ...release,
      delegateUrl: "http://delegate.example",
    })).toBe(false);
  });
});

describe("Collaboration client v2 requests", () => {
  type MutableReleaseConfiguration = {
    -readonly [K in keyof CollaborationReleaseConfiguration]:
      CollaborationReleaseConfiguration[K];
  };
  const mutableDeployment = deployment as unknown as MutableReleaseConfiguration;
  let originalConfiguration: CollaborationReleaseConfiguration;

  beforeEach(() => {
    originalConfiguration = {
      collaborationEnabled: mutableDeployment.collaborationEnabled,
      delegateUrl: mutableDeployment.delegateUrl,
      releaseIdentityStatus: mutableDeployment.releaseIdentityStatus,
      releaseSha: mutableDeployment.releaseSha,
      verificationChainReleaseSha:
        mutableDeployment.verificationChainReleaseSha,
      appId: mutableDeployment.appId,
      cvmId: mutableDeployment.cvmId,
      composeHash: mutableDeployment.composeHash,
      osImageHash: mutableDeployment.osImageHash,
      imageDigest: mutableDeployment.imageDigest,
      walletAuthDomain: mutableDeployment.walletAuthDomain,
      walletAuthUri: mutableDeployment.walletAuthUri,
      executionPolicyAnchorRelease:
        mutableDeployment.executionPolicyAnchorRelease,
    };
    Object.assign(mutableDeployment, liveReleaseConfiguration());
  });

  afterEach(() => {
    vi.restoreAllMocks();
    Object.assign(mutableDeployment, originalConfiguration);
  });

  it("sends bounded list pagination and treats cursor as opaque", async () => {
    const fetchMock = vi.fn(async (
      _input: RequestInfo | URL,
      _init?: RequestInit,
    ) => jsonResponse(listFixture(
      roomFixture(),
      { hasMore: true, cursor: "next.opaque.cursor" },
    )));
    vi.stubGlobal("fetch", fetchMock);
    const result = await listCollaborationRooms(TOKEN, {
      limit: 8,
      cursor: "incoming.opaque.cursor",
    });
    expect(result.next_cursor).toBe("next.opaque.cursor");
    expect(fetchMock.mock.calls[0][0]).toBe(
      "https://delegate.example/collaboration/rooms"
      + "?limit=8&cursor=incoming.opaque.cursor",
    );
  });

  it("uses the explicit invitation, archive, proposal, and query-grant routes", async () => {
    const invitation = (status: "accepted" | "declined" | "cancelled") => ({
      surface: "collaboration_invitation_result",
      schema_version: 2,
      room_id: ROOM_ID,
      member_address: OWNER,
      membership_status: status,
      membership_generation: 1,
      decision_recorded: true,
      visible_after_response: status === "accepted",
      ordinary_participant_authority: status === "accepted",
      room_generation: 2,
      room_state_commitment: digest("e"),
      raw_purpose_egress: false,
      raw_policy_egress: false,
      raw_signature_egress: false,
      ...localRollbackTruth(),
    });
    const responses = [
      invitation("accepted"),
      invitation("declined"),
      invitation("cancelled"),
      {
        surface: "collaboration_room_result",
        schema_version: 2,
        room: roomFixture({ archived: true }),
      },
      {
        surface: "collaboration_query_proposal_result",
        schema_version: 2,
        query: queryFixture(),
      },
      {
        surface: "collaboration_query_grant_result",
        schema_version: 2,
        verifier_kind: "eoa",
        query: queryFixture(),
        raw_signature_retained: false,
      },
    ];
    const fetchMock = vi.fn(async (
      _input: RequestInfo | URL,
      _init?: RequestInit,
    ) => jsonResponse(responses.shift()));
    vi.stubGlobal("fetch", fetchMock);
    await acceptCollaborationInvitation(TOKEN, ROOM_ID, "accept-room-0001");
    await declineCollaborationInvitation(TOKEN, ROOM_ID, "decline-room-0001");
    await cancelCollaborationInvitation(
      TOKEN,
      ROOM_ID,
      OWNER,
      "cancel-room-0001",
    );
    await archiveCollaborationRoom(TOKEN, ROOM_ID, "archive-room-0001");
    await proposeCollaborationQuery(
      TOKEN,
      ROOM_ID,
      digest("7"),
      "query-room-0001",
    );
    await submitCollaborationQueryGrant(TOKEN, ROOM_ID, {
      challenge_id: QUERY_CHALLENGE_ID,
      decision: "approve",
      signature: "0x1234",
    });
    expect(fetchMock.mock.calls.map((call) => String(call[0]))).toEqual([
      `https://delegate.example/collaboration/rooms/${ROOM_ID}/invitations/accept`,
      `https://delegate.example/collaboration/rooms/${ROOM_ID}/invitations/decline`,
      `https://delegate.example/collaboration/rooms/${ROOM_ID}/invitations/cancel`,
      `https://delegate.example/collaboration/rooms/${ROOM_ID}/archive`,
      `https://delegate.example/collaboration/rooms/${ROOM_ID}/query-proposals`,
      `https://delegate.example/collaboration/rooms/${ROOM_ID}/query-grants`,
    ]);
  });

  it("fetches exact query challenges and records exact-query snapshots", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => (
      String(input).includes("query-grant-challenges")
        ? jsonResponse(queryChallengeFixture())
        : jsonResponse(runFixture())
    ));
    vi.stubGlobal("fetch", fetchMock);
    const challenge = await fetchCollaborationQueryGrantChallenge(
      TOKEN,
      QUERY_CHALLENGE_ID,
    );
    expect(challenge.query_ref).toBe(digest("7"));
    const run = await authorizeCollaborationJointRun(
      TOKEN,
      ROOM_ID,
      digest("7"),
      "joint-run-0001",
    );
    expect(run.execution_status).toBe(
      "joint_consent_snapshot_not_dispatched",
    );
  });

  it("validates room creation and preserves commitment-only request bodies", async () => {
    const fetchMock = vi.fn(async (
      _input: RequestInfo | URL,
      _init?: RequestInit,
    ) => jsonResponse({
      surface: "collaboration_room_result",
      schema_version: 2,
      room: roomFixture({ invited: true }),
    }));
    vi.stubGlobal("fetch", fetchMock);
    await createCollaborationRoom(TOKEN, {
      room_id: ROOM_ID,
      idempotency_key: "create-room-0001",
      member_addresses: [OWNER],
      purpose_commitment: digest("1"),
      pipeline_commitment: digest("2"),
      corpus_policy_commitments: { [OWNER]: digest("4") },
      owner_allocations_bps: { [OWNER]: 10_000 },
    });
    const init = fetchMock.mock.calls[0][1] as RequestInit;
    expect(init.credentials).toBe("omit");
    expect(init.cache).toBe("no-store");
    expect(String(init.body)).not.toContain("purpose_text");
  });

  it("normalizes mixed-case owner-map keys without dropping allocations", async () => {
    const mixedCaseOwner = `0x${OWNER.slice(2).toUpperCase()}`;
    const fetchMock = vi.fn(async (
      _input: RequestInfo | URL,
      _init?: RequestInit,
    ) => jsonResponse({
      surface: "collaboration_room_result",
      schema_version: 2,
      room: roomFixture({ invited: true }),
    }));
    vi.stubGlobal("fetch", fetchMock);

    await createCollaborationRoom(TOKEN, {
      room_id: ROOM_ID,
      idempotency_key: "create-room-0002",
      member_addresses: [mixedCaseOwner],
      purpose_commitment: digest("1"),
      pipeline_commitment: digest("2"),
      corpus_policy_commitments: { [mixedCaseOwner]: digest("4") },
      owner_allocations_bps: { [mixedCaseOwner]: 10_000 },
    });

    const init = fetchMock.mock.calls[0][1] as RequestInit;
    const body = JSON.parse(String(init.body)) as Record<string, unknown>;
    expect(body.member_addresses).toEqual([OWNER]);
    expect(body.corpus_policy_commitments).toEqual({
      [OWNER]: digest("4"),
    });
    expect(body.owner_allocations_bps).toEqual({ [OWNER]: 10_000 });
  });

  it("fails closed when the frontend release gate is closed", async () => {
    mutableDeployment.collaborationEnabled = false;
    await expect(listCollaborationRooms(TOKEN)).rejects.toThrow(
      /not enabled/,
    );
  });
});

describe("Collaboration session authority", () => {
  it("invalidates on address, chain, wallet epoch, or expiry change", () => {
    const session = {
      accessToken: TOKEN,
      address: CREATOR,
      issuedAt: 100,
      expiresAt: 1_000,
      walletAuthorizationVersion: 7,
    };
    expect(collaborationSessionIsCurrent(session, {
      address: CREATOR,
      chainId: 84_532,
      walletAuthorizationVersion: 7,
      nowMs: 200_000,
    })).toBe(true);
    expect(collaborationSessionIsCurrent(session, {
      address: OWNER,
      chainId: 84_532,
      walletAuthorizationVersion: 7,
      nowMs: 200_000,
    })).toBe(false);
    expect(collaborationSessionIsCurrent(session, {
      address: CREATOR,
      chainId: 1,
      walletAuthorizationVersion: 7,
      nowMs: 200_000,
    })).toBe(false);
    expect(collaborationSessionIsCurrent(session, {
      address: CREATOR,
      chainId: 84_532,
      walletAuthorizationVersion: 8,
      nowMs: 200_000,
    })).toBe(false);
  });
});
