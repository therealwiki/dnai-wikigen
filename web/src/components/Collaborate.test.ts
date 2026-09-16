import { createComponent } from "solid-js";
import { renderToString } from "solid-js/web";
import { describe, expect, it } from "vitest";
import type {
  CollaborationConsentChallenge,
  CollaborationQueryGrantChallenge,
  CollaborationQueryGrantStatus,
  CollaborationQueryProposal,
  CollaborationRoom,
  CollaborationSession,
} from "../lib/collaboration";
import {
  Collaborate,
  collaborationAuthorityEpochIsCurrent,
  collaborationAuthorizationAttemptIsCurrent,
  collaborationConsentRecoveryMatches,
  collaborationExternalAuthorityFingerprint,
  collaborationQueryGrantRecoveryMatches,
  collaborationReleaseAuthorityFingerprint,
  collaborationRollbackEvidenceState,
  collaborationRoomMatchesCreationIntent,
  emptyCollaborationWalletScopedState,
} from "./Collaborate";
import collaborateSource from "./Collaborate.tsx?raw";

const WALLET_A = `0x${"1".repeat(40)}`;
const WALLET_B = `0x${"2".repeat(40)}`;

function releaseFingerprint(release = "a".repeat(40)): string {
  return collaborationReleaseAuthorityFingerprint({
    release,
    releaseSha: release,
    verificationChainReleaseSha: release,
    releaseIdentityStatus: "release_bound",
    collaborationEnabled: true,
    delegateUrl: "https://delegate.example",
    appId: "app_release_a",
    cvmId: "cvm_release_a",
    composeHash: "sha256:compose-a",
    imageDigest: "sha256:image-a",
    walletAuthDomain: "www.wikigen.me",
    walletAuthUri: "https://www.wikigen.me",
  });
}

function sessionFixture(overrides: Partial<CollaborationSession> = {}): CollaborationSession {
  return {
    accessToken: `${"a".repeat(40)}.${"b".repeat(40)}.${"c".repeat(40)}`,
    address: WALLET_A,
    issuedAt: 1_900_000_000,
    expiresAt: 1_900_000_600,
    walletAuthorizationVersion: 7,
    ...overrides,
  };
}

function deferred<T>(): {
  readonly promise: Promise<T>;
  readonly resolve: (value: T) => void;
  readonly reject: (cause: unknown) => void;
} {
  let resolvePromise: ((value: T) => void) | undefined;
  let rejectPromise: ((cause: unknown) => void) | undefined;
  const promise = new Promise<T>((resolve, reject) => {
    resolvePromise = resolve;
    rejectPromise = reject;
  });
  return {
    promise,
    resolve: (value) => resolvePromise?.(value),
    reject: (cause) => rejectPromise?.(cause),
  };
}

interface AuthorityHarness {
  authorityEpoch: number;
  operationRevision: number;
  currentSession: CollaborationSession | undefined;
  releaseFingerprint: string;
  address: string | undefined;
  chainId: number | undefined;
  walletAuthorizationVersion: number;
  nowMs: number;
}

interface CapturedAuthority {
  readonly authorityEpoch: number;
  readonly operationRevision: number;
  readonly session: CollaborationSession;
  readonly releaseFingerprint: string;
}

function captureAuthority(
  harness: AuthorityHarness,
  session: CollaborationSession,
): CapturedAuthority {
  return {
    authorityEpoch: harness.authorityEpoch,
    operationRevision: harness.operationRevision,
    session,
    releaseFingerprint: harness.releaseFingerprint,
  };
}

function authorityMayPublish(
  captured: CapturedAuthority,
  harness: AuthorityHarness,
): boolean {
  return collaborationAuthorityEpochIsCurrent({
    expectedAuthorityEpoch: captured.authorityEpoch,
    currentAuthorityEpoch: harness.authorityEpoch,
    expectedOperationRevision: captured.operationRevision,
    currentOperationRevision: harness.operationRevision,
    expectedSession: captured.session,
    currentSession: harness.currentSession,
    expectedReleaseFingerprint: captured.releaseFingerprint,
    currentReleaseFingerprint: harness.releaseFingerprint,
    currentAddress: harness.address,
    currentChainId: harness.chainId,
    currentWalletAuthorizationVersion: harness.walletAuthorizationVersion,
    nowMs: harness.nowMs,
  });
}

function authorityHarness(session = sessionFixture()): AuthorityHarness {
  return {
    authorityEpoch: 11,
    operationRevision: 23,
    currentSession: session,
    releaseFingerprint: releaseFingerprint(),
    address: session.address,
    chainId: 84532,
    walletAuthorizationVersion: session.walletAuthorizationVersion,
    nowMs: 1_900_000_100_000,
  };
}

function commitment(value: string): string {
  return `sha256:${value.repeat(64).slice(0, 64)}`;
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

function roomFixture(
  consentStatus: "active" | "revoked" | "pending" = "active",
): CollaborationRoom {
  return {
    surface: "collaboration_room",
    schema_version: 2,
    room_id: `room_${"a".repeat(32)}`,
    creator_address: WALLET_A,
    declared_member_addresses: [WALLET_A, WALLET_B],
    accepted_member_addresses: [WALLET_A, WALLET_B],
    pending_invitation_addresses: [],
    declined_member_addresses: [],
    cancelled_invitation_addresses: [],
    memberships: [
      {
        member_address: WALLET_A,
        membership_status: "accepted",
        membership_generation: 1,
        decision_recorded: true,
      },
      {
        member_address: WALLET_B,
        membership_status: "accepted",
        membership_generation: 1,
        decision_recorded: true,
      },
    ],
    requester_membership_status: "accepted",
    purpose_commitment: commitment("1"),
    pipeline_commitment: commitment("2"),
    room_commitment: commitment("3"),
    generation: 6,
    created_at: 1_900_000_000,
    updated_at: 1_900_000_100,
    owners: [{
      owner_address: WALLET_A,
      allocation_bps: 10_000,
      corpus_policy_commitment: commitment("4"),
      membership_status: "accepted",
      role_consent_status: consentStatus,
      role_consent_generation: consentStatus === "pending" ? 0 : 1,
      role_authorization_hash_recorded: consentStatus !== "pending",
      role_accepted: consentStatus === "active",
    }],
    all_required_memberships_accepted: true,
    all_required_roles_active: consentStatus === "active",
    current_query: null,
    all_required_query_grants_current: false,
    lifecycle_status: "active",
    archived_at: 0,
    reclaimable_after: 0,
    room_retention_policy: "active_not_pruned",
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

function consumedChallenge(
  decision: "activate" | "revoke",
): CollaborationConsentChallenge {
  return {
    surface: "collaboration_role_consent_challenge",
    schema_version: 2,
    challenge_id: `consent_${"b".repeat(32)}`,
    room_id: `room_${"a".repeat(32)}`,
    owner_address: WALLET_A,
    decision,
    room_commitment: commitment("3"),
    room_generation: 5,
    room_state_commitment: commitment("5"),
    challenge_commitment: commitment("6"),
    message: "x".repeat(128),
    issued_at: 1_900_000_050,
    expires_at: 1_900_000_500,
    status: "consumed",
    authorization_hash_recorded: true,
    reclaimable_after: 1_900_086_900,
    retention_policy: "bounded_reclaimable_after_terminal_or_expiry",
    participant_authenticated_projection: true,
    raw_signature_egress: false,
    ...localRollbackTruth(),
  };
}

function queryFixture(
  grantStatus: CollaborationQueryGrantStatus = "approved",
): CollaborationQueryProposal {
  return {
    surface: "collaboration_query_proposal",
    schema_version: 2,
    room_id: `room_${"a".repeat(32)}`,
    query_ref: commitment("7"),
    proposer_address: WALLET_B,
    room_commitment: commitment("3"),
    room_generation: 6,
    proposal_commitment: commitment("8"),
    allocation_commitment: commitment("9"),
    proposed_at: 1_900_000_110,
    proposal_current: true,
    owner_query_grants: [{
      owner_address: WALLET_A,
      grant_status: grantStatus,
      grant_generation: grantStatus === "pending" ? 0 : 1,
      authorization_hash_recorded: grantStatus !== "pending",
    }],
    all_required_query_grants_current: grantStatus === "approved",
    raw_query_egress: false,
    raw_policy_egress: false,
    raw_signature_egress: false,
    ...localRollbackTruth(),
  };
}

function consumedQueryGrantChallenge(
  decision: "approve" | "revoke",
): CollaborationQueryGrantChallenge {
  const query = queryFixture(
    decision === "approve" ? "approved" : "revoked",
  );
  return {
    surface: "collaboration_query_grant_challenge",
    schema_version: 2,
    challenge_id: `qgrant_${"c".repeat(32)}`,
    room_id: query.room_id,
    owner_address: WALLET_A,
    decision,
    room_commitment: query.room_commitment,
    room_generation: query.room_generation,
    query_ref: query.query_ref,
    proposal_commitment: query.proposal_commitment,
    allocation_commitment: query.allocation_commitment,
    owner_policy_commitment: commitment("4"),
    challenge_commitment: commitment("a"),
    message: "x".repeat(128),
    issued_at: 1_900_000_115,
    expires_at: 1_900_000_500,
    status: "consumed",
    authorization_hash_recorded: true,
    reclaimable_after: 1_900_086_900,
    retention_policy: "bounded_reclaimable_after_terminal_or_expiry",
    participant_authenticated_projection: true,
    raw_signature_egress: false,
    ...localRollbackTruth(),
  };
}

describe("wallet-authenticated Collaboration console", () => {
  it("renders the durable room lifecycle without promoting it to execution", () => {
    const html = renderToString(() => createComponent(Collaborate, {}));

    expect(html).toContain("Multi-owner authority console");
    expect(html).toContain("Implemented coordination workspace · release gate closed");
    expect(html).not.toContain("Roadmap workspace · release-gated control plane");
    expect(html).toContain("Collaboration not enabled");
    expect(html).toContain("Control plane closed");
    expect(html).toContain("Modeled current-state integrity");
    expect(html).not.toContain("Observed current file tamper-evident");
    expect(html).toContain("Create a durable room");
    expect(html).toContain("Owner allocation");
    expect(html).toContain("10,000 bps");
    expect(collaborateSource).toContain("JOINT CONSENT SNAPSHOT · NO DISPATCH");
    expect(collaborateSource).toContain(
      "Participant-authenticated projection · schema v2",
    );
    expect(html).toContain("Coordination session · no execution or spend authority");
    expect(html).toContain("No monotonic rollback witness observed");
    expect(collaborateSource).toContain(
      "No monotonic rollback witness · local HMAC only",
    );
    expect(collaborateSource).toContain(
      "Live witness · single-RPC reported-finalized",
    );
    expect(collaborateSource).toContain(
      "Independent RPC quorum and consensus proof are both false.",
    );
    expect(collaborateSource).not.toContain(
      "finalized Base Sepolia anchor verified",
    );
    expect(html).toContain("Generated collaboration brief");
  });

  it("offers an inline wallet handoff and retains bounded snapshot lifecycle facts", () => {
    const html = renderToString(() => createComponent(Collaborate, {
      requestWalletConnection: () => undefined,
    }));

    expect(html).toContain('data-collaboration-handoff="connect-wallet"');
    expect(html).toContain("Connect wallet");
    expect(collaborateSource).toContain("receipt().recorded_at");
    expect(collaborateSource).toContain("receipt().reclaimable_after");
    expect(collaborateSource).toContain("Bounded non-dispatched snapshot");
  });

  it("keeps unobserved and local-HMAC evidence in modeled states", () => {
    expect(collaborationRollbackEvidenceState(undefined)).toBe(
      "unobserved_modeled",
    );
    expect(collaborationRollbackEvidenceState(roomFixture())).toBe(
      "local_hmac_only_modeled",
    );
    expect(collaborateSource).toContain(
      "collaborationRollbackProtectionVerified(projection)",
    );
  });

  it("keeps all network mutations closed in the disconnected server render", () => {
    const html = renderToString(() => createComponent(Collaborate, {}));
    const mutationButtons = [
      ...html.matchAll(
        /<button[^>]*data-collaboration-action="[^"]+"[^>]*>[\s\S]*?<\/button>/g,
      ),
    ];

    expect(mutationButtons.length).toBeGreaterThanOrEqual(2);
    for (const [button] of mutationButtons) expect(button).toContain("disabled");
    expect(collaborateSource).toContain(
      "wallet.authorizeCollaborationConsole()",
    );
    expect(collaborateSource).toContain(
      "wallet.signWalletAuthorizationMessage",
    );
    expect(collaborateSource).toContain("sessionCurrent()");
  });

  it("retrieves and validates the exact consent challenge before signing", () => {
    expect(collaborateSource).toMatch(
      /issueCollaborationConsentChallenge[\s\S]*fetchCollaborationConsentChallenge[\s\S]*assertConsentChallengeForSigning[\s\S]*signWalletAuthorizationMessage/,
    );
    expect(collaborateSource).toContain(
      "challenge.challenge_commitment !== issued.challenge_commitment",
    );
    expect(collaborateSource).toContain(
      "Consent challenge changed between issuance and retrieval",
    );
    expect(collaborateSource).not.toMatch(
      /\b(?:localStorage|sessionStorage|indexedDB)\b/,
    );
  });

  it("labels every receipt evidence gap and never claims a dispatch or settlement", () => {
    const html = renderToString(() => createComponent(Collaborate, {}));

    expect(collaborateSource).toContain("Snapshot, not dispatched");
    expect(collaborateSource).toContain("No provider dispatch");
    expect(collaborateSource).toContain("No TDX attestation");
    expect(collaborateSource).toContain("No settlement or royalties");
    expect(collaborateSource).toMatch(
      /restoring an[\s\n]+older valid snapshot is not yet detectable/,
    );
    expect(html).not.toContain("TDX verified");
    expect(html).not.toContain("Royalties paid");
  });

  it("sends commitments and wallet addresses, not local labels or health data", () => {
    expect(collaborateSource).toContain("localRoomName");
    expect(collaborateSource).toContain(
      "held in component memory, never sent",
    );
    expect(collaborateSource).toContain("purpose_commitment: purposeHash");
    expect(collaborateSource).toContain("pipeline_commitment: pipelineHash");
    expect(collaborateSource).not.toContain("localStorage");
    expect(collaborateSource).not.toContain("rawArtifact");
    expect(collaborateSource).not.toContain("cardNumber");
  });

  it("exposes the complete v2 invitation, role, query, snapshot, and archive workflow", () => {
    for (const action of [
      "accept-invitation",
      "decline-invitation",
      "cancel-invitation",
      "owner-role-consent",
      "propose-query",
      "owner-query-grant",
      "authorize-query",
      "archive-room",
      "rooms-more",
    ]) {
      expect(collaborateSource).toContain(
        `data-collaboration-action="${action}"`,
      );
    }
    expect(collaborateSource).toContain("Membership authority");
    expect(collaborateSource).toContain("Owner room roles");
    expect(collaborateSource).toContain("EXACT QUERY PROPOSAL");
    expect(collaborateSource).toContain("Approve exact query");
    expect(collaborateSource).toContain("JOINT CONSENT SNAPSHOT");
    expect(collaborateSource).toContain("Archive quiescent room");
    expect(collaborateSource).toContain("Load more rooms");
    expect(collaborateSource).toContain("appendCollaborationRoomPage");
    expect(collaborateSource).toContain("cause.restartRequired");
  });

  it("retrieves and validates the exact query-grant challenge around signing", () => {
    expect(collaborateSource).toMatch(
      /issueCollaborationQueryGrantChallenge[\s\S]*fetchCollaborationQueryGrantChallenge[\s\S]*assertQueryGrantChallengeForSigning[\s\S]*signWalletAuthorizationMessage/,
    );
    expect(collaborateSource).toContain(
      "Query-grant challenge changed between issuance and retrieval",
    );
    expect(collaborateSource).toMatch(
      /signWalletAuthorizationMessage\([\s\S]*?authenticatedOperationIsCurrent\(operation\)[\s\S]*?assertQueryGrantChallengeForSigning[\s\S]*?authenticatedOperationIsCurrent\(operation\)[\s\S]*?submitCollaborationQueryGrant/,
    );
  });

  it("binds every authenticated await to an exact monotonic authority epoch", () => {
    const active = sessionFixture();
    const harness = authorityHarness(active);
    const captured = captureAuthority(harness, active);

    expect(authorityMayPublish(captured, harness)).toBe(true);

    harness.authorityEpoch += 1;
    expect(authorityMayPublish(captured, harness)).toBe(false);
    harness.authorityEpoch -= 1;

    harness.operationRevision += 1;
    expect(authorityMayPublish(captured, harness)).toBe(false);
    harness.operationRevision -= 1;

    harness.address = WALLET_B;
    expect(authorityMayPublish(captured, harness)).toBe(false);
    harness.address = WALLET_A;

    harness.chainId = 1;
    expect(authorityMayPublish(captured, harness)).toBe(false);
    harness.chainId = 84532;

    harness.walletAuthorizationVersion += 1;
    expect(authorityMayPublish(captured, harness)).toBe(false);
    harness.walletAuthorizationVersion -= 1;

    harness.releaseFingerprint = releaseFingerprint("d".repeat(40));
    expect(authorityMayPublish(captured, harness)).toBe(false);
    harness.releaseFingerprint = captured.releaseFingerprint;

    harness.nowMs = active.expiresAt * 1_000 - 4_999;
    expect(authorityMayPublish(captured, harness)).toBe(false);
    harness.nowMs = 1_900_000_100_000;

    harness.currentSession = {
      ...active,
      accessToken: `${"d".repeat(40)}.${"e".repeat(40)}.${"f".repeat(40)}`,
    };
    expect(authorityMayPublish(captured, harness)).toBe(false);
    harness.currentSession = undefined;
    expect(authorityMayPublish(captured, harness)).toBe(false);

    expect(collaborateSource).toContain("rotateAuthorityEpoch()");
    expect(collaborateSource).toContain("authorityRequests.abort()");
    expect(
      collaborateSource.match(/authenticatedOperationIsCurrent\(operation\)/g)
        ?.length,
    ).toBeGreaterThanOrEqual(70);
  });

  it("discards every late v2 operation publication after authority drift", async () => {
    const cases = [
      {
        action: "inspectRoom",
        drift(harness: AuthorityHarness) {
          harness.address = WALLET_B;
          harness.authorityEpoch += 1;
        },
      },
      {
        action: "createRoom",
        drift(harness: AuthorityHarness) {
          harness.chainId = 1;
          harness.authorityEpoch += 1;
        },
      },
      {
        action: "activate consent",
        drift(harness: AuthorityHarness) {
          harness.releaseFingerprint = releaseFingerprint("d".repeat(40));
          harness.authorityEpoch += 1;
        },
      },
      {
        action: "revoke consent",
        drift(harness: AuthorityHarness) {
          const active = harness.currentSession;
          if (active) harness.nowMs = active.expiresAt * 1_000 - 4_999;
          harness.authorityEpoch += 1;
        },
      },
      {
        action: "authorizeJointRun",
        drift(harness: AuthorityHarness) {
          harness.currentSession = undefined;
          harness.authorityEpoch += 1;
        },
      },
      {
        action: "refreshRooms",
        drift(harness: AuthorityHarness) {
          harness.walletAuthorizationVersion += 1;
          harness.authorityEpoch += 1;
        },
      },
      {
        action: "loadMoreRooms",
        drift(harness: AuthorityHarness) {
          harness.operationRevision += 1;
          harness.authorityEpoch += 1;
        },
      },
      {
        action: "accept invitation",
        drift(harness: AuthorityHarness) {
          harness.address = WALLET_B;
          harness.authorityEpoch += 1;
        },
      },
      {
        action: "decline invitation",
        drift(harness: AuthorityHarness) {
          harness.chainId = 1;
          harness.authorityEpoch += 1;
        },
      },
      {
        action: "cancel invitation",
        drift(harness: AuthorityHarness) {
          harness.walletAuthorizationVersion += 1;
          harness.authorityEpoch += 1;
        },
      },
      {
        action: "archive room",
        drift(harness: AuthorityHarness) {
          harness.releaseFingerprint = releaseFingerprint("e".repeat(40));
          harness.authorityEpoch += 1;
        },
      },
      {
        action: "propose query",
        drift(harness: AuthorityHarness) {
          harness.currentSession = undefined;
          harness.authorityEpoch += 1;
        },
      },
      {
        action: "approve query",
        drift(harness: AuthorityHarness) {
          harness.address = WALLET_B;
          harness.authorityEpoch += 1;
        },
      },
      {
        action: "revoke query",
        drift(harness: AuthorityHarness) {
          harness.chainId = 1;
          harness.authorityEpoch += 1;
        },
      },
    ] as const;

    for (const testCase of cases) {
      const active = sessionFixture();
      const harness = authorityHarness(active);
      const captured = captureAuthority(harness, active);
      const response = deferred<{ room: string; receipt: string }>();
      const state: {
        rooms: string[];
        selected: string | undefined;
        receipt: string | undefined;
        notice: string;
        error: string;
      } = {
        rooms: ["replacement-room"],
        selected: "replacement-room",
        receipt: "replacement-receipt",
        notice: "replacement session is current",
        error: "",
      };
      const pending = (async () => {
        try {
          const result = await response.promise;
          if (!authorityMayPublish(captured, harness)) return;
          state.rooms = [result.room];
          state.selected = result.room;
          state.receipt = result.receipt;
          state.notice = `${testCase.action} succeeded`;
          state.error = "";
        } catch {
          if (authorityMayPublish(captured, harness)) {
            state.error = `${testCase.action} failed`;
          }
        }
      })();

      testCase.drift(harness);
      response.resolve({
        room: `stale-${testCase.action}`,
        receipt: `stale-receipt-${testCase.action}`,
      });
      await pending;

      expect(state, testCase.action).toEqual({
        rooms: ["replacement-room"],
        selected: "replacement-room",
        receipt: "replacement-receipt",
        notice: "replacement session is current",
        error: "",
      });
    }
  });

  it("does not issue a follow-up bearer request or wallet signature after role, query-grant, or joint-snapshot drift", async () => {
    for (const action of [
      "activate",
      "revoke",
      "query-approve",
      "query-revoke",
      "joint-snapshot",
    ] as const) {
      const active = sessionFixture();
      const harness = authorityHarness(active);
      const captured = captureAuthority(harness, active);
      const firstRead = deferred<string>();
      let followUpBearerRequests = 0;
      let walletSignatures = 0;
      let publishedSuccess = "";

      const pending = (async () => {
        await firstRead.promise;
        if (!authorityMayPublish(captured, harness)) return;
        followUpBearerRequests += 1;
        if (action !== "joint-snapshot") walletSignatures += 1;
        if (!authorityMayPublish(captured, harness)) return;
        publishedSuccess = `${action} complete`;
      })();

      harness.currentSession = undefined;
      harness.authorityEpoch += 1;
      firstRead.resolve("late room projection");
      await pending;

      expect(followUpBearerRequests, action).toBe(0);
      expect(walletSignatures, action).toBe(0);
      expect(publishedSuccess, action).toBe("");
    }

    expect(collaborateSource).toMatch(
      /fetchCollaborationRoom\([\s\S]*?authenticatedOperationIsCurrent\(operation\)[\s\S]*?issueCollaborationConsentChallenge/,
    );
    expect(collaborateSource).toMatch(
      /fetchCollaborationConsentChallenge\([\s\S]*?authenticatedOperationIsCurrent\(operation\)[\s\S]*?signWalletAuthorizationMessage/,
    );
    expect(collaborateSource).toMatch(
      /signWalletAuthorizationMessage\([\s\S]*?authenticatedOperationIsCurrent\(operation\)[\s\S]*?submitCollaborationConsent/,
    );
    expect(collaborateSource).toMatch(
      /fetchCollaborationQueryGrantChallenge\([\s\S]*?authenticatedOperationIsCurrent\(operation\)[\s\S]*?signWalletAuthorizationMessage/,
    );
    expect(collaborateSource).toMatch(
      /signWalletAuthorizationMessage\([\s\S]*?authenticatedOperationIsCurrent\(operation\)[\s\S]*?submitCollaborationQueryGrant/,
    );
    expect(collaborateSource).toMatch(
      /authorizeCollaborationJointRun\([\s\S]*?authenticatedOperationIsCurrent\(operation\)[\s\S]*?fetchCollaborationJointRun/,
    );
  });

  it("discards a late rejection without overwriting replacement-session success or error state", async () => {
    const active = sessionFixture();
    const harness = authorityHarness(active);
    const captured = captureAuthority(harness, active);
    const response = deferred<string>();
    const state: {
      rooms: string[];
      selected: string | undefined;
      receipt: string | undefined;
      notice: string;
      error: string;
    } = {
      rooms: ["replacement-room"],
      selected: "replacement-room",
      receipt: "replacement-receipt",
      notice: "replacement success",
      error: "replacement warning",
    };
    const pending = (async () => {
      try {
        await response.promise;
        if (!authorityMayPublish(captured, harness)) return;
        state.notice = "stale success";
      } catch {
        if (!authorityMayPublish(captured, harness)) return;
        state.rooms = [];
        state.selected = undefined;
        state.receipt = undefined;
        state.notice = "";
        state.error = "stale request failed";
      }
    })();

    harness.currentSession = undefined;
    harness.authorityEpoch += 1;
    response.reject(new Error("old wallet request failed"));
    await pending;

    expect(state).toEqual({
      rooms: ["replacement-room"],
      selected: "replacement-room",
      receipt: "replacement-receipt",
      notice: "replacement success",
      error: "replacement warning",
    });
  });

  it("purges every wallet-scoped draft on disconnect and account replacement", () => {
    for (const transition of ["disconnect", "account switch"] as const) {
      const empty = emptyCollaborationWalletScopedState(
        transition === "disconnect" ? 41 : 42,
      );
      expect(empty.rooms, transition).toEqual([]);
      expect(empty.selectedRoom, transition).toBeUndefined();
      expect(empty.roomLabels, transition).toEqual({});
      expect(empty.jointReceipt, transition).toBeUndefined();
      expect(empty.currentStateObserved, transition).toBe(false);
      expect(empty.localRoomName, transition).toBe("");
      expect(empty.memberInvitations, transition).toBe("");
      expect(empty.purposeCommitment, transition).toBe("");
      expect(empty.pipelineCommitment, transition).toBe("");
      expect(empty.ownerDrafts, transition).toEqual([{
        key: transition === "disconnect" ? 41 : 42,
        address: "",
        allocation: "10000",
        policyCommitment: "",
      }]);
      expect(empty.queryCommitment, transition).toBe("");
      expect(empty.pendingRoomCreation, transition).toBeUndefined();
      expect(empty.pendingConsentRecovery, transition).toBeUndefined();
      expect(empty.pendingQueryProposal, transition).toBeUndefined();
      expect(empty.pendingQueryGrantRecovery, transition).toBeUndefined();
      expect(empty.pendingJointAuthorization, transition).toBeUndefined();
      expect(empty.roomsNextCursor, transition).toBeUndefined();
      expect(empty.roomsHaveMore, transition).toBe(false);
      expect(empty.notice, transition).toBe("");
      expect(empty.error, transition).toBe("");
    }

    const first = emptyCollaborationWalletScopedState(51);
    const second = emptyCollaborationWalletScopedState(52);
    expect(first.rooms).not.toBe(second.rooms);
    expect(first.roomLabels).not.toBe(second.roomLabels);
    expect(first.ownerDrafts).not.toBe(second.ownerDrafts);
    expect(collaborateSource).toMatch(
      /clearCollaborationSession[\s\S]*?purgeWalletScopedCollaborationState\(\)/,
    );
    expect(collaborateSource).toMatch(
      /installSession[\s\S]*?purgeWalletScopedCollaborationState\(\)/,
    );
    expect(collaborateSource).toContain(
      "? [{ ...current[0], address: next.address }]",
    );
  });

  it("recovers a lost room-create response with one retained room ID, key, and immutable request", async () => {
    const request = {
      room_id: `room_${"a".repeat(32)}`,
      idempotency_key: `collab.${"c".repeat(32)}`,
      member_addresses: [WALLET_A, WALLET_B],
      purpose_commitment: commitment("1"),
      pipeline_commitment: commitment("2"),
      corpus_policy_commitments: { [WALLET_A]: commitment("4") },
      owner_allocations_bps: { [WALLET_A]: 10_000 },
    };
    const committed = roomFixture("pending");
    expect(collaborationRoomMatchesCreationIntent(committed, request)).toBe(true);
    expect(collaborationRoomMatchesCreationIntent({
      ...committed,
      purpose_commitment: commitment("9"),
    }, request)).toBe(false);

    const lostResponse = deferred<CollaborationRoom>();
    const observedRequests: typeof request[] = [];
    let durableRoom: CollaborationRoom | undefined;
    const firstAttempt = (async () => {
      observedRequests.push(request);
      try {
        return await lostResponse.promise;
      } catch {
        return undefined;
      }
    })();

    // The durable write commits, but the browser loses the response.
    durableRoom = committed;
    lostResponse.reject(new DOMException("request timed out", "TimeoutError"));
    expect(await firstAttempt).toBeUndefined();

    // Recovery first reads the exact generated room ID and only replays the
    // same immutable request/idempotency tuple if that read is inconclusive.
    const retainedRequest = request;
    observedRequests.push(retainedRequest);
    const recovered = durableRoom;
    expect(recovered).toBeDefined();
    expect(collaborationRoomMatchesCreationIntent(recovered!, retainedRequest))
      .toBe(true);
    expect(observedRequests).toHaveLength(2);
    expect(observedRequests[1]).toBe(observedRequests[0]);
    expect(observedRequests.map((item) => item.room_id))
      .toEqual([request.room_id, request.room_id]);
    expect(observedRequests.map((item) => item.idempotency_key))
      .toEqual([request.idempotency_key, request.idempotency_key]);

    expect(
      collaborateSource.match(/createCollaborationIdentifier\("room"\)/g),
    ).toHaveLength(1);
    expect(collaborateSource).toContain(
      "Retry recovers the exact retained room",
    );
    expect(collaborateSource).toContain(
      "this console will not mint another room ID",
    );
  });

  it("recovers consent only from the exact consumed challenge and matching current room", async () => {
    for (const decision of ["activate", "revoke"] as const) {
      const challenge = consumedChallenge(decision);
      const room = roomFixture(decision === "activate" ? "active" : "revoked");
      const intent = {
        roomId: challenge.room_id,
        challengeId: challenge.challenge_id,
        challengeCommitment: challenge.challenge_commitment,
        ownerAddress: WALLET_A,
        decision,
        roomGeneration: challenge.room_generation,
      };
      const lostSubmit = deferred<void>();
      const challengeRead = deferred<CollaborationConsentChallenge>();
      const roomRead = deferred<CollaborationRoom>();
      const observed = { challengeId: "", roomId: "", success: "" };
      const pending = (async () => {
        try {
          await lostSubmit.promise;
        } catch {
          observed.challengeId = intent.challengeId;
          observed.roomId = intent.roomId;
          const [recoveredChallenge, recoveredRoom] = await Promise.all([
            challengeRead.promise,
            roomRead.promise,
          ]);
          if (collaborationConsentRecoveryMatches(
            recoveredChallenge,
            recoveredRoom,
            intent,
          )) observed.success = `recovered ${decision}`;
        }
      })();

      // EIP-1271 verification commits after the response path is lost.
      lostSubmit.reject(new DOMException("network response lost", "NetworkError"));
      challengeRead.resolve(challenge);
      roomRead.resolve(room);
      await pending;
      expect(observed).toEqual({
        challengeId: challenge.challenge_id,
        roomId: challenge.room_id,
        success: `recovered ${decision}`,
      });

      expect(collaborationConsentRecoveryMatches(
        { ...challenge, challenge_id: `consent_${"f".repeat(32)}` },
        room,
        intent,
      )).toBe(false);
      expect(collaborationConsentRecoveryMatches(
        challenge,
        roomFixture(decision === "activate" ? "revoked" : "active"),
        intent,
      )).toBe(false);
    }

    expect(collaborateSource).toContain("pollConsentRecovery");
    expect(collaborateSource).toContain(
      "Refresh before signing anything else",
    );
  });

  it("recovers query grants only from the exact consumed challenge and current proposal", () => {
    for (const decision of ["approve", "revoke"] as const) {
      const challenge = consumedQueryGrantChallenge(decision);
      const query = queryFixture(
        decision === "approve" ? "approved" : "revoked",
      );
      const intent = {
        roomId: challenge.room_id,
        challengeId: challenge.challenge_id,
        challengeCommitment: challenge.challenge_commitment,
        ownerAddress: WALLET_A,
        decision,
        roomGeneration: challenge.room_generation,
        queryRef: challenge.query_ref,
        proposalCommitment: challenge.proposal_commitment,
      };
      expect(collaborationQueryGrantRecoveryMatches(
        challenge,
        query,
        intent,
      )).toBe(true);
      expect(collaborationQueryGrantRecoveryMatches(
        {
          ...challenge,
          challenge_id: `qgrant_${"f".repeat(32)}`,
        },
        query,
        intent,
      )).toBe(false);
      expect(collaborationQueryGrantRecoveryMatches(
        challenge,
        {
          ...query,
          query_ref: commitment("b"),
        },
        intent,
      )).toBe(false);
      expect(collaborationQueryGrantRecoveryMatches(
        challenge,
        queryFixture(decision === "approve" ? "revoked" : "approved"),
        intent,
      )).toBe(false);
    }
    expect(collaborateSource).toContain("pollQueryGrantRecovery");
    expect(collaborateSource).toContain(
      "only that signature was replayed",
    );
  });

  it("retains one exact query proposal and idempotency key after a lost response", async () => {
    const intent = Object.freeze({
      roomId: `room_${"a".repeat(32)}`,
      queryRef: commitment("7"),
      idempotencyKey: `collab.${"c".repeat(32)}`,
    });
    const firstResponse = deferred<CollaborationQueryProposal>();
    const observed: typeof intent[] = [];
    const pending = (async () => {
      observed.push(intent);
      try {
        return await firstResponse.promise;
      } catch {
        return undefined;
      }
    })();

    firstResponse.reject(new DOMException("response lost", "NetworkError"));
    expect(await pending).toBeUndefined();
    observed.push(intent);
    expect(observed).toEqual([intent, intent]);
    expect(new Set(observed.map((item) => item.roomId)).size).toBe(1);
    expect(new Set(observed.map((item) => item.queryRef)).size).toBe(1);
    expect(new Set(observed.map((item) => item.idempotencyKey)).size).toBe(1);
    expect(collaborateSource).toContain(
      "Retry reuses the exact retained query and idempotency key; the editor remains locked.",
    );
    expect(collaborateSource).toContain("Retry exact proposal");
  });

  it("recovers a lost joint-snapshot response by replaying the exact query and idempotency key", async () => {
    const intent = Object.freeze({
      roomId: `room_${"a".repeat(32)}`,
      queryRef: commitment("7"),
      idempotencyKey: `collab.${"d".repeat(32)}`,
    });
    const firstResponse = deferred<string>();
    const observed: typeof intent[] = [];
    let committedRunId = "";
    const firstAttempt = (async () => {
      observed.push(intent);
      try {
        return await firstResponse.promise;
      } catch {
        return "";
      }
    })();

    committedRunId = `run_${"e".repeat(32)}`;
    firstResponse.reject(new DOMException("response lost", "NetworkError"));
    expect(await firstAttempt).toBe("");

    // The backend idempotency record returns the same committed run on replay.
    observed.push(intent);
    const recoveredRunId = committedRunId;
    expect(recoveredRunId).toBe(`run_${"e".repeat(32)}`);
    expect(observed).toEqual([intent, intent]);
    expect(new Set(observed.map((item) => item.roomId)).size).toBe(1);
    expect(new Set(observed.map((item) => item.queryRef)).size).toBe(1);
    expect(new Set(observed.map((item) => item.idempotencyKey)).size).toBe(1);

    expect(collaborateSource).toContain(
      "executeJointAuthorizationIntent(operation, intent)",
    );
    expect(collaborateSource).toContain(
      "Retry reuses the exact retained query and idempotency key",
    );
    expect(collaborateSource).toContain("Retry exact snapshot");
  });

  it("rejects a late console token when wallet or frontend release context changed", async () => {
    const oldRelease = releaseFingerprint();
    const expectedExternal = collaborationExternalAuthorityFingerprint({
      address: WALLET_A,
      chainId: 84532,
      walletAuthorizationVersion: 7,
      releaseFingerprint: oldRelease,
    });
    const tokenResponse = deferred<string>();
    let currentEpoch = 3;
    let currentOperation = 9;
    let currentExternal = expectedExternal;
    let installedToken = "";
    const pending = (async () => {
      const token = await tokenResponse.promise;
      if (!collaborationAuthorizationAttemptIsCurrent({
        expectedAuthorityEpoch: 3,
        currentAuthorityEpoch: currentEpoch,
        expectedOperationRevision: 9,
        currentOperationRevision: currentOperation,
        expectedExternalFingerprint: expectedExternal,
        currentExternalFingerprint: currentExternal,
      })) return;
      installedToken = token;
    })();

    currentEpoch += 1;
    currentOperation += 1;
    currentExternal = collaborationExternalAuthorityFingerprint({
      address: WALLET_B,
      chainId: 84532,
      walletAuthorizationVersion: 8,
      releaseFingerprint: releaseFingerprint("d".repeat(40)),
    });
    tokenResponse.resolve("stale-token");
    await pending;
    expect(installedToken).toBe("");
  });
});
