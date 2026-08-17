import {
  For,
  Show,
  createEffect,
  createMemo,
  createSignal,
  onCleanup,
} from "solid-js";
import {
  Check,
  CheckCircle2,
  CircleDashed,
  Fingerprint,
  KeyRound,
  LockKeyhole,
  Plus,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  UsersRound,
  WalletCards,
} from "lucide-solid";
import { deployment } from "../config";
import type { Locality } from "../types";
import type { ExecutionPolicyAnchorRelease } from "../lib/executionPolicyAnchor";
import {
  acceptCollaborationInvitation,
  appendCollaborationRoomPage,
  assertConsentChallengeForSigning,
  assertQueryGrantChallengeForSigning,
  archiveCollaborationRoom,
  authorizeCollaborationJointRun,
  cancelCollaborationInvitation,
  CollaborationRequestError,
  collaborationJointRunCurrentForRoom,
  collaborationRollbackProtectionVerified,
  collaborationReleaseConfigured,
  collaborationSessionIsCurrent,
  createCollaborationIdentifier,
  createCollaborationRoom,
  declineCollaborationInvitation,
  fetchCollaborationConsentChallenge,
  fetchCollaborationJointRun,
  fetchCollaborationQueryGrantChallenge,
  fetchCollaborationRoom,
  issueCollaborationConsentChallenge,
  issueCollaborationQueryGrantChallenge,
  listCollaborationRooms,
  parseCollaborationRollbackWitness,
  proposeCollaborationQuery,
  submitCollaborationConsent,
  submitCollaborationQueryGrant,
  type CollaborationConsentChallenge,
  type CollaborationConsentDecision,
  type CollaborationJointRun,
  type CollaborationQueryGrantChallenge,
  type CollaborationQueryGrantDecision,
  type CollaborationQueryProposal,
  type CollaborationRollbackProjection,
  type CollaborationRoom,
  type CollaborationSession,
} from "../lib/collaboration";
import { publicErrorText } from "../lib/errorText";
import { wallet } from "../lib/wallet";
import { collaborationExecutionTransportAdapter } from "../lib/collaborationExecutionTransport";
import { CollaborateExecution } from "./CollaborateExecution";

const COLLAB_TYPES = [
  "Gene modeling (variant-effect on pooled/sealed sequence)",
  "Cell-atlas simulation access",
  "Organ-on-chip access",
  "Sequence-me 101 onboarding",
  "Biopharma TEE setup",
];

const LOCALITIES: { v: Locality; label: string }[] = [
  { v: "on-device", label: "on-device (nothing leaves)" },
  { v: "enclave", label: "enclave / on-prem (bring model to data)" },
  { v: "hybrid", label: "hybrid (egress gated)" },
];

const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;

interface OwnerDraft {
  readonly key: number;
  readonly address: string;
  readonly allocation: string;
  readonly policyCommitment: string;
}

interface CollaborationAuthorizationAttempt {
  readonly authorityEpoch: number;
  readonly operationRevision: number;
  readonly externalFingerprint: string;
}

interface CollaborationAuthenticatedOperation {
  readonly authorityEpoch: number;
  readonly operationRevision: number;
  readonly session: CollaborationSession;
  readonly releaseFingerprint: string;
  readonly signal: AbortSignal;
}

type CollaborationRoomCreationRequest = Parameters<
  typeof createCollaborationRoom
>[1];

interface PendingRoomCreation {
  readonly request: CollaborationRoomCreationRequest;
  readonly localLabel: string;
}

interface PendingConsentRecovery {
  readonly roomId: string;
  readonly challengeId: string;
  readonly challengeCommitment: string;
  readonly ownerAddress: string;
  readonly decision: CollaborationConsentDecision;
  readonly roomGeneration: number;
  readonly signature: string;
}

interface PendingJointAuthorization {
  readonly roomId: string;
  readonly queryRef: string;
  readonly idempotencyKey: string;
}

interface PendingQueryProposal {
  readonly roomId: string;
  readonly queryRef: string;
  readonly idempotencyKey: string;
}

interface PendingQueryGrantRecovery {
  readonly roomId: string;
  readonly challengeId: string;
  readonly challengeCommitment: string;
  readonly ownerAddress: string;
  readonly decision: CollaborationQueryGrantDecision;
  readonly roomGeneration: number;
  readonly queryRef: string;
  readonly proposalCommitment: string;
  readonly signature: string;
}

interface CollaborationReleaseAuthorityContext {
  readonly release: string;
  readonly releaseSha: string | undefined;
  readonly verificationChainReleaseSha: string | undefined;
  readonly releaseIdentityStatus: string;
  readonly collaborationEnabled: boolean;
  readonly delegateUrl: string;
  readonly appId: string;
  readonly cvmId: string;
  readonly composeHash: string;
  readonly imageDigest: string;
  readonly walletAuthDomain: string;
  readonly walletAuthUri: string;
  readonly executionPolicyAnchorRelease?: ExecutionPolicyAnchorRelease;
}

export function collaborationReleaseAuthorityFingerprint(
  context: CollaborationReleaseAuthorityContext = deployment,
): string {
  const anchor = context.executionPolicyAnchorRelease;
  return JSON.stringify([
    "dnai.collaboration.frontend-release-authority.v1",
    context.release,
    context.releaseSha ?? null,
    context.verificationChainReleaseSha ?? null,
    context.releaseIdentityStatus,
    context.collaborationEnabled,
    context.delegateUrl,
    context.appId,
    context.cvmId,
    context.composeHash,
    context.imageDigest,
    context.walletAuthDomain,
    context.walletAuthUri,
    anchor
      ? [
          anchor.address.toLowerCase(),
          anchor.runtimeCodeHash.toLowerCase(),
          anchor.writer.toLowerCase(),
          anchor.writerReleaseCommitment.toLowerCase(),
          anchor.confirmations,
          anchor.maxBlockAgeSeconds,
          anchor.maxFutureBlockSkewSeconds,
        ]
      : null,
  ]);
}

export function collaborationExternalAuthorityFingerprint(input: {
  readonly address: string | undefined;
  readonly chainId: number | undefined;
  readonly walletAuthorizationVersion: number;
  readonly releaseFingerprint: string;
}): string {
  return JSON.stringify([
    "dnai.collaboration.external-authority.v1",
    input.address?.toLowerCase() ?? null,
    input.chainId ?? null,
    input.walletAuthorizationVersion,
    input.releaseFingerprint,
  ]);
}

export function collaborationAuthorizationAttemptIsCurrent(input: {
  readonly expectedAuthorityEpoch: number;
  readonly currentAuthorityEpoch: number;
  readonly expectedOperationRevision: number;
  readonly currentOperationRevision: number;
  readonly expectedExternalFingerprint: string;
  readonly currentExternalFingerprint: string;
}): boolean {
  return input.expectedAuthorityEpoch === input.currentAuthorityEpoch
    && input.expectedOperationRevision === input.currentOperationRevision
    && input.expectedExternalFingerprint === input.currentExternalFingerprint;
}

export function collaborationAuthorityEpochIsCurrent(input: {
  readonly expectedAuthorityEpoch: number;
  readonly currentAuthorityEpoch: number;
  readonly expectedOperationRevision: number;
  readonly currentOperationRevision: number;
  readonly expectedSession: CollaborationSession;
  readonly currentSession: CollaborationSession | undefined;
  readonly expectedReleaseFingerprint: string;
  readonly currentReleaseFingerprint: string;
  readonly currentAddress: string | undefined;
  readonly currentChainId: number | undefined;
  readonly currentWalletAuthorizationVersion: number;
  readonly nowMs?: number;
}): boolean {
  return input.expectedAuthorityEpoch === input.currentAuthorityEpoch
    && input.expectedOperationRevision === input.currentOperationRevision
    && input.expectedSession === input.currentSession
    && input.expectedReleaseFingerprint === input.currentReleaseFingerprint
    && collaborationSessionIsCurrent(input.expectedSession, {
      address: input.currentAddress,
      chainId: input.currentChainId,
      walletAuthorizationVersion: input.currentWalletAuthorizationVersion,
      nowMs: input.nowMs,
    });
}

export type CollaborationRollbackEvidenceState =
  | "unobserved_modeled"
  | "local_hmac_only_modeled"
  | "release_bound_backend_witness";

export function collaborationRollbackEvidenceState(
  projection: CollaborationRollbackProjection | undefined,
): CollaborationRollbackEvidenceState {
  if (!projection) return "unobserved_modeled";
  if (collaborationRollbackProtectionVerified(projection)) {
    return "release_bound_backend_witness";
  }
  try {
    const witness = parseCollaborationRollbackWitness(
      projection.rollback_witness,
    );
    if (
      projection.rollback_protection === false
      && witness.mode === "local_hmac_current_state_non_monotonic"
      && JSON.stringify(witness)
        === JSON.stringify(projection.rollback_witness)
    ) return "local_hmac_only_modeled";
  } catch {
    // A malformed or release-mismatched witness remains unobserved/modelled.
  }
  return "unobserved_modeled";
}

function safeError(cause: unknown, fallback: string): string {
  return publicErrorText(
    cause instanceof Error ? cause.message : fallback,
    fallback,
  );
}

function short(value: string, left = 10, right = 8): string {
  return value.length <= left + right + 3
    ? value
    : `${value.slice(0, left)}…${value.slice(-right)}`;
}

function formatTime(value: number): string {
  try {
    return new Intl.DateTimeFormat(undefined, {
      dateStyle: "medium",
      timeStyle: "short",
    }).format(new Date(value * 1_000));
  } catch {
    return "Invalid timestamp";
  }
}

function parseInvitations(value: string): string[] {
  const parts = value
    .split(/[\s,;]+/)
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean);
  if (parts.some((item) => !ADDRESS.test(item))) {
    throw new Error("Every member invitation must be a complete 0x wallet address");
  }
  return [...new Set(parts)];
}

function allocationValue(value: string): number {
  return /^(?:[1-9][0-9]{0,3}|10000)$/.test(value)
    ? Number(value)
    : 0;
}

export function emptyCollaborationWalletScopedState(ownerKey: number): {
  readonly rooms: readonly CollaborationRoom[];
  readonly selectedRoom: undefined;
  readonly roomLabels: Readonly<Record<string, string>>;
  readonly jointReceipt: undefined;
  readonly currentStateObserved: false;
  readonly localRoomName: "";
  readonly memberInvitations: "";
  readonly purposeCommitment: "";
  readonly pipelineCommitment: "";
  readonly ownerDrafts: readonly OwnerDraft[];
  readonly queryCommitment: "";
  readonly pendingRoomCreation: undefined;
  readonly pendingConsentRecovery: undefined;
  readonly pendingQueryProposal: undefined;
  readonly pendingQueryGrantRecovery: undefined;
  readonly pendingJointAuthorization: undefined;
  readonly roomsNextCursor: undefined;
  readonly roomsHaveMore: false;
  readonly busy: "";
  readonly error: "";
  readonly notice: "";
} {
  return {
    rooms: [],
    selectedRoom: undefined,
    roomLabels: Object.freeze({}),
    jointReceipt: undefined,
    currentStateObserved: false,
    localRoomName: "",
    memberInvitations: "",
    purposeCommitment: "",
    pipelineCommitment: "",
    ownerDrafts: Object.freeze([{
      key: ownerKey,
      address: "",
      allocation: "10000",
      policyCommitment: "",
    }]),
    queryCommitment: "",
    pendingRoomCreation: undefined,
    pendingConsentRecovery: undefined,
    pendingQueryProposal: undefined,
    pendingQueryGrantRecovery: undefined,
    pendingJointAuthorization: undefined,
    roomsNextCursor: undefined,
    roomsHaveMore: false,
    busy: "",
    error: "",
    notice: "",
  };
}

function sameStrings(
  left: readonly string[],
  right: readonly string[],
): boolean {
  return left.length === right.length
    && left.every((value, index) => value === right[index]);
}

export function collaborationRoomMatchesCreationIntent(
  room: CollaborationRoom,
  request: CollaborationRoomCreationRequest,
): boolean {
  const expectedMembers = [...request.member_addresses]
    .map((value) => value.toLowerCase())
    .sort();
  const observedMembers = [...room.declared_member_addresses].sort();
  const expectedOwners = Object.keys(request.corpus_policy_commitments).sort();
  const observedOwners = room.owners
    .map((owner) => owner.owner_address)
    .sort();
  return room.room_id === request.room_id
    && sameStrings(observedMembers, expectedMembers)
    && room.purpose_commitment === request.purpose_commitment
    && room.pipeline_commitment === request.pipeline_commitment
    && sameStrings(observedOwners, expectedOwners)
    && room.owners.every((owner) => (
      request.corpus_policy_commitments[owner.owner_address]
        === owner.corpus_policy_commitment
      && request.owner_allocations_bps[owner.owner_address]
        === owner.allocation_bps
    ));
}

export function collaborationConsentRecoveryMatches(
  challenge: CollaborationConsentChallenge,
  room: CollaborationRoom,
  intent: Omit<PendingConsentRecovery, "signature">,
): boolean {
  const owner = room.owners.find(
    (candidate) => candidate.owner_address === intent.ownerAddress,
  );
  return challenge.challenge_id === intent.challengeId
    && challenge.challenge_commitment === intent.challengeCommitment
    && challenge.room_id === intent.roomId
    && challenge.owner_address === intent.ownerAddress
    && challenge.decision === intent.decision
    && challenge.room_generation === intent.roomGeneration
    && challenge.status === "consumed"
    && challenge.authorization_hash_recorded
    && room.room_id === intent.roomId
    && room.generation > intent.roomGeneration
    && owner?.role_authorization_hash_recorded === true
    && owner.role_consent_status === (
      intent.decision === "activate" ? "active" : "revoked"
    );
}

export function collaborationQueryGrantRecoveryMatches(
  challenge: CollaborationQueryGrantChallenge,
  query: CollaborationQueryProposal,
  intent: Omit<PendingQueryGrantRecovery, "signature">,
): boolean {
  const grant = query.owner_query_grants.find(
    (candidate) => candidate.owner_address === intent.ownerAddress,
  );
  return challenge.challenge_id === intent.challengeId
    && challenge.challenge_commitment === intent.challengeCommitment
    && challenge.room_id === intent.roomId
    && challenge.owner_address === intent.ownerAddress
    && challenge.decision === intent.decision
    && challenge.room_generation === intent.roomGeneration
    && challenge.query_ref === intent.queryRef
    && challenge.proposal_commitment === intent.proposalCommitment
    && challenge.status === "consumed"
    && challenge.authorization_hash_recorded
    && query.room_id === intent.roomId
    && query.query_ref === intent.queryRef
    && query.proposal_commitment === intent.proposalCommitment
    && query.proposal_current
    && grant?.authorization_hash_recorded === true
    && grant.grant_status === (
      intent.decision === "approve" ? "approved" : "revoked"
    );
}

function recoveryPause(signal: AbortSignal, delayMs = 300): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) {
      reject(new DOMException("Collaboration authority was cleared", "AbortError"));
      return;
    }
    const aborted = () => {
      clearTimeout(timer);
      reject(new DOMException("Collaboration authority was cleared", "AbortError"));
    };
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", aborted);
      resolve();
    }, delayMs);
    signal.addEventListener("abort", aborted, { once: true });
  });
}

export function Collaborate(props: {
  requestWalletConnection?: () => void;
} = {}) {
  const [session, setSession] = createSignal<CollaborationSession>();
  const [rooms, setRooms] = createSignal<readonly CollaborationRoom[]>([]);
  const [roomsNextCursor, setRoomsNextCursor] = createSignal<string>();
  const [roomsHaveMore, setRoomsHaveMore] = createSignal(false);
  const [selectedRoom, setSelectedRoom] = createSignal<CollaborationRoom>();
  const [roomLabels, setRoomLabels] = createSignal<Readonly<Record<string, string>>>({});
  const [jointReceipt, setJointReceipt] = createSignal<CollaborationJointRun>();
  const [rollbackProjection, setRollbackProjection] =
    createSignal<CollaborationRollbackProjection>();
  const [busy, setBusy] = createSignal("");
  const [error, setError] = createSignal("");
  const [notice, setNotice] = createSignal("");

  const [localRoomName, setLocalRoomName] = createSignal("");
  const [memberInvitations, setMemberInvitations] = createSignal("");
  const [purposeCommitment, setPurposeCommitment] = createSignal("");
  const [pipelineCommitment, setPipelineCommitment] = createSignal("");
  let nextOwnerKey = 2;
  const [ownerDrafts, setOwnerDrafts] = createSignal<readonly OwnerDraft[]>([
    { key: 1, address: "", allocation: "10000", policyCommitment: "" },
  ]);
  const [queryCommitment, setQueryCommitment] = createSignal("");
  const [pendingRoomCreation, setPendingRoomCreation] = createSignal<
    PendingRoomCreation
  >();
  const [pendingConsentRecovery, setPendingConsentRecovery] = createSignal<
    PendingConsentRecovery
  >();
  const [pendingQueryProposal, setPendingQueryProposal] = createSignal<
    PendingQueryProposal
  >();
  const [pendingQueryGrantRecovery, setPendingQueryGrantRecovery] = createSignal<
    PendingQueryGrantRecovery
  >();
  const [pendingJointAuthorization, setPendingJointAuthorization] = createSignal<
    PendingJointAuthorization
  >();

  const [org, setOrg] = createSignal("");
  const [ctype, setCtype] = createSignal(COLLAB_TYPES[0]);
  const [locality, setLocality] = createSignal<Locality>("enclave");
  const [purpose, setPurpose] = createSignal("");
  const [budget, setBudget] = createSignal("");
  const [royalty, setRoyalty] = createSignal("");
  const [summary, setSummary] = createSignal("");
  const [copyState, setCopyState] = createSignal<"idle" | "copied" | "failed">("idle");

  let authorityEpoch = 0;
  let operationRevision = 0;
  let authorityRequests = new AbortController();
  let installedSessionReleaseFingerprint = "";
  let observedExternalAuthorityFingerprint: string | undefined;
  let expiryTimer: ReturnType<typeof setTimeout> | undefined;
  const walletMutationIdempotencyKeys = new Map<string, string>();

  const sessionCurrent = createMemo(() => collaborationSessionIsCurrent(
    session(),
    {
      address: wallet.account(),
      chainId: wallet.chainId(),
      walletAuthorizationVersion: wallet.authorizationVersion(),
    },
  ) && installedSessionReleaseFingerprint === collaborationReleaseAuthorityFingerprint());
  const releaseConfigured = createMemo(() => collaborationReleaseConfigured());
  const rollbackEvidence = createMemo(() => (
    collaborationRollbackEvidenceState(rollbackProjection())
  ));
  const connectedAddress = createMemo(() => (
    wallet.account()?.toLowerCase() ?? ""
  ));
  const allocationTotal = createMemo(() => ownerDrafts().reduce(
    (total, owner) => total + allocationValue(owner.allocation),
    0,
  ));

  const externalAuthorityFingerprint = () => (
    collaborationExternalAuthorityFingerprint({
      address: wallet.account(),
      chainId: wallet.chainId(),
      walletAuthorizationVersion: wallet.authorizationVersion(),
      releaseFingerprint: collaborationReleaseAuthorityFingerprint(),
    })
  );

  const rotateAuthorityEpoch = () => {
    authorityEpoch += 1;
    authorityRequests.abort();
    authorityRequests = new AbortController();
  };

  const purgeWalletScopedCollaborationState = () => {
    const empty = emptyCollaborationWalletScopedState(nextOwnerKey++);
    setRooms(empty.rooms);
    setRoomsNextCursor(empty.roomsNextCursor);
    setRoomsHaveMore(empty.roomsHaveMore);
    setSelectedRoom(empty.selectedRoom);
    setRoomLabels(empty.roomLabels);
    setJointReceipt(empty.jointReceipt);
    setRollbackProjection(undefined);
    setLocalRoomName(empty.localRoomName);
    setMemberInvitations(empty.memberInvitations);
    setPurposeCommitment(empty.purposeCommitment);
    setPipelineCommitment(empty.pipelineCommitment);
    setOwnerDrafts(empty.ownerDrafts);
    setQueryCommitment(empty.queryCommitment);
    setPendingRoomCreation(empty.pendingRoomCreation);
    setPendingConsentRecovery(empty.pendingConsentRecovery);
    setPendingQueryProposal(empty.pendingQueryProposal);
    setPendingQueryGrantRecovery(empty.pendingQueryGrantRecovery);
    setPendingJointAuthorization(empty.pendingJointAuthorization);
    walletMutationIdempotencyKeys.clear();
    setBusy(empty.busy);
    setError(empty.error);
    setNotice(empty.notice);
  };

  const clearCollaborationSession = (message = "") => {
    rotateAuthorityEpoch();
    operationRevision += 1;
    if (expiryTimer) clearTimeout(expiryTimer);
    expiryTimer = undefined;
    installedSessionReleaseFingerprint = "";
    setSession(undefined);
    purgeWalletScopedCollaborationState();
    setError(message);
  };

  const installSession = (next: CollaborationSession) => {
    if (expiryTimer) clearTimeout(expiryTimer);
    rotateAuthorityEpoch();
    installedSessionReleaseFingerprint = collaborationReleaseAuthorityFingerprint();
    purgeWalletScopedCollaborationState();
    setSession(next);
    const delay = Math.max(0, next.expiresAt * 1_000 - Date.now() - 4_000);
    expiryTimer = setTimeout(() => {
      clearCollaborationSession(
        "The wallet-scoped Collaboration session expired. Authorize again to continue.",
      );
    }, delay);
  };

  const currentSession = (): CollaborationSession => {
    const value = session();
    if (
      !collaborationReleaseConfigured()
      || installedSessionReleaseFingerprint
        !== collaborationReleaseAuthorityFingerprint()
      || !collaborationSessionIsCurrent(value, {
        address: wallet.account(),
        chainId: wallet.chainId(),
        walletAuthorizationVersion: wallet.authorizationVersion(),
      })
    ) {
      clearCollaborationSession(
        "Wallet, network, session expiry, or frontend release context changed. Authorize a fresh Collaboration session.",
      );
      throw new Error("A current wallet-scoped Collaboration session is required");
    }
    return value;
  };

  const beginAuthenticatedOperation = (
    busyState: string,
  ): CollaborationAuthenticatedOperation | undefined => {
    let active: CollaborationSession;
    try {
      active = currentSession();
    } catch {
      return undefined;
    }
    const revision = ++operationRevision;
    setBusy(busyState);
    setError("");
    setNotice("");
    return {
      authorityEpoch,
      operationRevision: revision,
      session: active,
      releaseFingerprint: installedSessionReleaseFingerprint,
      signal: authorityRequests.signal,
    };
  };

  const authenticatedOperationIsCurrent = (
    operation: CollaborationAuthenticatedOperation,
  ): boolean => {
    const authorityContextCurrent = collaborationAuthorityEpochIsCurrent({
      expectedAuthorityEpoch: operation.authorityEpoch,
      currentAuthorityEpoch: authorityEpoch,
      expectedOperationRevision: operation.operationRevision,
      currentOperationRevision: operation.operationRevision,
      expectedSession: operation.session,
      currentSession: session(),
      expectedReleaseFingerprint: operation.releaseFingerprint,
      currentReleaseFingerprint: collaborationReleaseAuthorityFingerprint(),
      currentAddress: wallet.account(),
      currentChainId: wallet.chainId(),
      currentWalletAuthorizationVersion: wallet.authorizationVersion(),
    });
    if (
      !authorityContextCurrent
      && operation.authorityEpoch === authorityEpoch
      && operation.session === session()
    ) {
      clearCollaborationSession(
        "Wallet, network, session expiry, or frontend release context changed. Collaboration authority was cleared.",
      );
      return false;
    }
    return authorityContextCurrent
      && operation.operationRevision === operationRevision;
  };

  const finishAuthenticatedOperation = (
    operation: CollaborationAuthenticatedOperation,
  ) => {
    if (authenticatedOperationIsCurrent(operation)) setBusy("");
  };

  const reportAuthenticatedOperationError = (
    operation: CollaborationAuthenticatedOperation,
    cause: unknown,
    fallback: string,
  ) => {
    if (authenticatedOperationIsCurrent(operation)) {
      setError(safeError(cause, fallback));
    }
  };

  createEffect(() => {
    const nextFingerprint = externalAuthorityFingerprint();
    const previousFingerprint = observedExternalAuthorityFingerprint;
    observedExternalAuthorityFingerprint = nextFingerprint;
    if (
      previousFingerprint !== undefined
      && previousFingerprint !== nextFingerprint
    ) {
      clearCollaborationSession(
        session()
          ? "Wallet, network, or frontend release context changed. Collaboration authority was cleared."
          : "",
      );
    }
  });

  onCleanup(() => {
    authorityEpoch += 1;
    operationRevision += 1;
    authorityRequests.abort();
    if (expiryTimer) clearTimeout(expiryTimer);
  });

  const observeRollbackProjection = (
    next: CollaborationRollbackProjection,
  ) => {
    const previous = rollbackProjection();
    if (
      previous
      && collaborationRollbackProtectionVerified(previous)
      && collaborationRollbackProtectionVerified(next)
      && (
        next.rollback_witness.authority_context_hash
          !== previous.rollback_witness.authority_context_hash
        || next.rollback_witness.anchor_sequence
          < previous.rollback_witness.anchor_sequence
        || (
          next.rollback_witness.anchor_sequence
            === previous.rollback_witness.anchor_sequence
          && JSON.stringify(next.rollback_witness)
            !== JSON.stringify(previous.rollback_witness)
        )
      )
    ) {
      setRollbackProjection(undefined);
      throw new Error(
        "Collaboration rollback witness regressed or changed at one anchor sequence",
      );
    }
    setRollbackProjection(next);
  };

  const upsertRoom = (room: CollaborationRoom) => {
    observeRollbackProjection(room);
    setRooms((current) => {
      const remaining = current.filter((item) => item.room_id !== room.room_id);
      return [room, ...remaining];
    });
    if (selectedRoom()?.room_id === room.room_id) setSelectedRoom(room);
  };

  const loadRooms = async (
    operation: CollaborationAuthenticatedOperation,
    cursor?: string,
  ): Promise<boolean> => {
    const result = await listCollaborationRooms(
      operation.session.accessToken,
      {
        limit: 8,
        cursor,
        signal: operation.signal,
      },
    );
    if (!authenticatedOperationIsCurrent(operation)) return false;
    const nextRooms = cursor
      ? appendCollaborationRoomPage(rooms(), result)
      : result.rooms;
    observeRollbackProjection(result);
    setRooms(nextRooms);
    setRoomsNextCursor(result.next_cursor ?? undefined);
    setRoomsHaveMore(result.has_more);
    const selected = selectedRoom();
    if (selected) {
      setSelectedRoom(
        nextRooms.find((room) => room.room_id === selected.room_id),
      );
    }
    return true;
  };

  const authorizationAttemptIsCurrent = (
    attempt: CollaborationAuthorizationAttempt,
  ): boolean => {
    const current = collaborationAuthorizationAttemptIsCurrent({
      expectedAuthorityEpoch: attempt.authorityEpoch,
      currentAuthorityEpoch: authorityEpoch,
      expectedOperationRevision: attempt.operationRevision,
      currentOperationRevision: operationRevision,
      expectedExternalFingerprint: attempt.externalFingerprint,
      currentExternalFingerprint: externalAuthorityFingerprint(),
    });
    if (
      !current
      && attempt.authorityEpoch === authorityEpoch
      && attempt.operationRevision === operationRevision
    ) {
      clearCollaborationSession(
        "Wallet, network, or frontend release context changed during authorization. Start again.",
      );
    }
    return current;
  };

  const passiveAttemptIsCurrent = (
    attempt: CollaborationAuthorizationAttempt,
  ): boolean => collaborationAuthorizationAttemptIsCurrent({
    expectedAuthorityEpoch: attempt.authorityEpoch,
    currentAuthorityEpoch: authorityEpoch,
    expectedOperationRevision: attempt.operationRevision,
    currentOperationRevision: operationRevision,
    expectedExternalFingerprint: attempt.externalFingerprint,
    currentExternalFingerprint: externalAuthorityFingerprint(),
  });

  const authorizeConsole = async () => {
    setError("");
    setNotice("");
    if (!releaseConfigured()) {
      setError(
        "The coordination and execution mutation paths are implemented, but this unsigned/dev frontend release does not authorize writes.",
      );
      return;
    }
    if (!wallet.account()) {
      setError("Connect a wallet from the site header before authorizing Collaboration.");
      return;
    }
    if (!wallet.isCorrectChain()) {
      setError("Switch the connected wallet to Base Sepolia before authorizing.");
      return;
    }
    const attempt: CollaborationAuthorizationAttempt = {
      authorityEpoch,
      operationRevision: ++operationRevision,
      externalFingerprint: externalAuthorityFingerprint(),
    };
    let installedOperation: CollaborationAuthenticatedOperation | undefined;
    setBusy("authorize");
    try {
      const token = await wallet.authorizeCollaborationConsole();
      if (!authorizationAttemptIsCurrent(attempt)) return;
      const next: CollaborationSession = {
        accessToken: token.access_token,
        address: token.address.toLowerCase(),
        issuedAt: token.issued_at,
        expiresAt: token.expires_at,
        walletAuthorizationVersion: wallet.authorizationVersion(),
      };
      installSession(next);
      setBusy("authorize");
      installedOperation = {
        authorityEpoch,
        operationRevision: attempt.operationRevision,
        session: next,
        releaseFingerprint: installedSessionReleaseFingerprint,
        signal: authorityRequests.signal,
      };
      setOwnerDrafts((current) => (
        current.length === 1 && !current[0].address
          ? [{ ...current[0], address: next.address }]
          : current
      ));
      if (
        await loadRooms(installedOperation)
        && authenticatedOperationIsCurrent(installedOperation)
      ) {
        setNotice(
          "Wallet-scoped room access established. No room, consent, transaction, execution, or fund movement was authorized by that signature.",
        );
      }
    } catch (cause) {
      const mayPublish = installedOperation
        ? authenticatedOperationIsCurrent(installedOperation)
        : authorizationAttemptIsCurrent(attempt);
      if (!mayPublish) return;
      clearCollaborationSession();
      setError(safeError(cause, "Could not authorize Collaboration access"));
    } finally {
      if (
        installedOperation
          ? authenticatedOperationIsCurrent(installedOperation)
          : authorizationAttemptIsCurrent(attempt)
      ) setBusy("");
    }
  };

  const switchChain = async () => {
    const attempt: CollaborationAuthorizationAttempt = {
      authorityEpoch,
      operationRevision: ++operationRevision,
      externalFingerprint: externalAuthorityFingerprint(),
    };
    setBusy("switch");
    setError("");
    setNotice("");
    try {
      await wallet.switchToBase();
    } catch (cause) {
      if (passiveAttemptIsCurrent(attempt)) {
        setError(safeError(cause, "Could not switch to Base Sepolia"));
      }
    } finally {
      if (passiveAttemptIsCurrent(attempt)) setBusy("");
    }
  };

  const refreshRooms = async () => {
    const operation = beginAuthenticatedOperation("refresh");
    if (!operation) return;
    const retainedRunId = jointReceipt()?.run_id;
    setJointReceipt(undefined);
    try {
      if (
        await loadRooms(operation)
        && authenticatedOperationIsCurrent(operation)
      ) {
        if (retainedRunId) {
          const refreshedRun = await fetchCollaborationJointRun(
            operation.session.accessToken,
            retainedRunId,
            operation.signal,
          );
          if (!authenticatedOperationIsCurrent(operation)) return;
          observeRollbackProjection(refreshedRun);
          setJointReceipt(refreshedRun);
        }
        setNotice(
          retainedRunId
            ? "Participant-visible room and joint-snapshot projections refreshed."
            : "Participant-visible room projections refreshed.",
        );
      }
    } catch (cause) {
      reportAuthenticatedOperationError(
        operation,
        cause,
        "Could not refresh Collaboration rooms",
      );
    } finally {
      finishAuthenticatedOperation(operation);
    }
  };

  const loadMoreRooms = async () => {
    const cursor = roomsNextCursor();
    if (!cursor || !roomsHaveMore()) return;
    const operation = beginAuthenticatedOperation("rooms-more");
    if (!operation) return;
    try {
      if (
        await loadRooms(operation, cursor)
        && authenticatedOperationIsCurrent(operation)
      ) setNotice("Loaded the next participant-visible room page.");
    } catch (cause) {
      if (
        cause instanceof CollaborationRequestError
        && cause.restartRequired
        && authenticatedOperationIsCurrent(operation)
      ) {
        try {
          if (
            await loadRooms(operation)
            && authenticatedOperationIsCurrent(operation)
          ) {
            setNotice(
              "The room snapshot changed while paging, so the list restarted from its first bounded page.",
            );
          }
          return;
        } catch (restartCause) {
          reportAuthenticatedOperationError(
            operation,
            restartCause,
            "Could not restart the Collaboration room list",
          );
          return;
        }
      }
      reportAuthenticatedOperationError(
        operation,
        cause,
        "Could not load more Collaboration rooms",
      );
    } finally {
      finishAuthenticatedOperation(operation);
    }
  };

  const inspectRoom = async (room: CollaborationRoom) => {
    const operation = beginAuthenticatedOperation(`room:${room.room_id}`);
    if (!operation) return;
    setJointReceipt(undefined);
    try {
      const current = await fetchCollaborationRoom(
        operation.session.accessToken,
        room.room_id,
        operation.signal,
      );
      if (!authenticatedOperationIsCurrent(operation)) return;
      upsertRoom(current);
      setSelectedRoom(current);
    } catch (cause) {
      reportAuthenticatedOperationError(
        operation,
        cause,
        "Could not read the Collaboration room",
      );
    } finally {
      finishAuthenticatedOperation(operation);
    }
  };

  const retainedMutationIdempotencyKey = (scope: string): string => {
    const existing = walletMutationIdempotencyKeys.get(scope);
    if (existing) return existing;
    const created = createCollaborationIdentifier("idem");
    walletMutationIdempotencyKeys.set(scope, created);
    return created;
  };

  const replayIdempotentMutation = async <T,>(
    operation: CollaborationAuthenticatedOperation,
    action: () => Promise<T>,
  ): Promise<{ readonly value: T; readonly recovered: boolean }> => {
    try {
      const value = await action();
      if (!authenticatedOperationIsCurrent(operation)) {
        throw new DOMException("Collaboration authority changed", "AbortError");
      }
      return { value, recovered: false };
    } catch (cause) {
      if (!authenticatedOperationIsCurrent(operation)) throw cause;
      await recoveryPause(operation.signal);
      if (!authenticatedOperationIsCurrent(operation)) throw cause;
      const value = await action();
      if (!authenticatedOperationIsCurrent(operation)) {
        throw new DOMException("Collaboration authority changed", "AbortError");
      }
      return { value, recovered: true };
    }
  };

  const respondToInvitation = async (
    decision: "accept" | "decline",
  ) => {
    const room = selectedRoom();
    if (!room || room.requester_membership_status !== "invited") return;
    const operation = beginAuthenticatedOperation(`invitation:${decision}`);
    if (!operation) return;
    const scope = `invitation:${decision}:${room.room_id}`;
    const idempotencyKey = retainedMutationIdempotencyKey(scope);
    try {
      const response = await replayIdempotentMutation(operation, () => (
        decision === "accept"
          ? acceptCollaborationInvitation(
              operation.session.accessToken,
              room.room_id,
              idempotencyKey,
              operation.signal,
            )
          : declineCollaborationInvitation(
              operation.session.accessToken,
              room.room_id,
              idempotencyKey,
              operation.signal,
            )
      ));
      if (!authenticatedOperationIsCurrent(operation)) return;
      observeRollbackProjection(response.value);
      walletMutationIdempotencyKeys.delete(scope);
      if (decision === "decline") {
        setRooms((current) => current.filter(
          (candidate) => candidate.room_id !== room.room_id,
        ));
        setSelectedRoom(undefined);
        setJointReceipt(undefined);
        setNotice(
          response.recovered
            ? "Recovered the exact invitation decline after an ambiguous response. This wallet no longer has room visibility."
            : "Invitation declined. This wallet no longer has room visibility.",
        );
        return;
      }
      const updated = await fetchCollaborationRoom(
        operation.session.accessToken,
        room.room_id,
        operation.signal,
      );
      if (!authenticatedOperationIsCurrent(operation)) return;
      upsertRoom(updated);
      setSelectedRoom(updated);
      setNotice(
        response.recovered
          ? "Recovered the exact invitation acceptance. Owner-role and query approvals remain separate."
          : "Membership accepted. Owner-role and query approvals remain separate.",
      );
    } catch (cause) {
      if (authenticatedOperationIsCurrent(operation)) {
        setError(
          `Invitation ${decision} outcome is ambiguous. Retry reuses the exact retained idempotency key.`,
        );
      }
    } finally {
      finishAuthenticatedOperation(operation);
    }
  };

  const cancelInvitation = async (inviteeAddress: string) => {
    const room = selectedRoom();
    if (!room || room.creator_address !== connectedAddress()) return;
    const operation = beginAuthenticatedOperation(
      `invitation:cancel:${inviteeAddress}`,
    );
    if (!operation) return;
    const scope = `invitation:cancel:${room.room_id}:${inviteeAddress}`;
    const idempotencyKey = retainedMutationIdempotencyKey(scope);
    try {
      const response = await replayIdempotentMutation(operation, () => (
        cancelCollaborationInvitation(
          operation.session.accessToken,
          room.room_id,
          inviteeAddress,
          idempotencyKey,
          operation.signal,
        )
      ));
      if (!authenticatedOperationIsCurrent(operation)) return;
      observeRollbackProjection(response.value);
      const updated = await fetchCollaborationRoom(
        operation.session.accessToken,
        room.room_id,
        operation.signal,
      );
      if (!authenticatedOperationIsCurrent(operation)) return;
      walletMutationIdempotencyKeys.delete(scope);
      upsertRoom(updated);
      setSelectedRoom(updated);
      setNotice(
        response.recovered
          ? "Recovered the exact invitation cancellation after an ambiguous response."
          : "Pending invitation cancelled.",
      );
    } catch (cause) {
      if (authenticatedOperationIsCurrent(operation)) {
        setError(
          "Invitation cancellation outcome is ambiguous. Retry reuses the exact retained invitee and idempotency key.",
        );
      }
    } finally {
      finishAuthenticatedOperation(operation);
    }
  };

  const archiveRoom = async () => {
    const room = selectedRoom();
    if (!room || room.creator_address !== connectedAddress()) return;
    const operation = beginAuthenticatedOperation("archive");
    if (!operation) return;
    const scope = `archive:${room.room_id}`;
    const idempotencyKey = retainedMutationIdempotencyKey(scope);
    try {
      const response = await replayIdempotentMutation(operation, () => (
        archiveCollaborationRoom(
          operation.session.accessToken,
          room.room_id,
          idempotencyKey,
          operation.signal,
        )
      ));
      if (!authenticatedOperationIsCurrent(operation)) return;
      walletMutationIdempotencyKeys.delete(scope);
      upsertRoom(response.value);
      setSelectedRoom(response.value);
      setJointReceipt(undefined);
      setNotice(
        response.recovered
          ? "Recovered the exact archive action. This room is now bounded-retention history."
          : "Room archived. It is now bounded-retention history with no live authority.",
      );
    } catch (cause) {
      if (authenticatedOperationIsCurrent(operation)) {
        setError(
          "Room archive outcome is ambiguous or the room is not quiescent. Retry reuses the exact retained action.",
        );
      }
    } finally {
      finishAuthenticatedOperation(operation);
    }
  };

  const updateOwner = (
    key: number,
    field: "address" | "allocation" | "policyCommitment",
    value: string,
  ) => {
    setOwnerDrafts((current) => current.map((owner) => (
      owner.key === key ? { ...owner, [field]: value } : owner
    )));
  };

  const addOwner = () => {
    if (ownerDrafts().length >= 16) return;
    const count = ownerDrafts().length + 1;
    const equal = Math.floor(10_000 / count);
    const next = ownerDrafts().map((owner) => ({
      ...owner,
      allocation: String(equal),
    }));
    const allocated = equal * count;
    next[0] = {
      ...next[0],
      allocation: String(equal + (10_000 - allocated)),
    };
    setOwnerDrafts([
      ...next,
      {
        key: nextOwnerKey++,
        address: "",
        allocation: String(equal),
        policyCommitment: "",
      },
    ]);
  };

  const removeOwner = (key: number) => {
    if (ownerDrafts().length <= 1) return;
    setOwnerDrafts((current) => current.filter((owner) => owner.key !== key));
  };

  const recoverRoomCreation = async (
    operation: CollaborationAuthenticatedOperation,
    intent: PendingRoomCreation,
  ): Promise<CollaborationRoom> => {
    try {
      const observed = await fetchCollaborationRoom(
        operation.session.accessToken,
        intent.request.room_id,
        operation.signal,
      );
      if (!authenticatedOperationIsCurrent(operation)) {
        throw new DOMException("Collaboration authority changed", "AbortError");
      }
      if (!collaborationRoomMatchesCreationIntent(observed, intent.request)) {
        throw new Error(
          "The recovered room ID does not match the retained immutable creation intent",
        );
      }
      return observed;
    } catch (cause) {
      if (!authenticatedOperationIsCurrent(operation)) throw cause;
    }

    try {
      const replayed = await createCollaborationRoom(
        operation.session.accessToken,
        intent.request,
        operation.signal,
      );
      if (!authenticatedOperationIsCurrent(operation)) {
        throw new DOMException("Collaboration authority changed", "AbortError");
      }
      if (!collaborationRoomMatchesCreationIntent(replayed, intent.request)) {
        throw new Error(
          "The idempotent room replay returned a different immutable intent",
        );
      }
      return replayed;
    } catch (cause) {
      if (!authenticatedOperationIsCurrent(operation)) throw cause;
    }

    try {
      const observed = await fetchCollaborationRoom(
        operation.session.accessToken,
        intent.request.room_id,
        operation.signal,
      );
      if (!authenticatedOperationIsCurrent(operation)) {
        throw new DOMException("Collaboration authority changed", "AbortError");
      }
      if (collaborationRoomMatchesCreationIntent(observed, intent.request)) {
        return observed;
      }
    } catch (cause) {
      if (!authenticatedOperationIsCurrent(operation)) throw cause;
    }
    throw new Error(
      `Room creation is ambiguous. Retry recovers the exact retained room ${intent.request.room_id} with the same idempotency key; this console will not mint another room ID.`,
    );
  };

  const createRoom = async () => {
    const operation = beginAuthenticatedOperation("create");
    if (!operation) return;
    try {
      let intent = pendingRoomCreation();
      if (!intent) {
        const drafts = ownerDrafts();
        if (allocationTotal() !== 10_000) {
          throw new Error("Owner allocations must sum to exactly 10,000 basis points");
        }
        const policies: Record<string, string> = {};
        const allocations: Record<string, number> = {};
        for (const draft of drafts) {
          const owner = draft.address.trim().toLowerCase();
          const policy = draft.policyCommitment.trim().toLowerCase();
          if (!ADDRESS.test(owner)) {
            throw new Error("Every owner needs a complete 0x wallet address");
          }
          if (!SHA256.test(policy)) {
            throw new Error("Every owner needs a nonzero sha256: corpus-policy commitment");
          }
          if (owner in policies) throw new Error("An owner wallet is listed more than once");
          policies[owner] = policy;
          allocations[owner] = allocationValue(draft.allocation);
        }
        const purposeHash = purposeCommitment().trim().toLowerCase();
        const pipelineHash = pipelineCommitment().trim().toLowerCase();
        if (!SHA256.test(purposeHash) || !SHA256.test(pipelineHash)) {
          throw new Error("Purpose and pipeline must each be nonzero sha256: commitments");
        }
        const members = [...new Set([
          operation.session.address,
          ...parseInvitations(memberInvitations()),
          ...Object.keys(policies),
        ])].sort();
        if (members.length > 16) {
          throw new Error("A Collaboration room supports at most 16 members");
        }
        intent = {
          request: {
            room_id: createCollaborationIdentifier("room"),
            idempotency_key: createCollaborationIdentifier("idem"),
            member_addresses: members,
            purpose_commitment: purposeHash,
            pipeline_commitment: pipelineHash,
            corpus_policy_commitments: policies,
            owner_allocations_bps: allocations,
          },
          localLabel: localRoomName().trim().slice(0, 64),
        };
        setPendingRoomCreation(intent);
      }
      let recovered = false;
      let room: CollaborationRoom;
      try {
        room = await createCollaborationRoom(
          operation.session.accessToken,
          intent.request,
          operation.signal,
        );
        if (!authenticatedOperationIsCurrent(operation)) return;
        if (!collaborationRoomMatchesCreationIntent(room, intent.request)) {
          throw new Error(
            "The room response does not match the retained immutable creation intent",
          );
        }
      } catch (cause) {
        if (!authenticatedOperationIsCurrent(operation)) return;
        room = await recoverRoomCreation(operation, intent);
        recovered = true;
      }
      if (!authenticatedOperationIsCurrent(operation)) return;
      setPendingRoomCreation(undefined);
      if (intent.localLabel) {
        setRoomLabels((current) => ({
          ...current,
          [room.room_id]: intent.localLabel,
        }));
      }
      upsertRoom(room);
      setSelectedRoom(room);
      setJointReceipt(undefined);
      setNotice(
        recovered
          ? "Recovered the exact durable room after an ambiguous response. The retained room ID and idempotency key were reused."
          : "Durable room commitments recorded. The local label stayed in this browser memory and was not sent.",
      );
    } catch (cause) {
      reportAuthenticatedOperationError(
        operation,
        cause,
        "Could not create the Collaboration room",
      );
    } finally {
      finishAuthenticatedOperation(operation);
    }
  };

  const pollConsentRecovery = async (
    operation: CollaborationAuthenticatedOperation,
    intent: PendingConsentRecovery,
    attempts: number,
  ): Promise<CollaborationRoom | undefined> => {
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      if (attempt > 0) {
        await recoveryPause(operation.signal);
        if (!authenticatedOperationIsCurrent(operation)) return undefined;
      }
      try {
        const challenge = await fetchCollaborationConsentChallenge(
          operation.session.accessToken,
          intent.challengeId,
          operation.signal,
        );
        if (!authenticatedOperationIsCurrent(operation)) return undefined;
        const room = await fetchCollaborationRoom(
          operation.session.accessToken,
          intent.roomId,
          operation.signal,
        );
        if (!authenticatedOperationIsCurrent(operation)) return undefined;
        if (collaborationConsentRecoveryMatches(challenge, room, intent)) {
          return room;
        }
        if (challenge.status === "consumed") {
          throw new Error(
            "Consent was consumed, but the current room no longer matches the intended owner decision. Refresh and inspect before any retry.",
          );
        }
        if (["superseded", "expired"].includes(challenge.status)) {
          throw new Error(
            `Consent was not confirmed: the exact challenge is ${challenge.status} and the current room does not match the intended decision.`,
          );
        }
      } catch (cause) {
        if (!authenticatedOperationIsCurrent(operation)) throw cause;
        if (
          cause instanceof Error
          && (
            cause.message.startsWith("Consent was consumed")
            || cause.message.startsWith("Consent was not confirmed")
          )
        ) throw cause;
      }
    }
    return undefined;
  };

  const recoverConsentMutation = async (
    operation: CollaborationAuthenticatedOperation,
    intent: PendingConsentRecovery,
  ): Promise<CollaborationRoom> => {
    const observed = await pollConsentRecovery(operation, intent, 3);
    if (observed) return observed;
    if (!authenticatedOperationIsCurrent(operation)) {
      throw new DOMException("Collaboration authority changed", "AbortError");
    }

    try {
      await submitCollaborationConsent(
        operation.session.accessToken,
        intent.roomId,
        {
          challenge_id: intent.challengeId,
          decision: intent.decision,
          signature: intent.signature,
        },
        operation.signal,
      );
    } catch (cause) {
      if (!authenticatedOperationIsCurrent(operation)) throw cause;
    }
    const replayObserved = await pollConsentRecovery(operation, intent, 3);
    if (replayObserved) return replayObserved;
    throw new Error(
      `Consent outcome is ambiguous for ${intent.challengeId}. The console polled the exact challenge and room and replayed only that signed action, but could not prove the current state. Refresh before signing anything else.`,
    );
  };

  const changeConsent = async (decision: CollaborationConsentDecision) => {
    const room = selectedRoom();
    if (!room) return;
    const operation = beginAuthenticatedOperation(`consent:${decision}`);
    if (!operation) return;
    let recoveryIntent: PendingConsentRecovery | undefined;
    try {
      if (!room.owners.some(
        (owner) => owner.owner_address === operation.session.address,
      )) {
        throw new Error("Only a listed owner wallet can change its consent");
      }
      const current = await fetchCollaborationRoom(
        operation.session.accessToken,
        room.room_id,
        operation.signal,
      );
      if (!authenticatedOperationIsCurrent(operation)) return;
      upsertRoom(current);
      const issued = await issueCollaborationConsentChallenge(
        operation.session.accessToken,
        current.room_id,
        decision,
        operation.signal,
      );
      if (!authenticatedOperationIsCurrent(operation)) return;
      const challenge = await fetchCollaborationConsentChallenge(
        operation.session.accessToken,
        issued.challenge_id,
        operation.signal,
      );
      if (!authenticatedOperationIsCurrent(operation)) return;
      if (challenge.challenge_commitment !== issued.challenge_commitment) {
        throw new Error("Consent challenge changed between issuance and retrieval");
      }
      assertConsentChallengeForSigning(challenge, {
        room: current,
        ownerAddress: operation.session.address,
        decision,
      });
      if (!authenticatedOperationIsCurrent(operation)) return;
      const signature = await wallet.signWalletAuthorizationMessage(
        challenge.message,
      );
      if (!authenticatedOperationIsCurrent(operation)) return;
      assertConsentChallengeForSigning(challenge, {
        room: current,
        ownerAddress: operation.session.address,
        decision,
      });
      if (!authenticatedOperationIsCurrent(operation)) return;
      recoveryIntent = {
        roomId: current.room_id,
        challengeId: challenge.challenge_id,
        challengeCommitment: challenge.challenge_commitment,
        ownerAddress: operation.session.address,
        decision,
        roomGeneration: challenge.room_generation,
        signature,
      };
      setPendingConsentRecovery(recoveryIntent);
      const updated = await submitCollaborationConsent(
        operation.session.accessToken,
        current.room_id,
        {
          challenge_id: challenge.challenge_id,
          decision,
          signature,
        },
        operation.signal,
      );
      if (!authenticatedOperationIsCurrent(operation)) return;
      setPendingConsentRecovery(undefined);
      upsertRoom(updated);
      setSelectedRoom(updated);
      setJointReceipt(undefined);
      setNotice(
        decision === "activate"
          ? "This owner’s exact room consent is active. Execution and settlement remain unauthorized."
          : "This owner’s prospective consent is revoked. Earlier joint receipts no longer establish current authority.",
      );
    } catch (cause) {
      if (!authenticatedOperationIsCurrent(operation)) return;
      if (recoveryIntent) {
        try {
          const updated = await recoverConsentMutation(
            operation,
            recoveryIntent,
          );
          if (!authenticatedOperationIsCurrent(operation)) return;
          setPendingConsentRecovery(undefined);
          upsertRoom(updated);
          setSelectedRoom(updated);
          setJointReceipt(undefined);
          setNotice(
            decision === "activate"
              ? "Recovered the exact consumed activation after an ambiguous response. Execution and settlement remain unauthorized."
              : "Recovered the exact consumed revocation after an ambiguous response. Earlier joint receipts no longer establish current authority.",
          );
        } catch (recoveryCause) {
          if (!authenticatedOperationIsCurrent(operation)) return;
          setPendingConsentRecovery(undefined);
          setError(safeError(
            recoveryCause,
            "Consent outcome remains ambiguous. Refresh the exact room before retrying.",
          ));
        }
        return;
      }
      reportAuthenticatedOperationError(operation, cause, "Could not update owner consent");
    } finally {
      finishAuthenticatedOperation(operation);
    }
  };

  const proposeQuery = async () => {
    const room = selectedRoom();
    if (!room) return;
    const operation = beginAuthenticatedOperation("query:propose");
    if (!operation) return;
    let intent = pendingQueryProposal();
    const wasPending = Boolean(intent);
    try {
      if (!intent) {
        const queryRef = queryCommitment().trim().toLowerCase();
        if (!SHA256.test(queryRef)) {
          throw new Error("Enter a nonzero sha256: commitment to the exact query");
        }
        intent = {
          roomId: room.room_id,
          queryRef,
          idempotencyKey: createCollaborationIdentifier("idem"),
        };
      }
      const current = await fetchCollaborationRoom(
        operation.session.accessToken,
        intent.roomId,
        operation.signal,
      );
      if (!authenticatedOperationIsCurrent(operation)) return;
      upsertRoom(current);
      setSelectedRoom(current);
      if (
        !wasPending
        && (
          current.lifecycle_status !== "active"
          || current.requester_membership_status !== "accepted"
          || !current.all_required_roles_active
        )
      ) {
        throw new Error(
          "Every owner must accept membership and activate its room role before a query can be proposed",
        );
      }
      setPendingQueryProposal(intent);
      const response = await replayIdempotentMutation(operation, () => (
        proposeCollaborationQuery(
          operation.session.accessToken,
          intent!.roomId,
          intent!.queryRef,
          intent!.idempotencyKey,
          operation.signal,
        )
      ));
      if (!authenticatedOperationIsCurrent(operation)) return;
      observeRollbackProjection(response.value);
      const updated = await fetchCollaborationRoom(
        operation.session.accessToken,
        intent.roomId,
        operation.signal,
      );
      if (!authenticatedOperationIsCurrent(operation)) return;
      if (
        !updated.current_query
        || updated.current_query.query_ref !== intent.queryRef
        || updated.current_query.proposal_commitment
          !== response.value.proposal_commitment
      ) {
        throw new Error(
          "The current room does not match the retained exact query proposal",
        );
      }
      setPendingQueryProposal(undefined);
      upsertRoom(updated);
      setSelectedRoom(updated);
      setJointReceipt(undefined);
      setNotice(
        response.recovered
          ? "Recovered the exact query proposal with its retained idempotency key. Every owner must now sign that query."
          : "Exact query proposed. Every owner must now sign that query; room-role consent alone is not enough.",
      );
    } catch (cause) {
      if (!authenticatedOperationIsCurrent(operation)) return;
      if (intent && pendingQueryProposal()) {
        try {
          const observed = await fetchCollaborationRoom(
            operation.session.accessToken,
            intent.roomId,
            operation.signal,
          );
          if (!authenticatedOperationIsCurrent(operation)) return;
          upsertRoom(observed);
          setSelectedRoom(observed);
          if (
            observed.current_query?.query_ref === intent.queryRef
            && observed.current_query.proposal_current
          ) {
            setPendingQueryProposal(undefined);
            setNotice(
              "Recovered the exact current query proposal from the room projection after an ambiguous response.",
            );
            return;
          }
          if (
            observed.current_query
            && observed.current_query.query_ref !== intent.queryRef
          ) {
            setPendingQueryProposal(undefined);
            setError(
              "Another query is now current. The retained proposal cannot be reused; inspect the current query before deciding what to propose next.",
            );
            return;
          }
        } catch (recoveryCause) {
          if (!authenticatedOperationIsCurrent(operation)) return;
        }
        setError(
          "Query proposal outcome is ambiguous. Retry reuses the exact retained query and idempotency key; the editor remains locked.",
        );
        return;
      }
      reportAuthenticatedOperationError(
        operation,
        cause,
        "Could not propose the exact Collaboration query",
      );
    } finally {
      finishAuthenticatedOperation(operation);
    }
  };

  const pollQueryGrantRecovery = async (
    operation: CollaborationAuthenticatedOperation,
    intent: PendingQueryGrantRecovery,
    attempts: number,
  ): Promise<CollaborationQueryProposal | undefined> => {
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      if (attempt > 0) {
        await recoveryPause(operation.signal);
        if (!authenticatedOperationIsCurrent(operation)) return undefined;
      }
      try {
        const challenge = await fetchCollaborationQueryGrantChallenge(
          operation.session.accessToken,
          intent.challengeId,
          operation.signal,
        );
        if (!authenticatedOperationIsCurrent(operation)) return undefined;
        const room = await fetchCollaborationRoom(
          operation.session.accessToken,
          intent.roomId,
          operation.signal,
        );
        if (!authenticatedOperationIsCurrent(operation)) return undefined;
        const query = room.current_query;
        if (
          query
          && collaborationQueryGrantRecoveryMatches(challenge, query, intent)
        ) return query;
        if (challenge.status === "consumed") {
          throw new Error(
            "The query grant was consumed, but that exact query is no longer current. Inspect the room before any new signature.",
          );
        }
        if (["superseded", "expired"].includes(challenge.status)) {
          throw new Error(
            `Query grant was not confirmed: the exact challenge is ${challenge.status}. Inspect the current query before retrying.`,
          );
        }
      } catch (cause) {
        if (!authenticatedOperationIsCurrent(operation)) throw cause;
        if (
          cause instanceof Error
          && (
            cause.message.startsWith("The query grant was consumed")
            || cause.message.startsWith("Query grant was not confirmed")
          )
        ) throw cause;
      }
    }
    return undefined;
  };

  const recoverQueryGrantMutation = async (
    operation: CollaborationAuthenticatedOperation,
    intent: PendingQueryGrantRecovery,
  ): Promise<CollaborationQueryProposal> => {
    const observed = await pollQueryGrantRecovery(operation, intent, 3);
    if (observed) return observed;
    if (!authenticatedOperationIsCurrent(operation)) {
      throw new DOMException("Collaboration authority changed", "AbortError");
    }
    try {
      await submitCollaborationQueryGrant(
        operation.session.accessToken,
        intent.roomId,
        {
          challenge_id: intent.challengeId,
          decision: intent.decision,
          signature: intent.signature,
        },
        operation.signal,
      );
    } catch (cause) {
      if (!authenticatedOperationIsCurrent(operation)) throw cause;
    }
    const replayObserved = await pollQueryGrantRecovery(operation, intent, 3);
    if (replayObserved) return replayObserved;
    throw new Error(
      `Query-grant outcome is ambiguous for ${intent.challengeId}. The exact challenge and room were polled and only that signature was replayed. Inspect the current query before signing again.`,
    );
  };

  const changeQueryGrant = async (
    decision: CollaborationQueryGrantDecision,
  ) => {
    const room = selectedRoom();
    if (!room?.current_query) return;
    const operation = beginAuthenticatedOperation(`query-grant:${decision}`);
    if (!operation) return;
    let recoveryIntent: PendingQueryGrantRecovery | undefined;
    try {
      const current = await fetchCollaborationRoom(
        operation.session.accessToken,
        room.room_id,
        operation.signal,
      );
      if (!authenticatedOperationIsCurrent(operation)) return;
      upsertRoom(current);
      setSelectedRoom(current);
      const query = current.current_query;
      const owner = current.owners.find(
        (candidate) => candidate.owner_address === operation.session.address,
      );
      if (!query?.proposal_current || !owner?.role_accepted) {
        throw new Error(
          "A current query and this wallet's active owner role are required",
        );
      }
      const issued = await issueCollaborationQueryGrantChallenge(
        operation.session.accessToken,
        current.room_id,
        decision,
        operation.signal,
      );
      if (!authenticatedOperationIsCurrent(operation)) return;
      const challenge = await fetchCollaborationQueryGrantChallenge(
        operation.session.accessToken,
        issued.challenge_id,
        operation.signal,
      );
      if (!authenticatedOperationIsCurrent(operation)) return;
      if (challenge.challenge_commitment !== issued.challenge_commitment) {
        throw new Error(
          "Query-grant challenge changed between issuance and retrieval",
        );
      }
      assertQueryGrantChallengeForSigning(challenge, {
        room: current,
        ownerAddress: operation.session.address,
        decision,
      });
      if (!authenticatedOperationIsCurrent(operation)) return;
      const signature = await wallet.signWalletAuthorizationMessage(
        challenge.message,
      );
      if (!authenticatedOperationIsCurrent(operation)) return;
      assertQueryGrantChallengeForSigning(challenge, {
        room: current,
        ownerAddress: operation.session.address,
        decision,
      });
      if (!authenticatedOperationIsCurrent(operation)) return;
      recoveryIntent = {
        roomId: current.room_id,
        challengeId: challenge.challenge_id,
        challengeCommitment: challenge.challenge_commitment,
        ownerAddress: operation.session.address,
        decision,
        roomGeneration: challenge.room_generation,
        queryRef: challenge.query_ref,
        proposalCommitment: challenge.proposal_commitment,
        signature,
      };
      setPendingQueryGrantRecovery(recoveryIntent);
      const updatedQuery = await submitCollaborationQueryGrant(
        operation.session.accessToken,
        current.room_id,
        {
          challenge_id: challenge.challenge_id,
          decision,
          signature,
        },
        operation.signal,
      );
      if (!authenticatedOperationIsCurrent(operation)) return;
      observeRollbackProjection(updatedQuery);
      const updatedRoom = await fetchCollaborationRoom(
        operation.session.accessToken,
        current.room_id,
        operation.signal,
      );
      if (!authenticatedOperationIsCurrent(operation)) return;
      if (
        updatedRoom.current_query?.proposal_commitment
          !== updatedQuery.proposal_commitment
      ) throw new Error("Query-grant result is not current in the room");
      setPendingQueryGrantRecovery(undefined);
      upsertRoom(updatedRoom);
      setSelectedRoom(updatedRoom);
      setJointReceipt(undefined);
      setNotice(
        decision === "approve"
          ? "This owner approved the exact current query. No execution was dispatched."
          : "This owner revoked the exact current query grant. Joint snapshots are no longer current.",
      );
    } catch (cause) {
      if (!authenticatedOperationIsCurrent(operation)) return;
      if (recoveryIntent) {
        try {
          await recoverQueryGrantMutation(operation, recoveryIntent);
          if (!authenticatedOperationIsCurrent(operation)) return;
          const updatedRoom = await fetchCollaborationRoom(
            operation.session.accessToken,
            recoveryIntent.roomId,
            operation.signal,
          );
          if (!authenticatedOperationIsCurrent(operation)) return;
          setPendingQueryGrantRecovery(undefined);
          upsertRoom(updatedRoom);
          setSelectedRoom(updatedRoom);
          setJointReceipt(undefined);
          setNotice(
            decision === "approve"
              ? "Recovered this owner's exact-query approval after an ambiguous response."
              : "Recovered this owner's exact-query revocation after an ambiguous response.",
          );
        } catch (recoveryCause) {
          if (!authenticatedOperationIsCurrent(operation)) return;
          setPendingQueryGrantRecovery(undefined);
          setError(safeError(
            recoveryCause,
            "Query-grant outcome remains ambiguous. Inspect the exact current query before retrying.",
          ));
        }
        return;
      }
      reportAuthenticatedOperationError(
        operation,
        cause,
        "Could not update this owner's exact-query grant",
      );
    } finally {
      finishAuthenticatedOperation(operation);
    }
  };

  const executeJointAuthorizationIntent = async (
    operation: CollaborationAuthenticatedOperation,
    intent: PendingJointAuthorization,
  ): Promise<CollaborationJointRun> => {
    const created = await authorizeCollaborationJointRun(
      operation.session.accessToken,
      intent.roomId,
      intent.queryRef,
      intent.idempotencyKey,
      operation.signal,
    );
    if (!authenticatedOperationIsCurrent(operation)) {
      throw new DOMException("Collaboration authority changed", "AbortError");
    }
    const receipt = await fetchCollaborationJointRun(
      operation.session.accessToken,
      created.run_id,
      operation.signal,
    );
    if (!authenticatedOperationIsCurrent(operation)) {
      throw new DOMException("Collaboration authority changed", "AbortError");
    }
    if (
      receipt.room_id !== intent.roomId
      || receipt.query_ref !== intent.queryRef
      || receipt.joint_consent_snapshot_commitment
        !== created.joint_consent_snapshot_commitment
    ) {
      throw new Error(
        "Joint consent snapshot changed between the retained intent and retrieval",
      );
    }
    return receipt;
  };

  const authorizeJointRun = async () => {
    const room = selectedRoom();
    if (!room?.current_query) return;
    const operation = beginAuthenticatedOperation("run");
    if (!operation) return;
    let intent = pendingJointAuthorization();
    const recoveringExistingIntent = Boolean(intent);
    let recovered = false;
    try {
      if (!intent) {
        intent = {
          roomId: room.room_id,
          queryRef: room.current_query.query_ref,
          idempotencyKey: createCollaborationIdentifier("idem"),
        };
        setPendingJointAuthorization(intent);
      }
      const current = await fetchCollaborationRoom(
        operation.session.accessToken,
        intent.roomId,
        operation.signal,
      );
      if (!authenticatedOperationIsCurrent(operation)) return;
      upsertRoom(current);
      setSelectedRoom(current);
      if (
        !recoveringExistingIntent
        && (
          current.current_query?.query_ref !== intent.queryRef
          || !current.all_required_query_grants_current
        )
      ) {
        setPendingJointAuthorization(undefined);
        throw new Error(
          "Every required owner must approve the exact current query before a joint snapshot",
        );
      }
      let receipt: CollaborationJointRun;
      try {
        receipt = await executeJointAuthorizationIntent(operation, intent);
      } catch (cause) {
        if (!authenticatedOperationIsCurrent(operation)) return;
        await recoveryPause(operation.signal);
        if (!authenticatedOperationIsCurrent(operation)) return;
        receipt = await executeJointAuthorizationIntent(operation, intent);
        recovered = true;
      }
      if (!authenticatedOperationIsCurrent(operation)) return;
      setPendingJointAuthorization(undefined);
      observeRollbackProjection(receipt);
      setJointReceipt(receipt);
      setNotice(
        recovered
          ? "Recovered the exact joint consent snapshot with the retained query and idempotency key. No provider dispatch, TDX attestation, settlement, or royalty distribution occurred."
          : "Joint consent snapshot recorded and retrieved. No provider dispatch, TDX attestation, settlement, or royalty distribution occurred.",
      );
    } catch (cause) {
      if (authenticatedOperationIsCurrent(operation)) {
        setJointReceipt(undefined);
        setError(pendingJointAuthorization()
          ? `Joint snapshot outcome is ambiguous for ${intent?.roomId ?? room.room_id}. Retry reuses the exact retained query and idempotency key; this console will not create a second intent.`
          : safeError(cause, "Could not record the joint consent snapshot"));
      }
    } finally {
      finishAuthenticatedOperation(operation);
    }
  };

  const brief = createMemo(
    () =>
      `WIKIGEN.ME — BIO-MODEL COLLABORATION BRIEF (bounded, IP-preserving)
------------------------------------------------------------------
From:               ${org() || "(your name / org)"}
Collaboration type: ${ctype()}
Locality preference: ${locality()}
Declared purpose:   ${purpose() || "(declared purpose — matched against corpus allowed-use)"}
Budget cap:         ${budget() ? `$${budget()}` : "(buyer budget cap)"}
Royalty per query:  ${royalty() ? `$${royalty()}` : "(seller metering for the expose path)"}

Non-confidential summary:
${summary() || "(one paragraph — capabilities sought, NOT raw data, sequences, or identifiers)"}

------------------------------------------------------------------
This brief carries no raw artifact. Diligence happens inside a TEE:
the model is brought to the sealed corpus, the pre-inference gate runs,
and only policy-approved bounded results plus a verifiable receipt may cross
the boundary once a fresh deployment passes every verification layer.`,
  );

  const mailto = createMemo(() => {
    const subject = `Bio-model collaboration — ${ctype()}`;
    return `mailto:collaborate@wikigen.me?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(brief())}`;
  });

  const copyBrief = async () => {
    try {
      await navigator.clipboard.writeText(brief());
      setCopyState("copied");
    } catch {
      setCopyState("failed");
    }
  };

  return (
    <>
      <section class="collaboration-console" aria-labelledby="collaboration-console-title">
        <div class="collaboration-console-head">
          <div>
            <p class="overline">
              {releaseConfigured()
                ? "Release-configured service · wallet-owned coordination"
                : "Implemented coordination workspace · release gate closed"}
            </p>
            <h2 id="collaboration-console-title">Multi-owner authority console</h2>
            <p>
              Record commitment-only rooms, let invitees accept membership, require
              owners to activate a room role and separately approve one exact query,
              then freeze the resulting joint consent snapshot. Raw purpose, policy,
              corpus, artifact, and signature material are never returned in
              participant projections.
            </p>
          </div>
          <div class="collaboration-truth-pills" aria-label="Collaboration evidence boundaries">
            <span>
              <ShieldCheck size={14} />
              {rollbackEvidence() === "unobserved_modeled"
                ? "Modeled current-state integrity"
                : rollbackEvidence() === "local_hmac_only_modeled"
                  ? "Modeled · HMAC current-state observed"
                  : "Backend state commitment matched to witness"}
            </span>
            <span
              classList={{
                configured:
                  rollbackEvidence() === "release_bound_backend_witness",
                warning:
                  rollbackEvidence() !== "release_bound_backend_witness",
              }}
              title={rollbackEvidence() === "release_bound_backend_witness"
                ? "Backend returned an exact release-matched Base Sepolia anchor status under a single-RPC reported-finalized model. Independent RPC quorum and consensus proof are both false."
                : "Local HMAC integrity can detect current-file modification but cannot prove that an older valid snapshot was not restored."}
            >
              {rollbackEvidence() === "release_bound_backend_witness"
                ? <><ShieldCheck size={14} /> Live witness · single-RPC reported-finalized</>
                : <><ShieldAlert size={14} /> {
                    rollbackEvidence() === "local_hmac_only_modeled"
                      ? "No monotonic rollback witness · local HMAC only"
                      : "No monotonic rollback witness observed"
                  }</>}
            </span>
            <span class="neutral"><CircleDashed size={14} /> Coordination session · no execution or spend authority</span>
            <span classList={{ configured: releaseConfigured(), closed: !releaseConfigured() }}>
              {releaseConfigured()
                ? <><Check size={14} /> Release flag enabled</>
                : <><LockKeyhole size={14} /> Control plane closed</>}
            </span>
          </div>
        </div>

        <div class="collaboration-session-bar">
          <div class="collaboration-session-identity">
            <span classList={{ ready: Boolean(wallet.account()) }}>
              <WalletCards size={17} />
            </span>
            <div>
              <small>CONNECTED OWNER</small>
              <strong>{wallet.account() ? short(wallet.account()!) : "No wallet connected"}</strong>
              <span>
                {!releaseConfigured()
                  ? "Release manifest keeps Collaboration API authority closed"
                  : wallet.account()
                  ? wallet.isCorrectChain()
                    ? "Base Sepolia · ready for a scoped nonce exchange"
                    : "Wrong network · switch before authorization"
                  : "Use MetaMask or another EIP-1193 / WalletConnect wallet from the header"}
              </span>
            </div>
          </div>
          <div class="collaboration-session-actions">
            <Show when={!wallet.account()}>
              <button
                class="secondary-button"
                type="button"
                data-collaboration-handoff="connect-wallet"
                disabled={Boolean(busy())}
                onClick={() => props.requestWalletConnection?.()}
              >
                <WalletCards size={15} /> Connect wallet
              </button>
            </Show>
            <Show when={wallet.account() && !wallet.isCorrectChain()}>
              <button
                class="secondary-button"
                type="button"
                disabled={Boolean(busy())}
                onClick={switchChain}
              >
                {busy() === "switch" ? "Switching…" : "Switch to Base Sepolia"}
              </button>
            </Show>
            <Show when={!sessionCurrent()} fallback={(
              <>
                <span class="collaboration-session-live"><Check size={13} /> Wallet scoped</span>
                <button
                  class="secondary-button"
                  type="button"
                  disabled={Boolean(busy())}
                  onClick={refreshRooms}
                >
                  <RefreshCw size={14} /> {busy() === "refresh" ? "Refreshing…" : "Refresh"}
                </button>
              </>
            )}>
              <button
                class="primary-button"
                type="button"
                data-collaboration-action="authorize"
                disabled={!releaseConfigured() || !wallet.account() || !wallet.isCorrectChain() || Boolean(busy())}
                onClick={authorizeConsole}
              >
                <KeyRound size={15} />
                {!releaseConfigured()
                  ? "Collaboration not enabled"
                  : busy() === "authorize"
                    ? "Check wallet…"
                    : "Authorize room access"}
              </button>
            </Show>
          </div>
        </div>

        <div class="collaboration-action-note">
          <LockKeyhole size={15} />
          <span>
            The console signature authorizes a short-lived <code>collaboration:console</code>{" "}
            read/write session only. Owner room-role consent and every exact-query
            grant require separate exact-message signatures. None of these signatures
            dispatches work, sends a transaction, or moves funds.
          </span>
        </div>

        <Show when={error()}>
          <div class="collaboration-feedback error" role="alert">
            <ShieldAlert size={15} /><span>{error()}</span>
          </div>
        </Show>
        <Show when={notice()}>
          <div class="collaboration-feedback success" role="status" aria-live="polite">
            <CheckCircle2 size={15} /><span>{notice()}</span>
          </div>
        </Show>

        <div class="collaboration-workspace">
          <aside class="collaboration-room-rail" aria-label="Your Collaboration rooms">
            <div class="collaboration-panel-title">
              <div><small>PARTICIPANT VIEW</small><h3>Your rooms</h3></div>
              <span>{rooms().length}/64</span>
            </div>
            <Show
              when={sessionCurrent()}
              fallback={(
                <div class="collaboration-empty">
                  <Fingerprint size={27} />
                  <strong>Wallet authority required</strong>
                  <p>Authorize above to fetch only rooms that include this wallet.</p>
                </div>
              )}
            >
              <Show
                when={rooms().length > 0}
                fallback={(
                  <div class="collaboration-empty">
                    <UsersRound size={27} />
                    <strong>No rooms yet</strong>
                    <p>Create a commitment-only room. Local labels are not uploaded.</p>
                  </div>
                )}
              >
                <div class="collaboration-room-list">
                  <For each={rooms()}>{(room) => (
                    <button
                      type="button"
                      classList={{
                        selected: selectedRoom()?.room_id === room.room_id,
                      }}
                      aria-pressed={selectedRoom()?.room_id === room.room_id}
                      onClick={() => inspectRoom(room)}
                      disabled={Boolean(busy()) || Boolean(pendingQueryProposal()) || Boolean(pendingJointAuthorization())}
                    >
                      <span classList={{ complete: room.all_required_query_grants_current }}>
                        {room.all_required_query_grants_current
                          ? <Check size={12} />
                          : <CircleDashed size={12} />}
                      </span>
                      <div>
                        <strong>{roomLabels()[room.room_id] || short(room.room_id, 13, 5)}</strong>
                        <small>
                          {room.requester_membership_status} · {room.lifecycle_status}
                          {" · "}{room.owners.length} owner{room.owners.length === 1 ? "" : "s"}
                        </small>
                      </div>
                    </button>
                  )}</For>
                  <Show when={roomsHaveMore() && roomsNextCursor()}>
                    <button
                      type="button"
                      class="secondary-button"
                      data-collaboration-action="rooms-more"
                      disabled={Boolean(busy())}
                      onClick={loadMoreRooms}
                    >
                      <RefreshCw size={13} />
                      {busy() === "rooms-more" ? "Loading…" : "Load more rooms"}
                    </button>
                  </Show>
                </div>
              </Show>
            </Show>
          </aside>

          <div class="collaboration-main">
            <section class="collaboration-create" aria-labelledby="create-collaboration-room-title">
              <div class="collaboration-panel-title">
                <div>
                  <small>COMMITMENTS ONLY</small>
                  <h3 id="create-collaboration-room-title">Create a durable room</h3>
                </div>
                <span>1–16 owners</span>
              </div>
              <form onSubmit={(event) => { event.preventDefault(); void createRoom(); }}>
                <div class="collaboration-form-grid two">
                  <div class="field">
                    <label for="collaboration-local-label">Local room label</label>
                    <input
                      id="collaboration-local-label"
                      maxlength="64"
                      value={localRoomName()}
                      disabled={Boolean(pendingRoomCreation()) || Boolean(busy())}
                      onInput={(event) => setLocalRoomName(event.currentTarget.value)}
                      placeholder="Atlas × variant model"
                      autocomplete="off"
                    />
                    <small>Convenience only · held in component memory, never sent.</small>
                  </div>
                  <div class="field">
                    <label for="collaboration-member-wallets">Participant wallet invitations</label>
                    <input
                      id="collaboration-member-wallets"
                      maxlength="700"
                      value={memberInvitations()}
                      disabled={Boolean(pendingRoomCreation()) || Boolean(busy())}
                      onInput={(event) => setMemberInvitations(event.currentTarget.value)}
                      placeholder="0x… 0x…"
                      spellcheck={false}
                      autocomplete="off"
                    />
                    <small>Space- or comma-separated. Owners and creator are included automatically.</small>
                  </div>
                  <div class="field">
                    <label for="collaboration-purpose-commitment">Purpose commitment</label>
                    <input
                      id="collaboration-purpose-commitment"
                      maxlength="71"
                      value={purposeCommitment()}
                      disabled={Boolean(pendingRoomCreation()) || Boolean(busy())}
                      onInput={(event) => setPurposeCommitment(event.currentTarget.value)}
                      placeholder="sha256:…"
                      spellcheck={false}
                      autocomplete="off"
                    />
                    <small>Do not paste purpose text, sequences, or identifiers.</small>
                  </div>
                  <div class="field">
                    <label for="collaboration-pipeline-commitment">Pipeline commitment</label>
                    <input
                      id="collaboration-pipeline-commitment"
                      maxlength="71"
                      value={pipelineCommitment()}
                      disabled={Boolean(pendingRoomCreation()) || Boolean(busy())}
                      onInput={(event) => setPipelineCommitment(event.currentTarget.value)}
                      placeholder="sha256:…"
                      spellcheck={false}
                      autocomplete="off"
                    />
                    <small>Commit the exact evaluator / pipeline policy out of band.</small>
                  </div>
                </div>

                <div class="collaboration-owner-editor">
                  <div class="collaboration-owner-editor-head">
                    <div>
                      <strong>Owner allocation</strong>
                      <small>Every owner independently activates this exact immutable room.</small>
                    </div>
                    <div classList={{ valid: allocationTotal() === 10_000 }}>
                      <span>{allocationTotal().toLocaleString()} / 10,000 bps</span>
                      <button
                        type="button"
                        class="secondary-button"
                        disabled={ownerDrafts().length >= 16 || Boolean(busy()) || Boolean(pendingRoomCreation())}
                        onClick={addOwner}
                      >
                        <Plus size={13} /> Add owner
                      </button>
                    </div>
                  </div>
                  <For each={ownerDrafts()}>{(owner, index) => (
                    <div class="collaboration-owner-row">
                      <span class="owner-index">{String(index() + 1).padStart(2, "0")}</span>
                      <div class="field">
                        <label for={`collaboration-owner-${owner.key}`}>Owner wallet</label>
                        <input
                          id={`collaboration-owner-${owner.key}`}
                          maxlength="42"
                          value={owner.address}
                          disabled={Boolean(pendingRoomCreation()) || Boolean(busy())}
                          onInput={(event) => updateOwner(
                            owner.key,
                            "address",
                            event.currentTarget.value,
                          )}
                          placeholder="0x…"
                          spellcheck={false}
                          autocomplete="off"
                        />
                      </div>
                      <div class="field policy">
                        <label for={`collaboration-policy-${owner.key}`}>Corpus-policy commitment</label>
                        <input
                          id={`collaboration-policy-${owner.key}`}
                          maxlength="71"
                          value={owner.policyCommitment}
                          disabled={Boolean(pendingRoomCreation()) || Boolean(busy())}
                          onInput={(event) => updateOwner(
                            owner.key,
                            "policyCommitment",
                            event.currentTarget.value,
                          )}
                          placeholder="sha256:…"
                          spellcheck={false}
                          autocomplete="off"
                        />
                      </div>
                      <div class="field bps">
                        <label for={`collaboration-bps-${owner.key}`}>Basis points</label>
                        <input
                          id={`collaboration-bps-${owner.key}`}
                          type="number"
                          inputmode="numeric"
                          min="1"
                          max="10000"
                          step="1"
                          value={owner.allocation}
                          disabled={Boolean(pendingRoomCreation()) || Boolean(busy())}
                          onInput={(event) => updateOwner(
                            owner.key,
                            "allocation",
                            event.currentTarget.value,
                          )}
                        />
                      </div>
                      <button
                        class="collaboration-remove-owner"
                        type="button"
                        aria-label={`Remove owner ${index() + 1}`}
                        disabled={ownerDrafts().length <= 1 || Boolean(busy()) || Boolean(pendingRoomCreation())}
                        onClick={() => removeOwner(owner.key)}
                      >
                        <Trash2 size={14} />
                      </button>
                    </div>
                  )}</For>
                </div>

                <div class="collaboration-create-foot">
                  <p>
                    {pendingRoomCreation()
                      ? `Recovery is pinned to ${pendingRoomCreation()!.request.room_id}. Draft controls stay locked so retry cannot mint a different identity.`
                      : "Room creation records wallet membership, commitments, allocation, and pending owner roles. It does not upload data or authorize a run."}
                  </p>
                  <button
                    class="primary-button"
                    type="submit"
                    data-collaboration-action="create-room"
                    disabled={!releaseConfigured() || !sessionCurrent() || allocationTotal() !== 10_000 || Boolean(busy())}
                  >
                    <Fingerprint size={15} />
                    {busy() === "create"
                      ? pendingRoomCreation() ? "Recovering room…" : "Recording room…"
                      : pendingRoomCreation() ? "Retry exact room" : "Record room commitments"}
                  </button>
                </div>
              </form>
            </section>

            <Show when={selectedRoom()}>{(room) => (
              <section class="collaboration-room-detail" aria-labelledby="collaboration-room-detail-title">
                <div class="collaboration-detail-head">
                  <div>
                    <p class="overline">Participant-authenticated projection · schema v2</p>
                    <h3 id="collaboration-room-detail-title">
                      {roomLabels()[room().room_id] || "Collaboration room"}
                    </h3>
                    <code>{room().room_id}</code>
                  </div>
                  <span classList={{ ready: room().all_required_query_grants_current }}>
                    {room().lifecycle_status === "archived"
                      ? <><CircleDashed size={14} /> Archived</>
                      : room().requester_membership_status === "invited"
                        ? <><CircleDashed size={14} /> Invitation pending</>
                        : room().all_required_query_grants_current
                          ? <><CheckCircle2 size={14} /> Exact query approved</>
                          : <><CircleDashed size={14} /> Authority incomplete</>}
                  </span>
                </div>

                <Show when={room().requester_membership_status === "invited"}>
                  <div class="collaboration-action-note">
                    <UsersRound size={15} />
                    <span>
                      The creator declared this wallet, but declaration is not
                      membership. Accept for ordinary room authority or decline
                      to remove this wallet’s visibility.
                    </span>
                    <button
                      class="primary-button"
                      type="button"
                      data-collaboration-action="accept-invitation"
                      disabled={Boolean(busy())}
                      onClick={() => respondToInvitation("accept")}
                    >
                      {busy() === "invitation:accept" ? "Accepting…" : "Accept membership"}
                    </button>
                    <button
                      class="secondary-button danger"
                      type="button"
                      data-collaboration-action="decline-invitation"
                      disabled={Boolean(busy())}
                      onClick={() => respondToInvitation("decline")}
                    >
                      {busy() === "invitation:decline" ? "Declining…" : "Decline"}
                    </button>
                  </div>
                </Show>

                <dl class="collaboration-commitment-grid">
                  <div><dt>Room commitment</dt><dd title={room().room_commitment}>{short(room().room_commitment, 18, 10)}</dd></div>
                  <div><dt>Purpose commitment</dt><dd title={room().purpose_commitment}>{short(room().purpose_commitment, 18, 10)}</dd></div>
                  <div><dt>Pipeline commitment</dt><dd title={room().pipeline_commitment}>{short(room().pipeline_commitment, 18, 10)}</dd></div>
                  <div><dt>Current generation</dt><dd>{room().generation} · updated {formatTime(room().updated_at)}</dd></div>
                </dl>

                <div class="collaboration-members-grid">
                  <div>
                    <div class="collaboration-subhead">
                      <strong>Membership authority</strong>
                      <span>{room().declared_member_addresses.length} declared</span>
                    </div>
                    <div class="collaboration-member-list">
                      <For each={room().memberships}>{(membership) => {
                        const owner = () => room().owners.find(
                          (item) => item.owner_address === membership.member_address,
                        );
                        return (
                          <div>
                            <span classList={{
                              active: membership.membership_status === "accepted",
                            }}>
                              {membership.membership_status === "accepted"
                                ? <Check size={11} />
                                : <CircleDashed size={11} />}
                            </span>
                            <div style={{ display: "grid", "min-width": "0" }}>
                              <code>{short(membership.member_address, 10, 7)}</code>
                              <small>
                                {membership.member_address === room().creator_address
                                  ? "creator · "
                                  : ""}
                                {membership.membership_status}
                                {owner() ? ` · owner ${owner()!.allocation_bps} bps` : " · participant"}
                              </small>
                            </div>
                            <Show when={
                              room().creator_address === connectedAddress()
                              && membership.membership_status === "invited"
                            }>
                              <button
                                class="secondary-button danger"
                                type="button"
                                data-collaboration-action="cancel-invitation"
                                disabled={Boolean(busy())}
                                onClick={() => cancelInvitation(
                                  membership.member_address,
                                )}
                              >
                                Cancel invite
                              </button>
                            </Show>
                          </div>
                        );
                      }}</For>
                    </div>
                  </div>
                  <div>
                    <div class="collaboration-subhead">
                      <strong>Owner room roles</strong>
                      <span>separate exact-message signature</span>
                    </div>
                    <div class="collaboration-consent-list">
                      <For each={room().owners}>{(owner) => (
                        <div>
                          <span class={`consent-state ${owner.role_consent_status}`}>
                            {owner.role_consent_status}
                          </span>
                          <div>
                            <code>{short(owner.owner_address, 10, 7)}</code>
                            <small>
                              membership {owner.membership_status} · role generation{" "}
                              {owner.role_consent_generation} · {owner.allocation_bps} bps
                            </small>
                          </div>
                          <Show when={
                            owner.owner_address === connectedAddress()
                            && owner.membership_status === "accepted"
                            && room().lifecycle_status === "active"
                          }>
                            <button
                              type="button"
                              class={owner.role_consent_status === "active"
                                ? "secondary-button danger"
                                : "primary-button"}
                              data-collaboration-action="owner-role-consent"
                              disabled={!releaseConfigured() || !sessionCurrent() || Boolean(busy()) || Boolean(pendingConsentRecovery()) || Boolean(pendingQueryGrantRecovery()) || Boolean(pendingJointAuthorization())}
                              onClick={() => changeConsent(
                                owner.role_consent_status === "active"
                                  ? "revoke"
                                  : "activate",
                              )}
                            >
                              {busy().startsWith("consent:")
                                ? "Check wallet…"
                                : owner.role_consent_status === "active"
                                  ? "Revoke room role"
                                  : "Activate room role"}
                            </button>
                          </Show>
                        </div>
                      )}</For>
                    </div>
                  </div>
                </div>

                <div class="collaboration-joint-run">
                  <div>
                    <small>EXACT QUERY PROPOSAL</small>
                    <h4>Propose one commitment, then collect fresh owner grants.</h4>
                    <p>
                      A room-role signature never carries over to a query. Replacing
                      the query invalidates every prior query grant and joint snapshot.
                    </p>
                  </div>
                  <div class="collaboration-query-control">
                    <label for="collaboration-query-commitment">Exact query commitment</label>
                    <input
                      id="collaboration-query-commitment"
                      maxlength="71"
                      value={queryCommitment()}
                      disabled={Boolean(busy()) || Boolean(pendingQueryProposal()) || Boolean(pendingJointAuthorization()) || room().lifecycle_status !== "active"}
                      onInput={(event) => setQueryCommitment(event.currentTarget.value)}
                      placeholder="sha256:…"
                      spellcheck={false}
                      autocomplete="off"
                    />
                    <button
                      class="primary-button"
                      type="button"
                      data-collaboration-action="propose-query"
                      disabled={!releaseConfigured() || !sessionCurrent() || room().requester_membership_status !== "accepted" || !room().all_required_roles_active || Boolean(busy()) || Boolean(pendingJointAuthorization())}
                      onClick={proposeQuery}
                    >
                      <Fingerprint size={14} />
                      {busy() === "query:propose"
                        ? "Recording exact query…"
                        : pendingQueryProposal()
                          ? "Retry exact proposal"
                          : room().current_query ? "Replace current query" : "Propose query"}
                    </button>
                  </div>
                </div>

                <Show
                  when={room().current_query}
                  fallback={(
                    <div class="collaboration-empty">
                      <Fingerprint size={25} />
                      <strong>No current query</strong>
                      <p>All accepted owners must activate their room roles before an accepted participant can propose one.</p>
                    </div>
                  )}
                >{(query) => (
                  <>
                    <dl class="collaboration-commitment-grid">
                      <div><dt>Current query</dt><dd title={query().query_ref}>{short(query().query_ref, 18, 10)}</dd></div>
                      <div><dt>Proposal</dt><dd title={query().proposal_commitment}>{short(query().proposal_commitment, 18, 10)}</dd></div>
                      <div><dt>Allocation</dt><dd title={query().allocation_commitment}>{short(query().allocation_commitment, 18, 10)}</dd></div>
                      <div><dt>Proposer</dt><dd>{short(query().proposer_address, 10, 7)}</dd></div>
                    </dl>

                    <div class="collaboration-consent-list">
                       <For each={query().owner_query_grants}>{(grant) => (
                         <div>
                           <span class={`consent-state ${
                             grant.grant_status === "approved"
                               ? "active"
                               : grant.grant_status
                           }`}>
                            {grant.grant_status}
                          </span>
                          <div>
                            <code>{short(grant.owner_address, 10, 7)}</code>
                            <small>
                              exact-query generation {grant.grant_generation}
                            </small>
                          </div>
                          <Show when={
                            grant.owner_address === connectedAddress()
                            && room().owners.find(
                              (owner) => owner.owner_address === grant.owner_address,
                            )?.role_accepted
                            && room().lifecycle_status === "active"
                          }>
                            <button
                              type="button"
                              class={grant.grant_status === "approved"
                                ? "secondary-button danger"
                                : "primary-button"}
                              data-collaboration-action="owner-query-grant"
                              disabled={Boolean(busy()) || Boolean(pendingQueryGrantRecovery()) || Boolean(pendingJointAuthorization())}
                              onClick={() => changeQueryGrant(
                                grant.grant_status === "approved"
                                  ? "revoke"
                                  : "approve",
                              )}
                            >
                              {busy().startsWith("query-grant:")
                                ? "Check wallet…"
                                : grant.grant_status === "approved"
                                  ? "Revoke query grant"
                                  : "Approve exact query"}
                            </button>
                          </Show>
                        </div>
                      )}</For>
                    </div>

                    <div class="collaboration-joint-run">
                      <div>
                        <small>JOINT CONSENT SNAPSHOT · NO DISPATCH</small>
                        <h4>Freeze the current query, grants, and allocation.</h4>
                        <p>
                          This bounded snapshot is coordination evidence only—not
                          execution authority, a CVM dispatch, TDX evidence, payment,
                          or royalty distribution.
                        </p>
                      </div>
                      <div class="collaboration-query-control">
                        <button
                          class="primary-button"
                          type="button"
                          data-collaboration-action="authorize-query"
                          disabled={!releaseConfigured() || !sessionCurrent() || (!pendingJointAuthorization() && !room().all_required_query_grants_current) || Boolean(busy())}
                          onClick={authorizeJointRun}
                        >
                          <KeyRound size={14} />
                          {busy() === "run"
                            ? pendingJointAuthorization() ? "Recovering exact snapshot…" : "Recording snapshot…"
                            : pendingJointAuthorization() ? "Retry exact snapshot" : "Record joint snapshot"}
                        </button>
                      </div>
                    </div>
                  </>
                )}</Show>

                <Show when={jointReceipt()}>{(receipt) => (
                  <article class="collaboration-receipt" aria-label="Joint consent snapshot receipt">
                    <div class="collaboration-receipt-head">
                      <div>
                        <span><Fingerprint size={15} /> JOINT CONSENT SNAPSHOT</span>
                        <strong>{collaborationJointRunCurrentForRoom(
                          receipt(),
                          room(),
                        ) ? "CURRENT" : "STALE"}</strong>
                      </div>
                      <code>{receipt().run_id}</code>
                    </div>
                    <dl>
                      <div><dt>Query</dt><dd title={receipt().query_ref}>{short(receipt().query_ref, 17, 10)}</dd></div>
                      <div><dt>Query grants</dt><dd title={receipt().query_grant_set_commitment}>{short(receipt().query_grant_set_commitment, 17, 10)}</dd></div>
                      <div><dt>Allocation</dt><dd title={receipt().allocation_commitment}>{short(receipt().allocation_commitment, 17, 10)}</dd></div>
                      <div><dt>Snapshot</dt><dd title={receipt().joint_consent_snapshot_commitment}>{short(receipt().joint_consent_snapshot_commitment, 17, 10)}</dd></div>
                      <div><dt>Recorded</dt><dd><time datetime={new Date(receipt().recorded_at * 1_000).toISOString()}>{new Date(receipt().recorded_at * 1_000).toISOString()}</time></dd></div>
                      <div><dt>Reclaimable after</dt><dd><time datetime={new Date(receipt().reclaimable_after * 1_000).toISOString()}>{new Date(receipt().reclaimable_after * 1_000).toISOString()}</time></dd></div>
                      <div><dt>Retention</dt><dd>Bounded non-dispatched snapshot</dd></div>
                    </dl>
                    <div class="collaboration-receipt-boundaries">
                      <span><CircleDashed size={12} /> Snapshot, not dispatched</span>
                      <span><ShieldAlert size={12} /> No TDX attestation</span>
                      <span><LockKeyhole size={12} /> No settlement or royalties</span>
                      <span><ShieldCheck size={12} /> Current state tamper-evident</span>
                    </div>
                  </article>
                )}</Show>

                <Show when={
                  room().creator_address === connectedAddress()
                  && room().lifecycle_status === "active"
                }>
                  <div class="collaboration-action-note">
                    <ShieldAlert size={15} />
                    <span>
                      Archive is explicit and only succeeds once the room is quiescent.
                      Archived rooms have no live authority and become reclaimable
                      under the bounded retention policy.
                    </span>
                    <button
                      class="secondary-button danger"
                      type="button"
                      data-collaboration-action="archive-room"
                      disabled={Boolean(busy())}
                      onClick={archiveRoom}
                    >
                      {busy() === "archive" ? "Archiving…" : "Archive quiescent room"}
                    </button>
                  </div>
                </Show>

                <div class="collaboration-integrity-boundary">
                  <ShieldAlert size={16} />
                  <Show
                    when={collaborationRollbackProtectionVerified(room())}
                    fallback={(
                      <p>
                        <strong>Current-state integrity is not history.</strong> The service
                        authenticates the present store and makes same-file tampering
                        detectable. It has no external monotonic anchor, so restoring an
                        older valid snapshot is not yet detectable. Re-fetch current room
                        state before relying on a snapshot.
                      </p>
                    )}
                  >
                    <p>
                      <strong>Release-bound rollback witness observed.</strong> The current
                      commitment is anchored through the configured Base Sepolia
                      ExecutionPolicyAnchor under its reported-finalized, confirmation-depth
                      model. This remains a single-RPC witness—not an independent RPC quorum,
                      consensus proof, TDX result, or execution authority.
                    </p>
                  </Show>
                </div>
              </section>
            )}</Show>
          </div>
        </div>
      </section>

      <CollaborateExecution
        room={selectedRoom()}
        jointRun={jointReceipt()}
        session={session()}
        connectedAddress={connectedAddress()}
        coordinationReleaseEnabled={releaseConfigured()}
        transportAdapter={collaborationExecutionTransportAdapter}
      />

      <div class="collaboration-local-divider">
        <span>LOCAL DISCOVERY TOOL</span>
      </div>
      <div class="callout teal">
        <strong>How the brief stays IP-preserving.</strong> You send a bounded brief — never
        raw sequences, genomes, or identifiers. This optional composer remains local to
        the browser and is separate from the durable commitment room above.
      </div>
      <div class="collab">
        <form onSubmit={(e) => e.preventDefault()} aria-label="Compose a collaboration brief">
          <div class="field">
            <label for="org">Your name / organization</label>
            <input id="org" maxlength="80" value={org()} onInput={(e) => setOrg(e.currentTarget.value)} placeholder="e.g. Meridian Longevity Lab" />
          </div>
          <div class="field">
            <label for="ctype">Collaboration type</label>
            <select id="ctype" value={ctype()} onChange={(e) => setCtype(e.currentTarget.value)}>
              {COLLAB_TYPES.map((t) => (
                <option value={t}>{t}</option>
              ))}
            </select>
          </div>
          <div class="field">
            <label for="loc">Locality preference</label>
            <select id="loc" value={locality()} onChange={(e) => setLocality(e.currentTarget.value as Locality)}>
              {LOCALITIES.map((l) => (
                <option value={l.v}>{l.label}</option>
              ))}
            </select>
          </div>
          <div class="field">
            <label for="purpose">Declared purpose</label>
            <input
              id="purpose"
              maxlength="160"
              value={purpose()}
              onInput={(e) => setPurpose(e.currentTarget.value)}
              placeholder="e.g. pre-competitive-collaboration"
            />
          </div>
          <div class="two-col">
            <div class="field">
              <label for="budget">Budget cap (USD)</label>
              <input id="budget" type="number" inputmode="decimal" min="0" max="100000000" step="0.01" value={budget()} onInput={(e) => setBudget(e.currentTarget.value)} placeholder="25000" />
            </div>
            <div class="field">
              <label for="royalty">Royalty / query (USD)</label>
              <input id="royalty" type="number" inputmode="decimal" min="0" max="1000000" step="0.000001" value={royalty()} onInput={(e) => setRoyalty(e.currentTarget.value)} placeholder="0.03" />
            </div>
          </div>
          <div class="field">
            <label for="summary">Non-confidential summary</label>
            <textarea
              id="summary"
              maxlength="1200"
              value={summary()}
              onInput={(e) => setSummary(e.currentTarget.value)}
              placeholder="What capability you're seeking — no raw data, sequences, or identifiers."
            />
          </div>
        </form>

        <div class="brief-out">
          <h3>Brief preview</h3>
          <pre class="json" style={{ "white-space": "pre-wrap" }} role="region" tabindex="0" aria-label="Generated collaboration brief">
            {brief()}
          </pre>
          <div class="callout">
            <strong>Do not paste raw health data here.</strong> This composer builds an outbound
            brief only. Nothing is transmitted by this page — the buttons open your own mail client
            or copy text locally.
          </div>
          <div style={{ display: "flex", gap: "10px", "flex-wrap": "wrap" }}>
            <a class="run-btn" style={{ "text-decoration": "none", "text-align": "center", flex: "1" }} href={mailto()}>
              ✉ Open email draft
            </a>
            <button class="filter-btn" onClick={copyBrief} type="button">
              {copyState() === "copied" ? "Copied" : copyState() === "failed" ? "Select preview to copy" : "Copy brief"}
            </button>
          </div>
          <span class="sr-only" role="status" aria-live="polite">{copyState() === "copied" ? "Brief copied to clipboard." : copyState() === "failed" ? "Clipboard access was unavailable. Select the preview text and copy it manually." : ""}</span>
        </div>
      </div>
    </>
  );
}
