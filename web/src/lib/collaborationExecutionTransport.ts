import {
  authorizeCollaborationExecution,
  collaborationJointRunCurrentForRoom,
  collaborationSessionIsCurrent,
  createCollaborationExecutionPlan,
  fetchCollaborationExecutionWorkerCapability,
  fetchCollaborationExecutionStatus,
  fetchCollaborationExecutionStatusEnvelope,
  issueCollaborationExecutionGrantChallenge,
  assertCollaborationExecutionWorkerCapabilityMatchesCurrentRelease,
  type CollaborationExecutionPlanProjection,
  type CollaborationExecutionWorkerCapability,
  type CollaborationJointRun,
  type CollaborationRoom,
  type CollaborationSession,
} from "./collaboration";
import {
  COLLABORATION_EXECUTION_RELEASE_PROFILE,
  COLLABORATION_EXECUTION_RELEASE_SERVICE,
  type CollaborationExecutionReleaseConfig,
} from "./collaborationExecutionReleaseConfig";

export const COLLABORATION_EXECUTION_API_CONTRACT =
  "dnai.collaboration.execution-api.v1" as const;

export interface CollaborationExecutionTransportAdapter {
  readonly contract: typeof COLLABORATION_EXECUTION_API_CONTRACT;
  readonly createPlan: typeof createCollaborationExecutionPlan;
  readonly issueGrantChallenge: typeof issueCollaborationExecutionGrantChallenge;
  readonly authorize: typeof authorizeCollaborationExecution;
  readonly fetchWorkerCapability:
    typeof fetchCollaborationExecutionWorkerCapability;
  readonly fetchStatus: typeof fetchCollaborationExecutionStatus;
  readonly fetchStatusEnvelope: typeof fetchCollaborationExecutionStatusEnvelope;
}

export const collaborationExecutionTransportAdapter:
CollaborationExecutionTransportAdapter = Object.freeze({
  contract: COLLABORATION_EXECUTION_API_CONTRACT,
  createPlan: createCollaborationExecutionPlan,
  issueGrantChallenge: issueCollaborationExecutionGrantChallenge,
  authorize: authorizeCollaborationExecution,
  fetchWorkerCapability: fetchCollaborationExecutionWorkerCapability,
  fetchStatus: fetchCollaborationExecutionStatus,
  fetchStatusEnvelope: fetchCollaborationExecutionStatusEnvelope,
});

export interface CollaborationExecutionTransportGate {
  readonly apiContractWired: boolean;
  readonly currentCollaborationSessionBound: boolean;
  readonly selectedRoomBound: boolean;
  readonly currentJointSnapshotBound: boolean;
  readonly canonicalReleaseConfigured: boolean;
  readonly executionReleaseEnabled: boolean;
  readonly workerPresenceProven: boolean;
  readonly reservationCapabilityReady: boolean;
  readonly tdxAttestationClaimed: false;
  readonly qvlVerified: false;
  readonly controlPlaneStatusReadsEnabled: boolean;
  readonly controlPlaneMutationCallsEnabled: boolean;
  readonly reservationWriteEnabled: false;
  readonly settlementWriteEnabled: false;
  readonly modeledStateUsedForReadiness: false;
  readonly blockers: readonly string[];
}

export function collaborationExecutionTransportGate(input: {
  readonly adapter?: CollaborationExecutionTransportAdapter;
  readonly session?: CollaborationSession;
  readonly walletContext?: {
    readonly address: string | undefined;
    readonly chainId: number | undefined;
    readonly walletAuthorizationVersion: number;
    readonly nowMs?: number;
  };
  readonly room?: CollaborationRoom;
  readonly jointRun?: CollaborationJointRun;
  readonly release?: CollaborationExecutionReleaseConfig;
  readonly workerCapability?: CollaborationExecutionWorkerCapability;
  readonly plan?: CollaborationExecutionPlanProjection;
}): CollaborationExecutionTransportGate {
  const apiContractWired = input.adapter?.contract
    === COLLABORATION_EXECUTION_API_CONTRACT;
  const sessionBound = Boolean(
    input.walletContext
    && collaborationSessionIsCurrent(input.session, input.walletContext),
  );
  const roomBound = Boolean(input.room);
  const jointBound = Boolean(
    input.room
    && input.jointRun
    && collaborationJointRunCurrentForRoom(input.jointRun, input.room),
  );
  const release = input.release;
  const canonicalReleaseConfigured = Boolean(
    release?.configured
    && release.truthStatus === "release-configured"
    && release.service === COLLABORATION_EXECUTION_RELEASE_SERVICE
    && release.profile === COLLABORATION_EXECUTION_RELEASE_PROFILE
    && release.releaseSha
    && release.finalReleaseAuthoritySha256
    && release.releaseVerificationSha256
    && release.mainRuntimeCvmId
    && release.royaltyReleaseActiveStateSha256
    && release.royaltyReleaseHistorySha256
    && release.royaltyReleaseHistoryReceiptSha256
    && release.workerPresenceProven === false
    && release.tdxAttestationClaimed === false
    && release.qvlVerified === false,
  );
  const executionReleaseEnabled = canonicalReleaseConfigured
    && release?.executionEnabled === true;
  let workerPresenceProven = false;
  if (input.workerCapability) {
    try {
      assertCollaborationExecutionWorkerCapabilityMatchesCurrentRelease(
        input.workerCapability,
        input.plan,
        input.walletContext?.nowMs,
      );
      workerPresenceProven = true;
    } catch {
      workerPresenceProven = false;
    }
  }
  const reservationCapabilityReady = Boolean(
    workerPresenceProven
    && input.workerCapability?.onchain_reservation_ready === true,
  );
  // This is a typed canonical-v4 build projection, never a component boolean
  // or client DTO. It authorizes rendering mutation controls but is not worker
  // liveness, TDX, QVL, chain-finality, or reservation evidence.
  const blockers: string[] = [];
  if (!apiContractWired) blockers.push("The typed execution API adapter is absent.");
  if (!sessionBound) blockers.push("A current Collaboration wallet session is required.");
  if (!roomBound) blockers.push("Select a participant-authenticated room.");
  if (!jointBound) blockers.push("Record and re-fetch a current joint consent snapshot.");
  if (!canonicalReleaseConfigured) {
    blockers.push(
      release?.issues[0]
        ?? "No canonical v4 Collaboration execution release is projected to the browser.",
    );
  }
  if (canonicalReleaseConfigured && !executionReleaseEnabled) {
    blockers.push("The signed current-v4 release decision keeps Collaboration execution disabled.");
  }
  const controlPlaneStatusReadsEnabled = apiContractWired
    && sessionBound
    && canonicalReleaseConfigured
    && executionReleaseEnabled;
  const controlPlaneMutationCallsEnabled = controlPlaneStatusReadsEnabled
    && roomBound
    && jointBound;
  const reservationWriteEnabled = false;
  const settlementWriteEnabled = false;
  if (!reservationCapabilityReady) {
    blockers.push("Royalty reservation writes require fresh authenticated release-matching worker presence.");
  } else if (!reservationWriteEnabled) {
    blockers.push("Worker presence is current; a reservation write still requires fresh Royalty authority and the exact persisted server reservation.");
  }
  if (!settlementWriteEnabled) {
    blockers.push("Royalty settlement writes await a fresh persisted dual-authorized settlement plan.");
  }
  return Object.freeze({
    apiContractWired,
    currentCollaborationSessionBound: sessionBound,
    selectedRoomBound: roomBound,
    currentJointSnapshotBound: jointBound,
    canonicalReleaseConfigured,
    executionReleaseEnabled,
    workerPresenceProven,
    reservationCapabilityReady,
    tdxAttestationClaimed: false as const,
    qvlVerified: false as const,
    controlPlaneStatusReadsEnabled,
    controlPlaneMutationCallsEnabled,
    reservationWriteEnabled,
    settlementWriteEnabled,
    modeledStateUsedForReadiness: false as const,
    blockers: Object.freeze(blockers),
  });
}

export interface CollaborationExecutionClientDtoEvidenceBoundary {
  readonly clientDtoAcceptedAsJournalEvidence: false;
  readonly clientDtoAcceptedAsFinalizedVaultEvidence: false;
  readonly clientDtoAcceptedAsTdxEvidence: false;
  readonly clientDtoAcceptedAsQvlEvidence: false;
  readonly clientDtoMayUnlockExecutionControls: false;
  readonly requiredSource:
    "participant_api_plus_trusted_local_journal_and_fresh_chain_read";
}

export function collaborationExecutionClientDtoEvidenceBoundary(
  value: unknown,
): CollaborationExecutionClientDtoEvidenceBoundary {
  // A DTO can help render a participant-visible projection, but its own fields
  // cannot authenticate the journal, a fresh finalized chain read, TDX, or QVL.
  // Deliberately ignore even truthy forged fields here.
  void value;
  return Object.freeze({
    clientDtoAcceptedAsJournalEvidence: false as const,
    clientDtoAcceptedAsFinalizedVaultEvidence: false as const,
    clientDtoAcceptedAsTdxEvidence: false as const,
    clientDtoAcceptedAsQvlEvidence: false as const,
    clientDtoMayUnlockExecutionControls: false as const,
    requiredSource:
      "participant_api_plus_trusted_local_journal_and_fresh_chain_read" as const,
  });
}
