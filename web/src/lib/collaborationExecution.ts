import { sha256, toHex } from "viem";
import {
  collaborationJointRunCurrentForRoom,
  type CollaborationJointRun,
  type CollaborationRoom,
} from "./collaboration";

export const COLLABORATION_EXECUTION_MODEL_SCHEMA =
  "dnai.collaboration.execution-workbench-model.v1" as const;

export type CollaborationExecutionScenario =
  | "release_disabled"
  | "happy_path"
  | "grant_drift"
  | "stale_finalized_evidence"
  | "adoption_disabled"
  | "adoption_enabled"
  | "ambiguous_reconciliation"
  | "bounded_result"
  | "settlement_withdrawal";

export type CollaborationExecutionState =
  | "disabled"
  | "modeled_grants_required"
  | "blocked_grant_drift"
  | "blocked_adoption"
  | "blocked_stale_finality"
  | "modeled_authorized"
  | "modeled_awaiting_royalty_reservation"
  | "modeled_dispatched"
  | "modeled_reconciliation"
  | "modeled_bounded_result"
  | "modeled_royalty_authorized"
  | "modeled_withdrawal";

export type CollaborationExecutionLaneId =
  | "coordination"
  | "execution_grants"
  | "compute_intent"
  | "funding"
  | "claim_handoff"
  | "bounded_result"
  | "royalty"
  | "withdrawal";

export type CollaborationExecutionLaneStatus =
  | "complete"
  | "active"
  | "pending"
  | "blocked"
  | "reconciliation";

export interface CollaborationExecutionLane {
  readonly id: CollaborationExecutionLaneId;
  readonly number: string;
  readonly label: string;
  readonly status: CollaborationExecutionLaneStatus;
  readonly evidence: "coordination_input" | "modeled" | "not_observed";
  readonly detail: string;
}

export interface CollaborationExecutionOwnerEvidence {
  readonly ownerAddress: string;
  readonly allocationBps: number;
  readonly queryGrantStatus: "approved" | "missing" | "revoked";
  readonly executionGrantStatus: "pending" | "current" | "drifted";
  readonly executionGrantScope: "one_shot_execution";
  readonly queryGrantIsExecutionGrant: false;
  readonly executionAuthorizationHash: string;
  readonly modeledWithdrawalAmount: number;
  readonly liveCreditObserved: false;
  readonly liveWithdrawalObserved: false;
}

export interface CollaborationExecutionModelInput {
  readonly scenario: CollaborationExecutionScenario;
  readonly happyPathStep?: number;
  readonly room?: CollaborationRoom;
  readonly jointRun?: CollaborationJointRun;
  readonly connectedAddress?: string;
  readonly coordinationReleaseEnabled?: boolean;
  readonly workloadSource?: "wallet" | "credential";
  readonly walletAdoptionEnabled?: boolean;
}

export interface CollaborationExecutionModel {
  readonly schema: typeof COLLABORATION_EXECUTION_MODEL_SCHEMA;
  readonly scenario: CollaborationExecutionScenario;
  readonly executionState: CollaborationExecutionState;
  readonly stateLabel: string;
  readonly productionExecutionEnabled: false;
  readonly modeledOnly: true;
  readonly coordination: {
    readonly source:
      | "participant_authenticated_room_projection"
      | "deterministic_demo_fixture";
    readonly releaseEnabled: boolean;
    readonly roomBound: boolean;
    readonly roomId: string;
    readonly roomGeneration: number;
    readonly queryGrantsCurrent: boolean;
    readonly jointSnapshotCurrent: boolean;
    readonly liveExecutionAuthority: false;
  };
  readonly owners: readonly CollaborationExecutionOwnerEvidence[];
  readonly commitments: {
    readonly executionBasis: string;
    readonly executionGrantSet: string;
    readonly computeAuthorizationContext: string;
    readonly computeDispatchIntent: string;
    readonly computeHandoff: string;
    readonly royaltyOwnerAmounts: string;
    readonly royaltyReservationId: string;
    readonly royaltyReleaseBinding: string;
  };
  readonly workload: {
    readonly sourceKind: "wallet" | "credential";
    readonly walletAdoptionEnabled: boolean;
    readonly adoptionStatus:
      | "not_required"
      | "release_disabled"
      | "eligible_modeled";
    readonly uploaderKeepsSourceAttribution: true;
    readonly deviceSpendAuthority: false;
    readonly fundingWalletAuthorityModeled: boolean;
    readonly adoptionLiveClaimObserved: false;
  };
  readonly funding: {
    readonly assetLabel: "Base Sepolia test asset";
    readonly maxTotalDebit: number;
    readonly maxComputeDebit: number;
    readonly royaltyTotal: number;
    readonly computeAuthorizationStatus:
      | "not_modeled"
      | "modeled_authorized";
    readonly royaltyReservationStatus:
      | "not_issued"
      | "modeled_terms_issued"
      | "modeled_finalized_active";
    readonly royaltyReservationServerGenerated: true;
    readonly royaltyDepositRequiredAfterGrantAuthorization: true;
    readonly balanceOrAllowanceIsAuthorization: false;
    readonly computeFundsReserved: false;
    readonly computeFundingFinalized: false;
    readonly modeledRoyaltyReservationFinalized: boolean;
    readonly liveRoyaltyDepositObserved: false;
    readonly liveRoyaltyReservationFinalizedObserved: false;
    readonly liveRoyaltyReservationActiveObserved: false;
    readonly liveRoyaltyReservationUnconsumedObserved: false;
  };
  readonly vaultEvidence: {
    readonly status: "unobserved" | "modeled_current_fixture" | "stale_fixture";
    readonly reportedFinalized: boolean;
    readonly freshnessProven: false;
    readonly modeledBlockAgeSeconds: number | null;
    readonly maximumModeledAgeSeconds: 600;
    readonly claimAllowedInModel: boolean;
    readonly liveRpcEvidenceObserved: false;
  };
  readonly computeJournal: {
    readonly projectionStatus:
      | "none"
      | "typed_projection"
      | "ambiguous_projection"
      | "bounded_projection";
    readonly sourceAuthenticationProven: false;
    readonly sourceAuthenticationBoundary:
      "trusted_local_compute_journal_reader_required";
    readonly providerDispatchMayHaveOccurred: boolean | null;
    readonly automaticProviderRedispatch: false;
    readonly reconciliationRequired: boolean;
    readonly liveJournalRecordObserved: false;
  };
  readonly boundedResult: null | {
    readonly resultClass: "completed_within_authorized_caps";
    readonly resultPolicy: "score_band_hash";
    readonly scoreBand: "top_10_percent";
    readonly resultCommitment: string;
    readonly usageCommitment: string;
    readonly actualComputeDebit: number;
    readonly rawResultIncluded: false;
    readonly tdxAttestationVerified: false;
    readonly qvlVerified: false;
  };
  readonly royalty: {
    readonly modeledStage:
      | "not_started"
      | "reservation_terms_issued"
      | "settlement_prepared"
      | "settlement_finalized"
      | "withdrawal_ready";
    readonly exactPayoutValidationProven: false;
    readonly releaseAuthorityVerified: false;
    readonly qvlAuthorizationVerified: false;
    readonly fundingFinalized: false;
    readonly broadcastObserved: false;
    readonly finalizedReceiptObserved: false;
    readonly withdrawalObserved: false;
  };
  readonly lanes: readonly CollaborationExecutionLane[];
  readonly blockers: readonly string[];
  readonly productionRequirements: readonly string[];
}

const DEMO_OWNER_A = `0x${"1".repeat(40)}`;
const DEMO_OWNER_B = `0x${"2".repeat(40)}`;
const DEMO_ROOM_ID = `room_${"a".repeat(32)}`;
const MODELED_MAX_TOTAL_DEBIT = 10_000;
const MODELED_MAX_COMPUTE_DEBIT = 7_000;
const MODELED_ROYALTY_TOTAL = 2_000;

const LANE_DEFINITIONS: readonly Omit<
  CollaborationExecutionLane,
  "status" | "evidence" | "detail"
>[] = [
  { id: "coordination", number: "01", label: "Room + joint snapshot" },
  { id: "execution_grants", number: "02", label: "Fresh execution grants" },
  { id: "compute_intent", number: "03", label: "Derived Compute intent" },
  { id: "funding", number: "04", label: "Compute auth + Royalty reservation" },
  { id: "claim_handoff", number: "05", label: "Claim + handoff" },
  { id: "bounded_result", number: "06", label: "Bounded result" },
  { id: "royalty", number: "07", label: "Royalty settlement" },
  { id: "withdrawal", number: "08", label: "Owner withdrawals" },
];

const LANE_DETAILS: Readonly<Record<CollaborationExecutionLaneId, string>> = {
  coordination: "Current room, exact query grants, allocation, and joint snapshot.",
  execution_grants: "A new one-shot grant from every owner; query grants never carry over.",
  compute_intent: "Canonical Compute v3 intent derived after the exact grant set exists.",
  funding: "Compute cap authorization is separate; exact Royalty terms are server-issued after fresh grants, then deposited onchain.",
  claim_handoff: "Fresh vault evidence is checked before the durable Compute handoff is released.",
  bounded_result: "Only a bounded score band and commitments may return; no raw result.",
  royalty: "An active finalized unconsumed reservation, settlement authority, and independent QVL authorization are separate evidence boundaries.",
  withdrawal: "Finalized owner credits are pull payments; each owner withdraws independently.",
};

function modelCommitment(domain: string, parts: readonly unknown[]): string {
  const serialized = JSON.stringify([domain, ...parts]);
  return `sha256:${sha256(toHex(serialized)).slice(2)}`;
}

function modelBytes32(domain: string, parts: readonly unknown[]): string {
  return sha256(toHex(JSON.stringify([domain, ...parts])));
}

function scenarioProgress(
  scenario: CollaborationExecutionScenario,
  happyPathStep: number | undefined,
): number {
  switch (scenario) {
    case "release_disabled": return 0;
    case "grant_drift": return 1;
    case "adoption_disabled": return 2;
    case "adoption_enabled": return 3;
    case "stale_finalized_evidence": return 3;
    case "ambiguous_reconciliation": return 4;
    case "bounded_result": return 5;
    case "settlement_withdrawal": return 7;
    case "happy_path":
      return Math.max(1, Math.min(7, Math.trunc(happyPathStep ?? 1)));
  }
}

function executionState(
  scenario: CollaborationExecutionScenario,
  progress: number,
): CollaborationExecutionState {
  if (scenario === "release_disabled") return "disabled";
  if (scenario === "grant_drift") return "blocked_grant_drift";
  if (scenario === "adoption_disabled") return "blocked_adoption";
  if (scenario === "stale_finalized_evidence") return "blocked_stale_finality";
  if (scenario === "ambiguous_reconciliation") return "modeled_reconciliation";
  if (scenario === "settlement_withdrawal") return "modeled_withdrawal";
  if (progress >= 6) return "modeled_royalty_authorized";
  if (progress >= 5) return "modeled_bounded_result";
  if (progress >= 4) return "modeled_dispatched";
  if (progress >= 3) return "modeled_awaiting_royalty_reservation";
  if (progress >= 2) return "modeled_authorized";
  return "modeled_grants_required";
}

function executionStateLabel(state: CollaborationExecutionState): string {
  const labels: Readonly<Record<CollaborationExecutionState, string>> = {
    disabled: "IMPLEMENTED · CURRENT RELEASE DISABLED",
    modeled_grants_required: "MODELED · FRESH GRANTS REQUIRED",
    blocked_grant_drift: "BLOCKED · OWNER GRANT DRIFT",
    blocked_adoption: "BLOCKED · WALLET ADOPTION DISABLED",
    blocked_stale_finality: "BLOCKED · FINALIZED EVIDENCE STALE",
    modeled_authorized: "MODELED · EXECUTION AUTHORIZED",
    modeled_awaiting_royalty_reservation: "MODELED · AWAITING FINALIZED ROYALTY RESERVATION",
    modeled_dispatched: "MODELED · COMPUTE HANDOFF",
    modeled_reconciliation: "MODELED · RECONCILIATION HOLD",
    modeled_bounded_result: "MODELED · BOUNDED RESULT READY",
    modeled_royalty_authorized: "MODELED · ROYALTY AUTHORIZATION",
    modeled_withdrawal: "MODELED · OWNER WITHDRAWAL STAGES",
  };
  return labels[state];
}

function laneStatus(
  index: number,
  progress: number,
  scenario: CollaborationExecutionScenario,
): CollaborationExecutionLaneStatus {
  if (scenario === "release_disabled") {
    return index === 0 ? "blocked" : "pending";
  }
  const blockedIndex = scenario === "grant_drift"
    ? 1
    : scenario === "adoption_disabled"
      ? 3
      : scenario === "stale_finalized_evidence"
        ? 4
        : -1;
  if (index === blockedIndex) return "blocked";
  if (scenario === "ambiguous_reconciliation" && index === 4) {
    return "reconciliation";
  }
  if (index < progress) return "complete";
  if (index === progress) return "active";
  return "pending";
}

function royaltyStage(
  scenario: CollaborationExecutionScenario,
  progress: number,
): CollaborationExecutionModel["royalty"]["modeledStage"] {
  if (scenario === "settlement_withdrawal") return "withdrawal_ready";
  if (progress >= 7) return "settlement_finalized";
  if (progress >= 6) return "reservation_terms_issued";
  return "not_started";
}

export function buildCollaborationExecutionModel(
  input: CollaborationExecutionModelInput,
): CollaborationExecutionModel {
  const room = input.room;
  const query = room?.current_query;
  const jointSnapshotCurrent = Boolean(
    room
      && input.jointRun
      && collaborationJointRunCurrentForRoom(input.jointRun, room),
  );
  const progress = scenarioProgress(input.scenario, input.happyPathStep);
  const state = executionState(input.scenario, progress);
  const workloadSource = input.workloadSource
    ?? (input.scenario === "adoption_disabled" || input.scenario === "adoption_enabled"
      ? "credential"
      : "wallet");
  const adoptionEnabled = input.walletAdoptionEnabled
    ?? input.scenario === "adoption_enabled";
  const roomId = room?.room_id ?? DEMO_ROOM_ID;
  const roomGeneration = room?.generation ?? 7;
  const queryRef = query?.query_ref
    ?? modelCommitment("demo-query", [roomId, roomGeneration]);
  const allocationCommitment = query?.allocation_commitment
    ?? modelCommitment("demo-allocation", [roomId, roomGeneration]);
  const jointSnapshot = input.jointRun?.joint_consent_snapshot_commitment
    ?? modelCommitment("demo-joint-snapshot", [roomId, queryRef]);

  const sourceOwners = room?.owners.length
    ? room.owners.map((owner) => ({
        address: owner.owner_address,
        allocationBps: owner.allocation_bps,
        queryGrantStatus: query?.owner_query_grants.find(
          (grant) => grant.owner_address === owner.owner_address,
        )?.grant_status ?? "pending",
      }))
    : [
        { address: DEMO_OWNER_A, allocationBps: 6_000, queryGrantStatus: "approved" },
        { address: DEMO_OWNER_B, allocationBps: 4_000, queryGrantStatus: "approved" },
      ];
  const ownerAddresses = sourceOwners.map((owner) => owner.address);
  const executionBasis = modelCommitment("execution-basis", [
    roomId,
    roomGeneration,
    queryRef,
    allocationCommitment,
    jointSnapshot,
    ownerAddresses,
  ]);
  let allocatedRoyalty = 0;
  const ownerAmounts = sourceOwners.map((owner, index) => {
    const amount = index === sourceOwners.length - 1
      ? MODELED_ROYALTY_TOTAL - allocatedRoyalty
      : Math.floor(
          MODELED_ROYALTY_TOTAL * owner.allocationBps / 10_000,
        );
    allocatedRoyalty += amount;
    return { owner: owner.address, amount };
  });
  const royaltyOwnerAmounts = modelBytes32("royalty-owner-amounts-model", [
    ownerAmounts,
  ]);

  const owners = Object.freeze(sourceOwners.map((owner, index) => {
    const drifted = input.scenario === "grant_drift" && index === 0;
    const current = progress >= 2 && input.scenario !== "release_disabled";
    return Object.freeze({
      ownerAddress: owner.address,
      allocationBps: owner.allocationBps,
      queryGrantStatus: owner.queryGrantStatus === "approved"
        ? "approved" as const
        : owner.queryGrantStatus === "revoked"
          ? "revoked" as const
          : "missing" as const,
      executionGrantStatus: drifted
        ? "drifted" as const
        : current
          ? "current" as const
          : "pending" as const,
      executionGrantScope: "one_shot_execution" as const,
      queryGrantIsExecutionGrant: false as const,
      executionAuthorizationHash: modelCommitment(
        "owner-execution-authorization",
        [executionBasis, owner.address, roomGeneration],
      ),
      modeledWithdrawalAmount: ownerAmounts[index]?.amount ?? 0,
      liveCreditObserved: false as const,
      liveWithdrawalObserved: false as const,
    });
  }));
  const grantSet = modelCommitment("execution-grant-set", [
    executionBasis,
    owners.map((owner) => [
      owner.ownerAddress,
      owner.executionAuthorizationHash,
      owner.executionGrantStatus,
    ]),
  ]);
  const computeAuthorizationContext = modelCommitment(
    "compute-collaboration-one-shot-context",
    [executionBasis, grantSet, roomId, queryRef],
  );
  const computeDispatchIntent = modelBytes32("compute-dispatch-intent", [
    computeAuthorizationContext,
    roomId,
    queryRef,
    workloadSource,
  ]);
  const computeHandoff = modelCommitment("compute-handoff", [
    computeDispatchIntent,
    computeAuthorizationContext,
    jointSnapshot,
  ]);
  const royaltyReservationId = modelBytes32(
    "royalty-reservation-id-model",
    [roomId, executionBasis, royaltyOwnerAmounts],
  );
  const royaltyReleaseBinding = modelCommitment(
    "royalty-release-binding-model",
    [roomId, royaltyOwnerAmounts, MODELED_MAX_TOTAL_DEBIT],
  );

  const adoptionBlocked = workloadSource === "credential" && !adoptionEnabled;
  const staleVault = input.scenario === "stale_finalized_evidence";
  const reconciliation = input.scenario === "ambiguous_reconciliation";
  const resultReady = progress >= 5
    && !staleVault
    && !adoptionBlocked
    && !reconciliation;

  const blockers: string[] = [];
  if (input.scenario === "release_disabled") {
    blockers.push("The execution implementation is present, but the current unsigned/dev release does not authorize Collaboration mutations.");
  }
  if (room && (!query?.all_required_query_grants_current || !jointSnapshotCurrent)) {
    blockers.push(
      "The selected live room does not yet have a current exact-query grant set and joint snapshot.",
    );
  }
  if (input.scenario === "grant_drift") {
    blockers.push(
      "An owner execution grant no longer matches the exact basis; derive a new intent only after every owner re-signs.",
    );
  }
  if (adoptionBlocked) {
    blockers.push(
      "This credential-uploaded workload cannot be funded by a wallet until the measured release enables immutable wallet adoption.",
    );
  }
  if (staleVault) {
    blockers.push(
      "The reported-finalized Compute vault observation is older than the modeled freshness window.",
    );
  }
  if (reconciliation) {
    blockers.push(
      "Provider dispatch may have occurred; automatic redispatch is forbidden until a trusted reader returns a conclusive projection.",
    );
  }

  const lanes = Object.freeze(LANE_DEFINITIONS.map((lane, index) => {
    const status = laneStatus(index, progress, input.scenario);
    return Object.freeze({
      ...lane,
      status,
      evidence: index === 0 && room
        ? "coordination_input" as const
        : status === "pending"
          ? "not_observed" as const
          : "modeled" as const,
      detail: LANE_DETAILS[lane.id],
    });
  }));

  const projectionPresent = progress >= 4 && !staleVault && !adoptionBlocked;
  const boundedResult = resultReady
    ? Object.freeze({
        resultClass: "completed_within_authorized_caps" as const,
        resultPolicy: "score_band_hash" as const,
        scoreBand: "top_10_percent" as const,
        resultCommitment: modelCommitment("bounded-result", [computeHandoff]),
        usageCommitment: modelCommitment("bounded-usage", [computeHandoff, 4_800]),
        actualComputeDebit: 4_800,
        rawResultIncluded: false as const,
        tdxAttestationVerified: false as const,
        qvlVerified: false as const,
      })
    : null;

  return Object.freeze({
    schema: COLLABORATION_EXECUTION_MODEL_SCHEMA,
    scenario: input.scenario,
    executionState: state,
    stateLabel: executionStateLabel(state),
    productionExecutionEnabled: false,
    modeledOnly: true,
    coordination: Object.freeze({
      source: room
        ? "participant_authenticated_room_projection" as const
        : "deterministic_demo_fixture" as const,
      releaseEnabled: input.coordinationReleaseEnabled === true,
      roomBound: Boolean(room),
      roomId,
      roomGeneration,
      queryGrantsCurrent: room
        ? query?.all_required_query_grants_current === true
        : true,
      jointSnapshotCurrent: room ? jointSnapshotCurrent : true,
      liveExecutionAuthority: false as const,
    }),
    owners,
    commitments: Object.freeze({
      executionBasis,
      executionGrantSet: grantSet,
      computeAuthorizationContext,
      computeDispatchIntent,
      computeHandoff,
      royaltyOwnerAmounts,
      royaltyReservationId,
      royaltyReleaseBinding,
    }),
    workload: Object.freeze({
      sourceKind: workloadSource,
      walletAdoptionEnabled: adoptionEnabled,
      adoptionStatus: workloadSource === "wallet"
        ? "not_required" as const
        : adoptionEnabled
          ? "eligible_modeled" as const
          : "release_disabled" as const,
      uploaderKeepsSourceAttribution: true as const,
      deviceSpendAuthority: false as const,
      fundingWalletAuthorityModeled:
        workloadSource === "wallet" || adoptionEnabled,
      adoptionLiveClaimObserved: false as const,
    }),
    funding: Object.freeze({
      assetLabel: "Base Sepolia test asset" as const,
      maxTotalDebit: MODELED_MAX_TOTAL_DEBIT,
      maxComputeDebit: MODELED_MAX_COMPUTE_DEBIT,
      royaltyTotal: MODELED_ROYALTY_TOTAL,
      computeAuthorizationStatus: progress >= 3 && !adoptionBlocked
        ? "modeled_authorized" as const
        : "not_modeled" as const,
      royaltyReservationStatus: progress >= 4 && !adoptionBlocked
        ? "modeled_finalized_active" as const
        : progress >= 3 && !adoptionBlocked
          ? "modeled_terms_issued" as const
          : "not_issued" as const,
      royaltyReservationServerGenerated: true as const,
      royaltyDepositRequiredAfterGrantAuthorization: true as const,
      balanceOrAllowanceIsAuthorization: false as const,
      computeFundsReserved: false as const,
      computeFundingFinalized: false as const,
      modeledRoyaltyReservationFinalized:
        progress >= 4 && !adoptionBlocked,
      liveRoyaltyDepositObserved: false as const,
      liveRoyaltyReservationFinalizedObserved: false as const,
      liveRoyaltyReservationActiveObserved: false as const,
      liveRoyaltyReservationUnconsumedObserved: false as const,
    }),
    vaultEvidence: Object.freeze({
      status: staleVault
        ? "stale_fixture" as const
        : progress >= 4
          ? "modeled_current_fixture" as const
          : "unobserved" as const,
      reportedFinalized: staleVault || progress >= 4,
      freshnessProven: false as const,
      modeledBlockAgeSeconds: staleVault ? 941 : progress >= 4 ? 42 : null,
      maximumModeledAgeSeconds: 600 as const,
      claimAllowedInModel:
        progress >= 4 && !staleVault && !adoptionBlocked,
      liveRpcEvidenceObserved: false as const,
    }),
    computeJournal: Object.freeze({
      projectionStatus: !projectionPresent
        ? "none" as const
        : reconciliation
          ? "ambiguous_projection" as const
          : resultReady
            ? "bounded_projection" as const
            : "typed_projection" as const,
      sourceAuthenticationProven: false as const,
      sourceAuthenticationBoundary:
        "trusted_local_compute_journal_reader_required" as const,
      providerDispatchMayHaveOccurred: !projectionPresent
        ? null
        : reconciliation || resultReady,
      automaticProviderRedispatch: false as const,
      reconciliationRequired: reconciliation,
      liveJournalRecordObserved: false as const,
    }),
    boundedResult,
    royalty: Object.freeze({
      modeledStage: royaltyStage(input.scenario, progress),
      exactPayoutValidationProven: false as const,
      releaseAuthorityVerified: false as const,
      qvlAuthorizationVerified: false as const,
      fundingFinalized: false as const,
      broadcastObserved: false as const,
      finalizedReceiptObserved: false as const,
      withdrawalObserved: false as const,
    }),
    lanes,
    blockers: Object.freeze(blockers),
    productionRequirements: Object.freeze([
      "Fresh one-shot execution grants verified for every current owner.",
      "Server-issued exact Royalty reservation deposited only after authorization, then observed active, finalized, and unconsumed by the worker.",
      "Current finalized Compute-vault read from the pinned release under a bounded freshness policy.",
      "Authenticated local Compute-journal reader; a client projection is never source evidence.",
      "Active Royalty settlement authority, independent QVL authorization, and a finalized broadcast receipt.",
    ]),
  });
}

export function nextCollaborationHappyPathStep(step: number): number {
  const normalized = Number.isFinite(step) ? Math.trunc(step) : 1;
  return normalized >= 7 ? 1 : Math.max(1, normalized + 1);
}
