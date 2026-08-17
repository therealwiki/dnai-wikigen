import { describe, expect, it } from "vitest";

import {
  buildCollaborationExecutionModel,
  nextCollaborationHappyPathStep,
} from "./collaborationExecution";

describe("Collaboration execution workbench model", () => {
  it("fails closed when the production execution release is disabled", () => {
    const model = buildCollaborationExecutionModel({
      scenario: "release_disabled",
      coordinationReleaseEnabled: true,
    });

    expect(model.executionState).toBe("disabled");
    expect(model.productionExecutionEnabled).toBe(false);
    expect(model.modeledOnly).toBe(true);
    expect(model.coordination.releaseEnabled).toBe(true);
    expect(model.coordination.liveExecutionAuthority).toBe(false);
    expect(model.funding.computeAuthorizationStatus).toBe("not_modeled");
    expect(model.funding.computeFundsReserved).toBe(false);
    expect(model.funding.royaltyReservationStatus).toBe("not_issued");
    expect(model.funding.liveRoyaltyReservationFinalizedObserved).toBe(false);
    expect(model.blockers).toContain(
      "The execution implementation is present, but the current unsigned/dev release does not authorize Collaboration mutations.",
    );
  });

  it("keeps exact-query grants separate from fresh one-shot execution grants", () => {
    const model = buildCollaborationExecutionModel({ scenario: "grant_drift" });

    expect(model.executionState).toBe("blocked_grant_drift");
    expect(model.owners[0]?.queryGrantStatus).toBe("approved");
    expect(model.owners[0]?.executionGrantStatus).toBe("drifted");
    expect(model.owners.every((owner) => owner.queryGrantIsExecutionGrant === false)).toBe(true);
    expect(model.owners.every((owner) => owner.executionGrantScope === "one_shot_execution")).toBe(true);
    expect(model.lanes.find((lane) => lane.id === "execution_grants")?.status).toBe("blocked");
    expect(model.blockers.join(" ")).toContain("every owner re-signs");
  });

  it("does not treat a stale reported-finalized observation as fresh claim evidence", () => {
    const model = buildCollaborationExecutionModel({
      scenario: "stale_finalized_evidence",
    });

    expect(model.executionState).toBe("blocked_stale_finality");
    expect(model.vaultEvidence.status).toBe("stale_fixture");
    expect(model.vaultEvidence.reportedFinalized).toBe(true);
    expect(model.vaultEvidence.freshnessProven).toBe(false);
    expect(model.vaultEvidence.modeledBlockAgeSeconds).toBeGreaterThan(
      model.vaultEvidence.maximumModeledAgeSeconds,
    );
    expect(model.vaultEvidence.claimAllowedInModel).toBe(false);
    expect(model.vaultEvidence.liveRpcEvidenceObserved).toBe(false);
    expect(model.lanes.find((lane) => lane.id === "claim_handoff")?.status).toBe("blocked");
  });

  it("blocks credential adoption until enabled without giving the uploader spend authority", () => {
    const disabled = buildCollaborationExecutionModel({
      scenario: "adoption_disabled",
      workloadSource: "credential",
      walletAdoptionEnabled: false,
    });
    const enabled = buildCollaborationExecutionModel({
      scenario: "adoption_enabled",
      workloadSource: "credential",
      walletAdoptionEnabled: true,
    });

    expect(disabled.executionState).toBe("blocked_adoption");
    expect(disabled.workload.adoptionStatus).toBe("release_disabled");
    expect(disabled.workload.fundingWalletAuthorityModeled).toBe(false);
    expect(disabled.funding.computeAuthorizationStatus).toBe("not_modeled");
    expect(enabled.workload.adoptionStatus).toBe("eligible_modeled");
    expect(enabled.workload.fundingWalletAuthorityModeled).toBe(true);
    expect(enabled.funding.computeAuthorizationStatus).toBe("modeled_authorized");
    expect(enabled.executionState).toBe("modeled_awaiting_royalty_reservation");
    expect(enabled.funding.royaltyReservationStatus).toBe("modeled_terms_issued");
    for (const model of [disabled, enabled]) {
      expect(model.workload.uploaderKeepsSourceAttribution).toBe(true);
      expect(model.workload.deviceSpendAuthority).toBe(false);
      expect(model.workload.adoptionLiveClaimObserved).toBe(false);
    }
  });

  it("keeps execution queued until the model reaches an exact finalized Royalty reservation", () => {
    const termsOnly = buildCollaborationExecutionModel({
      scenario: "happy_path",
      happyPathStep: 3,
    });
    const finalizedFixture = buildCollaborationExecutionModel({
      scenario: "happy_path",
      happyPathStep: 4,
    });

    expect(termsOnly.executionState).toBe("modeled_awaiting_royalty_reservation");
    expect(termsOnly.funding).toMatchObject({
      royaltyReservationStatus: "modeled_terms_issued",
      royaltyReservationServerGenerated: true,
      royaltyDepositRequiredAfterGrantAuthorization: true,
      balanceOrAllowanceIsAuthorization: false,
      modeledRoyaltyReservationFinalized: false,
      liveRoyaltyDepositObserved: false,
      liveRoyaltyReservationFinalizedObserved: false,
      liveRoyaltyReservationActiveObserved: false,
      liveRoyaltyReservationUnconsumedObserved: false,
    });
    expect(finalizedFixture.funding.royaltyReservationStatus).toBe(
      "modeled_finalized_active",
    );
    expect(finalizedFixture.funding.modeledRoyaltyReservationFinalized).toBe(true);
    expect(finalizedFixture.funding.liveRoyaltyReservationFinalizedObserved).toBe(false);
  });

  it("holds ambiguous provider state for trusted reconciliation and forbids redispatch", () => {
    const model = buildCollaborationExecutionModel({
      scenario: "ambiguous_reconciliation",
    });

    expect(model.executionState).toBe("modeled_reconciliation");
    expect(model.computeJournal.projectionStatus).toBe("ambiguous_projection");
    expect(model.computeJournal.reconciliationRequired).toBe(true);
    expect(model.computeJournal.providerDispatchMayHaveOccurred).toBe(true);
    expect(model.computeJournal.automaticProviderRedispatch).toBe(false);
    expect(model.computeJournal.sourceAuthenticationProven).toBe(false);
    expect(model.computeJournal.liveJournalRecordObserved).toBe(false);
    expect(model.boundedResult).toBeNull();
    expect(model.lanes.find((lane) => lane.id === "claim_handoff")?.status).toBe(
      "reconciliation",
    );
  });

  it("returns only a modeled bounded result and never upgrades it to TDX or QVL evidence", () => {
    const model = buildCollaborationExecutionModel({ scenario: "bounded_result" });

    expect(model.executionState).toBe("modeled_bounded_result");
    expect(model.computeJournal.projectionStatus).toBe("bounded_projection");
    expect(model.computeJournal.sourceAuthenticationProven).toBe(false);
    expect(model.boundedResult).toMatchObject({
      resultClass: "completed_within_authorized_caps",
      resultPolicy: "score_band_hash",
      scoreBand: "top_10_percent",
      rawResultIncluded: false,
      tdxAttestationVerified: false,
      qvlVerified: false,
    });
    expect(model.boundedResult?.actualComputeDebit).toBeLessThanOrEqual(
      model.funding.maxComputeDebit,
    );
  });

  it("models settlement and pull withdrawals without claiming live payout evidence", () => {
    const model = buildCollaborationExecutionModel({
      scenario: "settlement_withdrawal",
    });

    expect(model.executionState).toBe("modeled_withdrawal");
    expect(model.royalty.modeledStage).toBe("withdrawal_ready");
    expect(model.royalty).toMatchObject({
      exactPayoutValidationProven: false,
      releaseAuthorityVerified: false,
      qvlAuthorizationVerified: false,
      fundingFinalized: false,
      broadcastObserved: false,
      finalizedReceiptObserved: false,
      withdrawalObserved: false,
    });
    expect(model.funding.liveRoyaltyReservationFinalizedObserved).toBe(false);
    expect(model.owners.reduce(
      (total, owner) => total + owner.modeledWithdrawalAmount,
      0,
    )).toBe(model.funding.royaltyTotal);
    expect(model.owners.every((owner) => !owner.liveCreditObserved)).toBe(true);
    expect(model.owners.every((owner) => !owner.liveWithdrawalObserved)).toBe(true);
  });

  it("derives stable commitments from identical inputs and changes them across source intent", () => {
    const first = buildCollaborationExecutionModel({
      scenario: "bounded_result",
      workloadSource: "wallet",
    });
    const same = buildCollaborationExecutionModel({
      scenario: "bounded_result",
      workloadSource: "wallet",
    });
    const credential = buildCollaborationExecutionModel({
      scenario: "bounded_result",
      workloadSource: "credential",
      walletAdoptionEnabled: true,
    });

    expect(first.commitments).toEqual(same.commitments);
    expect(first.commitments.executionBasis).toBe(credential.commitments.executionBasis);
    expect(first.commitments.computeDispatchIntent).not.toBe(
      credential.commitments.computeDispatchIntent,
    );
    expect(first.commitments.computeHandoff).not.toBe(
      credential.commitments.computeHandoff,
    );
  });

  it("cycles the deterministic happy-path lab without escaping its seven modeled stages", () => {
    expect(nextCollaborationHappyPathStep(Number.NaN)).toBe(2);
    expect(nextCollaborationHappyPathStep(1)).toBe(2);
    expect(nextCollaborationHappyPathStep(6)).toBe(7);
    expect(nextCollaborationHappyPathStep(7)).toBe(1);
    expect(nextCollaborationHappyPathStep(99)).toBe(1);
  });
});
