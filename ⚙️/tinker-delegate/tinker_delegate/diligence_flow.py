"""One fail-closed diligence flow composing the bounded evaluation primitives.

Ties the pieces the rest of the package builds into a single ordered pipeline so
the gates cannot be skipped or reordered:

    evaluate (bounded EvaluationSummary)
      -> review    (evaluator persona panel: pass / hold / deny)
      -> disclose  (rental-stage transition: consent- and payment-gated)
      -> settle    (per-owner royalty split, only on a proceeding flow)

The composition guarantee is the point: royalty accrues *only* when the persona
panel passes AND the disclosure transition is allowed; a hold/deny at review, or
a denied stage transition, stops the flow before any disclosure or settlement.
Everything in and out is bounded — bands, decisions, hashes, amount bands — and
no raw data leaves.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Sequence

from tinker_delegate.evaluator_personas import (
    DEFAULT_PERSONAS,
    EvaluationSummary,
    Persona,
    PersonaDecision,
    evaluate_personas,
    summary_from_bio_evidence,
)
from tinker_delegate.rental_stages import (
    RentalLadder,
    RentalStage,
    StageTransition,
    advance_stage,
)
from tinker_delegate.royalty_distribution_plan import (
    DistributionRecipient,
    RoyaltyDistributionPlan,
    SettlementAuthorization,
    build_royalty_distribution_plan,
)
from tinker_delegate.disclosure_policy import DisclosureMode, decide_disclosure
from tinker_delegate.royalty_settlement import OwnerShare, split_royalty


class DiligenceFlowError(ValueError):
    """Raised when a diligence-flow post-step is applied to an invalid receipt."""


class FlowDecision(str, Enum):
    PROCEED = "proceed"
    HOLD = "hold"
    DENY = "deny"


@dataclass(frozen=True)
class DiligenceFlowReceipt:
    flow_decision: FlowDecision
    panel_decision: str
    reason_code: str
    result_type: str
    stage_transition: dict[str, Any] | None
    royalty_payouts: tuple[dict[str, Any], ...]
    panel_hash: str
    flow_hash: str
    raw_secret_egress: bool = False
    disclosure: dict[str, Any] | None = None
    reward_transcript_commitment: dict[str, Any] | None = None

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "kind": "diligence_flow_receipt",
            "flow_decision": self.flow_decision.value,
            "panel_decision": self.panel_decision,
            "reason_code": self.reason_code,
            "result_type": self.result_type,
            "stage_transition": self.stage_transition,
            "royalty_payouts": list(self.royalty_payouts),
            "disclosure": self.disclosure,
            "reward_transcript_commitment": self.reward_transcript_commitment,
            "panel_hash": self.panel_hash,
            "flow_hash": self.flow_hash,
            "raw_secret_egress": self.raw_secret_egress,
        }


def run_diligence_flow(
    *,
    summary: EvaluationSummary,
    ladder: RentalLadder,
    target_stage: RentalStage,
    current_stage: RentalStage | None = None,
    consent_ok: bool,
    payment_wei: int,
    royalty_total: int = 0,
    royalty_shares: Sequence[OwnerShare] = (),
    personas: tuple[Persona, ...] = DEFAULT_PERSONAS,
    disclosure_candidate: bytes | None = None,
    disclosure_dual_use: Any = None,
    disclosure_reid: Any = None,
    allow_public_disclosure: bool = False,
    disclosure_score_band: str = "withheld",
    reward_transcript_commitment: dict[str, Any] | None = None,
) -> DiligenceFlowReceipt:
    """Run the ordered, fail-closed diligence pipeline and return a bounded receipt.

    When ``disclosure_candidate`` (the winning solution bytes) is supplied, the
    final-solution disclosure policy runs after the disclosure/stage gate and
    before settlement: the bounded decision is recorded on the receipt, and a
    ``BLOCKED`` mode (dual-use prohibited) holds the flow before any payout.

    ``reward_transcript_commitment`` (the bounded commitment dict from a
    verifiable private-reward run, if the caller ran one) is recorded on every
    receipt, tying the settlement outcome to the run's proof-carrying transcript.
    """
    panel = evaluate_personas(summary, personas=personas)

    # Review gate: a non-PASS panel stops the flow before any disclosure/settlement.
    if panel.decision != PersonaDecision.PASS:
        flow = FlowDecision.HOLD if panel.decision == PersonaDecision.HOLD else FlowDecision.DENY
        return _receipt(
            flow_decision=flow,
            panel=panel,
            reason_code=f"review_{panel.decision.value}",
            result_type="",
            stage_transition=None,
            royalty_payouts=(),
            reward_transcript_commitment=reward_transcript_commitment,
        )

    # Disclosure gate: consent- and payment-gated stage transition.
    transition = advance_stage(
        ladder,
        current=current_stage,
        target=target_stage,
        consent_ok=consent_ok,
        payment_wei=payment_wei,
    )
    if not transition.allowed:
        return _receipt(
            flow_decision=FlowDecision.HOLD,
            panel=panel,
            reason_code=f"disclosure_{transition.reason_code}",
            result_type="",
            stage_transition=transition.to_public_dict(),
            royalty_payouts=(),
            reward_transcript_commitment=reward_transcript_commitment,
        )

    # Final-solution disclosure gate: decide how the winning candidate may be
    # released. A BLOCKED decision (dual-use prohibited) holds before settlement;
    # ESCROW/HASH_ONLY still settle but the release mode is recorded.
    disclosure_public: dict[str, Any] | None = None
    if disclosure_candidate is not None:
        decision = decide_disclosure(
            disclosure_candidate,
            dual_use=disclosure_dual_use,
            reid=disclosure_reid,
            allow_public=allow_public_disclosure,
            score_band=disclosure_score_band,
        )
        disclosure_public = decision.to_public_dict()
        if decision.mode == DisclosureMode.BLOCKED:
            return _receipt(
                flow_decision=FlowDecision.HOLD,
                panel=panel,
                reason_code="disclosure_blocked",
                result_type="",
                stage_transition=transition.to_public_dict(),
                royalty_payouts=(),
                disclosure=disclosure_public,
                reward_transcript_commitment=reward_transcript_commitment,
            )

    # Settlement: split the per-query royalty across owners (only on proceed).
    payouts: tuple[dict[str, Any], ...] = ()
    if royalty_shares:
        payouts = tuple(p.to_public_dict() for p in split_royalty(royalty_total, list(royalty_shares)))

    return _receipt(
        flow_decision=FlowDecision.PROCEED,
        panel=panel,
        reason_code="settled",
        result_type=transition.result_type,
        stage_transition=transition.to_public_dict(),
        royalty_payouts=payouts,
        disclosure=disclosure_public,
        reward_transcript_commitment=reward_transcript_commitment,
    )


def derive_leakage_signals(
    *,
    bounded_result: Any = None,
    offer_wei: int | None = None,
    offer_cap_wei: int | None = None,
    cost_wei: int | None = None,
    budget_wei: int | None = None,
) -> dict[str, bool | None]:
    """Derive the seller-protection/economics booleans from bounded evidence.

    `leakage_within_bounds` is grounded in the evaluation's own
    `raw_secret_egress == False` (a bounded reward/result object or dict), so it is
    proven by the evaluation rather than asserted. Missing evidence yields `None`,
    which the persona lenses treat as fail-closed DENY/HOLD.
    """
    egress: bool | None = None
    if bounded_result is not None:
        egress = getattr(bounded_result, "raw_secret_egress", None)
        if egress is None and isinstance(bounded_result, dict):
            egress = bounded_result.get("raw_secret_egress")

    leakage = (egress is False) if egress is not None else None
    offer = (offer_wei <= offer_cap_wei) if (offer_wei is not None and offer_cap_wei is not None) else None
    cost = (cost_wei <= budget_wei) if (cost_wei is not None and budget_wei is not None) else None
    return {
        "leakage_within_bounds": leakage,
        "offer_within_cap": offer,
        "cost_within_budget": cost,
    }


def run_bio_diligence_flow(
    *,
    result_candidate: Any = None,
    data_quality: Any = None,
    reid: Any = None,
    dual_use: Any = None,
    leakage_within_bounds: bool | None = None,
    offer_within_cap: bool | None = None,
    cost_within_budget: bool | None = None,
    bounded_result: Any = None,
    offer_wei: int | None = None,
    offer_cap_wei: int | None = None,
    cost_wei: int | None = None,
    budget_wei: int | None = None,
    ladder: RentalLadder,
    target_stage: RentalStage,
    current_stage: RentalStage | None = None,
    consent_ok: bool,
    payment_wei: int,
    royalty_total: int = 0,
    royalty_shares: Sequence[OwnerShare] = (),
    personas: tuple[Persona, ...] = DEFAULT_PERSONAS,
    disclosure_candidate: bytes | None = None,
    allow_public_disclosure: bool = False,
    disclosure_score_band: str = "withheld",
    reward_transcript_commitment: dict[str, Any] | None = None,
) -> DiligenceFlowReceipt:
    """Drive the diligence flow directly from bounded bio evaluation evidence.

    Bridges the bio assessments into an `EvaluationSummary` (unknown/absent bands
    fail closed) and runs the same ordered, fail-closed pipeline, so a real
    synthetic-assay evaluation flows end-to-end into review -> disclosure ->
    settlement without exposing raw data. When the explicit
    leakage/offer/budget booleans are not given, they are derived from
    `bounded_result` + the offer/cost/budget amounts via `derive_leakage_signals`,
    so the seller-protection/economics lenses rest on evaluation evidence rather
    than caller assertions.
    """
    derived = derive_leakage_signals(
        bounded_result=bounded_result,
        offer_wei=offer_wei,
        offer_cap_wei=offer_cap_wei,
        cost_wei=cost_wei,
        budget_wei=budget_wei,
    )
    summary = summary_from_bio_evidence(
        result_candidate=result_candidate,
        data_quality=data_quality,
        reid=reid,
        dual_use=dual_use,
        leakage_within_bounds=(
            leakage_within_bounds if leakage_within_bounds is not None else derived["leakage_within_bounds"]
        ),
        offer_within_cap=(
            offer_within_cap if offer_within_cap is not None else derived["offer_within_cap"]
        ),
        cost_within_budget=(
            cost_within_budget if cost_within_budget is not None else derived["cost_within_budget"]
        ),
    )
    return run_diligence_flow(
        summary=summary,
        ladder=ladder,
        target_stage=target_stage,
        current_stage=current_stage,
        consent_ok=consent_ok,
        payment_wei=payment_wei,
        royalty_total=royalty_total,
        royalty_shares=royalty_shares,
        personas=personas,
        disclosure_candidate=disclosure_candidate,
        disclosure_dual_use=dual_use,
        disclosure_reid=reid,
        allow_public_disclosure=allow_public_disclosure,
        disclosure_score_band=disclosure_score_band,
        reward_transcript_commitment=reward_transcript_commitment,
    )


def distribution_plan_from_flow(
    receipt: DiligenceFlowReceipt,
    *,
    contract_address: str,
    owner_addresses: dict[str, str],
    authorization: SettlementAuthorization,
    settlement_signature: str,
    qvl_signature: str,
    keystore_account: str = "dev",
) -> RoyaltyDistributionPlan:
    """Build the executable on-chain royalty plan from a *settled* flow receipt.

    A local flow receipt is never sufficient settlement authority. A plan is
    produced only for a PROCEED flow whose resolved payouts exactly match an
    independently supplied release-CVM/QVL signed, anchor-bound authorization.
    """
    if receipt.flow_decision != FlowDecision.PROCEED:
        raise DiligenceFlowError("distribution plan requires a proceeding flow")
    if not receipt.royalty_payouts:
        raise DiligenceFlowError("flow receipt has no royalty payouts to distribute")

    recipients: list[DistributionRecipient] = []
    for payout in receipt.royalty_payouts:
        owner_ref = payout["owner_ref"]
        address = owner_addresses.get(owner_ref)
        if not address:
            raise DiligenceFlowError(f"no address mapped for owner ref: {owner_ref}")
        recipients.append(DistributionRecipient(address, int(payout["amount"])))

    return build_royalty_distribution_plan(
        contract_address=contract_address,
        authorization=authorization,
        recipients=recipients,
        settlement_signature=settlement_signature,
        qvl_signature=qvl_signature,
        keystore_account=keystore_account,
    )


def _receipt(
    *,
    flow_decision: FlowDecision,
    panel: Any,
    reason_code: str,
    result_type: str,
    stage_transition: dict[str, Any] | None,
    royalty_payouts: tuple[dict[str, Any], ...],
    disclosure: dict[str, Any] | None = None,
    reward_transcript_commitment: dict[str, Any] | None = None,
) -> DiligenceFlowReceipt:
    flow_hash = _sha256_json(
        {
            "flow_decision": flow_decision.value,
            "panel_hash": panel.panel_hash,
            "reason_code": reason_code,
            "result_type": result_type,
            "stage_transition": stage_transition,
            "royalty_payouts": royalty_payouts,
            "disclosure": disclosure,
            "reward_transcript_commitment": reward_transcript_commitment,
        }
    )
    return DiligenceFlowReceipt(
        flow_decision=flow_decision,
        panel_decision=panel.decision.value,
        reason_code=reason_code,
        result_type=result_type,
        stage_transition=stage_transition,
        royalty_payouts=royalty_payouts,
        panel_hash=panel.panel_hash,
        flow_hash=flow_hash,
        disclosure=disclosure,
        reward_transcript_commitment=reward_transcript_commitment,
    )


def _sha256_json(value: Any) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return "0x" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
