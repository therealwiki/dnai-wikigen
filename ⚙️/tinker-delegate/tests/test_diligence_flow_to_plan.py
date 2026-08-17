import unittest

from tinker_delegate.diligence_flow import (
    DiligenceFlowError,
    distribution_plan_from_flow,
    run_diligence_flow,
)
from tinker_delegate.evaluator_personas import EvaluationSummary
from tinker_delegate.rental_stages import RentalStage, default_rental_ladder
from tinker_delegate.royalty_settlement import OwnerShare
from tinker_delegate.royalty_distribution_plan import (
    DistributionRecipient,
    SettlementAuthorization,
    compute_owner_amounts_hash,
)

CONTRACT = "0x" + "55" * 20
OWNER_A_ADDR = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
OWNER_B_ADDR = "0x90F79bf6EB2c4f870365E785982E1f101E93b906"
OWNERS = {"owner-a": OWNER_A_ADDR, "owner-b": OWNER_B_ADDR}
SETTLEMENT_SIGNATURE = "0x" + "aa" * 65
QVL_SIGNATURE = "0x" + "bb" * 65


def _authorization() -> SettlementAuthorization:
    recipients = [
        DistributionRecipient(OWNER_A_ADDR, 700_000_000),
        DistributionRecipient(OWNER_B_ADDR, 300_000_000),
    ]
    return SettlementAuthorization(
        settlement_id="0x" + "01" * 32,
        settlement_nonce=1,
        funding_reservation_id="0x" + "00" * 32,
        release_policy_commitment="0x" + "02" * 32,
        room_commitment="0x" + "03" * 32,
        room_state_commitment="0x" + "04" * 32,
        query_commitment="0x" + "05" * 32,
        grant_set_commitment="0x" + "06" * 32,
        allocation_commitment="0x" + "07" * 32,
        owners_amounts_hash=compute_owner_amounts_hash(recipients),
        asset_address="0x" + "00" * 20,
        total=10**9,
        execution_commitment="0x" + "08" * 32,
        result_commitment="0x" + "09" * 32,
        usage_commitment="0x" + "0a" * 32,
        attestation_evidence_hash="0x" + "0b" * 32,
        anchor_resource_hash="0x" + "0c" * 32,
        anchor_decision_hash="0x" + "0d" * 32,
        anchor_sequence=1,
        expiry=2_000_000_000,
    )


def _plan_kwargs():
    return {
        "contract_address": CONTRACT,
        "owner_addresses": OWNERS,
        "authorization": _authorization(),
        "settlement_signature": SETTLEMENT_SIGNATURE,
        "qvl_signature": QVL_SIGNATURE,
    }


def _clean_summary(**overrides) -> EvaluationSummary:
    base = dict(
        utility_band="high",
        data_quality_band="high",
        reidentification_risk="low",
        dual_use_tier="cleared",
        leakage_within_bounds=True,
        offer_within_cap=True,
        cost_within_budget=True,
    )
    base.update(overrides)
    return EvaluationSummary(**base)


def _flow(summary, **kw):
    params = dict(
        summary=summary,
        ladder=default_rental_ladder(),
        current_stage=RentalStage.RAW_INSPECTION,
        target_stage=RentalStage.TRAINING,
        consent_ok=True,
        payment_wei=10**16,
        royalty_total=10**9,
        royalty_shares=[OwnerShare("owner-a", 7000), OwnerShare("owner-b", 3000)],
    )
    params.update(kw)
    return run_diligence_flow(**params)


class DiligenceFlowToPlanTest(unittest.TestCase):
    def test_proceeding_flow_yields_executable_plan(self):
        receipt = _flow(_clean_summary())
        plan = distribution_plan_from_flow(receipt, **_plan_kwargs())
        self.assertEqual(plan.total_amount, 10**9)
        self.assertEqual(plan.recipient_count, 2)
        self.assertTrue(plan.native)
        self.assertIn("distributeNative", plan.function)
        self.assertIn(OWNER_A_ADDR.lower()[2:], plan.calldata.lower())
        self.assertFalse(plan.raw_secret_egress)

    def test_hold_flow_has_no_plan(self):
        receipt = _flow(_clean_summary(utility_band="low"))  # panel HOLD
        with self.assertRaises(DiligenceFlowError):
            distribution_plan_from_flow(
                receipt, **_plan_kwargs()
            )

    def test_deny_flow_has_no_plan(self):
        receipt = _flow(_clean_summary(dual_use_tier="prohibited"))  # panel DENY
        with self.assertRaises(DiligenceFlowError):
            distribution_plan_from_flow(
                receipt, **_plan_kwargs()
            )

    def test_proceed_without_royalty_has_no_plan(self):
        receipt = _flow(_clean_summary(), royalty_shares=(), royalty_total=0)
        with self.assertRaises(DiligenceFlowError):
            distribution_plan_from_flow(
                receipt, **_plan_kwargs()
            )

    def test_missing_owner_address_raises(self):
        receipt = _flow(_clean_summary())
        with self.assertRaises(DiligenceFlowError):
            kwargs = _plan_kwargs()
            kwargs["owner_addresses"] = {"owner-a": OWNER_A_ADDR}
            distribution_plan_from_flow(receipt, **kwargs)


if __name__ == "__main__":
    unittest.main()
