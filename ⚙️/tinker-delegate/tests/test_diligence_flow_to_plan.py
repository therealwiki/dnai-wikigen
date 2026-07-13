import unittest

from tinker_delegate.diligence_flow import (
    DiligenceFlowError,
    distribution_plan_from_flow,
    run_diligence_flow,
)
from tinker_delegate.evaluator_personas import EvaluationSummary
from tinker_delegate.rental_stages import RentalStage, default_rental_ladder
from tinker_delegate.royalty_settlement import OwnerShare

CONTRACT = "0x" + "55" * 20
QUERY = "0x" + "c3" * 32
OWNER_A_ADDR = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
OWNER_B_ADDR = "0x90F79bf6EB2c4f870365E785982E1f101E93b906"
OWNERS = {"owner-a": OWNER_A_ADDR, "owner-b": OWNER_B_ADDR}


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
        plan = distribution_plan_from_flow(
            receipt, contract_address=CONTRACT, query_ref=QUERY, owner_addresses=OWNERS
        )
        self.assertEqual(plan.total_amount, 10**9)
        self.assertEqual(plan.recipient_count, 2)
        self.assertTrue(plan.native)
        self.assertIn("distributeNative", plan.function)
        self.assertIn(OWNER_A_ADDR.lower(), plan.cast_command.lower())
        self.assertFalse(plan.raw_secret_egress)

    def test_hold_flow_has_no_plan(self):
        receipt = _flow(_clean_summary(utility_band="low"))  # panel HOLD
        with self.assertRaises(DiligenceFlowError):
            distribution_plan_from_flow(
                receipt, contract_address=CONTRACT, query_ref=QUERY, owner_addresses=OWNERS
            )

    def test_deny_flow_has_no_plan(self):
        receipt = _flow(_clean_summary(dual_use_tier="prohibited"))  # panel DENY
        with self.assertRaises(DiligenceFlowError):
            distribution_plan_from_flow(
                receipt, contract_address=CONTRACT, query_ref=QUERY, owner_addresses=OWNERS
            )

    def test_proceed_without_royalty_has_no_plan(self):
        receipt = _flow(_clean_summary(), royalty_shares=(), royalty_total=0)
        with self.assertRaises(DiligenceFlowError):
            distribution_plan_from_flow(
                receipt, contract_address=CONTRACT, query_ref=QUERY, owner_addresses=OWNERS
            )

    def test_missing_owner_address_raises(self):
        receipt = _flow(_clean_summary())
        with self.assertRaises(DiligenceFlowError):
            distribution_plan_from_flow(
                receipt, contract_address=CONTRACT, query_ref=QUERY,
                owner_addresses={"owner-a": OWNER_A_ADDR},  # owner-b missing
            )


if __name__ == "__main__":
    unittest.main()
