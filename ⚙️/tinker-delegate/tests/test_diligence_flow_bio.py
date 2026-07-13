import types
import unittest

from tinker_delegate.bio_data_quality import DataQualityBand
from tinker_delegate.bio_dual_use import DualUseTier
from tinker_delegate.bio_evaluators import SyntheticAssay, evaluate_synthetic_assay_qc
from tinker_delegate.bio_reid import ReidRiskBand
from tinker_delegate.diligence_flow import (
    FlowDecision,
    derive_leakage_signals,
    run_bio_diligence_flow,
)
from tinker_delegate.rental_stages import RentalStage, default_rental_ladder
from tinker_delegate.royalty_settlement import OwnerShare


def _clean_candidate():
    assay = SyntheticAssay(
        positive_controls=(100.0, 102.0, 98.0, 101.0),
        negative_controls=(10.0, 9.0, 11.0, 10.5),
        replicates=3,
    )
    return evaluate_synthetic_assay_qc(assay)


class BioDiligenceFlowTest(unittest.TestCase):
    def setUp(self):
        self.ladder = default_rental_ladder()
        self.shares = [OwnerShare("owner-a", 6000), OwnerShare("owner-b", 4000)]

    def _run(self, **kw):
        params = dict(
            result_candidate=_clean_candidate(),
            data_quality=types.SimpleNamespace(quality_band=DataQualityBand.GOOD),
            reid=types.SimpleNamespace(risk_band=ReidRiskBand.LOW),
            dual_use=types.SimpleNamespace(tier=DualUseTier.CLEARED),
            leakage_within_bounds=True,
            offer_within_cap=True,
            cost_within_budget=True,
            ladder=self.ladder,
            current_stage=RentalStage.RAW_INSPECTION,
            target_stage=RentalStage.TRAINING,
            consent_ok=True,
            payment_wei=10**16,
            royalty_total=10**9,
            royalty_shares=self.shares,
        )
        params.update(kw)
        return run_bio_diligence_flow(**params)

    def test_clean_bio_evaluation_proceeds_and_settles(self):
        receipt = self._run()
        self.assertEqual(receipt.flow_decision, FlowDecision.PROCEED)
        self.assertEqual(receipt.result_type, "utility_band")
        amounts = {p["owner_ref"]: p["amount"] for p in receipt.royalty_payouts}
        self.assertEqual(amounts, {"owner-a": 600_000_000, "owner-b": 400_000_000})
        self.assertFalse(receipt.raw_secret_egress)

    def test_prohibited_dual_use_denies_before_settlement(self):
        receipt = self._run(dual_use=types.SimpleNamespace(tier=DualUseTier.PROHIBITED))
        self.assertEqual(receipt.flow_decision, FlowDecision.DENY)
        self.assertIsNone(receipt.stage_transition)
        self.assertEqual(receipt.royalty_payouts, ())

    def test_poor_data_quality_denies(self):
        receipt = self._run(data_quality=types.SimpleNamespace(quality_band=DataQualityBand.POOR))
        self.assertEqual(receipt.flow_decision, FlowDecision.DENY)
        self.assertEqual(receipt.royalty_payouts, ())

    def test_no_consent_holds_before_settlement(self):
        receipt = self._run(consent_ok=False)
        self.assertEqual(receipt.flow_decision, FlowDecision.HOLD)
        self.assertEqual(receipt.panel_decision, "pass")
        self.assertEqual(receipt.royalty_payouts, ())

    def test_missing_evidence_denies(self):
        receipt = run_bio_diligence_flow(
            ladder=self.ladder,
            target_stage=RentalStage.TRAINING,
            current_stage=RentalStage.RAW_INSPECTION,
            consent_ok=True,
            payment_wei=10**16,
        )
        self.assertEqual(receipt.flow_decision, FlowDecision.DENY)

    def test_signals_derived_from_bounded_evidence_proceed(self):
        # No explicit booleans; derive from a bounded result + economic amounts.
        receipt = self._run(
            leakage_within_bounds=None,
            offer_within_cap=None,
            cost_within_budget=None,
            bounded_result={"raw_secret_egress": False},
            offer_wei=5,
            offer_cap_wei=10,
            cost_wei=3,
            budget_wei=10,
        )
        self.assertEqual(receipt.flow_decision, FlowDecision.PROCEED)

    def test_leaky_bounded_result_denies_via_seller_protection(self):
        # raw_secret_egress True -> leakage NOT within bounds -> seller lens DENY.
        receipt = self._run(
            leakage_within_bounds=None,
            offer_within_cap=None,
            cost_within_budget=None,
            bounded_result={"raw_secret_egress": True},
            offer_wei=5,
            offer_cap_wei=10,
            cost_wei=3,
            budget_wei=10,
        )
        self.assertEqual(receipt.flow_decision, FlowDecision.DENY)

    def test_over_budget_cost_denies(self):
        receipt = self._run(
            leakage_within_bounds=None,
            offer_within_cap=None,
            cost_within_budget=None,
            bounded_result={"raw_secret_egress": False},
            offer_wei=5,
            offer_cap_wei=10,
            cost_wei=20,
            budget_wei=10,
        )
        self.assertEqual(receipt.flow_decision, FlowDecision.DENY)

    def test_disclosure_public_recorded_on_settled_bio_flow(self):
        from tinker_delegate.bio_dual_use import DualUseAssessment
        from tinker_delegate.bio_reid import ReidAssessment

        # Real assessment objects carry both the .tier/.risk_band the summary
        # reads and the .denies_release/.blocks_release the disclosure gate reads.
        dual_use = DualUseAssessment(DualUseTier.CLEARED, (), "h")
        reid = ReidAssessment(ReidRiskBand.LOW, False, "ok", "h")
        receipt = self._run(
            dual_use=dual_use,
            reid=reid,
            disclosure_candidate=b"def denoise(train):\n    return train\n",
            allow_public_disclosure=True,
        )
        self.assertEqual(receipt.flow_decision, FlowDecision.PROCEED)
        self.assertEqual(receipt.disclosure["mode"], "public")

    def test_disclosure_defaults_to_escrow_without_public_permission(self):
        from tinker_delegate.bio_dual_use import DualUseAssessment
        from tinker_delegate.bio_reid import ReidAssessment

        dual_use = DualUseAssessment(DualUseTier.CLEARED, (), "h")
        reid = ReidAssessment(ReidRiskBand.LOW, False, "ok", "h")
        receipt = self._run(
            dual_use=dual_use,
            reid=reid,
            disclosure_candidate=b"def denoise(train):\n    return train\n",
        )
        self.assertEqual(receipt.flow_decision, FlowDecision.PROCEED)
        self.assertEqual(receipt.disclosure["mode"], "escrow")

    def test_reconstruction_risk_downgrades_disclosure_but_still_settles(self):
        from tinker_delegate.bio_dual_use import DualUseAssessment
        from tinker_delegate.bio_reid import ReidAssessment

        dual_use = DualUseAssessment(DualUseTier.CLEARED, (), "h")
        reid = ReidAssessment(ReidRiskBand.LOW, False, "ok", "h")
        leaky_candidate = b"KEY=tml-abcdefghij1234567890abcdefgh\ndef denoise(t):\n    return t\n"
        receipt = self._run(
            dual_use=dual_use,
            reid=reid,
            disclosure_candidate=leaky_candidate,
            allow_public_disclosure=True,
        )
        self.assertEqual(receipt.flow_decision, FlowDecision.PROCEED)
        self.assertEqual(receipt.disclosure["mode"], "hash_only")
        self.assertIn("secret_shaped_material", receipt.disclosure["reasons"])

    def test_derive_leakage_signals_helper(self):
        signals = derive_leakage_signals(
            bounded_result={"raw_secret_egress": False},
            offer_wei=1, offer_cap_wei=1, cost_wei=1, budget_wei=2,
        )
        self.assertEqual(signals, {
            "leakage_within_bounds": True,
            "offer_within_cap": True,
            "cost_within_budget": True,
        })
        # Missing evidence -> None (fail-closed downstream).
        self.assertEqual(
            derive_leakage_signals(),
            {"leakage_within_bounds": None, "offer_within_cap": None, "cost_within_budget": None},
        )


if __name__ == "__main__":
    unittest.main()
