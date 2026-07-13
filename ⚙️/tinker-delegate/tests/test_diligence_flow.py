import json
import unittest

from tinker_delegate.diligence_flow import FlowDecision, run_diligence_flow
from tinker_delegate.evaluator_personas import EvaluationSummary
from tinker_delegate.rental_stages import RentalStage, default_rental_ladder
from tinker_delegate.royalty_settlement import OwnerShare


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


class DiligenceFlowTest(unittest.TestCase):
    def setUp(self):
        self.ladder = default_rental_ladder()
        self.shares = [OwnerShare("owner-a", 7000), OwnerShare("owner-b", 3000)]

    def _flow(self, summary, **kw):
        params = dict(
            summary=summary,
            ladder=self.ladder,
            current_stage=RentalStage.RAW_INSPECTION,
            target_stage=RentalStage.TRAINING,
            consent_ok=True,
            payment_wei=10**16,
            royalty_total=10**9,
            royalty_shares=self.shares,
        )
        params.update(kw)
        return run_diligence_flow(**params)

    def test_clean_flow_proceeds_and_settles(self):
        receipt = self._flow(_clean_summary())
        self.assertEqual(receipt.flow_decision, FlowDecision.PROCEED)
        self.assertEqual(receipt.reason_code, "settled")
        self.assertEqual(receipt.result_type, "utility_band")
        amounts = {p["owner_ref"]: p["amount"] for p in receipt.royalty_payouts}
        self.assertEqual(amounts, {"owner-a": 700_000_000, "owner-b": 300_000_000})
        self.assertFalse(receipt.raw_secret_egress)

    def test_review_deny_blocks_before_disclosure_and_settlement(self):
        receipt = self._flow(_clean_summary(dual_use_tier="prohibited"))
        self.assertEqual(receipt.flow_decision, FlowDecision.DENY)
        self.assertTrue(receipt.reason_code.startswith("review_"))
        self.assertIsNone(receipt.stage_transition)  # never reached disclosure
        self.assertEqual(receipt.royalty_payouts, ())  # never settled

    def test_disclosure_blocked_holds_before_settlement(self):
        # Review passes, but the winning candidate's disclosure is BLOCKED
        # (dual-use prohibited) -> hold before any payout, decision recorded.
        from tinker_delegate.bio_dual_use import DualUseAssessment, DualUseTier

        prohibited = DualUseAssessment(DualUseTier.PROHIBITED, ("forbidden",), "h")
        receipt = self._flow(
            _clean_summary(),
            disclosure_candidate=b"def solve(x):\n    return x\n",
            disclosure_dual_use=prohibited,
            allow_public_disclosure=True,
        )
        self.assertEqual(receipt.flow_decision, FlowDecision.HOLD)
        self.assertEqual(receipt.reason_code, "disclosure_blocked")
        self.assertEqual(receipt.royalty_payouts, ())
        self.assertEqual(receipt.disclosure["mode"], "blocked")

    def test_reward_transcript_commitment_is_recorded_and_bound(self):
        commitment = {"surface": "reward_transcript_commitment", "commitment_hash": "ab" * 32}
        receipt = self._flow(_clean_summary(), reward_transcript_commitment=commitment)
        self.assertEqual(receipt.flow_decision, FlowDecision.PROCEED)
        self.assertEqual(receipt.reward_transcript_commitment, commitment)
        # It is bound into flow_hash: a different commitment changes the hash.
        other = self._flow(
            _clean_summary(),
            reward_transcript_commitment={"commitment_hash": "cd" * 32},
        )
        self.assertNotEqual(receipt.flow_hash, other.flow_hash)

    def test_clean_disclosure_records_public_and_settles(self):
        from tinker_delegate.bio_dual_use import DualUseAssessment, DualUseTier

        cleared = DualUseAssessment(DualUseTier.CLEARED, (), "h")
        receipt = self._flow(
            _clean_summary(),
            disclosure_candidate=b"def solve(x):\n    return sorted(x)\n",
            disclosure_dual_use=cleared,
            allow_public_disclosure=True,
        )
        self.assertEqual(receipt.flow_decision, FlowDecision.PROCEED)
        self.assertEqual(receipt.disclosure["mode"], "public")
        self.assertTrue(receipt.royalty_payouts)  # still settles

    def test_review_hold_blocks_before_settlement(self):
        receipt = self._flow(_clean_summary(utility_band="low"))
        self.assertEqual(receipt.flow_decision, FlowDecision.HOLD)
        self.assertIsNone(receipt.stage_transition)
        self.assertEqual(receipt.royalty_payouts, ())

    def test_disclosure_denied_blocks_settlement_even_when_review_passes(self):
        # Panel passes, but no consent for the training tier -> no settlement.
        receipt = self._flow(_clean_summary(), consent_ok=False)
        self.assertEqual(receipt.flow_decision, FlowDecision.HOLD)
        self.assertEqual(receipt.panel_decision, "pass")
        self.assertTrue(receipt.reason_code.startswith("disclosure_"))
        self.assertIsNotNone(receipt.stage_transition)
        self.assertEqual(receipt.stage_transition["decision"], "denied")
        self.assertEqual(receipt.royalty_payouts, ())  # no royalty without disclosure

    def test_underfunded_disclosure_holds(self):
        receipt = self._flow(_clean_summary(), payment_wei=10**15)  # below training reserve
        self.assertEqual(receipt.flow_decision, FlowDecision.HOLD)
        self.assertIn("payment_below_reserve", receipt.reason_code)
        self.assertEqual(receipt.royalty_payouts, ())

    def test_proceed_without_royalty_shares_has_no_payouts(self):
        receipt = self._flow(_clean_summary(), royalty_shares=(), royalty_total=0)
        self.assertEqual(receipt.flow_decision, FlowDecision.PROCEED)
        self.assertEqual(receipt.royalty_payouts, ())

    def test_full_disclosure_requires_consent_in_flow(self):
        receipt = self._flow(
            _clean_summary(),
            target_stage=RentalStage.FULL_DISCLOSURE,
            current_stage=RentalStage.INFERENCE,
            consent_ok=False,
            payment_wei=10**17,
        )
        self.assertEqual(receipt.flow_decision, FlowDecision.HOLD)
        self.assertIn("consent_required", receipt.reason_code)

    def test_receipt_is_bounded_and_deterministic(self):
        first = self._flow(_clean_summary())
        second = self._flow(_clean_summary())
        self.assertEqual(first.flow_hash, second.flow_hash)
        blob = json.dumps(first.to_public_dict())
        self.assertIn("flow_hash", blob)
        self.assertIn("diligence_flow_receipt", blob)


if __name__ == "__main__":
    unittest.main()
