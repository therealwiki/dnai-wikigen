import json
import unittest

from tinker_delegate.rental_stages import (
    RentalLadder,
    RentalStage,
    RentalStageError,
    ResultType,
    StagePolicy,
    TransitionDecision,
    advance_stage,
    default_rental_ladder,
)


class RentalStagesTest(unittest.TestCase):
    def setUp(self):
        self.ladder = default_rental_ladder()

    def test_first_move_into_raw_inspection_allowed(self):
        t = advance_stage(
            self.ladder,
            current=None,
            target=RentalStage.RAW_INSPECTION,
            consent_ok=False,  # raw inspection needs no consent
            payment_wei=0,
        )
        self.assertTrue(t.allowed)
        self.assertEqual(t.result_type, ResultType.SCORE_BAND.value)
        self.assertFalse(t.raw_secret_egress)

    def test_forward_progress_with_consent_and_payment(self):
        t = advance_stage(
            self.ladder,
            current=RentalStage.RAW_INSPECTION,
            target=RentalStage.TRAINING,
            consent_ok=True,
            payment_wei=10**16,
        )
        self.assertTrue(t.allowed)
        self.assertEqual(t.result_type, ResultType.UTILITY_BAND.value)

    def test_regression_denied(self):
        t = advance_stage(
            self.ladder,
            current=RentalStage.FULL_DISCLOSURE,
            target=RentalStage.RAW_INSPECTION,
            consent_ok=True,
            payment_wei=0,
        )
        self.assertFalse(t.allowed)
        self.assertEqual(t.reason_code, "no_forward_progress")

    def test_same_stage_denied(self):
        t = advance_stage(
            self.ladder,
            current=RentalStage.TRAINING,
            target=RentalStage.TRAINING,
            consent_ok=True,
            payment_wei=10**16,
        )
        self.assertFalse(t.allowed)
        self.assertEqual(t.reason_code, "no_forward_progress")

    def test_skipping_to_higher_tier_allowed_if_requirements_met(self):
        t = advance_stage(
            self.ladder,
            current=RentalStage.RAW_INSPECTION,
            target=RentalStage.FULL_DISCLOSURE,
            consent_ok=True,
            payment_wei=10**17,
        )
        self.assertTrue(t.allowed)
        self.assertEqual(t.result_type, ResultType.ARTIFACT.value)

    def test_full_disclosure_always_requires_consent(self):
        t = advance_stage(
            self.ladder,
            current=RentalStage.INFERENCE,
            target=RentalStage.FULL_DISCLOSURE,
            consent_ok=False,
            payment_wei=10**17,
        )
        self.assertFalse(t.allowed)
        self.assertEqual(t.reason_code, "consent_required")

    def test_training_requires_consent(self):
        t = advance_stage(
            self.ladder,
            current=RentalStage.RAW_INSPECTION,
            target=RentalStage.TRAINING,
            consent_ok=False,
            payment_wei=10**16,
        )
        self.assertFalse(t.allowed)
        self.assertEqual(t.reason_code, "consent_required")

    def test_payment_below_reserve_denied(self):
        t = advance_stage(
            self.ladder,
            current=RentalStage.RAW_INSPECTION,
            target=RentalStage.TRAINING,
            consent_ok=True,
            payment_wei=10**15,  # below the 0.01 ETH reserve
        )
        self.assertFalse(t.allowed)
        self.assertEqual(t.reason_code, "payment_below_reserve")

    def test_payment_above_cap_denied(self):
        t = advance_stage(
            self.ladder,
            current=RentalStage.RAW_INSPECTION,
            target=RentalStage.TRAINING,
            consent_ok=True,
            payment_wei=10**18,  # above the 0.1 ETH cap
        )
        self.assertFalse(t.allowed)
        self.assertEqual(t.reason_code, "payment_above_cap")

    def test_target_not_in_ladder_denied(self):
        partial = RentalLadder(
            policies=(
                StagePolicy(RentalStage.RAW_INSPECTION, 0, 10**16, ResultType.SCORE_BAND, False),
            )
        )
        t = advance_stage(
            partial,
            current=RentalStage.RAW_INSPECTION,
            target=RentalStage.TRAINING,
            consent_ok=True,
            payment_wei=10**16,
        )
        self.assertFalse(t.allowed)
        self.assertEqual(t.reason_code, "target_stage_not_in_ladder")

    def test_transition_output_is_bounded(self):
        t = advance_stage(
            self.ladder,
            current=None,
            target=RentalStage.RAW_INSPECTION,
            consent_ok=False,
            payment_wei=0,
        )
        blob = json.dumps(t.to_public_dict())
        self.assertIn("rental_stage_transition", blob)
        self.assertIn("result_type", blob)

    def test_ladder_out_of_order_rejected(self):
        with self.assertRaises(RentalStageError):
            RentalLadder(
                policies=(
                    StagePolicy(RentalStage.TRAINING, 0, 10**16, ResultType.UTILITY_BAND, True),
                    StagePolicy(RentalStage.RAW_INSPECTION, 0, 10**16, ResultType.SCORE_BAND, False),
                )
            )

    def test_bad_policy_cap_below_reserve_rejected(self):
        with self.assertRaises(RentalStageError):
            StagePolicy(RentalStage.TRAINING, 10**17, 10**16, ResultType.UTILITY_BAND, True)


if __name__ == "__main__":
    unittest.main()
