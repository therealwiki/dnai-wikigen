import json
import unittest

from tinker_delegate.bio_evaluators import (
    METHODOLOGY_CLASS,
    USE_CASE_ID,
    SyntheticAssay,
    demo_synthetic_assay_qc,
    evaluate_synthetic_assay_qc,
    run_synthetic_assay_qc,
    z_prime_factor,
)
from tinker_delegate.bio_validation import (
    BioBand,
    BioReadiness,
    BioReleaseDecision,
    BioSafetyBand,
    BioValidationError,
)

_READY = BioReadiness(
    risk_screen_enabled=True,
    reviewer_queue_enabled=True,
    bounded_schema_enabled=True,
    synthetic_or_approved_data_only=True,
)

_CLEAN = SyntheticAssay(
    positive_controls=(100.0, 102.0, 98.0, 101.0),
    negative_controls=(10.0, 9.0, 11.0, 10.5),
    replicates=3,
)


class ZPrimeTest(unittest.TestCase):
    def test_excellent_assay_scores_high(self):
        z = z_prime_factor([100, 102, 98, 101], [10, 9, 11, 10.5])
        self.assertGreaterEqual(z, 0.5)
        self.assertEqual(evaluate_synthetic_assay_qc(_CLEAN).score_band, BioBand.HIGH)

    def test_overlapping_controls_score_low(self):
        assay = SyntheticAssay(
            positive_controls=(12, 11, 13, 10),
            negative_controls=(10, 9, 11, 12),
            replicates=1,
        )
        c = evaluate_synthetic_assay_qc(assay)
        self.assertEqual(c.score_band, BioBand.LOW)
        self.assertIn("control_overlap", c.data_quality_flags)
        self.assertIn("low_replicates", c.data_quality_flags)

    def test_zero_signal_window_is_negative_infinity(self):
        z = z_prime_factor([5, 5, 5], [5, 5, 5])
        self.assertEqual(z, float("-inf"))

    def test_empty_controls_raise_bio_error_not_statistics_error(self):
        # Public function fails with the module's error, not a raw StatisticsError.
        with self.assertRaises(BioValidationError):
            z_prime_factor([], [1.0, 2.0])
        with self.assertRaises(BioValidationError):
            z_prime_factor([1.0, 2.0], [])

    def test_confidence_band_tracks_replicates(self):
        for reps, band in ((3, BioBand.HIGH), (2, BioBand.MEDIUM), (1, BioBand.LOW)):
            assay = SyntheticAssay(
                positive_controls=(100, 102, 98, 101),
                negative_controls=(10, 9, 11, 10.5),
                replicates=reps,
            )
            self.assertEqual(evaluate_synthetic_assay_qc(assay).confidence_band, band)


class EvaluatorValidationTest(unittest.TestCase):
    def test_requires_two_controls_each(self):
        with self.assertRaises(BioValidationError):
            SyntheticAssay(positive_controls=(1.0,), negative_controls=(0.0, 0.1))

    def test_rejects_non_finite(self):
        with self.assertRaises(BioValidationError):
            SyntheticAssay(positive_controls=(1.0, float("inf")), negative_controls=(0.0, 0.1))

    def test_candidate_uses_expected_labels(self):
        c = evaluate_synthetic_assay_qc(_CLEAN)
        self.assertEqual(c.use_case_id, USE_CASE_ID)
        self.assertEqual(c.methodology_class, METHODOLOGY_CLASS)
        self.assertFalse(c.individual_level_data)


class GateIntegrationTest(unittest.TestCase):
    def test_default_readiness_holds_fail_closed(self):
        receipt = run_synthetic_assay_qc(_CLEAN)
        self.assertEqual(receipt.decision, BioReleaseDecision.HOLD)
        self.assertFalse(receipt.result_schema["released"])
        # Bands are withheld until released.
        self.assertEqual(receipt.result_schema["score_band"], BioBand.WITHHELD.value)
        self.assertFalse(receipt.to_public_dict()["raw_secret_egress"])

    def test_full_readiness_releases_bounded_bands(self):
        receipt = run_synthetic_assay_qc(_CLEAN, _READY)
        self.assertEqual(receipt.decision, BioReleaseDecision.RELEASE)
        self.assertEqual(receipt.safety_band, BioSafetyBand.CLEARED)
        self.assertEqual(receipt.result_schema["score_band"], BioBand.HIGH.value)

    def test_forbidden_free_text_denies_even_when_ready(self):
        assay = SyntheticAssay(
            positive_controls=(100, 102, 98, 101),
            negative_controls=(10, 9, 11, 10.5),
            replicates=3,
            free_text_fields={"notes": "wetlab protocol step: add reagent, run pcr cycle"},
        )
        receipt = run_synthetic_assay_qc(assay, _READY)
        self.assertEqual(receipt.decision, BioReleaseDecision.DENY)
        self.assertEqual(receipt.safety_band, BioSafetyBand.BLOCKED)
        self.assertIn("wetlab_protocol", receipt.forbidden_categories)

    def test_free_text_is_never_echoed(self):
        secret = "wetlab protocol step add reagent MARKER12345"
        assay = SyntheticAssay(
            positive_controls=(100, 102, 98, 101),
            negative_controls=(10, 9, 11, 10.5),
            replicates=3,
            free_text_fields={"notes": secret},
        )
        blob = json.dumps(run_synthetic_assay_qc(assay, _READY).to_public_dict())
        self.assertNotIn("MARKER12345", blob)
        self.assertNotIn("reagent", blob)


class DeterminismTest(unittest.TestCase):
    def test_same_input_same_receipt_hash(self):
        a = run_synthetic_assay_qc(_CLEAN, _READY)
        b = run_synthetic_assay_qc(_CLEAN, _READY)
        self.assertEqual(a.result_hash, b.result_hash)
        self.assertEqual(a.to_public_dict(), b.to_public_dict())

    def test_demo_is_bounded_and_holds_by_default(self):
        demo = demo_synthetic_assay_qc()
        self.assertFalse(demo["raw_secret_egress"])
        self.assertEqual(demo["receipt"]["decision"], BioReleaseDecision.HOLD.value)


if __name__ == "__main__":
    unittest.main()
