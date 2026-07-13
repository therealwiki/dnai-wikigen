import json
import unittest

from tinker_delegate.bio_data_quality import (
    DataQualityBand,
    DataQualityError,
    DataQualityPolicy,
    DatasetProfile,
    assess_data_quality,
)
from tinker_delegate.bio_evaluators import SyntheticAssay, run_synthetic_assay_qc
from tinker_delegate.bio_validation import BioReadiness, BioReleaseDecision, BioSafetyBand

_READY = BioReadiness(
    risk_screen_enabled=True,
    reviewer_queue_enabled=True,
    bounded_schema_enabled=True,
    synthetic_or_approved_data_only=True,
)
_ASSAY = SyntheticAssay(
    positive_controls=(100.0, 102.0, 98.0, 101.0),
    negative_controls=(10.0, 9.0, 11.0, 10.5),
    replicates=3,
)


class AssessTest(unittest.TestCase):
    def test_clean_dataset_is_good_non_blocking(self):
        r = assess_data_quality(
            DatasetProfile(n_samples=500, n_features=20, class_counts={"a": 250, "b": 250})
        )
        self.assertEqual(r.quality_band, DataQualityBand.GOOD)
        self.assertFalse(r.blocks_release)
        self.assertEqual(r.flags, ())

    def test_train_test_contamination_blocks(self):
        r = assess_data_quality(DatasetProfile(n_samples=500, n_features=20, train_test_overlap=5))
        self.assertTrue(r.blocks_release)
        self.assertIn("train_test_contamination", r.flags)
        self.assertEqual(r.quality_band, DataQualityBand.POOR)

    def test_insufficient_samples_blocks(self):
        r = assess_data_quality(DatasetProfile(n_samples=10, n_features=20))
        self.assertTrue(r.blocks_release)
        self.assertIn("insufficient_samples", r.flags)

    def test_schema_mismatch_blocks(self):
        r = assess_data_quality(
            DatasetProfile(n_samples=500, n_features=19, expected_features=20)
        )
        self.assertTrue(r.blocks_release)
        self.assertIn("schema_mismatch", r.flags)

    def test_non_blocking_degradations_lower_band_only(self):
        r = assess_data_quality(
            DatasetProfile(
                n_samples=500,
                n_features=20,
                n_duplicate_rows=100,
                class_counts={"a": 480, "b": 20},
            )
        )
        self.assertFalse(r.blocks_release)
        self.assertIn("class_imbalance", r.flags)
        self.assertIn("excessive_duplicates", r.flags)
        self.assertEqual(r.quality_band, DataQualityBand.POOR)  # two non-blocking flags

    def test_single_non_blocking_flag_is_fair(self):
        r = assess_data_quality(
            DatasetProfile(n_samples=500, n_features=20, n_duplicate_rows=100)
        )
        self.assertEqual(r.quality_band, DataQualityBand.FAIR)
        self.assertFalse(r.blocks_release)

    def test_custom_policy_changes_verdict(self):
        profile = DatasetProfile(n_samples=20, n_features=10)
        self.assertTrue(assess_data_quality(profile).blocks_release)  # default min 30
        self.assertFalse(assess_data_quality(profile, DataQualityPolicy(min_samples=10)).blocks_release)

    def test_invalid_profiles_rejected(self):
        with self.assertRaises(DataQualityError):
            DatasetProfile(n_samples=0, n_features=5)
        with self.assertRaises(DataQualityError):
            DatasetProfile(n_samples=5, n_features=2, n_missing_cells=100)
        with self.assertRaises(DataQualityError):
            DatasetProfile(n_samples=5, n_features=2, n_duplicate_rows=5)

    def test_report_is_bounded(self):
        r = assess_data_quality(DatasetProfile(n_samples=500, n_features=20))
        pub = r.to_public_dict()
        self.assertFalse(pub["raw_secret_egress"])
        self.assertTrue(pub["profile_hash"].startswith("dq_"))
        self.assertNotIn("500", json.dumps(pub))


class GateIntegrationTest(unittest.TestCase):
    def test_blocking_data_quality_holds_even_when_ready(self):
        dq = assess_data_quality(DatasetProfile(n_samples=500, n_features=20, train_test_overlap=5))
        receipt = run_synthetic_assay_qc(_ASSAY, _READY, data_quality=dq)
        self.assertEqual(receipt.decision, BioReleaseDecision.HOLD)
        self.assertEqual(receipt.safety_band, BioSafetyBand.REVIEW)
        self.assertTrue(receipt.reason_code.startswith("data_quality_invalid:"))
        self.assertEqual(receipt.result_schema["data_quality"]["quality_band"], "poor")

    def test_non_blocking_data_quality_allows_release(self):
        dq = assess_data_quality(DatasetProfile(n_samples=500, n_features=20, n_duplicate_rows=100))
        receipt = run_synthetic_assay_qc(_ASSAY, _READY, data_quality=dq)
        self.assertEqual(receipt.decision, BioReleaseDecision.RELEASE)

    def test_poor_but_non_blocking_quality_still_releases_via_safety_gate(self):
        # Design contract (safety gate != quality gate): a POOR band from
        # DEGRADATION flags only (excessive duplicates + class imbalance) is NOT
        # `blocks_release` — the result is low-quality but not *misleading*, so
        # `evaluate_bio_release` (the SAFETY gate) releases it with the POOR band
        # attached rather than holding for biosecurity review. Buyer-value quality
        # judgment is a separate concern handled by the persona `data_quality`
        # lens (which maps POOR -> DENY). Only invalidating flags (contamination,
        # insufficient samples, schema mismatch) hold here. This pins the intended
        # separation so a future change can't silently conflate quality with safety.
        dq = assess_data_quality(
            DatasetProfile(
                n_samples=500, n_features=20, n_duplicate_rows=100,
                class_counts={"a": 480, "b": 20},
            )
        )
        self.assertEqual(dq.quality_band, DataQualityBand.POOR)
        self.assertFalse(dq.blocks_release)
        receipt = run_synthetic_assay_qc(_ASSAY, _READY, data_quality=dq)
        self.assertEqual(receipt.decision, BioReleaseDecision.RELEASE)

    def test_absent_data_quality_is_backward_compatible(self):
        self.assertEqual(run_synthetic_assay_qc(_ASSAY, _READY).decision, BioReleaseDecision.RELEASE)


if __name__ == "__main__":
    unittest.main()
