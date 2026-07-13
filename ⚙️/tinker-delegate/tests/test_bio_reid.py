import json
import unittest

from tinker_delegate.bio_evaluators import SyntheticAssay, run_synthetic_assay_qc
from tinker_delegate.bio_reid import (
    CohortReport,
    ReidError,
    ReidPolicy,
    ReidRiskBand,
    assess_reidentification,
)
from tinker_delegate.bio_validation import (
    BioReadiness,
    BioReleaseDecision,
    BioSafetyBand,
)

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


class AssessmentTest(unittest.TestCase):
    def test_large_suppressed_cohort_is_low_and_non_blocking(self):
        a = assess_reidentification(
            CohortReport(n_records=5000, min_subgroup_size=50, small_cells_suppressed=True)
        )
        self.assertEqual(a.risk_band, ReidRiskBand.LOW)
        self.assertFalse(a.blocks_release)

    def test_unsuppressed_small_cell_blocks(self):
        a = assess_reidentification(
            CohortReport(n_records=200, min_subgroup_size=3, small_cells_suppressed=False)
        )
        self.assertEqual(a.risk_band, ReidRiskBand.HIGH)
        self.assertTrue(a.blocks_release)
        self.assertEqual(a.reason_code, "unsuppressed_small_cell")

    def test_elevated_cohort_is_medium_non_blocking(self):
        a = assess_reidentification(
            CohortReport(n_records=200, min_subgroup_size=15, small_cells_suppressed=True)
        )
        self.assertEqual(a.risk_band, ReidRiskBand.MEDIUM)
        self.assertFalse(a.blocks_release)

    def test_individual_level_small_subgroup_blocks(self):
        a = assess_reidentification(
            CohortReport(n_records=50, min_subgroup_size=4, aggregates_only=False)
        )
        self.assertEqual(a.risk_band, ReidRiskBand.HIGH)
        self.assertTrue(a.blocks_release)
        self.assertEqual(a.reason_code, "individual_level_small_subgroup")

    def test_k_anonymity_boundaries_are_exact(self):
        # Pin the exact k-anonymity thresholds — the privacy guarantee IS the
        # boundary, so an off-by-one (`< k` -> `<= k`, or `< 2k` -> `<= 2k`) that
        # silently over/under-blocks must be caught. Default k=11, 2k=22.
        def band_block(min_size, suppressed):
            a = assess_reidentification(
                CohortReport(
                    n_records=5000,
                    min_subgroup_size=min_size,
                    small_cells_suppressed=suppressed,
                )
            )
            return a.risk_band, a.blocks_release

        # Blocking boundary (unsuppressed): k-1 blocks, exactly k does NOT
        # (a subgroup of size >= k is k-anonymous).
        self.assertEqual(band_block(10, False), (ReidRiskBand.HIGH, True))
        self.assertEqual(band_block(11, False), (ReidRiskBand.MEDIUM, False))
        # Medium/low boundary: 2k-1 is MEDIUM, exactly 2k is LOW.
        self.assertEqual(band_block(21, True), (ReidRiskBand.MEDIUM, False))
        self.assertEqual(band_block(22, True), (ReidRiskBand.LOW, False))

    def test_custom_policy_threshold(self):
        report = CohortReport(n_records=100, min_subgroup_size=8, small_cells_suppressed=False)
        # Default k=11 -> blocks; k=5 -> clears to medium/low.
        self.assertTrue(assess_reidentification(report).blocks_release)
        self.assertFalse(
            assess_reidentification(report, ReidPolicy(min_cohort_size=5)).blocks_release
        )

    def test_invalid_reports_rejected(self):
        with self.assertRaises(ReidError):
            CohortReport(n_records=0, min_subgroup_size=1)
        with self.assertRaises(ReidError):
            CohortReport(n_records=10, min_subgroup_size=20)

    def test_assessment_is_bounded(self):
        a = assess_reidentification(CohortReport(n_records=100, min_subgroup_size=50))
        pub = a.to_public_dict()
        self.assertFalse(pub["raw_secret_egress"])
        self.assertTrue(pub["report_hash"].startswith("reid_"))
        # No raw counts should be echoed into the bounded assessment.
        self.assertNotIn("100", json.dumps(pub))


class GateIntegrationTest(unittest.TestCase):
    def test_blocking_reid_holds_even_when_ready(self):
        reid = assess_reidentification(
            CohortReport(n_records=200, min_subgroup_size=3, small_cells_suppressed=False)
        )
        receipt = run_synthetic_assay_qc(_ASSAY, _READY, reid=reid)
        self.assertEqual(receipt.decision, BioReleaseDecision.HOLD)
        self.assertEqual(receipt.safety_band, BioSafetyBand.REVIEW)
        self.assertTrue(receipt.reason_code.startswith("reidentification_risk:"))
        self.assertFalse(receipt.result_schema["released"])
        self.assertEqual(receipt.result_schema["reid_assessment"]["risk_band"], "high")

    def test_non_blocking_reid_allows_release(self):
        reid = assess_reidentification(
            CohortReport(n_records=200, min_subgroup_size=15, small_cells_suppressed=True)
        )
        receipt = run_synthetic_assay_qc(_ASSAY, _READY, reid=reid)
        self.assertEqual(receipt.decision, BioReleaseDecision.RELEASE)

    def test_absent_reid_is_backward_compatible(self):
        receipt = run_synthetic_assay_qc(_ASSAY, _READY)
        self.assertEqual(receipt.decision, BioReleaseDecision.RELEASE)


if __name__ == "__main__":
    unittest.main()
