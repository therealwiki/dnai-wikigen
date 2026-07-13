import json
import unittest

from tinker_delegate.bio_dual_use import (
    DualUseFeatures,
    DualUseTier,
    classify_dual_use,
)
from tinker_delegate.bio_evaluators import (
    SyntheticAssay,
    evaluate_synthetic_assay_qc,
    run_synthetic_assay_qc,
)
from tinker_delegate.bio_validation import (
    BioReadiness,
    BioReleaseDecision,
    BioReviewRoute,
    BioSafetyBand,
    evaluate_bio_release,
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


class ClassifyTest(unittest.TestCase):
    def test_benign_synthetic_is_cleared(self):
        a = classify_dual_use(DualUseFeatures())
        self.assertEqual(a.tier, DualUseTier.CLEARED)
        self.assertFalse(a.blocks_release)
        self.assertFalse(a.denies_release)

    def test_gain_of_function_is_prohibited(self):
        a = classify_dual_use(DualUseFeatures(involves_gain_of_function=True))
        self.assertEqual(a.tier, DualUseTier.PROHIBITED)
        self.assertTrue(a.denies_release)
        self.assertIn("gain_of_function", a.reasons)

    def test_de_novo_design_is_prohibited(self):
        a = classify_dual_use(DualUseFeatures(de_novo_agent_design=True))
        self.assertEqual(a.tier, DualUseTier.PROHIBITED)

    def test_actionable_output_in_dangerous_context_is_prohibited(self):
        for feats in (
            DualUseFeatures(involves_pathogen=True, produces_sequences=True),
            DualUseFeatures(involves_toxin=True, produces_wetlab_protocol=True),
        ):
            a = classify_dual_use(feats)
            self.assertEqual(a.tier, DualUseTier.PROHIBITED)
            self.assertIn("actionable_output_in_dangerous_context", a.reasons)

    def test_pathogen_context_alone_is_review(self):
        a = classify_dual_use(DualUseFeatures(involves_pathogen=True))
        self.assertEqual(a.tier, DualUseTier.REVIEW)
        self.assertTrue(a.blocks_release)
        self.assertFalse(a.denies_release)

    def test_human_subjects_without_irb_is_review(self):
        a = classify_dual_use(DualUseFeatures(involves_human_subjects=True))
        self.assertEqual(a.tier, DualUseTier.REVIEW)
        self.assertIn("human_subjects_without_irb", a.reasons)

    def test_human_subjects_with_irb_clears(self):
        a = classify_dual_use(
            DualUseFeatures(involves_human_subjects=True, human_subjects_irb_approved=True)
        )
        self.assertEqual(a.tier, DualUseTier.CLEARED)

    def test_non_synthetic_data_is_review(self):
        a = classify_dual_use(DualUseFeatures(synthetic_or_public_data_only=False))
        self.assertEqual(a.tier, DualUseTier.REVIEW)
        self.assertIn("non_synthetic_data", a.reasons)

    def test_assessment_is_bounded(self):
        a = classify_dual_use(DualUseFeatures(involves_pathogen=True))
        pub = a.to_public_dict()
        self.assertFalse(pub["raw_secret_egress"])
        self.assertTrue(pub["features_hash"].startswith("dualuse_"))


class GateIntegrationTest(unittest.TestCase):
    def test_prohibited_denies_even_when_ready(self):
        du = classify_dual_use(DualUseFeatures(involves_gain_of_function=True))
        receipt = run_synthetic_assay_qc(_ASSAY, _READY, dual_use=du)
        self.assertEqual(receipt.decision, BioReleaseDecision.DENY)
        self.assertEqual(receipt.safety_band, BioSafetyBand.BLOCKED)
        self.assertTrue(receipt.reason_code.startswith("dual_use_prohibited:"))
        self.assertEqual(receipt.result_schema["dual_use"]["tier"], "prohibited")

    def test_receipt_is_self_explaining_without_suffix_leak(self):
        # A denied bio receipt carries a bounded, leak-free policy explanation of
        # its reason code; the ":suffix" (e.g. the specific dual-use reason) is not
        # echoed into the explanation.
        du = classify_dual_use(DualUseFeatures(involves_gain_of_function=True))
        pub = run_synthetic_assay_qc(_ASSAY, _READY, dual_use=du).to_public_dict()
        self.assertIn("explanation", pub)
        self.assertEqual(pub["explanation"]["category"], "biosecurity")
        self.assertEqual(pub["explanation"]["disposition"], "denied")
        self.assertNotIn("gain_of_function", json.dumps(pub["explanation"]))
        self.assertFalse(pub["explanation"]["reveals_private_content"])

    def test_review_holds_even_when_ready(self):
        du = classify_dual_use(DualUseFeatures(involves_pathogen=True))
        receipt = run_synthetic_assay_qc(_ASSAY, _READY, dual_use=du)
        self.assertEqual(receipt.decision, BioReleaseDecision.HOLD)
        self.assertEqual(receipt.safety_band, BioSafetyBand.REVIEW)

    def test_cleared_allows_release(self):
        du = classify_dual_use(DualUseFeatures())
        self.assertEqual(
            run_synthetic_assay_qc(_ASSAY, _READY, dual_use=du).decision,
            BioReleaseDecision.RELEASE,
        )

    def test_absent_dual_use_is_backward_compatible(self):
        self.assertEqual(
            run_synthetic_assay_qc(_ASSAY, _READY).decision, BioReleaseDecision.RELEASE
        )


class RequireDualUseScreenTest(unittest.TestCase):
    def _candidate(self):
        return evaluate_synthetic_assay_qc(_ASSAY)

    def test_missing_required_screen_fails_closed_to_hold(self):
        # A dual-use-domain caller requires the structured screen but supplies
        # none: the gate must HOLD, not silently RELEASE — a structurally
        # dangerous task (e.g. gain-of-function) whose text fields look benign
        # cannot bypass the structured axis by omission.
        receipt = evaluate_bio_release(
            self._candidate(), _READY, require_dual_use_screen=True
        )
        self.assertEqual(receipt.decision, BioReleaseDecision.HOLD)
        self.assertEqual(receipt.reason_code, "dual_use_screen_required")
        self.assertEqual(receipt.review_route, BioReviewRoute.BIOSECURITY_REVIEW)
        self.assertEqual(receipt.safety_band, BioSafetyBand.REVIEW)

    def test_supplied_cleared_screen_allows_release_when_required(self):
        du = classify_dual_use(DualUseFeatures())
        receipt = evaluate_bio_release(
            self._candidate(), _READY, dual_use=du, require_dual_use_screen=True
        )
        self.assertEqual(receipt.decision, BioReleaseDecision.RELEASE)

    def test_required_screen_does_not_override_prohibited_dual_use(self):
        # When a screen IS supplied and prohibits, deny still wins (require flag
        # doesn't downgrade a PROHIBITED result to a mere HOLD).
        du = classify_dual_use(DualUseFeatures(involves_gain_of_function=True))
        receipt = evaluate_bio_release(
            self._candidate(), _READY, dual_use=du, require_dual_use_screen=True
        )
        self.assertEqual(receipt.decision, BioReleaseDecision.DENY)

    def test_default_false_stays_backward_compatible(self):
        receipt = evaluate_bio_release(self._candidate(), _READY)
        self.assertEqual(receipt.decision, BioReleaseDecision.RELEASE)


if __name__ == "__main__":
    unittest.main()
