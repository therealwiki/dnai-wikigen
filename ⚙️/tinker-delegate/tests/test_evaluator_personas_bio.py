import types
import unittest

from tinker_delegate.bio_data_quality import DataQualityBand
from tinker_delegate.bio_dual_use import DualUseTier
from tinker_delegate.bio_evaluators import SyntheticAssay, evaluate_synthetic_assay_qc
from tinker_delegate.bio_reid import ReidRiskBand
from tinker_delegate.evaluator_personas import (
    Persona,
    PersonaDecision,
    evaluate_bio_personas,
    summary_from_bio_evidence,
)


def _clean_candidate():
    assay = SyntheticAssay(
        positive_controls=(100.0, 102.0, 98.0, 101.0),
        negative_controls=(10.0, 9.0, 11.0, 10.5),
        replicates=3,
    )
    return evaluate_synthetic_assay_qc(assay)


def _dq(band):
    return types.SimpleNamespace(quality_band=band)


def _reid(band):
    return types.SimpleNamespace(risk_band=band)


def _du(tier):
    return types.SimpleNamespace(tier=tier)


class BioPersonaBridgeTest(unittest.TestCase):
    def test_clean_bio_evidence_passes_all_personas(self):
        panel = evaluate_bio_personas(
            result_candidate=_clean_candidate(),
            data_quality=_dq(DataQualityBand.GOOD),
            reid=_reid(ReidRiskBand.LOW),
            dual_use=_du(DualUseTier.CLEARED),
            leakage_within_bounds=True,
            offer_within_cap=True,
            cost_within_budget=True,
        )
        self.assertEqual(panel.decision, PersonaDecision.PASS)
        self.assertFalse(panel.raw_secret_egress)

    def test_prohibited_dual_use_denies(self):
        panel = evaluate_bio_personas(
            result_candidate=_clean_candidate(),
            data_quality=_dq(DataQualityBand.GOOD),
            reid=_reid(ReidRiskBand.LOW),
            dual_use=_du(DualUseTier.PROHIBITED),
            leakage_within_bounds=True,
            offer_within_cap=True,
            cost_within_budget=True,
        )
        self.assertEqual(panel.decision, PersonaDecision.DENY)

    def test_omitted_dual_use_screen_fails_closed_even_when_all_else_clean(self):
        # Isolates the dual-use axis: EVERYTHING else is clean/present, only the
        # dual-use assessment is omitted. The production `run_bio_diligence_flow`
        # path (which maps `dual_use.tier` into the persona summary rather than
        # calling `evaluate_bio_release`) must still fail closed — an absent tier
        # is treated as DENY, so a task cannot reach settlement without a
        # dual-use screen even in the persona-panel path. Pins the load-bearing
        # empty-tier-is-DENY property against a future default-allow regression.
        summary = summary_from_bio_evidence(dual_use=None)
        self.assertEqual(summary.dual_use_tier, "")
        panel = evaluate_bio_personas(
            result_candidate=_clean_candidate(),
            data_quality=_dq(DataQualityBand.GOOD),
            reid=_reid(ReidRiskBand.LOW),
            dual_use=None,  # the ONLY missing signal
            leakage_within_bounds=True,
            offer_within_cap=True,
            cost_within_budget=True,
        )
        self.assertEqual(panel.decision, PersonaDecision.DENY)

    def test_poor_data_quality_denies(self):
        panel = evaluate_bio_personas(
            result_candidate=_clean_candidate(),
            data_quality=_dq(DataQualityBand.POOR),
            reid=_reid(ReidRiskBand.LOW),
            dual_use=_du(DualUseTier.CLEARED),
            leakage_within_bounds=True,
            offer_within_cap=True,
            cost_within_budget=True,
        )
        self.assertEqual(panel.decision, PersonaDecision.DENY)
        dq = next(v for v in panel.verdicts if v.persona == Persona.DATA_QUALITY)
        self.assertEqual(dq.decision, PersonaDecision.DENY)

    def test_fair_data_quality_and_review_tier_hold(self):
        panel = evaluate_bio_personas(
            result_candidate=_clean_candidate(),
            data_quality=_dq(DataQualityBand.FAIR),
            reid=_reid(ReidRiskBand.LOW),
            dual_use=_du(DualUseTier.REVIEW),
            leakage_within_bounds=True,
            offer_within_cap=True,
            cost_within_budget=True,
        )
        self.assertEqual(panel.decision, PersonaDecision.HOLD)

    def test_bridge_maps_bands_into_persona_vocabulary(self):
        summary = summary_from_bio_evidence(
            result_candidate=_clean_candidate(),
            data_quality=_dq(DataQualityBand.GOOD),
            reid=_reid(ReidRiskBand.HIGH),
            dual_use=_du(DualUseTier.CLEARED),
        )
        self.assertEqual(summary.data_quality_band, "medium")  # good -> medium (PASS)
        self.assertEqual(summary.reidentification_risk, "high")
        self.assertEqual(summary.dual_use_tier, "cleared")
        self.assertIn(summary.utility_band, ("exceptional", "high", "medium"))

    def test_missing_evidence_fails_closed(self):
        # No assessments supplied at all -> every lens denies.
        panel = evaluate_bio_personas()
        self.assertEqual(panel.decision, PersonaDecision.DENY)


if __name__ == "__main__":
    unittest.main()
