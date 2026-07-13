import json
import unittest

from tinker_delegate.evaluator_personas import (
    DEFAULT_PERSONAS,
    EvaluationSummary,
    Persona,
    PersonaDecision,
    evaluate_personas,
)


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


class EvaluatorPersonaTest(unittest.TestCase):
    def test_all_pass_panel_proceeds(self):
        panel = evaluate_personas(_clean_summary())
        self.assertEqual(panel.decision, PersonaDecision.PASS)
        self.assertEqual({v.persona for v in panel.verdicts}, set(DEFAULT_PERSONAS))
        self.assertFalse(panel.raw_secret_egress)

    def test_any_deny_denies_the_panel(self):
        panel = evaluate_personas(_clean_summary(dual_use_tier="prohibited"))
        self.assertEqual(panel.decision, PersonaDecision.DENY)
        bio = next(v for v in panel.verdicts if v.persona == Persona.BIOSECURITY)
        self.assertEqual(bio.decision, PersonaDecision.DENY)

    def test_any_hold_holds_the_panel(self):
        panel = evaluate_personas(_clean_summary(utility_band="low"))
        self.assertEqual(panel.decision, PersonaDecision.HOLD)

    def test_deny_beats_hold(self):
        # utility low (HOLD) + cost over budget (DENY) -> panel DENY.
        panel = evaluate_personas(_clean_summary(utility_band="low", cost_within_budget=False))
        self.assertEqual(panel.decision, PersonaDecision.DENY)

    def test_seller_protection_denies_on_unverified_leakage(self):
        panel = evaluate_personas(_clean_summary(leakage_within_bounds=None))
        seller = next(v for v in panel.verdicts if v.persona == Persona.SELLER_PROTECTION)
        self.assertEqual(seller.decision, PersonaDecision.DENY)
        self.assertEqual(seller.reason_code, "leakage_bound_unverified")

    def test_seller_protection_holds_on_offer_over_cap(self):
        panel = evaluate_personas(_clean_summary(offer_within_cap=False))
        seller = next(v for v in panel.verdicts if v.persona == Persona.SELLER_PROTECTION)
        self.assertEqual(seller.decision, PersonaDecision.HOLD)

    def test_biosecurity_holds_on_review_or_medium_reid(self):
        self.assertEqual(
            next(
                v for v in evaluate_personas(_clean_summary(dual_use_tier="review")).verdicts
                if v.persona == Persona.BIOSECURITY
            ).decision,
            PersonaDecision.HOLD,
        )
        self.assertEqual(
            next(
                v for v in evaluate_personas(_clean_summary(reidentification_risk="medium")).verdicts
                if v.persona == Persona.BIOSECURITY
            ).decision,
            PersonaDecision.HOLD,
        )

    def test_unknown_bands_fail_closed(self):
        # An unrecognized utility band denies rather than defaulting open.
        panel = evaluate_personas(_clean_summary(utility_band="stellar"))
        util = next(v for v in panel.verdicts if v.persona == Persona.BUYER_UTILITY)
        self.assertEqual(util.decision, PersonaDecision.DENY)

    def test_missing_bio_signals_fail_closed(self):
        panel = evaluate_personas(_clean_summary(dual_use_tier="", reidentification_risk=""))
        bio = next(v for v in panel.verdicts if v.persona == Persona.BIOSECURITY)
        self.assertEqual(bio.decision, PersonaDecision.DENY)

    def test_economics_denies_on_unverified_cost(self):
        # cost_within_budget=None (unknown, not just False) must DENY — an
        # unverified spend cannot pass economics by defaulting open.
        panel = evaluate_personas(_clean_summary(cost_within_budget=None))
        econ = next(v for v in panel.verdicts if v.persona == Persona.ECONOMICS)
        self.assertEqual(econ.decision, PersonaDecision.DENY)

    def test_data_quality_denies_on_missing_band(self):
        # An absent data-quality band (unknown) denies rather than defaulting open.
        panel = evaluate_personas(_clean_summary(data_quality_band=""))
        dq = next(v for v in panel.verdicts if v.persona == Persona.DATA_QUALITY)
        self.assertEqual(dq.decision, PersonaDecision.DENY)

    def test_subset_panel_only_runs_selected_personas(self):
        panel = evaluate_personas(
            _clean_summary(dual_use_tier="prohibited"),
            personas=(Persona.BUYER_UTILITY, Persona.ECONOMICS),
        )
        # Biosecurity not in the panel, so the prohibited tier does not deny.
        self.assertEqual(panel.decision, PersonaDecision.PASS)
        self.assertEqual(len(panel.verdicts), 2)

    def test_output_is_bounded_and_deterministic(self):
        s = _clean_summary()
        first = evaluate_personas(s)
        second = evaluate_personas(s)
        self.assertEqual(first.panel_hash, second.panel_hash)
        blob = json.dumps(first.to_public_dict())
        self.assertIn("panel_hash", blob)
        self.assertNotIn("raw", blob.replace("raw_secret_egress", ""))

    def test_empty_panel_rejected(self):
        with self.assertRaises(ValueError):
            evaluate_personas(_clean_summary(), personas=())


if __name__ == "__main__":
    unittest.main()
