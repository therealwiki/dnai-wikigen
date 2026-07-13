import json
import unittest

from tinker_delegate.bio_validation import (
    BioBand,
    BioReadiness,
    BioReleaseDecision,
    BioResultCandidate,
    BioReviewRoute,
    BioSafetyBand,
    BioValidationError,
    evaluate_bio_release,
    screen_forbidden_output,
)


def _ready() -> BioReadiness:
    return BioReadiness(
        risk_screen_enabled=True,
        reviewer_queue_enabled=True,
        bounded_schema_enabled=True,
        synthetic_or_approved_data_only=True,
    )


def _candidate(**overrides) -> BioResultCandidate:
    base = dict(
        use_case_id="synthetic-assay-qc",
        methodology_class="sft_lora_scorer",
        score_band=BioBand.HIGH,
        confidence_band=BioBand.MEDIUM,
        utility_band=BioBand.MEDIUM,
        data_quality_flags=("balanced",),
        compute_cost_band="low",
    )
    base.update(overrides)
    return BioResultCandidate(**base)


class BioValidationTest(unittest.TestCase):
    def test_default_readiness_fails_closed_with_hold(self):
        receipt = evaluate_bio_release(_candidate(), BioReadiness())
        self.assertEqual(receipt.decision, BioReleaseDecision.HOLD)
        self.assertEqual(receipt.reason_code, "readiness_incomplete")
        self.assertEqual(receipt.review_route, BioReviewRoute.EXPERT_IN_THE_LOOP)
        self.assertEqual(
            set(receipt.readiness_missing),
            {"risk_screen", "reviewer_queue", "bounded_schema", "data_policy"},
        )
        self.assertFalse(receipt.result_schema["released"])
        # Held results withhold every band.
        self.assertEqual(receipt.result_schema["score_band"], BioBand.WITHHELD.value)
        self.assertEqual(receipt.result_schema["utility_band"], BioBand.WITHHELD.value)

    def test_partial_readiness_still_holds(self):
        readiness = BioReadiness(
            risk_screen_enabled=True,
            reviewer_queue_enabled=True,
            bounded_schema_enabled=True,
            synthetic_or_approved_data_only=False,
        )
        receipt = evaluate_bio_release(_candidate(), readiness)
        self.assertEqual(receipt.decision, BioReleaseDecision.HOLD)
        self.assertEqual(receipt.readiness_missing, ("data_policy",))

    def test_all_ready_releases_bounded_bands(self):
        receipt = evaluate_bio_release(_candidate(), _ready())
        self.assertEqual(receipt.decision, BioReleaseDecision.RELEASE)
        self.assertEqual(receipt.safety_band, BioSafetyBand.CLEARED)
        self.assertIsNone(receipt.review_route)
        self.assertTrue(receipt.result_schema["released"])
        self.assertEqual(receipt.result_schema["score_band"], BioBand.HIGH.value)
        self.assertEqual(receipt.result_schema["compute_cost_band"], "low")
        self.assertEqual(receipt.result_schema["data_quality_flags"], ["balanced"])

    def test_forbidden_output_denies_even_when_ready(self):
        candidate = _candidate(
            free_text_fields={"notes": "First perform the wetlab protocol step 3 with reagent X."}
        )
        receipt = evaluate_bio_release(candidate, _ready())
        self.assertEqual(receipt.decision, BioReleaseDecision.DENY)
        self.assertEqual(receipt.safety_band, BioSafetyBand.BLOCKED)
        self.assertEqual(receipt.review_route, BioReviewRoute.BIOSECURITY_REVIEW)
        self.assertIn("wetlab_protocol", receipt.forbidden_categories)
        self.assertFalse(receipt.result_schema["released"])

    def test_forbidden_screen_covers_pathogen_and_patient_categories(self):
        self.assertIn("pathogen_enhancement", screen_forbidden_output("gain-of-function work"))
        self.assertIn("patient_level_output", screen_forbidden_output("includes patient id and MRN"))
        self.assertIn("model_weights", screen_forbidden_output("dump the model weights"))
        self.assertEqual(screen_forbidden_output("aggregate score band only"), ())

    def test_forbidden_screen_not_evaded_by_separator_swaps(self):
        # A safety screen must not be bypassable by swapping the separator in a
        # compound dangerous term. Underscore forms are ubiquitous in
        # code-derived identifiers; `de-novo` is a common hyphenation. All must
        # be caught the same as the canonical spaced form.
        for term in ("gain_of_function", "gain.of.function", "gainoffunction"):
            self.assertIn("pathogen_enhancement", screen_forbidden_output(term), term)
        for term in ("de-novo", "de_novo", "denovo"):
            self.assertIn("de_novo_harmful_design", screen_forbidden_output(term), term)
        for term in ("wet-lab", "wet_lab", "wetlab"):
            self.assertIn("wetlab_protocol", screen_forbidden_output(term), term)
        # No false positives: benign text with these tokens out of order or
        # embedded in other words must not trip the screen.
        for benign in ("the function gain was high", "novofunction library", "model performance"):
            self.assertEqual(screen_forbidden_output(benign), (), benign)

    def test_individual_level_data_without_dp_holds(self):
        candidate = _candidate(individual_level_data=True, differential_privacy_marked=False)
        receipt = evaluate_bio_release(candidate, _ready())
        self.assertEqual(receipt.decision, BioReleaseDecision.HOLD)
        self.assertEqual(receipt.reason_code, "individual_level_data_not_dp_marked")
        self.assertEqual(receipt.review_route, BioReviewRoute.BIOSECURITY_REVIEW)

    def test_individual_level_data_with_dp_can_release(self):
        candidate = _candidate(individual_level_data=True, differential_privacy_marked=True)
        receipt = evaluate_bio_release(candidate, _ready())
        self.assertEqual(receipt.decision, BioReleaseDecision.RELEASE)

    def test_live_dp_charge_admits_release_and_records_accounting(self):
        from tinker_delegate.dp_accounting import DpAccountant, DpParams, PrivacyMode

        acct = DpAccountant(PrivacyMode.DP, max_epsilon=1.0, max_delta=1e-5)
        charge = acct.charge(DpParams(epsilon=0.4, delta=2e-6))
        # No asserted boolean; the live DP charge backs the release.
        candidate = _candidate(individual_level_data=True, differential_privacy_marked=False)
        receipt = evaluate_bio_release(candidate, _ready(), dp_charge=charge)
        self.assertEqual(receipt.decision, BioReleaseDecision.RELEASE)
        self.assertEqual(receipt.result_schema["dp_accounting"]["mode"], "differential_privacy")
        self.assertTrue(receipt.result_schema["dp_accounting"]["phi_safe"])

    def test_exhausted_dp_charge_holds_even_if_boolean_marked(self):
        from tinker_delegate.dp_accounting import DpAccountant, DpParams, PrivacyMode

        acct = DpAccountant(PrivacyMode.DP, max_epsilon=1.0, max_delta=1e-5)
        acct.charge(DpParams(epsilon=0.8))
        denied = acct.charge(DpParams(epsilon=0.5))  # over budget -> not allowed
        # A live, denied charge takes precedence over the legacy boolean.
        candidate = _candidate(individual_level_data=True, differential_privacy_marked=True)
        receipt = evaluate_bio_release(candidate, _ready(), dp_charge=denied)
        self.assertEqual(receipt.decision, BioReleaseDecision.HOLD)
        self.assertEqual(
            receipt.reason_code, "individual_level_data_dp_dp_budget_exhausted"
        )
        self.assertEqual(receipt.review_route, BioReviewRoute.BIOSECURITY_REVIEW)

    def test_non_dp_charge_holds_individual_level_release(self):
        from tinker_delegate.dp_accounting import DpAccountant, DpParams, PrivacyMode

        acct = DpAccountant(PrivacyMode.NON_DP)
        charge = acct.charge(DpParams(epsilon=1.0))  # allowed but phi_safe=False
        candidate = _candidate(individual_level_data=True, differential_privacy_marked=True)
        receipt = evaluate_bio_release(candidate, _ready(), dp_charge=charge)
        self.assertEqual(receipt.decision, BioReleaseDecision.HOLD)
        self.assertFalse(receipt.result_schema["dp_accounting"]["phi_safe"])

    def test_forbidden_content_beats_missing_readiness(self):
        candidate = _candidate(free_text_fields={"m": "design a novel toxin de novo"})
        receipt = evaluate_bio_release(candidate, BioReadiness())
        # Most-protective check wins: DENY, not the readiness HOLD.
        self.assertEqual(receipt.decision, BioReleaseDecision.DENY)

    def test_receipt_is_egress_safe_and_hashes_free_text(self):
        secret = "raw record fastq row with patient id"
        candidate = _candidate(free_text_fields={"notes": secret})
        receipt = evaluate_bio_release(candidate, _ready())
        rendered = json.dumps(receipt.to_public_dict())
        self.assertNotIn(secret, rendered)
        self.assertNotIn("fastq", rendered)
        self.assertFalse(receipt.to_public_dict()["raw_secret_egress"])
        self.assertIn("free_text_screen", receipt.result_schema)
        self.assertFalse(receipt.result_schema["free_text_screen"]["notes"]["clean"])

    def test_invalid_candidate_fails_closed(self):
        with self.assertRaises(BioValidationError):
            BioResultCandidate(use_case_id="", methodology_class="x")
        with self.assertRaises(BioValidationError):
            BioResultCandidate(use_case_id="u", methodology_class="")


if __name__ == "__main__":
    unittest.main()
