import json
import unittest

from tinker_delegate.bio_methodology import (
    MagnitudeBand,
    MethodFamily,
    MethodologyError,
    MethodologyProfile,
    summarize_methodology,
)

_PROFILE = MethodologyProfile(
    method_family=MethodFamily.QC_SCORING,
    model_class="zprime_qc",
    evaluation_protocol="hidden_holdout",
    preprocessing=("log_normalize", "train_test_split"),
    sample_size_band=MagnitudeBand.MEDIUM,
    feature_count_band=MagnitudeBand.LARGE,
    hyperparameter_bands={"regularization": MagnitudeBand.SMALL},
)


class VocabularyTest(unittest.TestCase):
    def test_out_of_vocab_model_rejected(self):
        with self.assertRaises(MethodologyError):
            MethodologyProfile(
                method_family=MethodFamily.QC_SCORING,
                model_class="secret_model",
                evaluation_protocol="holdout",
            )

    def test_out_of_vocab_protocol_rejected(self):
        with self.assertRaises(MethodologyError):
            MethodologyProfile(
                method_family=MethodFamily.QC_SCORING,
                model_class="zprime_qc",
                evaluation_protocol="exfiltrate",
            )

    def test_out_of_vocab_preprocessing_rejected(self):
        with self.assertRaises(MethodologyError):
            MethodologyProfile(
                method_family=MethodFamily.DENOISING,
                model_class="denoiser_pooling",
                evaluation_protocol="holdout",
                preprocessing=("raw_dump",),
            )

    def test_out_of_vocab_hyperparameter_rejected(self):
        with self.assertRaises(MethodologyError):
            MethodologyProfile(
                method_family=MethodFamily.QC_SCORING,
                model_class="zprime_qc",
                evaluation_protocol="holdout",
                hyperparameter_bands={"secret_knob": MagnitudeBand.SMALL},
            )


class SummaryTest(unittest.TestCase):
    def test_summary_is_bounded_and_reconstruction_safe(self):
        s = summarize_methodology(_PROFILE)
        self.assertTrue(s["reconstruction_safe"])
        self.assertFalse(s["raw_secret_egress"])
        self.assertTrue(s["summary_clean"])
        self.assertTrue(s["methodology_hash"].startswith("methodology_"))
        # The summary is built only from controlled tokens.
        self.assertIn("zprime_qc", s["summary_text"])
        self.assertIn("hidden_holdout", s["summary_text"])

    def test_summary_contains_no_raw_values(self):
        # Only coarse bands appear — no exact numbers from the caller.
        s = summarize_methodology(_PROFILE)
        blob = json.dumps(s)
        for exact in ("0.5", "1000", "42"):
            self.assertNotIn(exact, blob)

    def test_notes_are_screened_and_hashed_not_echoed(self):
        profile = MethodologyProfile(
            method_family=MethodFamily.DENOISING,
            model_class="denoiser_pooling",
            evaluation_protocol="holdout",
            notes="wetlab protocol reagent MARKER77",
        )
        s = summarize_methodology(profile)
        blob = json.dumps(s)
        self.assertFalse(s["notes_clean"])
        self.assertTrue(s["notes_hash"])
        self.assertNotIn("MARKER77", blob)
        self.assertNotIn("reagent", blob)

    def test_deterministic(self):
        self.assertEqual(summarize_methodology(_PROFILE), summarize_methodology(_PROFILE))


if __name__ == "__main__":
    unittest.main()
