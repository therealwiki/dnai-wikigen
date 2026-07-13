"""Tests for the leak-free 'explain why denied/held' decision explainer."""
import json
import subprocess
import sys
import unittest
from pathlib import Path

from tinker_delegate.decision_explainer import (
    DecisionCategory,
    Disposition,
    explain_decision,
)

REPO = Path(__file__).resolve().parents[1]


class ExplainDecisionTest(unittest.TestCase):
    def test_known_exact_codes(self):
        self.assertEqual(explain_decision("float_value").category, DecisionCategory.LEAKAGE)
        self.assertEqual(explain_decision("float_value").disposition, Disposition.DENIED)
        self.assertEqual(explain_decision("run_verified").disposition, Disposition.ALLOWED)
        self.assertEqual(
            explain_decision("self_approval_denied").category, DecisionCategory.GOVERNANCE
        )

    def test_prefix_codes(self):
        self.assertEqual(
            explain_decision("dual_use_prohibited:gain_of_function").category,
            DecisionCategory.BIOSECURITY,
        )
        self.assertEqual(
            explain_decision("dual_use_prohibited:x").disposition, Disposition.DENIED
        )
        self.assertEqual(explain_decision("exceeds_daily_cap").category, DecisionCategory.BUDGET)
        self.assertEqual(
            explain_decision("funding_failure_bot_check").category, DecisionCategory.FUNDING
        )

    def test_is_leak_free_never_echoes_the_input(self):
        # A reason code carrying an injected private-looking suffix must NEVER be
        # echoed into the explanation — only fixed vocabulary is emitted.
        secret = "SECRET-PATIENT-9981-DIAGNOSIS"
        exp = explain_decision(f"dual_use_prohibited:{secret}")
        blob = json.dumps(exp.to_public_dict())
        self.assertNotIn(secret, blob)
        self.assertFalse(exp.reveals_private_content)
        self.assertFalse(exp.to_public_dict()["raw_secret_egress"])

    def test_unknown_code_falls_back_safely(self):
        exp = explain_decision("some_future_code_2099")
        self.assertEqual(exp.category, DecisionCategory.UNKNOWN)
        self.assertEqual(exp.disposition, Disposition.HELD)
        # The unknown code itself is not echoed.
        self.assertNotIn("some_future_code_2099", json.dumps(exp.to_public_dict()))

    def test_empty_or_bad_input_falls_back(self):
        self.assertEqual(explain_decision("").category, DecisionCategory.UNKNOWN)
        self.assertEqual(explain_decision(None).category, DecisionCategory.UNKNOWN)  # type: ignore[arg-type]


class ExplainerCoversRealDecisionCodesTest(unittest.TestCase):
    """Feed reason codes emitted by real modules; they must be explained (not
    left as the generic UNKNOWN fallback)."""

    def test_real_bio_denial_is_explained(self):
        from tinker_delegate.bio_dual_use import DualUseFeatures, classify_dual_use
        from tinker_delegate.bio_evaluators import SyntheticAssay, evaluate_synthetic_assay_qc
        from tinker_delegate.bio_validation import BioReadiness, evaluate_bio_release

        ready = BioReadiness(
            risk_screen_enabled=True, reviewer_queue_enabled=True,
            bounded_schema_enabled=True, synthetic_or_approved_data_only=True,
        )
        candidate = evaluate_synthetic_assay_qc(
            SyntheticAssay(positive_controls=(100.0, 102.0, 98.0, 101.0),
                           negative_controls=(10.0, 9.0, 11.0, 10.5), replicates=3)
        )
        du = classify_dual_use(DualUseFeatures(involves_gain_of_function=True))
        receipt = evaluate_bio_release(candidate, ready, dual_use=du)
        exp = explain_decision(receipt.reason_code)
        self.assertEqual(exp.category, DecisionCategory.BIOSECURITY)
        self.assertEqual(exp.disposition, Disposition.DENIED)

    def test_real_spend_denial_is_explained(self):
        from tinker_delegate.spend_budget import SpendCaps, SpendLedger

        ledger = SpendLedger(SpendCaps(daily_cap_wei=100))
        auth = ledger.authorize(200, day_bucket="2026-07-12")
        exp = explain_decision(auth.reason_code)  # "exceeds_daily_cap"
        self.assertEqual(exp.category, DecisionCategory.BUDGET)
        self.assertEqual(exp.disposition, Disposition.DENIED)

    def test_real_verification_failure_is_explained(self):
        exp = explain_decision("packet_inconsistent")
        self.assertEqual(exp.category, DecisionCategory.VERIFICATION)
        self.assertEqual(exp.disposition, Disposition.DENIED)


class ExplainDecisionCliTest(unittest.TestCase):
    def test_cli_emits_bounded_explanation_and_never_echoes_suffix(self):
        proc = subprocess.run(
            [sys.executable, "-m", "tinker_delegate.main", "explain-decision",
             "dual_use_prohibited:SECRET-SUFFIX-42"],
            check=False, cwd=REPO, text=True, capture_output=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        body = json.loads(proc.stdout)
        self.assertEqual(body["category"], "biosecurity")
        self.assertEqual(body["disposition"], "denied")
        self.assertFalse(body["raw_secret_egress"])
        self.assertNotIn("SECRET-SUFFIX-42", proc.stdout)


if __name__ == "__main__":
    unittest.main()
