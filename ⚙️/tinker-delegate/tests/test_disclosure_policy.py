import json
import unittest

from tinker_delegate.bio_dual_use import DualUseAssessment, DualUseTier
from tinker_delegate.bio_reid import ReidAssessment, ReidRiskBand
from tinker_delegate.disclosure_policy import (
    DisclosureMode,
    decide_disclosure,
)
from tinker_delegate.private_reward import assert_bounded_egress


def _cleared() -> DualUseAssessment:
    return DualUseAssessment(DualUseTier.CLEARED, (), "dualuse_cleared")


def _review() -> DualUseAssessment:
    return DualUseAssessment(DualUseTier.REVIEW, ("needs_review",), "dualuse_review")


def _prohibited() -> DualUseAssessment:
    return DualUseAssessment(DualUseTier.PROHIBITED, ("forbidden",), "dualuse_prohibited")


def _reid(band: ReidRiskBand) -> ReidAssessment:
    return ReidAssessment(band, band == ReidRiskBand.HIGH, "reason", "reidhash")


_CLEAN_CODE = b"def process(xs):\n    return sorted(xs)[1:-1]\n"


class DisclosurePolicyTest(unittest.TestCase):
    def test_clean_code_with_permission_is_public(self):
        decision = decide_disclosure(
            _CLEAN_CODE, dual_use=_cleared(), allow_public=True, score_band="high"
        )
        self.assertEqual(decision.mode, DisclosureMode.PUBLIC)
        self.assertTrue(decision.is_public)
        self.assertEqual(decision.disclosable_payload(_CLEAN_CODE), _CLEAN_CODE)

    def test_default_without_permission_is_escrow(self):
        decision = decide_disclosure(_CLEAN_CODE, dual_use=_cleared())
        self.assertEqual(decision.mode, DisclosureMode.ESCROW)
        self.assertIn("no_public_permission", decision.reasons)
        self.assertIsNone(decision.disclosable_payload(_CLEAN_CODE))

    def test_secret_shaped_material_downgrades_to_hash_only(self):
        leaky = b"TINKER_API_KEY=" + b"tml-" + b"abcdefghij1234567890abcdefgh\n"
        decision = decide_disclosure(leaky, dual_use=_cleared(), allow_public=True)
        self.assertEqual(decision.mode, DisclosureMode.HASH_ONLY)
        self.assertIn("secret_shaped_material", decision.reasons)
        self.assertIsNone(decision.disclosable_payload(leaky))

    def test_embedded_raw_data_blob_downgrades_to_hash_only(self):
        embedded = b"blob = '" + b"A" * 128 + b"'\n"
        decision = decide_disclosure(embedded, dual_use=_cleared(), allow_public=True)
        self.assertEqual(decision.mode, DisclosureMode.HASH_ONLY)
        self.assertIn("embedded_raw_data", decision.reasons)

    def test_non_text_candidate_is_never_public(self):
        decision = decide_disclosure(b"\xff\xfe\x00\x01", dual_use=_cleared(), allow_public=True)
        self.assertEqual(decision.mode, DisclosureMode.HASH_ONLY)
        self.assertIn("non_text_candidate", decision.reasons)

    def test_dual_use_prohibited_blocks_even_with_permission(self):
        decision = decide_disclosure(_CLEAN_CODE, dual_use=_prohibited(), allow_public=True)
        self.assertEqual(decision.mode, DisclosureMode.BLOCKED)
        self.assertIn("dual_use_prohibited", decision.reasons)
        self.assertIsNone(decision.disclosable_payload(_CLEAN_CODE))

    def test_dual_use_review_caps_at_escrow(self):
        decision = decide_disclosure(_CLEAN_CODE, dual_use=_review(), allow_public=True)
        self.assertEqual(decision.mode, DisclosureMode.ESCROW)
        self.assertIn("dual_use_review", decision.reasons)

    def test_reid_high_downgrades_to_hash_only(self):
        decision = decide_disclosure(
            _CLEAN_CODE, dual_use=_cleared(), reid=_reid(ReidRiskBand.HIGH), allow_public=True
        )
        self.assertEqual(decision.mode, DisclosureMode.HASH_ONLY)
        self.assertIn("reid_high", decision.reasons)

    def test_reid_medium_caps_at_escrow(self):
        decision = decide_disclosure(
            _CLEAN_CODE, dual_use=_cleared(), reid=_reid(ReidRiskBand.MEDIUM), allow_public=True
        )
        self.assertEqual(decision.mode, DisclosureMode.ESCROW)
        self.assertIn("reid_medium", decision.reasons)

    def test_reid_low_stays_public(self):
        decision = decide_disclosure(
            _CLEAN_CODE, dual_use=_cleared(), reid=_reid(ReidRiskBand.LOW), allow_public=True
        )
        self.assertEqual(decision.mode, DisclosureMode.PUBLIC)

    def test_most_restrictive_wins_across_signals(self):
        # Re-id HIGH (hash-only) AND dual-use prohibited (blocked) -> BLOCKED.
        decision = decide_disclosure(
            _CLEAN_CODE,
            dual_use=_prohibited(),
            reid=_reid(ReidRiskBand.HIGH),
            allow_public=True,
        )
        self.assertEqual(decision.mode, DisclosureMode.BLOCKED)

    def test_decision_is_bounded(self):
        decision = decide_disclosure(
            b"TINKER_API_KEY=" + b"tml-" + b"abcdefghij1234567890abcdefgh",
            dual_use=_cleared(),
            score_band="high",
        )
        public = decision.to_public_dict()
        assert_bounded_egress(public)
        self.assertFalse(public["raw_secret_egress"])
        blob = json.dumps(public)
        self.assertNotIn("tml-abcdefghij", blob)
        self.assertRegex(public["candidate_hash"], r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
