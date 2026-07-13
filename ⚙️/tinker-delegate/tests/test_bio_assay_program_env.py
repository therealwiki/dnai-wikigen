import json
import unittest

from tinker_delegate.private_reward import Candidate, Decision, RewardBand
from tinker_delegate.private_reward_envs.bio_assay_program import (
    BioAssayProgramCandidateSource,
    BioAssayProgramEnvironment,
    run_bio_assay_program_demo,
)
from tinker_delegate.private_reward_loop import (
    HillClimbOptimizer,
    LLMRepairOptimizer,
    RandomSearchOptimizer,
    StopReason,
    band_rank,
    run_private_reward_loop,
)

# Clean signal window with one high-side outlier in each control set.
_POS = [100.0, 101.0, 99.0, 100.5, 140.0]
_NEG = [10.0, 11.0, 9.0, 10.5, 40.0]

_PASSTHROUGH = (
    "def process(positive_wells, negative_wells):\n"
    "    return (positive_wells, negative_wells)\n"
)
_DROP_EXTREMES = (
    "def process(positive_wells, negative_wells):\n"
    "    def trim(xs):\n"
    "        s = sorted(xs)\n"
    "        return s[1:-1] if len(s) > 3 else s\n"
    "    return (trim(positive_wells), trim(negative_wells))\n"
)


def _env():
    return BioAssayProgramEnvironment(_POS, _NEG, max_queries=16)


class BioAssayProgramEnvTest(unittest.TestCase):
    def test_outlier_removal_beats_passthrough(self):
        passthrough_band = _env().evaluate(Candidate(_PASSTHROUGH.encode())).reward_band
        trimmed_band = _env().evaluate(Candidate(_DROP_EXTREMES.encode())).reward_band
        self.assertGreater(band_rank(trimmed_band), band_rank(passthrough_band))
        self.assertGreaterEqual(band_rank(trimmed_band), band_rank(RewardBand.HIGH))

    def test_fabricated_values_fail_closed(self):
        # Program invents far-apart constants to fake a huge Z'; must be rejected.
        fabricate = (
            "def process(positive_wells, negative_wells):\n"
            "    return ([1000.0, 1000.0, 1000.0], [0.0, 0.0, 0.0])\n"
        )
        feedback = _env().evaluate(Candidate(fabricate.encode()))
        self.assertEqual(feedback.reward_band, RewardBand.NEGLIGIBLE)

    def test_moving_positives_into_negatives_fails_closed(self):
        # Values are real members but placed in the wrong control set.
        swap = (
            "def process(positive_wells, negative_wells):\n"
            "    return (negative_wells, positive_wells)\n"
        )
        # Membership holds (values exist in the opposite universe only if equal),
        # so this must fail the multiset check and fall to NEGLIGIBLE.
        feedback = _env().evaluate(Candidate(swap.encode()))
        self.assertEqual(feedback.reward_band, RewardBand.NEGLIGIBLE)

    def test_too_few_controls_fail_closed(self):
        one_each = (
            "def process(positive_wells, negative_wells):\n"
            "    return ([positive_wells[0]], [negative_wells[0]])\n"
        )
        feedback = _env().evaluate(Candidate(one_each.encode()))
        self.assertEqual(feedback.reward_band, RewardBand.NEGLIGIBLE)

    def test_non_program_rejected(self):
        feedback = _env().evaluate(Candidate(b"print('hi')"))
        self.assertEqual(feedback.decision, Decision.POLICY_REJECTED)

    def test_banned_io_fails_closed(self):
        malicious = (
            "def process(positive_wells, negative_wells):\n"
            "    open('/etc/passwd')\n"
            "    return (positive_wells, negative_wells)\n"
        )
        feedback = _env().evaluate(Candidate(malicious.encode()))
        # Sandbox AST preflight blocks open(); reward falls closed.
        self.assertEqual(feedback.reward_band, RewardBand.NEGLIGIBLE)

    def test_no_raw_readings_in_bounded_output(self):
        env = _env()
        env.evaluate(Candidate(_DROP_EXTREMES.encode()))
        blob = json.dumps(env.finalize().to_public_dict())
        for raw in ("140.0", "100.5", "z_prime"):
            self.assertNotIn(raw, blob)

    def test_loop_drives_program_candidates(self):
        for factory in (RandomSearchOptimizer, HillClimbOptimizer, LLMRepairOptimizer):
            with self.subTest(optimizer=factory.__name__):
                env = _env()
                optimizer = factory(BioAssayProgramCandidateSource(), budget=16)
                outcome = run_private_reward_loop(env, optimizer, max_rounds=16)
                self.assertFalse(outcome.raw_secret_egress)
                self.assertGreater(outcome.rounds_run, 0)

    def test_hill_climb_selects_a_high_scoring_program(self):
        env = _env()
        optimizer = HillClimbOptimizer(BioAssayProgramCandidateSource(), budget=16)
        outcome = run_private_reward_loop(
            env, optimizer, max_rounds=16, target_band=RewardBand.HIGH
        )
        self.assertEqual(outcome.stop_reason, StopReason.TARGET_REACHED)
        self.assertGreaterEqual(band_rank(outcome.best_band), band_rank(RewardBand.HIGH))

    def test_demo_bounded_and_deterministic(self):
        first = run_bio_assay_program_demo()
        second = run_bio_assay_program_demo()
        self.assertFalse(first["raw_secret_egress"])
        self.assertEqual(
            first["outcome"]["loop_transcript_hash"],
            second["outcome"]["loop_transcript_hash"],
        )


if __name__ == "__main__":
    unittest.main()
