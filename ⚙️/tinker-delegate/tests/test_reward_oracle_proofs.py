"""Reward-oracle proof tests (TODO Milestone 4, P1).

These are cross-environment invariants the private-reward pitch rests on, asserted
against BOTH concrete environments (synthetic keyword + denoising holdout):

  1. No direct data reads   — sealed record payloads never appear in any public
                              surface (optimizer view, feedback, final, attest).
  2. No exact reward egress  — public feedback carries only a bounded band; the
                              exact InternalReward cannot be pulled under the
                              default external optimizer policy; public feedback
                              dicts expose only a bounded key whitelist.
  3. Query budget enforced   — exceeding the budget returns a bounded
                              BUDGET_EXHAUSTED decision (never an exception, never
                              a reward band).
  4. Sandbox egress capped   — candidate stdout is truncated to the policy cap and
                              banned-I/O candidates fail closed to negligible.
  5. Transcript hash stable  — identical candidate sequences produce identical
                              transcript/leakage/environment hashes, and a new
                              query changes the transcript hash.
"""
import json
import unittest

from tinker_delegate.private_reward import (
    Candidate,
    Decision,
    FeedbackMode,
    OptimizerLocation,
    RewardBand,
)
from tinker_delegate.private_reward_envs.denoising import (
    DenoisingHoldoutEnvironment,
    SealedCell,
)
from tinker_delegate.private_reward_envs.denoising_demo import (
    IDENTITY_DENOISER,
    POOL_DENOISER,
    denoising_demo_forbidden_values,
)
from tinker_delegate.private_reward_envs.synthetic import SyntheticHiddenKeywordEnvironment
from tinker_delegate.private_reward_holdout import HoldoutSplitPolicy
from tinker_delegate.private_reward_sandbox import (
    PythonCandidateSandbox,
    SandboxOutcome,
    SandboxPolicy,
)

# Bounded whitelist of keys allowed to leave the boundary on a feedback packet.
_ALLOWED_FEEDBACK_KEYS = {
    "candidate_hash",
    "decision",
    "feedback_mode",
    "reward_band",
    "public_message",
    "transcript_hash",
}
# Keys that would betray exact reward / raw data if they ever leaked.
_FORBIDDEN_KEYS = {"value", "metrics", "mse", "poisson", "baseline_mse", "baseline_poisson"}

_SYNTH_RECORDS = {
    "rec-00": b"sealed alpha pathway signal",
    "rec-01": b"sealed alpha validation note",
    "rec-02": b"sealed beta control sample",
    "rec-03": b"sealed alpha benchmark example",
    "rec-04": b"sealed gamma background row",
    "rec-05": b"sealed alpha private reward row",
    "rec-06": b"sealed beta synthetic holdout",
    "rec-07": b"sealed alpha final check",
    "rec-08": b"sealed delta unrelated baseline",
    "rec-09": b"sealed alpha hidden corpus",
}
_SYNTH_FORBIDDEN = tuple(_SYNTH_RECORDS) + tuple(
    v.decode() for v in _SYNTH_RECORDS.values()
)

_CELLS_TRAIN = (
    (10, 4, 2, 3, 0, 1), (7, 6, 4, 1, 2, 0), (9, 5, 3, 2, 1, 1), (12, 3, 5, 0, 1, 2),
    (6, 7, 2, 3, 0, 1), (8, 5, 4, 2, 2, 0), (11, 4, 3, 1, 1, 1), (7, 6, 3, 2, 0, 2),
    (9, 5, 3, 2, 1, 1), (8, 6, 3, 1, 1, 1),
)
_CELLS_TEST = (
    (9, 5, 3, 2, 1, 1), (8, 5, 3, 2, 1, 1), (10, 4, 4, 1, 1, 1), (9, 6, 2, 2, 1, 1),
    (7, 5, 3, 3, 1, 1), (9, 5, 3, 2, 1, 1), (10, 5, 3, 1, 1, 1), (8, 5, 4, 2, 1, 1),
    (9, 5, 3, 2, 1, 1), (9, 5, 3, 2, 1, 1),
)


def _synth_env(**policy):
    base = dict(max_reward_queries=8)
    base.update(policy)
    return SyntheticHiddenKeywordEnvironment(
        dict(_SYNTH_RECORDS), holdout_policy=HoldoutSplitPolicy(**base)
    )


def _denoise_env(**policy):
    base = dict(
        train_fraction=0.4, reward_fraction=0.3, final_validation_fraction=0.3,
        min_train_records=2, min_reward_records=2, min_final_validation_records=2,
        max_reward_queries=8, max_reward_queries_per_candidate=2,
        min_unique_reward_candidates_before_final=1,
    )
    base.update(policy)
    cells = [SealedCell(f"c{i:02d}", _CELLS_TRAIN[i], _CELLS_TEST[i]) for i in range(10)]
    return DenoisingHoldoutEnvironment(cells, holdout_policy=HoldoutSplitPolicy(**base))


class NoDirectDataReadTest(unittest.TestCase):
    def test_synthetic_sealed_records_never_egress(self):
        env = _synth_env()
        env.evaluate(Candidate(b"alpha"))
        env.evaluate(Candidate(b"beta"))
        blob = json.dumps(
            {
                "view": env.optimizer_view(),
                "final": env.finalize().to_public_dict(),
                "attest": env.attest().to_public_dict(),
            }
        )
        for forbidden in _SYNTH_FORBIDDEN:
            self.assertNotIn(forbidden, blob)

    def test_denoising_sealed_counts_never_egress(self):
        env = _denoise_env()
        env.evaluate(Candidate(POOL_DENOISER.encode()))
        blob = json.dumps(
            {
                "view": env.optimizer_view(),
                "final": env.finalize().to_public_dict(),
                "attest": env.attest().to_public_dict(),
            }
        )
        for forbidden in denoising_demo_forbidden_values():
            self.assertNotIn(forbidden, blob)


class NoExactRewardEgressTest(unittest.TestCase):
    def test_reward_precision_is_zero_in_public_feedback_modes(self):
        for env in (_synth_env(), _denoise_env()):
            self.assertNotEqual(env.query_budget.feedback_mode, FeedbackMode.NONE)
            self.assertEqual(env.query_budget.reward_precision_bits, 0)

    def test_exact_reward_cannot_be_pulled_under_external_policy(self):
        for env, cand in ((_synth_env(), b"alpha"), (_denoise_env(), POOL_DENOISER.encode())):
            self.assertEqual(env.optimizer_policy.location, OptimizerLocation.EXTERNAL)
            env.evaluate(Candidate(cand))
            with self.assertRaises(PermissionError):
                env.internal_reward_for_optimizer()

    def test_public_feedback_exposes_only_bounded_keys(self):
        for env, cand in ((_synth_env(), b"alpha"), (_denoise_env(), POOL_DENOISER.encode())):
            fb = env.evaluate(Candidate(cand)).to_public_dict()
            self.assertTrue(set(fb).issubset(_ALLOWED_FEEDBACK_KEYS))
            self.assertFalse(set(fb) & _FORBIDDEN_KEYS)
            # The band is a coarse enum value, never a raw float.
            self.assertIn(fb["reward_band"], {b.value for b in RewardBand})


class QueryBudgetTest(unittest.TestCase):
    def test_synthetic_budget_exhaustion_is_bounded(self):
        env = _synth_env(max_reward_queries=2, max_reward_queries_per_candidate=1)
        a = env.evaluate(Candidate(b"alpha"))
        b = env.evaluate(Candidate(b"beta"))
        c = env.evaluate(Candidate(b"gamma"))
        self.assertEqual(a.decision, Decision.PASS)
        self.assertEqual(b.decision, Decision.PASS)
        self.assertEqual(c.decision, Decision.BUDGET_EXHAUSTED)
        self.assertEqual(c.reward_band, RewardBand.WITHHELD)

    def test_denoising_budget_exhaustion_is_bounded(self):
        env = _denoise_env(max_reward_queries=2, max_reward_queries_per_candidate=1)
        env.evaluate(Candidate(IDENTITY_DENOISER.encode()))
        env.evaluate(Candidate(POOL_DENOISER.encode()))
        c = env.evaluate(Candidate(b"def denoise(train):\n    return [[1.0]]\n"))
        self.assertEqual(c.decision, Decision.BUDGET_EXHAUSTED)
        self.assertEqual(c.reward_band, RewardBand.WITHHELD)


class SandboxEgressCapTest(unittest.TestCase):
    def test_stdout_is_truncated_to_policy_cap(self):
        sb = PythonCandidateSandbox(SandboxPolicy(max_stdout_bytes=256))
        result = sb.run(Candidate(b"for _ in range(100000):\n    print('X'*80)\n"))
        self.assertEqual(result.outcome, SandboxOutcome.PASS)
        self.assertTrue(result.stdout_truncated)
        self.assertLessEqual(len(result.stdout.encode("utf-8")), 256)

    def test_denoising_env_fails_closed_on_huge_output_candidate(self):
        env = _denoise_env()
        # A candidate that floods stdout cannot smuggle data out; parsing the
        # denoised matrix fails and the band is negligible, with no marker leak.
        flood = b"def denoise(train):\n    print('LEAKMARKER'*10000)\n    return train\n"
        fb = env.evaluate(Candidate(flood))
        self.assertEqual(fb.reward_band, RewardBand.NEGLIGIBLE)
        self.assertNotIn("LEAKMARKER", json.dumps(env.finalize().to_public_dict()))

    def test_denoising_env_rejects_banned_io_candidate(self):
        env = _denoise_env()
        for program in (
            b"def denoise(train):\n    open('/etc/passwd')\n    return train\n",
            b"def denoise(train):\n    import socket\n    return train\n",
            b"def denoise(train):\n    __import__('os')\n    return train\n",
        ):
            fb = env.evaluate(Candidate(program))
            self.assertEqual(fb.reward_band, RewardBand.NEGLIGIBLE)


class TranscriptStabilityTest(unittest.TestCase):
    def _run_synth(self):
        env = _synth_env()
        for c in (b"alpha", b"beta", b"gamma"):
            env.evaluate(Candidate(c))
        return env

    def test_synthetic_hashes_are_deterministic(self):
        a, b = self._run_synth(), self._run_synth()
        self.assertEqual(a.transcript_hash, b.transcript_hash)
        self.assertEqual(a.leakage_hash, b.leakage_hash)
        self.assertEqual(a.environment_hash, b.environment_hash)

    def test_denoising_hashes_are_deterministic(self):
        def run():
            env = _denoise_env()
            env.evaluate(Candidate(IDENTITY_DENOISER.encode()))
            env.evaluate(Candidate(POOL_DENOISER.encode()))
            return env

        a, b = run(), run()
        self.assertEqual(a.transcript_hash, b.transcript_hash)
        self.assertEqual(a.leakage_hash, b.leakage_hash)
        self.assertEqual(a.environment_hash, b.environment_hash)

    def test_new_query_changes_transcript_hash(self):
        env = _synth_env()
        env.evaluate(Candidate(b"alpha"))
        before = env.transcript_hash
        env.evaluate(Candidate(b"beta"))
        self.assertNotEqual(before, env.transcript_hash)


if __name__ == "__main__":
    unittest.main()
