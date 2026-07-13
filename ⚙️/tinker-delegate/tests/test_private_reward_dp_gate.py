import unittest

from tinker_delegate.dp_accounting import DpAccountant, DpParams, PrivacyMode
from tinker_delegate.private_reward import (
    Candidate,
    Decision,
    FeedbackMode,
    LeakageBudget,
    RewardBand,
)
from tinker_delegate.private_reward_envs.synthetic import SyntheticHiddenKeywordEnvironment
from tinker_delegate.private_reward_holdout import HoldoutSplitPolicy

_RECORDS = {f"rec-{i}": f"the alpha marker {i}".encode("utf-8") for i in range(10)}


def _env(max_queries: int = 16) -> SyntheticHiddenKeywordEnvironment:
    policy = HoldoutSplitPolicy(max_reward_queries=max_queries)
    return SyntheticHiddenKeywordEnvironment(
        _RECORDS,
        holdout_policy=policy,
        query_budget=LeakageBudget(max_queries=max_queries, feedback_mode=FeedbackMode.BAND),
    )


class DpGatedRewardTest(unittest.TestCase):
    def test_dp_budget_binds_before_query_budget_and_fails_closed(self):
        env = _env()
        acct = DpAccountant(PrivacyMode.DP, max_epsilon=1.0, max_delta=0.0)
        env.set_dp_budget(acct, DpParams(epsilon=0.5))  # exactly two releases fit

        f1 = env.evaluate(Candidate(b"alpha"))
        f2 = env.evaluate(Candidate(b"beta"))
        self.assertEqual(f1.decision, Decision.PASS)
        self.assertEqual(f2.decision, Decision.PASS)

        # Third release would exceed the epsilon budget -> fail closed, no reward.
        f3 = env.evaluate(Candidate(b"gamma"))
        self.assertEqual(f3.decision, Decision.BUDGET_EXHAUSTED)
        self.assertEqual(f3.reward_band, RewardBand.WITHHELD)
        self.assertTrue(acct.exhausted)  # 1.0/1.0 spent exactly
        # The denied release did not consume more epsilon than the two that fit.
        self.assertAlmostEqual(acct.spent_epsilon, 1.0)

    def test_no_dp_budget_is_backward_compatible(self):
        env = _env()
        f = env.evaluate(Candidate(b"alpha"))
        self.assertEqual(f.decision, Decision.PASS)
        # No DP charge, no exhaustion, band released as normal.
        self.assertNotEqual(f.reward_band, RewardBand.WITHHELD)
        # Non-DP attestation carries no dp_status key (byte-identical to before).
        self.assertNotIn("dp_status", env.attest().to_public_dict())

    def test_dp_status_is_recorded_in_attestation(self):
        env = _env()
        acct = DpAccountant(PrivacyMode.DP, max_epsilon=1.0, max_delta=0.0)
        env.set_dp_budget(acct, DpParams(epsilon=0.5))
        env.evaluate(Candidate(b"alpha"))  # spends 0.5
        att = env.attest().to_public_dict()
        self.assertIn("dp_status", att)
        self.assertEqual(att["dp_status"]["mode"], "differential_privacy")
        self.assertTrue(att["dp_status"]["phi_safe"])
        self.assertAlmostEqual(att["dp_status"]["spent_epsilon"], 0.5)
        # finalize's egress check still passes with dp floats under attestation.
        env.finalize()

    def test_dp_gate_does_not_leak_reward_when_exhausted(self):
        env = _env()
        acct = DpAccountant(PrivacyMode.DP, max_epsilon=0.5, max_delta=0.0)
        env.set_dp_budget(acct, DpParams(epsilon=0.4))
        env.evaluate(Candidate(b"alpha"))  # spends 0.4
        blocked = env.evaluate(Candidate(b"beta"))  # 0.8 > 0.5 -> denied
        self.assertEqual(blocked.decision, Decision.BUDGET_EXHAUSTED)
        public = blocked.to_public_dict()
        self.assertFalse(public.get("raw_secret_egress", False))
        self.assertEqual(public["reward_band"], RewardBand.WITHHELD.value)


if __name__ == "__main__":
    unittest.main()
