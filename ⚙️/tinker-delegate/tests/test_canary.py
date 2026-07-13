import unittest

from tinker_delegate.canary import (
    CanaryCandidate,
    CanaryOutcome,
    CanarySentinel,
    CanaryTripped,
    flag_surprising_score,
)
from tinker_delegate.private_reward import (
    FeedbackMode,
    LeakageBudget,
    RewardBand,
    assert_bounded_egress,
)
from tinker_delegate.private_reward_envs.synthetic import SyntheticHiddenKeywordEnvironment
from tinker_delegate.private_reward_holdout import HoldoutSplitPolicy


# Every hidden record contains "alpha": it scores 1.0 (EXCEPTIONAL); any other
# alphanumeric token scores 0 (NEGLIGIBLE). That gives clean known answers.
_RECORDS = {f"rec-{i}": f"the alpha marker {i}".encode("utf-8") for i in range(10)}


def _make_env(max_queries: int = 16) -> SyntheticHiddenKeywordEnvironment:
    policy = HoldoutSplitPolicy(max_reward_queries=max_queries)
    return SyntheticHiddenKeywordEnvironment(
        _RECORDS,
        holdout_policy=policy,
        query_budget=LeakageBudget(max_queries=max_queries, feedback_mode=FeedbackMode.BAND),
    )


class CanarySentinelTest(unittest.TestCase):
    def test_known_junk_and_known_strong_canaries_pass(self):
        sentinel = CanarySentinel(
            [
                CanaryCandidate(b"zzzjunk", label="junk", max_band=RewardBand.LOW),
                CanaryCandidate(b"alpha", label="strong", min_band=RewardBand.HIGH),
            ]
        )
        report = sentinel.screen(_make_env())
        self.assertTrue(report.clear)
        self.assertEqual(report.tripped_count, 0)
        by_label = {r.label: r for r in report.results}
        self.assertEqual(by_label["junk"].outcome, CanaryOutcome.PASS)
        self.assertEqual(by_label["strong"].outcome, CanaryOutcome.PASS)

    def test_junk_scoring_high_trips_high(self):
        # A candidate we declared junk (max NEGLIGIBLE) actually scores high ->
        # the oracle is leaking or has been gamed.
        sentinel = CanarySentinel(
            [CanaryCandidate(b"alpha", label="leak", max_band=RewardBand.NEGLIGIBLE)]
        )
        report = sentinel.screen(_make_env())
        self.assertFalse(report.clear)
        self.assertEqual(report.results[0].outcome, CanaryOutcome.TRIPPED_HIGH)

    def test_strong_collapsing_trips_low(self):
        # A candidate we declared strong (min HIGH) scores negligible -> the
        # oracle has collapsed / been zeroed.
        sentinel = CanarySentinel(
            [CanaryCandidate(b"zzzjunk", label="collapse", min_band=RewardBand.HIGH)]
        )
        report = sentinel.screen(_make_env())
        self.assertFalse(report.clear)
        self.assertEqual(report.results[0].outcome, CanaryOutcome.TRIPPED_LOW)

    def test_assert_clear_fails_closed_on_trip(self):
        sentinel = CanarySentinel(
            [CanaryCandidate(b"alpha", label="leak", max_band=RewardBand.NEGLIGIBLE)]
        )
        with self.assertRaises(CanaryTripped):
            sentinel.assert_clear(_make_env())

    def test_assert_clear_returns_report_when_clear(self):
        sentinel = CanarySentinel([CanaryCandidate(b"zzzjunk", max_band=RewardBand.LOW)])
        report = sentinel.assert_clear(_make_env())
        self.assertTrue(report.clear)

    def test_budget_exhaustion_is_inconclusive_not_tripped(self):
        env = _make_env(max_queries=1)
        # Burn the single query, then screen: the canary gets BUDGET_EXHAUSTED.
        from tinker_delegate.private_reward import Candidate

        env.evaluate(Candidate(b"alpha"))
        sentinel = CanarySentinel(
            [CanaryCandidate(b"zzzjunk", label="j", min_band=RewardBand.HIGH)]
        )
        report = sentinel.screen(env)
        self.assertEqual(report.results[0].outcome, CanaryOutcome.INCONCLUSIVE)
        self.assertEqual(report.inconclusive_count, 1)
        self.assertTrue(report.clear)  # inconclusive neither passes nor trips

    def test_report_is_bounded(self):
        sentinel = CanarySentinel(
            [CanaryCandidate(b"alpha", label="strong", min_band=RewardBand.HIGH)]
        )
        public = sentinel.screen(_make_env()).to_public_dict()
        assert_bounded_egress(public)
        self.assertFalse(public["raw_secret_egress"])
        # Payload text never leaks; only a hash.
        import json

        blob = json.dumps(public)
        self.assertNotIn("alpha", blob)
        self.assertRegex(public["results"][0]["payload_hash"], r"^[0-9a-f]{64}$")

    def test_min_exceeds_max_rejected(self):
        with self.assertRaises(ValueError):
            CanaryCandidate(b"x", min_band=RewardBand.HIGH, max_band=RewardBand.LOW)


class SurprisingScoreTest(unittest.TestCase):
    def test_high_and_exceptional_are_flagged(self):
        self.assertTrue(flag_surprising_score(RewardBand.HIGH))
        self.assertTrue(flag_surprising_score(RewardBand.EXCEPTIONAL))

    def test_medium_and_below_are_not_flagged(self):
        self.assertFalse(flag_surprising_score(RewardBand.MEDIUM))
        self.assertFalse(flag_surprising_score(RewardBand.NEGLIGIBLE))
        self.assertFalse(flag_surprising_score(RewardBand.WITHHELD))

    def test_threshold_is_configurable(self):
        self.assertTrue(flag_surprising_score(RewardBand.MEDIUM, review_threshold=RewardBand.MEDIUM))


if __name__ == "__main__":
    unittest.main()
