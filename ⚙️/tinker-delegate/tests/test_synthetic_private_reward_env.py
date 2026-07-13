import unittest

from tinker_delegate.private_reward import Candidate, Decision, LeakageBudget, RewardBand
from tinker_delegate.private_reward_envs import SyntheticHiddenKeywordEnvironment
from tinker_delegate.private_reward_envs.synthetic_demo import (
    DEMO_RECORDS,
    hidden_demo_forbidden_values,
    run_synthetic_hidden_keyword_demo,
)
from tinker_delegate.private_reward_holdout import HoldoutSplitPolicy


def _records():
    return {
        f"record-{index}": f"private alpha signal {index}".encode("utf-8")
        for index in range(10)
    }


class SyntheticHiddenKeywordEnvironmentTest(unittest.TestCase):
    def test_evaluate_uses_reward_holdout_and_returns_bounded_feedback(self):
        env = SyntheticHiddenKeywordEnvironment(_records())
        candidate = Candidate(b"alpha")

        feedback = env.evaluate(candidate)

        self.assertEqual(feedback.decision, Decision.PASS)
        self.assertEqual(feedback.reward_band, RewardBand.EXCEPTIONAL)
        self.assertEqual(env.holdout.reward_query_count, 1)
        self.assertEqual(env.holdout.final_validation_count, 0)
        public = feedback.to_public_dict()
        self.assertNotIn("1.0", str(public))
        self.assertNotIn("matches", str(public))
        self.assertNotIn("alpha", str(public))

    def test_public_problem_and_manifest_do_not_expose_private_records(self):
        records = _records()
        env = SyntheticHiddenKeywordEnvironment(records)

        public = env.problem().to_public_dict()

        self.assertIn("holdout", public["public_metadata"])
        public_text = str(public)
        for record_id, payload in records.items():
            self.assertNotIn(record_id, public_text)
            self.assertNotIn(payload.decode("utf-8"), public_text)

    def test_environment_hash_is_stable_across_reward_queries(self):
        env = SyntheticHiddenKeywordEnvironment(_records())
        before = env.environment_hash

        env.evaluate(Candidate(b"alpha"))

        self.assertEqual(env.environment_hash, before)
        self.assertEqual(env.problem().public_metadata["holdout"]["partition_counts"]["train"], 6)
        self.assertNotIn("reward_query_count", str(env.problem().to_public_dict()))

    def test_finalize_uses_final_holdout_once_and_closes_reward_queries(self):
        env = SyntheticHiddenKeywordEnvironment(_records())
        env.evaluate(Candidate(b"alpha"))

        result = env.finalize()
        second = env.finalize()

        self.assertEqual(result, second)
        self.assertEqual(result.decision, Decision.PASS)
        self.assertEqual(result.result_band, RewardBand.EXCEPTIONAL)
        self.assertEqual(env.holdout.final_validation_count, 1)
        self.assertTrue(env.holdout.closed_to_reward_queries)
        rejected = env.evaluate(Candidate(b"alpha"))
        self.assertEqual(rejected.decision, Decision.POLICY_REJECTED)
        self.assertEqual(env.holdout.reward_query_count, 1)

    def test_final_result_attestation_includes_public_holdout_manifest_only(self):
        records = _records()
        env = SyntheticHiddenKeywordEnvironment(records)
        env.evaluate(Candidate(b"alpha"))

        result = env.finalize()

        public = result.to_public_dict()
        self.assertEqual(public["attestation"]["holdout"]["final_validation_count"], 1)
        self.assertTrue(public["attestation"]["holdout"]["closed_to_reward_queries"])
        public_text = str(public)
        for record_id, payload in records.items():
            self.assertNotIn(record_id, public_text)
            self.assertNotIn(payload.decode("utf-8"), public_text)
        self.assertNotIn("matches", public_text)
        self.assertNotIn("alpha", public_text)

    def test_query_budget_is_bound_to_holdout_reward_budget(self):
        holdout_policy = HoldoutSplitPolicy(max_reward_queries=1)
        env = SyntheticHiddenKeywordEnvironment(_records(), holdout_policy=holdout_policy)

        first = env.evaluate(Candidate(b"alpha"))
        second = env.evaluate(Candidate(b"alpha"))

        self.assertEqual(first.decision, Decision.PASS)
        self.assertEqual(second.decision, Decision.BUDGET_EXHAUSTED)
        self.assertEqual(env.holdout.reward_query_count, 1)

    def test_rejects_query_budget_larger_than_holdout_budget(self):
        with self.assertRaisesRegex(ValueError, "cannot exceed"):
            SyntheticHiddenKeywordEnvironment(
                _records(),
                holdout_policy=HoldoutSplitPolicy(max_reward_queries=1),
                query_budget=LeakageBudget(max_queries=2),
            )

    def test_candidate_policy_rejects_invalid_keywords_without_holdout_query(self):
        env = SyntheticHiddenKeywordEnvironment(_records())

        invalid = env.evaluate(Candidate(b"alpha beta"))
        non_utf8 = env.evaluate(Candidate(b"\xff"))

        self.assertEqual(invalid.decision, Decision.POLICY_REJECTED)
        self.assertEqual(non_utf8.decision, Decision.POLICY_REJECTED)
        self.assertEqual(env.holdout.reward_query_count, 0)

    def test_synthetic_demo_returns_bounded_public_packet(self):
        candidates = ("alpha", "beta")

        packet = run_synthetic_hidden_keyword_demo(candidates)

        self.assertEqual(packet["demo"], "synthetic_hidden_keyword")
        self.assertFalse(packet["raw_secret_egress"])
        self.assertEqual(packet["submitted_candidate_count"], 2)
        self.assertEqual(len(packet["feedback"]), 2)
        self.assertEqual(packet["final_result"]["public_message"], "bounded synthetic final validation result")
        commitment = packet["reward_transcript_commitment"]
        self.assertEqual(commitment["surface"], "reward_transcript_commitment")
        self.assertEqual(commitment["round_count"], 2)
        self.assertRegex(commitment["transcript_root"], r"^[0-9a-f]{64}$")
        self.assertRegex(commitment["transcript_chain_head"], r"^[0-9a-f]{64}$")
        public_text = str(packet)
        for forbidden in hidden_demo_forbidden_values(candidates):
            self.assertNotIn(forbidden, public_text)
        for payload in DEMO_RECORDS.values():
            self.assertNotIn(payload.decode("utf-8"), public_text)


if __name__ == "__main__":
    unittest.main()
