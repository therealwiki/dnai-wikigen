import unittest

from tinker_delegate.private_reward_holdout import (
    HiddenHoldoutSet,
    HoldoutPartition,
    HoldoutRecord,
    HoldoutSplitPolicy,
)


def _records(count=10):
    return {
        f"record-{index}": f"private-payload-{index}".encode("utf-8")
        for index in range(count)
    }


class HiddenHoldoutSetTest(unittest.TestCase):
    def test_splits_records_into_disjoint_partitions(self):
        holdout = HiddenHoldoutSet(_records(10))

        train = set(holdout.record_ids_for(HoldoutPartition.TRAIN))
        reward = set(holdout.record_ids_for(HoldoutPartition.REWARD))
        final = set(holdout.record_ids_for(HoldoutPartition.FINAL_VALIDATION))

        self.assertEqual(len(train), 6)
        self.assertEqual(len(reward), 2)
        self.assertEqual(len(final), 2)
        self.assertFalse(train & reward)
        self.assertFalse(train & final)
        self.assertFalse(reward & final)
        self.assertEqual(train | reward | final, set(_records(10)))

    def test_split_commitment_is_stable_and_seed_dependent(self):
        records = _records(12)
        first = HiddenHoldoutSet(records, HoldoutSplitPolicy(split_seed="seed-a"))
        second = HiddenHoldoutSet(records, HoldoutSplitPolicy(split_seed="seed-a"))
        third = HiddenHoldoutSet(records, HoldoutSplitPolicy(split_seed="seed-b"))

        self.assertEqual(first.split_commitment, second.split_commitment)
        self.assertEqual(first.partition_counts, second.partition_counts)
        self.assertNotEqual(first.split_commitment, third.split_commitment)

    def test_public_manifest_exposes_counts_and_commitments_not_records(self):
        records = _records(10)
        holdout = HiddenHoldoutSet(records)
        holdout.record_reward_query("candidate-a")

        public = holdout.public_manifest().to_public_dict()

        self.assertEqual(len(public["split_commitment"]), 64)
        self.assertEqual(public["partition_counts"]["train"], 6)
        self.assertEqual(public["reward_query_count"], 1)
        self.assertEqual(public["unique_reward_candidates"], 1)
        self.assertEqual(public["max_reward_queries_for_single_candidate"], 1)
        public_text = str(public)
        for record_id, payload in records.items():
            self.assertNotIn(record_id, public_text)
            self.assertNotIn(payload.decode("utf-8"), public_text)

    def test_reward_query_budget_is_enforced(self):
        policy = HoldoutSplitPolicy(max_reward_queries=2)
        holdout = HiddenHoldoutSet(_records(8), policy)

        holdout.record_reward_query("candidate-a")
        holdout.record_reward_query("candidate-b")

        with self.assertRaisesRegex(RuntimeError, "reward query budget"):
            holdout.record_reward_query("candidate-c")

    def test_final_validation_is_one_shot_and_closes_reward_queries(self):
        holdout = HiddenHoldoutSet(_records(8))
        holdout.record_reward_query("candidate-a")

        holdout.record_final_validation("candidate-final")

        self.assertTrue(holdout.closed_to_reward_queries)
        self.assertEqual(holdout.final_validation_count, 1)
        with self.assertRaisesRegex(RuntimeError, "closed after final validation"):
            holdout.record_reward_query("candidate-b")
        with self.assertRaisesRegex(RuntimeError, "final validation budget"):
            holdout.record_final_validation("candidate-second")

    def test_unique_reward_candidate_count_tracks_adaptive_repeats(self):
        holdout = HiddenHoldoutSet(_records(8))

        holdout.record_reward_query("candidate-a")
        holdout.record_reward_query("candidate-a")
        holdout.record_reward_query("candidate-b")

        manifest = holdout.public_manifest().to_public_dict()
        self.assertEqual(manifest["reward_query_count"], 3)
        self.assertEqual(manifest["unique_reward_candidates"], 2)
        self.assertEqual(manifest["max_reward_queries_for_single_candidate"], 2)

    def test_repeated_candidate_queries_fail_closed(self):
        policy = HoldoutSplitPolicy(max_reward_queries_per_candidate=2)
        holdout = HiddenHoldoutSet(_records(8), policy)

        holdout.record_reward_query("candidate-a")
        holdout.record_reward_query("candidate-a")

        with self.assertRaisesRegex(RuntimeError, "repeat limit"):
            holdout.record_reward_query("candidate-a")

    def test_final_validation_requires_minimum_unique_candidates(self):
        policy = HoldoutSplitPolicy(min_unique_reward_candidates_before_final=2)
        holdout = HiddenHoldoutSet(_records(8), policy)

        holdout.record_reward_query("candidate-a")

        with self.assertRaisesRegex(RuntimeError, "unique reward candidates"):
            holdout.record_final_validation("candidate-final")

        holdout.record_reward_query("candidate-b")
        holdout.record_final_validation("candidate-final")
        self.assertEqual(holdout.final_validation_count, 1)

    def test_records_for_is_internal_and_returns_payloads(self):
        holdout = HiddenHoldoutSet(_records(8))

        train_record = holdout.records_for(HoldoutPartition.TRAIN)[0]

        self.assertIsInstance(train_record, HoldoutRecord)
        self.assertTrue(train_record.payload.startswith(b"private-payload-"))

    def test_invalid_policies_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "sum to 1"):
            HoldoutSplitPolicy(train_fraction=0.5, reward_fraction=0.2, final_validation_fraction=0.2)
        with self.assertRaisesRegex(ValueError, "positive"):
            HoldoutSplitPolicy(final_validation_fraction=0)
        with self.assertRaisesRegex(ValueError, "max_reward_queries_per_candidate"):
            HoldoutSplitPolicy(max_reward_queries_per_candidate=0)
        with self.assertRaisesRegex(ValueError, "min_unique_reward_candidates"):
            HoldoutSplitPolicy(min_unique_reward_candidates_before_final=-1)
        with self.assertRaisesRegex(ValueError, "not enough records"):
            HiddenHoldoutSet(_records(2))
        with self.assertRaisesRegex(ValueError, "mapping key"):
            HiddenHoldoutSet({"a": HoldoutRecord(record_id="b", payload=b"x")})


if __name__ == "__main__":
    unittest.main()
