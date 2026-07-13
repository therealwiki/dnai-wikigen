import unittest

from tinker_delegate.private_reward import (
    BoundedFeedback,
    Candidate,
    CandidateSchema,
    Decision,
    FeedbackMode,
    InternalReward,
    LeakageBudget,
    OptimizerLocation,
    OptimizerPolicy,
    PrivateRewardEnvironment,
    PublicProblem,
    RewardBand,
    RewardLeakageError,
    SecurityTier,
    assert_bounded_egress,
)


class ToyPrivateRewardEnvironment(PrivateRewardEnvironment):
    def __init__(self, mode=FeedbackMode.BAND, max_queries=2):
        super().__init__()
        self._budget = LeakageBudget(max_queries=max_queries, feedback_mode=mode)

    def problem(self) -> PublicProblem:
        return PublicProblem(
            title="Synthetic sealed score",
            statement="Find a candidate with high hidden overlap.",
            public_metadata={"dataset": "synthetic"},
        )

    @property
    def candidate_schema(self) -> CandidateSchema:
        return CandidateSchema(
            kind="bytes",
            json_schema={"type": "string", "contentEncoding": "base64"},
            max_bytes=32,
        )

    @property
    def query_budget(self) -> LeakageBudget:
        return self._budget

    @property
    def security_tier(self) -> SecurityTier:
        return SecurityTier.INTERNAL_TEE

    def reward(self, candidate: Candidate) -> InternalReward:
        return InternalReward(value=candidate.payload.count(b"x") / 10.0, metrics={"raw_count": 7})

    def output_reducer(self, reward: InternalReward) -> BoundedFeedback:
        if reward.value >= 0.3:
            band = RewardBand.HIGH
        elif reward.value > 0:
            band = RewardBand.LOW
        else:
            band = RewardBand.NEGLIGIBLE
        return BoundedFeedback(
            candidate_hash="",
            decision=Decision.PASS,
            feedback_mode=FeedbackMode.BAND,
            reward_band=band,
            public_message="bounded score band",
        )


class InternalDenseRewardEnvironment(ToyPrivateRewardEnvironment):
    @property
    def optimizer_policy(self) -> OptimizerPolicy:
        return OptimizerPolicy.internal_dense()


class LeakyReducerEnvironment(ToyPrivateRewardEnvironment):
    """A misbehaving reducer that renders the exact reward into public_message."""

    def output_reducer(self, reward: InternalReward) -> BoundedFeedback:
        return BoundedFeedback(
            candidate_hash="",
            decision=Decision.PASS,
            feedback_mode=FeedbackMode.BAND,
            reward_band=RewardBand.HIGH,
            public_message=f"score {reward.value:.4f}",
        )


class BoundedEgressEnforcementTest(unittest.TestCase):
    def test_leaky_reducer_fails_closed_on_evaluate(self):
        env = LeakyReducerEnvironment()
        with self.assertRaises(RewardLeakageError):
            env.evaluate(Candidate(b"xxx"))

    def test_assert_bounded_egress_passes_clean_feedback(self):
        assert_bounded_egress(
            {
                "candidate_hash": "0x" + "cd" * 32,
                "decision": "pass",
                "reward_band": "high",
                "public_message": "bounded score band",
            }
        )

    def test_assert_bounded_egress_rejects_float_field(self):
        with self.assertRaises(RewardLeakageError):
            assert_bounded_egress({"reward_band": "high", "exact": 0.42})

    def test_assert_bounded_egress_rejects_reward_text(self):
        with self.assertRaises(RewardLeakageError):
            assert_bounded_egress({"public_message": "score 0.9731"})

    def test_assert_bounded_egress_rejects_reward_hidden_in_dict_key(self):
        # An exact reward smuggled as a dict KEY (not value) must still be caught,
        # whether the key is a string or a non-string (JSON stringifies it).
        for leaky in (
            {"0.9731": "high", "raw_secret_egress": False},  # float-string key
            {"metrics": {"9731000": "band"}},                # nested long-int-string key
            {0.9731: "high"},                                # float key
            {123456789012: "x"},                             # long precise int key
        ):
            with self.subTest(leaky=leaky):
                with self.assertRaises(RewardLeakageError):
                    assert_bounded_egress(leaky)

    def test_assert_bounded_egress_rejects_scientific_notation_reward(self):
        # A very small/large reward reprs in scientific notation (`1e-05`,
        # `2e+16`) with no decimal point; smuggled into a string it must still be
        # caught. A bare `1e5` inside a hex hash (no sign) is NOT a false positive.
        for leak in ("score 1e-05", "reward 2e+16", "val 1e-100"):
            with self.subTest(leak=leak):
                with self.assertRaises(RewardLeakageError):
                    assert_bounded_egress({"public_message": leak, "reward_band": "high"})
        # No false positive: a hex hash with a `1e5` substring is fine.
        assert_bounded_egress({"hash": "0x" + "1e5" * 20, "reward_band": "high"})

    def test_assert_bounded_egress_rejects_giant_int_value(self):
        # A single unbounded int VALUE (not a string) can carry a whole sealed
        # blob via int.from_bytes; it is invisible to the textual scan (which only
        # yields strings/keys), so the structural int-magnitude bound must catch
        # it. Legitimate uint256-sized values (counts, wei, timestamps) still pass.
        smuggled = int.from_bytes(b"sealed-training-data" * 50, "big")
        with self.assertRaises(RewardLeakageError):
            assert_bounded_egress({"metric": smuggled, "reward_band": "high"})
        assert_bounded_egress(
            {"reward_band": "high", "amount_wei": 2**256 - 1, "count": 3}
        )

    def test_deep_structure_fails_closed_even_under_ignored_attestation(self):
        # A deeply nested subtree under the structurally-ignored `attestation`
        # key must still fail closed cleanly (not RecursionError) via the textual
        # scan's depth bound.
        deep = {"x": "ok"}
        for _ in range(5000):
            deep = {"n": deep}
        with self.assertRaises(RewardLeakageError):
            assert_bounded_egress(
                {"result_band": "high", "attestation": deep},
                structural_ignore_keys=("attestation",),
            )

    def test_attestation_config_floats_allowed_when_ignored(self):
        # Split fractions live under attestation and are public config, not reward.
        assert_bounded_egress(
            {
                "result_band": "high",
                "attestation": {"policy": {"train_fraction": 0.6}},
            },
            structural_ignore_keys=("attestation",),
        )


class PrivateRewardEnvironmentTest(unittest.TestCase):
    def test_evaluate_returns_bounded_feedback_not_exact_reward(self):
        env = ToyPrivateRewardEnvironment()
        candidate = Candidate(b"xxx")

        feedback = env.evaluate(candidate)

        self.assertEqual(feedback.candidate_hash, candidate.candidate_hash)
        self.assertEqual(feedback.reward_band, RewardBand.HIGH)
        self.assertEqual(feedback.decision, Decision.PASS)
        public = feedback.to_public_dict()
        self.assertNotIn("0.3", str(public))
        self.assertNotIn("raw_count", str(public))
        self.assertEqual(env.accepted_count, 1)
        self.assertEqual(env.rejected_count, 0)

    def test_query_budget_rejects_without_computing_reward(self):
        env = ToyPrivateRewardEnvironment(max_queries=1)
        env.evaluate(Candidate(b"x"))
        internal_count = len(env._internal_rewards)

        feedback = env.evaluate(Candidate(b"xxxxxxxxxx"))

        self.assertEqual(feedback.decision, Decision.BUDGET_EXHAUSTED)
        self.assertEqual(feedback.reward_band, RewardBand.WITHHELD)
        self.assertEqual(len(env._internal_rewards), internal_count)
        self.assertEqual(env.accepted_count, 1)
        self.assertEqual(env.rejected_count, 1)

    def test_policy_rejects_oversized_candidate_without_reward(self):
        env = ToyPrivateRewardEnvironment()

        feedback = env.evaluate(Candidate(b"x" * 33))

        self.assertEqual(feedback.decision, Decision.POLICY_REJECTED)
        self.assertEqual(feedback.reward_band, RewardBand.WITHHELD)
        self.assertEqual(len(env._internal_rewards), 0)

    def test_feedback_modes_reduce_public_precision(self):
        env = ToyPrivateRewardEnvironment(mode=FeedbackMode.PASS_HOLD_DENY)

        feedback = env.evaluate(Candidate(b"xxxx"))

        self.assertEqual(feedback.feedback_mode, FeedbackMode.PASS_HOLD_DENY)
        self.assertEqual(feedback.reward_band, RewardBand.WITHHELD)

    def test_attestation_and_finalize_use_hashes_and_counts(self):
        env = ToyPrivateRewardEnvironment()
        env.evaluate(Candidate(b"x"))
        result = env.finalize()

        self.assertEqual(result.accepted_count, 1)
        self.assertEqual(result.rejected_count, 0)
        self.assertEqual(len(result.transcript_hash), 64)
        self.assertEqual(len(result.leakage_hash), 64)
        self.assertEqual(result.attestation["security_tier"], SecurityTier.INTERNAL_TEE.value)
        public = result.to_public_dict()
        self.assertNotIn("raw_count", str(public))
        self.assertNotIn("payload", str(public))

    def test_leakage_budget_fails_closed_on_public_precision(self):
        with self.assertRaisesRegex(ValueError, "public reward precision"):
            LeakageBudget(
                max_queries=1,
                feedback_mode=FeedbackMode.BAND,
                reward_precision_bits=8,
            )

    def test_reducer_candidate_hash_mismatch_fails_closed(self):
        class MismatchedReducerEnvironment(ToyPrivateRewardEnvironment):
            def output_reducer(self, reward: InternalReward) -> BoundedFeedback:
                return BoundedFeedback(
                    candidate_hash="not-the-candidate",
                    decision=Decision.PASS,
                    feedback_mode=FeedbackMode.BAND,
                    reward_band=RewardBand.HIGH,
                )

        env = MismatchedReducerEnvironment()

        with self.assertRaisesRegex(ValueError, "candidate_hash mismatch"):
            env.evaluate(Candidate(b"x"))

    def test_external_optimizer_is_bounded_by_default(self):
        env = ToyPrivateRewardEnvironment()
        env.evaluate(Candidate(b"xxx"))

        self.assertEqual(env.optimizer_policy.location, OptimizerLocation.EXTERNAL)
        self.assertFalse(env.optimizer_policy.allow_exact_rewards)
        with self.assertRaisesRegex(PermissionError, "forbids exact rewards"):
            env.internal_reward_for_optimizer()

        view = env.optimizer_view()
        self.assertEqual(view["optimizer_policy"]["location"], OptimizerLocation.EXTERNAL.value)
        self.assertNotIn("0.3", str(view))
        self.assertNotIn("raw_count", str(view))
        self.assertNotIn("xxx", str(view))

    def test_external_optimizer_policy_rejects_reward_derived_state(self):
        with self.assertRaisesRegex(ValueError, "external optimizers"):
            OptimizerPolicy(
                location=OptimizerLocation.EXTERNAL,
                allow_exact_rewards=True,
            )
        with self.assertRaisesRegex(ValueError, "external optimizers"):
            OptimizerPolicy(
                location=OptimizerLocation.EXTERNAL,
                allow_reward_derived_state=True,
            )
        with self.assertRaisesRegex(ValueError, "external optimizers"):
            OptimizerPolicy(
                location=OptimizerLocation.EXTERNAL,
                allow_private_checkpoints=True,
            )

    def test_transcript_chain_is_driven_live_and_attested(self):
        env = ToyPrivateRewardEnvironment()
        genesis = env.transcript_chain_head
        env.evaluate(Candidate(b"aaa"))
        env.evaluate(Candidate(b"bbbb"))
        env.evaluate(Candidate(b"ccccc"))
        # The chain advanced off genesis and verifies as append-only.
        self.assertNotEqual(env.transcript_chain_head, genesis)
        self.assertTrue(env.verify_transcript_chain())
        # The head is published in the attestation (and its bounded dict).
        attest = env.attest()
        self.assertEqual(attest.transcript_chain_head, env.transcript_chain_head)
        self.assertEqual(
            attest.to_public_dict()["transcript_chain_head"], env.transcript_chain_head
        )

    def test_transcript_chain_head_is_deterministic_across_identical_runs(self):
        a, b = ToyPrivateRewardEnvironment(), ToyPrivateRewardEnvironment()
        for payload in (b"aaa", b"bbbb", b"ccccc"):
            a.evaluate(Candidate(payload))
            b.evaluate(Candidate(payload))
        self.assertEqual(a.transcript_chain_head, b.transcript_chain_head)

    def test_rejections_also_extend_the_transcript_chain(self):
        env = ToyPrivateRewardEnvironment()
        env.evaluate(Candidate(b"aaa"))
        head_after_one = env.transcript_chain_head
        # An oversized candidate is policy-rejected but still logged to the chain.
        env.evaluate(Candidate(b"x" * 999))
        self.assertNotEqual(env.transcript_chain_head, head_after_one)
        self.assertTrue(env.verify_transcript_chain())

    def test_internal_dense_optimizer_can_read_exact_reward_inside_boundary(self):
        env = InternalDenseRewardEnvironment()

        public_feedback = env.evaluate(Candidate(b"xxx"))
        reward = env.internal_reward_for_optimizer()

        self.assertEqual(reward.value, 0.3)
        self.assertEqual(reward.metrics["raw_count"], 7)
        self.assertEqual(public_feedback.reward_band, RewardBand.HIGH)
        self.assertNotIn("0.3", str(public_feedback.to_public_dict()))
        self.assertEqual(env.attest().optimizer_location, OptimizerLocation.INTERNAL_TEE)
        self.assertEqual(len(env.attest().optimizer_policy_hash), 64)

    def test_attested_remote_dense_policy_requires_attestation(self):
        with self.assertRaisesRegex(ValueError, "requires attestation"):
            OptimizerPolicy(
                location=OptimizerLocation.ATTESTED_REMOTE,
                allow_exact_rewards=True,
                require_attestation=False,
            )

        policy = OptimizerPolicy.attested_remote_dense()

        self.assertEqual(policy.location, OptimizerLocation.ATTESTED_REMOTE)
        self.assertTrue(policy.allow_exact_rewards)
        self.assertTrue(policy.require_attestation)


if __name__ == "__main__":
    unittest.main()
