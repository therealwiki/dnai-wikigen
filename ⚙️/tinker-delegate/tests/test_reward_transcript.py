import json
import unittest

from tinker_delegate.private_reward import FeedbackMode, LeakageBudget
from tinker_delegate.private_reward_envs.synthetic import SyntheticHiddenKeywordEnvironment
from tinker_delegate.private_reward_holdout import HoldoutSplitPolicy
from tinker_delegate.private_reward_loop import (
    HillClimbOptimizer,
    PoolCandidateSource,
    run_private_reward_loop,
)
from tinker_delegate.reward_transcript import (
    RewardTranscript,
    _EMPTY_ROOT,
    leaf_hash,
    merkle_proof,
    merkle_root,
    verify_round_in_commitment,
)


_RECORDS = {f"rec-{i}": f"the alpha marker {i}".encode("utf-8") for i in range(10)}
_POOL = [b"beta", b"gamma", b"alpha", b"delta"]


def _make_env(max_queries: int = 16) -> SyntheticHiddenKeywordEnvironment:
    policy = HoldoutSplitPolicy(max_reward_queries=max_queries)
    return SyntheticHiddenKeywordEnvironment(
        _RECORDS,
        holdout_policy=policy,
        query_budget=LeakageBudget(max_queries=max_queries, feedback_mode=FeedbackMode.BAND),
    )


def _run():
    env = _make_env()
    optimizer = HillClimbOptimizer(PoolCandidateSource(_POOL), budget=8)
    return env, run_private_reward_loop(env, optimizer, max_rounds=8)


class MerkleTreeTest(unittest.TestCase):
    def test_root_is_deterministic_and_order_sensitive(self):
        leaves = [leaf_hash({"i": i}) for i in range(5)]
        self.assertEqual(merkle_root(leaves), merkle_root(list(leaves)))
        self.assertNotEqual(merkle_root(leaves), merkle_root(list(reversed(leaves))))

    def test_empty_root_is_domain_separated_constant(self):
        self.assertEqual(merkle_root([]), _EMPTY_ROOT)

    def test_single_leaf_root_is_the_leaf(self):
        leaves = [leaf_hash({"only": 1})]
        self.assertEqual(merkle_root(leaves), leaves[0])

    def test_proof_verifies_for_every_index_including_odd_counts(self):
        for n in (1, 2, 3, 4, 5, 7, 8):
            leaves = [leaf_hash({"i": i}) for i in range(n)]
            root = merkle_root(leaves)
            for idx in range(n):
                path = merkle_proof(leaves, idx)
                # Rebuild the root from the leaf + path.
                from tinker_delegate.reward_transcript import _root_from_path

                self.assertEqual(_root_from_path(leaves[idx], path), root, f"n={n} idx={idx}")

    def test_proof_out_of_range_raises(self):
        leaves = [leaf_hash({"i": 0})]
        with self.assertRaises(IndexError):
            merkle_proof(leaves, 3)

    def test_duplicate_last_node_malleability_is_documented(self):
        # Documents the exact security profile of this primitive so the invariant
        # is explicit: duplicate-last-node makes roots collide ACROSS lengths
        # (`[A,B,C]` == `[A,B,C,C]`), so a commitment MUST also bind the leaf
        # count. Same-length distinct leaf lists cannot collide (would need a
        # SHA-256 collision), which is why binding round_count fully mitigates it.
        leaves = [leaf_hash({"i": i}) for i in range(3)]
        malleated = leaves + [leaves[-1]]
        self.assertEqual(merkle_root(leaves), merkle_root(malleated))
        # Same length, different content -> different root.
        other = [leaf_hash({"i": i}) for i in range(2)] + [leaf_hash({"i": 99})]
        self.assertNotEqual(merkle_root(leaves), merkle_root(other))


class RewardTranscriptTest(unittest.TestCase):
    def test_build_binds_chain_and_round_count(self):
        env, outcome = _run()
        transcript = RewardTranscript.build(
            outcome,
            environment_hash=env.environment_hash,
            quote=b"tdx-quote-bytes",
            chain_event={"event": "settled", "block": 100},
        )
        c = transcript.commitment
        self.assertEqual(c.round_count, outcome.rounds_run)
        self.assertEqual(c.environment_hash, env.environment_hash)
        self.assertEqual(c.final_result_hash, outcome.loop_transcript_hash)
        self.assertTrue(c.quote_hash)
        self.assertTrue(c.chain_event_hash)
        self.assertRegex(c.commitment_hash, r"^[0-9a-f]{64}$")

    def test_chain_head_is_bound_into_commitment(self):
        env, outcome = _run()
        base = RewardTranscript.build(outcome, environment_hash=env.environment_hash)
        with_head = RewardTranscript.build(
            outcome,
            environment_hash=env.environment_hash,
            transcript_chain_head=env.transcript_chain_head,
        )
        # The env's live chain head is recorded and binds the commitment hash.
        self.assertEqual(with_head.commitment.transcript_chain_head, env.transcript_chain_head)
        self.assertTrue(env.transcript_chain_head)
        self.assertNotEqual(base.commitment.commitment_hash, with_head.commitment.commitment_hash)
        # Same transcript root though — only the binding differs.
        self.assertEqual(base.commitment.transcript_root, with_head.commitment.transcript_root)

    def test_inclusion_proof_verifies_against_commitment(self):
        env, outcome = _run()
        transcript = RewardTranscript.build(outcome, environment_hash=env.environment_hash)
        for idx in range(transcript.round_count):
            proof = transcript.prove(idx)
            self.assertTrue(proof.verify())
            self.assertTrue(verify_round_in_commitment(proof, transcript.commitment))

    def test_tampered_leaf_fails_verification(self):
        env, outcome = _run()
        transcript = RewardTranscript.build(outcome, environment_hash=env.environment_hash)
        proof = transcript.prove(0)
        forged = proof.__class__(
            round_index=proof.round_index,
            leaf_hash=leaf_hash({"round_index": 0, "forged": True}),
            audit_path=proof.audit_path,
            transcript_root=proof.transcript_root,
        )
        self.assertFalse(forged.verify())
        self.assertFalse(verify_round_in_commitment(forged, transcript.commitment))

    def test_proof_from_one_run_does_not_verify_against_another_root(self):
        env_a, outcome_a = _run()
        env_b, outcome_b = _run()
        ta = RewardTranscript.build(outcome_a, environment_hash=env_a.environment_hash)
        tb = RewardTranscript.build(outcome_b, environment_hash=env_b.environment_hash)
        proof_a = ta.prove(0)
        # Same round data across identical runs yields the same root, so force a
        # mismatch by checking a proof whose root differs from the commitment.
        mismatched = proof_a.__class__(
            round_index=proof_a.round_index,
            leaf_hash=proof_a.leaf_hash,
            audit_path=proof_a.audit_path,
            transcript_root="00" * 32,
        )
        self.assertFalse(verify_round_in_commitment(mismatched, tb.commitment))

    def test_public_dicts_are_bounded(self):
        from tinker_delegate.private_reward import assert_bounded_egress

        env, outcome = _run()
        transcript = RewardTranscript.build(
            outcome, environment_hash=env.environment_hash, quote=b"q"
        )
        commitment_public = transcript.certified_public_export()
        assert_bounded_egress(commitment_public)
        proof_public = transcript.prove(0).to_public_dict()
        assert_bounded_egress(proof_public)
        # No candidate payloads or raw values, only hashes/counts.
        blob = json.dumps(commitment_public) + json.dumps(proof_public)
        self.assertNotIn("alpha", blob)
        self.assertFalse(commitment_public["raw_secret_egress"])

    def test_empty_transcript_has_empty_root(self):
        class _Empty:
            rounds = ()
            loop_transcript_hash = "deadbeef"

        transcript = RewardTranscript.build(_Empty(), environment_hash="envhash")
        self.assertEqual(transcript.round_count, 0)
        self.assertEqual(transcript.commitment.transcript_root, _EMPTY_ROOT)
        with self.assertRaises(IndexError):
            transcript.prove(0)


if __name__ == "__main__":
    unittest.main()
