import copy
import unittest

from tinker_delegate.private_reward_envs.bio_assay_program_demo import (
    run_bio_assay_program_reward_demo,
)
from tinker_delegate.run_verification import verify_reward_run


class VerifyRewardRunTest(unittest.TestCase):
    def setUp(self):
        self.packet = run_bio_assay_program_reward_demo()

    def test_real_demo_packet_verifies_end_to_end(self):
        verdict = verify_reward_run(self.packet)
        self.assertTrue(verdict["verified"], verdict)
        self.assertTrue(verdict["certificate_verified"])
        self.assertTrue(verdict["commitment_recomputed"])
        self.assertTrue(verdict["binding_matches"])
        self.assertEqual(verdict["reason_code"], "run_verified")
        self.assertFalse(verdict["raw_secret_egress"])

    def test_all_demos_verify_uniformly(self):
        from tinker_delegate.private_reward_envs.denoising_demo import (
            run_denoising_holdout_demo,
        )
        from tinker_delegate.private_reward_envs.dp_bounded_demo import (
            run_dp_bounded_reward_demo,
        )
        from tinker_delegate.private_reward_envs.synthetic_demo import (
            run_synthetic_hidden_keyword_demo,
        )

        for packet in (
            run_synthetic_hidden_keyword_demo(),
            run_denoising_holdout_demo(),
            run_bio_assay_program_reward_demo(),
            run_dp_bounded_reward_demo(),
        ):
            with self.subTest(demo=packet["demo"]):
                verdict = verify_reward_run(packet)
                self.assertTrue(verdict["verified"], verdict)
                self.assertEqual(verdict["reason_code"], "run_verified")

    def test_verdict_is_self_explaining(self):
        # The verdict carries a bounded, leak-free explanation of its reason code.
        verdict = verify_reward_run(self.packet)
        self.assertIn("explanation", verdict)
        self.assertEqual(verdict["explanation"]["disposition"], "allowed")
        # A failing verdict explains the failure category.
        packet = copy.deepcopy(self.packet)
        packet["reproducibility_certificate"]["code_hash"] = "0x" + "11" * 32
        failed = verify_reward_run(packet)
        self.assertEqual(failed["explanation"]["category"], "verification")
        self.assertEqual(failed["explanation"]["disposition"], "denied")

    def test_tampered_certificate_hash_fails(self):
        packet = copy.deepcopy(self.packet)
        packet["reproducibility_certificate"]["code_hash"] = "0x" + "11" * 32
        verdict = verify_reward_run(packet)
        self.assertFalse(verdict["verified"])
        self.assertEqual(verdict["reason_code"], "certificate_hash_mismatch")

    def test_tampered_commitment_root_fails(self):
        packet = copy.deepcopy(self.packet)
        packet["reward_transcript_commitment"]["transcript_root"] = "ab" * 32
        verdict = verify_reward_run(packet)
        self.assertFalse(verdict["verified"])
        self.assertEqual(verdict["reason_code"], "commitment_hash_mismatch")

    def test_broken_binding_fails(self):
        # Swap in a self-consistent commitment whose hash no longer matches the
        # certificate's bound hash: certificate + commitment each verify alone,
        # but the binding between them is broken.
        packet = copy.deepcopy(self.packet)
        other = run_bio_assay_program_reward_demo(
            programs=[("passthrough", "def process(p, n):\n    return (p, n)")]
        )
        packet["reward_transcript_commitment"] = other["reward_transcript_commitment"]
        verdict = verify_reward_run(packet)
        self.assertFalse(verdict["verified"])
        self.assertTrue(verdict["certificate_verified"])
        self.assertTrue(verdict["commitment_recomputed"])
        self.assertFalse(verdict["binding_matches"])
        self.assertEqual(verdict["reason_code"], "binding_mismatch")

    def test_cert_commitment_reattached_to_wrong_body_fails_closed(self):
        # A valid, mutually-bound cert+commitment from a DIFFERENT run cannot be
        # spliced onto this packet's final_result/attestation and still verify.
        packet = copy.deepcopy(self.packet)
        other = run_bio_assay_program_reward_demo(
            programs=[
                ("passthrough", "def process(p, n):\n    return (p, n)"),
                ("drop", "def process(p, n):\n    return (sorted(p)[1:], sorted(n)[1:])"),
            ]
        )
        # Splice the other run's (internally consistent, mutually bound) pair in.
        packet["reproducibility_certificate"] = other["reproducibility_certificate"]
        packet["reward_transcript_commitment"] = other["reward_transcript_commitment"]
        verdict = verify_reward_run(packet)
        self.assertFalse(verdict["verified"])
        # cert verifies, commitment recomputes, and they bind to each other...
        self.assertTrue(verdict["certificate_verified"])
        self.assertTrue(verdict["commitment_recomputed"])
        self.assertTrue(verdict["binding_matches"])
        # ...but they don't match this packet's own final_result/attestation.
        self.assertFalse(verdict["packet_consistent"])
        self.assertEqual(verdict["reason_code"], "packet_inconsistent")

    def test_tampered_feedback_record_fails_closed(self):
        # The commitment is untouched, but a per-round feedback record is altered
        # so it no longer hashes to the committed Merkle root.
        packet = copy.deepcopy(self.packet)
        self.assertTrue(packet["feedback"])
        packet["feedback"][0] = dict(packet["feedback"][0], reward_band="exceptional")
        verdict = verify_reward_run(packet)
        self.assertFalse(verdict["verified"])
        self.assertTrue(verdict["certificate_verified"])
        self.assertTrue(verdict["commitment_recomputed"])
        self.assertFalse(verdict["packet_consistent"])
        self.assertEqual(verdict["reason_code"], "packet_inconsistent")

    def test_dropped_feedback_record_fails_closed(self):
        packet = copy.deepcopy(self.packet)
        packet["feedback"] = packet["feedback"][:-1]  # round_count no longer matches
        verdict = verify_reward_run(packet)
        self.assertFalse(verdict["verified"])
        self.assertEqual(verdict["reason_code"], "packet_inconsistent")

    def test_real_demo_feedback_is_leakage_bounded(self):
        verdict = verify_reward_run(self.packet)
        self.assertTrue(verdict["feedback_bounded"])

    def test_smuggled_reward_float_in_feedback_fails_closed(self):
        # A verifier must not bless a packet that leaks an exact reward value in a
        # per-round record, even if every hash still binds. Here we smuggle a float
        # AND repair the Merkle root + round_count so the binding checks all pass,
        # isolating the leakage gate as the thing that catches it.
        from tinker_delegate.reward_transcript import leaf_hash, merkle_root

        packet = copy.deepcopy(self.packet)
        packet["feedback"][0] = dict(packet["feedback"][0], exact_reward=0.9731)
        repaired_root = merkle_root([leaf_hash(f) for f in packet["feedback"]])
        packet["reward_transcript_commitment"]["transcript_root"] = repaired_root
        verdict = verify_reward_run(packet)
        self.assertFalse(verdict["verified"])
        self.assertFalse(verdict["feedback_bounded"])
        self.assertEqual(verdict["reason_code"], "packet_leaks")

    def test_smuggled_gradient_array_in_feedback_fails_closed(self):
        packet = copy.deepcopy(self.packet)
        packet["feedback"][0] = dict(
            packet["feedback"][0], grad=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        )
        verdict = verify_reward_run(packet)
        self.assertFalse(verdict["verified"])
        self.assertFalse(verdict["feedback_bounded"])
        self.assertEqual(verdict["reason_code"], "packet_leaks")

    def test_merkle_malleated_feedback_rejected_by_round_count(self):
        # The Merkle primitive has duplicate-last-node malleability: appending a
        # copy of the final round record yields the SAME committed root. The
        # round_count binding is the load-bearing mitigation — a malleated
        # feedback list (same root, +1 length) must be rejected as inconsistent.
        # This test names WHY round_count matters so a future refactor weakening
        # it fails here.
        from tinker_delegate.reward_transcript import leaf_hash, merkle_root

        packet = copy.deepcopy(self.packet)
        committed_root = packet["reward_transcript_commitment"]["transcript_root"]
        committed_count = int(packet["reward_transcript_commitment"]["round_count"])
        packet["feedback"] = list(packet["feedback"]) + [
            copy.deepcopy(packet["feedback"][-1])
        ]
        # The malleated list still hashes to the committed root (malleability)...
        self.assertEqual(
            merkle_root([leaf_hash(f) for f in packet["feedback"]]), committed_root
        )
        self.assertNotEqual(len(packet["feedback"]), committed_count)
        # ...but the length no longer matches the committed round_count, so the
        # verifier rejects it. Root equality alone would have let it through.
        verdict = verify_reward_run(packet)
        self.assertFalse(verdict["verified"])
        self.assertFalse(verdict["packet_consistent"])
        self.assertEqual(verdict["reason_code"], "packet_inconsistent")

    def test_missing_artifact_fails_closed(self):
        packet = copy.deepcopy(self.packet)
        del packet["reward_transcript_commitment"]
        verdict = verify_reward_run(packet)
        self.assertFalse(verdict["verified"])
        self.assertEqual(verdict["reason_code"], "missing_artifact")

    def test_empty_packet_fails_closed(self):
        verdict = verify_reward_run({})
        self.assertFalse(verdict["verified"])
        self.assertEqual(verdict["reason_code"], "missing_artifact")


class MechanismAccountingTest(unittest.TestCase):
    """The boundary must not enforce more than its declared policy caps."""

    def setUp(self):
        from tinker_delegate.private_reward_envs.denoising_demo import (
            run_denoising_holdout_demo,
        )

        self.packet = run_denoising_holdout_demo()

    def _holdout(self, packet):
        return packet["final_result"]["attestation"]["holdout"]

    def test_real_packet_accounting_is_consistent(self):
        verdict = verify_reward_run(self.packet)
        self.assertTrue(verdict["mechanism_accounting_consistent"])
        self.assertTrue(verdict["verified"])

    def test_reward_queries_exceeding_declared_cap_fail_closed(self):
        packet = copy.deepcopy(self.packet)
        self._holdout(packet)["reward_query_count"] = 999
        verdict = verify_reward_run(packet)
        self.assertFalse(verdict["verified"])
        self.assertFalse(verdict["mechanism_accounting_consistent"])
        self.assertEqual(verdict["reason_code"], "mechanism_accounting_violation")
        self.assertEqual(verdict["explanation"]["category"], "verification")

    def test_final_validations_exceeding_cap_fail_closed(self):
        packet = copy.deepcopy(self.packet)
        self._holdout(packet)["final_validation_count"] = 5
        verdict = verify_reward_run(packet)
        self.assertEqual(verdict["reason_code"], "mechanism_accounting_violation")

    def test_final_validation_without_closing_reward_queries_fails(self):
        packet = copy.deepcopy(self.packet)
        self._holdout(packet)["closed_to_reward_queries"] = False
        verdict = verify_reward_run(packet)
        self.assertEqual(verdict["reason_code"], "mechanism_accounting_violation")

    def test_unparseable_count_fails_closed(self):
        packet = copy.deepcopy(self.packet)
        self._holdout(packet)["reward_query_count"] = "lots"
        verdict = verify_reward_run(packet)
        self.assertFalse(verdict["mechanism_accounting_consistent"])


class RewardCodeBindingTest(unittest.TestCase):
    """Point (1): the attested code hash must match the source the reader read."""

    def setUp(self):
        from tinker_delegate.private_reward_envs.denoising_demo import (
            run_denoising_holdout_demo,
        )

        self.packet = run_denoising_holdout_demo()

    def test_correct_source_binds(self):
        from tinker_delegate.private_reward_envs import denoising as denoising_mod
        from tinker_delegate.run_verification import verify_reward_code_binding

        verdict = verify_reward_code_binding(self.packet, denoising_mod)
        self.assertTrue(verdict["code_binding_verified"])
        self.assertEqual(verdict["reason_code"], "code_binding_verified")
        self.assertEqual(verdict["explanation"]["disposition"], "allowed")
        # Both hashes are digests, so the verdict is bounded.
        from tinker_delegate.private_reward import assert_bounded_egress

        assert_bounded_egress(verdict)

    def test_wrong_source_fails_closed(self):
        from tinker_delegate.private_reward_envs import synthetic as synthetic_mod
        from tinker_delegate.run_verification import verify_reward_code_binding

        verdict = verify_reward_code_binding(self.packet, synthetic_mod)
        self.assertFalse(verdict["code_binding_verified"])
        self.assertEqual(verdict["reason_code"], "code_hash_mismatch")
        self.assertEqual(verdict["explanation"]["category"], "verification")

    def test_missing_certificate_fails_closed(self):
        from tinker_delegate.private_reward_envs import denoising as denoising_mod
        from tinker_delegate.run_verification import verify_reward_code_binding

        verdict = verify_reward_code_binding({}, denoising_mod)
        self.assertEqual(verdict["reason_code"], "missing_code_hash")

    def test_unreadable_source_fails_closed(self):
        from tinker_delegate.run_verification import verify_reward_code_binding

        for bad in (None, "/nonexistent/path/reward.py"):
            verdict = verify_reward_code_binding(self.packet, bad)
            self.assertFalse(verdict["code_binding_verified"])
            self.assertEqual(verdict["reason_code"], "code_source_unreadable")

    def test_accepts_a_list_of_targets(self):
        from tinker_delegate.private_reward_envs import denoising as denoising_mod
        from tinker_delegate.run_verification import verify_reward_code_binding

        verdict = verify_reward_code_binding(self.packet, [denoising_mod])
        self.assertTrue(verdict["code_binding_verified"])


class MechanismAccountingHelperTest(unittest.TestCase):
    """Direct checks of the ladder/holdout cap logic (no demo exercises ladder)."""

    def _check(self, attestation):
        from tinker_delegate.run_verification import _one_attestation_consistent

        return _one_attestation_consistent(attestation)

    def test_absent_manifests_are_vacuously_consistent(self):
        self.assertTrue(self._check({}))
        self.assertTrue(self._check({"environment_hash": "0xabc"}))

    def test_fixed_eta_ladder_within_caps_passes(self):
        att = {"ladder": {
            "policy": {"step_denominator": 20, "max_improvement_steps": 20, "max_submissions": 100},
            "submission_count": 40, "improvement_count": 12,
            "leaderboard_step_index": 18, "step_denominator": 20,
        }}
        self.assertTrue(self._check(att))

    def test_ladder_too_many_improvement_steps_fails(self):
        # The core Ladder guarantee: <= D genuine improvement steps.
        att = {"ladder": {
            "policy": {"step_denominator": 10, "max_improvement_steps": 10},
            "submission_count": 40, "improvement_count": 11,
            "leaderboard_step_index": 9, "step_denominator": 10,
        }}
        self.assertFalse(self._check(att))

    def test_ladder_index_past_grid_fails(self):
        att = {"ladder": {
            "policy": {"step_denominator": 10, "max_improvement_steps": 10},
            "submission_count": 3, "improvement_count": 1,
            "leaderboard_step_index": 11, "step_denominator": 10,
        }}
        self.assertFalse(self._check(att))

    def test_ladder_submission_budget_exceeded_fails(self):
        att = {"ladder": {
            "policy": {"step_denominator": 10, "max_improvement_steps": 10, "max_submissions": 5},
            "submission_count": 6, "improvement_count": 1,
            "leaderboard_step_index": 3, "step_denominator": 10,
        }}
        self.assertFalse(self._check(att))

    def test_paired_t_ladder_within_grid_passes_and_beyond_fails(self):
        good = {"ladder": {
            "variant": "paired_t", "submission_count": 5, "improvement_count": 2,
            "leaderboard_numerator": 33, "denominator": 50,
        }}
        self.assertTrue(self._check(good))
        bad = {"ladder": {
            "variant": "paired_t", "submission_count": 5, "improvement_count": 6,
            "leaderboard_numerator": 51, "denominator": 50,
        }}
        self.assertFalse(self._check(bad))


if __name__ == "__main__":
    unittest.main()
