import json
import unittest

from tinker_delegate.private_reward import RewardBand
from tinker_delegate.private_reward_envs.bio_assay_program_demo import (
    bio_assay_program_demo_forbidden_values,
    run_bio_assay_program_reward_demo,
)
from tinker_delegate.private_reward_loop import band_rank
from tinker_delegate.reproducibility import (
    ReproducibilityCertificate,
    verify_reproducibility_certificate,
)


class BioAssayProgramDemoTest(unittest.TestCase):
    def test_demo_is_bounded_and_hides_sealed_readings(self):
        result = run_bio_assay_program_reward_demo()
        self.assertEqual(result["demo"], "bio_assay_program_qc")
        self.assertFalse(result["raw_secret_egress"])
        blob = json.dumps(result, default=str)
        for forbidden in bio_assay_program_demo_forbidden_values():
            if len(forbidden) >= 4:
                self.assertNotIn(forbidden, blob)

    def test_robust_program_outscores_passthrough(self):
        result = run_bio_assay_program_reward_demo()
        by_label = {row["candidate_label"]: row["reward_band"] for row in result["feedback"]}
        passthrough = RewardBand(by_label["passthrough"])
        mad = RewardBand(by_label["mad_filter"])
        self.assertGreater(band_rank(mad), band_rank(passthrough))
        self.assertGreaterEqual(band_rank(mad), band_rank(RewardBand.HIGH))

    def test_demo_is_deterministic(self):
        first = run_bio_assay_program_reward_demo()
        second = run_bio_assay_program_reward_demo()
        self.assertEqual(
            first["final_result"]["transcript_hash"],
            second["final_result"]["transcript_hash"],
        )

    def test_forbidden_values_cover_outliers(self):
        forbidden = bio_assay_program_demo_forbidden_values()
        self.assertIn("140.0", forbidden)
        self.assertIn("40.0", forbidden)

    def test_demo_emits_verifiable_reproducibility_certificate(self):
        result = run_bio_assay_program_reward_demo()
        cert_dict = result["reproducibility_certificate"]
        self.assertEqual(cert_dict["kind"], "reproducibility_certificate")
        self.assertEqual(cert_dict["result_hash"], result["final_result"]["transcript_hash"])
        self.assertFalse(cert_dict["raw_secret_egress"])
        cert = ReproducibilityCertificate(
            run_config_hash=cert_dict["run_config_hash"],
            data_commitment=cert_dict["data_commitment"],
            code_hash=cert_dict["code_hash"],
            model_base=cert_dict["model_base"],
            result_hash=cert_dict["result_hash"],
            attestation_quote_hash=cert_dict["attestation_quote_hash"],
            transcript_commitment_hash=cert_dict["transcript_commitment_hash"],
            certificate_hash=cert_dict["certificate_hash"],
        )
        self.assertTrue(verify_reproducibility_certificate(cert))
        # The certificate binds the run's proof-carrying transcript commitment.
        self.assertEqual(
            cert_dict["transcript_commitment_hash"],
            result["reward_transcript_commitment"]["commitment_hash"],
        )

    def test_certificate_is_deterministic_across_runs(self):
        first = run_bio_assay_program_reward_demo()["reproducibility_certificate"]
        second = run_bio_assay_program_reward_demo()["reproducibility_certificate"]
        self.assertEqual(first["certificate_hash"], second["certificate_hash"])

    def test_demo_emits_proof_carrying_reward_transcript(self):
        from tinker_delegate.reward_transcript import (
            RewardTranscript,
            leaf_hash,
            merkle_root,
            verify_round_in_commitment,
        )

        result = run_bio_assay_program_reward_demo()
        commitment = result["reward_transcript_commitment"]
        self.assertEqual(commitment["surface"], "reward_transcript_commitment")
        self.assertFalse(commitment["raw_secret_egress"])
        self.assertEqual(commitment["round_count"], result["submitted_candidate_count"])
        self.assertEqual(
            commitment["final_result_hash"], result["final_result"]["transcript_hash"]
        )
        self.assertRegex(commitment["transcript_root"], r"^[0-9a-f]{64}$")
        # The env's live append-only chain head is bound into the commitment.
        self.assertRegex(commitment["transcript_chain_head"], r"^[0-9a-f]{64}$")

        # The commitment genuinely commits the emitted per-candidate feedback:
        # recompute the root from the feedback leaves and generate a working
        # inclusion proof for each candidate against the emitted root.
        recomputed_root = merkle_root([leaf_hash(row) for row in result["feedback"]])
        self.assertEqual(recomputed_root, commitment["transcript_root"])

        transcript = RewardTranscript.from_round_dicts(
            result["feedback"],
            environment_hash=commitment["environment_hash"],
            final_result_hash=commitment["final_result_hash"],
        )
        for idx in range(len(result["feedback"])):
            proof = transcript.prove(idx)
            self.assertTrue(verify_round_in_commitment(proof, transcript.commitment))

    def test_reward_transcript_commitment_is_deterministic(self):
        first = run_bio_assay_program_reward_demo()["reward_transcript_commitment"]
        second = run_bio_assay_program_reward_demo()["reward_transcript_commitment"]
        self.assertEqual(first["commitment_hash"], second["commitment_hash"])


if __name__ == "__main__":
    unittest.main()
