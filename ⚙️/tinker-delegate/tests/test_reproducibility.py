import dataclasses
import json
import unittest

from tinker_delegate.private_reward import RewardBand, RewardLeakageError
from tinker_delegate.private_reward_envs.bio_assay import (
    BioAssayCandidateSource,
    BioAssayRewardEnvironment,
)
from tinker_delegate.private_reward_loop import (
    HillClimbOptimizer,
    run_private_reward_loop,
)
from tinker_delegate.reproducibility import (
    ReproducibilityCertificate,
    RunConfig,
    build_reproducibility_certificate,
    certify_loop_run,
    hash_code_identity,
    verify_reproducibility_certificate,
)


def _run_config() -> RunConfig:
    return RunConfig(
        optimizer_name="hill_climb",
        model_base="none",
        hyperparameters={"learning_rate": 0.001, "budget": 16},
        random_seeds=(7, 42),
        max_rounds=16,
        target_band="high",
    )


class ReproducibilityCertificateTest(unittest.TestCase):
    def test_certify_loop_run_is_bounded_and_verifies(self):
        env = BioAssayRewardEnvironment(max_queries=16)
        optimizer = HillClimbOptimizer(BioAssayCandidateSource(), budget=16)
        outcome = run_private_reward_loop(env, optimizer, max_rounds=16, target_band=RewardBand.HIGH)
        cert = certify_loop_run(
            outcome,
            run_config=_run_config(),
            environment=env,
            code_hash=hash_code_identity("BioAssayRewardEnvironment", "z_prime_factor"),
        )
        self.assertIsInstance(cert, ReproducibilityCertificate)
        self.assertTrue(verify_reproducibility_certificate(cert))
        self.assertEqual(cert.result_hash, outcome.loop_transcript_hash)
        self.assertEqual(cert.data_commitment, env.environment_hash)
        self.assertFalse(cert.raw_secret_egress)
        # By default the proof-carrying transcript commitment is bound in.
        self.assertRegex(cert.transcript_commitment_hash, r"^[0-9a-f]{64}$")

    def test_transcript_binding_matches_the_rebuilt_commitment(self):
        from tinker_delegate.reward_transcript import RewardTranscript

        env = BioAssayRewardEnvironment(max_queries=16)
        optimizer = HillClimbOptimizer(BioAssayCandidateSource(), budget=16)
        outcome = run_private_reward_loop(env, optimizer, max_rounds=16, target_band=RewardBand.HIGH)
        cert = certify_loop_run(
            outcome,
            run_config=_run_config(),
            environment=env,
            code_hash=hash_code_identity("BioAssayRewardEnvironment", "z_prime_factor"),
        )
        rebuilt = RewardTranscript.build(
            outcome,
            environment_hash=env.environment_hash,
            transcript_chain_head=env.transcript_chain_head,
        )
        self.assertEqual(cert.transcript_commitment_hash, rebuilt.commitment.commitment_hash)
        # Opting out leaves the binding empty but the certificate still verifies.
        cert_unbound = certify_loop_run(
            outcome,
            run_config=_run_config(),
            environment=env,
            code_hash=hash_code_identity("BioAssayRewardEnvironment", "z_prime_factor"),
            bind_transcript=False,
        )
        self.assertEqual(cert_unbound.transcript_commitment_hash, "")
        self.assertTrue(verify_reproducibility_certificate(cert_unbound))
        self.assertNotEqual(cert.certificate_hash, cert_unbound.certificate_hash)

    def test_hyperparameter_floats_do_not_leak(self):
        cert = build_reproducibility_certificate(
            run_config=_run_config(),
            data_commitment="0x" + "ab" * 32,
            code_hash="0x" + "cd" * 32,
            result_hash="0x" + "ef" * 32,
        )
        blob = json.dumps(cert.to_public_dict())
        self.assertNotIn("0.001", blob)  # learning rate value never appears
        self.assertNotIn("learning_rate", blob)  # hyperparameter names stay internal
        self.assertNotIn("random_seeds", blob)  # seeds fold into run_config_hash only

    def test_certificate_is_deterministic(self):
        kwargs = dict(
            run_config=_run_config(),
            data_commitment="0x" + "ab" * 32,
            code_hash="0x" + "cd" * 32,
            result_hash="0x" + "ef" * 32,
        )
        self.assertEqual(
            build_reproducibility_certificate(**kwargs).certificate_hash,
            build_reproducibility_certificate(**kwargs).certificate_hash,
        )

    def test_tampering_is_detected(self):
        cert = build_reproducibility_certificate(
            run_config=_run_config(),
            data_commitment="0x" + "ab" * 32,
            code_hash="0x" + "cd" * 32,
            result_hash="0x" + "ef" * 32,
        )
        tampered = dataclasses.replace(cert, result_hash="0x" + "99" * 32)
        self.assertFalse(verify_reproducibility_certificate(tampered))

    def test_every_bound_field_tamper_is_detected(self):
        # Completeness of the binding: tampering ANY semantically-meaningful field
        # must fail verification. This guards against a future field being added to
        # the certificate but forgotten in `_certificate_hash` (an unbound field
        # would be silently tamperable). `raw_secret_egress` is a fixed audit flag
        # verify relies on nothing for, so it is intentionally excluded.
        cert = build_reproducibility_certificate(
            run_config=_run_config(),
            data_commitment="0x" + "ab" * 32,
            code_hash="0x" + "cd" * 32,
            result_hash="0x" + "ef" * 32,
            transcript_commitment_hash="0x" + "12" * 32,
        )
        bound_fields = {
            "run_config_hash": "0x" + "01" * 32,
            "data_commitment": "0x" + "02" * 32,
            "code_hash": "0x" + "03" * 32,
            "model_base": "tampered-model",
            "result_hash": "0x" + "04" * 32,
            "attestation_quote_hash": "0x" + "05" * 32,
            "transcript_commitment_hash": "0x" + "06" * 32,
        }
        # Sanity: the untampered certificate verifies.
        self.assertTrue(verify_reproducibility_certificate(cert))
        for field, new_value in bound_fields.items():
            with self.subTest(field=field):
                tampered = dataclasses.replace(cert, **{field: new_value})
                self.assertFalse(
                    verify_reproducibility_certificate(tampered),
                    f"tampering {field} was not detected — it may be unbound",
                )

    def test_config_change_changes_config_hash(self):
        base = _run_config().config_hash()
        changed = dataclasses.replace(_run_config(), random_seeds=(1, 2)).config_hash()
        self.assertNotEqual(base, changed)

    def test_attestation_quote_binds_into_certificate(self):
        quote = "0x" + "77" * 32
        with_quote = build_reproducibility_certificate(
            run_config=_run_config(),
            data_commitment="0x" + "ab" * 32,
            code_hash="0x" + "cd" * 32,
            result_hash="0x" + "ef" * 32,
            attestation_quote_hash=quote,
        )
        without = build_reproducibility_certificate(
            run_config=_run_config(),
            data_commitment="0x" + "ab" * 32,
            code_hash="0x" + "cd" * 32,
            result_hash="0x" + "ef" * 32,
        )
        self.assertEqual(with_quote.attestation_quote_hash, quote)
        self.assertNotEqual(with_quote.certificate_hash, without.certificate_hash)


if __name__ == "__main__":
    unittest.main()
