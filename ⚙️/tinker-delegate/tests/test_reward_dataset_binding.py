"""Point (2) of the third-party mechanism audit: bind a run to its sealed dataset.

A buyer holding the published sealed-dataset manifest must be able to confirm the
run consumed *that exact committed dataset* — without any plaintext — via the
`manifest_hash` commitment the run records in its provenance.
"""
import copy
import unittest

from tinker_delegate.private_reward import assert_bounded_egress
from tinker_delegate.run_verification import verify_reward_dataset_binding
from tinker_delegate.sealed_dataset import (
    DataSensitivity,
    generate_recipient_keypair,
    manifest_hash,
    seal_dataset,
    sign_manifest,
)

_SIGNER_KEY = "22" * 32


def _sealed(dataset_id="d1", body=b'{"x":1}'):
    _priv, pub = generate_recipient_keypair()
    _blob, manifest, _rcpt = seal_dataset(
        body,
        dataset_id=dataset_id,
        task="denoise",
        data_sensitivity=DataSensitivity.PUBLIC_BENCHMARK,
        recipient_public_keys=[pub],
    )
    return manifest


def _provenance_for(manifest):
    return {
        "sealed_dataset_provenance": {
            "dataset_id": manifest["dataset_id"],
            "publish_ciphertext_sha256": manifest["ciphertext_sha256"],
            "manifest_hash": manifest_hash(manifest),
        }
    }


class RewardDatasetBindingTest(unittest.TestCase):
    def test_correct_manifest_binds_and_is_bounded(self):
        manifest = _sealed()
        verdict = verify_reward_dataset_binding(_provenance_for(manifest), manifest)
        self.assertTrue(verdict["dataset_binding_verified"])
        self.assertEqual(verdict["reason_code"], "dataset_binding_verified")
        self.assertEqual(verdict["explanation"]["disposition"], "allowed")
        assert_bounded_egress(verdict)

    def test_signed_manifest_binds_with_expected_signer(self):
        from eth_account import Account

        manifest = _sealed()
        signed, _receipt = sign_manifest(manifest, _SIGNER_KEY)
        packet = _provenance_for(signed)  # signing does not change manifest_hash
        signer = Account.from_key(_SIGNER_KEY).address
        verdict = verify_reward_dataset_binding(packet, signed, expected_signer=signer)
        self.assertTrue(verdict["dataset_binding_verified"])
        self.assertTrue(verdict["owner_signature_verified"])

    def test_wrong_expected_signer_fails_closed(self):
        manifest = _sealed()
        signed, _r = sign_manifest(manifest, _SIGNER_KEY)
        packet = _provenance_for(signed)
        verdict = verify_reward_dataset_binding(
            packet, signed, expected_signer="0x000000000000000000000000000000000000dEaD"
        )
        self.assertFalse(verdict["dataset_binding_verified"])
        self.assertEqual(verdict["reason_code"], "dataset_manifest_invalid")

    def test_manifest_for_different_dataset_fails(self):
        run_manifest = _sealed(dataset_id="d1")
        other_manifest = _sealed(dataset_id="d2")
        verdict = verify_reward_dataset_binding(
            _provenance_for(run_manifest), other_manifest
        )
        self.assertFalse(verdict["dataset_binding_verified"])
        self.assertEqual(verdict["reason_code"], "dataset_commitment_mismatch")

    def test_tampered_manifest_fails(self):
        manifest = _sealed()
        packet = _provenance_for(manifest)  # commitment made against the clean manifest
        tampered = copy.deepcopy(manifest)
        tampered["task"] = "exfiltrate"
        verdict = verify_reward_dataset_binding(packet, tampered)
        self.assertFalse(verdict["dataset_binding_verified"])
        self.assertEqual(verdict["reason_code"], "dataset_commitment_mismatch")

    def test_missing_provenance_fails_closed(self):
        manifest = _sealed()
        verdict = verify_reward_dataset_binding({}, manifest)
        self.assertEqual(verdict["reason_code"], "missing_dataset_commitment")

    def test_provenance_lying_about_dataset_id_fails(self):
        # Commitment hash is correct, but the run's own provenance misdeclares the
        # dataset id — a valid manifest for the committed data cannot cover a lie.
        manifest = _sealed(dataset_id="d1")
        packet = _provenance_for(manifest)
        packet["sealed_dataset_provenance"]["dataset_id"] = "not-d1"
        verdict = verify_reward_dataset_binding(packet, manifest)
        self.assertFalse(verdict["dataset_binding_verified"])
        self.assertEqual(verdict["reason_code"], "dataset_provenance_mismatch")

    def test_real_sealed_demo_packet_carries_commitment(self):
        from tinker_delegate.private_reward_envs.denoising_sealed_demo import (
            run_denoising_sealed_dataset_demo,
        )

        packet = run_denoising_sealed_dataset_demo()
        commitment = packet["sealed_dataset_provenance"].get("manifest_hash")
        self.assertTrue(commitment)
        # Without the manifest in hand, a verifier can't bind — fails closed rather
        # than trusting the packet's self-declared provenance.
        verdict = verify_reward_dataset_binding(packet, {})
        self.assertFalse(verdict["dataset_binding_verified"])


if __name__ == "__main__":
    unittest.main()
