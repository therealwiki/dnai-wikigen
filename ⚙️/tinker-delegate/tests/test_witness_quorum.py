"""Neutral sealing-witness M-of-N quorum on a sealed-dataset commitment.

Defeats the "seller crafts data to favor one bidder" collusion: mutually-trusted
notaries co-sign the exact commitment that entered the boundary, and neither side
can later dispute what was sealed. Witnesses never see plaintext.
"""
import copy
import unittest

from eth_account import Account

from tinker_delegate.run_verification import verify_reward_dataset_binding
from tinker_delegate.sealed_dataset import (
    DataSensitivity,
    add_witness_signature,
    generate_recipient_keypair,
    manifest_hash,
    seal_dataset,
    sign_manifest,
    verify_witness_quorum,
)

_WK = ["11" * 32, "22" * 32, "33" * 32]
_ADDRS = [Account.from_key(k).address for k in _WK]


def _sealed(dataset_id="d1"):
    _priv, pub = generate_recipient_keypair()
    _blob, manifest, _rcpt = seal_dataset(
        b'{"x":1}',
        dataset_id=dataset_id,
        task="denoise",
        data_sensitivity=DataSensitivity.PUBLIC_BENCHMARK,
        recipient_public_keys=[pub],
    )
    return manifest


class WitnessQuorumTest(unittest.TestCase):
    def test_signing_does_not_change_the_commitment(self):
        manifest = _sealed()
        before = manifest_hash(manifest)
        manifest, _ = add_witness_signature(manifest, _WK[0])
        manifest, _ = add_witness_signature(manifest, _WK[1])
        self.assertEqual(manifest_hash(manifest), before)

    def test_quorum_met_and_unmet(self):
        manifest = _sealed()
        manifest, _ = add_witness_signature(manifest, _WK[0])
        manifest, _ = add_witness_signature(manifest, _WK[1])
        self.assertTrue(verify_witness_quorum(manifest, authorized_witnesses=_ADDRS, threshold=2)["ok"])
        self.assertFalse(verify_witness_quorum(manifest, authorized_witnesses=_ADDRS, threshold=3)["threshold_met"])

    def test_duplicate_witness_not_double_counted(self):
        manifest = _sealed()
        manifest, _ = add_witness_signature(manifest, _WK[0])
        manifest, _ = add_witness_signature(manifest, _WK[0])  # same witness again
        result = verify_witness_quorum(manifest, authorized_witnesses=_ADDRS, threshold=2)
        self.assertEqual(result["valid_witness_count"], 1)
        self.assertFalse(result["threshold_met"])

    def test_unauthorized_witness_ignored(self):
        manifest = _sealed()
        manifest, _ = add_witness_signature(manifest, _WK[0])
        manifest, _ = add_witness_signature(manifest, "99" * 32)  # not in the authorized set
        result = verify_witness_quorum(manifest, authorized_witnesses=_ADDRS, threshold=2)
        self.assertEqual(result["valid_witness_count"], 1)
        self.assertIn("unauthorized_witness", result["problems"])

    def test_tampering_invalidates_all_signatures(self):
        manifest = _sealed()
        manifest, _ = add_witness_signature(manifest, _WK[0])
        manifest, _ = add_witness_signature(manifest, _WK[1])
        tampered = copy.deepcopy(manifest)
        tampered["task"] = "exfiltrate"  # changes manifest_hash
        result = verify_witness_quorum(tampered, authorized_witnesses=_ADDRS, threshold=1)
        self.assertEqual(result["valid_witness_count"], 0)

    def test_witness_signatures_survive_owner_signing(self):
        manifest = _sealed()
        manifest, _ = add_witness_signature(manifest, _WK[0])
        manifest, _ = add_witness_signature(manifest, _WK[1])
        signed, _ = sign_manifest(manifest, _WK[2])
        self.assertTrue(verify_witness_quorum(signed, authorized_witnesses=_ADDRS, threshold=2)["ok"])

    def test_threshold_must_be_positive_int(self):
        manifest = _sealed()
        for bad in (0, -1, True):
            with self.assertRaises(Exception):
                verify_witness_quorum(manifest, authorized_witnesses=_ADDRS, threshold=bad)

    def test_receipt_is_bounded(self):
        manifest = _sealed()
        manifest, _ = add_witness_signature(manifest, _WK[0])
        result = verify_witness_quorum(manifest, authorized_witnesses=_ADDRS, threshold=1)
        self.assertFalse(result["raw_secret_egress"])
        # No raw witness address leaks — only prefixed hashes.
        for addr in _ADDRS:
            self.assertNotIn(addr.lower(), str(result).lower())


class DatasetBindingWithWitnessQuorumTest(unittest.TestCase):
    def _provenance_for(self, manifest):
        return {
            "sealed_dataset_provenance": {
                "dataset_id": manifest["dataset_id"],
                "publish_ciphertext_sha256": manifest["ciphertext_sha256"],
                "manifest_hash": manifest_hash(manifest),
            }
        }

    def test_binding_requires_quorum_when_requested(self):
        manifest = _sealed()
        manifest, _ = add_witness_signature(manifest, _WK[0])
        packet = self._provenance_for(manifest)
        policy = {"authorized_witnesses": _ADDRS, "threshold": 2}
        # Only one witness signed; a 2-of-N quorum is unmet.
        verdict = verify_reward_dataset_binding(packet, manifest, witness_quorum=policy)
        self.assertFalse(verdict["dataset_binding_verified"])
        self.assertEqual(verdict["reason_code"], "dataset_witness_quorum_unmet")
        self.assertTrue(verdict["witness_quorum_requested"])

    def test_binding_passes_when_quorum_met(self):
        manifest = _sealed()
        manifest, _ = add_witness_signature(manifest, _WK[0])
        manifest, _ = add_witness_signature(manifest, _WK[1])
        packet = self._provenance_for(manifest)
        policy = {"authorized_witnesses": _ADDRS, "threshold": 2}
        verdict = verify_reward_dataset_binding(packet, manifest, witness_quorum=policy)
        self.assertTrue(verdict["dataset_binding_verified"])
        self.assertTrue(verdict["witness_quorum_met"])
        self.assertEqual(verdict["valid_witness_count"], 2)

    def test_quorum_not_requested_leaves_binding_unchanged(self):
        manifest = _sealed()
        packet = self._provenance_for(manifest)
        verdict = verify_reward_dataset_binding(packet, manifest)
        self.assertTrue(verdict["dataset_binding_verified"])
        self.assertFalse(verdict["witness_quorum_requested"])


if __name__ == "__main__":
    unittest.main()
