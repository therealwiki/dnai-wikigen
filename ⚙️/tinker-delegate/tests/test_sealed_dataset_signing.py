import tempfile
import unittest

from eth_account import Account

from tinker_delegate.dataset_storage import (
    LocalStorageBackend,
    StorageBackendError,
    fetch_decrypt_dataset,
    publish_dataset,
)
from tinker_delegate.sealed_dataset import (
    generate_recipient_keypair,
    seal_dataset,
    sign_manifest,
    verify_manifest,
)


def _seal(pub, dataset_id="ds-sign", storage_ref=None, plaintext=b"sealed rows " * 100):
    blob, manifest, _receipt = seal_dataset(
        plaintext,
        dataset_id=dataset_id,
        task="denoising",
        data_sensitivity="private",
        recipient_public_keys=[pub],
        storage_ref=storage_ref,
    )
    return plaintext, blob, manifest


class OwnerSignatureTest(unittest.TestCase):
    def setUp(self):
        self.owner = Account.create()
        self.owner_key = self.owner.key.hex()
        _priv, self.pub = generate_recipient_keypair()

    def test_sign_receipt_is_bounded(self):
        _pt, _blob, manifest = _seal(self.pub)
        signed, receipt = sign_manifest(manifest, self.owner_key)
        self.assertTrue(receipt["success"])
        self.assertFalse(receipt["raw_secret_egress"])
        self.assertFalse(receipt["signature_returned"])
        self.assertFalse(receipt["private_key_returned"])
        blob = str(receipt)
        self.assertNotIn(self.owner_key, blob)
        self.assertNotIn(self.owner.address, blob)
        self.assertNotIn(signed["owner_signature"]["signature"], blob)

    def test_valid_signature_verifies(self):
        _pt, blob, manifest = _seal(self.pub)
        signed, _ = sign_manifest(manifest, self.owner_key)
        result = verify_manifest(signed, blob=blob)
        self.assertTrue(result["ok"])
        self.assertTrue(result["owner_signature_present"])
        self.assertTrue(result["owner_signature_verified"])

    def test_expected_signer_match_and_mismatch(self):
        _pt, blob, manifest = _seal(self.pub)
        signed, _ = sign_manifest(manifest, self.owner_key)
        ok = verify_manifest(signed, blob=blob, expected_signer=self.owner.address)
        self.assertTrue(ok["ok"])
        other = Account.create().address
        bad = verify_manifest(signed, blob=blob, expected_signer=other)
        self.assertFalse(bad["ok"])
        self.assertIn("unexpected_owner_signer", bad["problems"])

    def test_tampered_signed_field_fails(self):
        _pt, blob, manifest = _seal(self.pub)
        signed, _ = sign_manifest(manifest, self.owner_key)
        signed["data_sensitivity"] = "public_benchmark"
        result = verify_manifest(signed, blob=blob)
        self.assertFalse(result["ok"])
        self.assertIn("owner_signature_hash_mismatch", result["problems"])

    def test_tampered_signature_bytes_fail(self):
        _pt, blob, manifest = _seal(self.pub)
        signed, _ = sign_manifest(manifest, self.owner_key)
        sig = signed["owner_signature"]["signature"]
        # Corrupt a byte inside the r component (index 3, right after "0x"); this
        # deterministically changes the recovered address (unlike flipping only
        # the v recovery byte, which can preserve the recovery id).
        idx = 3
        replacement = "1" if sig[idx] != "1" else "2"
        signed["owner_signature"]["signature"] = sig[:idx] + replacement + sig[idx + 1 :]
        result = verify_manifest(signed, blob=blob)
        self.assertFalse(result["ok"])

    def test_missing_signature_when_expected(self):
        _pt, blob, manifest = _seal(self.pub)
        result = verify_manifest(manifest, blob=blob, expected_signer=self.owner.address)
        self.assertFalse(result["ok"])
        self.assertIn("missing_owner_signature", result["problems"])

    def test_unsigned_manifest_is_optional_by_default(self):
        _pt, blob, manifest = _seal(self.pub)
        result = verify_manifest(manifest, blob=blob)
        self.assertTrue(result["ok"])
        self.assertFalse(result["owner_signature_present"])
        self.assertIsNone(result["owner_signature_verified"])

    def test_publish_stores_signed_manifest_and_fetch_decrypt_round_trips(self):
        priv, pub = generate_recipient_keypair()
        with tempfile.TemporaryDirectory() as d:
            backend = LocalStorageBackend(d)
            # Sign after setting storage_ref to the target ref so publish stores verbatim.
            _pt, blob, manifest = _seal(pub, dataset_id="ds-pub")
            ref = backend.ref_for("ds-pub")
            manifest["storage_ref"] = ref
            signed, _ = sign_manifest(manifest, self.owner_key)
            receipt = publish_dataset(blob, signed, backend)
            self.assertTrue(receipt["ok"])
            self.assertNotIn("storage_ref", receipt)
            self.assertTrue(receipt["storage_ref_hash"].startswith("sealed_storage_ref_"))
            _stored_blob, stored_manifest = backend.fetch(ref)
            self.assertTrue(
                verify_manifest(stored_manifest, expected_signer=self.owner.address)["ok"]
            )
            buf, fr = fetch_decrypt_dataset(ref, priv)
            self.assertTrue(fr["decrypted"])
            self.assertIsNotNone(buf)

    def test_publish_refuses_signed_manifest_with_wrong_ref(self):
        priv, pub = generate_recipient_keypair()
        with tempfile.TemporaryDirectory() as d:
            backend = LocalStorageBackend(d)
            _pt, blob, manifest = _seal(pub, dataset_id="ds-wrong", storage_ref="local:///elsewhere/ds-wrong")
            signed, _ = sign_manifest(manifest, self.owner_key)
            with self.assertRaises(StorageBackendError):
                publish_dataset(blob, signed, backend)


if __name__ == "__main__":
    unittest.main()
