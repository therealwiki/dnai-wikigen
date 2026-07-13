import tempfile
import unittest
from pathlib import Path

from tinker_delegate.dataset_storage import (
    HttpsFetchBackend,
    LocalStorageBackend,
    StorageBackendError,
    _UnconfiguredBackend,
    backend_for_ref,
    fetch_decrypt_dataset,
    publish_dataset,
    resolve_backend,
)
from tinker_delegate.sealed_dataset import generate_recipient_keypair, seal_dataset


def _seal(recipient_pubkeys, dataset_id="ds-test", plaintext=None):
    plaintext = plaintext if plaintext is not None else b"sealed rows never egress " * 500
    blob, manifest, _receipt = seal_dataset(
        plaintext,
        dataset_id=dataset_id,
        task="denoising",
        data_sensitivity="private",
        recipient_public_keys=recipient_pubkeys,
    )
    return plaintext, blob, manifest


class LocalBackendTest(unittest.TestCase):
    def test_publish_and_fetch_round_trip(self):
        priv, pub = generate_recipient_keypair()
        plaintext, blob, manifest = _seal([pub])
        with tempfile.TemporaryDirectory() as d:
            backend = LocalStorageBackend(d)
            receipt = publish_dataset(blob, manifest, backend)
            self.assertTrue(receipt["ok"])
            self.assertEqual(receipt["backend_scheme"], "local")
            self.assertFalse(receipt["raw_secret_egress"])
            ref = receipt["storage_ref"]
            # The stored manifest carries its own storage_ref.
            fetched_blob, fetched_manifest = backend.fetch(ref)
            self.assertEqual(fetched_blob, blob)
            self.assertEqual(fetched_manifest["storage_ref"], ref)

    def test_publish_rejects_tampered_manifest(self):
        _priv, pub = generate_recipient_keypair()
        _plaintext, blob, manifest = _seal([pub])
        manifest["ciphertext_sha256"] = "00" * 32
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(StorageBackendError):
                publish_dataset(blob, manifest, LocalStorageBackend(d))

    def test_publish_refuses_signed_manifest_with_mismatched_ref(self):
        _priv, pub = generate_recipient_keypair()
        _plaintext, blob, manifest = _seal([pub])
        # A malformed/foreign signature with a non-matching storage_ref must not
        # be silently published (mutating storage_ref would break a real sig).
        manifest["owner_signature"] = {"kind": "ethereum_signed_message", "signature": "0xdead"}
        manifest["storage_ref"] = "local:///elsewhere/ds-test"
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(StorageBackendError):
                publish_dataset(blob, manifest, LocalStorageBackend(d))

    def test_dataset_id_with_path_separator_is_rejected(self):
        _priv, pub = generate_recipient_keypair()
        _plaintext, blob, manifest = _seal([pub], dataset_id="a/b")
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(StorageBackendError):
                publish_dataset(blob, manifest, LocalStorageBackend(d))


class FetchDecryptTest(unittest.TestCase):
    def _publish(self, d, recipient_pubkeys, plaintext=None):
        plaintext, blob, manifest = _seal(recipient_pubkeys, plaintext=plaintext)
        receipt = publish_dataset(blob, manifest, LocalStorageBackend(d))
        return plaintext, receipt["storage_ref"]

    def test_correct_key_decrypts_and_verifies(self):
        priv, pub = generate_recipient_keypair()
        with tempfile.TemporaryDirectory() as d:
            plaintext, ref = self._publish(d, [pub])
            buf, receipt = fetch_decrypt_dataset(ref, priv)
            self.assertTrue(receipt["decrypted"])
            self.assertTrue(receipt["plaintext_sha256_verified"])
            self.assertFalse(receipt["raw_secret_egress"])
            self.assertEqual(bytes(buf), plaintext)

    def test_wrong_key_fails_closed(self):
        priv, pub = generate_recipient_keypair()
        other_priv, _other_pub = generate_recipient_keypair()
        with tempfile.TemporaryDirectory() as d:
            _plaintext, ref = self._publish(d, [pub])
            buf, receipt = fetch_decrypt_dataset(ref, other_priv)
            self.assertIsNone(buf)
            self.assertFalse(receipt["decrypted"])
            self.assertEqual(receipt["reason"], "no_recipient_envelope_for_key")

    def test_multi_recipient_each_key_decrypts(self):
        priv_a, pub_a = generate_recipient_keypair()
        priv_b, pub_b = generate_recipient_keypair()
        with tempfile.TemporaryDirectory() as d:
            plaintext, ref = self._publish(d, [pub_a, pub_b])
            for priv in (priv_a, priv_b):
                buf, receipt = fetch_decrypt_dataset(ref, priv)
                self.assertTrue(receipt["decrypted"])
                self.assertEqual(bytes(buf), plaintext)

    def test_tampered_blob_fails_manifest_verification(self):
        priv, pub = generate_recipient_keypair()
        with tempfile.TemporaryDirectory() as d:
            _plaintext, ref = self._publish(d, [pub])
            blob_path = next(Path(d).glob("*.blob"))
            data = bytearray(blob_path.read_bytes())
            data[0] ^= 0xFF
            blob_path.write_bytes(data)
            buf, receipt = fetch_decrypt_dataset(ref, priv)
            self.assertIsNone(buf)
            self.assertFalse(receipt["manifest_ok"])
            self.assertEqual(receipt["reason"], "manifest_verification_failed")

    def test_receipts_never_contain_plaintext_or_key(self):
        priv, pub = generate_recipient_keypair()
        with tempfile.TemporaryDirectory() as d:
            plaintext, ref = self._publish(d, [pub], plaintext=b"MARKER-SECRET-ROWS" * 100)
            _buf, receipt = fetch_decrypt_dataset(ref, priv)
            import json

            blob = json.dumps(receipt)
            self.assertNotIn("MARKER-SECRET-ROWS", blob)
            self.assertNotIn(priv, blob)


class BackendResolutionTest(unittest.TestCase):
    def test_https_is_read_only(self):
        backend = resolve_backend("https")
        self.assertIsInstance(backend, HttpsFetchBackend)
        with self.assertRaises(StorageBackendError):
            backend.publish("ds", b"", {})

    def test_hf_and_s3_fail_closed(self):
        for scheme in ("hf", "s3"):
            backend = resolve_backend(scheme)
            self.assertIsInstance(backend, _UnconfiguredBackend)
            with self.assertRaises(StorageBackendError):
                backend.publish("ds", b"", {})
            with self.assertRaises(StorageBackendError):
                backend.fetch(f"{scheme}://host/ds")

    def test_unknown_scheme_rejected(self):
        with self.assertRaises(StorageBackendError):
            resolve_backend("ipfs")

    def test_local_requires_root(self):
        with self.assertRaises(StorageBackendError):
            resolve_backend("local")

    def test_backend_for_ref_uses_embedded_local_root(self):
        with tempfile.TemporaryDirectory() as d:
            priv, pub = generate_recipient_keypair()
            _plaintext, blob, manifest = _seal([pub])
            ref = publish_dataset(blob, manifest, LocalStorageBackend(d))["storage_ref"]
            backend = backend_for_ref(ref)
            self.assertIsInstance(backend, LocalStorageBackend)
            fetched_blob, _manifest = backend.fetch(ref)
            self.assertEqual(fetched_blob, blob)


if __name__ == "__main__":
    unittest.main()
