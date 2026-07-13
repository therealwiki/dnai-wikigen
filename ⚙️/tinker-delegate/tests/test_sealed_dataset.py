import json
import os
import unittest

from tinker_delegate.crypto import TEEKeyPair
from tinker_delegate.sealed_dataset import (
    DataSensitivity,
    SealedDatasetError,
    build_manifest,
    decrypt_dataset,
    encrypt_dataset,
    generate_dek,
    unwrap_dek,
    verify_manifest,
    wrap_dek,
)


class SealedDatasetTest(unittest.TestCase):
    def _round(self, plaintext: bytes, chunk_size: int = 64):
        dataset_id = "openproblems_v1_denoising"
        dek = generate_dek()
        tee = TEEKeyPair()
        enc = encrypt_dataset(plaintext, dek, dataset_id=dataset_id, chunk_size=chunk_size)
        wrapped = wrap_dek(dek, tee.public_key_bytes.hex(), dataset_id=dataset_id)
        manifest = build_manifest(
            enc,
            task="denoising",
            data_sensitivity=DataSensitivity.PUBLIC_BENCHMARK,
            recipients=[wrapped],
            storage_ref="hf://datasets/example/denoising-sealed",
        )
        return dataset_id, dek, tee, enc, manifest

    def test_envelope_round_trip_recovers_plaintext(self):
        plaintext = os.urandom(500)
        dataset_id, _, tee, enc, manifest = self._round(plaintext)
        unwrapped = unwrap_dek(manifest["recipients"][0], tee, dataset_id=dataset_id)
        recovered = decrypt_dataset(
            enc.blob,
            unwrapped,
            dataset_id=dataset_id,
            chunk_nonces=manifest["chunk"]["chunk_nonces"],
            expected_plaintext_sha256=manifest["plaintext_sha256"],
        )
        self.assertEqual(bytes(recovered), plaintext)

    def test_wrong_tee_key_cannot_unwrap(self):
        plaintext = os.urandom(128)
        dataset_id, _, _, _, manifest = self._round(plaintext)
        attacker = TEEKeyPair()
        with self.assertRaises(Exception):
            unwrap_dek(manifest["recipients"][0], attacker, dataset_id=dataset_id)

    def test_tampered_chunk_fails_authentication(self):
        plaintext = os.urandom(200)
        dataset_id, _, tee, enc, manifest = self._round(plaintext)
        dek = unwrap_dek(manifest["recipients"][0], tee, dataset_id=dataset_id)
        tampered = bytearray(enc.blob)
        tampered[-1] ^= 0x01
        with self.assertRaises(Exception):
            decrypt_dataset(
                bytes(tampered),
                dek,
                dataset_id=dataset_id,
                chunk_nonces=manifest["chunk"]["chunk_nonces"],
            )

    def test_wrong_dataset_id_aad_fails(self):
        plaintext = os.urandom(120)
        dataset_id, _, tee, enc, manifest = self._round(plaintext)
        dek = unwrap_dek(manifest["recipients"][0], tee, dataset_id=dataset_id)
        with self.assertRaises(Exception):
            decrypt_dataset(
                enc.blob,
                dek,
                dataset_id="different_dataset",
                chunk_nonces=manifest["chunk"]["chunk_nonces"],
            )

    def test_manifest_is_egress_safe(self):
        plaintext = b"secret expression matrix bytes" * 10
        _, dek, _, _, manifest = self._round(plaintext)
        rendered = json.dumps(manifest)
        self.assertNotIn(dek.hex(), rendered)
        self.assertNotIn(plaintext.decode(errors="ignore")[:10], rendered)
        self.assertFalse(manifest["raw_secret_egress"])

    def test_verify_manifest_happy_and_ciphertext_binding(self):
        plaintext = os.urandom(300)
        _, _, _, enc, manifest = self._round(plaintext)
        good = verify_manifest(manifest, blob=enc.blob)
        self.assertTrue(good["ok"])
        self.assertTrue(good["ciphertext_verified"])
        self.assertEqual(good["recipient_count"], 1)
        bad = verify_manifest(manifest, blob=enc.blob + b"x")
        self.assertFalse(bad["ok"])
        self.assertIn("ciphertext_hash_mismatch", bad["problems"])

    def test_verify_manifest_rejects_bad_sensitivity(self):
        plaintext = os.urandom(64)
        _, _, _, _, manifest = self._round(plaintext)
        manifest["data_sensitivity"] = "totally_public_promise"
        result = verify_manifest(manifest)
        self.assertFalse(result["ok"])
        self.assertIn("bad_data_sensitivity", result["problems"])

    def test_empty_plaintext_round_trips(self):
        dataset_id, _, tee, enc, manifest = self._round(b"")
        dek = unwrap_dek(manifest["recipients"][0], tee, dataset_id=dataset_id)
        recovered = decrypt_dataset(
            enc.blob, dek, dataset_id=dataset_id, chunk_nonces=manifest["chunk"]["chunk_nonces"]
        )
        self.assertEqual(bytes(recovered), b"")

    def test_dek_must_be_32_bytes(self):
        with self.assertRaises(SealedDatasetError):
            encrypt_dataset(b"data", b"short", dataset_id="d")

    def test_multi_recipient_manifest(self):
        plaintext = os.urandom(150)
        dataset_id = "d"
        dek = generate_dek()
        tee_a, tee_b = TEEKeyPair(), TEEKeyPair()
        enc = encrypt_dataset(plaintext, dek, dataset_id=dataset_id, chunk_size=64)
        recipients = [
            wrap_dek(dek, tee_a.public_key_bytes.hex(), dataset_id=dataset_id),
            wrap_dek(dek, tee_b.public_key_bytes.hex(), dataset_id=dataset_id),
        ]
        manifest = build_manifest(
            enc, task="t", data_sensitivity=DataSensitivity.PRIVATE, recipients=recipients
        )
        # Each recipient can unwrap its own envelope.
        d_a = unwrap_dek(manifest["recipients"][0], tee_a, dataset_id=dataset_id)
        d_b = unwrap_dek(manifest["recipients"][1], tee_b, dataset_id=dataset_id)
        self.assertEqual(d_a, dek)
        self.assertEqual(d_b, dek)


if __name__ == "__main__":
    unittest.main()
