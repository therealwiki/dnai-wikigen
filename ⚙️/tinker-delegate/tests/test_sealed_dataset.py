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
    generate_recipient_keypair,
    public_manifest_projection,
    seal_dataset,
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

    def test_internal_manifest_never_contains_plaintext_or_dek(self):
        plaintext = b"secret expression matrix bytes" * 10
        _, dek, _, _, manifest = self._round(plaintext)
        rendered = json.dumps(manifest)
        self.assertNotIn(dek.hex(), rendered)
        self.assertNotIn(plaintext.decode(errors="ignore")[:10], rendered)
        self.assertFalse(manifest["raw_secret_egress"])

    def test_public_projection_bands_private_shape_and_hashes_storage_ref(self):
        private_key, public_key = generate_recipient_keypair()
        del private_key
        plaintext = b"private-row" * 23
        storage_ref = "local:///Users/alice/private/sealed/dataset"
        _blob, internal, receipt = seal_dataset(
            plaintext,
            dataset_id="private-dataset",
            task="denoising",
            data_sensitivity=DataSensitivity.PRIVATE,
            recipient_public_keys=[public_key],
            storage_ref=storage_ref,
            chunk_size=64,
        )

        public = public_manifest_projection(internal)
        self.assertEqual(receipt, {"surface": "seal_dataset", **public})
        self.assertEqual(public["plaintext_size_band"], "xs_le_4_kib")
        self.assertEqual(public["chunk_count_band"], "small_1_to_4")
        self.assertNotIn("plaintext_size", public)
        self.assertNotIn("chunk_count", public)
        self.assertNotIn("chunk", public)
        self.assertNotIn("recipients", public)
        self.assertNotIn("storage_ref", public)
        self.assertNotEqual(public["storage_ref_hash"], storage_ref)
        self.assertNotIn(storage_ref, json.dumps(public))
        # Exact values remain available to the in-boundary transport path.
        self.assertEqual(internal["plaintext_size"], len(plaintext))
        self.assertEqual(internal["chunk"]["chunk_count"], 4)
        self.assertEqual(internal["storage_ref"], storage_ref)

    def test_distinct_private_inputs_have_same_bounded_public_shape(self):
        _private_key, public_key = generate_recipient_keypair()

        def project(payload: bytes) -> tuple[dict, dict]:
            _blob, internal, receipt = seal_dataset(
                payload,
                dataset_id="same-declared-dataset",
                task="denoising",
                data_sensitivity=DataSensitivity.PRIVATE,
                recipient_public_keys=[public_key],
                storage_ref="local:///private/root/same-declared-dataset",
                chunk_size=64,
            )
            bounded = dict(receipt)
            for field in (
                "ciphertext_sha256",
                "manifest_hash",
            ):
                bounded[field] = "<opaque-commitment>"
            return internal, bounded

        first_internal, first_public = project(b"a" * 65)   # exact chunk count 2
        second_internal, second_public = project(b"b" * 190)  # exact chunk count 3
        self.assertNotEqual(first_internal["plaintext_size"], second_internal["plaintext_size"])
        self.assertNotEqual(
            first_internal["chunk"]["chunk_count"],
            second_internal["chunk"]["chunk_count"],
        )
        self.assertEqual(first_public, second_public)

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
