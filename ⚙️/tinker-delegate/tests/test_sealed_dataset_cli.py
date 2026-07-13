import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tinker_delegate.crypto import TEEKeyPair
from tinker_delegate.sealed_dataset import decrypt_dataset, unwrap_dek

REPO = Path(__file__).resolve().parents[1]


def _run(*args: str):
    return subprocess.run(
        [sys.executable, "-m", "tinker_delegate.main", *args],
        check=False,
        cwd=REPO,
        text=True,
        capture_output=True,
    )


class SealedDatasetCliTest(unittest.TestCase):
    def test_encrypt_then_verify_and_decrypt_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            plaintext = b"sealed expression matrix bytes " * 100
            data_path = tmp / "dataset.bin"
            data_path.write_bytes(plaintext)

            tee = TEEKeyPair()
            pubkey_hex = tee.public_key_bytes.hex()

            blob_path = tmp / "dataset.blob"
            manifest_path = tmp / "manifest.json"
            receipt_path = tmp / "receipt.json"

            enc = _run(
                "encrypt-dataset",
                "--in", str(data_path),
                "--dataset-id", "openproblems_v1_denoising",
                "--task", "denoising",
                "--sensitivity", "private",
                "--recipient-pubkey", pubkey_hex,
                "--storage-ref", "hf://datasets/example/sealed",
                "--out-blob", str(blob_path),
                "--out-manifest", str(manifest_path),
                "--output", str(receipt_path),
            )
            self.assertEqual(enc.returncode, 0, enc.stderr)

            receipt = json.loads(receipt_path.read_text())
            self.assertFalse(receipt["raw_secret_egress"])
            self.assertEqual(receipt["data_sensitivity"], "private")
            self.assertEqual(receipt["recipient_count"], 1)
            # No plaintext or key material in the receipt.
            self.assertNotIn(b"expression".decode(), json.dumps(receipt))

            # verify-dataset-manifest with the blob passes.
            ver = _run(
                "verify-dataset-manifest",
                "--manifest", str(manifest_path),
                "--blob", str(blob_path),
            )
            self.assertEqual(ver.returncode, 0, ver.stderr)
            ver_out = json.loads(ver.stdout)
            self.assertTrue(ver_out["ok"])
            self.assertTrue(ver_out["ciphertext_verified"])

            # The recipient CVM key can actually unwrap + decrypt to plaintext.
            manifest = json.loads(manifest_path.read_text())
            dek = unwrap_dek(manifest["recipients"][0], tee, dataset_id="openproblems_v1_denoising")
            recovered = decrypt_dataset(
                blob_path.read_bytes(),
                dek,
                dataset_id="openproblems_v1_denoising",
                chunk_nonces=manifest["chunk"]["chunk_nonces"],
                expected_plaintext_sha256=manifest["plaintext_sha256"],
            )
            self.assertEqual(bytes(recovered), plaintext)

    def test_encrypt_requires_recipient(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            data_path = tmp / "d.bin"
            data_path.write_bytes(b"x")
            res = _run(
                "encrypt-dataset",
                "--in", str(data_path),
                "--dataset-id", "d",
                "--task", "t",
                "--sensitivity", "public_benchmark",
                "--out-blob", str(tmp / "b"),
                "--out-manifest", str(tmp / "m"),
            )
            self.assertEqual(res.returncode, 1)

    def test_verify_rejects_tampered_ciphertext(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            data_path = tmp / "d.bin"
            data_path.write_bytes(b"hello world payload")
            tee = TEEKeyPair()
            blob_path = tmp / "b.blob"
            manifest_path = tmp / "m.json"
            enc = _run(
                "encrypt-dataset",
                "--in", str(data_path),
                "--dataset-id", "d",
                "--task", "t",
                "--sensitivity", "public_benchmark",
                "--recipient-pubkey", tee.public_key_bytes.hex(),
                "--out-blob", str(blob_path),
                "--out-manifest", str(manifest_path),
            )
            self.assertEqual(enc.returncode, 0, enc.stderr)
            blob_path.write_bytes(blob_path.read_bytes() + b"tamper")
            ver = _run(
                "verify-dataset-manifest",
                "--manifest", str(manifest_path),
                "--blob", str(blob_path),
            )
            self.assertEqual(ver.returncode, 1)
            self.assertIn("ciphertext_hash_mismatch", json.loads(ver.stdout)["problems"])


if __name__ == "__main__":
    unittest.main()
