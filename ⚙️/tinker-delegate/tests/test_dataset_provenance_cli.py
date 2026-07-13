import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from eth_account import Account

from tinker_delegate.sealed_dataset import (
    DataSensitivity,
    build_provenance,
    generate_recipient_keypair,
    seal_dataset,
)

REPO = Path(__file__).resolve().parents[1]
_WITNESS_KEY = "11" * 32
_OWNER_KEY = "33" * 32
_WITNESS_ADDR = Account.from_key(_WITNESS_KEY).address
_OWNER_ADDR = Account.from_key(_OWNER_KEY).address


def _run(*args, env_extra=None):
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, "-m", "tinker_delegate.main", *args],
        check=False, cwd=REPO, text=True, capture_output=True, env=env,
    )


def _sealed_manifest_path(tmp, with_provenance=True):
    _priv, pub = generate_recipient_keypair()
    prov = build_provenance(
        source_pipeline="p", upstream_id="u", license="l",
        distribution_claim="rep", benchmark_ref="bench-v1",
    ) if with_provenance else None
    _blob, manifest, _r = seal_dataset(
        b'{"x":1}', dataset_id="d1", task="t",
        data_sensitivity=DataSensitivity.PUBLIC_BENCHMARK,
        recipient_public_keys=[pub], provenance=prov,
    )
    path = Path(tmp) / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


class WitnessSignCliTest(unittest.TestCase):
    def test_witness_cosign_writes_manifest_and_hides_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = _sealed_manifest_path(tmp)
            out = Path(tmp) / "cosigned.json"
            proc = _run(
                "witness-sign-dataset-manifest",
                "--manifest", str(manifest), "--out", str(out),
                env_extra={"DATASET_WITNESS_SIGNER_PRIVATE_KEY": _WITNESS_KEY},
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            receipt = json.loads(proc.stdout)
            self.assertTrue(receipt["success"])
            self.assertEqual(receipt["witness_count"], 1)
            self.assertFalse(receipt["private_key_returned"])
            self.assertNotIn(_WITNESS_KEY, proc.stdout)
            # The co-signed manifest carries a witness_signatures list.
            cosigned = json.loads(out.read_text())
            self.assertEqual(len(cosigned["witness_signatures"]), 1)

    def test_missing_key_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = _sealed_manifest_path(tmp)
            out = Path(tmp) / "cosigned.json"
            env = dict(os.environ)
            env.pop("DATASET_WITNESS_SIGNER_PRIVATE_KEY", None)
            proc = subprocess.run(
                [sys.executable, "-m", "tinker_delegate.main",
                 "witness-sign-dataset-manifest", "--manifest", str(manifest), "--out", str(out)],
                check=False, cwd=REPO, text=True, capture_output=True, env=env,
            )
            self.assertEqual(proc.returncode, 1)
            self.assertEqual(json.loads(proc.stdout)["error_kind"], "missing_signer_key")


class VerifyProvenanceCliTest(unittest.TestCase):
    def _signed_manifest_path(self, tmp):
        manifest = _sealed_manifest_path(tmp)
        signed = Path(tmp) / "signed.json"
        proc = _run(
            "sign-dataset-manifest", "--manifest", str(manifest), "--out", str(signed),
            env_extra={"DATASET_OWNER_SIGNER_PRIVATE_KEY": _OWNER_KEY},
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return signed

    def test_verifies_signed_provenance_and_exits_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            signed = self._signed_manifest_path(tmp)
            proc = _run(
                "verify-dataset-provenance", "--manifest", str(signed),
                "--expected-signer", _OWNER_ADDR, "--expected-benchmark", "bench-v1",
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            verdict = json.loads(proc.stdout)
            self.assertTrue(verdict["ok"])
            self.assertEqual(verdict["reason_code"], "dataset_provenance_verified")

    def test_wrong_benchmark_exits_nonzero(self):
        with tempfile.TemporaryDirectory() as tmp:
            signed = self._signed_manifest_path(tmp)
            proc = _run(
                "verify-dataset-provenance", "--manifest", str(signed),
                "--expected-benchmark", "wrong-benchmark",
            )
            self.assertEqual(proc.returncode, 1)
            self.assertEqual(json.loads(proc.stdout)["reason_code"], "dataset_benchmark_mismatch")

    def test_unsigned_provenance_exits_nonzero(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = _sealed_manifest_path(tmp)  # sealed but never signed
            proc = _run("verify-dataset-provenance", "--manifest", str(manifest))
            self.assertEqual(proc.returncode, 1)
            self.assertEqual(json.loads(proc.stdout)["reason_code"], "dataset_provenance_unsigned")


if __name__ == "__main__":
    unittest.main()
