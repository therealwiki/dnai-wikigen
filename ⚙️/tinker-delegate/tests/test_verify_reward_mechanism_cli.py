import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tinker_delegate.private_reward_envs import denoising as _denoising_mod
from tinker_delegate.private_reward_envs.denoising_demo import run_denoising_holdout_demo

REPO = Path(__file__).resolve().parents[1]
_ENV_SOURCE = _denoising_mod.__file__


def _run(*args: str):
    return subprocess.run(
        [sys.executable, "-m", "tinker_delegate.main", *args],
        check=False,
        cwd=REPO,
        text=True,
        capture_output=True,
    )


class VerifyRewardMechanismCliTest(unittest.TestCase):
    def _packet_path(self, tmp):
        path = Path(tmp) / "packet.json"
        path.write_text(json.dumps(run_denoising_holdout_demo()), encoding="utf-8")
        return path

    def test_packet_only_verifies_and_exits_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = _run("verify-reward-mechanism", "--packet", str(self._packet_path(tmp)))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        verdict = json.loads(proc.stdout)
        self.assertTrue(verdict["verified"])
        self.assertTrue(verdict["checks"]["code_binding"]["skipped"])
        self.assertFalse(verdict["raw_secret_egress"])

    def test_correct_source_binds_and_exits_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = _run(
                "verify-reward-mechanism",
                "--packet", str(self._packet_path(tmp)),
                "--source", _ENV_SOURCE,
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        verdict = json.loads(proc.stdout)
        self.assertTrue(verdict["verified"])
        self.assertEqual(verdict["reason_code"], "mechanism_verified")
        self.assertTrue(verdict["checks"]["code_binding"]["code_binding_verified"])

    def test_wrong_source_fails_and_exits_nonzero(self):
        from tinker_delegate.private_reward_envs import synthetic as synthetic_mod

        with tempfile.TemporaryDirectory() as tmp:
            proc = _run(
                "verify-reward-mechanism",
                "--packet", str(self._packet_path(tmp)),
                "--source", synthetic_mod.__file__,
            )
        self.assertEqual(proc.returncode, 1)
        verdict = json.loads(proc.stdout)
        self.assertFalse(verdict["verified"])
        self.assertEqual(verdict["reason_code"], "code_hash_mismatch")

    def test_witness_quorum_and_benchmark_via_cli(self):
        from eth_account import Account

        from tinker_delegate.sealed_dataset import (
            DataSensitivity,
            add_witness_signature,
            build_provenance,
            generate_recipient_keypair,
            manifest_hash,
            seal_dataset,
            sign_manifest,
        )

        wk = ["11" * 32, "22" * 32]
        addrs = [Account.from_key(k).address for k in wk]
        owner = "33" * 32
        owner_addr = Account.from_key(owner).address
        _priv, pub = generate_recipient_keypair()
        prov = build_provenance(
            source_pipeline="p", upstream_id="u", license="l",
            distribution_claim="rep", benchmark_ref="bench-v1",
        )
        _b, manifest, _r = seal_dataset(
            b'{"x":1}', dataset_id="d1", task="t",
            data_sensitivity=DataSensitivity.PUBLIC_BENCHMARK,
            recipient_public_keys=[pub], provenance=prov,
        )
        manifest, _ = add_witness_signature(manifest, wk[0])
        manifest, _ = add_witness_signature(manifest, wk[1])
        manifest, _ = sign_manifest(manifest, owner)

        with tempfile.TemporaryDirectory() as tmp:
            packet = run_denoising_holdout_demo()
            packet["sealed_dataset_provenance"] = {
                "dataset_id": "d1",
                "publish_ciphertext_sha256": manifest["ciphertext_sha256"],
                "manifest_hash": manifest_hash(manifest),
            }
            ppath = Path(tmp) / "packet.json"
            ppath.write_text(json.dumps(packet), encoding="utf-8")
            mpath = Path(tmp) / "manifest.json"
            mpath.write_text(json.dumps(manifest), encoding="utf-8")
            proc = _run(
                "verify-reward-mechanism",
                "--packet", str(ppath),
                "--manifest", str(mpath),
                "--expected-signer", owner_addr,
                "--witness", addrs[0], "--witness", addrs[1],
                "--witness-threshold", "2",
                "--expected-benchmark", "bench-v1",
                "--require-provenance",
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        verdict = json.loads(proc.stdout)
        self.assertTrue(verdict["verified"])
        self.assertTrue(verdict["checks"]["dataset_binding"]["witness_quorum_met"])
        self.assertTrue(verdict["checks"]["provenance"]["ok"])


if __name__ == "__main__":
    unittest.main()
