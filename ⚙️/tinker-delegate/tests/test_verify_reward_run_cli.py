import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tinker_delegate.private_reward_envs.bio_assay_program_demo import (
    run_bio_assay_program_reward_demo,
)

REPO = Path(__file__).resolve().parents[1]


def _run(*args: str):
    return subprocess.run(
        [sys.executable, "-m", "tinker_delegate.main", *args],
        check=False,
        cwd=REPO,
        text=True,
        capture_output=True,
    )


class VerifyRewardRunCliTest(unittest.TestCase):
    def test_cli_verifies_real_packet_and_exits_zero(self):
        packet = run_bio_assay_program_reward_demo()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "packet.json"
            path.write_text(json.dumps(packet), encoding="utf-8")
            proc = _run("verify-reward-run", "--packet", str(path))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        verdict = json.loads(proc.stdout)
        self.assertTrue(verdict["verified"])
        self.assertEqual(verdict["reason_code"], "run_verified")
        self.assertFalse(verdict["raw_secret_egress"])

    def test_cli_rejects_tampered_packet_and_exits_nonzero(self):
        packet = run_bio_assay_program_reward_demo()
        packet["reproducibility_certificate"]["code_hash"] = "0x" + "11" * 32
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "packet.json"
            path.write_text(json.dumps(packet), encoding="utf-8")
            proc = _run("verify-reward-run", "--packet", str(path))
        self.assertEqual(proc.returncode, 1)
        verdict = json.loads(proc.stdout)
        self.assertFalse(verdict["verified"])
        self.assertEqual(verdict["reason_code"], "certificate_hash_mismatch")


if __name__ == "__main__":
    unittest.main()
