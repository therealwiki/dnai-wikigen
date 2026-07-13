"""Tests for the sealed-dataset-sourced denoising demo: the sealed-data ->
environment -> bounded-reward mechanism exercised end to end."""
import json
import subprocess
import sys
import unittest
from pathlib import Path

from tinker_delegate.private_reward_envs.denoising_demo import (
    denoising_demo_forbidden_values,
    run_denoising_holdout_demo,
)
from tinker_delegate.private_reward_envs.denoising_sealed_demo import (
    run_denoising_sealed_dataset_demo,
)
from tinker_delegate.run_verification import verify_reward_run

REPO = Path(__file__).resolve().parents[1]


class DenoisingSealedDemoTest(unittest.TestCase):
    def setUp(self):
        self.packet = run_denoising_sealed_dataset_demo()

    def test_sealed_fetch_succeeds_and_is_public_benchmark(self):
        self.assertTrue(self.packet["sealed_fetch_ok"])
        prov = self.packet["sealed_dataset_provenance"]
        # Labelled public_benchmark so it is not misread as a privacy claim.
        self.assertEqual(prov["data_sensitivity"], "public_benchmark")
        # The data was decrypted in-boundary and its plaintext hash verified.
        self.assertTrue(prov["plaintext_sha256_verified"])
        self.assertTrue(prov["manifest_ok"])
        self.assertTrue(prov["recipient_key_hash"])

    def test_sealed_roundtrip_preserves_data_exactly(self):
        # The reward bands from cells fetched through the sealed envelope path
        # must equal the direct (in-code) demo's bands — proving the
        # seal -> publish -> fetch -> decrypt -> verify round-trip is lossless.
        direct = run_denoising_holdout_demo()
        self.assertEqual(
            [f["reward_band"] for f in self.packet["feedback"]],
            [f["reward_band"] for f in direct["feedback"]],
        )

    def test_no_raw_counts_leak_through_the_sealed_demo(self):
        # The sealed cell count vectors must never appear in the bounded output,
        # even though they were decrypted in-boundary to run the env.
        blob = json.dumps(self.packet)
        for forbidden in denoising_demo_forbidden_values():
            self.assertNotIn(forbidden, blob)
        self.assertFalse(self.packet["raw_secret_egress"])

    def test_sealed_demo_packet_verifies_end_to_end(self):
        # Like the other private-reward demos, the emitted packet must pass the
        # independent verifier (certificate + transcript binding + feedback
        # leakage bound).
        verdict = verify_reward_run(self.packet)
        self.assertTrue(verdict["verified"], verdict)
        self.assertEqual(verdict["reason_code"], "run_verified")
        self.assertTrue(verdict["feedback_bounded"])

    def test_cli_emits_bounded_sealed_demo(self):
        # The operator CLI runs the sealed demo and its output passes the shared
        # bounded-egress + forbidden-values guard (else it would exit non-zero).
        proc = subprocess.run(
            [sys.executable, "-m", "tinker_delegate.main", "denoising-sealed-dataset-demo"],
            check=False, cwd=REPO, text=True, capture_output=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        body = json.loads(proc.stdout)
        self.assertEqual(body["demo"], "denoising_sealed_dataset")
        self.assertTrue(body["sealed_fetch_ok"])
        self.assertEqual(
            body["sealed_dataset_provenance"]["data_sensitivity"], "public_benchmark"
        )
        self.assertFalse(body["raw_secret_egress"])


if __name__ == "__main__":
    unittest.main()
