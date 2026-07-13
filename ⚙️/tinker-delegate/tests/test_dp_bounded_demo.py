import json
import subprocess
import sys
import unittest
from pathlib import Path

from tinker_delegate.private_reward_envs.dp_bounded_demo import (
    dp_bounded_demo_forbidden_values,
    run_dp_bounded_reward_demo,
)
from tinker_delegate.run_verification import verify_reward_run

REPO = Path(__file__).resolve().parents[1]


class DpBoundedDemoTest(unittest.TestCase):
    def test_demo_shows_release_then_fail_closed_and_is_bounded(self):
        result = run_dp_bounded_reward_demo()  # 5 candidates, 0.4/query, max 1.0
        self.assertEqual(result["demo"], "dp_bounded_reward")
        self.assertFalse(result["raw_secret_egress"])
        # Two releases fit the 1.0 epsilon budget; the rest fail closed.
        self.assertEqual(result["dp_released_count"], 2)
        self.assertEqual(result["dp_withheld_count"], 3)
        # The exhausted releases carry a withheld band, never a reward.
        withheld = [f for f in result["feedback"] if f["decision"] == "budget_exhausted"]
        self.assertTrue(all(f["reward_band"] == "withheld" for f in withheld))

    def test_attestation_records_dp_status(self):
        result = run_dp_bounded_reward_demo()
        dp = result["attestation"]["dp_status"]
        self.assertEqual(dp["mode"], "differential_privacy")
        self.assertTrue(dp["phi_safe"])
        self.assertAlmostEqual(dp["spent_epsilon"], 0.8)  # two 0.4 releases fit
        self.assertAlmostEqual(dp["max_epsilon"], 1.0)

    def test_demo_hides_sealed_records_and_keywords(self):
        result = run_dp_bounded_reward_demo()
        blob = json.dumps(result, default=str)
        for forbidden in dp_bounded_demo_forbidden_values():
            if len(forbidden) >= 4:
                self.assertNotIn(forbidden, blob)

    def test_demo_run_verifies_end_to_end(self):
        # The demo emits a transcript-bound reproducibility certificate + commitment,
        # so verify_reward_run confirms the whole chain from public bytes alone.
        result = run_dp_bounded_reward_demo()
        verdict = verify_reward_run(result)
        self.assertTrue(verdict["verified"], verdict)
        self.assertEqual(verdict["reason_code"], "run_verified")
        self.assertEqual(
            result["reproducibility_certificate"]["transcript_commitment_hash"],
            result["reward_transcript_commitment"]["commitment_hash"],
        )


    def test_tampered_dp_status_fails_verification(self):
        import copy

        result = run_dp_bounded_reward_demo()
        # Sanity: the untampered run verifies.
        self.assertTrue(verify_reward_run(result)["verified"])
        # Tamper the attested privacy accounting so remaining != max - spent.
        tampered = copy.deepcopy(result)
        tampered["attestation"]["dp_status"]["spent_epsilon"] = 0.1
        verdict = verify_reward_run(tampered)
        self.assertFalse(verdict["verified"])
        self.assertEqual(verdict["reason_code"], "packet_inconsistent")

    def test_cli_emits_bounded_dp_demo(self):
        proc = subprocess.run(
            [sys.executable, "-m", "tinker_delegate.main", "dp-bounded-reward-demo"],
            check=False, cwd=REPO, text=True, capture_output=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        body = json.loads(proc.stdout)
        self.assertEqual(body["demo"], "dp_bounded_reward")
        self.assertEqual(body["dp_released_count"], 2)
        self.assertEqual(body["dp_withheld_count"], 3)
        self.assertFalse(body["raw_secret_egress"])


if __name__ == "__main__":
    unittest.main()
