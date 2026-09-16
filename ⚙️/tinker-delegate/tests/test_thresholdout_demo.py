import json
import subprocess
import sys
import unittest
from pathlib import Path

from tinker_delegate.private_reward import assert_bounded_egress
from tinker_delegate.private_reward_envs.thresholdout_demo import run_thresholdout_demo

REPO = Path(__file__).resolve().parents[1]


class ThresholdoutDemoTest(unittest.TestCase):
    def test_demo_runs_free_and_holdout_paths_within_budget(self):
        packet = run_thresholdout_demo(max_epsilon=1.5)
        self.assertEqual(packet["demo"], "thresholdout")
        self.assertEqual(len(packet["releases"]), 7)
        self.assertEqual(packet["dp_status"]["budget_status"], "exhausted")

    def test_over_budget_divergence_fails_closed(self):
        packet = run_thresholdout_demo(max_epsilon=1.5)
        # The stream's last divergence is over budget: no release (index -1).
        exhausted_release = [r for r in packet["releases"] if not r["has_release"]]
        self.assertTrue(exhausted_release)
        self.assertTrue(all(r["budget_status"] == "exhausted" for r in exhausted_release))

    def test_releases_are_bounded_egress_safe(self):
        packet = run_thresholdout_demo()
        assert_bounded_egress({"releases": packet["releases"]})
        self.assertFalse(packet["raw_secret_egress"])

    def test_public_packet_omits_secret_dependent_access_accounting(self):
        packet = run_thresholdout_demo(max_epsilon=1.5)
        self.assertNotIn("holdout_access_count", packet)
        self.assertNotIn("free_release_count", packet)
        self.assertNotIn("spent_epsilon", packet["dp_status"])
        for release in packet["releases"]:
            self.assertNotIn("used_holdout", release)
            self.assertNotIn("holdout_access_count", release)

    def test_cli_emits_bounded_packet(self):
        proc = subprocess.run(
            [sys.executable, "-m", "tinker_delegate.main", "thresholdout-demo"],
            check=False, cwd=REPO, text=True, capture_output=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        packet = json.loads(proc.stdout)
        self.assertEqual(packet["demo"], "thresholdout")
        self.assertFalse(packet["raw_secret_egress"])


if __name__ == "__main__":
    unittest.main()
