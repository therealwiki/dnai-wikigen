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
        # 3 tracking candidates answered free; 3 divergences spent budget (0.5 each
        # -> 1.5 = max), then the gate is exhausted.
        self.assertEqual(packet["free_release_count"], 3)
        self.assertEqual(packet["holdout_access_count"], 3)
        self.assertTrue(packet["dp_status"]["exhausted"])
        self.assertEqual(packet["dp_status"]["spent_epsilon"], 1.5)

    def test_over_budget_divergence_fails_closed(self):
        packet = run_thresholdout_demo(max_epsilon=1.5)
        # The stream's last divergence is over budget: no release (index -1).
        exhausted_release = [r for r in packet["releases"] if not r["has_release"]]
        self.assertTrue(exhausted_release)
        self.assertTrue(all(r["budget_exhausted"] for r in exhausted_release))

    def test_releases_are_bounded_egress_safe(self):
        packet = run_thresholdout_demo()
        assert_bounded_egress({"releases": packet["releases"]})
        self.assertFalse(packet["raw_secret_egress"])

    def test_leakage_bound_holds(self):
        packet = run_thresholdout_demo(max_epsilon=1.5)
        # total leakage == epsilon_per_access * holdout accesses, within budget.
        self.assertLessEqual(packet["dp_status"]["spent_epsilon"], 1.5)
        self.assertEqual(packet["dp_status"]["spent_epsilon"], 0.5 * packet["holdout_access_count"])

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
