"""Guarded live proof that a distribution-plan's calldata executes on Anvil.

Deploys RoyaltyDistributor, builds a plan with the Python builder, broadcasts the
plan's exact calldata, and asserts conservation. Opt-in: runs only when
DNAI_RUN_ANVIL_PROOFS=1 and anvil/cast/forge are on PATH.
"""
import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "prove-royalty-distribution-plan-anvil.py"
_TOOLS_PRESENT = all(shutil.which(tool) for tool in ("anvil", "cast", "forge"))
_ENABLED = os.environ.get("DNAI_RUN_ANVIL_PROOFS") == "1"


@unittest.skipUnless(_ENABLED and _TOOLS_PRESENT, "set DNAI_RUN_ANVIL_PROOFS=1 with foundry on PATH")
class RoyaltyDistributionPlanProofTest(unittest.TestCase):
    def test_plan_calldata_executes_and_conserves(self):
        result = subprocess.run(
            [sys.executable, str(_SCRIPT)],
            cwd=_SCRIPT.parents[1],
            check=False,
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        summary = json.loads(result.stdout[result.stdout.index("{"):])
        self.assertTrue(summary["plan_executes_and_conserves"])
        self.assertTrue(summary["pending_owner_a_matches_plan"])
        self.assertTrue(summary["pending_owner_b_matches_plan"])
        self.assertTrue(summary["drained_to_zero_after_withdraw"])
        self.assertFalse(summary["raw_secret_egress"])


if __name__ == "__main__":
    unittest.main()
