"""Guarded live proof that RoyaltyDistributor conserves funds on Anvil.

Spawns a real Anvil chain and deploys the contract, so it is opt-in: runs only
when DNAI_RUN_ANVIL_PROOFS=1 and anvil/cast/forge are on PATH. The default suite
skips it (the contract-level behavior is covered by the fast Foundry tests in
contracts/test/RoyaltyDistributor.t.sol).
"""
import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "prove-royalty-distributor-anvil.py"
_TOOLS_PRESENT = all(shutil.which(tool) for tool in ("anvil", "cast", "forge"))
_ENABLED = os.environ.get("DNAI_RUN_ANVIL_PROOFS") == "1"


@unittest.skipUnless(_ENABLED and _TOOLS_PRESENT, "set DNAI_RUN_ANVIL_PROOFS=1 with foundry on PATH")
class RoyaltyDistributorProofTest(unittest.TestCase):
    def test_pull_payment_conserves(self):
        result = subprocess.run(
            [sys.executable, str(_SCRIPT)],
            cwd=_SCRIPT.parents[1],
            check=False,
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        summary = json.loads(result.stdout[result.stdout.index("{"):])
        self.assertTrue(summary["conserved"])
        self.assertTrue(summary["pending_owner_a_matches"])
        self.assertTrue(summary["pending_owner_b_matches"])
        self.assertTrue(summary["held_full_total_after_distribute"])
        self.assertTrue(summary["drained_to_zero_after_withdraw"])
        self.assertFalse(summary["raw_secret_egress"])


if __name__ == "__main__":
    unittest.main()
