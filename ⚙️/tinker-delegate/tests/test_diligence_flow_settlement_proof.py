"""Guarded full-stack proof: bio flow -> derived plan -> on-chain settlement.

Runs a real diligence flow, derives the royalty plan, deploys RoyaltyDistributor
on Anvil, broadcasts the plan's calldata, and asserts conservation. Opt-in: runs
only when DNAI_RUN_ANVIL_PROOFS=1 and anvil/cast/forge are on PATH.
"""
import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "prove-diligence-flow-settlement-anvil.py"
_TOOLS_PRESENT = all(shutil.which(tool) for tool in ("anvil", "cast", "forge"))
_ENABLED = os.environ.get("DNAI_RUN_ANVIL_PROOFS") == "1"


@unittest.skipUnless(_ENABLED and _TOOLS_PRESENT, "set DNAI_RUN_ANVIL_PROOFS=1 with foundry on PATH")
class DiligenceFlowSettlementProofTest(unittest.TestCase):
    def test_flow_to_settlement_conserves(self):
        result = subprocess.run(
            [sys.executable, str(_SCRIPT)],
            cwd=_SCRIPT.parents[1],
            check=False,
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        summary = json.loads(result.stdout[result.stdout.index("{"):])
        self.assertEqual(summary["flow_decision"], "proceed")
        self.assertTrue(summary["flow_to_settlement_conserves"])
        self.assertTrue(summary["owner_a_credited_flow_payout"])
        self.assertTrue(summary["owner_b_credited_flow_payout"])
        self.assertTrue(summary["drained_to_zero_after_withdraw"])
        self.assertFalse(summary["raw_secret_egress"])


if __name__ == "__main__":
    unittest.main()
