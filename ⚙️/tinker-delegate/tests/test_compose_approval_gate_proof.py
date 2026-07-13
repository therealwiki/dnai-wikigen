"""Guarded live proof that the DiligenceRoom compose-approval gate works on Anvil.

This spawns a real Anvil chain and deploys the contract, so it is opt-in: it runs
only when DNAI_RUN_ANVIL_PROOFS=1 and anvil/cast/forge are on PATH. The default
unit suite skips it (the contract-level gate is already covered by fast Foundry
tests in contracts/test/DiligenceRoom.t.sol and the submitter preflight by
tests/test_chain_submitter.py).
"""
import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "prove-compose-approval-gate-anvil.py"
_TOOLS_PRESENT = all(shutil.which(tool) for tool in ("anvil", "cast", "forge"))
_ENABLED = os.environ.get("DNAI_RUN_ANVIL_PROOFS") == "1"


@unittest.skipUnless(_ENABLED and _TOOLS_PRESENT, "set DNAI_RUN_ANVIL_PROOFS=1 with foundry on PATH")
class ComposeApprovalGateProofTest(unittest.TestCase):
    def test_gate_admits_only_approved_compose(self):
        result = subprocess.run(
            [sys.executable, str(_SCRIPT)],
            cwd=_SCRIPT.parents[1],
            check=False,
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        summary = json.loads(result.stdout[result.stdout.index("{"):])
        self.assertTrue(summary["gate_admits_only_approved"])
        self.assertEqual(summary["revert_when_unapproved"], "ComposeHashNotApproved")
        self.assertEqual(summary["revert_when_approved"], "InvalidResultAuthorization")
        self.assertEqual(summary["revert_after_revoke"], "ComposeHashNotApproved")
        self.assertFalse(summary["raw_secret_egress"])


if __name__ == "__main__":
    unittest.main()
