"""Current-ABI unit checks and opt-in local compose-approval proof on Anvil.

This spawns a real Anvil chain and deploys the contract, so it is opt-in: it runs
only when DNAI_RUN_ANVIL_PROOFS=1 and anvil/cast/forge are on PATH. The default
unit suite skips it (the contract-level gate is already covered by fast Foundry
tests in contracts/test/DiligenceRoom.t.sol and the submitter preflight by
tests/test_chain_submitter.py).

This is deliberately a local-mode synthetic proof, not production admission or
QVL verification. Production's outer readiness guard requires exactly one
approved compose and rejects missing/revoked admission before the compose gate;
the harness must not disable or reinterpret that production guard.
"""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "prove-compose-approval-gate-anvil.py"
_TOOLS_PRESENT = all(shutil.which(tool) for tool in ("anvil", "cast", "forge"))
_ENABLED = os.environ.get("DNAI_RUN_ANVIL_PROOFS") == "1"
_SPEC = importlib.util.spec_from_file_location("compose_approval_gate_anvil_proof", _SCRIPT)
_PROOF = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_PROOF)


class ComposeApprovalGateHarnessUnitTest(unittest.TestCase):
    def test_deploys_explicit_local_constructor_with_unlocked_account(self):
        with patch.object(_PROOF, "_run_json", return_value={"deployedTo": _PROOF.TEE}) as run:
            self.assertEqual(_PROOF._deploy("http://127.0.0.1:12345"), _PROOF.TEE)
        args = run.call_args.args[0]
        self.assertEqual(args[-3:], ["--constructor-args", "false", _PROOF.ZERO_ADDRESS])
        self.assertIn("--unlocked", args)
        self.assertEqual(args[args.index("--from") + 1], _PROOF.DEVELOPER)
        self.assertNotIn("--private-key", args)

    def test_submission_uses_current_dual_authorization_abi_and_fresh_bounded_leases(self):
        with patch.object(_PROOF, "_block_timestamp", return_value=12345), \
                patch.object(_PROOF, "_call_revert_reason", return_value="reverted") as call:
            self.assertEqual(_PROOF._submit_revert_reason("http://127.0.0.1:12345", _PROOF.TEE), "reverted")
        rpc, sender, contract, signature, values = call.call_args.args
        self.assertEqual(sender, _PROOF.TEE)
        self.assertEqual(signature, "submitResult(uint256,uint8,uint256,bytes32,uint256,bytes32,uint256,bytes,bytes)")
        self.assertEqual(len(values), 9)
        self.assertEqual(values[3:], [
            _PROOF.COMPOSE_HASH, "12645", _PROOF.ATTESTATION_EVIDENCE_HASH,
            "12585", _PROOF.DUMMY_SIG, _PROOF.DUMMY_SIG,
        ])

    def test_deal_expiry_uses_advanced_chain_time_and_survives_compose_delay(self):
        with patch.object(_PROOF, "_block_timestamp", return_value=12345), \
                patch.object(_PROOF.time, "time", return_value=1), \
                patch.object(_PROOF, "_send") as send:
            expiry = _PROOF._create_deal("http://127.0.0.1:12345", _PROOF.TEE)
        self.assertEqual(expiry, 12345 + 3 * 24 * 60 * 60)
        self.assertGreater(expiry, 12345 + 172800)
        self.assertEqual(send.call_args.args[4][1], str(expiry))

    def test_chain_guard_rejects_external_or_nonlocal_network_before_deployment(self):
        with patch.object(_PROOF, "_run", return_value="31337") as run:
            for endpoint in ("https://sepolia.base.org", "http://localhost:12345", "http://user@127.0.0.1:12345"):
                with self.subTest(endpoint=endpoint), self.assertRaisesRegex(RuntimeError, "loopback-only"):
                    _PROOF._assert_local_chain(endpoint)
            run.assert_not_called()
            _PROOF._assert_local_chain("http://127.0.0.1:12345")
        with patch.object(_PROOF, "_run", return_value="84532"), \
                self.assertRaisesRegex(RuntimeError, "local chain 31337"):
            _PROOF._assert_local_chain("http://127.0.0.1:12345")


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
        self.assertEqual(summary["proof_scope"], "local_mode_synthetic_compose_gate_only")
        self.assertEqual(summary["chain_id"], 31337)
        self.assertFalse(summary["production_release"])
        self.assertFalse(summary["production_e2e"])
        self.assertFalse(summary["genuine_attestation_evidence"])
        self.assertTrue(summary["authorization_bindings_frozen"])
        self.assertTrue(summary["authorization_binding_timelocks_checked"])
        self.assertEqual(summary["admission_timelock_seconds"], 172800)
        self.assertTrue(summary["early_compose_activation_rejected"])
        self.assertTrue(summary["elapsed_timelock_alone_does_not_admit"])
        self.assertTrue(summary["gate_required"])
        self.assertTrue(summary["gate_admits_only_approved"])
        self.assertEqual(summary["revert_when_unapproved"], "ComposeHashNotApproved")
        self.assertEqual(summary["revert_when_approved"], "InvalidResultAuthorization")
        self.assertEqual(summary["revert_after_revoke"], "ComposeHashNotApproved")
        self.assertFalse(summary["raw_secret_egress"])


if __name__ == "__main__":
    unittest.main()
