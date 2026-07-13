import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from eth_hash.auto import keccak

from tinker_delegate.governance_plan import (
    APPROVE_COMPOSE_HASH_SELECTOR,
    APPROVE_TEE_IDENTITY_SELECTOR,
    build_governance_plan_from_authorization,
)
from tinker_delegate.result_verifier import ResultAuthorization, ResultVerifierError

CONTRACT = "0x" + "55" * 20
TEE = "0x90F79bf6EB2c4f870365E785982E1f101E93b906"
COMPOSE = "0x" + "e5" * 32
POLICY_HASH = "0x" + "ab" * 32


def _authorization(*, authorized: bool = True, compose_hash: str = COMPOSE) -> ResultAuthorization:
    return ResultAuthorization(
        authorized=authorized,
        chain_id=84532,
        contract_address=CONTRACT,
        deal_id=0,
        tee_identity=TEE,
        compose_hash=compose_hash,
        score_band_value=3,
        compute_cost_wei=10**15,
        result_hash="0x" + "cd" * 32,
        authorization_expiry=2_000_000_000,
        verifier_address="0x" + "22" * 20,
        verifier_custody="dstack_derived",
        verifier_signature="0x" + "11" * 65,
        verifier_signature_hash="0x" + "33" * 32,
        authorization_digest="0x" + "44" * 32,
        signer_attestation_hash="0x" + "66" * 32,
        signer_attestation_report_data="0x" + "77" * 32,
        signer_attestation_quote_size=128,
        policy_hash=POLICY_HASH,
    )


class GovernancePlanTest(unittest.TestCase):
    def test_plan_has_both_approval_calls(self):
        plan = build_governance_plan_from_authorization(_authorization())
        funcs = [c.function for c in plan.calls]
        self.assertEqual(funcs, ["approveComposeHash", "approveTeeIdentity"])
        self.assertEqual(plan.contract_address.lower(), CONTRACT.lower())
        self.assertEqual(plan.compose_hash, COMPOSE)
        self.assertEqual(plan.policy_hash, POLICY_HASH)
        self.assertTrue(plan.requires_developer_broadcast)
        self.assertFalse(plan.raw_secret_egress)

    def test_calldata_matches_selectors_and_args(self):
        plan = build_governance_plan_from_authorization(_authorization())
        compose_call, identity_call = plan.calls

        expected_compose = "0x" + (APPROVE_COMPOSE_HASH_SELECTOR + bytes.fromhex("e5" * 32)).hex()
        self.assertEqual(compose_call.calldata, expected_compose)
        self.assertTrue(compose_call.calldata.startswith("0x" + keccak(b"approveComposeHash(bytes32)")[:4].hex()))

        tee_word = bytes(12) + bytes.fromhex(TEE[2:])
        expected_identity = "0x" + (APPROVE_TEE_IDENTITY_SELECTOR + tee_word + bytes.fromhex("e5" * 32)).hex()
        self.assertEqual(identity_call.calldata, expected_identity)

    def test_cast_commands_use_keystore_not_raw_key(self):
        plan = build_governance_plan_from_authorization(_authorization())
        blob = json.dumps(plan.to_public_dict())
        self.assertIn("--account dev", blob)
        self.assertNotIn("--private-key", blob)
        self.assertNotIn("--unlocked", blob)
        for call in plan.calls:
            self.assertIn("cast send", call.cast_command)
            self.assertIn(CONTRACT, call.cast_command)

    def test_unauthorized_result_rejected(self):
        with self.assertRaises(ResultVerifierError):
            build_governance_plan_from_authorization(_authorization(authorized=False))

    def test_zero_compose_hash_rejected(self):
        with self.assertRaises(ResultVerifierError):
            build_governance_plan_from_authorization(_authorization(compose_hash="0x" + "00" * 32))

    def test_output_is_bounded_no_secret_material(self):
        plan = build_governance_plan_from_authorization(_authorization())
        blob = json.dumps(plan.to_public_dict())
        # No signatures, digests, or verifier private material in the plan.
        self.assertNotIn("11" * 65, blob)  # verifier signature
        self.assertNotIn("44" * 32, blob)  # authorization digest
        self.assertFalse(plan.to_public_dict()["raw_secret_egress"])


class GovernancePlanCliTest(unittest.TestCase):
    def test_cli_emits_bounded_plan(self):
        payload = {
            "authorized": True,
            "chain_id": 84532,
            "contract_address": CONTRACT,
            "deal_id": 0,
            "tee_identity": TEE,
            "compose_hash": COMPOSE,
            "policy_hash": POLICY_HASH,
        }
        with tempfile.TemporaryDirectory() as tmp:
            auth_path = Path(tmp) / "auth.json"
            out_path = Path(tmp) / "plan.json"
            auth_path.write_text(json.dumps(payload), encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable, "-m", "tinker_delegate.main",
                    "governance-approval-plan", str(auth_path),
                    "--output", str(out_path),
                ],
                cwd=Path(__file__).resolve().parents[1],
                check=False, text=True, capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            plan = json.loads(out_path.read_text(encoding="utf-8"))
            self.assertEqual(
                [c["function"] for c in plan["calls"]],
                ["approveComposeHash", "approveTeeIdentity"],
            )
            self.assertFalse(plan["raw_secret_egress"])
            blob = json.dumps(plan)
            self.assertIn("--account dev", blob)
            self.assertNotIn("--private-key", blob)

    def test_cli_rejects_unauthorized(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth_path = Path(tmp) / "auth.json"
            auth_path.write_text(
                json.dumps({"authorized": False, "contract_address": CONTRACT,
                            "tee_identity": TEE, "compose_hash": COMPOSE}),
                encoding="utf-8",
            )
            result = subprocess.run(
                [sys.executable, "-m", "tinker_delegate.main",
                 "governance-approval-plan", str(auth_path)],
                cwd=Path(__file__).resolve().parents[1],
                check=False, text=True, capture_output=True,
            )
            self.assertEqual(result.returncode, 1)


if __name__ == "__main__":
    unittest.main()
