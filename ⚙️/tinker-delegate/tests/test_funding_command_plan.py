import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tinker_delegate.funding_command_plan import build_funding_command_plan


COMPOSE_HASH = "0x" + "11" * 32
OS_IMAGE_HASH = "0x" + "22" * 32
ENCUMBRANCE_ADDRESS = "0x" + "33" * 20


def _manifest(*, with_encumbrance: bool = True) -> dict:
    contracts = {}
    if with_encumbrance:
        contracts["tinkerAccountEncumbrance"] = {
            "status": "deployed_current_operator_controlled",
            "address": ENCUMBRANCE_ADDRESS,
            "initialComposeHash": COMPOSE_HASH,
            "initialComposeHashApproved": True,
            "maxAddBalanceWei": 10 * 10**18,
            "maxSpendWei": 10 * 10**18,
            "policyUnitsPerUsdWei": 10**18,
            "emergencyHalted": False,
        }
    return {
        "phala": {
            "endpoints": {
                "delegate": "https://delegate.example",
            },
            "composeHash": COMPOSE_HASH,
            "appId": "app_123",
            "osImageHash": OS_IMAGE_HASH,
            "osIsDev": False,
        },
        "contracts": contracts,
    }


class FundingCommandPlanTest(unittest.TestCase):
    def test_missing_encumbrance_contract_is_not_ready_but_outputs_bounded_templates(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "deployment.json"
            manifest_path.write_text(json.dumps(_manifest(with_encumbrance=False)), encoding="utf-8")

            plan = build_funding_command_plan(manifest_path=manifest_path).to_public_dict()

            self.assertFalse(plan["ready"])
            self.assertEqual(plan["reasons"], ["missing_tinker_encumbrance_contract"])
            self.assertEqual(plan["encumbrance_deployment_status"], "fresh_contract_suite_required")
            self.assertEqual(plan["delegate_api_url"], "https://delegate.example")
            self.assertIn("--require-encumbrance", plan["packet_argv"])
            self.assertIn("<missing-encumbrance-contract>", plan["packet_argv"])
            self.assertIn("encumbrance_deploy_dry_run_shell", plan)
            self.assertIn("encumbrance_deploy_broadcast_shell", plan)
            self.assertIn("BROADCAST=false", plan["encumbrance_deploy_dry_run_shell"])
            self.assertIn("BROADCAST=true", plan["encumbrance_deploy_broadcast_shell"])
            self.assertIn("deploy-base-sepolia.sh", plan["encumbrance_deploy_broadcast_shell"])
            self.assertNotIn("deploy-tinker-encumbrance-base-sepolia.sh", plan["encumbrance_deploy_broadcast_shell"])
            self.assertIn("new canonical seven-contract fresh release", plan["encumbrance_deploy_note"])
            self.assertIn("do not repair or overwrite one contract", plan["encumbrance_deploy_note"])
            self.assertIn("--account dev", plan["encumbrance_deploy_note"])
            rendered = json.dumps(plan)
            self.assertNotIn("Card number", rendered)
            self.assertNotIn("Bearer ", rendered)
            self.assertNotIn("tml-", rendered)
            self.assertNotIn("--private-key", rendered)
            self.assertNotIn("PRIVATE_KEY", rendered)

    def test_ready_manifest_builds_prompt_packet_command_with_contract_policy(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "deployment.json"
            manifest_path.write_text(json.dumps(_manifest()), encoding="utf-8")

            plan = build_funding_command_plan(
                manifest_path=manifest_path,
                amount_dollars=10,
                output_dir="./packet",
                validation_id="run-1",
            ).to_public_dict()

            self.assertTrue(plan["ready"])
            self.assertEqual(plan["reasons"], [])
            self.assertEqual(plan["encumbrance_contract_address"], ENCUMBRANCE_ADDRESS.lower())
            self.assertEqual(plan["encumbrance_deployment_status"], "existing_contract_recorded")
            self.assertEqual(plan["encumbrance_deploy_dry_run_argv"], [])
            self.assertEqual(plan["encumbrance_deploy_broadcast_argv"], [])
            self.assertEqual(plan["encumbrance_deploy_dry_run_shell"], "")
            self.assertEqual(plan["encumbrance_deploy_broadcast_shell"], "")
            self.assertIn("--fetch-attestation", plan["packet_argv"])
            self.assertIn("--run-card-attempt", plan["packet_argv"])
            self.assertIn("--prompt-card", plan["packet_argv"])
            self.assertIn("--run-reauth-attempt", plan["packet_argv"])
            self.assertIn("--run-add-balance-attempt", plan["packet_argv"])
            self.assertIn("--require-add-balance-endpoint", plan["packet_argv"])
            self.assertIn("--encumbrance-contract-address", plan["packet_argv"])
            self.assertIn(ENCUMBRANCE_ADDRESS, plan["packet_shell"])
            self.assertIn('test -n "${TINKER_RUNTIME_AUTH_TOKEN:-}"', plan["packet_shell"])
            self.assertIn('test -n "${BASE_SEPOLIA_RPC_URL:-}"', plan["packet_shell"])
            self.assertIn("Foundry --account dev", plan["encumbrance_deploy_note"])
            self.assertNotIn("--private-key", json.dumps(plan))

    def test_prefers_funding_validation_attested_hash_over_general_phala_hash(self):
        funding_hash = "0x" + "44" * 32
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest = _manifest()
            manifest["phala"]["fundingValidationEvidence"] = {
                "attestedComposeHash": funding_hash,
            }
            manifest_path = Path(tmpdir) / "deployment.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            plan = build_funding_command_plan(manifest_path=manifest_path).to_public_dict()

            self.assertEqual(plan["compose_hash"], funding_hash)
            self.assertIn(funding_hash, plan["packet_argv"])
            self.assertNotIn(COMPOSE_HASH, plan["packet_argv"])

    def test_amount_above_manifest_cap_is_not_ready(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "deployment.json"
            manifest_path.write_text(json.dumps(_manifest()), encoding="utf-8")

            plan = build_funding_command_plan(
                manifest_path=manifest_path,
                amount_dollars=11,
            ).to_public_dict()

            self.assertFalse(plan["ready"])
            self.assertIn("requested_amount_exceeds_tinker_encumbrance_cap", plan["reasons"])

    def test_cli_writes_bounded_not_ready_plan(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "deployment.json"
            output_path = Path(tmpdir) / "plan.json"
            manifest_path.write_text(json.dumps(_manifest(with_encumbrance=False)), encoding="utf-8")

            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tinker_delegate.main",
                    "funding-command-plan",
                    "--manifest",
                    str(manifest_path),
                    "--output",
                    str(output_path),
                ],
                check=False,
                cwd=Path(__file__).resolve().parents[1],
                text=True,
                capture_output=True,
            )

            self.assertEqual(result.returncode, 1)
            plan = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertFalse(plan["ready"])
            self.assertEqual(plan["reasons"], ["missing_tinker_encumbrance_contract"])
            self.assertEqual(plan["encumbrance_deployment_status"], "fresh_contract_suite_required")


if __name__ == "__main__":
    unittest.main()
