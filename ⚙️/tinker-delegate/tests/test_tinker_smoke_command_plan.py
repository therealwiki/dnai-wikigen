import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tinker_delegate.tinker_smoke_command_plan import (
    NEW_COMPOSE_HASH_PLACEHOLDER,
    build_tinker_smoke_command_plan,
)


COMPOSE_HASH = "0x" + "11" * 32
OS_IMAGE_HASH = "0x" + "22" * 32
ENCUMBRANCE_ADDRESS = "0x" + "33" * 20


def _manifest(*, live_has_project: bool = False, compose_approved: bool = True) -> dict:
    return {
        "phala": {
            "endpoints": {
                "delegate": "https://delegate.example",
            },
            "composeHash": COMPOSE_HASH,
            "appId": "app_123",
            "osImageHash": OS_IMAGE_HASH,
            "osIsDev": True,
            "tinkerSdkSmokeEvidence": {
                "attestedComposeHash": COMPOSE_HASH,
                "composeApproval": {
                    "composeHash": COMPOSE_HASH,
                    "approved": compose_approved,
                },
                "runtimeEnv": {
                    "containsTinkerProjectId": live_has_project,
                    "containsTinkerBaseUrl": False,
                },
                "smokeReceipt": {
                    "clientConfig": {
                        "apiKeyArgument": "provided",
                        "projectIdArgument": "provided" if live_has_project else "omitted",
                        "baseUrlArgument": "sdk_default",
                        "baseUrlHostFamily": "sdk_default",
                    },
                },
            },
        },
        "contracts": {
            "tinkerAccountEncumbrance": {
                "address": ENCUMBRANCE_ADDRESS,
                "maxSpendWei": 10 * 10**18,
                "policyUnitsPerUsdWei": 10**18,
                "emergencyHalted": False,
            },
        },
    }


class TinkerSmokeCommandPlanTest(unittest.TestCase):
    def test_missing_optional_project_config_is_ready_and_outputs_bounded_templates(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "deployment.json"
            manifest_path.write_text(json.dumps(_manifest(live_has_project=False)), encoding="utf-8")

            plan = build_tinker_smoke_command_plan(
                manifest_path=manifest_path,
                env={
                    "TINKER_RUNTIME_AUTH_TOKEN": "runtime-secret",
                    "BASE_SEPOLIA_RPC_URL": "https://rpc.example/secret",
                },
            ).to_public_dict()

            self.assertTrue(plan["ready"])
            self.assertEqual(plan["reasons"], [])
            self.assertIn("tinker_project_id_not_configured_optional", plan["warnings"])
            self.assertEqual(plan["next_action"], "run_smoke_sequence")
            self.assertEqual(plan["current_live_client_config"]["project_id_argument"], "omitted")
            self.assertNotIn('test -n "${TINKER_PROJECT_ID:-}"', plan["redeploy_shell"])
            self.assertIn("tinker-client-config", plan["client_config_install_argv"])
            self.assertIn("--install", plan["client_config_install_argv"])
            self.assertIn("--self-compose-hash-env", plan["redeploy_argv"])
            self.assertIn("TINKER_ENCUMBRANCE_COMPOSE_HASH", plan["redeploy_argv"])
            self.assertIn("TINKER_ENCUMBRANCE_COMPOSE_HASH", plan["verify_compose_argv"])
            self.assertIn("TINKER_PROXY_REQUIRE_DEPLOYMENT_POLICY", plan["verify_compose_argv"])
            self.assertIn("TINKER_PROXY_REQUIRE_ISSUE_POLICY", plan["verify_compose_argv"])
            self.assertIn('test -n "${TINKER_PROJECT_ID:-}"', plan["client_config_install_shell"])
            self.assertIn('test -n "${TINKER_RUNTIME_AUTH_TOKEN:-}"', plan["client_config_install_shell"])
            self.assertIn(COMPOSE_HASH, plan["smoke_argv"])
            rendered = json.dumps(plan)
            self.assertNotIn("runtime-secret", rendered)
            self.assertNotIn("rpc.example/secret", rendered)
            self.assertNotIn("--private-key", rendered)
            self.assertFalse(plan["raw_secret_egress"])

    def test_local_project_config_without_live_install_points_to_seal_step(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "deployment.json"
            manifest_path.write_text(json.dumps(_manifest(live_has_project=False)), encoding="utf-8")

            plan = build_tinker_smoke_command_plan(
                manifest_path=manifest_path,
                env={
                    "TINKER_PROJECT_ID": "secret-project-id",
                    "TINKER_RUNTIME_AUTH_TOKEN": "runtime-secret",
                    "BASE_SEPOLIA_RPC_URL": "https://rpc.example/secret",
                },
            ).to_public_dict()

            self.assertTrue(plan["ready"])
            self.assertEqual(plan["reasons"], [])
            self.assertEqual(plan["next_action"], "seal_client_config")
            self.assertIn("--project-id-env", plan["client_config_install_argv"])
            self.assertIn("TINKER_PROJECT_ID", plan["client_config_install_argv"])
            rendered = json.dumps(plan)
            self.assertNotIn("secret-project-id", rendered)
            self.assertNotIn("runtime-secret", rendered)
            self.assertNotIn("rpc.example/secret", rendered)

    def test_unapproved_current_compose_points_to_onchain_approval(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "deployment.json"
            manifest_path.write_text(
                json.dumps(_manifest(live_has_project=False, compose_approved=False)),
                encoding="utf-8",
            )

            plan = build_tinker_smoke_command_plan(
                manifest_path=manifest_path,
                env={
                    "TINKER_RUNTIME_AUTH_TOKEN": "runtime-secret",
                    "BASE_SEPOLIA_RPC_URL": "https://rpc.example/secret",
                },
            ).to_public_dict()

            self.assertFalse(plan["ready"])
            self.assertEqual(plan["reasons"], ["current_compose_not_approved"])
            self.assertFalse(plan["current_compose_approved"])
            self.assertEqual(plan["next_action"], "approve_current_compose")
            self.assertIn(COMPOSE_HASH, plan["approve_compose_argv"])
            self.assertIn(COMPOSE_HASH, plan["encumbrance_preflight_argv"])
            self.assertIn(COMPOSE_HASH, plan["smoke_argv"])

    def test_ready_manifest_builds_smoke_sequence_without_secret_values(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "deployment.json"
            manifest_path.write_text(json.dumps(_manifest(live_has_project=True)), encoding="utf-8")

            plan = build_tinker_smoke_command_plan(
                manifest_path=manifest_path,
                env={
                    "TINKER_PROJECT_ID": "secret-project-id",
                    "TINKER_RUNTIME_AUTH_TOKEN": "runtime-secret",
                    "BASE_SEPOLIA_RPC_URL": "https://rpc.example/secret",
                },
            ).to_public_dict()

            self.assertTrue(plan["ready"])
            self.assertEqual(plan["reasons"], [])
            self.assertEqual(plan["next_action"], "run_smoke_sequence")
            self.assertIn("phala_cvm_still_reports_dev_os", plan["warnings"])
            self.assertIn("--require-encumbrance", plan["smoke_argv"])
            self.assertIn("spend-tinker-compute", plan["encumbrance_preflight_argv"])
            self.assertIn("approveComposeHash(bytes32)", plan["approve_compose_argv"])
            self.assertIn("tinker-client-config", plan["client_config_install_argv"])
            self.assertIn('test -n "${TINKER_RUNTIME_AUTH_TOKEN:-}"', plan["smoke_shell"])
            rendered = json.dumps(plan)
            self.assertNotIn("secret-project-id", rendered)
            self.assertNotIn("runtime-secret", rendered)
            self.assertNotIn("rpc.example/secret", rendered)

    def test_account_access_blocked_makes_plan_not_ready(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "deployment.json"
            manifest_path.write_text(json.dumps(_manifest(live_has_project=True)), encoding="utf-8")
            plan = build_tinker_smoke_command_plan(
                manifest_path=manifest_path,
                account_access_state="access_blocked_billing",
                env={
                    "TINKER_RUNTIME_AUTH_TOKEN": "runtime-secret",
                    "BASE_SEPOLIA_RPC_URL": "https://rpc.example/secret",
                },
            ).to_public_dict()
            self.assertFalse(plan["ready"])
            self.assertIn("tinker_account_access_blocked", plan["reasons"])
            self.assertEqual(plan["next_action"], "resolve_tinker_account_activation")
            self.assertEqual(plan["account_access_state"], "access_blocked_billing")

    def test_account_access_active_is_ready_without_warning(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "deployment.json"
            manifest_path.write_text(json.dumps(_manifest(live_has_project=True)), encoding="utf-8")
            plan = build_tinker_smoke_command_plan(
                manifest_path=manifest_path,
                account_access_state="active",
                env={
                    "TINKER_RUNTIME_AUTH_TOKEN": "runtime-secret",
                    "BASE_SEPOLIA_RPC_URL": "https://rpc.example/secret",
                },
            ).to_public_dict()
            self.assertTrue(plan["ready"])
            self.assertEqual(plan["account_access_state"], "active")
            self.assertNotIn("tinker_account_access_unverified", plan["warnings"])
            self.assertNotIn("tinker_account_access_blocked", plan["reasons"])

    def test_account_access_default_is_unverified_warning(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "deployment.json"
            manifest_path.write_text(json.dumps(_manifest(live_has_project=True)), encoding="utf-8")
            plan = build_tinker_smoke_command_plan(
                manifest_path=manifest_path,
                env={
                    "TINKER_RUNTIME_AUTH_TOKEN": "runtime-secret",
                    "BASE_SEPOLIA_RPC_URL": "https://rpc.example/secret",
                },
            ).to_public_dict()
            self.assertTrue(plan["ready"])  # unverified is a warning, not a blocker
            self.assertEqual(plan["account_access_state"], "unverified")
            self.assertIn("tinker_account_access_unverified", plan["warnings"])

    def test_cli_writes_bounded_not_ready_plan(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "deployment.json"
            output_path = Path(tmpdir) / "plan.json"
            manifest_path.write_text(json.dumps(_manifest(live_has_project=False)), encoding="utf-8")

            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tinker_delegate.main",
                    "tinker-smoke-command-plan",
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
            self.assertIn("missing_runtime_auth_env", plan["reasons"])
            self.assertIn("missing_encumbrance_rpc_env", plan["reasons"])


if __name__ == "__main__":
    unittest.main()
