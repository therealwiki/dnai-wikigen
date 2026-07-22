import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from eth_account import Account
from eth_hash.auto import keccak

from tinker_delegate.compute_runtime_cli import (
    ATTESTATION_DOMAIN,
    AnchoredComputeExecutionAuthorizer,
    ComputeBootstrapError,
    _verify_current_execution_attestation,
    build_compute_runtime,
    main,
)
from tinker_delegate.compute_runtime import ComputeExecutionPolicyUnavailable
from tinker_delegate.config import Settings
from tinker_delegate.execution_policy_anchor import (
    AnchoredExecutionPolicyCoordinator,
)
from tinker_delegate.execution_policy_store import (
    ExecutionPolicyStore,
    execution_policy_approver_hash,
    execution_policy_approver_root_hash,
)
from tests.execution_policy_anchor_fakes import (
    MemoryExecutionPolicyAnchorGateway,
    WRITER_RELEASE,
)


IDENTITY = "0x" + "11" * 20
VAULT = "0x" + "22" * 20
COMPOSE = "0x" + "33" * 32


class ComputeRuntimeCliTest(unittest.TestCase):
    def test_installed_cli_fails_closed_before_any_mutation_without_adapter(self):
        output = io.StringIO()
        with redirect_stdout(output):
            code = main(["--once"])
        self.assertEqual(code, 78)
        status = json.loads(output.getvalue())
        self.assertEqual(
            status["reason"],
            "idempotent_tinker_provider_adapter_unavailable",
        )
        self.assertFalse(status["provider_authoritative"])
        self.assertTrue(status["execution_policy_anchor_gate_integrated"])
        self.assertFalse(status["legacy_credit_ledger_mutated"])
        self.assertFalse(status["raw_prompt_egress"])

    def test_compute_authorizer_rejects_anchor_writer_custody(self):
        with tempfile.TemporaryDirectory() as temporary:
            coordinator = AnchoredExecutionPolicyCoordinator(
                ExecutionPolicyStore(
                    Path(temporary) / "execution-policy.json",
                    integrity_key=b"p" * 32,
                ),
                MemoryExecutionPolicyAnchorGateway(read_only=False),
            )
            with self.assertRaisesRegex(
                ComputeExecutionPolicyUnavailable,
                "read-only policy anchor gateway",
            ):
                AnchoredComputeExecutionAuthorizer(Settings(), coordinator)
            coordinator.close()

    def test_production_builder_rejects_anchor_release_domain_drift(self):
        class IdempotentProvider:
            supports_idempotent_dispatch = True

        account = Account.from_key("0x" + "81" * 32)
        approver_hash = execution_policy_approver_hash(account.address)
        approver_root = execution_policy_approver_root_hash({approver_hash})
        gateway = MemoryExecutionPolicyAnchorGateway(read_only=True)
        with tempfile.TemporaryDirectory() as temporary:
            settings = Settings(
                execution_policy_store_path=str(
                    Path(temporary) / "execution-policy.json"
                ),
                execution_policy_approved_signers=account.address,
                execution_policy_approver_root_hash=approver_root,
                execution_policy_approval_domain=(
                    "base-sepolia:84532:"
                    + "91" * 32
                    + ":0x"
                    + "92" * 32
                    + ":"
                    + "93" * 32
                    + ":"
                    + approver_root
                ),
            )
            with (
                patch(
                    "tinker_delegate.compute_runtime_cli.dstack_utils.is_dstack_enabled",
                    return_value=True,
                ),
                patch(
                    "tinker_delegate.compute_runtime_cli.dstack_utils.is_dstack_simulator",
                    return_value=False,
                ),
                patch(
                    "tinker_delegate.compute_runtime_cli.execution_policy_integrity_key",
                    return_value=b"p" * 32,
                ),
                patch(
                    "tinker_delegate.compute_runtime_cli.HttpsExecutionPolicyAnchorGateway.from_settings",
                    return_value=gateway,
                ) as from_settings,
            ):
                with self.assertRaisesRegex(
                    ComputeBootstrapError,
                    "^execution_policy_anchor_gate_unavailable$",
                ):
                    build_compute_runtime(settings, provider=IdempotentProvider())
        from_settings.assert_called_once_with(settings, read_only=True)
        self.assertTrue(gateway.closed)

    def test_production_builder_rejects_approver_root_drift(self):
        class IdempotentProvider:
            supports_idempotent_dispatch = True

        account = Account.from_key("0x" + "82" * 32)
        configured_root = "94" * 32
        gateway = MemoryExecutionPolicyAnchorGateway(read_only=True)
        with tempfile.TemporaryDirectory() as temporary:
            settings = Settings(
                execution_policy_store_path=str(
                    Path(temporary) / "execution-policy.json"
                ),
                execution_policy_approved_signers=account.address,
                execution_policy_approver_root_hash=configured_root,
                execution_policy_approval_domain=(
                    "base-sepolia:84532:"
                    + WRITER_RELEASE[2:]
                    + ":0x"
                    + "95" * 32
                    + ":"
                    + "96" * 32
                    + ":"
                    + configured_root
                ),
            )
            with (
                patch(
                    "tinker_delegate.compute_runtime_cli.dstack_utils.is_dstack_enabled",
                    return_value=True,
                ),
                patch(
                    "tinker_delegate.compute_runtime_cli.dstack_utils.is_dstack_simulator",
                    return_value=False,
                ),
                patch(
                    "tinker_delegate.compute_runtime_cli.execution_policy_integrity_key",
                    return_value=b"p" * 32,
                ),
                patch(
                    "tinker_delegate.compute_runtime_cli.HttpsExecutionPolicyAnchorGateway.from_settings",
                    return_value=gateway,
                ),
                patch(
                    "tinker_delegate.compute_runtime_cli.verify_live_execution_policy_release_binding"
                ),
            ):
                with self.assertRaisesRegex(
                    ComputeBootstrapError,
                    "^execution_policy_anchor_gate_unavailable$",
                ):
                    build_compute_runtime(settings, provider=IdempotentProvider())
        self.assertTrue(gateway.closed)

    def test_fresh_quote_is_bound_to_identity_vault_chain_and_compose(self):
        report_data = keccak(
            ATTESTATION_DOMAIN
            + (84532).to_bytes(32, "big")
            + bytes.fromhex(VAULT[2:])
            + bytes.fromhex(IDENTITY[2:])
            + bytes.fromhex(COMPOSE[2:])
        )
        details = {
            "quote": "0x" + "44" * 512,
            "quote_report_data": "0x" + (report_data + b"\0" * 32).hex(),
            "compose_hash": COMPOSE[2:],
        }
        with patch(
            "tinker_delegate.compute_runtime_cli.dstack_utils.get_attestation_details",
            return_value=details,
        ):
            _verify_current_execution_attestation(
                identity_address=IDENTITY,
                vault_address=VAULT,
                expected_compose_hash=COMPOSE,
            )
        details["compose_hash"] = "55" * 32
        with patch(
            "tinker_delegate.compute_runtime_cli.dstack_utils.get_attestation_details",
            return_value=details,
        ):
            with self.assertRaises(ComputeBootstrapError):
                _verify_current_execution_attestation(
                    identity_address=IDENTITY,
                    vault_address=VAULT,
                    expected_compose_hash=COMPOSE,
                )

    def test_packaging_exposes_cli_without_local_key_or_dynamic_provider_flags(self):
        root = Path(__file__).resolve().parents[1]
        pyproject = (root / "pyproject.toml").read_text()
        source = (
            root / "tinker_delegate" / "compute_runtime_cli.py"
        ).read_text()
        self.assertIn(
            'tinker-compute-runtime = "tinker_delegate.compute_runtime_cli:main"',
            pyproject,
        )
        self.assertNotIn("--private-key", source)
        self.assertNotIn("--provider-module", source)
        self.assertNotIn("DSTACK_SIMULATOR_ENDPOINT", source)

    def test_dstack_compose_wires_shared_policy_leased_compute_worker(self):
        root = Path(__file__).resolve().parents[1]
        for name in (
            "docker-compose.dstack.yaml",
            "docker-compose.all.dstack.yaml",
        ):
            compose = (root / name).read_text()
            self.assertIn("compute-execution-worker:", compose)
            self.assertIn('profiles: ["compute-execution"]', compose)
            self.assertIn(
                'command: ["tinker-compute-runtime", "--poll"]',
                compose,
            )
            self.assertGreaterEqual(
                compose.count(
                    "TINKER_COMPUTE_DISPATCH_STORE_PATH: "
                    "/data/compute_exact_asset_dispatch.json"
                ),
                1,
            )
            self.assertGreaterEqual(
                compose.count(
                    "TINKER_EXECUTION_POLICY_STORE_PATH: "
                    "/data/execution_policy_state.json"
                ),
                2,
            )
            self.assertIn("- delegate-data:/data", compose)


if __name__ == "__main__":
    unittest.main()
