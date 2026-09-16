"""Production bootstrap for the exact-asset Compute execution CVM.

The bootstrap deliberately has no local-key, simulator, raw-prompt, arbitrary
provider module, or unverified-attestation flags. The only installed provider
is the release-pinned Tinker adapter. It checkpoints one attempt before the
first provider request and treats every post-boundary uncertainty as a terminal
ambiguity hold; it never claims upstream idempotent replay or redispatches.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, TextIO

from eth_hash.auto import keccak

from tinker_delegate import dstack_utils
from tinker_delegate.compute_runtime import (
    BASE_SEPOLIA_CHAIN_ID,
    CompiledRecipeExecutor,
    ComputeCycleResult,
    ComputeExecutionPolicyNotPassed,
    ComputeExecutionPolicyUnavailable,
    ComputeExecutionJournal,
    ComputeExecutionWorker,
    ComputeRuntimeError,
    DstackComputeExecutionIdentity,
    compute_execution_integrity_key,
)
from tinker_delegate.execution_policy_anchor import (
    AnchoredExecutionPolicyCoordinator,
    ExecutionPolicyAnchorError,
    HttpsExecutionPolicyAnchorGateway,
    verify_live_execution_policy_release_binding,
)
from tinker_delegate.execution_policy_store import (
    ExecutionPolicyNotPassed,
    ExecutionPolicyStore,
    ExecutionPolicyStoreError,
    ExecutionPolicyStoreUnavailable,
    execution_policy_integrity_key,
    execution_policy_trust_context,
)
from tinker_delegate.compute_vault_gateway import (
    HttpsComputeMeteringClient,
    HttpsComputeVaultGateway,
)
from tinker_delegate.config import Settings
from tinker_delegate.compute_tinker_provider import (
    TinkerProviderReleaseError,
    build_tinker_compute_provider,
    compute_provider_status_store,
)


STATUS_SCHEMA = "dnai.compute.execution-bootstrap-status.v1"
METERING_AUTH_TOKEN_ENV = "TINKER_COMPUTE_METERING_AUTH_TOKEN"
ATTESTATION_DOMAIN = b"dnai-wikigen/compute-execution-attestation/v1\0"
MIN_TDX_QUOTE_BYTES = 512
MAX_TDX_QUOTE_BYTES = 64 * 1024

_ADDRESS = re.compile(r"^0x[0-9a-f]{40}$")
_BYTES32 = re.compile(r"^0x[0-9a-f]{64}$")


class ComputeBootstrapError(ComputeRuntimeError):
    """A bounded release prerequisite is missing or inconsistent."""


class AnchoredComputeExecutionAuthorizer:
    """Bind exact Compute job IDs to one immutable policy release context."""

    def __init__(
        self,
        settings: Settings,
        coordinator: AnchoredExecutionPolicyCoordinator,
    ):
        if getattr(coordinator.gateway, "read_only", False) is not True:
            raise ComputeExecutionPolicyUnavailable(
                "Compute execution requires a read-only policy anchor gateway"
            )
        self.coordinator = coordinator
        try:
            (
                self.approval_domain_hash,
                self.approved_approver_hashes,
                self.approver_root_hash,
            ) = execution_policy_trust_context(settings)
        except (ExecutionPolicyStoreError, ExecutionPolicyStoreUnavailable) as exc:
            raise ComputeExecutionPolicyUnavailable(
                "execution-policy trust roots are unavailable"
            ) from exc

    @contextmanager
    def authorized_execution_lease(
        self,
        *,
        job_id: str,
        execution_context_hash: str,
        now: int,
    ):
        """Hold a fresh read-only anchored PASS through one whole worker cycle."""

        try:
            with self.coordinator.authorized_execution_lease(
                surface="compute_dispatch",
                resource_id=job_id,
                now=now,
                expected_approval_domain_hash=self.approval_domain_hash,
                expected_approver_root_hash=self.approver_root_hash,
                approved_approver_hashes=self.approved_approver_hashes,
                expected_execution_context_hash=execution_context_hash,
            ) as record:
                yield record
        except ExecutionPolicyNotPassed as exc:
            raise ComputeExecutionPolicyNotPassed(
                "execution policy is not passed for this Compute job"
            ) from exc
        except (
            ExecutionPolicyStoreError,
            ExecutionPolicyStoreUnavailable,
            ExecutionPolicyAnchorError,
            OSError,
        ) as exc:
            raise ComputeExecutionPolicyUnavailable(
                "execution-policy anchor verification is unavailable"
            ) from exc


@dataclass
class ComputeRuntimeBundle:
    worker: ComputeExecutionWorker
    gateway: HttpsComputeVaultGateway
    metering: HttpsComputeMeteringClient
    policy_coordinator: AnchoredExecutionPolicyCoordinator

    def close(self) -> None:
        try:
            self.metering.close()
        finally:
            try:
                self.gateway.close()
            finally:
                self.policy_coordinator.close()

    def __enter__(self) -> "ComputeRuntimeBundle":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()


def build_compute_runtime(
    settings: Settings,
    *,
    provider: CompiledRecipeExecutor,
) -> ComputeRuntimeBundle:
    """Construct the only production-shaped worker path.

    ``provider`` is dependency-injected for the compiled adapter. The
    installed CLI does not dynamically import providers: that would create an
    arbitrary-code configuration surface inside the TEE. The worker receives
    no bypass flag: construction requires a release-bound read-only anchor
    coordinator and every actionable cycle requires its exact job PASS lease.
    """

    if (
        getattr(provider, "supports_idempotent_dispatch", True) is not False
        or getattr(provider, "supports_at_most_once_dispatch", False) is not True
        or not callable(getattr(provider, "prepare_attempt", None))
    ):
        raise ComputeBootstrapError("at_most_once_provider_adapter_unavailable")
    if (
        getattr(provider, "supports_checkpointed_workload_release", False)
        is not True
    ):
        raise ComputeBootstrapError("checkpointed_workload_release_unavailable")
    if not dstack_utils.is_dstack_enabled() or dstack_utils.is_dstack_simulator():
        raise ComputeBootstrapError("real_dstack_cvm_required")
    policy_path = str(settings.execution_policy_store_path or "").strip()
    if not policy_path:
        raise ComputeBootstrapError("execution_policy_anchor_gate_unavailable")

    policy_gateway = None
    policy_coordinator = None
    try:
        policy_store = ExecutionPolicyStore(
            policy_path,
            integrity_key=execution_policy_integrity_key(settings),
        )
        policy_gateway = HttpsExecutionPolicyAnchorGateway.from_settings(
            settings,
            read_only=True,
        )
        verify_live_execution_policy_release_binding(settings, policy_gateway)
        policy_coordinator = AnchoredExecutionPolicyCoordinator(
            policy_store,
            policy_gateway,
        )
        policy_authorizer = AnchoredComputeExecutionAuthorizer(
            settings,
            policy_coordinator,
        )
    except (
        ComputeExecutionPolicyUnavailable,
        ExecutionPolicyStoreError,
        ExecutionPolicyStoreUnavailable,
        ExecutionPolicyAnchorError,
        OSError,
        ValueError,
    ) as exc:
        if policy_coordinator is not None:
            policy_coordinator.close()
        elif policy_gateway is not None:
            policy_gateway.close()
        raise ComputeBootstrapError(
            "execution_policy_anchor_gate_unavailable"
        ) from exc

    try:
        path = str(settings.compute_dispatch_store_path or "").strip()
        if not path:
            raise ComputeBootstrapError("compute_dispatch_journal_missing")
        rpc_url = str(settings.compute_chain_rpc_url or "").strip()
        vault = _address(settings.compute_vault_address)
        runtime_hash = _bytes32(settings.compute_vault_runtime_code_hash)
        expected_compose = _bytes32(settings.compute_vault_compose_hash)
        metering_policy_set_hash = _bytes32(
            settings.compute_metering_policy_set_hash
        )
        metering_url = str(settings.compute_metering_url or "").strip()
        metering_token = os.environ.get(METERING_AUTH_TOKEN_ENV, "").strip()
        key_path = str(settings.compute_execution_signer_key_path or "").strip()
        if not rpc_url or not metering_url or not metering_token or not key_path:
            raise ComputeBootstrapError("compute_execution_configuration_missing")
    except ComputeRuntimeError:
        policy_coordinator.close()
        raise

    try:
        identity = DstackComputeExecutionIdentity.from_key_path(key_path)
        _verify_current_execution_attestation(
            identity_address=identity.address,
            vault_address=vault,
            expected_compose_hash=expected_compose,
        )
        journal = ComputeExecutionJournal(
            path,
            integrity_key=compute_execution_integrity_key(settings),
        )
    except ComputeRuntimeError:
        policy_coordinator.close()
        raise
    except Exception:
        policy_coordinator.close()
        raise ComputeBootstrapError("dstack_execution_identity_unavailable") from None

    gateway = None
    metering = None
    try:
        gateway = HttpsComputeVaultGateway(
            rpc_url,
            vault_address=vault,
            runtime_code_hash=runtime_hash,
            identity=identity,
        )
        metering = HttpsComputeMeteringClient(
            metering_url,
            auth_token=metering_token,
        )
        worker = ComputeExecutionWorker(
            journal=journal,
            gateway=gateway,
            identity=identity,
            provider=provider,
            metering=metering,
            policy_authorizer=policy_authorizer,
            metering_policy_set_hash=metering_policy_set_hash,
            confirmations=int(settings.compute_execution_confirmations),
            max_block_age_seconds=int(
                settings.compute_execution_max_block_age_seconds
            ),
            max_future_block_skew_seconds=int(
                settings.compute_execution_max_future_block_skew_seconds
            ),
        )
        return ComputeRuntimeBundle(worker, gateway, metering, policy_coordinator)
    except Exception:
        if metering is not None:
            metering.close()
        if gateway is not None:
            gateway.close()
        policy_coordinator.close()
        raise


def _verify_current_execution_attestation(
    *,
    identity_address: str,
    vault_address: str,
    expected_compose_hash: str,
) -> None:
    """Bind one fresh in-memory quote to identity, vault, chain and compose."""

    identity = _address(identity_address)
    vault = _address(vault_address)
    compose = _bytes32(expected_compose_hash)
    report_data = keccak(
        ATTESTATION_DOMAIN
        + BASE_SEPOLIA_CHAIN_ID.to_bytes(32, "big")
        + bytes.fromhex(vault[2:])
        + bytes.fromhex(identity[2:])
        + bytes.fromhex(compose[2:])
    )
    try:
        details = dstack_utils.get_attestation_details(report_data)
        quote = _hex_bytes(
            details.get("quote"),
            minimum=MIN_TDX_QUOTE_BYTES,
            maximum=MAX_TDX_QUOTE_BYTES,
        )
        observed_report_data = _hex_bytes(
            details.get("quote_report_data"), minimum=64, maximum=64
        )
        observed_compose = _bytes32(details.get("compose_hash"))
    except Exception:
        raise ComputeBootstrapError("fresh_dstack_attestation_unavailable") from None
    # Keep the quote live only through this function. Its bytes and hash are not
    # persisted or emitted; chain admission supplies the external compose and
    # identity check for every exact job snapshot.
    if (
        not quote
        or observed_report_data[:32] != report_data
        or observed_report_data[32:] != b"\0" * 32
        or observed_compose != compose
    ):
        raise ComputeBootstrapError("dstack_attestation_binding_mismatch")


def _installed_provider(settings: Settings) -> CompiledRecipeExecutor:
    """Construct the sole compiled, release-pinned provider adapter."""

    try:
        return build_tinker_compute_provider(settings)
    except TinkerProviderReleaseError as exc:
        raise ComputeBootstrapError("tinker_provider_release_unavailable") from exc


def _public_status(state: str, reason: str) -> dict[str, Any]:
    return {
        "schema": STATUS_SCHEMA,
        "state": state,
        "reason": reason,
        "chain_id": BASE_SEPOLIA_CHAIN_ID,
        "execution_policy_anchor_gate_integrated": True,
        "provider_authoritative": False,
        "provider_dispatch_may_have_occurred": False,
        "legacy_credit_ledger_mutated": False,
        "raw_prompt_egress": False,
        "raw_examples_egress": False,
        "raw_output_egress": False,
        "exception_detail_egress": False,
    }


def _write_status(stream: TextIO, value: dict[str, Any]) -> None:
    stream.write(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    )
    stream.flush()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="tinker-compute-runtime",
        description="Run fail-closed exact-asset Compute execution cycles.",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--once",
        action="store_true",
        help="Run one bounded journal cycle and exit.",
    )
    mode.add_argument(
        "--poll",
        action="store_true",
        help="Continuously poll the shared journal using serialized cycles.",
    )
    args = parser.parse_args(argv)
    if not args.once and not args.poll:
        _write_status(
            sys.stdout,
            _public_status("blocked", "explicit_execution_mode_required"),
        )
        return 64
    try:
        settings = Settings()
        provider = _installed_provider(settings)
        with build_compute_runtime(settings, provider=provider) as runtime:
            heartbeat = compute_provider_status_store(settings)
            heartbeat.write_ready(settings)
            if args.once:
                result: ComputeCycleResult = runtime.worker.run_once()
                _write_status(sys.stdout, result.to_public_dict())
                return 0
            interval = float(settings.compute_execution_poll_interval_seconds)
            if not 0.1 <= interval <= 60.0:
                raise ComputeBootstrapError(
                    "compute_execution_poll_interval_invalid"
                )
            while True:
                heartbeat.write_ready(settings)
                result = runtime.worker.run_once()
                _write_status(sys.stdout, result.to_public_dict())
                time.sleep(interval)
    except KeyboardInterrupt:
        return 0
    except (ComputeBootstrapError, ComputeRuntimeError):
        _write_status(
            sys.stdout,
            _public_status("blocked", "compute_execution_bootstrap_rejected"),
        )
        return 78
    except Exception:
        _write_status(
            sys.stdout,
            _public_status("retryable", "bounded_runtime_unavailable"),
        )
        return 75


def _address(value: Any) -> str:
    normalized = str(value).lower()
    if not _ADDRESS.fullmatch(normalized) or normalized == "0x" + "00" * 20:
        raise ComputeBootstrapError("compute_execution_configuration_invalid")
    return normalized


def _bytes32(value: Any) -> str:
    normalized = str(value).lower()
    if not normalized.startswith("0x") and re.fullmatch(
        r"[0-9a-f]{64}", normalized
    ):
        normalized = "0x" + normalized
    if not _BYTES32.fullmatch(normalized) or normalized == "0x" + "00" * 32:
        raise ComputeBootstrapError("compute_execution_configuration_invalid")
    return normalized


def _hex_bytes(value: Any, *, minimum: int, maximum: int) -> bytes:
    if not isinstance(value, str):
        raise ValueError
    normalized = value.lower().removeprefix("0x")
    if (
        len(normalized) % 2
        or not minimum * 2 <= len(normalized) <= maximum * 2
        or not re.fullmatch(r"[0-9a-f]+", normalized)
    ):
        raise ValueError
    return bytes.fromhex(normalized)


if __name__ == "__main__":
    raise SystemExit(main())
