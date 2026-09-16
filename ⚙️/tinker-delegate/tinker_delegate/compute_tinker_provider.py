"""Release-pinned Tinker execution for exact-asset Compute jobs.

This adapter deliberately does **not** claim that Tinker's server deduplicates
repeated ``X-Idempotency-Key`` values. The deterministic header installed on
every allowlisted request is a request commitment only. The execution journal
therefore checkpoints one at-most-once attempt immediately before the first
provider request. A crash, timeout, redirect, transport error, malformed
response, or any other post-boundary failure becomes a terminal
``provider_outcome_ambiguous`` hold; it is never automatically redispatched and
the encrypted workload is retained for separately attested reconciliation.

All provider configuration and credentials are loaded inside a real dstack CVM
from purpose-separated sealed stores. Customer proxy JWTs, browser credentials,
raw prompts/examples, decoded model output, provider identifiers, exception
details, SDK logs, and upstream response bodies never enter the journal or a
public status surface.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import importlib.metadata
import json
import logging
import os
import re
import secrets
import stat
import time
from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Protocol, Sequence
from urllib.parse import urlsplit

import httpx

from tinker_delegate import dstack_utils
from tinker_delegate.api_key_store import build_api_key_store
from tinker_delegate.compute_runtime import (
    COMPILED_RECIPES,
    CompiledRecipePolicy,
    ComputeDispatchIntent,
    ComputeProviderDispatchFailure,
    ComputeRuntimePolicyError,
    ComputeRuntimeRetryable,
    ProviderUsage,
)
from tinker_delegate.compute_provider_release import (
    PINNED_QWEN3_TOKENIZER_PATH,
    PINNED_QWEN3_TOKENIZER_RELEASE_SHA256,
    PINNED_TINKER_BASE_URL,
    PINNED_TINKER_BASE_URL_SHA256,
    PINNED_TINKER_PROVIDER_RELEASE_SHA256,
    PINNED_TINKER_REQUEST_CONTRACT_SHA256,
    PINNED_TINKER_SDK_SOURCE_SHA256,
    PINNED_TINKER_SDK_VERSION,
    PROVIDER_ADAPTER_ID,
)
from tinker_delegate.compute_workload_ingress import (
    INFERENCE_PAYLOAD_SCHEMA,
    INFERENCE_WORKLOAD_SCHEMA,
    SFT_JSONL_WORKLOAD_SCHEMA,
    ComputeWorkloadIngressError,
    ComputeWorkloadIngressService,
    ComputeWorkloadIngressUnavailable,
    ComputeWorkloadDispatchClaim,
    build_compute_workload_ingress,
)
from tinker_delegate.secure_secret_file import secure_secret_file_exists
from tinker_delegate.tinker_client_config_store import (
    build_tinker_client_config_store,
)
from tinker_delegate.tinker_training import _build_training_data
from tinker_delegate.session import IsolatedTinkerSession


PROVIDER_STATUS_SCHEMA = "dnai.compute.provider-runtime-status.v1"
PROVIDER_STATUS_MAC_DOMAIN = b"dnai-wikigen/compute-provider-status/v1\0"
PROVIDER_RESULT_DOMAIN = b"dnai-wikigen/compute-provider-result/v1\0"
PROVIDER_REQUEST_KEY_DOMAIN = b"dnai-wikigen/tinker-request-key/v1\0"
PROVIDER_REQUEST_TRANSCRIPT_DOMAIN = (
    b"dnai-wikigen/tinker-request-transcript/v1\0"
)

MAX_PROVIDER_REQUEST_BYTES = 16 * 1024 * 1024
MAX_PROVIDER_RESPONSE_BYTES = 32 * 1024 * 1024
MAX_TOKENIZER_FILES = 64
MAX_TOKENIZER_FILE_BYTES = 32 * 1024 * 1024
MAX_TOKENIZER_TOTAL_BYTES = 128 * 1024 * 1024

_SHA256 = re.compile(r"^sha256:(?!0{64}$)[0-9a-f]{64}$")
_BYTES32 = re.compile(r"^0x(?!0{64}$)[0-9a-f]{64}$")
_ADDRESS = re.compile(r"^0x(?!0{40}$)[0-9a-f]{40}$")
_PROJECT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_DSTACK_PATH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$")
_SAFE_RELATIVE_PATH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$")
_PROVIDER_DATA_ROOT = Path("/data")

_FORBIDDEN_PROVIDER_ENV = (
    "TINKER_API_KEY",
    "TINKER_BASE_URL",
    "TINKER_PROJECT_ID",
    "TINKER_TAGS",
    "TINKER_CREDENTIAL_CMD",
    "TINKER_FEATURE_GATES",
    "TINKER_SUBPROCESS_SAMPLING",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
)

_PINNED_CLIENT_CONFIG: dict[str, str | int | bool] = {
    "billing_exception_max_pause_duration_sec": 0,
    "credential_default_source": "api_key",
    "fwd_via_fwdbwd": False,
    "inflight_response_bytes_semaphore_size": 52_428_800,
    "parallel_fwdbwd_chunks": False,
    "pjwt_auth_enabled": False,
    "proto_compress_fwdbwd": False,
    "proto_write_fwdbwd": False,
    "sample_dispatch_bytes_semaphore_size": 10_485_760,
    "sample_enable_stuck_detection": False,
    "sample_max_concurrent_requests": 1,
    "sample_no_retries": True,
    "use_pyqwest_transport": False,
}

_ROUTE_CONTRACT: dict[str, tuple[str, frozenset[str], frozenset[str]]] = {
    "/api/v1/create_session": (
        "create_session",
        frozenset({"tags", "user_metadata", "sdk_version", "project_id", "type"}),
        frozenset(),
    ),
    "/api/v1/create_sampling_session": (
        "create_sampling_session",
        frozenset({"session_id", "sampling_session_seq_id", "base_model", "type"}),
        frozenset({"model_path"}),
    ),
    "/api/v1/asample": (
        "asample",
        frozenset(
            {
                "num_samples",
                "prompt",
                "sampling_params",
                "sampling_session_id",
                "seq_id",
                "prompt_logprobs",
                "topk_prompt_logprobs",
                "type",
            }
        ),
        frozenset({"base_model", "model_path"}),
    ),
    "/api/v1/retrieve_future": (
        "retrieve_future",
        frozenset({"request_id", "allow_metadata_only"}),
        frozenset(),
    ),
    "/api/v1/create_model": (
        "create_model",
        frozenset(
            {
                "session_id",
                "model_seq_id",
                "base_model",
                "user_metadata",
                "lora_config",
                "type",
            }
        ),
        frozenset(),
    ),
    "/api/v1/get_info": (
        "get_info",
        frozenset({"model_id", "type"}),
        frozenset(),
    ),
    "/api/v1/forward_backward": (
        "forward_backward",
        frozenset({"forward_backward_input", "model_id", "seq_id"}),
        frozenset(),
    ),
    "/api/v1/optim_step": (
        "optim_step",
        frozenset({"adam_params", "model_id", "seq_id", "type"}),
        frozenset(),
    ),
}

_REQUEST_CONTRACT_MANIFEST = {
    "schema": "dnai.compute.tinker-request-contract.v1",
    "adapter_id": PROVIDER_ADAPTER_ID,
    "sdk_version": PINNED_TINKER_SDK_VERSION,
    "sdk_source_sha256": PINNED_TINKER_SDK_SOURCE_SHA256,
    "base_url_sha256": PINNED_TINKER_BASE_URL_SHA256,
    "routes": [
        {
            "path": path,
            "name": value[0],
            "method": "POST",
            "required_fields": sorted(value[1]),
            "optional_fields": sorted(value[2]),
        }
        for path, value in sorted(_ROUTE_CONTRACT.items())
    ],
    "idempotency_header": "X-Idempotency-Key",
    "idempotency_semantics": "request_commitment_only_no_server_replay_claim",
    "automatic_redispatch": False,
    "redirects": False,
    "environment_proxies": False,
    "telemetry": False,
    "provider_identifiers_persisted": False,
}


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ComputeRuntimePolicyError("provider value is not canonical JSON") from exc


_COMPUTED_TINKER_REQUEST_CONTRACT_SHA256 = "sha256:" + hashlib.sha256(
    _canonical_json(_REQUEST_CONTRACT_MANIFEST)
).hexdigest()
if _COMPUTED_TINKER_REQUEST_CONTRACT_SHA256 != PINNED_TINKER_REQUEST_CONTRACT_SHA256:
    raise RuntimeError("pinned Tinker request contract digest drifted")


class TinkerProviderReleaseError(ComputeRuntimePolicyError):
    """One exact provider release/configuration binding was rejected."""


class TinkerProviderUnavailable(ComputeRuntimeRetryable):
    """A bounded local/provider dependency is unavailable."""


class TinkerRequestContractError(RuntimeError):
    """A request was rejected before it could cross the provider boundary."""


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _request_contract_public() -> dict[str, Any]:
    return {
        "adapter_id": PROVIDER_ADAPTER_ID,
        "sdk_version": PINNED_TINKER_SDK_VERSION,
        "sdk_source_sha256": PINNED_TINKER_SDK_SOURCE_SHA256,
        "request_contract_sha256": PINNED_TINKER_REQUEST_CONTRACT_SHA256,
        "base_url_sha256": PINNED_TINKER_BASE_URL_SHA256,
        "provider_release_sha256": PINNED_TINKER_PROVIDER_RELEASE_SHA256,
        "idempotency_header_role": "request_commitment_only",
        "idempotent_provider_replay_claimed": False,
        "automatic_provider_redispatch": False,
        "adapter_contract": {
            "at_most_once_attempt_checkpoint": True,
            "terminal_ambiguity_hold": True,
            "ambiguous_outcome_ciphertext_retained": True,
        },
        "runtime_guarantees": {
            "at_most_once_attempt_checkpoint": False,
            "terminal_ambiguity_hold": False,
            "ambiguous_outcome_ciphertext_retained": False,
        },
    }


def _canonical_data_file_path(value: Any, *, purpose: str) -> Path:
    raw = str(value or "").strip()
    candidate = Path(raw)
    try:
        common = os.path.commonpath((str(_PROVIDER_DATA_ROOT), raw))
    except ValueError as exc:
        raise TinkerProviderReleaseError(f"{purpose} path is invalid") from exc
    if (
        not raw
        or not candidate.is_absolute()
        or os.path.normpath(raw) != raw
        or candidate.name in {"", ".", ".."}
        or any(part in {"", ".", ".."} for part in candidate.parts)
        or common != str(_PROVIDER_DATA_ROOT)
        or candidate == _PROVIDER_DATA_ROOT
    ):
        raise TinkerProviderReleaseError(f"{purpose} path is invalid")
    if purpose == "provider status" and candidate.parent != _PROVIDER_DATA_ROOT:
        raise TinkerProviderReleaseError("provider status path is invalid")
    return candidate


def installed_tinker_sdk_source_sha256() -> str:
    """Hash every installed Tinker ``.py`` source file for same-version drift."""

    try:
        import tinker

        root = Path(tinker.__file__).resolve().parent
        files = sorted(
            path
            for path in root.rglob("*.py")
            if "__pycache__" not in path.parts
        )
        if not files or len(files) > 1_000:
            raise OSError
        entries = []
        total = 0
        for path in files:
            details = path.lstat()
            if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
                raise OSError
            raw = path.read_bytes()
            total += len(raw)
            if total > 16 * 1024 * 1024:
                raise OSError
            entries.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "bytes": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                }
            )
        return _sha256(
            _canonical_json(
                {
                    "schema": "dnai.compute.tinker-sdk-source-contract.v1",
                    "version": PINNED_TINKER_SDK_VERSION,
                    "files": entries,
                }
            )
        )
    except Exception:
        raise TinkerProviderReleaseError("Tinker SDK source contract is unavailable") from None


def tokenizer_release_sha256(path: str | Path) -> str:
    """Commit an exact, symlink-free local tokenizer directory."""

    root = Path(path)
    try:
        root_info = root.lstat()
        if not stat.S_ISDIR(root_info.st_mode):
            raise OSError
        candidates = sorted(root.rglob("*"), key=lambda item: item.as_posix())
        entries: list[dict[str, Any]] = []
        total = 0
        for candidate in candidates:
            details = candidate.lstat()
            if stat.S_ISDIR(details.st_mode):
                continue
            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_nlink != 1
                or details.st_size < 1
                or details.st_size > MAX_TOKENIZER_FILE_BYTES
            ):
                raise OSError
            relative = candidate.relative_to(root).as_posix()
            if (
                not _SAFE_RELATIVE_PATH.fullmatch(relative)
                or any(part in {"", ".", ".."} for part in relative.split("/"))
            ):
                raise OSError
            raw = candidate.read_bytes()
            total += len(raw)
            if total > MAX_TOKENIZER_TOTAL_BYTES:
                raise OSError
            entries.append(
                {
                    "path": relative,
                    "bytes": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                }
            )
        if not entries or len(entries) > MAX_TOKENIZER_FILES:
            raise OSError
        return _sha256(
            _canonical_json(
                {
                    "schema": "dnai.compute.qwen3-8b-tokenizer-release.v1",
                    "files": entries,
                }
            )
        )
    except Exception:
        raise TinkerProviderReleaseError("tokenizer release is unavailable") from None


def _validate_provider_environment() -> None:
    if any(os.environ.get(name, "") for name in _FORBIDDEN_PROVIDER_ENV):
        raise TinkerProviderReleaseError("provider environment override is forbidden")
    if os.environ.get("TINKER_TELEMETRY") != "0":
        raise TinkerProviderReleaseError("Tinker telemetry must be explicitly disabled")
    if os.environ.get("HF_HUB_OFFLINE") != "1" or os.environ.get(
        "TRANSFORMERS_OFFLINE"
    ) != "1":
        raise TinkerProviderReleaseError("offline tokenizer mode is required")


def _validate_dstack_path(value: Any, *, purpose: str) -> str:
    path = str(value or "").strip()
    if (
        not _DSTACK_PATH.fullmatch(path)
        or purpose not in path
        or any(part in {"", ".", ".."} for part in path.split("/"))
    ):
        raise TinkerProviderReleaseError("provider dstack key path is invalid")
    return path


def _provider_release_binding(settings: Any) -> dict[str, Any]:
    return {
        "adapter_id": str(settings.compute_provider_adapter_id or ""),
        "sdk_version": str(settings.compute_provider_sdk_version or ""),
        "sdk_source_sha256": str(
            settings.compute_provider_sdk_source_sha256 or ""
        ),
        "request_contract_sha256": str(
            settings.compute_provider_request_contract_sha256 or ""
        ),
        "base_url_sha256": str(settings.compute_provider_base_url_sha256 or ""),
        "tokenizer_release_sha256": str(
            settings.compute_provider_tokenizer_release_sha256 or ""
        ),
        "provider_release_sha256": PINNED_TINKER_PROVIDER_RELEASE_SHA256,
        "chain_id": int(settings.compute_workload_chain_id),
        "vault_address": str(settings.compute_vault_address or "").lower(),
        "vault_runtime_code_hash": str(
            settings.compute_vault_runtime_code_hash or ""
        ).lower(),
        "compose_hash": str(settings.compute_vault_compose_hash or "").lower(),
        "metering_policy_set_hash": str(
            settings.compute_metering_policy_set_hash or ""
        ).lower(),
        "workload_release_authority_sha256": str(
            settings.compute_workload_release_authority_sha256 or ""
        ),
        "workload_measurement_policy_set_sha256": str(
            settings.compute_workload_measurement_policy_set_sha256 or ""
        ),
        "workload_qvl_measurement_policy_sha256": str(
            settings.compute_workload_qvl_measurement_policy_sha256 or ""
        ),
        "workload_main_runtime_evidence_sha256": str(
            settings.compute_workload_main_runtime_evidence_sha256 or ""
        ),
        "idempotent_provider_replay_claimed": False,
        "automatic_provider_redispatch": False,
        "ambiguous_outcome_ciphertext_retained": True,
    }


def validate_compute_provider_public_release(settings: Any) -> dict[str, Any]:
    """Validate descriptor and release pins without touching worker secrets.

    The delegate uses this projection only to authenticate a worker heartbeat.
    Actual tokenizer bytes, sealed provider credentials, workload decryption,
    chain policy, and the fresh TDX execution identity remain worker-only.
    """

    if settings.compute_provider_execution_enabled is not True:
        raise TinkerProviderReleaseError("provider execution is disabled")
    if not dstack_utils.is_dstack_enabled() or dstack_utils.is_dstack_simulator():
        raise TinkerProviderReleaseError("real dstack CVM is required")
    _validate_provider_environment()
    expected = {
        "adapter_id": PROVIDER_ADAPTER_ID,
        "sdk_version": PINNED_TINKER_SDK_VERSION,
        "sdk_source_sha256": PINNED_TINKER_SDK_SOURCE_SHA256,
        "request_contract_sha256": PINNED_TINKER_REQUEST_CONTRACT_SHA256,
        "base_url_sha256": PINNED_TINKER_BASE_URL_SHA256,
    }
    binding = _provider_release_binding(settings)
    if any(binding[key] != value for key, value in expected.items()):
        raise TinkerProviderReleaseError("provider release pin mismatch")
    try:
        installed_version = importlib.metadata.version("tinker")
    except importlib.metadata.PackageNotFoundError:
        raise TinkerProviderReleaseError("Tinker SDK is unavailable") from None
    if installed_version != PINNED_TINKER_SDK_VERSION:
        raise TinkerProviderReleaseError("Tinker SDK version drift")
    if installed_tinker_sdk_source_sha256() != PINNED_TINKER_SDK_SOURCE_SHA256:
        raise TinkerProviderReleaseError("Tinker SDK source drift")

    tokenizer_path = str(settings.compute_provider_tokenizer_path or "").strip()
    tokenizer_digest = str(
        settings.compute_provider_tokenizer_release_sha256 or ""
    )
    if (
        tokenizer_path != PINNED_QWEN3_TOKENIZER_PATH
        or tokenizer_digest != PINNED_QWEN3_TOKENIZER_RELEASE_SHA256
    ):
        raise TinkerProviderReleaseError("tokenizer release pin mismatch")

    timeout = float(settings.compute_provider_request_timeout_seconds)
    ttl = int(settings.compute_provider_status_ttl_seconds)
    if not 5.0 <= timeout <= 300.0 or not 10 <= ttl <= 120:
        raise TinkerProviderReleaseError("provider runtime bound is invalid")
    _canonical_data_file_path(
        settings.compute_provider_status_path,
        purpose="provider status",
    )
    _validate_dstack_path(
        settings.compute_provider_result_key_path,
        purpose="compute_provider_result",
    )
    _validate_dstack_path(
        settings.compute_provider_status_key_path,
        purpose="compute_provider_status",
    )
    if (
        str(settings.compute_provider_status_integrity_key or "")
        or str(settings.api_key_store_key or "")
        or str(settings.client_config_store_key or "")
        or str(settings.project_id or "")
        or str(settings.base_url or "")
    ):
        raise TinkerProviderReleaseError("explicit provider secrets/config are forbidden")

    for path_value in (
        settings.api_key_store_path,
        settings.client_config_store_path,
        settings.compute_workload_ingress_store_path,
        settings.compute_dispatch_store_path,
    ):
        _canonical_data_file_path(path_value, purpose="sealed provider")

    if (
        int(settings.compute_workload_chain_id) != 84_532
        or not _ADDRESS.fullmatch(binding["vault_address"])
        or not _BYTES32.fullmatch(binding["vault_runtime_code_hash"])
        or not _BYTES32.fullmatch(binding["compose_hash"])
        or not _BYTES32.fullmatch(binding["metering_policy_set_hash"])
    ):
        raise TinkerProviderReleaseError("exact-asset release binding is invalid")
    for value in (
        settings.compute_workload_fresh_deployment_receipt_sha256,
        settings.compute_workload_deployment_intent_sha256,
        settings.compute_workload_release_authority_sha256,
        settings.compute_workload_measurement_policy_set_sha256,
        settings.compute_workload_qvl_measurement_policy_sha256,
        settings.compute_workload_main_runtime_evidence_sha256,
        settings.compute_workload_qvl_release_policy_hash,
    ):
        if not _SHA256.fullmatch(str(value or "")):
            raise TinkerProviderReleaseError("workload release pin is invalid")
    qvl = urlsplit(str(settings.compute_workload_qvl_url or ""))
    if (
        qvl.scheme != "https"
        or not qvl.hostname
        or qvl.username
        or qvl.password
        or qvl.fragment
        or not _ADDRESS.fullmatch(
            str(settings.compute_workload_qvl_verifier_address or "").lower()
        )
        or not str(settings.compute_workload_cvm_id or "")
        or not str(settings.compute_workload_ceremony_nonce or "")
    ):
        raise TinkerProviderReleaseError("workload QVL release is invalid")
    return binding


def validate_compute_provider_release(settings: Any) -> dict[str, Any]:
    """Validate worker-only files after the public release binding is exact."""

    binding = validate_compute_provider_public_release(settings)
    tokenizer_path = str(settings.compute_provider_tokenizer_path or "").strip()
    tokenizer_digest = str(
        settings.compute_provider_tokenizer_release_sha256 or ""
    )
    if tokenizer_release_sha256(tokenizer_path) != tokenizer_digest:
        raise TinkerProviderReleaseError("tokenizer release pin mismatch")
    return binding


def compute_provider_static_capability(settings: Any) -> dict[str, Any]:
    """Bounded public projection; never decrypts provider credentials."""

    result = {
        "schema": "dnai.compute.provider-capability.v1",
        "source_present": True,
        "release_configured": False,
        "provider_dispatch": False,
        "allowed_operations": ["inference", "training"],
        "allowed_result_policies": ["bounded_summary_receipt"],
        **_request_contract_public(),
        "reason": "provider_execution_not_enabled",
    }
    try:
        validate_compute_provider_public_release(settings)
    except TinkerProviderReleaseError as exc:
        reason_map = {
            "provider execution is disabled": "provider_execution_not_enabled",
            "real dstack CVM is required": "real_dstack_cvm_required",
            "Tinker SDK is unavailable": "tinker_sdk_unavailable",
            "Tinker SDK version drift": "tinker_sdk_version_drift",
            "Tinker SDK source drift": "tinker_sdk_source_drift",
            "provider release pin mismatch": "provider_release_pin_mismatch",
            "tokenizer release pin mismatch": "tokenizer_release_pin_mismatch",
            "Tinker telemetry must be explicitly disabled": "telemetry_not_disabled",
            "offline tokenizer mode is required": "offline_tokenizer_not_enforced",
            "provider environment override is forbidden": "provider_environment_override",
        }
        result["reason"] = reason_map.get(str(exc), "provider_release_incomplete")
        return result
    result.update(
        {
            "release_configured": True,
            # Process presence is checked independently through the heartbeat.
            "provider_dispatch": False,
            "reason": "fresh_provider_runtime_heartbeat_required",
        }
    )
    return result


def _provider_status_integrity_key(settings: Any) -> bytes:
    explicit = str(settings.compute_provider_status_integrity_key or "")
    if dstack_utils.is_dstack_enabled():
        if explicit:
            raise TinkerProviderReleaseError(
                "explicit provider status key is local-only"
            )
        material = dstack_utils.derive_storage_key(
            _validate_dstack_path(
                settings.compute_provider_status_key_path,
                purpose="compute_provider_status",
            )
        )
    else:
        if len(explicit.encode("utf-8")) < 32:
            raise TinkerProviderReleaseError("provider status key is unavailable")
        material = explicit.encode("utf-8")
    return hashlib.sha256(
        b"dnai-wikigen/compute-provider-status-key/v1\0" + material
    ).digest()


class ComputeProviderStatusStore:
    """Atomic HMAC-authenticated process-presence heartbeat.

    This is explicitly not TDX evidence. Per-job execution still requires the
    exact chain, execution-policy, recipient-QVL, and workload leases.
    """

    def __init__(self, path: str | Path, *, integrity_key: bytes):
        self.path = Path(path)
        if (
            not self.path.is_absolute()
            or self.path.name in {"", ".", ".."}
            or os.path.normpath(str(self.path)) != str(self.path)
            or len(integrity_key) < 32
        ):
            raise TinkerProviderReleaseError("provider status store is invalid")
        self.key = bytes(integrity_key)

    @contextmanager
    def _opened_parent(self) -> Iterator[int]:
        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        descriptor = -1
        try:
            descriptor = os.open(self.path.parent, flags)
            details = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(details.st_mode)
                or details.st_uid != os.geteuid()
                or stat.S_IMODE(details.st_mode) & 0o022
            ):
                raise OSError
            yield descriptor
        except OSError:
            raise TinkerProviderReleaseError(
                "provider status directory is unavailable"
            ) from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    @staticmethod
    def _file_identity(details: os.stat_result) -> tuple[int, ...]:
        return (
            details.st_dev,
            details.st_ino,
            details.st_size,
            details.st_mtime_ns,
            details.st_ctime_ns,
            details.st_mode,
            details.st_uid,
            details.st_nlink,
        )

    @staticmethod
    def _require_status_file(details: os.stat_result) -> None:
        if (
            not stat.S_ISREG(details.st_mode)
            or stat.S_IMODE(details.st_mode) != 0o600
            or details.st_uid != os.geteuid()
            or details.st_nlink != 1
            or not 2 <= details.st_size <= 32 * 1024
        ):
            raise OSError

    def write_ready(self, settings: Any, *, observed_at: int | None = None) -> None:
        timestamp = int(time.time()) if observed_at is None else int(observed_at)
        body = {
            "schema": PROVIDER_STATUS_SCHEMA,
            "state": "ready",
            "observed_at": timestamp,
            "release": _provider_release_binding(settings),
            "process_presence_only": True,
            "tdx_evidence": False,
            "provider_credential_present": True,
            "provider_credential_returned": False,
            "raw_secret_egress": False,
        }
        envelope = {
            "body": body,
            "mac": hmac.new(
                self.key,
                PROVIDER_STATUS_MAC_DOMAIN + _canonical_json(body),
                hashlib.sha256,
            ).hexdigest(),
        }
        encoded = _canonical_json(envelope) + b"\n"
        temporary = f".{self.path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
        descriptor = -1
        with self._opened_parent() as directory:
            try:
                try:
                    initial = os.stat(
                        self.path.name,
                        dir_fd=directory,
                        follow_symlinks=False,
                    )
                    self._require_status_file(initial)
                    initial_identity = self._file_identity(initial)
                except FileNotFoundError:
                    initial_identity = None
                descriptor = os.open(
                    temporary,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                    0o600,
                    dir_fd=directory,
                )
                view = memoryview(encoded)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise OSError
                    view = view[written:]
                os.fchmod(descriptor, 0o600)
                os.fsync(descriptor)
                os.close(descriptor)
                descriptor = -1
                try:
                    before_replace = os.stat(
                        self.path.name,
                        dir_fd=directory,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    before_replace = None
                if initial_identity is None:
                    if before_replace is not None:
                        raise OSError
                elif (
                    before_replace is None
                    or self._file_identity(before_replace) != initial_identity
                ):
                    raise OSError
                os.replace(
                    temporary,
                    self.path.name,
                    src_dir_fd=directory,
                    dst_dir_fd=directory,
                )
                committed = os.stat(
                    self.path.name,
                    dir_fd=directory,
                    follow_symlinks=False,
                )
                self._require_status_file(committed)
                if committed.st_size != len(encoded):
                    raise OSError
                os.fsync(directory)
            except Exception:
                if descriptor >= 0:
                    os.close(descriptor)
                try:
                    os.unlink(temporary, dir_fd=directory)
                except FileNotFoundError:
                    pass
                except OSError:
                    pass
                raise TinkerProviderReleaseError(
                    "provider status write is unavailable"
                ) from None

    def read_fresh(
        self,
        settings: Any,
        *,
        now: int | None = None,
    ) -> dict[str, Any]:
        timestamp = int(time.time()) if now is None else int(now)
        try:
            with self._opened_parent() as directory:
                before_path = os.stat(
                    self.path.name,
                    dir_fd=directory,
                    follow_symlinks=False,
                )
                self._require_status_file(before_path)
                descriptor = os.open(
                    self.path.name,
                    os.O_RDONLY
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=directory,
                )
                try:
                    before = os.fstat(descriptor)
                    self._require_status_file(before)
                    if self._file_identity(before) != self._file_identity(before_path):
                        raise OSError
                    chunks: list[bytes] = []
                    remaining = before.st_size
                    while remaining:
                        chunk = os.read(descriptor, min(remaining, 65_536))
                        if not chunk:
                            raise OSError
                        chunks.append(chunk)
                        remaining -= len(chunk)
                    if os.read(descriptor, 1):
                        raise OSError
                    after = os.fstat(descriptor)
                    after_path = os.stat(
                        self.path.name,
                        dir_fd=directory,
                        follow_symlinks=False,
                    )
                    if (
                        self._file_identity(after) != self._file_identity(before)
                        or self._file_identity(after_path)
                        != self._file_identity(before)
                    ):
                        raise OSError
                    raw = b"".join(chunks)
                finally:
                    os.close(descriptor)
            envelope = json.loads(raw)
            if not isinstance(envelope, dict) or set(envelope) != {"body", "mac"}:
                raise OSError
            body = envelope["body"]
            if not isinstance(body, dict) or set(body) != {
                "schema",
                "state",
                "observed_at",
                "release",
                "process_presence_only",
                "tdx_evidence",
                "provider_credential_present",
                "provider_credential_returned",
                "raw_secret_egress",
            }:
                raise OSError
            expected = hmac.new(
                self.key,
                PROVIDER_STATUS_MAC_DOMAIN + _canonical_json(body),
                hashlib.sha256,
            ).hexdigest()
            if not isinstance(envelope["mac"], str) or not hmac.compare_digest(
                envelope["mac"], expected
            ):
                raise OSError
            observed = int(body["observed_at"])
            if (
                body["schema"] != PROVIDER_STATUS_SCHEMA
                or body["state"] != "ready"
                or body["release"] != _provider_release_binding(settings)
                or body["process_presence_only"] is not True
                or body["tdx_evidence"] is not False
                or body["provider_credential_present"] is not True
                or body["provider_credential_returned"] is not False
                or body["raw_secret_egress"] is not False
                or observed > timestamp + 5
                or timestamp - observed
                > int(settings.compute_provider_status_ttl_seconds)
            ):
                raise OSError
            return {
                "authenticated": True,
                "fresh": True,
                "process_presence_only": True,
                "tdx_evidence": False,
                "observed_at": observed,
            }
        except Exception:
            raise TinkerProviderReleaseError(
                "provider runtime heartbeat is unavailable"
            ) from None


def compute_provider_public_capability(settings: Any) -> dict[str, Any]:
    result = compute_provider_static_capability(settings)
    if result["release_configured"] is not True:
        return result
    try:
        heartbeat = ComputeProviderStatusStore(
            settings.compute_provider_status_path,
            integrity_key=_provider_status_integrity_key(settings),
        ).read_fresh(settings)
    except TinkerProviderReleaseError:
        result["reason"] = "fresh_provider_runtime_heartbeat_required"
        return result
    result.update(
        {
            "provider_dispatch": True,
            "reason": "ready_at_most_once_ambiguity_hold",
            "runtime": heartbeat,
            "runtime_guarantees": {
                "at_most_once_attempt_checkpoint": True,
                "terminal_ambiguity_hold": True,
                "ambiguous_outcome_ciphertext_retained": True,
            },
        }
    )
    return result


@dataclass(frozen=True)
class TinkerRequestTranscriptEntry:
    route: str
    method: str
    request_body_sha256: str
    request_key_sha256: str

    def to_private_dict(self) -> dict[str, str]:
        return {
            "route": self.route,
            "method": self.method,
            "request_body_sha256": self.request_body_sha256,
            "request_key_sha256": self.request_key_sha256,
        }


class TinkerDispatchRequestGuard:
    """Enforce the exact provider origin, route, shape, and request key."""

    def __init__(
        self,
        *,
        dispatch_id: str,
        api_key: str,
        operation: str,
    ):
        normalized = str(dispatch_id).lower()
        if not _BYTES32.fullmatch(normalized):
            raise TinkerProviderReleaseError("dispatch ID is invalid")
        if (
            not isinstance(api_key, str)
            or not api_key.startswith("tml-")
            or not 8 <= len(api_key.encode("utf-8")) <= 512
            or any(character.isspace() for character in api_key)
        ):
            raise TinkerProviderReleaseError("sealed provider credential is invalid")
        if operation not in {"inference", "training"}:
            raise TinkerProviderReleaseError("provider operation is unsupported")
        self._dispatch_id = normalized
        self._api_key = api_key
        self._operation = operation
        self._armed = False
        self._boundary_crossed = False
        self._transcript: list[TinkerRequestTranscriptEntry] = []

    @property
    def provider_boundary_crossed(self) -> bool:
        return self._boundary_crossed

    @property
    def transcript(self) -> tuple[TinkerRequestTranscriptEntry, ...]:
        return tuple(self._transcript)

    def arm_after_reauthentication(self) -> None:
        if self._armed or self._boundary_crossed or self._transcript:
            raise TinkerProviderReleaseError("provider request guard is already armed")
        self._armed = True

    async def on_request(self, request: httpx.Request) -> None:
        if not self._armed or self._boundary_crossed and not self._transcript:
            raise TinkerRequestContractError("provider request guard is not armed")
        split = urlsplit(str(request.url))
        base = urlsplit(PINNED_TINKER_BASE_URL)
        if (
            request.method.upper() != "POST"
            or split.scheme != "https"
            or split.hostname != base.hostname
            or split.port not in {None, 443}
            or split.username
            or split.password
            or split.query
            or split.fragment
            or not split.path.startswith(base.path + "/")
        ):
            raise TinkerRequestContractError("provider request origin is not allowlisted")
        route_path = split.path[len(base.path) :]
        contract = _ROUTE_CONTRACT.get(route_path)
        if contract is None:
            raise TinkerRequestContractError("provider request route is not allowlisted")
        route_name, required_fields, optional_fields = contract
        if self._operation == "inference" and route_name not in {
            "create_session",
            "create_sampling_session",
            "asample",
            "retrieve_future",
        }:
            raise TinkerRequestContractError("provider route is outside inference recipe")
        if self._operation == "training" and route_name not in {
            "create_session",
            "create_model",
            "get_info",
            "forward_backward",
            "optim_step",
            "retrieve_future",
        }:
            raise TinkerRequestContractError("provider route is outside training recipe")
        body = await request.aread()
        if not body or len(body) > MAX_PROVIDER_REQUEST_BYTES:
            raise TinkerRequestContractError("provider request body is outside its bound")
        content_type = request.headers.get("content-type", "").split(";", 1)[0].lower()
        if content_type != "application/json":
            raise TinkerRequestContractError("provider request encoding is unsupported")
        try:
            value = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise TinkerRequestContractError("provider request body is invalid") from None
        if (
            not isinstance(value, dict)
            or not required_fields.issubset(value)
            or not set(value).issubset(required_fields | optional_fields)
        ):
            raise TinkerRequestContractError("provider request shape is not allowlisted")
        self._validate_route_value(route_name, value)
        if any(
            header in request.headers
            for header in ("authorization", "cookie", "proxy-authorization")
        ):
            raise TinkerRequestContractError("forbidden provider header")
        if request.headers.get("x-api-key") != self._api_key:
            raise TinkerRequestContractError("provider credential header mismatch")
        body_digest = hashlib.sha256(body).hexdigest()
        key_material = _canonical_json(
            {
                "schema": "dnai.compute.tinker-request-key.v1",
                "dispatch_id": self._dispatch_id,
                "method": "POST",
                "route": route_name,
                "body_sha256": body_digest,
            }
        )
        request_key = "dnai-" + base64.urlsafe_b64encode(
            hashlib.sha256(
                PROVIDER_REQUEST_KEY_DOMAIN + key_material
            ).digest()
        ).decode("ascii").rstrip("=")
        request.headers["X-Idempotency-Key"] = request_key
        self._transcript.append(
            TinkerRequestTranscriptEntry(
                route=route_name,
                method="POST",
                request_body_sha256=body_digest,
                request_key_sha256=hashlib.sha256(
                    request_key.encode("ascii")
                ).hexdigest(),
            )
        )
        # The hook runs immediately before transport dispatch. From this point
        # onward the upstream outcome is conservatively considered ambiguous
        # unless the complete bounded response sequence succeeds.
        self._boundary_crossed = True

    async def on_response(self, response: httpx.Response) -> None:
        if not self._boundary_crossed:
            raise TinkerRequestContractError("provider response preceded request")
        if 300 <= response.status_code < 400 or response.has_redirect_location:
            raise TinkerRequestContractError("provider redirect is forbidden")
        content_length = response.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > MAX_PROVIDER_RESPONSE_BYTES:
                    raise TinkerRequestContractError("provider response is oversized")
            except ValueError:
                raise TinkerRequestContractError("provider response length is invalid") from None
        raw = await response.aread()
        if len(raw) > MAX_PROVIDER_RESPONSE_BYTES:
            raise TinkerRequestContractError("provider response is oversized")
        if response.status_code < 200 or response.status_code >= 300:
            # Never parse, log, or retain provider error bodies.
            raise TinkerRequestContractError("provider returned a bounded failure")

    def _validate_route_value(self, route: str, value: Mapping[str, Any]) -> None:
        if route == "create_session":
            if (
                value.get("tags") != []
                or value.get("user_metadata") != {}
                or value.get("sdk_version") != PINNED_TINKER_SDK_VERSION
                or value.get("type") != "create_session"
                or not isinstance(value.get("project_id"), str)
            ):
                raise TinkerRequestContractError("create-session request is not compiled")
        elif route == "create_sampling_session":
            if (
                value.get("sampling_session_seq_id") != 0
                or value.get("base_model") != "Qwen/Qwen3-8B"
                or value.get("type") != "create_sampling_session"
                or "model_path" in value
            ):
                raise TinkerRequestContractError("sampling-session request is not compiled")
        elif route == "asample":
            params = value.get("sampling_params")
            if (
                value.get("num_samples") != 1
                or value.get("seq_id") != 0
                or value.get("prompt_logprobs") is not False
                or value.get("topk_prompt_logprobs") != 0
                or value.get("type") != "sample"
                or not isinstance(params, dict)
                or params.get("temperature") != 0
                or not isinstance(params.get("max_tokens"), int)
                or not 1 <= params["max_tokens"] <= 4_096
                or "base_model" in value
                or "model_path" in value
            ):
                raise TinkerRequestContractError("sample request is not compiled")
        elif route == "retrieve_future":
            if (
                not isinstance(value.get("request_id"), str)
                or not value["request_id"]
                or value.get("allow_metadata_only") not in {True, False}
            ):
                raise TinkerRequestContractError("future request is not compiled")
        elif route == "create_model":
            lora = value.get("lora_config")
            metadata = value.get("user_metadata")
            if (
                value.get("model_seq_id") != 0
                or value.get("base_model") != "Qwen/Qwen3-8B"
                or value.get("type") != "create_model"
                or not isinstance(metadata, dict)
                or not isinstance(lora, dict)
                or lora.get("rank") != 32
                or lora.get("train_mlp") is not True
                or lora.get("train_attn") is not True
                or lora.get("train_unembed") is not True
            ):
                raise TinkerRequestContractError("create-model request is not compiled")
        elif route == "get_info":
            if value.get("type") != "get_info":
                raise TinkerRequestContractError("model-info request is not compiled")
        elif route == "forward_backward":
            request = value.get("forward_backward_input")
            if (
                value.get("seq_id") != 1
                or not isinstance(request, dict)
                or request.get("loss_fn") != "cross_entropy"
                or not isinstance(request.get("data"), list)
                or not request["data"]
            ):
                raise TinkerRequestContractError("training request is not compiled")
        elif route == "optim_step":
            adam = value.get("adam_params")
            if (
                value.get("seq_id") != 2
                or value.get("type") != "optim_step"
                or not isinstance(adam, dict)
                or adam.get("learning_rate") != 0.0001
                or adam.get("beta1") != 0.9
                or adam.get("beta2") != 0.95
                or adam.get("eps") != 1e-12
                or adam.get("weight_decay") != 0.0
                or adam.get("grad_clip_norm") != 0.0
            ):
                raise TinkerRequestContractError("optimizer request is not compiled")

    def assert_compiled_sequence(self) -> None:
        routes: list[str] = []
        for entry in self._transcript:
            if not routes or routes[-1] != entry.route:
                routes.append(entry.route)
        expected = (
            ["create_session", "create_sampling_session", "asample", "retrieve_future"]
            if self._operation == "inference"
            else [
                "create_session",
                "create_model",
                "retrieve_future",
                "get_info",
                "forward_backward",
                "retrieve_future",
                "optim_step",
                "retrieve_future",
            ]
        )
        if routes != expected or not self._boundary_crossed:
            raise TinkerRequestContractError("provider request sequence is incomplete")

    @property
    def private_transcript_sha256(self) -> str:
        if not self._transcript:
            raise TinkerRequestContractError("provider request transcript is empty")
        return _sha256(
            PROVIDER_REQUEST_TRANSCRIPT_DOMAIN
            + _canonical_json([entry.to_private_dict() for entry in self._transcript])
        )


@dataclass(frozen=True)
class TinkerCompiledExecution:
    prefill_tokens: int
    sample_tokens: int
    training_tokens: int
    private_result_sha256: str = field(repr=False)
    private_transcript_sha256: str = field(repr=False)

    def __post_init__(self) -> None:
        for value in (
            self.prefill_tokens,
            self.sample_tokens,
            self.training_tokens,
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise TinkerRequestContractError("provider usage is invalid")
        if not _SHA256.fullmatch(self.private_result_sha256) or not _SHA256.fullmatch(
            self.private_transcript_sha256
        ):
            raise TinkerRequestContractError("private provider commitment is invalid")


class TinkerRecipeRunner(Protocol):
    @property
    def provider_boundary_crossed(self) -> bool: ...

    def run(
        self,
        *,
        settings: Any,
        intent: ComputeDispatchIntent,
        policy: CompiledRecipePolicy,
        dispatch_id: str,
        plaintext: bytearray,
        tokenizer: Any,
        api_key: str,
        project_id: str,
        guard: TinkerDispatchRequestGuard,
        reauthenticate: Callable[[], Any],
    ) -> TinkerCompiledExecution: ...


class TinkerCompiledRecipeRunner:
    """Execute the two frozen Qwen3-8B recipes through Tinker 0.22.7."""

    def __init__(self):
        self._last_guard: TinkerDispatchRequestGuard | None = None

    @property
    def provider_boundary_crossed(self) -> bool:
        return bool(
            self._last_guard is not None
            and self._last_guard.provider_boundary_crossed
        )

    def run(
        self,
        *,
        settings: Any,
        intent: ComputeDispatchIntent,
        policy: CompiledRecipePolicy,
        dispatch_id: str,
        plaintext: bytearray,
        tokenizer: Any,
        api_key: str,
        project_id: str,
        guard: TinkerDispatchRequestGuard,
        reauthenticate: Callable[[], Any],
    ) -> TinkerCompiledExecution:
        self._last_guard = guard
        # This obtains a fresh QVL/release/envelope binding immediately before
        # the first possible provider request. It returns a fixed validation
        # marker and never exposes the quote or plaintext.
        reauthenticate()
        guard.arm_after_reauthentication()
        http_client = httpx.AsyncClient(
            base_url=PINNED_TINKER_BASE_URL,
            timeout=httpx.Timeout(
                float(settings.compute_provider_request_timeout_seconds)
            ),
            follow_redirects=False,
            trust_env=False,
            limits=httpx.Limits(
                max_connections=1,
                max_keepalive_connections=1,
            ),
            event_hooks={
                "request": [guard.on_request],
                "response": [guard.on_response],
            },
        )
        service_client = None
        previous_disable = logging.root.manager.disable
        try:
            import tinker

            logging.disable(logging.CRITICAL)
            with open(os.devnull, "w", encoding="utf-8") as sink, redirect_stdout(
                sink
            ), redirect_stderr(sink):
                service_client = tinker.ServiceClient(
                    user_metadata={},
                    project_id=project_id,
                    api_key=api_key,
                    base_url=PINNED_TINKER_BASE_URL,
                    timeout=httpx.Timeout(
                        float(settings.compute_provider_request_timeout_seconds)
                    ),
                    max_retries=0,
                    http_client=http_client,
                    _client_config=dict(_PINNED_CLIENT_CONFIG),
                )
                self._cancel_heartbeat(service_client)
                if intent.operation == "inference":
                    result = self._run_inference(
                        tinker,
                        service_client,
                        tokenizer,
                        intent,
                        plaintext,
                    )
                else:
                    result = self._run_training(
                        tinker,
                        service_client,
                        tokenizer,
                        intent,
                        dispatch_id,
                        plaintext,
                    )
            guard.assert_compiled_sequence()
            return TinkerCompiledExecution(
                prefill_tokens=result[0],
                sample_tokens=result[1],
                training_tokens=result[2],
                private_result_sha256=result[3],
                private_transcript_sha256=guard.private_transcript_sha256,
            )
        finally:
            logging.disable(previous_disable)
            self._close_clients(service_client, http_client)

    @staticmethod
    def _cancel_heartbeat(service_client: Any) -> None:
        holder = service_client.holder
        future = holder.run_coroutine_threadsafe(holder._async_cleanup())
        future.result(timeout=5)
        holder._session_heartbeat_task = None

    @staticmethod
    def _close_clients(service_client: Any, http_client: httpx.AsyncClient) -> None:
        try:
            if service_client is not None:
                holder = service_client.holder
                try:
                    holder.run_coroutine_threadsafe(
                        holder._async_cleanup()
                    ).result(timeout=5)
                except Exception:
                    pass
                try:
                    holder.run_coroutine_threadsafe(http_client.aclose()).result(
                        timeout=5
                    )
                    return
                except Exception:
                    pass
        finally:
            # AsyncClient may not have bound to a loop if construction failed.
            if service_client is None:
                try:
                    import asyncio

                    asyncio.run(http_client.aclose())
                except Exception:
                    pass

    @staticmethod
    def _run_inference(
        tinker: Any,
        service_client: Any,
        tokenizer: Any,
        intent: ComputeDispatchIntent,
        plaintext: bytearray,
    ) -> tuple[int, int, int, str]:
        try:
            payload = json.loads(bytes(plaintext))
        except Exception:
            raise TinkerRequestContractError("inference payload is invalid") from None
        if (
            not isinstance(payload, dict)
            or set(payload) != {"schema", "prompt"}
            or payload.get("schema") != INFERENCE_PAYLOAD_SCHEMA
            or not isinstance(payload.get("prompt"), str)
        ):
            raise TinkerRequestContractError("inference payload is invalid")
        prompt = payload["prompt"]
        prompt_tokens = tokenizer.encode(prompt, add_special_tokens=True)
        if (
            not isinstance(prompt_tokens, Sequence)
            or isinstance(prompt_tokens, (str, bytes, bytearray))
            or not 1 <= len(prompt_tokens) <= intent.max_prefill_tokens
            or any(
                isinstance(token, bool) or not isinstance(token, int) or token < 0
                for token in prompt_tokens
            )
        ):
            raise TinkerRequestContractError("inference tokenization exceeds cap")
        sampler = service_client.create_sampling_client(
            base_model="Qwen/Qwen3-8B"
        )
        response = sampler.sample(
            prompt=tinker.ModelInput.from_ints(list(prompt_tokens)),
            num_samples=1,
            sampling_params=tinker.SamplingParams(
                max_tokens=int(intent.max_sample_tokens),
                temperature=0,
                top_k=-1,
                top_p=1,
            ),
            include_prompt_logprobs=False,
            topk_prompt_logprobs=0,
        ).result()
        sequences = getattr(response, "sequences", None)
        if not isinstance(sequences, Sequence) or len(sequences) != 1:
            raise TinkerRequestContractError("sample response is outside bound")
        sampled_tokens = list(getattr(sequences[0], "tokens", ()))
        if (
            not 1 <= len(sampled_tokens) <= intent.max_sample_tokens
            or any(
                isinstance(token, bool) or not isinstance(token, int) or token < 0
                for token in sampled_tokens
            )
        ):
            raise TinkerRequestContractError("sample response is outside bound")
        private_result = _sha256(
            b"dnai-wikigen/compute-private-sample-tokens/v1\0"
            + _canonical_json(sampled_tokens)
        )
        prefill = len(prompt_tokens)
        sample = len(sampled_tokens)
        del sampled_tokens, sequences, response, sampler, prompt_tokens, prompt, payload
        return prefill, sample, 0, private_result

    @staticmethod
    def _run_training(
        tinker: Any,
        service_client: Any,
        tokenizer: Any,
        intent: ComputeDispatchIntent,
        dispatch_id: str,
        plaintext: bytearray,
    ) -> tuple[int, int, int, str]:
        try:
            lines = bytes(plaintext).splitlines()
            examples = []
            for raw in lines:
                value = json.loads(raw)
                if (
                    not isinstance(value, dict)
                    or set(value) != {"prompt", "completion"}
                    or not isinstance(value["prompt"], str)
                    or not isinstance(value["completion"], str)
                ):
                    raise ValueError
                examples.append((value["prompt"], value["completion"]))
        except Exception:
            raise TinkerRequestContractError("training payload is invalid") from None
        session = IsolatedTinkerSession(service_client, dispatch_id)
        seed = int(dispatch_id[2:18], 16) % (2**31 - 1)
        session.create_training(
            base_model="Qwen/Qwen3-8B",
            rank=32,
            seed=seed,
        )
        data = _build_training_data(tinker, tokenizer, tuple(examples))
        if not data:
            raise TinkerRequestContractError("training data is empty")
        session.forward_backward(data, loss_fn="cross_entropy").result()
        session.optim_step(tinker.AdamParams(learning_rate=0.0001)).result()
        training_tokens = int(session.meter.train_tokens)
        if not 1 <= training_tokens <= intent.max_train_tokens:
            raise TinkerRequestContractError("training tokenization exceeds cap")
        private_result = _sha256(
            b"dnai-wikigen/compute-private-training-success/v1\0"
            + _canonical_json(
                {
                    "dispatch_id": dispatch_id,
                    "training_tokens": training_tokens,
                    "steps_completed": 1,
                    "checkpoint_created": False,
                }
            )
        )
        del data, examples, lines, session
        return 0, 0, training_tokens, private_result


def _secure_sealed_file(path: str | Path, *, maximum: int) -> Path:
    candidate = Path(path)
    try:
        if not candidate.is_absolute() or not secure_secret_file_exists(
            candidate,
            minimum=29,
            maximum=maximum,
        ):
            raise OSError
        return candidate
    except Exception:
        raise TinkerProviderReleaseError("sealed provider store is unavailable") from None


def _load_sealed_provider_configuration(settings: Any) -> tuple[str, str]:
    _secure_sealed_file(settings.api_key_store_path, maximum=4 * 1024)
    _secure_sealed_file(settings.client_config_store_path, maximum=64 * 1024)
    with open(os.devnull, "w", encoding="utf-8") as sink, redirect_stdout(
        sink
    ), redirect_stderr(sink):
        api_key = build_api_key_store(settings).load()
        config = build_tinker_client_config_store(settings).load()
    project_id = str(config.get("project_id") or "")
    base_url = str(config.get("base_url") or "")
    if (
        not isinstance(api_key, str)
        or not api_key.startswith("tml-")
        or not 8 <= len(api_key.encode("utf-8")) <= 512
        or any(character.isspace() for character in api_key)
        or not _PROJECT.fullmatch(project_id)
        or base_url != PINNED_TINKER_BASE_URL
    ):
        raise TinkerProviderReleaseError("sealed provider configuration is invalid")
    return api_key, project_id


def _load_pinned_tokenizer(settings: Any) -> Any:
    path = str(settings.compute_provider_tokenizer_path)
    expected = str(settings.compute_provider_tokenizer_release_sha256)
    if tokenizer_release_sha256(path) != expected:
        raise TinkerProviderReleaseError("tokenizer release pin mismatch")
    try:
        from transformers.models.auto.tokenization_auto import AutoTokenizer

        tokenizer = AutoTokenizer.from_pretrained(
            path,
            local_files_only=True,
            trust_remote_code=False,
        )
    except Exception:
        raise TinkerProviderReleaseError("offline tokenizer is unavailable") from None
    # Detect any mutation or lazy side effect during the load.
    if tokenizer_release_sha256(path) != expected:
        raise TinkerProviderReleaseError("tokenizer release changed during load")
    return tokenizer


@dataclass(repr=False)
class PreparedTinkerProviderAttempt:
    settings: Any = field(repr=False)
    intent: ComputeDispatchIntent = field(repr=False)
    policy: CompiledRecipePolicy = field(repr=False)
    dispatch_id: str
    plaintext: bytearray = field(repr=False)
    tokenizer: Any = field(repr=False)
    api_key: str = field(repr=False)
    project_id: str = field(repr=False)
    result_key: bytes = field(repr=False)
    reauthenticate: Callable[[], Any] = field(repr=False)
    runner: TinkerRecipeRunner = field(repr=False)
    _guard: TinkerDispatchRequestGuard = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._guard = TinkerDispatchRequestGuard(
            dispatch_id=self.dispatch_id,
            api_key=self.api_key,
            operation=self.intent.operation,
        )

    @property
    def provider_boundary_crossed(self) -> bool:
        return bool(
            self._guard.provider_boundary_crossed
            or getattr(self.runner, "provider_boundary_crossed", False) is True
        )

    def execute(self) -> ProviderUsage:
        try:
            execution = self.runner.run(
                settings=self.settings,
                intent=self.intent,
                policy=self.policy,
                dispatch_id=self.dispatch_id,
                plaintext=self.plaintext,
                tokenizer=self.tokenizer,
                api_key=self.api_key,
                project_id=self.project_id,
                guard=self._guard,
                reauthenticate=self.reauthenticate,
            )
            if not isinstance(execution, TinkerCompiledExecution):
                raise TinkerRequestContractError("provider execution result is invalid")
            usage_without_commitment = {
                "schema": "dnai.compute.provider-bounded-result-material.v1",
                "intent_commitment": self.intent.commitment,
                "authorization_kind": self.intent.authorization_kind,
                "authorization_context_commitment": (
                    self.intent.authorization_context_commitment
                ),
                "dispatch_id": self.dispatch_id,
                "recipe_policy_commitment": self.policy.commitment,
                "result_policy": self.intent.result_policy,
                "operation": self.intent.operation,
                "outcome": "succeeded",
                "prefill_tokens": execution.prefill_tokens,
                "sample_tokens": execution.sample_tokens,
                "training_tokens": execution.training_tokens,
                "private_result_sha256": execution.private_result_sha256,
                "private_request_transcript_sha256": (
                    execution.private_transcript_sha256
                ),
                "raw_output_released": False,
                "provider_identifier_persisted": False,
            }
            result_commitment = "0x" + hmac.new(
                self.result_key,
                PROVIDER_RESULT_DOMAIN + _canonical_json(usage_without_commitment),
                hashlib.sha256,
            ).hexdigest()
            usage = ProviderUsage(
                outcome="succeeded",
                prefill_tokens=execution.prefill_tokens,
                sample_tokens=execution.sample_tokens,
                training_tokens=execution.training_tokens,
                result_commitment=result_commitment,
                provider_authoritative_invoice=False,
            )
            usage.validate_for(self.intent)
            return usage
        except Exception:
            raise ComputeProviderDispatchFailure(
                provider_boundary_crossed=self.provider_boundary_crossed
            ) from None


class TinkerComputeProviderAdapter:
    """Compiled provider adapter accepted by :class:`ComputeExecutionWorker`."""

    supports_idempotent_dispatch = False
    supports_at_most_once_dispatch = True
    supports_checkpointed_workload_release = True

    def __init__(
        self,
        settings: Any,
        *,
        ingress: ComputeWorkloadIngressService,
        result_key: bytes,
        runner: TinkerRecipeRunner | None = None,
    ):
        validate_compute_provider_release(settings)
        if not isinstance(ingress, ComputeWorkloadIngressService):
            raise TinkerProviderReleaseError("Compute workload ingress is required")
        if not isinstance(result_key, bytes) or len(result_key) < 32:
            raise TinkerProviderReleaseError("provider result key is invalid")
        self.settings = settings
        self.ingress = ingress
        self.result_key = bytes(result_key)
        self.runner = runner or TinkerCompiledRecipeRunner()

    @contextmanager
    def prepare_attempt(
        self,
        intent: ComputeDispatchIntent,
        policy: CompiledRecipePolicy,
        *,
        dispatch_id: str,
    ) -> Iterator[PreparedTinkerProviderAttempt]:
        if (
            not isinstance(intent, ComputeDispatchIntent)
            or policy is not intent.validate_compiled_recipe()
            or COMPILED_RECIPES.get((intent.operation, intent.model, intent.recipe))
            is not policy
            or intent.result_policy != "bounded_summary_receipt"
            or intent.authorization_kind
            not in {"standalone", "collaboration_one_shot"}
            or not _SHA256.fullmatch(
                intent.authorization_context_commitment
            )
            or not _BYTES32.fullmatch(str(dispatch_id).lower())
        ):
            raise TinkerProviderReleaseError("compiled provider intent is not allowlisted")
        claim = ComputeWorkloadDispatchClaim(
            job_id=intent.job_id,
            intent_commitment=intent.commitment,
            funding_wallet=intent.user,
            execution_binding_commitment=(
                intent.workload_execution_binding_commitment
            ),
        )
        try:
            with self.ingress.lease_for_provider_execution(
                intent.workload_id,
                project_id=intent.project_reference,
                claim=claim,
                source_kind=intent.workload_source_kind,
                recipient_release_commitment=(
                    intent.workload_recipient_release_commitment
                ),
            ) as lease:
                manifest = lease.manifest
                if (
                    manifest.schema != intent.workload_schema
                    or manifest.operation != intent.operation
                    or manifest.model != intent.model
                    or manifest.recipe != intent.recipe
                    or manifest.max_prefill_tokens != intent.max_prefill_tokens
                    or manifest.max_sample_tokens != intent.max_sample_tokens
                    or manifest.max_train_tokens != intent.max_train_tokens
                    or "0x" + manifest.commitment.removeprefix("sha256:")
                    != intent.manifest_commitment
                ):
                    raise TinkerProviderReleaseError(
                        "workload manifest does not match exact intent"
                    )
                api_key, project_id = _load_sealed_provider_configuration(
                    self.settings
                )
                tokenizer = _load_pinned_tokenizer(self.settings)
                yield PreparedTinkerProviderAttempt(
                    settings=self.settings,
                    intent=intent,
                    policy=policy,
                    dispatch_id=str(dispatch_id).lower(),
                    plaintext=lease.plaintext,
                    tokenizer=tokenizer,
                    api_key=api_key,
                    project_id=project_id,
                    result_key=self.result_key,
                    reauthenticate=lease.reauthenticate,
                    runner=self.runner,
                )
        except (ComputeWorkloadIngressError, ComputeWorkloadIngressUnavailable) as exc:
            raise TinkerProviderUnavailable("Compute workload lease is unavailable") from exc

    def release_after_usage_checkpoint(
        self,
        intent: ComputeDispatchIntent,
        policy: CompiledRecipePolicy,
        *,
        dispatch_id: str,
        usage: ProviderUsage,
        release_checkpoint_commitment: str,
    ) -> None:
        if (
            policy is not intent.validate_compiled_recipe()
            or not _BYTES32.fullmatch(str(dispatch_id).lower())
            or not isinstance(usage, ProviderUsage)
            or not _SHA256.fullmatch(str(release_checkpoint_commitment))
        ):
            raise TinkerProviderReleaseError("workload release checkpoint is invalid")
        usage.validate_for(intent)
        claim = ComputeWorkloadDispatchClaim(
            job_id=intent.job_id,
            intent_commitment=intent.commitment,
            funding_wallet=intent.user,
            execution_binding_commitment=(
                intent.workload_execution_binding_commitment
            ),
        )
        try:
            self.ingress.release_after_usage_checkpoint(
                intent.workload_id,
                project_id=intent.project_reference,
                claim=claim,
                release_checkpoint_commitment=release_checkpoint_commitment,
            )
        except (ComputeWorkloadIngressError, ComputeWorkloadIngressUnavailable) as exc:
            raise TinkerProviderUnavailable(
                "Compute workload release is unavailable"
            ) from exc


def build_tinker_compute_provider(settings: Any) -> TinkerComputeProviderAdapter:
    validate_compute_provider_release(settings)
    try:
        result_key = hashlib.sha256(
            b"dnai-wikigen/compute-provider-result-key/v1\0"
            + dstack_utils.derive_storage_key(
                _validate_dstack_path(
                    settings.compute_provider_result_key_path,
                    purpose="compute_provider_result",
                )
            )
        ).digest()
        ingress = build_compute_workload_ingress(settings)
        # Fail before advertising worker presence if sealed provider stores or
        # the local tokenizer cannot be opened under the exact release.
        _load_sealed_provider_configuration(settings)
        _load_pinned_tokenizer(settings)
        return TinkerComputeProviderAdapter(
            settings,
            ingress=ingress,
            result_key=result_key,
        )
    except TinkerProviderReleaseError:
        raise
    except Exception:
        raise TinkerProviderReleaseError("provider adapter is unavailable") from None


def compute_provider_status_store(settings: Any) -> ComputeProviderStatusStore:
    return ComputeProviderStatusStore(
        settings.compute_provider_status_path,
        integrity_key=_provider_status_integrity_key(settings),
    )
