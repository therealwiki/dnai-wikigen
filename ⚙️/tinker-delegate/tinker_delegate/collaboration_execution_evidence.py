"""Authenticated release-bound presence for the Collaboration worker.

This record proves only that the purpose-separated worker process recently
reported under the exact reviewed main-runtime bindings.  It is neither a TDX
quote nor a per-execution QVL verdict.  Those job-specific proofs remain
mandatory for Royalty settlement.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from tinker_delegate import dstack_utils
from tinker_delegate.royalty_qvl_client import (
    AuthenticatedRoyaltyQvlCapabilityObservation,
    RoyaltyQvlClientError,
)


HEARTBEAT_SCHEMA = "dnai.collaboration.execution-worker-heartbeat.v1"
RELEASE_BINDING_SCHEMA = (
    "dnai.collaboration.execution-worker-release-binding.v1"
)
CAPABILITY_SCHEMA = "dnai.collaboration.execution-worker-capability.v1"
EVIDENCE_CLASSIFICATION = (
    "authenticated_worker_presence_not_job_attestation"
)
WORKER_SERVICE = "collaboration-execution-worker"
WORKER_PROFILE = "collaboration-execution"
BASE_SEPOLIA_CHAIN_ID = 84_532
MAX_HEARTBEAT_BYTES = 32 * 1024
MAX_HEARTBEAT_TTL_SECONDS = 300
MAX_FUTURE_SKEW_SECONDS = 5

_MAC_DOMAIN = b"dnai-wikigen/collaboration-execution-worker-heartbeat/v1\0"
_RELEASE_DOMAIN = (
    b"dnai-wikigen/collaboration-execution-worker-release-binding/v1\0"
)
_PRESENCE_DOMAIN = (
    b"dnai-wikigen/collaboration-execution-worker-presence-binding/v1\0"
)
_HEX40 = re.compile(r"^(?!0{40}$)[0-9a-f]{40}$")
_HEX64 = re.compile(r"^(?!0{64}$)[0-9a-f]{64}$")
_SHA256 = re.compile(r"^sha256:(?!0{64}$)[0-9a-f]{64}$")
_BYTES32 = re.compile(r"^0x(?!0{64}$)[0-9a-f]{64}$")
_ADDRESS = re.compile(r"^0x(?!0{40}$)[0-9a-f]{40}$")
_CVM_ID = re.compile(r"^[a-z0-9][a-z0-9._:-]{7,127}$")


class CollaborationExecutionEvidenceError(RuntimeError):
    """Heartbeat state is malformed, unsafe, stale, or unauthenticated."""


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise CollaborationExecutionEvidenceError(
            "Collaboration worker evidence is not canonical JSON"
        ) from exc


def _exact(value: Mapping[str, Any], fields: frozenset[str], label: str) -> None:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise CollaborationExecutionEvidenceError(f"{label} fields are invalid")


def _timestamp(value: Any, label: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 1
        or value > 4_102_444_800
    ):
        raise CollaborationExecutionEvidenceError(f"{label} is invalid")
    return value


def _commitment(domain: bytes, value: Any) -> str:
    return "sha256:" + hashlib.sha256(domain + _canonical_json(value)).hexdigest()


@dataclass(frozen=True)
class CollaborationExecutionWorkerReleaseBindings:
    release_git_sha: str
    release_verification_sha256: str
    deployment_intent_sha256: str
    release_authority_sha256: str
    ceremony_nonce: str
    main_runtime_cvm_id: str
    main_runtime_compose_hash: str
    main_runtime_app_id: str
    main_runtime_os_image_hash: str
    royalty_release_binding_commitment: str
    royalty_distributor_address: str
    compute_vault_address: str
    compute_vault_runtime_code_hash: str
    chain_id: int = BASE_SEPOLIA_CHAIN_ID
    worker_service: str = WORKER_SERVICE
    worker_profile: str = WORKER_PROFILE

    _FIELDS = frozenset(
        {
            "release_git_sha",
            "release_verification_sha256",
            "deployment_intent_sha256",
            "release_authority_sha256",
            "ceremony_nonce",
            "main_runtime_cvm_id",
            "main_runtime_compose_hash",
            "main_runtime_app_id",
            "main_runtime_os_image_hash",
            "royalty_release_binding_commitment",
            "royalty_distributor_address",
            "compute_vault_address",
            "compute_vault_runtime_code_hash",
            "chain_id",
            "worker_service",
            "worker_profile",
        }
    )

    def __post_init__(self) -> None:
        if not _HEX40.fullmatch(self.release_git_sha):
            raise CollaborationExecutionEvidenceError("worker release SHA is invalid")
        for value, label in (
            (self.release_verification_sha256, "worker release verification"),
            (self.deployment_intent_sha256, "deployment intent"),
            (self.release_authority_sha256, "release authority"),
            (self.royalty_release_binding_commitment, "Royalty release binding"),
        ):
            if not _SHA256.fullmatch(value):
                raise CollaborationExecutionEvidenceError(f"{label} is invalid")
        if not _BYTES32.fullmatch(self.ceremony_nonce):
            raise CollaborationExecutionEvidenceError("ceremony nonce is invalid")
        if not _CVM_ID.fullmatch(self.main_runtime_cvm_id):
            raise CollaborationExecutionEvidenceError("main runtime CVM id is invalid")
        if not _BYTES32.fullmatch(self.main_runtime_compose_hash):
            raise CollaborationExecutionEvidenceError("main runtime compose hash is invalid")
        if not _HEX40.fullmatch(self.main_runtime_app_id):
            raise CollaborationExecutionEvidenceError("main runtime app id is invalid")
        if not _HEX64.fullmatch(self.main_runtime_os_image_hash):
            raise CollaborationExecutionEvidenceError("main runtime OS image hash is invalid")
        for value, label in (
            (self.royalty_distributor_address, "Royalty distributor"),
            (self.compute_vault_address, "Compute vault"),
        ):
            if not _ADDRESS.fullmatch(value):
                raise CollaborationExecutionEvidenceError(f"{label} is invalid")
        if not _BYTES32.fullmatch(self.compute_vault_runtime_code_hash):
            raise CollaborationExecutionEvidenceError("Compute vault runtime hash is invalid")
        if self.chain_id != BASE_SEPOLIA_CHAIN_ID:
            raise CollaborationExecutionEvidenceError("worker chain is not Base Sepolia")
        if self.worker_service != WORKER_SERVICE or self.worker_profile != WORKER_PROFILE:
            raise CollaborationExecutionEvidenceError("worker service/profile is invalid")

    def to_dict(self) -> dict[str, Any]:
        return {
            field: getattr(self, field)
            for field in self._FIELDS
        }

    @classmethod
    def from_mapping(
        cls, value: Mapping[str, Any]
    ) -> "CollaborationExecutionWorkerReleaseBindings":
        _exact(value, cls._FIELDS, "worker release binding")
        return cls(**{field: value[field] for field in cls._FIELDS})

    @property
    def commitment(self) -> str:
        return _commitment(
            _RELEASE_DOMAIN,
            {
                "schema": RELEASE_BINDING_SCHEMA,
                "release_binding": self.to_dict(),
            },
        )


@dataclass(frozen=True)
class CollaborationExecutionWorkerHeartbeat:
    bindings: CollaborationExecutionWorkerReleaseBindings
    observed_at: int
    state: str
    real_dstack: bool
    simulator: bool
    qvl_configuration: str
    qvl_reachability: str
    qvl_capability_observation: (
        AuthenticatedRoyaltyQvlCapabilityObservation | None
    ) = None

    _FIELDS = frozenset(
        {
            "bindings",
            "observed_at",
            "state",
            "real_dstack",
            "simulator",
            "qvl_configuration",
            "qvl_reachability",
            "qvl_capability_observation",
        }
    )

    def __post_init__(self) -> None:
        if not isinstance(
            self.bindings, CollaborationExecutionWorkerReleaseBindings
        ):
            raise CollaborationExecutionEvidenceError("heartbeat bindings are invalid")
        _timestamp(self.observed_at, "heartbeat time")
        if self.state not in {"ready", "processing", "unavailable"}:
            raise CollaborationExecutionEvidenceError("heartbeat state is invalid")
        if self.real_dstack is not True or self.simulator is not False:
            raise CollaborationExecutionEvidenceError("heartbeat is not real dstack")
        if self.qvl_configuration not in {
            "complete",
            "incomplete",
        }:
            raise CollaborationExecutionEvidenceError("QVL configuration is invalid")
        if self.qvl_reachability not in {
            "configured_not_probed",
            "authenticated_exact_capability",
            "unreachable",
            "mismatch",
            "unavailable",
        }:
            raise CollaborationExecutionEvidenceError("QVL reachability is invalid")
        if (
            self.qvl_configuration == "incomplete"
            and self.qvl_reachability != "unavailable"
        ) or (
            self.qvl_configuration == "complete"
            and self.qvl_reachability == "unavailable"
        ):
            raise CollaborationExecutionEvidenceError("QVL capability is inconsistent")
        observation = self.qvl_capability_observation
        if self.qvl_reachability == "authenticated_exact_capability":
            if (
                not isinstance(
                    observation,
                    AuthenticatedRoyaltyQvlCapabilityObservation,
                )
                or observation.release_binding_sha256
                != self.bindings.royalty_release_binding_commitment
                or observation.observed_at > self.observed_at
            ):
                raise CollaborationExecutionEvidenceError(
                    "QVL capability observation is invalid"
                )
        elif observation is not None:
            raise CollaborationExecutionEvidenceError(
                "QVL capability observation is inconsistent"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "bindings": self.bindings.to_dict(),
            "observed_at": self.observed_at,
            "state": self.state,
            "real_dstack": self.real_dstack,
            "simulator": self.simulator,
            "qvl_configuration": self.qvl_configuration,
            "qvl_reachability": self.qvl_reachability,
            "qvl_capability_observation": (
                None
                if self.qvl_capability_observation is None
                else self.qvl_capability_observation.to_public_dict()
            ),
        }

    @classmethod
    def from_mapping(
        cls, value: Mapping[str, Any]
    ) -> "CollaborationExecutionWorkerHeartbeat":
        _exact(value, cls._FIELDS, "worker heartbeat")
        bindings = value["bindings"]
        if not isinstance(bindings, Mapping):
            raise CollaborationExecutionEvidenceError("heartbeat bindings are invalid")
        observation = value["qvl_capability_observation"]
        if observation is not None and not isinstance(observation, Mapping):
            raise CollaborationExecutionEvidenceError(
                "QVL capability observation is invalid"
            )
        try:
            parsed_observation = (
                None
                if observation is None
                else AuthenticatedRoyaltyQvlCapabilityObservation.from_public_dict(
                    observation
                )
            )
        except RoyaltyQvlClientError as exc:
            raise CollaborationExecutionEvidenceError(
                "QVL capability observation is invalid"
            ) from exc
        return cls(
            bindings=CollaborationExecutionWorkerReleaseBindings.from_mapping(
                bindings
            ),
            observed_at=_timestamp(value["observed_at"], "heartbeat time"),
            state=str(value["state"]),
            real_dstack=value["real_dstack"],
            simulator=value["simulator"],
            qvl_configuration=str(value["qvl_configuration"]),
            qvl_reachability=str(value["qvl_reachability"]),
            qvl_capability_observation=parsed_observation,
        )


class CollaborationExecutionWorkerHeartbeatStore:
    _ROOT_FIELDS = frozenset({"schema", "heartbeat", "mac"})

    def __init__(self, path: str | Path, *, integrity_key: bytes) -> None:
        if not isinstance(path, (str, Path)) or not str(path).strip():
            raise CollaborationExecutionEvidenceError("heartbeat path is required")
        if not isinstance(integrity_key, bytes) or len(integrity_key) < 32:
            raise CollaborationExecutionEvidenceError("heartbeat key is invalid")
        self.path = Path(os.path.abspath(os.fspath(path)))
        self._key = bytes(integrity_key)

    def write(self, heartbeat: CollaborationExecutionWorkerHeartbeat) -> None:
        if not isinstance(heartbeat, CollaborationExecutionWorkerHeartbeat):
            raise CollaborationExecutionEvidenceError("heartbeat is invalid")
        if self.path.is_symlink():
            raise CollaborationExecutionEvidenceError("heartbeat path cannot be a symlink")
        if self.path.exists():
            previous = self.read()
            if heartbeat.observed_at < previous.observed_at:
                raise CollaborationExecutionEvidenceError("heartbeat time regressed")
        payload = heartbeat.to_dict()
        encoded_payload = _canonical_json(payload)
        mac = hmac.new(self._key, _MAC_DOMAIN + encoded_payload, hashlib.sha256).hexdigest()
        encoded = _canonical_json(
            {"schema": HEARTBEAT_SCHEMA, "heartbeat": payload, "mac": mac}
        )
        if len(encoded) > MAX_HEARTBEAT_BYTES:
            raise CollaborationExecutionEvidenceError("heartbeat is oversized")
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{self.path.name}.", dir=self.path.parent
        )
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                descriptor = -1
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            directory = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError as exc:
            raise CollaborationExecutionEvidenceError(
                "heartbeat persistence failed"
            ) from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    def read(self) -> CollaborationExecutionWorkerHeartbeat:
        try:
            if self.path.is_symlink():
                raise CollaborationExecutionEvidenceError(
                    "heartbeat path cannot be a symlink"
                )
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(self.path, flags)
            try:
                details = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(details.st_mode)
                    or stat.S_IMODE(details.st_mode) != 0o600
                    or details.st_nlink != 1
                    or details.st_uid != os.geteuid()
                    or details.st_size < 2
                    or details.st_size > MAX_HEARTBEAT_BYTES
                ):
                    raise CollaborationExecutionEvidenceError(
                        "heartbeat file is unsafe"
                    )
                raw = os.read(descriptor, MAX_HEARTBEAT_BYTES + 1)
            finally:
                os.close(descriptor)
        except CollaborationExecutionEvidenceError:
            raise
        except OSError as exc:
            raise CollaborationExecutionEvidenceError(
                "heartbeat is unavailable"
            ) from exc
        if len(raw) > MAX_HEARTBEAT_BYTES:
            raise CollaborationExecutionEvidenceError("heartbeat is oversized")
        try:
            root = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise CollaborationExecutionEvidenceError("heartbeat JSON is invalid") from exc
        if not isinstance(root, Mapping):
            raise CollaborationExecutionEvidenceError("heartbeat root is invalid")
        _exact(root, self._ROOT_FIELDS, "heartbeat envelope")
        if root["schema"] != HEARTBEAT_SCHEMA:
            raise CollaborationExecutionEvidenceError("heartbeat schema is invalid")
        payload = root["heartbeat"]
        mac = root["mac"]
        if (
            not isinstance(payload, Mapping)
            or not isinstance(mac, str)
            or not re.fullmatch(r"[0-9a-f]{64}", mac)
        ):
            raise CollaborationExecutionEvidenceError("heartbeat envelope is invalid")
        expected = hmac.new(
            self._key, _MAC_DOMAIN + _canonical_json(payload), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(mac, expected):
            raise CollaborationExecutionEvidenceError(
                "heartbeat authentication failed"
            )
        return CollaborationExecutionWorkerHeartbeat.from_mapping(payload)


def collaboration_execution_worker_heartbeat_integrity_key(settings: Any) -> bytes:
    explicit = str(
        getattr(
            settings,
            "collaboration_execution_worker_heartbeat_integrity_key",
            "",
        )
        or ""
    )
    if dstack_utils.is_dstack_enabled():
        if dstack_utils.is_dstack_simulator() or explicit:
            raise CollaborationExecutionEvidenceError(
                "real dstack derived heartbeat key is required"
            )
        path = str(
            getattr(
                settings,
                "collaboration_execution_worker_heartbeat_key_path",
                "tinker/collaboration_execution_worker_heartbeat",
            )
            or ""
        ).strip()
        if not path:
            raise CollaborationExecutionEvidenceError(
                "heartbeat key path is unavailable"
            )
        try:
            material = dstack_utils.derive_storage_key(path)
        except Exception as exc:
            raise CollaborationExecutionEvidenceError(
                "heartbeat key derivation failed"
            ) from exc
        return hashlib.sha256(
            b"dnai-wikigen/collaboration-execution-worker-heartbeat/dstack/v1\0"
            + material
        ).digest()
    if len(explicit.encode("utf-8")) < 32:
        raise CollaborationExecutionEvidenceError(
            "local heartbeat key is unavailable"
        )
    return hashlib.sha256(
        b"dnai-wikigen/collaboration-execution-worker-heartbeat/local/v1\0"
        + explicit.encode("utf-8")
    ).digest()


def collaboration_execution_worker_release_bindings(
    settings: Any,
) -> CollaborationExecutionWorkerReleaseBindings:
    from tinker_delegate.collaboration_execution_service import (
        royalty_release_binding_commitment,
        royalty_release_binding_from_settings,
    )

    royalty = royalty_release_binding_from_settings(settings)
    return CollaborationExecutionWorkerReleaseBindings(
        release_git_sha=str(
            getattr(settings, "collaboration_execution_release_git_sha", "") or ""
        ),
        release_verification_sha256=str(
            getattr(
                settings,
                "collaboration_execution_release_verification_sha256",
                "",
            )
            or ""
        ),
        deployment_intent_sha256=str(
            getattr(settings, "release_deployment_intent_sha256", "") or ""
        ),
        release_authority_sha256=str(
            getattr(settings, "release_authority_sha256", "") or ""
        ),
        ceremony_nonce=str(
            getattr(settings, "release_ceremony_nonce", "") or ""
        ),
        main_runtime_cvm_id=str(
            getattr(settings, "main_runtime_cvm_id", "") or ""
        ),
        main_runtime_compose_hash=str(
            getattr(settings, "royalty_main_runtime_compose_hash", "") or ""
        ),
        main_runtime_app_id=str(
            getattr(settings, "royalty_main_runtime_app_id", "") or ""
        ),
        main_runtime_os_image_hash=str(
            getattr(settings, "royalty_main_runtime_os_image_hash", "") or ""
        ),
        royalty_release_binding_commitment=(
            royalty_release_binding_commitment(royalty)
        ),
        royalty_distributor_address=royalty.distributor_address,
        compute_vault_address=str(
            getattr(settings, "compute_vault_address", "") or ""
        ),
        compute_vault_runtime_code_hash=str(
            getattr(settings, "compute_vault_runtime_code_hash", "") or ""
        ),
    )


def project_collaboration_execution_worker_capability(
    *,
    enabled: bool,
    expected_bindings: CollaborationExecutionWorkerReleaseBindings | None,
    heartbeat_store: CollaborationExecutionWorkerHeartbeatStore | None,
    now: int,
    ttl_seconds: int,
) -> dict[str, Any]:
    current = _timestamp(now, "current time")
    if (
        not isinstance(ttl_seconds, int)
        or isinstance(ttl_seconds, bool)
        or ttl_seconds < 5
        or ttl_seconds > MAX_HEARTBEAT_TTL_SECONDS
    ):
        raise CollaborationExecutionEvidenceError("heartbeat TTL is invalid")
    heartbeat: CollaborationExecutionWorkerHeartbeat | None = None
    reason = "execution_disabled"
    if enabled:
        if expected_bindings is None:
            reason = "release_binding_unavailable"
        elif heartbeat_store is None:
            reason = "heartbeat_unavailable"
        else:
            try:
                heartbeat = heartbeat_store.read()
            except CollaborationExecutionEvidenceError:
                reason = "heartbeat_invalid"
            else:
                if heartbeat.bindings != expected_bindings:
                    reason = "release_binding_mismatch"
                elif heartbeat.observed_at > current + MAX_FUTURE_SKEW_SECONDS:
                    reason = "heartbeat_invalid"
                elif current - heartbeat.observed_at > ttl_seconds:
                    reason = "heartbeat_stale"
                elif heartbeat.state == "unavailable":
                    reason = "worker_unavailable"
                elif heartbeat.qvl_configuration != "complete":
                    reason = "qvl_configuration_incomplete"
                elif heartbeat.qvl_reachability == "configured_not_probed":
                    reason = "qvl_capability_not_probed"
                elif heartbeat.qvl_reachability == "unreachable":
                    reason = "qvl_capability_unreachable"
                elif heartbeat.qvl_reachability == "mismatch":
                    reason = "qvl_capability_mismatch"
                elif heartbeat.qvl_reachability != "authenticated_exact_capability":
                    reason = "qvl_capability_unavailable"
                elif heartbeat.qvl_capability_observation is None:
                    reason = "qvl_capability_unavailable"
                elif (
                    heartbeat.qvl_capability_observation.release_binding_sha256
                    != expected_bindings.royalty_release_binding_commitment
                ):
                    reason = "qvl_capability_mismatch"
                elif (
                    heartbeat.qvl_capability_observation.observed_at
                    > current + MAX_FUTURE_SKEW_SECONDS
                ):
                    reason = "qvl_capability_invalid"
                elif (
                    current
                    - heartbeat.qvl_capability_observation.observed_at
                    > ttl_seconds
                    or heartbeat.qvl_capability_observation.challenge.expires_at
                    <= current
                ):
                    reason = "qvl_capability_stale"
                else:
                    reason = "ready"
    live = enabled and reason == "ready"
    release_commitment = (
        expected_bindings.commitment
        if expected_bindings is not None
        else None
    )
    observed_at = heartbeat.observed_at if live and heartbeat else None
    qvl_observation = (
        heartbeat.qvl_capability_observation
        if live and heartbeat is not None
        else None
    )
    presence_commitment = None
    if observed_at is not None and release_commitment is not None:
        presence_commitment = _commitment(
            _PRESENCE_DOMAIN,
            {
                "schema": CAPABILITY_SCHEMA,
                "heartbeat_schema": HEARTBEAT_SCHEMA,
                "observed_at": observed_at,
                "release_binding_sha256": release_commitment,
                "evidence_classification": EVIDENCE_CLASSIFICATION,
                "qvl_capability_observation_sha256": (
                    qvl_observation.commitment
                    if qvl_observation is not None
                    else None
                ),
            },
        )
    return {
        "surface": "collaboration_execution_worker_capability",
        "schema": CAPABILITY_SCHEMA,
        "status": "live" if live else "unavailable",
        "gate_reason": reason,
        "execution_enabled": enabled,
        "queue_control_plane_available": enabled,
        "queued_work_executable": live,
        "onchain_reservation_ready": live,
        "worker_connected": live,
        "freshness": "fresh" if live else "unavailable",
        "evidence_authenticity": "hmac_verified" if live else "unverified",
        "evidence_classification": EVIDENCE_CLASSIFICATION,
        "heartbeat_observed_at": observed_at,
        "presence_binding_sha256": presence_commitment,
        "release_binding_sha256": release_commitment,
        "release_binding": (
            expected_bindings.to_dict()
            if expected_bindings is not None
            else None
        ),
        "qvl_capability": {
            "configuration": (
                heartbeat.qvl_configuration
                if live and heartbeat is not None
                else "unavailable"
            ),
            "reachability": (
                heartbeat.qvl_reachability
                if live and heartbeat is not None
                else "unavailable"
            ),
            "observation_sha256": (
                qvl_observation.commitment
                if qvl_observation is not None
                else None
            ),
            "observed_at": (
                qvl_observation.observed_at
                if qvl_observation is not None
                else None
            ),
            "expires_at": (
                qvl_observation.challenge.expires_at
                if qvl_observation is not None
                else None
            ),
            "profile": (
                qvl_observation.challenge.profile
                if qvl_observation is not None
                else None
            ),
            "royalty_authorization_schema": (
                qvl_observation.to_public_dict()[
                    "royalty_authorization_schema"
                ]
                if qvl_observation is not None
                else None
            ),
            "per_job_qvl_required": True,
            "per_job_qvl_verified": False,
        },
        "real_dstack": bool(live),
        "simulator": False,
        "tdx_job_attestation_proven": False,
        "qvl_job_verdict_proven": False,
        "warning": (
            "Fresh authenticated worker presence matches the reviewed release. "
            "This is not a job attestation; settlement still requires fresh TDX, "
            "QVL, anchor, and finalized on-chain evidence."
            if live
            else "Execution may be queued, but on-chain reservation is blocked "
            "until a fresh authenticated release-matching worker is present."
        ),
    }


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value
