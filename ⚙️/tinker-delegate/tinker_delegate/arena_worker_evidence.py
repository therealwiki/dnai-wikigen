"""Authenticated, release-bound presence evidence for the Arena safe-IR worker.

The heartbeat in this module is deliberately *not* an attestation format.  It
proves only that a process holding a distinct dstack-derived integrity key
recently reported status while using the exact release, image, catalog, and
safe-IR policy pins expected by the API.  Per-job TDX/DCAP authorization stays
in :mod:`arena_safe_worker` and its independent QVL path.

Public capability projection is fail-closed.  General Python never becomes
live, and safe-IR becomes live only when the deployment gate is enabled and a
fresh, authenticated, exactly matching heartbeat is present.
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
from tinker_delegate.arena_safe_ir import SAFE_IR_POLICY_COMMITMENT, SAFE_IR_RUNTIME
from tinker_delegate.arena_store import (
    DNASEQ_SAFE_IR_CHALLENGE_ID,
    DNASEQ_SAFE_IR_CHALLENGE_VERSION,
)


HEARTBEAT_SCHEMA = "dnai.arena.safe-worker-heartbeat.v1"
CAPABILITY_SCHEMA_VERSION = 2
RELEASE_BINDING_SCHEMA = "dnai.arena.safe-worker-release-binding.v1"
HEARTBEAT_BINDING_SCHEMA = "dnai.arena.safe-worker-presence-binding.v1"
MAX_HEARTBEAT_BYTES = 16 * 1024
MAX_HEARTBEAT_TTL_SECONDS = 300
MAX_FUTURE_SKEW_SECONDS = 5
EVIDENCE_CLASSIFICATION = "authenticated_worker_presence_not_tdx_attestation"

_RELEASE_BINDING_DIGEST_DOMAIN = (
    b"dnai-wikigen/arena-worker-release-binding/v1\0"
)
_HEARTBEAT_BINDING_DIGEST_DOMAIN = (
    b"dnai-wikigen/arena-worker-presence-binding/v1\0"
)

_HEX_40 = re.compile(r"^[0-9a-f]{40}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_BYTES32 = re.compile(r"^0x[0-9a-f]{64}$")
_APP_ID = re.compile(r"^[\x21-\x7e]{1,128}$")


class ArenaWorkerEvidenceError(RuntimeError):
    """Raised for malformed, unauthenticated, or unavailable heartbeat state."""


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
        raise ArenaWorkerEvidenceError("worker evidence is not canonical JSON") from exc


def _exact_keys(value: Mapping[str, Any], expected: frozenset[str], *, label: str) -> None:
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ArenaWorkerEvidenceError(f"{label} fields are invalid")


def _bounded_int(value: Any, *, minimum: int, maximum: int, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ArenaWorkerEvidenceError(f"{label} is invalid")
    if value < minimum or value > maximum:
        raise ArenaWorkerEvidenceError(f"{label} is invalid")
    return value


def _sha256_commitment(domain: bytes, value: Any) -> str:
    if not isinstance(domain, bytes) or not domain:
        raise ArenaWorkerEvidenceError("worker evidence digest domain is invalid")
    return "sha256:" + hashlib.sha256(domain + _canonical_json(value)).hexdigest()


@dataclass(frozen=True)
class ArenaWorkerReleaseBindings:
    """Exact public build/deployment values repeated by every heartbeat."""

    release_sha: str
    image_digest: str
    release_manifest_sha256: str
    approved_challenge_set_sha256: str
    approved_challenge_key: str
    release_policy_commitment: str
    catalog_manifest_hash: str
    runtime: str
    runtime_policy_commitment: str
    compose_hash: str
    app_id: str
    os_image_hash: str

    _FIELDS = frozenset(
        {
            "release_sha",
            "image_digest",
            "release_manifest_sha256",
            "approved_challenge_set_sha256",
            "approved_challenge_key",
            "release_policy_commitment",
            "catalog_manifest_hash",
            "runtime",
            "runtime_policy_commitment",
            "compose_hash",
            "app_id",
            "os_image_hash",
        }
    )

    def __post_init__(self) -> None:
        if not _HEX_40.fullmatch(self.release_sha):
            raise ArenaWorkerEvidenceError("worker release SHA is invalid")
        if not _SHA256.fullmatch(self.image_digest):
            raise ArenaWorkerEvidenceError("worker image digest is invalid")
        if not _SHA256.fullmatch(self.release_manifest_sha256):
            raise ArenaWorkerEvidenceError("worker release manifest digest is invalid")
        if (
            not _SHA256.fullmatch(self.approved_challenge_set_sha256)
            or self.approved_challenge_set_sha256 == "sha256:" + "0" * 64
        ):
            raise ArenaWorkerEvidenceError("worker approved challenge-set digest is invalid")
        if self.approved_challenge_key != (
            f"{DNASEQ_SAFE_IR_CHALLENGE_ID}@{DNASEQ_SAFE_IR_CHALLENGE_VERSION}"
        ):
            raise ArenaWorkerEvidenceError("worker challenge is not release-approved")
        if not _BYTES32.fullmatch(self.release_policy_commitment):
            raise ArenaWorkerEvidenceError("worker release policy commitment is invalid")
        if not _HEX_64.fullmatch(self.catalog_manifest_hash):
            raise ArenaWorkerEvidenceError("worker catalog manifest hash is invalid")
        if self.runtime != SAFE_IR_RUNTIME:
            raise ArenaWorkerEvidenceError("worker runtime is not safe-IR")
        if self.runtime_policy_commitment != SAFE_IR_POLICY_COMMITMENT:
            raise ArenaWorkerEvidenceError("worker runtime policy is not canonical safe-IR")
        if not _HEX_64.fullmatch(self.compose_hash):
            raise ArenaWorkerEvidenceError("worker compose hash is invalid")
        if not _APP_ID.fullmatch(self.app_id):
            raise ArenaWorkerEvidenceError("worker app id is invalid")
        if not _HEX_64.fullmatch(self.os_image_hash):
            raise ArenaWorkerEvidenceError("worker OS image hash is invalid")

    def to_dict(self) -> dict[str, str]:
        return {
            "release_sha": self.release_sha,
            "image_digest": self.image_digest,
            "release_manifest_sha256": self.release_manifest_sha256,
            "approved_challenge_set_sha256": self.approved_challenge_set_sha256,
            "approved_challenge_key": self.approved_challenge_key,
            "release_policy_commitment": self.release_policy_commitment,
            "catalog_manifest_hash": self.catalog_manifest_hash,
            "runtime": self.runtime,
            "runtime_policy_commitment": self.runtime_policy_commitment,
            "compose_hash": self.compose_hash,
            "app_id": self.app_id,
            "os_image_hash": self.os_image_hash,
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ArenaWorkerReleaseBindings":
        _exact_keys(value, cls._FIELDS, label="worker release binding")
        if any(not isinstance(item, str) for item in value.values()):
            raise ArenaWorkerEvidenceError("worker release binding values are invalid")
        return cls(**{key: str(value[key]) for key in cls._FIELDS})


def arena_worker_release_binding_sha256(
    bindings: ArenaWorkerReleaseBindings,
) -> str:
    """Commit the complete, validated public release binding canonically."""

    if not isinstance(bindings, ArenaWorkerReleaseBindings):
        raise ArenaWorkerEvidenceError("worker release binding is invalid")
    return _sha256_commitment(
        _RELEASE_BINDING_DIGEST_DOMAIN,
        {
            "schema": RELEASE_BINDING_SCHEMA,
            "release_binding": bindings.to_dict(),
        },
    )


def arena_worker_heartbeat_binding_sha256(
    *,
    challenge_id: str,
    challenge_version: str,
    heartbeat_observed_at: int,
    release_binding_sha256: str,
) -> str:
    """Commit the bounded public facts derived from one verified heartbeat.

    This is not the heartbeat MAC and cannot be used to forge or authenticate a
    heartbeat.  It is a domain-separated commitment over only the public facts
    needed to bind an activation observation to one fresh, exact release.
    """

    if challenge_id != DNASEQ_SAFE_IR_CHALLENGE_ID:
        raise ArenaWorkerEvidenceError("worker heartbeat challenge is invalid")
    if challenge_version != DNASEQ_SAFE_IR_CHALLENGE_VERSION:
        raise ArenaWorkerEvidenceError("worker heartbeat challenge version is invalid")
    observed_at = _bounded_int(
        heartbeat_observed_at,
        minimum=0,
        maximum=4_102_444_800,
        label="worker heartbeat time",
    )
    if not isinstance(release_binding_sha256, str) or not _SHA256.fullmatch(
        release_binding_sha256
    ):
        raise ArenaWorkerEvidenceError("worker release binding digest is invalid")
    return _sha256_commitment(
        _HEARTBEAT_BINDING_DIGEST_DOMAIN,
        {
            "schema": HEARTBEAT_BINDING_SCHEMA,
            "heartbeat_schema": HEARTBEAT_SCHEMA,
            "challenge_id": challenge_id,
            "challenge_version": challenge_version,
            "heartbeat_observed_at": observed_at,
            "release_binding_sha256": release_binding_sha256,
            "evidence_classification": EVIDENCE_CLASSIFICATION,
        },
    )


@dataclass(frozen=True)
class ArenaWorkerHeartbeat:
    bindings: ArenaWorkerReleaseBindings
    observed_at: int
    state: str

    _FIELDS = frozenset({"bindings", "observed_at", "state"})

    def __post_init__(self) -> None:
        if not isinstance(self.bindings, ArenaWorkerReleaseBindings):
            raise ArenaWorkerEvidenceError("worker heartbeat bindings are invalid")
        _bounded_int(
            self.observed_at,
            minimum=0,
            maximum=4_102_444_800,
            label="worker heartbeat time",
        )
        if self.state not in {"ready", "processing", "unavailable"}:
            raise ArenaWorkerEvidenceError("worker heartbeat state is invalid")

    def to_dict(self) -> dict[str, Any]:
        return {
            "bindings": self.bindings.to_dict(),
            "observed_at": self.observed_at,
            "state": self.state,
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ArenaWorkerHeartbeat":
        _exact_keys(value, cls._FIELDS, label="worker heartbeat")
        raw_bindings = value["bindings"]
        if not isinstance(raw_bindings, Mapping):
            raise ArenaWorkerEvidenceError("worker heartbeat bindings are invalid")
        return cls(
            bindings=ArenaWorkerReleaseBindings.from_mapping(raw_bindings),
            observed_at=_bounded_int(
                value["observed_at"],
                minimum=0,
                maximum=4_102_444_800,
                label="worker heartbeat time",
            ),
            state=str(value["state"]),
        )


class ArenaWorkerHeartbeatStore:
    """Single-record atomic heartbeat file authenticated with HMAC-SHA256."""

    _ROOT_FIELDS = frozenset({"schema", "heartbeat", "mac"})

    def __init__(self, path: str | Path, *, integrity_key: bytes) -> None:
        if not isinstance(path, (str, Path)) or not str(path).strip():
            raise ArenaWorkerEvidenceError("worker heartbeat path is required")
        if not isinstance(integrity_key, bytes) or len(integrity_key) < 32:
            raise ArenaWorkerEvidenceError("worker heartbeat integrity key is invalid")
        self.path = Path(path)
        self._key = bytes(integrity_key)

    def write(self, heartbeat: ArenaWorkerHeartbeat) -> None:
        if not isinstance(heartbeat, ArenaWorkerHeartbeat):
            raise ArenaWorkerEvidenceError("worker heartbeat is invalid")
        if self.path.is_symlink():
            raise ArenaWorkerEvidenceError("worker heartbeat path cannot be a symlink")
        payload = heartbeat.to_dict()
        encoded_payload = _canonical_json(payload)
        mac = hmac.new(
            self._key,
            b"dnai-wikigen/arena-worker-heartbeat/v1\0" + encoded_payload,
            hashlib.sha256,
        ).hexdigest()
        encoded = _canonical_json(
            {"schema": HEARTBEAT_SCHEMA, "heartbeat": payload, "mac": mac}
        )
        if len(encoded) > MAX_HEARTBEAT_BYTES:
            raise ArenaWorkerEvidenceError("worker heartbeat is oversized")
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{self.path.name}.",
            dir=self.path.parent,
        )
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            descriptor = -1
            os.replace(temporary, self.path)
            directory = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError as exc:
            raise ArenaWorkerEvidenceError("worker heartbeat persistence failed") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    def read(self) -> ArenaWorkerHeartbeat:
        try:
            if self.path.is_symlink():
                raise ArenaWorkerEvidenceError("worker heartbeat path cannot be a symlink")
            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(self.path, flags)
            try:
                details = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(details.st_mode)
                    or stat.S_IMODE(details.st_mode) != 0o600
                    or details.st_size < 2
                    or details.st_size > MAX_HEARTBEAT_BYTES
                ):
                    raise ArenaWorkerEvidenceError("worker heartbeat file is unsafe")
                raw = os.read(descriptor, MAX_HEARTBEAT_BYTES + 1)
            finally:
                os.close(descriptor)
        except ArenaWorkerEvidenceError:
            raise
        except OSError as exc:
            raise ArenaWorkerEvidenceError("worker heartbeat is unavailable") from exc
        if len(raw) > MAX_HEARTBEAT_BYTES:
            raise ArenaWorkerEvidenceError("worker heartbeat is oversized")
        try:
            root = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise ArenaWorkerEvidenceError("worker heartbeat JSON is invalid") from exc
        if not isinstance(root, Mapping):
            raise ArenaWorkerEvidenceError("worker heartbeat root is invalid")
        _exact_keys(root, self._ROOT_FIELDS, label="worker heartbeat envelope")
        if root["schema"] != HEARTBEAT_SCHEMA:
            raise ArenaWorkerEvidenceError("worker heartbeat schema is invalid")
        payload = root["heartbeat"]
        supplied_mac = root["mac"]
        if not isinstance(payload, Mapping) or not isinstance(supplied_mac, str):
            raise ArenaWorkerEvidenceError("worker heartbeat envelope is invalid")
        if not _HEX_64.fullmatch(supplied_mac):
            raise ArenaWorkerEvidenceError("worker heartbeat MAC is invalid")
        expected_mac = hmac.new(
            self._key,
            b"dnai-wikigen/arena-worker-heartbeat/v1\0" + _canonical_json(payload),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(supplied_mac, expected_mac):
            raise ArenaWorkerEvidenceError("worker heartbeat authentication failed")
        return ArenaWorkerHeartbeat.from_mapping(payload)


def arena_worker_heartbeat_integrity_key(settings: Any) -> bytes:
    """Resolve a key isolated from wallet, ingress, runtime, and policy keys."""

    if dstack_utils.is_dstack_enabled():
        if dstack_utils.is_dstack_simulator():
            raise ArenaWorkerEvidenceError("real dstack is required for live heartbeat")
        path = str(
            getattr(
                settings,
                "arena_worker_heartbeat_key_path",
                "tinker/arena_worker_heartbeat",
            )
            or ""
        ).strip()
        if not path:
            raise ArenaWorkerEvidenceError("worker heartbeat dstack key path is missing")
        try:
            derived = dstack_utils.derive_storage_key(path)
        except Exception as exc:
            raise ArenaWorkerEvidenceError("worker heartbeat key derivation failed") from exc
        return hashlib.sha256(
            b"dnai-wikigen/arena-worker-heartbeat/dstack/v1\0" + derived
        ).digest()
    explicit = str(
        getattr(settings, "arena_worker_heartbeat_integrity_key", "") or ""
    )
    if len(explicit.encode("utf-8")) < 32:
        raise ArenaWorkerEvidenceError("local worker heartbeat key is unavailable")
    return hashlib.sha256(
        b"dnai-wikigen/arena-worker-heartbeat/local/v1\0"
        + explicit.encode("utf-8")
    ).digest()


def arena_worker_expected_release_bindings(settings: Any) -> ArenaWorkerReleaseBindings:
    """Resolve the API's deployment-injected public descriptor pins.

    These values are separate from the worker's sealed release manifest. The
    release pipeline injects them into the public delegate from its reviewed
    deployment descriptor, while the worker repeats values obtained from its
    independently hash-pinned manifest. A mismatch therefore fails closed
    without granting the delegate access to the sealed evaluator volume.
    """

    from tinker_delegate.arena_store import default_challenge_catalog

    challenge = default_challenge_catalog().get(
        DNASEQ_SAFE_IR_CHALLENGE_ID,
        DNASEQ_SAFE_IR_CHALLENGE_VERSION,
    )
    return ArenaWorkerReleaseBindings(
        release_sha=str(getattr(settings, "arena_worker_release_sha", "") or "").strip(),
        image_digest=str(
            getattr(settings, "arena_worker_image_digest", "") or ""
        ).strip(),
        release_manifest_sha256=str(
            getattr(settings, "arena_worker_release_manifest_sha256", "") or ""
        ).strip(),
        approved_challenge_set_sha256=str(
            getattr(
                settings,
                "arena_worker_approved_challenge_set_sha256",
                "",
            )
            or ""
        ).strip(),
        approved_challenge_key=(
            f"{DNASEQ_SAFE_IR_CHALLENGE_ID}@{DNASEQ_SAFE_IR_CHALLENGE_VERSION}"
        ),
        release_policy_commitment=str(
            getattr(settings, "arena_worker_release_policy_commitment", "") or ""
        ).strip(),
        catalog_manifest_hash=challenge.manifest_hash,
        runtime=SAFE_IR_RUNTIME,
        runtime_policy_commitment=SAFE_IR_POLICY_COMMITMENT,
        compose_hash=str(
            getattr(settings, "arena_worker_compose_hash", "") or ""
        ).strip(),
        app_id=str(getattr(settings, "arena_worker_app_id", "") or "").strip(),
        os_image_hash=str(
            getattr(settings, "arena_worker_os_image_hash", "") or ""
        ).strip(),
    )


def worker_status_state(status_state: str) -> str:
    """Collapse process detail into one non-sensitive presence state."""

    if status_state in {"idle", "completed", "failed"}:
        return "ready"
    if status_state in {"blocked", "operator_error", "stopped"}:
        return "unavailable"
    raise ArenaWorkerEvidenceError("worker process status cannot be projected")


def project_arena_worker_capability(
    *,
    challenge_id: str,
    challenge_version: str,
    enabled: bool,
    expected_bindings: ArenaWorkerReleaseBindings | None,
    heartbeat_store: ArenaWorkerHeartbeatStore | None,
    now: int,
    ttl_seconds: int,
) -> dict[str, Any]:
    """Project live safe-IR execution only from fresh exact authenticated state."""

    current = _bounded_int(now, minimum=0, maximum=4_102_444_800, label="current time")
    ttl = _bounded_int(
        ttl_seconds,
        minimum=5,
        maximum=MAX_HEARTBEAT_TTL_SECONDS,
        label="worker heartbeat ttl",
    )
    safe_ir = (
        challenge_id == DNASEQ_SAFE_IR_CHALLENGE_ID
        and challenge_version == DNASEQ_SAFE_IR_CHALLENGE_VERSION
    )
    reason = "python_preview_only" if not safe_ir else "live_release_not_enabled"
    heartbeat: ArenaWorkerHeartbeat | None = None
    if safe_ir and enabled:
        if expected_bindings is None:
            reason = "release_descriptor_unavailable"
        elif heartbeat_store is None:
            reason = "evidence_unavailable"
        else:
            try:
                heartbeat = heartbeat_store.read()
            except ArenaWorkerEvidenceError:
                reason = "evidence_invalid"
            else:
                if heartbeat.bindings != expected_bindings:
                    reason = "evidence_mismatch"
                elif heartbeat.observed_at > current + MAX_FUTURE_SKEW_SECONDS:
                    reason = "evidence_invalid"
                elif current - heartbeat.observed_at > ttl:
                    reason = "evidence_stale"
                elif heartbeat.state == "unavailable":
                    reason = "worker_unavailable"
                else:
                    reason = "ready"
    live = safe_ir and enabled and reason == "ready"
    release_binding = None
    release_binding_sha256 = None
    if expected_bindings is not None:
        release_binding = expected_bindings.to_dict()
        release_binding_sha256 = arena_worker_release_binding_sha256(
            expected_bindings
        )
    heartbeat_observed_at = heartbeat.observed_at if live and heartbeat else None
    heartbeat_binding_sha256 = None
    if heartbeat_observed_at is not None and release_binding_sha256 is not None:
        heartbeat_binding_sha256 = arena_worker_heartbeat_binding_sha256(
            challenge_id=challenge_id,
            challenge_version=challenge_version,
            heartbeat_observed_at=heartbeat_observed_at,
            release_binding_sha256=release_binding_sha256,
        )
    return {
        "surface": "arena_worker_capability",
        "schema_version": CAPABILITY_SCHEMA_VERSION,
        "challenge_id": challenge_id,
        "challenge_version": challenge_version,
        "status": "live" if live else "modeled",
        "backend": "release_bound_safe_ir_worker" if live else "source_ready_preview",
        "isolation": "independent_job_gate_required" if live else "not_connected",
        "live_execution": live,
        "worker_connected": live,
        "safe_ir_execution_ready": live,
        "hostile_general_code_ready": False,
        "python_preview_live": False,
        "freshness": "fresh" if live else "unavailable",
        "evidence_authenticity": "hmac_verified" if live else "unverified",
        "evidence_classification": EVIDENCE_CLASSIFICATION,
        "gate_reason": reason,
        "heartbeat_observed_at": heartbeat_observed_at,
        "heartbeat_binding_sha256": heartbeat_binding_sha256,
        "release_binding_sha256": release_binding_sha256,
        "release_binding": release_binding,
        "warning": (
            "Fresh authenticated worker presence matches the exact release pins. "
            "This heartbeat is not TDX evidence; every job still requires its "
            "independent quote, QVL, registry, and execution-policy gates."
            if live
            else "Source-ready projection only. Live execution requires the deployed "
            "release descriptor and a fresh matching authenticated safe-IR heartbeat."
        ),
        "product_status": "live" if live else "modeled",
        "exact_timing_egress": False,
        "internal_error_egress": False,
        "raw_candidate_egress": False,
        "tdx_attestation_egress": False,
    }


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value
