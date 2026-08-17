"""Fail-closed ChallengeRegistry admission for Arena ciphertext ingress.

The browser supplies a *proposed* snapshot so its ciphertext can be bound to
one exact challenge release and one exact Base Sepolia block.  That proposal is
never accepted as authority.  Before either the ciphertext blob or its queue
record is persisted, the delegate independently:

* selects the request block only after one configured RPC reports it finalized;
* checks the block number, hash, and timestamp before and after every contract
  read at that same block number, including a second read of the moving
  ``finalized`` tag;
* pins the registry runtime bytecode and the complete frozen/open challenge
  state to deployment-controlled release configuration; and
* returns only a bounded authorization receipt.  This is single-RPC evidence,
  not RPC quorum, consensus proof, worker job authorization, or TDX evidence.

This boundary does not yet have an authenticated atomic store for a monotonic
finalized-block checkpoint across separate requests.  Each request therefore
revalidates the RPC's current finalized head independently, but cannot prove
that the same RPC did not roll back below a previously accepted finalized head.
The Arena state file has a purpose-separated HMAC integrity envelope, but that
does not make it an anti-rollback primitive and it is not part of the same
transaction as both later ingress writes. It is therefore deliberately not
repurposed as false monotonic durability authority here.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import time
from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from eth_hash.auto import keccak

from tinker_delegate.arena_release_approval import (
    ArenaReleaseApprovalError,
    MAX_APPROVED_CHALLENGE_BINDINGS_JSON_BYTES,
    MAX_APPROVED_CHALLENGES,
    normalize_release_approved_challenge_bindings,
    release_approved_challenge_set_sha256,
    require_release_approved_challenge,
)
from tinker_delegate.arena_store import ChallengeManifest
from tinker_delegate.arena_worker_cli import (
    ArenaRegistryChallengeState,
    ArenaRegistryVersionState,
    HttpsArenaRegistryReader,
)


BASE_SEPOLIA_CHAIN_ID = 84_532
AUTHORIZATION_SCHEMA_VERSION = 1
AUTHORIZATION_VERIFICATION_MODEL = (
    "single_rpc_reported_finalized_pinned_block"
)
AUTHORIZATION_COMMITMENT_DOMAIN = (
    b"dnai-wikigen/arena-registry-authorization-snapshot/v1\0"
)
MAX_BLOCK_AGE_SECONDS = 300
MAX_FUTURE_BLOCK_SKEW_SECONDS = 30

_ADDRESS = re.compile(r"^0x[0-9a-f]{40}$")
_BYTES32 = re.compile(r"^0x[0-9a-f]{64}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_UINT = re.compile(r"^(0|[1-9][0-9]{0,77})$")
_CHALLENGE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)
_METADATA_URI = re.compile(r"^[\x21-\x7e]{1,256}$")

_SNAPSHOT_FIELDS = frozenset(
    {
        "schema_version",
        "verification_model",
        "chain_id",
        "block_number",
        "block_hash",
        "block_timestamp",
        "registry_address",
        "registry_runtime_code_hash",
        "approved_challenge_set_sha256",
        "catalog_challenge_id",
        "catalog_challenge_version",
        "catalog_manifest_hash",
        "registry_challenge_id",
        "registry_version",
        "controller_address",
        "pending_controller_address",
        "metadata_uri",
        "metadata_hash",
        "sealed_artifact_commitment",
        "evaluator_commitment",
        "release_policy_commitment",
        "registry_paused",
        "challenge_paused",
        "lifecycle",
        "configuration_frozen",
        "latest_version",
    }
)
_CONFIGURED_BINDING_FIELDS = frozenset(
    {
        "registry_challenge_id",
        "registry_version",
        "controller_address",
        "pending_controller_address",
        "lifecycle",
        "paused",
        "configuration_frozen",
        "catalog_manifest_hash",
        "metadata_uri",
        "metadata_hash",
        "sealed_artifact_commitment",
        "evaluator_commitment",
        "release_policy_commitment",
    }
)


class ArenaRegistryAdmissionError(RuntimeError):
    """Bounded fail-closed ingress authorization error."""


def _exact_mapping(
    value: Any, expected: frozenset[str], *, label: str
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ArenaRegistryAdmissionError(f"{label} fields are invalid")
    return value


def _integer(value: Any, *, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ArenaRegistryAdmissionError(f"{label} is invalid")
    if value < minimum or value > maximum:
        raise ArenaRegistryAdmissionError(f"{label} is invalid")
    return value


def _decimal_uint(value: Any, *, label: str, maximum: int) -> int:
    if not isinstance(value, str) or _UINT.fullmatch(value) is None:
        raise ArenaRegistryAdmissionError(f"{label} is invalid")
    parsed = int(value)
    if parsed > maximum:
        raise ArenaRegistryAdmissionError(f"{label} is invalid")
    return parsed


def _bounded_ascii(value: Any, *, label: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ArenaRegistryAdmissionError(f"{label} is invalid")
    return value


def _nonzero(value: Any, *, label: str, pattern: re.Pattern[str]) -> str:
    parsed = _bounded_ascii(value, label=label, pattern=pattern)
    raw = parsed.removeprefix("sha256:").removeprefix("0x")
    if raw == "0" * len(raw):
        raise ArenaRegistryAdmissionError(f"{label} is invalid")
    return parsed


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
        raise ArenaRegistryAdmissionError(
            "Arena registry authorization is not canonical JSON"
        ) from exc


def _canonical_configured_bindings_json(value: Any) -> Mapping[str, Any]:
    """Decode the projector's exact compact-ASCII runtime environment value."""

    if not isinstance(value, str):
        raise ArenaRegistryAdmissionError(
            "Arena registry release bindings are unavailable"
        )
    try:
        raw = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ArenaRegistryAdmissionError(
            "Arena registry release bindings are unavailable"
        ) from exc
    if (
        len(raw) < 2
        or len(raw) > MAX_APPROVED_CHALLENGE_BINDINGS_JSON_BYTES
        or value[:1] != "{"
        or value[-1:] != "}"
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise ArenaRegistryAdmissionError(
            "Arena registry release bindings are unavailable"
        )

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        decoded_object: dict[str, Any] = {}
        for key, item in pairs:
            if key in decoded_object:
                raise ArenaRegistryAdmissionError(
                    "Arena registry release bindings contain duplicate fields"
                )
            decoded_object[key] = item
        return decoded_object

    def reject_nonfinite_constant(_value: str) -> None:
        raise ArenaRegistryAdmissionError(
            "Arena registry release bindings are unavailable"
        )

    try:
        decoded = json.loads(
            value,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonfinite_constant,
        )
    except ArenaRegistryAdmissionError:
        raise
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ArenaRegistryAdmissionError(
            "Arena registry release bindings are unavailable"
        ) from exc
    if (
        not isinstance(decoded, Mapping)
        or not 1 <= len(decoded) <= MAX_APPROVED_CHALLENGES
        or not hmac.compare_digest(raw, _canonical_json(decoded))
    ):
        raise ArenaRegistryAdmissionError(
            "Arena registry release bindings are unavailable"
        )
    return decoded


def _admission_clock_seconds(value: Any) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
    ):
        raise ArenaRegistryAdmissionError(
            "Arena registry admission clock is invalid"
        )
    observed = int(value)
    if observed < 1:
        raise ArenaRegistryAdmissionError(
            "Arena registry admission clock is invalid"
        )
    return observed


@dataclass(frozen=True)
class ArenaRegistryAuthorizationSnapshot:
    schema_version: int
    verification_model: str
    chain_id: int
    block_number: int
    block_hash: str
    block_timestamp: int
    registry_address: str
    registry_runtime_code_hash: str
    approved_challenge_set_sha256: str
    catalog_challenge_id: str
    catalog_challenge_version: str
    catalog_manifest_hash: str
    registry_challenge_id: int
    registry_version: int
    controller_address: str
    pending_controller_address: str
    metadata_uri: str
    metadata_hash: str
    sealed_artifact_commitment: str
    evaluator_commitment: str
    release_policy_commitment: str
    registry_paused: bool
    challenge_paused: bool
    lifecycle: int
    configuration_frozen: bool
    latest_version: int

    @classmethod
    def from_mapping(
        cls, value: Mapping[str, Any]
    ) -> "ArenaRegistryAuthorizationSnapshot":
        payload = _exact_mapping(
            value, _SNAPSHOT_FIELDS, label="Arena registry authorization snapshot"
        )
        if payload["registry_paused"] is not False:
            raise ArenaRegistryAdmissionError("Arena registry snapshot is paused")
        if payload["challenge_paused"] is not False:
            raise ArenaRegistryAdmissionError("Arena challenge snapshot is paused")
        if payload["configuration_frozen"] is not True:
            raise ArenaRegistryAdmissionError(
                "Arena challenge snapshot is not configuration-frozen"
            )
        return cls(
            schema_version=_integer(
                payload["schema_version"],
                label="snapshot schema version",
                minimum=AUTHORIZATION_SCHEMA_VERSION,
                maximum=AUTHORIZATION_SCHEMA_VERSION,
            ),
            verification_model=_bounded_ascii(
                payload["verification_model"],
                label="snapshot verification model",
                pattern=re.compile(
                    "^" + re.escape(AUTHORIZATION_VERIFICATION_MODEL) + "$"
                ),
            ),
            chain_id=_integer(
                payload["chain_id"],
                label="snapshot chain ID",
                minimum=BASE_SEPOLIA_CHAIN_ID,
                maximum=BASE_SEPOLIA_CHAIN_ID,
            ),
            block_number=_decimal_uint(
                payload["block_number"],
                label="snapshot block number",
                maximum=2**64 - 1,
            ),
            block_hash=_nonzero(
                payload["block_hash"], label="snapshot block hash", pattern=_BYTES32
            ),
            block_timestamp=_decimal_uint(
                payload["block_timestamp"],
                label="snapshot block timestamp",
                maximum=2**64 - 1,
            ),
            registry_address=_nonzero(
                payload["registry_address"],
                label="snapshot registry address",
                pattern=_ADDRESS,
            ),
            registry_runtime_code_hash=_nonzero(
                payload["registry_runtime_code_hash"],
                label="snapshot registry runtime code hash",
                pattern=_BYTES32,
            ),
            approved_challenge_set_sha256=_nonzero(
                payload["approved_challenge_set_sha256"],
                label="snapshot approved challenge set",
                pattern=_SHA256,
            ),
            catalog_challenge_id=_bounded_ascii(
                payload["catalog_challenge_id"],
                label="snapshot catalog challenge ID",
                pattern=_CHALLENGE_ID,
            ),
            catalog_challenge_version=_bounded_ascii(
                payload["catalog_challenge_version"],
                label="snapshot catalog challenge version",
                pattern=_SEMVER,
            ),
            catalog_manifest_hash=_nonzero(
                payload["catalog_manifest_hash"],
                label="snapshot catalog manifest hash",
                pattern=_HEX64,
            ),
            registry_challenge_id=_decimal_uint(
                payload["registry_challenge_id"],
                label="snapshot registry challenge ID",
                maximum=2**256 - 1,
            ),
            registry_version=_integer(
                payload["registry_version"],
                label="snapshot registry version",
                minimum=1,
                maximum=2**32 - 1,
            ),
            controller_address=_nonzero(
                payload["controller_address"],
                label="snapshot controller address",
                pattern=_ADDRESS,
            ),
            pending_controller_address=_bounded_ascii(
                payload["pending_controller_address"],
                label="snapshot pending controller address",
                pattern=_ADDRESS,
            ),
            metadata_uri=_bounded_ascii(
                payload["metadata_uri"],
                label="snapshot metadata URI",
                pattern=_METADATA_URI,
            ),
            metadata_hash=_nonzero(
                payload["metadata_hash"],
                label="snapshot metadata hash",
                pattern=_BYTES32,
            ),
            sealed_artifact_commitment=_nonzero(
                payload["sealed_artifact_commitment"],
                label="snapshot sealed artifact commitment",
                pattern=_BYTES32,
            ),
            evaluator_commitment=_nonzero(
                payload["evaluator_commitment"],
                label="snapshot evaluator commitment",
                pattern=_BYTES32,
            ),
            release_policy_commitment=_nonzero(
                payload["release_policy_commitment"],
                label="snapshot release policy commitment",
                pattern=_BYTES32,
            ),
            registry_paused=False,
            challenge_paused=False,
            lifecycle=_integer(
                payload["lifecycle"],
                label="snapshot challenge lifecycle",
                minimum=1,
                maximum=1,
            ),
            configuration_frozen=True,
            latest_version=_integer(
                payload["latest_version"],
                label="snapshot latest version",
                minimum=1,
                maximum=2**32 - 1,
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "verification_model": self.verification_model,
            "chain_id": self.chain_id,
            "block_number": str(self.block_number),
            "block_hash": self.block_hash,
            "block_timestamp": str(self.block_timestamp),
            "registry_address": self.registry_address,
            "registry_runtime_code_hash": self.registry_runtime_code_hash,
            "approved_challenge_set_sha256": self.approved_challenge_set_sha256,
            "catalog_challenge_id": self.catalog_challenge_id,
            "catalog_challenge_version": self.catalog_challenge_version,
            "catalog_manifest_hash": self.catalog_manifest_hash,
            "registry_challenge_id": str(self.registry_challenge_id),
            "registry_version": self.registry_version,
            "controller_address": self.controller_address,
            "pending_controller_address": self.pending_controller_address,
            "metadata_uri": self.metadata_uri,
            "metadata_hash": self.metadata_hash,
            "sealed_artifact_commitment": self.sealed_artifact_commitment,
            "evaluator_commitment": self.evaluator_commitment,
            "release_policy_commitment": self.release_policy_commitment,
            "registry_paused": False,
            "challenge_paused": False,
            "lifecycle": 1,
            "configuration_frozen": True,
            "latest_version": self.latest_version,
        }

    @property
    def sha256(self) -> str:
        digest = hashlib.sha256()
        digest.update(AUTHORIZATION_COMMITMENT_DOMAIN)
        digest.update(_canonical_json(self.to_dict()))
        return "sha256:" + digest.hexdigest()


@dataclass(frozen=True)
class ArenaRegistryBlock:
    number: int
    block_hash: str
    timestamp: int


@dataclass(frozen=True)
class ArenaRegistryIngressAuthorization:
    snapshot_sha256: str
    chain_id: int
    block_number: int
    block_hash: str
    registry_address: str
    registry_challenge_id: int
    registry_version: int

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "surface": "arena_registry_ingress_boundary",
            "schema_version": 1,
            "status": "proxy_independently_verified_at_finalized_block",
            "verification_model": AUTHORIZATION_VERIFICATION_MODEL,
            "browser_preflight_accepted_as_authority": False,
            "proxy_registry_authorized": True,
            "worker_registry_authorized": False,
            "registry_authorization_sha256": self.snapshot_sha256,
            "chain_id": self.chain_id,
            "block_number": str(self.block_number),
            "block_hash": self.block_hash,
            "registry_address": self.registry_address,
            "registry_challenge_id": str(self.registry_challenge_id),
            "registry_version": self.registry_version,
            "independent_rpc_quorum_verified": False,
            "consensus_proof_verified": False,
        }


class ArenaRegistryAdmissionReader(Protocol):
    def chain_id(self) -> int: ...

    def finalized_block(self) -> ArenaRegistryBlock: ...

    def block(self, block_number: int) -> ArenaRegistryBlock: ...

    def bytecode(self, address: str, block_number: int) -> bytes: ...

    def registry_paused(self, address: str, block_number: int) -> bool: ...

    def challenge_exists(
        self, address: str, challenge_id: int, block_number: int
    ) -> bool: ...

    def challenge(
        self, address: str, challenge_id: int, block_number: int
    ) -> ArenaRegistryChallengeState: ...

    def version(
        self,
        address: str,
        challenge_id: int,
        version: int,
        block_number: int,
    ) -> ArenaRegistryVersionState: ...

    def close(self) -> None: ...


def _rpc_quantity(value: Any, *, label: str) -> int:
    if (
        not isinstance(value, str)
        or re.fullmatch(r"0x(?:0|[1-9a-f][0-9a-f]*)", value) is None
    ):
        raise ArenaRegistryAdmissionError(f"RPC {label} is malformed")
    return int(value, 16)


class HttpsArenaRegistryAdmissionReader(HttpsArenaRegistryReader):
    """Bounded HTTPS JSON-RPC reader with explicit finalized block identity."""

    @staticmethod
    def _block_from_result(value: Any) -> ArenaRegistryBlock:
        if not isinstance(value, Mapping):
            raise ArenaRegistryAdmissionError("RPC block is unavailable")
        block_hash = value.get("hash")
        if not isinstance(block_hash, str):
            raise ArenaRegistryAdmissionError("RPC block hash is unavailable")
        return ArenaRegistryBlock(
            number=_rpc_quantity(value.get("number"), label="block number"),
            block_hash=_nonzero(
                block_hash.lower(), label="RPC block hash", pattern=_BYTES32
            ),
            timestamp=_rpc_quantity(
                value.get("timestamp"), label="block timestamp"
            ),
        )

    def finalized_block(self) -> ArenaRegistryBlock:
        return self._block_from_result(
            self._call("eth_getBlockByNumber", ["finalized", False])
        )

    def block(self, block_number: int) -> ArenaRegistryBlock:
        if isinstance(block_number, bool) or not isinstance(block_number, int):
            raise ArenaRegistryAdmissionError("RPC block number is invalid")
        return self._block_from_result(
            self._call("eth_getBlockByNumber", [hex(block_number), False])
        )


def _configured_binding(settings: Any, challenge: ChallengeManifest) -> dict[str, Any]:
    raw = getattr(
        settings, "arena_registry_approved_challenge_bindings_json", ""
    )
    approved_sha = getattr(
        settings, "arena_registry_approved_challenge_set_sha256", ""
    )
    if (
        not isinstance(approved_sha, str)
        or _SHA256.fullmatch(approved_sha) is None
        or approved_sha == "sha256:" + "0" * 64
    ):
        raise ArenaRegistryAdmissionError(
            "Arena registry release bindings are unavailable"
        )
    decoded = _canonical_configured_bindings_json(raw)
    normalized_for_set: dict[str, dict[str, Any]] = {}
    release_commitments: dict[str, str] = {}
    for key, raw_binding in decoded.items():
        binding = _exact_mapping(
            raw_binding,
            _CONFIGURED_BINDING_FIELDS,
            label="Arena configured registry binding",
        )
        stripped = dict(binding)
        release_commitment = _nonzero(
            stripped.pop("release_policy_commitment"),
            label="configured release policy commitment",
            pattern=_BYTES32,
        )
        if not isinstance(key, str):
            raise ArenaRegistryAdmissionError(
                "Arena configured registry binding key is invalid"
            )
        normalized_for_set[key] = stripped
        release_commitments[key] = release_commitment
    try:
        normalized_for_set = normalize_release_approved_challenge_bindings(
            normalized_for_set
        )
        normalized_ids = sorted(
            int(binding["registry_challenge_id"])
            for binding in normalized_for_set.values()
        )
        if normalized_ids != list(range(1, len(normalized_ids) + 1)):
            raise ArenaReleaseApprovalError(
                "approved challenge bindings must use contiguous genesis IDs 1..N"
            )
        for key, binding in normalized_for_set.items():
            commitments = {
                binding["metadata_hash"],
                binding["sealed_artifact_commitment"],
                binding["evaluator_commitment"],
                release_commitments[key],
            }
            if len(commitments) != 4:
                raise ArenaReleaseApprovalError(
                    "approved challenge commitments are not pairwise distinct"
                )
        observed_sha = release_approved_challenge_set_sha256(
            normalized_for_set
        )
    except ArenaReleaseApprovalError as exc:
        raise ArenaRegistryAdmissionError(
            "Arena registry release bindings are unavailable"
        ) from exc
    if not hmac.compare_digest(observed_sha, approved_sha):
        raise ArenaRegistryAdmissionError(
            "Arena approved challenge-set commitment is invalid"
        )
    try:
        selected = require_release_approved_challenge(
            normalized_for_set,
            approved_set_sha256=approved_sha,
            challenge_id=challenge.challenge_id,
            challenge_version=challenge.version,
        )
    except ArenaReleaseApprovalError as exc:
        raise ArenaRegistryAdmissionError(
            "Arena challenge is not release-approved"
        ) from exc
    key = f"{challenge.challenge_id}@{challenge.version}"
    if selected["catalog_manifest_hash"] != challenge.manifest_hash:
        raise ArenaRegistryAdmissionError(
            "Arena catalog manifest is not release-approved"
        )
    return {
        **selected,
        "release_policy_commitment": release_commitments[key],
        "approved_challenge_set_sha256": approved_sha,
    }


def authorize_arena_registry_submission(
    settings: Any,
    *,
    challenge: ChallengeManifest,
    snapshot: ArenaRegistryAuthorizationSnapshot,
    reader: ArenaRegistryAdmissionReader | None = None,
    now: int | None = None,
) -> ArenaRegistryIngressAuthorization:
    """Independently authorize one exact request snapshot before persistence."""

    if not isinstance(challenge, ChallengeManifest):
        raise ArenaRegistryAdmissionError("Arena challenge is unavailable")
    if not isinstance(snapshot, ArenaRegistryAuthorizationSnapshot):
        raise ArenaRegistryAdmissionError(
            "Arena registry authorization snapshot is unavailable"
        )
    configured = _configured_binding(settings, challenge)
    rpc_url = str(getattr(settings, "arena_registry_rpc_url", "") or "").strip()
    registry_address = str(
        getattr(settings, "arena_registry_address", "") or ""
    ).strip().lower()
    registry_code_hash = str(
        getattr(settings, "arena_registry_runtime_code_hash", "") or ""
    ).strip().lower()
    configured_max_age = getattr(
        settings, "arena_registry_max_block_age_seconds", 0
    )
    configured_future_skew = getattr(
        settings,
        "arena_registry_max_future_block_skew_seconds",
        -1,
    )
    max_age = _integer(
        configured_max_age,
        label="Arena registry maximum block age",
        minimum=30,
        maximum=3_600,
    )
    future_skew = _integer(
        configured_future_skew,
        label="Arena registry future block skew",
        minimum=0,
        maximum=300,
    )
    if not rpc_url or _ADDRESS.fullmatch(registry_address) is None:
        raise ArenaRegistryAdmissionError("Arena registry admission is not configured")
    _nonzero(
        registry_code_hash,
        label="configured registry runtime code hash",
        pattern=_BYTES32,
    )
    clock = time.time if now is None else lambda: now
    checked_at = _admission_clock_seconds(clock())

    expected_snapshot = {
        "chain_id": BASE_SEPOLIA_CHAIN_ID,
        "registry_address": registry_address,
        "registry_runtime_code_hash": registry_code_hash,
        "approved_challenge_set_sha256": configured[
            "approved_challenge_set_sha256"
        ],
        "catalog_challenge_id": challenge.challenge_id,
        "catalog_challenge_version": challenge.version,
        "catalog_manifest_hash": challenge.manifest_hash,
        "registry_challenge_id": int(configured["registry_challenge_id"]),
        "registry_version": int(configured["registry_version"]),
        "controller_address": configured["controller_address"],
        "pending_controller_address": configured["pending_controller_address"],
        "metadata_uri": configured["metadata_uri"],
        "metadata_hash": configured["metadata_hash"],
        "sealed_artifact_commitment": configured[
            "sealed_artifact_commitment"
        ],
        "evaluator_commitment": configured["evaluator_commitment"],
        "release_policy_commitment": configured[
            "release_policy_commitment"
        ],
        "registry_paused": False,
        "challenge_paused": False,
        "lifecycle": 1,
        "configuration_frozen": True,
        "latest_version": int(configured["registry_version"]),
    }
    snapshot_dict = snapshot.to_dict()
    for field, expected in expected_snapshot.items():
        actual = getattr(snapshot, field)
        if actual != expected:
            raise ArenaRegistryAdmissionError(
                "Arena registry snapshot does not match the approved release"
            )

    owned_reader = reader is None
    active_reader: ArenaRegistryAdmissionReader | None = reader
    try:
        if active_reader is None:
            active_reader = HttpsArenaRegistryAdmissionReader(rpc_url)
        if active_reader.chain_id() != BASE_SEPOLIA_CHAIN_ID:
            raise ArenaRegistryAdmissionError("Arena registry RPC is on the wrong chain")
        finalized = active_reader.finalized_block()
        if (
            finalized.number != snapshot.block_number
            or finalized.block_hash != snapshot.block_hash
            or finalized.timestamp != snapshot.block_timestamp
        ):
            raise ArenaRegistryAdmissionError(
                "Arena registry snapshot is not the current finalized block"
            )
        before = active_reader.block(snapshot.block_number)
        if (
            before != finalized
            or snapshot.block_timestamp > checked_at + future_skew
            or checked_at - snapshot.block_timestamp > max_age
        ):
            raise ArenaRegistryAdmissionError(
                "Arena registry snapshot block is stale or noncanonical"
            )

        code = active_reader.bytecode(registry_address, snapshot.block_number)
        if not code or "0x" + keccak(code).hex() != registry_code_hash:
            raise ArenaRegistryAdmissionError(
                "Arena registry runtime bytecode is not approved"
            )
        registry_paused = active_reader.registry_paused(
            registry_address, snapshot.block_number
        )
        exists = active_reader.challenge_exists(
            registry_address,
            snapshot.registry_challenge_id,
            snapshot.block_number,
        )
        state = active_reader.challenge(
            registry_address,
            snapshot.registry_challenge_id,
            snapshot.block_number,
        )
        version = active_reader.version(
            registry_address,
            snapshot.registry_challenge_id,
            snapshot.registry_version,
            snapshot.block_number,
        )
        after = active_reader.block(snapshot.block_number)
        finalized_after = active_reader.finalized_block()
        if before != after:
            raise ArenaRegistryAdmissionError(
                "Arena registry snapshot block changed during verification"
            )
        if finalized_after != finalized:
            raise ArenaRegistryAdmissionError(
                "Arena registry finalized block advanced during verification"
            )
        expected_state = ArenaRegistryChallengeState(
            controller=snapshot.controller_address,
            pending_controller=snapshot.pending_controller_address,
            lifecycle=1,
            latest_version=snapshot.registry_version,
            paused=False,
            configuration_frozen=True,
        )
        expected_version = ArenaRegistryVersionState(
            metadata_uri=snapshot.metadata_uri,
            metadata_hash=snapshot.metadata_hash,
            sealed_artifact_commitment=snapshot.sealed_artifact_commitment,
            evaluator_commitment=snapshot.evaluator_commitment,
            release_policy_commitment=snapshot.release_policy_commitment,
        )
        if registry_paused or not exists or state != expected_state:
            raise ArenaRegistryAdmissionError(
                "Arena registry challenge is not frozen and open"
            )
        if version != expected_version:
            raise ArenaRegistryAdmissionError(
                "Arena registry challenge commitments do not match"
            )
        # Force canonical serialization before returning a commitment used by
        # the AEAD binding; this also protects against future non-JSON fields.
        _canonical_json(snapshot_dict)
        completed_at = _admission_clock_seconds(clock())
        if (
            completed_at < checked_at
            or snapshot.block_timestamp > completed_at + future_skew
            or completed_at - snapshot.block_timestamp > max_age
        ):
            raise ArenaRegistryAdmissionError(
                "Arena registry snapshot became stale during verification"
            )
        return ArenaRegistryIngressAuthorization(
            snapshot_sha256=snapshot.sha256,
            chain_id=BASE_SEPOLIA_CHAIN_ID,
            block_number=snapshot.block_number,
            block_hash=snapshot.block_hash,
            registry_address=registry_address,
            registry_challenge_id=snapshot.registry_challenge_id,
            registry_version=snapshot.registry_version,
        )
    except ArenaRegistryAdmissionError:
        raise
    except Exception as exc:
        raise ArenaRegistryAdmissionError(
            "Arena registry admission is unavailable"
        ) from exc
    finally:
        if owned_reader and active_reader is not None:
            try:
                active_reader.close()
            except Exception:
                # Closing a read-only bounded HTTP transport must not leak a
                # transport-specific exception or upgrade the evidence claim.
                pass
