"""Exact release-approved Arena challenge-set commitments.

The public ``ChallengeRegistry`` is intentionally extensible.  A registry row
therefore proves that a challenge exists; it does not grant a running release
permission to execute it.  This module defines the separate, finite set that a
reviewed release approved.  Consumers recompute the domain-separated digest
from the complete normalized set and then select one exact ``id@version`` row.
Unrelated rows added to the registry cannot change or enlarge that set.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any, Mapping


APPROVED_CHALLENGE_SET_SCHEMA = "dnai.arena.release-approved-challenge-set.v1"
APPROVED_CHALLENGE_SET_DOMAIN = (
    b"dnai-wikigen/arena-release-approved-challenge-set/v1\0"
)
MAX_APPROVED_CHALLENGES = 32
MAX_APPROVED_CHALLENGE_BINDINGS_JSON_BYTES = 64 * 1024

_CHALLENGE_KEY = re.compile(
    r"^[a-z0-9][a-z0-9-]{0,63}@"
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)
_UINT = re.compile(r"^[1-9][0-9]{0,77}$")
_ADDRESS = re.compile(r"^0x[0-9a-f]{40}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_BYTES32 = re.compile(r"^0x[0-9a-f]{64}$")
_ZERO_ADDRESS = "0x" + "0" * 40

APPROVED_BINDING_FIELDS = frozenset(
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
    }
)


class ArenaReleaseApprovalError(ValueError):
    """Raised when a release-approved challenge set is not exact/canonical."""


def normalize_release_approved_challenge_bindings(
    value: Any,
) -> dict[str, dict[str, Any]]:
    """Return a canonical, sorted, finite release-approved binding set."""

    if not isinstance(value, Mapping):
        raise ArenaReleaseApprovalError("approved challenge bindings are invalid")
    entries = sorted(value.items())
    if not 1 <= len(entries) <= MAX_APPROVED_CHALLENGES:
        raise ArenaReleaseApprovalError("approved challenge binding count is invalid")

    normalized: dict[str, dict[str, Any]] = {}
    registry_ids: set[str] = set()
    for key, raw in entries:
        if not isinstance(key, str) or _CHALLENGE_KEY.fullmatch(key) is None:
            raise ArenaReleaseApprovalError("approved challenge key is invalid")
        if not isinstance(raw, Mapping) or set(raw) != APPROVED_BINDING_FIELDS:
            raise ArenaReleaseApprovalError(
                f"approved challenge binding {key} fields are invalid"
            )

        registry_id = raw["registry_challenge_id"]
        if (
            not isinstance(registry_id, str)
            or _UINT.fullmatch(registry_id) is None
            or int(registry_id) >= 2**256
            or registry_id in registry_ids
        ):
            raise ArenaReleaseApprovalError(
                f"approved challenge binding {key} registry id is invalid"
            )
        registry_ids.add(registry_id)

        registry_version = raw["registry_version"]
        if (
            isinstance(registry_version, bool)
            or not isinstance(registry_version, int)
            or not 1 <= registry_version < 2**32
        ):
            raise ArenaReleaseApprovalError(
                f"approved challenge binding {key} registry version is invalid"
            )

        controller = _address(raw["controller_address"], key, "controller")
        if controller == _ZERO_ADDRESS:
            raise ArenaReleaseApprovalError(
                f"approved challenge binding {key} controller address is zero"
            )
        pending_controller = _address(
            raw["pending_controller_address"], key, "pending controller"
        )
        if pending_controller != _ZERO_ADDRESS:
            raise ArenaReleaseApprovalError(
                f"approved challenge binding {key} pending controller is not empty"
            )
        if (
            raw["lifecycle"] != "open"
            or raw["paused"] is not False
            or raw["configuration_frozen"] is not True
        ):
            raise ArenaReleaseApprovalError(
                f"approved challenge binding {key} is not frozen and open"
            )

        manifest_hash = _hex64(raw["catalog_manifest_hash"], key, "manifest")
        metadata_uri = raw["metadata_uri"]
        if (
            not isinstance(metadata_uri, str)
            or not 1 <= len(metadata_uri.encode("ascii", errors="ignore")) <= 256
            or any(ord(character) < 0x21 or ord(character) > 0x7E for character in metadata_uri)
        ):
            raise ArenaReleaseApprovalError(
                f"approved challenge binding {key} metadata URI is invalid"
            )
        metadata_hash = _bytes32(raw["metadata_hash"], key, "metadata")
        if metadata_hash != "0x" + manifest_hash:
            raise ArenaReleaseApprovalError(
                f"approved challenge binding {key} metadata hash does not commit to its manifest"
            )
        sealed = _bytes32(raw["sealed_artifact_commitment"], key, "sealed artifact")
        evaluator = _bytes32(raw["evaluator_commitment"], key, "evaluator")
        if len({metadata_hash, sealed, evaluator}) != 3:
            raise ArenaReleaseApprovalError(
                f"approved challenge binding {key} commitments are not distinct"
            )

        normalized[key] = {
            "registry_challenge_id": registry_id,
            "registry_version": registry_version,
            "controller_address": controller,
            "pending_controller_address": pending_controller,
            "lifecycle": "open",
            "paused": False,
            "configuration_frozen": True,
            "catalog_manifest_hash": manifest_hash,
            "metadata_uri": metadata_uri,
            "metadata_hash": metadata_hash,
            "sealed_artifact_commitment": sealed,
            "evaluator_commitment": evaluator,
        }
    return normalized


def release_approved_challenge_set_sha256(value: Any) -> str:
    """Hash the complete canonical approved set, never live registry contents."""

    normalized = normalize_release_approved_challenge_bindings(value)
    # ``release_policy_commitment`` is deliberately outside this set shape to
    # avoid a hash cycle: each selected on-chain release-policy commitment
    # includes this set digest and is checked separately against chain.
    payload = {
        "schema": APPROVED_CHALLENGE_SET_SCHEMA,
        "bindings": normalized,
    }
    digest = hashlib.sha256()
    digest.update(APPROVED_CHALLENGE_SET_DOMAIN)
    digest.update(_canonical_json(payload))
    return "sha256:" + digest.hexdigest()


def require_release_approved_challenge(
    bindings: Any,
    *,
    approved_set_sha256: str,
    challenge_id: str,
    challenge_version: str,
) -> dict[str, Any]:
    """Return one member only after the whole set matches its release digest."""

    normalized = normalize_release_approved_challenge_bindings(bindings)
    observed = release_approved_challenge_set_sha256(normalized)
    if not isinstance(approved_set_sha256, str) or not hmac.compare_digest(
        observed, approved_set_sha256
    ):
        raise ArenaReleaseApprovalError("approved challenge set digest mismatch")
    key = f"{challenge_id}@{challenge_version}"
    try:
        return normalized[key]
    except KeyError:
        raise ArenaReleaseApprovalError(
            f"challenge {key} is not release-approved"
        ) from None


def _address(value: Any, key: str, label: str) -> str:
    if not isinstance(value, str) or _ADDRESS.fullmatch(value) is None:
        raise ArenaReleaseApprovalError(
            f"approved challenge binding {key} {label} address is invalid"
        )
    return value


def _hex64(value: Any, key: str, label: str) -> str:
    if not isinstance(value, str) or _HEX_64.fullmatch(value) is None or value == "0" * 64:
        raise ArenaReleaseApprovalError(
            f"approved challenge binding {key} {label} hash is invalid"
        )
    return value


def _bytes32(value: Any, key: str, label: str) -> str:
    if not isinstance(value, str) or _BYTES32.fullmatch(value) is None or value == "0x" + "0" * 64:
        raise ArenaReleaseApprovalError(
            f"approved challenge binding {key} {label} commitment is invalid"
        )
    return value


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
        raise ArenaReleaseApprovalError("approved challenge set is not canonical JSON") from exc
