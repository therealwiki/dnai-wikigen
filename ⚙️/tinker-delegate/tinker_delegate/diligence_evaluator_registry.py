"""Release-pinned registry for the three production diligence recipes.

The registry is public authority data.  It maps the exact bytes32 commitment
selected by the buyer onchain to one canonical policy document and one compiled
deterministic recipe.  Loading/validation may read the reviewed manifest before
evaluation; the returned evaluator itself performs no I/O and delegates only to
``evaluate_artifact_v1``.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from typing import Any, Mapping

from eth_hash.auto import keccak

from tinker_delegate.deterministic_diligence_evaluator import (
    COMPILED_RECIPES,
    CSV_TABLE_RECIPE,
    MAX_ARTIFACT_BYTES,
    POLICY_SCHEMA,
    SFT_JSONL_RECIPE,
    VCF_STRUCTURAL_QC_RECIPE,
    evaluate_artifact_v1,
    parse_policy_v1,
    policy_commitment_sha256,
)


RELEASE_MANIFEST_SCHEMA = "dnai.diligence-evaluator-release.v1"
DESCRIPTOR_SCHEMA = "dnai.diligence-evaluator-policy-descriptor.v1"
MAX_RELEASE_MANIFEST_BYTES = 65_536
EVALUATOR_POLICY_SET_TYPE = (
    "DiligenceRoomEvaluatorPolicySet(bytes32[3] evaluatorPolicies)"
)
EVALUATOR_POLICY_SET_TYPEHASH = keccak(EVALUATOR_POLICY_SET_TYPE.encode("ascii"))
DISPLAY_SCHEMAS = {
    CSV_TABLE_RECIPE: "dnai.diligence-artifact.csv-table.v1",
    SFT_JSONL_RECIPE: "dnai.diligence-artifact.sft-jsonl.v1",
    VCF_STRUCTURAL_QC_RECIPE: "dnai.diligence-artifact.vcf.v1",
}

_BYTES32 = re.compile(r"^0x(?!0{64}$)[0-9a-f]{64}$")
_SHA256 = re.compile(r"^sha256:(?!0{64}$)[0-9a-f]{64}$")
_MANIFEST_KEYS = frozenset(
    {
        "schema",
        "descriptor_schema",
        "evaluator_policy_set_root",
        "max_artifact_bytes",
        "policies",
    }
)
_DESCRIPTOR_KEYS = frozenset(
    {
        "recipe",
        "policy_commitment",
        "display_schema",
        "max_artifact_bytes",
        "policy_document_sha256",
        "policy_document",
    }
)


class DiligenceEvaluatorRegistryError(ValueError):
    """Stable, content-free release-registry rejection."""


def _reject(code: str) -> None:
    raise DiligenceEvaluatorRegistryError(code)


def _duplicate_free_json(raw: bytes) -> Any:
    def pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                _reject("release_manifest_duplicate_key")
            result[key] = value
        return result

    def reject_constant(_value: str) -> None:
        _reject("release_manifest_nonfinite_number")

    try:
        return json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=pairs_hook,
            parse_constant=reject_constant,
        )
    except DiligenceEvaluatorRegistryError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError):
        _reject("release_manifest_json_invalid")


def _canonical_json(value: Any) -> bytes:
    try:
        return (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        _reject("release_manifest_json_invalid")


def _read_stable_regular_manifest(manifest_path: str) -> bytes:
    descriptor = -1
    try:
        descriptor = os.open(
            manifest_path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size <= 0
            or before.st_size > MAX_RELEASE_MANIFEST_BYTES
        ):
            _reject("release_manifest_size_invalid")
        chunks = bytearray()
        while True:
            chunk = os.read(descriptor, min(65_536, MAX_RELEASE_MANIFEST_BYTES + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
            if len(chunks) > MAX_RELEASE_MANIFEST_BYTES:
                _reject("release_manifest_size_invalid")
        after = os.fstat(descriptor)
        if (
            len(chunks) != before.st_size
            or before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
        ):
            _reject("release_manifest_changed")
        return bytes(chunks)
    except DiligenceEvaluatorRegistryError:
        raise
    except OSError:
        _reject("release_manifest_unavailable")
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def policy_commitment_bytes32(canonical_policy_json: bytes) -> str:
    """Translate the domain-separated policy SHA-256 to Solidity bytes32."""

    commitment = policy_commitment_sha256(canonical_policy_json)
    return "0x" + commitment.removeprefix("sha256:")


def evaluator_policy_set_root(commitments: tuple[str, str, str]) -> str:
    """Mirror ``DiligenceRoom.computeEvaluatorPolicySetRoot`` exactly."""

    normalized = tuple(sorted(value.lower() for value in commitments))
    if len(set(normalized)) != 3 or any(_BYTES32.fullmatch(value) is None for value in normalized):
        _reject("release_policy_commitments_invalid")
    encoded = EVALUATOR_POLICY_SET_TYPEHASH + b"".join(
        bytes.fromhex(value[2:]) for value in normalized
    )
    return "0x" + keccak(encoded).hex()


@dataclass(frozen=True, slots=True)
class DiligencePolicyDescriptor:
    recipe: str
    policy_commitment: str
    display_schema: str
    max_artifact_bytes: int
    policy_document_sha256: str
    canonical_policy_json: bytes

    def to_public_dict(self) -> dict[str, object]:
        return {
            "recipe": self.recipe,
            "policy_commitment": self.policy_commitment,
            "display_schema": self.display_schema,
            "max_artifact_bytes": self.max_artifact_bytes,
            "policy_document_sha256": self.policy_document_sha256,
        }


@dataclass(frozen=True, slots=True)
class DiligenceEvaluatorRegistry:
    descriptors: tuple[
        DiligencePolicyDescriptor,
        DiligencePolicyDescriptor,
        DiligencePolicyDescriptor,
    ]
    evaluator_policy_set_root: str
    manifest_sha256: str

    def resolve(self, policy_commitment: str) -> "DeterministicDiligenceEvaluator":
        normalized = policy_commitment.lower()
        if _BYTES32.fullmatch(normalized) is None:
            _reject("deal_evaluator_policy_commitment_invalid")
        for descriptor in self.descriptors:
            if descriptor.policy_commitment == normalized:
                return DeterministicDiligenceEvaluator(descriptor)
        _reject("deal_evaluator_policy_not_in_release")

    def public_descriptors(self) -> list[dict[str, object]]:
        return [descriptor.to_public_dict() for descriptor in self.descriptors]


@dataclass(frozen=True, slots=True)
class DeterministicDiligenceEvaluator:
    """One recipe-bound callable accepted by ``ControlPlane.evaluate``."""

    descriptor: DiligencePolicyDescriptor
    requires_tinker_session = False

    async def __call__(
        self,
        *,
        artifact: bytes,
        artifact_type: str,
        session: object | None,
        budget_cap: int,
        reserve_price: int,
    ) -> dict[str, float]:
        # These public context values cannot select code or affect the private
        # result.  Only the frozen descriptor selected by the onchain bytes32
        # commitment controls the recipe.
        del artifact_type, session, budget_cap, reserve_price
        return evaluate_artifact_v1(
            artifact=artifact,
            recipe=self.descriptor.recipe,
            canonical_policy_json=self.descriptor.canonical_policy_json,
            expected_policy_commitment_sha256=(
                "sha256:" + self.descriptor.policy_commitment[2:]
            ),
        )


def load_diligence_evaluator_registry(
    manifest_path: str,
    *,
    expected_manifest_sha256: str,
    expected_policy_set_root: str,
) -> DiligenceEvaluatorRegistry:
    if not manifest_path:
        _reject("release_manifest_authority_missing")
    raw = _read_stable_regular_manifest(manifest_path)
    return load_diligence_evaluator_registry_bytes(
        raw,
        expected_manifest_sha256=expected_manifest_sha256,
        expected_policy_set_root=expected_policy_set_root,
    )


def load_diligence_evaluator_registry_bytes(
    raw: bytes,
    *,
    expected_manifest_sha256: str,
    expected_policy_set_root: str,
) -> DiligenceEvaluatorRegistry:
    """Validate exact in-memory release bytes against projected authority."""

    if not _SHA256.fullmatch(expected_manifest_sha256):
        _reject("release_manifest_authority_missing")
    if _BYTES32.fullmatch(expected_policy_set_root) is None:
        _reject("release_policy_set_root_invalid")
    if (
        type(raw) is not bytes
        or not raw
        or len(raw) > MAX_RELEASE_MANIFEST_BYTES
    ):
        _reject("release_manifest_size_invalid")
    actual_manifest_sha256 = "sha256:" + hashlib.sha256(raw).hexdigest()
    if actual_manifest_sha256 != expected_manifest_sha256:
        _reject("release_manifest_sha256_mismatch")
    payload = _duplicate_free_json(raw)
    if raw != _canonical_json(payload):
        _reject("release_manifest_json_not_canonical")
    if not isinstance(payload, dict) or set(payload) != _MANIFEST_KEYS:
        _reject("release_manifest_fields_invalid")
    if (
        payload["schema"] != RELEASE_MANIFEST_SCHEMA
        or payload["descriptor_schema"] != DESCRIPTOR_SCHEMA
        or type(payload["max_artifact_bytes"]) is not int
        or payload["max_artifact_bytes"] != MAX_ARTIFACT_BYTES
        or not isinstance(payload["policies"], list)
        or len(payload["policies"]) != 3
    ):
        _reject("release_manifest_shape_invalid")

    descriptors: list[DiligencePolicyDescriptor] = []
    for index, item in enumerate(payload["policies"]):
        if not isinstance(item, dict) or set(item) != _DESCRIPTOR_KEYS:
            _reject("release_descriptor_fields_invalid")
        recipe = item["recipe"]
        if type(recipe) is not str or recipe != COMPILED_RECIPES[index]:
            _reject("release_descriptor_recipe_order_invalid")
        if (
            item["display_schema"] != DISPLAY_SCHEMAS[recipe]
            or type(item["max_artifact_bytes"]) is not int
            or item["max_artifact_bytes"] != MAX_ARTIFACT_BYTES
            or not isinstance(item["policy_document"], dict)
        ):
            _reject("release_descriptor_shape_invalid")
        canonical_policy = _canonical_json(item["policy_document"])
        parsed = parse_policy_v1(canonical_policy)
        if parsed.recipe != recipe:
            _reject("release_descriptor_policy_recipe_mismatch")
        commitment = policy_commitment_bytes32(canonical_policy)
        document_sha256 = "sha256:" + hashlib.sha256(canonical_policy).hexdigest()
        if (
            item["policy_commitment"] != commitment
            or item["policy_document_sha256"] != document_sha256
        ):
            _reject("release_descriptor_commitment_mismatch")
        descriptors.append(
            DiligencePolicyDescriptor(
                recipe=recipe,
                policy_commitment=commitment,
                display_schema=DISPLAY_SCHEMAS[recipe],
                max_artifact_bytes=MAX_ARTIFACT_BYTES,
                policy_document_sha256=document_sha256,
                canonical_policy_json=canonical_policy,
            )
        )

    commitments = tuple(descriptor.policy_commitment for descriptor in descriptors)
    if len(set(commitments)) != 3:
        _reject("release_policy_commitments_invalid")
    calculated_root = evaluator_policy_set_root(commitments)  # type: ignore[arg-type]
    if (
        payload["evaluator_policy_set_root"] != calculated_root
        or expected_policy_set_root != calculated_root
    ):
        _reject("release_policy_set_root_mismatch")
    return DiligenceEvaluatorRegistry(
        descriptors=(descriptors[0], descriptors[1], descriptors[2]),
        evaluator_policy_set_root=calculated_root,
        manifest_sha256=actual_manifest_sha256,
    )


def build_diligence_evaluator_release_manifest(
    policies: Mapping[str, bytes],
) -> dict[str, object]:
    """Build the canonical signed-release descriptor shape for tooling/tests."""

    descriptors: list[dict[str, object]] = []
    commitments: list[str] = []
    for recipe in COMPILED_RECIPES:
        canonical_policy = policies.get(recipe)
        if type(canonical_policy) is not bytes:
            _reject("release_policy_document_missing")
        parsed = parse_policy_v1(canonical_policy)
        if parsed.recipe != recipe:
            _reject("release_descriptor_policy_recipe_mismatch")
        commitment = policy_commitment_bytes32(canonical_policy)
        commitments.append(commitment)
        descriptors.append(
            {
                "recipe": recipe,
                "policy_commitment": commitment,
                "display_schema": DISPLAY_SCHEMAS[recipe],
                "max_artifact_bytes": MAX_ARTIFACT_BYTES,
                "policy_document_sha256": (
                    "sha256:" + hashlib.sha256(canonical_policy).hexdigest()
                ),
                "policy_document": json.loads(canonical_policy),
            }
        )
    return {
        "schema": RELEASE_MANIFEST_SCHEMA,
        "descriptor_schema": DESCRIPTOR_SCHEMA,
        "evaluator_policy_set_root": evaluator_policy_set_root(
            (commitments[0], commitments[1], commitments[2])
        ),
        "max_artifact_bytes": MAX_ARTIFACT_BYTES,
        "policies": descriptors,
    }


__all__ = [
    "DESCRIPTOR_SCHEMA",
    "DISPLAY_SCHEMAS",
    "DiligenceEvaluatorRegistry",
    "DiligenceEvaluatorRegistryError",
    "DiligencePolicyDescriptor",
    "EVALUATOR_POLICY_SET_TYPE",
    "EVALUATOR_POLICY_SET_TYPEHASH",
    "MAX_RELEASE_MANIFEST_BYTES",
    "RELEASE_MANIFEST_SCHEMA",
    "build_diligence_evaluator_release_manifest",
    "evaluator_policy_set_root",
    "load_diligence_evaluator_registry",
    "load_diligence_evaluator_registry_bytes",
    "policy_commitment_bytes32",
]
