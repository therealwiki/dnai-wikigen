"""Exact JS final-binding to Python Royalty runtime-binding adapter.

The JavaScript artifact and the Python runtime commitment deliberately retain
different schemas and domains.  This module proves the single reviewed mapping
between them; it does not accept a caller-authored runtime override.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

from tinker_delegate.royalty_settlement_authorization import (
    RoyaltySettlementReleaseBinding,
)


ADAPTER_SCHEMA = "dnai.royalty-settlement-runtime-binding-adapter.v1"
ADAPTER_STATUS = "exact_js_final_binding_to_python_runtime_binding"
ADAPTER_TRUTH_STATUS = (
    "deterministic_cross_language_projection_not_runtime_startup_or_chain_evidence"
)
SOURCE_BINDING_SCHEMA = "dnai.royalty-settlement-release-binding.v1"
RECONCILIATION_SCHEMA = (
    "dnai.royalty-settlement-release-reconciliation-receipt.v1"
)
RECONCILIATION_STATUS = (
    "current_final_authority_v4_and_h_reconciled_to_prescription"
)
RECONCILIATION_TRUTH_STATUS = (
    "canonical_artifacts_reconciled_not_chain_access_or_transaction_finality_collection"
)
SOURCE_BINDING_DOMAIN = b"dnai-wikigen/royalty-settlement-release-binding/v1\0"
RUNTIME_BINDING_DOMAIN = (
    b"dnai-wikigen/collaboration-royalty-release-binding/v1\0"
)

_ADAPTER_FIELDS = {
    "schema",
    "status",
    "truth_status",
    "source_binding",
    "source_binding_sha256",
    "reconciliation_receipt",
    "runtime_binding",
    "runtime_binding_commitment",
}
_SOURCE_FIELDS = {
    "schema",
    "final_release_authority_v4_sha256",
    "release_sha",
    "deployment_intent_sha256",
    "royalty_release_active_state_sha256",
    "royalty_release_history_sha256",
    "royalty_release_history_receipt_sha256",
    "royalty_release_authority",
    "royalty_settlement_release_binding_template",
}
_RECONCILIATION_FIELDS = {
    "schema",
    "status",
    "truth_status",
    "release_sha",
    "deployment_intent_sha256",
    "royalty_release_prescriptive_authority_sha256",
    "final_release_authority_v4_sha256",
    "royalty_release_history_receipt_sha256",
    "royalty_release_history_sha256",
    "royalty_settlement_release_binding_sha256",
}
_RUNTIME_FIELDS = {
    field.name for field in RoyaltySettlementReleaseBinding.__dataclass_fields__.values()
}


class RoyaltyReleaseBindingAdapterError(ValueError):
    """The cross-language adapter receipt or projection is invalid."""


def _record(value: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise RoyaltyReleaseBindingAdapterError(
            f"{label} fields do not match the exact schema"
        )
    return value


def _canonical_compact(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except Exception:
        raise RoyaltyReleaseBindingAdapterError(
            "adapter value is not canonical JSON"
        ) from None


def _canonical_artifact(value: Any) -> bytes:
    try:
        return (
            json.dumps(
                value,
                sort_keys=True,
                indent=2,
                ensure_ascii=True,
                allow_nan=False,
            )
            + "\n"
        ).encode("ascii")
    except Exception:
        raise RoyaltyReleaseBindingAdapterError(
            "adapter artifact is not canonical JSON"
        ) from None


def _sha256(domain: bytes, payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(domain + payload).hexdigest()


def source_binding_sha256(value: Mapping[str, Any]) -> str:
    _record(value, _SOURCE_FIELDS, "JavaScript Royalty source binding")
    if value["schema"] != SOURCE_BINDING_SCHEMA:
        raise RoyaltyReleaseBindingAdapterError(
            "JavaScript Royalty source-binding schema is invalid"
        )
    return _sha256(SOURCE_BINDING_DOMAIN, _canonical_artifact(value))


def runtime_binding_commitment(value: Mapping[str, Any]) -> str:
    _record(value, _RUNTIME_FIELDS, "Python Royalty runtime binding")
    return _sha256(RUNTIME_BINDING_DOMAIN, _canonical_compact(value))


def royalty_release_binding_from_adapter_receipt(
    value: Mapping[str, Any],
) -> RoyaltySettlementReleaseBinding:
    """Validate one adapter receipt and return its immutable runtime binding."""

    receipt = _record(value, _ADAPTER_FIELDS, "Royalty binding adapter receipt")
    if (
        receipt["schema"] != ADAPTER_SCHEMA
        or receipt["status"] != ADAPTER_STATUS
        or receipt["truth_status"] != ADAPTER_TRUTH_STATUS
    ):
        raise RoyaltyReleaseBindingAdapterError(
            "Royalty binding adapter identity is invalid"
        )

    source = _record(
        receipt["source_binding"], _SOURCE_FIELDS, "JavaScript Royalty source binding"
    )
    reconciliation = _record(
        receipt["reconciliation_receipt"],
        _RECONCILIATION_FIELDS,
        "Royalty reconciliation receipt",
    )
    runtime = _record(
        receipt["runtime_binding"], _RUNTIME_FIELDS, "Python Royalty runtime binding"
    )
    source_digest = source_binding_sha256(source)
    if receipt["source_binding_sha256"] != source_digest:
        raise RoyaltyReleaseBindingAdapterError(
            "JavaScript Royalty source-binding digest is invalid"
        )
    if (
        reconciliation["schema"] != RECONCILIATION_SCHEMA
        or reconciliation["status"] != RECONCILIATION_STATUS
        or reconciliation["truth_status"] != RECONCILIATION_TRUTH_STATUS
        or reconciliation["release_sha"] != source["release_sha"]
        or reconciliation["deployment_intent_sha256"]
        != source["deployment_intent_sha256"]
        or reconciliation["final_release_authority_v4_sha256"]
        != source["final_release_authority_v4_sha256"]
        or reconciliation["royalty_release_history_sha256"]
        != source["royalty_release_history_sha256"]
        or reconciliation["royalty_release_history_receipt_sha256"]
        != source["royalty_release_history_receipt_sha256"]
        or reconciliation["royalty_settlement_release_binding_sha256"]
        != source_digest
    ):
        raise RoyaltyReleaseBindingAdapterError(
            "Royalty reconciliation receipt does not bind the JavaScript source"
        )

    authority = source["royalty_release_authority"]
    template = source["royalty_settlement_release_binding_template"]
    expected_projection = {
        "distributor_address": authority["distributor_address"],
        "distributor_runtime_code_hash": template["distributor_runtime_code_hash"],
        "owner_address": authority["owner"],
        "authority_nonce": authority["authority_nonce"],
        "settlement_verifier_address": authority["settlement_verifier"],
        "royalty_qvl_verifier_address": authority["qvl_verifier"],
        "execution_policy_anchor_address": authority["execution_policy_anchor"],
        "anchor_writer_release_commitment": authority[
            "anchor_writer_release_commitment"
        ],
        "release_policy_commitment": authority["release_policy_commitment"],
        "royalty_qvl_signer_key_id": template["royalty_qvl_signer_key_id"],
        "qvl_release_policy_hash": template["qvl_release_policy_hash"],
        "main_runtime_cvm_id": template["main_runtime_cvm_id"],
        "deployment_intent_sha256": source["deployment_intent_sha256"],
        "release_authority_sha256": source["final_release_authority_v4_sha256"],
        "ceremony_nonce": template["ceremony_nonce"],
        "measurement_policy_sha256": template["measurement_policy_sha256"],
        "compose_hash": template["compose_hash"],
        "app_id": template["app_id"],
        "os_image_hash": template["os_image_hash"],
        "chain_id": template["chain_id"],
        "max_authorization_lifetime_seconds": template[
            "max_authorization_lifetime_seconds"
        ],
    }
    for field, expected in expected_projection.items():
        if runtime[field] != expected:
            raise RoyaltyReleaseBindingAdapterError(
                f"Python Royalty runtime field {field} differs from JavaScript authority"
            )

    try:
        binding = RoyaltySettlementReleaseBinding(**runtime)
    except Exception as exc:
        raise RoyaltyReleaseBindingAdapterError(
            f"Python Royalty runtime binding is invalid: {exc}"
        ) from exc
    expected_commitment = runtime_binding_commitment(runtime)
    if receipt["runtime_binding_commitment"] != expected_commitment:
        raise RoyaltyReleaseBindingAdapterError(
            "Python Royalty runtime-binding commitment is invalid"
        )
    return binding
