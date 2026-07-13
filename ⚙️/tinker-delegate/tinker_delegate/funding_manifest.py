"""Bounded audit manifests for Tinker funding validation runs."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any

from tinker_delegate.redaction import redact_text


MANIFEST_VERSION = "tinker_funding_validation_manifest/v1"
FORBIDDEN_MANIFEST_KEYS = frozenset(
    {
        "api_key",
        "artifact",
        "artifact_hex",
        "card",
        "card_number",
        "cardholder_name",
        "cvc",
        "cvv",
        "number",
        "otp",
        "password",
        "private_key",
        "raw_card",
        "secret",
        "token",
    }
)


@dataclass(frozen=True)
class FundingValidationManifest:
    """Public bounded audit envelope for one operator funding validation."""

    validation_id_hash: str
    preflight_hash: str
    receipt_hash: str
    funding_mode: str
    preflight_ready: bool
    receipt_surface: str
    receipt_outcome: str
    receipt_amount_band: str
    receipt_balance_band: str
    receipt_tdx_quote_hash: str
    card_payload_destroyed: bool
    no_raw_secret_egress: bool
    no_raw_card_retained: bool
    attestation_policy_hash: str = ""
    issued_at: int = field(default_factory=lambda: int(time.time()))

    def to_public_dict(self) -> dict[str, Any]:
        body = {
            "version": MANIFEST_VERSION,
            "validation_id_hash": self.validation_id_hash,
            "preflight_hash": self.preflight_hash,
            "receipt_hash": self.receipt_hash,
            "funding_mode": self.funding_mode,
            "preflight_ready": self.preflight_ready,
            "receipt_surface": self.receipt_surface,
            "receipt_outcome": self.receipt_outcome,
            "receipt_amount_band": self.receipt_amount_band,
            "receipt_balance_band": self.receipt_balance_band,
            "receipt_tdx_quote_hash": self.receipt_tdx_quote_hash,
            "card_payload_destroyed": self.card_payload_destroyed,
            "no_raw_secret_egress": self.no_raw_secret_egress,
            "no_raw_card_retained": self.no_raw_card_retained,
            "attestation_policy_hash": self.attestation_policy_hash,
            "issued_at": self.issued_at,
        }
        body["manifest_hash"] = hash_bounded_object(body)
        return body


@dataclass(frozen=True)
class FundingManifestVerification:
    """Bounded verification result for a saved funding validation packet."""

    ok: bool
    checks: list[dict[str, Any]]
    manifest_hash: str = ""
    preflight_hash: str = ""
    receipt_hash: str = ""
    receipt_surface: str = ""
    receipt_outcome: str = ""
    preflight_ready: bool = False
    no_raw_card_retained: bool = False
    issued_at: int = field(default_factory=lambda: int(time.time()))

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "checks": self.checks,
            "manifest_hash": self.manifest_hash,
            "preflight_hash": self.preflight_hash,
            "receipt_hash": self.receipt_hash,
            "receipt_surface": self.receipt_surface,
            "receipt_outcome": self.receipt_outcome,
            "preflight_ready": self.preflight_ready,
            "no_raw_card_retained": self.no_raw_card_retained,
            "issued_at": self.issued_at,
        }


def build_funding_validation_manifest(
    *,
    preflight: dict[str, Any],
    receipt: dict[str, Any],
    validation_id: str = "",
    attestation_policy: dict[str, Any] | None = None,
) -> FundingValidationManifest:
    """Build a public validation manifest from already-bounded inputs."""
    assert_no_secret_material(preflight)
    assert_no_secret_material(receipt)
    attestation_policy = attestation_policy or {}
    assert_no_secret_material(attestation_policy)

    policy = preflight.get("policy") or {}
    no_raw_secret_egress = receipt.get("raw_secret_egress") is False
    card_payload_destroyed = bool(receipt.get("card_payload_destroyed"))
    return FundingValidationManifest(
        validation_id_hash=hash_bounded_object(validation_id or "unspecified"),
        preflight_hash=hash_bounded_object(preflight),
        receipt_hash=hash_bounded_object(receipt),
        funding_mode=str(policy.get("mode", "")),
        preflight_ready=bool(preflight.get("ready")),
        receipt_surface=str(receipt.get("surface", "")),
        receipt_outcome=str(receipt.get("outcome", "")),
        receipt_amount_band=str(receipt.get("amount_band", "")),
        receipt_balance_band=str(receipt.get("balance_band", "")),
        receipt_tdx_quote_hash=str(receipt.get("tdx_quote_hash", "")),
        card_payload_destroyed=card_payload_destroyed,
        no_raw_secret_egress=no_raw_secret_egress,
        no_raw_card_retained=bool(card_payload_destroyed and no_raw_secret_egress),
        attestation_policy_hash=hash_bounded_object(attestation_policy) if attestation_policy else "",
    )


def verify_funding_validation_manifest(
    *,
    preflight: dict[str, Any],
    receipt: dict[str, Any],
    manifest: dict[str, Any],
    validation_id: str = "",
    attestation_policy: dict[str, Any] | None = None,
    require_ready: bool = False,
    require_no_raw_card_retained: bool = True,
) -> FundingManifestVerification:
    """Verify a saved preflight/receipt/manifest packet without echoing inputs."""
    checks: list[dict[str, Any]] = []
    try:
        assert_no_secret_material(preflight)
        assert_no_secret_material(receipt)
        assert_no_secret_material(manifest)
        attestation_policy = attestation_policy or {}
        assert_no_secret_material(attestation_policy)
    except ValueError as exc:
        return FundingManifestVerification(
            ok=False,
            checks=[_check("secret_material", False, str(exc))],
        )

    expected_preflight_hash = hash_bounded_object(preflight)
    expected_receipt_hash = hash_bounded_object(receipt)
    expected_validation_id_hash = hash_bounded_object(validation_id or "unspecified")
    expected_policy_hash = hash_bounded_object(attestation_policy) if attestation_policy else ""
    observed_manifest_hash = _manifest_hash_from_public_dict(manifest)

    checks.append(_check("version", manifest.get("version") == MANIFEST_VERSION, str(manifest.get("version", ""))))
    checks.append(_check(
        "manifest_hash",
        manifest.get("manifest_hash") == observed_manifest_hash,
        "matches" if manifest.get("manifest_hash") == observed_manifest_hash else "mismatch",
    ))
    checks.append(_check(
        "preflight_hash",
        manifest.get("preflight_hash") == expected_preflight_hash,
        "matches" if manifest.get("preflight_hash") == expected_preflight_hash else "mismatch",
    ))
    checks.append(_check(
        "receipt_hash",
        manifest.get("receipt_hash") == expected_receipt_hash,
        "matches" if manifest.get("receipt_hash") == expected_receipt_hash else "mismatch",
    ))
    checks.append(_check(
        "validation_id_hash",
        manifest.get("validation_id_hash") == expected_validation_id_hash,
        "matches" if manifest.get("validation_id_hash") == expected_validation_id_hash else "mismatch",
    ))
    checks.append(_check(
        "attestation_policy_hash",
        manifest.get("attestation_policy_hash", "") == expected_policy_hash,
        "matches" if manifest.get("attestation_policy_hash", "") == expected_policy_hash else "mismatch",
    ))
    if require_ready:
        checks.append(_check(
            "preflight_ready",
            manifest.get("preflight_ready") is True,
            "ready" if manifest.get("preflight_ready") is True else "not_ready",
        ))
    if require_no_raw_card_retained:
        checks.append(_check(
            "no_raw_card_retained",
            manifest.get("no_raw_card_retained") is True,
            "true" if manifest.get("no_raw_card_retained") is True else "false",
        ))

    return FundingManifestVerification(
        ok=all(check["ok"] for check in checks),
        checks=checks,
        manifest_hash=str(manifest.get("manifest_hash", "")),
        preflight_hash=str(manifest.get("preflight_hash", "")),
        receipt_hash=str(manifest.get("receipt_hash", "")),
        receipt_surface=str(manifest.get("receipt_surface", "")),
        receipt_outcome=str(manifest.get("receipt_outcome", "")),
        preflight_ready=bool(manifest.get("preflight_ready")),
        no_raw_card_retained=bool(manifest.get("no_raw_card_retained")),
    )


def hash_bounded_object(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _manifest_hash_from_public_dict(manifest: dict[str, Any]) -> str:
    body = dict(manifest)
    body.pop("manifest_hash", None)
    return hash_bounded_object(body)


def _check(name: str, ok: bool, status: str) -> dict[str, Any]:
    return {"name": name, "ok": bool(ok), "status": status}


def assert_no_secret_material(value: Any) -> None:
    rendered = json.dumps(value, sort_keys=True, default=str)
    if redact_text(rendered) != rendered:
        raise ValueError("funding validation manifest input contains secret-like material")
    _assert_no_forbidden_keys(value)


def _assert_no_forbidden_keys(value: Any) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            normalized = str(key).lower()
            if normalized in FORBIDDEN_MANIFEST_KEYS:
                raise ValueError(f"funding validation manifest input contains forbidden key: {key}")
            _assert_no_forbidden_keys(nested)
    elif isinstance(value, list):
        for nested in value:
            _assert_no_forbidden_keys(nested)
