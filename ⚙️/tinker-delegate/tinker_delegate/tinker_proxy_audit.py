"""External bounded verifier for Tinker proxy-token audit artifacts."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

from tinker_delegate.funding_manifest import hash_bounded_object
from tinker_delegate.redaction import redact_text
from tinker_delegate.tinker_proxy import SUPPORTED_PROXY_SCOPES
from tinker_delegate.tinker_proxy_store import (
    ProxyTokenStore,
    summarize_proxy_token_records,
)


PROXY_AUDIT_VERIFICATION_VERSION = "tinker_proxy_token_audit_verification/v1"

FORBIDDEN_PROXY_AUDIT_KEYS = frozenset(
    {
        "api_key",
        "authorization",
        "bearer",
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

OPERATION_SCOPE_BY_SURFACE = {
    "tinker_proxy": "proxy:status",
    "tinker_sdk_smoke": "tinker:smoke",
    "payment_method_status": "billing:payment-method-status",
    "add_balance": "billing:add-balance",
}


@dataclass(frozen=True)
class ProxyAuditVerification:
    ok: bool
    checks: list[dict[str, Any]]
    audit_hash: str = ""
    record_count: int = 0
    issued_count: int = 0
    revoked_count: int = 0
    active_count: int = 0
    operation_receipt_count: int = 0
    bound_operation_receipt_count: int = 0
    missing_operation_binding_count: int = 0
    issued_at: int = field(default_factory=lambda: int(time.time()))

    def to_public_dict(self) -> dict[str, Any]:
        body = {
            "surface": "tinker_proxy_audit_verification",
            "version": PROXY_AUDIT_VERIFICATION_VERSION,
            "ok": self.ok,
            "checks": self.checks,
            "audit_hash": self.audit_hash,
            "record_count": self.record_count,
            "issued_count": self.issued_count,
            "revoked_count": self.revoked_count,
            "active_count": self.active_count,
            "operation_receipt_count": self.operation_receipt_count,
            "bound_operation_receipt_count": self.bound_operation_receipt_count,
            "missing_operation_binding_count": self.missing_operation_binding_count,
            "issued_at": self.issued_at,
            "raw_secret_egress": False,
        }
        body["verification_hash"] = hash_bounded_object(body)
        return body


def verify_proxy_token_audit(
    *,
    audit: dict[str, Any],
    operation_receipts: list[dict[str, Any]] | None = None,
    require_operation_binding: bool = False,
) -> ProxyAuditVerification:
    """Verify a public proxy-token audit and bounded operation receipts.

    The verifier never needs plaintext JWTs, subjects, upstream Tinker keys, or
    project ids. Operation receipts can be cryptographically useful only when
    they carry a bounded ``proxy_auth_context`` with the JWT-id hash and scope
    used to authorize the operation.
    """

    operation_receipts = operation_receipts or []
    checks: list[dict[str, Any]] = []

    try:
        assert_no_proxy_audit_secret_material(audit)
        for receipt in operation_receipts:
            assert_no_proxy_audit_secret_material(receipt)
    except ValueError as exc:
        return ProxyAuditVerification(
            ok=False,
            checks=[_check("secret_material", False, str(exc))],
            audit_hash=hash_bounded_object(_safe_hashable(audit)),
            operation_receipt_count=len(operation_receipts),
        )

    records, record_error = _records_from_audit(audit)
    if record_error:
        checks.append(_check("audit_records_shape", False, record_error))
        records = []
    else:
        checks.append(_check("audit_records_shape", True, "valid"))

    checks.append(_check(
        "audit_raw_secret_egress",
        audit.get("raw_secret_egress") is False,
        "false" if audit.get("raw_secret_egress") is False else "not_false",
    ))

    summary = summarize_proxy_token_records(records)
    checks.extend(_verify_summary_counts(audit, summary))
    checks.extend(_verify_record_chronology(records))

    operation_checks, bound_count, missing_count = _verify_operation_receipts(
        records,
        operation_receipts,
        require_operation_binding=require_operation_binding,
    )
    checks.extend(operation_checks)

    return ProxyAuditVerification(
        ok=all(check["ok"] for check in checks),
        checks=checks,
        audit_hash=hash_bounded_object(audit),
        record_count=summary["record_count"],
        issued_count=summary["issued_count"],
        revoked_count=summary["revoked_count"],
        active_count=summary["active_unexpired_or_unknown_count"],
        operation_receipt_count=len(operation_receipts),
        bound_operation_receipt_count=bound_count,
        missing_operation_binding_count=missing_count,
    )


def assert_no_proxy_audit_secret_material(value: Any) -> None:
    rendered = json.dumps(value, sort_keys=True, default=str)
    if redact_text(rendered) != rendered:
        raise ValueError("proxy audit verifier input contains secret-like material")
    _assert_no_forbidden_keys(value)


def _records_from_audit(audit: dict[str, Any]) -> tuple[list[dict[str, Any]], str]:
    records_value = audit.get("records")
    if records_value is None and isinstance(audit.get("proxy_tokens"), list):
        records_value = audit["proxy_tokens"]
    if not isinstance(records_value, list):
        return [], "audit must contain records list"
    records: list[dict[str, Any]] = []
    try:
        for record in records_value:
            if not isinstance(record, dict):
                return [], "audit records must be objects"
            records.append(ProxyTokenStore._sanitize_record(record))
    except ValueError as exc:
        return [], str(exc)
    return records, ""


def _verify_summary_counts(audit: dict[str, Any], summary: dict[str, Any]) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    for field in ("record_count", "issued_count", "revoked_count"):
        if field in audit:
            checks.append(_check(
                f"summary_{field}",
                audit.get(field) == summary[field],
                "matches" if audit.get(field) == summary[field] else "mismatch",
            ))
    if "active_unexpired_or_unknown_count" in audit:
        field = "active_unexpired_or_unknown_count"
        checks.append(_check(
            "summary_active_count",
            audit.get(field) == summary[field],
            "matches" if audit.get(field) == summary[field] else "mismatch",
        ))
    return checks


def _verify_record_chronology(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    issued_by_hash: dict[str, dict[str, Any]] = {}
    duplicate_issues: set[str] = set()
    invalid_scope_records = 0
    invalid_time_records = 0
    dangling_revocations = 0
    backwards_revocations = 0

    for record in records:
        jwt_id_hash = str(record["jwt_id_hash"])
        if record["event"] == "issued":
            if jwt_id_hash in issued_by_hash:
                duplicate_issues.add(jwt_id_hash)
            issued_by_hash[jwt_id_hash] = record
            scopes = set(record.get("scopes", []))
            if not scopes or not scopes.issubset(SUPPORTED_PROXY_SCOPES):
                invalid_scope_records += 1
            if int(record["issued_at"]) >= int(record["expires_at"]):
                invalid_time_records += 1
        elif record["event"] == "revoked":
            issue = issued_by_hash.get(jwt_id_hash)
            if issue is None:
                dangling_revocations += 1
            elif int(record["revoked_at"]) < int(issue["issued_at"]):
                backwards_revocations += 1

    checks.append(_check(
        "unique_issued_tokens",
        not duplicate_issues,
        "unique" if not duplicate_issues else "duplicates",
    ))
    checks.append(_check(
        "issued_scopes_supported",
        invalid_scope_records == 0,
        "supported" if invalid_scope_records == 0 else "unsupported_scope",
    ))
    checks.append(_check(
        "issued_expiry_after_issue",
        invalid_time_records == 0,
        "valid" if invalid_time_records == 0 else "invalid_time_window",
    ))
    checks.append(_check(
        "revocations_reference_issued_tokens",
        dangling_revocations == 0,
        "all_referenced" if dangling_revocations == 0 else "dangling_revocation",
    ))
    checks.append(_check(
        "revocations_after_issue",
        backwards_revocations == 0,
        "chronological" if backwards_revocations == 0 else "revoked_before_issue",
    ))
    return checks


def _verify_operation_receipts(
    records: list[dict[str, Any]],
    receipts: list[dict[str, Any]],
    *,
    require_operation_binding: bool,
) -> tuple[list[dict[str, Any]], int, int]:
    checks: list[dict[str, Any]] = []
    bound_count = 0
    missing_count = 0
    issued_by_hash = {
        str(record["jwt_id_hash"]): record
        for record in records
        if record.get("event") == "issued"
    }
    revocations_by_hash: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        if record.get("event") == "revoked":
            revocations_by_hash.setdefault(str(record["jwt_id_hash"]), []).append(record)

    for index, receipt in enumerate(receipts):
        prefix = f"operation_receipt_{index}"
        surface = _receipt_surface(receipt)
        context = _proxy_auth_context(receipt)
        operation_time = _receipt_issued_at(receipt)
        raw_secret_ok = _receipt_raw_secret_egress_false(receipt)
        supported_surface = surface in OPERATION_SCOPE_BY_SURFACE

        checks.append(_check(
            f"{prefix}_raw_secret_egress",
            raw_secret_ok,
            "false" if raw_secret_ok else "not_false",
        ))
        checks.append(_check(
            f"{prefix}_surface_supported",
            supported_surface,
            surface if supported_surface else "unsupported",
        ))
        if context is None:
            missing_count += 1
            checks.append(_check(
                f"{prefix}_proxy_auth_context",
                not require_operation_binding,
                "missing" if require_operation_binding else "missing_allowed",
            ))
            continue

        bound_count += 1
        jwt_id_hash = str(context.get("jwt_id_hash", ""))
        required_scope = str(context.get("required_scope", "")) or OPERATION_SCOPE_BY_SURFACE.get(surface, "")
        issue = issued_by_hash.get(jwt_id_hash)
        scopes = set(context.get("scopes") or [])
        issue_scopes = set(issue.get("scopes", [])) if issue else set()

        checks.append(_check(
            f"{prefix}_proxy_context_raw_secret_egress",
            context.get("raw_secret_egress") is False,
            "false" if context.get("raw_secret_egress") is False else "not_false",
        ))
        checks.append(_check(
            f"{prefix}_token_was_issued",
            issue is not None,
            "issued" if issue else "not_found",
        ))
        checks.append(_check(
            f"{prefix}_required_scope_present",
            bool(required_scope and required_scope in scopes and required_scope in issue_scopes),
            required_scope if required_scope in scopes and required_scope in issue_scopes else "missing_scope",
        ))
        checks.append(_check(
            f"{prefix}_subject_hash_matches_issue",
            bool(issue and context.get("subject_hash") == issue.get("subject_hash")),
            "matches" if issue and context.get("subject_hash") == issue.get("subject_hash") else "mismatch",
        ))
        checks.append(_check(
            f"{prefix}_timestamp_present",
            operation_time > 0,
            "present" if operation_time > 0 else "missing",
        ))
        if issue is None or operation_time <= 0:
            continue

        revoked_before_receipt = any(
            int(revocation["revoked_at"]) <= operation_time
            for revocation in revocations_by_hash.get(jwt_id_hash, [])
        )
        issue_expiry = int(issue["expires_at"])
        context_expiry = int(context.get("expires_at", 0))
        checks.append(_check(
            f"{prefix}_after_issue",
            operation_time >= int(issue["issued_at"]),
            "after_issue" if operation_time >= int(issue["issued_at"]) else "before_issue",
        ))
        checks.append(_check(
            f"{prefix}_before_expiry",
            operation_time < issue_expiry and operation_time < context_expiry,
            "before_expiry" if operation_time < issue_expiry and operation_time < context_expiry else "expired",
        ))
        checks.append(_check(
            f"{prefix}_before_revocation",
            not revoked_before_receipt,
            "not_revoked_at_operation_time" if not revoked_before_receipt else "revoked_before_operation",
        ))

    return checks, bound_count, missing_count


def _receipt_surface(receipt: dict[str, Any]) -> str:
    if "surface" in receipt:
        return str(receipt.get("surface", ""))
    attempt_record = receipt.get("attempt_record")
    if isinstance(attempt_record, dict):
        return str(attempt_record.get("surface", ""))
    return ""


def _receipt_issued_at(receipt: dict[str, Any]) -> int:
    value = receipt.get("issued_at")
    if value is None and isinstance(receipt.get("attempt_record"), dict):
        value = receipt["attempt_record"].get("issued_at")
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _receipt_raw_secret_egress_false(receipt: dict[str, Any]) -> bool:
    if receipt.get("raw_secret_egress") is False:
        return True
    attempt_record = receipt.get("attempt_record")
    return isinstance(attempt_record, dict) and attempt_record.get("raw_secret_egress") is False


def _proxy_auth_context(receipt: dict[str, Any]) -> dict[str, Any] | None:
    context = receipt.get("proxy_auth_context")
    if isinstance(context, dict):
        return context
    attempt_record = receipt.get("attempt_record")
    if isinstance(attempt_record, dict) and isinstance(attempt_record.get("proxy_auth_context"), dict):
        return attempt_record["proxy_auth_context"]
    return None


def _assert_no_forbidden_keys(value: Any) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            normalized = str(key).lower()
            if normalized in FORBIDDEN_PROXY_AUDIT_KEYS:
                raise ValueError(f"proxy audit verifier input contains forbidden key: {key}")
            _assert_no_forbidden_keys(nested)
    elif isinstance(value, list):
        for nested in value:
            _assert_no_forbidden_keys(nested)


def _safe_hashable(value: Any) -> Any:
    try:
        json.dumps(value, sort_keys=True, default=str)
        return value
    except Exception:
        return "unhashable_proxy_audit_input"


def _check(name: str, ok: bool, status: str) -> dict[str, Any]:
    return {"name": name, "ok": bool(ok), "status": status}
