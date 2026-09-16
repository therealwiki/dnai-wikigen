"""Client-side consistency checks for tinker-delegate attestation envelopes.

These checks do not implement Intel DCAP/QVL signature, collateral, TCB, or
measurement verification. They therefore cannot turn service-produced evidence
into a cryptographic TDX verdict. Production callers must use an independent
verifier before releasing secrets; the service-local ``verified`` field remains
false until that verifier is integrated as a separate trust domain.
"""

from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Any
from urllib.parse import urlencode, urljoin

import httpx

from tinker_delegate.card_channel import PUBLIC_ATTESTATION_FIELDS, attestation_report_data
from tinker_delegate.tdx_quote import TdxQuoteError, parse_tdx_quote


class AttestationVerificationError(RuntimeError):
    """Raised when attestation evidence does not satisfy local policy."""


@dataclass(frozen=True)
class AttestationPolicy:
    """Expected attestation identity for a client-side verification."""

    expected_compose_hash: str = ""
    expected_app_id: str = ""
    expected_os_image_hash: str = ""
    context: str = "artifact"
    allow_local: bool = False
    max_age_seconds: float = 60.0


@dataclass(frozen=True)
class AttestationVerificationResult:
    """Bounded envelope facts accepted by the consistency checker."""

    mode: str
    report_context: str
    encryption_public_key: str
    report_data: str
    quote_size: int
    compose_hash: str = ""
    app_id: str = ""
    os_image_hash: str = ""
    fetched_at: float = 0.0


def _endpoint(base_url: str, path: str) -> str:
    return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


def attestation_endpoint(base_url: str, context: str) -> str:
    """Build a context-specific attestation endpoint URL."""
    return _endpoint(base_url, "/attestation") + "?" + urlencode({"context": context})


def _hex_bytes(value: object, field: str, *, expected_len: int | None = None) -> bytes:
    if not isinstance(value, str) or not value:
        raise AttestationVerificationError(f"{field} is missing")
    raw = value[2:] if value.startswith(("0x", "0X")) else value
    try:
        decoded = bytes.fromhex(raw)
    except ValueError as exc:
        raise AttestationVerificationError(f"{field} must be hex") from exc
    if expected_len is not None and len(decoded) != expected_len:
        raise AttestationVerificationError(f"{field} must be {expected_len} bytes")
    if expected_len is None and not decoded:
        raise AttestationVerificationError(f"{field} must be non-empty")
    return decoded


def verify_attestation_envelope(
    attestation: dict[str, Any],
    policy: AttestationPolicy,
    *,
    fetched_at: float | None = None,
    now: float | None = None,
    enforce_quote_binding: bool = False,
) -> AttestationVerificationResult:
    """Check the bounded fields exposed by `/attestation` for consistency.

    This checks dstack mode, quote presence, claimed compose/app/image
    identity, operation context, public-key shape, report-data key binding,
    exposed quote report-data binding, and optional client fetch freshness.

    When `enforce_quote_binding` is true, the raw `quote` blob is additionally
    parsed structurally (Intel TDX DCAP v4) and the report_data embedded *in the
    quote bytes* must match the claimed `report_data` — closing the gap where a
    submitter could pair a real quote with an independently-claimed report_data.
    This is a fail-closed structural check only; the Intel signature/cert chain
    trust root must be supplied by a QVL / DCAP verifier. Default false preserves
    behaviour for simulator/opaque quotes that are not real TDX v4 quotes.
    """
    unexpected_fields = set(attestation).difference(PUBLIC_ATTESTATION_FIELDS)
    if unexpected_fields:
        rendered = ", ".join(sorted(str(field) for field in unexpected_fields))
        raise AttestationVerificationError(
            f"attestation contains forbidden or unexpected fields: {rendered}"
        )

    checked_at = time.time() if now is None else now
    evidence_time = checked_at if fetched_at is None else fetched_at
    if policy.max_age_seconds >= 0 and checked_at - evidence_time > policy.max_age_seconds:
        raise AttestationVerificationError("attestation evidence is stale")

    mode = attestation.get("mode")
    quote_size = 0
    quote_bytes = b""
    if mode == "local":
        if not policy.allow_local:
            raise AttestationVerificationError("local attestation is not allowed")
    elif mode == "tdx":
        if attestation.get("verified") is not True:
            raise AttestationVerificationError(
                "independent cryptographic attestation verdict is unavailable"
            )
        quote_bytes = _hex_bytes(attestation.get("quote"), "quote")
        quote_size = len(quote_bytes)
        if not policy.expected_compose_hash:
            raise AttestationVerificationError("expected compose hash is required for tdx mode")
        if attestation.get("compose_hash") != policy.expected_compose_hash:
            raise AttestationVerificationError("compose hash mismatch")
        if policy.expected_app_id and attestation.get("app_id") != policy.expected_app_id:
            raise AttestationVerificationError("app id mismatch")
        if (
            policy.expected_os_image_hash
            and attestation.get("os_image_hash") != policy.expected_os_image_hash
        ):
            raise AttestationVerificationError("OS image hash mismatch")
    else:
        raise AttestationVerificationError("attestation mode must be tdx")

    if attestation.get("report_context") != policy.context:
        raise AttestationVerificationError("report context mismatch")

    public_key = _hex_bytes(
        attestation.get("encryption_public_key"),
        "encryption_public_key",
        expected_len=32,
    )
    report_data = _hex_bytes(attestation.get("report_data"), "report_data", expected_len=32)
    expected_report_data = attestation_report_data(policy.context, public_key)
    if report_data != expected_report_data:
        raise AttestationVerificationError("report data does not bind the encryption key")

    quote_report_data_value = attestation.get("quote_report_data")
    if quote_report_data_value:
        quote_report_data = _hex_bytes(quote_report_data_value, "quote_report_data")
        if len(quote_report_data) == 64:
            if quote_report_data[:32] != report_data or quote_report_data[32:] != b"\x00" * 32:
                raise AttestationVerificationError("quote report data mismatch")
        elif len(quote_report_data) != 32:
            raise AttestationVerificationError("quote_report_data must be 32 or 64 bytes")
        elif quote_report_data != report_data:
            raise AttestationVerificationError("quote report data mismatch")

    if enforce_quote_binding and mode == "tdx":
        try:
            parsed = parse_tdx_quote(quote_bytes)
        except TdxQuoteError as exc:
            raise AttestationVerificationError(
                f"quote does not parse as a TDX v4 quote: {exc}"
            ) from exc
        # The TD report's 64-byte report_data is the 32-byte key binding followed
        # by 32 zero bytes (same convention checked for the claimed field above).
        if parsed.report_data[:32] != report_data or parsed.report_data[32:] != b"\x00" * 32:
            raise AttestationVerificationError(
                "report data embedded in the quote does not match the claimed report data"
            )

    return AttestationVerificationResult(
        mode=str(mode),
        report_context=policy.context,
        encryption_public_key=public_key.hex(),
        report_data=report_data.hex(),
        quote_size=quote_size,
        compose_hash=str(attestation.get("compose_hash") or ""),
        app_id=str(attestation.get("app_id") or ""),
        os_image_hash=str(attestation.get("os_image_hash") or ""),
        fetched_at=evidence_time,
    )


def fetch_and_verify_attestation(
    base_url: str,
    policy: AttestationPolicy,
    *,
    client: httpx.Client | None = None,
) -> AttestationVerificationResult:
    """Fetch `/attestation` and check its bounded public envelope only."""
    owns_client = client is None
    http = client or httpx.Client(timeout=30.0)
    fetched_at = time.time()
    try:
        response = http.get(attestation_endpoint(base_url, policy.context))
        response.raise_for_status()
        return verify_attestation_envelope(response.json(), policy, fetched_at=fetched_at)
    finally:
        if owns_client:
            http.close()
