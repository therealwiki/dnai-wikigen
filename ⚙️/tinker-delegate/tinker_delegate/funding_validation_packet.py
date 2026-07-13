"""One-command bounded packet generation for funding validation attempts."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urljoin

import httpx
from tinker_delegate.billing_uploader import (
    BillingCardUploadPolicy,
    BillingCardUploadResult,
    upload_billing_card_payload,
)
from tinker_delegate.funding_manifest import (
    assert_no_secret_material,
    build_funding_validation_manifest,
    hash_bounded_object,
    verify_funding_validation_manifest,
)
from tinker_delegate.funding_policy import funding_validation_preflight
from tinker_delegate.redaction import redact_text


PacketUploadFn = Callable[[str, dict[str, Any], BillingCardUploadPolicy], BillingCardUploadResult]
AddBalanceFn = Callable[[str, float, str], dict[str, Any]]
ReauthFn = Callable[[str, str], dict[str, Any]]


@dataclass(frozen=True)
class FundingValidationPacketResult:
    """Bounded summary for a generated funding-validation packet."""

    ok: bool
    output_dir: str
    preflight_path: str
    receipt_path: str = ""
    manifest_path: str = ""
    verification_path: str = ""
    add_balance_receipt_path: str = ""
    reauth_receipt_path: str = ""
    add_balance_manifest_path: str = ""
    add_balance_verification_path: str = ""
    preflight_ready: bool = False
    card_attempt_run: bool = False
    reauth_attempt_run: bool = False
    add_balance_attempt_run: bool = False
    receipt_surface: str = ""
    reauth_receipt_outcome: str = ""
    receipt_outcome: str = ""
    add_balance_receipt_outcome: str = ""
    manifest_hash: str = ""
    add_balance_manifest_hash: str = ""
    verification_ok: bool = False
    add_balance_verification_ok: bool = False
    error_kind: str = ""
    error: str = ""
    issued_at: int = 0

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "output_dir": self.output_dir,
            "preflight_path": self.preflight_path,
            "receipt_path": self.receipt_path,
            "manifest_path": self.manifest_path,
            "verification_path": self.verification_path,
            "add_balance_receipt_path": self.add_balance_receipt_path,
            "reauth_receipt_path": self.reauth_receipt_path,
            "add_balance_manifest_path": self.add_balance_manifest_path,
            "add_balance_verification_path": self.add_balance_verification_path,
            "preflight_ready": self.preflight_ready,
            "card_attempt_run": self.card_attempt_run,
            "reauth_attempt_run": self.reauth_attempt_run,
            "add_balance_attempt_run": self.add_balance_attempt_run,
            "receipt_surface": self.receipt_surface,
            "reauth_receipt_outcome": self.reauth_receipt_outcome,
            "receipt_outcome": self.receipt_outcome,
            "add_balance_receipt_outcome": self.add_balance_receipt_outcome,
            "manifest_hash": self.manifest_hash,
            "add_balance_manifest_hash": self.add_balance_manifest_hash,
            "verification_ok": self.verification_ok,
            "add_balance_verification_ok": self.add_balance_verification_ok,
            "error_kind": self.error_kind,
            "error": self.error,
            "issued_at": self.issued_at,
        }


@dataclass(frozen=True)
class FundingValidationPacketCheck:
    """Bounded checker result for a generated packet directory."""

    ok: bool
    packet_dir: str
    checks: list[dict[str, Any]]
    payment_manifest_hash: str = ""
    add_balance_manifest_hash: str = ""
    summary_ok: bool = False
    deployed_evidence: bool = False
    issued_at: int = 0

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "packet_dir": self.packet_dir,
            "checks": self.checks,
            "payment_manifest_hash": self.payment_manifest_hash,
            "add_balance_manifest_hash": self.add_balance_manifest_hash,
            "summary_ok": self.summary_ok,
            "deployed_evidence": self.deployed_evidence,
            "issued_at": self.issued_at,
        }


def run_funding_validation_packet(
    settings: Any,
    *,
    output_dir: Path,
    api_url: str,
    amount_dollars: float | None = None,
    expected_compose_hash: str = "",
    expected_app_id: str = "",
    expected_os_image_hash: str = "",
    allow_local_attestation: bool = False,
    auth_token: str = "",
    fetch_attestation: bool = False,
    require_add_balance_endpoint: bool = False,
    validation_id: str = "",
    receipt_json: Path | None = None,
    add_balance_receipt_json: Path | None = None,
    run_card_attempt: bool = False,
    run_reauth_attempt: bool = False,
    run_add_balance_attempt: bool = False,
    card_data: dict[str, Any] | None = None,
    upload_fn: PacketUploadFn = upload_billing_card_payload,
    reauth_fn: ReauthFn | None = None,
    add_balance_fn: AddBalanceFn | None = None,
) -> FundingValidationPacketResult:
    """Create a bounded validation packet from preflight through verification."""
    output_dir.mkdir(parents=True, exist_ok=True)
    issued_at = int(time.time())
    preflight_path = output_dir / "preflight.json"
    receipt_path = output_dir / "payment-method-receipt.json"
    reauth_receipt_path = output_dir / "reauth-receipt.json"
    manifest_path = output_dir / "funding-manifest.json"
    verification_path = output_dir / "funding-verification.json"
    add_balance_receipt_path = output_dir / "add-balance-receipt.json"
    add_balance_manifest_path = output_dir / "add-balance-manifest.json"
    add_balance_verification_path = output_dir / "add-balance-verification.json"
    summary_path = output_dir / "funding-validation-summary.json"
    policy = {
        "compose_hash": expected_compose_hash,
        "app_id": expected_app_id,
        "os_image_hash": expected_os_image_hash,
    }
    preflight_ready = False

    try:
        preflight = funding_validation_preflight(
            settings,
            amount_dollars=amount_dollars,
            require_add_balance_endpoint=bool(require_add_balance_endpoint or run_add_balance_attempt),
            api_url=api_url,
            expected_compose_hash=expected_compose_hash,
            expected_app_id=expected_app_id,
            expected_os_image_hash=expected_os_image_hash,
            allow_local_attestation=allow_local_attestation,
            fetch_attestation=fetch_attestation,
        ).to_public_dict()
        preflight_ready = bool(preflight["ready"])
        _write_bounded_json(preflight_path, preflight)

        if not preflight_ready:
            return _write_summary(
                summary_path,
                FundingValidationPacketResult(
                    ok=False,
                    output_dir=str(output_dir),
                    preflight_path=str(preflight_path),
                    preflight_ready=False,
                    reauth_attempt_run=run_reauth_attempt,
                    error_kind="preflight_not_ready",
                    error="funding preflight did not pass; funding attempts skipped",
                    issued_at=issued_at,
                ),
            )

        reauth_receipt: dict[str, Any] | None = None
        if run_reauth_attempt:
            reauth_receipt = _run_reauth_receipt(
                receipt_path=reauth_receipt_path,
                api_url=api_url,
                auth_token=auth_token,
                reauth_fn=reauth_fn or _post_reauth,
            )

        receipt: dict[str, Any] | None = None
        manifest: dict[str, Any] | None = None
        verification: dict[str, Any] | None = None
        card_receipt_requested = bool(receipt_json is not None or run_card_attempt)
        add_balance_receipt_requested = bool(add_balance_receipt_json is not None or run_add_balance_attempt)
        if not card_receipt_requested and not add_balance_receipt_requested:
            raise ValueError("funding-validation-packet requires payment-method or add-balance evidence")

        if card_receipt_requested:
            receipt = _load_or_create_receipt(
                receipt_path=receipt_path,
                receipt_json=receipt_json,
                run_card_attempt=run_card_attempt,
                card_data=card_data,
                api_url=api_url,
                policy=BillingCardUploadPolicy(
                    expected_compose_hash=expected_compose_hash,
                    expected_app_id=expected_app_id,
                    expected_os_image_hash=expected_os_image_hash,
                    allow_local=allow_local_attestation,
                    auth_token=auth_token,
                ),
                upload_fn=upload_fn,
            )

            manifest = build_funding_validation_manifest(
                preflight=preflight,
                receipt=receipt,
                validation_id=validation_id,
                attestation_policy=policy,
            ).to_public_dict()
            _write_bounded_json(manifest_path, manifest)

            verification = verify_funding_validation_manifest(
                preflight=preflight,
                receipt=receipt,
                manifest=manifest,
                validation_id=validation_id,
                attestation_policy=policy,
                require_ready=True,
            ).to_public_dict()
            _write_bounded_json(verification_path, verification)

        add_balance_receipt: dict[str, Any] | None = None
        add_balance_manifest: dict[str, Any] | None = None
        add_balance_verification: dict[str, Any] | None = None
        if add_balance_receipt_requested:
            add_balance_receipt = _load_or_create_add_balance_receipt(
                receipt_path=add_balance_receipt_path,
                receipt_json=add_balance_receipt_json,
                run_add_balance_attempt=run_add_balance_attempt,
                amount_dollars=amount_dollars,
                api_url=api_url,
                auth_token=auth_token,
                add_balance_fn=add_balance_fn or _post_add_balance,
            )
            add_balance_manifest = build_funding_validation_manifest(
                preflight=preflight,
                receipt=add_balance_receipt,
                validation_id=f"{validation_id}:add_balance" if validation_id else "add_balance",
                attestation_policy=policy,
            ).to_public_dict()
            _write_bounded_json(add_balance_manifest_path, add_balance_manifest)
            add_balance_verification = verify_funding_validation_manifest(
                preflight=preflight,
                receipt=add_balance_receipt,
                manifest=add_balance_manifest,
                validation_id=f"{validation_id}:add_balance" if validation_id else "add_balance",
                attestation_policy=policy,
                require_ready=True,
                require_no_raw_card_retained=False,
            ).to_public_dict()
            _write_bounded_json(add_balance_verification_path, add_balance_verification)

        return _write_summary(
            summary_path,
            FundingValidationPacketResult(
                ok=(verification is None or bool(verification["ok"])) and (
                    add_balance_verification is None or bool(add_balance_verification["ok"])
                ),
                output_dir=str(output_dir),
                preflight_path=str(preflight_path),
                receipt_path=str(receipt_path) if receipt else "",
                manifest_path=str(manifest_path) if manifest else "",
                verification_path=str(verification_path) if verification else "",
                add_balance_receipt_path=str(add_balance_receipt_path) if add_balance_receipt else "",
                add_balance_manifest_path=str(add_balance_manifest_path) if add_balance_manifest else "",
                add_balance_verification_path=(
                    str(add_balance_verification_path) if add_balance_verification else ""
                ),
                preflight_ready=True,
                card_attempt_run=run_card_attempt,
                reauth_attempt_run=run_reauth_attempt,
                add_balance_attempt_run=run_add_balance_attempt,
                reauth_receipt_path=str(reauth_receipt_path) if reauth_receipt else "",
                receipt_surface=str(receipt.get("surface", "")) if receipt else "",
                reauth_receipt_outcome=(
                    str(reauth_receipt.get("outcome", "")) if reauth_receipt else ""
                ),
                receipt_outcome=str(receipt.get("outcome", "")) if receipt else "",
                add_balance_receipt_outcome=(
                    str(add_balance_receipt.get("outcome", "")) if add_balance_receipt else ""
                ),
                manifest_hash=str(manifest.get("manifest_hash", "")) if manifest else "",
                add_balance_manifest_hash=(
                    str(add_balance_manifest.get("manifest_hash", "")) if add_balance_manifest else ""
                ),
                verification_ok=bool(verification["ok"]) if verification else False,
                add_balance_verification_ok=(
                    bool(add_balance_verification["ok"]) if add_balance_verification else False
                ),
                issued_at=issued_at,
            ),
        )
    except Exception as exc:
        return _write_summary(
            summary_path,
            FundingValidationPacketResult(
                ok=False,
                output_dir=str(output_dir),
                preflight_path=str(preflight_path),
                preflight_ready=preflight_ready,
                card_attempt_run=run_card_attempt,
                reauth_attempt_run=run_reauth_attempt,
                add_balance_attempt_run=run_add_balance_attempt,
                error_kind=type(exc).__name__,
                error=redact_text(exc),
                issued_at=issued_at,
            ),
        )
    finally:
        if card_data:
            for key in list(card_data):
                card_data[key] = ""


def _load_or_create_receipt(
    *,
    receipt_path: Path,
    receipt_json: Path | None,
    run_card_attempt: bool,
    card_data: dict[str, Any] | None,
    api_url: str,
    policy: BillingCardUploadPolicy,
    upload_fn: PacketUploadFn,
) -> dict[str, Any]:
    if receipt_json is not None and run_card_attempt:
        raise ValueError("provide either receipt_json or run_card_attempt, not both")
    if receipt_json is not None:
        receipt = json.loads(receipt_json.read_text(encoding="utf-8"))
        _write_bounded_json(receipt_path, receipt)
        return receipt
    if not run_card_attempt:
        raise ValueError("no receipt_json provided and run_card_attempt is false")
    if card_data is None:
        raise ValueError("run_card_attempt requires card_data")

    forbidden_values = tuple(str(value) for value in card_data.values() if value)
    result = upload_fn(api_url, card_data, policy)
    response = result.response
    _assert_no_secret_output(response, forbidden_values=forbidden_values)
    receipt = response.get("attempt_record")
    if not isinstance(receipt, dict):
        raise ValueError("encrypted card attempt response did not include bounded attempt_record")
    _write_bounded_json(receipt_path, receipt, forbidden_values=forbidden_values)
    return receipt


def _run_reauth_receipt(
    *,
    receipt_path: Path,
    api_url: str,
    auth_token: str,
    reauth_fn: ReauthFn,
) -> dict[str, Any]:
    response = reauth_fn(api_url, auth_token)
    _assert_no_secret_output(response)
    receipt = response.get("attempt_record")
    if not isinstance(receipt, dict):
        raise ValueError("reauth response did not include bounded attempt_record")
    _write_bounded_json(receipt_path, receipt)
    return receipt


def _load_or_create_add_balance_receipt(
    *,
    receipt_path: Path,
    receipt_json: Path | None,
    run_add_balance_attempt: bool,
    amount_dollars: float | None,
    api_url: str,
    auth_token: str,
    add_balance_fn: AddBalanceFn,
) -> dict[str, Any]:
    if receipt_json is not None and run_add_balance_attempt:
        raise ValueError("provide either add_balance_receipt_json or run_add_balance_attempt, not both")
    if receipt_json is not None:
        receipt = json.loads(receipt_json.read_text(encoding="utf-8"))
        _write_bounded_json(receipt_path, receipt)
        return receipt
    if not run_add_balance_attempt:
        raise ValueError("no add_balance_receipt_json provided and run_add_balance_attempt is false")
    if amount_dollars is None:
        raise ValueError("run_add_balance_attempt requires amount_dollars")

    response = add_balance_fn(api_url, float(amount_dollars), auth_token)
    _assert_no_secret_output(response)
    receipt = response.get("attempt_record")
    if not isinstance(receipt, dict):
        raise ValueError("add-balance response did not include bounded attempt_record")
    _write_bounded_json(receipt_path, receipt)
    return receipt


def _post_add_balance(api_url: str, amount_dollars: float, auth_token: str = "") -> dict[str, Any]:
    endpoint = urljoin(api_url.rstrip("/") + "/", "/billing/add-balance".lstrip("/"))
    headers = {"Authorization": f"Bearer {auth_token}"} if auth_token else None
    with httpx.Client(timeout=30.0) as client:
        response = client.post(endpoint, json={"amount_dollars": amount_dollars}, headers=headers)
        response.raise_for_status()
        return response.json()


def _post_reauth(api_url: str, auth_token: str = "") -> dict[str, Any]:
    endpoint = urljoin(api_url.rstrip("/") + "/", "/auth/reauth".lstrip("/"))
    headers = {"Authorization": f"Bearer {auth_token}"} if auth_token else None
    with httpx.Client(timeout=180.0) as client:
        response = client.post(endpoint, headers=headers)
        response.raise_for_status()
        return response.json()


def _write_summary(path: Path, result: FundingValidationPacketResult) -> FundingValidationPacketResult:
    _write_bounded_json(path, result.to_public_dict())
    return result


def _write_bounded_json(
    path: Path,
    payload: dict[str, Any],
    *,
    forbidden_values: tuple[str, ...] = (),
) -> None:
    _assert_no_secret_output(payload, forbidden_values=forbidden_values)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")


def _assert_no_secret_output(payload: Any, *, forbidden_values: tuple[str, ...] = ()) -> None:
    assert_no_secret_material(payload)
    rendered = json.dumps(payload, sort_keys=True, default=str)
    if redact_text(rendered) != rendered:
        raise ValueError("funding validation packet output contains secret-like material")
    for value in forbidden_values:
        if value and len(value) >= 4 and value in rendered:
            raise ValueError("funding validation packet output contains submitted secret material")


def packet_id_for_summary(summary: dict[str, Any]) -> str:
    """Stable helper for external packet catalogs."""
    return hash_bounded_object(summary)


def check_funding_validation_packet(
    *,
    packet_dir: Path,
    validation_id: str = "",
    expected_compose_hash: str = "",
    expected_app_id: str = "",
    expected_os_image_hash: str = "",
    require_add_balance: bool = False,
    require_deployed_attestation: bool = False,
) -> FundingValidationPacketCheck:
    """Replay-check a packet directory without echoing packet bodies."""
    issued_at = int(time.time())
    checks: list[dict[str, Any]] = []
    policy = {
        "compose_hash": expected_compose_hash,
        "app_id": expected_app_id,
        "os_image_hash": expected_os_image_hash,
    }
    paths = {
        "preflight": packet_dir / "preflight.json",
        "receipt": packet_dir / "payment-method-receipt.json",
        "manifest": packet_dir / "funding-manifest.json",
        "verification": packet_dir / "funding-verification.json",
        "summary": packet_dir / "funding-validation-summary.json",
        "add_balance_receipt": packet_dir / "add-balance-receipt.json",
        "add_balance_manifest": packet_dir / "add-balance-manifest.json",
        "add_balance_verification": packet_dir / "add-balance-verification.json",
    }

    required_names = ("preflight", "summary")
    missing_required = [name for name in required_names if not paths[name].exists()]
    checks.append(_packet_check(
        "required_files",
        not missing_required,
        "present" if not missing_required else "missing",
    ))
    if missing_required:
        return FundingValidationPacketCheck(
            ok=False,
            packet_dir=str(packet_dir),
            checks=checks,
            issued_at=issued_at,
        )

    try:
        preflight = _load_packet_json(paths["preflight"])
        summary = _load_packet_json(paths["summary"])
    except ValueError as exc:
        checks.append(_packet_check("bounded_json", False, str(exc)))
        return FundingValidationPacketCheck(
            ok=False,
            packet_dir=str(packet_dir),
            checks=checks,
            issued_at=issued_at,
        )

    payment_names = ("receipt", "manifest", "verification")
    add_balance_names = ("add_balance_receipt", "add_balance_manifest", "add_balance_verification")
    payment_file_count = sum(1 for name in payment_names if paths[name].exists())
    add_balance_file_count = sum(1 for name in add_balance_names if paths[name].exists())
    payment_present = payment_file_count == len(payment_names)
    add_balance_present = add_balance_file_count == len(add_balance_names)
    payment_partial = 0 < payment_file_count < len(payment_names)
    add_balance_partial = 0 < add_balance_file_count < len(add_balance_names)
    if payment_partial:
        checks.append(_packet_check("payment_files", False, "partial"))
    if add_balance_partial:
        checks.append(_packet_check("add_balance_files", False, "partial"))
    checks.append(_packet_check(
        "evidence_files",
        (payment_present or add_balance_present) and not payment_partial and not add_balance_partial,
        "present" if payment_present or add_balance_present else "missing",
    ))
    if payment_partial or add_balance_partial or (not payment_present and not add_balance_present):
        return FundingValidationPacketCheck(
            ok=False,
            packet_dir=str(packet_dir),
            checks=checks,
            summary_ok=bool(summary.get("ok")),
            issued_at=issued_at,
        )

    manifest: dict[str, Any] | None = None
    payment_manifest_hash = ""
    if payment_present:
        try:
            receipt = _load_packet_json(paths["receipt"])
            manifest = _load_packet_json(paths["manifest"])
            verification_file = _load_packet_json(paths["verification"])
        except ValueError as exc:
            checks.append(_packet_check("payment_bounded_json", False, str(exc)))
        else:
            payment_verification = verify_funding_validation_manifest(
                preflight=preflight,
                receipt=receipt,
                manifest=manifest,
                validation_id=validation_id,
                attestation_policy=policy,
                require_ready=True,
            ).to_public_dict()
            payment_manifest_hash = str(manifest.get("manifest_hash", ""))
            checks.append(_packet_check(
                "payment_manifest_replay",
                bool(payment_verification["ok"]),
                "ok" if payment_verification["ok"] else "failed",
            ))
            checks.append(_packet_check(
                "payment_verification_file",
                verification_file.get("ok") is True
                and verification_file.get("manifest_hash") == payment_verification.get("manifest_hash"),
                "matches"
                if verification_file.get("manifest_hash") == payment_verification.get("manifest_hash")
                else "mismatch",
            ))
            checks.append(_packet_check(
                "summary_payment_hash",
                summary.get("manifest_hash") == manifest.get("manifest_hash"),
                "matches" if summary.get("manifest_hash") == manifest.get("manifest_hash") else "mismatch",
            ))
    else:
        checks.append(_packet_check(
            "payment_files",
            True,
            "not_required_for_add_balance_only",
        ))

    deployed_evidence = _has_deployed_attestation(preflight)
    checks.append(_packet_check(
        "deployed_attestation",
        deployed_evidence if require_deployed_attestation else True,
        "tdx_verified" if deployed_evidence else "not_required" if not require_deployed_attestation else "missing",
    ))

    checks.append(_packet_check(
        "add_balance_files",
        add_balance_present if require_add_balance else True,
        "present" if add_balance_present else "not_required" if not require_add_balance else "missing",
    ))
    add_balance_manifest_hash = ""
    add_balance_ok = True
    if add_balance_present:
        try:
            add_balance_receipt = _load_packet_json(paths["add_balance_receipt"])
            add_balance_manifest = _load_packet_json(paths["add_balance_manifest"])
            add_balance_verification_file = _load_packet_json(paths["add_balance_verification"])
        except ValueError as exc:
            checks.append(_packet_check("add_balance_bounded_json", False, str(exc)))
            add_balance_ok = False
        else:
            add_balance_replay = verify_funding_validation_manifest(
                preflight=preflight,
                receipt=add_balance_receipt,
                manifest=add_balance_manifest,
                validation_id=f"{validation_id}:add_balance" if validation_id else "add_balance",
                attestation_policy=policy,
                require_ready=True,
                require_no_raw_card_retained=False,
            ).to_public_dict()
            add_balance_manifest_hash = str(add_balance_manifest.get("manifest_hash", ""))
            add_balance_ok = bool(add_balance_replay["ok"])
            checks.append(_packet_check(
                "add_balance_manifest_replay",
                add_balance_ok,
                "ok" if add_balance_ok else "failed",
            ))
            checks.append(_packet_check(
                "add_balance_verification_file",
                add_balance_verification_file.get("ok") is True
                and add_balance_verification_file.get("manifest_hash") == add_balance_replay.get("manifest_hash"),
                "matches"
                if add_balance_verification_file.get("manifest_hash") == add_balance_replay.get("manifest_hash")
                else "mismatch",
            ))
            checks.append(_packet_check(
                "summary_add_balance_hash",
                summary.get("add_balance_manifest_hash") == add_balance_manifest.get("manifest_hash"),
                "matches"
                if summary.get("add_balance_manifest_hash") == add_balance_manifest.get("manifest_hash")
                else "mismatch",
            ))

    return FundingValidationPacketCheck(
        ok=all(check["ok"] for check in checks),
        packet_dir=str(packet_dir),
        checks=checks,
        payment_manifest_hash=payment_manifest_hash,
        add_balance_manifest_hash=add_balance_manifest_hash,
        summary_ok=bool(summary.get("ok")),
        deployed_evidence=deployed_evidence,
        issued_at=issued_at,
    )


def _load_packet_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path.name} is not a JSON object")
    _assert_no_secret_output(payload)
    return payload


def _has_deployed_attestation(preflight: dict[str, Any]) -> bool:
    for check in preflight.get("checks", []):
        if not isinstance(check, dict):
            continue
        if check.get("name") == "billing_attestation_fetch":
            return bool(check.get("ok") is True and check.get("status") == "tdx")
    return False


def _packet_check(name: str, ok: bool, status: str) -> dict[str, Any]:
    return {"name": name, "ok": bool(ok), "status": status}
