"""Encrypted storage for bounded Tinker funding receipts."""

from __future__ import annotations

import hmac
import json
import os
import re
from pathlib import Path
from typing import Any, Mapping

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from tinker_delegate.automation_receipts import (
    AMOUNT_BANDS,
    BALANCE_BANDS,
    AutomationOutcome,
    AutomationStage,
    AutomationSurface,
    canonical_receipt_evidence_hash,
)
from tinker_delegate.dstack_utils import derive_storage_key, is_dstack_enabled


PUBLIC_RECEIPT_FIELDS = (
    "surface",
    "outcome",
    "furthest_stage",
    "bounded_message",
    "evidence_hash",
    "account_hash",
    "amount_band",
    "balance_band",
    "tdx_quote_hash",
    "card_payload_destroyed",
    "raw_secret_egress",
    "issued_at",
)
ALLOWED_RECEIPT_FIELDS = frozenset(PUBLIC_RECEIPT_FIELDS)
_LOWER_HEX_64 = re.compile(r"^[0-9a-f]{64}$")


def _require_enum_value(value: object, enum_type, field_name: str) -> str:
    if type(value) is not str:
        raise ValueError(f"funding receipt {field_name} must be a string enum code")
    try:
        return enum_type(value).value
    except ValueError as exc:
        raise ValueError(f"funding receipt {field_name} is not an allowed enum code") from exc


def _require_optional_hash(value: object, field_name: str) -> str:
    if type(value) is not str:
        raise ValueError(f"funding receipt {field_name} must be a string")
    if value and _LOWER_HEX_64.fullmatch(value) is None:
        raise ValueError(f"funding receipt {field_name} must be empty or lowercase sha256 hex")
    return value


def validate_bounded_funding_receipt(receipt: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and copy the exact canonical public funding-receipt shape.

    Persisted receipts fail closed.  In particular, the public message must be
    exactly the ``AutomationOutcome`` code and the evidence hash must recompute
    from the bounded projection.  No legacy raw page/error sentence is accepted.
    """

    if not isinstance(receipt, Mapping):
        raise ValueError("funding receipt must be an object")
    fields = set(receipt)
    unknown_fields = fields - ALLOWED_RECEIPT_FIELDS
    if unknown_fields:
        raise ValueError("funding receipt contains forbidden fields")
    missing_fields = ALLOWED_RECEIPT_FIELDS - fields
    if missing_fields:
        raise ValueError("funding receipt is missing required fields")

    bounded = {field: receipt[field] for field in PUBLIC_RECEIPT_FIELDS}
    bounded["surface"] = _require_enum_value(
        bounded["surface"], AutomationSurface, "surface"
    )
    bounded["outcome"] = _require_enum_value(
        bounded["outcome"], AutomationOutcome, "outcome"
    )
    bounded["furthest_stage"] = _require_enum_value(
        bounded["furthest_stage"], AutomationStage, "furthest_stage"
    )

    if type(bounded["bounded_message"]) is not str:
        raise ValueError("funding receipt bounded_message must be a string enum code")
    if bounded["bounded_message"] != bounded["outcome"]:
        raise ValueError("funding receipt bounded_message must equal its outcome code")

    if type(bounded["amount_band"]) is not str or bounded["amount_band"] not in AMOUNT_BANDS:
        raise ValueError("funding receipt amount_band is invalid")
    if type(bounded["balance_band"]) is not str or bounded["balance_band"] not in BALANCE_BANDS:
        raise ValueError("funding receipt balance_band is invalid")
    bounded["account_hash"] = _require_optional_hash(bounded["account_hash"], "account_hash")
    bounded["tdx_quote_hash"] = _require_optional_hash(
        bounded["tdx_quote_hash"], "tdx_quote_hash"
    )

    if type(bounded["card_payload_destroyed"]) is not bool:
        raise ValueError("funding receipt card_payload_destroyed must be boolean")
    if bounded["raw_secret_egress"] is not False:
        raise ValueError("funding receipt must explicitly report raw_secret_egress=false")
    if type(bounded["issued_at"]) is not int or bounded["issued_at"] < 0:
        raise ValueError("funding receipt issued_at must be a non-negative integer")

    evidence_hash = bounded["evidence_hash"]
    if type(evidence_hash) is not str or _LOWER_HEX_64.fullmatch(evidence_hash) is None:
        raise ValueError("funding receipt evidence_hash must be lowercase sha256 hex")
    expected_hash = canonical_receipt_evidence_hash(bounded)
    if not hmac.compare_digest(evidence_hash, expected_hash):
        raise ValueError("funding receipt evidence_hash does not match its bounded projection")
    return bounded


class FundingReceiptStore:
    """Persist bounded funding receipts under local or dstack-derived encryption."""

    def __init__(
        self,
        path: str,
        key_hex: str = "",
        *,
        dstack_enabled: bool = False,
        dstack_key_path: str = "tinker/funding_receipts",
    ):
        self.path = Path(path)
        self._key_path = self.path.with_suffix(".key")

        if key_hex:
            self.key = bytes.fromhex(key_hex)
        elif dstack_enabled:
            self.key = derive_storage_key(dstack_key_path)
            print(f"[funding_receipt_store] derived storage key from dstack path {dstack_key_path}")
        elif self._key_path.exists():
            self.key = bytes.fromhex(self._key_path.read_text().strip())
            print(f"[funding_receipt_store] loaded key from {self._key_path}")
        else:
            self.key = AESGCM.generate_key(bit_length=256)
            self._key_path.parent.mkdir(parents=True, exist_ok=True)
            self._key_path.write_text(self.key.hex())
            print(f"[funding_receipt_store] auto-generated and saved key to {self._key_path}")

        self._aesgcm = AESGCM(self.key)

    def load(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        raw = self.path.read_bytes()
        nonce, ciphertext = raw[:12], raw[12:]
        plaintext = self._aesgcm.decrypt(nonce, ciphertext, None)
        data = json.loads(plaintext)
        if not isinstance(data, dict) or set(data) != {"funding_receipts"}:
            raise ValueError("funding receipt store envelope is malformed")
        receipts = data["funding_receipts"]
        if not isinstance(receipts, list):
            raise ValueError("funding receipt store records must be a list")
        return [self._sanitize_receipt(receipt) for receipt in receipts]

    def append(self, receipt: dict[str, Any]) -> dict[str, Any]:
        bounded = self._sanitize_receipt(receipt)
        receipts = self.load()
        receipts.append(bounded)
        self.save(receipts)
        return bounded

    def save(self, receipts: list[dict[str, Any]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        bounded_receipts = [self._sanitize_receipt(receipt) for receipt in receipts]
        plaintext = json.dumps(
            {"funding_receipts": bounded_receipts},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        nonce = os.urandom(12)
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, None)
        tmp_path = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp_path.write_bytes(nonce + ciphertext)
        tmp_path.replace(self.path)

    @staticmethod
    def _sanitize_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
        return validate_bounded_funding_receipt(receipt)


def build_funding_receipt_store(settings) -> FundingReceiptStore:
    return FundingReceiptStore(
        settings.funding_receipt_store_path,
        settings.funding_receipt_store_key,
        dstack_enabled=is_dstack_enabled(),
        dstack_key_path=settings.funding_receipt_key_path,
    )
