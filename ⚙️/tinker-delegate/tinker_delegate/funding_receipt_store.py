"""Encrypted storage for bounded Tinker funding receipts."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from tinker_delegate.dstack_utils import derive_storage_key, is_dstack_enabled


ALLOWED_RECEIPT_FIELDS = frozenset(
    {
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
    }
)


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
        receipts = data.get("funding_receipts", [])
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
        unknown_fields = set(receipt) - ALLOWED_RECEIPT_FIELDS
        if unknown_fields:
            raise ValueError(f"funding receipt contains forbidden fields: {sorted(unknown_fields)}")
        bounded = {field: receipt[field] for field in sorted(ALLOWED_RECEIPT_FIELDS) if field in receipt}
        if bounded.get("raw_secret_egress") is not False:
            raise ValueError("funding receipt must explicitly report raw_secret_egress=false")
        required = {"surface", "outcome", "furthest_stage", "evidence_hash", "issued_at"}
        missing = required - set(bounded)
        if missing:
            raise ValueError(f"funding receipt missing required fields: {sorted(missing)}")
        return bounded


def build_funding_receipt_store(settings) -> FundingReceiptStore:
    return FundingReceiptStore(
        settings.funding_receipt_store_path,
        settings.funding_receipt_store_key,
        dstack_enabled=is_dstack_enabled(),
        dstack_key_path=settings.funding_receipt_key_path,
    )
