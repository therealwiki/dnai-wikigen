"""Encrypted storage for bounded Tinker deal/run metadata."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from tinker_delegate.dstack_utils import derive_storage_key, is_dstack_enabled


ALLOWED_RUN_METADATA_FIELDS = frozenset(
    {
        "artifact_hash",
        "artifact_sealed_retained",
        "artifact_size_band",
        "budget_cap_band",
        "buyer_hash",
        "buyer_refund_band",
        "chain_block_band",
        "chain_event_name",
        "chain_log_index_band",
        "chain_tx_hash",
        "checkpoint_ids_hash",
        "cleanup_success",
        "confidence",
        "compute_cost_band",
        "dev_payment_band",
        "deal_hash",
        "deleted_checkpoint_count",
        "delete_attempts",
        "destruction_complete",
        "destruction_record_hash",
        "event",
        "expiry_band",
        "evaluator_policy_commitment",
        "failed_checkpoint_count",
        "fee_band",
        "refund_band",
        "issued_at",
        "listed_checkpoint_count",
        "offer_price_band",
        "raw_secret_egress",
        "reconciliation_status",
        "recommendation",
        "reserve_price_band",
        "result_hash",
        "retention_action",
        "settlement_safe",
        "score_band",
        "seller_hash",
        "seller_payment_band",
        "tdx_quote_hash",
        "tee_identity_hash",
        "training_run_id_hash",
    }
)


EVALUATOR_POLICY_COMMITMENT_PATTERN = re.compile(
    r"^0x(?!0{64}$)[0-9a-f]{64}$"
)


ALLOWED_RUN_METADATA_EVENTS = frozenset(
    {
        "deal_funded",
        "artifact_received",
        "evaluation_completed",
        "evaluation_failed",
        "chain_event",
        "deal_resolved",
        "retention_swept",
    }
)


def stable_hash(value: str | bytes | None, *, prefix: str) -> str:
    """Hash an internal identifier before it can enter persisted metadata."""
    if value is None:
        return ""
    raw = value if isinstance(value, bytes) else str(value).encode("utf-8")
    return hashlib.sha256(prefix.encode("utf-8") + b"\0" + raw).hexdigest()


def value_band(value: int | float | None) -> str:
    """Coarsen wei/count-like values before persistence."""
    if value is None:
        return "unknown"
    numeric = float(value)
    if not math.isfinite(numeric) or numeric < 0:
        return "invalid"
    if numeric == 0:
        return "zero"
    if numeric < 10**6:
        return "<1e6"
    if numeric < 10**9:
        return "1e6-1e9"
    if numeric < 10**12:
        return "1e9-1e12"
    if numeric < 10**15:
        return "1e12-1e15"
    if numeric < 10**18:
        return "1e15-1e18"
    return ">=1e18"


def size_band(byte_count: int | None) -> str:
    """Coarsen artifact sizes before persistence."""
    if byte_count is None:
        return "unknown"
    if byte_count < 0:
        return "invalid"
    if byte_count == 0:
        return "zero"
    if byte_count <= 1024:
        return "<=1KiB"
    if byte_count <= 1024 * 1024:
        return "<=1MiB"
    if byte_count <= 64 * 1024 * 1024:
        return "<=64MiB"
    return ">64MiB"


class RunMetadataStore:
    """Persist bounded run metadata under local or dstack-derived encryption."""

    def __init__(
        self,
        path: str,
        key_hex: str = "",
        *,
        dstack_enabled: bool = False,
        dstack_key_path: str = "tinker/run_metadata",
    ):
        self.path = Path(path)
        self._key_path = self.path.with_suffix(".key")

        if key_hex:
            self.key = bytes.fromhex(key_hex)
        elif dstack_enabled:
            self.key = derive_storage_key(dstack_key_path)
            print(f"[run_metadata_store] derived storage key from dstack path {dstack_key_path}")
        elif self._key_path.exists():
            self.key = bytes.fromhex(self._key_path.read_text().strip())
            print(f"[run_metadata_store] loaded key from {self._key_path}")
        else:
            self.key = AESGCM.generate_key(bit_length=256)
            self._key_path.parent.mkdir(parents=True, exist_ok=True)
            self._key_path.write_text(self.key.hex())
            print(f"[run_metadata_store] auto-generated and saved key to {self._key_path}")

        self._aesgcm = AESGCM(self.key)

    def load(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        raw = self.path.read_bytes()
        nonce, ciphertext = raw[:12], raw[12:]
        plaintext = self._aesgcm.decrypt(nonce, ciphertext, None)
        data = json.loads(plaintext)
        records = data.get("run_metadata", [])
        return [self._sanitize_record(record) for record in records]

    def append(self, record: dict[str, Any]) -> dict[str, Any]:
        bounded = self._sanitize_record(record)
        records = self.load()
        records.append(bounded)
        self.save(records)
        return bounded

    def save(self, records: list[dict[str, Any]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        bounded_records = [self._sanitize_record(record) for record in records]
        plaintext = json.dumps(
            {"run_metadata": bounded_records},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        nonce = os.urandom(12)
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, None)
        tmp_path = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp_path.write_bytes(nonce + ciphertext)
        tmp_path.replace(self.path)

    @staticmethod
    def _sanitize_record(record: dict[str, Any]) -> dict[str, Any]:
        unknown_fields = set(record) - ALLOWED_RUN_METADATA_FIELDS
        if unknown_fields:
            raise ValueError(f"run metadata contains forbidden fields: {sorted(unknown_fields)}")
        bounded = {field: record[field] for field in sorted(ALLOWED_RUN_METADATA_FIELDS) if field in record}
        if bounded.get("raw_secret_egress") is not False:
            raise ValueError("run metadata must explicitly report raw_secret_egress=false")
        required = {"event", "deal_hash", "issued_at"}
        missing = required - set(bounded)
        if missing:
            raise ValueError(f"run metadata missing required fields: {sorted(missing)}")
        if bounded["event"] not in ALLOWED_RUN_METADATA_EVENTS:
            raise ValueError("run metadata contains unsupported event")
        evaluator_policy = bounded.get("evaluator_policy_commitment")
        if evaluator_policy is not None and (
            not isinstance(evaluator_policy, str)
            or EVALUATOR_POLICY_COMMITMENT_PATTERN.fullmatch(evaluator_policy) is None
        ):
            raise ValueError(
                "run metadata evaluator policy commitment must be a nonzero lowercase bytes32"
            )
        return bounded


def make_run_metadata_event(event: str, deal_id: str, **fields: Any) -> dict[str, Any]:
    """Create a bounded metadata event without raw deal/account/run handles."""
    record = {
        "event": event,
        "deal_hash": stable_hash(deal_id, prefix="deal_id"),
        "issued_at": fields.pop("issued_at", int(time.time())),
        "raw_secret_egress": False,
    }
    record.update(fields)
    return record


def build_run_metadata_store(settings) -> RunMetadataStore:
    return RunMetadataStore(
        settings.run_metadata_store_path,
        settings.run_metadata_store_key,
        dstack_enabled=is_dstack_enabled(),
        dstack_key_path=settings.run_metadata_key_path,
    )
