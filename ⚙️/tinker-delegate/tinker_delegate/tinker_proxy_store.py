"""Encrypted audit and revocation store for Tinker proxy tokens."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from tinker_delegate.dstack_utils import derive_storage_key, is_dstack_enabled


ALLOWED_PROXY_TOKEN_RECORD_FIELDS = frozenset(
    {
        "event",
        "subject_hash",
        "jwt_id_hash",
        "recipient_public_key_hash",
        "scopes",
        "issued_at",
        "expires_at",
        "revoked_at",
        "revocation_reason",
        "raw_secret_egress",
    }
)

ALLOWED_PROXY_TOKEN_EVENTS = frozenset({"issued", "revoked"})


class ProxyTokenStore:
    """Persist bounded proxy-token issue/revoke records under encryption."""

    def __init__(
        self,
        path: str,
        key_hex: str = "",
        *,
        dstack_enabled: bool = False,
        dstack_key_path: str = "tinker/proxy_tokens",
    ):
        self.path = Path(path)
        self._key_path = self.path.with_suffix(".key")

        if key_hex:
            self.key = bytes.fromhex(key_hex)
        elif dstack_enabled:
            self.key = derive_storage_key(dstack_key_path)
            print(f"[proxy_token_store] derived storage key from dstack path {dstack_key_path}")
        elif self._key_path.exists():
            self.key = bytes.fromhex(self._key_path.read_text().strip())
            print(f"[proxy_token_store] loaded key from {self._key_path}")
        else:
            self.key = AESGCM.generate_key(bit_length=256)
            self._key_path.parent.mkdir(parents=True, exist_ok=True)
            self._key_path.write_text(self.key.hex())
            print(f"[proxy_token_store] auto-generated and saved key to {self._key_path}")

        self._aesgcm = AESGCM(self.key)

    def load(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        raw = self.path.read_bytes()
        nonce, ciphertext = raw[:12], raw[12:]
        plaintext = self._aesgcm.decrypt(nonce, ciphertext, None)
        data = json.loads(plaintext)
        records = data.get("proxy_tokens", [])
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
            {"proxy_tokens": bounded_records},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        nonce = os.urandom(12)
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, None)
        tmp_path = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp_path.write_bytes(nonce + ciphertext)
        tmp_path.replace(self.path)

    def revoked_token_hashes(self) -> set[str]:
        return {
            str(record["jwt_id_hash"])
            for record in self.load()
            if record.get("event") == "revoked"
        }

    def revoke(self, jwt_id_hash: str, *, reason: str = "", revoked_at: int | None = None) -> dict[str, Any]:
        normalized = _normalize_hash(jwt_id_hash, "jwt_id_hash")
        records = self.load()
        issued = [
            record
            for record in records
            if record.get("event") == "issued" and record.get("jwt_id_hash") == normalized
        ]
        if not issued:
            raise ValueError("proxy token revoke target was not issued")
        existing_revocations = [
            record
            for record in records
            if record.get("event") == "revoked" and record.get("jwt_id_hash") == normalized
        ]
        if existing_revocations:
            return existing_revocations[-1]
        record = {
            "event": "revoked",
            "jwt_id_hash": normalized,
            "revoked_at": int(time.time() if revoked_at is None else revoked_at),
            "revocation_reason": _bounded_reason(reason),
            "raw_secret_egress": False,
        }
        bounded = self._sanitize_record(record)
        records.append(bounded)
        self.save(records)
        return bounded

    @staticmethod
    def _sanitize_record(record: dict[str, Any]) -> dict[str, Any]:
        unknown_fields = set(record) - ALLOWED_PROXY_TOKEN_RECORD_FIELDS
        if unknown_fields:
            raise ValueError(f"proxy token record contains forbidden fields: {sorted(unknown_fields)}")
        bounded = {
            field: record[field]
            for field in sorted(ALLOWED_PROXY_TOKEN_RECORD_FIELDS)
            if field in record
        }
        if bounded.get("raw_secret_egress") is not False:
            raise ValueError("proxy token record must explicitly report raw_secret_egress=false")
        if bounded.get("event") not in ALLOWED_PROXY_TOKEN_EVENTS:
            raise ValueError("proxy token record contains unsupported event")
        _normalize_hash(str(bounded.get("jwt_id_hash", "")), "jwt_id_hash")
        if "subject_hash" in bounded:
            _normalize_hash(str(bounded["subject_hash"]), "subject_hash")
        if "recipient_public_key_hash" in bounded:
            _normalize_hash(str(bounded["recipient_public_key_hash"]), "recipient_public_key_hash")
        if bounded["event"] == "issued":
            required = {
                "event",
                "subject_hash",
                "jwt_id_hash",
                "recipient_public_key_hash",
                "scopes",
                "issued_at",
                "expires_at",
                "raw_secret_egress",
            }
        else:
            required = {"event", "jwt_id_hash", "revoked_at", "raw_secret_egress"}
        missing = required - set(bounded)
        if missing:
            raise ValueError(f"proxy token record missing required fields: {sorted(missing)}")
        if "scopes" in bounded:
            scopes = bounded["scopes"]
            if not isinstance(scopes, list) or not all(isinstance(scope, str) for scope in scopes):
                raise ValueError("proxy token record scopes must be a list of strings")
            bounded["scopes"] = sorted(set(scopes))
        if "revocation_reason" in bounded:
            bounded["revocation_reason"] = _bounded_reason(str(bounded["revocation_reason"]))
        return bounded


def make_proxy_token_issue_record(
    *,
    subject_hash: str,
    jwt_id_hash: str,
    recipient_public_key_hash: str,
    scopes: list[str],
    issued_at: int,
    expires_at: int,
) -> dict[str, Any]:
    return {
        "event": "issued",
        "subject_hash": _normalize_hash(subject_hash, "subject_hash"),
        "jwt_id_hash": _normalize_hash(jwt_id_hash, "jwt_id_hash"),
        "recipient_public_key_hash": _normalize_hash(
            recipient_public_key_hash,
            "recipient_public_key_hash",
        ),
        "scopes": sorted(set(scopes)),
        "issued_at": int(issued_at),
        "expires_at": int(expires_at),
        "raw_secret_egress": False,
    }


def summarize_proxy_token_records(records: list[dict[str, Any]]) -> dict[str, Any]:
    issued = [record for record in records if record.get("event") == "issued"]
    revoked = [record for record in records if record.get("event") == "revoked"]
    active = {
        record["jwt_id_hash"]
        for record in issued
        if record.get("jwt_id_hash")
    } - {
        record["jwt_id_hash"]
        for record in revoked
        if record.get("jwt_id_hash")
    }
    return {
        "surface": "tinker_proxy_token_audit",
        "record_count": len(records),
        "issued_count": len(issued),
        "revoked_count": len(revoked),
        "active_unexpired_or_unknown_count": len(active),
        "records": records,
        "raw_secret_egress": False,
    }


def build_proxy_token_store(settings) -> ProxyTokenStore:
    return ProxyTokenStore(
        settings.proxy_token_store_path,
        settings.proxy_token_store_key,
        dstack_enabled=is_dstack_enabled(),
        dstack_key_path=settings.proxy_token_key_path,
    )


def _normalize_hash(value: str, field_name: str) -> str:
    if len(value) != 64:
        raise ValueError(f"{field_name} must be a 64-char hex hash")
    try:
        int(value, 16)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be hex") from exc
    return value.lower()


def _bounded_reason(reason: str) -> str:
    normalized = reason.strip().lower().replace(" ", "_")
    if not normalized:
        return "unspecified"
    allowed = {
        "unspecified",
        "operator_requested",
        "scope_changed",
        "recipient_rotated",
        "suspected_compromise",
        "expired_replaced",
    }
    return normalized if normalized in allowed else "other"
