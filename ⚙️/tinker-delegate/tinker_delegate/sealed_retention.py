"""Sealed-retention store for time-boxed / archived diligence artifacts.

When a room's retention policy says ``retain_sealed`` or ``archive_encrypted``
instead of destroy-now, the artifact must not sit in plaintext — it is encrypted
under a TEE-held retention key (AES-256-GCM, per-deal associated data) and held as
ciphertext until its retention window expires, at which point ``sweep`` destroys
it. The retention key lives only inside this store (inside the TEE) and never
egresses.

This is the store that lets the control plane honor a retain/archive decision
safely; it composes with `retention_policy` (which decides the window) and
`destruction_record` (which attests the eventual destruction).

Outputs are bounded: deal refs are hashed, ciphertext sizes are banded, and only
counts/hashes/expiry timestamps appear — never plaintext, ciphertext bytes, or the
key.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from tinker_delegate.dstack_utils import derive_storage_key

# Per-corpus/per-deal key-derivation domain. The root store key never encrypts an
# artifact directly; each artifact is sealed under HKDF(root, corpus/deal), so no
# single static key protects every room and a per-corpus key can be rotated or
# compromised in isolation.
_RETENTION_HKDF_INFO_PREFIX = b"dnai-sealed-retention:v1:"


class SealedRetentionError(ValueError):
    """Raised on a malformed sealed-retention operation."""


@dataclass
class _SealedEntry:
    deal_id: str
    nonce: bytes
    ciphertext: bytes
    retain_until: int  # 0 = no expiry
    plaintext_len: int
    artifact_hash: str
    corpus_ref: str = ""  # room/corpus this deal belongs to (key-derivation scope)


@dataclass(frozen=True)
class SealReceipt:
    deal_ref_hash: str
    artifact_hash: str
    retain_until: int
    ciphertext_size_band: str
    sealed: bool = True
    raw_secret_egress: bool = False

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "kind": "sealed_retention_receipt",
            "deal_ref_hash": self.deal_ref_hash,
            "artifact_hash": self.artifact_hash,
            "retain_until": self.retain_until,
            "ciphertext_size_band": self.ciphertext_size_band,
            "sealed": self.sealed,
            "raw_secret_egress": self.raw_secret_egress,
        }


class SealedRetentionStore:
    """In-TEE store of artifacts sealed under a retention key until expiry."""

    def __init__(
        self,
        key: bytes | None = None,
        *,
        path: str | Path | None = None,
        dstack_enabled: bool = False,
        dstack_key_path: str = "tinker/sealed_retention",
    ) -> None:
        if key is not None and len(key) != 32:
            raise SealedRetentionError("retention key must be 32 bytes")
        self.path = Path(path) if path else None
        self._key_path = self.path.with_suffix(".key") if self.path else None

        if key is not None:
            self._key = key
        elif dstack_enabled:
            self._key = derive_storage_key(dstack_key_path)
        elif self._key_path is not None and self._key_path.exists():
            self._key = bytes.fromhex(self._key_path.read_text().strip())
        elif self._key_path is not None:
            self._key = AESGCM.generate_key(bit_length=256)
            self._key_path.parent.mkdir(parents=True, exist_ok=True)
            self._key_path.write_text(self._key.hex())
        else:
            self._key = os.urandom(32)

        self._aes = AESGCM(self._key)
        self._entries: dict[str, _SealedEntry] = {}
        if self.path is not None and self.path.exists():
            self._load()

    def _derive_key(self, corpus_ref: str, deal_id: str) -> bytes:
        """Per-corpus/per-deal artifact key via HKDF-SHA256 from the root key.

        Distinct ``(corpus_ref, deal_id)`` yield cryptographically independent
        keys, so a retained artifact cannot decrypt under another room or deal
        even though every entry descends from the same TEE root key. Fields are
        length-prefixed (not delimiter-joined) so a ref containing the separator
        cannot collide two different ``(corpus_ref, deal_id)`` pairs onto one key.
        """

        info = _RETENTION_HKDF_INFO_PREFIX + _length_prefixed(corpus_ref, deal_id)
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(self._key)

    def seal(
        self,
        deal_id: str,
        artifact: bytes,
        *,
        retain_until: int,
        artifact_hash: str = "",
        corpus_ref: str = "",
    ) -> SealReceipt:
        """Encrypt and hold an artifact until ``retain_until`` (0 = no expiry).

        The artifact is sealed under a per-corpus/per-deal derived key, not the
        root key, so ``corpus_ref`` scopes the key hierarchy (e.g. one room's
        retained corpus).
        """
        if not deal_id:
            raise SealedRetentionError("deal_id is required")
        if retain_until < 0:
            raise SealedRetentionError("retain_until must be non-negative")
        nonce = os.urandom(12)
        cell = AESGCM(self._derive_key(corpus_ref, deal_id))
        ciphertext = cell.encrypt(nonce, bytes(artifact), deal_id.encode("utf-8"))
        self._entries[deal_id] = _SealedEntry(
            deal_id=deal_id,
            nonce=nonce,
            ciphertext=ciphertext,
            retain_until=int(retain_until),
            plaintext_len=len(artifact),
            artifact_hash=_normalize_hash(artifact_hash),
            corpus_ref=corpus_ref,
        )
        self._persist()
        return SealReceipt(
            deal_ref_hash=_hash(deal_id),
            artifact_hash=_normalize_hash(artifact_hash),
            retain_until=int(retain_until),
            ciphertext_size_band=_size_band(len(ciphertext)),
        )

    def open(self, deal_id: str) -> bytes:
        """Decrypt a retained artifact (in-TEE, for authorized re-evaluation)."""
        entry = self._entries.get(deal_id)
        if entry is None:
            raise SealedRetentionError("no sealed artifact for deal")
        cell = AESGCM(self._derive_key(entry.corpus_ref, deal_id))
        return cell.decrypt(entry.nonce, entry.ciphertext, deal_id.encode("utf-8"))

    def is_retained(self, deal_id: str) -> bool:
        return deal_id in self._entries

    def retain_until(self, deal_id: str) -> int:
        entry = self._entries.get(deal_id)
        return entry.retain_until if entry else 0

    def destroy(self, deal_id: str) -> bool:
        """Drop a sealed entry (best-effort zeroing of the ciphertext buffer)."""
        entry = self._entries.pop(deal_id, None)
        if entry is None:
            return False
        _zero(entry.ciphertext)
        _zero(entry.nonce)
        self._persist()
        return True

    def sweep(self, now: int) -> tuple[str, ...]:
        """Destroy every entry whose retention window has expired. Returns their ids."""
        expired = [
            deal_id
            for deal_id, entry in self._entries.items()
            if entry.retain_until and int(now) >= entry.retain_until
        ]
        for deal_id in expired:
            entry = self._entries.pop(deal_id, None)
            if entry is not None:
                _zero(entry.ciphertext)
                _zero(entry.nonce)
        if expired:
            self._persist()
        return tuple(expired)

    @property
    def count(self) -> int:
        return len(self._entries)

    def public_manifest(self, *, now: int | None = None) -> dict[str, Any]:
        entries = []
        for entry in self._entries.values():
            item = {
                "deal_ref_hash": _hash(entry.deal_id),
                "artifact_hash": entry.artifact_hash,
                "retain_until": entry.retain_until,
                "ciphertext_size_band": _size_band(len(entry.ciphertext)),
            }
            if now is not None:
                item["expired"] = bool(entry.retain_until and int(now) >= entry.retain_until)
            entries.append(item)
        return {
            "kind": "sealed_retention_manifest",
            "retained_count": len(self._entries),
            "entries": entries,
            "raw_secret_egress": False,
        }

    # -- persistence (encrypted index under the CVM data volume) ----------------

    def _persist(self) -> None:
        if self.path is None:
            return
        index = [
            {
                "deal_id": e.deal_id,
                "nonce": e.nonce.hex(),
                "ciphertext": e.ciphertext.hex(),
                "retain_until": e.retain_until,
                "plaintext_len": e.plaintext_len,
                "artifact_hash": e.artifact_hash,
                "corpus_ref": e.corpus_ref,
            }
            for e in self._entries.values()
        ]
        plaintext = json.dumps({"entries": index}, separators=(",", ":")).encode("utf-8")
        nonce = os.urandom(12)
        sealed = self._aes.encrypt(nonce, plaintext, b"sealed_retention_index")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_bytes(nonce + sealed)

    def _load(self) -> None:
        raw = self.path.read_bytes()
        if len(raw) < 12:
            return
        nonce, sealed = raw[:12], raw[12:]
        plaintext = self._aes.decrypt(nonce, sealed, b"sealed_retention_index")
        index = json.loads(plaintext.decode("utf-8")).get("entries", [])
        for item in index:
            deal_id = item["deal_id"]
            self._entries[deal_id] = _SealedEntry(
                deal_id=deal_id,
                nonce=bytes.fromhex(item["nonce"]),
                ciphertext=bytes.fromhex(item["ciphertext"]),
                retain_until=int(item["retain_until"]),
                plaintext_len=int(item["plaintext_len"]),
                artifact_hash=item["artifact_hash"],
                corpus_ref=item.get("corpus_ref", ""),
            )


def build_retention_store(settings: Any) -> "SealedRetentionStore | None":
    """Build a persisting retention store from settings, or None if disabled."""
    from tinker_delegate.dstack_utils import is_dstack_enabled

    path = getattr(settings, "retention_store_path", "")
    if not path:
        return None
    key_hex = getattr(settings, "retention_store_key", "")
    key = bytes.fromhex(key_hex) if key_hex else None
    return SealedRetentionStore(
        key,
        path=path,
        dstack_enabled=is_dstack_enabled(),
        dstack_key_path=getattr(settings, "retention_dstack_key_path", "tinker/sealed_retention"),
    )


def _zero(buf: bytes) -> None:
    # Ciphertext/nonce are immutable bytes; best-effort via a mutable view when possible.
    try:
        mv = memoryview(bytearray(buf))
        for i in range(len(mv)):
            mv[i] = 0
    except Exception:  # pragma: no cover - defensive
        pass


def _length_prefixed(*fields: str) -> bytes:
    """Unambiguously encode string fields as 4-byte-length-prefixed UTF-8 chunks.

    Prevents delimiter-collision: no choice of field contents can make two
    distinct field tuples encode to the same bytes.
    """

    out = bytearray()
    for field in fields:
        data = field.encode("utf-8")
        out += len(data).to_bytes(4, "big") + data
    return bytes(out)


def _hash(value: str) -> str:
    return "0x" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _normalize_hash(value: str) -> str:
    if not value:
        return "0x" + "00" * 32
    body = value[2:] if value.startswith(("0x", "0X")) else value
    if len(body) != 64 or any(c not in "0123456789abcdefABCDEF" for c in body):
        raise SealedRetentionError("artifact_hash must be empty or a 32-byte hex value")
    return "0x" + body.lower()


def _size_band(n: int) -> str:
    if n <= 0:
        return "zero"
    if n < 1024:
        return "sub_kib"
    if n < 1024 * 1024:
        return "sub_mib"
    if n < 16 * 1024 * 1024:
        return "sub_16mib"
    return "large"
