"""In-TEE escrow for a winning candidate under the ESCROW disclosure mode.

``disclosure_policy.decide_disclosure`` can rule that a winning solution may be
released only as a sealed, authorization-gated artifact (``DisclosureMode.ESCROW``)
— not published, not hash-only. This module makes that ruling physical: it seals
the candidate under a per-escrow key derived from a TEE root key (HKDF-SHA256) and
releases the plaintext only to a caller presenting the authorization secret that
was committed at seal time.

Fail-closed by construction: only an ESCROW decision may be sealed here, release
requires the exact authorization secret (its hash is bound as AES-GCM associated
data, so a wrong secret fails authentication), and every receipt is bounded
(hashes/mode only — never the candidate or the secret).
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from tinker_delegate.disclosure_policy import DisclosureMode

_HKDF_INFO_PREFIX = b"dnai-solution-escrow:v1:"


class SolutionEscrowError(ValueError):
    """Raised when a candidate cannot be sealed or released from escrow."""


def _sha256_hex(data: bytes, *, prefix: str) -> str:
    return "0x" + hashlib.sha256(prefix.encode("utf-8") + b"\0" + data).hexdigest()


@dataclass(frozen=True)
class EscrowReceipt:
    escrow_ref_hash: str
    candidate_hash: str
    disclosure_mode: str
    sealed: bool
    raw_secret_egress: bool = False

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "kind": "solution_escrow_receipt",
            "escrow_ref_hash": self.escrow_ref_hash,
            "candidate_hash": self.candidate_hash,
            "disclosure_mode": self.disclosure_mode,
            "sealed": self.sealed,
            "raw_secret_egress": self.raw_secret_egress,
        }


@dataclass
class _Entry:
    nonce: bytes
    ciphertext: bytes
    candidate_hash: str
    authorization_hash: str


class SolutionEscrowStore:
    """Seal ESCROW-mode candidates under per-escrow keys; release on authorization."""

    def __init__(self, key: bytes | None = None) -> None:
        if key is not None and len(key) != 32:
            raise SolutionEscrowError("escrow root key must be 32 bytes")
        self._key = key if key is not None else os.urandom(32)
        self._entries: dict[str, _Entry] = {}

    def _derive_key(self, escrow_id: str) -> bytes:
        info = _HKDF_INFO_PREFIX + escrow_id.encode("utf-8")
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(self._key)

    def seal(
        self,
        escrow_id: str,
        candidate: bytes,
        *,
        disclosure_mode: DisclosureMode | str,
        authorization: bytes,
    ) -> EscrowReceipt:
        """Seal a candidate for later authorized release. ESCROW mode only."""

        if not escrow_id:
            raise SolutionEscrowError("escrow_id is required")
        mode = disclosure_mode.value if isinstance(disclosure_mode, DisclosureMode) else str(disclosure_mode)
        if mode != DisclosureMode.ESCROW.value:
            # PUBLIC releases plaintext directly; HASH_ONLY/BLOCKED must not retain
            # the candidate at all — only ESCROW is sealable here.
            raise SolutionEscrowError(f"only ESCROW disclosures may be sealed (got {mode})")
        if not authorization:
            raise SolutionEscrowError("authorization secret is required")
        if escrow_id in self._entries:
            raise SolutionEscrowError("escrow_id already sealed")

        authorization_hash = _sha256_hex(bytes(authorization), prefix="escrow_authorization")
        candidate_hash = _sha256_hex(bytes(candidate), prefix="escrow_candidate")
        nonce = os.urandom(12)
        aad = (escrow_id + "|" + authorization_hash).encode("utf-8")
        ciphertext = AESGCM(self._derive_key(escrow_id)).encrypt(nonce, bytes(candidate), aad)
        self._entries[escrow_id] = _Entry(
            nonce=nonce,
            ciphertext=ciphertext,
            candidate_hash=candidate_hash,
            authorization_hash=authorization_hash,
        )
        return EscrowReceipt(
            escrow_ref_hash=_sha256_hex(escrow_id.encode("utf-8"), prefix="escrow_ref"),
            candidate_hash=candidate_hash,
            disclosure_mode=mode,
            sealed=True,
        )

    def release(self, escrow_id: str, *, authorization: bytes) -> bytes:
        """Return the sealed candidate iff the authorization secret matches."""

        entry = self._entries.get(escrow_id)
        if entry is None:
            raise SolutionEscrowError("no sealed candidate for escrow_id")
        authorization_hash = _sha256_hex(bytes(authorization), prefix="escrow_authorization")
        if authorization_hash != entry.authorization_hash:
            raise SolutionEscrowError("authorization does not match")
        aad = (escrow_id + "|" + entry.authorization_hash).encode("utf-8")
        return AESGCM(self._derive_key(escrow_id)).decrypt(entry.nonce, entry.ciphertext, aad)

    def is_sealed(self, escrow_id: str) -> bool:
        return escrow_id in self._entries

    def count(self) -> int:
        return len(self._entries)

    def public_manifest(self) -> dict[str, Any]:
        return {
            "kind": "solution_escrow_manifest",
            "sealed_count": len(self._entries),
            "raw_secret_egress": False,
        }
