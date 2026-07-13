"""Bounded, attestable destruction / cleanup records for the diligence room.

After a deal resolves, the TEE destroys the sealed material — the raw artifact
buffer, derived keys, and any evaluation checkpoints. This module turns the facts
of that cleanup into a bounded, recomputable audit record so a buyer/owner/auditor
can verify destruction happened without any raw data leaving the boundary.

Fail-closed: a record is marked ``complete`` only when every *required*
destruction step succeeded (by default: the raw artifact was deleted AND its
in-memory buffer was zeroed). If a required step did not succeed, the record is
``complete=false`` with an ``incomplete_destruction`` reason — an honest,
non-self-approving audit signal, not a silent pass.

Everything emitted is bounded: the deal ref is hashed, the artifact commitment is
already a hash, and only counts/booleans/hashes appear — never raw artifact bytes,
key material, or checkpoint paths/ids.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any


class DestructionError(ValueError):
    """Raised on malformed destruction evidence."""


@dataclass(frozen=True)
class DestructionEvidence:
    deal_ref: str
    artifact_hash: str = ""
    artifact_deleted: bool = False
    memory_zeroed: bool = False
    keys_dropped: int = 0
    checkpoints_deleted: int = 0
    checkpoints_expired: int = 0
    require_artifact_delete: bool = True
    require_memory_zero: bool = True

    def __post_init__(self) -> None:
        for count in (self.keys_dropped, self.checkpoints_deleted, self.checkpoints_expired):
            if count < 0:
                raise DestructionError("destruction counts must be non-negative")
        if not self.deal_ref:
            raise DestructionError("deal_ref is required")


@dataclass(frozen=True)
class DestructionRecord:
    deal_ref_hash: str
    artifact_hash: str
    artifact_deleted: bool
    memory_zeroed: bool
    keys_dropped_count: int
    checkpoints_deleted_count: int
    checkpoints_expired_count: int
    complete: bool
    reason_code: str
    issued_at: int
    record_hash: str
    raw_secret_egress: bool = False

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "kind": "destruction_record",
            "deal_ref_hash": self.deal_ref_hash,
            "artifact_hash": self.artifact_hash,
            "artifact_deleted": self.artifact_deleted,
            "memory_zeroed": self.memory_zeroed,
            "keys_dropped_count": self.keys_dropped_count,
            "checkpoints_deleted_count": self.checkpoints_deleted_count,
            "checkpoints_expired_count": self.checkpoints_expired_count,
            "complete": self.complete,
            "reason_code": self.reason_code,
            "issued_at": self.issued_at,
            "record_hash": self.record_hash,
            "raw_secret_egress": self.raw_secret_egress,
        }


def build_destruction_record(evidence: DestructionEvidence, *, at: int | None = None) -> DestructionRecord:
    """Build a bounded, recomputable destruction record from cleanup evidence."""
    issued_at = int(time.time()) if at is None else int(at)

    missing: list[str] = []
    if evidence.require_artifact_delete and not evidence.artifact_deleted:
        missing.append("artifact_not_deleted")
    if evidence.require_memory_zero and not evidence.memory_zeroed:
        missing.append("memory_not_zeroed")
    complete = not missing
    reason_code = "destroyed" if complete else "incomplete_destruction:" + ",".join(sorted(missing))

    deal_ref_hash = _sha256_hex(evidence.deal_ref)
    artifact_hash = _normalize_hash(evidence.artifact_hash)

    fields = {
        "deal_ref_hash": deal_ref_hash,
        "artifact_hash": artifact_hash,
        "artifact_deleted": evidence.artifact_deleted,
        "memory_zeroed": evidence.memory_zeroed,
        "keys_dropped_count": evidence.keys_dropped,
        "checkpoints_deleted_count": evidence.checkpoints_deleted,
        "checkpoints_expired_count": evidence.checkpoints_expired,
        "complete": complete,
        "reason_code": reason_code,
        "issued_at": issued_at,
    }
    record_hash = _sha256_json(fields)

    return DestructionRecord(
        deal_ref_hash=deal_ref_hash,
        artifact_hash=artifact_hash,
        artifact_deleted=evidence.artifact_deleted,
        memory_zeroed=evidence.memory_zeroed,
        keys_dropped_count=evidence.keys_dropped,
        checkpoints_deleted_count=evidence.checkpoints_deleted,
        checkpoints_expired_count=evidence.checkpoints_expired,
        complete=complete,
        reason_code=reason_code,
        issued_at=issued_at,
        record_hash=record_hash,
    )


def verify_destruction_record(record: DestructionRecord) -> bool:
    """Recompute the record hash to detect tampering."""
    expected = _sha256_json(
        {
            "deal_ref_hash": record.deal_ref_hash,
            "artifact_hash": record.artifact_hash,
            "artifact_deleted": record.artifact_deleted,
            "memory_zeroed": record.memory_zeroed,
            "keys_dropped_count": record.keys_dropped_count,
            "checkpoints_deleted_count": record.checkpoints_deleted_count,
            "checkpoints_expired_count": record.checkpoints_expired_count,
            "complete": record.complete,
            "reason_code": record.reason_code,
            "issued_at": record.issued_at,
        }
    )
    return expected == record.record_hash


def _normalize_hash(value: str) -> str:
    if not value:
        return "0x" + "00" * 32
    body = value[2:] if value.startswith(("0x", "0X")) else value
    if len(body) != 64 or any(c not in "0123456789abcdefABCDEF" for c in body):
        raise DestructionError("artifact_hash must be empty or a 32-byte hex value")
    return "0x" + body.lower()


def _sha256_hex(value: str) -> str:
    return "0x" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sha256_json(value: Any) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return "0x" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
