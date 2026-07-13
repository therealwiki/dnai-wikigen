"""Append-only, tamper-evident transcript logger for bounded reward events.

The private-reward environment already recomputes a flat ``transcript_hash`` over
all its query records. This logger is the complementary *streaming* primitive: it
appends one bounded event at a time and binds each entry to the previous entry's
chain hash, so the log is append-only and tamper-evident — you cannot insert,
delete, or reorder an entry without breaking the chain from that point forward.

Each entry's ``chain_hash = H(prev_chain_hash || event_hash || index)`` (genesis
``prev`` is 32 zero bytes). ``verify_chain`` recomputes the whole chain to detect
any tampering. Only hashes/counts leave; the caller supplies already-bounded event
dicts (candidate hash, decision, reward band — never payloads or exact rewards).
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

# Domain-separated genesis "previous" hash. A hash (not all-zeros) so every
# bounded hex field is hash-shaped and never reads as a long decimal integer.
_GENESIS_PREV = hashlib.sha256(b"transcript-chain-genesis").hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def event_hash(bounded_event: dict[str, Any]) -> str:
    """Domain-separated hash of one bounded event dict."""

    return _sha256_hex(b"transcript-event\x00" + _canonical(bounded_event))


def _chain_step(prev_chain_hash: str, event_hex: str, index: int) -> str:
    payload = bytes.fromhex(prev_chain_hash) + bytes.fromhex(event_hex) + index.to_bytes(8, "big")
    return _sha256_hex(b"transcript-chain\x00" + payload)


@dataclass(frozen=True)
class TranscriptEntry:
    index: int
    event_hash: str
    prev_hash: str
    chain_hash: str

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "event_hash": self.event_hash,
            "prev_hash": self.prev_hash,
            "chain_hash": self.chain_hash,
        }


class TranscriptLogger:
    """Accumulate bounded events into an append-only hash chain."""

    def __init__(self) -> None:
        self._entries: list[TranscriptEntry] = []

    @property
    def head(self) -> str:
        """Chain hash of the last entry, or the genesis value if empty."""

        return self._entries[-1].chain_hash if self._entries else _GENESIS_PREV

    @property
    def entries(self) -> tuple[TranscriptEntry, ...]:
        return tuple(self._entries)

    def __len__(self) -> int:
        return len(self._entries)

    def append(self, bounded_event: dict[str, Any]) -> TranscriptEntry:
        prev = self.head
        index = len(self._entries)
        ev = event_hash(bounded_event)
        entry = TranscriptEntry(
            index=index,
            event_hash=ev,
            prev_hash=prev,
            chain_hash=_chain_step(prev, ev, index),
        )
        self._entries.append(entry)
        return entry

    def verify(self) -> bool:
        return verify_chain(self._entries)

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "surface": "transcript_log",
            "length": len(self._entries),
            "head": self.head,
            "entries": [entry.to_public_dict() for entry in self._entries],
            "raw_secret_egress": False,
        }


def verify_chain(entries: "tuple[TranscriptEntry, ...] | list[TranscriptEntry]") -> bool:
    """Recompute the chain to confirm it is an untampered append-only log."""

    prev = _GENESIS_PREV
    for expected_index, entry in enumerate(entries):
        if entry.index != expected_index:
            return False
        if entry.prev_hash != prev:
            return False
        try:
            recomputed = _chain_step(entry.prev_hash, entry.event_hash, entry.index)
        except ValueError:  # malformed hex
            return False
        if recomputed != entry.chain_hash:
            return False
        prev = entry.chain_hash
    return True
