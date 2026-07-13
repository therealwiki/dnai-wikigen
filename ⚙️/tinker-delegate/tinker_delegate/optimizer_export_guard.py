"""Leakage-bound guard for optimizer state / updates leaving the TEE boundary.

PROJECT.md and the private-reward invariants require that if optimization updates
leave the attested boundary, they must be proven not to encode private
reward/data; otherwise optimizer state and reward-derived gradients stay inside.
The `private_reward` reducer and `private_reward_loop` already keep *their* egress
bounded by construction, but nothing enforced that an arbitrary "publish this
optimizer export" payload is safe. This module is that enforcement gate.

An export is admitted only if it contains none of the realistic reward/data
leakage vectors:

* ``float`` anywhere — exact reward values and reward-derived gradients are
  floats; bounded egress is bands (strings), decisions, hashes, and counts (ints).
  Banning floats is the crux of "reward-derived values do not leave".
* numeric arrays longer than a small cap — gradient vectors, weight tensors, or
  embeddings, even if integer-encoded.
* a single integer wider than 256 bits — one unbounded scalar int can encode an
  entire sealed blob (``int.from_bytes(...)``) without tripping the array cap.
* an aggregate integer payload over 512 bytes — many separately-small int fields
  summing to a bulk exfiltration (bounds, does not eliminate, the channel).
* oversized hex/byte blobs — could carry raw sealed data rather than a hash.
* secret-shaped material (via the shared ``redact_text`` detector).
* a truthy ``raw_secret_egress`` self-declaration.

Output is a bounded ``ExportAuditResult`` (allowed flag, reason code, offending
field *paths* — never values, counts, and a deterministic leakage hash).
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from tinker_delegate.redaction import redact_text

_MAX_NUMERIC_ARRAY_LEN = 8
_MAX_BLOB_HEX_CHARS = 512  # 256 bytes; a bytes32 hash is 64 hex + "0x"
# A single Python int is otherwise unbounded: `int.from_bytes(sealed_blob)` is one
# scalar int that the array cap never sees. Every legitimate bounded integer —
# counts, score bands, unix expiries, nonces, and even uint256 wei amounts / hashes
# carried as ints — fits in 256 bits; anything larger is a data payload, not a
# bounded value, so it fails closed.
_MAX_INT_BITS = 256
# Even with per-scalar (256-bit) and per-array (<=8) bounds, many separately-small
# int fields could aggregate a bulk payload. Cap the TOTAL integer byte-width
# across the whole export (all int leaves, array elements, and dict keys). Real
# bounded exports carry only a few dozen int-bytes (a LoopOutcome export is ~23);
# 512 bytes leaves >20x headroom while making KB-MB tensor/dataset exfiltration via
# aggregated integers infeasible. This bounds — does not eliminate — the channel.
_MAX_TOTAL_INT_BYTES = 512
# Real bounded outputs nest only a few levels; anything past this is a hostile /
# malformed structure and fails closed instead of raising RecursionError.
_MAX_EXPORT_DEPTH = 64


class ExportLeakageError(ValueError):
    """Raised when an optimizer export would leak reward-derived material."""


@dataclass(frozen=True)
class ExportAuditResult:
    allowed: bool
    reason_code: str
    offending_field_paths: tuple[str, ...]
    field_count: int
    leakage_hash: str
    raw_secret_egress: bool = False

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason_code": self.reason_code,
            "offending_field_paths": list(self.offending_field_paths),
            "field_count": self.field_count,
            "leakage_hash": self.leakage_hash,
            "raw_secret_egress": self.raw_secret_egress,
        }


def audit_optimizer_export(
    payload: Any,
    *,
    max_numeric_array_len: int = _MAX_NUMERIC_ARRAY_LEN,
    max_blob_hex_chars: int = _MAX_BLOB_HEX_CHARS,
    max_total_int_bytes: int = _MAX_TOTAL_INT_BYTES,
) -> ExportAuditResult:
    """Audit a proposed optimizer export for reward/data leakage.

    Returns a bounded result; never raises for a leaky payload (use
    ``certify_optimizer_export`` for the fail-closed variant).
    """
    float_paths: list[str] = []
    array_paths: list[str] = []
    blob_paths: list[str] = []
    big_int_paths: list[str] = []
    disallowed_paths: list[str] = []
    too_deep_paths: list[str] = []
    field_count = 0
    total_int_bytes = 0

    def _walk(node: Any, path: str, depth: int = 0) -> None:
        nonlocal field_count, total_int_bytes
        field_count += 1
        # Bound recursion: a hostile reducer sending a deeply nested structure
        # must fail closed with a clean rejection, not an uncontrolled
        # RecursionError. Real bounded outputs are only a few levels deep.
        if depth > _MAX_EXPORT_DEPTH:
            too_deep_paths.append(path)
            return
        # bool must be checked before int (bool is a subclass of int).
        if isinstance(node, bool) or node is None:
            return
        if isinstance(node, float):
            float_paths.append(path)
            return
        if isinstance(node, int):
            # Bound scalar-int magnitude: a single unbounded int can carry an
            # entire sealed blob (`int.from_bytes(...)`) without ever tripping the
            # per-array numeric cap. Sign is irrelevant — bit_length is magnitude.
            if node.bit_length() > _MAX_INT_BITS:
                big_int_paths.append(path)
            # Accumulate this int's byte-width toward the aggregate budget so many
            # separately-small int fields cannot sum to a bulk exfiltration.
            total_int_bytes += max(1, (node.bit_length() + 7) // 8)
            return
        if isinstance(node, bytes):
            if len(node) * 2 > max_blob_hex_chars:
                blob_paths.append(path)
            return
        if isinstance(node, str):
            if _is_hexish(node) and len(node) > max_blob_hex_chars:
                blob_paths.append(path)
            return
        if isinstance(node, dict):
            for key, value in node.items():
                # Walk the KEY too: a Python dict may key on a float / int / blob
                # (JSON stringifies it on egress), so a reward smuggled as a key
                # must be caught by the same structural bans as a value.
                _walk(key, f"{path}.<key:{key}>" if path else f"<key:{key}>", depth + 1)
                _walk(value, f"{path}.{key}" if path else str(key), depth + 1)
            return
        if isinstance(node, (list, tuple)):
            numeric_children = sum(
                1 for item in node if isinstance(item, (int, float)) and not isinstance(item, bool)
            )
            if numeric_children > max_numeric_array_len:
                array_paths.append(path)
            for index, item in enumerate(node):
                _walk(item, f"{path}[{index}]", depth + 1)
            return
        # Any other type is not a bounded egress value.
        disallowed_paths.append(path)

    _walk(payload, "")

    declared_egress = bool(payload.get("raw_secret_egress")) if isinstance(payload, dict) else False

    # Priority order: the most severe / most specific reason first.
    reason = "ok"
    offending: tuple[str, ...] = ()
    if too_deep_paths:
        reason, offending = "structure_too_deep", tuple(too_deep_paths)
    elif declared_egress:
        reason, offending = "reward_egress_flag", ("raw_secret_egress",)
    elif float_paths:
        reason, offending = "float_value", tuple(float_paths)
    elif array_paths:
        reason, offending = "numeric_array", tuple(array_paths)
    elif blob_paths:
        reason, offending = "oversized_blob", tuple(blob_paths)
    elif big_int_paths:
        reason, offending = "oversized_int", tuple(big_int_paths)
    elif total_int_bytes > max_total_int_bytes:
        reason, offending = "aggregate_int_payload", ()
    elif disallowed_paths:
        reason, offending = "disallowed_type", tuple(disallowed_paths)
    else:
        try:
            rendered = json.dumps(payload, sort_keys=True, default=str)
        except (TypeError, ValueError):
            rendered = str(payload)
        if redact_text(rendered) != rendered:
            reason, offending = "secret_shaped", ()

    allowed = reason == "ok"
    leakage_hash = _leakage_hash(reason, offending, field_count)
    return ExportAuditResult(
        allowed=allowed,
        reason_code=reason,
        offending_field_paths=offending,
        field_count=field_count,
        leakage_hash=leakage_hash,
        raw_secret_egress=False,
    )


def certify_optimizer_export(payload: Any, **kwargs: Any) -> ExportAuditResult:
    """Fail-closed variant: raise ExportLeakageError unless the export is safe."""
    result = audit_optimizer_export(payload, **kwargs)
    if not result.allowed:
        raise ExportLeakageError(
            f"optimizer export rejected: {result.reason_code}"
        )
    return result


def _is_hexish(value: str) -> bool:
    body = value[2:] if value.startswith(("0x", "0X")) else value
    return len(body) >= 8 and all(c in "0123456789abcdefABCDEF" for c in body)


def _leakage_hash(reason: str, offending: tuple[str, ...], field_count: int) -> str:
    canonical = json.dumps(
        {"reason": reason, "offending": sorted(offending), "field_count": field_count},
        sort_keys=True,
        separators=(",", ":"),
    )
    return "0x" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
