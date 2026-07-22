"""Canonical loading of one immutable multi-asset metering policy set."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from eth_utils import keccak
from pydantic import ValidationError

from .errors import MeteringError, PolicyRejected, StateUnavailable
from .models import AssetRatePolicy, MAX_POLICY_BYTES, MeteringPolicySet


RATE_CARD_DOMAIN = b"dnai-wikigen/compute-rate-card/v1\x00"


@dataclass(frozen=True)
class LoadedPolicySet:
    policy: MeteringPolicySet
    canonical_bytes: bytes
    policy_set_hash: str


def _reject_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def parse_duplicate_free_json(raw: bytes) -> Any:
    try:
        text = raw.decode("utf-8", errors="strict")
        return json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise PolicyRejected from exc


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def rate_card_payload(asset_policy: AssetRatePolicy, *, developer_fee_bps: int) -> dict[str, object]:
    return {
        "schema": "dnai.compute-rate-card.v1",
        "asset": asset_policy.asset,
        "developer_fee_bps": developer_fee_bps,
        "provider": asset_policy.provider,
        "rates": [entry.model_dump(mode="json") for entry in asset_policy.rates],
        "limits": asset_policy.limits.model_dump(mode="json"),
    }


def compute_rate_policy_commitment(asset_policy: AssetRatePolicy, *, developer_fee_bps: int) -> str:
    payload = rate_card_payload(asset_policy, developer_fee_bps=developer_fee_bps)
    return "0x" + keccak(RATE_CARD_DOMAIN + canonical_json_bytes(payload)).hex()


def validate_policy_set_bytes(raw: bytes) -> LoadedPolicySet:
    if len(raw) < 2 or len(raw) > MAX_POLICY_BYTES:
        raise PolicyRejected
    decoded = parse_duplicate_free_json(raw)
    try:
        policy = MeteringPolicySet.model_validate(decoded, strict=True)
    except ValidationError as exc:
        raise PolicyRejected from exc
    for entry in policy.asset_policies:
        if (
            compute_rate_policy_commitment(entry, developer_fee_bps=policy.developer_fee_bps)
            != entry.rate_policy_commitment
        ):
            raise PolicyRejected
    canonical = canonical_json_bytes(policy.model_dump(mode="json", by_alias=True))
    if len(canonical) > MAX_POLICY_BYTES:
        raise PolicyRejected
    return LoadedPolicySet(
        policy=policy,
        canonical_bytes=canonical,
        policy_set_hash="0x" + hashlib.sha256(canonical).hexdigest(),
    )


def _read_secure_regular_file(path_value: str) -> bytes:
    if "\x00" in path_value:
        raise StateUnavailable
    path = Path(path_value)
    if not path.is_absolute():
        raise StateUnavailable
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise StateUnavailable from exc
    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
        raise StateUnavailable
    if before.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise StateUnavailable
    if before.st_size < 2 or before.st_size > MAX_POLICY_BYTES:
        raise StateUnavailable

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                or opened.st_dev != before.st_dev
                or opened.st_ino != before.st_ino
            ):
                raise StateUnavailable
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(descriptor, min(8192, MAX_POLICY_BYTES + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > MAX_POLICY_BYTES:
                    raise StateUnavailable
            raw = b"".join(chunks)
            after = os.fstat(descriptor)
            if (
                len(raw) < 2
                or len(raw) != opened.st_size
                or after.st_size != opened.st_size
                or after.st_mtime_ns != opened.st_mtime_ns
                or after.st_ctime_ns != opened.st_ctime_ns
                or after.st_dev != opened.st_dev
                or after.st_ino != opened.st_ino
            ):
                raise StateUnavailable
            return raw
        finally:
            os.close(descriptor)
    except MeteringError:
        raise
    except OSError as exc:
        raise StateUnavailable from exc


def load_policy_set(path: str) -> LoadedPolicySet:
    try:
        return validate_policy_set_bytes(_read_secure_regular_file(path))
    except PolicyRejected as exc:
        raise StateUnavailable from exc
