"""Secure, duplicate-free loading of an externally mounted release policy."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from .errors import QvlServiceError, VerifierUnavailable
from .models import MAX_POLICY_BYTES, ReleasePolicy


@dataclass(frozen=True)
class LoadedReleasePolicy:
    policy: ReleasePolicy
    canonical_bytes: bytes
    policy_hash: str


def _reject_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON object key")
        value[key] = item
    return value


def parse_duplicate_free_json(raw: bytes) -> Any:
    try:
        text = raw.decode("utf-8", errors="strict")
        return json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise VerifierUnavailable from exc


def validate_release_policy_bytes(raw: bytes) -> LoadedReleasePolicy:
    if len(raw) < 2 or len(raw) > MAX_POLICY_BYTES:
        raise VerifierUnavailable
    decoded = parse_duplicate_free_json(raw)
    try:
        policy = ReleasePolicy.model_validate(decoded, strict=True)
    except ValidationError as exc:
        raise VerifierUnavailable from exc
    canonical = json.dumps(
        policy.model_dump(mode="json", by_alias=True),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    if len(canonical) > MAX_POLICY_BYTES:
        raise VerifierUnavailable
    return LoadedReleasePolicy(
        policy=policy,
        canonical_bytes=canonical,
        policy_hash="0x" + hashlib.sha256(canonical).hexdigest(),
    )


def _read_secure_regular_file(path_value: str) -> bytes:
    if "\x00" in path_value:
        raise VerifierUnavailable
    path = Path(path_value)
    if not path.is_absolute():
        raise VerifierUnavailable
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise VerifierUnavailable from exc
    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
        raise VerifierUnavailable
    if before.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise VerifierUnavailable
    if before.st_size < 2 or before.st_size > MAX_POLICY_BYTES:
        raise VerifierUnavailable

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or (opened.st_mode & (stat.S_IWGRP | stat.S_IWOTH))
                or opened.st_dev != before.st_dev
                or opened.st_ino != before.st_ino
            ):
                raise VerifierUnavailable
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(descriptor, min(8192, MAX_POLICY_BYTES + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > MAX_POLICY_BYTES:
                    raise VerifierUnavailable
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
                raise VerifierUnavailable
            return raw
        finally:
            os.close(descriptor)
    except QvlServiceError:
        raise
    except OSError as exc:
        raise VerifierUnavailable from exc


def load_release_policy(path: str) -> LoadedReleasePolicy:
    return validate_release_policy_bytes(_read_secure_regular_file(path))
