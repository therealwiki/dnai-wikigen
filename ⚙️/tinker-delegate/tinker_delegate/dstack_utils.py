"""Helpers for dstack-backed storage and attestation."""

from __future__ import annotations

import hashlib
import os
from typing import Any

from dstack_sdk import DstackClient


def _client() -> DstackClient:
    endpoint = os.environ.get("DSTACK_SIMULATOR_ENDPOINT", "").strip()
    if endpoint:
        return DstackClient(endpoint)
    return DstackClient()


def is_dstack_enabled() -> bool:
    raw = os.environ.get("DSTACK_ENABLED") or os.environ.get("TINKER_DSTACK_ENABLED") or "false"
    return raw.lower() == "true"


def is_dstack_simulator() -> bool:
    """Return whether dstack calls are routed to modeled simulator evidence."""

    return bool(os.environ.get("DSTACK_SIMULATOR_ENDPOINT", "").strip())


def _normalize_report_data(report_data: str | bytes) -> bytes:
    raw = report_data.encode() if isinstance(report_data, str) else report_data
    if len(raw) <= 64:
        return raw
    return hashlib.sha256(raw).digest()


def derive_storage_key(path: str) -> bytes:
    client = _client()
    result = client.get_key(path, "encryption")
    return result.decode_key()[:32]


def get_attestation(report_data: str | bytes) -> tuple[str, str, str]:
    details = get_attestation_details(report_data)
    return details["quote"], details["app_id"], details["compose_hash"]


def get_attestation_details(report_data: str | bytes) -> dict[str, Any]:
    """Return only the bounded dstack evidence used by in-process consumers.

    ``client.info()`` also exposes raw TCB metadata, including a rendered
    application compose.  Rendered compose data can contain resolved runtime
    environment values, so it must never be collected into this return value or
    become reachable from a public API response.
    """
    client = _client()
    info = client.info()
    quote = client.get_quote(_normalize_report_data(report_data))
    return {
        "quote": quote.quote,
        "quote_report_data": quote.report_data,
        "app_id": info.app_id,
        "os_image_hash": info.os_image_hash,
        "compose_hash": info.compose_hash,
    }
