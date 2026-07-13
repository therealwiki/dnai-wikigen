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
    client = _client()
    info = client.info()
    quote = client.get_quote(_normalize_report_data(report_data))
    tcb_info = info.tcb_info.model_dump() if hasattr(info.tcb_info, "model_dump") else {}
    return {
        "quote": quote.quote,
        "event_log": quote.event_log,
        "quote_report_data": quote.report_data,
        "vm_config": quote.vm_config,
        "app_id": info.app_id,
        "instance_id": info.instance_id,
        "app_name": info.app_name,
        "device_id": info.device_id,
        "mr_aggregated": info.mr_aggregated,
        "os_image_hash": info.os_image_hash,
        "compose_hash": info.compose_hash,
        "tcb_info": tcb_info,
    }
