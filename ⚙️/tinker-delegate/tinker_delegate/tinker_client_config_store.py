"""Encrypted storage for Tinker SDK client configuration."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from tinker_delegate.config import Settings
from tinker_delegate.dstack_utils import derive_storage_key, is_dstack_enabled
from tinker_delegate.run_metadata_store import stable_hash


class TinkerClientConfigStore:
    """Persist Tinker project/base-url config under local or dstack encryption."""

    def __init__(
        self,
        path: str,
        key_hex: str = "",
        *,
        dstack_enabled: bool = False,
        dstack_key_path: str = "tinker/client_config",
    ):
        self.path = Path(path)
        self._key_path = self.path.with_suffix(".key")
        self.key_source = "local_generated"

        if key_hex:
            self.key = bytes.fromhex(key_hex)
            self.key_source = "explicit_env"
        elif dstack_enabled:
            self.key = derive_storage_key(dstack_key_path)
            self.key_source = "dstack_derived"
            print(f"[client_config_store] derived storage key from dstack path {dstack_key_path}")
        elif self._key_path.exists():
            self.key = bytes.fromhex(self._key_path.read_text().strip())
            self.key_source = "local_key_file"
            print(f"[client_config_store] loaded key from {self._key_path}")
        else:
            self.key = AESGCM.generate_key(bit_length=256)
            self._key_path.parent.mkdir(parents=True, exist_ok=True)
            self._key_path.write_text(self.key.hex())
            print(f"[client_config_store] auto-generated and saved key to {self._key_path}")

        self._aesgcm = AESGCM(self.key)

    def exists(self) -> bool:
        return self.path.exists()

    def save(self, *, project_id: str = "", base_url: str = "") -> dict[str, Any]:
        payload = _normalize_client_config(project_id=project_id, base_url=base_url)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        nonce = os.urandom(12)
        plaintext = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, None)
        tmp_path = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp_path.write_bytes(nonce + ciphertext)
        tmp_path.replace(self.path)
        return payload

    def load(self) -> dict[str, str]:
        if not self.path.exists():
            return {"project_id": "", "base_url": ""}
        raw = self.path.read_bytes()
        nonce, ciphertext = raw[:12], raw[12:]
        data = json.loads(self._aesgcm.decrypt(nonce, ciphertext, None))
        return _normalize_client_config(
            project_id=str(data.get("project_id", "")),
            base_url=str(data.get("base_url", "")),
        )


def build_tinker_client_config_store(settings: Settings) -> TinkerClientConfigStore:
    return TinkerClientConfigStore(
        settings.client_config_store_path,
        settings.client_config_store_key,
        dstack_enabled=is_dstack_enabled(),
        dstack_key_path=settings.client_config_key_path,
    )


def resolve_tinker_client_config(settings: Settings) -> dict[str, str]:
    """Resolve SDK client config without creating a local store as a side effect."""

    env_config = _normalize_client_config(
        project_id=getattr(settings, "project_id", ""),
        base_url=getattr(settings, "base_url", ""),
    )
    needs_store = not env_config["project_id"] or not env_config["base_url"]
    store_config = {"project_id": "", "base_url": ""}
    store_path = Path(settings.client_config_store_path)
    if needs_store and (
        settings.client_config_store_key
        or store_path.exists()
        or is_dstack_enabled()
    ):
        store_config = build_tinker_client_config_store(settings).load()
    return {
        "project_id": env_config["project_id"] or store_config["project_id"],
        "base_url": env_config["base_url"] or store_config["base_url"],
    }


def save_tinker_client_config(
    settings: Settings,
    *,
    project_id: str = "",
    base_url: str = "",
) -> dict[str, Any]:
    saved = build_tinker_client_config_store(settings).save(project_id=project_id, base_url=base_url)
    return build_tinker_client_config_status(settings, saved=saved, surface="tinker_client_config_install")


def build_tinker_client_config_status(
    settings: Settings,
    *,
    saved: dict[str, str] | None = None,
    surface: str = "tinker_client_config",
) -> dict[str, Any]:
    store_path = Path(settings.client_config_store_path)
    configured = saved if saved is not None else resolve_tinker_client_config(settings)
    project_id = configured["project_id"]
    base_url = configured["base_url"]
    store_exists = store_path.exists()
    return {
        "surface": surface,
        "schema_version": 1,
        "success": True,
        "client_config": {
            "project_id_configured": bool(project_id),
            "project_id_hash": stable_hash(project_id, prefix="tinker_project") if project_id else "",
            "project_id_returned": False,
            "base_url_configured": bool(base_url),
            "base_url_host_family": _base_url_host_family(base_url),
            "base_url_hash": stable_hash(base_url, prefix="tinker_base_url") if base_url else "",
            "base_url_returned": False,
        },
        "store": {
            "encrypted": True,
            "exists": store_exists or saved is not None,
            "key_source": _store_key_source(settings, store_exists=store_exists),
            "path_returned": False,
        },
        "next_required_configuration": _next_required_configuration(project_id_configured=bool(project_id)),
        "raw_secret_egress": False,
    }


def _normalize_client_config(*, project_id: str = "", base_url: str = "") -> dict[str, str]:
    project_id = str(project_id or "").strip()
    base_url = str(base_url or "").strip()
    if any(ch.isspace() for ch in project_id):
        raise ValueError("Tinker project id must not contain whitespace")
    if len(project_id) > 256:
        raise ValueError("Tinker project id is too long")
    if base_url:
        parsed = urlparse(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("Tinker base URL must be http(s)")
        if parsed.username or parsed.password:
            raise ValueError("Tinker base URL must not contain credentials")
        if len(base_url) > 512:
            raise ValueError("Tinker base URL is too long")
    return {"project_id": project_id, "base_url": base_url}


def _store_key_source(settings: Settings, *, store_exists: bool) -> str:
    if settings.client_config_store_key:
        return "explicit_env"
    if is_dstack_enabled():
        return "dstack_derived"
    if store_exists:
        return "local_key_file"
    return "not_initialized"


def _base_url_host_family(base_url: str) -> str:
    if not base_url:
        return "sdk_default"
    host = urlparse(base_url).hostname or ""
    if host.endswith("thinkingmachines.dev") or host.endswith("thinkingmachines.ai"):
        return "thinkingmachines"
    if host in {"localhost", "127.0.0.1", "::1"}:
        return "local"
    return "custom"


def _next_required_configuration(*, project_id_configured: bool) -> list[str]:
    if project_id_configured:
        return []
    return ["seal_tinker_project_id_in_delegate_if_provider_requires_it"]
