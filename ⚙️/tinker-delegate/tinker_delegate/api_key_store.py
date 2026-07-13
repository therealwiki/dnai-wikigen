"""Encrypted storage for the Tinker API key."""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from tinker_delegate.config import Settings
from tinker_delegate.dstack_utils import derive_storage_key, is_dstack_enabled


class ApiKeyStore:
    def __init__(
        self,
        path: str,
        key_hex: str = "",
        *,
        dstack_enabled: bool = False,
        dstack_key_path: str = "tinker/api_key",
    ):
        self.path = Path(path)
        self._key_path = self.path.with_suffix(".key")

        if key_hex:
            self.key = bytes.fromhex(key_hex)
        elif dstack_enabled:
            self.key = derive_storage_key(dstack_key_path)
            print(f"[api_key_store] derived storage key from dstack path {dstack_key_path}")
        elif self._key_path.exists():
            self.key = bytes.fromhex(self._key_path.read_text().strip())
            print(f"[api_key_store] loaded key from {self._key_path}")
        else:
            self.key = AESGCM.generate_key(bit_length=256)
            self._key_path.parent.mkdir(parents=True, exist_ok=True)
            self._key_path.write_text(self.key.hex())
            print(f"[api_key_store] auto-generated and saved key to {self._key_path}")

        self._aesgcm = AESGCM(self.key)

    def exists(self) -> bool:
        return self.path.exists()

    def save(self, api_key: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        nonce = os.urandom(12)
        ciphertext = self._aesgcm.encrypt(nonce, api_key.encode(), None)
        self.path.write_bytes(nonce + ciphertext)
        print(f"[api_key_store] saved encrypted API key to {self.path}")

    def load(self) -> str | None:
        if not self.path.exists():
            return None
        raw = self.path.read_bytes()
        nonce, ciphertext = raw[:12], raw[12:]
        return self._aesgcm.decrypt(nonce, ciphertext, None).decode()


def build_api_key_store(settings: Settings) -> ApiKeyStore:
    return ApiKeyStore(
        settings.api_key_store_path,
        settings.api_key_store_key,
        dstack_enabled=is_dstack_enabled(),
        dstack_key_path=settings.dstack_key_path,
    )


def resolve_api_key(settings: Settings) -> str:
    api_key = os.environ.get("TINKER_API_KEY", "")
    if api_key:
        return api_key

    if (
        not is_dstack_enabled()
        and not settings.api_key_store_key
        and not Path(settings.api_key_store_path).exists()
    ):
        return ""

    store = build_api_key_store(settings)
    return store.load() or ""
