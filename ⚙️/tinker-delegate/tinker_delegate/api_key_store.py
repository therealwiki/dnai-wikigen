"""Encrypted storage for the Tinker API key."""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from tinker_delegate.config import Settings
from tinker_delegate.dstack_utils import derive_storage_key, is_dstack_enabled
from tinker_delegate.secure_secret_file import (
    load_or_create_secure_secret_file,
    read_secure_secret_file,
    secure_secret_file_exists,
    write_secure_secret_file,
)


_WRAPPING_KEY_HEX_BYTES = 64
_ENCRYPTED_API_KEY_MIN_BYTES = 29
_ENCRYPTED_API_KEY_MAX_BYTES = 4 * 1024


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
            self.key = _storage_key(key_hex)
        elif dstack_enabled:
            self.key = _storage_key(derive_storage_key(dstack_key_path))
            print(f"[api_key_store] derived storage key from dstack path {dstack_key_path}")
        else:
            key_hex_bytes, created = load_or_create_secure_secret_file(
                self._key_path,
                lambda: AESGCM.generate_key(bit_length=256).hex().encode("ascii"),
                exact_size=_WRAPPING_KEY_HEX_BYTES,
            )
            self.key = _storage_key(key_hex_bytes)
            if created:
                print(f"[api_key_store] auto-generated and saved key to {self._key_path}")
            else:
                print(f"[api_key_store] loaded key from {self._key_path}")

        self._aesgcm = AESGCM(self.key)

    def exists(self) -> bool:
        return secure_secret_file_exists(
            self.path,
            minimum=_ENCRYPTED_API_KEY_MIN_BYTES,
            maximum=_ENCRYPTED_API_KEY_MAX_BYTES,
        )

    def save(self, api_key: str) -> None:
        nonce = os.urandom(12)
        ciphertext = self._aesgcm.encrypt(nonce, api_key.encode(), None)
        write_secure_secret_file(
            self.path,
            nonce + ciphertext,
            minimum=_ENCRYPTED_API_KEY_MIN_BYTES,
            maximum=_ENCRYPTED_API_KEY_MAX_BYTES,
        )
        print(f"[api_key_store] saved encrypted API key to {self.path}")

    def load(self) -> str | None:
        try:
            raw = read_secure_secret_file(
                self.path,
                minimum=_ENCRYPTED_API_KEY_MIN_BYTES,
                maximum=_ENCRYPTED_API_KEY_MAX_BYTES,
            )
        except FileNotFoundError:
            return None
        nonce, ciphertext = raw[:12], raw[12:]
        return self._aesgcm.decrypt(nonce, ciphertext, None).decode()


def _storage_key(value: str | bytes) -> bytes:
    if isinstance(value, bytes) and len(value) == 32:
        return bytes(value)
    try:
        key = bytes.fromhex(value.decode("ascii") if isinstance(value, bytes) else value)
    except (UnicodeDecodeError, ValueError):
        raise ValueError("Tinker API-key storage key is invalid") from None
    if len(key) != 32:
        raise ValueError("Tinker API-key storage key must be 32 bytes")
    return key


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
        and not secure_secret_file_exists(
            settings.api_key_store_path,
            minimum=_ENCRYPTED_API_KEY_MIN_BYTES,
            maximum=_ENCRYPTED_API_KEY_MAX_BYTES,
        )
    ):
        return ""

    store = build_api_key_store(settings)
    return store.load() or ""
