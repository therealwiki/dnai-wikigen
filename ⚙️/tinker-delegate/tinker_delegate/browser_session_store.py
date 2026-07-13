"""Encrypted storage for Tinker browser session state."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from tinker_delegate.config import Settings
from tinker_delegate.dstack_utils import derive_storage_key, is_dstack_enabled


class BrowserSessionStore:
    """Persist Playwright storage_state under local or dstack-derived encryption."""

    def __init__(
        self,
        path: str,
        key_hex: str = "",
        *,
        dstack_enabled: bool = False,
        dstack_key_path: str = "tinker/browser_session",
    ):
        self.path = Path(path)
        self._key_path = self.path.with_suffix(".key")

        if key_hex:
            self.key = bytes.fromhex(key_hex)
        elif dstack_enabled:
            self.key = derive_storage_key(dstack_key_path)
            print(f"[browser_session_store] derived storage key from dstack path {dstack_key_path}")
        elif self._key_path.exists():
            self.key = bytes.fromhex(self._key_path.read_text().strip())
            print(f"[browser_session_store] loaded key from {self._key_path}")
        else:
            self.key = AESGCM.generate_key(bit_length=256)
            self._key_path.parent.mkdir(parents=True, exist_ok=True)
            self._key_path.write_text(self.key.hex())
            print(f"[browser_session_store] auto-generated and saved key to {self._key_path}")

        self._aesgcm = AESGCM(self.key)

    def exists(self) -> bool:
        return self.path.exists()

    def save(self, storage_state: dict[str, Any]) -> None:
        """Encrypt Playwright storage_state without logging cookie/localStorage values."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        plaintext = json.dumps(storage_state, sort_keys=True, separators=(",", ":")).encode()
        nonce = os.urandom(12)
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, None)
        tmp_path = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp_path.write_bytes(nonce + ciphertext)
        tmp_path.replace(self.path)
        print(f"[browser_session_store] saved encrypted browser session to {self.path}")

    def load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None
        raw = self.path.read_bytes()
        nonce, ciphertext = raw[:12], raw[12:]
        plaintext = self._aesgcm.decrypt(nonce, ciphertext, None)
        state = json.loads(plaintext)
        if not isinstance(state, dict):
            raise ValueError("browser session storage_state must decode to an object")
        return state


def build_browser_session_store(settings: Settings) -> BrowserSessionStore:
    return BrowserSessionStore(
        settings.browser_session_store_path,
        settings.browser_session_store_key,
        dstack_enabled=is_dstack_enabled(),
        dstack_key_path=settings.browser_session_key_path,
    )
