"""Encrypted replay ledger for released OTP hashes."""

import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from email_oracle.dstack_utils import derive_storage_key


class OtpReplayStore:
    """Persist released OTP-use hashes under local or dstack-derived encryption."""

    def __init__(
        self,
        path: str,
        key_hex: str = "",
        *,
        dstack_enabled: bool = False,
        dstack_key_path: str = "email/otp_replay",
    ):
        self.path = Path(path)
        self._key_path = self.path.with_suffix(".key")

        if key_hex:
            self.key = bytes.fromhex(key_hex)
        elif dstack_enabled:
            self.key = derive_storage_key(dstack_key_path)
            print(f"[replay_store] derived storage key from dstack path {dstack_key_path}")
        elif self._key_path.exists():
            self.key = bytes.fromhex(self._key_path.read_text().strip())
            print(f"[replay_store] loaded key from {self._key_path}")
        else:
            self.key = AESGCM.generate_key(bit_length=256)
            self._key_path.parent.mkdir(parents=True, exist_ok=True)
            self._key_path.write_text(self.key.hex())
            print(f"[replay_store] auto-generated and saved key to {self._key_path}")

        self._aesgcm = AESGCM(self.key)

    def load(self) -> set[str]:
        """Load the replay ledger, or return an empty set if it does not exist."""
        if not self.path.exists():
            return set()
        raw = self.path.read_bytes()
        nonce, ciphertext = raw[:12], raw[12:]
        plaintext = self._aesgcm.decrypt(nonce, ciphertext, None)
        data = json.loads(plaintext)
        return set(data.get("used_otp_hashes", []))

    def save(self, used_otp_hashes: set[str]) -> None:
        """Encrypt and atomically save the replay ledger."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        plaintext = json.dumps(
            {"used_otp_hashes": sorted(used_otp_hashes)},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        nonce = os.urandom(12)
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, None)
        tmp_path = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp_path.write_bytes(nonce + ciphertext)
        tmp_path.replace(self.path)
