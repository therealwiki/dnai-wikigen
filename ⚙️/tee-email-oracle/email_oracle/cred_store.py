"""Encrypted credential storage."""

import json
import os
import hashlib
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from email_oracle.dstack_utils import derive_storage_key


@dataclass
class EmailCredentials:
    username: str
    domain: str
    password: str

    @property
    def email(self) -> str:
        return f"{self.username}@{self.domain}"

    @property
    def imap_login(self) -> str:
        return self.email

    def to_dict(self) -> dict:
        return {"username": self.username, "domain": self.domain, "password": self.password}

    @classmethod
    def from_dict(cls, d: dict) -> "EmailCredentials":
        return cls(username=d["username"], domain=d["domain"], password=d["password"])


class CredentialStore:
    """AES-256-GCM encrypted credential file.

    In dstack TEE, the key is derived deterministically from dstack KMS.
    Locally, it's from ORACLE_CRED_STORE_KEY env var or auto-generated.
    Auto-generated keys are persisted to a .key file next to credentials.
    """

    def __init__(
        self,
        path: str,
        key_hex: str = "",
        *,
        dstack_enabled: bool = False,
        dstack_key_path: str = "email/creds",
    ):
        self.path = Path(path)
        self._key_path = self.path.with_suffix(".key")

        if key_hex:
            self.key = bytes.fromhex(key_hex)
        elif dstack_enabled:
            self.key = derive_storage_key(dstack_key_path)
            print(f"[cred_store] derived storage key from dstack path {dstack_key_path}")
        elif self._key_path.exists():
            # Load previously auto-generated key
            self.key = bytes.fromhex(self._key_path.read_text().strip())
            print(f"[cred_store] loaded key from {self._key_path}")
        else:
            # Auto-generate and persist (local dev only)
            self.key = AESGCM.generate_key(bit_length=256)
            self._key_path.parent.mkdir(parents=True, exist_ok=True)
            self._key_path.write_text(self.key.hex())
            print(f"[cred_store] auto-generated and saved key to {self._key_path}")

        self._aesgcm = AESGCM(self.key)

    def save(self, creds: EmailCredentials) -> None:
        """Encrypt and save credentials."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        plaintext = json.dumps(creds.to_dict()).encode()
        nonce = os.urandom(12)
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, None)
        self.path.write_bytes(nonce + ciphertext)
        email_hash = hashlib.sha256(creds.email.encode("utf-8")).hexdigest()
        print(f"[cred_store] saved credentials email_hash={email_hash}")

    def load(self) -> EmailCredentials | None:
        """Load and decrypt credentials, or None if not found."""
        if not self.path.exists():
            return None
        raw = self.path.read_bytes()
        nonce, ciphertext = raw[:12], raw[12:]
        plaintext = self._aesgcm.decrypt(nonce, ciphertext, None)
        return EmailCredentials.from_dict(json.loads(plaintext))

    def exists(self) -> bool:
        return self.path.exists()
