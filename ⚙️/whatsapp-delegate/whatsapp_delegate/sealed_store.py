"""Sealed-at-rest storage for WhatsApp message data.

Encryption: AES-256-GCM.
Key source:
  - dstack TEE: derive_key("whatsapp/messages") — deterministic per CVM
  - local dev:  WA_SEAL_KEY_HEX env var, or auto-generated .key file

The sealed blob lives at /data/messages.enc. Only the TEE can decrypt it.
Pipeline access goes through pipeline_gate, never direct file reads.
"""

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass
class WhatsAppExport:
    """Container for exported WhatsApp data."""

    phone: str
    export_ts: str  # ISO 8601
    chats: list[dict] = field(default_factory=list)
    # Each chat: {name, messages: [{sender, text, timestamp}]}

    def to_dict(self) -> dict:
        return {"phone": self.phone, "export_ts": self.export_ts, "chats": self.chats}

    @classmethod
    def from_dict(cls, d: dict) -> "WhatsAppExport":
        return cls(phone=d["phone"], export_ts=d["export_ts"], chats=d.get("chats", []))

    @property
    def total_messages(self) -> int:
        return sum(len(c.get("messages", [])) for c in self.chats)


class SealedStore:
    """AES-256-GCM encrypted message store.

    In dstack TEE, the key comes from derive_key("whatsapp/messages").
    Locally, from WA_SEAL_KEY_HEX env var or auto-generated.
    """

    def __init__(self, path: str, dstack_enabled: bool = False, key_hex: str = ""):
        self.path = Path(path) / "messages.enc"
        self._key_path = self.path.with_suffix(".key")
        self._dstack = dstack_enabled

        if dstack_enabled:
            self.key = self._derive_dstack_key()
        elif key_hex:
            self.key = bytes.fromhex(key_hex)
        elif self._key_path.exists():
            self.key = bytes.fromhex(self._key_path.read_text().strip())
            print(f"[sealed_store] loaded key from {self._key_path}")
        else:
            self.key = AESGCM.generate_key(bit_length=256)
            self._key_path.parent.mkdir(parents=True, exist_ok=True)
            self._key_path.write_text(self.key.hex())
            print(f"[sealed_store] auto-generated key → {self._key_path}")

        self._aesgcm = AESGCM(self.key)

    @staticmethod
    def _derive_dstack_key() -> bytes:
        """Derive a deterministic key from dstack KMS."""
        from dstack_sdk import DstackClient

        client = DstackClient()
        resp = client.derive_key("whatsapp/messages")
        # derive_key returns 64 hex chars (32 bytes)
        return bytes.fromhex(resp.key[:64])

    def seal(self, export: WhatsAppExport) -> None:
        """Encrypt and persist the message export."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        plaintext = json.dumps(export.to_dict()).encode()
        nonce = os.urandom(12)
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, None)
        self.path.write_bytes(nonce + ciphertext)
        print(f"[sealed_store] sealed {export.total_messages} messages for {export.phone}")

    def unseal(self) -> WhatsAppExport | None:
        """Decrypt and return the stored export, or None."""
        if not self.path.exists():
            return None
        raw = self.path.read_bytes()
        nonce, ciphertext = raw[:12], raw[12:]
        plaintext = self._aesgcm.decrypt(nonce, ciphertext, None)
        return WhatsAppExport.from_dict(json.loads(plaintext))

    def exists(self) -> bool:
        return self.path.exists()

    def delete(self) -> None:
        """Irrevocably destroy sealed data."""
        if self.path.exists():
            # Overwrite with random bytes before unlink
            size = self.path.stat().st_size
            self.path.write_bytes(os.urandom(size))
            self.path.unlink()
            print("[sealed_store] sealed data destroyed")
