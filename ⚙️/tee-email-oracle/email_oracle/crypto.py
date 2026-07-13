"""X25519 + AES-256-GCM helpers for oracle credential ingress."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


ORACLE_CREDENTIALS_HKDF_INFO = b"tee-email-oracle-credentials"
NONCE_SIZE = 12


@dataclass(frozen=True)
class EncryptedPayload:
    """Hex-encoded X25519/AES-GCM wire payload."""

    ephemeral_public_key: bytes
    nonce: bytes
    ciphertext: bytes

    @classmethod
    def from_hex(cls, data: dict[str, str]) -> "EncryptedPayload":
        return cls(
            ephemeral_public_key=bytes.fromhex(data["ephemeral_public_key"]),
            nonce=bytes.fromhex(data["nonce"]),
            ciphertext=bytes.fromhex(data["ciphertext"]),
        )

    def to_hex(self) -> dict[str, str]:
        return {
            "ephemeral_public_key": self.ephemeral_public_key.hex(),
            "nonce": self.nonce.hex(),
            "ciphertext": self.ciphertext.hex(),
        }


def _derive_aes_key(shared_secret: bytes, info: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    ).derive(shared_secret)


class TEEKeyPair:
    """Ephemeral in-memory ingress keypair whose public key is bound to attestation."""

    def __init__(self) -> None:
        self._private = X25519PrivateKey.generate()
        self.public_key_bytes = self._private.public_key().public_bytes_raw()

    def decrypt(
        self,
        payload: EncryptedPayload,
        *,
        info: bytes,
        associated_data: bytes | None = None,
    ) -> bytes:
        sender_public = X25519PublicKey.from_public_bytes(payload.ephemeral_public_key)
        shared_secret = self._private.exchange(sender_public)
        aes_key = _derive_aes_key(shared_secret, info)
        return AESGCM(aes_key).decrypt(payload.nonce, payload.ciphertext, associated_data)


def encrypt_for_tee(
    plaintext: bytes | bytearray,
    tee_public_key: bytes,
    *,
    info: bytes,
    associated_data: bytes | None = None,
) -> EncryptedPayload:
    """Encrypt a plaintext buffer to an attested TEE public key."""
    ephemeral_private = X25519PrivateKey.generate()
    ephemeral_public = ephemeral_private.public_key().public_bytes_raw()
    shared_secret = ephemeral_private.exchange(X25519PublicKey.from_public_bytes(tee_public_key))
    aes_key = _derive_aes_key(shared_secret, info)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(aes_key).encrypt(nonce, bytes(plaintext), associated_data)
    return EncryptedPayload(ephemeral_public, nonce, ciphertext)


def attestation_report_data(service: str, context: str, public_key: bytes) -> bytes:
    """Report data binding a service/context pair to an ingress encryption key."""
    payload = json.dumps(
        {
            "service": service,
            "context": context,
            "encryption_public_key": public_key.hex(),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(payload).digest()
