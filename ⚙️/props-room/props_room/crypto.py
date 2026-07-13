"""Small ECIES-like helper for attested ingress."""

from __future__ import annotations

from dataclasses import dataclass
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


HKDF_INFO = b"props-room-ingress"
NONCE_SIZE = 12


@dataclass
class EncryptedEnvelope:
    ephemeral_public_key: bytes
    nonce: bytes
    ciphertext: bytes

    def to_hex(self) -> dict[str, str]:
        return {
            "ephemeral_public_key": self.ephemeral_public_key.hex(),
            "nonce": self.nonce.hex(),
            "ciphertext": self.ciphertext.hex(),
        }


def _derive_aes_key(shared_secret: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=HKDF_INFO,
    ).derive(shared_secret)


class TEEKeyPair:
    """Ephemeral X25519 key pair bound to the current process."""

    def __init__(self) -> None:
        self._private = X25519PrivateKey.generate()
        self.public_key_bytes = self._private.public_key().public_bytes_raw()

    def decrypt(self, envelope: EncryptedEnvelope) -> bytes:
        sender_public = X25519PublicKey.from_public_bytes(envelope.ephemeral_public_key)
        shared_secret = self._private.exchange(sender_public)
        key = _derive_aes_key(shared_secret)
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(envelope.nonce, envelope.ciphertext, None)


def encrypt_for_tee(plaintext: bytes, tee_public_key: bytes) -> EncryptedEnvelope:
    ephemeral_private = X25519PrivateKey.generate()
    ephemeral_public = ephemeral_private.public_key().public_bytes_raw()
    tee_public = X25519PublicKey.from_public_bytes(tee_public_key)
    shared_secret = ephemeral_private.exchange(tee_public)
    key = _derive_aes_key(shared_secret)
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return EncryptedEnvelope(
        ephemeral_public_key=ephemeral_public,
        nonce=nonce,
        ciphertext=ciphertext,
    )
