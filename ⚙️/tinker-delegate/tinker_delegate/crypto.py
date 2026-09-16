"""X25519 + AES-256-GCM encryption for TEE-bound payload channels.

Protocol (ECIES-like):
  1. TEE generates an X25519 keypair on boot. Public key served via /attestation.
  2. Developer verifies TDX quote, extracts TEE's public key.
  3. Developer generates ephemeral X25519 keypair.
  4. Developer computes shared_secret = ECDH(ephemeral_private, tee_public).
  5. Developer derives AES key via a channel-specific HKDF-SHA256 context.
  6. Developer encrypts CardPayload JSON with AES-256-GCM.
  7. Developer sends {ephemeral_public_key, nonce, ciphertext, tag} to POST /billing/card.
  8. TEE computes same shared_secret, derives same AES key, decrypts.
  9. TEE zeroes plaintext after filling Stripe form.

Why X25519 + AES-256-GCM:
  - X25519: Fast, constant-time ECDH. No padding oracles.
  - AES-256-GCM: Authenticated encryption. Detects tampering.
  - HKDF: Standard key derivation from raw ECDH output.
  - No certificates needed: TEE's public key is bound to TDX quote.
"""
import json
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


CARD_HKDF_INFO = b"tinker-delegate-card"
ARTIFACT_HKDF_INFO = b"tinker-delegate-artifact"
NONCE_SIZE = 12  # 96 bits for AES-GCM


@dataclass
class EncryptedPayload:
    """Wire format for encrypted card data."""
    ephemeral_public_key: bytes  # 32 bytes — sender's ephemeral X25519 public key
    nonce: bytes                 # 12 bytes — AES-GCM nonce
    ciphertext: bytes            # variable — encrypted JSON + 16-byte GCM tag

    def to_hex(self) -> dict:
        return {
            "ephemeral_public_key": self.ephemeral_public_key.hex(),
            "nonce": self.nonce.hex(),
            "ciphertext": self.ciphertext.hex(),
        }

    @classmethod
    def from_hex(cls, data: dict) -> "EncryptedPayload":
        return cls(
            ephemeral_public_key=bytes.fromhex(data["ephemeral_public_key"]),
            nonce=bytes.fromhex(data["nonce"]),
            ciphertext=bytes.fromhex(data["ciphertext"]),
        )


def _derive_aes_key(
    shared_secret: bytes,
    info: bytes = CARD_HKDF_INFO,
    *,
    salt: bytes | None = None,
) -> bytes:
    """HKDF-SHA256 to derive 256-bit AES key from raw ECDH output."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    ).derive(shared_secret)


# ---------------------------------------------------------------------------
# TEE side: key generation + decryption
# ---------------------------------------------------------------------------

class TEEKeyPair:
    """X25519 keypair for the TEE. Generated once on boot."""

    def __init__(self):
        self._private = X25519PrivateKey.generate()
        self.public_key_bytes = self._private.public_key().public_bytes_raw()

    @classmethod
    def from_private_key_hex(cls, private_key_hex: str) -> "TEEKeyPair":
        """Reconstruct a keypair from a persisted raw X25519 private key (hex).

        Used for local/dev recipient key custody (a 0600 key file), and to let
        an in-boundary key source drive the same decrypt path as the boot-time
        generated key. Production CVM custody derives this from dstack.
        """
        self = cls.__new__(cls)
        self._private = X25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
        self.public_key_bytes = self._private.public_key().public_bytes_raw()
        return self

    def decrypt(
        self,
        payload: EncryptedPayload,
        *,
        info: bytes = CARD_HKDF_INFO,
        associated_data: bytes | None = None,
        hkdf_salt: bytes | None = None,
    ) -> bytes:
        """Decrypt an encrypted payload for the selected channel."""
        sender_public = X25519PublicKey.from_public_bytes(payload.ephemeral_public_key)
        shared_secret = self._private.exchange(sender_public)
        aes_key = _derive_aes_key(shared_secret, info, salt=hkdf_salt)
        aesgcm = AESGCM(aes_key)
        return aesgcm.decrypt(payload.nonce, payload.ciphertext, associated_data)


# ---------------------------------------------------------------------------
# Developer side: encryption
# ---------------------------------------------------------------------------

def encrypt_for_tee(
    plaintext: bytes,
    tee_public_key: bytes,
    *,
    info: bytes = CARD_HKDF_INFO,
    associated_data: bytes | None = None,
) -> EncryptedPayload:
    """Encrypt data to the TEE's X25519 public key.

    Used by the developer CLI / SDK to encrypt card details before sending
    them to the TEE's /billing/card endpoint.
    """
    ephemeral_private = X25519PrivateKey.generate()
    ephemeral_public = ephemeral_private.public_key().public_bytes_raw()

    tee_pub = X25519PublicKey.from_public_bytes(tee_public_key)
    shared_secret = ephemeral_private.exchange(tee_pub)
    aes_key = _derive_aes_key(shared_secret, info)

    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)

    return EncryptedPayload(
        ephemeral_public_key=ephemeral_public,
        nonce=nonce,
        ciphertext=ciphertext,
    )


def encrypt_card_payload(card_data: dict, tee_public_key_hex: str) -> dict:
    """Convenience: encrypt a card payload dict → hex-encoded wire format.

    Usage (developer side):
        card = {
            "card_number": "4242424242424242",
            "exp_month": "12", "exp_year": "28",
            "cvc": "123", "cardholder_name": "Dev Team",
        }
        encrypted = encrypt_card_payload(card, tee_public_key_hex="ab12...")
        requests.post("https://tee-host/billing/card", json={"encrypted": encrypted})
    """
    plaintext = json.dumps(card_data).encode()
    tee_public_key = bytes.fromhex(tee_public_key_hex)
    payload = encrypt_for_tee(plaintext, tee_public_key, info=CARD_HKDF_INFO)
    return payload.to_hex()
