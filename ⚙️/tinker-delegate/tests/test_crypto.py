"""Security-property tests for the X25519 + AES-256-GCM TEE payload channel.

`crypto.py` is the cryptographic foundation everything sealed rests on. These
tests pin its load-bearing properties directly at the primitive level: authenticated
round-trip, tamper detection, associated-data binding, channel domain separation,
and — critically — that every encryption uses a fresh ephemeral key + nonce, so the
classic AES-GCM nonce-reuse-under-a-fixed-key failure mode is structurally absent.
"""
import unittest

from cryptography.exceptions import InvalidTag

from tinker_delegate.crypto import (
    ARTIFACT_HKDF_INFO,
    CARD_HKDF_INFO,
    EncryptedPayload,
    TEEKeyPair,
    encrypt_for_tee,
)


class CryptoChannelTest(unittest.TestCase):
    def setUp(self):
        self.tee = TEEKeyPair()
        self.pub = self.tee.public_key_bytes
        self.plaintext = b'{"card_number": "4242", "cvc": "123"}'

    def test_authenticated_round_trip(self):
        payload = encrypt_for_tee(self.plaintext, self.pub)
        self.assertEqual(self.tee.decrypt(payload), self.plaintext)

    def test_tampered_ciphertext_is_rejected(self):
        payload = encrypt_for_tee(self.plaintext, self.pub)
        bad = bytearray(payload.ciphertext)
        bad[0] ^= 0xFF
        tampered = EncryptedPayload(payload.ephemeral_public_key, payload.nonce, bytes(bad))
        with self.assertRaises(InvalidTag):
            self.tee.decrypt(tampered)

    def test_tampered_nonce_is_rejected(self):
        payload = encrypt_for_tee(self.plaintext, self.pub)
        bad_nonce = bytearray(payload.nonce)
        bad_nonce[0] ^= 0xFF
        tampered = EncryptedPayload(payload.ephemeral_public_key, bytes(bad_nonce), payload.ciphertext)
        with self.assertRaises(InvalidTag):
            self.tee.decrypt(tampered)

    def test_associated_data_binding(self):
        aad = b"deal-42:card-channel"
        payload = encrypt_for_tee(self.plaintext, self.pub, associated_data=aad)
        # Correct AAD decrypts...
        self.assertEqual(self.tee.decrypt(payload, associated_data=aad), self.plaintext)
        # ...wrong or absent AAD does not (the AAD is authenticated).
        with self.assertRaises(InvalidTag):
            self.tee.decrypt(payload, associated_data=b"deal-99:card-channel")
        with self.assertRaises(InvalidTag):
            self.tee.decrypt(payload, associated_data=None)

    def test_channel_domain_separation(self):
        # Encrypt on the card channel; decrypting on the artifact channel derives a
        # different key and must fail (channels are domain-separated by HKDF info).
        payload = encrypt_for_tee(self.plaintext, self.pub, info=CARD_HKDF_INFO)
        self.assertEqual(self.tee.decrypt(payload, info=CARD_HKDF_INFO), self.plaintext)
        with self.assertRaises(InvalidTag):
            self.tee.decrypt(payload, info=ARTIFACT_HKDF_INFO)

    def test_each_encryption_uses_fresh_ephemeral_and_nonce(self):
        # The load-bearing nonce-safety property: encrypting the SAME plaintext
        # twice must yield different ephemeral keys, different nonces, and
        # different ciphertexts — so no AES-GCM nonce is ever reused under a key.
        a = encrypt_for_tee(self.plaintext, self.pub)
        b = encrypt_for_tee(self.plaintext, self.pub)
        self.assertNotEqual(a.ephemeral_public_key, b.ephemeral_public_key)
        self.assertNotEqual(a.nonce, b.nonce)
        self.assertNotEqual(a.ciphertext, b.ciphertext)
        # Both still decrypt to the same plaintext.
        self.assertEqual(self.tee.decrypt(a), self.plaintext)
        self.assertEqual(self.tee.decrypt(b), self.plaintext)

    def test_a_different_tee_key_cannot_decrypt(self):
        payload = encrypt_for_tee(self.plaintext, self.pub)
        other = TEEKeyPair()
        with self.assertRaises(InvalidTag):
            other.decrypt(payload)

    def test_keypair_reconstructed_from_hex_decrypts(self):
        priv_hex = "44" * 32
        kp = TEEKeyPair.from_private_key_hex(priv_hex)
        payload = encrypt_for_tee(self.plaintext, kp.public_key_bytes)
        # A second reconstruction from the same hex decrypts the same payload.
        self.assertEqual(
            TEEKeyPair.from_private_key_hex(priv_hex).decrypt(payload), self.plaintext
        )

    def test_payload_hex_round_trip(self):
        payload = encrypt_for_tee(self.plaintext, self.pub)
        restored = EncryptedPayload.from_hex(payload.to_hex())
        self.assertEqual(self.tee.decrypt(restored), self.plaintext)


if __name__ == "__main__":
    unittest.main()
