import json
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from eth_account import Account
from eth_account.messages import encode_defunct

from tinker_delegate.compute_auth import (
    COMPUTE_CONSOLE_SCOPE,
    COMPUTE_CREDENTIAL_HKDF_INFO,
    ComputeAuthError,
    ComputeAuthUnavailable,
    ComputeWalletAuthService,
    ComputeWalletChallengeStore,
    classify_compute_token,
    compute_credential_signing_key,
    compute_wallet_signing_key,
    encrypt_compute_credential_token,
    issue_compute_credential_token,
    verify_compute_credential_token,
)
from tinker_delegate.config import Settings
from tinker_delegate.crypto import _derive_aes_key


WALLET_KEY = "compute-wallet-test-key-" + "w" * 48
CREDENTIAL_KEY = "compute-credential-test-key-" + "c" * 48
PRIVATE_KEY = "0x" + "11" * 32


def _noncanonical_signature_alias(token: str) -> str:
    """Change only unused Base64URL pad bits, preserving signature bytes."""

    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    parts = token.split(".")
    index = alphabet.index(parts[2][-1])
    if index % 4 != 0:
        raise AssertionError("HS256 signature was not canonically encoded")
    parts[2] = parts[2][:-1] + alphabet[index + 1]
    return ".".join(parts)


def sign(message: str) -> str:
    return Account.sign_message(
        encode_defunct(text=message), private_key=PRIVATE_KEY
    ).signature.hex()


class ComputeWalletAuthTest(unittest.TestCase):
    def setUp(self):
        self.settings = Settings(
            compute_wallet_auth_signing_key=WALLET_KEY,
            compute_credential_signing_key=CREDENTIAL_KEY,
        )
        self.store = ComputeWalletChallengeStore(max_pending=4)
        self.service = ComputeWalletAuthService(self.settings, self.store)
        self.account = Account.from_key(PRIVATE_KEY)

    def test_challenge_is_base_sepolia_console_only_and_replay_resistant(self):
        challenge = self.service.issue_challenge(
            address=self.account.address, now=100
        )
        self.assertIn("Chain ID: 84532", challenge.message)
        self.assertIn("urn:dnai:scope:compute:console", challenge.message)
        self.assertIn("will not trigger a blockchain transaction", challenge.message)
        claims, token = self.service.exchange_signature(
            nonce=challenge.nonce,
            signature=sign(challenge.message),
            now=101,
        )
        self.assertEqual(claims.address, self.account.address.lower())
        self.assertEqual(classify_compute_token(token), "wallet")
        verified = self.service.verify_token(
            token, required_scope=COMPUTE_CONSOLE_SCOPE, now=110
        )
        self.assertEqual(verified.scopes, (COMPUTE_CONSOLE_SCOPE,))
        with self.assertRaisesRegex(ComputeAuthError, "already used"):
            self.service.exchange_signature(
                nonce=challenge.nonce,
                signature=sign(challenge.message),
                now=102,
            )

    def test_tamper_expiry_and_wrong_signer_fail(self):
        challenge = self.service.issue_challenge(
            address=self.account.address, now=100
        )
        wrong = Account.create()
        wrong_signature = Account.sign_message(
            encode_defunct(text=challenge.message), private_key=wrong.key
        ).signature.hex()
        with self.assertRaisesRegex(ComputeAuthError, "does not match"):
            self.service.exchange_signature(
                nonce=challenge.nonce, signature=wrong_signature, now=101
            )
        _claims, token = self.service.exchange_signature(
            nonce=challenge.nonce, signature=sign(challenge.message), now=102
        )
        with self.assertRaisesRegex(ComputeAuthError, "expired"):
            self.service.verify_token(token, now=702)
        tampered = _noncanonical_signature_alias(token)
        with self.assertRaisesRegex(ComputeAuthError, "signature"):
            self.service.verify_token(tampered, now=110)

    def test_compute_keys_use_distinct_dstack_paths_and_domains(self):
        settings = Settings(
            compute_wallet_auth_key_path="compute/wallet-test",
            compute_credential_key_path="compute/credential-test",
        )
        with (
            patch(
                "tinker_delegate.compute_auth.dstack_utils.is_dstack_enabled",
                return_value=True,
            ),
            patch(
                "tinker_delegate.compute_auth.dstack_utils.derive_storage_key",
                return_value=b"d" * 32,
            ) as derive,
        ):
            wallet_key = compute_wallet_signing_key(settings)
            credential_key = compute_credential_signing_key(settings)
        self.assertNotEqual(wallet_key, credential_key)
        self.assertEqual(
            derive.call_args_list[0].args[0], "compute/wallet-test"
        )
        self.assertEqual(
            derive.call_args_list[1].args[0], "compute/credential-test"
        )

    def test_missing_local_key_fails_before_requesting_signature(self):
        service = ComputeWalletAuthService(Settings(), ComputeWalletChallengeStore())
        with patch(
            "tinker_delegate.compute_auth.dstack_utils.is_dstack_enabled",
            return_value=False,
        ):
            with self.assertRaises(ComputeAuthUnavailable):
                service.issue_challenge(address=self.account.address, now=100)


class ComputeCredentialAuthTest(unittest.TestCase):
    def setUp(self):
        self.settings = Settings(
            compute_credential_signing_key=CREDENTIAL_KEY,
        )

    def test_scoped_token_is_encrypted_to_device_and_verifies(self):
        claims, token = issue_compute_credential_token(
            self.settings,
            credential_id="cred_12345678",
            project_id="prj_12345678",
            device_id="dev_12345678",
            generation=1,
            scopes=["jobs:read", "jobs:create"],
            daily_credit_cap=500,
            expires_at=700,
            now=100,
        )
        self.assertEqual(classify_compute_token(token), "credential")
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key().public_bytes_raw().hex()
        capsule = encrypt_compute_credential_token(
            token,
            recipient_public_key_hex=public_key,
            claims=claims,
        )
        encrypted = capsule["encrypted_token"]
        shared_secret = private_key.exchange(
            X25519PublicKey.from_public_bytes(
                bytes.fromhex(encrypted["ephemeral_public_key"])
            )
        )
        plaintext = AESGCM(
            _derive_aes_key(shared_secret, info=COMPUTE_CREDENTIAL_HKDF_INFO)
        ).decrypt(
            bytes.fromhex(encrypted["nonce"]),
            bytes.fromhex(encrypted["ciphertext"]),
            bytes.fromhex(capsule["associated_data"]),
        )
        self.assertEqual(plaintext.decode(), token)
        self.assertFalse(capsule["plaintext_token_returned"])
        verified = verify_compute_credential_token(
            self.settings, token, required_scope="jobs:create", now=200
        )
        self.assertEqual(verified.project_id, "prj_12345678")
        self.assertEqual(verified.daily_credit_cap, 500)

    def test_scope_expiry_and_audience_are_enforced(self):
        _claims, token = issue_compute_credential_token(
            self.settings,
            credential_id="cred_12345678",
            project_id="prj_12345678",
            device_id="dev_12345678",
            generation=1,
            scopes=["jobs:read"],
            daily_credit_cap=10,
            expires_at=200,
            now=100,
        )
        with self.assertRaisesRegex(ComputeAuthError, "missing required scope"):
            verify_compute_credential_token(
                self.settings, token, required_scope="jobs:create", now=150
            )
        with self.assertRaisesRegex(ComputeAuthError, "expired"):
            verify_compute_credential_token(
                self.settings, token, required_scope="jobs:read", now=200
            )
        other = Settings(
            compute_credential_signing_key=CREDENTIAL_KEY,
            compute_credential_audience="another-service",
        )
        with self.assertRaisesRegex(ComputeAuthError, "audience"):
            verify_compute_credential_token(
                other, token, required_scope="jobs:read", now=150
            )


if __name__ == "__main__":
    unittest.main()
