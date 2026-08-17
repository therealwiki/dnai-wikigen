import unittest
from unittest.mock import patch

from eth_account import Account
from eth_account.messages import encode_defunct

from tinker_delegate.arena_auth import (
    ARENA_AGENT_MANAGE_SCOPE,
    ARENA_AGENT_MANAGEMENT_SCOPES,
    ARENA_OWNER_MANAGE_SCOPE,
    ARENA_OWNER_READ_SCOPE,
    ARENA_SESSION_SCOPES,
    ARENA_SUBMIT_SCOPE,
    ArenaAuthError,
    ArenaAuthUnavailable,
    ArenaWalletAuthService,
    ArenaWalletChallengeStore,
    _decode_token,
    _encode_token,
    arena_agent_store_integrity_key,
    arena_store_integrity_key,
    arena_token_signing_key,
)
from tinker_delegate.config import Settings
from tinker_delegate.wallet_auth import (
    ARTIFACT_UPLOAD_SCOPE,
    WalletAuthError,
    WalletAuthService,
    WalletChallengeStore,
)


LOCAL_SIGNING_KEY = "local-test-arena-wallet-auth-key-" + ("7" * 48)
SUBMITTER_KEY = "0x" + ("33" * 32)
OTHER_KEY = "0x" + ("44" * 32)


def _signature(message: str, private_key: str) -> str:
    return Account.sign_message(
        encode_defunct(text=message),
        private_key=private_key,
    ).signature.hex()


def _noncanonical_signature_alias(token: str) -> str:
    """Change only unused Base64URL pad bits, preserving signature bytes."""

    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    parts = token.split(".")
    index = alphabet.index(parts[2][-1])
    if index % 4 != 0:
        raise AssertionError("HS256 signature was not canonically encoded")
    parts[2] = parts[2][:-1] + alphabet[index + 1]
    return ".".join(parts)


class ArenaWalletAuthServiceTest(unittest.TestCase):
    def setUp(self):
        self.settings = Settings(
            wallet_auth_signing_key=LOCAL_SIGNING_KEY,
            wallet_auth_domain="arena.example",
            wallet_auth_uri="https://arena.example",
            wallet_auth_chain_id=84532,
            arena_wallet_auth_challenge_ttl_seconds=60,
            arena_wallet_auth_token_ttl_seconds=90,
        )
        self.store = ArenaWalletChallengeStore(max_pending=8)
        self.service = ArenaWalletAuthService(self.settings, self.store)
        self.submitter = Account.from_key(SUBMITTER_KEY)

    def _issue_and_exchange(self, *, version: str = "1.0.0", now: int = 100):
        challenge = self.service.issue_challenge(
            address=self.submitter.address,
            challenge_id="synthetic-assay-qc",
            challenge_version=version,
            now=now,
        )
        claims, token = self.service.exchange_signature(
            nonce=challenge.nonce,
            signature=_signature(challenge.message, SUBMITTER_KEY),
            now=now + 1,
        )
        return challenge, claims, token

    def test_challenge_and_token_are_bound_to_challenge_version(self):
        challenge, claims, token = self._issue_and_exchange()

        self.assertIn("Chain ID: 84532", challenge.message)
        self.assertIn(
            "urn:dnai:arena:challenge:synthetic-assay-qc:version:1.0.0",
            challenge.message,
        )
        self.assertIn("urn:dnai:scope:challenge:submit", challenge.message)
        self.assertEqual(claims.scopes, ARENA_SESSION_SCOPES)
        self.assertIn(f"urn:dnai:scope:{ARENA_OWNER_READ_SCOPE}", challenge.message)
        self.assertIn(f"urn:dnai:scope:{ARENA_OWNER_MANAGE_SCOPE}", challenge.message)
        self.assertIn("cancel only before worker claim", challenge.message)
        self.assertIn("retry terminal ciphertext unlink", challenge.message)
        self.assertNotIn(ARENA_AGENT_MANAGE_SCOPE, challenge.message)
        verified = self.service.verify_token(
            token,
            required_scope=ARENA_SUBMIT_SCOPE,
            challenge_id="synthetic-assay-qc",
            challenge_version="1.0.0",
            now=150,
        )
        self.assertEqual(verified.address, self.submitter.address.lower())
        owner_verified = self.service.verify_token(
            token,
            required_scope=ARENA_OWNER_READ_SCOPE,
            challenge_id="synthetic-assay-qc",
            challenge_version="1.0.0",
            now=150,
        )
        self.assertEqual(owner_verified.scopes, ARENA_SESSION_SCOPES)
        manage_verified = self.service.verify_token(
            token,
            required_scope=ARENA_OWNER_MANAGE_SCOPE,
            challenge_id="synthetic-assay-qc",
            challenge_version="1.0.0",
            now=150,
        )
        self.assertEqual(manage_verified.scopes, ARENA_SESSION_SCOPES)
        with self.assertRaisesRegex(ArenaAuthError, "missing required"):
            self.service.verify_token(
                token,
                required_scope=ARENA_AGENT_MANAGE_SCOPE,
                challenge_id="synthetic-assay-qc",
                challenge_version="1.0.0",
                now=150,
            )

        with self.assertRaisesRegex(ArenaAuthError, "different challenge version"):
            self.service.verify_token(
                token,
                required_scope=ARENA_SUBMIT_SCOPE,
                challenge_id="synthetic-assay-qc",
                challenge_version="2.0.0",
                now=150,
            )

    def test_agent_management_requires_a_separate_exact_wallet_consent(self):
        challenge = self.service.issue_challenge(
            address=self.submitter.address,
            challenge_id="synthetic-assay-qc",
            challenge_version="1.0.0",
            purpose="agent_management",
            now=100,
        )
        self.assertEqual(challenge.scope, ARENA_AGENT_MANAGE_SCOPE)
        self.assertIn(f"urn:dnai:scope:{ARENA_AGENT_MANAGE_SCOPE}", challenge.message)
        self.assertNotIn(f"urn:dnai:scope:{ARENA_SUBMIT_SCOPE}", challenge.message)
        claims, token = self.service.exchange_signature(
            nonce=challenge.nonce,
            signature=_signature(challenge.message, SUBMITTER_KEY),
            now=101,
        )
        self.assertEqual(claims.scopes, ARENA_AGENT_MANAGEMENT_SCOPES)
        verified = self.service.verify_token(
            token,
            required_scope=ARENA_AGENT_MANAGE_SCOPE,
            challenge_id="synthetic-assay-qc",
            challenge_version="1.0.0",
            now=120,
        )
        self.assertEqual(verified.scopes, ARENA_AGENT_MANAGEMENT_SCOPES)
        for disallowed in (
            ARENA_SUBMIT_SCOPE,
            ARENA_OWNER_READ_SCOPE,
            ARENA_OWNER_MANAGE_SCOPE,
        ):
            with self.subTest(disallowed=disallowed):
                with self.assertRaisesRegex(ArenaAuthError, "missing required"):
                    self.service.verify_token(
                        token,
                        required_scope=disallowed,
                        challenge_id="synthetic-assay-qc",
                        challenge_version="1.0.0",
                        now=120,
                    )

    def test_nonce_is_single_use_and_wrong_signer_does_not_consume_it(self):
        challenge = self.service.issue_challenge(
            address=self.submitter.address,
            challenge_id="synthetic-assay-qc",
            challenge_version="1.0.0",
            now=100,
        )
        with self.assertRaisesRegex(ArenaAuthError, "does not match"):
            self.service.exchange_signature(
                nonce=challenge.nonce,
                signature=_signature(challenge.message, OTHER_KEY),
                now=101,
            )
        self.service.exchange_signature(
            nonce=challenge.nonce,
            signature=_signature(challenge.message, SUBMITTER_KEY),
            now=102,
        )
        with self.assertRaisesRegex(ArenaAuthError, "already used"):
            self.service.exchange_signature(
                nonce=challenge.nonce,
                signature=_signature(challenge.message, SUBMITTER_KEY),
                now=103,
            )

    def test_expired_challenge_and_token_fail_closed(self):
        challenge = self.service.issue_challenge(
            address=self.submitter.address,
            challenge_id="synthetic-assay-qc",
            challenge_version="1.0.0",
            now=100,
        )
        with self.assertRaisesRegex(ArenaAuthError, "expired"):
            self.service.exchange_signature(
                nonce=challenge.nonce,
                signature=_signature(challenge.message, SUBMITTER_KEY),
                now=160,
            )

        _challenge, _claims, token = self._issue_and_exchange(now=200)
        with self.assertRaisesRegex(ArenaAuthError, "expired"):
            self.service.verify_token(
                token,
                required_scope=ARENA_SUBMIT_SCOPE,
                challenge_id="synthetic-assay-qc",
                challenge_version="1.0.0",
                now=291,
            )

    def test_noncanonical_signature_alias_is_rejected(self):
        _challenge, _claims, token = self._issue_and_exchange()

        with self.assertRaisesRegex(ArenaAuthError, "signature"):
            self.service.verify_token(
                _noncanonical_signature_alias(token),
                required_scope=ARENA_SUBMIT_SCOPE,
                challenge_id="synthetic-assay-qc",
                challenge_version="1.0.0",
                now=120,
            )

    def test_signed_wallet_claims_require_exact_schema_types_and_scope_text(self):
        _challenge, _claims, token = self._issue_and_exchange()
        signing_key = arena_token_signing_key(self.settings)
        original = _decode_token(token, signing_key)
        mutations = (
            {**original, "future_authority": True},
            {**original, "iat": True},
            {**original, "nbf": "101"},
            {**original, "exp": 191.0},
            {**original, "scope": "  " + original["scope"]},
            {**original, "scope": original["scope"].replace(" ", "  ", 1)},
            {
                **original,
                "scope": (
                    f"{ARENA_SUBMIT_SCOPE} {ARENA_OWNER_READ_SCOPE} "
                    f"{ARENA_AGENT_MANAGE_SCOPE}"
                ),
            },
        )
        for payload in mutations:
            with self.subTest(payload=payload):
                with self.assertRaises(ArenaAuthError):
                    self.service.verify_token(
                        _encode_token(payload, signing_key),
                        required_scope=ARENA_SUBMIT_SCOPE,
                        challenge_id="synthetic-assay-qc",
                        challenge_version="1.0.0",
                        now=120,
                    )

    def test_arena_and_deal_tokens_are_not_interchangeable(self):
        _challenge, _claims, arena_token = self._issue_and_exchange()
        deal_service = WalletAuthService(self.settings, WalletChallengeStore())

        with self.assertRaisesRegex(WalletAuthError, "signature|header"):
            deal_service.verify_token(
                arena_token,
                required_scope=ARTIFACT_UPLOAD_SCOPE,
                deal_id="7",
                now=120,
            )

        deal_challenge = deal_service.issue_challenge(
            address=self.submitter.address,
            deal_id="7",
            now=100,
        )
        _deal_claims, deal_token = deal_service.exchange_signature(
            nonce=deal_challenge.nonce,
            signature=_signature(deal_challenge.message, SUBMITTER_KEY),
            now=101,
        )
        with self.assertRaisesRegex(ArenaAuthError, "signature|header"):
            self.service.verify_token(
                deal_token,
                required_scope=ARENA_SUBMIT_SCOPE,
                challenge_id="synthetic-assay-qc",
                challenge_version="1.0.0",
                now=120,
            )

    def test_dstack_uses_distinct_arena_key_path(self):
        settings = Settings(
            wallet_auth_signing_key=LOCAL_SIGNING_KEY,
            arena_wallet_auth_key_path="tinker/arena-auth-test",
        )
        with (
            patch("tinker_delegate.arena_auth.dstack_utils.is_dstack_enabled", return_value=True),
            patch(
                "tinker_delegate.arena_auth.dstack_utils.derive_storage_key",
                return_value=b"a" * 32,
            ) as derive,
        ):
            key = arena_token_signing_key(settings)

        self.assertEqual(len(key), 32)
        derive.assert_called_once_with("tinker/arena-auth-test")

    def test_arena_queue_integrity_key_has_its_own_domain_and_dstack_path(self):
        settings = Settings(
            wallet_auth_signing_key=LOCAL_SIGNING_KEY,
            arena_store_integrity_key="same-local-input-" + ("a" * 32),
            arena_agent_store_integrity_key="same-local-input-" + ("a" * 32),
            arena_store_integrity_key_path="tinker/arena-store-test",
        )
        with patch(
            "tinker_delegate.arena_auth.dstack_utils.is_dstack_enabled",
            return_value=False,
        ):
            queue_key = arena_store_integrity_key(settings)
            agent_key = arena_agent_store_integrity_key(settings)
        self.assertEqual(len(queue_key), 32)
        self.assertNotEqual(queue_key, agent_key)

        with (
            patch(
                "tinker_delegate.arena_auth.dstack_utils.is_dstack_enabled",
                return_value=True,
            ),
            patch(
                "tinker_delegate.arena_auth.dstack_utils.derive_storage_key",
                return_value=b"q" * 32,
            ) as derive,
        ):
            dstack_key = arena_store_integrity_key(settings)
        self.assertEqual(len(dstack_key), 32)
        derive.assert_called_once_with("tinker/arena-store-test")

    def test_missing_key_fails_before_challenge(self):
        service = ArenaWalletAuthService(Settings(), ArenaWalletChallengeStore())
        with patch(
            "tinker_delegate.arena_auth.dstack_utils.is_dstack_enabled",
            return_value=False,
        ):
            with self.assertRaises(ArenaAuthUnavailable):
                service.issue_challenge(
                    address=self.submitter.address,
                    challenge_id="synthetic-assay-qc",
                    challenge_version="1.0.0",
                    now=100,
                )


if __name__ == "__main__":
    unittest.main()
