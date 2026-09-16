import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import hmac
import json
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from eth_account import Account
from eth_account.messages import encode_defunct

from tinker_delegate.collaboration_auth import (
    COLLABORATION_CONSOLE_SCOPE,
    CollaborationAuthError,
    CollaborationAuthUnavailable,
    CollaborationChallengeCapacityError,
    CollaborationWalletAuthService,
    CollaborationWalletChallengeStore,
    classify_unverified_collaboration_token_header,
    collaboration_store_integrity_key,
    collaboration_wallet_signing_key,
)
from tinker_delegate.compute_auth import (
    ComputeWalletAuthService,
    ComputeWalletChallengeStore,
    compute_wallet_signing_key,
)
from tinker_delegate.wallet_signature_verifier import (
    WalletSignatureError,
    WalletSignatureUnavailable,
)


PRIVATE_KEY = "0x" + "61" * 32
COLLABORATION_KEY = "collaboration-wallet-test-key-" + "c" * 48
STORE_KEY = "collaboration-store-test-key-" + "s" * 48


def settings(**overrides):
    values = {
        "collaboration_wallet_auth_signing_key": COLLABORATION_KEY,
        "collaboration_store_integrity_key": STORE_KEY,
        "collaboration_wallet_auth_challenge_ttl_seconds": 300,
        "collaboration_wallet_auth_token_ttl_seconds": 600,
        "collaboration_wallet_auth_issuer": "",
        "collaboration_wallet_auth_audience": "",
        "collaboration_wallet_auth_key_path": "",
        "collaboration_store_integrity_key_path": "",
        "wallet_auth_domain": "www.wikigen.me",
        "wallet_auth_uri": "https://www.wikigen.me",
        "wallet_auth_chain_id": 84532,
        "wallet_signature_primary_rpc_url": "",
        "wallet_signature_secondary_rpc_url": "",
        "wallet_signature_max_bytes": 4096,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def sign(message: str, private_key: str = PRIVATE_KEY) -> str:
    return Account.sign_message(
        encode_defunct(text=message),
        private_key=private_key,
    ).signature.hex()


def noncanonical_signature_alias(token: str) -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    parts = token.split(".")
    index = alphabet.index(parts[2][-1])
    if index % 4 != 0:
        raise AssertionError("HS256 signature was not canonically encoded")
    parts[2] = parts[2][:-1] + alphabet[index + 1]
    return ".".join(parts)


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def decode_json_part(value: str):
    return json.loads(
        base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    )


def resign_token_payload(token: str, payload, key: bytes) -> str:
    header, _old_payload, _old_signature = token.split(".")
    encoded_payload = b64url(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    )
    signing_input = f"{header}.{encoded_payload}".encode("ascii")
    signature = hmac.new(key, signing_input, hashlib.sha256).digest()
    return f"{header}.{encoded_payload}.{b64url(signature)}"


class StubVerifier:
    def __init__(self, result="eip1271", error=None):
        self.result = result
        self.error = error
        self.calls = []

    def verify(self, *, address, message, signature):
        self.calls.append((address, message, signature))
        if self.error is not None:
            raise self.error
        return self.result


class BlockingVerifier:
    def __init__(self):
        self.started = threading.Event()
        self.release = threading.Event()
        self.calls = 0

    def verify(self, *, address, message, signature):
        self.calls += 1
        self.started.set()
        if not self.release.wait(timeout=2):
            raise AssertionError("test verifier was not released")
        return "eoa"


class CollaborationWalletAuthTest(unittest.TestCase):
    def setUp(self):
        self.account = Account.from_key(PRIVATE_KEY)
        self.store = CollaborationWalletChallengeStore(max_pending=4)
        self.service = CollaborationWalletAuthService(settings(), self.store)

    def test_base_sepolia_console_challenge_token_and_replay_boundary(self):
        challenge = self.service.issue_challenge(
            address=self.account.address,
            now=100,
        )
        self.assertEqual(challenge.scope, COLLABORATION_CONSOLE_SCOPE)
        self.assertIn("Chain ID: 84532", challenge.message)
        self.assertIn(
            "urn:dnai:scope:collaboration:console",
            challenge.message,
        )
        self.assertIn("will not create a room", challenge.message)
        self.assertIn("will not", challenge.message)
        self.assertIn("transfer funds", challenge.message)

        claims, token = self.service.exchange_signature(
            nonce=challenge.nonce,
            signature=sign(challenge.message),
            now=101,
        )
        self.assertEqual(claims.address, self.account.address.lower())
        self.assertEqual(
            classify_unverified_collaboration_token_header(token),
            "wallet",
        )
        verified = self.service.verify_token(token, now=110)
        self.assertEqual(verified.scopes, (COLLABORATION_CONSOLE_SCOPE,))
        self.assertNotIn(claims.jwt_id, str(claims.to_public_dict()))

        with self.assertRaisesRegex(CollaborationAuthError, "already used"):
            self.service.exchange_signature(
                nonce=challenge.nonce,
                signature=sign(challenge.message),
                now=102,
            )

    def test_wrong_signer_is_bounded_and_correct_retry_can_succeed(self):
        challenge = self.service.issue_challenge(
            address=self.account.address,
            now=100,
        )
        wrong = Account.create()
        with self.assertRaisesRegex(
            CollaborationAuthError,
            "^Collaboration wallet signature is invalid$",
        ):
            self.service.exchange_signature(
                nonce=challenge.nonce,
                signature=sign(challenge.message, wrong.key.hex()),
                now=101,
            )
        claims, _token = self.service.exchange_signature(
            nonce=challenge.nonce,
            signature=sign(challenge.message),
            now=102,
        )
        self.assertEqual(claims.address, self.account.address.lower())

    def test_three_failed_attempts_retire_challenge(self):
        challenge = self.service.issue_challenge(
            address=self.account.address,
            now=100,
        )
        wrong = Account.create()
        wrong_signature = sign(challenge.message, wrong.key.hex())
        for _ in range(3):
            with self.assertRaises(CollaborationAuthError):
                self.service.exchange_signature(
                    nonce=challenge.nonce,
                    signature=wrong_signature,
                    now=101,
                )
        with self.assertRaisesRegex(CollaborationAuthError, "already used"):
            self.service.exchange_signature(
                nonce=challenge.nonce,
                signature=sign(challenge.message),
                now=102,
            )

    def test_expiry_tampering_and_wrong_scope_fail_closed(self):
        challenge = self.service.issue_challenge(
            address=self.account.address,
            now=100,
        )
        _claims, token = self.service.exchange_signature(
            nonce=challenge.nonce,
            signature=sign(challenge.message),
            now=101,
        )
        with self.assertRaisesRegex(CollaborationAuthError, "expired"):
            self.service.verify_token(token, now=701)
        with self.assertRaisesRegex(CollaborationAuthError, "signature"):
            self.service.verify_token(
                noncanonical_signature_alias(token),
                now=110,
            )
        with self.assertRaisesRegex(CollaborationAuthError, "scope"):
            self.service.verify_token(
                token,
                required_scope="collaboration:admin",
                now=110,
            )

    def test_capacity_refuses_eviction_and_expired_records_are_pruned(self):
        store = CollaborationWalletChallengeStore(max_pending=1)
        service = CollaborationWalletAuthService(settings(), store)
        first = service.issue_challenge(address=self.account.address, now=100)
        with self.assertRaises(CollaborationChallengeCapacityError):
            service.issue_challenge(address=self.account.address, now=101)
        replacement = service.issue_challenge(address=self.account.address, now=400)
        self.assertNotEqual(first.nonce, replacement.nonce)

    def test_challenge_exchange_rejects_before_issue_and_at_exact_expiry(self):
        verifier = StubVerifier()
        service = CollaborationWalletAuthService(
            settings(),
            CollaborationWalletChallengeStore(),
            signature_verifier=verifier,
        )
        challenge = service.issue_challenge(address=self.account.address, now=100)
        with self.assertRaisesRegex(CollaborationAuthError, "unknown, expired"):
            service.exchange_signature(
                nonce=challenge.nonce,
                signature="0x" + "ab" * 65,
                now=99,
            )
        self.assertEqual(verifier.calls, [])
        claims, _token = service.exchange_signature(
            nonce=challenge.nonce,
            signature="0x" + "ab" * 65,
            now=100,
        )
        self.assertEqual(claims.issued_at, 100)

        expires_exactly = service.issue_challenge(
            address=self.account.address,
            now=500,
        )
        with self.assertRaisesRegex(CollaborationAuthError, "unknown, expired"):
            service.exchange_signature(
                nonce=expires_exactly.nonce,
                signature="0x" + "ab" * 65,
                now=800,
            )
        self.assertEqual(len(verifier.calls), 1)

    def test_explicit_test_clocks_must_be_exact_integers(self):
        with self.assertRaisesRegex(CollaborationAuthError, "clock must be an integer"):
            self.service.issue_challenge(address=self.account.address, now=True)
        challenge = self.service.issue_challenge(
            address=self.account.address,
            now=100,
        )
        with self.assertRaisesRegex(CollaborationAuthError, "clock must be an integer"):
            self.service.exchange_signature(
                nonce=challenge.nonce,
                signature=sign(challenge.message),
                now=101.0,
            )

    def test_clock_regression_during_verification_fails_and_releases_nonce(self):
        verifier = StubVerifier()
        service = CollaborationWalletAuthService(
            settings(),
            CollaborationWalletChallengeStore(),
            signature_verifier=verifier,
        )
        challenge = service.issue_challenge(address=self.account.address, now=100)
        with (
            patch(
                "tinker_delegate.collaboration_auth.time.time",
                side_effect=[101, 100],
            ),
            self.assertRaisesRegex(
                CollaborationAuthUnavailable,
                "clock regressed",
            ),
        ):
            service.exchange_signature(
                nonce=challenge.nonce,
                signature="0x" + "ab" * 65,
            )
        claims, _token = service.exchange_signature(
            nonce=challenge.nonce,
            signature="0x" + "ab" * 65,
            now=102,
        )
        self.assertEqual(claims.issued_at, 102)

    def test_eip1271_result_is_accepted_with_unverified_header_routing(self):
        verifier = StubVerifier("eip1271")
        service = CollaborationWalletAuthService(
            settings(),
            CollaborationWalletChallengeStore(),
            signature_verifier=verifier,
        )
        challenge = service.issue_challenge(address=self.account.address, now=100)
        claims, token = service.exchange_signature(
            nonce=challenge.nonce,
            signature="0x" + "ab" * 96,
            now=101,
        )
        self.assertEqual(claims.address, self.account.address.lower())
        self.assertEqual(
            classify_unverified_collaboration_token_header(token),
            "wallet",
        )
        self.assertEqual(verifier.calls[0][0], self.account.address.lower())

    def test_verifier_errors_are_classified_without_consuming_unbounded_attempts(self):
        unavailable = StubVerifier(
            error=WalletSignatureUnavailable("provider unavailable")
        )
        service = CollaborationWalletAuthService(
            settings(),
            CollaborationWalletChallengeStore(),
            signature_verifier=unavailable,
        )
        challenge = service.issue_challenge(address=self.account.address, now=100)
        with self.assertRaises(CollaborationAuthUnavailable):
            service.exchange_signature(
                nonce=challenge.nonce,
                signature="0x" + "ab" * 65,
                now=101,
            )

        rejected = StubVerifier(
            error=WalletSignatureError("signature rejected")
        )
        service = CollaborationWalletAuthService(
            settings(),
            CollaborationWalletChallengeStore(),
            signature_verifier=rejected,
        )
        challenge = service.issue_challenge(address=self.account.address, now=100)
        secret_detail = "signature rejected with provider secret=do-not-leak"
        rejected.error = WalletSignatureError(secret_detail)
        with self.assertRaises(CollaborationAuthError) as caught:
            service.exchange_signature(
                nonce=challenge.nonce,
                signature="0x" + "ab" * 65,
                now=101,
            )
        self.assertEqual(
            str(caught.exception),
            "Collaboration wallet signature is invalid",
        )
        self.assertNotIn(secret_detail, str(caught.exception))

    def test_compute_token_is_rejected_even_with_same_local_secret(self):
        compute_settings = settings(
            compute_wallet_auth_signing_key=COLLABORATION_KEY,
            compute_wallet_auth_challenge_ttl_seconds=300,
            compute_wallet_auth_token_ttl_seconds=600,
            compute_wallet_auth_issuer="",
            compute_wallet_auth_audience="",
            compute_wallet_auth_key_path="",
        )
        compute_service = ComputeWalletAuthService(
            compute_settings,
            ComputeWalletChallengeStore(),
        )
        challenge = compute_service.issue_challenge(
            address=self.account.address,
            now=100,
        )
        _claims, token = compute_service.exchange_signature(
            nonce=challenge.nonce,
            signature=sign(challenge.message),
            now=101,
        )
        self.assertNotEqual(
            compute_wallet_signing_key(compute_settings),
            collaboration_wallet_signing_key(settings()),
        )
        with self.assertRaisesRegex(CollaborationAuthError, "unsupported"):
            classify_unverified_collaboration_token_header(token)
        with self.assertRaises(CollaborationAuthError):
            self.service.verify_token(token, now=110)

    def test_unverified_header_classifier_does_not_authenticate_arbitrary_tokens(self):
        challenge = self.service.issue_challenge(
            address=self.account.address,
            now=100,
        )
        _claims, valid_token = self.service.exchange_signature(
            nonce=challenge.nonce,
            signature=sign(challenge.message),
            now=101,
        )
        key = collaboration_wallet_signing_key(settings())
        arbitrary_tokens = (
            ".".join(
                (
                    valid_token.split(".")[0],
                    b64url(b'{"not":"claims"}'),
                    b64url(b"\0" * 32),
                )
            ),
            resign_token_payload(valid_token, ["not", "a", "mapping"], key),
        )
        for arbitrary in arbitrary_tokens:
            with self.subTest(token=arbitrary):
                self.assertEqual(
                    classify_unverified_collaboration_token_header(arbitrary),
                    "wallet",
                )
                with self.assertRaises(CollaborationAuthError):
                    self.service.verify_token(arbitrary, now=110)

    def test_temporal_claims_require_non_boolean_exact_integers(self):
        challenge = self.service.issue_challenge(
            address=self.account.address,
            now=100,
        )
        _claims, token = self.service.exchange_signature(
            nonce=challenge.nonce,
            signature=sign(challenge.message),
            now=101,
        )
        parts = token.split(".")
        payload = decode_json_part(parts[1])
        key = collaboration_wallet_signing_key(settings())
        for field in ("iat", "nbf", "exp"):
            for invalid in (True, 101.0, "101"):
                with self.subTest(field=field, invalid=invalid):
                    modified = dict(payload)
                    modified[field] = invalid
                    malformed = resign_token_payload(token, modified, key)
                    with self.assertRaisesRegex(
                        CollaborationAuthError,
                        "timestamps are invalid",
                    ):
                        self.service.verify_token(malformed, now=110)

    def test_only_one_concurrent_exchange_can_verify_and_consume_a_nonce(self):
        verifier = BlockingVerifier()
        service = CollaborationWalletAuthService(
            settings(),
            CollaborationWalletChallengeStore(),
            signature_verifier=verifier,
        )
        challenge = service.issue_challenge(address=self.account.address, now=100)
        with ThreadPoolExecutor(max_workers=2) as executor:
            first = executor.submit(
                service.exchange_signature,
                nonce=challenge.nonce,
                signature="0x" + "ab" * 65,
                now=101,
            )
            self.assertTrue(verifier.started.wait(timeout=2))
            with self.assertRaisesRegex(CollaborationAuthError, "already used"):
                service.exchange_signature(
                    nonce=challenge.nonce,
                    signature="0x" + "cd" * 65,
                    now=101,
                )
            verifier.release.set()
            claims, token = first.result(timeout=2)
        self.assertEqual(verifier.calls, 1)
        self.assertEqual(claims.address, self.account.address.lower())
        self.assertEqual(
            service.verify_token(token, now=110).address,
            self.account.address.lower(),
        )

    def test_keys_are_domain_and_path_separated_under_dstack(self):
        configured = settings(
            collaboration_wallet_auth_key_path="collaboration/wallet",
            collaboration_store_integrity_key_path="collaboration/store",
        )
        with (
            patch(
                "tinker_delegate.collaboration_auth.dstack_utils.is_dstack_enabled",
                return_value=True,
            ),
            patch(
                "tinker_delegate.collaboration_auth.dstack_utils.derive_storage_key",
                return_value=b"k" * 32,
            ) as derive,
        ):
            wallet_key = collaboration_wallet_signing_key(configured)
            store_key = collaboration_store_integrity_key(configured)
        self.assertNotEqual(wallet_key, store_key)
        self.assertEqual(
            [call.args[0] for call in derive.call_args_list],
            ["collaboration/wallet", "collaboration/store"],
        )

    def test_missing_local_keys_and_non_base_chain_fail_before_signature(self):
        with patch(
            "tinker_delegate.collaboration_auth.dstack_utils.is_dstack_enabled",
            return_value=False,
        ):
            with self.assertRaises(CollaborationAuthUnavailable):
                CollaborationWalletAuthService(
                    settings(collaboration_wallet_auth_signing_key=""),
                    CollaborationWalletChallengeStore(),
                ).issue_challenge(address=self.account.address, now=100)
        with self.assertRaisesRegex(CollaborationAuthError, "Base Sepolia"):
            CollaborationWalletAuthService(
                settings(wallet_auth_chain_id=1),
                CollaborationWalletChallengeStore(),
            ).issue_challenge(address=self.account.address, now=100)


if __name__ == "__main__":
    unittest.main()
