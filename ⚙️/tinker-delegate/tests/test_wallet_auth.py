import unittest
from types import SimpleNamespace
from unittest.mock import patch

from eth_account import Account
from eth_account.messages import encode_defunct
from fastapi.testclient import TestClient
from pydantic import ValidationError

from tinker_delegate import api
from tinker_delegate.artifacts import artifact_commitment, encrypt_artifact_payload
from tinker_delegate.config import Settings
from tinker_delegate.wallet_auth import (
    ARTIFACT_UPLOAD_SCOPE,
    WalletAuthError,
    WalletAuthService,
    WalletAuthUnavailable,
    WalletChallengeStore,
    wallet_token_signing_key,
)


LOCAL_SIGNING_KEY = "local-test-wallet-auth-key-" + ("7" * 48)
SELLER_KEY = "0x" + ("11" * 32)
OTHER_KEY = "0x" + ("22" * 32)
COMMITMENT_SECRET = bytes(range(32))
ROOM = "0x3333333333333333333333333333333333333333"
EVALUATOR_POLICY = "0x" + "44" * 32


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


class WalletAuthServiceTest(unittest.TestCase):
    def setUp(self):
        self.settings = Settings(
            wallet_auth_signing_key=LOCAL_SIGNING_KEY,
            wallet_auth_challenge_ttl_seconds=60,
            wallet_auth_token_ttl_seconds=90,
            wallet_auth_chain_id=84532,
            wallet_auth_domain="app.example",
            wallet_auth_uri="https://app.example",
        )
        self.store = WalletChallengeStore(max_pending=8)
        self.service = WalletAuthService(self.settings, self.store)
        self.seller = Account.from_key(SELLER_KEY)

    def _issue_and_exchange(self, *, deal_id: str = "7", now: int = 100):
        challenge = self.service.issue_challenge(
            address=self.seller.address,
            deal_id=deal_id,
            now=now,
        )
        claims, token = self.service.exchange_signature(
            nonce=challenge.nonce,
            signature=_signature(challenge.message, SELLER_KEY),
            now=now + 1,
        )
        return challenge, claims, token

    def test_personal_sign_challenge_exchanges_for_deal_scoped_token(self):
        challenge, claims, token = self._issue_and_exchange()

        self.assertIn("Chain ID: 84532", challenge.message)
        self.assertIn("urn:dnai:deal:7", challenge.message)
        self.assertIn("urn:dnai:scope:artifact:upload", challenge.message)
        self.assertNotIn(SELLER_KEY[2:], challenge.message)
        self.assertEqual(claims.address, self.seller.address.lower())
        verified = self.service.verify_token(
            token,
            required_scope=ARTIFACT_UPLOAD_SCOPE,
            deal_id="7",
            now=150,
        )
        self.assertEqual(verified.address, self.seller.address.lower())
        self.assertEqual(verified.scopes, (ARTIFACT_UPLOAD_SCOPE,))

    def test_nonce_is_single_use_after_successful_exchange(self):
        challenge, _claims, _token = self._issue_and_exchange()

        with self.assertRaisesRegex(WalletAuthError, "already used"):
            self.service.exchange_signature(
                nonce=challenge.nonce,
                signature=_signature(challenge.message, SELLER_KEY),
                now=102,
            )

    def test_wrong_signer_does_not_exchange_or_consume_challenge(self):
        challenge = self.service.issue_challenge(
            address=self.seller.address,
            deal_id="7",
            now=100,
        )

        with self.assertRaisesRegex(WalletAuthError, "does not match"):
            self.service.exchange_signature(
                nonce=challenge.nonce,
                signature=_signature(challenge.message, OTHER_KEY),
                now=101,
            )

        claims, _token = self.service.exchange_signature(
            nonce=challenge.nonce,
            signature=_signature(challenge.message, SELLER_KEY),
            now=102,
        )
        self.assertEqual(claims.address, self.seller.address.lower())

    def test_expired_challenge_and_token_fail_closed(self):
        challenge = self.service.issue_challenge(
            address=self.seller.address,
            deal_id="7",
            now=100,
        )
        with self.assertRaisesRegex(WalletAuthError, "expired"):
            self.service.exchange_signature(
                nonce=challenge.nonce,
                signature=_signature(challenge.message, SELLER_KEY),
                now=160,
            )

        _challenge, _claims, token = self._issue_and_exchange(now=200)
        with self.assertRaisesRegex(WalletAuthError, "expired"):
            self.service.verify_token(
                token,
                required_scope=ARTIFACT_UPLOAD_SCOPE,
                deal_id="7",
                now=291,
            )

    def test_token_is_bound_to_deal_and_detects_tampering(self):
        _challenge, _claims, token = self._issue_and_exchange(deal_id="7")

        with self.assertRaisesRegex(WalletAuthError, "different deal"):
            self.service.verify_token(
                token,
                required_scope=ARTIFACT_UPLOAD_SCOPE,
                deal_id="8",
                now=120,
            )
        tampered = _noncanonical_signature_alias(token)
        with self.assertRaisesRegex(WalletAuthError, "signature"):
            self.service.verify_token(
                tampered,
                required_scope=ARTIFACT_UPLOAD_SCOPE,
                deal_id="7",
                now=120,
            )

    def test_dstack_key_is_derived_at_distinct_configured_path(self):
        settings = Settings(
            wallet_auth_key_path="tinker/wallet-auth-test",
            wallet_auth_signing_key=LOCAL_SIGNING_KEY,
        )
        with (
            patch("tinker_delegate.wallet_auth.dstack_utils.is_dstack_enabled", return_value=True),
            patch(
                "tinker_delegate.wallet_auth.dstack_utils.derive_storage_key",
                return_value=b"d" * 32,
            ) as derive,
        ):
            key = wallet_token_signing_key(settings)

        self.assertEqual(len(key), 32)
        derive.assert_called_once_with("tinker/wallet-auth-test")

    def test_missing_local_or_dstack_key_fails_before_challenge(self):
        service = WalletAuthService(Settings(), WalletChallengeStore())
        with patch(
            "tinker_delegate.wallet_auth.dstack_utils.is_dstack_enabled",
            return_value=False,
        ):
            with self.assertRaises(WalletAuthUnavailable):
                service.issue_challenge(address=self.seller.address, deal_id="7", now=100)


class WalletArtifactApiTest(unittest.TestCase):
    def setUp(self):
        self.original_settings = api.settings
        api.settings = Settings(
            wallet_auth_signing_key=LOCAL_SIGNING_KEY,
            diligence_room_address=ROOM,
        )
        api._wallet_challenges.clear()
        self.client = TestClient(api.app)
        self.seller = Account.from_key(SELLER_KEY)

    def tearDown(self):
        api._wallet_challenges.clear()
        api.settings = self.original_settings

    def _wallet_token(self, private_key: str, deal_id: str = "7") -> str:
        account = Account.from_key(private_key)
        challenge = self.client.post(
            "/auth/wallet/challenge",
            json={"address": account.address, "deal_id": deal_id},
        )
        self.assertEqual(challenge.status_code, 200, challenge.text)
        body = challenge.json()
        exchanged = self.client.post(
            "/auth/wallet/token",
            json={
                "nonce": body["nonce"],
                "signature": _signature(body["message"], private_key),
            },
        )
        self.assertEqual(exchanged.status_code, 200, exchanged.text)
        return exchanged.json()["access_token"]

    def _encrypted_payload(self):
        artifact = b"seller-private-artifact"
        artifact_hash = artifact_commitment(artifact, COMMITMENT_SECRET)
        payload = encrypt_artifact_payload(
            artifact,
            api.get_tee_keypair().public_key_bytes.hex(),
            deal_id="7",
            artifact_hash=artifact_hash,
            commitment_secret=COMMITMENT_SECRET,
            chain_id=84532,
            diligence_room_address=ROOM,
            evaluator_policy_commitment=EVALUATOR_POLICY,
        )
        return artifact, artifact_hash, payload

    def test_all_wallet_token_models_accept_bounded_contract_signatures(self):
        contract_signature = "0x" + "ab" * 200
        for model in (
            api.WalletTokenRequest,
            api.ArenaWalletTokenRequest,
            api.ComputeWalletTokenRequest,
        ):
            with self.subTest(model=model.__name__):
                request = model(
                    nonce="0" * 32,
                    signature=contract_signature,
                )
                self.assertEqual(request.signature, contract_signature)

    def test_wallet_requests_cannot_supply_a_signature_rpc_url(self):
        payloads = (
            (
                api.WalletChallengeRequest,
                {
                    "address": self.seller.address,
                    "deal_id": "7",
                    "rpc_url": "https://attacker.example",
                },
            ),
            (
                api.ArenaWalletChallengeRequest,
                {
                    "address": self.seller.address,
                    "challenge_id": "safe-ir",
                    "challenge_version": "1.0.0",
                    "rpc_url": "https://attacker.example",
                },
            ),
            (
                api.ComputeWalletChallengeRequest,
                {
                    "address": self.seller.address,
                    "rpc_url": "https://attacker.example",
                },
            ),
        )
        for model, payload in payloads:
            with self.subTest(model=model.__name__):
                with self.assertRaises(ValidationError):
                    model.model_validate(payload)

    def test_encrypted_upload_requires_token_before_control_plane_or_decrypt(self):
        _artifact, _artifact_hash, payload = self._encrypted_payload()
        with patch("tinker_delegate.api._get_control_plane") as get_control_plane:
            response = self.client.post("/deal/7/artifact/encrypted", json=payload)

        self.assertEqual(response.status_code, 401)
        get_control_plane.assert_not_called()

    def test_runtime_bearer_cannot_be_used_as_wallet_token(self):
        _artifact, _artifact_hash, payload = self._encrypted_payload()
        with patch("tinker_delegate.api._get_control_plane") as get_control_plane:
            response = self.client.post(
                "/deal/7/artifact/encrypted",
                json=payload,
                headers={"Authorization": "Bearer operator-runtime-secret"},
            )

        self.assertEqual(response.status_code, 401)
        get_control_plane.assert_not_called()

    def test_encrypted_upload_rejects_non_seller_wallet_before_decrypt(self):
        _artifact, _artifact_hash, payload = self._encrypted_payload()
        token = self._wallet_token(OTHER_KEY)

        class ControlPlane:
            def get_deal_context(self, _deal_id):
                return SimpleNamespace(
                    seller=self.seller,
                    committed_artifact_hash=_artifact_hash,
                    evaluator_policy_commitment=EVALUATOR_POLICY,
                )

            def receive_artifact(self, *_args):
                raise AssertionError("artifact must not reach control plane")

        cp = ControlPlane()
        cp.seller = self.seller.address
        with (
            patch("tinker_delegate.api._get_control_plane", return_value=cp),
            patch(
                "tinker_delegate.api.decrypt_artifact_payload",
                side_effect=AssertionError("decrypt must happen after role auth"),
            ),
        ):
            response = self.client.post(
                "/deal/7/artifact/encrypted",
                json=payload,
                headers={"Authorization": f"Bearer {token}"},
            )

        self.assertEqual(response.status_code, 403)
        self.assertIn("not the funded deal seller", response.json()["detail"])

    def test_encrypted_upload_accepts_funded_seller_and_zeroes_buffer(self):
        artifact, artifact_hash, payload = self._encrypted_payload()
        token = self._wallet_token(SELLER_KEY)

        class ControlPlane:
            seen = None
            seen_ref = None

            def get_deal_context(self, _deal_id):
                return SimpleNamespace(
                    seller=self.seller,
                    committed_artifact_hash=artifact_hash,
                    evaluator_policy_commitment=EVALUATOR_POLICY,
                )

            def receive_artifact(self, _deal_id, value, received_hash, commitment_secret):
                self.seen = (bytes(value), received_hash)
                self.seen_ref = value
                self.secret_ref = commitment_secret

        cp = ControlPlane()
        cp.seller = self.seller.address
        with patch("tinker_delegate.api._get_control_plane", return_value=cp):
            response = self.client.post(
                "/deal/7/artifact/encrypted",
                json=payload,
                headers={"Authorization": f"Bearer {token}"},
            )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(cp.seen, (artifact, artifact_hash))
        self.assertEqual(cp.seen_ref, bytearray(len(artifact)))
        self.assertEqual(cp.secret_ref, bytearray(32))


if __name__ == "__main__":
    unittest.main()
