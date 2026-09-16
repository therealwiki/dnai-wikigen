import base64
import hashlib
import json
import os
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from eth_account import Account
from eth_account.messages import encode_defunct
from fastapi.testclient import TestClient

from tinker_delegate import api
from tinker_delegate.arena_agent_store import (
    ArenaAgentAuthorizationError,
    ArenaAgentCapExceeded,
    ArenaAgentStore,
    ArenaAgentStoreCorruptError,
    ArenaAgentStoreUnavailableError,
)
from tinker_delegate.arena_auth import (
    ARENA_AGENT_CREDENTIAL_HKDF_INFO,
    ARENA_AGENT_MANAGE_SCOPE,
    ARENA_AGENT_SCOPES,
    ARENA_OWNER_READ_SCOPE,
    ARENA_SUBMIT_SCOPE,
    ArenaAuthError,
    _AGENT_JWT_HEADER,
    _decode_token,
    _encode_token,
    arena_agent_credential_signing_key,
    encrypt_arena_agent_credential_token,
    issue_arena_agent_credential_token,
    verify_arena_agent_credential_token,
)
from tinker_delegate.arena_store import (
    BIO_CHALLENGE_ID,
    BIO_CHALLENGE_VERSION,
    DNASEQ_SAFE_IR_CHALLENGE_ID,
    DNASEQ_SAFE_IR_CHALLENGE_VERSION,
)
from tinker_delegate.config import Settings
from tinker_delegate.crypto import _derive_aes_key


WALLET_PRIVATE_KEY = "0x" + "71" * 32
WALLET_SIGNING_KEY = "arena-agent-wallet-test-key-" + "w" * 48
AGENT_SIGNING_KEY = "arena-agent-credential-test-key-" + "c" * 48
STORE_INTEGRITY_KEY_TEXT = "arena-agent-store-integrity-test-key-" + "s" * 48
STORE_INTEGRITY_KEY = hashlib.sha256(STORE_INTEGRITY_KEY_TEXT.encode()).digest()
NOW = 1_900_000_000


def _signature(message: str) -> str:
    return Account.sign_message(
        encode_defunct(text=message), private_key=WALLET_PRIVATE_KEY
    ).signature.hex()


def _jwt_payload(token: str) -> dict:
    encoded = token.split(".")[1]
    encoded += "=" * (-len(encoded) % 4)
    return json.loads(base64.urlsafe_b64decode(encoded))


class ArenaAgentAuthTest(unittest.TestCase):
    def setUp(self):
        self.settings = Settings(
            wallet_auth_signing_key=WALLET_SIGNING_KEY,
            arena_agent_credential_signing_key=AGENT_SIGNING_KEY,
            arena_agent_credential_max_ttl_seconds=86_400,
        )
        self.owner = Account.from_key(WALLET_PRIVATE_KEY).address.lower()

    def _issue(self):
        return issue_arena_agent_credential_token(
            self.settings,
            credential_id="acred_" + "a" * 24,
            device_id="adev_" + "b" * 24,
            owner_address=self.owner,
            challenge_id=BIO_CHALLENGE_ID,
            challenge_version=BIO_CHALLENGE_VERSION,
            generation=1,
            scopes=ARENA_AGENT_SCOPES,
            daily_submission_cap=4,
            expires_at=NOW + 3_600,
            now=NOW,
        )

    def _resign(self, payload: dict) -> str:
        return _encode_token(
            payload,
            arena_agent_credential_signing_key(self.settings),
            header=_AGENT_JWT_HEADER,
        )

    def test_exact_claims_verify_and_management_scope_is_never_delegated(self):
        claims, token = self._issue()
        verified = verify_arena_agent_credential_token(
            self.settings,
            token,
            required_scope=ARENA_SUBMIT_SCOPE,
            challenge_id=BIO_CHALLENGE_ID,
            challenge_version=BIO_CHALLENGE_VERSION,
            now=NOW + 1,
        )
        self.assertEqual(verified, claims)
        self.assertEqual(verified.scopes, ARENA_AGENT_SCOPES)
        self.assertNotIn(ARENA_AGENT_MANAGE_SCOPE, verified.scopes)
        with self.assertRaisesRegex(ArenaAuthError, "unsupported required"):
            verify_arena_agent_credential_token(
                self.settings,
                token,
                required_scope=ARENA_AGENT_MANAGE_SCOPE,
                challenge_id=BIO_CHALLENGE_ID,
                challenge_version=BIO_CHALLENGE_VERSION,
                now=NOW + 1,
            )

    def test_signed_extra_claim_and_non_exact_scope_are_rejected(self):
        _claims, token = self._issue()
        payload = _jwt_payload(token)
        payload["future_authority"] = True
        with self.assertRaisesRegex(ArenaAuthError, "payload schema"):
            verify_arena_agent_credential_token(
                self.settings,
                self._resign(payload),
                required_scope=ARENA_SUBMIT_SCOPE,
                challenge_id=BIO_CHALLENGE_ID,
                challenge_version=BIO_CHALLENGE_VERSION,
                now=NOW + 1,
            )

        payload = _jwt_payload(token)
        payload["scope"] = "challenge:submit challenge:submissions:read"
        with self.assertRaisesRegex(ArenaAuthError, "not canonical"):
            verify_arena_agent_credential_token(
                self.settings,
                self._resign(payload),
                required_scope=ARENA_SUBMIT_SCOPE,
                challenge_id=BIO_CHALLENGE_ID,
                challenge_version=BIO_CHALLENGE_VERSION,
                now=NOW + 1,
            )

    def test_signed_numeric_claims_reject_bool_string_and_float(self):
        _claims, token = self._issue()
        for field in ("iat", "nbf", "exp", "generation", "daily_submission_cap"):
            for invalid in (True, "1", 1.0):
                with self.subTest(field=field, invalid=invalid):
                    payload = _jwt_payload(token)
                    payload[field] = invalid
                    with self.assertRaises(ArenaAuthError):
                        verify_arena_agent_credential_token(
                            self.settings,
                            self._resign(payload),
                            required_scope=ARENA_OWNER_READ_SCOPE,
                            challenge_id=BIO_CHALLENGE_ID,
                            challenge_version=BIO_CHALLENGE_VERSION,
                            now=NOW + 1,
                        )

    def test_all_zero_and_known_low_order_x25519_keys_are_bounded_errors(self):
        claims, token = self._issue()
        low_order_keys = (
            "00" * 32,
            "01" + "00" * 31,
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        )
        for public_key in low_order_keys:
            with self.subTest(public_key=public_key[:8]):
                with self.assertRaisesRegex(ArenaAuthError, "low-order"):
                    encrypt_arena_agent_credential_token(
                        token,
                        recipient_public_key_hex=public_key,
                        claims=claims,
                    )

    def test_noncanonical_x25519_aliases_are_rejected(self):
        claims, token = self._issue()
        aliases = (
            (2 | (1 << 255)).to_bytes(32, "little").hex(),
            ((1 << 255) - 19 + 2).to_bytes(32, "little").hex(),
        )
        for public_key in aliases:
            with self.subTest(public_key=public_key[-8:]):
                with self.assertRaisesRegex(ArenaAuthError, "non-canonical"):
                    encrypt_arena_agent_credential_token(
                        token,
                        recipient_public_key_hex=public_key,
                        claims=claims,
                    )

    def test_capsule_round_trip_uses_distinct_arena_hkdf_domain(self):
        claims, token = self._issue()
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key().public_bytes_raw().hex()
        capsule = encrypt_arena_agent_credential_token(
            token, recipient_public_key_hex=public_key, claims=claims
        )
        encrypted = capsule["encrypted_token"]
        shared = private_key.exchange(
            X25519PublicKey.from_public_bytes(
                bytes.fromhex(encrypted["ephemeral_public_key"])
            )
        )
        plaintext = AESGCM(
            _derive_aes_key(shared, info=ARENA_AGENT_CREDENTIAL_HKDF_INFO)
        ).decrypt(
            bytes.fromhex(encrypted["nonce"]),
            bytes.fromhex(encrypted["ciphertext"]),
            bytes.fromhex(capsule["associated_data"]),
        )
        self.assertEqual(plaintext.decode(), token)
        self.assertFalse(capsule["plaintext_token_returned"])


class ArenaAgentStoreTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.path = self.root / "arena-agent.json"
        self.owner = Account.from_key(WALLET_PRIVATE_KEY).address.lower()
        self.settings = Settings(
            wallet_auth_signing_key=WALLET_SIGNING_KEY,
            arena_agent_credential_signing_key=AGENT_SIGNING_KEY,
        )

    def tearDown(self):
        self.temporary.cleanup()

    def _registered(self, *, cap: int = 2):
        claims, _token = issue_arena_agent_credential_token(
            self.settings,
            credential_id="acred_" + "c" * 24,
            device_id="adev_" + "d" * 24,
            owner_address=self.owner,
            challenge_id=BIO_CHALLENGE_ID,
            challenge_version=BIO_CHALLENGE_VERSION,
            generation=1,
            scopes=ARENA_AGENT_SCOPES,
            daily_submission_cap=cap,
            expires_at=NOW + 86_000,
            now=NOW,
        )
        private_key = X25519PrivateKey.generate()
        store = ArenaAgentStore(self.path, integrity_key=STORE_INTEGRITY_KEY)
        store.issue_device_credential(
            owner_address=self.owner,
            challenge_id=BIO_CHALLENGE_ID,
            challenge_version=BIO_CHALLENGE_VERSION,
            device_id=claims.device_id,
            credential_id=claims.credential_id,
            label="arena-ci",
            kind="ci_service",
            public_key_hex=private_key.public_key().public_bytes_raw().hex(),
            name="dnaseq-agent",
            scopes=claims.scopes,
            daily_submission_cap=claims.daily_submission_cap,
            generation=claims.generation,
            jwt_id_hash=hashlib.sha256(
                b"arena_agent_credential_jti:" + claims.jwt_id.encode()
            ).hexdigest(),
            issued_at=claims.issued_at,
            expires_at=claims.expires_at,
        )
        return store, claims

    def test_request_commitment_is_part_of_attempt_identity(self):
        store, claims = self._registered(cap=2)
        common = dict(
            required_scope=ARENA_SUBMIT_SCOPE,
            used_at=NOW + 10,
            submission_idempotency_key="same-key",
        )
        first = store.authorize_credential(
            claims, submission_request_commitment="1" * 64, **common
        )
        replay = store.authorize_credential(
            claims, submission_request_commitment="1" * 64, **common
        )
        changed = store.authorize_credential(
            claims, submission_request_commitment="2" * 64, **common
        )
        self.assertEqual(first["submission_attempts_used_today"], 1)
        self.assertEqual(replay["submission_attempts_used_today"], 1)
        self.assertEqual(changed["submission_attempts_used_today"], 2)
        with self.assertRaises(ArenaAgentCapExceeded):
            store.authorize_credential(
                claims,
                required_scope=ARENA_SUBMIT_SCOPE,
                used_at=NOW + 11,
                submission_idempotency_key="third-key",
                submission_request_commitment="3" * 64,
            )

    def test_rotation_preserves_daily_attempt_cap_and_supersedes_old_token(self):
        store, claims = self._registered(cap=1)
        admitted = store.authorize_credential(
            claims,
            required_scope=ARENA_SUBMIT_SCOPE,
            used_at=NOW + 10,
            submission_idempotency_key="before-rotation",
            submission_request_commitment="a" * 64,
        )
        self.assertEqual(admitted["submission_attempts_used_today"], 1)

        rotated_claims, _rotated_token = issue_arena_agent_credential_token(
            self.settings,
            credential_id=claims.credential_id,
            device_id=claims.device_id,
            owner_address=self.owner,
            challenge_id=BIO_CHALLENGE_ID,
            challenge_version=BIO_CHALLENGE_VERSION,
            generation=2,
            scopes=ARENA_AGENT_SCOPES,
            daily_submission_cap=1,
            expires_at=NOW + 3_620,
            now=NOW + 20,
        )
        rotated = store.rotate_credential(
            owner_address=self.owner,
            challenge_id=BIO_CHALLENGE_ID,
            challenge_version=BIO_CHALLENGE_VERSION,
            credential_id=claims.credential_id,
            expected_generation=1,
            new_jwt_id_hash=hashlib.sha256(
                b"arena_agent_credential_jti:" + rotated_claims.jwt_id.encode()
            ).hexdigest(),
            issued_at=rotated_claims.issued_at,
            expires_at=rotated_claims.expires_at,
        )
        self.assertEqual(rotated["generation"], 2)
        self.assertEqual(rotated["submission_attempts_used_today"], 1)
        self.assertIsNone(rotated["last_used_at"])

        reloaded = ArenaAgentStore(self.path, integrity_key=STORE_INTEGRITY_KEY)
        listed_after_rotation = reloaded.list_credentials(
            owner_address=self.owner,
            challenge_id=BIO_CHALLENGE_ID,
            challenge_version=BIO_CHALLENGE_VERSION,
            now=NOW + 20,
        )
        self.assertEqual(listed_after_rotation[0]["submission_attempts_used_today"], 1)
        self.assertIsNone(listed_after_rotation[0]["last_used_at"])

        with self.assertRaisesRegex(ArenaAgentAuthorizationError, "superseded"):
            store.authorize_credential(
                claims,
                required_scope=ARENA_OWNER_READ_SCOPE,
                used_at=NOW + 21,
            )
        replay = store.authorize_credential(
            rotated_claims,
            required_scope=ARENA_SUBMIT_SCOPE,
            used_at=NOW + 21,
            submission_idempotency_key="before-rotation",
            submission_request_commitment="a" * 64,
        )
        self.assertEqual(replay["submission_attempts_used_today"], 1)
        with self.assertRaises(ArenaAgentCapExceeded):
            store.authorize_credential(
                rotated_claims,
                required_scope=ARENA_SUBMIT_SCOPE,
                used_at=NOW + 22,
                submission_idempotency_key="after-rotation",
                submission_request_commitment="b" * 64,
            )

    def test_issue_transaction_compacts_only_credentials_past_expiry(self):
        store, first_claims = self._registered(cap=1)
        issued_at = first_claims.expires_at + 1
        second_claims, _token = issue_arena_agent_credential_token(
            self.settings,
            credential_id="acred_" + "e" * 24,
            device_id="adev_" + "f" * 24,
            owner_address=self.owner,
            challenge_id=BIO_CHALLENGE_ID,
            challenge_version=BIO_CHALLENGE_VERSION,
            generation=1,
            scopes=ARENA_AGENT_SCOPES,
            daily_submission_cap=1,
            expires_at=issued_at + 3_600,
            now=issued_at,
        )
        private_key = X25519PrivateKey.generate()
        store.issue_device_credential(
            owner_address=self.owner,
            challenge_id=BIO_CHALLENGE_ID,
            challenge_version=BIO_CHALLENGE_VERSION,
            device_id=second_claims.device_id,
            credential_id=second_claims.credential_id,
            label="replacement-agent",
            kind="autonomous_agent",
            public_key_hex=private_key.public_key().public_bytes_raw().hex(),
            name="replacement-agent",
            scopes=second_claims.scopes,
            daily_submission_cap=second_claims.daily_submission_cap,
            generation=second_claims.generation,
            jwt_id_hash=hashlib.sha256(
                b"arena_agent_credential_jti:" + second_claims.jwt_id.encode()
            ).hexdigest(),
            issued_at=second_claims.issued_at,
            expires_at=second_claims.expires_at,
        )
        listed = store.list_credentials(
            owner_address=self.owner,
            challenge_id=BIO_CHALLENGE_ID,
            challenge_version=BIO_CHALLENGE_VERSION,
            now=issued_at,
        )
        self.assertEqual(
            [item["credential_id"] for item in listed],
            [second_claims.credential_id],
        )

    def test_two_instances_concurrently_cannot_over_admit_cap(self):
        first, claims = self._registered(cap=1)
        second = ArenaAgentStore(self.path, integrity_key=STORE_INTEGRITY_KEY)
        barrier = threading.Barrier(3)

        def attempt(store: ArenaAgentStore, suffix: str) -> str:
            barrier.wait(timeout=5)
            try:
                store.authorize_credential(
                    claims,
                    required_scope=ARENA_SUBMIT_SCOPE,
                    used_at=NOW + 20,
                    submission_idempotency_key=f"concurrent-{suffix}",
                    submission_request_commitment=suffix * 64,
                )
                return "admitted"
            except ArenaAgentCapExceeded:
                return "capped"

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(attempt, first, "a"), executor.submit(attempt, second, "b")]
            barrier.wait(timeout=5)
            results = [future.result(timeout=5) for future in futures]
        self.assertCountEqual(results, ["admitted", "capped"])
        fresh = ArenaAgentStore(self.path, integrity_key=STORE_INTEGRITY_KEY)
        listed = fresh.list_credentials(
            owner_address=self.owner,
            challenge_id=BIO_CHALLENGE_ID,
            challenge_version=BIO_CHALLENGE_VERSION,
            now=NOW + 20,
        )
        self.assertEqual(listed[0]["submission_attempts_used_today"], 1)

    def test_use_time_and_day_never_move_backward(self):
        store, claims = self._registered(cap=2)
        store.authorize_credential(
            claims,
            required_scope=ARENA_SUBMIT_SCOPE,
            used_at=NOW + 100,
            submission_idempotency_key="forward",
            submission_request_commitment="a" * 64,
        )
        with self.assertRaisesRegex(ArenaAgentAuthorizationError, "moved backward"):
            store.authorize_credential(
                claims,
                required_scope=ARENA_OWNER_READ_SCOPE,
                used_at=NOW + 99,
            )

    def test_leaf_and_ancestor_symlinks_and_unsafe_modes_fail_closed(self):
        store, _claims = self._registered()
        os.chmod(self.path, 0o644)
        try:
            with self.assertRaisesRegex(ArenaAgentStoreCorruptError, "mode"):
                store.list_credentials(
                    owner_address=self.owner,
                    challenge_id=BIO_CHALLENGE_ID,
                    challenge_version=BIO_CHALLENGE_VERSION,
                    now=NOW,
                )
        finally:
            os.chmod(self.path, 0o600)

        leaf = self.root / "leaf-link.json"
        leaf.symlink_to(self.path)
        with self.assertRaises(ArenaAgentStoreCorruptError):
            ArenaAgentStore(leaf, integrity_key=STORE_INTEGRITY_KEY)

        real_parent = self.root / "real-parent"
        real_parent.mkdir(mode=0o700)
        alias_parent = self.root / "alias-parent"
        alias_parent.symlink_to(real_parent, target_is_directory=True)
        with self.assertRaisesRegex(ArenaAgentStoreCorruptError, "ancestor"):
            ArenaAgentStore(
                alias_parent / "state.json", integrity_key=STORE_INTEGRITY_KEY
            )

    def test_lock_and_parent_io_failures_are_unavailable_not_bad_requests(self):
        store, _claims = self._registered()
        with patch("tinker_delegate.arena_agent_store.os.open", side_effect=PermissionError):
            with self.assertRaises(ArenaAgentStoreUnavailableError):
                store.list_credentials(
                    owner_address=self.owner,
                    challenge_id=BIO_CHALLENGE_ID,
                    challenge_version=BIO_CHALLENGE_VERSION,
                    now=NOW,
                )

        unavailable_path = self.root / "missing" / "state.json"
        with patch("pathlib.Path.mkdir", side_effect=PermissionError):
            with self.assertRaises(ArenaAgentStoreUnavailableError):
                ArenaAgentStore(
                    unavailable_path,
                    integrity_key=STORE_INTEGRITY_KEY,
                )

    def test_plaintext_token_is_not_persisted(self):
        _store, claims = self._registered()
        raw = self.path.read_text(encoding="utf-8")
        self.assertNotIn(claims.jwt_id, raw)
        self.assertNotIn("plaintext_token", raw)


class ArenaAgentApiTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.original_settings = api.settings
        self.original_arena_store = api._arena_store_instance
        self.original_arena_store_path = api._arena_store_instance_path
        self.original_agent_store = api._arena_agent_store_instance
        self.original_agent_identity = api._arena_agent_store_instance_identity
        api.settings = Settings(
            wallet_auth_signing_key=WALLET_SIGNING_KEY,
            wallet_auth_domain="arena.example",
            wallet_auth_uri="https://arena.example",
            wallet_auth_chain_id=84532,
            arena_store_path=str(self.root / "arena.json"),
            arena_agent_credential_signing_key=AGENT_SIGNING_KEY,
            arena_agent_store_integrity_key=STORE_INTEGRITY_KEY_TEXT,
            arena_agent_store_path=str(self.root / "arena-agent.json"),
        )
        api._arena_store_instance = None
        api._arena_store_instance_path = ""
        api._arena_agent_store_instance = None
        api._arena_agent_store_instance_identity = None
        api._arena_wallet_challenges.clear()
        self.client = TestClient(api.app)
        self.account = Account.from_key(WALLET_PRIVATE_KEY)

    def tearDown(self):
        api._arena_wallet_challenges.clear()
        api._arena_store_instance = self.original_arena_store
        api._arena_store_instance_path = self.original_arena_store_path
        api._arena_agent_store_instance = self.original_agent_store
        api._arena_agent_store_instance_identity = self.original_agent_identity
        api.settings = self.original_settings
        self.temporary.cleanup()

    def _wallet_token(
        self,
        challenge_id: str = BIO_CHALLENGE_ID,
        challenge_version: str = BIO_CHALLENGE_VERSION,
    ) -> str:
        response = self.client.post(
            "/auth/arena/challenge",
            json={
                "address": self.account.address,
                "challenge_id": challenge_id,
                "challenge_version": challenge_version,
                "purpose": "agent_management",
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        challenge = response.json()
        self.assertIn(f"urn:dnai:scope:{ARENA_AGENT_MANAGE_SCOPE}", challenge["message"])
        response = self.client.post(
            "/auth/arena/token",
            json={"nonce": challenge["nonce"], "signature": _signature(challenge["message"])},
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["scopes"], [ARENA_AGENT_MANAGE_SCOPE])
        return response.json()["access_token"]

    @staticmethod
    def _decrypt(body: dict, private_key: X25519PrivateKey) -> str:
        capsule = body["capsule"]
        encrypted = capsule["encrypted_token"]
        shared = private_key.exchange(
            X25519PublicKey.from_public_bytes(
                bytes.fromhex(encrypted["ephemeral_public_key"])
            )
        )
        return AESGCM(
            _derive_aes_key(shared, info=ARENA_AGENT_CREDENTIAL_HKDF_INFO)
        ).decrypt(
            bytes.fromhex(encrypted["nonce"]),
            bytes.fromhex(encrypted["ciphertext"]),
            bytes.fromhex(capsule["associated_data"]),
        ).decode()

    def _issue(self, wallet_token: str, *, public_key: str | None = None):
        private_key = X25519PrivateKey.generate()
        response = self.client.post(
            f"/arena/challenges/{BIO_CHALLENGE_ID}/versions/{BIO_CHALLENGE_VERSION}/agent-credentials",
            headers={"Authorization": f"Bearer {wallet_token}"},
            json={
                "device_label": "arena-ci",
                "device_kind": "ci_service",
                "public_key": public_key or private_key.public_key().public_bytes_raw().hex(),
                "name": "dnaseq-agent",
                "scopes": list(ARENA_AGENT_SCOPES),
                "expires_in_seconds": 3_600,
                "daily_submission_cap": 3,
            },
        )
        return response, private_key

    def test_issue_use_rotate_revoke_and_cross_domain_isolation(self):
        wallet_token = self._wallet_token()
        issued, private_key = self._issue(wallet_token)
        self.assertEqual(issued.status_code, 200, issued.text)
        body = issued.json()
        self.assertNotIn("access_token", body)
        self.assertFalse(body["plaintext_token_returned"])
        self.assertFalse(body["tdx_attestation"])
        self.assertFalse(body["execution_authority"])
        self.assertEqual(body["product_status"], "modeled")
        agent_token = self._decrypt(body, private_key)

        mine = self.client.get(
            f"/arena/challenges/{BIO_CHALLENGE_ID}/versions/{BIO_CHALLENGE_VERSION}/submissions/mine",
            headers={"Authorization": f"Bearer {agent_token}"},
        )
        self.assertEqual(mine.status_code, 200, mine.text)

        management = self.client.get(
            f"/arena/challenges/{BIO_CHALLENGE_ID}/versions/{BIO_CHALLENGE_VERSION}/agent-credentials",
            headers={"Authorization": f"Bearer {agent_token}"},
        )
        self.assertEqual(management.status_code, 401, management.text)

        wrong_challenge = self.client.get(
            f"/arena/challenges/{DNASEQ_SAFE_IR_CHALLENGE_ID}/versions/{DNASEQ_SAFE_IR_CHALLENGE_VERSION}/submissions/mine",
            headers={"Authorization": f"Bearer {agent_token}"},
        )
        self.assertEqual(wrong_challenge.status_code, 401, wrong_challenge.text)

        compute = self.client.post(
            "/compute/projects",
            headers={
                "Authorization": f"Bearer {agent_token}",
                "Idempotency-Key": "agent-cross-domain",
            },
            json={"name": "must-not-create"},
        )
        self.assertEqual(compute.status_code, 401, compute.text)

        credential_id = body["credential"]["credential_id"]
        rotated = self.client.post(
            f"/arena/challenges/{BIO_CHALLENGE_ID}/versions/{BIO_CHALLENGE_VERSION}/agent-credentials/{credential_id}/rotate",
            headers={"Authorization": f"Bearer {wallet_token}"},
            json={"expires_in_seconds": 3_600, "expected_generation": 1},
        )
        self.assertEqual(rotated.status_code, 200, rotated.text)
        rotated_token = self._decrypt(rotated.json(), private_key)
        self.assertTrue(rotated.json()["prior_generation_revoked"])

        stale_retry = self.client.post(
            f"/arena/challenges/{BIO_CHALLENGE_ID}/versions/{BIO_CHALLENGE_VERSION}/agent-credentials/{credential_id}/rotate",
            headers={"Authorization": f"Bearer {wallet_token}"},
            json={"expires_in_seconds": 3_600, "expected_generation": 1},
        )
        self.assertEqual(stale_retry.status_code, 403, stale_retry.text)
        listed_after_stale = self.client.get(
            f"/arena/challenges/{BIO_CHALLENGE_ID}/versions/{BIO_CHALLENGE_VERSION}/agent-credentials",
            headers={"Authorization": f"Bearer {wallet_token}"},
        )
        self.assertEqual(listed_after_stale.status_code, 200, listed_after_stale.text)
        self.assertEqual(listed_after_stale.json()["credentials"][0]["generation"], 2)

        old = self.client.get(
            f"/arena/challenges/{BIO_CHALLENGE_ID}/versions/{BIO_CHALLENGE_VERSION}/submissions/mine",
            headers={"Authorization": f"Bearer {agent_token}"},
        )
        self.assertEqual(old.status_code, 403, old.text)
        current = self.client.get(
            f"/arena/challenges/{BIO_CHALLENGE_ID}/versions/{BIO_CHALLENGE_VERSION}/submissions/mine",
            headers={"Authorization": f"Bearer {rotated_token}"},
        )
        self.assertEqual(current.status_code, 200, current.text)

        revoked = self.client.post(
            f"/arena/challenges/{BIO_CHALLENGE_ID}/versions/{BIO_CHALLENGE_VERSION}/agent-credentials/{credential_id}/revoke",
            headers={"Authorization": f"Bearer {wallet_token}"},
        )
        self.assertEqual(revoked.status_code, 200, revoked.text)
        self.assertEqual(revoked.headers["cache-control"], "no-store, max-age=0")
        after = self.client.get(
            f"/arena/challenges/{BIO_CHALLENGE_ID}/versions/{BIO_CHALLENGE_VERSION}/submissions/mine",
            headers={"Authorization": f"Bearer {rotated_token}"},
        )
        self.assertEqual(after.status_code, 403, after.text)

        raw = (self.root / "arena-agent.json").read_text(encoding="utf-8")
        self.assertNotIn(agent_token, raw)
        self.assertNotIn(rotated_token, raw)

    def test_low_order_key_rejects_before_store_mutation(self):
        wallet_token = self._wallet_token()
        response, _private_key = self._issue(wallet_token, public_key="00" * 32)
        self.assertEqual(response.status_code, 400, response.text)
        listed = self.client.get(
            f"/arena/challenges/{BIO_CHALLENGE_ID}/versions/{BIO_CHALLENGE_VERSION}/agent-credentials",
            headers={"Authorization": f"Bearer {wallet_token}"},
        )
        self.assertEqual(listed.status_code, 200, listed.text)
        self.assertEqual(listed.json()["credentials"], [])

    def test_store_io_unavailability_maps_to_503_for_auth_and_management(self):
        wallet_token = self._wallet_token()
        issued, private_key = self._issue(wallet_token)
        self.assertEqual(issued.status_code, 200, issued.text)
        agent_token = self._decrypt(issued.json(), private_key)

        class UnavailableStore:
            def list_credentials(self, **_kwargs):
                raise ArenaAgentStoreUnavailableError("simulated storage outage")

            def authorize_credential(self, *_args, **_kwargs):
                raise ArenaAgentStoreUnavailableError("simulated storage outage")

        with patch.object(api, "_get_arena_agent_store", return_value=UnavailableStore()):
            management = self.client.get(
                f"/arena/challenges/{BIO_CHALLENGE_ID}/versions/{BIO_CHALLENGE_VERSION}/agent-credentials",
                headers={"Authorization": f"Bearer {wallet_token}"},
            )
            self.assertEqual(management.status_code, 503, management.text)
            authenticated = self.client.get(
                f"/arena/challenges/{BIO_CHALLENGE_ID}/versions/{BIO_CHALLENGE_VERSION}/submissions/mine",
                headers={"Authorization": f"Bearer {agent_token}"},
            )
            self.assertEqual(authenticated.status_code, 503, authenticated.text)


if __name__ == "__main__":
    unittest.main()
