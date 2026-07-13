import json
import os
import tempfile
import unittest
from unittest.mock import patch

from eth_account import Account
from eth_account.messages import encode_defunct
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from tinker_delegate.config import Settings
from tinker_delegate.crypto import _derive_aes_key
from tinker_delegate.tinker_encumbrance import TinkerOperationKind
from tinker_delegate.tinker_proxy import (
    PROXY_TOKEN_HKDF_INFO,
    build_tinker_proxy_status,
    get_proxy_issue_policy_status,
    issue_encrypted_proxy_token,
    save_proxy_issue_policy,
    sign_proxy_grant_lifecycle,
    verify_proxy_token,
)
from tinker_delegate.tinker_proxy_store import build_proxy_token_store
from tinker_delegate.run_metadata_store import stable_hash


UPSTREAM_KEY = "tml-secretsecretsecretsecretsecret"
PROJECT_ID = "proj-sensitive"
BASE_URL = "https://api.thinkingmachines.ai"
SIGNING_KEY_HEX = "11" * 32
STORE_KEY_HEX = "66" * 32
CONTRACT = "0x" + "22" * 20
COMPOSE_HASH = "0x" + "33" * 32


def _recipient_keypair():
    private_key = X25519PrivateKey.generate()
    public_key_hex = private_key.public_key().public_bytes_raw().hex()
    return private_key, public_key_hex


def _decrypt_token(private_key, payload: dict) -> str:
    encrypted = payload["encrypted_token"]
    sender_public = X25519PublicKey.from_public_bytes(bytes.fromhex(encrypted["ephemeral_public_key"]))
    shared_secret = private_key.exchange(sender_public)
    aes_key = _derive_aes_key(shared_secret, info=PROXY_TOKEN_HKDF_INFO)
    return AESGCM(aes_key).decrypt(
        bytes.fromhex(encrypted["nonce"]),
        bytes.fromhex(encrypted["ciphertext"]),
        bytes.fromhex(payload["associated_data"]),
    ).decode("utf-8")


def _write_proxy_issue_policy(
    path: str,
    *,
    subject: str,
    recipient_public_key_hex: str,
    scopes: list[str],
    ttl: int,
    scope_limits: dict | None = None,
    lifecycle: dict | None = None,
):
    grant = {
        "subject_hash": stable_hash(subject, prefix="proxy_subject"),
        "recipient_public_key_hash": stable_hash(
            recipient_public_key_hex.lower(),
            prefix="proxy_recipient_public_key",
        ),
        "scopes": scopes,
        "max_ttl_seconds": ttl,
    }
    if scope_limits is not None:
        grant["scope_limits"] = scope_limits
    if lifecycle is not None:
        grant["lifecycle"] = lifecycle
    policy = {
        "schema_version": 1,
        "grants": [grant],
    }
    with open(path, "w") as handle:
        json.dump(policy, handle, sort_keys=True)
    return policy


def _active_grant_lifecycle(*, approved_at: int = 900, expires_at: int = 2000) -> dict:
    return {
        "status": "active",
        "approved_by_hash": stable_hash("reviewer-1", prefix="proxy_grant_reviewer"),
        "approval_event_hash": stable_hash("approval-event-1", prefix="proxy_grant_approval"),
        "approved_at": approved_at,
        "expires_at": expires_at,
    }


def _active_signed_grant_lifecycle(account, *, approved_at: int = 900, expires_at: int = 2000) -> dict:
    return {
        "status": "active",
        "approved_by_hash": stable_hash(account.address.lower(), prefix="proxy_grant_reviewer"),
        "approval_event_hash": stable_hash("approval-event-1", prefix="proxy_grant_approval"),
        "approved_at": approved_at,
        "expires_at": expires_at,
    }


def _write_proxy_identity_registry(
    path: str,
    *,
    subject: str = "buyer-agent-1",
    reviewer: str = "reviewer-1",
    subject_status: str = "active",
    reviewer_status: str = "active",
    subject_expires_at: int = 2000,
    reviewer_expires_at: int = 2000,
):
    registry = {
        "schema_version": 1,
        "identities": [
            {
                "identity_hash": stable_hash(subject, prefix="proxy_subject"),
                "role": "agent",
                "status": subject_status,
                "expires_at": subject_expires_at,
            },
            {
                "identity_hash": stable_hash(reviewer, prefix="proxy_grant_reviewer"),
                "role": "reviewer",
                "status": reviewer_status,
                "expires_at": reviewer_expires_at,
            },
        ],
    }
    with open(path, "w") as handle:
        json.dump(registry, handle, sort_keys=True)
    return registry


def _identity_registry_hash(registry: dict) -> str:
    unsigned = {
        "schema_version": 1,
        "identities": sorted(
            [
                {
                    "identity_hash": identity["identity_hash"].lower(),
                    "role": identity["role"].lower(),
                    "status": identity["status"].lower(),
                    "expires_at": int(identity["expires_at"]),
                }
                for identity in registry["identities"]
            ],
            key=lambda item: (item["identity_hash"], item["role"]),
        ),
    }
    return stable_hash(json.dumps(unsigned, separators=(",", ":"), sort_keys=True), prefix="proxy_identity_registry")


def _sign_proxy_identity_registry(registry: dict, account) -> dict:
    registry_hash = _identity_registry_hash(registry)
    signed = account.sign_message(encode_defunct(hexstr="0x" + registry_hash))
    signed_registry = dict(registry)
    signed_registry["signature"] = {
        "kind": "ethereum_signed_message",
        "signer": account.address,
        "registry_hash": "0x" + registry_hash,
        "signature": "0x" + bytes(signed.signature).hex(),
    }
    return signed_registry


class _EncumbranceResult:
    def __init__(self, *, allowed: bool = True, reason: str = "allowed"):
        self.allowed = allowed
        self.reason = reason

    def to_public_dict(self):
        return {
            "checked": True,
            "allowed": self.allowed,
            "reason": self.reason,
            "operation": "add_balance",
            "operation_kind": int(TinkerOperationKind.ADD_BALANCE),
            "contract_address": CONTRACT.lower(),
            "compose_hash": COMPOSE_HASH,
            "compose_approved": self.allowed,
            "emergency_halted": False,
            "amount_wei": str(10 * 10**18),
            "max_amount_wei": str(10 * 10**18),
            "limit_kind": "add_balance",
            "raw_secret_egress": False,
        }


class TinkerProxyTest(unittest.TestCase):
    def _settings(self, tmpdir: str, **overrides) -> Settings:
        values = {
            "proxy_jwt_key": SIGNING_KEY_HEX,
            "proxy_token_store_path": os.path.join(tmpdir, "proxy_tokens.enc"),
            "proxy_token_store_key": STORE_KEY_HEX,
        }
        values.update(overrides)
        return Settings(**values)

    def test_status_is_bounded_and_does_not_return_upstream_config(self):
        settings = Settings(
            project_id=PROJECT_ID,
            base_url=BASE_URL,
            proxy_jwt_key=SIGNING_KEY_HEX,
            proxy_require_issue_policy=True,
            proxy_issue_policy_path="/sealed/policy.json",
            proxy_require_grant_lifecycle_signature=True,
            proxy_require_identity_registry_signature=True,
            proxy_identity_registry_signer=Account.create("status signer").address,
        )

        with patch.dict(os.environ, {"TINKER_API_KEY": UPSTREAM_KEY}, clear=False):
            status = build_tinker_proxy_status(settings)

        rendered = repr(status)
        self.assertTrue(status["success"])
        self.assertEqual(status["sealed_client_config"]["api_key_configured"], True)
        self.assertEqual(status["sealed_client_config"]["project_id_configured"], True)
        self.assertEqual(status["sealed_client_config"]["base_url_host_family"], "thinkingmachines")
        self.assertTrue(status["token_issuer"]["issue_policy_required"])
        self.assertTrue(status["token_issuer"]["issue_policy_configured"])
        self.assertTrue(status["token_issuer"]["grant_lifecycle_signature_required"])
        self.assertTrue(status["token_issuer"]["identity_registry_signature_required"])
        self.assertTrue(status["token_issuer"]["identity_registry_signer_configured"])
        self.assertFalse(status["raw_secret_egress"])
        self.assertNotIn(UPSTREAM_KEY, rendered)
        self.assertNotIn(PROJECT_ID, rendered)
        self.assertNotIn(BASE_URL, rendered)
        self.assertNotIn(settings.proxy_identity_registry_signer, rendered)

    def test_issue_encrypted_proxy_token_and_verify_decrypted_jwt(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            private_key, public_key_hex = _recipient_keypair()
            settings = self._settings(
                tmpdir,
                proxy_approved_subjects="buyer-agent-1",
                proxy_jwt_default_ttl_seconds=60,
                proxy_jwt_max_ttl_seconds=120,
            )

            issued = issue_encrypted_proxy_token(
                settings,
                subject="buyer-agent-1",
                scopes=["proxy:status", "tinker:smoke"],
                recipient_public_key_hex=public_key_hex,
                ttl_seconds=90,
                now=1000,
            )
            token = _decrypt_token(private_key, issued)
            verification = verify_proxy_token(settings, token, required_scope="proxy:status", now=1010)
            records = build_proxy_token_store(settings).load()

        rendered = repr(issued)
        self.assertTrue(issued["success"])
        self.assertEqual(issued["token"]["ttl_seconds"], 90)
        self.assertEqual(verification["scopes"], ["proxy:status", "tinker:smoke"])
        self.assertEqual(records[0]["event"], "issued")
        self.assertEqual(records[0]["jwt_id_hash"], issued["token"]["jwt_id_hash"])
        self.assertEqual(issued["audit_record"], records[0])
        self.assertFalse(issued["plaintext_token_returned"])
        self.assertFalse(issued["raw_secret_egress"])
        self.assertNotIn(token, rendered)
        self.assertNotIn("buyer-agent-1", rendered)

    def test_issue_encrypted_proxy_token_binds_to_hash_only_issue_policy(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            private_key, public_key_hex = _recipient_keypair()
            policy_path = os.path.join(tmpdir, "proxy-policy.json")
            _write_proxy_issue_policy(
                policy_path,
                subject="buyer-agent-1",
                recipient_public_key_hex=public_key_hex,
                scopes=["proxy:status", "billing:payment-method-status"],
                ttl=60,
            )
            settings = self._settings(
                tmpdir,
                proxy_require_issue_policy=True,
                proxy_issue_policy_path=policy_path,
            )

            issued = issue_encrypted_proxy_token(
                settings,
                subject="buyer-agent-1",
                scopes=["billing:payment-method-status"],
                recipient_public_key_hex=public_key_hex,
                ttl_seconds=60,
                now=1000,
            )
            token = _decrypt_token(private_key, issued)
            verification = verify_proxy_token(
                settings,
                token,
                required_scope="billing:payment-method-status",
                now=1001,
            )

        rendered = repr(issued)
        self.assertTrue(issued["success"])
        self.assertTrue(issued["policy_binding"]["required"])
        self.assertTrue(issued["policy_binding"]["configured"])
        self.assertEqual(issued["policy_binding"]["requested_scopes"], ["billing:payment-method-status"])
        self.assertEqual(verification["scopes"], ["billing:payment-method-status"])
        self.assertFalse(issued["policy_binding"]["raw_secret_egress"])
        self.assertNotIn("buyer-agent-1", rendered)
        self.assertNotIn(public_key_hex, rendered)

    def test_issue_policy_embeds_spend_limit_for_add_balance_scope(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            private_key, public_key_hex = _recipient_keypair()
            policy_path = os.path.join(tmpdir, "proxy-policy.json")
            _write_proxy_issue_policy(
                policy_path,
                subject="buyer-agent-1",
                recipient_public_key_hex=public_key_hex,
                scopes=["billing:add-balance"],
                ttl=60,
                scope_limits={"billing:add-balance": {"max_amount_usd": 10}},
            )
            settings = self._settings(
                tmpdir,
                proxy_require_issue_policy=True,
                proxy_issue_policy_path=policy_path,
            )

            issued = issue_encrypted_proxy_token(
                settings,
                subject="buyer-agent-1",
                scopes=["billing:add-balance"],
                recipient_public_key_hex=public_key_hex,
                ttl_seconds=60,
                now=1000,
            )
            token = _decrypt_token(private_key, issued)
            verification = verify_proxy_token(
                settings,
                token,
                required_scope="billing:add-balance",
                now=1001,
            )

        self.assertEqual(
            issued["policy_binding"]["scope_limits"],
            {"billing:add-balance": {"max_amount_usd": 10.0}},
        )
        self.assertEqual(
            verification["scope_limits"],
            {"billing:add-balance": {"max_amount_usd": 10.0}},
        )

    def test_issue_policy_can_require_active_hash_only_grant_lifecycle(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            private_key, public_key_hex = _recipient_keypair()
            policy_path = os.path.join(tmpdir, "proxy-policy.json")
            lifecycle = _active_grant_lifecycle()
            _write_proxy_issue_policy(
                policy_path,
                subject="buyer-agent-1",
                recipient_public_key_hex=public_key_hex,
                scopes=["proxy:status"],
                ttl=60,
                lifecycle=lifecycle,
            )
            settings = self._settings(
                tmpdir,
                proxy_require_issue_policy=True,
                proxy_issue_policy_path=policy_path,
                proxy_require_grant_lifecycle=True,
            )

            issued = issue_encrypted_proxy_token(
                settings,
                subject="buyer-agent-1",
                scopes=["proxy:status"],
                recipient_public_key_hex=public_key_hex,
                ttl_seconds=60,
                now=1000,
            )
            token = _decrypt_token(private_key, issued)
            verification = verify_proxy_token(settings, token, required_scope="proxy:status", now=1001)

        grant_lifecycle = issued["policy_binding"]["grant_lifecycle"]
        rendered = repr(issued)
        self.assertEqual(grant_lifecycle["status"], "active")
        self.assertEqual(grant_lifecycle["approved_by_hash"], lifecycle["approved_by_hash"])
        self.assertEqual(grant_lifecycle["approval_event_hash"], lifecycle["approval_event_hash"])
        self.assertTrue(grant_lifecycle["checked"])
        self.assertFalse(grant_lifecycle["raw_secret_egress"])
        self.assertEqual(verification["scopes"], ["proxy:status"])
        self.assertNotIn("reviewer-1", rendered)
        self.assertNotIn("approval-event-1", rendered)

    def test_issue_policy_requires_grant_lifecycle_when_enabled(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _, public_key_hex = _recipient_keypair()
            policy_path = os.path.join(tmpdir, "proxy-policy.json")
            _write_proxy_issue_policy(
                policy_path,
                subject="buyer-agent-1",
                recipient_public_key_hex=public_key_hex,
                scopes=["proxy:status"],
                ttl=60,
            )
            settings = self._settings(
                tmpdir,
                proxy_require_issue_policy=True,
                proxy_issue_policy_path=policy_path,
                proxy_require_grant_lifecycle=True,
            )

            with self.assertRaisesRegex(ValueError, "grant lifecycle is required"):
                issue_encrypted_proxy_token(
                    settings,
                    subject="buyer-agent-1",
                    scopes=["proxy:status"],
                    recipient_public_key_hex=public_key_hex,
                    ttl_seconds=60,
                    now=1000,
                )

    def test_issue_policy_rejects_inactive_grant_lifecycle(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _, public_key_hex = _recipient_keypair()
            policy_path = os.path.join(tmpdir, "proxy-policy.json")
            _write_proxy_issue_policy(
                policy_path,
                subject="buyer-agent-1",
                recipient_public_key_hex=public_key_hex,
                scopes=["proxy:status"],
                ttl=60,
                lifecycle={"status": "pending"},
            )
            settings = self._settings(
                tmpdir,
                proxy_require_issue_policy=True,
                proxy_issue_policy_path=policy_path,
                proxy_require_grant_lifecycle=True,
            )

            with self.assertRaisesRegex(ValueError, "grant lifecycle is not active"):
                issue_encrypted_proxy_token(
                    settings,
                    subject="buyer-agent-1",
                    scopes=["proxy:status"],
                    recipient_public_key_hex=public_key_hex,
                    ttl_seconds=60,
                    now=1000,
                )

    def test_issue_policy_rejects_expired_or_future_grant_lifecycle(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _, public_key_hex = _recipient_keypair()
            expired_policy_path = os.path.join(tmpdir, "expired-policy.json")
            _write_proxy_issue_policy(
                expired_policy_path,
                subject="buyer-agent-1",
                recipient_public_key_hex=public_key_hex,
                scopes=["proxy:status"],
                ttl=60,
                lifecycle=_active_grant_lifecycle(approved_at=100, expires_at=900),
            )
            expired_settings = self._settings(
                tmpdir,
                proxy_require_issue_policy=True,
                proxy_issue_policy_path=expired_policy_path,
                proxy_require_grant_lifecycle=True,
            )

            with self.assertRaisesRegex(ValueError, "grant lifecycle expired"):
                issue_encrypted_proxy_token(
                    expired_settings,
                    subject="buyer-agent-1",
                    scopes=["proxy:status"],
                    recipient_public_key_hex=public_key_hex,
                    ttl_seconds=60,
                    now=1000,
                )

            future_policy_path = os.path.join(tmpdir, "future-policy.json")
            _write_proxy_issue_policy(
                future_policy_path,
                subject="buyer-agent-1",
                recipient_public_key_hex=public_key_hex,
                scopes=["proxy:status"],
                ttl=60,
                lifecycle=_active_grant_lifecycle(approved_at=1200, expires_at=2000),
            )
            future_settings = self._settings(
                tmpdir,
                proxy_require_issue_policy=True,
                proxy_issue_policy_path=future_policy_path,
                proxy_require_grant_lifecycle=True,
            )

            with self.assertRaisesRegex(ValueError, "grant lifecycle is not active yet"):
                issue_encrypted_proxy_token(
                    future_settings,
                    subject="buyer-agent-1",
                    scopes=["proxy:status"],
                    recipient_public_key_hex=public_key_hex,
                    ttl_seconds=60,
                    now=1000,
                )

    def test_issue_policy_can_require_reviewer_signed_grant_lifecycle(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            private_key, public_key_hex = _recipient_keypair()
            reviewer = Account.create("reviewer signs proxy grant lifecycle")
            policy_path = os.path.join(tmpdir, "proxy-policy.json")
            unsigned_policy = _write_proxy_issue_policy(
                policy_path,
                subject="buyer-agent-1",
                recipient_public_key_hex=public_key_hex,
                scopes=["proxy:status"],
                ttl=60,
                lifecycle=_active_signed_grant_lifecycle(reviewer),
            )
            signed_grant, sign_receipt = sign_proxy_grant_lifecycle(
                unsigned_policy["grants"][0],
                reviewer.key.hex(),
            )
            with open(policy_path, "w") as handle:
                json.dump({"schema_version": 1, "grants": [signed_grant]}, handle, sort_keys=True)
            settings = self._settings(
                tmpdir,
                proxy_require_issue_policy=True,
                proxy_issue_policy_path=policy_path,
                proxy_require_grant_lifecycle=True,
                proxy_require_grant_lifecycle_signature=True,
            )

            issued = issue_encrypted_proxy_token(
                settings,
                subject="buyer-agent-1",
                scopes=["proxy:status"],
                recipient_public_key_hex=public_key_hex,
                ttl_seconds=60,
                now=1000,
            )
            token = _decrypt_token(private_key, issued)
            verification = verify_proxy_token(settings, token, required_scope="proxy:status", now=1001)

        binding = issued["policy_binding"]["grant_lifecycle"]["approval_signature_binding"]
        rendered = repr([issued, sign_receipt])
        self.assertTrue(binding["required"])
        self.assertTrue(binding["verified"])
        self.assertEqual(binding["approval_hash"], sign_receipt["approval_hash"])
        self.assertEqual(verification["scopes"], ["proxy:status"])
        self.assertFalse(binding["raw_secret_egress"])
        self.assertNotIn(reviewer.key.hex(), rendered)
        self.assertNotIn(reviewer.address, rendered)
        self.assertNotIn(signed_grant["lifecycle"]["approval_signature"]["signature"], rendered)
        self.assertNotIn("buyer-agent-1", rendered)

    def test_issue_policy_requires_reviewer_signature_when_enabled(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _, public_key_hex = _recipient_keypair()
            reviewer = Account.create("unsigned proxy grant reviewer")
            policy_path = os.path.join(tmpdir, "proxy-policy.json")
            _write_proxy_issue_policy(
                policy_path,
                subject="buyer-agent-1",
                recipient_public_key_hex=public_key_hex,
                scopes=["proxy:status"],
                ttl=60,
                lifecycle=_active_signed_grant_lifecycle(reviewer),
            )
            settings = self._settings(
                tmpdir,
                proxy_require_issue_policy=True,
                proxy_issue_policy_path=policy_path,
                proxy_require_grant_lifecycle=True,
                proxy_require_grant_lifecycle_signature=True,
            )

            with self.assertRaisesRegex(ValueError, "grant lifecycle signature is required"):
                issue_encrypted_proxy_token(
                    settings,
                    subject="buyer-agent-1",
                    scopes=["proxy:status"],
                    recipient_public_key_hex=public_key_hex,
                    ttl_seconds=60,
                    now=1000,
                )

    def test_grant_lifecycle_signature_must_match_approved_reviewer_hash(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _, public_key_hex = _recipient_keypair()
            approved_reviewer = Account.create("approved proxy grant reviewer")
            wrong_reviewer = Account.create("wrong proxy grant reviewer")
            policy_path = os.path.join(tmpdir, "proxy-policy.json")
            unsigned_policy = _write_proxy_issue_policy(
                policy_path,
                subject="buyer-agent-1",
                recipient_public_key_hex=public_key_hex,
                scopes=["proxy:status"],
                ttl=60,
                lifecycle=_active_signed_grant_lifecycle(approved_reviewer),
            )

            with self.assertRaisesRegex(ValueError, "signer does not match"):
                sign_proxy_grant_lifecycle(unsigned_policy["grants"][0], wrong_reviewer.key.hex())

    def test_issue_policy_can_require_hash_only_identity_registry(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            private_key, public_key_hex = _recipient_keypair()
            policy_path = os.path.join(tmpdir, "proxy-policy.json")
            registry_path = os.path.join(tmpdir, "identity-registry.json")
            _write_proxy_issue_policy(
                policy_path,
                subject="buyer-agent-1",
                recipient_public_key_hex=public_key_hex,
                scopes=["proxy:status"],
                ttl=60,
                lifecycle=_active_grant_lifecycle(),
            )
            registry = _write_proxy_identity_registry(registry_path)
            settings = self._settings(
                tmpdir,
                proxy_require_issue_policy=True,
                proxy_issue_policy_path=policy_path,
                proxy_require_grant_lifecycle=True,
                proxy_require_identity_registry=True,
                proxy_identity_registry_path=registry_path,
            )

            issued = issue_encrypted_proxy_token(
                settings,
                subject="buyer-agent-1",
                scopes=["proxy:status"],
                recipient_public_key_hex=public_key_hex,
                ttl_seconds=60,
                now=1000,
            )
            token = _decrypt_token(private_key, issued)
            verification = verify_proxy_token(settings, token, required_scope="proxy:status", now=1001)

        binding = issued["policy_binding"]["identity_binding"]
        rendered = repr(issued)
        self.assertEqual(
            binding["registry_hash"],
            stable_hash(json.dumps(registry, separators=(",", ":"), sort_keys=True), prefix="proxy_identity_registry"),
        )
        self.assertEqual(binding["subject"]["role"], "agent")
        self.assertEqual(binding["reviewer"]["role"], "reviewer")
        self.assertFalse(binding["raw_secret_egress"])
        self.assertEqual(verification["scopes"], ["proxy:status"])
        self.assertNotIn("buyer-agent-1", rendered)
        self.assertNotIn("reviewer-1", rendered)

    def test_identity_registry_can_require_verifier_signature(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            private_key, public_key_hex = _recipient_keypair()
            policy_path = os.path.join(tmpdir, "proxy-policy.json")
            registry_path = os.path.join(tmpdir, "identity-registry.json")
            _write_proxy_issue_policy(
                policy_path,
                subject="buyer-agent-1",
                recipient_public_key_hex=public_key_hex,
                scopes=["proxy:status"],
                ttl=60,
                lifecycle=_active_grant_lifecycle(),
            )
            registry = _write_proxy_identity_registry(registry_path)
            signer_account = Account.create("proxy identity registry signer")
            signed_registry = _sign_proxy_identity_registry(registry, signer_account)
            with open(registry_path, "w") as handle:
                json.dump(signed_registry, handle, sort_keys=True)
            signer = signer_account.address
            settings = self._settings(
                tmpdir,
                proxy_require_issue_policy=True,
                proxy_issue_policy_path=policy_path,
                proxy_require_grant_lifecycle=True,
                proxy_require_identity_registry=True,
                proxy_identity_registry_path=registry_path,
                proxy_require_identity_registry_signature=True,
                proxy_identity_registry_signer=signer,
            )

            issued = issue_encrypted_proxy_token(
                settings,
                subject="buyer-agent-1",
                scopes=["proxy:status"],
                recipient_public_key_hex=public_key_hex,
                ttl_seconds=60,
                now=1000,
            )
            token = _decrypt_token(private_key, issued)
            verification = verify_proxy_token(settings, token, required_scope="proxy:status", now=1001)

        binding = issued["policy_binding"]["identity_binding"]
        signature_binding = binding["signature_binding"]
        rendered = repr(issued)
        self.assertTrue(signature_binding["required"])
        self.assertTrue(signature_binding["verified"])
        self.assertEqual(signature_binding["registry_hash"], _identity_registry_hash(registry))
        self.assertEqual(binding["registry_hash"], _identity_registry_hash(registry))
        self.assertEqual(signature_binding["signer_hash"], stable_hash(signer.lower(), prefix="proxy_identity_registry_signer"))
        self.assertEqual(verification["scopes"], ["proxy:status"])
        self.assertFalse(signature_binding["raw_secret_egress"])
        self.assertNotIn(signer, rendered)
        self.assertNotIn(signed_registry["signature"]["signature"], rendered)

    def test_identity_registry_signature_required_fails_closed_when_missing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _, public_key_hex = _recipient_keypair()
            policy_path = os.path.join(tmpdir, "proxy-policy.json")
            registry_path = os.path.join(tmpdir, "identity-registry.json")
            _write_proxy_issue_policy(
                policy_path,
                subject="buyer-agent-1",
                recipient_public_key_hex=public_key_hex,
                scopes=["proxy:status"],
                ttl=60,
                lifecycle=_active_grant_lifecycle(),
            )
            _write_proxy_identity_registry(registry_path)
            settings = self._settings(
                tmpdir,
                proxy_require_issue_policy=True,
                proxy_issue_policy_path=policy_path,
                proxy_require_grant_lifecycle=True,
                proxy_require_identity_registry=True,
                proxy_identity_registry_path=registry_path,
                proxy_require_identity_registry_signature=True,
                proxy_identity_registry_signer=Account.create("proxy identity registry signer").address,
            )

            with self.assertRaisesRegex(ValueError, "identity registry signature is required"):
                issue_encrypted_proxy_token(
                    settings,
                    subject="buyer-agent-1",
                    scopes=["proxy:status"],
                    recipient_public_key_hex=public_key_hex,
                    ttl_seconds=60,
                    now=1000,
                )

    def test_identity_registry_signature_rejects_tamper_or_wrong_signer(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _, public_key_hex = _recipient_keypair()
            policy_path = os.path.join(tmpdir, "proxy-policy.json")
            registry_path = os.path.join(tmpdir, "identity-registry.json")
            _write_proxy_issue_policy(
                policy_path,
                subject="buyer-agent-1",
                recipient_public_key_hex=public_key_hex,
                scopes=["proxy:status"],
                ttl=60,
                lifecycle=_active_grant_lifecycle(),
            )
            registry = _write_proxy_identity_registry(registry_path)
            signer_account = Account.create("proxy identity registry signer")
            signed_registry = _sign_proxy_identity_registry(registry, signer_account)
            signed_registry["identities"][0]["status"] = "revoked"
            with open(registry_path, "w") as handle:
                json.dump(signed_registry, handle, sort_keys=True)
            signer = signer_account.address
            settings = self._settings(
                tmpdir,
                proxy_require_issue_policy=True,
                proxy_issue_policy_path=policy_path,
                proxy_require_grant_lifecycle=True,
                proxy_require_identity_registry=True,
                proxy_identity_registry_path=registry_path,
                proxy_require_identity_registry_signature=True,
                proxy_identity_registry_signer=signer,
            )

            with self.assertRaisesRegex(ValueError, "signature hash mismatch"):
                issue_encrypted_proxy_token(
                    settings,
                    subject="buyer-agent-1",
                    scopes=["proxy:status"],
                    recipient_public_key_hex=public_key_hex,
                    ttl_seconds=60,
                    now=1000,
                )

            signed_registry = _sign_proxy_identity_registry(registry, signer_account)
            with open(registry_path, "w") as handle:
                json.dump(signed_registry, handle, sort_keys=True)
            wrong_signer_settings = self._settings(
                tmpdir,
                proxy_require_issue_policy=True,
                proxy_issue_policy_path=policy_path,
                proxy_require_grant_lifecycle=True,
                proxy_require_identity_registry=True,
                proxy_identity_registry_path=registry_path,
                proxy_require_identity_registry_signature=True,
                proxy_identity_registry_signer=Account.create("wrong-proxy-registry-signer").address,
            )

            with self.assertRaisesRegex(ValueError, "identity registry signer mismatch"):
                issue_encrypted_proxy_token(
                    wrong_signer_settings,
                    subject="buyer-agent-1",
                    scopes=["proxy:status"],
                    recipient_public_key_hex=public_key_hex,
                    ttl_seconds=60,
                    now=1000,
                )

    def test_identity_registry_required_fails_closed_without_registry_path(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _, public_key_hex = _recipient_keypair()
            policy_path = os.path.join(tmpdir, "proxy-policy.json")
            _write_proxy_issue_policy(
                policy_path,
                subject="buyer-agent-1",
                recipient_public_key_hex=public_key_hex,
                scopes=["proxy:status"],
                ttl=60,
                lifecycle=_active_grant_lifecycle(),
            )
            settings = self._settings(
                tmpdir,
                proxy_require_issue_policy=True,
                proxy_issue_policy_path=policy_path,
                proxy_require_grant_lifecycle=True,
                proxy_require_identity_registry=True,
            )

            with self.assertRaisesRegex(ValueError, "identity registry is required"):
                issue_encrypted_proxy_token(
                    settings,
                    subject="buyer-agent-1",
                    scopes=["proxy:status"],
                    recipient_public_key_hex=public_key_hex,
                    ttl_seconds=60,
                    now=1000,
                )

    def test_identity_registry_rejects_inactive_subject_or_expired_reviewer(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _, public_key_hex = _recipient_keypair()
            policy_path = os.path.join(tmpdir, "proxy-policy.json")
            _write_proxy_issue_policy(
                policy_path,
                subject="buyer-agent-1",
                recipient_public_key_hex=public_key_hex,
                scopes=["proxy:status"],
                ttl=60,
                lifecycle=_active_grant_lifecycle(),
            )
            inactive_registry_path = os.path.join(tmpdir, "inactive-registry.json")
            _write_proxy_identity_registry(inactive_registry_path, subject_status="suspended")
            inactive_settings = self._settings(
                tmpdir,
                proxy_require_issue_policy=True,
                proxy_issue_policy_path=policy_path,
                proxy_require_grant_lifecycle=True,
                proxy_require_identity_registry=True,
                proxy_identity_registry_path=inactive_registry_path,
            )

            with self.assertRaisesRegex(ValueError, "subject identity is not active"):
                issue_encrypted_proxy_token(
                    inactive_settings,
                    subject="buyer-agent-1",
                    scopes=["proxy:status"],
                    recipient_public_key_hex=public_key_hex,
                    ttl_seconds=60,
                    now=1000,
                )

            expired_registry_path = os.path.join(tmpdir, "expired-registry.json")
            _write_proxy_identity_registry(expired_registry_path, reviewer_expires_at=900)
            expired_settings = self._settings(
                tmpdir,
                proxy_require_issue_policy=True,
                proxy_issue_policy_path=policy_path,
                proxy_require_grant_lifecycle=True,
                proxy_require_identity_registry=True,
                proxy_identity_registry_path=expired_registry_path,
            )

            with self.assertRaisesRegex(ValueError, "reviewer identity expired"):
                issue_encrypted_proxy_token(
                    expired_settings,
                    subject="buyer-agent-1",
                    scopes=["proxy:status"],
                    recipient_public_key_hex=public_key_hex,
                    ttl_seconds=60,
                    now=1000,
                )

    def test_issue_policy_can_require_deployment_policy_before_minting(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            private_key, public_key_hex = _recipient_keypair()
            policy_path = os.path.join(tmpdir, "proxy-policy.json")
            _write_proxy_issue_policy(
                policy_path,
                subject="buyer-agent-1",
                recipient_public_key_hex=public_key_hex,
                scopes=["billing:add-balance"],
                ttl=60,
                scope_limits={"billing:add-balance": {"max_amount_usd": 10}},
            )
            settings = self._settings(
                tmpdir,
                proxy_require_issue_policy=True,
                proxy_issue_policy_path=policy_path,
                proxy_require_deployment_policy=True,
                encumbrance_contract_address=CONTRACT,
                encumbrance_compose_hash=COMPOSE_HASH,
                encumbrance_rpc_url="https://example.invalid/rpc",
            )

            with patch(
                "tinker_delegate.tinker_encumbrance.preflight_tinker_operation",
                return_value=_EncumbranceResult(),
            ) as preflight:
                issued = issue_encrypted_proxy_token(
                    settings,
                    subject="buyer-agent-1",
                    scopes=["billing:add-balance"],
                    recipient_public_key_hex=public_key_hex,
                    ttl_seconds=60,
                    now=1000,
                )
            token = _decrypt_token(private_key, issued)
            verification = verify_proxy_token(
                settings,
                token,
                required_scope="billing:add-balance",
                now=1001,
            )

        preflight.assert_called_once()
        call = preflight.call_args.kwargs
        self.assertEqual(call["operation_kind"], TinkerOperationKind.ADD_BALANCE)
        self.assertEqual(call["amount_dollars"], 10.0)
        self.assertTrue(call["required"])
        deployment = issued["policy_binding"]["deployment_policy"]
        rendered = repr(issued)
        self.assertTrue(deployment["required"])
        self.assertTrue(deployment["checks"][0]["allowed"])
        self.assertFalse(deployment["raw_secret_egress"])
        self.assertEqual(
            verification["scope_limits"],
            {"billing:add-balance": {"max_amount_usd": 10.0}},
        )
        self.assertNotIn("https://example.invalid/rpc", rendered)
        self.assertNotIn(token, rendered)

    def test_deployment_policy_denies_token_before_minting(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _, public_key_hex = _recipient_keypair()
            policy_path = os.path.join(tmpdir, "proxy-policy.json")
            _write_proxy_issue_policy(
                policy_path,
                subject="buyer-agent-1",
                recipient_public_key_hex=public_key_hex,
                scopes=["billing:add-balance"],
                ttl=60,
                scope_limits={"billing:add-balance": {"max_amount_usd": 10}},
            )
            settings = self._settings(
                tmpdir,
                proxy_require_issue_policy=True,
                proxy_issue_policy_path=policy_path,
                proxy_require_deployment_policy=True,
                encumbrance_contract_address=CONTRACT,
                encumbrance_compose_hash=COMPOSE_HASH,
                encumbrance_rpc_url="https://example.invalid/rpc",
            )

            with patch(
                "tinker_delegate.tinker_encumbrance.preflight_tinker_operation",
                return_value=_EncumbranceResult(allowed=False, reason="compose_hash_not_approved"),
            ):
                with self.assertRaisesRegex(ValueError, "compose_hash_not_approved"):
                    issue_encrypted_proxy_token(
                        settings,
                        subject="buyer-agent-1",
                        scopes=["billing:add-balance"],
                        recipient_public_key_hex=public_key_hex,
                        ttl_seconds=60,
                        now=1000,
                    )

    def test_deployment_policy_checks_read_only_scope_compose_approval(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            private_key, public_key_hex = _recipient_keypair()
            settings = self._settings(
                tmpdir,
                proxy_approved_subjects="buyer-agent-1",
                proxy_require_deployment_policy=True,
                encumbrance_contract_address=CONTRACT,
                encumbrance_compose_hash=COMPOSE_HASH,
                encumbrance_rpc_url="https://example.invalid/rpc",
            )

            with patch(
                "tinker_delegate.tinker_encumbrance.preflight_tinker_operation",
                return_value=_EncumbranceResult(),
            ) as preflight:
                issued = issue_encrypted_proxy_token(
                    settings,
                    subject="buyer-agent-1",
                    scopes=["proxy:status"],
                    recipient_public_key_hex=public_key_hex,
                    ttl_seconds=60,
                    now=1000,
                )
            token = _decrypt_token(private_key, issued)

        call = preflight.call_args.kwargs
        self.assertEqual(call["operation_kind"], TinkerOperationKind.MANUAL_PREFUND)
        self.assertEqual(call["amount_dollars"], 0.0)
        self.assertTrue(call["required"])
        self.assertTrue(issued["policy_binding"]["deployment_policy"]["checked"])
        self.assertNotIn(token, repr(issued))

    def test_issue_policy_requires_spend_limit_for_add_balance_scope(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _, public_key_hex = _recipient_keypair()
            policy_path = os.path.join(tmpdir, "proxy-policy.json")
            _write_proxy_issue_policy(
                policy_path,
                subject="buyer-agent-1",
                recipient_public_key_hex=public_key_hex,
                scopes=["billing:add-balance"],
                ttl=60,
            )
            settings = self._settings(
                tmpdir,
                proxy_require_issue_policy=True,
                proxy_issue_policy_path=policy_path,
            )

            with self.assertRaisesRegex(ValueError, "spend scope is missing"):
                issue_encrypted_proxy_token(
                    settings,
                    subject="buyer-agent-1",
                    scopes=["billing:add-balance"],
                    recipient_public_key_hex=public_key_hex,
                    ttl_seconds=60,
                    now=1000,
                )

    def test_issue_policy_rejects_unapproved_recipient_key(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _, approved_public_key_hex = _recipient_keypair()
            _, other_public_key_hex = _recipient_keypair()
            policy_path = os.path.join(tmpdir, "proxy-policy.json")
            _write_proxy_issue_policy(
                policy_path,
                subject="buyer-agent-1",
                recipient_public_key_hex=approved_public_key_hex,
                scopes=["proxy:status"],
                ttl=60,
            )
            settings = self._settings(
                tmpdir,
                proxy_require_issue_policy=True,
                proxy_issue_policy_path=policy_path,
            )

            with self.assertRaisesRegex(ValueError, "not allowed by policy"):
                issue_encrypted_proxy_token(
                    settings,
                    subject="buyer-agent-1",
                    scopes=["proxy:status"],
                    recipient_public_key_hex=other_public_key_hex,
                    ttl_seconds=60,
                )

    def test_issue_policy_rejects_ttl_over_policy_cap(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _, public_key_hex = _recipient_keypair()
            policy_path = os.path.join(tmpdir, "proxy-policy.json")
            _write_proxy_issue_policy(
                policy_path,
                subject="buyer-agent-1",
                recipient_public_key_hex=public_key_hex,
                scopes=["proxy:status"],
                ttl=30,
            )
            settings = self._settings(
                tmpdir,
                proxy_require_issue_policy=True,
                proxy_issue_policy_path=policy_path,
            )

            with self.assertRaisesRegex(ValueError, "ttl exceeds policy cap"):
                issue_encrypted_proxy_token(
                    settings,
                    subject="buyer-agent-1",
                    scopes=["proxy:status"],
                    recipient_public_key_hex=public_key_hex,
                    ttl_seconds=60,
                )

    def test_issue_policy_required_fails_closed_without_policy_path(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _, public_key_hex = _recipient_keypair()
            settings = self._settings(tmpdir, proxy_require_issue_policy=True)

            with self.assertRaisesRegex(ValueError, "policy is required"):
                issue_encrypted_proxy_token(
                    settings,
                    subject="buyer-agent-1",
                    scopes=["proxy:status"],
                    recipient_public_key_hex=public_key_hex,
                    ttl_seconds=60,
                )

    def test_save_proxy_issue_policy_writes_canonical_bounded_summary(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _, public_key_hex = _recipient_keypair()
            policy_path = os.path.join(tmpdir, "proxy-policy.json")
            input_policy_path = os.path.join(tmpdir, "input-policy.json")
            policy = _write_proxy_issue_policy(
                input_policy_path,
                subject="buyer-agent-1",
                recipient_public_key_hex=public_key_hex,
                scopes=["billing:add-balance"],
                ttl=60,
                scope_limits={"billing:add-balance": {"max_amount_usd": 10}},
            )
            settings = self._settings(
                tmpdir,
                proxy_require_issue_policy=True,
                proxy_issue_policy_path=policy_path,
            )

            saved = save_proxy_issue_policy(settings, policy)
            status = get_proxy_issue_policy_status(settings)

        rendered = repr([saved, status])
        self.assertTrue(saved["success"])
        self.assertTrue(status["policy_present"])
        self.assertEqual(status["grant_count"], 1)
        self.assertEqual(status["grants"][0]["scope_limits"]["billing:add-balance"]["max_amount_usd"], 10.0)
        self.assertFalse(status["raw_secret_egress"])
        self.assertNotIn("buyer-agent-1", rendered)
        self.assertNotIn(public_key_hex, rendered)

    def test_issuer_rejects_unapproved_subject(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _, public_key_hex = _recipient_keypair()
            settings = self._settings(tmpdir, proxy_approved_subjects="approved-agent")

            with self.assertRaises(ValueError):
                issue_encrypted_proxy_token(
                    settings,
                    subject="other-agent",
                    scopes=["proxy:status"],
                    recipient_public_key_hex=public_key_hex,
                )

    def test_verifier_rejects_missing_scope(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            private_key, public_key_hex = _recipient_keypair()
            settings = self._settings(tmpdir)
            issued = issue_encrypted_proxy_token(
                settings,
                subject="buyer-agent-1",
                scopes=["proxy:status"],
                recipient_public_key_hex=public_key_hex,
                ttl_seconds=60,
                now=1000,
            )
            token = _decrypt_token(private_key, issued)

            with self.assertRaises(ValueError):
                verify_proxy_token(settings, token, required_scope="billing:add-balance", now=1001)

    def test_verifier_rejects_revoked_token(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            private_key, public_key_hex = _recipient_keypair()
            settings = self._settings(tmpdir)
            issued = issue_encrypted_proxy_token(
                settings,
                subject="buyer-agent-1",
                scopes=["proxy:status"],
                recipient_public_key_hex=public_key_hex,
                ttl_seconds=60,
                now=1000,
            )
            token = _decrypt_token(private_key, issued)
            store = build_proxy_token_store(settings)
            store.revoke(issued["token"]["jwt_id_hash"], reason="operator_requested", revoked_at=1001)

            with self.assertRaises(ValueError):
                verify_proxy_token(settings, token, required_scope="proxy:status", now=1002)

    def test_revoke_rejects_unknown_token_hash_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _, public_key_hex = _recipient_keypair()
            settings = self._settings(tmpdir)
            store = build_proxy_token_store(settings)

            with self.assertRaisesRegex(ValueError, "revoke target was not issued"):
                store.revoke("ab" * 32, reason="operator_requested", revoked_at=1001)

            issued = issue_encrypted_proxy_token(
                settings,
                subject="buyer-agent-1",
                scopes=["proxy:status"],
                recipient_public_key_hex=public_key_hex,
                ttl_seconds=60,
                now=1000,
            )
            jwt_id_hash = issued["token"]["jwt_id_hash"]
            first = store.revoke(jwt_id_hash, reason="operator_requested", revoked_at=1001)
            second = store.revoke(jwt_id_hash, reason="suspected_compromise", revoked_at=1002)
            audit = store.load()

        self.assertEqual(first, second)
        self.assertEqual([record["event"] for record in audit], ["issued", "revoked"])
        self.assertEqual(first["revocation_reason"], "operator_requested")
        self.assertFalse(first["raw_secret_egress"])


if __name__ == "__main__":
    unittest.main()
