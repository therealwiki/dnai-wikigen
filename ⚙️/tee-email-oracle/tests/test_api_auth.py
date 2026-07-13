import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from email_oracle.api import app, state
from email_oracle.config import Settings
from email_oracle.credential_uploader import encrypt_credentials_payload
from email_oracle.cred_store import EmailCredentials
from email_oracle.imap_client import ExtractedPin


def _reset_state(settings: Settings) -> None:
    state.settings = settings
    state.store = None
    state.creds = None
    state.imap = None
    state.imap_connected = False
    state.otp_replay_store = None
    state.otp_replay_store_ready = True
    state.used_otp_hashes = set()
    state.tee_keypair = None


def _scoped_pin_payload(**overrides):
    payload = {
        "target_service": "tinker",
        "expected_sender": "no-reply@thinkingmachines.ai",
        "expected_subject_contains": "",
        "max_age_seconds": 300,
        "extract_pattern": r"\b\d{6}\b",
        "nonce": "nonce-123456",
        "caller_identity": "tinker-delegate.test",
        "reason": "tinker-auth-test",
        "delete_after": False,
    }
    payload.update(overrides)
    return payload


class FakeIMAP:
    def __init__(self, pin: str = "123456"):
        self.pin = pin
        self.search_calls = []
        self.deleted = []

    def search_and_extract(self, **kwargs):
        self.search_calls.append(kwargs)
        return ExtractedPin(
            pin=self.pin,
            email_id="42",
            subject="Your Thinking Machines code",
            sender="Thinking Machines Lab <no-reply@thinkingmachines.ai>",
            received_at="Wed, 08 Jul 2026 12:00:00 +0000",
            body_snippet="redacted",
        )

    def delete_email(self, email_id: str) -> None:
        self.deleted.append(email_id)

    def _ensure_connected(self) -> None:
        return None


class ExplodingHealthIMAP(FakeIMAP):
    def _ensure_connected(self) -> None:
        raise RuntimeError("health should not reconnect imap")


class FakeReplayStore:
    def __init__(self, fail_save: bool = False):
        self.fail_save = fail_save
        self.saved_hashes = None

    def save(self, used_otp_hashes: set[str]) -> None:
        if self.fail_save:
            raise RuntimeError("disk failed")
        self.saved_hashes = set(used_otp_hashes)


class FakeCredentialStore:
    def __init__(self):
        self.saved = None

    def save(self, creds: EmailCredentials) -> None:
        self.saved = creds


class ConnectableIMAP:
    def __init__(self, creds, settings):
        self.creds = creds
        self.settings = settings
        self.connected = False

    def connect(self):
        self.connected = True

    def disconnect(self):
        self.connected = False


class ExplodingConnectIMAP(ConnectableIMAP):
    def connect(self):
        raise RuntimeError("startup should not connect imap")


class StartupCredentialStore:
    def __init__(self, *args, **kwargs):
        pass

    def exists(self):
        return True

    def load(self):
        return EmailCredentials("oracle", "example.com", "secret-password")


class StartupReplayStore:
    def __init__(self, *args, **kwargs):
        pass

    def load(self):
        return set()


class ApiAuthTest(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)

    def test_pin_requires_bearer_token_when_runtime_auth_is_enabled(self):
        _reset_state(Settings(runtime_auth_required=True, runtime_auth_token="shared-secret"))

        response = self.client.post("/pin", json={})

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers["www-authenticate"], "Bearer")

    def test_pin_rejects_wrong_bearer_token(self):
        _reset_state(Settings(runtime_auth_required=True, runtime_auth_token="shared-secret"))

        response = self.client.post(
            "/pin",
            headers={"Authorization": "Bearer wrong-secret"},
            json={},
        )

        self.assertEqual(response.status_code, 403)

    def test_pin_accepts_correct_bearer_token_before_oracle_state_check(self):
        _reset_state(Settings(runtime_auth_required=True, runtime_auth_token="shared-secret"))

        response = self.client.post(
            "/pin",
            headers={"Authorization": "Bearer shared-secret"},
            json=_scoped_pin_payload(),
        )

        self.assertEqual(response.status_code, 503)
        self.assertIn("Oracle not initialized", response.json()["detail"])

    def test_pin_requires_consumer_registry_when_configured_before_imap(self):
        _reset_state(
            Settings(
                runtime_auth_required=True,
                runtime_auth_token="shared-secret",
                auth_required=True,
            )
        )
        state.creds = EmailCredentials("oracle", "example.com", "pw")
        state.imap = FakeIMAP()

        response = self.client.post(
            "/pin",
            headers={"Authorization": "Bearer shared-secret"},
            json=_scoped_pin_payload(),
        )

        self.assertEqual(response.status_code, 503)
        self.assertIn("EmailOracleAuth policy denied: missing_contract", response.json()["detail"])
        self.assertEqual(state.imap.search_calls, [])

    def test_pin_rejects_unauthorized_consumer_before_imap(self):
        _reset_state(Settings(runtime_auth_required=True, runtime_auth_token="shared-secret"))
        state.creds = EmailCredentials("oracle", "example.com", "pw")
        state.imap = FakeIMAP()

        class Denied:
            allowed = False
            checked = True
            reason = "consumer_not_authorized"

        with patch("email_oracle.api.check_consumer_authorization", return_value=Denied()):
            response = self.client.post(
                "/pin",
                headers={"Authorization": "Bearer shared-secret"},
                json=_scoped_pin_payload(),
            )

        self.assertEqual(response.status_code, 403)
        self.assertIn("consumer_not_authorized", response.json()["detail"])
        self.assertEqual(state.imap.search_calls, [])

    def test_pin_requires_scoped_request_metadata(self):
        _reset_state(Settings(runtime_auth_required=True, runtime_auth_token="shared-secret"))

        response = self.client.post(
            "/pin",
            headers={"Authorization": "Bearer shared-secret"},
            json={},
        )

        self.assertEqual(response.status_code, 422)

    def test_pin_releases_scoped_otp_once(self):
        _reset_state(Settings(runtime_auth_required=True, runtime_auth_token="shared-secret"))
        state.creds = EmailCredentials("oracle", "example.com", "pw")
        state.imap = FakeIMAP()

        response = self.client.post(
            "/pin",
            headers={"Authorization": "Bearer shared-secret"},
            json=_scoped_pin_payload(delete_after=True),
        )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["pin"], "123456")
        self.assertEqual(body["oracle_email"], "oracle@example.com")
        self.assertEqual(len(body["request_hash"]), 64)
        self.assertEqual(len(body["otp_use_hash"]), 64)
        self.assertEqual(state.imap.search_calls[0]["from_filter"], "no-reply@thinkingmachines.ai")
        self.assertEqual(state.imap.deleted, ["42"])

        replay = self.client.post(
            "/pin",
            headers={"Authorization": "Bearer shared-secret"},
            json=_scoped_pin_payload(nonce="nonce-abcdef"),
        )
        self.assertEqual(replay.status_code, 409)
        self.assertIn("already been released", replay.json()["detail"])

    def test_pin_rejects_overlong_extraction(self):
        _reset_state(Settings(runtime_auth_required=True, runtime_auth_token="shared-secret", pin_max_length=6))
        state.creds = EmailCredentials("oracle", "example.com", "pw")
        state.imap = FakeIMAP(pin="123456789")

        response = self.client.post(
            "/pin",
            headers={"Authorization": "Bearer shared-secret"},
            json=_scoped_pin_payload(extract_pattern=r"\d+"),
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("length cap", response.json()["detail"])

    def test_pin_persists_replay_hash_before_release(self):
        _reset_state(Settings(runtime_auth_required=True, runtime_auth_token="shared-secret"))
        state.creds = EmailCredentials("oracle", "example.com", "pw")
        state.imap = FakeIMAP()
        state.otp_replay_store = FakeReplayStore()

        response = self.client.post(
            "/pin",
            headers={"Authorization": "Bearer shared-secret"},
            json=_scoped_pin_payload(),
        )

        self.assertEqual(response.status_code, 200)
        otp_use_hash = response.json()["otp_use_hash"]
        self.assertIn(otp_use_hash, state.used_otp_hashes)
        self.assertIn(otp_use_hash, state.otp_replay_store.saved_hashes)

    def test_pin_fails_closed_when_replay_store_cannot_persist(self):
        _reset_state(Settings(runtime_auth_required=True, runtime_auth_token="shared-secret"))
        state.creds = EmailCredentials("oracle", "example.com", "pw")
        state.imap = FakeIMAP()
        state.otp_replay_store = FakeReplayStore(fail_save=True)

        response = self.client.post(
            "/pin",
            headers={"Authorization": "Bearer shared-secret"},
            json=_scoped_pin_payload(),
        )

        self.assertEqual(response.status_code, 503)
        self.assertIn("Could not persist OTP replay ledger", response.json()["detail"])
        self.assertEqual(state.used_otp_hashes, set())

    def test_pin_fails_closed_when_replay_store_is_unavailable(self):
        _reset_state(Settings(runtime_auth_required=True, runtime_auth_token="shared-secret"))
        state.creds = EmailCredentials("oracle", "example.com", "pw")
        state.imap = FakeIMAP()
        state.otp_replay_store_ready = False

        response = self.client.post(
            "/pin",
            headers={"Authorization": "Bearer shared-secret"},
            json=_scoped_pin_payload(),
        )

        self.assertEqual(response.status_code, 503)
        self.assertIn("OTP replay ledger is unavailable", response.json()["detail"])

    def test_inbox_requires_bearer_token_when_runtime_auth_is_enabled(self):
        _reset_state(Settings(runtime_auth_required=True, runtime_auth_token="shared-secret"))

        response = self.client.get("/inbox")

        self.assertEqual(response.status_code, 401)

    def test_inbox_accepts_correct_bearer_token_before_imap_check(self):
        _reset_state(Settings(runtime_auth_required=True, runtime_auth_token="shared-secret"))

        response = self.client.get("/inbox", headers={"Authorization": "Bearer shared-secret"})

        self.assertEqual(response.status_code, 503)
        self.assertIn("IMAP not connected", response.json()["detail"])

    def test_health_returns_bounded_email_status_only(self):
        _reset_state(Settings())
        state.creds = EmailCredentials("oracle", "example.com", "secret-password")
        state.imap = FakeIMAP()
        state.imap_connected = True

        response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["status"], "ok")
        self.assertTrue(body["oracle_ready"])
        self.assertTrue(body["imap_connected"])
        self.assertEqual(body["oracle_email"], "")
        self.assertEqual(len(body["oracle_email_hash"]), 64)
        self.assertNotIn("oracle@example.com", response.text)

    def test_health_does_not_touch_imap_connection(self):
        _reset_state(Settings())
        state.creds = EmailCredentials("oracle", "example.com", "secret-password")
        state.imap = ExplodingHealthIMAP()
        state.imap_connected = True

        response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["status"], "ok")
        self.assertTrue(body["oracle_ready"])
        self.assertTrue(body["imap_connected"])

    def test_startup_defers_imap_connect_until_pin_request(self):
        with (
            patch("email_oracle.api.CredentialStore", StartupCredentialStore),
            patch("email_oracle.api.OtpReplayStore", StartupReplayStore),
            patch("email_oracle.api.IMAPClient", ExplodingConnectIMAP),
            TestClient(app) as client,
        ):
            response = client.get("/health")

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["status"], "degraded")
        self.assertFalse(body["oracle_ready"])
        self.assertFalse(body["imap_connected"])
        self.assertEqual(len(body["oracle_email_hash"]), 64)

    def test_email_address_requires_runtime_auth_when_enabled(self):
        _reset_state(Settings(runtime_auth_required=True, runtime_auth_token="shared-secret"))
        state.creds = EmailCredentials("oracle", "example.com", "secret-password")

        denied = self.client.get("/email")
        self.assertEqual(denied.status_code, 401)

        response = self.client.get("/email", headers={"Authorization": "Bearer shared-secret"})

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["oracle_email"], "oracle@example.com")
        self.assertEqual(len(body["oracle_email_hash"]), 64)

    def test_attestation_exposes_context_bound_credential_ingress_key(self):
        _reset_state(Settings())

        response = self.client.get("/attestation?context=oracle-credentials")

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["mode"], "local")
        self.assertEqual(body["report_context"], "oracle-credentials")
        self.assertEqual(len(body["encryption_public_key"]), 64)
        self.assertEqual(len(body["report_data"]), 64)
        self.assertEqual(body["oracle_email"], "")
        self.assertEqual(body["oracle_email_hash"], "")
        self.assertFalse(body["oracle_ready"])
        self.assertNotIn("password", body)

    def test_attestation_returns_bounded_email_status_only(self):
        _reset_state(Settings())
        state.creds = EmailCredentials("oracle", "example.com", "secret-password")

        response = self.client.get("/attestation?context=attestation")

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["oracle_email"], "")
        self.assertEqual(len(body["oracle_email_hash"]), 64)
        self.assertTrue(body["oracle_ready"])
        self.assertNotIn("oracle@example.com", response.text)

    def test_encrypted_credential_provisioning_is_disabled_by_default(self):
        _reset_state(Settings())
        state.store = FakeCredentialStore()
        attestation = self.client.get("/attestation?context=oracle-credentials").json()
        encrypted = encrypt_credentials_payload(
            {"username": "oracle", "domain": "example.com", "password": "secret-password"},
            attestation["encryption_public_key"],
        )

        response = self.client.post("/credentials/encrypted", json=encrypted)

        self.assertEqual(response.status_code, 403)
        self.assertIsNone(state.store.saved)

    def test_encrypted_credential_provisioning_stores_and_returns_hashes_only(self):
        _reset_state(
            Settings(
                allow_credential_provisioning_endpoint=True,
                credential_provisioning_token="provision-token",
            )
        )
        state.store = FakeCredentialStore()
        attestation = self.client.get("/attestation?context=oracle-credentials").json()
        credentials = {
            "username": "oracle",
            "domain": "example.com",
            "password": "secret-password",
        }
        encrypted = encrypt_credentials_payload(credentials, attestation["encryption_public_key"])

        with patch("email_oracle.api.IMAPClient", ConnectableIMAP):
            response = self.client.post(
                "/credentials/encrypted",
                headers={"Authorization": "Bearer provision-token"},
                json=encrypted,
            )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["status"], "stored")
        self.assertTrue(body["imap_connected"])
        self.assertEqual(len(body["credential_email_hash"]), 64)
        self.assertEqual(len(body["credential_domain_hash"]), 64)
        self.assertFalse(body["raw_secret_egress"])
        rendered = response.text
        self.assertNotIn("oracle@example.com", rendered)
        self.assertNotIn("oracle", rendered)
        self.assertNotIn("example.com", rendered)
        self.assertNotIn("secret-password", rendered)
        self.assertEqual(state.store.saved.email, "oracle@example.com")

    def test_inbox_requires_consumer_registry_before_imap(self):
        _reset_state(
            Settings(
                runtime_auth_required=True,
                runtime_auth_token="shared-secret",
                auth_required=True,
            )
        )
        state.imap = FakeIMAP()

        response = self.client.get("/inbox", headers={"Authorization": "Bearer shared-secret"})

        self.assertEqual(response.status_code, 503)
        self.assertIn("EmailOracleAuth policy denied: missing_contract", response.json()["detail"])
        self.assertEqual(state.imap.search_calls, [])

    def test_local_dev_can_leave_runtime_auth_disabled(self):
        _reset_state(Settings(runtime_auth_required=False, runtime_auth_token=""))

        response = self.client.post("/pin", json=_scoped_pin_payload())

        self.assertEqual(response.status_code, 503)
        self.assertIn("Oracle not initialized", response.json()["detail"])


if __name__ == "__main__":
    unittest.main()
