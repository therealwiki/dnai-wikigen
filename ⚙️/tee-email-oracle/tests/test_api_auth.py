import unittest
import hashlib
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

from email_oracle.api import EMAIL_COMMITMENT_SCHEME, app, state
from email_oracle.chain_auth import CANONICAL_CALLER_IDENTITY, EmailOracleAuthError
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
        "caller_identity": CANONICAL_CALLER_IDENTITY,
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
        self.mailbox_list_calls = 0

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

    def list_recent(self, **_kwargs):
        self.mailbox_list_calls += 1
        return [
            {
                "id": "private-message-id",
                "from": "Private Sender <private-sender@example.test>",
                "subject": "private mailbox subject",
                "date": "private mailbox date",
            }
        ]


class PrivateMetadataIMAP(FakeIMAP):
    def __init__(self, *, email_id: str, subject: str, sender: str, received_at: str, body: str):
        super().__init__()
        self.email_id = email_id
        self.subject = subject
        self.sender = sender
        self.received_at = received_at
        self.body = body

    def search_and_extract(self, **kwargs):
        self.search_calls.append(kwargs)
        return ExtractedPin(
            pin=self.pin,
            email_id=self.email_id,
            subject=self.subject,
            sender=self.sender,
            received_at=self.received_at,
            body_snippet=self.body,
        )


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

    def test_pin_rejects_legacy_delegate_identity_before_rpc_or_imap(self):
        _reset_state(
            Settings(
                runtime_auth_required=True,
                runtime_auth_token="shared-secret",
                auth_required=True,
                auth_contract_address="0x" + "11" * 20,
                auth_contract_runtime_code_hash="0x" + "22" * 32,
                auth_consumer_app_id="0x" + "33" * 20,
                auth_consumer_compose_hash="0x" + "44" * 32,
                auth_expected_caller_identity=CANONICAL_CALLER_IDENTITY,
            )
        )
        state.creds = EmailCredentials("oracle", "example.com", "pw")
        state.imap = FakeIMAP()

        response = self.client.post(
            "/pin",
            headers={"Authorization": "Bearer shared-secret"},
            json=_scoped_pin_payload(caller_identity="tinker-delegate"),
        )

        self.assertEqual(response.status_code, 503)
        self.assertIn("caller_identity_mismatch", response.json()["detail"])
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
        self.assertEqual(
            set(body),
            {"pin", "request_hash", "attestation_report_data", "tdx_quote"},
        )
        self.assertEqual(body["pin"], "123456")
        self.assertEqual(len(body["request_hash"]), 64)
        self.assertEqual(len(body["attestation_report_data"]), 64)
        self.assertEqual(body["tdx_quote"], "")
        for forbidden in (
            "oracle_email",
            "oracle_email_hash",
            "email_id",
            "email_id_hash",
            "subject",
            "subject_hash",
            "sender",
            "sender_hash",
            "received_at",
            "timestamp",
            "otp_use_hash",
        ):
            self.assertNotIn(forbidden, body)
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
            json=_scoped_pin_payload(),
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("six-digit OTP", response.json()["detail"])

    def test_pin_rejects_caller_selected_regex_before_mailbox_access(self):
        _reset_state(Settings(runtime_auth_required=True, runtime_auth_token="shared-secret"))
        state.creds = EmailCredentials("oracle", "example.com", "pw")
        state.imap = FakeIMAP()

        response = self.client.post(
            "/pin",
            headers={"Authorization": "Bearer shared-secret"},
            json=_scoped_pin_payload(extract_pattern=r"(?s).+"),
        )

        self.assertEqual(response.status_code, 422)
        self.assertEqual(state.imap.search_calls, [])

    def test_pin_rejects_mailbox_scope_widening_before_mailbox_access(self):
        _reset_state(Settings(runtime_auth_required=True, runtime_auth_token="shared-secret"))
        state.creds = EmailCredentials("oracle", "example.com", "pw")
        state.imap = FakeIMAP()

        attacks = (
            {"target_service": "gmail"},
            {"expected_sender": ""},
            {"expected_sender": "attacker.example"},
            {"expected_subject_contains": "password reset"},
        )
        for override in attacks:
            with self.subTest(override=override):
                response = self.client.post(
                    "/pin",
                    headers={"Authorization": "Bearer shared-secret"},
                    json=_scoped_pin_payload(**override),
                )
                self.assertEqual(response.status_code, 422)

        self.assertEqual(state.imap.search_calls, [])

    def test_pin_rejects_unknown_request_fields(self):
        _reset_state(Settings(runtime_auth_required=True, runtime_auth_token="shared-secret"))

        response = self.client.post(
            "/pin",
            headers={"Authorization": "Bearer shared-secret"},
            json=_scoped_pin_payload(mailbox="archive", return_body=True),
        )

        self.assertEqual(response.status_code, 422)

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
        self.assertEqual(len(state.used_otp_hashes), 1)
        otp_use_hash = next(iter(state.used_otp_hashes))
        self.assertEqual(len(otp_use_hash), 64)
        self.assertEqual(state.otp_replay_store.saved_hashes, {otp_use_hash})
        self.assertNotIn("otp_use_hash", response.json())

    def test_private_mailbox_metadata_cannot_change_pin_response_bytes(self):
        _reset_state(
            Settings(
                runtime_auth_required=True,
                runtime_auth_token="shared-secret",
                dstack_enabled=True,
            )
        )
        state.creds = EmailCredentials("oracle-one", "private.example", "pw")
        first_private_values = (
            "private-message-alpha",
            "Board acquisition details",
            "Private Director <director@private.example>",
            "Mon, 13 Jul 2026 01:02:03 +0000",
            "confidential body alpha",
        )
        second_private_values = (
            "private-message-omega",
            "Different medical subject",
            "Private Clinician <doctor@hospital.example>",
            "Tue, 14 Jul 2026 04:05:06 +0000",
            "confidential body omega",
        )

        quote_inputs = []

        def fake_attestation(report_data):
            quote_inputs.append(bytes(report_data))
            return ("aa" * 64, "private-app-id", "private-compose-hash")

        with patch("email_oracle.api.get_attestation", side_effect=fake_attestation):
            state.imap = PrivateMetadataIMAP(
                email_id=first_private_values[0],
                subject=first_private_values[1],
                sender=first_private_values[2],
                received_at=first_private_values[3],
                body=first_private_values[4],
            )
            first = self.client.post(
                "/pin",
                headers={"Authorization": "Bearer shared-secret"},
                json=_scoped_pin_payload(),
            )

            # The mailbox identity is also private and contributes only to the
            # internal replay ledger, never the public response proof.
            state.creds = EmailCredentials("oracle-two", "another.example", "pw")
            state.imap = PrivateMetadataIMAP(
                email_id=second_private_values[0],
                subject=second_private_values[1],
                sender=second_private_values[2],
                received_at=second_private_values[3],
                body=second_private_values[4],
            )
            second = self.client.post(
                "/pin",
                headers={"Authorization": "Bearer shared-secret"},
                json=_scoped_pin_payload(),
            )

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(first.content, second.content)
        self.assertEqual(quote_inputs[0], quote_inputs[1])
        self.assertEqual(len(state.used_otp_hashes), 2)
        for private_value in (*first_private_values, *second_private_values):
            self.assertNotIn(private_value, first.text)
            self.assertNotIn(private_value, second.text)

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

    def test_inbox_route_is_absent_even_with_runtime_auth(self):
        _reset_state(Settings(runtime_auth_required=True, runtime_auth_token="shared-secret"))
        state.imap = FakeIMAP()

        denied = self.client.get("/inbox")
        authenticated = self.client.get(
            "/inbox?max_age=999999&limit=100",
            headers={"Authorization": "Bearer shared-secret"},
        )

        self.assertEqual(denied.status_code, 404)
        self.assertEqual(authenticated.status_code, 404)
        self.assertNotIn("/inbox", self.client.get("/openapi.json").json()["paths"])
        self.assertEqual(state.imap.mailbox_list_calls, 0)
        for private_value in (
            "private-message-id",
            "private-sender@example.test",
            "private mailbox subject",
            "private mailbox date",
        ):
            self.assertNotIn(private_value, denied.text)
            self.assertNotIn(private_value, authenticated.text)

    def test_health_returns_liveness_only(self):
        _reset_state(Settings())
        state.creds = EmailCredentials("oracle", "example.com", "secret-password")
        state.imap = FakeIMAP()
        state.imap_connected = True

        response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {"service": "tee-email-oracle", "status": "ok"},
        )
        self.assertNotIn("oracle@example.com", response.text)

    def test_health_does_not_touch_imap_connection(self):
        _reset_state(Settings())
        state.creds = EmailCredentials("oracle", "example.com", "secret-password")
        state.imap = ExplodingHealthIMAP()
        state.imap_connected = True

        response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {"service": "tee-email-oracle", "status": "ok"},
        )

    def test_startup_defers_imap_connect_until_pin_request(self):
        with (
            patch("email_oracle.api.CredentialStore", StartupCredentialStore),
            patch("email_oracle.api.OtpReplayStore", StartupReplayStore),
            patch("email_oracle.api.IMAPClient", ExplodingConnectIMAP),
            TestClient(app) as client,
        ):
            response = client.get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {"service": "tee-email-oracle", "status": "ok"},
        )

    def test_production_startup_fails_when_checkpoint_is_not_durable(self):
        production = Mock(
            production_release=True,
            auth_checkpoint_store_path="/data/email_auth_checkpoint.json",
        )
        with (
            patch("email_oracle.api.Settings", return_value=production),
            patch(
                "email_oracle.api.FinalizedBlockCheckpointStore.ensure_ready",
                side_effect=EmailOracleAuthError("credentialed filesystem detail"),
            ),
            self.assertRaisesRegex(
                RuntimeError,
                "production EmailOracleAuth checkpoint store is unavailable",
            ),
        ):
            with TestClient(app):
                pass

    def test_health_bytes_do_not_depend_on_private_oracle_state(self):
        _reset_state(Settings(dstack_enabled=False))
        empty = self.client.get("/health")

        state.settings = Settings(dstack_enabled=True)
        state.creds = EmailCredentials("private-oracle", "secret.example", "secret-password")
        state.imap = ExplodingHealthIMAP()
        state.imap_connected = True
        populated = self.client.get("/health")

        self.assertEqual(empty.content, populated.content)
        self.assertEqual(populated.json(), {"service": "tee-email-oracle", "status": "ok"})
        for forbidden in (
            "private-oracle",
            "secret.example",
            "oracle_ready",
            "imap_connected",
            "dstack_enabled",
            "timestamp",
        ):
            self.assertNotIn(forbidden, populated.text)

    def test_email_endpoint_requires_auth_and_returns_commitment_only(self):
        _reset_state(Settings(runtime_auth_required=True, runtime_auth_token="shared-secret"))
        state.creds = EmailCredentials("oracle", "example.com", "secret-password")

        denied = self.client.get("/email")
        self.assertEqual(denied.status_code, 401)

        response = self.client.get("/email", headers={"Authorization": "Bearer shared-secret"})

        self.assertEqual(response.status_code, 200)
        body = response.json()
        expected_commitment = hashlib.sha256(
            EMAIL_COMMITMENT_SCHEME.encode("ascii") + b"\x00oracle@example.com"
        ).hexdigest()
        self.assertEqual(
            body,
            {
                "oracle_ready": True,
                "oracle_email_commitment": expected_commitment,
                "commitment_scheme": EMAIL_COMMITMENT_SCHEME,
                "raw_email_egress": False,
                "timestamp": body["timestamp"],
            },
        )
        self.assertNotIn("oracle_email", body)
        self.assertNotIn("oracle_email_hash", body)
        self.assertNotIn("oracle@example.com", response.text)
        self.assertNotIn("example.com", response.text)

    def test_attestation_exposes_context_bound_credential_ingress_key(self):
        _reset_state(Settings())

        response = self.client.get("/attestation?context=oracle-credentials")

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(
            set(body),
            {
                "service",
                "report_context",
                "encryption_public_key",
                "report_data",
                "mode",
                "tdx_quote",
                "quote_report_data",
                "app_id",
                "compose_hash",
                "os_image_hash",
                "verified",
            },
        )
        self.assertEqual(body["service"], "tee-email-oracle")
        self.assertEqual(body["mode"], "local")
        self.assertEqual(body["report_context"], "oracle-credentials")
        self.assertEqual(len(body["encryption_public_key"]), 64)
        self.assertEqual(len(body["report_data"]), 64)
        self.assertFalse(body["verified"])
        self.assertNotIn("password", body)

    def test_tdx_quote_retrieval_does_not_self_assert_verification(self):
        _reset_state(Settings(dstack_enabled=True))
        details = {
            "quote": "aa",
            "app_id": "app-ok",
            "compose_hash": "compose-ok",
            "quote_report_data": "bb",
            "os_image_hash": "os-ok",
        }

        with (
            patch("email_oracle.api.is_dstack_simulator", return_value=False),
            patch("email_oracle.api.get_attestation_details", return_value=details),
        ):
            response = self.client.get("/attestation?context=oracle-credentials")

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["mode"], "tdx")
        self.assertEqual(body["tdx_quote"], "aa")
        self.assertFalse(body["verified"])

    def test_simulator_quote_is_explicitly_modeled_not_tdx(self):
        _reset_state(Settings(dstack_enabled=True))
        details = {
            "quote": "modeled-quote",
            "app_id": "sim-app",
            "compose_hash": "sim-compose",
            "quote_report_data": "bb",
            "os_image_hash": "sim-os",
        }

        with (
            patch("email_oracle.api.is_dstack_simulator", return_value=True),
            patch("email_oracle.api.get_attestation_details", return_value=details),
        ):
            response = self.client.get("/attestation?context=oracle-credentials")

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["mode"], "simulator")
        self.assertFalse(body["verified"])

    def test_attestation_response_clamps_lower_layer_self_verification_claim(self):
        _reset_state(Settings())

        with patch(
            "email_oracle.api._attestation_payload",
            return_value={
                "service": "tee-email-oracle",
                "tdx_quote": "aa",
                "app_id": "app-ok",
                "compose_hash": "compose-ok",
                "os_image_hash": "os-ok",
                "quote_report_data": "33" * 32,
                "mode": "tdx",
                "encryption_public_key": "11" * 32,
                "report_context": "oracle-credentials",
                "report_data": "22" * 32,
                "verified": True,
            },
        ):
            response = self.client.get("/attestation?context=oracle-credentials")

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["verified"])

    def test_attestation_bytes_do_not_depend_on_private_oracle_state(self):
        _reset_state(Settings())
        empty = self.client.get("/attestation?context=attestation")

        state.creds = EmailCredentials("oracle", "example.com", "secret-password")
        state.imap = FakeIMAP()
        state.imap_connected = True
        populated = self.client.get("/attestation?context=attestation")

        self.assertEqual(empty.status_code, 200)
        self.assertEqual(populated.status_code, 200)
        self.assertEqual(empty.content, populated.content)
        for forbidden in (
            "oracle@example.com",
            "oracle_email",
            "oracle_ready",
            "imap_connected",
            "timestamp",
        ):
            self.assertNotIn(forbidden, populated.text)

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

    def test_local_dev_can_leave_runtime_auth_disabled(self):
        _reset_state(Settings(runtime_auth_required=False, runtime_auth_token=""))

        response = self.client.post("/pin", json=_scoped_pin_payload())

        self.assertEqual(response.status_code, 503)
        self.assertIn("Oracle not initialized", response.json()["detail"])


if __name__ == "__main__":
    unittest.main()
