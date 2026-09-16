import contextlib
import io
import unittest
from email.message import EmailMessage
from unittest.mock import patch

from fastapi.testclient import TestClient

from email_oracle.account_creator import verify_imap_login
from email_oracle.api import app, state
from email_oracle.config import Settings
from email_oracle.cred_store import EmailCredentials
from email_oracle.imap_client import IMAPClient
from email_oracle.main import cmd_check


class FakeImapLogin:
    def __init__(self, host, port):
        self.host = host
        self.port = port

    def login(self, username, password):
        self.username = username
        self.password = password

    def select(self, mailbox):
        self.mailbox = mailbox

    def logout(self):
        pass


class FakeStore:
    def __init__(self, creds):
        self.creds = creds

    def exists(self):
        return True

    def load(self):
        return self.creds


class FakeRecentClient:
    def __init__(self, creds, settings):
        self.creds = creds
        self.settings = settings

    def connect(self):
        pass

    def disconnect(self):
        pass

    def list_recent(self, max_age_seconds=3600, limit=20):
        return [
            {
                "date": "Wed, 08 Jul 2026 12:00:00 +0000",
                "from": "Thinking Machines Lab <no-reply@thinkingmachines.ai>",
                "subject": "Your code is 123456",
            }
        ]


class FakeSearchConnection:
    def noop(self):
        pass

    def search(self, charset, search_str):
        self.search_str = search_str
        return "OK", [b"1"]

    def fetch(self, msg_id, query):
        msg = EmailMessage()
        msg["From"] = "Thinking Machines Lab <no-reply@thinkingmachines.ai>"
        msg["Subject"] = "Your code is 123456"
        msg["Date"] = "Wed, 08 Jul 2026 12:00:00 +0000"
        msg.set_content("Your code is 123456")
        return "OK", [(b"1", msg.as_bytes())]


class FakeSpoofedSenderConnection(FakeSearchConnection):
    def fetch(self, msg_id, query):
        msg = EmailMessage()
        msg["From"] = "no-reply@thinkingmachines.ai <attacker@example.net>"
        msg["Subject"] = "Your code"
        msg["Date"] = "Wed, 08 Jul 2026 12:00:00 +0000"
        msg.set_content("Your code is 123456")
        return "OK", [(b"1", msg.as_bytes())]


class MailboxEgressTrap:
    def __init__(self):
        self.calls = 0

    def list_recent(self, **_kwargs):
        self.calls += 1
        print("private-id private-sender@example.test private-subject private-date")
        return []


class OracleLogHygieneTest(unittest.TestCase):
    def test_removed_inbox_route_cannot_call_or_log_mailbox_metadata(self):
        trap = MailboxEgressTrap()
        state.settings = Settings(
            runtime_auth_required=True,
            runtime_auth_token="shared-secret",
        )
        state.creds = EmailCredentials("oracle", "example.com", "secret-password")
        state.imap = trap
        output = io.StringIO()

        with contextlib.redirect_stdout(output):
            response = TestClient(app).get(
                "/inbox",
                headers={"Authorization": "Bearer shared-secret"},
            )

        self.assertEqual(response.status_code, 404)
        self.assertEqual(trap.calls, 0)
        rendered = output.getvalue() + response.text
        self.assertNotIn("private-id", rendered)
        self.assertNotIn("private-sender@example.test", rendered)
        self.assertNotIn("private-subject", rendered)
        self.assertNotIn("private-date", rendered)
        self.assertNotIn("oracle@example.com", rendered)

    def test_verify_imap_login_logs_only_email_hash(self):
        creds = EmailCredentials("oracle", "example.com", "secret-password")
        settings = Settings(cockli_imap_host="mail.example", cockli_imap_port=993)
        output = io.StringIO()

        with patch("imaplib.IMAP4_SSL", FakeImapLogin), contextlib.redirect_stdout(output):
            verify_imap_login(creds, settings)

        rendered = output.getvalue()
        self.assertIn("email_hash=", rendered)
        self.assertNotIn("oracle@example.com", rendered)
        self.assertNotIn("oracle", rendered)
        self.assertNotIn("secret-password", rendered)

    def test_imap_pin_search_logs_hashes_not_mail_headers_or_filters(self):
        creds = EmailCredentials("oracle", "example.com", "secret-password")
        client = IMAPClient(creds, Settings())
        client._conn = FakeSearchConnection()
        output = io.StringIO()

        with contextlib.redirect_stdout(output):
            result = client.search_and_extract(
                from_filter="no-reply@thinkingmachines.ai",
                subject_contains="",
            )

        self.assertIsNotNone(result)
        rendered = output.getvalue()
        self.assertIn("from_filter_hash=", rendered)
        self.assertIn("subject_filter_hash=", rendered)
        self.assertIn("subject_hash=", rendered)
        self.assertIn("sender_hash=", rendered)
        self.assertNotIn("no-reply@thinkingmachines.ai", rendered)
        self.assertNotIn("Thinking Machines Lab", rendered)
        self.assertNotIn("Your code", rendered)
        self.assertNotIn("123456", rendered)

    def test_imap_rechecks_exact_sender_before_reading_otp(self):
        creds = EmailCredentials("oracle", "example.com", "secret-password")
        client = IMAPClient(creds, Settings())
        client._conn = FakeSpoofedSenderConnection()

        result = client.search_and_extract()

        self.assertIsNone(result)

    def test_check_command_logs_recent_email_hashes_only(self):
        creds = EmailCredentials("oracle", "example.com", "secret-password")
        output = io.StringIO()

        with (
            patch("email_oracle.imap_client.IMAPClient", FakeRecentClient),
            contextlib.redirect_stdout(output),
        ):
            cmd_check(Settings(), FakeStore(creds))

        rendered = output.getvalue()
        self.assertIn("email_hash=", rendered)
        self.assertIn("from_hash=", rendered)
        self.assertIn("subject_hash=", rendered)
        self.assertNotIn("oracle@example.com", rendered)
        self.assertNotIn("no-reply@thinkingmachines.ai", rendered)
        self.assertNotIn("Your code", rendered)
        self.assertNotIn("123456", rendered)


if __name__ == "__main__":
    unittest.main()
