"""Tests for fail-closed mailbox retention (minimize OTP-mail lifetime)."""
import json
import unittest

from tinker_delegate.inbound_email_safety import extract_inbound_email
from tinker_delegate.mailbox_retention import (
    MailboxRetentionError,
    MailboxRetentionPolicy,
    MessageDisposition,
    decide_message_disposition,
)


class MailboxRetentionPolicyTest(unittest.TestCase):
    def test_negative_ttl_rejected(self):
        with self.assertRaises(MailboxRetentionError):
            MailboxRetentionPolicy(max_unused_retention_seconds=-1)


class DecideDispositionTest(unittest.TestCase):
    def _decide(self, **kw):
        kw.setdefault("policy", MailboxRetentionPolicy())
        return decide_message_disposition(**kw)

    def test_consumed_without_audit_is_deleted(self):
        d = self._decide(consumed=True, received_at=0, now=10)
        self.assertEqual(d.disposition, MessageDisposition.DELETE)
        self.assertTrue(d.deletes)
        self.assertFalse(d.keeps_raw_body)

    def test_consumed_with_audit_within_ttl_is_redacted(self):
        policy = MailboxRetentionPolicy(audit_retention_enabled=True, audit_retention_seconds=1000)
        d = self._decide(consumed=True, received_at=0, now=500, policy=policy)
        self.assertEqual(d.disposition, MessageDisposition.REDACT_FOR_AUDIT)
        # A redacted audit record does not keep the raw body.
        self.assertFalse(d.keeps_raw_body)

    def test_consumed_with_audit_past_ttl_is_deleted(self):
        policy = MailboxRetentionPolicy(audit_retention_enabled=True, audit_retention_seconds=1000)
        d = self._decide(consumed=True, received_at=0, now=1000, policy=policy)
        self.assertEqual(d.disposition, MessageDisposition.DELETE)
        self.assertEqual(d.reason_code, "audit_ttl_expired")

    def test_unconsumed_within_window_is_retained(self):
        policy = MailboxRetentionPolicy(max_unused_retention_seconds=100)
        d = self._decide(consumed=False, received_at=0, now=50, policy=policy)
        self.assertEqual(d.disposition, MessageDisposition.RETAIN)
        self.assertTrue(d.keeps_raw_body)

    def test_unconsumed_past_window_expires(self):
        policy = MailboxRetentionPolicy(max_unused_retention_seconds=100)
        d = self._decide(consumed=False, received_at=0, now=100, policy=policy)
        self.assertEqual(d.disposition, MessageDisposition.DELETE)
        self.assertEqual(d.reason_code, "unconsumed_expired")

    def test_clock_skew_does_not_expire_unconsumed(self):
        # now < received_at (non-monotonic clock): age clamps to 0 -> still within
        # window, so an unconsumed message is retained (not spuriously deleted or
        # kept forever).
        policy = MailboxRetentionPolicy(max_unused_retention_seconds=100)
        d = self._decide(consumed=False, received_at=1000, now=0, policy=policy)
        self.assertEqual(d.disposition, MessageDisposition.RETAIN)

    def test_output_is_bounded(self):
        d = self._decide(consumed=True, received_at=0, now=10)
        pub = d.to_public_dict()
        self.assertFalse(pub["raw_secret_egress"])
        self.assertIn("disposition", json.dumps(pub))


class ExtractThenRetainComposesTest(unittest.TestCase):
    def test_extracted_otp_message_is_deleted_by_default(self):
        # Compose with inbound_email_safety: once the structured OTP is extracted,
        # the message is consumed and (default, no audit) deleted — the OTP-bearing
        # raw email does not linger.
        extract = extract_inbound_email("code", "Your code is 483920", otp_lengths=(6,))
        self.assertTrue(extract.otp_present)
        decision = decide_message_disposition(
            consumed=extract.otp_present,
            received_at=0,
            now=5,
            policy=MailboxRetentionPolicy(),
        )
        self.assertEqual(decision.disposition, MessageDisposition.DELETE)


if __name__ == "__main__":
    unittest.main()
