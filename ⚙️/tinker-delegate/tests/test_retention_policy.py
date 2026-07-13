import json
import unittest

from tinker_delegate.retention_policy import (
    RetentionAction,
    RetentionError,
    RetentionMode,
    RetentionPolicy,
    evaluate_retention,
)


class RetentionPolicyTest(unittest.TestCase):
    def test_immediate_destroys_now(self):
        d = evaluate_retention(RetentionPolicy(RetentionMode.IMMEDIATE), settled_at=100, now=100)
        self.assertEqual(d.action, RetentionAction.DESTROY_NOW)
        self.assertTrue(d.must_destroy)
        self.assertFalse(d.raw_secret_egress)

    def test_time_boxed_within_window_retains(self):
        policy = RetentionPolicy(RetentionMode.TIME_BOXED, retention_seconds=1000)
        d = evaluate_retention(policy, settled_at=100, now=500)
        self.assertEqual(d.action, RetentionAction.RETAIN_SEALED)
        self.assertEqual(d.retain_until, 1100)
        self.assertFalse(d.expired)
        self.assertFalse(d.must_destroy)

    def test_time_boxed_expired_destroys(self):
        policy = RetentionPolicy(RetentionMode.TIME_BOXED, retention_seconds=1000)
        d = evaluate_retention(policy, settled_at=100, now=1100)
        self.assertEqual(d.action, RetentionAction.DESTROY_NOW)
        self.assertTrue(d.expired)
        self.assertEqual(d.reason_code, "retention_window_expired")

    def test_time_boxed_zero_window_fails_closed_to_destroy(self):
        policy = RetentionPolicy(RetentionMode.TIME_BOXED, retention_seconds=0)
        d = evaluate_retention(policy, settled_at=100, now=100)
        self.assertEqual(d.action, RetentionAction.DESTROY_NOW)
        self.assertIn("fail_closed", d.reason_code)

    def test_archive_with_key_archives(self):
        policy = RetentionPolicy(RetentionMode.POST_SETTLEMENT_ARCHIVE, archive_key_ref="room/archive-key")
        d = evaluate_retention(policy, settled_at=100, now=200)
        self.assertEqual(d.action, RetentionAction.ARCHIVE_ENCRYPTED)
        self.assertFalse(d.must_destroy)

    def test_archive_without_key_fails_closed_to_destroy(self):
        policy = RetentionPolicy(RetentionMode.POST_SETTLEMENT_ARCHIVE, archive_key_ref="")
        d = evaluate_retention(policy, settled_at=100, now=200)
        self.assertEqual(d.action, RetentionAction.DESTROY_NOW)
        self.assertEqual(d.reason_code, "archive_key_missing_fail_closed")

    def test_negative_retention_rejected(self):
        with self.assertRaises(RetentionError):
            RetentionPolicy(RetentionMode.TIME_BOXED, retention_seconds=-1)

    def test_policy_hash_hides_archive_key_ref(self):
        policy = RetentionPolicy(RetentionMode.POST_SETTLEMENT_ARCHIVE, archive_key_ref="room/secret-key-ref")
        blob = json.dumps(policy.to_public_dict())
        self.assertNotIn("secret-key-ref", blob)
        self.assertTrue(policy.to_public_dict()["archive_key_configured"])

    def test_decision_is_bounded_and_deterministic(self):
        policy = RetentionPolicy(RetentionMode.TIME_BOXED, retention_seconds=1000)
        a = evaluate_retention(policy, settled_at=100, now=500)
        b = evaluate_retention(policy, settled_at=100, now=500)
        self.assertEqual(a.policy_hash, b.policy_hash)
        self.assertIn("retention_decision", json.dumps(a.to_public_dict()))


if __name__ == "__main__":
    unittest.main()
