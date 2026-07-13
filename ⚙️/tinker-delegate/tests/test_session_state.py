import json
import unittest

from tinker_delegate.session_state import (
    FAIL_CLOSED,
    LOGIN_LOOP,
    PROCEED,
    REFRESH_OTP,
    SESSION_ACTIVE,
    STALE_SESSION,
    UNKNOWN,
    classify_session_state,
    decide_otp_action,
    session_state_receipt,
)


class ClassifySessionStateTest(unittest.TestCase):
    def test_active_session(self):
        self.assertEqual(classify_session_state("You are signed in. Dashboard."), SESSION_ACTIVE)

    def test_stale_session_refreshes(self):
        state = classify_session_state("Your session has expired. Please sign in again.")
        self.assertEqual(state, STALE_SESSION)
        self.assertEqual(decide_otp_action(state), REFRESH_OTP)

    def test_rate_limit_text_is_login_loop(self):
        state = classify_session_state("Too many attempts. Please try again later.")
        self.assertEqual(state, LOGIN_LOOP)
        self.assertEqual(decide_otp_action(state), FAIL_CLOSED)

    def test_attempt_count_forces_login_loop_over_text(self):
        # Even if the page looks like a normal stale session, exceeding the
        # attempt budget means we are looping -> fail closed, do not refresh.
        state = classify_session_state(
            "Please sign in again.", recent_failed_attempts=3, max_attempts=3
        )
        self.assertEqual(state, LOGIN_LOOP)
        self.assertEqual(decide_otp_action(state), FAIL_CLOSED)

    def test_below_threshold_stale_session_still_refreshes(self):
        state = classify_session_state(
            "Session timed out.", recent_failed_attempts=1, max_attempts=3
        )
        self.assertEqual(state, STALE_SESSION)

    def test_empty_and_ambiguous_are_unknown_and_fail_closed(self):
        self.assertEqual(classify_session_state(""), UNKNOWN)
        self.assertEqual(classify_session_state("some unrelated content"), UNKNOWN)
        self.assertEqual(decide_otp_action(UNKNOWN), FAIL_CLOSED)

    def test_negative_attempts_is_unknown(self):
        self.assertEqual(classify_session_state("signed in", recent_failed_attempts=-1), UNKNOWN)

    def test_invalid_max_attempts_rejected(self):
        with self.assertRaises(ValueError):
            classify_session_state("x", max_attempts=0)

    def test_active_action_is_proceed(self):
        self.assertEqual(decide_otp_action(SESSION_ACTIVE), PROCEED)


class SessionStateReceiptTest(unittest.TestCase):
    def test_receipt_is_bounded_and_hashes_page_text(self):
        secret_page = "session expired for user patient-42 token sk-livesecret"
        receipt = session_state_receipt(secret_page)
        self.assertEqual(receipt["kind"], "session_state_status")
        self.assertEqual(receipt["state"], STALE_SESSION)
        self.assertEqual(receipt["action"], REFRESH_OTP)
        self.assertTrue(receipt["should_refresh_otp"])
        self.assertFalse(receipt["raw_secret_egress"])
        blob = json.dumps(receipt)
        self.assertNotIn("patient-42", blob)
        self.assertNotIn("sk-livesecret", blob)
        self.assertRegex(receipt["page_text_hash"], r"^0x[0-9a-f]{64}$")

    def test_login_loop_receipt_does_not_refresh(self):
        receipt = session_state_receipt(
            "please sign in again", recent_failed_attempts=5, max_attempts=3
        )
        self.assertEqual(receipt["state"], LOGIN_LOOP)
        self.assertFalse(receipt["should_refresh_otp"])
        self.assertEqual(receipt["action"], FAIL_CLOSED)
        self.assertEqual(receipt["recent_failed_attempts"], 5)

    def test_unknown_receipt_fails_closed(self):
        receipt = session_state_receipt("")
        self.assertEqual(receipt["state"], UNKNOWN)
        self.assertFalse(receipt["should_refresh_otp"])


if __name__ == "__main__":
    unittest.main()
