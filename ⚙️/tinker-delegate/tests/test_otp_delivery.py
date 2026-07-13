import json
import unittest

from tinker_delegate.otp_delivery import (
    OtpDeliveryError,
    compute_delivery_hash,
    otp_delivery_receipt,
)


class ComputeDeliveryHashTest(unittest.TestCase):
    def test_hash_is_deterministic_and_0x_bytes32(self):
        h1 = compute_delivery_hash("0xConsumer", "req-1", "123456")
        h2 = compute_delivery_hash("0xConsumer", "req-1", "123456")
        self.assertEqual(h1, h2)
        self.assertRegex(h1, r"^0x[0-9a-f]{64}$")

    def test_distinct_inputs_yield_distinct_hashes(self):
        base = compute_delivery_hash("0xConsumer", "req-1", "123456")
        self.assertNotEqual(base, compute_delivery_hash("0xOther", "req-1", "123456"))
        self.assertNotEqual(base, compute_delivery_hash("0xConsumer", "req-2", "123456"))
        self.assertNotEqual(base, compute_delivery_hash("0xConsumer", "req-1", "654321"))

    def test_missing_inputs_rejected(self):
        with self.assertRaises(OtpDeliveryError):
            compute_delivery_hash("", "req-1", "123456")
        with self.assertRaises(OtpDeliveryError):
            compute_delivery_hash("0xConsumer", "", "123456")
        with self.assertRaises(OtpDeliveryError):
            compute_delivery_hash("0xConsumer", "req-1", "")

    def test_field_boundary_is_collision_resistant(self):
        # Shifting a character across the consumer/request boundary must not
        # produce the same commitment (length-prefixed, not delimiter-joined).
        self.assertNotEqual(
            compute_delivery_hash("consumer", "xreq", "otp"),
            compute_delivery_hash("consumerx", "req", "otp"),
        )

    def test_raw_otp_never_appears_in_hash_output(self):
        otp = "super-secret-otp-990011"
        h = compute_delivery_hash("0xConsumer", "req-1", otp)
        self.assertNotIn(otp, h)


class OtpDeliveryReceiptTest(unittest.TestCase):
    def test_receipt_is_bounded_and_hides_raw_values(self):
        otp = "secret-otp-424242"
        receipt = otp_delivery_receipt("0xConsumerSecret", "req-secret-7", otp)
        self.assertEqual(receipt["kind"], "otp_delivery_receipt")
        self.assertFalse(receipt["raw_secret_egress"])
        self.assertFalse(receipt["otp_returned"])
        blob = json.dumps(receipt)
        self.assertNotIn(otp, blob)
        self.assertNotIn("0xConsumerSecret", blob)
        self.assertNotIn("req-secret-7", blob)
        self.assertRegex(receipt["delivery_hash"], r"^0x[0-9a-f]{64}$")
        self.assertRegex(receipt["consumer_app_id_hash"], r"^0x[0-9a-f]{64}$")
        self.assertRegex(receipt["request_id_hash"], r"^0x[0-9a-f]{64}$")

    def test_receipt_delivery_hash_matches_compute(self):
        receipt = otp_delivery_receipt("0xC", "r", "otp")
        self.assertEqual(receipt["delivery_hash"], compute_delivery_hash("0xC", "r", "otp"))


if __name__ == "__main__":
    unittest.main()
