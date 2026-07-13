import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from tinker_delegate.card_channel import (
    CardPayload,
    attestation_report_data,
    get_attestation,
    get_tee_keypair,
    handle_card_update,
)
from tinker_delegate.config import Settings
from tinker_delegate.funding_receipt_store import FundingReceiptStore


def _payload() -> CardPayload:
    return CardPayload(
        card_number="4242424242424242",
        exp_month="12",
        exp_year="2030",
        cvc="123",
        cardholder_name="Test User",
        address_line1="123 Main St",
        address_city="SF",
        address_state="CA",
        address_postal="94105",
    )


class CardChannelTest(unittest.IsolatedAsyncioTestCase):
    def test_attestation_report_data_binds_context_and_public_key(self):
        keypair = get_tee_keypair()
        billing = attestation_report_data("billing", keypair.public_key_bytes)
        artifact = attestation_report_data("artifact", keypair.public_key_bytes)
        other_key = bytes([keypair.public_key_bytes[0] ^ 1]) + keypair.public_key_bytes[1:]

        self.assertEqual(len(billing), 32)
        self.assertNotEqual(billing, artifact)
        self.assertNotEqual(billing, attestation_report_data("billing", other_key))

        attestation = get_attestation("artifact")
        self.assertEqual(attestation["report_context"], "artifact")
        self.assertEqual(
            attestation["report_data"],
            attestation_report_data("artifact", keypair.public_key_bytes).hex(),
        )
        self.assertEqual(attestation["encryption_public_key"], keypair.public_key_bytes.hex())

    def test_tdx_attestation_includes_public_dstack_evidence(self):
        details = {
            "quote": "aa",
            "quote_report_data": "bb",
            "event_log": "[]",
            "vm_config": "{}",
            "app_id": "app-ok",
            "instance_id": "instance-ok",
            "app_name": "delegate",
            "device_id": "device-ok",
            "mr_aggregated": "mr-ok",
            "os_image_hash": "os-ok",
            "compose_hash": "compose-ok",
            "tcb_info": {"compose_hash": "compose-ok"},
        }

        with (
            patch("tinker_delegate.card_channel.is_dstack_enabled", return_value=True),
            patch("tinker_delegate.card_channel.get_attestation_details", return_value=details),
        ):
            attestation = get_attestation("artifact")

        self.assertEqual(attestation["mode"], "tdx")
        self.assertEqual(attestation["quote"], "aa")
        self.assertEqual(attestation["event_log"], "[]")
        self.assertEqual(attestation["os_image_hash"], "os-ok")
        self.assertEqual(attestation["compose_hash"], "compose-ok")
        self.assertEqual(attestation["tcb_info"], {"compose_hash": "compose-ok"})

    async def test_plaintext_payload_is_wiped_after_success(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            payload = _payload()
            receipt_path = Path(tmpdir) / "funding_receipts.enc"
            settings = Settings(
                funding_receipt_store_path=str(receipt_path),
                funding_receipt_store_key="66" * 32,
                funding_mode="operator_capped_validation",
            )

            with (
                patch(
                    "tinker_delegate.card_channel.add_payment_method",
                    new=AsyncMock(return_value={"success": False, "error": "stubbed"}),
                ),
                patch("tinker_delegate.card_channel.get_attestation", return_value={}),
            ):
                result = await handle_card_update(payload, settings)

            self.assertFalse(result.success)
            self.assertEqual(result.error, "stubbed")
            self.assertEqual(result.attempt_record["surface"], "payment_method")
            self.assertEqual(result.attempt_record["outcome"], "unknown_failure")
            self.assertEqual(result.attempt_record["bounded_message"], "unknown_failure")
            self.assertTrue(result.attempt_record["card_payload_destroyed"])
            stored = FundingReceiptStore(str(receipt_path), key_hex="66" * 32).load()
            self.assertEqual(stored, [result.attempt_record])
            self.assertEqual(payload.card_number, "")
            self.assertEqual(payload.exp_month, "")
            self.assertEqual(payload.exp_year, "")
            self.assertEqual(payload.cvc, "")
            self.assertEqual(payload.cardholder_name, "")
            self.assertEqual(payload.address_line1, "")

    async def test_plaintext_payload_is_wiped_after_exception(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            payload = _payload()
            receipt_path = Path(tmpdir) / "funding_receipts.enc"
            settings = Settings(
                funding_receipt_store_path=str(receipt_path),
                funding_receipt_store_key="77" * 32,
                funding_mode="operator_capped_validation",
            )

            with patch(
                "tinker_delegate.card_channel.add_payment_method",
                new=AsyncMock(side_effect=RuntimeError("browser failed")),
            ):
                result = await handle_card_update(payload, settings)

            self.assertFalse(result.success)
            self.assertEqual(result.error, "browser failed")
            self.assertEqual(result.attempt_record["surface"], "payment_method")
            self.assertEqual(result.attempt_record["outcome"], "transient_browser_failure")
            self.assertEqual(result.attempt_record["bounded_message"], "transient_browser_failure")
            self.assertNotIn("browser failed", result.attempt_record["bounded_message"])
            self.assertTrue(result.attempt_record["card_payload_destroyed"])
            stored = FundingReceiptStore(str(receipt_path), key_hex="77" * 32).load()
            self.assertEqual(stored, [result.attempt_record])
            self.assertEqual(payload.card_number, "")
            self.assertEqual(payload.exp_month, "")
            self.assertEqual(payload.exp_year, "")
            self.assertEqual(payload.cvc, "")
            self.assertEqual(payload.cardholder_name, "")
            self.assertEqual(payload.address_line1, "")

    async def test_receipt_persistence_failure_fails_closed(self):
        payload = _payload()

        class FailingStore:
            def append(self, receipt):
                raise RuntimeError("disk full card_number=4242424242424242")

        with (
            patch(
                "tinker_delegate.card_channel.add_payment_method",
                new=AsyncMock(return_value={"success": True}),
            ),
            patch("tinker_delegate.card_channel.get_attestation", return_value={}),
            patch("tinker_delegate.card_channel.build_funding_receipt_store", return_value=FailingStore()),
        ):
            result = await handle_card_update(
                payload,
                Settings(funding_mode="operator_capped_validation"),
            )

        self.assertFalse(result.success)
        self.assertIn("funding receipt persistence failed", result.error)
        self.assertNotIn("4242424242424242", result.error)
        self.assertIsNone(result.attempt_record)
        self.assertEqual(payload.card_number, "")


if __name__ == "__main__":
    unittest.main()
