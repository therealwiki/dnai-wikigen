import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from tinker_delegate import api
from tinker_delegate.card_channel import (
    BalancePayload,
    CardPayload,
    EncryptedCardPayload,
    handle_add_balance,
    handle_card_update,
    handle_encrypted_card_update,
)
from tinker_delegate.config import Settings
from tinker_delegate.funding_policy import (
    FundingMode,
    FundingPolicyError,
    funding_validation_preflight,
    funding_policy_status,
    require_add_balance_allowed,
    require_card_automation_allowed,
)
from tinker_delegate.funding_receipt_store import FundingReceiptStore


def _payload() -> CardPayload:
    return CardPayload(
        card_number="4242424242424242",
        exp_month="12",
        exp_year="2030",
        cvc="123",
        cardholder_name="Test User",
    )


class FundingPolicyTest(unittest.IsolatedAsyncioTestCase):
    def test_default_manual_prefund_denies_browser_funding(self):
        settings = Settings()
        status = funding_policy_status(settings)

        self.assertEqual(status.mode, FundingMode.MANUAL_PREFUND)
        self.assertFalse(status.card_automation_allowed)
        self.assertFalse(status.add_balance_automation_allowed)
        with self.assertRaises(FundingPolicyError):
            require_card_automation_allowed(settings)
        with self.assertRaises(FundingPolicyError):
            require_add_balance_allowed(settings)

    def test_operator_capped_validation_allows_browser_funding(self):
        settings = Settings(
            funding_mode="operator_capped_validation",
            allow_plaintext_card_endpoint=True,
            allow_add_balance_endpoint=True,
        )
        status = funding_policy_status(settings)

        self.assertEqual(status.mode, FundingMode.OPERATOR_CAPPED_VALIDATION)
        self.assertTrue(status.card_automation_allowed)
        self.assertTrue(status.add_balance_automation_allowed)
        self.assertTrue(status.plaintext_card_endpoint_allowed)
        self.assertTrue(status.add_balance_endpoint_allowed)
        self.assertIn("operator-owned capped validation", status.raw_card_scope)
        require_card_automation_allowed(settings)
        require_add_balance_allowed(settings)

    def test_default_preflight_fails_closed_without_browser_or_card(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = Settings(
                funding_receipt_store_path=str(Path(tmpdir) / "funding_receipts.enc"),
                funding_receipt_store_key="44" * 32,
            )

            result = funding_validation_preflight(settings, amount_dollars=10.0)

        body = result.to_public_dict()
        self.assertFalse(body["ready"])
        checks = {check["name"]: check for check in body["checks"]}
        self.assertEqual(checks["funding_mode"]["status"], "manual_prefund")
        self.assertFalse(checks["funding_mode"]["ok"])
        self.assertEqual(checks["funding_receipt_store"]["status"], "loadable")
        self.assertEqual(checks["billing_attestation_policy"]["status"], "missing_api_url")
        self.assertNotIn("4242424242424242", repr(body))

    def test_operator_validation_preflight_passes_with_bounded_local_policy(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = Settings(
                funding_mode="operator_capped_validation",
                funding_receipt_store_path=str(Path(tmpdir) / "funding_receipts.enc"),
                funding_receipt_store_key="55" * 32,
            )

            result = funding_validation_preflight(
                settings,
                amount_dollars=10.0,
                api_url="http://localhost:8080",
                allow_local_attestation=True,
            )

        body = result.to_public_dict()
        self.assertTrue(body["ready"])
        checks = {check["name"]: check for check in body["checks"]}
        self.assertEqual(checks["funding_mode"]["status"], "operator_capped_validation")
        self.assertEqual(checks["requested_amount"]["status"], "within_cap")
        self.assertEqual(checks["billing_attestation_policy"]["status"], "configured")
        self.assertEqual(checks["billing_attestation_fetch"]["status"], "skipped")

    def test_preflight_rejects_below_minimum_amount_and_disabled_endpoint(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = Settings(
                funding_mode="operator_capped_validation",
                funding_receipt_store_path=str(Path(tmpdir) / "funding_receipts.enc"),
                funding_receipt_store_key="66" * 32,
                max_add_balance_usd=10.0,
                allow_add_balance_endpoint=False,
            )

            result = funding_validation_preflight(
                settings,
                amount_dollars=6.0,
                require_add_balance_endpoint=True,
                api_url="http://localhost:8080",
                allow_local_attestation=True,
            )

        body = result.to_public_dict()
        self.assertFalse(body["ready"])
        checks = {check["name"]: check for check in body["checks"]}
        self.assertEqual(checks["requested_amount"]["status"], "below_minimum")
        self.assertEqual(checks["add_balance_endpoint"]["status"], "disabled")

    async def test_default_policy_denies_plaintext_card_before_browser(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            receipt_path = Path(tmpdir) / "funding_receipts.enc"
            settings = Settings(
                funding_receipt_store_path=str(receipt_path),
                funding_receipt_store_key="11" * 32,
            )
            payload = _payload()

            with patch("tinker_delegate.card_channel.add_payment_method", new=AsyncMock()) as add_payment:
                result = await handle_card_update(payload, settings)

            self.assertFalse(result.success)
            self.assertEqual(result.attempt_record["outcome"], "policy_denied")
            self.assertTrue(result.attempt_record["card_payload_destroyed"])
            self.assertEqual(payload.card_number, "")
            self.assertNotIn("4242424242424242", result.model_dump_json())
            add_payment.assert_not_called()
            stored = FundingReceiptStore(str(receipt_path), key_hex="11" * 32).load()
            self.assertEqual(stored, [result.attempt_record])

    async def test_default_policy_denies_encrypted_card_before_decrypt(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            receipt_path = Path(tmpdir) / "funding_receipts.enc"
            settings = Settings(
                funding_receipt_store_path=str(receipt_path),
                funding_receipt_store_key="22" * 32,
            )
            payload = EncryptedCardPayload(
                ephemeral_public_key="00",
                nonce="00",
                ciphertext="00",
            )

            with (
                patch("tinker_delegate.card_channel.add_payment_method", new=AsyncMock()) as add_payment,
                patch("tinker_delegate.card_channel.EncryptedPayload.from_hex") as from_hex,
            ):
                result = await handle_encrypted_card_update(payload, settings)

            self.assertFalse(result.success)
            self.assertEqual(result.attempt_record["outcome"], "policy_denied")
            self.assertTrue(result.attempt_record["card_payload_destroyed"])
            self.assertNotIn("4242424242424242", result.model_dump_json())
            add_payment.assert_not_called()
            from_hex.assert_not_called()
            stored = FundingReceiptStore(str(receipt_path), key_hex="22" * 32).load()
            self.assertEqual(stored, [result.attempt_record])

    async def test_default_policy_denies_add_balance_before_browser(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            receipt_path = Path(tmpdir) / "funding_receipts.enc"
            settings = Settings(
                funding_receipt_store_path=str(receipt_path),
                funding_receipt_store_key="33" * 32,
            )

            with patch("tinker_delegate.card_channel.add_balance", new=AsyncMock()) as add_balance:
                result = await handle_add_balance(BalancePayload(amount_dollars=10.0), settings)

            self.assertFalse(result.success)
            self.assertEqual(result.attempt_record["surface"], "add_balance")
            self.assertEqual(result.attempt_record["outcome"], "policy_denied")
            self.assertEqual(result.attempt_record["amount_band"], "5_25_usd")
            add_balance.assert_not_called()
            stored = FundingReceiptStore(str(receipt_path), key_hex="33" * 32).load()
            self.assertEqual(stored, [result.attempt_record])

    async def test_required_encumbrance_denies_plaintext_card_before_browser(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            receipt_path = Path(tmpdir) / "funding_receipts.enc"
            settings = Settings(
                funding_mode="operator_capped_validation",
                encumbrance_required=True,
                funding_receipt_store_path=str(receipt_path),
                funding_receipt_store_key="88" * 32,
            )
            payload = _payload()

            with patch("tinker_delegate.card_channel.add_payment_method", new=AsyncMock()) as add_payment:
                result = await handle_card_update(payload, settings)

            self.assertFalse(result.success)
            self.assertIn("missing_contract", result.error)
            self.assertEqual(result.attempt_record["outcome"], "policy_denied")
            self.assertTrue(result.attempt_record["card_payload_destroyed"])
            self.assertEqual(payload.card_number, "")
            add_payment.assert_not_called()

    async def test_required_encumbrance_denies_encrypted_card_before_decrypt(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            receipt_path = Path(tmpdir) / "funding_receipts.enc"
            settings = Settings(
                funding_mode="operator_capped_validation",
                encumbrance_required=True,
                funding_receipt_store_path=str(receipt_path),
                funding_receipt_store_key="99" * 32,
            )
            payload = EncryptedCardPayload(
                ephemeral_public_key="00",
                nonce="00",
                ciphertext="00",
            )

            with (
                patch("tinker_delegate.card_channel.add_payment_method", new=AsyncMock()) as add_payment,
                patch("tinker_delegate.card_channel.EncryptedPayload.from_hex") as from_hex,
            ):
                result = await handle_encrypted_card_update(payload, settings)

            self.assertFalse(result.success)
            self.assertIn("missing_contract", result.error)
            self.assertEqual(result.attempt_record["outcome"], "policy_denied")
            self.assertTrue(result.attempt_record["card_payload_destroyed"])
            add_payment.assert_not_called()
            from_hex.assert_not_called()

    async def test_required_encumbrance_denies_add_balance_before_browser(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            receipt_path = Path(tmpdir) / "funding_receipts.enc"
            settings = Settings(
                funding_mode="operator_capped_validation",
                encumbrance_required=True,
                funding_receipt_store_path=str(receipt_path),
                funding_receipt_store_key="aa" * 32,
            )

            with patch("tinker_delegate.card_channel.add_balance", new=AsyncMock()) as add_balance:
                result = await handle_add_balance(BalancePayload(amount_dollars=10.0), settings)

            self.assertFalse(result.success)
            self.assertIn("missing_contract", result.error)
            self.assertEqual(result.attempt_record["surface"], "add_balance")
            self.assertEqual(result.attempt_record["outcome"], "policy_denied")
            add_balance.assert_not_called()


class FundingPolicyApiTest(unittest.TestCase):
    def setUp(self):
        self.original_settings = api.settings

    def tearDown(self):
        api.settings = self.original_settings

    def test_funding_policy_endpoint_returns_bounded_mode(self):
        api.settings = Settings(funding_mode="manual_prefund")
        client = TestClient(api.app)

        response = client.get("/billing/funding-policy")

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["mode"], "manual_prefund")
        self.assertFalse(body["card_automation_allowed"])
        self.assertEqual(body["raw_card_scope"], "denied")

    def test_funding_preflight_endpoint_returns_bounded_checks(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            api.settings = Settings(
                funding_mode="operator_capped_validation",
                funding_receipt_store_path=str(Path(tmpdir) / "funding_receipts.enc"),
                funding_receipt_store_key="77" * 32,
            )
            client = TestClient(api.app)

            response = client.get(
                "/billing/funding-preflight",
                params={
                    "amount_dollars": 10.0,
                    "api_url": "http://localhost:8080",
                    "allow_local_attestation": True,
                },
            )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertTrue(body["ready"])
        self.assertEqual(body["policy"]["mode"], "operator_capped_validation")
        self.assertNotIn("4242424242424242", repr(body))


if __name__ == "__main__":
    unittest.main()
