import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from tinker_delegate.card_channel import CardPayload, handle_card_update
from tinker_delegate.config import Settings
from tinker_delegate.redaction import redact_text


class RedactionTest(unittest.IsolatedAsyncioTestCase):
    def test_redacts_api_key_bearer_card_and_artifact_material(self):
        text = (
            'Authorization: Bearer secret-token TINKER_API_KEY=tml-secretsecretsecretsecret '
            '"card_number":"4242424242424242" cvc=123 '
            '"artifact_hex":"abcdefabcdefabcdefabcdefabcdefabcdef" '
            "oracle@example.com"
        )

        redacted = redact_text(text)

        self.assertNotIn("secret-token", redacted)
        self.assertNotIn("tml-secretsecretsecretsecret", redacted)
        self.assertNotIn("4242424242424242", redacted)
        self.assertNotIn("cvc=123", redacted)
        self.assertNotIn("abcdefabcdefabcdefabcdefabcdefabcdef", redacted)
        self.assertNotIn("oracle@example.com", redacted)

    def test_redacts_openrouter_and_openai_style_api_keys(self):
        # The evaluator agent uses OPENROUTER_API_KEY (format sk-or-v1-...); its
        # keys must be redacted just like the Tinker (tml-) key.
        secrets = [
            "sk-or-v1-abcdef1234567890abcdef1234567890abcd",
            "sk-proj-ABCDEF1234567890abcdefghij",
            "error hitting model with sk-1234567890abcdefghijKLMN",
        ]
        for text in secrets:
            with self.subTest(text=text[:12]):
                redacted = redact_text(text)
                self.assertIn("sk-<redacted>", redacted)
                # No trailing key material survives.
                self.assertNotIn("1234567890abcdef", redacted)
        self.assertIn("<redacted>", redact_text("OPENROUTER_API_KEY=sk-or-v1-secret1234567890"))

    def test_does_not_over_redact_benign_bounded_output(self):
        # redact_text underpins the egress guard's secret_shaped check, so it must
        # not flag benign bounded output (hashes, bands) as secret material.
        benign = '{"reward_band": "high", "hash": "0x' + "ab" * 32 + '", "skip": true}'
        self.assertEqual(redact_text(benign), benign)

    async def test_card_update_error_is_redacted(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            payload = CardPayload(
                card_number="4242424242424242",
                exp_month="12",
                exp_year="2030",
                cvc="123",
                cardholder_name="Test User",
            )
            settings = Settings(
                funding_receipt_store_path=str(Path(tmpdir) / "funding_receipts.enc"),
                funding_receipt_store_key="99" * 32,
                funding_mode="operator_capped_validation",
            )
            error = RuntimeError("processor saw card_number=4242424242424242 cvc=123")

            with patch("tinker_delegate.card_channel.add_payment_method", new=AsyncMock(side_effect=error)):
                result = await handle_card_update(payload, settings)

        self.assertFalse(result.success)
        self.assertNotIn("4242424242424242", result.error)
        self.assertNotIn("cvc=123", result.error)


if __name__ == "__main__":
    unittest.main()
