import types
import unittest
from unittest.mock import patch

from tinker_delegate.config import Settings
from tinker_delegate.main import (
    _prompt_billing_card_payload,
    _read_masked_prompt_chars,
    _validate_prompt_billing_policy,
)
from tinker_delegate.tinker_encumbrance import TinkerEncumbrancePolicyResult


class PromptBillingCliTest(unittest.TestCase):
    def test_masked_prompt_echoes_masks_and_supports_backspace(self):
        chars = iter("123\x7f45\n")
        writes = []
        flushes = []

        value = _read_masked_prompt_chars(
            lambda: next(chars),
            writes.append,
            lambda: flushes.append(True),
        )

        self.assertEqual(value, "1245")
        self.assertEqual("".join(writes), "***\b \b**\r\n")
        self.assertGreaterEqual(len(flushes), 1)

    def test_prompt_card_payload_reads_fields_without_argv(self):
        prompts = []
        values = iter([
            "4242424242424242",
            "07",
            "2031",
            "123",
            "Test User",
            "",
            "",
            "",
            "94105",
            "",
        ])

        def fake_prompt(label: str) -> str:
            prompts.append(label)
            return next(values)

        payload = _prompt_billing_card_payload(prompt_fn=fake_prompt)

        self.assertEqual(payload["card_number"], "4242424242424242")
        self.assertEqual(payload["exp_month"], "07")
        self.assertEqual(payload["exp_year"], "2031")
        self.assertEqual(payload["cvc"], "123")
        self.assertEqual(payload["cardholder_name"], "Test User")
        self.assertEqual(payload["address_postal"], "94105")
        self.assertEqual(payload["address_country"], "US")
        self.assertEqual(len(prompts), 10)

    def test_prompt_policy_requires_deployed_attestation_expectations(self):
        args = types.SimpleNamespace(
            command="add-card-encrypted-prompt",
            allow_local_attestation=False,
            compose_hash="compose-ok",
            app_id="",
            os_image_hash="os-ok",
        )

        with self.assertRaisesRegex(ValueError, "--app-id"):
            _validate_prompt_billing_policy(args)

    def test_prompt_policy_allows_local_only_when_explicit(self):
        args = types.SimpleNamespace(
            command="add-card-encrypted-prompt",
            allow_local_attestation=True,
            compose_hash="",
            app_id="",
            os_image_hash="",
        )

        _validate_prompt_billing_policy(args)

    def test_prompt_policy_requires_live_encumbrance_when_flagged(self):
        args = types.SimpleNamespace(
            command="add-card-encrypted-prompt",
            allow_local_attestation=False,
            compose_hash="0x" + "11" * 32,
            app_id="app-ok",
            os_image_hash="os-ok",
            require_encumbrance=True,
            encumbrance_contract_address="0x" + "22" * 20,
            encumbrance_rpc_url="https://sepolia.base.org",
            encumbrance_compose_hash="",
        )
        allowed = TinkerEncumbrancePolicyResult(
            checked=True,
            allowed=True,
            reason="allowed",
            operation="add_payment_method",
            operation_kind=0,
        )

        with patch(
            "tinker_delegate.tinker_encumbrance.preflight_tinker_operation",
            return_value=allowed,
        ) as preflight:
            _validate_prompt_billing_policy(args, Settings())

        self.assertEqual(preflight.call_count, 1)
        self.assertEqual(preflight.call_args.kwargs["compose_hash"], "0x" + "11" * 32)
        self.assertTrue(preflight.call_args.kwargs["required"])

    def test_prompt_policy_checks_add_balance_before_prompt_when_amount_is_present(self):
        args = types.SimpleNamespace(
            command="funding-validation-packet",
            allow_local_attestation=False,
            compose_hash="0x" + "11" * 32,
            app_id="app-ok",
            os_image_hash="os-ok",
            require_encumbrance=True,
            encumbrance_contract_address="0x" + "22" * 20,
            encumbrance_rpc_url="https://sepolia.base.org",
            encumbrance_compose_hash="0x" + "33" * 32,
        )
        allowed = TinkerEncumbrancePolicyResult(
            checked=True,
            allowed=True,
            reason="allowed",
            operation="add_payment_method",
            operation_kind=0,
        )

        with patch(
            "tinker_delegate.tinker_encumbrance.preflight_tinker_operation",
            return_value=allowed,
        ) as preflight:
            _validate_prompt_billing_policy(args, Settings(), amount_dollars=10.0)

        self.assertEqual(preflight.call_count, 2)
        self.assertTrue(all(call.kwargs["required"] for call in preflight.call_args_list))
        self.assertTrue(all(call.kwargs["compose_hash"] == "0x" + "33" * 32 for call in preflight.call_args_list))

    def test_prompt_policy_denies_when_encumbrance_denies(self):
        args = types.SimpleNamespace(
            command="add-card-encrypted-prompt",
            allow_local_attestation=False,
            compose_hash="0x" + "11" * 32,
            app_id="app-ok",
            os_image_hash="os-ok",
            require_encumbrance=True,
            encumbrance_contract_address="0x" + "22" * 20,
            encumbrance_rpc_url="https://sepolia.base.org",
            encumbrance_compose_hash="",
        )
        denied = TinkerEncumbrancePolicyResult(
            checked=True,
            allowed=False,
            reason="compose_hash_not_approved",
            operation="add_payment_method",
            operation_kind=0,
        )

        with patch(
            "tinker_delegate.tinker_encumbrance.preflight_tinker_operation",
            return_value=denied,
        ):
            with self.assertRaisesRegex(ValueError, "compose_hash_not_approved"):
                _validate_prompt_billing_policy(args, Settings())


if __name__ == "__main__":
    unittest.main()
