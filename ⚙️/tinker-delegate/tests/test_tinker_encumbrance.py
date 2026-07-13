import unittest

from tinker_delegate.config import Settings
from tinker_delegate.tinker_encumbrance import (
    APPROVED_COMPOSE_SELECTOR,
    EMERGENCY_HALTED_SELECTOR,
    MAX_ADD_BALANCE_SELECTOR,
    MAX_SPEND_SELECTOR,
    TinkerEncumbranceChecker,
    TinkerOperationKind,
    amount_dollars_to_policy_wei,
    encode_bool,
    encode_uint,
    preflight_tinker_operation,
)


COMPOSE_HASH = "0x" + "11" * 32
CONTRACT = "0x" + "22" * 20


class FakeRpc:
    def __init__(
        self,
        *,
        emergency_halted: bool = False,
        compose_approved: bool = True,
        max_add_balance_wei: int = 5 * 10**18,
        max_spend_wei: int = 9 * 10**18,
    ):
        self.emergency_halted = emergency_halted
        self.compose_approved = compose_approved
        self.max_add_balance_wei = max_add_balance_wei
        self.max_spend_wei = max_spend_wei
        self.calls = []

    def eth_call(self, tx):
        self.calls.append(tx)
        data = bytes.fromhex(tx["data"][2:])
        selector = data[:4]
        if selector == EMERGENCY_HALTED_SELECTOR:
            return encode_bool(self.emergency_halted)
        if selector == APPROVED_COMPOSE_SELECTOR:
            return encode_bool(self.compose_approved)
        if selector == MAX_ADD_BALANCE_SELECTOR:
            return encode_uint(self.max_add_balance_wei)
        if selector == MAX_SPEND_SELECTOR:
            return encode_uint(self.max_spend_wei)
        raise AssertionError(f"unexpected selector {selector.hex()}")


class TinkerEncumbranceTest(unittest.TestCase):
    def test_optional_missing_contract_is_unchecked_allowed(self):
        result = preflight_tinker_operation(
            Settings(),
            operation_kind=TinkerOperationKind.ADD_BALANCE,
            amount_dollars=5.0,
        )

        self.assertFalse(result.checked)
        self.assertTrue(result.allowed)
        self.assertEqual(result.reason, "not_configured")
        self.assertFalse(result.raw_secret_egress)

    def test_required_missing_contract_fails_closed(self):
        result = preflight_tinker_operation(
            Settings(encumbrance_required=True),
            operation_kind=TinkerOperationKind.ADD_BALANCE,
            amount_dollars=5.0,
        )

        self.assertFalse(result.checked)
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, "missing_contract")

    def test_add_balance_policy_allows_approved_compose_under_cap(self):
        rpc = FakeRpc()
        checker = TinkerEncumbranceChecker(rpc, CONTRACT)

        result = checker.check_operation(
            operation_kind=TinkerOperationKind.ADD_BALANCE,
            compose_hash=COMPOSE_HASH,
            amount_wei=5 * 10**18,
        )

        self.assertTrue(result.checked)
        self.assertTrue(result.allowed)
        self.assertEqual(result.reason, "allowed")
        self.assertEqual(result.max_amount_wei, 5 * 10**18)
        self.assertEqual(result.limit_kind, "add_balance")
        self.assertEqual(len(rpc.calls), 3)

    def test_add_balance_policy_denies_over_cap(self):
        result = TinkerEncumbranceChecker(FakeRpc(max_add_balance_wei=5 * 10**18), CONTRACT).check_operation(
            operation_kind=TinkerOperationKind.ADD_BALANCE,
            compose_hash=COMPOSE_HASH,
            amount_wei=6 * 10**18,
        )

        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, "add_balance_cap_exceeded")

    def test_policy_denies_unapproved_compose_before_limit(self):
        result = TinkerEncumbranceChecker(FakeRpc(compose_approved=False), CONTRACT).check_operation(
            operation_kind=TinkerOperationKind.SPEND_TINKER_COMPUTE,
            compose_hash=COMPOSE_HASH,
            amount_wei=1,
        )

        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, "compose_hash_not_approved")

    def test_policy_amount_conversion_uses_configured_units_per_usd(self):
        result = preflight_tinker_operation(
            Settings(
                encumbrance_contract_address=CONTRACT,
                encumbrance_compose_hash=COMPOSE_HASH,
                encumbrance_policy_units_per_usd_wei=100,
            ),
            operation_kind=TinkerOperationKind.ADD_BALANCE,
            amount_dollars=4.25,
            rpc=FakeRpc(max_add_balance_wei=500),
        )

        self.assertTrue(result.allowed)
        self.assertEqual(result.amount_wei, 425)
        self.assertEqual(amount_dollars_to_policy_wei(4.25, units_per_usd=100), 425)


if __name__ == "__main__":
    unittest.main()
