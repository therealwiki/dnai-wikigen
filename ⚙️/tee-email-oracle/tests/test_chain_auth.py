import unittest

from email_oracle.chain_auth import (
    IS_CONSUMER_AUTHORIZED_SELECTOR,
    EmailOracleAuthChecker,
    EmailOracleAuthError,
    check_consumer_authorization,
    encode_bool,
)
from email_oracle.config import Settings


CONTRACT = "0x" + "11" * 20
CONSUMER = "0x" + "22" * 20
COMPOSE_HASH = "0x" + "33" * 32


class FakeRpc:
    def __init__(self, allowed: bool):
        self.allowed = allowed
        self.calls = []

    def eth_call(self, tx):
        self.calls.append(tx)
        return encode_bool(self.allowed)


class EmailOracleChainAuthTest(unittest.TestCase):
    def test_optional_missing_contract_is_allowed_for_local_dev(self):
        result = check_consumer_authorization(Settings(), caller_identity="tinker-delegate.test")

        self.assertFalse(result.checked)
        self.assertTrue(result.allowed)
        self.assertEqual(result.reason, "not_configured")
        self.assertFalse(result.raw_secret_egress)

    def test_required_missing_contract_fails_closed(self):
        result = check_consumer_authorization(Settings(auth_required=True))

        self.assertFalse(result.checked)
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, "missing_contract")

    def test_checker_encodes_is_consumer_authorized_call(self):
        rpc = FakeRpc(allowed=True)
        result = EmailOracleAuthChecker(rpc, CONTRACT).is_consumer_authorized(
            consumer_app_id=CONSUMER,
            consumer_compose_hash=COMPOSE_HASH,
            caller_identity="tinker-delegate.test",
        )

        self.assertTrue(result.checked)
        self.assertTrue(result.allowed)
        self.assertEqual(result.reason, "allowed")
        self.assertEqual(result.consumer_app_id, CONSUMER)
        self.assertEqual(result.consumer_compose_hash, COMPOSE_HASH)
        self.assertEqual(len(rpc.calls), 1)
        calldata = rpc.calls[0]["data"]
        self.assertTrue(calldata.startswith("0x" + IS_CONSUMER_AUTHORIZED_SELECTOR.hex()))
        self.assertIn(CONSUMER[2:].rjust(64, "0"), calldata)
        self.assertTrue(calldata.endswith(COMPOSE_HASH[2:]))

    def test_checker_returns_registry_denial(self):
        result = EmailOracleAuthChecker(FakeRpc(allowed=False), CONTRACT).is_consumer_authorized(
            consumer_app_id=CONSUMER,
            consumer_compose_hash=COMPOSE_HASH,
        )

        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, "consumer_not_authorized")

    def test_expected_caller_identity_mismatch_denies_before_rpc(self):
        rpc = FakeRpc(allowed=True)
        result = check_consumer_authorization(
            Settings(
                auth_contract_address=CONTRACT,
                auth_consumer_app_id=CONSUMER,
                auth_consumer_compose_hash=COMPOSE_HASH,
                auth_expected_caller_identity="expected",
            ),
            caller_identity="wrong",
            rpc=rpc,
        )

        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, "caller_identity_mismatch")
        self.assertEqual(rpc.calls, [])

    def test_invalid_compose_hash_rejects(self):
        with self.assertRaises(EmailOracleAuthError):
            EmailOracleAuthChecker(FakeRpc(allowed=True), CONTRACT).is_consumer_authorized(
                consumer_app_id=CONSUMER,
                consumer_compose_hash="0x00",
            )


if __name__ == "__main__":
    unittest.main()
