import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock

from eth_hash.auto import keccak
import httpx
from pydantic import ValidationError

from email_oracle.chain_auth import (
    BASE_SEPOLIA_CHAIN_ID,
    CANONICAL_CALLER_IDENTITY,
    IS_CONSUMER_AUTHORIZED_SELECTOR,
    RELEASE_CONFIGURATION_READY_SELECTOR,
    EmailOracleAuthChecker,
    EmailOracleAuthError,
    FinalizedBlockCheckpointStore,
    JsonRpcClient,
    check_consumer_authorization,
    encode_bool,
)
from email_oracle.config import Settings


CONTRACT = "0x" + "11" * 20
CONSUMER = "0x" + "22" * 20
COMPOSE_HASH = "0x" + "33" * 32
BLOCK_HASH = "0x" + "44" * 32
OTHER_BLOCK_HASH = "0x" + "55" * 32
RUNTIME_CODE = bytes.fromhex("6001600055")
RUNTIME_CODE_HASH = "0x" + keccak(RUNTIME_CODE).hex()
NOW = 2_000_000_000


class FakeRpc:
    def __init__(
        self,
        *,
        finalized_number: int = 100,
        block_hash: str = BLOCK_HASH,
        timestamp: int = NOW - 30,
        runtime_code: bytes = RUNTIME_CODE,
        ready: bool = True,
        allowed: bool = True,
        chain_id: int = BASE_SEPOLIA_CHAIN_ID,
        post_read_block_hash: str = "",
    ):
        self.finalized_number = finalized_number
        self.block_hash = block_hash
        self.timestamp = timestamp
        self.runtime_code = runtime_code
        self.ready = ready
        self.allowed = allowed
        self.chain_id = chain_id
        self.post_read_block_hash = post_read_block_hash
        self.calls: list[tuple[str, list]] = []
        self._number_reads: dict[str, int] = {}

    def call(self, method, params):
        self.calls.append((method, params))
        if method == "eth_chainId":
            return hex(self.chain_id)
        if method == "eth_getBlockByNumber":
            tag = params[0]
            number = self.finalized_number if tag == "finalized" else int(tag, 16)
            if tag != "finalized":
                self._number_reads[tag] = self._number_reads.get(tag, 0) + 1
            block_hash = self.block_hash
            if (
                tag != "finalized"
                and self.post_read_block_hash
                and self._number_reads[tag] > 1
            ):
                block_hash = self.post_read_block_hash
            return {
                "number": hex(number),
                "hash": block_hash,
                "timestamp": hex(self.timestamp),
            }
        if method == "eth_getCode":
            return "0x" + self.runtime_code.hex()
        if method == "eth_call":
            calldata = params[0]["data"]
            if calldata == "0x" + RELEASE_CONFIGURATION_READY_SELECTOR.hex():
                return encode_bool(self.ready)
            if calldata.startswith("0x" + IS_CONSUMER_AUTHORIZED_SELECTOR.hex()):
                return encode_bool(self.allowed)
            raise AssertionError(f"unexpected calldata {calldata}")
        raise AssertionError(f"unexpected JSON-RPC method {method}")


class FakeCheckpointStore:
    def __init__(self):
        self.records: list[tuple[int, str]] = []

    def record(self, block_number: int, block_hash: str) -> None:
        self.records.append((block_number, block_hash))


def _settings(**overrides) -> Settings:
    values = {
        "auth_required": True,
        "auth_contract_address": CONTRACT,
        "auth_chain_id": BASE_SEPOLIA_CHAIN_ID,
        "auth_contract_runtime_code_hash": RUNTIME_CODE_HASH,
        "auth_consumer_app_id": CONSUMER,
        "auth_consumer_compose_hash": COMPOSE_HASH,
        "auth_expected_caller_identity": CANONICAL_CALLER_IDENTITY,
        "auth_max_finalized_block_age_seconds": 900,
        "auth_max_future_block_skew_seconds": 30,
    }
    values.update(overrides)
    return Settings(**values)


class EmailOracleChainAuthTest(unittest.TestCase):
    def test_optional_missing_contract_is_allowed_for_local_dev(self):
        result = check_consumer_authorization(
            Settings(), caller_identity="tinker-delegate.test"
        )

        self.assertFalse(result.checked)
        self.assertTrue(result.allowed)
        self.assertEqual(result.reason, "not_configured")
        self.assertFalse(result.raw_secret_egress)

    def test_required_missing_contract_fails_closed(self):
        result = check_consumer_authorization(Settings(auth_required=True))

        self.assertFalse(result.checked)
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, "missing_contract")

    def test_production_release_requires_exact_fail_closed_invariants(self):
        required = {
            "production_release": True,
            "dstack_enabled": True,
            "auto_genesis": False,
            "runtime_auth_required": True,
            "auth_required": True,
            "auth_contract_address": CONTRACT,
            "auth_rpc_url": "https://rpc-one.example/base-sepolia/key-one",
            "auth_rpc_url_secondary": "https://rpc-two.example/base-sepolia/key-two",
            "auth_chain_id": BASE_SEPOLIA_CHAIN_ID,
            "auth_contract_runtime_code_hash": RUNTIME_CODE_HASH,
            "auth_consumer_app_id": CONSUMER,
            "auth_consumer_compose_hash": COMPOSE_HASH,
            "auth_expected_caller_identity": CANONICAL_CALLER_IDENTITY,
        }
        settings = Settings(**required)
        self.assertTrue(settings.production_release)

        unsafe_values = (
            ("dstack_enabled", False),
            ("runtime_auth_required", False),
            ("runtime_auth_token", "static-runtime-token"),
            ("runtime_auth_key_path", "oracle/wrong"),
            ("auth_required", False),
            ("auth_contract_address", ""),
            ("auth_rpc_url", "http://rpc-one.example"),
            ("auth_rpc_url_secondary", ""),
            ("auth_rpc_url_secondary", "https://rpc-one.example/other-key"),
            ("auth_chain_id", 1),
            ("auth_contract_runtime_code_hash", ""),
            ("auth_consumer_app_id", ""),
            ("auth_consumer_compose_hash", ""),
            ("auth_expected_caller_identity", "tinker-delegate"),
            ("auth_max_finalized_block_age_seconds", 901),
            ("auth_max_future_block_skew_seconds", 61),
            ("auth_checkpoint_store_path", "/tmp/checkpoint.json"),
            ("allow_credential_provisioning_endpoint", True),
            ("credential_provisioning_token", "static-provisioning-token"),
            ("auto_genesis", True),
            ("cred_store_path", "/tmp/credentials.enc"),
            ("cred_store_key", "11" * 32),
            ("dstack_key_path", "email/wrong"),
            ("otp_replay_store_path", "/tmp/otp_replay.enc"),
            ("otp_replay_store_key", "22" * 32),
            ("otp_replay_key_path", "email/wrong-replay"),
        )
        for key, unsafe in unsafe_values:
            with self.subTest(key=key, unsafe=unsafe), self.assertRaises(
                ValidationError
            ):
                Settings(**(required | {key: unsafe}))

        secret = "provider-secret-api-key"
        with self.assertRaises(ValidationError) as caught:
            Settings(
                **(
                    required
                    | {
                        "auth_rpc_url": f"http://rpc-one.example/{secret}",
                    }
                )
            )
        self.assertNotIn(secret, str(caught.exception))

    def test_quorum_pins_all_reads_to_one_common_finalized_block(self):
        primary = FakeRpc(finalized_number=102)
        secondary = FakeRpc(finalized_number=100)
        checkpoint = FakeCheckpointStore()

        result = check_consumer_authorization(
            _settings(),
            caller_identity=CANONICAL_CALLER_IDENTITY,
            rpc=primary,
            rpc_secondary=secondary,
            checkpoint_store=checkpoint,
            now=NOW,
        )

        self.assertTrue(result.checked)
        self.assertTrue(result.allowed)
        self.assertEqual(result.reason, "allowed")
        self.assertEqual(result.chain_id, BASE_SEPOLIA_CHAIN_ID)
        self.assertEqual(result.finalized_block_number, 100)
        self.assertEqual(result.finalized_block_hash, BLOCK_HASH)
        self.assertEqual(checkpoint.records, [(100, BLOCK_HASH)])
        for rpc in (primary, secondary):
            pinned_calls = [
                (method, params)
                for method, params in rpc.calls
                if method in {"eth_getCode", "eth_call"}
            ]
            self.assertTrue(pinned_calls)
            self.assertTrue(all(params[-1] == "0x64" for _, params in pinned_calls))
            calldata = [params[0]["data"] for method, params in rpc.calls if method == "eth_call"]
            self.assertEqual(calldata[0], "0x" + RELEASE_CONFIGURATION_READY_SELECTOR.hex())
            self.assertTrue(
                calldata[1].startswith("0x" + IS_CONSUMER_AUTHORIZED_SELECTOR.hex())
            )
            self.assertIn(CONSUMER[2:].rjust(64, "0"), calldata[1])
            self.assertTrue(calldata[1].endswith(COMPOSE_HASH[2:]))

    def test_release_not_ready_denies_even_when_consumer_is_registered(self):
        result = check_consumer_authorization(
            _settings(),
            caller_identity=CANONICAL_CALLER_IDENTITY,
            rpc=FakeRpc(ready=False, allowed=True),
            rpc_secondary=FakeRpc(ready=False, allowed=True),
            checkpoint_store=FakeCheckpointStore(),
            now=NOW,
        )

        self.assertTrue(result.checked)
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, "release_configuration_not_ready")

    def test_current_consumer_revocation_denies(self):
        result = check_consumer_authorization(
            _settings(),
            caller_identity=CANONICAL_CALLER_IDENTITY,
            rpc=FakeRpc(allowed=False),
            rpc_secondary=FakeRpc(allowed=False),
            checkpoint_store=FakeCheckpointStore(),
            now=NOW,
        )

        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, "consumer_not_authorized")

    def test_caller_identity_mismatch_denies_before_rpc(self):
        primary = FakeRpc()
        secondary = FakeRpc()
        result = check_consumer_authorization(
            _settings(),
            caller_identity="tinker-delegate",
            rpc=primary,
            rpc_secondary=secondary,
            now=NOW,
        )

        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, "caller_identity_mismatch")
        self.assertEqual(primary.calls, [])
        self.assertEqual(secondary.calls, [])

    def test_one_injected_rpc_is_rejected(self):
        with self.assertRaisesRegex(EmailOracleAuthError, "both independent"):
            check_consumer_authorization(
                _settings(),
                caller_identity=CANONICAL_CALLER_IDENTITY,
                rpc=FakeRpc(),
                now=NOW,
            )

    def test_wrong_chain_or_disagreement_fails_closed(self):
        for secondary_chain in (1, BASE_SEPOLIA_CHAIN_ID + 1):
            with self.subTest(chain_id=secondary_chain), self.assertRaisesRegex(
                EmailOracleAuthError, "Base Sepolia"
            ):
                check_consumer_authorization(
                    _settings(),
                    caller_identity=CANONICAL_CALLER_IDENTITY,
                    rpc=FakeRpc(),
                    rpc_secondary=FakeRpc(chain_id=secondary_chain),
                    now=NOW,
                )

    def test_runtime_code_and_expected_hash_are_both_enforced(self):
        with self.assertRaisesRegex(EmailOracleAuthError, "disagree.*runtime code"):
            check_consumer_authorization(
                _settings(),
                caller_identity=CANONICAL_CALLER_IDENTITY,
                rpc=FakeRpc(),
                rpc_secondary=FakeRpc(runtime_code=b"\x60\x00"),
                now=NOW,
            )
        with self.assertRaisesRegex(EmailOracleAuthError, "code hash mismatch"):
            check_consumer_authorization(
                _settings(auth_contract_runtime_code_hash="0x" + "99" * 32),
                caller_identity=CANONICAL_CALLER_IDENTITY,
                rpc=FakeRpc(),
                rpc_secondary=FakeRpc(),
                now=NOW,
            )

    def test_policy_result_disagreement_fails_closed(self):
        for field, primary, secondary in (
            ("releaseConfigurationReady", FakeRpc(ready=True), FakeRpc(ready=False)),
            ("isConsumerAuthorized", FakeRpc(allowed=True), FakeRpc(allowed=False)),
        ):
            with self.subTest(field=field), self.assertRaisesRegex(
                EmailOracleAuthError, field
            ):
                check_consumer_authorization(
                    _settings(),
                    caller_identity=CANONICAL_CALLER_IDENTITY,
                    rpc=primary,
                    rpc_secondary=secondary,
                    now=NOW,
                )

    def test_stale_and_future_finalized_blocks_fail_closed(self):
        for timestamp, message in (
            (NOW - 901, "stale"),
            (NOW + 31, "future"),
        ):
            with self.subTest(timestamp=timestamp), self.assertRaisesRegex(
                EmailOracleAuthError, message
            ):
                check_consumer_authorization(
                    _settings(),
                    caller_identity=CANONICAL_CALLER_IDENTITY,
                    rpc=FakeRpc(timestamp=timestamp),
                    rpc_secondary=FakeRpc(timestamp=timestamp),
                    now=NOW,
                )

    def test_block_hash_disagreement_and_mid_read_change_fail_closed(self):
        with self.assertRaisesRegex(EmailOracleAuthError, "common finalized block"):
            check_consumer_authorization(
                _settings(),
                caller_identity=CANONICAL_CALLER_IDENTITY,
                rpc=FakeRpc(),
                rpc_secondary=FakeRpc(block_hash=OTHER_BLOCK_HASH),
                now=NOW,
            )
        with self.assertRaisesRegex(EmailOracleAuthError, "common finalized block"):
            check_consumer_authorization(
                _settings(),
                caller_identity=CANONICAL_CALLER_IDENTITY,
                rpc=FakeRpc(post_read_block_hash=OTHER_BLOCK_HASH),
                rpc_secondary=FakeRpc(),
                now=NOW,
            )

    def test_invalid_compose_hash_rejects_before_rpc(self):
        with self.assertRaises(EmailOracleAuthError):
            EmailOracleAuthChecker(
                FakeRpc(),
                FakeRpc(),
                CONTRACT,
                expected_runtime_code_hash=RUNTIME_CODE_HASH,
                now=NOW,
            ).is_consumer_authorized(
                consumer_app_id=CONSUMER,
                consumer_compose_hash="0x00",
            )

    def test_durable_checkpoint_is_atomic_and_monotonic(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "checkpoint.json"
            store = FinalizedBlockCheckpointStore(str(path))
            initial = store.ensure_ready()
            self.assertEqual(initial.block_number, 0)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

            store.record(100, BLOCK_HASH)
            self.assertEqual(store.load().block_number, 100)
            persisted = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(persisted["block_hash"], BLOCK_HASH)
            store.record(100, BLOCK_HASH)
            with self.assertRaisesRegex(EmailOracleAuthError, "regressed"):
                store.record(99, BLOCK_HASH)
            with self.assertRaisesRegex(EmailOracleAuthError, "conflicts"):
                store.record(100, OTHER_BLOCK_HASH)

    def test_checkpoint_symlink_fails_closed(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target.json"
            target.write_text("{}", encoding="utf-8")
            link = root / "checkpoint.json"
            link.symlink_to(target)
            with self.assertRaisesRegex(EmailOracleAuthError, "safely"):
                FinalizedBlockCheckpointStore(str(link)).load()

    def test_checkpoint_duplicate_json_fields_fail_closed(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "checkpoint.json"
            path.write_text(
                '{"schema":"dnai.email-oracle.finalized-checkpoint.v1",'
                '"block_number":1,"block_number":2,"block_hash":"'
                + BLOCK_HASH
                + '"}\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(EmailOracleAuthError, "repeats"):
                FinalizedBlockCheckpointStore(str(path)).load()

    def test_transport_error_never_exposes_rpc_url_or_provider_message(self):
        secret = "rpc-secret-api-key"
        client = JsonRpcClient(
            f"https://rpc.example/{secret}",
            label="primary",
        )
        request = httpx.Request("POST", f"https://rpc.example/{secret}")
        client._client.post = Mock(
            side_effect=httpx.ConnectError(
                f"failed request to https://rpc.example/{secret}",
                request=request,
            )
        )

        with self.assertRaises(EmailOracleAuthError) as caught:
            client.call("eth_chainId", [])
        self.assertNotIn(secret, str(caught.exception))
        self.assertNotIn("https://", str(caught.exception))
        self.assertEqual(
            str(caught.exception),
            "EmailOracleAuth primary RPC transport failed",
        )
        client.close()

        remote = JsonRpcClient(
            f"https://rpc.example/{secret}",
            label="secondary",
        )
        remote._client.post = Mock(
            return_value=httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "error": {"message": f"request URL contained {secret}"},
                },
                request=request,
            )
        )
        with self.assertRaises(EmailOracleAuthError) as remote_error:
            remote.call("eth_chainId", [])
        self.assertNotIn(secret, str(remote_error.exception))
        self.assertEqual(
            str(remote_error.exception),
            "EmailOracleAuth secondary RPC rejected eth_chainId",
        )
        remote.close()


if __name__ == "__main__":
    unittest.main()
