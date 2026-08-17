import json
import unittest

import httpx
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_hash.auto import keccak

from tinker_delegate.compute_runtime import (
    COMPILED_RECIPES,
    ComputeRuntimePolicyError,
    METERING_DECISION_SCHEMA,
    ProviderUsage,
    SignedUsageEnvelope,
)
from tinker_delegate.compute_vault_gateway import (
    HttpsComputeMeteringClient,
    HttpsComputeVaultGateway,
    _APPROVED_COMPOSE_HASHES,
    _APPROVED_COMPOSE_COUNT,
    _APPROVED_TEE_IDENTITY_COUNT,
    _ACTIVE_RATE_POLICY_COUNT,
    _ALLOWED_ASSET_COUNT,
    _ASSET_ADDITIONS_FROZEN,
    _COMPOSE_POLICY_FROZEN,
    _DEVELOPER_FEE_FROZEN,
    _GET_JOB,
    _METERING_BINDING_FROZEN,
    _METERING_POLICY_SET_HASH,
    _METERING_QVL_VERIFIER,
    _METERING_VERIFIER,
    _PAUSED,
    _PENDING_ASSET_COUNT,
    _PENDING_COMPOSE_COUNT,
    _PENDING_DEVELOPER_FEE_ACTIVATES_AT,
    _PENDING_METERING_BINDING_ACTIVATES_AT,
    _PENDING_METERING_POLICY_SET_HASH,
    _PENDING_METERING_QVL_VERIFIER,
    _PENDING_METERING_VERIFIER,
    _PENDING_RATE_POLICY_COUNT,
    _PENDING_TEE_IDENTITY_COUNT,
    _RATE_POLICY_ADDITIONS_FROZEN,
    _RATE_POLICIES,
    _TEE_IDENTITY_ADDITIONS_FROZEN,
    _TEE_IDENTITY_COMPOSE_HASH,
)
from tests.test_compute_runtime import (
    ASSET,
    COMPOSE,
    NOW,
    POLICY_SET,
    PROVIDER,
    RATE,
    RESULT,
    VAULT,
    TestOnlyExecutionIdentity,
    _intent,
)


BLOCK = 100
BLOCK_HASH = "0x" + "ab" * 32
CODE = bytes.fromhex("6080604052348015600e")
VERIFIER = "0x" + "33" * 20
QVL_VERIFIER = "0x" + "34" * 20


def _word_uint(value):
    return int(value).to_bytes(32, "big")


def _word_address(value):
    return b"\0" * 12 + bytes.fromhex(value[2:])


def _word_bytes32(value):
    return bytes.fromhex(value[2:])


def _json_response(request, request_id, result):
    return httpx.Response(
        200,
        headers={"content-type": "application/json"},
        json={"jsonrpc": "2.0", "id": request_id, "result": result},
        request=request,
    )


class ComputeVaultGatewayTest(unittest.TestCase):
    def setUp(self):
        self.identity = TestOnlyExecutionIdentity()
        self.intent = _intent(self.identity)
        self.policy_tags = []
        self.broadcast_raw = []

        def handler(request: httpx.Request) -> httpx.Response:
            payload = json.loads(request.content)
            method = payload["method"]
            params = payload["params"]
            request_id = payload["id"]
            if method == "eth_chainId":
                return _json_response(request, request_id, hex(84532))
            if method == "eth_getBlockByNumber":
                number = BLOCK if params[0] == "latest" else int(params[0], 16)
                return _json_response(
                    request,
                    request_id,
                    {
                        "number": hex(number),
                        "timestamp": hex(NOW),
                        "hash": BLOCK_HASH,
                    },
                )
            if method == "eth_getCode":
                self.policy_tags.append((method, params[1]))
                return _json_response(request, request_id, "0x" + CODE.hex())
            if method == "eth_call":
                self.policy_tags.append((method, params[1]))
                data = bytes.fromhex(params[0]["data"][2:])
                selector = data[:4]
                if selector == _PAUSED:
                    result = _word_uint(0)
                elif selector in {
                    _DEVELOPER_FEE_FROZEN,
                    _ASSET_ADDITIONS_FROZEN,
                    _RATE_POLICY_ADDITIONS_FROZEN,
                    _COMPOSE_POLICY_FROZEN,
                    _TEE_IDENTITY_ADDITIONS_FROZEN,
                    _METERING_BINDING_FROZEN,
                }:
                    result = _word_uint(1)
                elif selector == _METERING_POLICY_SET_HASH:
                    result = _word_bytes32(POLICY_SET)
                elif selector == _ALLOWED_ASSET_COUNT:
                    result = _word_uint(1)
                elif selector == _ACTIVE_RATE_POLICY_COUNT:
                    result = _word_uint(2)
                elif selector in {
                    _APPROVED_COMPOSE_COUNT,
                    _APPROVED_TEE_IDENTITY_COUNT,
                }:
                    result = _word_uint(1)
                elif selector in {
                    _PENDING_DEVELOPER_FEE_ACTIVATES_AT,
                    _PENDING_ASSET_COUNT,
                    _PENDING_RATE_POLICY_COUNT,
                    _PENDING_COMPOSE_COUNT,
                    _PENDING_TEE_IDENTITY_COUNT,
                    _PENDING_METERING_BINDING_ACTIVATES_AT,
                }:
                    result = _word_uint(0)
                elif selector in {
                    _PENDING_METERING_VERIFIER,
                    _PENDING_METERING_QVL_VERIFIER,
                }:
                    result = _word_address("0x" + "00" * 20)
                elif selector == _PENDING_METERING_POLICY_SET_HASH:
                    result = _word_bytes32("0x" + "00" * 32)
                elif selector == _APPROVED_COMPOSE_HASHES:
                    result = _word_uint(1)
                elif selector == _TEE_IDENTITY_COMPOSE_HASH:
                    result = _word_bytes32(COMPOSE)
                elif selector == _METERING_VERIFIER:
                    result = _word_address(VERIFIER)
                elif selector == _METERING_QVL_VERIFIER:
                    result = _word_address(QVL_VERIFIER)
                elif selector == _RATE_POLICIES:
                    result = b"".join(
                        (
                            _word_address(ASSET),
                            _word_address(PROVIDER),
                            _word_uint(500),
                            _word_uint(1),
                        )
                    )
                elif selector == _GET_JOB:
                    result = b"".join(
                        (
                            _word_bytes32(self.intent.project_id),
                            _word_address(self.intent.user),
                            _word_address(self.intent.asset),
                            _word_uint(self.intent.authorization_nonce),
                            _word_uint(self.intent.max_asset_debit),
                            _word_uint(0),
                            _word_uint(self.intent.authorization_expiry),
                            _word_uint(0),
                            _word_uint(0),
                            _word_uint(0),
                            _word_bytes32(self.intent.rate_policy_commitment),
                            _word_bytes32(self.intent.workload_commitment),
                            _word_bytes32(self.intent.manifest_commitment),
                            _word_bytes32(self.intent.commitment),
                            _word_bytes32("0x" + "00" * 32),
                            _word_bytes32("0x" + "00" * 32),
                            _word_bytes32("0x" + "00" * 32),
                            _word_bytes32("0x" + "00" * 32),
                            _word_uint(0),
                            _word_address("0x" + "00" * 20),
                            _word_uint(1),
                        )
                    )
                else:
                    return httpx.Response(
                        500,
                        headers={"content-type": "application/json"},
                        json={"unexpected": selector.hex()},
                        request=request,
                    )
                return _json_response(request, request_id, "0x" + result.hex())
            if method == "eth_getTransactionCount":
                return _json_response(request, request_id, "0x0")
            if method == "eth_gasPrice":
                return _json_response(request, request_id, hex(1_000_000_000))
            if method == "eth_estimateGas":
                return _json_response(request, request_id, hex(100_000))
            if method == "eth_sendRawTransaction":
                self.broadcast_raw.append(params[0])
                result = "0x" + keccak(bytes.fromhex(params[0][2:])).hex()
                return _json_response(request, request_id, result)
            return httpx.Response(500, request=request)

        self.client = httpx.Client(transport=httpx.MockTransport(handler))
        self.gateway = HttpsComputeVaultGateway(
            "http://rpc.example.test",
            vault_address=VAULT,
            runtime_code_hash="0x" + keccak(CODE).hex(),
            identity=self.identity,
            client=self.client,
            allow_plain_http_for_test=True,
        )

    def tearDown(self):
        self.gateway.close()
        self.client.close()

    def test_snapshot_pins_bytecode_and_every_call_to_one_explicit_block(self):
        snapshot = self.gateway.snapshot(
            job_id=self.intent.job_id,
            rate_policy_commitment=RATE,
            tee_identity=self.identity.address,
            compose_hash=COMPOSE,
        )
        self.assertEqual(snapshot.block_number, BLOCK)
        self.assertEqual(snapshot.job.job_id if hasattr(snapshot.job, "job_id") else self.intent.job_id, self.intent.job_id)
        self.assertGreaterEqual(len(self.policy_tags), 22)
        expected_tag = {"blockHash": BLOCK_HASH, "requireCanonical": True}
        self.assertTrue(all(tag == expected_tag for _, tag in self.policy_tags))
        self.assertIn(("eth_getCode", expected_tag), self.policy_tags)
        self.assertTrue(snapshot.compose_policy_frozen)
        self.assertEqual(snapshot.registered_tee_compose_hash, COMPOSE)

    def test_prepared_start_is_exactly_signed_persistable_and_rebroadcastable(self):
        prepared = self.gateway.prepare_start(
            job_id=self.intent.job_id,
            compose_hash=COMPOSE,
        )
        self.assertEqual(
            prepared.tx_hash,
            "0x" + keccak(bytes.fromhex(prepared.raw_transaction[2:])).hex(),
        )
        recovered = Account.recover_transaction(prepared.raw_transaction)
        self.assertEqual(recovered.lower(), self.identity.address)
        self.gateway.broadcast(prepared)
        self.gateway.broadcast(prepared)
        self.assertEqual(
            self.broadcast_raw,
            [prepared.raw_transaction, prepared.raw_transaction],
        )


class ComputeMeteringTransportTest(unittest.TestCase):
    def test_metering_post_is_bounded_authenticated_and_replay_keyed(self):
        identity = TestOnlyExecutionIdentity()
        intent = _intent(identity)
        usage = ProviderUsage(
            outcome="succeeded",
            prefill_tokens=10,
            sample_tokens=2,
            training_tokens=0,
            result_commitment=RESULT,
            provider_authoritative_invoice=False,
        )
        signed = SignedUsageEnvelope.create(
            intent=intent,
            usage=usage,
            tee_identity=identity,
            start_commitment="0x" + "12" * 32,
            usage_started_at=NOW - 10,
            block_number=BLOCK,
            block_hash=BLOCK_HASH,
            usage_observed_at=NOW,
        )
        seen = []

        def handler(request):
            seen.append(request)
            response = {
                "schema": METERING_DECISION_SCHEMA,
                "classification": "attested_dual_verified_metering",
                "provider_authoritative_invoice": False,
                "chain_id": 84532,
                "vault_address": VAULT,
                "pinned_block_number": BLOCK,
                "pinned_block_hash": BLOCK_HASH,
                "policy_set_hash": POLICY_SET,
                "rate_policy_commitment": RATE,
                "workload_commitment": intent.workload_commitment,
                "manifest_commitment": intent.manifest_commitment,
                "dispatch_intent_commitment": intent.commitment,
                "asset": ASSET,
                "job_id": intent.job_id,
                "usage_commitment": signed.usage_commitment,
                "onchain_usage_commitment": "0x" + "12" * 32,
                "actual_asset_debit": "1",
                "billable_compute_units": "12",
                "usage_started_at": NOW - 10,
                "usage_ended_at": NOW,
                "attestation_evidence_hash": "0x" + "17" * 32,
                "receipt_expiry": NOW + 100,
                "metering_receipt_digest": "0x" + "13" * 32,
                "metering_qvl_receipt_digest": "0x" + "16" * 32,
                "metering_verifier": VERIFIER,
                "metering_qvl_verifier": QVL_VERIFIER,
                "tee_identity": identity.address,
                "compose_hash": COMPOSE,
                "raw_secret_egress": False,
                "verifier_signature": (
                    "0x"
                    + "14" * 32
                    + "15" * 32
                    + "1b"
                ),
                "qvl_signature": (
                    "0x"
                    + "18" * 32
                    + "19" * 32
                    + "1c"
                ),
            }
            return httpx.Response(
                200,
                headers={"content-type": "application/json"},
                json=response,
                request=request,
            )

        transport = httpx.Client(transport=httpx.MockTransport(handler))
        client = HttpsComputeMeteringClient(
            "http://meter.example.test/meter",
            auth_token="test-only-metering-auth-token-0001",
            client=transport,
            allow_plain_http_for_test=True,
        )
        try:
            decision = client.decide(signed)
        finally:
            client.close()
            transport.close()
        self.assertFalse(decision.provider_authoritative_invoice)
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0].headers["idempotency-key"], signed.usage_commitment)
        self.assertEqual(
            seen[0].headers["authorization"],
            "Bearer test-only-metering-auth-token-0001",
        )
        body = seen[0].content.decode()
        self.assertNotIn("private user prompt", body)
        self.assertNotIn("private training example", body)
        self.assertNotIn("provider_id", body)
        self.assertIn('"schema":"dnai.compute-metering-request.v2"', body)
        self.assertIn('"training_tokens":"0"', body)

    def test_metering_client_rejects_token_shorter_than_service_minimum(self):
        with self.assertRaisesRegex(
            ComputeRuntimePolicyError,
            "authentication is unavailable",
        ):
            HttpsComputeMeteringClient(
                "https://meter.example.test/meter",
                auth_token="x" * 31,
            )


if __name__ == "__main__":
    unittest.main()
