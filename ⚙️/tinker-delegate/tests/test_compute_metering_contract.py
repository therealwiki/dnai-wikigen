"""Cross-package wire contract between execution and independent metering."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

from eth_keys import keys
from fastapi.testclient import TestClient

METERING_SRC = Path(__file__).resolve().parents[2] / "compute-metering" / "src"
if str(METERING_SRC) not in sys.path:
    sys.path.insert(0, str(METERING_SRC))

from compute_metering.models import (  # noqa: E402
    ComputeUsageEnvelope as ServiceUsageEnvelope,
    MeteringDecision as ServiceMeteringDecision,
    MeteringRequest as ServiceMeteringRequest,
)
from compute_metering.policy import canonical_json_bytes  # noqa: E402
from compute_metering.service import Runtime, _create_app  # noqa: E402
from compute_metering.usage import (  # noqa: E402
    compute_usage_commitment,
    verify_usage_envelope,
)

from tinker_delegate.compute_runtime import (  # noqa: E402
    MeteringDecision,
    ProviderUsage,
    SignedUsageEnvelope,
)
from tests.test_compute_runtime import (  # noqa: E402
    ASSET,
    BLOCK_HASH,
    COMPOSE,
    NOW,
    POLICY_SET,
    RATE,
    RESULT,
    VAULT,
    TestOnlyExecutionIdentity,
    _intent,
)


TOKEN = "cross-package-metering-token-0001"


class _RpcLifecycle:
    async def start(self):
        return None

    async def close(self):
        return None


class _ReplayLifecycle:
    def close(self):
        return None


class _ContractMeter:
    def __init__(self, verifier_key: keys.PrivateKey):
        self.verifier_key = verifier_key
        self.qvl_key = keys.PrivateKey(bytes.fromhex("33" * 32))
        self.requests = []

    async def meter(self, request: ServiceMeteringRequest) -> bytes:
        self.requests.append(request)
        verify_usage_envelope(
            request.usage,
            expected_tee_identity=request.usage.tee_identity,
        )
        digest = "0x" + "13" * 32
        qvl_digest = "0x" + "16" * 32
        raw = bytearray(
            self.verifier_key.sign_msg_hash(bytes.fromhex(digest[2:])).to_bytes()
        )
        raw[64] += 27
        qvl_raw = bytearray(
            self.qvl_key.sign_msg_hash(bytes.fromhex(qvl_digest[2:])).to_bytes()
        )
        qvl_raw[64] += 27
        decision = ServiceMeteringDecision(
            schema="dnai.compute-metering-decision.v2",
            classification="attested_dual_verified_metering",
            provider_authoritative_invoice=False,
            chain_id=84532,
            vault_address=VAULT,
            pinned_block_number=request.block.number,
            pinned_block_hash=request.block.hash,
            policy_set_hash=POLICY_SET,
            rate_policy_commitment=RATE,
            workload_commitment=request.usage.workload_commitment,
            manifest_commitment=request.usage.manifest_commitment,
            dispatch_intent_commitment=request.usage.dispatch_intent_commitment,
            asset=ASSET,
            job_id=request.usage.job_id,
            usage_commitment=request.usage.usage_commitment,
            onchain_usage_commitment="0x" + "15" * 32,
            actual_asset_debit="5",
            billable_compute_units="55",
            usage_started_at=request.usage.usage_started_at,
            usage_ended_at=request.usage.usage_observed_at,
            attestation_evidence_hash="0x" + "14" * 32,
            receipt_expiry=NOW + 120,
            metering_receipt_digest=digest,
            metering_qvl_receipt_digest=qvl_digest,
            metering_verifier=(
                self.verifier_key.public_key.to_checksum_address().lower()
            ),
            metering_qvl_verifier=(
                self.qvl_key.public_key.to_checksum_address().lower()
            ),
            tee_identity=request.usage.tee_identity,
            compose_hash=COMPOSE,
            raw_secret_egress=False,
            verifier_signature="0x" + bytes(raw).hex(),
            qvl_signature="0x" + bytes(qvl_raw).hex(),
        )
        return canonical_json_bytes(
            decision.model_dump(mode="json", by_alias=True)
        )


class ComputeMeteringWireContractTest(unittest.TestCase):
    def test_dispatch_request_is_accepted_by_service_and_response_parses_exactly(self):
        identity = TestOnlyExecutionIdentity()
        intent = _intent(identity)
        signed = SignedUsageEnvelope.create(
            intent=intent,
            usage=ProviderUsage(
                outcome="succeeded",
                prefill_tokens=50,
                sample_tokens=5,
                training_tokens=0,
                result_commitment=RESULT,
                provider_authoritative_invoice=False,
            ),
            tee_identity=identity,
            start_commitment="0x" + "12" * 32,
            usage_started_at=NOW - 1,
            block_number=44_000_000,
            block_hash=BLOCK_HASH,
            usage_observed_at=NOW,
        )
        # First prove the dispatch serializer is the metering package's strict
        # model, commitment, and signer contract without translation.
        parsed_request = ServiceMeteringRequest.model_validate(
            signed.to_dict(), strict=True
        )
        self.assertIsInstance(parsed_request.usage, ServiceUsageEnvelope)
        self.assertEqual(
            compute_usage_commitment(parsed_request.usage),
            signed.usage_commitment,
        )
        verify_usage_envelope(
            parsed_request.usage, expected_tee_identity=identity.address
        )

        meter = _ContractMeter(keys.PrivateKey(bytes.fromhex("22" * 32)))
        runtime = Runtime(
            release=SimpleNamespace(),
            meter=meter,
            rpc=_RpcLifecycle(),
            replay=_ReplayLifecycle(),
            auth_token=TOKEN,
            identity_attestor=None,
            identity_qvl_client=None,
            max_concurrency=2,
            rate_capacity=10,
            rate_refill_per_second=1.0,
            request_body_timeout_seconds=5.0,
        )
        with TestClient(
            _create_app(runtime), raise_server_exceptions=False
        ) as service:
            response = service.post(
                "/meter",
                headers={"Authorization": f"Bearer {TOKEN}"},
                json=signed.to_dict(),
            )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(len(meter.requests), 1)
        self.assertEqual(meter.requests[0], parsed_request)

        # Then prove the exact canonical service response is accepted by the
        # execution worker's settlement parser without legacy field aliases.
        parsed_decision = MeteringDecision.from_dict(response.json())
        self.assertEqual(parsed_decision.policy_set_hash, POLICY_SET)
        self.assertEqual(
            parsed_decision.metering_receipt_digest, "0x" + "13" * 32
        )
        self.assertEqual(
            parsed_decision.metering_qvl_receipt_digest, "0x" + "16" * 32
        )
        self.assertFalse(parsed_decision.provider_authoritative_invoice)
        self.assertNotIn("receipt_digest", response.json())
        self.assertNotIn("provider_authoritative", response.json())
        self.assertEqual(
            response.json()["provider_authoritative_invoice"], False
        )


if __name__ == "__main__":
    unittest.main()
