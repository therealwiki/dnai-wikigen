import asyncio
import json
import sys
import types
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient


sys.modules.setdefault(
    "tinker",
    types.SimpleNamespace(ServiceClient=object, TrainingClient=object, SamplingClient=object),
)

from tinker_delegate import api  # noqa: E402
from tinker_delegate.artifacts import artifact_keccak256, encrypt_artifact_payload  # noqa: E402
from tinker_delegate.control_plane import ControlPlane, DealState, ScoreBand  # noqa: E402
from tinker_delegate.fake_tinker_backend import FakeTinkerServiceClient  # noqa: E402
from tinker_delegate.local_synthetic_room import (  # noqa: E402
    build_synthetic_room_public_packet,
    synthetic_room_evaluator,
)
from tinker_delegate.run_metadata_store import RunMetadataStore  # noqa: E402


class InMemoryRunMetadataStore:
    def __init__(self):
        self.records = []

    def append(self, record):
        bounded = RunMetadataStore._sanitize_record(record)
        self.records.append(bounded)
        return bounded


class LocalSyntheticRoomTest(unittest.TestCase):
    def test_encrypted_artifact_fake_tinker_evaluation_and_cleanup_are_bounded(self):
        private_artifact = b"private synthetic artifact: do not leak this payload"
        artifact_hash = artifact_keccak256(private_artifact)
        deal_id = "deal-local-synthetic"
        budget_cap = 10**18
        reserve_price = 10**17
        metadata_store = InMemoryRunMetadataStore()
        fake_tinker = FakeTinkerServiceClient(api_key="sealed-fake-key")
        cp = ControlPlane(
            "sealed-fake-key",
            run_metadata_store=metadata_store,
            project_id="sealed-project-id",
            service_client_factory=lambda **_kwargs: fake_tinker,
        )
        cp.on_deal_funded(
            deal_id,
            buyer="0x00000000000000000000000000000000000000b0",
            seller="0x000000000000000000000000000000000000005e",
            budget_cap=budget_cap,
            reserve_price=reserve_price,
        )

        encrypted = encrypt_artifact_payload(
            private_artifact,
            api.get_tee_keypair().public_key_bytes.hex(),
            deal_id=deal_id,
            artifact_hash=artifact_hash,
        )
        client = TestClient(api.app)
        with patch("tinker_delegate.api._get_control_plane", return_value=cp):
            response = client.post(f"/deal/{deal_id}/artifact/encrypted", json=encrypted)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["size"], len(private_artifact))
        ctx = cp._deals[deal_id]
        self.assertEqual(ctx.artifact_hash, artifact_hash)
        stored_artifact = ctx.artifact
        self.assertEqual(bytes(stored_artifact), private_artifact)

        result = asyncio.run(cp.evaluate(deal_id, synthetic_room_evaluator))

        self.assertEqual(result.score_band, ScoreBand.MEDIUM)
        self.assertEqual(result.recommendation, "accept")
        self.assertEqual(len(fake_tinker.created_training_clients), 1)
        train_kwargs, training_client = fake_tinker.created_training_clients[0]
        self.assertEqual(train_kwargs["user_metadata"]["deal_id"], deal_id)
        self.assertEqual(train_kwargs["user_metadata"]["surface"], "local_synthetic_room")
        self.assertEqual(len(training_client.forward_backward_calls), 1)
        self.assertEqual(len(fake_tinker.samplers), 1)
        self.assertEqual(len(fake_tinker.samplers[0].sample_calls), 1)

        cp.on_deal_resolved(deal_id)

        self.assertEqual(ctx.state, DealState.RESOLVED)
        self.assertIsNone(ctx.artifact)
        self.assertEqual(stored_artifact, bytearray(len(private_artifact)))
        self.assertIsNotNone(ctx.cleanup_attestation)
        self.assertTrue(ctx.cleanup_attestation.success)
        self.assertEqual(ctx.cleanup_attestation.listed_checkpoint_count, 2)
        self.assertEqual(ctx.cleanup_attestation.deleted_checkpoint_count, 2)
        self.assertEqual(len(fake_tinker.rest_client.deleted), 2)

        packet = build_synthetic_room_public_packet(
            deal_id=deal_id,
            artifact_hash=artifact_hash,
            artifact_size=len(private_artifact),
            budget_cap=budget_cap,
            reserve_price=reserve_price,
            result=result,
            cleanup_attestation=ctx.cleanup_attestation,
            service_client=fake_tinker,
        )

        self.assertTrue(packet["success"])
        self.assertEqual(packet["surface"], "local_synthetic_room")
        self.assertEqual(packet["mode"], "modeled_fake_tinker")
        self.assertEqual(packet["artifact_hash"], artifact_hash)
        self.assertEqual(packet["result"]["score_band"], "medium")
        self.assertFalse(packet["egress"]["raw_artifact_returned"])
        self.assertFalse(packet["egress"]["raw_sample_returned"])
        self.assertFalse(packet["egress"]["raw_training_run_id_returned"])
        self.assertFalse(packet["egress"]["raw_checkpoint_path_returned"])
        self.assertFalse(packet["egress"]["raw_secret_egress"])
        self.assertFalse(packet["real_tinker_sdk_used"])
        self.assertFalse(packet["deployed_phala_evidence"])
        self.assertFalse(packet["on_chain_settlement_evidence"])

        rendered_packet = json.dumps(packet, sort_keys=True)
        forbidden_values = (
            private_artifact.decode("utf-8"),
            "sealed-fake-key",
            "sealed-project-id",
            "fake-run-1",
            "tinker://fake-run-1",
            "fake-sample-derived-from-sealed-artifact",
        )
        for forbidden in forbidden_values:
            self.assertNotIn(forbidden, rendered_packet)

        self.assertEqual(
            [record["event"] for record in metadata_store.records],
            ["deal_funded", "artifact_received", "evaluation_completed", "deal_resolved"],
        )
        rendered_metadata = json.dumps(metadata_store.records, sort_keys=True)
        for forbidden in forbidden_values:
            self.assertNotIn(forbidden, rendered_metadata)


    def test_over_budget_compute_cost_fails_closed_to_reject(self):
        # A deal whose metered developer charge (compute + fee) cannot fit under
        # the budget after the seller offer must be refused in the TEE — the
        # cost reconciler flips the recommendation to reject and records the
        # bounded settlement-unsafe verdict, instead of pushing a charge that
        # would revert on chain.
        private_artifact = b"private synthetic artifact for the over-budget path"
        artifact_hash = artifact_keccak256(private_artifact)
        deal_id = "deal-over-budget"
        budget_cap = 1_000  # far below the metered compute cost (~1e10 wei)
        reserve_price = 1
        metadata_store = InMemoryRunMetadataStore()
        fake_tinker = FakeTinkerServiceClient(api_key="sealed-fake-key")
        cp = ControlPlane(
            "sealed-fake-key",
            run_metadata_store=metadata_store,
            project_id="sealed-project-id",
            service_client_factory=lambda **_kwargs: fake_tinker,
        )
        cp.on_deal_funded(
            deal_id,
            buyer="0x00000000000000000000000000000000000000b0",
            seller="0x000000000000000000000000000000000000005e",
            budget_cap=budget_cap,
            reserve_price=reserve_price,
        )

        encrypted = encrypt_artifact_payload(
            private_artifact,
            api.get_tee_keypair().public_key_bytes.hex(),
            deal_id=deal_id,
            artifact_hash=artifact_hash,
        )
        client = TestClient(api.app)
        with patch("tinker_delegate.api._get_control_plane", return_value=cp):
            response = client.post(f"/deal/{deal_id}/artifact/encrypted", json=encrypted)
        self.assertEqual(response.status_code, 200)

        result = asyncio.run(cp.evaluate(deal_id, synthetic_room_evaluator))

        # Band still reflects the quality signal, but settlement is refused.
        self.assertEqual(result.score_band, ScoreBand.MEDIUM)
        self.assertFalse(result.settlement_safe)
        self.assertEqual(result.reconciliation_status, "over_budget")
        self.assertEqual(result.recommendation, "reject")

        completed = [r for r in metadata_store.records if r["event"] == "evaluation_completed"]
        self.assertEqual(len(completed), 1)
        self.assertFalse(completed[0]["settlement_safe"])
        self.assertEqual(completed[0]["reconciliation_status"], "over_budget")


if __name__ == "__main__":
    unittest.main()
