import asyncio
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import AsyncMock

from tinker_delegate.run_metadata_store import (
    RunMetadataStore,
    make_run_metadata_event,
    size_band,
    stable_hash,
    value_band,
)


class RunMetadataStoreTest(unittest.TestCase):
    def test_round_trips_encrypted_bounded_run_metadata(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "run_metadata.enc"
            key = "88" * 32
            record = make_run_metadata_event(
                "artifact_received",
                "deal-secret-1",
                artifact_hash="0x" + "ab" * 32,
                artifact_size_band=size_band(len(b"private-artifact")),
            )

            store = RunMetadataStore(str(path), key_hex=key)
            persisted = store.append(record)

            self.assertEqual(persisted["event"], "artifact_received")
            self.assertEqual(persisted["artifact_size_band"], "<=1KiB")
            self.assertNotIn("deal-secret-1", str(persisted))
            self.assertTrue(path.exists())
            ciphertext = path.read_bytes()
            self.assertNotIn(b"artifact_received", ciphertext)
            self.assertNotIn(b"deal-secret-1", ciphertext)
            self.assertNotIn(b"private-artifact", ciphertext)

            reloaded = RunMetadataStore(str(path), key_hex=key)
            self.assertEqual(reloaded.load(), [persisted])

    def test_rejects_forbidden_run_metadata_fields(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "run_metadata.enc"
            store = RunMetadataStore(str(path), key_hex="99" * 32)
            record = make_run_metadata_event("deal_funded", "deal-1")
            record["training_run_id"] = "raw-run-id"

            with self.assertRaisesRegex(ValueError, "forbidden fields"):
                store.append(record)

    def test_rejects_raw_secret_egress_true(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "run_metadata.enc"
            store = RunMetadataStore(str(path), key_hex="aa" * 32)
            record = make_run_metadata_event("deal_funded", "deal-1")
            record["raw_secret_egress"] = True

            with self.assertRaisesRegex(ValueError, "raw_secret_egress=false"):
                store.append(record)

    def test_helpers_bound_and_hash_values(self):
        self.assertEqual(value_band(0), "zero")
        self.assertEqual(value_band(10**7), "1e6-1e9")
        self.assertEqual(size_band(1024), "<=1KiB")
        self.assertEqual(size_band(1025), "<=1MiB")
        self.assertNotEqual(
            stable_hash("same-value", prefix="deal_id"),
            stable_hash("same-value", prefix="training_run_id"),
        )


class ControlPlaneRunMetadataTest(unittest.TestCase):
    def setUp(self):
        sys.modules.setdefault("tinker", types.SimpleNamespace())

    def test_control_plane_service_client_receives_project_and_base_url(self):
        from tinker_delegate import control_plane as control_plane_module

        created = {}

        class FakeServiceClient:
            def __init__(self, **kwargs):
                created.update(kwargs)

        original_tinker = control_plane_module.tinker
        control_plane_module.tinker = types.SimpleNamespace(ServiceClient=FakeServiceClient)
        try:
            cp = control_plane_module.ControlPlane(
                "tml-secret-value",
                project_id="proj-secret",
                base_url="https://custom.thinkingmachines.dev/services/tinker-prod",
            )
            cp._create_service_client()
        finally:
            control_plane_module.tinker = original_tinker

        self.assertEqual(created["api_key"], "tml-secret-value")
        self.assertEqual(created["project_id"], "proj-secret")
        self.assertEqual(
            created["base_url"],
            "https://custom.thinkingmachines.dev/services/tinker-prod",
        )

    def test_control_plane_records_bounded_lifecycle_metadata(self):
        from tinker_delegate.control_plane import ControlPlane, DealContext

        records = []

        class Store:
            def append(self, record):
                records.append(record)
                return record

        cp = ControlPlane.__new__(ControlPlane)
        cp._run_metadata_store = Store()
        cp._deals = {}
        cp._create_service_client = lambda: object()

        ctx = cp.on_deal_funded("deal-raw", "buyer-raw", "seller-raw", 10**18, 10**15)
        self.assertEqual(ctx.deal_id, "deal-raw")
        self.assertEqual(records[0]["event"], "deal_funded")
        self.assertIn("buyer_hash", records[0])
        self.assertNotIn("buyer-raw", str(records))
        self.assertNotIn("seller-raw", str(records))

        cp.receive_artifact(
            "deal-raw",
            b"private-artifact",
            "0xecf12e1baabfc7f190573602c3bc8beef404c2a38fc9a3d35d34f3c8f9d820eb",
        )
        self.assertEqual(records[1]["event"], "artifact_received")
        self.assertEqual(records[1]["artifact_size_band"], "<=1KiB")
        self.assertNotIn("private-artifact", str(records))

    def test_control_plane_records_evaluation_and_cleanup_without_raw_run_id(self):
        from tinker_delegate.control_plane import ControlPlane, DealContext

        records = []

        class Store:
            def append(self, record):
                records.append(record)
                return record

        class Session:
            compute_cost_wei = 10**9
            fee_wei = 10**6
            training_run_id = "run-secret-1"

            def cleanup(self):
                from tinker_delegate.session import CleanupAttestation

                return CleanupAttestation(
                    deal_id="deal-raw",
                    training_run_id="run-secret-1",
                    started_at=1.0,
                    completed_at=2.0,
                    listed_checkpoint_count=1,
                    deleted_checkpoint_count=1,
                    failed_checkpoint_count=0,
                    delete_attempts=1,
                    success=True,
                    checkpoint_ids_hash="c" * 64,
                )

        evaluator = AsyncMock(
            return_value={
                "quality_delta": 0.11,
                "benchmark": "hidden",
                "confidence": "high",
                "methodology": "bounded",
            }
        )
        cp = ControlPlane.__new__(ControlPlane)
        cp._run_metadata_store = Store()
        ctx = DealContext("deal-raw", "buyer", "seller", 10**18, 10**15, session=Session())
        ctx.artifact = bytearray(b"private-artifact")
        cp._deals = {"deal-raw": ctx}

        result = asyncio.run(cp.evaluate("deal-raw", evaluator))
        cp.on_deal_resolved("deal-raw")

        self.assertEqual(result.score_band.value, "high")
        self.assertEqual(records[0]["event"], "evaluation_completed")
        self.assertEqual(records[0]["offer_price_band"], "1e15-1e18")
        self.assertEqual(records[0]["compute_cost_band"], "1e9-1e12")
        self.assertEqual(records[1]["event"], "deal_resolved")
        self.assertEqual(records[1]["cleanup_success"], True)
        self.assertEqual(records[1]["checkpoint_ids_hash"], "c" * 64)
        self.assertNotIn("run-secret-1", str(records))
        self.assertNotIn("private-artifact", str(records))
        # Retention + attested destruction are wired into resolution.
        self.assertEqual(records[1]["retention_action"], "destroy_now")
        self.assertTrue(records[1]["destruction_complete"])
        self.assertRegex(records[1]["destruction_record_hash"], r"^0x[0-9a-f]{64}$")
        from tinker_delegate.destruction_record import (
            DestructionRecord,
            verify_destruction_record,
        )
        dr = ctx.destruction_record
        self.assertTrue(dr["complete"])
        self.assertTrue(dr["artifact_deleted"])
        self.assertTrue(dr["memory_zeroed"])
        self.assertTrue(verify_destruction_record(DestructionRecord(**{k: v for k, v in dr.items() if k != "kind"})))
        self.assertEqual(ctx.retention_decision["action"], "destroy_now")

    def test_control_plane_records_bounded_chain_event_metadata(self):
        from tinker_delegate.control_plane import ControlPlane

        records = []

        class Store:
            def append(self, record):
                records.append(record)
                return record

        cp = ControlPlane.__new__(ControlPlane)
        cp._run_metadata_store = Store()

        cp.on_chain_event(
            "DealCreated",
            "deal-raw",
            block_number=43866350,
            tx_hash="0x" + "12" * 32,
            log_index=4,
            fields={
                "seller": "0x1111111111111111111111111111111111111111",
                "tee_identity": "0x2222222222222222222222222222222222222222",
                "reserve_price": 10**15,
                "expiry": 1783502000,
                "artifact_hash": "0x" + "ab" * 32,
            },
        )

        self.assertEqual(records[0]["event"], "chain_event")
        self.assertEqual(records[0]["chain_event_name"], "DealCreated")
        self.assertEqual(records[0]["reserve_price_band"], "1e15-1e18")
        self.assertEqual(records[0]["artifact_hash"], "0x" + "ab" * 32)
        self.assertIn("seller_hash", records[0])
        self.assertIn("tee_identity_hash", records[0])
        self.assertIn("chain_tx_hash", records[0])
        self.assertNotIn("deal-raw", str(records))
        self.assertNotIn("0x1111111111111111111111111111111111111111", str(records))
        self.assertNotIn("0x2222222222222222222222222222222222222222", str(records))
        self.assertNotIn("0x" + "12" * 32, str(records))


if __name__ == "__main__":
    unittest.main()
