import json
import unittest

from tinker_delegate.destruction_record import (
    DestructionError,
    DestructionEvidence,
    build_destruction_record,
    verify_destruction_record,
)

ARTIFACT_HASH = "0x" + "cd" * 32


class DestructionRecordTest(unittest.TestCase):
    def test_complete_destruction_record(self):
        record = build_destruction_record(
            DestructionEvidence(
                deal_ref="deal://room-1",
                artifact_hash=ARTIFACT_HASH,
                artifact_deleted=True,
                memory_zeroed=True,
                keys_dropped=2,
                checkpoints_deleted=1,
                checkpoints_expired=0,
            ),
            at=1_000_000,
        )
        self.assertTrue(record.complete)
        self.assertEqual(record.reason_code, "destroyed")
        self.assertEqual(record.artifact_hash, ARTIFACT_HASH)
        self.assertTrue(verify_destruction_record(record))
        self.assertFalse(record.raw_secret_egress)

    def test_incomplete_when_artifact_not_deleted(self):
        record = build_destruction_record(
            DestructionEvidence(
                deal_ref="deal://room-1",
                artifact_deleted=False,
                memory_zeroed=True,
            ),
            at=1,
        )
        self.assertFalse(record.complete)
        self.assertIn("artifact_not_deleted", record.reason_code)

    def test_incomplete_when_memory_not_zeroed(self):
        record = build_destruction_record(
            DestructionEvidence(
                deal_ref="deal://room-1",
                artifact_deleted=True,
                memory_zeroed=False,
            ),
            at=1,
        )
        self.assertFalse(record.complete)
        self.assertIn("memory_not_zeroed", record.reason_code)

    def test_relaxed_requirements_allow_complete(self):
        # A room that does not require memory zeroing still completes on delete.
        record = build_destruction_record(
            DestructionEvidence(
                deal_ref="deal://room-1",
                artifact_deleted=True,
                memory_zeroed=False,
                require_memory_zero=False,
            ),
            at=1,
        )
        self.assertTrue(record.complete)

    def test_deal_ref_is_hashed_not_echoed(self):
        record = build_destruction_record(
            DestructionEvidence(deal_ref="deal://secret-room", artifact_deleted=True, memory_zeroed=True),
            at=1,
        )
        blob = json.dumps(record.to_public_dict())
        self.assertNotIn("secret-room", blob)
        self.assertRegex(record.deal_ref_hash, r"^0x[0-9a-f]{64}$")

    def test_tampering_detected(self):
        import dataclasses

        record = build_destruction_record(
            DestructionEvidence(deal_ref="deal://room-1", artifact_deleted=True, memory_zeroed=True),
            at=1,
        )
        tampered = dataclasses.replace(record, complete=False, reason_code="incomplete_destruction:x")
        self.assertFalse(verify_destruction_record(tampered))

    def test_deterministic_for_fixed_timestamp(self):
        ev = DestructionEvidence(deal_ref="deal://room-1", artifact_deleted=True, memory_zeroed=True)
        self.assertEqual(
            build_destruction_record(ev, at=42).record_hash,
            build_destruction_record(ev, at=42).record_hash,
        )

    def test_negative_count_rejected(self):
        with self.assertRaises(DestructionError):
            DestructionEvidence(deal_ref="deal://room-1", keys_dropped=-1)

    def test_bad_artifact_hash_rejected(self):
        with self.assertRaises(DestructionError):
            build_destruction_record(
                DestructionEvidence(deal_ref="deal://room-1", artifact_hash="0xdead", artifact_deleted=True, memory_zeroed=True)
            )

    def test_empty_artifact_hash_defaults_to_zero(self):
        record = build_destruction_record(
            DestructionEvidence(deal_ref="deal://room-1", artifact_deleted=True, memory_zeroed=True),
            at=1,
        )
        self.assertEqual(record.artifact_hash, "0x" + "00" * 32)


if __name__ == "__main__":
    unittest.main()
