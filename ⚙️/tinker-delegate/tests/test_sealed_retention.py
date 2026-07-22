import json
import sys
import types
import unittest

from tinker_delegate.artifacts import artifact_commitment
from tinker_delegate.sealed_retention import (
    SealedRetentionError,
    SealedRetentionStore,
)

ARTIFACT = b"sealed-private-artifact-bytes"
ARTIFACT_HASH = "0x" + "cd" * 32


class SealedRetentionStoreTest(unittest.TestCase):
    def test_seal_and_open_roundtrip(self):
        store = SealedRetentionStore()
        receipt = store.seal("deal-1", ARTIFACT, retain_until=2000, artifact_hash=ARTIFACT_HASH)
        self.assertTrue(receipt.sealed)
        self.assertTrue(store.is_retained("deal-1"))
        self.assertEqual(store.retain_until("deal-1"), 2000)
        self.assertEqual(store.open("deal-1"), ARTIFACT)
        self.assertFalse(receipt.raw_secret_egress)

    def test_receipt_is_bounded_no_plaintext(self):
        store = SealedRetentionStore()
        receipt = store.seal("deal-secret-ref", ARTIFACT, retain_until=2000)
        blob = json.dumps(receipt.to_public_dict())
        self.assertNotIn("deal-secret-ref", blob)
        self.assertNotIn("sealed-private-artifact", blob)
        self.assertEqual(receipt.ciphertext_size_band, "sub_kib")

    def test_wrong_deal_id_cannot_decrypt(self):
        # Deal id is the AAD; opening under a different id fails authentication.
        store = SealedRetentionStore()
        store.seal("deal-1", ARTIFACT, retain_until=0)
        with self.assertRaises(Exception):
            store._aes.decrypt(store._entries["deal-1"].nonce, store._entries["deal-1"].ciphertext, b"deal-2")

    def test_sweep_destroys_expired_only(self):
        store = SealedRetentionStore()
        store.seal("deal-a", ARTIFACT, retain_until=1000)
        store.seal("deal-b", ARTIFACT, retain_until=3000)
        store.seal("deal-c", ARTIFACT, retain_until=0)  # no expiry
        destroyed = store.sweep(now=1500)
        self.assertEqual(set(destroyed), {"deal-a"})
        self.assertFalse(store.is_retained("deal-a"))
        self.assertTrue(store.is_retained("deal-b"))
        self.assertTrue(store.is_retained("deal-c"))  # no-expiry never swept
        self.assertEqual(store.count, 2)

    def test_destroy_removes_entry(self):
        store = SealedRetentionStore()
        store.seal("deal-1", ARTIFACT, retain_until=0)
        self.assertTrue(store.destroy("deal-1"))
        self.assertFalse(store.is_retained("deal-1"))
        self.assertFalse(store.destroy("deal-1"))  # already gone
        with self.assertRaises(SealedRetentionError):
            store.open("deal-1")

    def test_manifest_is_bounded(self):
        store = SealedRetentionStore()
        store.seal("deal-secret", ARTIFACT, retain_until=1000, artifact_hash=ARTIFACT_HASH)
        manifest = store.public_manifest(now=1500)
        self.assertEqual(manifest["retained_count"], 1)
        self.assertFalse(manifest["raw_secret_egress"])
        self.assertTrue(manifest["entries"][0]["expired"])
        self.assertNotIn("deal-secret", json.dumps(manifest))

    def test_bad_key_length_rejected(self):
        with self.assertRaises(SealedRetentionError):
            SealedRetentionStore(key=b"short")

    def test_negative_retain_until_rejected(self):
        store = SealedRetentionStore()
        with self.assertRaises(SealedRetentionError):
            store.seal("deal-1", ARTIFACT, retain_until=-1)

    def test_bad_artifact_hash_rejected(self):
        store = SealedRetentionStore()
        with self.assertRaises(SealedRetentionError):
            store.seal("deal-1", ARTIFACT, retain_until=0, artifact_hash="0xdead")


class SealedRetentionPersistenceTest(unittest.TestCase):
    def test_survives_restart_with_same_key_file(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sealed_retention.enc"
            store = SealedRetentionStore(path=path)
            store.seal("deal-1", ARTIFACT, retain_until=5000, artifact_hash=ARTIFACT_HASH)
            self.assertTrue(path.exists())

            # New store instance, same path (+ its .key sidecar): entry reloads.
            reloaded = SealedRetentionStore(path=path)
            self.assertTrue(reloaded.is_retained("deal-1"))
            self.assertEqual(reloaded.open("deal-1"), ARTIFACT)
            self.assertEqual(reloaded.retain_until("deal-1"), 5000)

    def test_destroy_and_sweep_persist(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sealed_retention.enc"
            store = SealedRetentionStore(path=path)
            store.seal("deal-a", ARTIFACT, retain_until=1000)
            store.seal("deal-b", ARTIFACT, retain_until=3000)
            store.sweep(now=1500)  # destroys deal-a
            reloaded = SealedRetentionStore(path=path)
            self.assertFalse(reloaded.is_retained("deal-a"))
            self.assertTrue(reloaded.is_retained("deal-b"))

    def test_persisted_file_is_encrypted(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sealed_retention.enc"
            store = SealedRetentionStore(path=path)
            store.seal("deal-secret", ARTIFACT, retain_until=1000)
            raw = path.read_bytes()
            self.assertNotIn(b"deal-secret", raw)
            self.assertNotIn(b"sealed-private-artifact", raw)


class SealedRetentionKeyHierarchyTest(unittest.TestCase):
    def test_root_key_never_encrypts_artifacts_directly(self):
        # The root AES key must not decrypt an artifact sealed under a derived key.
        store = SealedRetentionStore()
        store.seal("deal-1", ARTIFACT, retain_until=0, corpus_ref="room-a")
        entry = store._entries["deal-1"]
        with self.assertRaises(Exception):
            store._aes.decrypt(entry.nonce, entry.ciphertext, b"deal-1")
        # But the derived-key path opens it.
        self.assertEqual(store.open("deal-1"), ARTIFACT)

    def test_distinct_corpus_yields_distinct_key_and_ciphertext(self):
        store = SealedRetentionStore()
        k_a = store._derive_key("room-a", "deal-1")
        k_b = store._derive_key("room-b", "deal-1")
        k_deal2 = store._derive_key("room-a", "deal-2")
        self.assertNotEqual(k_a, k_b)      # per-corpus separation
        self.assertNotEqual(k_a, k_deal2)  # per-deal separation
        # Derivation is deterministic.
        self.assertEqual(k_a, store._derive_key("room-a", "deal-1"))
        self.assertEqual(len(k_a), 32)

    def test_cross_corpus_ciphertext_cannot_decrypt(self):
        # An artifact sealed under room-a must not open if its entry is relabeled
        # room-b (the derived key changes, so authentication fails).
        import dataclasses

        store = SealedRetentionStore()
        store.seal("deal-1", ARTIFACT, retain_until=0, corpus_ref="room-a")
        store._entries["deal-1"] = dataclasses.replace(
            store._entries["deal-1"], corpus_ref="room-b"
        )
        with self.assertRaises(Exception):
            store.open("deal-1")

    def test_derivation_is_collision_resistant_across_separator(self):
        # A ref containing the old ":" separator must not collide two distinct
        # (corpus_ref, deal_id) pairs onto the same key.
        store = SealedRetentionStore()
        self.assertNotEqual(store._derive_key("a", "b:c"), store._derive_key("a:b", "c"))
        self.assertNotEqual(store._derive_key("room", "deal"), store._derive_key("roomdeal", ""))
        # Determinism preserved.
        self.assertEqual(store._derive_key("room", "deal"), store._derive_key("room", "deal"))

    def test_corpus_ref_survives_persistence_roundtrip(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sealed_retention.enc"
            store = SealedRetentionStore(path=path)
            store.seal("deal-1", ARTIFACT, retain_until=0, corpus_ref="room-a")
            reloaded = SealedRetentionStore(path=path)
            self.assertEqual(reloaded._entries["deal-1"].corpus_ref, "room-a")
            self.assertEqual(reloaded.open("deal-1"), ARTIFACT)


class RetentionFactoryTest(unittest.TestCase):
    def test_build_retention_store_disabled_when_no_path(self):
        from tinker_delegate.config import Settings
        from tinker_delegate.sealed_retention import build_retention_store

        self.assertIsNone(build_retention_store(Settings()))

    def test_build_retention_store_persists_when_path_set(self):
        import tempfile
        from pathlib import Path

        from tinker_delegate.config import Settings
        from tinker_delegate.sealed_retention import build_retention_store

        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "sealed_retention.enc")
            store = build_retention_store(Settings(retention_store_path=path))
            self.assertIsNotNone(store)
            store.seal("deal-1", ARTIFACT, retain_until=1000)
            self.assertTrue(Path(path).exists())

    def test_build_retention_policy_from_settings(self):
        from tinker_delegate.config import Settings
        from tinker_delegate.retention_policy import RetentionMode, build_retention_policy

        p = build_retention_policy(Settings(retention_mode="time_boxed", retention_seconds=3600))
        self.assertEqual(p.mode, RetentionMode.TIME_BOXED)
        self.assertEqual(p.retention_seconds, 3600)
        # Unknown mode -> fail closed to immediate.
        self.assertEqual(build_retention_policy(Settings(retention_mode="bogus")).mode, RetentionMode.IMMEDIATE)


class ControlPlaneRetentionWiringTest(unittest.TestCase):
    def _make_cp(self, policy):
        sys.modules.setdefault("tinker", types.SimpleNamespace())
        from tinker_delegate.control_plane import ControlPlane, DealContext

        records = []

        class Store:
            def append(self, record):
                records.append(record)
                return record

        cp = ControlPlane.__new__(ControlPlane)
        cp._run_metadata_store = Store()
        cp._deals = {}
        cp._retention_policy = policy
        cp._retention_store = SealedRetentionStore()
        return cp, records, DealContext

    def test_retain_decision_seals_instead_of_destroying(self):
        from tinker_delegate.retention_policy import RetentionMode, RetentionPolicy

        cp, records, DealContext = self._make_cp(
            RetentionPolicy(RetentionMode.TIME_BOXED, retention_seconds=1000)
        )
        commitment_secret = bytes(range(32))
        commitment = artifact_commitment(b"private-artifact", commitment_secret)
        ctx = DealContext("deal-r", "buyer", "seller", 10**18, 10**15, commitment)
        ctx.artifact = bytearray(b"private-artifact")
        ctx.artifact_commitment_secret = bytearray(commitment_secret)
        ctx.artifact_hash = commitment
        cp._deals["deal-r"] = ctx

        cp.on_deal_resolved("deal-r")

        # Sealed, not destroyed: artifact removed from memory but held in the store.
        self.assertIsNone(ctx.artifact)
        self.assertTrue(cp._retention_store.is_retained("deal-r"))
        self.assertEqual(records[-1]["retention_action"], "retain_sealed")
        self.assertTrue(records[-1]["artifact_sealed_retained"])
        self.assertNotIn("destruction_record_hash", records[-1])
        self.assertNotIn("private-artifact", str(records))

    def test_retention_store_failure_still_zeroes_artifact_and_v2_secret(self):
        from tinker_delegate.retention_policy import RetentionMode, RetentionPolicy

        cp, _records, DealContext = self._make_cp(
            RetentionPolicy(RetentionMode.TIME_BOXED, retention_seconds=1000)
        )

        class RejectingStore:
            def seal(self, *_args, **_kwargs):
                raise OSError("synthetic retention failure")

        cp._retention_store = RejectingStore()
        commitment_secret = bytes(range(32))
        commitment = artifact_commitment(b"private-artifact", commitment_secret)
        ctx = DealContext("deal-r", "buyer", "seller", 10**18, 10**15, commitment)
        ctx.artifact = bytearray(b"private-artifact")
        ctx.artifact_commitment_secret = bytearray(commitment_secret)
        ctx.artifact_hash = commitment
        cp._deals["deal-r"] = ctx
        stored_artifact = ctx.artifact
        stored_secret = ctx.artifact_commitment_secret

        with self.assertRaisesRegex(OSError, "synthetic retention failure"):
            cp.on_deal_resolved("deal-r")

        self.assertIsNone(ctx.artifact)
        self.assertIsNone(ctx.artifact_commitment_secret)
        self.assertEqual(stored_artifact, bytearray(len(b"private-artifact")))
        self.assertEqual(stored_secret, bytearray(len(commitment_secret)))

    def test_sweep_destroys_expired_and_emits_record(self):
        from tinker_delegate.retention_policy import RetentionMode, RetentionPolicy

        cp, records, DealContext = self._make_cp(
            RetentionPolicy(RetentionMode.TIME_BOXED, retention_seconds=0)  # will destroy immediately anyway
        )
        # Seal directly to control the expiry deterministically.
        cp._retention_store.seal("deal-x", b"x", retain_until=1000)
        swept = cp.sweep_retention(now=2000)
        self.assertEqual(len(swept), 1)
        self.assertTrue(swept[0]["complete"])
        self.assertFalse(cp._retention_store.is_retained("deal-x"))
        self.assertEqual(records[-1]["event"], "retention_swept")


if __name__ == "__main__":
    unittest.main()
