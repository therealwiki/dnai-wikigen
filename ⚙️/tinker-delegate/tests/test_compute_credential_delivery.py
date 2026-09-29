import copy
import hashlib
import hmac
import json
import os
import secrets
import stat
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from tinker_delegate import compute_store as module
from tinker_delegate.compute_auth import (
    encrypt_compute_credential_token,
    issue_compute_credential_token,
)
from tinker_delegate.compute_store import (
    ComputeAuthorizationError,
    ComputeCapExceeded,
    ComputeIdempotencyConflict,
    ComputeStore,
    ComputeStoreCorruptError,
    ComputeStoreError,
)
from tinker_delegate.config import Settings


class ComputeCredentialDeliveryTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "compute.json"
        self.integrity_key = b"i" * 32
        self.store = ComputeStore(self.path, integrity_key=self.integrity_key)
        self.settings = Settings(compute_credential_signing_key="credential-test-key-" + "x" * 48)
        self.owner = "0x" + "11" * 20
        self.other = "0x" + "22" * 20
        self.project = self.store.create_project(owner_address=self.owner, name="project", idempotency_key="create-project-1", created_at=90)[0]["project_id"]
        self.device = self._device("primary")
        self.key = "credential-delivery-1"

    def tearDown(self):
        self.temporary.cleanup()

    def _device(self, label):
        return self.store.register_device(self.project, actor_address=self.owner, label=label, kind="developer_device", public_key_hex=X25519PrivateKey.generate().public_key().public_bytes_raw().hex(), registered_at=91)

    def _prepare(self, *, key=None, now=100, **changes):
        args = dict(actor_address=self.owner, action="issue", idempotency_key=key or self.key, replay_context="a" * 64, expires_in_seconds=3600, now=now, device_id=self.device["device_id"], name="agent", scopes=["jobs:read"], daily_credit_cap=100)
        args.update(changes)
        return self.store.prepare_credential_delivery(self.project, **args)

    def _material(self, prepared, *, now=100):
        request = prepared["request"]
        credential_id = request["credential_id"] or "cred_" + secrets.token_hex(12)
        claims, token = issue_compute_credential_token(self.settings, credential_id=credential_id, project_id=self.project, device_id=request["device_id"], generation=(request["expected_generation"] or 0) + 1, scopes=request["scopes"], daily_credit_cap=request["daily_credit_cap"], expires_at=now + request["expires_in_seconds"], now=now)
        capsule = encrypt_compute_credential_token(token, recipient_public_key_hex=prepared["device"]["public_key_hex"], claims=claims)
        return dict(request=request, credential_id=credential_id, jwt_id_hash=hashlib.sha256(b"compute_credential_jti:" + claims.jwt_id.encode()).hexdigest(), issued_at=now, expires_at=claims.expires_at, capsule=capsule, now=now), token

    def _commit(self, prepared, *, key=None, now=100):
        material, token = self._material(prepared, now=now)
        return self.store.commit_credential_delivery(idempotency_key=key or self.key, **material), token

    def _issue(self, *, key=None, now=100, **changes):
        prepared = self._prepare(key=key, now=now, **changes)
        return prepared["replay"] or self._commit(prepared, key=key, now=now)[0]

    def _restart(self):
        self.store = ComputeStore(self.path, integrity_key=self.integrity_key)

    def _signed_root(self, payload, version):
        return {"surface": "compute_console_store", "schema_version": version, "payload": payload, "integrity": {"algorithm": "HMAC-SHA256", "value": hmac.new(self.integrity_key, module._canonical_json(payload), hashlib.sha256).hexdigest()}}

    def test_lost_issue_response_replays_identical_ciphertext_after_restart(self):
        first, token = self._commit(self._prepare())
        self.assertFalse(first["idempotent_replay"])
        self._restart()
        replay = self._issue(now=101)
        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(first["credential"], replay["credential"])
        self.assertEqual(first["capsule"], replay["capsule"])
        self.assertEqual(len(self.store.list_credentials(self.project, self.owner, now=101)), 1)
        self.assertNotIn(token, self.path.read_text())

    def test_same_key_registration_replay_succeeds_at_device_capacity(self):
        last_device = self.device
        for index in range(1, 128):
            last_device = self._device(f"device-{index}")
        existing = self.store.device_for_issuance(self.project, actor_address=self.owner, device_id=last_device["device_id"])
        before = self.path.read_bytes()
        self.assertEqual(len(self.store.list_devices(self.project, self.owner)), 128)
        replay = self.store.register_device(self.project, actor_address=self.owner, label=existing["label"], kind="developer_device", public_key_hex=existing["public_key_hex"], registered_at=100)
        self.assertEqual(replay, last_device)
        with self.assertRaises(ComputeCapExceeded):
            self._device("over-capacity")
        self.assertEqual(before, self.path.read_bytes())

    def test_lost_rotation_response_replays_before_original_generation_cas(self):
        issued = self._issue()
        credential_id = issued["credential"]["credential_id"]
        args = dict(action="rotate", credential_id=credential_id, expected_generation=1)
        prepared = self._prepare(key="rotation-request-1", now=101, **args)
        rotated = self._commit(prepared, key="rotation-request-1", now=101)[0]
        self._restart()
        replay = self._prepare(key="rotation-request-1", now=102, **args)["replay"]
        self.assertEqual(rotated["capsule"], replay["capsule"])
        self.assertEqual(replay["credential"]["generation"], 2)
        with self.assertRaises(ComputeIdempotencyConflict):
            self._prepare(key="different-rotation", now=102, **args)

    def test_stable_request_substitutions_conflict_without_writes(self):
        self._issue()
        other_device = self._device("other")
        before = self.path.read_bytes()
        for changes in ({"name": "changed"}, {"daily_credit_cap": 101}, {"expires_in_seconds": 3599}, {"scopes": ["jobs:create"]}, {"device_id": other_device["device_id"]}, {"replay_context": "b" * 64}):
            with self.subTest(changes=changes), self.assertRaises(ComputeIdempotencyConflict):
                self._prepare(**changes)
            self.assertEqual(before, self.path.read_bytes())

    def test_action_substitution_and_removed_actor_are_denied(self):
        self.store.add_member(self.project, actor_address=self.owner, member_address=self.other, role="developer", updated_at=95)
        issued = self._issue(actor_address=self.other)
        with self.assertRaises(ComputeIdempotencyConflict):
            self._prepare(actor_address=self.other, action="rotate", credential_id=issued["credential"]["credential_id"], expected_generation=1)
        self.store.remove_member(self.project, actor_address=self.owner, member_address=self.other, updated_at=102)
        with self.assertRaises(ComputeAuthorizationError):
            self._prepare(actor_address=self.other, now=103)

    def test_device_revocation_denies_replay_and_pending_commit(self):
        prepared = self._prepare()
        material, _token = self._material(prepared)
        self.store.revoke_device(self.project, actor_address=self.owner, device_id=self.device["device_id"], revoked_at=101)
        with self.assertRaises(ComputeAuthorizationError):
            self.store.commit_credential_delivery(idempotency_key=self.key, **material)
        self.assertEqual(self.store.list_credentials(self.project, self.owner, now=102), [])

    def test_revoked_device_and_downgraded_member_cannot_recover_capsule(self):
        self.store.add_member(self.project, actor_address=self.owner, member_address=self.other, role="developer", updated_at=95)
        self._issue(actor_address=self.other)
        self.store.add_member(self.project, actor_address=self.owner, member_address=self.other, role="viewer", updated_at=101)
        with self.assertRaises(ComputeAuthorizationError):
            self._prepare(actor_address=self.other, now=102)
        self.store.add_member(self.project, actor_address=self.owner, member_address=self.other, role="developer", updated_at=103)
        self.store.revoke_device(self.project, actor_address=self.owner, device_id=self.device["device_id"], revoked_at=104)
        with self.assertRaises(ComputeAuthorizationError):
            self._prepare(actor_address=self.other, now=105)

    def test_credential_revocation_and_supersession_deny_old_capsules(self):
        issued = self._issue()
        credential_id = issued["credential"]["credential_id"]
        rotated = self._prepare(key="rotation-request-1", action="rotate", credential_id=credential_id, expected_generation=1)
        self._commit(rotated, key="rotation-request-1")
        with self.assertRaises(ComputeIdempotencyConflict):
            self._prepare()
        self.store.revoke_credential(self.project, actor_address=self.owner, credential_id=credential_id, revoked_at=102)
        with self.assertRaises(ComputeAuthorizationError):
            self._prepare(key="rotation-request-1", action="rotate", credential_id=credential_id, expected_generation=1)

    def test_expiry_prunes_ciphertext_but_tombstone_prevents_remint_after_restart(self):
        self._issue()
        self.assertIsNotNone(self._prepare(now=699)["replay"])
        with self.assertRaises(ComputeIdempotencyConflict):
            self._prepare(now=700)
        self._issue(key="new-issuance-after-expiry", now=701)
        self._restart()
        with self.assertRaises(ComputeIdempotencyConflict):
            self._prepare(now=702)
        state = json.loads(self.path.read_text())["payload"]
        self.assertEqual(len(state["credential_deliveries"]), 1)
        self.assertEqual(sum(item["result_kind"] == "credential_delivery" for item in state["idempotency"].values()), 2)
        self.assertEqual(len(state["credentials"]), 2)

    def test_token_expiry_is_stricter_than_recovery_window(self):
        self._issue(expires_in_seconds=60)
        with self.assertRaises(ComputeIdempotencyConflict):
            self._prepare(now=160, expires_in_seconds=60)

    def test_collection_and_capsule_byte_caps_fail_without_credential_commit(self):
        self._issue()
        before = self.path.read_bytes()
        for name in ("MAX_CREDENTIAL_DELIVERIES", "MAX_CREDENTIAL_DELIVERIES_PER_PROJECT"):
            with self.subTest(name=name), patch.object(module, name, 1), self.assertRaises(ComputeCapExceeded):
                self._issue(key="second-credential")
            self.assertEqual(before, self.path.read_bytes())
        with patch.object(module, "MAX_CREDENTIAL_CAPSULE_BYTES", 100), self.assertRaises(ComputeStoreError):
            self._issue(key="oversized-credential")
        self.assertEqual(before, self.path.read_bytes())

    def test_permanent_tombstone_capacity_fails_closed_without_new_generation(self):
        self._issue()
        before = self.path.read_bytes()
        count = len(json.loads(before)["payload"]["idempotency"])
        with patch.object(module, "MAX_IDEMPOTENCY_RECORDS", count), self.assertRaises(ComputeCapExceeded):
            self._issue(key="tombstone-capacity-new")
        self.assertEqual(before, self.path.read_bytes())

    def test_rotation_replaces_its_superseded_recovery_slot_at_capacity(self):
        issued = self._issue()
        prepared = self._prepare(key="rotation-at-capacity", action="rotate", credential_id=issued["credential"]["credential_id"], expected_generation=1)
        with patch.object(module, "MAX_CREDENTIAL_DELIVERIES", 1), patch.object(module, "MAX_CREDENTIAL_DELIVERIES_PER_PROJECT", 1):
            rotated = self._commit(prepared, key="rotation-at-capacity")[0]
        self.assertEqual(rotated["credential"]["generation"], 2)
        self.assertEqual(len(json.loads(self.path.read_text())["payload"]["credential_deliveries"]), 1)
        with self.assertRaises(ComputeIdempotencyConflict):
            self._prepare()

    def test_capsule_substitution_is_rejected_before_commit(self):
        prepared = self._prepare()
        material, _token = self._material(prepared)
        before = self.path.read_bytes()
        for field, value in (("associated_data_hash", "b" * 64), ("recipient_public_key_hash", "b" * 64), ("plaintext_token_returned", True), ("extra", "bad")):
            altered = copy.deepcopy(material)
            altered["capsule"][field] = value
            with self.subTest(field=field), self.assertRaises(ComputeStoreError):
                self.store.commit_credential_delivery(idempotency_key=self.key, **altered)
            self.assertEqual(before, self.path.read_bytes())

    def test_concurrent_identical_issuance_commits_one_winner(self):
        materials = [self._material(self._prepare())[0] for _ in range(2)]
        barrier = threading.Barrier(2)
        results, errors = [], []
        def run(material):
            try:
                barrier.wait(timeout=5)
                results.append(self.store.commit_credential_delivery(idempotency_key=self.key, **material))
            except Exception as exc:
                errors.append(exc)
        threads = [threading.Thread(target=run, args=(material,)) for material in materials]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["capsule"], results[1]["capsule"])
        self.assertEqual(sorted(result["idempotent_replay"] for result in results), [False, True])
        self.assertEqual(len(self.store.list_credentials(self.project, self.owner, now=100)), 1)

    def test_concurrent_distinct_rotation_keys_preserve_generation_cas(self):
        issued = self._issue()
        args = dict(action="rotate", credential_id=issued["credential"]["credential_id"], expected_generation=1)
        first = self._prepare(key="rotation-request-a", **args)
        second = self._prepare(key="rotation-request-b", **args)
        barrier = threading.Barrier(2)
        results, errors = [], []
        def run(prepared, key):
            try:
                material, _token = self._material(prepared)
                barrier.wait(timeout=5)
                results.append(self.store.commit_credential_delivery(idempotency_key=key, **material))
            except Exception as exc:
                errors.append(exc)
        threads = [threading.Thread(target=run, args=(first, "rotation-request-a")), threading.Thread(target=run, args=(second, "rotation-request-b"))]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["credential"]["generation"], 2)
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], ComputeIdempotencyConflict)

    def test_authenticated_v1_migration_preserves_payload_and_private_mode(self):
        self.store.create_credential(self.project, actor_address=self.owner, credential_id="cred_existing", device_id=self.device["device_id"], name="existing-agent", scopes=("jobs:read",), daily_credit_cap=100, generation=1, jwt_id_hash="b" * 64, issued_at=95, expires_at=3695)
        self.store.grant_credits(self.project, amount_credits=100, reason="operator_testnet_grant", idempotency_key="existing-credit-grant", granted_at=96)
        self.store.create_job(self.project, actor_kind="wallet", actor_id=self.owner, credential_id=None, name="existing-job", operation="inference", model="qwen3_8b", recipe="qwen3_8b_bounded", max_credits=25, result_policy="bounded_summary_receipt", environment_version="env_v1", idempotency_key="existing-job-reservation", created_at=97)
        payload = json.loads(self.path.read_text())["payload"]
        del payload["credential_deliveries"]
        self.path.write_text(json.dumps(self._signed_root(payload, 1)))
        self._restart()
        root = json.loads(self.path.read_text())
        self.assertEqual(root["schema_version"], 2)
        self.assertEqual({key: value for key, value in root["payload"].items() if key != "credential_deliveries"}, payload)
        self.assertEqual(root["payload"]["credential_deliveries"], {})
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)

    def test_migration_rejects_tampering_unknown_and_mixed_schemas(self):
        original = json.loads(self.path.read_text())
        payload = original["payload"]
        legacy = {key: value for key, value in payload.items() if key != "credential_deliveries"}
        cases = [self._signed_root(payload, 1), self._signed_root(legacy, 2), self._signed_root(legacy, 3), self._signed_root({**legacy, "unknown": {}}, 1)]
        tampered = self._signed_root(legacy, 1)
        tampered["integrity"]["value"] = "0" * 64
        cases.append(tampered)
        for root in cases:
            self.path.write_text(json.dumps(root))
            before = self.path.read_bytes()
            with self.assertRaises(ComputeStoreCorruptError):
                self._restart()
            self.assertEqual(before, self.path.read_bytes())

    def test_signed_but_malformed_cached_capsule_is_rejected_on_load(self):
        self._issue()
        root = json.loads(self.path.read_text())
        delivery = next(iter(root["payload"]["credential_deliveries"].values()))
        delivery["capsule"]["associated_data"] = "00"
        self.path.write_text(json.dumps(self._signed_root(root["payload"], 2)))
        with self.assertRaises(ComputeStoreCorruptError):
            self._restart()

    def test_failure_after_replace_reconciles_memory_and_retry_recovers_same_capsule(self):
        prepared = self._prepare()
        material, _token = self._material(prepared)
        original_fsync = os.fsync
        def fail_directory(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError("injected directory fsync failure")
            return original_fsync(fd)
        with patch.object(module.os, "fsync", side_effect=fail_directory), self.assertRaises(OSError):
            self.store.commit_credential_delivery(idempotency_key=self.key, **material)
        replay = self._prepare(now=101)["replay"]
        self.assertEqual(replay["capsule"], material["capsule"])
        self.assertEqual(len(self.store.list_credentials(self.project, self.owner, now=101)), 1)

    def test_failure_before_replace_has_no_partial_credential_or_cache(self):
        before = self.path.read_bytes()
        with patch.object(module.os, "replace", side_effect=OSError("injected replacement failure")), self.assertRaises(OSError):
            self._commit(self._prepare())
        self.assertEqual(before, self.path.read_bytes())
        self.assertIsNone(self._prepare()["replay"])

    def test_failed_disk_reconciliation_poison_store_until_restart(self):
        with patch.object(self.store, "_persist", side_effect=OSError("write outcome unavailable")), patch.object(self.store, "_load", side_effect=ComputeStoreCorruptError("disk unavailable")), self.assertRaises(ComputeStoreCorruptError):
            self._commit(self._prepare())
        with self.assertRaises(ComputeStoreCorruptError):
            self._prepare()
        with self.assertRaises(ComputeStoreCorruptError):
            self.store.list_credentials(self.project, self.owner, now=100)
        self._restart()
        self.assertIsNone(self._prepare()["replay"])


if __name__ == "__main__":
    unittest.main()
