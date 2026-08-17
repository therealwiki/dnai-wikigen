import json
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from tinker_delegate.arena_safe_ir import SAFE_IR_POLICY_COMMITMENT, SAFE_IR_RUNTIME
from tinker_delegate.arena_store import (
    BIO_CHALLENGE_ID,
    BIO_CHALLENGE_VERSION,
    BIO_SAFE_IR_CHALLENGE_ID,
    BIO_SAFE_IR_CHALLENGE_VERSION,
    default_challenge_catalog,
)
from tinker_delegate.arena_worker_evidence import (
    EVIDENCE_CLASSIFICATION,
    ArenaWorkerEvidenceError,
    ArenaWorkerHeartbeat,
    ArenaWorkerHeartbeatStore,
    ArenaWorkerReleaseBindings,
    arena_worker_expected_release_bindings,
    arena_worker_heartbeat_binding_sha256,
    arena_worker_heartbeat_integrity_key,
    arena_worker_release_binding_sha256,
    project_arena_worker_capability,
)
from tinker_delegate.config import Settings


NOW = 1_900_000_000


def _bindings() -> ArenaWorkerReleaseBindings:
    challenge = default_challenge_catalog().get(
        BIO_SAFE_IR_CHALLENGE_ID,
        BIO_SAFE_IR_CHALLENGE_VERSION,
    )
    return ArenaWorkerReleaseBindings(
        release_sha="1" * 40,
        image_digest="sha256:" + "2" * 64,
        release_manifest_sha256="sha256:" + "3" * 64,
        approved_challenge_set_sha256="sha256:" + "a" * 64,
        approved_challenge_key=(
            f"{BIO_SAFE_IR_CHALLENGE_ID}@{BIO_SAFE_IR_CHALLENGE_VERSION}"
        ),
        release_policy_commitment="0x" + "4" * 64,
        catalog_manifest_hash=challenge.manifest_hash,
        runtime=SAFE_IR_RUNTIME,
        runtime_policy_commitment=SAFE_IR_POLICY_COMMITMENT,
        compose_hash="5" * 64,
        app_id="app_arena_safe_ir",
        os_image_hash="6" * 64,
    )


class ArenaWorkerEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "worker-heartbeat.json"
        self.store = ArenaWorkerHeartbeatStore(
            self.path,
            integrity_key=b"h" * 32,
        )
        self.bindings = _bindings()

    def _project(self, *, now=NOW, enabled=True, bindings=None, store=None):
        return project_arena_worker_capability(
            challenge_id=BIO_SAFE_IR_CHALLENGE_ID,
            challenge_version=BIO_SAFE_IR_CHALLENGE_VERSION,
            enabled=enabled,
            expected_bindings=self.bindings if bindings is None else bindings,
            heartbeat_store=self.store if store is None else store,
            now=now,
            ttl_seconds=30,
        )

    def test_fresh_authenticated_exact_heartbeat_is_the_only_live_projection(self):
        self.store.write(
            ArenaWorkerHeartbeat(
                bindings=self.bindings,
                observed_at=NOW - 2,
                state="ready",
            )
        )
        projection = self._project()

        self.assertEqual(projection["schema_version"], 2)
        self.assertEqual(projection["status"], "live")
        self.assertTrue(projection["live_execution"])
        self.assertTrue(projection["safe_ir_execution_ready"])
        self.assertFalse(projection["hostile_general_code_ready"])
        self.assertFalse(projection["python_preview_live"])
        self.assertEqual(
            projection["evidence_classification"],
            EVIDENCE_CLASSIFICATION,
        )
        self.assertEqual(projection["evidence_authenticity"], "hmac_verified")
        self.assertEqual(projection["heartbeat_observed_at"], NOW - 2)
        self.assertEqual(projection["release_binding"], self.bindings.to_dict())
        self.assertEqual(
            projection["release_binding_sha256"],
            arena_worker_release_binding_sha256(self.bindings),
        )
        self.assertEqual(
            projection["heartbeat_binding_sha256"],
            arena_worker_heartbeat_binding_sha256(
                challenge_id=BIO_SAFE_IR_CHALLENGE_ID,
                challenge_version=BIO_SAFE_IR_CHALLENGE_VERSION,
                heartbeat_observed_at=NOW - 2,
                release_binding_sha256=projection["release_binding_sha256"],
            ),
        )
        self.assertFalse(projection["tdx_attestation_egress"])
        self.assertFalse(projection["exact_timing_egress"])
        self.assertNotIn("tdx_verified", json.dumps(projection).lower())

    def test_disabled_stale_future_mismatch_and_unavailable_fail_closed(self):
        self.store.write(
            ArenaWorkerHeartbeat(
                bindings=self.bindings,
                observed_at=NOW - 2,
                state="ready",
            )
        )
        disabled = self._project(enabled=False)
        self.assertEqual(disabled["gate_reason"], "live_release_not_enabled")
        self.assertFalse(disabled["live_execution"])

        self.store.write(
            ArenaWorkerHeartbeat(
                bindings=self.bindings,
                observed_at=NOW - 31,
                state="ready",
            )
        )
        self.assertEqual(self._project()["gate_reason"], "evidence_stale")
        self.assertIsNone(self._project()["heartbeat_observed_at"])
        self.assertIsNone(self._project()["heartbeat_binding_sha256"])

        self.store.write(
            ArenaWorkerHeartbeat(
                bindings=self.bindings,
                observed_at=NOW + 6,
                state="ready",
            )
        )
        self.assertEqual(self._project()["gate_reason"], "evidence_invalid")
        self.assertIsNone(self._project()["heartbeat_observed_at"])

        self.store.write(
            ArenaWorkerHeartbeat(
                bindings=replace(self.bindings, release_sha="a" * 40),
                observed_at=NOW,
                state="ready",
            )
        )
        self.assertEqual(self._project()["gate_reason"], "evidence_mismatch")
        self.assertIsNone(self._project()["heartbeat_binding_sha256"])

        self.store.write(
            ArenaWorkerHeartbeat(
                bindings=self.bindings,
                observed_at=NOW,
                state="unavailable",
            )
        )
        self.assertEqual(self._project()["gate_reason"], "worker_unavailable")
        self.assertFalse(self._project()["worker_connected"])
        self.assertIsNone(self._project()["heartbeat_observed_at"])

    def test_public_digests_bind_release_and_freshness_canonically(self):
        self.store.write(
            ArenaWorkerHeartbeat(
                bindings=self.bindings,
                observed_at=NOW - 2,
                state="ready",
            )
        )
        first = self._project()
        self.assertEqual(
            first["release_binding_sha256"],
            "sha256:"
            "dda813e4a5aa72ad6b8058447919e78d9bc8b07291679d147f536ba6c59ddc99",
        )
        self.assertEqual(
            first["heartbeat_binding_sha256"],
            "sha256:"
            "63a4a9a1ba70fb1027860faa4e25498c2ea9397ecbe9f17c3d38d82f68f4e4d0",
        )

        reordered = ArenaWorkerReleaseBindings.from_mapping(
            dict(reversed(list(self.bindings.to_dict().items())))
        )
        self.assertEqual(
            arena_worker_release_binding_sha256(reordered),
            first["release_binding_sha256"],
        )

        self.store.write(
            ArenaWorkerHeartbeat(
                bindings=self.bindings,
                observed_at=NOW - 1,
                state="ready",
            )
        )
        later = self._project()
        self.assertEqual(
            later["release_binding_sha256"],
            first["release_binding_sha256"],
        )
        self.assertNotEqual(
            later["heartbeat_binding_sha256"],
            first["heartbeat_binding_sha256"],
        )

        changed_bindings = replace(
            self.bindings,
            app_id="app_arena_safe_ir_next",
        )
        changed_path = Path(self.temp.name) / "changed-worker-heartbeat.json"
        changed_store = ArenaWorkerHeartbeatStore(
            changed_path,
            integrity_key=b"h" * 32,
        )
        changed_store.write(
            ArenaWorkerHeartbeat(
                bindings=changed_bindings,
                observed_at=NOW - 1,
                state="ready",
            )
        )
        changed = project_arena_worker_capability(
            challenge_id=BIO_SAFE_IR_CHALLENGE_ID,
            challenge_version=BIO_SAFE_IR_CHALLENGE_VERSION,
            enabled=True,
            expected_bindings=changed_bindings,
            heartbeat_store=changed_store,
            now=NOW,
            ttl_seconds=30,
        )
        self.assertNotEqual(
            changed["release_binding_sha256"],
            first["release_binding_sha256"],
        )
        self.assertNotEqual(
            changed["heartbeat_binding_sha256"],
            later["heartbeat_binding_sha256"],
        )

    def test_public_projection_never_exposes_heartbeat_mac_key_or_raw_body(self):
        self.store.write(
            ArenaWorkerHeartbeat(
                bindings=self.bindings,
                observed_at=NOW,
                state="ready",
            )
        )
        envelope = json.loads(self.path.read_text("ascii"))
        projection = self._project()
        encoded = json.dumps(projection, sort_keys=True)

        self.assertNotIn("mac", projection)
        self.assertNotIn("heartbeat", projection)
        self.assertNotIn("integrity_key", projection)
        self.assertNotIn(envelope["mac"], encoded)
        self.assertNotIn((b"h" * 32).decode("ascii"), encoded)
        self.assertEqual(
            projection["evidence_classification"],
            "authenticated_worker_presence_not_tdx_attestation",
        )

    def test_tampering_wrong_key_and_unsafe_file_fail_closed(self):
        self.store.write(
            ArenaWorkerHeartbeat(
                bindings=self.bindings,
                observed_at=NOW,
                state="ready",
            )
        )
        payload = json.loads(self.path.read_text("ascii"))
        payload["heartbeat"]["state"] = "unavailable"
        self.path.write_text(json.dumps(payload), encoding="ascii")
        self.path.chmod(0o600)
        self.assertEqual(self._project()["gate_reason"], "evidence_invalid")

        self.store.write(
            ArenaWorkerHeartbeat(
                bindings=self.bindings,
                observed_at=NOW,
                state="ready",
            )
        )
        wrong = ArenaWorkerHeartbeatStore(self.path, integrity_key=b"x" * 32)
        self.assertEqual(self._project(store=wrong)["gate_reason"], "evidence_invalid")

        self.path.chmod(0o644)
        self.assertEqual(self._project()["gate_reason"], "evidence_invalid")

    def test_general_python_projection_can_never_be_live(self):
        self.store.write(
            ArenaWorkerHeartbeat(
                bindings=self.bindings,
                observed_at=NOW,
                state="ready",
            )
        )
        projection = project_arena_worker_capability(
            challenge_id=BIO_CHALLENGE_ID,
            challenge_version=BIO_CHALLENGE_VERSION,
            enabled=True,
            expected_bindings=self.bindings,
            heartbeat_store=self.store,
            now=NOW,
            ttl_seconds=30,
        )
        self.assertEqual(projection["gate_reason"], "python_preview_only")
        self.assertEqual(projection["status"], "modeled")
        self.assertFalse(projection["live_execution"])
        self.assertFalse(projection["python_preview_live"])

    def test_integrity_key_uses_a_distinct_dstack_domain(self):
        settings = Settings(
            arena_worker_heartbeat_key_path="tinker/arena-heartbeat-test",
            arena_worker_heartbeat_integrity_key="local-" + "k" * 40,
        )
        with patch(
            "tinker_delegate.arena_worker_evidence.dstack_utils.is_dstack_enabled",
            return_value=False,
        ):
            local = arena_worker_heartbeat_integrity_key(settings)
        self.assertEqual(len(local), 32)

        with (
            patch(
                "tinker_delegate.arena_worker_evidence.dstack_utils.is_dstack_enabled",
                return_value=True,
            ),
            patch(
                "tinker_delegate.arena_worker_evidence.dstack_utils.is_dstack_simulator",
                return_value=False,
            ),
            patch(
                "tinker_delegate.arena_worker_evidence.dstack_utils.derive_storage_key",
                return_value=b"d" * 32,
            ) as derive,
        ):
            dstack = arena_worker_heartbeat_integrity_key(settings)
        self.assertEqual(len(dstack), 32)
        self.assertNotEqual(local, dstack)
        derive.assert_called_once_with("tinker/arena-heartbeat-test")

    def test_api_descriptor_bindings_are_exact_and_fail_on_missing_pin(self):
        expected = self.bindings
        settings = Settings(
            arena_worker_release_sha=expected.release_sha,
            arena_worker_image_digest=expected.image_digest,
            arena_worker_release_manifest_sha256=expected.release_manifest_sha256,
            arena_worker_approved_challenge_set_sha256=(
                expected.approved_challenge_set_sha256
            ),
            arena_worker_release_policy_commitment=expected.release_policy_commitment,
            arena_worker_compose_hash=expected.compose_hash,
            arena_worker_app_id=expected.app_id,
            arena_worker_os_image_hash=expected.os_image_hash,
        )
        self.assertEqual(arena_worker_expected_release_bindings(settings), expected)
        with self.assertRaisesRegex(ArenaWorkerEvidenceError, "release SHA"):
            arena_worker_expected_release_bindings(
                settings.model_copy(update={"arena_worker_release_sha": ""})
            )

    def test_store_rejects_symlink_and_malformed_bindings(self):
        with self.assertRaises(ArenaWorkerEvidenceError):
            replace(self.bindings, runtime="python3.11")
        with self.assertRaisesRegex(ArenaWorkerEvidenceError, "challenge-set"):
            replace(
                self.bindings,
                approved_challenge_set_sha256="sha256:" + "0" * 64,
            )
        with self.assertRaisesRegex(ArenaWorkerEvidenceError, "not release-approved"):
            replace(self.bindings, approved_challenge_key="new-row@1.0.0")
        target = Path(self.temp.name) / "target.json"
        target.write_text("{}", encoding="ascii")
        self.path.symlink_to(target)
        with self.assertRaisesRegex(ArenaWorkerEvidenceError, "symlink"):
            self.store.write(
                ArenaWorkerHeartbeat(
                    bindings=self.bindings,
                    observed_at=NOW,
                    state="ready",
                )
            )


if __name__ == "__main__":
    unittest.main()
