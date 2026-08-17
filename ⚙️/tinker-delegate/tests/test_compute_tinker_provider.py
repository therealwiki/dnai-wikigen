import os
import stat
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from tinker_delegate.compute_tinker_provider import (
    ComputeProviderStatusStore,
    TinkerComputeProviderAdapter,
    TinkerProviderReleaseError,
    _canonical_data_file_path,
    compute_provider_public_capability,
    compute_provider_static_capability,
)
from tinker_delegate.compute_runtime import (
    ComputeDispatchIntent,
    ProviderUsage,
)
from tinker_delegate.compute_workload_ingress import (
    ComputeWorkloadDispatchClaim,
)
from tinker_delegate.compute_provider_release import (
    PINNED_QWEN3_TOKENIZER_FILES,
    PINNED_QWEN3_TOKENIZER_PATH,
    PINNED_QWEN3_TOKENIZER_RELEASE_SHA256,
    PINNED_TINKER_PROVIDER_RELEASE_SHA256,
    pinned_qwen3_tokenizer_manifest,
    pinned_tinker_provider_release_manifest,
)
from tinker_delegate.config import Settings


def _credential_intent() -> ComputeDispatchIntent:
    return ComputeDispatchIntent.create(
        project_reference="prj_alpha",
        job_reference="job_alpha",
        user="0x" + "11" * 20,
        asset="0x" + "00" * 20,
        authorization_nonce=4,
        max_asset_debit=25,
        authorization_expiry=1_800_000_600,
        rate_policy_commitment="0x" + "66" * 32,
        compose_hash="0x" + "77" * 32,
        operation="inference",
        model="qwen3_8b",
        recipe="qwen3_8b_bounded",
        result_policy="bounded_summary_receipt",
        max_prefill_tokens=100,
        max_sample_tokens=20,
        max_train_tokens=0,
        workload_id="wrk_" + "ab" * 16,
        workload_schema="dnai.compute.workload.inference.v1",
        manifest_commitment="0x" + "91" * 32,
        workload_commitment="0x" + "92" * 32,
        workload_source_kind="credential",
        workload_execution_binding_commitment="sha256:" + "94" * 32,
        workload_recipient_release_commitment="sha256:" + "95" * 32,
    )


class _RecordingIngress:
    def __init__(self, manifest):
        self.manifest = manifest
        self.lease_calls = []
        self.release_calls = []

    @contextmanager
    def lease_for_provider_execution(self, workload_id, **kwargs):
        self.lease_calls.append((workload_id, kwargs))
        yield SimpleNamespace(
            manifest=self.manifest,
            plaintext=bytearray(b"private payload"),
            reauthenticate=lambda: SimpleNamespace(valid=True),
        )

    def release_after_usage_checkpoint(self, workload_id, **kwargs):
        self.release_calls.append((workload_id, kwargs))


class ComputeTinkerProviderCapabilityTest(unittest.TestCase):
    def test_adapter_uses_v3_source_binding_and_wallet_funded_claim(self):
        intent = _credential_intent()
        policy = intent.validate_compiled_recipe()
        manifest = SimpleNamespace(
            schema=intent.workload_schema,
            operation=intent.operation,
            model=intent.model,
            recipe=intent.recipe,
            max_prefill_tokens=intent.max_prefill_tokens,
            max_sample_tokens=intent.max_sample_tokens,
            max_train_tokens=intent.max_train_tokens,
            commitment="sha256:" + intent.manifest_commitment.removeprefix("0x"),
        )
        ingress = _RecordingIngress(manifest)
        adapter = object.__new__(TinkerComputeProviderAdapter)
        adapter.settings = Settings()
        adapter.ingress = ingress
        adapter.result_key = b"r" * 32
        adapter.runner = object()
        dispatch_id = "0x" + "97" * 32

        with (
            patch(
                "tinker_delegate.compute_tinker_provider._load_sealed_provider_configuration",
                return_value=("tml-test-key", "provider-project"),
            ),
            patch(
                "tinker_delegate.compute_tinker_provider._load_pinned_tokenizer",
                return_value=object(),
            ),
        ):
            with adapter.prepare_attempt(
                intent,
                policy,
                dispatch_id=dispatch_id,
            ) as attempt:
                self.assertEqual(attempt.intent, intent)
                self.assertEqual(attempt.dispatch_id, dispatch_id)
                self.assertEqual(bytes(attempt.plaintext), b"private payload")

        self.assertEqual(len(ingress.lease_calls), 1)
        workload_id, lease = ingress.lease_calls[0]
        self.assertEqual(workload_id, intent.workload_id)
        self.assertEqual(lease["project_id"], intent.project_reference)
        self.assertEqual(lease["source_kind"], "credential")
        self.assertEqual(
            lease["recipient_release_commitment"],
            intent.workload_recipient_release_commitment,
        )
        self.assertEqual(
            lease["claim"],
            ComputeWorkloadDispatchClaim(
                job_id=intent.job_id,
                intent_commitment=intent.commitment,
                funding_wallet=intent.user,
                execution_binding_commitment=(
                    intent.workload_execution_binding_commitment
                ),
            ),
        )
        self.assertNotEqual(
            lease["claim"].funding_wallet,
            "credential",
        )

        usage = ProviderUsage(
            outcome="succeeded",
            prefill_tokens=10,
            sample_tokens=5,
            training_tokens=0,
            result_commitment="0x" + "98" * 32,
            provider_authoritative_invoice=False,
        )
        adapter.release_after_usage_checkpoint(
            intent,
            policy,
            dispatch_id=dispatch_id,
            usage=usage,
            release_checkpoint_commitment="sha256:" + "99" * 32,
        )
        self.assertEqual(len(ingress.release_calls), 1)
        released_workload, release = ingress.release_calls[0]
        self.assertEqual(released_workload, intent.workload_id)
        self.assertEqual(release["project_id"], intent.project_reference)
        self.assertEqual(release["claim"], lease["claim"])
        self.assertEqual(
            release["release_checkpoint_commitment"],
            "sha256:" + "99" * 32,
        )

    def test_tokenizer_release_is_one_exact_offline_three_file_bundle(self):
        self.assertEqual(PINNED_QWEN3_TOKENIZER_PATH, "/opt/dnai/qwen3-8b-tokenizer")
        self.assertEqual(
            PINNED_QWEN3_TOKENIZER_RELEASE_SHA256,
            "sha256:d933156af48aa90a117025537b4291c2e72b62ad14ddcfa7d77f3258928cd2e0",
        )
        self.assertEqual(
            [entry.path for entry in PINNED_QWEN3_TOKENIZER_FILES],
            ["config.json", "tokenizer.json", "tokenizer_config.json"],
        )
        self.assertEqual(
            [entry["path"] for entry in pinned_qwen3_tokenizer_manifest()["files"]],
            ["config.json", "tokenizer.json", "tokenizer_config.json"],
        )

    def test_provider_release_digest_freezes_adapter_and_crash_semantics(self):
        self.assertEqual(
            PINNED_TINKER_PROVIDER_RELEASE_SHA256,
            "sha256:4264a2226ac9c850d8f053c98ac90d0f6dcbc58702919899384a9b2442b35631",
        )
        manifest = pinned_tinker_provider_release_manifest()
        self.assertEqual(
            set(manifest),
            {
                "schema",
                "adapter_id",
                "sdk_version",
                "sdk_source_sha256",
                "request_contract_sha256",
                "base_url_sha256",
                "tokenizer_path",
                "tokenizer_release_sha256",
                "idempotency_header_role",
                "idempotent_provider_replay_claimed",
                "automatic_provider_redispatch",
                "at_most_once_attempt_checkpoint",
                "terminal_ambiguity_hold",
                "ambiguous_outcome_ciphertext_retained",
                "provider_authoritative_invoice",
                "raw_secret_egress",
            },
        )
        self.assertFalse(manifest["idempotent_provider_replay_claimed"])
        self.assertFalse(manifest["automatic_provider_redispatch"])
        self.assertFalse(manifest["provider_authoritative_invoice"])
        self.assertFalse(manifest["raw_secret_egress"])

    def test_disabled_release_describes_adapter_without_claiming_runtime_guarantees(self):
        capability = compute_provider_static_capability(Settings())

        self.assertTrue(capability["source_present"])
        self.assertFalse(capability["release_configured"])
        self.assertFalse(capability["provider_dispatch"])
        self.assertEqual(capability["reason"], "provider_execution_not_enabled")
        self.assertTrue(
            capability["adapter_contract"]["at_most_once_attempt_checkpoint"]
        )
        self.assertTrue(
            capability["adapter_contract"]["terminal_ambiguity_hold"]
        )
        self.assertFalse(
            capability["runtime_guarantees"]["at_most_once_attempt_checkpoint"]
        )
        self.assertFalse(
            capability["runtime_guarantees"]["terminal_ambiguity_hold"]
        )
        self.assertFalse(capability["idempotent_provider_replay_claimed"])
        self.assertFalse(capability["automatic_provider_redispatch"])

    def test_public_capability_requires_authenticated_fresh_heartbeat(self):
        configured = {
            **compute_provider_static_capability(Settings()),
            "release_configured": True,
            "reason": "fresh_provider_runtime_heartbeat_required",
        }
        with (
            patch(
                "tinker_delegate.compute_tinker_provider.compute_provider_static_capability",
                return_value=configured,
            ),
            patch(
                "tinker_delegate.compute_tinker_provider._provider_status_integrity_key",
                return_value=b"k" * 32,
            ),
            patch.object(
                ComputeProviderStatusStore,
                "read_fresh",
                return_value={
                    "authenticated": True,
                    "fresh": True,
                    "process_presence_only": True,
                    "tdx_evidence": False,
                    "observed_at": 1_700_000_000,
                },
            ),
        ):
            capability = compute_provider_public_capability(
                Settings(compute_provider_status_path="/data/provider-status.json")
            )

        self.assertTrue(capability["provider_dispatch"])
        self.assertEqual(
            capability["reason"], "ready_at_most_once_ambiguity_hold"
        )
        self.assertTrue(
            capability["runtime_guarantees"]["at_most_once_attempt_checkpoint"]
        )
        self.assertTrue(
            capability["runtime_guarantees"]["terminal_ambiguity_hold"]
        )
        self.assertTrue(capability["runtime"]["process_presence_only"])
        self.assertFalse(capability["runtime"]["tdx_evidence"])

    def test_provider_paths_reject_parent_traversal_and_nested_status(self):
        for value in (
            "/data/../provider-status.json",
            "/data/provider/../provider-status.json",
            "/data//provider-status.json",
            "/tmp/provider-status.json",
        ):
            with self.subTest(value=value):
                with self.assertRaises(TinkerProviderReleaseError):
                    _canonical_data_file_path(value, purpose="provider status")

        with self.assertRaises(TinkerProviderReleaseError):
            _canonical_data_file_path(
                "/data/nested/provider-status.json",
                purpose="provider status",
            )
        self.assertEqual(
            _canonical_data_file_path(
                "/data/provider-status.json",
                purpose="provider status",
            ),
            Path("/data/provider-status.json"),
        )


class ComputeProviderStatusStoreTest(unittest.TestCase):
    def test_round_trip_is_authenticated_fresh_and_mode_0600(self):
        with tempfile.TemporaryDirectory() as temporary:
            os.chmod(temporary, 0o700)
            path = Path(temporary) / "provider-status.json"
            settings = Settings(compute_provider_status_ttl_seconds=30)
            store = ComputeProviderStatusStore(path, integrity_key=b"k" * 32)

            store.write_ready(settings, observed_at=1_700_000_000)
            heartbeat = store.read_fresh(settings, now=1_700_000_010)

            self.assertTrue(heartbeat["authenticated"])
            self.assertTrue(heartbeat["fresh"])
            self.assertTrue(heartbeat["process_presence_only"])
            self.assertFalse(heartbeat["tdx_evidence"])
            self.assertEqual(
                stat.S_IMODE(path.stat().st_mode),
                0o600,
            )

    def test_stale_tampered_and_symlinked_heartbeats_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            os.chmod(temporary, 0o700)
            path = Path(temporary) / "provider-status.json"
            settings = Settings(compute_provider_status_ttl_seconds=30)
            store = ComputeProviderStatusStore(path, integrity_key=b"k" * 32)
            store.write_ready(settings, observed_at=1_700_000_000)

            with self.assertRaises(TinkerProviderReleaseError):
                store.read_fresh(settings, now=1_700_000_031)

            raw = bytearray(path.read_bytes())
            raw[-3] ^= 1
            path.write_bytes(raw)
            os.chmod(path, 0o600)
            with self.assertRaises(TinkerProviderReleaseError):
                store.read_fresh(settings, now=1_700_000_001)

            path.unlink()
            target = Path(temporary) / "target.json"
            target.write_bytes(b"{}")
            os.chmod(target, 0o600)
            path.symlink_to(target)
            with self.assertRaises(TinkerProviderReleaseError):
                store.read_fresh(settings, now=1_700_000_001)

    def test_group_writable_parent_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            os.chmod(temporary, 0o770)
            store = ComputeProviderStatusStore(
                Path(temporary) / "provider-status.json",
                integrity_key=b"k" * 32,
            )
            with self.assertRaises(TinkerProviderReleaseError):
                store.write_ready(Settings(), observed_at=1_700_000_000)


if __name__ == "__main__":
    unittest.main()
