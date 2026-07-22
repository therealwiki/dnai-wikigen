import json
import os
import unittest
from dataclasses import replace
from unittest.mock import patch

from eth_hash.auto import keccak

from tinker_delegate.arena_registry_admission import (
    AUTHORIZATION_VERIFICATION_MODEL,
    ArenaRegistryAdmissionError,
    ArenaRegistryAuthorizationSnapshot,
    ArenaRegistryBlock,
    authorize_arena_registry_submission,
)
from tinker_delegate.arena_release_approval import (
    MAX_APPROVED_CHALLENGE_BINDINGS_JSON_BYTES,
    release_approved_challenge_set_sha256,
)
from tinker_delegate.arena_store import (
    BIO_CHALLENGE_ID,
    BIO_CHALLENGE_VERSION,
    default_challenge_catalog,
)
from tinker_delegate.arena_worker_cli import (
    ArenaRegistryChallengeState,
    ArenaRegistryVersionState,
)
from tinker_delegate.config import Settings


NOW = 1_700_000_100
BLOCK_NUMBER = 12_345
BLOCK_HASH = "0x" + "f" * 64
REGISTRY = "0x" + "1" * 40
CONTROLLER = "0x" + "2" * 40
ZERO_ADDRESS = "0x" + "0" * 40
CODE = bytes.fromhex("6001600055")
CODE_HASH = "0x" + keccak(CODE).hex()
SEALED = "0x" + "b" * 64
EVALUATOR = "0x" + "c" * 64
RELEASE_POLICY = "0x" + "d" * 64


def release_fixture():
    challenge = default_challenge_catalog().get(
        BIO_CHALLENGE_ID, BIO_CHALLENGE_VERSION
    )
    approved = {
        f"{challenge.challenge_id}@{challenge.version}": {
            "registry_challenge_id": "1",
            "registry_version": 7,
            "controller_address": CONTROLLER,
            "pending_controller_address": ZERO_ADDRESS,
            "lifecycle": "open",
            "paused": False,
            "configuration_frozen": True,
            "catalog_manifest_hash": challenge.manifest_hash,
            "metadata_uri": "ipfs://arena-registry-admission-test",
            "metadata_hash": "0x" + challenge.manifest_hash,
            "sealed_artifact_commitment": SEALED,
            "evaluator_commitment": EVALUATOR,
        }
    }
    approved_sha = release_approved_challenge_set_sha256(approved)
    configured = {
        key: {**value, "release_policy_commitment": RELEASE_POLICY}
        for key, value in approved.items()
    }
    settings = Settings(
        arena_registry_rpc_url="https://base-sepolia-rpc.example.test",
        arena_registry_address=REGISTRY,
        arena_registry_runtime_code_hash=CODE_HASH,
        arena_registry_approved_challenge_bindings_json=json.dumps(
            configured, sort_keys=True, separators=(",", ":")
        ),
        arena_registry_approved_challenge_set_sha256=approved_sha,
        arena_registry_max_block_age_seconds=300,
        arena_registry_max_future_block_skew_seconds=30,
    )
    snapshot = ArenaRegistryAuthorizationSnapshot.from_mapping(
        {
            "schema_version": 1,
            "verification_model": AUTHORIZATION_VERIFICATION_MODEL,
            "chain_id": 84_532,
            "block_number": str(BLOCK_NUMBER),
            "block_hash": BLOCK_HASH,
            "block_timestamp": str(NOW - 100),
            "registry_address": REGISTRY,
            "registry_runtime_code_hash": CODE_HASH,
            "approved_challenge_set_sha256": approved_sha,
            "catalog_challenge_id": challenge.challenge_id,
            "catalog_challenge_version": challenge.version,
            "catalog_manifest_hash": challenge.manifest_hash,
            "registry_challenge_id": "1",
            "registry_version": 7,
            "controller_address": CONTROLLER,
            "pending_controller_address": ZERO_ADDRESS,
            "metadata_uri": "ipfs://arena-registry-admission-test",
            "metadata_hash": "0x" + challenge.manifest_hash,
            "sealed_artifact_commitment": SEALED,
            "evaluator_commitment": EVALUATOR,
            "release_policy_commitment": RELEASE_POLICY,
            "registry_paused": False,
            "challenge_paused": False,
            "lifecycle": 1,
            "configuration_frozen": True,
            "latest_version": 7,
        }
    )
    return challenge, settings, snapshot


def settings_with_bindings(settings: Settings, bindings: dict) -> Settings:
    approved = {
        key: {
            field: value
            for field, value in binding.items()
            if field != "release_policy_commitment"
        }
        for key, binding in bindings.items()
    }
    return settings.model_copy(
        update={
            "arena_registry_approved_challenge_bindings_json": json.dumps(
                bindings, sort_keys=True, separators=(",", ":")
            ),
            "arena_registry_approved_challenge_set_sha256": (
                release_approved_challenge_set_sha256(approved)
            ),
        }
    )


class FakeRegistryReader:
    def __init__(self, snapshot: ArenaRegistryAuthorizationSnapshot):
        self.chain = 84_532
        self.finalized = ArenaRegistryBlock(
            snapshot.block_number, snapshot.block_hash, snapshot.block_timestamp
        )
        self.numbered = self.finalized
        self.code = CODE
        self.paused = False
        self.exists = True
        self.challenge_state = ArenaRegistryChallengeState(
            controller=snapshot.controller_address,
            pending_controller=snapshot.pending_controller_address,
            lifecycle=1,
            latest_version=snapshot.registry_version,
            paused=False,
            configuration_frozen=True,
        )
        self.version_state = ArenaRegistryVersionState(
            metadata_uri=snapshot.metadata_uri,
            metadata_hash=snapshot.metadata_hash,
            sealed_artifact_commitment=snapshot.sealed_artifact_commitment,
            evaluator_commitment=snapshot.evaluator_commitment,
            release_policy_commitment=snapshot.release_policy_commitment,
        )
        self.block_reads = 0
        self.reorg_after_reads = False
        self.finalized_reads = 0
        self.advance_finalized_after_reads = False
        self.closed = False

    def chain_id(self):
        return self.chain

    def finalized_block(self):
        self.finalized_reads += 1
        if self.advance_finalized_after_reads and self.finalized_reads > 1:
            return replace(
                self.finalized,
                number=self.finalized.number + 1,
                block_hash="0x" + "a" * 64,
                timestamp=self.finalized.timestamp + 2,
            )
        return self.finalized

    def block(self, _number):
        self.block_reads += 1
        if self.reorg_after_reads and self.block_reads > 1:
            return replace(self.numbered, block_hash="0x" + "e" * 64)
        return self.numbered

    def bytecode(self, _address, _number):
        return self.code

    def registry_paused(self, _address, _number):
        return self.paused

    def challenge_exists(self, _address, _challenge_id, _number):
        return self.exists

    def challenge(self, _address, _challenge_id, _number):
        return self.challenge_state

    def version(self, _address, _challenge_id, _version, _number):
        return self.version_state

    def close(self):
        self.closed = True


class ArenaRegistryAdmissionTest(unittest.TestCase):
    def setUp(self):
        self.challenge, self.settings, self.snapshot = release_fixture()

    def authorize(self, reader=None, snapshot=None, settings=None):
        return authorize_arena_registry_submission(
            settings or self.settings,
            challenge=self.challenge,
            snapshot=snapshot or self.snapshot,
            reader=reader or FakeRegistryReader(self.snapshot),
            now=NOW,
        )

    def test_documented_environment_names_populate_the_exact_settings(self):
        env = {
            "TINKER_ARENA_REGISTRY_RPC_URL": self.settings.arena_registry_rpc_url,
            "TINKER_ARENA_REGISTRY_ADDRESS": self.settings.arena_registry_address,
            "TINKER_ARENA_REGISTRY_RUNTIME_CODE_HASH": (
                self.settings.arena_registry_runtime_code_hash
            ),
            "TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_BINDINGS_JSON": (
                self.settings.arena_registry_approved_challenge_bindings_json
            ),
            "TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_SET_SHA256": (
                self.settings.arena_registry_approved_challenge_set_sha256
            ),
            "TINKER_ARENA_REGISTRY_MAX_BLOCK_AGE_SECONDS": "301",
            "TINKER_ARENA_REGISTRY_MAX_FUTURE_BLOCK_SKEW_SECONDS": "31",
        }
        with patch.dict(os.environ, env, clear=True):
            configured = Settings()
        self.assertEqual(configured.arena_registry_rpc_url, env[
            "TINKER_ARENA_REGISTRY_RPC_URL"
        ])
        self.assertEqual(configured.arena_registry_address, REGISTRY)
        self.assertEqual(configured.arena_registry_runtime_code_hash, CODE_HASH)
        self.assertEqual(
            configured.arena_registry_approved_challenge_bindings_json,
            env["TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_BINDINGS_JSON"],
        )
        self.assertEqual(
            configured.arena_registry_approved_challenge_set_sha256,
            env["TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_SET_SHA256"],
        )
        self.assertEqual(configured.arena_registry_max_block_age_seconds, 301)
        self.assertEqual(configured.arena_registry_max_future_block_skew_seconds, 31)

    def test_exact_snapshot_hash_and_bounded_proxy_receipt(self):
        self.assertEqual(set(self.snapshot.to_dict()), {
            "schema_version", "verification_model", "chain_id", "block_number",
            "block_hash", "block_timestamp", "registry_address",
            "registry_runtime_code_hash", "approved_challenge_set_sha256",
            "catalog_challenge_id", "catalog_challenge_version",
            "catalog_manifest_hash", "registry_challenge_id", "registry_version",
            "controller_address", "pending_controller_address", "metadata_uri",
            "metadata_hash", "sealed_artifact_commitment", "evaluator_commitment",
            "release_policy_commitment", "registry_paused", "challenge_paused",
            "lifecycle", "configuration_frozen", "latest_version",
        })
        self.assertEqual(
            self.snapshot.sha256,
            "sha256:959f93a7268b3c697e5e362ae589dbf70cd8a3c7bc13320cacacf592ba22fdd7",
        )
        receipt = self.authorize().to_public_dict()
        self.assertEqual(
            receipt["status"],
            "proxy_independently_verified_at_finalized_block",
        )
        self.assertTrue(receipt["proxy_registry_authorized"])
        self.assertFalse(receipt["worker_registry_authorized"])
        self.assertFalse(receipt["independent_rpc_quorum_verified"])
        self.assertFalse(receipt["consensus_proof_verified"])
        self.assertEqual(receipt["registry_authorization_sha256"], self.snapshot.sha256)

    def test_wrong_chain_finalized_advance_hash_mismatch_and_reorg_fail(self):
        cases = []
        wrong_chain = FakeRegistryReader(self.snapshot)
        wrong_chain.chain = 8_453
        cases.append(wrong_chain)
        advanced = FakeRegistryReader(self.snapshot)
        advanced.finalized = replace(advanced.finalized, number=BLOCK_NUMBER + 1)
        cases.append(advanced)
        wrong_hash = FakeRegistryReader(self.snapshot)
        wrong_hash.numbered = replace(wrong_hash.numbered, block_hash="0x" + "e" * 64)
        cases.append(wrong_hash)
        reorg = FakeRegistryReader(self.snapshot)
        reorg.reorg_after_reads = True
        cases.append(reorg)
        for reader in cases:
            with self.subTest(reader=reader):
                with self.assertRaises(ArenaRegistryAdmissionError):
                    self.authorize(reader=reader)

    def test_new_finalized_head_during_reads_fails_with_old_block_still_canonical(self):
        reader = FakeRegistryReader(self.snapshot)
        reader.advance_finalized_after_reads = True

        with self.assertRaisesRegex(
            ArenaRegistryAdmissionError,
            "finalized block advanced during verification",
        ):
            self.authorize(reader=reader)

        self.assertEqual(reader.numbered, reader.finalized)
        self.assertEqual(reader.block_reads, 2)
        self.assertEqual(reader.finalized_reads, 2)

    def test_runtime_binding_json_is_exact_compact_ascii_without_duplicates(self):
        canonical = self.settings.arena_registry_approved_challenge_bindings_json
        top_level_duplicate = canonical[:-1] + "," + canonical[1:]
        valid_binding = next(iter(json.loads(canonical).values()))
        too_many_bindings = json.dumps(
            {
                f"challenge-{index}@1.0.0": {
                    **valid_binding,
                    "registry_challenge_id": str(index),
                }
                for index in range(1, 34)
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        cases = (
            " " + canonical,
            canonical + "\n",
            canonical.replace(":", ": ", 1),
            canonical.replace("ipfs://", "ipfs://café-", 1),
            top_level_duplicate,
            too_many_bindings,
            "{" + (" " * MAX_APPROVED_CHALLENGE_BINDINGS_JSON_BYTES) + "}",
        )
        for raw in cases:
            settings = self.settings.model_copy(
                update={
                    "arena_registry_approved_challenge_bindings_json": raw
                }
            )
            with self.subTest(raw_prefix=raw[:32]):
                with self.assertRaises(ArenaRegistryAdmissionError):
                    self.authorize(settings=settings)

    def test_runtime_catalog_requires_contiguous_genesis_ids(self):
        bindings = json.loads(
            self.settings.arena_registry_approved_challenge_bindings_json
        )
        only = next(iter(bindings.values()))
        only["registry_challenge_id"] = "2"
        settings = settings_with_bindings(self.settings, bindings)

        with self.assertRaisesRegex(
            ArenaRegistryAdmissionError,
            "release bindings are unavailable",
        ):
            self.authorize(settings=settings)

    def test_runtime_catalog_accepts_the_exact_32_binding_upper_bound(self):
        bindings = json.loads(
            self.settings.arena_registry_approved_challenge_bindings_json
        )
        template = dict(next(iter(bindings.values())))
        for index in range(2, 33):
            bindings[f"challenge-{index}@1.0.0"] = {
                **template,
                "registry_challenge_id": str(index),
                "metadata_uri": f"ipfs://arena-release-{index}",
            }
        settings = settings_with_bindings(self.settings, bindings)
        snapshot = replace(
            self.snapshot,
            approved_challenge_set_sha256=(
                settings.arena_registry_approved_challenge_set_sha256
            ),
        )

        authorization = self.authorize(
            settings=settings,
            snapshot=snapshot,
        )
        self.assertEqual(authorization.registry_challenge_id, 1)

    def test_all_four_runtime_commitments_must_be_pairwise_distinct(self):
        bindings = json.loads(
            self.settings.arena_registry_approved_challenge_bindings_json
        )
        only = next(iter(bindings.values()))
        only["release_policy_commitment"] = only["evaluator_commitment"]
        settings = settings_with_bindings(self.settings, bindings)

        with self.assertRaisesRegex(
            ArenaRegistryAdmissionError,
            "release bindings are unavailable",
        ):
            self.authorize(settings=settings)

    def test_timing_configuration_uses_exact_finite_projected_bounds(self):
        cases = (
            {"arena_registry_max_block_age_seconds": 29},
            {"arena_registry_max_block_age_seconds": 3_601},
            {"arena_registry_max_future_block_skew_seconds": -1},
            {"arena_registry_max_future_block_skew_seconds": 301},
            {"arena_registry_max_block_age_seconds": 300.5},
            {"arena_registry_max_future_block_skew_seconds": "30"},
        )
        for update in cases:
            with self.subTest(update=update):
                settings = self.settings.model_copy(update=update)
                with self.assertRaises(ArenaRegistryAdmissionError):
                    self.authorize(settings=settings)

    def test_fresh_completion_clock_rejects_a_snapshot_that_ages_out(self):
        with patch(
            "tinker_delegate.arena_registry_admission.time.time",
            side_effect=(NOW, NOW + 201),
        ):
            with self.assertRaisesRegex(
                ArenaRegistryAdmissionError,
                "became stale during verification",
            ):
                authorize_arena_registry_submission(
                    self.settings,
                    challenge=self.challenge,
                    snapshot=self.snapshot,
                    reader=FakeRegistryReader(self.snapshot),
                )

    def test_completion_clock_rollback_fails_closed(self):
        with patch(
            "tinker_delegate.arena_registry_admission.time.time",
            side_effect=(NOW, NOW - 1),
        ):
            with self.assertRaisesRegex(
                ArenaRegistryAdmissionError,
                "became stale during verification",
            ):
                authorize_arena_registry_submission(
                    self.settings,
                    challenge=self.challenge,
                    snapshot=self.snapshot,
                    reader=FakeRegistryReader(self.snapshot),
                )

    def test_every_runtime_and_challenge_commitment_mismatch_fails_closed(self):
        mutations = (
            ("code", b"\x60\x01"),
            ("paused", True),
            ("exists", False),
            (
                "challenge_state",
                replace(self.authorized_reader().challenge_state, paused=True),
            ),
            (
                "version_state",
                replace(
                    self.authorized_reader().version_state,
                    evaluator_commitment="0x" + "e" * 64,
                ),
            ),
        )
        for field, value in mutations:
            reader = self.authorized_reader()
            setattr(reader, field, value)
            with self.subTest(field=field):
                with self.assertRaises(ArenaRegistryAdmissionError):
                    self.authorize(reader=reader)

    def authorized_reader(self):
        return FakeRegistryReader(self.snapshot)

    def test_snapshot_tamper_changes_digest_and_is_not_release_authorized(self):
        tampered_payload = self.snapshot.to_dict()
        tampered_payload["block_hash"] = "0x" + "e" * 64
        tampered = ArenaRegistryAuthorizationSnapshot.from_mapping(tampered_payload)
        self.assertNotEqual(tampered.sha256, self.snapshot.sha256)
        with self.assertRaises(ArenaRegistryAdmissionError):
            self.authorize(snapshot=tampered)


if __name__ == "__main__":
    unittest.main()
