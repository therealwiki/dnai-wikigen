import base64
import hashlib
import io
import json
import os
import stat
import tempfile
import tomllib
import unittest
from pathlib import Path

from eth_hash.auto import keccak

from tinker_delegate.arena_policy_provisioner import (
    AUTH_KEY_B64_ENV,
    AUTH_TAG_ENV,
    EVALUATOR_B64_ENV,
    EVALUATOR_FILENAME,
    EVALUATOR_SHA256_ENV,
    LOCK_FILENAME,
    MAX_B64_JSON_CHARS,
    RELEASE_B64_ENV,
    RELEASE_FILENAME,
    RELEASE_SHA256_ENV,
    ArenaPolicyProvisionError,
    build_parser,
    main,
    provision_auth_tag,
    provision_from_environment,
)
from tinker_delegate.arena_release_approval import (
    release_approved_challenge_set_sha256,
)
from tinker_delegate.arena_safe_ir import (
    SAFE_IR_POLICY_COMMITMENT,
    SAFE_IR_RUNTIME,
)
from tinker_delegate.arena_store import (
    BIO_SAFE_IR_CHALLENGE_ID,
    BIO_SAFE_IR_CHALLENGE_VERSION,
    default_challenge_catalog,
)
from tinker_delegate.arena_worker_cli import (
    BASE_SEPOLIA_CHAIN_ID,
    EVALUATOR_SCHEMA,
    RELEASE_SCHEMA,
    compute_arena_release_policy_commitment,
    sealed_evaluator_commitment,
)
from tinker_delegate.execution_policy_store import (
    execution_policy_approval_domain_hash,
    execution_policy_approver_root_hash,
)


REGISTRY = "0x" + "99" * 20
TEE = "0x" + "88" * 20
QVL = "0x" + "77" * 20
COMPOSE = "22" * 32
OS_IMAGE = "33" * 32
APP_ID = "app_arena_provision_test"
POLICY_MANIFEST_COMMITMENT = "55" * 32
POLICY_APPROVER_HASHES = ("66" * 32, "77" * 32)
POLICY_APPROVER_ROOT_HASH = execution_policy_approver_root_hash(
    POLICY_APPROVER_HASHES
)
POLICY_ANCHOR_WRITER = "0x" + "dd" * 20
DOMAIN = ":".join(
    (
        "base-sepolia",
        str(BASE_SEPOLIA_CHAIN_ID),
        POLICY_MANIFEST_COMMITMENT,
        "0x" + COMPOSE,
        hashlib.sha256(APP_ID.encode("ascii")).hexdigest(),
        POLICY_APPROVER_ROOT_HASH,
    )
)
POLICY_ROLLBACK_ANCHOR = {
    "schema": "dnai.execution-policy-rollback-anchor.v1",
    "status": "verified_active_frozen_release_writer",
    "chain_id": BASE_SEPOLIA_CHAIN_ID,
    "contract_address": "0x" + "aa" * 20,
    "runtime_code_hash": "0x" + "bb" * 32,
    "release_manifest_commitment": POLICY_MANIFEST_COMMITMENT,
    "evidence_sha256": "sha256:" + "cc" * 32,
    "writer_address": POLICY_ANCHOR_WRITER,
    "writer_release_commitment": "0x" + POLICY_MANIFEST_COMMITMENT,
    "writer_custody": "dstack_derived_execution_policy_anchor_writer",
    "writer_key_path": "tinker/execution_policy_anchor_writer",
    "confirmations": 12,
    "max_block_age_seconds": 3_600,
    "max_future_block_skew_seconds": 30,
    "verification_model": (
        "single_rpc_reported_finalized_with_confirmation_depth"
    ),
    "independent_rpc_quorum_verified": False,
    "consensus_proof_verified": False,
}
AUTH_KEY = bytes.fromhex("a5" * 32)


def _canonical(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _valid_payloads():
    challenge = default_challenge_catalog().get(
        BIO_SAFE_IR_CHALLENGE_ID,
        BIO_SAFE_IR_CHALLENGE_VERSION,
    )
    evaluator = {
        "schema": EVALUATOR_SCHEMA,
        "challenge_id": BIO_SAFE_IR_CHALLENGE_ID,
        "challenge_version": BIO_SAFE_IR_CHALLENGE_VERSION,
        "challenge_manifest_hash": challenge.manifest_hash,
        "runtime": SAFE_IR_RUNTIME,
        "runtime_policy_commitment": SAFE_IR_POLICY_COMMITMENT,
        "synthetic_only": True,
        "positive_controls": [100.0, 101.0, 99.0, 100.5],
        "negative_controls": [10.0, 11.0, 9.0, 10.5],
    }
    binding = {
        "catalog_challenge_id": BIO_SAFE_IR_CHALLENGE_ID,
        "catalog_challenge_version": BIO_SAFE_IR_CHALLENGE_VERSION,
        "catalog_manifest_hash": challenge.manifest_hash,
        "runtime": SAFE_IR_RUNTIME,
        "runtime_policy_commitment": SAFE_IR_POLICY_COMMITMENT,
        "registry_challenge_id": "7",
        "registry_version": 1,
        "metadata_uri": "ipfs://synthetic-safe-ir-provision-test",
        "metadata_hash": "0x" + challenge.manifest_hash,
        "sealed_artifact_commitment": sealed_evaluator_commitment(evaluator),
        "evaluator_commitment": "0x"
        + SAFE_IR_POLICY_COMMITMENT.removeprefix("sha256:"),
    }
    tee_release = {
        "compose_hash": COMPOSE,
        "app_id": APP_ID,
        "os_image_hash": OS_IMAGE,
        "tee_signer_address": TEE,
    }
    approved_bindings = {
        f"{BIO_SAFE_IR_CHALLENGE_ID}@{BIO_SAFE_IR_CHALLENGE_VERSION}": {
            "registry_challenge_id": binding["registry_challenge_id"],
            "registry_version": binding["registry_version"],
            "controller_address": "0x" + "77" * 20,
            "pending_controller_address": "0x" + "00" * 20,
            "lifecycle": "open",
            "paused": False,
            "configuration_frozen": True,
            "catalog_manifest_hash": binding["catalog_manifest_hash"],
            "metadata_uri": binding["metadata_uri"],
            "metadata_hash": binding["metadata_hash"],
            "sealed_artifact_commitment": binding[
                "sealed_artifact_commitment"
            ],
            "evaluator_commitment": binding["evaluator_commitment"],
        }
    }
    approved_set_sha256 = release_approved_challenge_set_sha256(
        approved_bindings
    )
    approval_domain_hash = execution_policy_approval_domain_hash(DOMAIN)
    release_commitment = compute_arena_release_policy_commitment(
        chain_id=BASE_SEPOLIA_CHAIN_ID,
        challenge_registry_address=REGISTRY,
        challenge_registry_runtime_code_hash="0x" + keccak(b"\x60\x00").hex(),
        approved_challenge_set_sha256=approved_set_sha256,
        binding=binding,
        tee_release=tee_release,
        trusted_qvl_verifier_addresses=[QVL],
        max_qvl_verdict_age_seconds=300,
        execution_policy_canonicalization_version=(
            "policy-kernel-canonicalization/v2"
        ),
        execution_policy_approval_schema=(
            "dnai-wikigen/execution-policy-approval/v3"
        ),
        execution_policy_api_schema_version=3,
        execution_policy_store_schema_version=5,
        execution_policy_approval_domain=DOMAIN,
        execution_policy_approval_domain_hash=approval_domain_hash,
        execution_policy_approver_hashes=POLICY_APPROVER_HASHES,
        execution_policy_approver_root_hash=POLICY_APPROVER_ROOT_HASH,
        execution_policy_rollback_anchor=POLICY_ROLLBACK_ANCHOR,
    )
    release = {
        "schema": RELEASE_SCHEMA,
        "chain_id": BASE_SEPOLIA_CHAIN_ID,
        "challenge_registry_address": REGISTRY,
        "challenge_registry_runtime_code_hash": "0x"
        + keccak(b"\x60\x00").hex(),
        "approved_challenge_bindings": approved_bindings,
        "approved_challenge_set_sha256": approved_set_sha256,
        "challenge_binding": {
            **binding,
            "release_policy_commitment": release_commitment,
        },
        "tee_release": tee_release,
        "trusted_qvl_verifier_addresses": [QVL],
        "max_qvl_verdict_age_seconds": 300,
        "execution_policy_canonicalization_version": (
            "policy-kernel-canonicalization/v2"
        ),
        "execution_policy_approval_schema": (
            "dnai-wikigen/execution-policy-approval/v3"
        ),
        "execution_policy_api_schema_version": 3,
        "execution_policy_store_schema_version": 5,
        "execution_policy_approval_domain": DOMAIN,
        "execution_policy_approval_domain_hash": approval_domain_hash,
        "execution_policy_approver_hashes": list(POLICY_APPROVER_HASHES),
        "execution_policy_approver_root_hash": POLICY_APPROVER_ROOT_HASH,
        "execution_policy_rollback_anchor": POLICY_ROLLBACK_ANCHOR,
    }
    return release, evaluator


def _environment(release_raw, evaluator_raw, *, key=AUTH_KEY):
    release_hash = "sha256:" + hashlib.sha256(release_raw).hexdigest()
    evaluator_hash = "sha256:" + hashlib.sha256(evaluator_raw).hexdigest()
    return {
        RELEASE_B64_ENV: _b64url(release_raw),
        EVALUATOR_B64_ENV: _b64url(evaluator_raw),
        RELEASE_SHA256_ENV: release_hash,
        EVALUATOR_SHA256_ENV: evaluator_hash,
        AUTH_KEY_B64_ENV: _b64url(key),
        AUTH_TAG_ENV: provision_auth_tag(
            key,
            release_sha256=release_hash,
            evaluator_sha256=evaluator_hash,
            release_size=len(release_raw),
            evaluator_size=len(evaluator_raw),
        ),
    }


class ArenaPolicyProvisionerTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output_dir = Path(self.temp.name) / "arena"
        release, evaluator = _valid_payloads()
        self.release_raw = _canonical(release)
        self.evaluator_raw = _canonical(evaluator)

    def assert_no_policy_files(self):
        self.assertFalse((self.output_dir / RELEASE_FILENAME).exists())
        self.assertFalse((self.output_dir / EVALUATOR_FILENAME).exists())

    def test_authenticated_environment_provisions_exact_0600_regular_files(self):
        environ = _environment(self.release_raw, self.evaluator_raw)

        provision_from_environment(environ=environ, output_dir=self.output_dir)

        self.assertEqual(environ, {})
        self.assertEqual(
            (self.output_dir / RELEASE_FILENAME).read_bytes(),
            self.release_raw,
        )
        self.assertEqual(
            (self.output_dir / EVALUATOR_FILENAME).read_bytes(),
            self.evaluator_raw,
        )
        self.assertEqual(stat.S_IMODE(self.output_dir.stat().st_mode), 0o700)
        for name in (RELEASE_FILENAME, EVALUATOR_FILENAME, LOCK_FILENAME):
            details = (self.output_dir / name).lstat()
            self.assertTrue(stat.S_ISREG(details.st_mode))
            self.assertEqual(stat.S_IMODE(details.st_mode), 0o600)
            self.assertEqual(details.st_nlink, 1)
        self.assertEqual(
            [path.name for path in self.output_dir.glob(".*.tmp")],
            [],
        )

        # A one-shot service restart is deterministic and leaves the same
        # authenticated file pair rather than accumulating policy versions.
        provision_from_environment(
            environ=_environment(self.release_raw, self.evaluator_raw),
            output_dir=self.output_dir,
        )
        self.assertEqual(
            (self.output_dir / RELEASE_FILENAME).read_bytes(),
            self.release_raw,
        )

    def test_base64_is_canonical_unpadded_urlsafe_and_size_bounded(self):
        for invalid in (
            _environment(self.release_raw, self.evaluator_raw)[RELEASE_B64_ENV]
            + "=",
            "not+urlsafe",
            "A",
        ):
            with self.subTest(invalid=invalid[-12:]):
                environ = _environment(self.release_raw, self.evaluator_raw)
                environ[RELEASE_B64_ENV] = invalid
                with self.assertRaisesRegex(
                    ArenaPolicyProvisionError,
                    "provision_encoding_invalid",
                ):
                    provision_from_environment(
                        environ=environ,
                        output_dir=self.output_dir,
                    )
                self.assert_no_policy_files()

        environ = _environment(self.release_raw, self.evaluator_raw)
        environ[RELEASE_B64_ENV] = "A" * (MAX_B64_JSON_CHARS + 1)
        with self.assertRaisesRegex(
            ArenaPolicyProvisionError,
            "provision_payload_too_large",
        ):
            provision_from_environment(environ=environ, output_dir=self.output_dir)
        self.assert_no_policy_files()

    def test_hash_and_hmac_both_fail_closed_before_output(self):
        environ = _environment(self.release_raw, self.evaluator_raw)
        environ[RELEASE_SHA256_ENV] = "sha256:" + "11" * 32
        with self.assertRaisesRegex(
            ArenaPolicyProvisionError,
            "provision_hash_mismatch",
        ):
            provision_from_environment(environ=environ, output_dir=self.output_dir)
        self.assert_no_policy_files()

        environ = _environment(self.release_raw, self.evaluator_raw)
        environ[AUTH_TAG_ENV] = "hmac-sha256:" + "22" * 32
        with self.assertRaisesRegex(
            ArenaPolicyProvisionError,
            "provision_authentication_failed",
        ):
            provision_from_environment(environ=environ, output_dir=self.output_dir)
        self.assert_no_policy_files()

    def test_json_must_be_canonical_finite_unique_object_schema(self):
        noncanonical = b" " + self.release_raw
        duplicate = self.release_raw[:-1] + b',"schema":"' + RELEASE_SCHEMA.encode() + b'"}'
        non_object = b"[]"
        non_finite = b'{"schema":NaN}'
        for invalid in (noncanonical, duplicate, non_object, non_finite):
            with self.subTest(prefix=invalid[:12]):
                with self.assertRaisesRegex(
                    ArenaPolicyProvisionError,
                    "provision_json_invalid",
                ):
                    provision_from_environment(
                        environ=_environment(invalid, self.evaluator_raw),
                        output_dir=self.output_dir,
                    )
                self.assert_no_policy_files()

        release, _evaluator = _valid_payloads()
        release["schema"] = "dnai.arena.untrusted.v1"
        with self.assertRaisesRegex(
            ArenaPolicyProvisionError,
            "provision_release_invalid",
        ):
            provision_from_environment(
                environ=_environment(_canonical(release), self.evaluator_raw),
                output_dir=self.output_dir,
            )
        self.assert_no_policy_files()

    def test_worker_release_policy_and_evaluator_commitments_are_reused(self):
        release, evaluator = _valid_payloads()
        release["challenge_binding"]["release_policy_commitment"] = "0x" + "44" * 32
        with self.assertRaisesRegex(
            ArenaPolicyProvisionError,
            "provision_release_invalid",
        ):
            provision_from_environment(
                environ=_environment(_canonical(release), self.evaluator_raw),
                output_dir=self.output_dir,
            )
        self.assert_no_policy_files()

        release, evaluator = _valid_payloads()
        evaluator["positive_controls"] = [200.0, 201.0]
        with self.assertRaisesRegex(
            ArenaPolicyProvisionError,
            "provision_evaluator_invalid",
        ):
            provision_from_environment(
                environ=_environment(self.release_raw, _canonical(evaluator)),
                output_dir=self.output_dir,
            )
        self.assert_no_policy_files()

    def test_output_directory_symlinks_and_broad_modes_are_rejected(self):
        target = Path(self.temp.name) / "target"
        target.mkdir(mode=0o700)
        self.output_dir.symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(
            ArenaPolicyProvisionError,
            "provision_output_unavailable",
        ):
            provision_from_environment(
                environ=_environment(self.release_raw, self.evaluator_raw),
                output_dir=self.output_dir,
            )
        self.assertEqual(list(target.iterdir()), [])

        self.output_dir.unlink()
        self.output_dir.mkdir(mode=0o755)
        self.output_dir.chmod(0o755)
        with self.assertRaisesRegex(
            ArenaPolicyProvisionError,
            "provision_output_unavailable",
        ):
            provision_from_environment(
                environ=_environment(self.release_raw, self.evaluator_raw),
                output_dir=self.output_dir,
            )
        self.assert_no_policy_files()

    def test_cli_accepts_no_payload_args_and_never_logs_secrets_or_hashes(self):
        parser = build_parser()
        self.assertEqual({action.dest for action in parser._actions}, {"help"})
        project = tomllib.loads(
            (Path(__file__).parents[1] / "pyproject.toml").read_text()
        )
        self.assertEqual(
            project["project"]["scripts"]["tinker-arena-provision"],
            "tinker_delegate.arena_policy_provisioner:main",
        )

        stream = io.StringIO()
        environ = _environment(self.release_raw, self.evaluator_raw)
        secret_values = tuple(environ.values())
        self.assertEqual(
            main(
                [],
                environ=environ,
                output_dir=self.output_dir,
                stdout=stream,
            ),
            0,
        )
        status = json.loads(stream.getvalue())
        self.assertTrue(status["provisioned"])
        self.assertFalse(status["sealed_evaluator_egress"])
        self.assertFalse(status["hash_egress"])
        for secret in secret_values:
            self.assertNotIn(secret, stream.getvalue())

        argument_stream = io.StringIO()
        self.assertEqual(
            main(["payload-super-secret"], environ={}, stdout=argument_stream),
            64,
        )
        self.assertNotIn("payload-super-secret", argument_stream.getvalue())
        self.assertEqual(
            json.loads(argument_stream.getvalue())["reason"],
            "environment_inputs_only",
        )


if __name__ == "__main__":
    unittest.main()
