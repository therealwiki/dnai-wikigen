from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import stat
from unittest.mock import patch

import pytest

from tinker_delegate.deterministic_diligence_evaluator import (
    COMPILED_RECIPES,
    compile_policy_v1,
)
from tinker_delegate.diligence_evaluator_provisioner import (
    DiligenceEvaluatorProvisionError,
    MANIFEST_B64_ENV,
    MANIFEST_FILENAME,
    MANIFEST_PATH_ENV,
    MANIFEST_SHA256_ENV,
    POLICY_SET_ROOT_ENV,
    main,
    provision_from_environment,
)
from tinker_delegate.diligence_evaluator_registry import (
    build_diligence_evaluator_release_manifest,
    load_diligence_evaluator_registry,
)


def _digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("ascii")).hexdigest()


def _release_bytes() -> tuple[bytes, str]:
    digests = {
        "evaluator_bundle_digest_sha256": _digest("reviewed-evaluator-bundle"),
        "entrypoint_digest_sha256": _digest("reviewed-entrypoint"),
        "input_schema_digest_sha256": _digest("reviewed-input-schema"),
        "output_schema_digest_sha256": _digest("reviewed-output-schema"),
    }
    policies = {
        recipe: compile_policy_v1(recipe=recipe, **digests)
        for recipe in COMPILED_RECIPES
    }
    payload = build_diligence_evaluator_release_manifest(policies)
    raw = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    return raw, payload["evaluator_policy_set_root"]


def _environment(output_dir):
    raw, root = _release_bytes()
    manifest_path = output_dir / MANIFEST_FILENAME
    return {
        MANIFEST_B64_ENV: base64.urlsafe_b64encode(raw).decode("ascii").rstrip("="),
        MANIFEST_PATH_ENV: str(manifest_path),
        MANIFEST_SHA256_ENV: "sha256:" + hashlib.sha256(raw).hexdigest(),
        POLICY_SET_ROOT_ENV: root,
    }, raw, manifest_path


def test_networkless_provisioner_publishes_exact_validated_manifest(tmp_path):
    environment, raw, manifest_path = _environment(tmp_path)
    source = dict(environment)

    published = provision_from_environment(
        environ=source,
        output_dir=tmp_path,
        expected_manifest_path=manifest_path,
    )

    assert published == manifest_path
    assert published.read_bytes() == raw
    assert stat.S_IMODE(published.stat().st_mode) == 0o600
    assert all(name not in source for name in environment)
    registry = load_diligence_evaluator_registry(
        str(published),
        expected_manifest_sha256=environment[MANIFEST_SHA256_ENV],
        expected_policy_set_root=environment[POLICY_SET_ROOT_ENV],
    )
    assert len(registry.descriptors) == 3


def test_exact_retry_is_idempotent_but_existing_drift_is_rejected(tmp_path):
    environment, _raw, manifest_path = _environment(tmp_path)
    for _ in range(2):
        provision_from_environment(
            environ=dict(environment),
            output_dir=tmp_path,
            expected_manifest_path=manifest_path,
        )
    manifest_path.write_bytes(b"{}\n")
    with pytest.raises(DiligenceEvaluatorProvisionError, match="provision_output_conflict"):
        provision_from_environment(
            environ=dict(environment),
            output_dir=tmp_path,
            expected_manifest_path=manifest_path,
        )


def test_existing_exact_manifest_with_public_mode_is_rejected(tmp_path):
    environment, raw, manifest_path = _environment(tmp_path)
    manifest_path.write_bytes(raw)
    manifest_path.chmod(0o644)

    with pytest.raises(
        DiligenceEvaluatorProvisionError,
        match="provision_output_unavailable",
    ):
        provision_from_environment(
            environ=dict(environment),
            output_dir=tmp_path,
            expected_manifest_path=manifest_path,
        )


def test_symlink_output_directory_is_rejected(tmp_path):
    actual = tmp_path / "actual"
    actual.mkdir()
    output = tmp_path / "output"
    output.symlink_to(actual, target_is_directory=True)
    environment, _raw, _manifest_path = _environment(output)

    with pytest.raises(
        DiligenceEvaluatorProvisionError,
        match="provision_output_unavailable",
    ):
        provision_from_environment(
            environ=dict(environment),
            output_dir=output,
            expected_manifest_path=output / MANIFEST_FILENAME,
        )
    assert not (actual / MANIFEST_FILENAME).exists()


def test_existing_symlink_manifest_is_rejected_without_touching_target(tmp_path):
    environment, raw, manifest_path = _environment(tmp_path)
    target = tmp_path / "target.json"
    target.write_bytes(raw)
    manifest_path.symlink_to(target)

    with pytest.raises(
        DiligenceEvaluatorProvisionError,
        match="provision_output_unavailable",
    ):
        provision_from_environment(
            environ=dict(environment),
            output_dir=tmp_path,
            expected_manifest_path=manifest_path,
        )
    assert target.read_bytes() == raw


def test_publication_race_never_replaces_existing_destination(tmp_path):
    environment, _raw, manifest_path = _environment(tmp_path)
    raced = b"concurrent-publication\n"
    real_link = os.link

    def link_after_competing_create(
        source,
        destination,
        *,
        src_dir_fd,
        dst_dir_fd,
        follow_symlinks,
    ):
        competitor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=dst_dir_fd,
        )
        try:
            os.write(competitor, raced)
        finally:
            os.close(competitor)
        return real_link(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
            follow_symlinks=follow_symlinks,
        )

    with (
        patch(
            "tinker_delegate.diligence_evaluator_provisioner.os.link",
            side_effect=link_after_competing_create,
        ),
        pytest.raises(
            DiligenceEvaluatorProvisionError,
            match="provision_output_conflict",
        ),
    ):
        provision_from_environment(
            environ=dict(environment),
            output_dir=tmp_path,
            expected_manifest_path=manifest_path,
        )
    assert manifest_path.read_bytes() == raced


@pytest.mark.parametrize(
    "mutation,reason",
    [
        ({MANIFEST_B64_ENV: "***"}, "provision_encoding_invalid"),
        ({MANIFEST_SHA256_ENV: "sha256:" + "44" * 32}, "provision_hash_mismatch"),
        ({POLICY_SET_ROOT_ENV: "0x" + "55" * 32}, "provision_release_invalid"),
        ({MANIFEST_PATH_ENV: "/tmp/substituted.json"}, "provision_configuration_missing"),
    ],
)
def test_payload_hash_root_and_path_substitution_fail_closed(tmp_path, mutation, reason):
    environment, _raw, manifest_path = _environment(tmp_path)
    with pytest.raises(DiligenceEvaluatorProvisionError, match=reason):
        provision_from_environment(
            environ={**environment, **mutation},
            output_dir=tmp_path,
            expected_manifest_path=manifest_path,
        )
    assert not manifest_path.exists()


def test_missing_input_and_noncanonical_manifest_fail_closed(tmp_path):
    environment, raw, manifest_path = _environment(tmp_path)
    del environment[MANIFEST_B64_ENV]
    with pytest.raises(DiligenceEvaluatorProvisionError, match="provision_configuration_missing"):
        provision_from_environment(
            environ=environment,
            output_dir=tmp_path,
            expected_manifest_path=manifest_path,
        )

    environment, _raw, manifest_path = _environment(tmp_path)
    noncanonical = json.dumps(json.loads(raw), indent=2).encode("ascii")
    environment[MANIFEST_B64_ENV] = base64.urlsafe_b64encode(noncanonical).decode("ascii").rstrip("=")
    environment[MANIFEST_SHA256_ENV] = "sha256:" + hashlib.sha256(noncanonical).hexdigest()
    with pytest.raises(DiligenceEvaluatorProvisionError, match="provision_release_invalid"):
        provision_from_environment(
            environ=environment,
            output_dir=tmp_path,
            expected_manifest_path=manifest_path,
        )


def test_cli_rejects_payload_arguments_and_emits_bounded_status(tmp_path):
    output = io.StringIO()
    code = main(["private-payload"], stdout=output)
    assert code == 64
    assert "environment_inputs_only" in output.getvalue()
    assert "private-payload" not in output.getvalue()
