from __future__ import annotations

import hashlib
import json
from pathlib import Path

from tinker_delegate.diligence_evaluator_bundle import BUNDLE_FILES
from tinker_delegate.diligence_evaluator_registry import (
    load_diligence_evaluator_registry,
)
from tinker_delegate.diligence_evaluator_release_builder import (
    build_diligence_evaluator_release,
)


def _fixture(tmp_path: Path) -> Path:
    source_root = Path(__file__).resolve().parents[1]
    for relative in BUNDLE_FILES:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if relative in {
            "policies/diligence-evaluator-input-v1.json",
            "policies/diligence-evaluator-output-v1.json",
        }:
            target.write_bytes((source_root / relative).read_bytes())
        else:
            target.write_bytes(f"reviewed:{relative}\n".encode("ascii"))
    return tmp_path


def test_builder_produces_exact_canonical_three_policy_manifest(tmp_path):
    release = build_diligence_evaluator_release(_fixture(tmp_path))
    assert release.manifest_bytes.endswith(b"\n")
    assert release.manifest_sha256 == (
        "sha256:" + hashlib.sha256(release.manifest_bytes).hexdigest()
    )
    payload = json.loads(release.manifest_bytes)
    assert payload["evaluator_policy_set_root"] == release.evaluator_policy_set_root
    assert tuple(sorted(
        item["policy_commitment"] for item in payload["policies"]
    )) == release.evaluator_policy_commitments
    assert tuple(sorted(release.evaluator_policy_commitments)) == (
        release.evaluator_policy_commitments
    )
    assert len(set(release.evaluator_policy_commitments)) == 3
    assert all(
        item["policy_document"]["evaluator_bundle_digest_sha256"]
        == release.evaluator_bundle_digest_sha256
        for item in payload["policies"]
    )
    path = tmp_path / "manifest.json"
    path.write_bytes(release.manifest_bytes)
    registry = load_diligence_evaluator_registry(
        str(path),
        expected_manifest_sha256=release.manifest_sha256,
        expected_policy_set_root=release.evaluator_policy_set_root,
    )
    assert tuple(sorted(
        descriptor.policy_commitment for descriptor in registry.descriptors
    )) == release.evaluator_policy_commitments


def test_builder_commitments_drift_when_bundle_or_schema_drifts(tmp_path):
    root = _fixture(tmp_path)
    baseline = build_diligence_evaluator_release(root)
    target = root / "tinker_delegate/evaluator.py"
    target.write_bytes(target.read_bytes() + b"drift\n")
    changed = build_diligence_evaluator_release(root)
    assert changed.evaluator_bundle_digest_sha256 != baseline.evaluator_bundle_digest_sha256
    assert changed.evaluator_policy_commitments != baseline.evaluator_policy_commitments
    assert changed.evaluator_policy_set_root != baseline.evaluator_policy_set_root
