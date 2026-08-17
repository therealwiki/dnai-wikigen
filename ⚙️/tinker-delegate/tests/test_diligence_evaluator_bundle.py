from __future__ import annotations

import hashlib
import json

import pytest

from tinker_delegate.diligence_evaluator_bundle import (
    BUNDLE_DIGEST_DOMAIN,
    BUNDLE_FILES,
    BUNDLE_SCHEMA,
    DiligenceEvaluatorBundleError,
    diligence_evaluator_bundle_descriptor,
    diligence_evaluator_bundle_digest,
    diligence_evaluator_bundle_bytes,
)


def _fixture(tmp_path):
    for index, relative in enumerate(BUNDLE_FILES, start=1):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(f"fixture-{index}:{relative}\n".encode("ascii"))
    return tmp_path


def test_bundle_digest_is_domain_separated_canonical_and_ordered(tmp_path):
    root = _fixture(tmp_path)
    descriptor = diligence_evaluator_bundle_descriptor(root)
    assert descriptor["schema"] == BUNDLE_SCHEMA
    assert [item["path"] for item in descriptor["files"]] == list(BUNDLE_FILES)
    canonical = diligence_evaluator_bundle_bytes(root)
    assert canonical == (
        json.dumps(descriptor, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")
    expected = "sha256:" + hashlib.sha256(
        BUNDLE_DIGEST_DOMAIN + canonical
    ).hexdigest()
    assert diligence_evaluator_bundle_digest(root) == expected
    assert expected == "sha256:f66469be092d232dee23c8861962ed288f05ebaa38780ba52ada3771a46aa199"


def test_bundle_digest_changes_for_every_authority_file(tmp_path):
    root = _fixture(tmp_path)
    baseline = diligence_evaluator_bundle_digest(root)
    for relative in BUNDLE_FILES:
        path = root / relative
        original = path.read_bytes()
        path.write_bytes(original + b"drift\n")
        try:
            assert diligence_evaluator_bundle_digest(root) != baseline
        finally:
            path.write_bytes(original)


def test_bundle_rejects_missing_and_symlinked_inputs(tmp_path):
    root = _fixture(tmp_path)
    missing = root / BUNDLE_FILES[0]
    missing.unlink()
    with pytest.raises(DiligenceEvaluatorBundleError):
        diligence_evaluator_bundle_digest(root)
    missing.write_text("restored\n", encoding="ascii")
    target = root / BUNDLE_FILES[1]
    target.unlink()
    target.symlink_to(root / BUNDLE_FILES[0])
    with pytest.raises(DiligenceEvaluatorBundleError):
        diligence_evaluator_bundle_digest(root)
