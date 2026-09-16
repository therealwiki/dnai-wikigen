"""Build the canonical non-circular three-policy Diligence release manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from tinker_delegate.deterministic_diligence_evaluator import (
    COMPILED_RECIPES,
    compile_policy_v1,
)
from tinker_delegate.diligence_evaluator_bundle import (
    diligence_evaluator_bundle_digest_from_files,
    read_diligence_evaluator_bundle_files,
)
from tinker_delegate.diligence_evaluator_registry import (
    build_diligence_evaluator_release_manifest,
)


ENTRYPOINT_PATH = "tinker_delegate/deterministic_diligence_evaluator.py"
INPUT_SCHEMA_PATH = "policies/diligence-evaluator-input-v1.json"
OUTPUT_SCHEMA_PATH = "policies/diligence-evaluator-output-v1.json"


class DiligenceEvaluatorReleaseBuildError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class BuiltDiligenceEvaluatorRelease:
    manifest_bytes: bytes
    manifest_sha256: str
    evaluator_bundle_digest_sha256: str
    evaluator_policy_set_root: str
    evaluator_policy_commitments: tuple[str, str, str]


def _sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def build_diligence_evaluator_release(
    project_root: str | Path,
) -> BuiltDiligenceEvaluatorRelease:
    root = Path(project_root)
    snapshot = read_diligence_evaluator_bundle_files(root)
    digests = {
        "evaluator_bundle_digest_sha256": diligence_evaluator_bundle_digest_from_files(
            snapshot
        ),
        "entrypoint_digest_sha256": _sha256(snapshot[ENTRYPOINT_PATH]),
        "input_schema_digest_sha256": _sha256(snapshot[INPUT_SCHEMA_PATH]),
        "output_schema_digest_sha256": _sha256(snapshot[OUTPUT_SCHEMA_PATH]),
    }
    policies = {
        recipe: compile_policy_v1(recipe=recipe, **digests)
        for recipe in COMPILED_RECIPES
    }
    manifest = build_diligence_evaluator_release_manifest(policies)
    raw = (
        json.dumps(
            manifest,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")
    # Contract configuration and final authority use one canonical lexical order;
    # policy documents remain in recipe order inside the manifest itself.
    commitments = tuple(sorted(
        item["policy_commitment"] for item in manifest["policies"]
    ))
    return BuiltDiligenceEvaluatorRelease(
        manifest_bytes=raw,
        manifest_sha256=_sha256(raw),
        evaluator_bundle_digest_sha256=digests[
            "evaluator_bundle_digest_sha256"
        ],
        evaluator_policy_set_root=manifest["evaluator_policy_set_root"],
        evaluator_policy_commitments=(
            commitments[0], commitments[1], commitments[2]
        ),
    )


def _write_exclusive(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        written = 0
        while written < len(raw):
            written += os.write(descriptor, raw[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="tinker-diligence-evaluator-release")
    parser.add_argument("--project-root", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    release = build_diligence_evaluator_release(args.project_root)
    try:
        _write_exclusive(Path(args.output), release.manifest_bytes)
    except OSError:
        return 73
    print(
        json.dumps(
            {
                "evaluator_bundle_digest_sha256": release.evaluator_bundle_digest_sha256,
                "evaluator_policy_commitments": list(
                    release.evaluator_policy_commitments
                ),
                "evaluator_policy_set_root": release.evaluator_policy_set_root,
                "manifest_sha256": release.manifest_sha256,
                "schema": "dnai.diligence-evaluator-release-build-receipt.v1",
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


__all__ = [
    "BuiltDiligenceEvaluatorRelease",
    "DiligenceEvaluatorReleaseBuildError",
    "build_diligence_evaluator_release",
    "main",
]
