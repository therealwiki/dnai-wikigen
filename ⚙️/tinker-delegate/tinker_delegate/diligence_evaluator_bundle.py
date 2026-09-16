"""Canonical digest of the reproducible Diligence evaluator source bundle."""

from __future__ import annotations

import hashlib
import json
import stat
from pathlib import Path


BUNDLE_SCHEMA = "dnai.diligence-evaluator-source-bundle.v1"
BUNDLE_DIGEST_DOMAIN = b"dnai.diligence-evaluator-source-bundle.v1\0"
BUNDLE_FILES = (
    "policies/diligence-evaluator-input-v1.json",
    "policies/diligence-evaluator-output-v1.json",
    "pyproject.toml",
    "tinker_delegate/deterministic_diligence_evaluator.py",
    "tinker_delegate/diligence_evaluator_registry.py",
    "tinker_delegate/evaluator.py",
    "uv.lock",
)
MAX_BUNDLE_FILE_BYTES = 16 * 1024 * 1024


class DiligenceEvaluatorBundleError(ValueError):
    pass


def read_diligence_evaluator_bundle_files(
    project_root: str | Path,
) -> dict[str, bytes]:
    """Read one stable, no-symlink snapshot of every bundle authority file."""

    root = Path(project_root)
    snapshot: dict[str, bytes] = {}
    for relative in BUNDLE_FILES:
        path = root / relative
        try:
            before = path.lstat()
            if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_BUNDLE_FILE_BYTES:
                raise DiligenceEvaluatorBundleError("evaluator_bundle_file_invalid")
            raw = path.read_bytes()
            after = path.lstat()
        except DiligenceEvaluatorBundleError:
            raise
        except OSError:
            raise DiligenceEvaluatorBundleError("evaluator_bundle_file_unavailable") from None
        if (
            len(raw) != before.st_size
            or before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
            or before.st_size != after.st_size
        ):
            raise DiligenceEvaluatorBundleError("evaluator_bundle_file_changed")
        snapshot[relative] = raw
    return snapshot


def diligence_evaluator_bundle_descriptor_from_files(
    snapshot: dict[str, bytes],
) -> dict:
    if tuple(snapshot) != BUNDLE_FILES or any(type(raw) is not bytes for raw in snapshot.values()):
        raise DiligenceEvaluatorBundleError("evaluator_bundle_snapshot_invalid")
    files: list[dict[str, object]] = []
    for relative, raw in snapshot.items():
        files.append(
            {
                "path": relative,
                "byte_length": len(raw),
                "sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
            }
        )
    return {"schema": BUNDLE_SCHEMA, "files": files}


def diligence_evaluator_bundle_descriptor(project_root: str | Path) -> dict:
    """Return the exact path/hash/length descriptor used by release tooling."""

    return diligence_evaluator_bundle_descriptor_from_files(
        read_diligence_evaluator_bundle_files(project_root)
    )


def diligence_evaluator_bundle_digest(project_root: str | Path) -> str:
    canonical = diligence_evaluator_bundle_bytes(project_root)
    return "sha256:" + hashlib.sha256(BUNDLE_DIGEST_DOMAIN + canonical).hexdigest()


def diligence_evaluator_bundle_digest_from_files(snapshot: dict[str, bytes]) -> str:
    canonical = diligence_evaluator_bundle_bytes_from_files(snapshot)
    return "sha256:" + hashlib.sha256(BUNDLE_DIGEST_DOMAIN + canonical).hexdigest()


def diligence_evaluator_bundle_bytes(project_root: str | Path) -> bytes:
    """Canonical public source-bundle descriptor bytes (the digest preimage)."""

    return diligence_evaluator_bundle_bytes_from_files(
        read_diligence_evaluator_bundle_files(project_root)
    )


def diligence_evaluator_bundle_bytes_from_files(snapshot: dict[str, bytes]) -> bytes:
    descriptor = diligence_evaluator_bundle_descriptor_from_files(snapshot)
    return (
        json.dumps(
            descriptor,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


__all__ = [
    "BUNDLE_DIGEST_DOMAIN",
    "BUNDLE_FILES",
    "BUNDLE_SCHEMA",
    "DiligenceEvaluatorBundleError",
    "diligence_evaluator_bundle_descriptor",
    "diligence_evaluator_bundle_digest",
    "diligence_evaluator_bundle_bytes",
    "diligence_evaluator_bundle_bytes_from_files",
    "diligence_evaluator_bundle_descriptor_from_files",
    "diligence_evaluator_bundle_digest_from_files",
    "read_diligence_evaluator_bundle_files",
]
