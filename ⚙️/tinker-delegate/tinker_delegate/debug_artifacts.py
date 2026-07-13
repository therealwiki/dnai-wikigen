"""Helpers for deleting browser debug artifacts that may contain secrets."""

from __future__ import annotations

from pathlib import Path


SECRET_DEBUG_ARTIFACT_PATTERNS = (
    "trace*.zip",
    "*.trace",
    "*.har",
    "*.webm",
    "*.mp4",
    "screenshot_billing_*.png",
    "screenshot_*card*.png",
    "screenshot_stripe_*.png",
)


def purge_secret_debug_artifacts(
    artifact_dir: str | Path,
    *,
    patterns: tuple[str, ...] = SECRET_DEBUG_ARTIFACT_PATTERNS,
) -> int:
    """Delete known secret-bearing browser traces, HARs, videos, and screenshots.

    The function only operates inside an explicitly supplied directory. It does
    not recurse by default and returns only a count, avoiding path names in
    public status surfaces.
    """
    if not artifact_dir:
        return 0

    root = Path(artifact_dir).expanduser()
    if not root.exists() or not root.is_dir():
        return 0

    deleted = 0
    seen: set[Path] = set()
    for pattern in patterns:
        for path in root.glob(pattern):
            if path in seen or not path.is_file():
                continue
            seen.add(path)
            path.unlink(missing_ok=True)
            deleted += 1
    return deleted
