"""Runtime hardening helpers for secret-bearing delegate processes."""

from __future__ import annotations


def disable_core_dumps() -> bool:
    """Disable process core dumps where the host platform supports rlimits."""
    try:
        import resource
    except Exception:  # pragma: no cover - platform without resource module
        return False

    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (OSError, ValueError):  # pragma: no cover - host policy dependent
        return False
    return True
