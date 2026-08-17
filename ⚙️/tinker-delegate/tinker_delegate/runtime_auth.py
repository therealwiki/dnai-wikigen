"""Shared runtime bearer-token resolution for internal delegate callers."""

from __future__ import annotations

import hashlib
from typing import Any

from tinker_delegate import dstack_utils


class RuntimeAuthUnavailable(RuntimeError):
    """Raised when runtime auth is required but no secure token can be resolved."""


def runtime_auth_enabled(settings: Any) -> bool:
    """Return whether runtime bearer checks should be enforced.

    dstack mode always enforces them, even if an operator forgot to set the
    legacy ``runtime_auth_required`` flag.  Local development preserves the
    existing opt-in behavior for non-internal endpoints.
    """

    return bool(
        getattr(settings, "runtime_auth_required", False)
        or getattr(settings, "runtime_auth_token", "")
        or dstack_utils.is_dstack_enabled()
    )


def runtime_auth_available(settings: Any) -> bool:
    """Return whether configured or CVM-derived runtime auth is available."""

    return bool(getattr(settings, "runtime_auth_token", "") or dstack_utils.is_dstack_enabled())


def resolve_runtime_auth_token(settings: Any) -> str:
    """Resolve the shared internal bearer token without logging it."""

    explicit = str(getattr(settings, "runtime_auth_token", "") or "")
    if explicit:
        return explicit
    if dstack_utils.is_dstack_enabled():
        key_path = str(
            getattr(settings, "runtime_auth_key_path", "tinker/runtime-auth")
            or "tinker/runtime-auth"
        )
        try:
            key = dstack_utils.derive_storage_key(key_path)
        except Exception as exc:
            raise RuntimeAuthUnavailable("delegate runtime auth key derivation failed") from exc
        return hashlib.sha256(b"tinker-delegate-runtime-auth:" + key).hexdigest()
    return ""
