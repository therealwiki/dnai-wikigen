"""Shared runtime status for the delegate process."""

from __future__ import annotations

from copy import deepcopy


_DEFAULT_STATE = {
    "api_key_available": False,
    "api_key_source": "none",
    "bootstrap_attempted": False,
    "bootstrap_success": False,
    "bootstrap_error": "",
    "bootstrap_error_kind": "",
    "last_bootstrap_attempt_record": None,
    "reauth_attempted": False,
    "reauth_success": False,
    "reauth_error_kind": "",
    "last_reauth_attempt_record": None,
}

_state = deepcopy(_DEFAULT_STATE)


def get_runtime_state() -> dict:
    """Return a copy of the current runtime status."""
    return deepcopy(_state)


def reset_runtime_state() -> None:
    """Reset runtime status to defaults."""
    _state.clear()
    _state.update(deepcopy(_DEFAULT_STATE))


def update_runtime_state(**kwargs) -> None:
    """Update one or more runtime status fields."""
    _state.update(kwargs)
