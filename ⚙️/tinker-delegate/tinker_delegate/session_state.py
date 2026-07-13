"""Bounded session-state classifier for the TEE-owned auth flow.

Before the automation refreshes an OTP (which pulls a fresh magic code through the
email oracle) it must decide whether that is the right move. Two failure modes
matter:

* a **stale session** — the saved browser session expired / logged out — where a
  single OTP refresh is the correct, safe recovery; and
* a **login loop** — repeated failed sign-ins / rate-limited attempts — where
  refreshing again would hammer the provider and the email oracle, risk locking
  the account, and never converge. There the automation must **fail closed** and
  escalate instead of requesting another code.

``classify_session_state`` turns the auth page text plus a recent-failed-attempt
count into a bounded state; ``decide_otp_action`` maps that to REFRESH_OTP /
FAIL_CLOSED / PROCEED. Everything is deterministic and fails closed on the
unknown/ambiguous case — no raw page text, codes, or credentials egress.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

# Bounded state vocabulary (closed set).
SESSION_ACTIVE = "session_active"
STALE_SESSION = "stale_session"
LOGIN_LOOP = "login_loop"
UNKNOWN = "unknown"

# Bounded action vocabulary (closed set).
PROCEED = "proceed"
REFRESH_OTP = "refresh_otp"
FAIL_CLOSED = "fail_closed"

_ACTION = {
    SESSION_ACTIVE: PROCEED,
    STALE_SESSION: REFRESH_OTP,   # a single re-auth is the safe recovery
    LOGIN_LOOP: FAIL_CLOSED,      # never hammer OTP; escalate
    UNKNOWN: FAIL_CLOSED,         # fail closed on ambiguity
}

_STALE_HINTS = (
    "session expired",
    "your session has expired",
    "please sign in again",
    "please log in again",
    "you have been logged out",
    "session timed out",
    "session timeout",
    "re-authenticate",
    "authentication required",
)

# Text that on its own signals the provider is rate-limiting / looping logins.
_LOOP_HINTS = (
    "too many attempts",
    "too many login attempts",
    "too many failed",
    "try again later",
    "rate limit",
    "rate-limited",
    "temporarily locked",
    "account locked",
    "please wait before trying again",
)

_ACTIVE_HINTS = (
    "signed in",
    "logged in",
    "you are signed in",
    "session active",
    "welcome back",
    "dashboard",
)


def classify_session_state(
    text: str,
    *,
    recent_failed_attempts: int = 0,
    max_attempts: int = 3,
) -> str:
    """Map auth page text + a failed-attempt count to a bounded session state.

    ``recent_failed_attempts >= max_attempts`` forces ``LOGIN_LOOP`` regardless of
    the page text — the count is authoritative because a loop is defined by
    behavior over time, not a single page. ``max_attempts`` must be >= 1.
    """

    if max_attempts < 1:
        raise ValueError("max_attempts must be >= 1")

    if recent_failed_attempts < 0:
        return UNKNOWN
    if recent_failed_attempts >= max_attempts:
        return LOGIN_LOOP

    normalized = re.sub(r"\s+", " ", text or "").strip().lower()
    if not normalized:
        return UNKNOWN

    # Provider rate-limit / lockout text is a loop signal even below the count.
    if any(hint in normalized for hint in _LOOP_HINTS):
        return LOGIN_LOOP
    if any(hint in normalized for hint in _STALE_HINTS):
        return STALE_SESSION
    if any(hint in normalized for hint in _ACTIVE_HINTS):
        return SESSION_ACTIVE
    return UNKNOWN


def decide_otp_action(state: str) -> str:
    """Bounded action for a session state; unknown states fail closed."""

    return _ACTION.get(state, FAIL_CLOSED)


def session_state_receipt(
    text: str,
    *,
    recent_failed_attempts: int = 0,
    max_attempts: int = 3,
) -> dict[str, Any]:
    """Bounded receipt: state, action, attempt count, page-text hash — no raw text.

    ``should_refresh_otp`` is the single decision the caller acts on; it is true
    only for a genuine stale session, never for a login loop or an ambiguous page.
    """

    state = classify_session_state(
        text, recent_failed_attempts=recent_failed_attempts, max_attempts=max_attempts
    )
    action = decide_otp_action(state)
    normalized = re.sub(r"\s+", " ", text or "").strip().lower()
    page_text_hash = "0x" + hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    return {
        "kind": "session_state_status",
        "state": state,
        "action": action,
        "should_refresh_otp": action == REFRESH_OTP,
        "recent_failed_attempts": max(0, int(recent_failed_attempts)),
        "max_attempts": int(max_attempts),
        "bounded_message": f"session_state:{state}",
        "page_text_hash": page_text_hash,
        "raw_secret_egress": False,
    }
