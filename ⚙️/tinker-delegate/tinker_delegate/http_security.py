"""HTTP boundary hardening shared by the delegate API."""

from __future__ import annotations

import ipaddress
from typing import Any
from urllib.parse import urlsplit

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware


class HttpSecurityError(ValueError):
    """Raised when an HTTP origin or outbound target violates policy."""


def parse_cors_origins(value: str) -> tuple[str, ...]:
    """Parse an exact, comma-separated origin allowlist.

    HTTPS is required except for explicit loopback development origins.  Paths,
    credentials, wildcard hosts, queries, and fragments are rejected.
    """

    origins: list[str] = []
    for raw in str(value or "").split(","):
        candidate = raw.strip()
        if not candidate:
            continue
        if "*" in candidate:
            raise HttpSecurityError("CORS origins must not contain wildcards")
        parsed = urlsplit(candidate)
        _validate_origin_parts(parsed, purpose="CORS origin", allow_loopback_http=True)
        normalized = _normalized_origin(parsed)
        if normalized not in origins:
            origins.append(normalized)
    return tuple(origins)


def configure_cors(app: FastAPI, settings: Any) -> tuple[str, ...]:
    """Install strict optional CORS middleware and return accepted origins."""

    origins = parse_cors_origins(getattr(settings, "cors_allowed_origins", ""))
    if origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(origins),
            allow_credentials=False,
            allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            allow_headers=[
                "Authorization",
                "Content-Type",
                "Idempotency-Key",
                "Cache-Control",
                "Pragma",
            ],
            max_age=600,
        )
    return origins


def validate_https_allowlisted_url(url: str, allowed_hosts: str) -> str:
    """Validate an operator-supplied outbound base URL against an exact host list.

    The result is a normalized origin with no path.  IP literals are rejected
    even when listed, avoiding accidental access to cloud metadata or private
    network services.  A non-default port must be included explicitly in the
    allowlist as ``host:port``.
    """

    candidate = str(url or "").strip()
    if not candidate:
        raise HttpSecurityError("delegate API URL is required")
    parsed = urlsplit(candidate)
    _validate_origin_parts(parsed, purpose="delegate API URL", allow_loopback_http=False)
    if parsed.scheme.lower() != "https":
        raise HttpSecurityError("delegate API URL must use HTTPS")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise HttpSecurityError("delegate API URL must be an origin without path, query, or fragment")

    host = (parsed.hostname or "").lower().rstrip(".")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise HttpSecurityError("delegate API URL must use an allowlisted DNS hostname")

    allowed = _parse_allowed_hosts(allowed_hosts)
    acceptable_authorities = {host}
    if parsed.port is not None:
        acceptable_authorities.add(f"{host}:{parsed.port}")
    if parsed.port not in (None, 443):
        acceptable_authorities.discard(host)
    if not acceptable_authorities.intersection(allowed):
        raise HttpSecurityError("delegate API URL host is not allowlisted")
    return _normalized_origin(parsed)


def _parse_allowed_hosts(value: str) -> frozenset[str]:
    allowed: set[str] = set()
    for raw in str(value or "").split(","):
        item = raw.strip().lower().rstrip(".")
        if not item:
            continue
        if "*" in item or "://" in item or any(char in item for char in "/?#@"):
            raise HttpSecurityError("funding preflight hosts must be exact hostnames")
        host, separator, port = item.partition(":")
        if not host or (separator and (not port.isdigit() or not 1 <= int(port) <= 65535)):
            raise HttpSecurityError("funding preflight host allowlist is invalid")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise HttpSecurityError("funding preflight allowlist must not contain IP literals")
        allowed.add(item)
    if not allowed:
        raise HttpSecurityError("funding preflight host allowlist is empty")
    return frozenset(allowed)


def _validate_origin_parts(parsed, *, purpose: str, allow_loopback_http: bool) -> None:
    if parsed.scheme.lower() not in {"https", "http"}:
        raise HttpSecurityError(f"{purpose} must use HTTP or HTTPS")
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise HttpSecurityError(f"{purpose} must not contain credentials")
    try:
        port = parsed.port
    except ValueError as exc:
        raise HttpSecurityError(f"{purpose} port is invalid") from exc
    if port is not None and not 1 <= port <= 65535:
        raise HttpSecurityError(f"{purpose} port is invalid")
    host = parsed.hostname.lower().rstrip(".")
    if parsed.scheme.lower() == "http" and not (
        allow_loopback_http and host in {"localhost", "127.0.0.1", "::1"}
    ):
        raise HttpSecurityError(f"{purpose} must use HTTPS")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise HttpSecurityError(f"{purpose} must not contain a path, query, or fragment")


def _normalized_origin(parsed) -> str:
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower().rstrip(".")
    if ":" in host:
        host = f"[{host}]"
    port = parsed.port
    if port is None or (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"
