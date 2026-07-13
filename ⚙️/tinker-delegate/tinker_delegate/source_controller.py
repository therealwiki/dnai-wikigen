"""Bounded source-controller records for TEE-held source accounts.

The email, Tinker, Stripe, and data-source accounts live inside the attested TEE.
A source-controller record is the bounded audit artifact for that custody: who
controls a source, what access an owner/reviewer approved, its scope, expiry, and
revocation — plus an audit hash. `SourceControllerRegistry.authorize` answers,
fail-closed, whether a given source+scope access is currently permitted.

Two invariants are enforced:

* Non-self-approval: a grant's `approved_by` must differ from its
  `controller_ref` — a controller cannot approve their own (widened) access.
* Scope containment: authorization requires the exact requested scope to be in
  the grant's approved scope set; an unknown source, expired/revoked grant, or
  out-of-scope request all DENY.

Everything emitted is bounded: source/controller/approver refs are hashed (never
echoed), and only statuses, scope, timestamps, and hashes appear — no raw account
identifiers or credentials.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any


class SourceStatus(str, Enum):
    ACTIVE = "active"
    NOT_YET_ACTIVE = "not_yet_active"
    EXPIRED = "expired"
    REVOKED = "revoked"


class SourceControllerError(ValueError):
    """Raised on a malformed source-controller grant."""


@dataclass(frozen=True)
class SourceGrant:
    source_ref: str
    controller_ref: str
    approved_by: str
    scopes: tuple[str, ...]
    granted_at: int
    expires_at: int = 0  # 0 = no expiry
    revoked_at: int = 0  # 0 = not revoked

    def __post_init__(self) -> None:
        if not self.source_ref or not self.controller_ref or not self.approved_by:
            raise SourceControllerError("source_ref, controller_ref, and approved_by are required")
        if self.approved_by == self.controller_ref:
            raise SourceControllerError("controller cannot self-approve source access")
        if not self.scopes:
            raise SourceControllerError("at least one approved scope is required")
        if len(set(self.scopes)) != len(self.scopes):
            raise SourceControllerError("scopes must be unique")
        if self.granted_at < 0 or self.expires_at < 0 or self.revoked_at < 0:
            raise SourceControllerError("timestamps must be non-negative")
        if self.expires_at and self.expires_at < self.granted_at:
            raise SourceControllerError("expires_at cannot precede granted_at")

    def status(self, now: int) -> SourceStatus:
        if self.revoked_at and now >= self.revoked_at:
            return SourceStatus.REVOKED
        if now < self.granted_at:
            return SourceStatus.NOT_YET_ACTIVE
        if self.expires_at and now >= self.expires_at:
            return SourceStatus.EXPIRED
        return SourceStatus.ACTIVE

    def audit_hash(self) -> str:
        return _sha256_json(
            {
                "source_ref_hash": _hash(self.source_ref),
                "controller_ref_hash": _hash(self.controller_ref),
                "approved_by_hash": _hash(self.approved_by),
                "scopes": sorted(self.scopes),
                "granted_at": self.granted_at,
                "expires_at": self.expires_at,
                "revoked_at": self.revoked_at,
            }
        )

    def to_public_dict(self, *, now: int | None = None) -> dict[str, Any]:
        d = {
            "source_ref_hash": _hash(self.source_ref),
            "controller_ref_hash": _hash(self.controller_ref),
            "approved_by_hash": _hash(self.approved_by),
            "scopes": sorted(self.scopes),
            "granted_at": self.granted_at,
            "expires_at": self.expires_at,
            "revoked": bool(self.revoked_at),
            "audit_hash": self.audit_hash(),
            "raw_secret_egress": False,
        }
        if now is not None:
            d["status"] = self.status(now).value
        return d


@dataclass(frozen=True)
class SourceAuthorization:
    allowed: bool
    status: str
    reason_code: str
    source_ref_hash: str
    scope: str
    audit_hash: str
    raw_secret_egress: bool = False

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "kind": "source_authorization",
            "allowed": self.allowed,
            "status": self.status,
            "reason_code": self.reason_code,
            "source_ref_hash": self.source_ref_hash,
            "scope": self.scope,
            "audit_hash": self.audit_hash,
            "raw_secret_egress": self.raw_secret_egress,
        }


class SourceControllerRegistry:
    """Registry of source-controller grants with fail-closed authorization."""

    def __init__(self, grants: tuple[SourceGrant, ...] = ()) -> None:
        by_source: dict[str, SourceGrant] = {}
        for grant in grants:
            if grant.source_ref in by_source:
                raise SourceControllerError("duplicate grant for a source_ref")
            by_source[grant.source_ref] = grant
        self._by_source = by_source

    def authorize(self, source_ref: str, scope: str, *, now: int) -> SourceAuthorization:
        source_hash = _hash(source_ref)
        grant = self._by_source.get(source_ref)
        if grant is None:
            return SourceAuthorization(False, "unknown", "no_source_grant", source_hash, scope, "")

        status = grant.status(now)
        if status != SourceStatus.ACTIVE:
            return SourceAuthorization(False, status.value, f"grant_{status.value}", source_hash, scope, grant.audit_hash())
        if scope not in grant.scopes:
            return SourceAuthorization(False, status.value, "scope_not_approved", source_hash, scope, grant.audit_hash())
        return SourceAuthorization(True, status.value, "authorized", source_hash, scope, grant.audit_hash())

    def public_manifest(self, *, now: int | None = None) -> dict[str, Any]:
        return {
            "kind": "source_controller_manifest",
            "grant_count": len(self._by_source),
            "grants": [g.to_public_dict(now=now) for g in self._by_source.values()],
            "raw_secret_egress": False,
        }


def load_source_registry(path: str | Path) -> SourceControllerRegistry:
    """Load a source-controller registry from a JSON grants file.

    Grants are validated at construction (non-self-approval, scope containment),
    so a malformed or self-approving grant file fails loudly rather than silently
    admitting bad custody.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    grants: list[SourceGrant] = []
    for item in data.get("grants", []):
        grants.append(
            SourceGrant(
                source_ref=str(item["source_ref"]),
                controller_ref=str(item["controller_ref"]),
                approved_by=str(item["approved_by"]),
                scopes=tuple(str(s) for s in item["scopes"]),
                granted_at=int(item.get("granted_at", 0)),
                expires_at=int(item.get("expires_at", 0)),
                revoked_at=int(item.get("revoked_at", 0)),
            )
        )
    return SourceControllerRegistry(tuple(grants))


def build_source_registry(settings: Any) -> SourceControllerRegistry | None:
    """Build a source registry from settings, or None if not provisioned."""
    path = getattr(settings, "source_grants_path", "")
    if not path or not Path(path).exists():
        return None
    return load_source_registry(path)


def _hash(value: str) -> str:
    return "0x" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sha256_json(value: Any) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return "0x" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
