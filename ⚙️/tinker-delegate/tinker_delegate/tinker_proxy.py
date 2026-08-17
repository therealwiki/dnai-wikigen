"""Bounded Tinker proxy credentials and status helpers.

The Tinker proxy is the intended public surface for Tinker operations. The CVM
keeps the upstream Tinker API key, project id, base URL, browser session, and
payment state sealed; approved users receive only scoped delegate tokens and
bounded operation receipts.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from eth_account import Account
from eth_account.messages import encode_defunct

from tinker_delegate.api_key_store import resolve_api_key
from tinker_delegate.chain_submitter import normalize_address
from tinker_delegate.crypto import _derive_aes_key, encrypt_for_tee
from tinker_delegate.dstack_utils import derive_storage_key, is_dstack_enabled
from tinker_delegate.run_metadata_store import stable_hash
from tinker_delegate.tinker_client_config_store import resolve_tinker_client_config
from tinker_delegate.tinker_proxy_store import (
    build_proxy_token_store,
    make_proxy_token_issue_record,
)


PROXY_TOKEN_HKDF_INFO = b"tinker-delegate-proxy-token"
SUPPORTED_PROXY_SCOPES = {
    "proxy:status",
    "tinker:smoke",
    "tinker:train",
    "billing:balance",
    "billing:payment-method-status",
    "billing:add-balance",
}
SPEND_LIMIT_PROXY_SCOPES = frozenset({"billing:add-balance", "tinker:smoke", "tinker:train"})


def generate_proxy_recipient_keypair() -> tuple[str, str]:
    """Generate a recipient X25519 keypair for encrypted proxy-token delivery."""

    private_key = X25519PrivateKey.generate()
    private_key_hex = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    ).hex()
    public_key_hex = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()
    return private_key_hex, public_key_hex


def decrypt_encrypted_proxy_token(payload: dict[str, Any], recipient_private_key_hex: str) -> str:
    """Decrypt an encrypted proxy-token issuance response with the recipient key."""

    private_key = X25519PrivateKey.from_private_bytes(bytes.fromhex(recipient_private_key_hex))
    encrypted = payload["encrypted_token"]
    sender_public = X25519PublicKey.from_public_bytes(bytes.fromhex(encrypted["ephemeral_public_key"]))
    shared_secret = private_key.exchange(sender_public)
    aes_key = _derive_aes_key(shared_secret, info=PROXY_TOKEN_HKDF_INFO)
    plaintext = AESGCM(aes_key).decrypt(
        bytes.fromhex(encrypted["nonce"]),
        bytes.fromhex(encrypted["ciphertext"]),
        bytes.fromhex(payload["associated_data"]),
    )
    return plaintext.decode("utf-8")


@dataclass(frozen=True)
class ProxyTokenClaims:
    subject: str
    scopes: tuple[str, ...]
    issued_at: int
    expires_at: int
    jwt_id: str
    issuer: str
    audience: str
    scope_limits: dict[str, dict[str, float]]

    def to_jwt_payload(self) -> dict[str, Any]:
        payload = {
            "iss": self.issuer,
            "aud": self.audience,
            "sub": self.subject,
            "scope": " ".join(self.scopes),
            "iat": self.issued_at,
            "nbf": self.issued_at,
            "exp": self.expires_at,
            "jti": self.jwt_id,
        }
        if self.scope_limits:
            payload["limits"] = self.scope_limits
        return payload

    def to_public_dict(self) -> dict[str, Any]:
        public = {
            "subject_hash": stable_hash(self.subject, prefix="proxy_subject"),
            "scopes": list(self.scopes),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "ttl_seconds": max(0, self.expires_at - self.issued_at),
            "jwt_id_hash": stable_hash(self.jwt_id, prefix="proxy_jti"),
        }
        if self.scope_limits:
            public["scope_limits"] = self.scope_limits
        return public


def build_tinker_proxy_status(settings) -> dict[str, Any]:
    """Return bounded evidence about the sealed Tinker proxy configuration."""

    api_key_configured = bool(resolve_api_key(settings))
    client_config = resolve_tinker_client_config(settings)
    project_id = client_config["project_id"]
    base_url = client_config["base_url"]
    return {
        "surface": "tinker_proxy",
        "schema_version": 1,
        "success": api_key_configured,
        "proxy_boundary": {
            "mode": "tee_cvm_delegate" if is_dstack_enabled() else "local_or_unattested_delegate",
            "sdk_client_created_inside_delegate": True,
            "jwt_signing_key_source": _signing_key_source(settings),
            "raw_credentials_returned": False,
            "raw_project_id_returned": False,
            "raw_secret_egress": False,
        },
        "sealed_client_config": {
            "api_key_configured": api_key_configured,
            "api_key_returned": False,
            "project_id_configured": bool(project_id),
            "project_id_hash": stable_hash(project_id, prefix="tinker_project") if project_id else "",
            "project_id_returned": False,
            "base_url_configured": bool(base_url),
            "base_url_host_family": _base_url_host_family(base_url),
            "base_url_hash": stable_hash(base_url, prefix="tinker_base_url") if base_url else "",
            "base_url_returned": False,
        },
        "token_issuer": {
            "enabled": bool(getattr(settings, "allow_tinker_proxy_token_issuance", False)),
            "format": "jwt_hs256",
            "delivery": "x25519_aes_256_gcm_envelope",
            "audit_store": "sealed",
            "issue_policy_required": bool(getattr(settings, "proxy_require_issue_policy", False)),
            "issue_policy_configured": bool(getattr(settings, "proxy_issue_policy_path", "")),
            "deployment_policy_required": bool(getattr(settings, "proxy_require_deployment_policy", False)),
            "grant_lifecycle_required": bool(getattr(settings, "proxy_require_grant_lifecycle", False)),
            "grant_lifecycle_signature_required": bool(
                getattr(settings, "proxy_require_grant_lifecycle_signature", False)
            ),
            "identity_registry_required": bool(getattr(settings, "proxy_require_identity_registry", False)),
            "identity_registry_configured": bool(getattr(settings, "proxy_identity_registry_path", "")),
            "identity_registry_signature_required": bool(
                getattr(settings, "proxy_require_identity_registry_signature", False)
            ),
            "identity_registry_signer_configured": bool(
                getattr(settings, "proxy_identity_registry_signer", "")
            ),
            "encumbrance_contract_configured": bool(getattr(settings, "encumbrance_contract_address", "")),
            "encumbrance_compose_hash_configured": bool(getattr(settings, "encumbrance_compose_hash", "")),
            "plaintext_token_returned": False,
            "supported_scopes": sorted(SUPPORTED_PROXY_SCOPES),
        },
        "allowed_proxy_operations": [
            {
                "operation": "status",
                "enabled": True,
                "bounded_output": True,
                "raw_secret_egress": False,
            },
            {
                "operation": "tinker_sdk_smoke",
                "enabled": bool(getattr(settings, "allow_tinker_smoke_endpoint", False)),
                "bounded_output": True,
                "raw_secret_egress": False,
            },
            {
                "operation": "add_balance",
                "enabled": bool(getattr(settings, "allow_add_balance_endpoint", False)),
                "bounded_output": True,
                "raw_secret_egress": False,
            },
        ],
        "next_required_configuration": _next_required_configuration(
            api_key_configured=api_key_configured,
            project_id_configured=bool(project_id),
        ),
        "raw_secret_egress": False,
    }


def issue_encrypted_proxy_token(
    settings,
    *,
    subject: str,
    scopes: list[str] | tuple[str, ...],
    recipient_public_key_hex: str,
    ttl_seconds: int | None = None,
    now: int | None = None,
) -> dict[str, Any]:
    """Issue a scoped JWT and encrypt it to the approved recipient public key."""

    subject = _normalize_subject(subject)
    normalized_scopes = _normalize_scopes(scopes)
    normalized_ttl = _normalize_ttl(settings, ttl_seconds)
    _validate_approved_subject(settings, subject)
    recipient_public_key = _decode_x25519_public_key(recipient_public_key_hex)
    recipient_public_key_hash = stable_hash(
        recipient_public_key_hex.lower(),
        prefix="proxy_recipient_public_key",
    )
    policy_binding = _validate_proxy_issue_policy(
        settings,
        subject=subject,
        scopes=normalized_scopes,
        recipient_public_key_hash=recipient_public_key_hash,
        ttl_seconds=normalized_ttl,
        now=now,
    )
    deployment_binding = _validate_proxy_deployment_policy(
        settings,
        scopes=normalized_scopes,
        policy_binding=policy_binding,
    )
    if deployment_binding.get("required"):
        policy_binding = {
            **policy_binding,
            "deployment_policy": deployment_binding,
        }
    claims, token = issue_proxy_token(
        settings,
        subject=subject,
        scopes=normalized_scopes,
        ttl_seconds=normalized_ttl,
        now=now,
        scope_limits=policy_binding.get("scope_limits", {}),
    )
    associated_data = _proxy_token_associated_data(claims)
    envelope = encrypt_for_tee(
        token.encode("utf-8"),
        recipient_public_key,
        info=PROXY_TOKEN_HKDF_INFO,
        associated_data=associated_data,
    )
    audit_record = build_proxy_token_store(settings).append(
        make_proxy_token_issue_record(
            subject_hash=claims.to_public_dict()["subject_hash"],
            jwt_id_hash=claims.to_public_dict()["jwt_id_hash"],
            recipient_public_key_hash=recipient_public_key_hash,
            scopes=list(claims.scopes),
            issued_at=claims.issued_at,
            expires_at=claims.expires_at,
        )
    )
    return {
        "surface": "tinker_proxy_token",
        "schema_version": 1,
        "success": True,
        "delivery": "x25519_aes_256_gcm_envelope",
        "encrypted_token": envelope.to_hex(),
        "associated_data": associated_data.hex(),
        "token": claims.to_public_dict(),
        "recipient_public_key_hash": recipient_public_key_hash,
        "policy_binding": policy_binding,
        "associated_data_hash": stable_hash(
            associated_data.hex(),
            prefix="proxy_token_aad",
        ),
        "audit_record": audit_record,
        "plaintext_token_returned": False,
        "raw_secret_egress": False,
    }


def save_proxy_issue_policy(settings, policy: dict[str, Any]) -> dict[str, Any]:
    """Persist a canonical hash-only proxy issue policy in delegate storage."""

    path = _proxy_issue_policy_path(settings, required=True)
    normalized = normalize_proxy_issue_policy(policy)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(_canonical_json(normalized), encoding="utf-8")
    tmp_path.replace(path)
    return summarize_proxy_issue_policy(
        normalized,
        configured=True,
        required=bool(getattr(settings, "proxy_require_issue_policy", False)),
    )


def get_proxy_issue_policy_status(settings) -> dict[str, Any]:
    """Return bounded status for the configured proxy issue policy."""

    policy_path = _proxy_issue_policy_path(settings, required=False)
    if policy_path is None:
        return {
            "surface": "tinker_proxy_issue_policy",
            "schema_version": 1,
            "success": True,
            "required": bool(getattr(settings, "proxy_require_issue_policy", False)),
            "path_configured": False,
            "policy_present": False,
            "grant_count": 0,
            "raw_secret_egress": False,
        }
    if not policy_path.exists():
        return {
            "surface": "tinker_proxy_issue_policy",
            "schema_version": 1,
            "success": True,
            "required": bool(getattr(settings, "proxy_require_issue_policy", False)),
            "path_configured": True,
            "policy_present": False,
            "grant_count": 0,
            "raw_secret_egress": False,
        }
    policy = _load_proxy_issue_policy(str(policy_path))
    return summarize_proxy_issue_policy(
        policy,
        configured=True,
        required=bool(getattr(settings, "proxy_require_issue_policy", False)),
    )


def save_proxy_identity_registry(settings, registry: dict[str, Any]) -> dict[str, Any]:
    """Persist a normalized hash-only identity registry and return bounded status."""

    path = _proxy_identity_registry_path(settings, required=True)
    assert path is not None
    normalized = _normalize_proxy_identity_registry(registry)
    if bool(getattr(settings, "proxy_require_identity_registry_signature", False)):
        _validate_proxy_identity_registry_signature(settings, normalized)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_canonical_json(normalized) + "\n", encoding="utf-8")
    return summarize_proxy_identity_registry(
        normalized,
        configured=True,
        required=bool(getattr(settings, "proxy_require_identity_registry", False)),
        settings=settings,
    )


def get_proxy_identity_registry_status(settings) -> dict[str, Any]:
    """Return bounded status for the configured proxy identity registry."""

    registry_path = _proxy_identity_registry_path(settings, required=False)
    required = bool(getattr(settings, "proxy_require_identity_registry", False))
    if registry_path is None:
        return {
            "surface": "tinker_proxy_identity_registry",
            "success": True,
            "configured": False,
            "required": required,
            "registry_present": False,
            "raw_secret_egress": False,
        }
    if not registry_path.exists():
        return {
            "surface": "tinker_proxy_identity_registry",
            "success": True,
            "configured": True,
            "required": required,
            "registry_present": False,
            "raw_secret_egress": False,
        }
    registry = _load_proxy_identity_registry(str(registry_path))
    return summarize_proxy_identity_registry(
        registry,
        configured=True,
        required=required,
        settings=settings,
    )


def summarize_proxy_identity_registry(
    registry: dict[str, Any],
    *,
    configured: bool = True,
    required: bool = True,
    settings=None,
) -> dict[str, Any]:
    """Summarize a proxy identity registry without exposing raw identities."""

    normalized = _normalize_proxy_identity_registry(registry)
    unsigned = _proxy_identity_registry_unsigned(normalized)
    signature_present = isinstance(normalized.get("signature"), dict)
    signature_binding: dict[str, Any] = {
        "required": bool(getattr(settings, "proxy_require_identity_registry_signature", False)) if settings else False,
        "configured": signature_present,
        "raw_secret_egress": False,
    }
    if signature_present and settings is not None:
        try:
            signature_binding = _validate_proxy_identity_registry_signature(settings, normalized)
        except ValueError as exc:
            if bool(getattr(settings, "proxy_require_identity_registry_signature", False)):
                raise
            signature_binding = {
                "required": False,
                "configured": True,
                "verified": False,
                "error_hash": stable_hash(str(exc), prefix="proxy_identity_registry_signature_error"),
                "raw_secret_egress": False,
            }
    return {
        "surface": "tinker_proxy_identity_registry",
        "success": True,
        "configured": configured,
        "required": required,
        "registry_present": True,
        "registry_hash": _proxy_identity_registry_hash(unsigned),
        "identity_count": len(unsigned.get("identities", [])),
        "role_counts": _proxy_identity_registry_role_counts(unsigned),
        "signature_binding": signature_binding,
        "raw_secret_egress": False,
    }


def summarize_proxy_issue_policy(policy: dict[str, Any], *, configured: bool = True, required: bool = True) -> dict[str, Any]:
    """Return bounded policy summary without raw identities or credentials."""

    normalized = normalize_proxy_issue_policy(policy)
    grants = normalized["grants"]
    return {
        "surface": "tinker_proxy_issue_policy",
        "schema_version": 1,
        "success": True,
        "required": required,
        "path_configured": configured,
        "policy_present": True,
        "policy_hash": stable_hash(_canonical_json(normalized), prefix="proxy_issue_policy"),
        "grant_count": len(grants),
        "grants": [
            {
                "grant_hash": stable_hash(_canonical_json(grant), prefix="proxy_issue_grant"),
                "subject_hash": grant["subject_hash"],
                "recipient_public_key_hash": grant["recipient_public_key_hash"],
                "scopes": grant["scopes"],
                "scope_limits": grant.get("scope_limits", {}),
                "lifecycle": _public_proxy_grant_lifecycle(grant.get("lifecycle", {})),
                "max_ttl_seconds": grant["max_ttl_seconds"],
                "raw_secret_egress": False,
            }
            for grant in grants
        ],
        "raw_secret_egress": False,
    }


def normalize_proxy_issue_policy(policy: dict[str, Any]) -> dict[str, Any]:
    """Validate and canonicalize a hash-only proxy issue policy."""

    if not isinstance(policy, dict):
        raise ValueError("proxy issue policy must be an object")
    if policy.get("schema_version") != 1:
        raise ValueError("proxy issue policy schema_version must be 1")
    grants = policy.get("grants")
    if not isinstance(grants, list):
        raise ValueError("proxy issue policy grants must be a list")
    normalized_grants: list[dict[str, Any]] = []
    for grant in grants:
        if not isinstance(grant, dict):
            raise ValueError("proxy issue policy grant must be an object")
        grant_scopes_raw = grant.get("scopes", [])
        if not isinstance(grant_scopes_raw, list) or not all(isinstance(scope, str) for scope in grant_scopes_raw):
            raise ValueError("proxy issue policy grant scopes must be strings")
        grant_scopes = list(_normalize_scopes(tuple(grant_scopes_raw)))
        max_ttl = int(grant.get("max_ttl_seconds", 0) or 0)
        if max_ttl <= 0:
            raise ValueError("proxy issue policy grant ttl cap is required")
        scope_limits = _normalize_scope_limits(
            grant.get("scope_limits", {}),
            set(grant_scopes),
            require_spend_limits=True,
        )
        normalized_grant: dict[str, Any] = {
            "subject_hash": _normalize_hex_hash(str(grant.get("subject_hash", "")), "subject_hash"),
            "recipient_public_key_hash": _normalize_hex_hash(
                str(grant.get("recipient_public_key_hash", "")),
                "recipient_public_key_hash",
            ),
            "scopes": grant_scopes,
            "max_ttl_seconds": max_ttl,
        }
        if scope_limits:
            normalized_grant["scope_limits"] = scope_limits
        lifecycle = _normalize_proxy_grant_lifecycle(grant.get("lifecycle"))
        if lifecycle:
            normalized_grant["lifecycle"] = lifecycle
        normalized_grants.append(normalized_grant)
    return {
        "schema_version": 1,
        "grants": sorted(
            normalized_grants,
            key=lambda item: (
                item["subject_hash"],
                item["recipient_public_key_hash"],
                ",".join(item["scopes"]),
            ),
        ),
    }


def issue_proxy_token(
    settings,
    *,
    subject: str,
    scopes: list[str] | tuple[str, ...],
    ttl_seconds: int | None = None,
    now: int | None = None,
    scope_limits: dict[str, dict[str, float]] | None = None,
) -> tuple[ProxyTokenClaims, str]:
    """Issue a scoped JWT signed by CVM-derived or explicit local key material."""

    subject = _normalize_subject(subject)
    normalized_scopes = _normalize_scopes(scopes)
    issued_at = int(time.time() if now is None else now)
    ttl = _normalize_ttl(settings, ttl_seconds)
    claims = ProxyTokenClaims(
        subject=subject,
        scopes=normalized_scopes,
        issued_at=issued_at,
        expires_at=issued_at + ttl,
        jwt_id=str(uuid.uuid4()),
        issuer=getattr(settings, "proxy_jwt_issuer", "") or "dnai-wikigen:tinker-proxy",
        audience=getattr(settings, "proxy_jwt_audience", "") or "dnai-wikigen:tinker-delegate",
        scope_limits=_normalize_scope_limits(scope_limits or {}, set(normalized_scopes), require_spend_limits=False),
    )
    token = _encode_jwt(claims.to_jwt_payload(), _proxy_signing_key(settings))
    return claims, token


def verify_proxy_token(
    settings,
    token: str,
    *,
    required_scope: str = "",
    now: int | None = None,
) -> dict[str, Any]:
    """Verify a scoped proxy JWT without returning the raw subject or token."""

    payload = _decode_jwt(token, _proxy_signing_key(settings))
    current = int(time.time() if now is None else now)
    issuer = getattr(settings, "proxy_jwt_issuer", "") or "dnai-wikigen:tinker-proxy"
    audience = getattr(settings, "proxy_jwt_audience", "") or "dnai-wikigen:tinker-delegate"
    if payload.get("iss") != issuer:
        raise ValueError("proxy token issuer mismatch")
    if payload.get("aud") != audience:
        raise ValueError("proxy token audience mismatch")
    if current < int(payload.get("nbf", 0)):
        raise ValueError("proxy token not yet valid")
    if current >= int(payload.get("exp", 0)):
        raise ValueError("proxy token expired")
    scopes = tuple(str(payload.get("scope", "")).split())
    if required_scope and required_scope not in scopes:
        raise ValueError("proxy token missing required scope")
    subject = str(payload.get("sub", ""))
    jwt_id = str(payload.get("jti", ""))
    jwt_id_hash = stable_hash(jwt_id, prefix="proxy_jti")
    if jwt_id_hash in build_proxy_token_store(settings).revoked_token_hashes():
        raise ValueError("proxy token revoked")
    return {
        "valid": True,
        "subject_hash": stable_hash(subject, prefix="proxy_subject"),
        "jwt_id_hash": jwt_id_hash,
        "scopes": list(scopes),
        "scope_limits": _normalize_scope_limits(payload.get("limits", {}), set(scopes), require_spend_limits=False),
        "expires_at": int(payload["exp"]),
        "raw_secret_egress": False,
    }


def _encode_jwt(payload: dict[str, Any], key: bytes) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    signing_input = b".".join(
        [
            _b64url_json(header),
            _b64url_json(payload),
        ]
    )
    signature = hmac.new(key, signing_input, hashlib.sha256).digest()
    return (signing_input + b"." + _b64url(signature)).decode("ascii")


def _decode_jwt(token: str, key: bytes) -> dict[str, Any]:
    if not isinstance(token, str) or len(token) > 4096:
        raise ValueError("invalid proxy token format")
    parts = token.split(".")
    if len(parts) != 3 or any(not part for part in parts):
        raise ValueError("invalid proxy token format")
    try:
        signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("invalid proxy token format") from exc
    try:
        supplied = _b64url_decode(parts[2])
    except ValueError as exc:
        raise ValueError("invalid proxy token signature") from exc
    expected = hmac.new(key, signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(supplied, expected):
        raise ValueError("invalid proxy token signature")
    header = json.loads(_b64url_decode(parts[0]))
    if header.get("alg") != "HS256" or header.get("typ") != "JWT":
        raise ValueError("unsupported proxy token header")
    payload = json.loads(_b64url_decode(parts[1]))
    if not isinstance(payload, dict):
        raise ValueError("invalid proxy token payload")
    return payload


def _proxy_signing_key(settings) -> bytes:
    explicit = getattr(settings, "proxy_jwt_key", "")
    if explicit:
        return hashlib.sha256(bytes.fromhex(explicit)).digest()
    if is_dstack_enabled():
        return hashlib.sha256(
            b"tinker-proxy-jwt:" + derive_storage_key(getattr(settings, "proxy_jwt_key_path", "tinker/proxy_jwt"))
        ).digest()
    env_key = os.environ.get("TINKER_PROXY_JWT_KEY", "")
    if env_key:
        return hashlib.sha256(bytes.fromhex(env_key)).digest()
    raise ValueError("proxy JWT signing key unavailable outside dstack")


def _validate_approved_subject(settings, subject: str) -> None:
    approved = [
        item.strip()
        for item in str(getattr(settings, "proxy_approved_subjects", "") or "").split(",")
        if item.strip()
    ]
    if approved and subject.strip() not in approved:
        raise ValueError("proxy token subject is not approved")


def _validate_proxy_issue_policy(
    settings,
    *,
    subject: str,
    scopes: tuple[str, ...],
    recipient_public_key_hash: str,
    ttl_seconds: int,
    now: int | None = None,
) -> dict[str, Any]:
    policy_path = str(getattr(settings, "proxy_issue_policy_path", "") or "").strip()
    require_policy = bool(getattr(settings, "proxy_require_issue_policy", False))
    if not policy_path:
        if require_policy:
            raise ValueError("proxy issue policy is required")
        return {
            "required": False,
            "configured": False,
            "raw_secret_egress": False,
        }

    policy = _load_proxy_issue_policy(policy_path)
    grants = policy.get("grants")
    if not isinstance(grants, list):
        raise ValueError("proxy issue policy grants must be a list")
    subject_hash = stable_hash(subject, prefix="proxy_subject")
    requested_scopes = set(scopes)
    policy_hash = stable_hash(_canonical_json(policy), prefix="proxy_issue_policy")
    lifecycle_required = bool(getattr(settings, "proxy_require_grant_lifecycle", False))
    now_int = int(time.time() if now is None else now)
    ttl_cap_fail = False
    lifecycle_fail = ""

    for grant in grants:
        if not isinstance(grant, dict):
            raise ValueError("proxy issue policy grant must be an object")
        grant_subject_hash = str(grant.get("subject_hash", "")).lower()
        grant_recipient_hash = str(grant.get("recipient_public_key_hash", "")).lower()
        grant_scopes = grant.get("scopes", [])
        if not isinstance(grant_scopes, list) or not all(isinstance(scope, str) for scope in grant_scopes):
            raise ValueError("proxy issue policy grant scopes must be strings")
        normalized_grant_scopes = set(_normalize_scopes(tuple(grant_scopes)))
        if grant_subject_hash != subject_hash or grant_recipient_hash != recipient_public_key_hash:
            continue
        if not requested_scopes.issubset(normalized_grant_scopes):
            continue
        max_ttl = int(grant.get("max_ttl_seconds", 0) or 0)
        if max_ttl <= 0:
            raise ValueError("proxy issue policy grant ttl cap is required")
        if ttl_seconds > max_ttl:
            ttl_cap_fail = True
            continue
        scope_limits = _normalize_scope_limits(
            grant.get("scope_limits", {}),
            requested_scopes,
            require_spend_limits=True,
        )
        try:
            grant_lifecycle = _validate_proxy_grant_lifecycle(
                grant.get("lifecycle", {}),
                grant=grant,
                required=lifecycle_required,
                signature_required=bool(getattr(settings, "proxy_require_grant_lifecycle_signature", False)),
                now=now_int,
            )
        except ValueError as exc:
            lifecycle_fail = str(exc)
            continue
        identity_binding = _validate_proxy_identity_registry(
            settings,
            subject_hash=subject_hash,
            grant_lifecycle=grant_lifecycle,
            now=now_int,
        )
        return {
            "required": True,
            "configured": True,
            "policy_hash": policy_hash,
            "grant_hash": stable_hash(_canonical_json(grant), prefix="proxy_issue_grant"),
            "subject_hash": subject_hash,
            "recipient_public_key_hash": recipient_public_key_hash,
            "requested_scopes": list(scopes),
            "granted_scopes": sorted(normalized_grant_scopes),
            "scope_limits": scope_limits,
            "grant_lifecycle": grant_lifecycle,
            "identity_binding": identity_binding,
            "max_ttl_seconds": max_ttl,
            "ttl_seconds": ttl_seconds,
            "raw_secret_egress": False,
        }
    if ttl_cap_fail:
        raise ValueError("proxy token ttl exceeds policy cap")
    if lifecycle_fail:
        raise ValueError(lifecycle_fail)
    raise ValueError("proxy token issuance is not allowed by policy")


def _validate_proxy_deployment_policy(
    settings,
    *,
    scopes: tuple[str, ...],
    policy_binding: dict[str, Any],
) -> dict[str, Any]:
    require_policy = bool(getattr(settings, "proxy_require_deployment_policy", False))
    if not require_policy:
        return {
            "required": False,
            "raw_secret_egress": False,
        }

    from tinker_delegate.tinker_encumbrance import (
        TinkerOperationKind,
        preflight_tinker_operation,
    )

    checks: list[dict[str, Any]] = []
    for operation_kind, amount_dollars in _proxy_deployment_operations(scopes, policy_binding):
        result = preflight_tinker_operation(
            settings,
            operation_kind=operation_kind,
            amount_dollars=amount_dollars,
            required=True,
        ).to_public_dict()
        checks.append(result)
        if not result.get("allowed"):
            raise ValueError(f"proxy deployment policy denied token issuance: {result.get('reason')}")

    return {
        "required": True,
        "checked": bool(checks),
        "checks": checks,
        "raw_secret_egress": False,
    }


def _proxy_deployment_operations(
    scopes: tuple[str, ...],
    policy_binding: dict[str, Any],
) -> list[tuple[Any, float]]:
    from tinker_delegate.tinker_encumbrance import TinkerOperationKind

    scope_set = set(scopes)
    operations: list[tuple[Any, float]] = []
    if "billing:add-balance" in scope_set:
        operations.append(
            (
                TinkerOperationKind.ADD_BALANCE,
                _scope_limit_amount(policy_binding, "billing:add-balance"),
            )
        )
    if "tinker:smoke" in scope_set:
        operations.append(
            (
                TinkerOperationKind.SPEND_TINKER_COMPUTE,
                _scope_limit_amount(policy_binding, "tinker:smoke"),
            )
        )
    if "tinker:train" in scope_set:
        operations.append(
            (
                TinkerOperationKind.SPEND_TINKER_COMPUTE,
                _scope_limit_amount(policy_binding, "tinker:train"),
            )
        )
    if not operations:
        operations.append((TinkerOperationKind.MANUAL_PREFUND, 0.0))
    return operations


def _scope_limit_amount(policy_binding: dict[str, Any], scope: str) -> float:
    limits = policy_binding.get("scope_limits", {})
    if not isinstance(limits, dict):
        raise ValueError("proxy deployment policy requires bounded scope limits")
    scope_limits = limits.get(scope, {})
    if not isinstance(scope_limits, dict) or "max_amount_usd" not in scope_limits:
        raise ValueError("proxy deployment policy requires bounded spend cap")
    try:
        amount = float(scope_limits["max_amount_usd"])
    except (TypeError, ValueError) as exc:
        raise ValueError("proxy deployment policy spend cap must be numeric") from exc
    if amount <= 0:
        raise ValueError("proxy deployment policy spend cap must be positive")
    return amount


def _normalize_proxy_grant_lifecycle(raw_lifecycle: Any) -> dict[str, Any]:
    if raw_lifecycle in (None, ""):
        return {}
    if not isinstance(raw_lifecycle, dict):
        raise ValueError("proxy issue policy grant lifecycle must be an object")
    status = str(raw_lifecycle.get("status", "")).strip().lower()
    if status not in {"active", "pending", "revoked", "expired"}:
        raise ValueError("proxy issue policy grant lifecycle status is invalid")
    lifecycle: dict[str, Any] = {"status": status}
    approved_by_hash = str(raw_lifecycle.get("approved_by_hash", "") or "").strip()
    if approved_by_hash:
        lifecycle["approved_by_hash"] = _normalize_hex_hash(
            approved_by_hash,
            "approved_by_hash",
        )
    approval_event_hash = str(raw_lifecycle.get("approval_event_hash", "") or "").strip()
    if approval_event_hash:
        lifecycle["approval_event_hash"] = _normalize_hex_hash(
            approval_event_hash,
            "approval_event_hash",
        )
    approved_at = int(raw_lifecycle.get("approved_at", 0) or 0)
    expires_at = int(raw_lifecycle.get("expires_at", 0) or 0)
    if approved_at:
        lifecycle["approved_at"] = approved_at
    if expires_at:
        lifecycle["expires_at"] = expires_at
    if "approval_signature" in raw_lifecycle:
        lifecycle["approval_signature"] = _normalize_proxy_grant_lifecycle_signature_block(
            raw_lifecycle.get("approval_signature")
        )
    if status == "active":
        if "approved_by_hash" not in lifecycle:
            raise ValueError("proxy issue policy active grant lifecycle requires approved_by_hash")
        if approved_at <= 0:
            raise ValueError("proxy issue policy active grant lifecycle requires approved_at")
        if expires_at <= 0:
            raise ValueError("proxy issue policy active grant lifecycle requires expires_at")
        if expires_at <= approved_at:
            raise ValueError("proxy issue policy active grant lifecycle expires before approval")
    return lifecycle


def _validate_proxy_grant_lifecycle(
    lifecycle: dict[str, Any],
    *,
    grant: dict[str, Any],
    required: bool,
    signature_required: bool,
    now: int,
) -> dict[str, Any]:
    if not lifecycle:
        if required:
            raise ValueError("proxy issue policy grant lifecycle is required")
        return {}
    normalized = _normalize_proxy_grant_lifecycle(lifecycle)
    if normalized.get("status") != "active":
        raise ValueError("proxy issue policy grant lifecycle is not active")
    approved_at = int(normalized.get("approved_at", 0) or 0)
    expires_at = int(normalized.get("expires_at", 0) or 0)
    if approved_at > now:
        raise ValueError("proxy issue policy grant lifecycle is not active yet")
    if expires_at <= now:
        raise ValueError("proxy issue policy grant lifecycle expired")
    signature_binding = _validate_proxy_grant_lifecycle_signature(
        grant,
        normalized,
        required=signature_required,
    )
    return {
        **_public_proxy_grant_lifecycle(normalized),
        "approval_signature_binding": signature_binding,
        "checked": True,
        "raw_secret_egress": False,
    }


def _public_proxy_grant_lifecycle(lifecycle: dict[str, Any]) -> dict[str, Any]:
    """Return lifecycle evidence with raw signatures and signer addresses removed."""

    if not lifecycle:
        return {}
    public = {
        field: lifecycle[field]
        for field in ("status", "approved_by_hash", "approval_event_hash", "approved_at", "expires_at")
        if field in lifecycle
    }
    signature = lifecycle.get("approval_signature")
    if isinstance(signature, dict):
        public["approval_signature"] = {
            "kind": signature.get("kind", "ethereum_signed_message"),
            "approval_hash": str(signature.get("approval_hash", "") or ""),
            "signer_hash": stable_hash(
                str(signature.get("signer", "")).lower(),
                prefix="proxy_grant_lifecycle_signer",
            )
            if signature.get("signer")
            else "",
            "signature_hash": stable_hash(
                str(signature.get("signature", "")),
                prefix="proxy_grant_lifecycle_signature",
            )
            if signature.get("signature")
            else "",
            "signature_returned": False,
            "signer_address_returned": False,
            "raw_secret_egress": False,
        }
    return public


def _normalize_proxy_grant_lifecycle_signature_block(raw_signature: Any) -> dict[str, str]:
    if not isinstance(raw_signature, dict):
        raise ValueError("proxy issue policy grant lifecycle signature must be an object")
    kind = str(raw_signature.get("kind", "")).strip().lower()
    if kind not in {"ethereum_signed_message", "ethereum_personal_sign"}:
        raise ValueError("proxy issue policy grant lifecycle signature kind is invalid")
    signer = normalize_address(str(raw_signature.get("signer", "")))
    signature = str(raw_signature.get("signature", "")).strip().lower()
    if signature.startswith("0x"):
        signature_hex = signature[2:]
    else:
        signature_hex = signature
    if len(signature_hex) != 130:
        raise ValueError("proxy issue policy grant lifecycle signature must be 65 bytes")
    try:
        bytes.fromhex(signature_hex)
    except ValueError as exc:
        raise ValueError("proxy issue policy grant lifecycle signature must be hex") from exc
    approval_hash = str(raw_signature.get("approval_hash", "") or "").strip().lower()
    if approval_hash:
        approval_hash = _normalize_hex_hash(
            approval_hash[2:] if approval_hash.startswith("0x") else approval_hash,
            "approval_hash",
        )
    return {
        "kind": "ethereum_signed_message",
        "signer": signer,
        "approval_hash": approval_hash,
        "signature": "0x" + signature_hex,
    }


def _proxy_grant_lifecycle_unsigned(lifecycle: dict[str, Any]) -> dict[str, Any]:
    return {
        field: lifecycle[field]
        for field in ("status", "approved_by_hash", "approval_event_hash", "approved_at", "expires_at")
        if field in lifecycle
    }


def _proxy_grant_approval_payload(grant: dict[str, Any], lifecycle: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "subject_hash": grant["subject_hash"],
        "recipient_public_key_hash": grant["recipient_public_key_hash"],
        "scopes": list(grant["scopes"]),
        "scope_limits": grant.get("scope_limits", {}),
        "max_ttl_seconds": int(grant["max_ttl_seconds"]),
        "lifecycle": _proxy_grant_lifecycle_unsigned(lifecycle),
    }


def _proxy_grant_approval_hash(grant: dict[str, Any], lifecycle: dict[str, Any]) -> str:
    return stable_hash(
        _canonical_json(_proxy_grant_approval_payload(grant, lifecycle)),
        prefix="proxy_grant_lifecycle_approval",
    )


def _validate_proxy_grant_lifecycle_signature(
    grant: dict[str, Any],
    lifecycle: dict[str, Any],
    *,
    required: bool,
) -> dict[str, Any]:
    signature_block = lifecycle.get("approval_signature")
    if not signature_block:
        if required:
            raise ValueError("proxy issue policy grant lifecycle signature is required")
        return {
            "required": required,
            "configured": False,
            "raw_secret_egress": False,
        }

    approval_hash = _proxy_grant_approval_hash(grant, lifecycle)
    signed_hash = str(signature_block.get("approval_hash", "") or "").strip().lower()
    if signed_hash and signed_hash != approval_hash:
        raise ValueError("proxy issue policy grant lifecycle signature hash mismatch")
    try:
        recovered = Account.recover_message(
            encode_defunct(hexstr="0x" + approval_hash),
            signature=signature_block["signature"],
        )
        recovered_normalized = normalize_address(recovered)
    except Exception as exc:
        raise ValueError("proxy issue policy grant lifecycle signature is invalid") from exc
    declared_signer = normalize_address(str(signature_block.get("signer", "")))
    if recovered_normalized != declared_signer:
        raise ValueError("proxy issue policy grant lifecycle signer mismatch")
    reviewer_hash = stable_hash(recovered_normalized, prefix="proxy_grant_reviewer")
    if reviewer_hash != lifecycle.get("approved_by_hash"):
        raise ValueError("proxy issue policy grant lifecycle signer is not the approved reviewer")
    return {
        "required": required,
        "configured": True,
        "verified": True,
        "kind": signature_block["kind"],
        "approval_hash": approval_hash,
        "signer_hash": stable_hash(
            recovered_normalized,
            prefix="proxy_grant_lifecycle_signer",
        ),
        "signature_hash": stable_hash(
            signature_block["signature"],
            prefix="proxy_grant_lifecycle_signature",
        ),
        "raw_secret_egress": False,
    }

def _validate_proxy_identity_registry(
    settings,
    *,
    subject_hash: str,
    grant_lifecycle: dict[str, Any],
    now: int,
) -> dict[str, Any]:
    required = bool(getattr(settings, "proxy_require_identity_registry", False))
    registry_path = str(getattr(settings, "proxy_identity_registry_path", "") or "").strip()
    if not registry_path:
        if required:
            raise ValueError("proxy identity registry is required")
        return {
            "required": False,
            "configured": False,
            "raw_secret_egress": False,
        }
    registry = _load_proxy_identity_registry(registry_path)
    signature_binding = _validate_proxy_identity_registry_signature(settings, registry)
    subject = _find_active_proxy_identity(
        registry,
        subject_hash,
        allowed_roles={"user", "agent", "operator_validation"},
        label="subject",
        now=now,
    )
    lifecycle = grant_lifecycle or {}
    reviewer_hash = str(lifecycle.get("approved_by_hash", "") or "").strip().lower()
    if not reviewer_hash:
        raise ValueError("proxy identity registry requires grant lifecycle reviewer hash")
    reviewer = _find_active_proxy_identity(
        registry,
        reviewer_hash,
        allowed_roles={"reviewer", "admin"},
        label="reviewer",
        now=now,
    )
    return {
        "required": required,
        "configured": True,
        "registry_hash": _proxy_identity_registry_hash(registry),
        "signature_binding": signature_binding,
        "subject": subject,
        "reviewer": reviewer,
        "raw_secret_egress": False,
    }


def _load_proxy_identity_registry(registry_path: str) -> dict[str, Any]:
    path = Path(registry_path)
    try:
        registry = json.loads(path.read_text())
    except OSError as exc:
        raise ValueError("proxy identity registry is unavailable") from exc
    except json.JSONDecodeError as exc:
        raise ValueError("proxy identity registry is invalid JSON") from exc
    return _normalize_proxy_identity_registry(registry)


def _normalize_proxy_identity_registry(registry: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(registry, dict):
        raise ValueError("proxy identity registry must be an object")
    if registry.get("schema_version") != 1:
        raise ValueError("proxy identity registry schema_version must be 1")
    identities = registry.get("identities")
    if not isinstance(identities, list):
        raise ValueError("proxy identity registry identities must be a list")
    normalized_identities = []
    for identity in identities:
        if not isinstance(identity, dict):
            raise ValueError("proxy identity registry identity must be an object")
        role = str(identity.get("role", "")).strip().lower()
        if role not in {"user", "agent", "reviewer", "admin", "operator_validation"}:
            raise ValueError("proxy identity registry identity role is invalid")
        status = str(identity.get("status", "")).strip().lower()
        if status not in {"active", "suspended", "revoked", "expired"}:
            raise ValueError("proxy identity registry identity status is invalid")
        expires_at = int(identity.get("expires_at", 0) or 0)
        normalized_identities.append(
            {
                "identity_hash": _normalize_hex_hash(
                    str(identity.get("identity_hash", "")),
                    "identity_hash",
                ),
                "role": role,
                "status": status,
                "expires_at": expires_at,
            }
        )
    normalized: dict[str, Any] = {
        "schema_version": 1,
        "identities": sorted(
            normalized_identities,
            key=lambda item: (item["identity_hash"], item["role"]),
        ),
    }
    if "signature" in registry:
        normalized["signature"] = _normalize_proxy_identity_registry_signature_block(
            registry.get("signature")
        )
    return normalized


def _proxy_identity_registry_unsigned(registry: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "identities": list(registry.get("identities", [])),
    }


def _proxy_identity_registry_hash(registry: dict[str, Any]) -> str:
    return stable_hash(
        _canonical_json(_proxy_identity_registry_unsigned(registry)),
        prefix="proxy_identity_registry",
    )


def _normalize_proxy_identity_registry_signature_block(raw_signature: Any) -> dict[str, str]:
    if not isinstance(raw_signature, dict):
        raise ValueError("proxy identity registry signature must be an object")
    kind = str(raw_signature.get("kind", "")).strip().lower()
    if kind not in {"ethereum_signed_message", "ethereum_personal_sign"}:
        raise ValueError("proxy identity registry signature kind is invalid")
    signer = normalize_address(str(raw_signature.get("signer", "")))
    signature = str(raw_signature.get("signature", "")).strip().lower()
    if signature.startswith("0x"):
        signature_hex = signature[2:]
    else:
        signature_hex = signature
    if len(signature_hex) != 130:
        raise ValueError("proxy identity registry signature must be 65 bytes")
    try:
        bytes.fromhex(signature_hex)
    except ValueError as exc:
        raise ValueError("proxy identity registry signature must be hex") from exc
    signed_registry_hash = str(raw_signature.get("registry_hash", "") or "").strip().lower()
    if signed_registry_hash:
        signed_registry_hash = _normalize_hex_hash(
            signed_registry_hash[2:] if signed_registry_hash.startswith("0x") else signed_registry_hash,
            "registry_hash",
        )
    return {
        "kind": "ethereum_signed_message",
        "signer": signer,
        "signature": "0x" + signature_hex,
        "registry_hash": signed_registry_hash,
    }


def _validate_proxy_identity_registry_signature(settings, registry: dict[str, Any]) -> dict[str, Any]:
    required = bool(getattr(settings, "proxy_require_identity_registry_signature", False))
    signer_raw = str(getattr(settings, "proxy_identity_registry_signer", "") or "").strip()
    if not signer_raw:
        if required:
            raise ValueError("proxy identity registry signer is required")
        return {
            "required": False,
            "configured": False,
            "raw_secret_egress": False,
        }
    expected_signer = normalize_address(signer_raw)
    signature_block = registry.get("signature")
    if not signature_block:
        if required:
            raise ValueError("proxy identity registry signature is required")
        return {
            "required": False,
            "configured": True,
            "signer_hash": stable_hash(expected_signer, prefix="proxy_identity_registry_signer"),
            "raw_secret_egress": False,
        }
    registry_hash = _proxy_identity_registry_hash(registry)
    signed_hash = str(signature_block.get("registry_hash", "") or "").strip().lower()
    if signed_hash and signed_hash != registry_hash:
        raise ValueError("proxy identity registry signature hash mismatch")
    try:
        recovered = Account.recover_message(
            encode_defunct(hexstr="0x" + registry_hash),
            signature=signature_block["signature"],
        )
        recovered_normalized = normalize_address(recovered)
    except Exception as exc:
        raise ValueError("proxy identity registry signature is invalid") from exc
    declared_signer = normalize_address(str(signature_block.get("signer", "")))
    if recovered_normalized != declared_signer:
        raise ValueError("proxy identity registry signer mismatch")
    if recovered_normalized != expected_signer:
        raise ValueError("proxy identity registry signer mismatch")
    return {
        "required": required,
        "configured": True,
        "verified": True,
        "kind": signature_block["kind"],
        "registry_hash": registry_hash,
        "signer_hash": stable_hash(recovered_normalized, prefix="proxy_identity_registry_signer"),
        "signature_hash": stable_hash(signature_block["signature"], prefix="proxy_identity_registry_signature"),
        "raw_secret_egress": False,
    }


def sign_proxy_identity_registry(registry: dict[str, Any], signer_private_key: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return a normalized signed hash-only identity registry and bounded receipt."""

    normalized = _normalize_proxy_identity_registry(registry)
    unsigned = _proxy_identity_registry_unsigned(normalized)
    registry_hash = _proxy_identity_registry_hash(unsigned)
    account = Account.from_key(signer_private_key)
    signer = normalize_address(account.address)
    signed = account.sign_message(encode_defunct(hexstr="0x" + registry_hash))
    signature = "0x" + bytes(signed.signature).hex()
    signed_registry = {
        **unsigned,
        "signature": {
            "kind": "ethereum_signed_message",
            "signer": signer,
            "registry_hash": "0x" + registry_hash,
            "signature": signature,
        },
    }
    receipt = {
        "surface": "tinker_proxy_identity_registry_sign",
        "success": True,
        "registry_hash": registry_hash,
        "identity_count": len(unsigned.get("identities", [])),
        "role_counts": _proxy_identity_registry_role_counts(unsigned),
        "signature": {
            "kind": "ethereum_signed_message",
            "signer_hash": stable_hash(signer, prefix="proxy_identity_registry_signer"),
            "signature_hash": stable_hash(signature, prefix="proxy_identity_registry_signature"),
            "signature_returned": False,
            "signer_address_returned": False,
            "private_key_returned": False,
            "raw_secret_egress": False,
        },
        "raw_secret_egress": False,
    }
    return signed_registry, receipt


def sign_proxy_grant_lifecycle(grant: dict[str, Any], signer_private_key: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Sign a hash-only proxy grant lifecycle and return bounded signer evidence."""

    if not isinstance(grant, dict):
        raise ValueError("proxy issue policy grant must be an object")
    normalized_policy = normalize_proxy_issue_policy({"schema_version": 1, "grants": [grant]})
    normalized_grant = normalized_policy["grants"][0]
    lifecycle = normalized_grant.get("lifecycle", {})
    if not lifecycle:
        raise ValueError("proxy issue policy grant lifecycle is required")
    lifecycle_unsigned = _proxy_grant_lifecycle_unsigned(lifecycle)
    if lifecycle_unsigned.get("status") != "active":
        raise ValueError("proxy issue policy grant lifecycle is not active")
    account = Account.from_key(signer_private_key)
    signer = normalize_address(account.address)
    reviewer_hash = stable_hash(signer, prefix="proxy_grant_reviewer")
    if lifecycle_unsigned.get("approved_by_hash") != reviewer_hash:
        raise ValueError("signer does not match proxy grant approved_by_hash")
    approval_hash = _proxy_grant_approval_hash(normalized_grant, lifecycle_unsigned)
    signed = account.sign_message(encode_defunct(hexstr="0x" + approval_hash))
    signature = "0x" + bytes(signed.signature).hex()
    signed_lifecycle = {
        **lifecycle_unsigned,
        "approval_signature": {
            "kind": "ethereum_signed_message",
            "signer": signer,
            "approval_hash": "0x" + approval_hash,
            "signature": signature,
        },
    }
    signed_grant = {
        **{key: value for key, value in normalized_grant.items() if key != "lifecycle"},
        "lifecycle": signed_lifecycle,
    }
    receipt = {
        "surface": "tinker_proxy_grant_lifecycle_sign",
        "success": True,
        "grant_hash": stable_hash(_canonical_json(signed_grant), prefix="proxy_issue_grant"),
        "approval_hash": approval_hash,
        "subject_hash": signed_grant["subject_hash"],
        "recipient_public_key_hash": signed_grant["recipient_public_key_hash"],
        "scopes": signed_grant["scopes"],
        "lifecycle": _public_proxy_grant_lifecycle(signed_lifecycle),
        "signature": {
            "kind": "ethereum_signed_message",
            "signer_hash": stable_hash(signer, prefix="proxy_grant_lifecycle_signer"),
            "signature_hash": stable_hash(signature, prefix="proxy_grant_lifecycle_signature"),
            "signature_returned": False,
            "signer_address_returned": False,
            "private_key_returned": False,
            "raw_secret_egress": False,
        },
        "raw_secret_egress": False,
    }
    return signed_grant, receipt


def verify_signed_proxy_identity_registry(registry: dict[str, Any], expected_signer: str) -> dict[str, Any]:
    """Verify a signed hash-only proxy identity registry with bounded output."""

    normalized = _normalize_proxy_identity_registry(registry)
    settings = type(
        "ProxyIdentityRegistryVerifySettings",
        (),
        {
            "proxy_require_identity_registry_signature": True,
            "proxy_identity_registry_signer": expected_signer,
        },
    )()
    signature_binding = _validate_proxy_identity_registry_signature(settings, normalized)
    unsigned = _proxy_identity_registry_unsigned(normalized)
    return {
        "surface": "tinker_proxy_identity_registry_verify",
        "success": True,
        "registry_hash": _proxy_identity_registry_hash(unsigned),
        "identity_count": len(unsigned.get("identities", [])),
        "role_counts": _proxy_identity_registry_role_counts(unsigned),
        "signature_binding": signature_binding,
        "raw_secret_egress": False,
    }


def _proxy_identity_registry_role_counts(registry: dict[str, Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for identity in registry.get("identities", []):
        role = str(identity.get("role", "unknown"))
        counts[role] = counts.get(role, 0) + 1
    return dict(sorted(counts.items()))


def _find_active_proxy_identity(
    registry: dict[str, Any],
    identity_hash: str,
    *,
    allowed_roles: set[str],
    label: str,
    now: int,
) -> dict[str, Any]:
    for identity in registry.get("identities", []):
        if identity.get("identity_hash") != identity_hash:
            continue
        if identity.get("role") not in allowed_roles:
            continue
        if identity.get("status") != "active":
            raise ValueError(f"proxy identity registry {label} identity is not active")
        expires_at = int(identity.get("expires_at", 0) or 0)
        if expires_at <= now:
            raise ValueError(f"proxy identity registry {label} identity expired")
        return {
            "identity_hash": identity["identity_hash"],
            "role": identity["role"],
            "status": identity["status"],
            "expires_at": expires_at,
            "raw_secret_egress": False,
        }
    raise ValueError(f"proxy identity registry {label} identity is not approved")


def _load_proxy_issue_policy(policy_path: str) -> dict[str, Any]:
    path = Path(policy_path)
    try:
        policy = json.loads(path.read_text())
    except OSError as exc:
        raise ValueError("proxy issue policy is unavailable") from exc
    except json.JSONDecodeError as exc:
        raise ValueError("proxy issue policy is invalid JSON") from exc
    return normalize_proxy_issue_policy(policy)


def _proxy_issue_policy_path(settings, *, required: bool) -> Path | None:
    raw_path = str(getattr(settings, "proxy_issue_policy_path", "") or "").strip()
    if not raw_path:
        if required:
            raise ValueError("proxy issue policy path is not configured")
        return None
    return Path(raw_path)


def _proxy_identity_registry_path(settings, *, required: bool) -> Path | None:
    raw_path = str(getattr(settings, "proxy_identity_registry_path", "") or "").strip()
    if not raw_path:
        if required:
            raise ValueError("proxy identity registry path is not configured")
        return None
    return Path(raw_path)


def _normalize_hex_hash(value: str, field_name: str) -> str:
    normalized = value.lower()
    if len(normalized) != 64:
        raise ValueError(f"proxy issue policy {field_name} must be a 64-char hex hash")
    try:
        int(normalized, 16)
    except ValueError as exc:
        raise ValueError(f"proxy issue policy {field_name} must be hex") from exc
    return normalized


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _normalize_scope_limits(
    raw_limits: Any,
    scopes: set[str],
    *,
    require_spend_limits: bool,
) -> dict[str, dict[str, float]]:
    if raw_limits in (None, ""):
        raw_limits = {}
    if not isinstance(raw_limits, dict):
        raise ValueError("proxy issue policy scope limits must be an object")
    normalized: dict[str, dict[str, float]] = {}
    for scope, limits in raw_limits.items():
        scope_name = str(scope).strip()
        if scope_name not in SUPPORTED_PROXY_SCOPES:
            raise ValueError("proxy issue policy scope limit has unsupported scope")
        if scope_name not in scopes:
            continue
        if not isinstance(limits, dict):
            raise ValueError("proxy issue policy scope limit must be an object")
        max_amount = limits.get("max_amount_usd", None)
        if max_amount is None:
            raise ValueError("proxy issue policy scope limit missing max_amount_usd")
        try:
            max_amount_float = float(max_amount)
        except (TypeError, ValueError) as exc:
            raise ValueError("proxy issue policy scope limit max_amount_usd must be numeric") from exc
        if max_amount_float <= 0:
            raise ValueError("proxy issue policy scope limit max_amount_usd must be positive")
        normalized[scope_name] = {"max_amount_usd": max_amount_float}

    if require_spend_limits:
        missing = sorted(scope for scope in scopes if scope in SPEND_LIMIT_PROXY_SCOPES and scope not in normalized)
        if missing:
            raise ValueError("proxy issue policy spend scope is missing max_amount_usd")
    return normalized


def _signing_key_source(settings) -> str:
    if getattr(settings, "proxy_jwt_key", ""):
        return "explicit_env_or_settings"
    if is_dstack_enabled():
        return "dstack_derived"
    if os.environ.get("TINKER_PROXY_JWT_KEY", ""):
        return "explicit_env_or_settings"
    return "unavailable"


def _normalize_subject(subject: str) -> str:
    normalized = subject.strip()
    if not normalized:
        raise ValueError("proxy token subject is required")
    if len(normalized) > 128:
        raise ValueError("proxy token subject is too long")
    return normalized


def _normalize_scopes(scopes: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    normalized = tuple(sorted({scope.strip() for scope in scopes if scope.strip()}))
    if not normalized:
        raise ValueError("at least one proxy token scope is required")
    unsupported = [scope for scope in normalized if scope not in SUPPORTED_PROXY_SCOPES]
    if unsupported:
        raise ValueError("unsupported proxy token scope")
    return normalized


def _normalize_ttl(settings, ttl_seconds: int | None) -> int:
    default_ttl = int(getattr(settings, "proxy_jwt_default_ttl_seconds", 900) or 900)
    max_ttl = int(getattr(settings, "proxy_jwt_max_ttl_seconds", 3600) or 3600)
    ttl = int(ttl_seconds if ttl_seconds is not None else default_ttl)
    if ttl <= 0:
        raise ValueError("proxy token ttl must be positive")
    return min(ttl, max_ttl)


def _decode_x25519_public_key(value: str) -> bytes:
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError("recipient public key must be hex") from exc
    if len(raw) != 32:
        raise ValueError("recipient public key must be 32 bytes")
    return raw


def _proxy_token_associated_data(claims: ProxyTokenClaims) -> bytes:
    return json.dumps(
        {
            "surface": "tinker_proxy_token",
            "subject_hash": stable_hash(claims.subject, prefix="proxy_subject"),
            "jwt_id_hash": stable_hash(claims.jwt_id, prefix="proxy_jti"),
            "scopes": list(claims.scopes),
            "expires_at": claims.expires_at,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _b64url_json(value: dict[str, Any]) -> bytes:
    return _b64url(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _b64url(value: bytes) -> bytes:
    return base64.urlsafe_b64encode(value).rstrip(b"=")


def _b64url_decode(value: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("invalid base64url")
    padding = "=" * (-len(value) % 4)
    decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    if _b64url(decoded).decode("ascii") != value:
        raise ValueError("non-canonical base64url")
    return decoded


def _next_required_configuration(*, api_key_configured: bool, project_id_configured: bool) -> list[str]:
    missing: list[str] = []
    if not api_key_configured:
        missing.append("seal_tinker_api_key_in_delegate")
    if not project_id_configured:
        missing.append("seal_tinker_project_id_in_delegate_if_provider_requires_it")
    return missing


def _base_url_host_family(base_url: str) -> str:
    if not base_url:
        return "sdk_default"
    try:
        host = (urlparse(base_url).hostname or "").lower()
    except Exception:
        return "invalid"
    if not host:
        return "invalid"
    if host in {"localhost", "127.0.0.1", "::1"}:
        return "localhost"
    if (
        host.startswith("10.")
        or host.startswith("192.168.")
        or host.startswith("172.16.")
        or host.startswith("172.17.")
        or host.startswith("172.18.")
        or host.startswith("172.19.")
        or host.startswith("172.2")
        or host.startswith("172.30.")
        or host.startswith("172.31.")
    ):
        return "private_network"
    if host.endswith("thinkingmachines.ai"):
        return "thinkingmachines"
    return "external"
