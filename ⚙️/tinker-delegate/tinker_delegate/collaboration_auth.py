"""Domain-separated wallet authentication for multi-owner collaboration rooms.

The collaboration console is deliberately isolated from Deal artifact upload,
Arena, Compute, reviewer, proxy, and operator-runtime authority. A wallet
exchanges one bounded Base Sepolia ``personal_sign`` challenge for a short-lived
``collaboration:console`` bearer. The bearer proves only the wallet principal;
room membership, owner consent, and run authorization remain durable
state-machine checks in :mod:`tinker_delegate.collaboration_store`.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any

from tinker_delegate import dstack_utils
from tinker_delegate.wallet_auth import (
    MAX_WALLET_CHALLENGE_VERIFICATION_ATTEMPTS,
    WalletAuthError,
    normalize_wallet_address,
)
from tinker_delegate.wallet_signature_verifier import (
    BASE_SEPOLIA_CHAIN_ID,
    WalletSignatureError,
    WalletSignatureUnavailable,
    WalletSignatureVerifier,
    wallet_signature_verifier_from_settings,
)


COLLABORATION_CONSOLE_SCOPE = "collaboration:console"
_NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
_JTI_RE = re.compile(r"^[0-9a-f]{32}$")
_JWT_PART_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_WALLET_HEADER = {
    "alg": "HS256",
    "kid": "dstack-collaboration-wallet-v1",
    "typ": "JWT",
}
_INVALID_WALLET_SIGNATURE_MESSAGE = "Collaboration wallet signature is invalid"


class CollaborationAuthError(ValueError):
    """A collaboration challenge, signature, or token is invalid."""


class CollaborationAuthUnavailable(RuntimeError):
    """Secure signing material or wallet verification is unavailable."""


class CollaborationChallengeCapacityError(RuntimeError):
    """A valid challenge was not evicted to admit another challenge."""


@dataclass(frozen=True)
class CollaborationWalletChallenge:
    address: str
    nonce: str
    message: str
    issued_at: int
    expires_at: int
    scope: str = COLLABORATION_CONSOLE_SCOPE

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "nonce": self.nonce,
            "message": self.message,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "scope": self.scope,
            "chain_id": BASE_SEPOLIA_CHAIN_ID,
        }


@dataclass(frozen=True)
class CollaborationWalletClaims:
    address: str
    scopes: tuple[str, ...]
    issued_at: int
    expires_at: int
    jwt_id: str

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "scopes": list(self.scopes),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "jwt_id_hash": hashlib.sha256(
                b"collaboration-wallet-jti:" + self.jwt_id.encode("ascii")
            ).hexdigest(),
        }


class CollaborationWalletChallengeStore:
    """Bounded process-local store for single-use collaboration challenges."""

    def __init__(self, *, max_pending: int = 1024) -> None:
        if (
            not isinstance(max_pending, int)
            or isinstance(max_pending, bool)
            or max_pending <= 0
        ):
            raise ValueError("Collaboration wallet challenge capacity must be positive")
        self.max_pending = max_pending
        self._records: dict[str, CollaborationWalletChallenge] = {}
        self._attempts: dict[str, int] = {}
        self._in_flight: set[str] = set()
        self._lock = threading.Lock()

    def put(self, challenge: CollaborationWalletChallenge, *, now: int) -> None:
        with self._lock:
            self._prune_locked(now)
            if len(self._records) >= self.max_pending:
                raise CollaborationChallengeCapacityError(
                    "Collaboration wallet challenge capacity reached"
                )
            self._records[challenge.nonce] = challenge
            self._attempts[challenge.nonce] = 0
            self._in_flight.discard(challenge.nonce)

    def reserve_verification(
        self,
        nonce: str,
        *,
        now: int,
    ) -> CollaborationWalletChallenge:
        with self._lock:
            self._prune_locked(now)
            challenge = self._records.get(nonce)
            attempts = self._attempts.get(nonce, 0)
            if (
                challenge is None
                or nonce in self._in_flight
                or attempts >= MAX_WALLET_CHALLENGE_VERIFICATION_ATTEMPTS
                or now < challenge.issued_at
            ):
                raise CollaborationAuthError(
                    "Collaboration wallet challenge is unknown, expired, or already used"
                )
            self._attempts[nonce] = attempts + 1
            self._in_flight.add(nonce)
            return challenge

    def release_verification(
        self,
        nonce: str,
        expected: CollaborationWalletChallenge,
    ) -> None:
        with self._lock:
            if self._records.get(nonce) is not expected:
                return
            self._in_flight.discard(nonce)
            if (
                self._attempts.get(nonce, 0)
                >= MAX_WALLET_CHALLENGE_VERIFICATION_ATTEMPTS
            ):
                self._delete_locked(nonce)

    def consume_if_current(
        self,
        nonce: str,
        expected: CollaborationWalletChallenge,
        *,
        now: int,
    ) -> CollaborationWalletChallenge:
        with self._lock:
            self._prune_locked(now)
            challenge = self._records.get(nonce)
            if (
                challenge is None
                or challenge is not expected
                or nonce not in self._in_flight
            ):
                raise CollaborationAuthError(
                    "Collaboration wallet challenge is unknown, expired, or already used"
                )
            self._delete_locked(nonce)
            return challenge

    def clear(self) -> None:
        with self._lock:
            self._records.clear()
            self._attempts.clear()
            self._in_flight.clear()

    def _prune_locked(self, now: int) -> None:
        for nonce in [
            key for key, value in self._records.items() if now >= value.expires_at
        ]:
            self._delete_locked(nonce)

    def _delete_locked(self, nonce: str) -> None:
        self._records.pop(nonce, None)
        self._attempts.pop(nonce, None)
        self._in_flight.discard(nonce)


class CollaborationWalletAuthService:
    """Issue and verify short-lived collaboration-console wallet tokens."""

    def __init__(
        self,
        settings: Any,
        store: CollaborationWalletChallengeStore,
        signature_verifier: WalletSignatureVerifier | None = None,
    ) -> None:
        self.settings = settings
        self.store = store
        self.signature_verifier = signature_verifier

    def issue_challenge(
        self,
        *,
        address: str,
        now: int | None = None,
    ) -> CollaborationWalletChallenge:
        issued_at = _clock_time(now)
        normalized_address = _normalize_address(address)
        collaboration_wallet_signing_key(self.settings)
        ttl = _bounded_positive_int(
            getattr(
                self.settings,
                "collaboration_wallet_auth_challenge_ttl_seconds",
                300,
            ),
            label="Collaboration wallet challenge ttl",
            maximum=600,
        )
        nonce = secrets.token_hex(16)
        expires_at = issued_at + ttl
        challenge = CollaborationWalletChallenge(
            address=normalized_address,
            nonce=nonce,
            message=_challenge_message(
                self.settings,
                address=normalized_address,
                nonce=nonce,
                issued_at=issued_at,
                expires_at=expires_at,
            ),
            issued_at=issued_at,
            expires_at=expires_at,
        )
        self.store.put(challenge, now=issued_at)
        return challenge

    def exchange_signature(
        self,
        *,
        nonce: str,
        signature: str,
        now: int | None = None,
    ) -> tuple[CollaborationWalletClaims, str]:
        current = _clock_time(now)
        if not isinstance(nonce, str) or not _NONCE_RE.fullmatch(nonce):
            raise CollaborationAuthError(
                "Collaboration wallet challenge nonce is invalid"
            )
        ttl = _bounded_positive_int(
            getattr(
                self.settings,
                "collaboration_wallet_auth_token_ttl_seconds",
                600,
            ),
            label="Collaboration wallet token ttl",
            maximum=900,
        )
        key = collaboration_wallet_signing_key(self.settings)
        challenge = self.store.reserve_verification(nonce, now=current)
        verifier = self.signature_verifier
        verified = False
        try:
            if verifier is None:
                verifier = wallet_signature_verifier_from_settings(self.settings)
            kind = verifier.verify(
                address=challenge.address,
                message=challenge.message,
                signature=signature,
            )
            if kind not in ("eoa", "eip1271"):
                raise WalletSignatureUnavailable(
                    "wallet signature verifier returned an unsupported result"
                )
            verified = True
        except WalletSignatureUnavailable as exc:
            raise CollaborationAuthUnavailable(
                "Collaboration wallet signature verification is unavailable"
            ) from exc
        except WalletSignatureError as exc:
            raise CollaborationAuthError(_INVALID_WALLET_SIGNATURE_MESSAGE) from exc
        except Exception as exc:
            raise CollaborationAuthUnavailable(
                "Collaboration wallet signature verification is unavailable"
            ) from exc
        finally:
            if not verified:
                self.store.release_verification(nonce, challenge)

        consumed_at = current if now is not None else _clock_time(None)
        if consumed_at < current:
            self.store.release_verification(nonce, challenge)
            raise CollaborationAuthUnavailable(
                "Collaboration wallet verification clock regressed"
            )
        try:
            challenge = self.store.consume_if_current(
                nonce,
                challenge,
                now=consumed_at,
            )
        except Exception:
            self.store.release_verification(nonce, challenge)
            raise
        claims = CollaborationWalletClaims(
            address=challenge.address,
            scopes=(COLLABORATION_CONSOLE_SCOPE,),
            issued_at=consumed_at,
            expires_at=consumed_at + ttl,
            jwt_id=secrets.token_hex(16),
        )
        token = _encode_token(
            {
                "iss": _setting_text(
                    self.settings,
                    "collaboration_wallet_auth_issuer",
                    "dnai-wikigen:collaboration-wallet-auth",
                ),
                "aud": _setting_text(
                    self.settings,
                    "collaboration_wallet_auth_audience",
                    "dnai-wikigen:collaboration-console",
                ),
                "sub": claims.address,
                "scope": COLLABORATION_CONSOLE_SCOPE,
                "iat": claims.issued_at,
                "nbf": claims.issued_at,
                "exp": claims.expires_at,
                "jti": claims.jwt_id,
            },
            key,
        )
        return claims, token

    def verify_token(
        self,
        token: str,
        *,
        required_scope: str = COLLABORATION_CONSOLE_SCOPE,
        now: int | None = None,
    ) -> CollaborationWalletClaims:
        payload = _decode_token(token, collaboration_wallet_signing_key(self.settings))
        current = _clock_time(now)
        if payload.get("iss") != _setting_text(
            self.settings,
            "collaboration_wallet_auth_issuer",
            "dnai-wikigen:collaboration-wallet-auth",
        ):
            raise CollaborationAuthError("Collaboration wallet token issuer mismatch")
        if payload.get("aud") != _setting_text(
            self.settings,
            "collaboration_wallet_auth_audience",
            "dnai-wikigen:collaboration-console",
        ):
            raise CollaborationAuthError("Collaboration wallet token audience mismatch")
        issued_at, expires_at = _validate_times(
            payload,
            now=current,
            max_ttl=_bounded_positive_int(
                getattr(
                    self.settings,
                    "collaboration_wallet_auth_token_ttl_seconds",
                    600,
                ),
                label="Collaboration wallet token ttl",
                maximum=900,
            ),
        )
        address = _normalize_address(payload.get("sub"))
        scopes = tuple(str(payload.get("scope", "")).split())
        if scopes != (COLLABORATION_CONSOLE_SCOPE,) or required_scope not in scopes:
            raise CollaborationAuthError("Collaboration wallet token scope is invalid")
        jwt_id = str(payload.get("jti", ""))
        if not _JTI_RE.fullmatch(jwt_id):
            raise CollaborationAuthError("Collaboration wallet token id is invalid")
        return CollaborationWalletClaims(
            address=address,
            scopes=scopes,
            issued_at=issued_at,
            expires_at=expires_at,
            jwt_id=jwt_id,
        )


def classify_unverified_collaboration_token_header(token: str) -> str:
    """Route an unverified token using only its exact collaboration JWT header.

    This function does not authenticate the signature or validate any payload
    claim.  The caller must pass the token to
    :meth:`CollaborationWalletAuthService.verify_token` before trusting it.
    """

    parts = _token_parts(token)
    try:
        header = json.loads(_b64url_decode(parts[0]))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CollaborationAuthError("Collaboration token header is invalid") from exc
    if header != _WALLET_HEADER:
        raise CollaborationAuthError("Collaboration token header is unsupported")
    return "wallet"


def collaboration_wallet_signing_key(settings: Any) -> bytes:
    return _resolve_key(
        settings,
        explicit_name="collaboration_wallet_auth_signing_key",
        path_name="collaboration_wallet_auth_key_path",
        default_path="tinker/collaboration_wallet_auth",
        domain=b"dnai-collaboration-wallet-auth-v1:",
    )


def collaboration_store_integrity_key(settings: Any) -> bytes:
    return _resolve_key(
        settings,
        explicit_name="collaboration_store_integrity_key",
        path_name="collaboration_store_integrity_key_path",
        default_path="tinker/collaboration_store_integrity",
        domain=b"dnai-collaboration-store-integrity-v1:",
    )


def _resolve_key(
    settings: Any,
    *,
    explicit_name: str,
    path_name: str,
    default_path: str,
    domain: bytes,
) -> bytes:
    if dstack_utils.is_dstack_enabled():
        path = str(getattr(settings, path_name, default_path) or "").strip()
        if not path:
            raise CollaborationAuthUnavailable(
                "Collaboration dstack key path is not configured"
            )
        try:
            material = dstack_utils.derive_storage_key(path)
        except Exception as exc:
            raise CollaborationAuthUnavailable(
                "Collaboration dstack key derivation failed"
            ) from exc
        return hashlib.sha256(domain + b"dstack:" + material).digest()
    explicit = str(getattr(settings, explicit_name, "") or "")
    if len(explicit) < 32:
        raise CollaborationAuthUnavailable(
            f"{explicit_name} must be at least 32 characters outside dstack"
        )
    return hashlib.sha256(
        domain + b"local:" + explicit.encode("utf-8")
    ).digest()


def _challenge_message(
    settings: Any,
    *,
    address: str,
    nonce: str,
    issued_at: int,
    expires_at: int,
) -> str:
    domain = _setting_text(settings, "wallet_auth_domain", "www.wikigen.me")
    uri = _setting_text(settings, "wallet_auth_uri", "https://www.wikigen.me")
    chain_id = _bounded_positive_int(
        getattr(settings, "wallet_auth_chain_id", BASE_SEPOLIA_CHAIN_ID),
        label="Collaboration wallet chain id",
        maximum=2**63 - 1,
    )
    if chain_id != BASE_SEPOLIA_CHAIN_ID:
        raise CollaborationAuthError(
            "Collaboration wallet auth requires Base Sepolia chain 84532"
        )
    if any("\n" in value or "\r" in value for value in (domain, uri)):
        raise CollaborationAuthError(
            "Collaboration wallet auth domain or uri contains a newline"
        )
    return (
        f"{domain} wants you to sign in with your Ethereum account:\n"
        f"{address}\n\n"
        "Authorize access to the multi-owner Collaboration Console. This "
        "signature will not create a room, approve owner consent, trigger a "
        "blockchain transaction, or transfer funds.\n\n"
        f"URI: {uri}\n"
        "Version: 1\n"
        f"Chain ID: {chain_id}\n"
        f"Nonce: {nonce}\n"
        f"Issued At: {issued_at}\n"
        f"Expiration Time: {expires_at}\n"
        "Resources:\n"
        f"- urn:dnai:scope:{COLLABORATION_CONSOLE_SCOPE}"
    )


def _validate_times(
    payload: dict[str, Any],
    *,
    now: int,
    max_ttl: int,
) -> tuple[int, int]:
    try:
        issued_at = payload["iat"]
        not_before = payload["nbf"]
        expires_at = payload["exp"]
    except KeyError as exc:
        raise CollaborationAuthError(
            "Collaboration wallet token timestamps are invalid"
        ) from exc
    if any(
        type(value) is not int
        for value in (issued_at, not_before, expires_at)
    ):
        raise CollaborationAuthError(
            "Collaboration wallet token timestamps are invalid"
        )
    if not_before != issued_at or now < not_before:
        raise CollaborationAuthError("Collaboration wallet token is not yet valid")
    if expires_at <= issued_at or now >= expires_at:
        raise CollaborationAuthError("Collaboration wallet token expired")
    if expires_at - issued_at > max_ttl:
        raise CollaborationAuthError(
            "Collaboration wallet token lifetime exceeds configured limit"
        )
    return issued_at, expires_at


def _normalize_address(value: Any) -> str:
    try:
        return normalize_wallet_address(str(value if value is not None else ""))
    except WalletAuthError as exc:
        raise CollaborationAuthError(str(exc)) from exc


def _clock_time(now: int | None) -> int:
    if now is None:
        return int(time.time())
    if type(now) is not int:
        raise CollaborationAuthError(
            "Collaboration authentication clock must be an integer"
        )
    return now


def _bounded_positive_int(value: Any, *, label: str, maximum: int) -> int:
    if isinstance(value, bool):
        raise CollaborationAuthError(f"{label} must be an integer")
    try:
        normalized = int(value)
    except (TypeError, ValueError) as exc:
        raise CollaborationAuthError(f"{label} must be an integer") from exc
    if normalized <= 0 or normalized > maximum:
        raise CollaborationAuthError(f"{label} is outside the supported range")
    return normalized


def _setting_text(settings: Any, name: str, default: str) -> str:
    value = str(getattr(settings, name, "") or default).strip()
    if not value:
        raise CollaborationAuthError(f"{name} must not be empty")
    return value


def _encode_token(payload: dict[str, Any], key: bytes) -> str:
    signing_input = b".".join((_b64url_json(_WALLET_HEADER), _b64url_json(payload)))
    signature = hmac.new(key, signing_input, hashlib.sha256).digest()
    return (signing_input + b"." + _b64url(signature)).decode("ascii")


def _decode_token(token: str, key: bytes) -> dict[str, Any]:
    parts = _token_parts(token)
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    try:
        supplied = _b64url_decode(parts[2])
    except ValueError as exc:
        raise CollaborationAuthError(
            "Collaboration token signature is invalid"
        ) from exc
    expected = hmac.new(key, signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(supplied, expected):
        raise CollaborationAuthError("Collaboration token signature is invalid")
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CollaborationAuthError("Collaboration token JSON is invalid") from exc
    if header != _WALLET_HEADER or not isinstance(payload, dict):
        raise CollaborationAuthError(
            "Collaboration token header or payload is invalid"
        )
    return payload


def _token_parts(token: str) -> list[str]:
    if not isinstance(token, str) or len(token) > 4096:
        raise CollaborationAuthError("Collaboration token format is invalid")
    parts = token.split(".")
    if len(parts) != 3 or any(
        not part or not _JWT_PART_RE.fullmatch(part) for part in parts
    ):
        raise CollaborationAuthError("Collaboration token format is invalid")
    return parts


def _b64url_json(value: dict[str, Any]) -> bytes:
    return _b64url(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )


def _b64url(value: bytes) -> bytes:
    return base64.urlsafe_b64encode(value).rstrip(b"=")


def _b64url_decode(value: str) -> bytes:
    if not value or not _JWT_PART_RE.fullmatch(value):
        raise ValueError("invalid base64url")
    padding = "=" * (-len(value) % 4)
    decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    if _b64url(decoded).decode("ascii") != value:
        raise ValueError("non-canonical base64url")
    return decoded
