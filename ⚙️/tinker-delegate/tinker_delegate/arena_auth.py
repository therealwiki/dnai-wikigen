"""Narrow Ethereum wallet authorization for Arena challenge submissions.

Arena authorization is intentionally separate from seller artifact-upload
authorization.  A browser signs a short-lived, challenge-version-bound
``personal_sign`` message and exchanges the one-time nonce for a short-lived
token carrying the exact Arena session scopes: encrypted submission and the
authenticated owner's bounded read projection.  The distinct issuer,
audience, signing-key domain, JWT key id, and resource claims prevent an Arena
token from being accepted by the deal, operator, or Tinker proxy paths.
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
    recover_wallet_address,
)
from tinker_delegate.wallet_signature_verifier import (
    BASE_SEPOLIA_CHAIN_ID,
    WalletSignatureError,
    WalletSignatureUnavailable,
    WalletSignatureVerifier,
    wallet_signature_verifier_from_settings,
)


ARENA_SUBMIT_SCOPE = "challenge:submit"
ARENA_OWNER_READ_SCOPE = "challenge:submissions:read"
ARENA_SESSION_SCOPES = (ARENA_SUBMIT_SCOPE, ARENA_OWNER_READ_SCOPE)
_CHALLENGE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_CHALLENGE_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
_JTI_RE = re.compile(r"^[0-9a-f]{32}$")
_JWT_HEADER = {"alg": "HS256", "kid": "dstack-arena-wallet-v1", "typ": "JWT"}


class ArenaAuthError(ValueError):
    """Raised when an Arena challenge, signature, or token is invalid."""


class ArenaAuthUnavailable(RuntimeError):
    """Raised when secure Arena token-signing material is unavailable."""


class ArenaChallengeCapacityError(RuntimeError):
    """Raised rather than evicting an unexpired wallet challenge."""


@dataclass(frozen=True)
class ArenaWalletChallenge:
    address: str
    challenge_id: str
    challenge_version: str
    scope: str
    nonce: str
    message: str
    issued_at: int
    expires_at: int

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "challenge_id": self.challenge_id,
            "challenge_version": self.challenge_version,
            "scope": self.scope,
            "nonce": self.nonce,
            "message": self.message,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }


@dataclass(frozen=True)
class ArenaWalletTokenClaims:
    address: str
    challenge_id: str
    challenge_version: str
    scopes: tuple[str, ...]
    issued_at: int
    expires_at: int
    jwt_id: str

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "challenge_id": self.challenge_id,
            "challenge_version": self.challenge_version,
            "scopes": list(self.scopes),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "jwt_id_hash": hashlib.sha256(
                b"arena-wallet-auth-jti:" + self.jwt_id.encode("utf-8")
            ).hexdigest(),
        }


class ArenaWalletChallengeStore:
    """Bounded process-local store for single-use Arena login challenges."""

    def __init__(self, *, max_pending: int = 1024):
        if max_pending <= 0:
            raise ValueError("Arena wallet challenge capacity must be positive")
        self.max_pending = int(max_pending)
        self._records: dict[str, ArenaWalletChallenge] = {}
        self._verification_attempts: dict[str, int] = {}
        self._verification_in_flight: set[str] = set()
        self._lock = threading.Lock()

    def put(self, challenge: ArenaWalletChallenge, *, now: int) -> None:
        with self._lock:
            self._prune_locked(now)
            if len(self._records) >= self.max_pending:
                raise ArenaChallengeCapacityError("Arena wallet challenge capacity reached")
            self._records[challenge.nonce] = challenge
            self._verification_attempts[challenge.nonce] = 0
            self._verification_in_flight.discard(challenge.nonce)

    def consume_verified(
        self,
        nonce: str,
        signature: str,
        *,
        now: int,
    ) -> ArenaWalletChallenge:
        """Locally verify and consume a challenge nonce for compatibility."""

        challenge = self.reserve_verification(nonce, now=now)
        verified = False
        try:
            try:
                recovered = recover_wallet_address(challenge.message, signature)
            except WalletAuthError as exc:
                raise ArenaAuthError(str(exc)) from exc
            if not hmac.compare_digest(recovered, challenge.address):
                raise ArenaAuthError(
                    "Arena wallet signature does not match challenge address"
                )
            verified = True
        finally:
            if not verified:
                self.release_verification(nonce, challenge)
        return self.consume_if_current(nonce, challenge, now=now)

    def reserve_verification(
        self,
        nonce: str,
        *,
        now: int,
    ) -> ArenaWalletChallenge:
        """Reserve one bounded verification attempt without holding the lock."""

        with self._lock:
            self._prune_locked(now)
            challenge = self._records.get(nonce)
            attempts = self._verification_attempts.get(nonce, 0)
            if (
                challenge is None
                or nonce in self._verification_in_flight
                or attempts >= MAX_WALLET_CHALLENGE_VERIFICATION_ATTEMPTS
            ):
                raise ArenaAuthError(
                    "Arena wallet challenge is unknown, expired, or already used"
                )
            self._verification_attempts[nonce] = attempts + 1
            self._verification_in_flight.add(nonce)
            return challenge

    def release_verification(
        self,
        nonce: str,
        expected: ArenaWalletChallenge,
    ) -> None:
        """Release a failed attempt and retire a nonce at its attempt limit."""

        with self._lock:
            if self._records.get(nonce) is not expected:
                return
            self._verification_in_flight.discard(nonce)
            if (
                self._verification_attempts.get(nonce, 0)
                >= MAX_WALLET_CHALLENGE_VERIFICATION_ATTEMPTS
            ):
                self._delete_locked(nonce)

    def get_pending(self, nonce: str, *, now: int) -> ArenaWalletChallenge:
        """Return an immutable challenge before any external verification."""

        with self._lock:
            self._prune_locked(now)
            challenge = self._records.get(nonce)
            if challenge is None:
                raise ArenaAuthError("Arena wallet challenge is unknown, expired, or already used")
            return challenge

    def consume_if_current(
        self,
        nonce: str,
        expected: ArenaWalletChallenge,
        *,
        now: int,
    ) -> ArenaWalletChallenge:
        """Compare-and-delete after verification outside the store lock."""

        with self._lock:
            self._prune_locked(now)
            challenge = self._records.get(nonce)
            if (
                challenge is None
                or challenge is not expected
                or nonce not in self._verification_in_flight
            ):
                raise ArenaAuthError("Arena wallet challenge is unknown, expired, or already used")
            self._delete_locked(nonce)
            return challenge

    def clear(self) -> None:
        with self._lock:
            self._records.clear()
            self._verification_attempts.clear()
            self._verification_in_flight.clear()

    def _prune_locked(self, now: int) -> None:
        for nonce in [
            nonce for nonce, item in self._records.items() if now >= item.expires_at
        ]:
            self._delete_locked(nonce)

    def _delete_locked(self, nonce: str) -> None:
        self._records.pop(nonce, None)
        self._verification_attempts.pop(nonce, None)
        self._verification_in_flight.discard(nonce)


class ArenaWalletAuthService:
    """Issue and verify challenge-version-bound Arena submission tokens."""

    def __init__(
        self,
        settings: Any,
        challenge_store: ArenaWalletChallengeStore,
        signature_verifier: WalletSignatureVerifier | None = None,
    ):
        self.settings = settings
        self.challenge_store = challenge_store
        self.signature_verifier = signature_verifier

    def issue_challenge(
        self,
        *,
        address: str,
        challenge_id: str,
        challenge_version: str,
        now: int | None = None,
    ) -> ArenaWalletChallenge:
        issued_at = int(time.time() if now is None else now)
        normalized_address = normalize_wallet_address(address)
        normalized_id = normalize_challenge_id(challenge_id)
        normalized_version = normalize_challenge_version(challenge_version)
        # Fail before asking the wallet to sign if the corresponding token
        # cannot be issued securely by this runtime.
        arena_token_signing_key(self.settings)
        ttl = _bounded_positive_int(
            getattr(self.settings, "arena_wallet_auth_challenge_ttl_seconds", 300),
            name="Arena wallet challenge ttl",
            maximum=600,
        )
        nonce = secrets.token_hex(16)
        expires_at = issued_at + ttl
        message = _challenge_message(
            self.settings,
            address=normalized_address,
            challenge_id=normalized_id,
            challenge_version=normalized_version,
            nonce=nonce,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        challenge = ArenaWalletChallenge(
            address=normalized_address,
            challenge_id=normalized_id,
            challenge_version=normalized_version,
            scope=" ".join(ARENA_SESSION_SCOPES),
            nonce=nonce,
            message=message,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        self.challenge_store.put(challenge, now=issued_at)
        return challenge

    def exchange_signature(
        self,
        *,
        nonce: str,
        signature: str,
        now: int | None = None,
    ) -> tuple[ArenaWalletTokenClaims, str]:
        current = int(time.time() if now is None else now)
        normalized_nonce = _normalize_nonce(nonce)
        ttl = _bounded_positive_int(
            getattr(self.settings, "arena_wallet_auth_token_ttl_seconds", 300),
            name="Arena wallet token ttl",
            maximum=900,
        )
        signing_key = arena_token_signing_key(self.settings)
        challenge = self.challenge_store.reserve_verification(
            normalized_nonce,
            now=current,
        )
        verifier = self.signature_verifier
        verified = False
        try:
            if verifier is None:
                verifier = wallet_signature_verifier_from_settings(self.settings)
            verification_kind = verifier.verify(
                address=challenge.address,
                message=challenge.message,
                signature=signature,
            )
            if verification_kind not in ("eoa", "eip1271"):
                raise WalletSignatureUnavailable(
                    "wallet signature verifier returned an unsupported result"
                )
            verified = True
        except WalletSignatureUnavailable as exc:
            raise ArenaAuthUnavailable(
                "Arena wallet signature verification is unavailable"
            ) from exc
        except WalletSignatureError as exc:
            raise ArenaAuthError(str(exc)) from exc
        except Exception as exc:
            raise ArenaAuthUnavailable(
                "Arena wallet signature verification is unavailable"
            ) from exc
        finally:
            if not verified:
                self.challenge_store.release_verification(
                    normalized_nonce,
                    challenge,
                )
        consumed_at = current if now is not None else int(time.time())
        challenge = self.challenge_store.consume_if_current(
            normalized_nonce,
            challenge,
            now=consumed_at,
        )
        claims = ArenaWalletTokenClaims(
            address=challenge.address,
            challenge_id=challenge.challenge_id,
            challenge_version=challenge.challenge_version,
            scopes=ARENA_SESSION_SCOPES,
            issued_at=consumed_at,
            expires_at=consumed_at + ttl,
            jwt_id=secrets.token_hex(16),
        )
        payload = {
            "iss": _setting_text(
                self.settings,
                "arena_wallet_auth_issuer",
                "dnai-wikigen:arena-wallet-auth",
            ),
            "aud": _setting_text(
                self.settings,
                "arena_wallet_auth_audience",
                "dnai-wikigen:arena",
            ),
            "sub": claims.address,
            "challenge_id": claims.challenge_id,
            "challenge_version": claims.challenge_version,
            "scope": " ".join(claims.scopes),
            "iat": claims.issued_at,
            "nbf": claims.issued_at,
            "exp": claims.expires_at,
            "jti": claims.jwt_id,
        }
        return claims, _encode_token(payload, signing_key)

    def verify_token(
        self,
        token: str,
        *,
        required_scope: str,
        challenge_id: str,
        challenge_version: str,
        now: int | None = None,
    ) -> ArenaWalletTokenClaims:
        payload = _decode_token(token, arena_token_signing_key(self.settings))
        current = int(time.time() if now is None else now)
        if payload.get("iss") != _setting_text(
            self.settings,
            "arena_wallet_auth_issuer",
            "dnai-wikigen:arena-wallet-auth",
        ):
            raise ArenaAuthError("Arena wallet token issuer mismatch")
        if payload.get("aud") != _setting_text(
            self.settings,
            "arena_wallet_auth_audience",
            "dnai-wikigen:arena",
        ):
            raise ArenaAuthError("Arena wallet token audience mismatch")
        try:
            not_before = int(payload["nbf"])
            issued_at = int(payload["iat"])
            expires_at = int(payload["exp"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ArenaAuthError("Arena wallet token timestamps are invalid") from exc
        if not_before != issued_at or current < not_before:
            raise ArenaAuthError("Arena wallet token is not yet valid")
        if expires_at <= issued_at or current >= expires_at:
            raise ArenaAuthError("Arena wallet token expired")
        configured_ttl = _bounded_positive_int(
            getattr(self.settings, "arena_wallet_auth_token_ttl_seconds", 300),
            name="Arena wallet token ttl",
            maximum=900,
        )
        if expires_at - issued_at > configured_ttl:
            raise ArenaAuthError("Arena wallet token lifetime exceeds configured limit")

        address = normalize_wallet_address(str(payload.get("sub", "")))
        token_id = normalize_challenge_id(str(payload.get("challenge_id", "")))
        token_version = normalize_challenge_version(
            str(payload.get("challenge_version", ""))
        )
        expected_id = normalize_challenge_id(challenge_id)
        expected_version = normalize_challenge_version(challenge_version)
        if not hmac.compare_digest(token_id, expected_id) or not hmac.compare_digest(
            token_version,
            expected_version,
        ):
            raise ArenaAuthError("Arena wallet token is bound to a different challenge version")
        scopes = tuple(part for part in str(payload.get("scope", "")).split() if part)
        if scopes != ARENA_SESSION_SCOPES:
            raise ArenaAuthError("Arena wallet token contains unsupported scope")
        if required_scope not in scopes:
            raise ArenaAuthError("Arena wallet token is missing required scope")
        jwt_id = str(payload.get("jti", ""))
        if not _JTI_RE.fullmatch(jwt_id):
            raise ArenaAuthError("Arena wallet token id is invalid")
        return ArenaWalletTokenClaims(
            address=address,
            challenge_id=token_id,
            challenge_version=token_version,
            scopes=scopes,
            issued_at=issued_at,
            expires_at=expires_at,
            jwt_id=jwt_id,
        )


def normalize_challenge_id(value: str) -> str:
    if not isinstance(value, str) or not _CHALLENGE_ID_RE.fullmatch(value.strip()):
        raise ArenaAuthError("challenge id contains unsupported characters")
    return value.strip()


def normalize_challenge_version(value: str) -> str:
    if not isinstance(value, str) or not _CHALLENGE_VERSION_RE.fullmatch(value.strip()):
        raise ArenaAuthError("challenge version contains unsupported characters")
    return value.strip()


def arena_token_signing_key(settings: Any) -> bytes:
    """Resolve signing material in an Arena-specific cryptographic domain."""

    if dstack_utils.is_dstack_enabled():
        path = str(
            getattr(settings, "arena_wallet_auth_key_path", "tinker/arena_wallet_auth")
            or ""
        )
        if not path:
            raise ArenaAuthUnavailable("Arena wallet auth dstack key path is not configured")
        try:
            derived = dstack_utils.derive_storage_key(path)
        except Exception as exc:
            raise ArenaAuthUnavailable("Arena wallet auth dstack key derivation failed") from exc
        return hashlib.sha256(b"tinker-arena-wallet-auth:dstack:" + derived).digest()
    # Reuse the one local-development secret while retaining cryptographic
    # domain separation. Production dstack deployments use the distinct path.
    explicit = str(getattr(settings, "wallet_auth_signing_key", "") or "")
    if explicit:
        if len(explicit) < 32:
            raise ArenaAuthUnavailable(
                "local wallet signing key must be at least 32 characters"
            )
        return hashlib.sha256(
            b"tinker-arena-wallet-auth:local:" + explicit.encode("utf-8")
        ).digest()
    raise ArenaAuthUnavailable("Arena wallet auth signing key is unavailable outside dstack")


def _challenge_message(
    settings: Any,
    *,
    address: str,
    challenge_id: str,
    challenge_version: str,
    nonce: str,
    issued_at: int,
    expires_at: int,
) -> str:
    domain = _setting_text(settings, "wallet_auth_domain", "www.wikigen.me")
    uri = _setting_text(
        settings,
        "wallet_auth_uri",
        "https://www.wikigen.me",
    )
    chain_id = _bounded_positive_int(
        getattr(settings, "wallet_auth_chain_id", 84532),
        name="wallet auth chain id",
        maximum=2**63 - 1,
    )
    if chain_id != BASE_SEPOLIA_CHAIN_ID:
        raise ArenaAuthError("Arena wallet authentication requires Base Sepolia chain 84532")
    for field_name, field_value in (("domain", domain), ("uri", uri)):
        if "\n" in field_value or "\r" in field_value:
            raise ArenaAuthError(f"wallet auth {field_name} contains a newline")
    return (
        f"{domain} wants you to sign in with your Ethereum account:\n"
        f"{address}\n\n"
        "Authorize encrypted candidate submissions and read only your bounded "
        "submission status for the specified Arena challenge version during this "
        "short session. This request will not trigger a blockchain transaction.\n\n"
        f"URI: {uri}\n"
        "Version: 1\n"
        f"Chain ID: {chain_id}\n"
        f"Nonce: {nonce}\n"
        f"Issued At: {issued_at}\n"
        f"Expiration Time: {expires_at}\n"
        "Resources:\n"
        f"- urn:dnai:arena:challenge:{challenge_id}:version:{challenge_version}\n"
        f"- urn:dnai:scope:{ARENA_SUBMIT_SCOPE}\n"
        f"- urn:dnai:scope:{ARENA_OWNER_READ_SCOPE}"
    )


def _normalize_nonce(value: str) -> str:
    if not isinstance(value, str) or not _NONCE_RE.fullmatch(value):
        raise ArenaAuthError("Arena wallet challenge nonce is invalid")
    return value


def _bounded_positive_int(value: Any, *, name: str, maximum: int) -> int:
    try:
        normalized = int(value)
    except (TypeError, ValueError) as exc:
        raise ArenaAuthError(f"{name} must be an integer") from exc
    if normalized <= 0 or normalized > maximum:
        raise ArenaAuthError(f"{name} is outside the supported range")
    return normalized


def _setting_text(settings: Any, name: str, default: str) -> str:
    value = str(getattr(settings, name, "") or default).strip()
    if not value:
        raise ArenaAuthError(f"{name} must not be empty")
    return value


def _encode_token(payload: dict[str, Any], key: bytes) -> str:
    signing_input = b".".join((_b64url_json(_JWT_HEADER), _b64url_json(payload)))
    signature = hmac.new(key, signing_input, hashlib.sha256).digest()
    return (signing_input + b"." + _b64url(signature)).decode("ascii")


def _decode_token(token: str, key: bytes) -> dict[str, Any]:
    if not isinstance(token, str) or len(token) > 4096:
        raise ArenaAuthError("Arena wallet token format is invalid")
    parts = token.split(".")
    if len(parts) != 3 or any(not part for part in parts):
        raise ArenaAuthError("Arena wallet token format is invalid")
    try:
        signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    except UnicodeEncodeError as exc:
        raise ArenaAuthError("Arena wallet token encoding is invalid") from exc
    try:
        supplied_signature = _b64url_decode(parts[2])
    except ValueError as exc:
        raise ArenaAuthError("Arena wallet token signature is invalid") from exc
    expected_signature = hmac.new(key, signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(supplied_signature, expected_signature):
        raise ArenaAuthError("Arena wallet token signature is invalid")
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArenaAuthError("Arena wallet token JSON is invalid") from exc
    if header != _JWT_HEADER:
        raise ArenaAuthError("Arena wallet token header is unsupported")
    if not isinstance(payload, dict):
        raise ArenaAuthError("Arena wallet token payload is invalid")
    return payload


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
