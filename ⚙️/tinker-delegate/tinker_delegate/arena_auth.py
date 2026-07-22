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

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from tinker_delegate import dstack_utils
from tinker_delegate.crypto import encrypt_for_tee
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
ARENA_AGENT_MANAGE_SCOPE = "challenge:agents:manage"
ARENA_SESSION_SCOPES = (
    ARENA_SUBMIT_SCOPE,
    ARENA_OWNER_READ_SCOPE,
)
ARENA_AGENT_MANAGEMENT_SCOPES = (ARENA_AGENT_MANAGE_SCOPE,)
ARENA_AGENT_SCOPES = tuple(sorted((ARENA_SUBMIT_SCOPE, ARENA_OWNER_READ_SCOPE)))
ARENA_AGENT_CREDENTIAL_HKDF_INFO = b"dnai-wikigen-arena-agent-credential-v1"
ARENA_AGENT_CREDENTIAL_ISSUER = "dnai-wikigen:arena-agent-credential"
ARENA_AGENT_CREDENTIAL_AUDIENCE = "dnai-wikigen:arena-agent"
_CHALLENGE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_CHALLENGE_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
_JTI_RE = re.compile(r"^[0-9a-f]{32}$")
_RESOURCE_ID_RE = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
_JWT_PART_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_JWT_HEADER = {"alg": "HS256", "kid": "dstack-arena-wallet-v1", "typ": "JWT"}
_AGENT_JWT_HEADER = {
    "alg": "HS256",
    "kid": "dstack-arena-agent-v1",
    "typ": "JWT",
}
_AGENT_JWT_PAYLOAD_FIELDS = frozenset(
    {
        "iss",
        "aud",
        "sub",
        "device_id",
        "owner_address",
        "challenge_id",
        "challenge_version",
        "generation",
        "scope",
        "daily_submission_cap",
        "iat",
        "nbf",
        "exp",
        "jti",
    }
)
_WALLET_JWT_PAYLOAD_FIELDS = frozenset(
    {
        "iss",
        "aud",
        "sub",
        "challenge_id",
        "challenge_version",
        "scope",
        "iat",
        "nbf",
        "exp",
        "jti",
    }
)

# RFC 7748 low-order encodings. X25519PublicKey.from_public_bytes() accepts
# these syntactically, but ECDH yields an all-zero shared secret. Reject them
# before any durable device registration and still translate an exchange-time
# rejection below, so this boundary never turns attacker input into a 500.
_X25519_LOW_ORDER_PUBLIC_KEYS = frozenset(
    {
        "00" * 32,
        "01" + "00" * 31,
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ec" + "ff" * 30 + "7f",
        "ed" + "ff" * 30 + "7f",
        "ee" + "ff" * 30 + "7f",
    }
)


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


@dataclass(frozen=True)
class ArenaAgentCredentialClaims:
    """Exact challenge-version authority carried by one agent device token."""

    credential_id: str
    device_id: str
    owner_address: str
    challenge_id: str
    challenge_version: str
    generation: int
    scopes: tuple[str, ...]
    daily_submission_cap: int
    issued_at: int
    expires_at: int
    jwt_id: str

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "credential_id": self.credential_id,
            "device_id": self.device_id,
            "owner_address_hash": _stable_hash(
                self.owner_address, "arena_agent_owner"
            ),
            "challenge_id": self.challenge_id,
            "challenge_version": self.challenge_version,
            "generation": self.generation,
            "scopes": list(self.scopes),
            "daily_submission_cap": self.daily_submission_cap,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "jwt_id_hash": _stable_hash(
                self.jwt_id, "arena_agent_credential_jti"
            ),
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
        purpose: str = "session",
        now: int | None = None,
    ) -> ArenaWalletChallenge:
        issued_at = int(time.time() if now is None else now)
        normalized_address = normalize_wallet_address(address)
        normalized_id = normalize_challenge_id(challenge_id)
        normalized_version = normalize_challenge_version(challenge_version)
        if purpose == "session":
            scopes = ARENA_SESSION_SCOPES
        elif purpose == "agent_management":
            scopes = ARENA_AGENT_MANAGEMENT_SCOPES
        else:
            raise ArenaAuthError("Arena wallet authorization purpose is unsupported")
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
            scopes=scopes,
        )
        challenge = ArenaWalletChallenge(
            address=normalized_address,
            challenge_id=normalized_id,
            challenge_version=normalized_version,
            scope=" ".join(scopes),
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
        scopes = _arena_wallet_scopes(challenge.scope)
        claims = ArenaWalletTokenClaims(
            address=challenge.address,
            challenge_id=challenge.challenge_id,
            challenge_version=challenge.challenge_version,
            scopes=scopes,
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
        current = _strict_wallet_claim_int(
            int(time.time()) if now is None else now,
            "current time",
            0,
            4_102_444_800,
        )
        if set(payload) != _WALLET_JWT_PAYLOAD_FIELDS:
            raise ArenaAuthError("Arena wallet token payload schema is unsupported")
        if payload["iss"] != _setting_text(
            self.settings,
            "arena_wallet_auth_issuer",
            "dnai-wikigen:arena-wallet-auth",
        ):
            raise ArenaAuthError("Arena wallet token issuer mismatch")
        if payload["aud"] != _setting_text(
            self.settings,
            "arena_wallet_auth_audience",
            "dnai-wikigen:arena",
        ):
            raise ArenaAuthError("Arena wallet token audience mismatch")
        not_before = _strict_wallet_claim_int(
            payload["nbf"], "nbf", 0, 4_102_444_800
        )
        issued_at = _strict_wallet_claim_int(
            payload["iat"], "iat", 0, 4_102_444_800
        )
        expires_at = _strict_wallet_claim_int(
            payload["exp"], "exp", 1, 4_102_444_800
        )
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

        if not all(
            isinstance(payload[field], str)
            for field in ("sub", "challenge_id", "challenge_version", "scope", "jti")
        ):
            raise ArenaAuthError("Arena wallet token string claims are invalid")
        address = normalize_wallet_address(payload["sub"])
        token_id = normalize_challenge_id(payload["challenge_id"])
        token_version = normalize_challenge_version(payload["challenge_version"])
        expected_id = normalize_challenge_id(challenge_id)
        expected_version = normalize_challenge_version(challenge_version)
        if not hmac.compare_digest(token_id, expected_id) or not hmac.compare_digest(
            token_version,
            expected_version,
        ):
            raise ArenaAuthError("Arena wallet token is bound to a different challenge version")
        scopes = _arena_wallet_scopes(payload["scope"])
        if required_scope not in scopes:
            raise ArenaAuthError("Arena wallet token is missing required scope")
        jwt_id = payload["jti"]
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


def issue_arena_agent_credential_token(
    settings: Any,
    *,
    credential_id: str,
    device_id: str,
    owner_address: str,
    challenge_id: str,
    challenge_version: str,
    generation: int,
    scopes: list[str] | tuple[str, ...],
    daily_submission_cap: int,
    expires_at: int,
    now: int | None = None,
) -> tuple[ArenaAgentCredentialClaims, str]:
    """Issue one Arena-agent token in a purpose-separated JWT domain."""

    current = _strict_agent_claim_int(
        int(time.time()) if now is None else now,
        "current time",
        0,
        4_102_444_800,
    )
    credential_id = _agent_resource_id(credential_id, "credential_id")
    device_id = _agent_resource_id(device_id, "device_id")
    owner = normalize_wallet_address(owner_address)
    challenge = normalize_challenge_id(challenge_id)
    version = normalize_challenge_version(challenge_version)
    normalized_scopes = _normalize_agent_scopes(scopes)
    if (
        not isinstance(generation, int)
        or isinstance(generation, bool)
        or generation <= 0
        or generation > 1_000_000
    ):
        raise ArenaAuthError("Arena agent credential generation is invalid")
    if (
        not isinstance(daily_submission_cap, int)
        or isinstance(daily_submission_cap, bool)
        or daily_submission_cap <= 0
        or daily_submission_cap > 32
    ):
        raise ArenaAuthError("Arena agent daily submission cap is invalid")
    max_ttl = _bounded_positive_int(
        getattr(settings, "arena_agent_credential_max_ttl_seconds", 86_400),
        name="Arena agent credential max ttl",
        maximum=86_400,
    )
    if (
        not isinstance(expires_at, int)
        or isinstance(expires_at, bool)
        or expires_at <= current
        or expires_at > 4_102_444_800
        or expires_at - current > max_ttl
    ):
        raise ArenaAuthError(
            "Arena agent credential expiry exceeds the configured lifetime"
        )
    claims = ArenaAgentCredentialClaims(
        credential_id=credential_id,
        device_id=device_id,
        owner_address=owner,
        challenge_id=challenge,
        challenge_version=version,
        generation=generation,
        scopes=normalized_scopes,
        daily_submission_cap=daily_submission_cap,
        issued_at=current,
        expires_at=expires_at,
        jwt_id=secrets.token_hex(16),
    )
    payload = {
        "iss": ARENA_AGENT_CREDENTIAL_ISSUER,
        "aud": ARENA_AGENT_CREDENTIAL_AUDIENCE,
        "sub": claims.credential_id,
        "device_id": claims.device_id,
        "owner_address": claims.owner_address,
        "challenge_id": claims.challenge_id,
        "challenge_version": claims.challenge_version,
        "generation": claims.generation,
        "scope": " ".join(claims.scopes),
        "daily_submission_cap": claims.daily_submission_cap,
        "iat": claims.issued_at,
        "nbf": claims.issued_at,
        "exp": claims.expires_at,
        "jti": claims.jwt_id,
    }
    return claims, _encode_token(
        payload,
        arena_agent_credential_signing_key(settings),
        header=_AGENT_JWT_HEADER,
    )


def verify_arena_agent_credential_token(
    settings: Any,
    token: str,
    *,
    required_scope: str,
    challenge_id: str,
    challenge_version: str,
    now: int | None = None,
) -> ArenaAgentCredentialClaims:
    """Authenticate an agent token and its exact challenge/version binding."""

    if required_scope not in ARENA_AGENT_SCOPES:
        raise ArenaAuthError("unsupported required Arena agent scope")
    payload = _decode_token(
        token,
        arena_agent_credential_signing_key(settings),
        expected_header=_AGENT_JWT_HEADER,
    )
    current = _strict_agent_claim_int(
        int(time.time()) if now is None else now,
        "current time",
        0,
        4_102_444_800,
    )
    if set(payload) != _AGENT_JWT_PAYLOAD_FIELDS:
        raise ArenaAuthError("Arena agent credential payload schema is unsupported")
    if payload["iss"] != ARENA_AGENT_CREDENTIAL_ISSUER:
        raise ArenaAuthError("Arena agent credential issuer mismatch")
    if payload["aud"] != ARENA_AGENT_CREDENTIAL_AUDIENCE:
        raise ArenaAuthError("Arena agent credential audience mismatch")
    issued_at = _strict_agent_claim_int(payload["iat"], "iat", 0, 4_102_444_800)
    not_before = _strict_agent_claim_int(payload["nbf"], "nbf", 0, 4_102_444_800)
    expires_at = _strict_agent_claim_int(payload["exp"], "exp", 1, 4_102_444_800)
    generation = _strict_agent_claim_int(payload["generation"], "generation", 1, 1_000_000)
    daily_submission_cap = _strict_agent_claim_int(
        payload["daily_submission_cap"], "daily_submission_cap", 1, 32
    )
    if not_before != issued_at or current < not_before:
        raise ArenaAuthError("Arena agent credential is not yet valid")
    if expires_at <= issued_at or current >= expires_at:
        raise ArenaAuthError("Arena agent credential expired")
    max_ttl = _bounded_positive_int(
        getattr(settings, "arena_agent_credential_max_ttl_seconds", 86_400),
        name="Arena agent credential max ttl",
        maximum=86_400,
    )
    if expires_at - issued_at > max_ttl:
        raise ArenaAuthError("Arena agent credential lifetime exceeds configured limit")
    credential_id = _agent_resource_id(payload["sub"], "credential_id")
    device_id = _agent_resource_id(payload["device_id"], "device_id")
    if not isinstance(payload["owner_address"], str):
        raise ArenaAuthError("Arena agent credential owner is invalid")
    if not isinstance(payload["challenge_id"], str) or not isinstance(
        payload["challenge_version"], str
    ):
        raise ArenaAuthError("Arena agent credential challenge binding is invalid")
    owner = normalize_wallet_address(payload["owner_address"])
    token_challenge = normalize_challenge_id(payload["challenge_id"])
    token_version = normalize_challenge_version(payload["challenge_version"])
    expected_challenge = normalize_challenge_id(challenge_id)
    expected_version = normalize_challenge_version(challenge_version)
    if not hmac.compare_digest(token_challenge, expected_challenge) or not hmac.compare_digest(
        token_version, expected_version
    ):
        raise ArenaAuthError(
            "Arena agent credential is bound to a different challenge version"
        )
    if not isinstance(payload["scope"], str):
        raise ArenaAuthError("Arena agent credential scope is invalid")
    if payload["scope"] != " ".join(ARENA_AGENT_SCOPES):
        raise ArenaAuthError("Arena agent credential scope is not canonical")
    scopes = ARENA_AGENT_SCOPES
    if required_scope not in scopes:
        raise ArenaAuthError("Arena agent credential is missing required scope")
    jwt_id = payload["jti"]
    if not isinstance(jwt_id, str):
        raise ArenaAuthError("Arena agent credential token id is invalid")
    if not _JTI_RE.fullmatch(jwt_id):
        raise ArenaAuthError("Arena agent credential token id is invalid")
    return ArenaAgentCredentialClaims(
        credential_id=credential_id,
        device_id=device_id,
        owner_address=owner,
        challenge_id=token_challenge,
        challenge_version=token_version,
        generation=generation,
        scopes=scopes,
        daily_submission_cap=daily_submission_cap,
        issued_at=issued_at,
        expires_at=expires_at,
        jwt_id=jwt_id,
    )


def encrypt_arena_agent_credential_token(
    token: str,
    *,
    recipient_public_key_hex: str,
    claims: ArenaAgentCredentialClaims,
) -> dict[str, Any]:
    """Encrypt one agent token to its device; plaintext is never returned."""

    public_key_hex, public_key_bytes = validate_arena_agent_device_public_key(
        recipient_public_key_hex
    )
    associated_data = json.dumps(
        {
            "surface": "arena_agent_credential",
            "credential_id": claims.credential_id,
            "device_id": claims.device_id,
            "owner_address_hash": _stable_hash(
                claims.owner_address, "arena_agent_owner"
            ),
            "challenge_id": claims.challenge_id,
            "challenge_version": claims.challenge_version,
            "generation": claims.generation,
            "jwt_id_hash": _stable_hash(
                claims.jwt_id, "arena_agent_credential_jti"
            ),
            "expires_at": claims.expires_at,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    try:
        envelope = encrypt_for_tee(
            token.encode("utf-8"),
            public_key_bytes,
            info=ARENA_AGENT_CREDENTIAL_HKDF_INFO,
            associated_data=associated_data,
        )
    except (TypeError, ValueError) as exc:
        raise ArenaAuthError("Arena agent device public key is low-order or invalid") from exc
    return {
        "delivery": "x25519_aes_256_gcm_envelope",
        "encrypted_token": envelope.to_hex(),
        "associated_data": associated_data.hex(),
        "associated_data_hash": _stable_hash(
            associated_data.hex(), "arena_agent_credential_aad"
        ),
        "recipient_public_key_hash": _stable_hash(
            public_key_hex, "arena_agent_device_key"
        ),
        "plaintext_token_returned": False,
    }


def classify_arena_token(token: str) -> str:
    """Route only exact Arena wallet or Arena-agent JWT headers."""

    if not isinstance(token, str) or len(token) > 4_096:
        raise ArenaAuthError("Arena token format is invalid")
    parts = token.split(".")
    if len(parts) != 3 or any(not _JWT_PART_RE.fullmatch(part) for part in parts):
        raise ArenaAuthError("Arena token format is invalid")
    try:
        header = json.loads(_b64url_decode(parts[0]))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArenaAuthError("Arena token header is invalid") from exc
    if header == _JWT_HEADER:
        return "wallet"
    if header == _AGENT_JWT_HEADER:
        return "agent"
    raise ArenaAuthError("Arena token header is unsupported")


def _normalize_agent_scopes(
    scopes: list[str] | tuple[str, ...],
) -> tuple[str, ...]:
    if not isinstance(scopes, (list, tuple)) or any(
        not isinstance(scope, str) for scope in scopes
    ):
        raise ArenaAuthError("Arena agent credential scopes are invalid")
    normalized = tuple(scopes)
    if normalized != ARENA_AGENT_SCOPES:
        raise ArenaAuthError(
            "Arena agent credentials require exact ordered submit and owner-read scopes"
        )
    return normalized


def _agent_resource_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _RESOURCE_ID_RE.fullmatch(value):
        raise ArenaAuthError(f"Arena agent {label} is malformed")
    return value


def _strict_agent_claim_int(
    value: Any, label: str, minimum: int, maximum: int
) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < minimum
        or value > maximum
    ):
        raise ArenaAuthError(f"Arena agent credential {label} claim is invalid")
    return value


def _strict_wallet_claim_int(
    value: Any, label: str, minimum: int, maximum: int
) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < minimum
        or value > maximum
    ):
        raise ArenaAuthError(f"Arena wallet token {label} claim is invalid")
    return value


def _arena_wallet_scopes(value: Any) -> tuple[str, ...]:
    if value == " ".join(ARENA_SESSION_SCOPES):
        return ARENA_SESSION_SCOPES
    if value == " ".join(ARENA_AGENT_MANAGEMENT_SCOPES):
        return ARENA_AGENT_MANAGEMENT_SCOPES
    raise ArenaAuthError("Arena wallet token scope is not canonical")


def validate_arena_agent_device_public_key(value: Any) -> tuple[str, bytes]:
    """Return a canonical X25519 key after rejecting every known low-order point."""

    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise ArenaAuthError(
            "Arena agent device public key must be 32-byte X25519 hex"
        )
    canonical = value.lower()
    public_key_bytes = bytes.fromhex(canonical)
    if int.from_bytes(public_key_bytes, "little") >= 2**255 - 19:
        raise ArenaAuthError("Arena agent device public key is non-canonical")
    if canonical in _X25519_LOW_ORDER_PUBLIC_KEYS:
        raise ArenaAuthError("Arena agent device public key is low-order or invalid")
    try:
        X25519PublicKey.from_public_bytes(public_key_bytes)
    except ValueError as exc:
        raise ArenaAuthError(
            "Arena agent device public key must be 32-byte X25519 hex"
        ) from exc
    return canonical, public_key_bytes


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


def arena_agent_credential_signing_key(settings: Any) -> bytes:
    """Resolve a key that cannot validate wallet, Compute, or Deal tokens."""

    return _arena_agent_key(
        settings,
        explicit_name="arena_agent_credential_signing_key",
        path_name="arena_agent_credential_key_path",
        default_path="tinker/arena_agent_credentials",
        domain=b"tinker-arena-agent-credential-v1:",
    )


def arena_agent_store_integrity_key(settings: Any) -> bytes:
    """Resolve an independent HMAC key for persisted credential status."""

    return _arena_agent_key(
        settings,
        explicit_name="arena_agent_store_integrity_key",
        path_name="arena_agent_store_integrity_key_path",
        default_path="tinker/arena_agent_store_integrity",
        domain=b"tinker-arena-agent-store-integrity-v1:",
    )


def _arena_agent_key(
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
            raise ArenaAuthUnavailable("Arena agent dstack key path is not configured")
        try:
            material = dstack_utils.derive_storage_key(path)
        except Exception as exc:
            raise ArenaAuthUnavailable("Arena agent dstack key derivation failed") from exc
        return hashlib.sha256(domain + b"dstack:" + material).digest()
    explicit = str(getattr(settings, explicit_name, "") or "")
    if not explicit:
        # Local development may reuse the wallet secret as input material, but
        # the purpose-specific domain still produces an unrelated key.  A CVM
        # always uses the independent dstack path above.
        explicit = str(getattr(settings, "wallet_auth_signing_key", "") or "")
    if len(explicit) < 32:
        raise ArenaAuthUnavailable(
            f"{explicit_name} must be at least 32 characters outside dstack"
        )
    return hashlib.sha256(domain + b"local:" + explicit.encode("utf-8")).digest()


def _challenge_message(
    settings: Any,
    *,
    address: str,
    challenge_id: str,
    challenge_version: str,
    nonce: str,
    issued_at: int,
    expires_at: int,
    scopes: tuple[str, ...],
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
    if scopes == ARENA_SESSION_SCOPES:
        statement = (
            "Authorize encrypted candidate submissions and read only your bounded "
            "submission status for the specified challenge version during this "
            "short session. This request will not trigger a blockchain transaction."
        )
    elif scopes == ARENA_AGENT_MANAGEMENT_SCOPES:
        statement = (
            "Authorize management of delegated Arena agent credentials for the "
            "specified challenge version during this short session. Management may "
            "issue a submit + owner-read bearer valid for up to 24 hours, or list, "
            "rotate, and revoke those credentials. This request will not trigger a "
            "blockchain transaction."
        )
    else:
        raise ArenaAuthError("Arena wallet authorization scope is unsupported")
    resources = "\n".join(f"- urn:dnai:scope:{scope}" for scope in scopes)
    return (
        f"{domain} wants you to sign in with your Ethereum account:\n"
        f"{address}\n\n"
        f"{statement}\n\n"
        f"URI: {uri}\n"
        "Version: 1\n"
        f"Chain ID: {chain_id}\n"
        f"Nonce: {nonce}\n"
        f"Issued At: {issued_at}\n"
        f"Expiration Time: {expires_at}\n"
        "Resources:\n"
        f"- urn:dnai:arena:challenge:{challenge_id}:version:{challenge_version}\n"
        f"{resources}"
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


def _encode_token(
    payload: dict[str, Any],
    key: bytes,
    *,
    header: dict[str, str] = _JWT_HEADER,
) -> str:
    signing_input = b".".join((_b64url_json(header), _b64url_json(payload)))
    signature = hmac.new(key, signing_input, hashlib.sha256).digest()
    return (signing_input + b"." + _b64url(signature)).decode("ascii")


def _decode_token(
    token: str,
    key: bytes,
    *,
    expected_header: dict[str, str] = _JWT_HEADER,
) -> dict[str, Any]:
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
    if header != expected_header:
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


def _stable_hash(value: str, prefix: str) -> str:
    return hashlib.sha256(
        prefix.encode("ascii") + b":" + value.encode("utf-8")
    ).hexdigest()
