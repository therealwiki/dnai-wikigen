"""Authentication primitives for the off-chain Compute Console.

Compute Console authentication is deliberately isolated from deal upload,
Arena, upstream Tinker proxy, and operator-runtime authentication.  Wallets
exchange a one-time Base Sepolia ``personal_sign`` challenge for a short-lived
console token.  Project credentials are separate, scoped JWTs whose plaintext
is delivered only inside an X25519/AES-GCM envelope to a registered device.

Device encryption binds credential *delivery* to the device key.  It is not a
claim of hardware attestation or per-request proof-of-possession.
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


COMPUTE_CONSOLE_SCOPE = "compute:console"
SUPPORTED_COMPUTE_CREDENTIAL_SCOPES = frozenset(
    {
        "jobs:create",
        "jobs:read",
        "workloads:create",
        "workloads:delete",
        "challenge:submit",
        "submissions:read",
        "receipts:read",
    }
)
COMPUTE_CREDENTIAL_HKDF_INFO = b"dnai-wikigen-compute-credential-v1"

_NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
_JTI_RE = re.compile(r"^[0-9a-f]{32}$")
_RESOURCE_ID_RE = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
_JWT_PART_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_WALLET_HEADER = {"alg": "HS256", "kid": "dstack-compute-wallet-v1", "typ": "JWT"}
_CREDENTIAL_HEADER = {
    "alg": "HS256",
    "kid": "dstack-compute-credential-v1",
    "typ": "JWT",
}


class ComputeAuthError(ValueError):
    """Raised when a Compute challenge, signature, or token is invalid."""


class ComputeAuthUnavailable(RuntimeError):
    """Raised when Compute key material or chain verification is unavailable."""


class ComputeChallengeCapacityError(RuntimeError):
    """Raised rather than evicting a still-valid login challenge."""


@dataclass(frozen=True)
class ComputeWalletChallenge:
    address: str
    nonce: str
    message: str
    issued_at: int
    expires_at: int
    scope: str = COMPUTE_CONSOLE_SCOPE

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "nonce": self.nonce,
            "message": self.message,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "scope": self.scope,
            "chain_id": 84532,
        }


@dataclass(frozen=True)
class ComputeWalletClaims:
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
            "jwt_id_hash": _stable_hash(self.jwt_id, "compute_wallet_jti"),
        }


@dataclass(frozen=True)
class ComputeCredentialClaims:
    credential_id: str
    project_id: str
    device_id: str
    generation: int
    scopes: tuple[str, ...]
    daily_credit_cap: int
    issued_at: int
    expires_at: int
    jwt_id: str

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "credential_id": self.credential_id,
            "project_id": self.project_id,
            "device_id": self.device_id,
            "generation": self.generation,
            "scopes": list(self.scopes),
            "daily_credit_cap": self.daily_credit_cap,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "jwt_id_hash": _stable_hash(self.jwt_id, "compute_credential_jti"),
        }


class ComputeWalletChallengeStore:
    """Bounded process-local single-use challenge store."""

    def __init__(self, *, max_pending: int = 1024) -> None:
        if not isinstance(max_pending, int) or isinstance(max_pending, bool) or max_pending <= 0:
            raise ValueError("Compute wallet challenge capacity must be positive")
        self.max_pending = max_pending
        self._records: dict[str, ComputeWalletChallenge] = {}
        self._verification_attempts: dict[str, int] = {}
        self._verification_in_flight: set[str] = set()
        self._lock = threading.Lock()

    def put(self, challenge: ComputeWalletChallenge, *, now: int) -> None:
        with self._lock:
            self._prune_locked(now)
            if len(self._records) >= self.max_pending:
                raise ComputeChallengeCapacityError("Compute wallet challenge capacity reached")
            self._records[challenge.nonce] = challenge
            self._verification_attempts[challenge.nonce] = 0
            self._verification_in_flight.discard(challenge.nonce)

    def consume_verified(
        self, nonce: str, signature: str, *, now: int
    ) -> ComputeWalletChallenge:
        challenge = self.reserve_verification(nonce, now=now)
        verified = False
        try:
            try:
                recovered = recover_wallet_address(challenge.message, signature)
            except WalletAuthError as exc:
                raise ComputeAuthError(str(exc)) from exc
            if not hmac.compare_digest(recovered, challenge.address):
                raise ComputeAuthError(
                    "Compute wallet signature does not match challenge address"
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
    ) -> ComputeWalletChallenge:
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
                raise ComputeAuthError(
                    "Compute wallet challenge is unknown, expired, or already used"
                )
            self._verification_attempts[nonce] = attempts + 1
            self._verification_in_flight.add(nonce)
            return challenge

    def release_verification(
        self,
        nonce: str,
        expected: ComputeWalletChallenge,
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

    def get_pending(self, nonce: str, *, now: int) -> ComputeWalletChallenge:
        """Return an immutable challenge before any external verification."""

        with self._lock:
            self._prune_locked(now)
            challenge = self._records.get(nonce)
            if challenge is None:
                raise ComputeAuthError(
                    "Compute wallet challenge is unknown, expired, or already used"
                )
            return challenge

    def consume_if_current(
        self,
        nonce: str,
        expected: ComputeWalletChallenge,
        *,
        now: int,
    ) -> ComputeWalletChallenge:
        """Compare-and-delete after verification outside the store lock."""

        with self._lock:
            self._prune_locked(now)
            challenge = self._records.get(nonce)
            if (
                challenge is None
                or challenge is not expected
                or nonce not in self._verification_in_flight
            ):
                raise ComputeAuthError(
                    "Compute wallet challenge is unknown, expired, or already used"
                )
            self._delete_locked(nonce)
            return challenge

    def clear(self) -> None:
        with self._lock:
            self._records.clear()
            self._verification_attempts.clear()
            self._verification_in_flight.clear()

    def _prune_locked(self, now: int) -> None:
        for nonce in [
            key for key, value in self._records.items() if now >= value.expires_at
        ]:
            self._delete_locked(nonce)

    def _delete_locked(self, nonce: str) -> None:
        self._records.pop(nonce, None)
        self._verification_attempts.pop(nonce, None)
        self._verification_in_flight.discard(nonce)


class ComputeWalletAuthService:
    """Issue and verify short-lived, console-only wallet tokens."""

    def __init__(
        self,
        settings: Any,
        store: ComputeWalletChallengeStore,
        signature_verifier: WalletSignatureVerifier | None = None,
    ) -> None:
        self.settings = settings
        self.store = store
        self.signature_verifier = signature_verifier

    def issue_challenge(
        self, *, address: str, now: int | None = None
    ) -> ComputeWalletChallenge:
        issued_at = int(time.time() if now is None else now)
        normalized_address = normalize_wallet_address(address)
        compute_wallet_signing_key(self.settings)
        ttl = _bounded_positive_int(
            getattr(self.settings, "compute_wallet_auth_challenge_ttl_seconds", 300),
            label="Compute wallet challenge ttl",
            maximum=600,
        )
        nonce = secrets.token_hex(16)
        expires_at = issued_at + ttl
        challenge = ComputeWalletChallenge(
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
        self, *, nonce: str, signature: str, now: int | None = None
    ) -> tuple[ComputeWalletClaims, str]:
        current = int(time.time() if now is None else now)
        if not isinstance(nonce, str) or not _NONCE_RE.fullmatch(nonce):
            raise ComputeAuthError("Compute wallet challenge nonce is invalid")
        ttl = _bounded_positive_int(
            getattr(self.settings, "compute_wallet_auth_token_ttl_seconds", 600),
            label="Compute wallet token ttl",
            maximum=900,
        )
        key = compute_wallet_signing_key(self.settings)
        challenge = self.store.reserve_verification(nonce, now=current)
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
            raise ComputeAuthUnavailable(
                "Compute wallet signature verification is unavailable"
            ) from exc
        except WalletSignatureError as exc:
            raise ComputeAuthError(str(exc)) from exc
        except Exception as exc:
            raise ComputeAuthUnavailable(
                "Compute wallet signature verification is unavailable"
            ) from exc
        finally:
            if not verified:
                self.store.release_verification(nonce, challenge)
        consumed_at = current if now is not None else int(time.time())
        challenge = self.store.consume_if_current(
            nonce,
            challenge,
            now=consumed_at,
        )
        claims = ComputeWalletClaims(
            address=challenge.address,
            scopes=(COMPUTE_CONSOLE_SCOPE,),
            issued_at=consumed_at,
            expires_at=consumed_at + ttl,
            jwt_id=secrets.token_hex(16),
        )
        token = _encode_token(
            {
                "iss": _setting_text(
                    self.settings,
                    "compute_wallet_auth_issuer",
                    "dnai-wikigen:compute-wallet-auth",
                ),
                "aud": _setting_text(
                    self.settings,
                    "compute_wallet_auth_audience",
                    "dnai-wikigen:compute-console",
                ),
                "sub": claims.address,
                "scope": COMPUTE_CONSOLE_SCOPE,
                "iat": claims.issued_at,
                "nbf": claims.issued_at,
                "exp": claims.expires_at,
                "jti": claims.jwt_id,
            },
            key,
            _WALLET_HEADER,
        )
        return claims, token

    def verify_token(
        self,
        token: str,
        *,
        required_scope: str = COMPUTE_CONSOLE_SCOPE,
        now: int | None = None,
    ) -> ComputeWalletClaims:
        payload = _decode_token(token, compute_wallet_signing_key(self.settings), _WALLET_HEADER)
        current = int(time.time() if now is None else now)
        if payload.get("iss") != _setting_text(
            self.settings,
            "compute_wallet_auth_issuer",
            "dnai-wikigen:compute-wallet-auth",
        ):
            raise ComputeAuthError("Compute wallet token issuer mismatch")
        if payload.get("aud") != _setting_text(
            self.settings,
            "compute_wallet_auth_audience",
            "dnai-wikigen:compute-console",
        ):
            raise ComputeAuthError("Compute wallet token audience mismatch")
        issued_at, expires_at = _validate_times(
            payload,
            now=current,
            max_ttl=_bounded_positive_int(
                getattr(self.settings, "compute_wallet_auth_token_ttl_seconds", 600),
                label="Compute wallet token ttl",
                maximum=900,
            ),
            token_label="Compute wallet token",
        )
        try:
            address = normalize_wallet_address(str(payload.get("sub", "")))
        except WalletAuthError as exc:
            raise ComputeAuthError(str(exc)) from exc
        scopes = tuple(str(payload.get("scope", "")).split())
        if scopes != (COMPUTE_CONSOLE_SCOPE,) or required_scope not in scopes:
            raise ComputeAuthError("Compute wallet token scope is invalid")
        jwt_id = str(payload.get("jti", ""))
        if not _JTI_RE.fullmatch(jwt_id):
            raise ComputeAuthError("Compute wallet token id is invalid")
        return ComputeWalletClaims(
            address=address,
            scopes=scopes,
            issued_at=issued_at,
            expires_at=expires_at,
            jwt_id=jwt_id,
        )


def issue_compute_credential_token(
    settings: Any,
    *,
    credential_id: str,
    project_id: str,
    device_id: str,
    generation: int,
    scopes: list[str] | tuple[str, ...],
    daily_credit_cap: int,
    expires_at: int,
    now: int | None = None,
) -> tuple[ComputeCredentialClaims, str]:
    """Issue one credential JWT; callers must persist its commitment/status."""

    current = int(time.time() if now is None else now)
    normalized_scopes = normalize_compute_scopes(scopes)
    for label, value in (
        ("credential_id", credential_id),
        ("project_id", project_id),
        ("device_id", device_id),
    ):
        if not isinstance(value, str) or not _RESOURCE_ID_RE.fullmatch(value):
            raise ComputeAuthError(f"{label} is malformed")
    if not isinstance(generation, int) or isinstance(generation, bool) or generation <= 0:
        raise ComputeAuthError("credential generation is invalid")
    if (
        not isinstance(daily_credit_cap, int)
        or isinstance(daily_credit_cap, bool)
        or daily_credit_cap <= 0
        or daily_credit_cap > 1_000_000
    ):
        raise ComputeAuthError("credential daily credit cap is invalid")
    max_ttl = _bounded_positive_int(
        getattr(settings, "compute_credential_max_ttl_seconds", 604800),
        label="Compute credential max ttl",
        maximum=604800,
    )
    if (
        not isinstance(expires_at, int)
        or isinstance(expires_at, bool)
        or expires_at <= current
        or expires_at - current > max_ttl
    ):
        raise ComputeAuthError("credential expiry exceeds the configured lifetime")
    claims = ComputeCredentialClaims(
        credential_id=credential_id,
        project_id=project_id,
        device_id=device_id,
        generation=generation,
        scopes=normalized_scopes,
        daily_credit_cap=daily_credit_cap,
        issued_at=current,
        expires_at=expires_at,
        jwt_id=secrets.token_hex(16),
    )
    token = _encode_token(
        {
            "iss": _setting_text(
                settings,
                "compute_credential_issuer",
                "dnai-wikigen:compute-credential",
            ),
            "aud": _setting_text(
                settings,
                "compute_credential_audience",
                "dnai-wikigen:compute-jobs",
            ),
            "sub": claims.credential_id,
            "project_id": claims.project_id,
            "device_id": claims.device_id,
            "generation": claims.generation,
            "scope": " ".join(claims.scopes),
            "daily_credit_cap": claims.daily_credit_cap,
            "iat": claims.issued_at,
            "nbf": claims.issued_at,
            "exp": claims.expires_at,
            "jti": claims.jwt_id,
        },
        compute_credential_signing_key(settings),
        _CREDENTIAL_HEADER,
    )
    return claims, token


def verify_compute_credential_token(
    settings: Any,
    token: str,
    *,
    required_scope: str,
    now: int | None = None,
) -> ComputeCredentialClaims:
    if required_scope not in SUPPORTED_COMPUTE_CREDENTIAL_SCOPES:
        raise ComputeAuthError("unsupported required Compute credential scope")
    payload = _decode_token(
        token,
        compute_credential_signing_key(settings),
        _CREDENTIAL_HEADER,
    )
    current = int(time.time() if now is None else now)
    if payload.get("iss") != _setting_text(
        settings, "compute_credential_issuer", "dnai-wikigen:compute-credential"
    ):
        raise ComputeAuthError("Compute credential issuer mismatch")
    if payload.get("aud") != _setting_text(
        settings, "compute_credential_audience", "dnai-wikigen:compute-jobs"
    ):
        raise ComputeAuthError("Compute credential audience mismatch")
    issued_at, expires_at = _validate_times(
        payload,
        now=current,
        max_ttl=_bounded_positive_int(
            getattr(settings, "compute_credential_max_ttl_seconds", 604800),
            label="Compute credential max ttl",
            maximum=604800,
        ),
        token_label="Compute credential",
    )
    try:
        credential_id = _resource_id(payload.get("sub"), "credential_id")
        project_id = _resource_id(payload.get("project_id"), "project_id")
        device_id = _resource_id(payload.get("device_id"), "device_id")
        generation = int(payload["generation"])
        daily_credit_cap = int(payload["daily_credit_cap"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ComputeAuthError("Compute credential claims are invalid") from exc
    if generation <= 0 or daily_credit_cap <= 0 or daily_credit_cap > 1_000_000:
        raise ComputeAuthError("Compute credential limits are invalid")
    scopes = normalize_compute_scopes(str(payload.get("scope", "")).split())
    if required_scope not in scopes:
        raise ComputeAuthError("Compute credential is missing required scope")
    jwt_id = str(payload.get("jti", ""))
    if not _JTI_RE.fullmatch(jwt_id):
        raise ComputeAuthError("Compute credential token id is invalid")
    return ComputeCredentialClaims(
        credential_id=credential_id,
        project_id=project_id,
        device_id=device_id,
        generation=generation,
        scopes=scopes,
        daily_credit_cap=daily_credit_cap,
        issued_at=issued_at,
        expires_at=expires_at,
        jwt_id=jwt_id,
    )


def encrypt_compute_credential_token(
    token: str,
    *,
    recipient_public_key_hex: str,
    claims: ComputeCredentialClaims,
) -> dict[str, Any]:
    """Encrypt a credential JWT to a device key without returning plaintext."""

    try:
        public_key_bytes = bytes.fromhex(recipient_public_key_hex)
        X25519PublicKey.from_public_bytes(public_key_bytes)
    except (TypeError, ValueError) as exc:
        raise ComputeAuthError("device public key must be 32-byte X25519 hex") from exc
    if len(public_key_bytes) != 32:
        raise ComputeAuthError("device public key must be 32-byte X25519 hex")
    associated_data = json.dumps(
        {
            "surface": "compute_credential",
            "credential_id": claims.credential_id,
            "project_id": claims.project_id,
            "device_id": claims.device_id,
            "generation": claims.generation,
            "jwt_id_hash": _stable_hash(claims.jwt_id, "compute_credential_jti"),
            "expires_at": claims.expires_at,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    envelope = encrypt_for_tee(
        token.encode("utf-8"),
        public_key_bytes,
        info=COMPUTE_CREDENTIAL_HKDF_INFO,
        associated_data=associated_data,
    )
    return {
        "delivery": "x25519_aes_256_gcm_envelope",
        "encrypted_token": envelope.to_hex(),
        "associated_data": associated_data.hex(),
        "associated_data_hash": _stable_hash(
            associated_data.hex(), "compute_credential_aad"
        ),
        "recipient_public_key_hash": _stable_hash(
            recipient_public_key_hex.lower(), "compute_device_key"
        ),
        "plaintext_token_returned": False,
    }


def normalize_compute_scopes(scopes: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    if not isinstance(scopes, (list, tuple)):
        raise ComputeAuthError("Compute credential scopes must be a list")
    if any(not isinstance(scope, str) for scope in scopes):
        raise ComputeAuthError("Compute credential scope is invalid")
    normalized = tuple(sorted({scope.strip() for scope in scopes if scope.strip()}))
    if not normalized or len(normalized) > len(SUPPORTED_COMPUTE_CREDENTIAL_SCOPES):
        raise ComputeAuthError("at least one bounded Compute credential scope is required")
    if any(scope not in SUPPORTED_COMPUTE_CREDENTIAL_SCOPES for scope in normalized):
        raise ComputeAuthError("unsupported Compute credential scope")
    return normalized


def classify_compute_token(token: str) -> str:
    """Return ``wallet`` or ``credential`` from the exact JWT header.

    This is only routing metadata. The selected verifier still authenticates
    the signature and every claim before the token is trusted.
    """

    if not isinstance(token, str) or len(token) > 4096:
        raise ComputeAuthError("Compute token format is invalid")
    parts = token.split(".")
    if len(parts) != 3 or any(not _JWT_PART_RE.fullmatch(part) for part in parts):
        raise ComputeAuthError("Compute token format is invalid")
    try:
        header = json.loads(_b64url_decode(parts[0]))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ComputeAuthError("Compute token header is invalid") from exc
    if header == _WALLET_HEADER:
        return "wallet"
    if header == _CREDENTIAL_HEADER:
        return "credential"
    raise ComputeAuthError("Compute token header is unsupported")


def compute_wallet_signing_key(settings: Any) -> bytes:
    return _resolve_key(
        settings,
        explicit_name="compute_wallet_auth_signing_key",
        path_name="compute_wallet_auth_key_path",
        default_path="tinker/compute_wallet_auth",
        domain=b"dnai-compute-wallet-auth-v1:",
    )


def compute_credential_signing_key(settings: Any) -> bytes:
    return _resolve_key(
        settings,
        explicit_name="compute_credential_signing_key",
        path_name="compute_credential_key_path",
        default_path="tinker/compute_credentials",
        domain=b"dnai-compute-credential-v1:",
    )


def compute_store_integrity_key(settings: Any) -> bytes:
    return _resolve_key(
        settings,
        explicit_name="compute_store_integrity_key",
        path_name="compute_store_integrity_key_path",
        default_path="tinker/compute_store_integrity",
        domain=b"dnai-compute-store-integrity-v1:",
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
            raise ComputeAuthUnavailable("Compute dstack key path is not configured")
        try:
            material = dstack_utils.derive_storage_key(path)
        except Exception as exc:
            raise ComputeAuthUnavailable("Compute dstack key derivation failed") from exc
        return hashlib.sha256(domain + b"dstack:" + material).digest()
    explicit = str(getattr(settings, explicit_name, "") or "")
    if len(explicit) < 32:
        raise ComputeAuthUnavailable(
            f"{explicit_name} must be at least 32 characters outside dstack"
        )
    return hashlib.sha256(domain + b"local:" + explicit.encode("utf-8")).digest()


def _challenge_message(
    settings: Any,
    *,
    address: str,
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
        label="Compute wallet chain id",
        maximum=2**63 - 1,
    )
    if chain_id != BASE_SEPOLIA_CHAIN_ID:
        raise ComputeAuthError("Compute Console wallet auth requires Base Sepolia chain 84532")
    if any("\n" in value or "\r" in value for value in (domain, uri)):
        raise ComputeAuthError("Compute wallet auth domain or uri contains a newline")
    return (
        f"{domain} wants you to sign in with your Ethereum account:\n"
        f"{address}\n\n"
        "Authorize access to the off-chain Compute Console. This signature "
        "will not trigger a blockchain transaction or transfer funds.\n\n"
        f"URI: {uri}\n"
        "Version: 1\n"
        f"Chain ID: {chain_id}\n"
        f"Nonce: {nonce}\n"
        f"Issued At: {issued_at}\n"
        f"Expiration Time: {expires_at}\n"
        "Resources:\n"
        f"- urn:dnai:scope:{COMPUTE_CONSOLE_SCOPE}"
    )


def _validate_times(
    payload: dict[str, Any], *, now: int, max_ttl: int, token_label: str
) -> tuple[int, int]:
    try:
        issued_at = int(payload["iat"])
        not_before = int(payload["nbf"])
        expires_at = int(payload["exp"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ComputeAuthError(f"{token_label} timestamps are invalid") from exc
    if not_before != issued_at or now < not_before:
        raise ComputeAuthError(f"{token_label} is not yet valid")
    if expires_at <= issued_at or now >= expires_at:
        raise ComputeAuthError(f"{token_label} expired")
    if expires_at - issued_at > max_ttl:
        raise ComputeAuthError(f"{token_label} lifetime exceeds configured limit")
    return issued_at, expires_at


def _resource_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _RESOURCE_ID_RE.fullmatch(value):
        raise ComputeAuthError(f"{label} is malformed")
    return value


def _bounded_positive_int(value: Any, *, label: str, maximum: int) -> int:
    if isinstance(value, bool):
        raise ComputeAuthError(f"{label} must be an integer")
    try:
        normalized = int(value)
    except (TypeError, ValueError) as exc:
        raise ComputeAuthError(f"{label} must be an integer") from exc
    if normalized <= 0 or normalized > maximum:
        raise ComputeAuthError(f"{label} is outside the supported range")
    return normalized


def _setting_text(settings: Any, name: str, default: str) -> str:
    value = str(getattr(settings, name, "") or default).strip()
    if not value:
        raise ComputeAuthError(f"{name} must not be empty")
    return value


def _encode_token(payload: dict[str, Any], key: bytes, header: dict[str, str]) -> str:
    signing_input = b".".join((_b64url_json(header), _b64url_json(payload)))
    signature = hmac.new(key, signing_input, hashlib.sha256).digest()
    return (signing_input + b"." + _b64url(signature)).decode("ascii")


def _decode_token(
    token: str, key: bytes, expected_header: dict[str, str]
) -> dict[str, Any]:
    if not isinstance(token, str) or len(token) > 4096:
        raise ComputeAuthError("Compute token format is invalid")
    parts = token.split(".")
    if len(parts) != 3 or any(not _JWT_PART_RE.fullmatch(part) for part in parts):
        raise ComputeAuthError("Compute token format is invalid")
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    try:
        supplied = _b64url_decode(parts[2])
    except ValueError as exc:
        raise ComputeAuthError("Compute token signature is invalid") from exc
    expected = hmac.new(key, signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(supplied, expected):
        raise ComputeAuthError("Compute token signature is invalid")
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ComputeAuthError("Compute token JSON is invalid") from exc
    if header != expected_header or not isinstance(payload, dict):
        raise ComputeAuthError("Compute token header or payload is invalid")
    return payload


def _b64url_json(value: dict[str, Any]) -> bytes:
    return _b64url(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def _b64url(value: bytes) -> bytes:
    return base64.urlsafe_b64encode(value).rstrip(b"=")


def _b64url_decode(value: str) -> bytes:
    if not _JWT_PART_RE.fullmatch(value):
        raise ValueError("invalid base64url")
    padding = "=" * (-len(value) % 4)
    decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    if _b64url(decoded).decode("ascii") != value:
        raise ValueError("non-canonical base64url")
    return decoded


def _stable_hash(value: str, prefix: str) -> str:
    return hashlib.sha256(prefix.encode() + b":" + value.encode()).hexdigest()
