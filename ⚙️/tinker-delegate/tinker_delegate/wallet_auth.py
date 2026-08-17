"""Replay-resistant Ethereum wallet authentication for artifact ingress.

The browser signs a short-lived, deal-bound challenge with ``personal_sign``.
After recovering the Ethereum address, the delegate exchanges the one-time
challenge for a short-lived HS256 bearer token.  In a CVM the token key is
derived from dstack and never leaves the TEE; an explicit local key exists only
for development and tests.
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

from eth_account import Account
from eth_account.messages import encode_defunct

from tinker_delegate import dstack_utils
from tinker_delegate.wallet_signature_verifier import (
    BASE_SEPOLIA_CHAIN_ID,
    WalletSignatureError,
    WalletSignatureUnavailable,
    WalletSignatureVerifier,
    wallet_signature_verifier_from_settings,
)


ARTIFACT_UPLOAD_SCOPE = "artifact:upload"
MAX_WALLET_CHALLENGE_VERIFICATION_ATTEMPTS = 3
_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_DEAL_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


class WalletAuthError(ValueError):
    """Raised when a wallet challenge, signature, or token is invalid."""


class WalletAuthUnavailable(RuntimeError):
    """Raised when secure signing material or chain verification is unavailable."""


class WalletChallengeCapacityError(RuntimeError):
    """Raised instead of evicting an unexpired challenge under load."""


@dataclass(frozen=True)
class WalletChallenge:
    address: str
    deal_id: str
    scope: str
    nonce: str
    message: str
    issued_at: int
    expires_at: int

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "deal_id": self.deal_id,
            "scope": self.scope,
            "nonce": self.nonce,
            "message": self.message,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }


@dataclass(frozen=True)
class WalletTokenClaims:
    address: str
    deal_id: str
    scopes: tuple[str, ...]
    issued_at: int
    expires_at: int
    jwt_id: str

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "deal_id": self.deal_id,
            "scopes": list(self.scopes),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "jwt_id_hash": hashlib.sha256(
                b"wallet-auth-jti:" + self.jwt_id.encode("utf-8")
            ).hexdigest(),
        }


class WalletChallengeStore:
    """Bounded, process-local store for single-use login challenges.

    A restart intentionally invalidates every pending challenge.  The store is
    guarded by a lock so two concurrent token exchanges cannot consume the same
    nonce.  It refuses new challenges at capacity rather than evicting a valid
    user's pending challenge.
    """

    def __init__(self, *, max_pending: int = 1024):
        if max_pending <= 0:
            raise ValueError("wallet challenge capacity must be positive")
        self.max_pending = max_pending
        self._records: dict[str, WalletChallenge] = {}
        self._verification_attempts: dict[str, int] = {}
        self._verification_in_flight: set[str] = set()
        self._lock = threading.Lock()

    def put(self, challenge: WalletChallenge, *, now: int) -> None:
        with self._lock:
            self._prune_locked(now)
            if len(self._records) >= self.max_pending:
                raise WalletChallengeCapacityError("wallet challenge capacity reached")
            self._records[challenge.nonce] = challenge
            self._verification_attempts[challenge.nonce] = 0
            self._verification_in_flight.discard(challenge.nonce)

    def consume_verified(self, nonce: str, signature: str, *, now: int) -> WalletChallenge:
        """Locally verify and consume ``nonce`` for compatibility.

        A bounded number of invalid signatures may be retried, which permits a
        wallet UI to recover from a transport-corrupted signature without
        allowing one nonce to amplify unbounded verification work. Services
        reserve one attempt before EIP-1271 I/O, outside this store's lock.
        """

        challenge = self.reserve_verification(nonce, now=now)
        verified = False
        try:
            recovered = recover_wallet_address(challenge.message, signature)
            if not hmac.compare_digest(recovered, challenge.address):
                raise WalletAuthError(
                    "wallet signature does not match challenge address"
                )
            verified = True
        finally:
            if not verified:
                self.release_verification(nonce, challenge)
        return self.consume_if_current(nonce, challenge, now=now)

    def reserve_verification(self, nonce: str, *, now: int) -> WalletChallenge:
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
                raise WalletAuthError(
                    "wallet challenge is unknown, expired, or already used"
                )
            self._verification_attempts[nonce] = attempts + 1
            self._verification_in_flight.add(nonce)
            return challenge

    def release_verification(self, nonce: str, expected: WalletChallenge) -> None:
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

    def get_pending(self, nonce: str, *, now: int) -> WalletChallenge:
        """Return the immutable pending challenge without reserving its nonce."""

        with self._lock:
            self._prune_locked(now)
            challenge = self._records.get(nonce)
            if challenge is None:
                raise WalletAuthError("wallet challenge is unknown, expired, or already used")
            return challenge

    def consume_if_current(
        self,
        nonce: str,
        expected: WalletChallenge,
        *,
        now: int,
    ) -> WalletChallenge:
        """Compare-and-delete a challenge after verification outside the lock."""

        with self._lock:
            self._prune_locked(now)
            challenge = self._records.get(nonce)
            if (
                challenge is None
                or challenge is not expected
                or nonce not in self._verification_in_flight
            ):
                raise WalletAuthError("wallet challenge is unknown, expired, or already used")
            self._delete_locked(nonce)
            return challenge

    def clear(self) -> None:
        with self._lock:
            self._records.clear()
            self._verification_attempts.clear()
            self._verification_in_flight.clear()

    def _prune_locked(self, now: int) -> None:
        expired = [nonce for nonce, item in self._records.items() if now >= item.expires_at]
        for nonce in expired:
            self._delete_locked(nonce)

    def _delete_locked(self, nonce: str) -> None:
        self._records.pop(nonce, None)
        self._verification_attempts.pop(nonce, None)
        self._verification_in_flight.discard(nonce)


class WalletAuthService:
    """Issue wallet challenges and exchange them for deal-scoped tokens."""

    def __init__(
        self,
        settings: Any,
        challenge_store: WalletChallengeStore,
        signature_verifier: WalletSignatureVerifier | None = None,
    ):
        self.settings = settings
        self.challenge_store = challenge_store
        self.signature_verifier = signature_verifier

    def issue_challenge(
        self,
        *,
        address: str,
        deal_id: str,
        now: int | None = None,
    ) -> WalletChallenge:
        issued_at = int(time.time() if now is None else now)
        normalized_address = normalize_wallet_address(address)
        normalized_deal_id = normalize_deal_id(deal_id)
        # Fail before asking a wallet to sign if this runtime could not issue the
        # corresponding token securely.
        wallet_token_signing_key(self.settings)
        ttl = _bounded_positive_int(
            getattr(self.settings, "wallet_auth_challenge_ttl_seconds", 300),
            name="wallet challenge ttl",
            maximum=600,
        )
        nonce = secrets.token_hex(16)
        expires_at = issued_at + ttl
        message = _challenge_message(
            self.settings,
            address=normalized_address,
            deal_id=normalized_deal_id,
            nonce=nonce,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        challenge = WalletChallenge(
            address=normalized_address,
            deal_id=normalized_deal_id,
            scope=ARTIFACT_UPLOAD_SCOPE,
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
    ) -> tuple[WalletTokenClaims, str]:
        current = int(time.time() if now is None else now)
        normalized_nonce = _normalize_nonce(nonce)
        ttl = _bounded_positive_int(
            getattr(self.settings, "wallet_auth_token_ttl_seconds", 300),
            name="wallet token ttl",
            maximum=900,
        )
        signing_key = wallet_token_signing_key(self.settings)
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
            raise WalletAuthUnavailable("wallet signature verification is unavailable") from exc
        except WalletSignatureError as exc:
            raise WalletAuthError(str(exc)) from exc
        except Exception as exc:
            raise WalletAuthUnavailable(
                "wallet signature verification is unavailable"
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
        claims = WalletTokenClaims(
            address=challenge.address,
            deal_id=challenge.deal_id,
            scopes=(challenge.scope,),
            issued_at=consumed_at,
            expires_at=consumed_at + ttl,
            jwt_id=secrets.token_hex(16),
        )
        payload = {
            "iss": _setting_text(
                self.settings,
                "wallet_auth_issuer",
                "dnai-wikigen:wallet-auth",
            ),
            "aud": _setting_text(
                self.settings,
                "wallet_auth_audience",
                "dnai-wikigen:tinker-delegate",
            ),
            "sub": claims.address,
            "deal_id": claims.deal_id,
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
        deal_id: str,
        now: int | None = None,
    ) -> WalletTokenClaims:
        payload = _decode_token(token, wallet_token_signing_key(self.settings))
        current = int(time.time() if now is None else now)
        issuer = _setting_text(
            self.settings,
            "wallet_auth_issuer",
            "dnai-wikigen:wallet-auth",
        )
        audience = _setting_text(
            self.settings,
            "wallet_auth_audience",
            "dnai-wikigen:tinker-delegate",
        )
        if payload.get("iss") != issuer:
            raise WalletAuthError("wallet token issuer mismatch")
        if payload.get("aud") != audience:
            raise WalletAuthError("wallet token audience mismatch")
        try:
            not_before = int(payload["nbf"])
            issued_at = int(payload["iat"])
            expires_at = int(payload["exp"])
        except (KeyError, TypeError, ValueError) as exc:
            raise WalletAuthError("wallet token timestamps are invalid") from exc
        if not_before != issued_at or current < not_before:
            raise WalletAuthError("wallet token is not yet valid")
        if expires_at <= issued_at or current >= expires_at:
            raise WalletAuthError("wallet token expired")
        configured_ttl = _bounded_positive_int(
            getattr(self.settings, "wallet_auth_token_ttl_seconds", 300),
            name="wallet token ttl",
            maximum=900,
        )
        if expires_at - issued_at > configured_ttl:
            raise WalletAuthError("wallet token lifetime exceeds configured limit")

        address = normalize_wallet_address(str(payload.get("sub", "")))
        token_deal_id = normalize_deal_id(str(payload.get("deal_id", "")))
        expected_deal_id = normalize_deal_id(deal_id)
        if not hmac.compare_digest(token_deal_id, expected_deal_id):
            raise WalletAuthError("wallet token is bound to a different deal")
        scopes = tuple(part for part in str(payload.get("scope", "")).split() if part)
        if not scopes or any(scope != ARTIFACT_UPLOAD_SCOPE for scope in scopes):
            raise WalletAuthError("wallet token contains unsupported scope")
        if required_scope not in scopes:
            raise WalletAuthError("wallet token is missing required scope")
        jwt_id = str(payload.get("jti", ""))
        if not re.fullmatch(r"[0-9a-f]{32}", jwt_id):
            raise WalletAuthError("wallet token id is invalid")
        return WalletTokenClaims(
            address=address,
            deal_id=token_deal_id,
            scopes=scopes,
            issued_at=issued_at,
            expires_at=expires_at,
            jwt_id=jwt_id,
        )


def normalize_wallet_address(value: str) -> str:
    """Return a canonical comparison form for an Ethereum address."""

    if not isinstance(value, str) or not _ADDRESS_RE.fullmatch(value.strip()):
        raise WalletAuthError("wallet address must be a 20-byte 0x-prefixed hex address")
    return value.strip().lower()


def normalize_deal_id(value: str) -> str:
    if not isinstance(value, str) or not _DEAL_ID_RE.fullmatch(value.strip()):
        raise WalletAuthError("deal id contains unsupported characters")
    return value.strip()


def recover_wallet_address(message: str, signature: str) -> str:
    if not isinstance(signature, str):
        raise WalletAuthError("wallet signature must be hex")
    raw_hex = signature[2:] if signature.startswith(("0x", "0X")) else signature
    if len(raw_hex) != 130:
        raise WalletAuthError("wallet signature must be 65 bytes")
    try:
        raw = bytes.fromhex(raw_hex)
    except ValueError as exc:
        raise WalletAuthError("wallet signature must be hex") from exc
    try:
        recovered = Account.recover_message(encode_defunct(text=message), signature=raw)
    except Exception as exc:
        raise WalletAuthError("wallet signature recovery failed") from exc
    return normalize_wallet_address(recovered)


def wallet_token_signing_key(settings: Any) -> bytes:
    """Resolve domain-separated wallet-token key material.

    Explicit material is a local-development escape hatch.  Production dstack
    deployments derive the key from the CVM KMS path.
    """

    if dstack_utils.is_dstack_enabled():
        path = str(getattr(settings, "wallet_auth_key_path", "tinker/wallet_auth") or "")
        if not path:
            raise WalletAuthUnavailable("wallet auth dstack key path is not configured")
        try:
            derived = dstack_utils.derive_storage_key(path)
        except Exception as exc:
            raise WalletAuthUnavailable("wallet auth dstack key derivation failed") from exc
        return hashlib.sha256(b"tinker-wallet-auth:dstack:" + derived).digest()
    explicit = str(getattr(settings, "wallet_auth_signing_key", "") or "")
    if explicit:
        if len(explicit) < 32:
            raise WalletAuthUnavailable("local wallet signing key must be at least 32 characters")
        return hashlib.sha256(b"tinker-wallet-auth:local:" + explicit.encode("utf-8")).digest()
    raise WalletAuthUnavailable("wallet auth signing key is unavailable outside dstack")


def _challenge_message(
    settings: Any,
    *,
    address: str,
    deal_id: str,
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
        raise WalletAuthError("wallet authentication requires Base Sepolia chain 84532")
    for field_name, field_value in (("domain", domain), ("uri", uri)):
        if "\n" in field_value or "\r" in field_value:
            raise WalletAuthError(f"wallet auth {field_name} contains a newline")
    return (
        f"{domain} wants you to sign in with your Ethereum account:\n"
        f"{address}\n\n"
        "Authorize encrypted artifact upload for the specified diligence deal. "
        "This request will not trigger a blockchain transaction.\n\n"
        f"URI: {uri}\n"
        "Version: 1\n"
        f"Chain ID: {chain_id}\n"
        f"Nonce: {nonce}\n"
        f"Issued At: {issued_at}\n"
        f"Expiration Time: {expires_at}\n"
        "Resources:\n"
        f"- urn:dnai:deal:{deal_id}\n"
        f"- urn:dnai:scope:{ARTIFACT_UPLOAD_SCOPE}"
    )


def _normalize_nonce(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{32}", value):
        raise WalletAuthError("wallet challenge nonce is invalid")
    return value


def _bounded_positive_int(value: Any, *, name: str, maximum: int) -> int:
    try:
        normalized = int(value)
    except (TypeError, ValueError) as exc:
        raise WalletAuthError(f"{name} must be an integer") from exc
    if normalized <= 0 or normalized > maximum:
        raise WalletAuthError(f"{name} is outside the supported range")
    return normalized


def _setting_text(settings: Any, name: str, default: str) -> str:
    value = str(getattr(settings, name, "") or default).strip()
    if not value:
        raise WalletAuthError(f"{name} must not be empty")
    return value


def _encode_token(payload: dict[str, Any], key: bytes) -> str:
    header = {"alg": "HS256", "typ": "JWT", "kid": "dstack-wallet-v1"}
    signing_input = b".".join((_b64url_json(header), _b64url_json(payload)))
    signature = hmac.new(key, signing_input, hashlib.sha256).digest()
    return (signing_input + b"." + _b64url(signature)).decode("ascii")


def _decode_token(token: str, key: bytes) -> dict[str, Any]:
    if not isinstance(token, str) or len(token) > 4096:
        raise WalletAuthError("wallet token format is invalid")
    parts = token.split(".")
    if len(parts) != 3 or any(not part for part in parts):
        raise WalletAuthError("wallet token format is invalid")
    try:
        signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    except UnicodeEncodeError as exc:
        raise WalletAuthError("wallet token encoding is invalid") from exc
    try:
        supplied_signature = _b64url_decode(parts[2])
    except ValueError as exc:
        # A syntactically different Base64URL signature must not be accepted
        # merely because its non-zero padding bits decode to the same bytes.
        raise WalletAuthError("wallet token signature is invalid") from exc
    expected_signature = hmac.new(key, signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(supplied_signature, expected_signature):
        raise WalletAuthError("wallet token signature is invalid")
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WalletAuthError("wallet token JSON is invalid") from exc
    if header != {"alg": "HS256", "kid": "dstack-wallet-v1", "typ": "JWT"}:
        raise WalletAuthError("wallet token header is unsupported")
    if not isinstance(payload, dict):
        raise WalletAuthError("wallet token payload is invalid")
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
