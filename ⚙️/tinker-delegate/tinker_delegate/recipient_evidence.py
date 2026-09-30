"""Renewable, independently authenticated public ingress-recipient evidence.

This module transports quotes, never claims to perform Intel DCAP itself. Every
response binds the actual quote bytes to an independently signed QVL v4 verdict
and immutable release-provided trust pins. No bearer or private key is public.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from typing import Any, Callable, Mapping

import httpx

from tinker_delegate import dstack_utils
from tinker_delegate.arena_ingress import arena_attestation_report_data
from tinker_delegate.card_channel import attestation_report_data
from tinker_delegate.qvl_freshness import (
    authenticate_qvl_challenge,
    challenge_request,
    qvl_challenge_from_public_dict,
)
from tinker_delegate.result_verifier import (
    IndependentAttestationExpectation,
    authenticate_independent_attestation_verdict,
    independent_attestation_verdict_from_public_dict,
)
from tinker_delegate.tdx_quote import extract_report_data


EVIDENCE_SCHEMA = "dnai.recipient-evidence.v1"
QUOTE_SCHEMA = "dnai.recipient-quote.v1"
TRUST_SCHEMA = "dnai.recipient-trust-policy.v1"
MAX_QVL_RESPONSE_BYTES = 96 * 1024
MIN_QUOTE_BYTES = 1024
MAX_QUOTE_BYTES = 16 * 1024
CONTEXT_PROFILES = {"artifact": "artifact_recipient", "arena": "arena"}
AUTH_TOKEN_ENV = {
    "artifact": "TINKER_ARTIFACT_RECIPIENT_QVL_AUTH_TOKEN",
    "arena": "TINKER_ARENA_RECIPIENT_QVL_AUTH_TOKEN",
}
TRUST_FIELDS = frozenset({
    "schema", "context", "profile", "domain", "chain_id", "cvm_id",
    "deployment_intent_sha256", "release_authority_sha256", "ceremony_nonce",
    "measurement_policy_sha256", "release_policy_hash", "verifier_address",
    "signer_address", "contract_address", "compose_hash", "app_id",
    "os_image_hash", "encryption_public_key", "key_id", "report_data",
    "max_verdict_age_seconds",
})
RECIPIENT_FIELDS = frozenset({
    "encryption_public_key", "key_id", "report_context", "report_data",
})
VERDICT_FIELDS = frozenset({
    "schema", "verification_method", "verified", "domain", "cvm_id",
    "deployment_intent_sha256", "release_authority_sha256", "ceremony_nonce",
    "measurement_policy_sha256", "profile", "release_policy_hash",
    "challenge_id", "challenge_digest", "challenge_issued_at",
    "challenge_expires_at", "quote_hash", "report_data", "compose_hash",
    "app_id", "os_image_hash", "signer_address", "chain_id",
    "contract_address", "issued_at", "activation_evidence_lease_expires_at",
    "expires_at", "verifier_address", "verifier_signature",
})
_BARE32 = re.compile(r"^(?!0{64}$)[0-9a-f]{64}$")
_BYTES32 = re.compile(r"^0x(?!0{64}$)[0-9a-f]{64}$")
_SHA256 = re.compile(r"^sha256:(?!0{64}$)[0-9a-f]{64}$")
_ADDRESS = re.compile(r"^0x(?!0{40}$)[0-9a-f]{40}$")
_APP_ID = re.compile(r"^(?!0{40}$)[0-9a-f]{40}$")
_CVM_ID = re.compile(r"^[a-z0-9][a-z0-9._:-]{7,127}$")


class RecipientEvidenceUnavailable(ValueError):
    """Fixed public failure; never includes lower-layer errors or payloads."""


class RecipientQuoteRateLimited(ValueError):
    """The bounded quote collector is busy or within its cooldown."""


def _unavailable() -> RecipientEvidenceUnavailable:
    return RecipientEvidenceUnavailable("Recipient evidence is unavailable")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _unavailable()
        result[key] = value
    return result


def _json_object(raw: bytes | str) -> dict[str, Any]:
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if not isinstance(value, dict):
            raise ValueError
        return value
    except Exception:
        raise _unavailable() from None


def _matches(value: Any, pattern: re.Pattern[str]) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def recipient_binding(context: str, public_key: bytes) -> dict[str, str]:
    if context not in CONTEXT_PROFILES or not isinstance(public_key, bytes) or len(public_key) != 32:
        raise _unavailable()
    if not _BARE32.fullmatch(public_key.hex()):
        raise _unavailable()
    report = (attestation_report_data("artifact", public_key)
              if context == "artifact" else arena_attestation_report_data(public_key))
    return {
        "encryption_public_key": public_key.hex(),
        "key_id": "sha256:" + hashlib.sha256(public_key).hexdigest(),
        "report_context": context,
        "report_data": report.hex(),
    }


def parse_recipient_trust_policy(value: Mapping[str, Any] | str) -> dict[str, Any]:
    try:
        if isinstance(value, str):
            if not 1 <= len(value.encode("utf-8")) <= 16 * 1024:
                raise ValueError
            value = _json_object(value)
        if not isinstance(value, Mapping) or set(value) != TRUST_FIELDS:
            raise ValueError
        policy = dict(value)
        context = policy["context"]
        if (policy["schema"] != TRUST_SCHEMA
                or context not in CONTEXT_PROFILES
                or policy["profile"] != CONTEXT_PROFILES[context]
                or policy["domain"] != "main_runtime_cvm"
                or type(policy["chain_id"]) is not int or policy["chain_id"] != 84532
                or type(policy["max_verdict_age_seconds"]) is not int
                or not 1 <= policy["max_verdict_age_seconds"] <= 900):
            raise ValueError
        patterns = {
            "cvm_id": _CVM_ID, "deployment_intent_sha256": _SHA256,
            "release_authority_sha256": _SHA256, "ceremony_nonce": _BYTES32,
            "measurement_policy_sha256": _SHA256, "release_policy_hash": _BYTES32,
            "verifier_address": _ADDRESS, "signer_address": _ADDRESS,
            "contract_address": _ADDRESS, "compose_hash": _BYTES32,
            "app_id": _APP_ID, "os_image_hash": _BARE32,
            "encryption_public_key": _BARE32, "key_id": _SHA256,
            "report_data": _BYTES32,
        }
        if any(not _matches(policy[field], pattern) for field, pattern in patterns.items()):
            raise ValueError
        binding = recipient_binding(context, bytes.fromhex(policy["encryption_public_key"]))
        if (binding["key_id"] != policy["key_id"]
                or "0x" + binding["report_data"] != policy["report_data"]
                or policy["verifier_address"] == policy["signer_address"]):
            raise ValueError
        return policy
    except Exception:
        raise _unavailable() from None


def _verify_url(value: str) -> str:
    try:
        if not isinstance(value, str) or len(value) > 2048:
            raise ValueError
        parsed = httpx.URL(value)
        if (parsed.scheme != "https" or not parsed.host or parsed.userinfo
                or parsed.query or parsed.fragment or parsed.path != "/verify"
                or parsed.host in {"localhost", "127.0.0.1", "::1"}):
            raise ValueError
        return str(parsed)
    except Exception:
        raise _unavailable() from None


def _hex_bytes(value: Any, minimum: int, maximum: int) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"(?:0x)?[0-9a-f]+", value):
        raise _unavailable()
    raw = value.removeprefix("0x")
    if len(raw) % 2 or not minimum * 2 <= len(raw) <= maximum * 2:
        raise _unavailable()
    return bytes.fromhex(raw)


def _collect_quote(context: str, recipient: Mapping[str, Any], challenge_digest: str) -> dict[str, Any]:
    """Collect a quote, not a verdict; exact caller challenge is data only."""
    if (not dstack_utils.is_dstack_enabled() or dstack_utils.is_dstack_simulator()
            or context not in CONTEXT_PROFILES or not _matches(challenge_digest, _BYTES32)
            or not isinstance(recipient, Mapping) or set(recipient) != RECIPIENT_FIELDS):
        raise _unavailable()
    expected = recipient_binding(context, _hex_bytes(recipient.get("encryption_public_key"), 32, 32))
    if dict(recipient) != expected:
        raise _unavailable()
    report_data = bytes.fromhex(expected["report_data"]) + bytes.fromhex(challenge_digest[2:])
    details = dstack_utils.get_attestation_details(report_data)
    quote = _hex_bytes(details.get("quote"), MIN_QUOTE_BYTES, MAX_QUOTE_BYTES)
    if (_hex_bytes(details.get("quote_report_data"), 64, 64) != report_data
            or extract_report_data(quote) != report_data):
        raise _unavailable()
    compose_hash = "0x" + _hex_bytes(details.get("compose_hash"), 32, 32).hex()
    app_id = _hex_bytes(details.get("app_id"), 20, 20).hex()
    os_image_hash = _hex_bytes(details.get("os_image_hash"), 32, 32).hex()
    if not _BYTES32.fullmatch(compose_hash) or not _APP_ID.fullmatch(app_id) or not _BARE32.fullmatch(os_image_hash):
        raise _unavailable()
    return {
        "schema": QUOTE_SCHEMA, "context": context, "recipient": expected,
        "quote": "0x" + quote.hex(), "quote_hash": "0x" + hashlib.sha256(quote).hexdigest(),
        "quote_report_data": "0x" + report_data.hex(), "compose_hash": compose_hash,
        "app_id": app_id, "os_image_hash": os_image_hash, "verified": False,
    }


class RecipientQuoteCollector:
    """Two fixed contexts, one in-flight call each, at most one start per 2s.

    This process-wide limit is not an authenticated attestation claim. Remote
    dstack I/O happens after releasing the small scheduling lock.
    """

    def __init__(self, *, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._last_start: dict[str, float] = {}
        self._inflight: set[str] = set()

    def collect(self, context: str, recipient: Mapping[str, Any], *,
                challenge_digest: str, custody_mode: str) -> dict[str, Any]:
        if context not in CONTEXT_PROFILES or custody_mode != "dstack" or not _matches(challenge_digest, _BYTES32):
            raise _unavailable()
        with self._lock:
            now = self._clock()
            if context in self._inflight or now - self._last_start.get(context, float("-inf")) < 2:
                raise RecipientQuoteRateLimited("Recipient quote collection is rate limited")
            self._last_start[context] = now
            self._inflight.add(context)
        try:
            return _collect_quote(context, recipient, challenge_digest)
        except Exception:
            raise _unavailable() from None
        finally:
            with self._lock:
                self._inflight.discard(context)


class HttpsRecipientEvidenceProvider:
    """One immutable context/release, bounded HTTPS transport, renewable cache.

    A per-instance singleflight condition is released during all remote I/O.
    The factory has a separate short-lived registry lock, never a network lock.
    """

    def __init__(self, *, trust_policy: Mapping[str, Any] | str,
                 qvl_url: str, auth_token: str, client: httpx.Client | None = None,
                 clock: Callable[[], float] = time.time) -> None:
        if (not dstack_utils.is_dstack_enabled() or dstack_utils.is_dstack_simulator()
                or not isinstance(auth_token, str) or not 32 <= len(auth_token) <= 4096
                or any(not 0x21 <= ord(c) <= 0x7e for c in auth_token)):
            raise _unavailable()
        policy = parse_recipient_trust_policy(trust_policy)
        self._policy_bytes = _canonical(policy)
        self.context = policy["context"]
        self.qvl_url = _verify_url(qvl_url)
        self.challenge_url = str(httpx.URL(self.qvl_url).copy_with(path="/challenge"))
        self._auth_token = auth_token
        self._clock = clock
        self._client = client or httpx.Client(timeout=httpx.Timeout(30.0, connect=10.0),
                                             follow_redirects=False, trust_env=False)
        self._owns_client = client is None
        self._condition = threading.Condition()
        self._inflight = False
        self._cache: tuple[str, bytes, int] | None = None
        self._used_challenges: dict[str, tuple[str, int]] = {}

    def __repr__(self) -> str:
        return f"HttpsRecipientEvidenceProvider(context={self.context!r})"

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def _now(self) -> int:
        value = self._clock()
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value < 2**53:
            raise _unavailable()
        return int(value)

    def _post(self, url: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        try:
            request = self._client.build_request("POST", url, headers={
                "Accept": "application/json", "Authorization": f"Bearer {self._auth_token}",
                "Cache-Control": "no-store", "Content-Type": "application/json",
            }, content=_canonical(dict(payload)))
            response = self._client.send(request, stream=True, follow_redirects=False)
            try:
                media = response.headers.get("content-type", "").split(";", 1)[0].lower()
                if (response.status_code != 200 or response.history
                        or not (media == "application/json" or media.endswith("+json"))):
                    raise ValueError
                length = response.headers.get("content-length")
                if length is not None and not 1 <= int(length) <= MAX_QVL_RESPONSE_BYTES:
                    raise ValueError
                raw = bytearray()
                for chunk in response.iter_bytes():
                    if len(chunk) > MAX_QVL_RESPONSE_BYTES - len(raw):
                        raise ValueError
                    raw.extend(chunk)
                return _json_object(bytes(raw))
            finally:
                response.close()
        except Exception:
            raise _unavailable() from None

    def evidence(self, recipient: Mapping[str, Any], *, custody_mode: str) -> dict[str, Any]:
        try:
            if (custody_mode != "dstack" or not dstack_utils.is_dstack_enabled()
                    or dstack_utils.is_dstack_simulator()):
                raise ValueError
            policy = _json_object(self._policy_bytes)
            expected = recipient_binding(self.context, bytes.fromhex(policy["encryption_public_key"]))
            if not isinstance(recipient, Mapping) or set(recipient) != RECIPIENT_FIELDS or dict(recipient) != expected:
                raise ValueError
            cache_key = hashlib.sha256(self._policy_bytes + b"\x00" + _canonical(expected)).hexdigest()
            with self._condition:
                if not self._condition.wait_for(lambda: not self._inflight, timeout=90):
                    raise ValueError
                now = self._now()
                if self._cache and self._cache[0] == cache_key and now < self._cache[2]:
                    return _json_object(self._cache[1])
                self._cache = None
                self._inflight = True
            try:
                result, expires_at = self._renew(policy, expected)
                encoded = _canonical(result)
                with self._condition:
                    if self._now() >= expires_at:
                        raise _unavailable()
                    self._cache = (cache_key, encoded, expires_at)
                return _json_object(encoded)
            finally:
                with self._condition:
                    self._inflight = False
                    self._condition.notify_all()
        except Exception:
            raise _unavailable() from None

    def _renew(self, policy: dict[str, Any], recipient: dict[str, str]) -> tuple[dict[str, Any], int]:
        fields = {key: policy[key] for key in (
            "chain_id", "domain", "cvm_id", "deployment_intent_sha256",
            "release_authority_sha256", "ceremony_nonce", "measurement_policy_sha256",
        )}
        challenge = qvl_challenge_from_public_dict(self._post(
            self.challenge_url, challenge_request(policy["profile"], **fields),
        ))
        challenge_check = dict(
            expected_profile=policy["profile"], expected_chain_id=policy["chain_id"],
            expected_domain=policy["domain"], expected_cvm_id=policy["cvm_id"],
            expected_deployment_intent_sha256=policy["deployment_intent_sha256"],
            expected_release_authority_sha256=policy["release_authority_sha256"],
            expected_ceremony_nonce=policy["ceremony_nonce"],
            expected_measurement_policy_sha256=policy["measurement_policy_sha256"],
            trusted_verifier_addresses=(policy["verifier_address"],),
            expected_policy_hash=policy["release_policy_hash"],
        )
        now = self._now()
        authenticate_qvl_challenge(challenge, **challenge_check, now=now)
        self._used_challenges = {key: value for key, value in self._used_challenges.items() if value[1] > now}
        if (challenge.challenge_id in self._used_challenges
                or any(value[0] == challenge.challenge_digest for value in self._used_challenges.values())
                or len(self._used_challenges) >= 256):
            raise _unavailable()
        self._used_challenges[challenge.challenge_id] = (challenge.challenge_digest, challenge.expires_at)
        observation = _collect_quote(self.context, recipient, challenge.challenge_digest)
        authenticate_qvl_challenge(challenge, **challenge_check, now=self._now())
        quote = _hex_bytes(observation["quote"], MIN_QUOTE_BYTES, MAX_QUOTE_BYTES)
        quote_report_data = _hex_bytes(observation["quote_report_data"], 64, 64)
        if any(observation[key] != policy[key] for key in ("compose_hash", "app_id", "os_image_hash")):
            raise _unavailable()
        quote_hash = "0x" + hashlib.sha256(quote).hexdigest()
        expectation_payload = {
            "mode": "tdx", "signer_address": policy["signer_address"],
            "chain_id": policy["chain_id"], "contract_address": policy["contract_address"],
            "report_data": policy["report_data"], "quote_report_data": "0x" + quote_report_data.hex(),
            "quote_hash": quote_hash, "quote_size": len(quote),
            "compose_hash": policy["compose_hash"], "app_id": policy["app_id"],
            "os_image_hash": policy["os_image_hash"], "raw_secret_egress": False,
        }
        verdict_payload = self._post(self.qvl_url, {
            "schema": "dnai.independent-tdx-verification-request.v2",
            "challenge": challenge.to_public_dict(), "quote": "0x" + quote.hex(),
            "expectation": expectation_payload,
        })
        if set(verdict_payload) != VERDICT_FIELDS:
            raise _unavailable()
        verdict = independent_attestation_verdict_from_public_dict(verdict_payload)
        expectation = IndependentAttestationExpectation(
            trusted_verifier_addresses=(policy["verifier_address"],),
            **fields, profile=policy["profile"], release_policy_hash=policy["release_policy_hash"],
            challenge_id=challenge.challenge_id, challenge_digest=challenge.challenge_digest,
            challenge_issued_at=challenge.issued_at, challenge_expires_at=challenge.expires_at,
            quote_hash=quote_hash, report_data=policy["report_data"],
            compose_hash=policy["compose_hash"], app_id=policy["app_id"],
            os_image_hash=policy["os_image_hash"], signer_address=policy["signer_address"],
            contract_address=policy["contract_address"], max_age_seconds=policy["max_verdict_age_seconds"],
        )
        authenticate_independent_attestation_verdict(verdict, expectation=expectation, now=self._now())
        return ({
            "schema": EVIDENCE_SCHEMA, "context": self.context, "recipient": recipient,
            "quote": "0x" + quote.hex(), "quote_report_data": "0x" + quote_report_data.hex(),
            "challenge": challenge.to_public_dict(), "verdict": verdict.to_public_dict(),
        }, min(verdict.expires_at, verdict.issued_at + policy["max_verdict_age_seconds"]))
