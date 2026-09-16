"""Bounded admission control for public wallet challenge issuance.

The four wallet-signature surfaces share one limiter.  Its global sliding-window
capacity is required to stay below every process-local nonce store capacity,
and its window covers the longest configured nonce TTL.  Therefore traffic
that passes this gate cannot fill any nonce store, even when every accepted
request targets the same surface.

Peer identity defaults to the ASGI server's direct socket peer.  A forwarded
client-IP header is considered only when both an exact header and pinned proxy
CIDRs are configured and the direct peer belongs to one of those CIDRs.
"""

from __future__ import annotations

import hashlib
import ipaddress
import math
import threading
import time
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any


_ALLOWED_PROXY_HEADERS = frozenset({"cf-connecting-ip", "x-real-ip"})


class WalletChallengeLimitConfigurationError(ValueError):
    """Raised when admission controls cannot prove store-capacity safety."""


@dataclass(frozen=True)
class WalletChallengeRateLimited(Exception):
    """Stable rate-limit result without revealing which bucket saturated."""

    retry_after: int

    def __str__(self) -> str:
        return "wallet challenge rate limit exceeded"


def _positive_int(value: Any, *, label: str, maximum: int = 86_400) -> int:
    if isinstance(value, bool):
        raise WalletChallengeLimitConfigurationError(f"{label} must be a positive integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise WalletChallengeLimitConfigurationError(
            f"{label} must be a positive integer"
        ) from exc
    if parsed <= 0 or parsed > maximum:
        raise WalletChallengeLimitConfigurationError(f"{label} is outside its safe range")
    return parsed


def _canonical_address(value: Any) -> str:
    text = str(value or "").strip().lower()
    if len(text) != 42 or not text.startswith("0x"):
        raise ValueError("wallet address is invalid")
    try:
        bytes.fromhex(text[2:])
    except ValueError as exc:
        raise ValueError("wallet address is invalid") from exc
    return text


def _source_key(value: Any) -> str:
    """Return a bounded non-secret bucket key for a direct/client IP value."""

    raw = str(value or "").strip()
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        # ASGI test harnesses and unusual servers can expose a non-IP peer name.
        # It is not accepted as forwarded identity; all equal names still share
        # one bounded bucket and raw text is not retained.
        digest = hashlib.sha256(raw.lower().encode("utf-8")).hexdigest()[:24]
        return f"peer-name:{digest}"
    if isinstance(address, ipaddress.IPv6Address):
        network = ipaddress.ip_network(f"{address}/64", strict=False)
        return f"ipv6-64:{network.network_address.compressed}"
    return f"ipv4:{address.compressed}"


class WalletChallengePeerPolicy:
    """Resolve a trustworthy peer bucket with optional pinned-proxy support."""

    def __init__(
        self,
        *,
        trusted_proxy_cidrs: str = "",
        client_ip_header: str = "",
    ) -> None:
        header = str(client_ip_header or "").strip().lower()
        raw_cidrs = str(trusted_proxy_cidrs or "")
        if len(raw_cidrs.encode("utf-8")) > 4096:
            raise WalletChallengeLimitConfigurationError(
                "wallet challenge trusted proxy policy is too large"
            )
        cidr_values = [
            part.strip()
            for part in raw_cidrs.split(",")
            if part.strip()
        ]
        if len(cidr_values) > 128:
            raise WalletChallengeLimitConfigurationError(
                "wallet challenge trusted proxy policy has too many CIDRs"
            )
        if bool(header) != bool(cidr_values):
            raise WalletChallengeLimitConfigurationError(
                "forwarded client-IP trust requires both an exact header and pinned proxy CIDRs"
            )
        if header and header not in _ALLOWED_PROXY_HEADERS:
            raise WalletChallengeLimitConfigurationError(
                "wallet challenge client-IP header is not an approved single-IP header"
            )
        networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for value in cidr_values:
            try:
                network = ipaddress.ip_network(value, strict=True)
            except ValueError as exc:
                raise WalletChallengeLimitConfigurationError(
                    "wallet challenge trusted proxy CIDR is invalid or noncanonical"
                ) from exc
            if network.with_prefixlen != value:
                raise WalletChallengeLimitConfigurationError(
                    "wallet challenge trusted proxy CIDR is invalid or noncanonical"
                )
            if network.prefixlen == 0 or network.is_multicast:
                raise WalletChallengeLimitConfigurationError(
                    "wallet challenge trusted proxy CIDR is too broad or unsafe"
                )
            networks.append(network)
        self.header = header
        self.networks = tuple(networks)

    @classmethod
    def from_settings(cls, settings: Any) -> "WalletChallengePeerPolicy":
        return cls(
            trusted_proxy_cidrs=getattr(
                settings,
                "wallet_auth_challenge_trusted_proxy_cidrs",
                "",
            ),
            client_ip_header=getattr(
                settings,
                "wallet_auth_challenge_client_ip_header",
                "",
            ),
        )

    def source(self, *, direct_peer: Any, headers: Mapping[str, str]) -> str:
        peer_text = str(direct_peer or "").strip()
        try:
            peer_ip = ipaddress.ip_address(peer_text)
        except ValueError:
            peer_ip = None
        trusted = peer_ip is not None and any(peer_ip in network for network in self.networks)
        if trusted and self.header:
            # Approved headers must contain exactly one canonical IP.  Lists are
            # rejected so no leftmost/rightmost proxy-chain assumption exists.
            forwarded = str(headers.get(self.header, "") or "").strip()
            if len(forwarded) > 64:
                return _source_key(peer_text)
            try:
                forwarded_ip = ipaddress.ip_address(forwarded)
            except ValueError:
                return _source_key(peer_text)
            if forwarded != forwarded_ip.compressed:
                return _source_key(peer_text)
            return _source_key(forwarded_ip.compressed)
        # Forwarded headers from an unpinned direct peer are deliberately ignored.
        return _source_key(peer_text)


class WalletChallengeAdmissionLimiter:
    """Atomic global/address/peer sliding-window limiter."""

    def __init__(
        self,
        *,
        window_seconds: int,
        global_capacity: int,
        address_capacity: int,
        peer_capacity: int,
        minimum_store_capacity: int,
        maximum_challenge_ttl: int,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.window_seconds = _positive_int(window_seconds, label="wallet challenge limiter window")
        self.global_capacity = _positive_int(
            global_capacity,
            label="wallet challenge global capacity",
        )
        self.address_capacity = _positive_int(
            address_capacity,
            label="wallet challenge address capacity",
        )
        self.peer_capacity = _positive_int(peer_capacity, label="wallet challenge peer capacity")
        self.minimum_store_capacity = _positive_int(
            minimum_store_capacity,
            label="minimum wallet challenge store capacity",
            maximum=1_000_000,
        )
        self.maximum_challenge_ttl = _positive_int(
            maximum_challenge_ttl,
            label="maximum wallet challenge TTL",
        )
        if self.window_seconds < self.maximum_challenge_ttl:
            raise WalletChallengeLimitConfigurationError(
                "wallet challenge limiter window must cover the maximum challenge TTL"
            )
        if self.global_capacity >= self.minimum_store_capacity:
            raise WalletChallengeLimitConfigurationError(
                "wallet challenge global capacity must remain below every nonce store capacity"
            )
        if (
            self.address_capacity > self.global_capacity
            or self.peer_capacity > self.global_capacity
        ):
            raise WalletChallengeLimitConfigurationError(
                "wallet challenge sub-bucket capacities must not exceed global capacity"
            )
        self._clock = clock
        self._global: deque[float] = deque()
        self._addresses: dict[str, deque[float]] = {}
        self._peers: dict[str, deque[float]] = {}
        self._lock = threading.Lock()
        self._last_now = float("-inf")

    @classmethod
    def from_settings(cls, settings: Any) -> "WalletChallengeAdmissionLimiter":
        ttl_values = (
            getattr(settings, "wallet_auth_challenge_ttl_seconds", 300),
            getattr(settings, "arena_wallet_auth_challenge_ttl_seconds", 300),
            getattr(settings, "compute_wallet_auth_challenge_ttl_seconds", 300),
            getattr(settings, "review_authority_challenge_ttl_seconds", 300),
        )
        store_values = (
            getattr(settings, "wallet_auth_max_pending_challenges", 1024),
            getattr(settings, "arena_wallet_auth_max_pending_challenges", 1024),
            getattr(settings, "compute_wallet_auth_max_pending_challenges", 1024),
            getattr(settings, "review_authority_max_pending_challenges", 1024),
        )
        maximum_ttl = max(
            _positive_int(value, label="wallet challenge TTL", maximum=600)
            for value in ttl_values
        )
        minimum_store = min(
            _positive_int(value, label="wallet challenge store capacity", maximum=1_000_000)
            for value in store_values
        )
        return cls(
            window_seconds=getattr(
                settings,
                "wallet_auth_challenge_limit_window_seconds",
                600,
            ),
            global_capacity=getattr(
                settings,
                "wallet_auth_challenge_global_limit",
                768,
            ),
            address_capacity=getattr(
                settings,
                "wallet_auth_challenge_address_limit",
                64,
            ),
            peer_capacity=getattr(
                settings,
                "wallet_auth_challenge_peer_limit",
                256,
            ),
            minimum_store_capacity=minimum_store,
            maximum_challenge_ttl=maximum_ttl,
        )

    def _prune(self, values: deque[float], now: float) -> None:
        cutoff = now - self.window_seconds
        while values and values[0] <= cutoff:
            values.popleft()

    def _retry_after(self, values: deque[float], now: float) -> int:
        if not values:
            return 1
        return max(1, math.ceil(values[0] + self.window_seconds - now))

    def _prune_map(self, buckets: dict[str, deque[float]], now: float) -> None:
        """Remove every expired identity bucket while holding ``self._lock``.

        Pruning only the identity named by the current request would leave old
        one-shot address and peer keys resident forever.  The global capacity
        bounds this scan to fewer than ``minimum_store_capacity`` live entries,
        so a complete sweep keeps both identity maps bounded without creating a
        second, independently fallible eviction policy.
        """

        for key, bucket in tuple(buckets.items()):
            self._prune(bucket, now)
            if not bucket:
                del buckets[key]

    def admit(self, *, address: Any, peer_source: str) -> None:
        canonical_address = _canonical_address(address)
        canonical_peer = str(peer_source or "").strip()
        if not canonical_peer or len(canonical_peer) > 128:
            raise ValueError("wallet challenge peer source is invalid")
        observed_now = float(self._clock())
        if not math.isfinite(observed_now):
            raise WalletChallengeLimitConfigurationError(
                "wallet challenge limiter clock is invalid"
            )
        with self._lock:
            # Nonce expiry uses the wall clock too. If it moves backwards, keep
            # the limiter frozen at its prior timestamp so entries cannot age
            # out while their corresponding nonce records remain live longer.
            now = max(observed_now, self._last_now)
            self._last_now = now
            prior_global_count = len(self._global)
            self._prune(self._global, now)
            # Every identity timestamp is also in the same-window global
            # bucket.  A full identity sweep is therefore needed only when at
            # least one global admission expired, avoiding O(capacity) work on
            # a flood of already-rate-limited requests.
            if len(self._global) != prior_global_count:
                self._prune_map(self._addresses, now)
                self._prune_map(self._peers, now)
            address_bucket = self._addresses.get(canonical_address, deque())
            peer_bucket = self._peers.get(canonical_peer, deque())
            retry_values: list[int] = []
            if len(self._global) >= self.global_capacity:
                retry_values.append(self._retry_after(self._global, now))
            if len(address_bucket) >= self.address_capacity:
                retry_values.append(self._retry_after(address_bucket, now))
            if len(peer_bucket) >= self.peer_capacity:
                retry_values.append(self._retry_after(peer_bucket, now))
            if retry_values:
                raise WalletChallengeRateLimited(max(retry_values))

            self._global.append(now)
            if canonical_address not in self._addresses:
                self._addresses[canonical_address] = address_bucket
            self._addresses[canonical_address].append(now)
            if canonical_peer not in self._peers:
                self._peers[canonical_peer] = peer_bucket
            self._peers[canonical_peer].append(now)

    def accepted_count(self) -> int:
        """Bounded test/diagnostic count; no address or peer identities egress."""

        observed_now = float(self._clock())
        if not math.isfinite(observed_now):
            raise WalletChallengeLimitConfigurationError(
                "wallet challenge limiter clock is invalid"
            )
        with self._lock:
            now = max(observed_now, self._last_now)
            self._last_now = now
            prior_global_count = len(self._global)
            self._prune(self._global, now)
            if len(self._global) != prior_global_count:
                self._prune_map(self._addresses, now)
                self._prune_map(self._peers, now)
            return len(self._global)
