import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from tinker_delegate import api
from tinker_delegate.arena_store import BIO_CHALLENGE_ID, BIO_CHALLENGE_VERSION
from tinker_delegate.config import Settings
from tinker_delegate.wallet_auth import WalletChallengeStore
from tinker_delegate.wallet_challenge_limiter import (
    WalletChallengeAdmissionLimiter,
    WalletChallengeLimitConfigurationError,
    WalletChallengePeerPolicy,
    WalletChallengeRateLimited,
)


ADDRESS_A = "0x" + "11" * 20
ADDRESS_B = "0x" + "22" * 20
LOCAL_WALLET_KEY = "challenge-limiter-wallet-key-" + "w" * 48


class MutableClock:
    def __init__(self, value=1000.0):
        self.value = value

    def __call__(self):
        return self.value


def limiter(clock, *, global_capacity=3, address_capacity=2, peer_capacity=2):
    return WalletChallengeAdmissionLimiter(
        window_seconds=60,
        global_capacity=global_capacity,
        address_capacity=address_capacity,
        peer_capacity=peer_capacity,
        minimum_store_capacity=global_capacity + 1,
        maximum_challenge_ttl=60,
        clock=clock,
    )


class WalletChallengeAdmissionLimiterTest(unittest.TestCase):
    def test_default_settings_keep_a_256_nonce_headroom_in_all_four_stores(self):
        gate = WalletChallengeAdmissionLimiter.from_settings(Settings())
        self.assertEqual(gate.window_seconds, 600)
        self.assertEqual(gate.maximum_challenge_ttl, 300)
        self.assertEqual(gate.global_capacity, 768)
        self.assertEqual(gate.minimum_store_capacity, 1024)
        self.assertEqual(
            gate.minimum_store_capacity - gate.global_capacity,
            256,
        )

    def test_review_ttl_and_store_capacity_join_the_shared_safety_proof(self):
        with self.assertRaisesRegex(
            WalletChallengeLimitConfigurationError,
            "below every nonce store capacity",
        ):
            WalletChallengeAdmissionLimiter.from_settings(
                Settings(review_authority_max_pending_challenges=768)
            )
        with self.assertRaisesRegex(
            WalletChallengeLimitConfigurationError,
            "outside its safe range",
        ):
            WalletChallengeAdmissionLimiter.from_settings(
                Settings(review_authority_challenge_ttl_seconds=601)
            )

    def test_configuration_proves_window_and_capacity_below_store_exhaustion(self):
        with self.assertRaisesRegex(
            WalletChallengeLimitConfigurationError,
            "cover the maximum challenge TTL",
        ):
            WalletChallengeAdmissionLimiter(
                window_seconds=59,
                global_capacity=3,
                address_capacity=2,
                peer_capacity=2,
                minimum_store_capacity=4,
                maximum_challenge_ttl=60,
            )
        with self.assertRaisesRegex(
            WalletChallengeLimitConfigurationError,
            "below every nonce store capacity",
        ):
            WalletChallengeAdmissionLimiter(
                window_seconds=60,
                global_capacity=4,
                address_capacity=2,
                peer_capacity=2,
                minimum_store_capacity=4,
                maximum_challenge_ttl=60,
            )

    def test_address_peer_and_global_saturation_have_exact_retry_after(self):
        clock = MutableClock()
        gate = limiter(clock)
        gate.admit(address=ADDRESS_A.upper().replace("0X", "0x"), peer_source="peer-a")
        gate.admit(address=ADDRESS_A, peer_source="peer-a")

        with self.assertRaises(WalletChallengeRateLimited) as raised:
            gate.admit(address=ADDRESS_A, peer_source="peer-a")
        self.assertEqual(raised.exception.retry_after, 60)
        self.assertEqual(str(raised.exception), "wallet challenge rate limit exceeded")

        # A different address and peer can use the last global slot, but no
        # fourth request can enter any nonce store during the same TTL window.
        gate.admit(address=ADDRESS_B, peer_source="peer-b")
        with self.assertRaises(WalletChallengeRateLimited) as global_limit:
            gate.admit(address="0x" + "33" * 20, peer_source="peer-c")
        self.assertEqual(global_limit.exception.retry_after, 60)
        self.assertEqual(gate.accepted_count(), 3)

        clock.value += 17.2
        with self.assertRaises(WalletChallengeRateLimited) as partial:
            gate.admit(address="0x" + "44" * 20, peer_source="peer-d")
        self.assertEqual(partial.exception.retry_after, 43)
        clock.value += 42.8
        gate.admit(address="0x" + "44" * 20, peer_source="peer-d")
        self.assertEqual(gate.accepted_count(), 1)

    def test_concurrent_saturation_never_exceeds_atomic_capacity(self):
        clock = MutableClock()
        gate = limiter(
            clock,
            global_capacity=7,
            address_capacity=7,
            peer_capacity=7,
        )
        workers = 32
        barrier = threading.Barrier(workers)

        def attempt():
            barrier.wait(timeout=5)
            try:
                gate.admit(address=ADDRESS_A, peer_source="shared-peer")
                return "accepted"
            except WalletChallengeRateLimited as exc:
                return f"limited:{exc.retry_after}"

        with ThreadPoolExecutor(max_workers=workers) as executor:
            results = list(executor.map(lambda _index: attempt(), range(workers)))

        self.assertEqual(results.count("accepted"), 7)
        self.assertEqual(results.count("limited:60"), workers - 7)
        self.assertEqual(gate.accepted_count(), 7)

    def test_backward_wall_clock_cannot_age_out_live_nonce_admissions(self):
        clock = MutableClock()
        gate = limiter(
            clock,
            global_capacity=1,
            address_capacity=1,
            peer_capacity=1,
        )
        gate.admit(address=ADDRESS_A, peer_source="peer-a")
        clock.value -= 3600
        with self.assertRaises(WalletChallengeRateLimited) as raised:
            gate.admit(address=ADDRESS_B, peer_source="peer-b")
        self.assertEqual(raised.exception.retry_after, 60)
        self.assertEqual(gate.accepted_count(), 1)

    def test_rotating_identities_cannot_accumulate_expired_bucket_keys(self):
        clock = MutableClock()
        gate = limiter(
            clock,
            global_capacity=7,
            address_capacity=7,
            peer_capacity=7,
        )
        for index in range(7):
            gate.admit(
                address="0x" + f"{index + 1:040x}",
                peer_source=f"ipv4:192.0.2.{index + 1}",
            )
        self.assertEqual(len(gate._addresses), 7)
        self.assertEqual(len(gate._peers), 7)

        clock.value += 60
        gate.admit(address=ADDRESS_A, peer_source="ipv4:198.51.100.10")

        self.assertEqual(gate.accepted_count(), 1)
        self.assertEqual(tuple(gate._addresses), (ADDRESS_A,))
        self.assertEqual(tuple(gate._peers), ("ipv4:198.51.100.10",))


class WalletChallengePeerPolicyTest(unittest.TestCase):
    def test_server_preserves_direct_socket_peer_for_the_pinned_proxy_policy(self):
        source = (
            Path(__file__).resolve().parents[1]
            / "tinker_delegate"
            / "main.py"
        ).read_text(encoding="utf-8")
        self.assertIn("proxy_headers=False", source)

    def test_forwarded_headers_are_ignored_without_a_pinned_proxy_policy(self):
        policy = WalletChallengePeerPolicy()
        source = policy.source(
            direct_peer="203.0.113.10",
            headers={"cf-connecting-ip": "198.51.100.9"},
        )
        self.assertEqual(source, "ipv4:203.0.113.10")

    def test_only_a_pinned_direct_proxy_can_supply_one_canonical_client_ip(self):
        policy = WalletChallengePeerPolicy(
            trusted_proxy_cidrs="203.0.113.0/24",
            client_ip_header="CF-Connecting-IP",
        )
        self.assertEqual(
            policy.source(
                direct_peer="203.0.113.10",
                headers={"cf-connecting-ip": "198.51.100.9"},
            ),
            "ipv4:198.51.100.9",
        )
        self.assertEqual(
            policy.source(
                direct_peer="192.0.2.10",
                headers={"cf-connecting-ip": "198.51.100.9"},
            ),
            "ipv4:192.0.2.10",
        )
        # Lists and noncanonical values do not become client identities.
        self.assertEqual(
            policy.source(
                direct_peer="203.0.113.10",
                headers={"cf-connecting-ip": "198.51.100.9, 192.0.2.1"},
            ),
            "ipv4:203.0.113.10",
        )

    def test_partial_or_ambiguous_proxy_configuration_is_rejected(self):
        with self.assertRaises(WalletChallengeLimitConfigurationError):
            WalletChallengePeerPolicy(client_ip_header="CF-Connecting-IP")
        with self.assertRaises(WalletChallengeLimitConfigurationError):
            WalletChallengePeerPolicy(
                trusted_proxy_cidrs="203.0.113.0/24",
                client_ip_header="X-Forwarded-For",
            )
        with self.assertRaisesRegex(
            WalletChallengeLimitConfigurationError,
            "too broad",
        ):
            WalletChallengePeerPolicy(
                trusted_proxy_cidrs="0.0.0.0/0",
                client_ip_header="CF-Connecting-IP",
            )


class WalletChallengeApiLimitTest(unittest.TestCase):
    def test_shared_gate_returns_exact_429_and_retry_after_across_surfaces(self):
        clock = MutableClock()
        gate = limiter(
            clock,
            global_capacity=1,
            address_capacity=1,
            peer_capacity=1,
        )
        settings = Settings(wallet_auth_signing_key=LOCAL_WALLET_KEY)
        with (
            patch.object(api, "settings", settings),
            patch.object(api, "_wallet_challenges", WalletChallengeStore(max_pending=2)),
            patch.object(api, "_wallet_challenge_limiter", gate),
            patch.object(api, "_wallet_challenge_peer_policy", WalletChallengePeerPolicy()),
            patch.object(api, "_require_arena_challenge", return_value=None),
        ):
            client = TestClient(api.app)
            accepted = client.post(
                "/auth/wallet/challenge",
                json={"address": ADDRESS_A, "deal_id": "deal-rate-limit"},
            )
            limited = client.post(
                "/auth/compute/challenge",
                json={"address": ADDRESS_B},
            )
            arena_limited = client.post(
                "/auth/arena/challenge",
                json={
                    "address": ADDRESS_B,
                    "challenge_id": BIO_CHALLENGE_ID,
                    "challenge_version": BIO_CHALLENGE_VERSION,
                },
            )

        self.assertEqual(accepted.status_code, 200, accepted.text)
        self.assertEqual(limited.status_code, 429, limited.text)
        self.assertEqual(
            limited.json(),
            {"detail": "Wallet challenge issuance is rate limited"},
        )
        self.assertEqual(limited.headers.get("retry-after"), "60")
        self.assertEqual(arena_limited.status_code, 429, arena_limited.text)
        self.assertEqual(arena_limited.json(), limited.json())
        self.assertEqual(arena_limited.headers.get("retry-after"), "60")


if __name__ == "__main__":
    unittest.main()
