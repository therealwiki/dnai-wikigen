import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

import httpx
from eth_account import Account
from eth_account.messages import defunct_hash_message, encode_defunct

from tinker_delegate.arena_auth import (
    ArenaAuthError,
    ArenaWalletAuthService,
    ArenaWalletChallengeStore,
)
from tinker_delegate.compute_auth import (
    ComputeAuthError,
    ComputeWalletAuthService,
    ComputeWalletChallengeStore,
)
from tinker_delegate.config import Settings
from tinker_delegate.wallet_auth import (
    WalletAuthError,
    WalletAuthService,
    WalletAuthUnavailable,
    WalletChallengeStore,
)
from tinker_delegate.wallet_signature_verifier import (
    BASE_SEPOLIA_CHAIN_ID,
    EIP1271_CALL_GAS_LIMIT,
    EIP1271_MAGIC_VALUE,
    BaseSepoliaWalletSignatureVerifier,
    BoundedJsonRpcClient,
    LocalEoaWalletSignatureVerifier,
    WalletSignatureError,
    WalletSignatureUnavailable,
    wallet_signature_verifier_from_settings,
)


LOCAL_WALLET_KEY = "shared-wallet-signing-key-" + "w" * 48
LOCAL_COMPUTE_KEY = "shared-compute-signing-key-" + "c" * 48
EOA_PRIVATE_KEY = "0x" + "55" * 32
CONTRACT_ADDRESS = "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
FINALIZED_BLOCK = 123_456
FINALIZED_BLOCK_HASH = "0x" + "ab" * 32


def _sign(message: str) -> str:
    return Account.sign_message(
        encode_defunct(text=message),
        private_key=EOA_PRIVATE_KEY,
    ).signature.hex()


class FakeRpc:
    def __init__(self, responses=None, *, failure=None):
        self.responses = dict(responses or {})
        self.failure = failure
        self.calls = []

    def request(self, method, params):
        self.calls.append((method, params))
        if self.failure is not None:
            raise self.failure
        response = self.responses[method]
        if isinstance(response, Exception):
            raise response
        if callable(response):
            return response(method, params)
        return response


def _block_response(finalized_block=FINALIZED_BLOCK, block_hash=FINALIZED_BLOCK_HASH):
    def respond(_method, params):
        tag = params[0]
        number = finalized_block if tag == "finalized" else int(tag, 16)
        return {"number": hex(number), "hash": block_hash}

    return respond


def _rpc(
    *,
    chain_id=BASE_SEPOLIA_CHAIN_ID,
    code="0x",
    call_result=None,
    finalized_block=FINALIZED_BLOCK,
    block_hash=FINALIZED_BLOCK_HASH,
):
    responses = {
        "eth_chainId": hex(chain_id),
        "eth_getBlockByNumber": _block_response(finalized_block, block_hash),
        "eth_getCode": code,
    }
    if call_result is not None:
        responses["eth_call"] = call_result
    return FakeRpc(responses)


class FakeStreamResponse:
    def __init__(self, *, status_code=200, headers=None, chunks=()):
        self.status_code = status_code
        self.headers = dict(headers or {})
        self.chunks = tuple(chunks)

    def __enter__(self):
        return self

    def __exit__(self, _type, _value, _traceback):
        return False

    def iter_bytes(self):
        yield from self.chunks


class AcceptingContractVerifier:
    def __init__(self, barrier=None):
        self.barrier = barrier
        self.calls = []
        self._lock = threading.Lock()

    def verify(self, *, address, message, signature):
        with self._lock:
            self.calls.append((address, message, signature))
        if self.barrier is not None:
            self.barrier.wait(timeout=5)
        return "eip1271"


class BlockingContractVerifier:
    def __init__(self):
        self.started = threading.Event()
        self.release = threading.Event()
        self.calls = []

    def verify(self, *, address, message, signature):
        self.calls.append((address, message, signature))
        self.started.set()
        if not self.release.wait(timeout=5):
            raise AssertionError("test did not release contract verification")
        return "eip1271"


class RejectingContractVerifier:
    def __init__(self):
        self.calls = []

    def verify(self, *, address, message, signature):
        self.calls.append((address, message, signature))
        raise WalletSignatureError("EIP-1271 contract wallet rejected signature")


class WalletSignatureVerifierTest(unittest.TestCase):
    def setUp(self):
        self.account = Account.from_key(EOA_PRIVATE_KEY)
        self.message = "dnai exact login challenge"

    def test_local_eoa_behavior_is_preserved_without_rpc(self):
        verifier = LocalEoaWalletSignatureVerifier()

        self.assertEqual(
            verifier.verify(
                address=self.account.address,
                message=self.message,
                signature=_sign(self.message),
            ),
            "eoa",
        )
        with self.assertRaisesRegex(WalletSignatureError, "does not match"):
            verifier.verify(
                address=Account.create().address,
                message=self.message,
                signature=_sign(self.message),
            )

    def test_two_base_sepolia_rpcs_detect_eoa_at_one_finalized_block(self):
        primary = _rpc(finalized_block=FINALIZED_BLOCK + 2)
        secondary = _rpc(finalized_block=FINALIZED_BLOCK)
        verifier = BaseSepoliaWalletSignatureVerifier(primary, secondary)

        result = verifier.verify(
            address=self.account.address,
            message=self.message,
            signature=_sign(self.message),
        )

        self.assertEqual(result, "eoa")
        for rpc in (primary, secondary):
            self.assertEqual(
                [call[0] for call in rpc.calls],
                [
                    "eth_chainId",
                    "eth_getBlockByNumber",
                    "eth_getBlockByNumber",
                    "eth_getCode",
                ],
            )
            self.assertEqual(
                rpc.calls[-1][1],
                [self.account.address.lower(), hex(FINALIZED_BLOCK)],
            )

    def test_each_rpc_phase_queries_both_providers_concurrently(self):
        barrier = threading.Barrier(2)

        def chain_id(_method, _params):
            barrier.wait(timeout=2)
            return hex(BASE_SEPOLIA_CHAIN_ID)

        primary = _rpc()
        secondary = _rpc()
        primary.responses["eth_chainId"] = chain_id
        secondary.responses["eth_chainId"] = chain_id
        verifier = BaseSepoliaWalletSignatureVerifier(primary, secondary)

        self.assertEqual(
            verifier.verify(
                address=self.account.address,
                message=self.message,
                signature=_sign(self.message),
            ),
            "eoa",
        )

    def test_contract_signature_uses_eip191_digest_and_exact_1271_selector(self):
        signature_bytes = bytes(range(200))
        call_result = "0x" + (EIP1271_MAGIC_VALUE + b"\x00" * 28).hex()
        primary = _rpc(code="0x60006000", call_result=call_result)
        secondary = _rpc(code="0x60006000", call_result=call_result)
        verifier = BaseSepoliaWalletSignatureVerifier(
            primary,
            secondary,
        )

        result = verifier.verify(
            address=CONTRACT_ADDRESS,
            message=self.message,
            signature="0x" + signature_bytes.hex(),
        )

        self.assertEqual(result, "eip1271")
        for rpc in (primary, secondary):
            self.assertEqual(
                [call[0] for call in rpc.calls],
                [
                    "eth_chainId",
                    "eth_getBlockByNumber",
                    "eth_getBlockByNumber",
                    "eth_getCode",
                    "eth_call",
                ],
            )
            call, block = rpc.calls[-1][1]
            self.assertEqual(block, hex(FINALIZED_BLOCK))
            self.assertEqual(call["to"], CONTRACT_ADDRESS.lower())
            self.assertEqual(call["gas"], hex(EIP1271_CALL_GAS_LIMIT))
            calldata = bytes.fromhex(call["data"][2:])
            self.assertEqual(calldata[:4], EIP1271_MAGIC_VALUE)
            self.assertEqual(
                calldata[4:36],
                bytes(defunct_hash_message(text=self.message)),
            )
            self.assertEqual(int.from_bytes(calldata[36:68], "big"), 64)
            self.assertEqual(
                int.from_bytes(calldata[68:100], "big"),
                len(signature_bytes),
            )
            self.assertEqual(
                calldata[100 : 100 + len(signature_bytes)],
                signature_bytes,
            )

    def test_wrong_magic_wrong_chain_and_rpc_failure_fail_closed(self):
        cases = (
            (
                "wrong magic",
                _rpc(code="0x6000", call_result="0xffffffff"),
                _rpc(code="0x6000", call_result="0xffffffff"),
                WalletSignatureError,
                "rejected",
            ),
            (
                "wrong chain",
                _rpc(chain_id=1),
                _rpc(),
                WalletSignatureUnavailable,
                "not both connected to Base Sepolia",
            ),
            (
                "rpc failure",
                FakeRpc(failure=WalletSignatureUnavailable("RPC offline")),
                _rpc(),
                WalletSignatureUnavailable,
                "RPC offline",
            ),
        )
        for label, primary, secondary, error_type, message in cases:
            with self.subTest(label=label):
                verifier = BaseSepoliaWalletSignatureVerifier(primary, secondary)
                with self.assertRaisesRegex(error_type, message):
                    verifier.verify(
                        address=CONTRACT_ADDRESS,
                        message=self.message,
                        signature="0x1234",
                    )

    def test_rpc_data_rejects_noncanonical_whitespace_hex(self):
        primary = _rpc(code="0x60  00")
        verifier = BaseSepoliaWalletSignatureVerifier(primary, _rpc(code="0x6000"))

        with self.assertRaisesRegex(WalletSignatureUnavailable, "malformed"):
            verifier.verify(
                address=CONTRACT_ADDRESS,
                message=self.message,
                signature="0x1234",
            )

    def test_finalized_block_code_and_magic_divergence_all_fail_closed(self):
        magic = "0x" + EIP1271_MAGIC_VALUE.hex()
        cases = (
            (
                "finalized block",
                _rpc(code="0x6000", call_result=magic),
                _rpc(
                    code="0x6000",
                    call_result=magic,
                    block_hash="0x" + "cd" * 32,
                ),
                "finalized block",
            ),
            (
                "code classification",
                _rpc(code="0x", call_result=magic),
                _rpc(code="0x6000", call_result=magic),
                "code classification",
            ),
            (
                "runtime code",
                _rpc(code="0x6000", call_result=magic),
                _rpc(code="0x6001", call_result=magic),
                "runtime code",
            ),
            (
                "magic",
                _rpc(code="0x6000", call_result=magic),
                _rpc(code="0x6000", call_result="0xffffffff"),
                "EIP-1271 validity",
            ),
        )
        for label, primary, secondary, expected in cases:
            with self.subTest(label=label):
                verifier = BaseSepoliaWalletSignatureVerifier(primary, secondary)
                with self.assertRaisesRegex(WalletSignatureUnavailable, expected):
                    verifier.verify(
                        address=CONTRACT_ADDRESS,
                        message=self.message,
                        signature="0x1234",
                    )

    def test_rpc_configuration_requires_two_distinct_provider_origins(self):
        with self.assertRaisesRegex(WalletSignatureUnavailable, "two configured"):
            wallet_signature_verifier_from_settings(
                Settings(wallet_auth_rpc_url="https://primary.example/rpc")
            )
        with self.assertRaisesRegex(WalletSignatureUnavailable, "distinct origins"):
            wallet_signature_verifier_from_settings(
                Settings(
                    wallet_auth_rpc_url="https://same.example/primary",
                    wallet_auth_rpc_url_secondary="https://same.example/secondary",
                )
            )
        verifier = wallet_signature_verifier_from_settings(
            Settings(
                wallet_auth_rpc_url="https://primary.example/rpc",
                wallet_auth_rpc_url_secondary="https://secondary.example/rpc",
            )
        )
        self.assertIsInstance(verifier, BaseSepoliaWalletSignatureVerifier)

    def test_malformed_or_oversized_signature_is_rejected_before_rpc(self):
        primary = FakeRpc(failure=AssertionError("RPC must not be called"))
        secondary = FakeRpc(failure=AssertionError("RPC must not be called"))
        verifier = BaseSepoliaWalletSignatureVerifier(primary, secondary)

        for signature in (
            "0x",
            "0x1",
            "0xzz",
            "0x12  34",
            "0x" + "11" * 4097,
        ):
            with self.subTest(signature_length=len(signature)):
                with self.assertRaises(WalletSignatureError):
                    verifier.verify(
                        address=CONTRACT_ADDRESS,
                        message=self.message,
                        signature=signature,
                    )
        self.assertEqual(primary.calls, [])
        self.assertEqual(secondary.calls, [])

    def test_json_rpc_client_enforces_https_timeout_and_decoded_body_bound(self):
        with self.assertRaisesRegex(WalletSignatureUnavailable, "HTTPS"):
            BoundedJsonRpcClient("http://rpc.example.test")

        oversized = FakeStreamResponse(chunks=(b"x" * 1025,))
        client = BoundedJsonRpcClient(
            "https://rpc.example.test/base-sepolia",
            timeout_seconds=1.25,
            max_response_bytes=1024,
        )
        with patch(
            "tinker_delegate.wallet_signature_verifier.httpx.stream",
            return_value=oversized,
        ) as stream:
            with self.assertRaisesRegex(WalletSignatureUnavailable, "exceeds"):
                client.request("eth_chainId", [])

        kwargs = stream.call_args.kwargs
        self.assertFalse(kwargs["follow_redirects"])
        self.assertFalse(kwargs["trust_env"])
        self.assertEqual(kwargs["timeout"].connect, 1.25)

    def test_json_rpc_transport_errors_are_generic_and_fail_closed(self):
        client = BoundedJsonRpcClient("https://rpc.example.test")
        with patch(
            "tinker_delegate.wallet_signature_verifier.httpx.stream",
            side_effect=httpx.ConnectError("secret provider failure"),
        ):
            with self.assertRaisesRegex(
                WalletSignatureUnavailable,
                "wallet signature RPC request failed",
            ) as raised:
                client.request("eth_chainId", [])
        self.assertNotIn("secret provider failure", str(raised.exception))

    def test_json_rpc_rejects_boolean_and_float_response_ids(self):
        client = BoundedJsonRpcClient("https://rpc.example.test")
        for response_id in (True, 1.0):
            response = FakeStreamResponse(
                chunks=(
                    (
                        '{"jsonrpc":"2.0","id":'
                        + str(response_id).lower()
                        + ',"result":"0x14a34"}'
                    ).encode(),
                )
            )
            with self.subTest(response_id=response_id), patch(
                "tinker_delegate.wallet_signature_verifier.httpx.stream",
                return_value=response,
            ):
                with self.assertRaisesRegex(WalletSignatureUnavailable, "invalid"):
                    client.request("eth_chainId", [])

    def test_json_rpc_deeply_nested_json_fails_closed(self):
        client = BoundedJsonRpcClient("https://rpc.example.test")
        nested = b"[" * 1_100 + b"0" + b"]" * 1_100
        response = FakeStreamResponse(chunks=(nested,))
        with patch(
            "tinker_delegate.wallet_signature_verifier.httpx.stream",
            return_value=response,
        ):
            with self.assertRaisesRegex(
                WalletSignatureUnavailable,
                "not valid JSON|response is invalid",
            ):
                client.request("eth_chainId", [])

    def test_global_external_verification_capacity_fails_before_rpc(self):
        primary = FakeRpc(failure=AssertionError("RPC must not be called while busy"))
        secondary = FakeRpc(failure=AssertionError("RPC must not be called while busy"))
        verifier = BaseSepoliaWalletSignatureVerifier(primary, secondary)
        slots = threading.BoundedSemaphore(1)
        self.assertTrue(slots.acquire(blocking=False))
        try:
            with patch(
                "tinker_delegate.wallet_signature_verifier._EXTERNAL_VERIFICATION_SLOTS",
                slots,
            ):
                with self.assertRaisesRegex(
                    WalletSignatureUnavailable,
                    "temporarily unavailable",
                ):
                    verifier.verify(
                        address=CONTRACT_ADDRESS,
                        message=self.message,
                        signature="0x1234",
                    )
        finally:
            slots.release()
        self.assertEqual(primary.calls, [])
        self.assertEqual(secondary.calls, [])

    def test_global_external_verification_slot_is_released_after_failures(self):
        primary = FakeRpc(
            failure=WalletSignatureUnavailable("Base Sepolia RPC unavailable")
        )
        secondary = _rpc()
        verifier = BaseSepoliaWalletSignatureVerifier(primary, secondary)

        for _attempt in range(12):
            with self.assertRaisesRegex(WalletSignatureUnavailable, "RPC unavailable"):
                verifier.verify(
                    address=CONTRACT_ADDRESS,
                    message=self.message,
                    signature="0x1234",
                )
        self.assertEqual(len(primary.calls), 12)
        self.assertEqual(len(secondary.calls), 12)

    def test_all_compose_surfaces_wire_bounded_wallet_rpc_configuration(self):
        root = Path(__file__).resolve().parents[1]
        local_manifests = (
            "docker-compose.yaml",
            "docker-compose.all.yaml",
        )
        production_manifests = (
            "docker-compose.dstack.yaml",
            "docker-compose.all.dstack.yaml",
            "docker-compose.all.phala.yaml",
        )
        controls = (
            "TINKER_WALLET_AUTH_RPC_TIMEOUT_SECONDS: "
            "${TINKER_WALLET_AUTH_RPC_TIMEOUT_SECONDS:-3.0}",
            "TINKER_WALLET_AUTH_RPC_MAX_RESPONSE_BYTES: "
            "${TINKER_WALLET_AUTH_RPC_MAX_RESPONSE_BYTES:-131072}",
            "TINKER_WALLET_AUTH_MAX_SIGNATURE_BYTES: "
            "${TINKER_WALLET_AUTH_MAX_SIGNATURE_BYTES:-4096}",
            "TINKER_WALLET_AUTH_CHALLENGE_LIMIT_WINDOW_SECONDS: "
            "${TINKER_WALLET_AUTH_CHALLENGE_LIMIT_WINDOW_SECONDS:-600}",
            "TINKER_WALLET_AUTH_CHALLENGE_GLOBAL_LIMIT: "
            "${TINKER_WALLET_AUTH_CHALLENGE_GLOBAL_LIMIT:-768}",
            "TINKER_WALLET_AUTH_CHALLENGE_ADDRESS_LIMIT: "
            "${TINKER_WALLET_AUTH_CHALLENGE_ADDRESS_LIMIT:-64}",
            "TINKER_WALLET_AUTH_CHALLENGE_PEER_LIMIT: "
            "${TINKER_WALLET_AUTH_CHALLENGE_PEER_LIMIT:-256}",
        )
        for name in (*local_manifests, *production_manifests):
            text = (root / name).read_text(encoding="utf-8")
            with self.subTest(manifest=name):
                for control in controls:
                    self.assertIn(control, text)
        for name in local_manifests:
            self.assertIn(
                "TINKER_WALLET_AUTH_RPC_URL: ${TINKER_WALLET_AUTH_RPC_URL:-}",
                (root / name).read_text(encoding="utf-8"),
            )
            self.assertIn(
                "TINKER_WALLET_AUTH_RPC_URL_SECONDARY: "
                "${TINKER_WALLET_AUTH_RPC_URL_SECONDARY:-}",
                (root / name).read_text(encoding="utf-8"),
            )
        for name in production_manifests:
            self.assertIn(
                "TINKER_WALLET_AUTH_RPC_URL: "
                "${TINKER_WALLET_AUTH_RPC_URL:?Trusted Base Sepolia "
                "wallet-auth HTTPS RPC URL required}",
                (root / name).read_text(encoding="utf-8"),
            )
            self.assertIn(
                "TINKER_WALLET_AUTH_RPC_URL_SECONDARY: "
                "${TINKER_WALLET_AUTH_RPC_URL_SECONDARY:?Independent secondary "
                "Base Sepolia wallet-auth HTTPS RPC URL required}",
                (root / name).read_text(encoding="utf-8"),
            )


class WalletAuthService1271IntegrationTest(unittest.TestCase):
    def setUp(self):
        self.settings = Settings(
            wallet_auth_signing_key=LOCAL_WALLET_KEY,
            compute_wallet_auth_signing_key=LOCAL_COMPUTE_KEY,
            wallet_auth_chain_id=BASE_SEPOLIA_CHAIN_ID,
        )

    def _cases(self, verifier):
        deal_store = WalletChallengeStore(max_pending=4)
        arena_store = ArenaWalletChallengeStore(max_pending=4)
        compute_store = ComputeWalletChallengeStore(max_pending=4)
        return (
            (
                "deal",
                WalletAuthService(self.settings, deal_store, verifier),
                lambda service: service.issue_challenge(
                    address=CONTRACT_ADDRESS,
                    deal_id="deal-1271",
                    now=100,
                ),
                WalletAuthError,
            ),
            (
                "arena",
                ArenaWalletAuthService(self.settings, arena_store, verifier),
                lambda service: service.issue_challenge(
                    address=CONTRACT_ADDRESS,
                    challenge_id="safe-ir",
                    challenge_version="1.0.0",
                    now=100,
                ),
                ArenaAuthError,
            ),
            (
                "compute",
                ComputeWalletAuthService(self.settings, compute_store, verifier),
                lambda service: service.issue_challenge(
                    address=CONTRACT_ADDRESS,
                    now=100,
                ),
                ComputeAuthError,
            ),
        )

    def test_deal_arena_and_compute_all_accept_1271_and_reject_replay(self):
        for label, service, issue, error_type in self._cases(AcceptingContractVerifier()):
            with self.subTest(service=label):
                challenge = issue(service)
                claims, _token = service.exchange_signature(
                    nonce=challenge.nonce,
                    signature="0x1234",
                    now=101,
                )
                self.assertEqual(claims.address, CONTRACT_ADDRESS.lower())
                with self.assertRaisesRegex(error_type, "already used"):
                    service.exchange_signature(
                        nonce=challenge.nonce,
                        signature="0x1234",
                        now=102,
                    )

    def test_concurrent_contract_exchanges_allow_one_in_flight_and_consume_once(self):
        for label in ("deal", "arena", "compute"):
            with self.subTest(service=label):
                verifier = BlockingContractVerifier()
                case = next(case for case in self._cases(verifier) if case[0] == label)
                _label, service, issue, error_type = case
                challenge = issue(service)

                def exchange():
                    try:
                        service.exchange_signature(
                            nonce=challenge.nonce,
                            signature="0x1234",
                            now=101,
                        )
                        return "accepted"
                    except error_type as exc:
                        return str(exc)

                with ThreadPoolExecutor(max_workers=1) as executor:
                    first = executor.submit(exchange)
                    self.assertTrue(verifier.started.wait(timeout=5))
                    second = exchange()
                    verifier.release.set()
                    results = [first.result(timeout=5), second]

                self.assertEqual(results.count("accepted"), 1)
                self.assertEqual(sum("already used" in result for result in results), 1)
                self.assertEqual(len(verifier.calls), 1)

    def test_failed_verification_attempts_are_bounded_per_nonce(self):
        for label in ("deal", "arena", "compute"):
            with self.subTest(service=label):
                verifier = RejectingContractVerifier()
                case = next(case for case in self._cases(verifier) if case[0] == label)
                _label, service, issue, error_type = case
                challenge = issue(service)

                for _attempt in range(3):
                    with self.assertRaisesRegex(error_type, "rejected"):
                        service.exchange_signature(
                            nonce=challenge.nonce,
                            signature="0x1234",
                            now=101,
                        )
                self.assertEqual(len(verifier.calls), 3)
                with self.assertRaisesRegex(error_type, "already used"):
                    service.exchange_signature(
                        nonce=challenge.nonce,
                        signature="0x1234",
                        now=101,
                    )
                self.assertEqual(len(verifier.calls), 3)

    def test_rpc_failure_does_not_consume_nonce(self):
        failing_primary = FakeRpc(
            failure=WalletSignatureUnavailable("Base Sepolia RPC offline")
        )
        service = WalletAuthService(
            self.settings,
            WalletChallengeStore(max_pending=4),
            BaseSepoliaWalletSignatureVerifier(failing_primary, _rpc()),
        )
        challenge = service.issue_challenge(
            address=CONTRACT_ADDRESS,
            deal_id="deal-1271",
            now=100,
        )

        with self.assertRaises(WalletAuthUnavailable):
            service.exchange_signature(
                nonce=challenge.nonce,
                signature="0x1234",
                now=101,
            )

        service.signature_verifier = AcceptingContractVerifier()
        claims, _token = service.exchange_signature(
            nonce=challenge.nonce,
            signature="0x1234",
            now=102,
        )
        self.assertEqual(claims.address, CONTRACT_ADDRESS.lower())

    def test_unexpected_verifier_failure_is_generic_and_releases_reservation(self):
        class ExplodingVerifier:
            def verify(self, **_kwargs):
                raise RuntimeError("secret-bearing provider diagnostic")

        service = WalletAuthService(
            self.settings,
            WalletChallengeStore(max_pending=4),
            ExplodingVerifier(),
        )
        challenge = service.issue_challenge(
            address=CONTRACT_ADDRESS,
            deal_id="deal-1271",
            now=100,
        )

        with self.assertRaisesRegex(
            WalletAuthUnavailable,
            "verification is unavailable",
        ) as raised:
            service.exchange_signature(
                nonce=challenge.nonce,
                signature="0x1234",
                now=101,
            )
        self.assertNotIn("secret-bearing", str(raised.exception))

        service.signature_verifier = AcceptingContractVerifier()
        claims, _token = service.exchange_signature(
            nonce=challenge.nonce,
            signature="0x1234",
            now=102,
        )
        self.assertEqual(claims.address, CONTRACT_ADDRESS.lower())

    def test_all_challenge_domains_reject_non_base_sepolia_configuration(self):
        wrong_chain = self.settings.model_copy(update={"wallet_auth_chain_id": 1})
        services = (
            (
                WalletAuthService(wrong_chain, WalletChallengeStore()),
                lambda service: service.issue_challenge(
                    address=CONTRACT_ADDRESS, deal_id="deal-1271", now=100
                ),
                WalletAuthError,
            ),
            (
                ArenaWalletAuthService(wrong_chain, ArenaWalletChallengeStore()),
                lambda service: service.issue_challenge(
                    address=CONTRACT_ADDRESS,
                    challenge_id="safe-ir",
                    challenge_version="1.0.0",
                    now=100,
                ),
                ArenaAuthError,
            ),
            (
                ComputeWalletAuthService(wrong_chain, ComputeWalletChallengeStore()),
                lambda service: service.issue_challenge(
                    address=CONTRACT_ADDRESS, now=100
                ),
                ComputeAuthError,
            ),
        )
        for service, issue, error_type in services:
            with self.assertRaisesRegex(error_type, "Base Sepolia"):
                issue(service)


if __name__ == "__main__":
    unittest.main()
