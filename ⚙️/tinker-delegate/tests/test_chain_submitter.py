import hashlib
import json
import subprocess
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from eth_account import Account
from eth_account.messages import encode_defunct
from eth_hash.auto import keccak

from tinker_delegate.chain_submitter import (
    ChainSubmitterError,
    DealRead,
    DiligenceRoomSubmitter,
    DstackEthereumSigner,
    PreparedSubmissionAttempt,
    PUBLIC_RESULT_TYPEHASH,
    SignerAttestationEvidence,
    SignerUnavailable,
    attestation_authorization_digest,
    authenticate_result_authorization,
    canonical_public_result_hash,
    decode_deal_call_result,
    encode_submit_result_calldata,
    encode_uint256,
    eth_signed_message_digest,
    policy_compute_cost,
    result_authorization_digest,
    signer_attestation_report_data,
    verify_signer_attestation_evidence,
)
from tinker_delegate.config import Settings


COMPOSE_HASH = "0x" + "99" * 32
CONTRACT_ADDRESS = "0x" + "55" * 20
VERIFIER_SIGNATURE = "0x" + "11" * 65
POLICY_COMPUTE = 10**16
EVALUATOR_POLICY_COMMITMENT = "0x" + "66" * 32
ATTESTATION_EVIDENCE_HASH = "0x" + "88" * 32
ATTESTATION_AUTHORIZATION_EXPIRY = int(time.time()) + 240
AUTHORIZATION_EXPIRY = int(time.time()) + 300
RESULT_VERIFIER_ACCOUNT = Account.from_key(bytes.fromhex("31" * 32))
ATTESTATION_VERIFIER_ACCOUNT = Account.from_key(bytes.fromhex("32" * 32))
ATTESTATION_POLICY_HASH = "0x" + "77" * 32


def _signer_attestation(
    *,
    signer_address: str,
    chain_id: int = 31337,
    contract_address: str = CONTRACT_ADDRESS,
    compose_hash: str = COMPOSE_HASH,
) -> SignerAttestationEvidence:
    report_data = "0x" + signer_attestation_report_data(
        signer_address=signer_address,
        chain_id=chain_id,
        contract_address=contract_address,
    ).hex()
    return SignerAttestationEvidence(
        mode="tdx",
        signer_address=signer_address,
        chain_id=chain_id,
        contract_address=contract_address,
        report_data=report_data,
        quote_report_data=report_data,
        quote_hash="0x" + "88" * 32,
        quote_size=128,
        compose_hash=compose_hash,
        app_id="app-ok",
        os_image_hash="os-ok",
    )


def _word_int(value: int) -> str:
    return value.to_bytes(32, "big").hex()


def _word_address(address: str) -> str:
    raw = address.lower().removeprefix("0x")
    return ("0" * 24) + raw


def _deal_response(*, tee_identity: str, state: int = 1, budget_cap: int = 10**18) -> str:
    words = [
        _word_address("0x" + "11" * 20),  # seller
        _word_address("0x" + "22" * 20),  # buyer
        _word_int(10**15),  # reservePrice
        _word_int(budget_cap),
        _word_int(9999999999),  # expiry
        _word_int(state),
        "33" * 32,  # artifactHash
        _word_address(tee_identity),
        _word_int(0),  # scoreBand
        _word_int(0),  # computeCost
        _word_int(0),  # fee
        "00" * 32,  # resultHash
        "00" * 32,  # resultComposeHash
        _word_address("0x" + "00" * 20),  # paymentToken
        EVALUATOR_POLICY_COMMITMENT[2:],
        "00" * 32,  # attestationEvidenceHash
        _word_int(0),  # resultAuthorizationExpiry
        _word_int(0),  # attestationAuthorizationExpiry
    ]
    return "0x" + "".join(words)


class InjectedTestSigner:
    custody = "injected_test_signer"
    allow_unverified_result_authorization_for_local_testing = True

    def __init__(self):
        self._account = Account.create("dnai-wikigen-chain-submit-test")
        self.address = self._account.address

    def sign_transaction(self, transaction):
        return self._account.sign_transaction(transaction)


class ProductionLikeInjectedSigner(InjectedTestSigner):
    """Test-only signer that exercises the production authorization gate."""

    custody = "dstack_derived_test"
    allow_unverified_result_authorization_for_local_testing = False


_COMPOSE_APPROVAL_REQUIRED_SELECTOR = "0x" + keccak(b"composeApprovalRequired()")[:4].hex()
_APPROVED_COMPOSE_HASHES_SELECTOR = "0x" + keccak(b"approvedComposeHashes(bytes32)")[:4].hex()
_FEE_BPS_SELECTOR = "0x" + keccak(b"feeBps()")[:4].hex()
_COMPUTE_POLICY_SELECTOR = "0x" + keccak(
    b"computeSettlementPolicyEnabled()"
)[:4].hex()
_RESULT_VERIFIER_SELECTOR = "0x" + keccak(b"resultVerifier()")[:4].hex()
_ATTESTATION_VERIFIER_SELECTOR = "0x" + keccak(b"attestationVerifier()")[:4].hex()
_ATTESTATION_POLICY_SELECTOR = "0x" + keccak(
    b"attestationReleasePolicyHash()"
)[:4].hex()
_ATTESTATION_FROZEN_SELECTOR = "0x" + keccak(
    b"attestationBindingFrozen()"
)[:4].hex()


def _bool_word(value: bool) -> str:
    return "0x" + (1 if value else 0).to_bytes(32, "big").hex()


def _uint_word(value: int) -> str:
    return "0x" + int(value).to_bytes(32, "big").hex()


class FakeRpc:
    def __init__(
        self,
        deal_response: str,
        *,
        compose_approval_required: bool = False,
        compose_hash_approved: bool = False,
        fee_bps: int = 100,
        fee_bps_response: str | None = None,
        compute_settlement_policy_enabled: bool = True,
        result_verifier: str = RESULT_VERIFIER_ACCOUNT.address,
        attestation_verifier: str = ATTESTATION_VERIFIER_ACCOUNT.address,
        attestation_release_policy_hash: str = ATTESTATION_POLICY_HASH,
        attestation_binding_frozen: bool = True,
    ):
        self.deal_response = deal_response
        self.compose_approval_required = compose_approval_required
        self.compose_hash_approved = compose_hash_approved
        self.fee_bps = fee_bps
        self.fee_bps_response = fee_bps_response
        self.compute_settlement_policy_enabled = compute_settlement_policy_enabled
        self.result_verifier = result_verifier
        self.attestation_verifier = attestation_verifier
        self.attestation_release_policy_hash = attestation_release_policy_hash
        self.attestation_binding_frozen = attestation_binding_frozen
        self.sent_raw_transactions: list[bytes] = []
        self.estimate_calls: list[dict] = []

    def eth_call(self, tx):
        self.last_eth_call = tx
        data = tx.get("data", "")
        if data.startswith(_COMPOSE_APPROVAL_REQUIRED_SELECTOR):
            return _bool_word(self.compose_approval_required)
        if data.startswith(_APPROVED_COMPOSE_HASHES_SELECTOR):
            return _bool_word(self.compose_hash_approved)
        if data.startswith(_FEE_BPS_SELECTOR):
            if self.fee_bps_response is not None:
                return self.fee_bps_response
            return _uint_word(self.fee_bps)
        if data.startswith(_COMPUTE_POLICY_SELECTOR):
            return _bool_word(self.compute_settlement_policy_enabled)
        if data.startswith(_RESULT_VERIFIER_SELECTOR):
            return "0x" + _word_address(self.result_verifier)
        if data.startswith(_ATTESTATION_VERIFIER_SELECTOR):
            return "0x" + _word_address(self.attestation_verifier)
        if data.startswith(_ATTESTATION_POLICY_SELECTOR):
            return self.attestation_release_policy_hash
        if data.startswith(_ATTESTATION_FROZEN_SELECTOR):
            return _bool_word(self.attestation_binding_frozen)
        return self.deal_response

    def chain_id(self):
        return 31337

    def nonce(self, address):
        self.nonce_address = address
        return 7

    def gas_price(self):
        return 1_000_000_000

    def estimate_gas(self, tx):
        self.estimate_calls.append(tx)
        return 123456

    def send_raw_transaction(self, raw_transaction: bytes):
        self.sent_raw_transactions.append(raw_transaction)
        return "0x" + keccak(raw_transaction).hex()


def _authorization_args(
    rpc: FakeRpc,
    *,
    deal_id: int = 1,
    score_band: str | int = "medium",
    compute_cost_wei: int = POLICY_COMPUTE,
    compose_hash: str = COMPOSE_HASH,
    result_verifier_account=RESULT_VERIFIER_ACCOUNT,
    attestation_verifier_account=ATTESTATION_VERIFIER_ACCOUNT,
) -> dict[str, object]:
    deal = decode_deal_call_result(rpc.deal_response)
    result_digest = result_authorization_digest(
        chain_id=rpc.chain_id(),
        contract_address=CONTRACT_ADDRESS,
        deal_id=deal_id,
        deal=deal,
        compose_hash=compose_hash,
        score_band=score_band,
        compute_cost_wei=compute_cost_wei,
        authorization_expiry=AUTHORIZATION_EXPIRY,
        attestation_release_policy_hash=rpc.attestation_release_policy_hash,
    )
    qvl_digest = attestation_authorization_digest(
        chain_id=rpc.chain_id(),
        contract_address=CONTRACT_ADDRESS,
        deal_id=deal_id,
        deal=deal,
        compose_hash=compose_hash,
        score_band=score_band,
        compute_cost_wei=compute_cost_wei,
        attestation_release_policy_hash=rpc.attestation_release_policy_hash,
        attestation_evidence_hash=ATTESTATION_EVIDENCE_HASH,
        authorization_expiry=ATTESTATION_AUTHORIZATION_EXPIRY,
    )
    return {
        "authorization_expiry": AUTHORIZATION_EXPIRY,
        "verifier_signature": "0x"
        + result_verifier_account.sign_message(
            encode_defunct(hexstr=result_digest)
        ).signature.hex(),
        "attestation_evidence_hash": ATTESTATION_EVIDENCE_HASH,
        "attestation_authorization_expiry": ATTESTATION_AUTHORIZATION_EXPIRY,
        "attestation_verifier_signature": "0x"
        + attestation_verifier_account.sign_message(
            encode_defunct(hexstr=qvl_digest)
        ).signature.hex(),
    }


class ChainSubmitterTest(unittest.TestCase):
    def test_prepared_hash_and_nonce_are_exposed_before_network_send(self):
        signer = InjectedTestSigner()
        rpc = FakeRpc(_deal_response(tee_identity=signer.address))
        attempts: list[PreparedSubmissionAttempt] = []

        def checkpoint(attempt):
            self.assertEqual(rpc.sent_raw_transactions, [])
            attempts.append(attempt)

        receipt = DiligenceRoomSubmitter(
            rpc,
            CONTRACT_ADDRESS,
            signer,
        ).submit_result(
            deal_id=1,
            score_band="medium",
            compute_cost_wei=POLICY_COMPUTE,
            compose_hash=COMPOSE_HASH,
            before_broadcast=checkpoint,
            **_authorization_args(rpc),
        )

        self.assertEqual(len(attempts), 1)
        self.assertEqual(attempts[0].tx_hash, receipt.tx_hash)
        self.assertEqual(attempts[0].nonce, receipt.nonce)
        self.assertEqual(attempts[0].result_hash, receipt.result_hash)

    def test_submit_result_encodes_bounded_contract_call(self):
        calldata = encode_submit_result_calldata(
            deal_id=5,
            score_band="high",
            compute_cost_wei=123,
            compose_hash=COMPOSE_HASH,
            authorization_expiry=AUTHORIZATION_EXPIRY,
            verifier_signature=VERIFIER_SIGNATURE,
            attestation_evidence_hash=ATTESTATION_EVIDENCE_HASH,
            attestation_authorization_expiry=ATTESTATION_AUTHORIZATION_EXPIRY,
            attestation_verifier_signature=VERIFIER_SIGNATURE,
        )

        self.assertTrue(calldata.startswith("0x"))
        self.assertEqual(
            len(bytes.fromhex(calldata[2:])),
            4 + (9 * 32) + 2 * (32 + 96),
        )
        self.assertIn(_word_int(5), calldata)
        self.assertIn(_word_int(3), calldata)
        self.assertNotIn("44" * 32, calldata)
        self.assertIn(COMPOSE_HASH[2:], calldata)
        self.assertIn(_word_int(AUTHORIZATION_EXPIRY), calldata)
        self.assertIn(_word_int(9 * 32), calldata)
        self.assertIn(_word_int(65), calldata)

    def test_canonical_public_result_hash_is_domain_separated_and_public_only(self):
        deal = decode_deal_call_result(
            _deal_response(tee_identity="0x" + "77" * 20)
        )
        base = canonical_public_result_hash(
            chain_id=31337,
            contract_address=CONTRACT_ADDRESS,
            deal_id=1,
            deal=deal,
            compose_hash=COMPOSE_HASH,
            score_band="medium",
            compute_cost_wei=POLICY_COMPUTE,
        )
        same = canonical_public_result_hash(
            chain_id=31337,
            contract_address=CONTRACT_ADDRESS,
            deal_id=1,
            deal=deal,
            compose_hash=COMPOSE_HASH,
            score_band=2,
            compute_cost_wei=POLICY_COMPUTE,
        )
        changed_band = canonical_public_result_hash(
            chain_id=31337,
            contract_address=CONTRACT_ADDRESS,
            deal_id=1,
            deal=deal,
            compose_hash=COMPOSE_HASH,
            score_band="high",
            compute_cost_wei=POLICY_COMPUTE,
        )

        self.assertEqual(base, same)
        self.assertNotEqual(base, changed_band)
        self.assertRegex(base, r"^0x[0-9a-f]{64}$")

    def test_canonical_public_result_hash_matches_solidity_vector(self):
        deal = DealRead(
            seller="0x" + "22" * 20,
            buyer="0x" + "33" * 20,
            reserve_price=500_000_000_000_000_000,
            budget_cap=2_000_000_000_000_000_000,
            expiry=1_800_000_000,
            state=1,
            artifact_hash="0x" + "aa" * 32,
            tee_identity="0x" + "44" * 20,
            score_band=0,
            compute_cost=0,
            fee=0,
            result_hash="0x" + "00" * 32,
            evaluator_policy_commitment="0x" + "cc" * 32,
        )

        self.assertEqual(
            "0x" + PUBLIC_RESULT_TYPEHASH.hex(),
            "0xcc7808e2d534524498257da49708e62cc622bfddd641a5e5f3560882b0ce4c46",
        )
        self.assertEqual(
            canonical_public_result_hash(
                chain_id=84532,
                contract_address="0x" + "11" * 20,
                deal_id=7,
                deal=deal,
                compose_hash="0x" + "bb" * 32,
                score_band=2,
                compute_cost_wei=20_000_000_000_000_000,
            ),
            "0x76d9e72181f1906242b7e0a1484b8aef5c1057a6b93734d3f37d5b6c09b0195a",
        )

    def test_submit_result_broadcasts_from_matching_tee_signer(self):
        signer = InjectedTestSigner()
        rpc = FakeRpc(_deal_response(tee_identity=signer.address))
        submitter = DiligenceRoomSubmitter(
            rpc,
            CONTRACT_ADDRESS,
            signer,
        )
        authorization = _authorization_args(rpc)

        receipt = submitter.submit_result(
            deal_id=1,
            score_band="medium",
            compute_cost_wei=POLICY_COMPUTE,
            compose_hash=COMPOSE_HASH,
            **authorization,
        )
        deal = decode_deal_call_result(rpc.deal_response)
        expected_commitment = canonical_public_result_hash(
            chain_id=31337,
            contract_address=CONTRACT_ADDRESS,
            deal_id=1,
            deal=deal,
            compose_hash=COMPOSE_HASH,
            score_band="medium",
            compute_cost_wei=POLICY_COMPUTE,
        )

        self.assertTrue(receipt.submitted)
        self.assertEqual(
            receipt.tx_hash,
            "0x" + keccak(rpc.sent_raw_transactions[0]).hex(),
        )
        self.assertEqual(receipt.score_band, "medium")
        self.assertEqual(receipt.score_band_value, 2)
        self.assertEqual(receipt.chain_id, 31337)
        self.assertEqual(receipt.nonce, 7)
        self.assertEqual(receipt.gas_limit, 123456)
        self.assertEqual(receipt.result_hash, expected_commitment)
        self.assertEqual(receipt.compose_hash, COMPOSE_HASH)
        self.assertEqual(receipt.expiry, 9999999999)
        self.assertEqual(receipt.authorization_expiry, AUTHORIZATION_EXPIRY)
        self.assertEqual(
            receipt.verifier_signature_hash,
            "0x"
            + hashlib.sha256(
                bytes.fromhex(str(authorization["verifier_signature"])[2:])
            ).hexdigest(),
        )
        self.assertEqual(receipt.custody, "injected_test_signer")
        self.assertFalse(receipt.raw_secret_egress)
        self.assertEqual(len(rpc.sent_raw_transactions), 1)
        recovered = Account.recover_transaction(rpc.sent_raw_transactions[0])
        self.assertEqual(recovered.lower(), signer.address.lower())

    def test_submit_result_rejects_wrong_deal_state_or_signer(self):
        signer = InjectedTestSigner()
        wrong_tee = "0x" + "77" * 20
        submitter = DiligenceRoomSubmitter(
            FakeRpc(_deal_response(tee_identity=wrong_tee)),
            CONTRACT_ADDRESS,
            signer,
        )
        with self.assertRaisesRegex(ChainSubmitterError, "teeIdentity"):
            submitter.submit_result(
                deal_id=1,
                score_band="low",
                compute_cost_wei=POLICY_COMPUTE,
                compose_hash=COMPOSE_HASH,
                **_authorization_args(
                    submitter.rpc,
                    score_band="low",
                ),
            )

        submitter = DiligenceRoomSubmitter(
            FakeRpc(_deal_response(tee_identity=signer.address, state=0)),
            CONTRACT_ADDRESS,
            signer,
        )
        with self.assertRaisesRegex(ChainSubmitterError, "Funded"):
            submitter.submit_result(
                deal_id=1,
                score_band="low",
                compute_cost_wei=POLICY_COMPUTE,
                compose_hash=COMPOSE_HASH,
                **_authorization_args(
                    submitter.rpc,
                    score_band="low",
                ),
            )

    def test_submit_result_fails_closed_when_compose_not_approved_onchain(self):
        signer = InjectedTestSigner()
        rpc = FakeRpc(
            _deal_response(tee_identity=signer.address),
            compose_approval_required=True,
            compose_hash_approved=False,
        )
        submitter = DiligenceRoomSubmitter(rpc, CONTRACT_ADDRESS, signer)
        with self.assertRaisesRegex(ChainSubmitterError, "not approved on-chain"):
            submitter.submit_result(
                deal_id=1,
                score_band="high",
                compute_cost_wei=POLICY_COMPUTE,
                compose_hash=COMPOSE_HASH,
                **_authorization_args(rpc, score_band="high"),
            )
        # Fail closed BEFORE broadcasting — no transaction sent, no gas spent.
        self.assertEqual(len(rpc.sent_raw_transactions), 0)

    def test_submit_result_broadcasts_when_compose_approved_onchain(self):
        signer = InjectedTestSigner()
        rpc = FakeRpc(
            _deal_response(tee_identity=signer.address),
            compose_approval_required=True,
            compose_hash_approved=True,
        )
        submitter = DiligenceRoomSubmitter(rpc, CONTRACT_ADDRESS, signer)
        receipt = submitter.submit_result(
            deal_id=1,
            score_band="high",
            compute_cost_wei=POLICY_COMPUTE,
            compose_hash=COMPOSE_HASH,
            **_authorization_args(rpc, score_band="high"),
        )
        self.assertTrue(receipt.submitted)
        self.assertEqual(len(rpc.sent_raw_transactions), 1)

    def test_submit_result_ignores_gate_when_not_required(self):
        # Gate off on-chain: an unapproved compose still submits (backward compat).
        signer = InjectedTestSigner()
        rpc = FakeRpc(
            _deal_response(tee_identity=signer.address),
            compose_approval_required=False,
            compose_hash_approved=False,
        )
        submitter = DiligenceRoomSubmitter(rpc, CONTRACT_ADDRESS, signer)
        receipt = submitter.submit_result(
            deal_id=1,
            score_band="high",
            compute_cost_wei=POLICY_COMPUTE,
            compose_hash=COMPOSE_HASH,
            **_authorization_args(rpc, score_band="high"),
        )
        self.assertTrue(receipt.submitted)
        self.assertEqual(len(rpc.sent_raw_transactions), 1)

    def test_submit_result_rejects_evaluator_modulated_compute_cost(self):
        signer = InjectedTestSigner()
        budget = 10**18
        rpc = FakeRpc(
            _deal_response(tee_identity=signer.address, budget_cap=budget),
            fee_bps=1000,
        )
        submitter = DiligenceRoomSubmitter(rpc, CONTRACT_ADDRESS, signer)
        with self.assertRaisesRegex(ChainSubmitterError, "deterministic"):
            submitter.submit_result(
                deal_id=1,
                score_band="low",
                compute_cost_wei=950_000_000_000_000_000,
                compose_hash=COMPOSE_HASH,
                **_authorization_args(
                    rpc,
                    score_band="low",
                    compute_cost_wei=950_000_000_000_000_000,
                ),
            )
        self.assertEqual(len(rpc.sent_raw_transactions), 0)

    def test_submit_result_rejects_contract_without_compute_policy_gate(self):
        signer = InjectedTestSigner()
        rpc = FakeRpc(
            _deal_response(tee_identity=signer.address),
            compute_settlement_policy_enabled=False,
        )
        submitter = DiligenceRoomSubmitter(rpc, CONTRACT_ADDRESS, signer)

        with self.assertRaisesRegex(ChainSubmitterError, "not enabled"):
            submitter.submit_result(
                deal_id=1,
                score_band="medium",
                compute_cost_wei=POLICY_COMPUTE,
                compose_hash=COMPOSE_HASH,
                **_authorization_args(rpc),
            )

        self.assertEqual(rpc.sent_raw_transactions, [])

    def test_submit_result_fails_closed_when_fee_getter_absent(self):
        signer = InjectedTestSigner()
        rpc = FakeRpc(
            _deal_response(tee_identity=signer.address),
            fee_bps_response="0x",
        )
        submitter = DiligenceRoomSubmitter(rpc, CONTRACT_ADDRESS, signer)
        with self.assertRaisesRegex(ChainSubmitterError, "short uint256"):
            submitter.read_fee_bps()

    def test_read_fee_bps_returns_onchain_value(self):
        signer = InjectedTestSigner()
        rpc = FakeRpc(_deal_response(tee_identity=signer.address), fee_bps=250)
        submitter = DiligenceRoomSubmitter(rpc, CONTRACT_ADDRESS, signer)
        self.assertEqual(submitter.read_fee_bps(), 250)

    def test_read_fee_bps_preserves_valid_onchain_zero(self):
        signer = InjectedTestSigner()
        rpc = FakeRpc(_deal_response(tee_identity=signer.address), fee_bps=0)
        submitter = DiligenceRoomSubmitter(rpc, CONTRACT_ADDRESS, signer)

        self.assertEqual(submitter.read_fee_bps(), 0)

    def test_reads_exact_frozen_attestation_binding(self):
        signer = InjectedTestSigner()
        rpc = FakeRpc(_deal_response(tee_identity=signer.address))
        submitter = DiligenceRoomSubmitter(rpc, CONTRACT_ADDRESS, signer)

        self.assertEqual(
            submitter.read_attestation_verifier().lower(),
            ATTESTATION_VERIFIER_ACCOUNT.address.lower(),
        )
        self.assertEqual(
            submitter.read_attestation_release_policy_hash(), "0x" + "77" * 32
        )
        self.assertTrue(submitter.read_attestation_binding_frozen())

    def test_submit_result_honors_zero_fee_policy(self):
        signer = InjectedTestSigner()
        budget = 10**18
        rpc = FakeRpc(
            _deal_response(tee_identity=signer.address, budget_cap=budget),
            fee_bps=0,
        )
        submitter = DiligenceRoomSubmitter(rpc, CONTRACT_ADDRESS, signer)

        receipt = submitter.submit_result(
            deal_id=1,
            score_band="medium",
            compute_cost_wei=budget // 100,
            compose_hash=COMPOSE_HASH,
            **_authorization_args(rpc, compute_cost_wei=budget // 100),
        )

        self.assertTrue(receipt.submitted)
        self.assertEqual(len(rpc.sent_raw_transactions), 1)

    def test_policy_compute_cost_caps_when_reserve_consumes_budget(self):
        signer = InjectedTestSigner()
        rpc = FakeRpc(
            _deal_response(tee_identity=signer.address, budget_cap=100),
            fee_bps=100,
        )
        submitter = DiligenceRoomSubmitter(
            rpc,
            CONTRACT_ADDRESS,
            signer,
        )
        deal = decode_deal_call_result(rpc.deal_response)
        self.assertEqual(policy_compute_cost(deal, 100), 0)
        receipt = submitter.submit_result(
            deal_id=1,
            score_band="low",
            compute_cost_wei=0,
            compose_hash=COMPOSE_HASH,
            **_authorization_args(
                rpc,
                score_band="low",
                compute_cost_wei=0,
            ),
        )
        self.assertTrue(receipt.submitted)

    def test_dstack_signer_fails_closed_outside_dstack_mode(self):
        with patch("tinker_delegate.chain_submitter.is_dstack_enabled", return_value=False):
            with self.assertRaisesRegex(SignerUnavailable, "dstack mode"):
                DstackEthereumSigner.from_settings(Settings())

    def test_cli_submit_result_has_no_private_key_flag(self):
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "tinker_delegate.main",
                "submit-result",
                "--help",
            ],
            check=True,
            cwd=Path(__file__).resolve().parents[1],
            text=True,
            capture_output=True,
        )
        help_body = result.stdout.lower()
        self.assertIn("submit-result", help_body)
        self.assertNotIn("private-key", help_body)
        self.assertNotIn("seed", help_body)
        self.assertNotIn("mnemonic", help_body)
        self.assertNotIn("result_hash", help_body)
        self.assertNotIn("payload", help_body)
        self.assertNotIn("reward-transcript", help_body)

    def test_bounded_receipt_json_contains_no_secret_shaped_fields(self):
        signer = InjectedTestSigner()
        rpc = FakeRpc(_deal_response(tee_identity=signer.address))
        receipt = DiligenceRoomSubmitter(
            rpc,
            CONTRACT_ADDRESS,
            signer,
            gas_limit=200000,
        ).submit_result(
            deal_id=1,
            score_band="medium",
            compute_cost_wei=POLICY_COMPUTE,
            compose_hash=COMPOSE_HASH,
            **_authorization_args(rpc),
        )

        body = json.dumps(receipt.to_public_dict())
        self.assertIn('"raw_secret_egress": false', body)
        self.assertNotIn("private", body.lower())
        self.assertNotIn("card", body.lower())
        self.assertNotIn("api_key", body.lower())

    def test_submit_result_uses_signer_attestation_compose_hash(self):
        signer = InjectedTestSigner()
        rpc = FakeRpc(_deal_response(tee_identity=signer.address))
        receipt = DiligenceRoomSubmitter(
            rpc,
            CONTRACT_ADDRESS,
            signer,
        ).submit_result(
            deal_id=1,
            score_band="medium",
            compute_cost_wei=POLICY_COMPUTE,
            signer_attestation=_signer_attestation(signer_address=signer.address),
            **_authorization_args(rpc),
        )

        self.assertEqual(receipt.compose_hash, COMPOSE_HASH)
        self.assertEqual(receipt.signer_attestation_hash, "0x" + "88" * 32)
        self.assertEqual(receipt.signer_attestation_quote_size, 128)
        self.assertEqual(
            receipt.signer_attestation_report_data,
            "0x" + signer_attestation_report_data(
                signer_address=signer.address,
                chain_id=31337,
                contract_address=CONTRACT_ADDRESS,
            ).hex(),
        )

    def test_production_submission_requires_authenticated_onchain_verifier(self):
        signer = ProductionLikeInjectedSigner()
        verifier = Account.create("independent-result-verifier")
        rpc = FakeRpc(
            _deal_response(tee_identity=signer.address),
            result_verifier=verifier.address,
        )
        deal = decode_deal_call_result(rpc.deal_response)
        digest = result_authorization_digest(
            chain_id=31337,
            contract_address=CONTRACT_ADDRESS,
            deal_id=1,
            deal=deal,
            compose_hash=COMPOSE_HASH,
            score_band="medium",
            compute_cost_wei=POLICY_COMPUTE,
            authorization_expiry=AUTHORIZATION_EXPIRY,
            attestation_release_policy_hash=rpc.attestation_release_policy_hash,
        )
        signature = verifier.sign_message(encode_defunct(hexstr=digest)).signature.hex()
        qvl_args = _authorization_args(
            rpc,
            result_verifier_account=verifier,
        )

        receipt = DiligenceRoomSubmitter(rpc, CONTRACT_ADDRESS, signer).submit_result(
            deal_id=1,
            score_band="medium",
            compute_cost_wei=POLICY_COMPUTE,
            authorization_expiry=AUTHORIZATION_EXPIRY,
            verifier_signature="0x" + signature,
            signer_attestation=_signer_attestation(signer_address=signer.address),
            attestation_evidence_hash=qvl_args["attestation_evidence_hash"],
            attestation_authorization_expiry=qvl_args[
                "attestation_authorization_expiry"
            ],
            attestation_verifier_signature=qvl_args[
                "attestation_verifier_signature"
            ],
        )

        self.assertTrue(receipt.result_authorization_authenticated)
        self.assertEqual(
            receipt.result_verifier_address.lower(), verifier.address.lower()
        )
        self.assertEqual(
            receipt.result_authorization_verdict,
            "authenticated_onchain_result_verifier_signature",
        )
        self.assertEqual(len(rpc.sent_raw_transactions), 1)

    def test_service_quote_envelope_cannot_self_authorize_production_submission(self):
        signer = ProductionLikeInjectedSigner()
        independent_verifier = Account.create("independent-result-verifier")
        rpc = FakeRpc(
            _deal_response(tee_identity=signer.address),
            result_verifier=independent_verifier.address,
        )

        # The envelope is internally consistent and looks like TDX evidence, but
        # it was produced by the submitting service. A signature from that same
        # TEE key is not an independent verifier verdict and must fail closed.
        deal = decode_deal_call_result(rpc.deal_response)
        digest = result_authorization_digest(
            chain_id=31337,
            contract_address=CONTRACT_ADDRESS,
            deal_id=1,
            deal=deal,
            compose_hash=COMPOSE_HASH,
            score_band="medium",
            compute_cost_wei=POLICY_COMPUTE,
            authorization_expiry=AUTHORIZATION_EXPIRY,
            attestation_release_policy_hash=rpc.attestation_release_policy_hash,
        )
        self_signature = signer._account.sign_message(encode_defunct(hexstr=digest)).signature.hex()
        qvl_args = _authorization_args(
            rpc,
            result_verifier_account=independent_verifier,
        )

        with self.assertRaisesRegex(
            ChainSubmitterError,
            "not signed by the on-chain verifier",
        ):
            DiligenceRoomSubmitter(rpc, CONTRACT_ADDRESS, signer).submit_result(
                deal_id=1,
                score_band="medium",
                compute_cost_wei=POLICY_COMPUTE,
                authorization_expiry=AUTHORIZATION_EXPIRY,
                verifier_signature="0x" + self_signature,
                signer_attestation=_signer_attestation(signer_address=signer.address),
                attestation_evidence_hash=qvl_args["attestation_evidence_hash"],
                attestation_authorization_expiry=qvl_args[
                    "attestation_authorization_expiry"
                ],
                attestation_verifier_signature=qvl_args[
                    "attestation_verifier_signature"
                ],
            )

        self.assertEqual(rpc.sent_raw_transactions, [])

    def test_result_authorization_rejects_same_key_and_expired_verdicts(self):
        signer = ProductionLikeInjectedSigner()
        signature = "0x" + "11" * 65
        common = {
            "tee_identity": signer.address,
            "chain_id": 31337,
            "contract_address": CONTRACT_ADDRESS,
            "deal_id": 1,
            "deal": decode_deal_call_result(
                _deal_response(tee_identity=signer.address)
            ),
            "compose_hash": COMPOSE_HASH,
            "score_band": "medium",
            "compute_cost_wei": POLICY_COMPUTE,
            "verifier_signature": signature,
            "attestation_release_policy_hash": ATTESTATION_POLICY_HASH,
        }
        with self.assertRaisesRegex(ChainSubmitterError, "independent"):
            authenticate_result_authorization(
                verifier_address=signer.address,
                authorization_expiry=AUTHORIZATION_EXPIRY,
                now=AUTHORIZATION_EXPIRY - 300,
                **common,
            )
        with self.assertRaisesRegex(ChainSubmitterError, "expired"):
            authenticate_result_authorization(
                verifier_address="0x" + "aa" * 20,
                authorization_expiry=100,
                now=100,
                **common,
            )

    def test_result_authorization_digest_matches_contract_shape(self):
        deal = decode_deal_call_result(
            _deal_response(tee_identity="0x" + "aa" * 20)
        )
        digest = result_authorization_digest(
            chain_id=31337,
            contract_address=CONTRACT_ADDRESS,
            deal_id=1,
            deal=deal,
            compose_hash=COMPOSE_HASH,
            score_band="medium",
            compute_cost_wei=POLICY_COMPUTE,
            authorization_expiry=AUTHORIZATION_EXPIRY,
            attestation_release_policy_hash=ATTESTATION_POLICY_HASH,
        )
        signed_digest = eth_signed_message_digest(digest)

        self.assertRegex(digest, r"^0x[0-9a-f]{64}$")
        self.assertRegex(signed_digest, r"^0x[0-9a-f]{64}$")
        self.assertNotEqual(digest, signed_digest)

    def test_signer_attestation_rejects_wrong_context(self):
        signer = InjectedTestSigner()
        evidence = _signer_attestation(signer_address=signer.address, chain_id=84532)

        with self.assertRaisesRegex(ChainSubmitterError, "chain id mismatch"):
            verify_signer_attestation_evidence(
                evidence,
                signer_address=signer.address,
                chain_id=31337,
                contract_address=CONTRACT_ADDRESS,
            )

    def test_signer_attestation_rejects_compose_mismatch(self):
        signer = InjectedTestSigner()
        evidence = _signer_attestation(signer_address=signer.address)

        with self.assertRaisesRegex(ChainSubmitterError, "compose hash mismatch"):
            verify_signer_attestation_evidence(
                evidence,
                signer_address=signer.address,
                chain_id=31337,
                contract_address=CONTRACT_ADDRESS,
                expected_compose_hash="0x" + "77" * 32,
            )


class EncodeUint256Test(unittest.TestCase):
    def test_valid_range(self):
        self.assertEqual(encode_uint256(0), b"\x00" * 32)
        self.assertEqual(encode_uint256(2**256 - 1), b"\xff" * 32)

    def test_out_of_range_raises_module_error(self):
        # Negative and >= 2**256 both fail with ChainSubmitterError, never a raw
        # OverflowError from to_bytes (money-path encoder hygiene).
        with self.assertRaises(ChainSubmitterError):
            encode_uint256(-1)
        with self.assertRaises(ChainSubmitterError):
            encode_uint256(2**256)


if __name__ == "__main__":
    unittest.main()
