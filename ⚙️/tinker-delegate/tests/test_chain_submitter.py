import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from eth_account import Account
from eth_hash.auto import keccak

from tinker_delegate.chain_submitter import (
    ChainSubmitterError,
    DiligenceRoomSubmitter,
    DstackEthereumSigner,
    ResultCommitment,
    SignerAttestationEvidence,
    SignerUnavailable,
    encode_submit_result_calldata,
    encode_uint256,
    eth_signed_message_digest,
    result_authorization_digest,
    signer_attestation_report_data,
    verify_signer_attestation_evidence,
)
from tinker_delegate.config import Settings


COMPOSE_HASH = "0x" + "99" * 32
CONTRACT_ADDRESS = "0x" + "55" * 20
AUTHORIZATION_EXPIRY = 2_000_000_000
VERIFIER_SIGNATURE = "0x" + "11" * 65


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
    ]
    return "0x" + "".join(words)


class InjectedTestSigner:
    custody = "injected_test_signer"

    def __init__(self):
        self._account = Account.create("dnai-wikigen-chain-submit-test")
        self.address = self._account.address

    def sign_transaction(self, transaction):
        return self._account.sign_transaction(transaction)


_COMPOSE_APPROVAL_REQUIRED_SELECTOR = "0x" + keccak(b"composeApprovalRequired()")[:4].hex()
_APPROVED_COMPOSE_HASHES_SELECTOR = "0x" + keccak(b"approvedComposeHashes(bytes32)")[:4].hex()
_FEE_BPS_SELECTOR = "0x" + keccak(b"feeBps()")[:4].hex()


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
    ):
        self.deal_response = deal_response
        self.compose_approval_required = compose_approval_required
        self.compose_hash_approved = compose_hash_approved
        self.fee_bps = fee_bps
        self.fee_bps_response = fee_bps_response
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
        return "0x" + "ab" * 32


class ChainSubmitterTest(unittest.TestCase):
    def test_submit_result_encodes_bounded_contract_call(self):
        result_hash = "0x" + "44" * 32
        calldata = encode_submit_result_calldata(
            deal_id=5,
            score_band="high",
            compute_cost_wei=123,
            result_hash=result_hash,
            compose_hash=COMPOSE_HASH,
            authorization_expiry=AUTHORIZATION_EXPIRY,
            verifier_signature=VERIFIER_SIGNATURE,
        )

        self.assertTrue(calldata.startswith("0x"))
        self.assertEqual(len(bytes.fromhex(calldata[2:])), 4 + (7 * 32) + 32 + 96)
        self.assertIn(_word_int(5), calldata)
        self.assertIn(_word_int(3), calldata)
        self.assertIn("44" * 32, calldata)
        self.assertIn(COMPOSE_HASH[2:], calldata)
        self.assertIn(_word_int(AUTHORIZATION_EXPIRY), calldata)
        self.assertIn(_word_int(7 * 32), calldata)
        self.assertIn(_word_int(65), calldata)

    def test_submit_result_broadcasts_from_matching_tee_signer(self):
        signer = InjectedTestSigner()
        rpc = FakeRpc(_deal_response(tee_identity=signer.address))
        submitter = DiligenceRoomSubmitter(
            rpc,
            CONTRACT_ADDRESS,
            signer,
        )

        receipt = submitter.submit_result(
            deal_id=1,
            score_band="medium",
            compute_cost_wei=10**15,
            result_hash="0x" + "66" * 32,
            authorization_expiry=AUTHORIZATION_EXPIRY,
            verifier_signature=VERIFIER_SIGNATURE,
            compose_hash=COMPOSE_HASH,
        )
        expected_commitment = ResultCommitment(
            chain_id=31337,
            contract_address=CONTRACT_ADDRESS,
            deal_id=1,
            nonce=7,
            compose_hash=COMPOSE_HASH,
            payload_result_hash="0x" + "66" * 32,
            score_band_value=2,
            compute_cost_wei=10**15,
            expiry=9999999999,
        ).digest()

        self.assertTrue(receipt.submitted)
        self.assertEqual(receipt.tx_hash, "0x" + "ab" * 32)
        self.assertEqual(receipt.score_band, "medium")
        self.assertEqual(receipt.score_band_value, 2)
        self.assertEqual(receipt.chain_id, 31337)
        self.assertEqual(receipt.nonce, 7)
        self.assertEqual(receipt.gas_limit, 123456)
        self.assertEqual(receipt.payload_result_hash, "0x" + "66" * 32)
        self.assertEqual(receipt.result_hash, expected_commitment)
        self.assertEqual(receipt.compose_hash, COMPOSE_HASH)
        self.assertEqual(receipt.expiry, 9999999999)
        self.assertEqual(receipt.authorization_expiry, AUTHORIZATION_EXPIRY)
        self.assertEqual(
            receipt.verifier_signature_hash,
            "0x" + hashlib.sha256(bytes.fromhex("11" * 65)).hexdigest(),
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
                compute_cost_wei=1,
                result_hash="0x" + "66" * 32,
                authorization_expiry=AUTHORIZATION_EXPIRY,
                verifier_signature=VERIFIER_SIGNATURE,
                compose_hash=COMPOSE_HASH,
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
                compute_cost_wei=1,
                result_hash="0x" + "66" * 32,
                authorization_expiry=AUTHORIZATION_EXPIRY,
                verifier_signature=VERIFIER_SIGNATURE,
                compose_hash=COMPOSE_HASH,
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
                compute_cost_wei=10**15,
                result_hash="0x" + "66" * 32,
                authorization_expiry=AUTHORIZATION_EXPIRY,
                verifier_signature=VERIFIER_SIGNATURE,
                compose_hash=COMPOSE_HASH,
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
            compute_cost_wei=10**15,
            result_hash="0x" + "66" * 32,
            authorization_expiry=AUTHORIZATION_EXPIRY,
            verifier_signature=VERIFIER_SIGNATURE,
            compose_hash=COMPOSE_HASH,
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
            compute_cost_wei=10**15,
            result_hash="0x" + "66" * 32,
            authorization_expiry=AUTHORIZATION_EXPIRY,
            verifier_signature=VERIFIER_SIGNATURE,
            compose_hash=COMPOSE_HASH,
        )
        self.assertTrue(receipt.submitted)
        self.assertEqual(len(rpc.sent_raw_transactions), 1)

    def test_submit_result_uses_onchain_fee_bps_for_budget_check(self):
        # A raised on-chain fee (10%) tightens the budget check: a compute cost
        # that fits under 1% now exceeds budget once the real fee is read.
        signer = InjectedTestSigner()
        budget = 10**18
        compute = 950_000_000_000_000_000  # 0.95 ETH; +10% fee = 1.045 ETH > budget
        rpc = FakeRpc(
            _deal_response(tee_identity=signer.address, budget_cap=budget),
            fee_bps=1000,
        )
        submitter = DiligenceRoomSubmitter(rpc, CONTRACT_ADDRESS, signer)
        with self.assertRaisesRegex(ChainSubmitterError, "budget"):
            submitter.submit_result(
                deal_id=1,
                score_band="low",
                compute_cost_wei=compute,
                result_hash="0x" + "66" * 32,
                authorization_expiry=AUTHORIZATION_EXPIRY,
                verifier_signature=VERIFIER_SIGNATURE,
                compose_hash=COMPOSE_HASH,
            )
        self.assertEqual(len(rpc.sent_raw_transactions), 0)

    def test_submit_result_falls_back_to_default_fee_when_getter_absent(self):
        # Older deployment without feeBps(): empty return -> default 1%, submit ok.
        signer = InjectedTestSigner()
        rpc = FakeRpc(
            _deal_response(tee_identity=signer.address),
            fee_bps_response="0x",
        )
        submitter = DiligenceRoomSubmitter(rpc, CONTRACT_ADDRESS, signer)
        self.assertEqual(submitter.read_fee_bps(), 100)
        receipt = submitter.submit_result(
            deal_id=1,
            score_band="medium",
            compute_cost_wei=10**15,
            result_hash="0x" + "66" * 32,
            authorization_expiry=AUTHORIZATION_EXPIRY,
            verifier_signature=VERIFIER_SIGNATURE,
            compose_hash=COMPOSE_HASH,
        )
        self.assertTrue(receipt.submitted)

    def test_read_fee_bps_returns_onchain_value(self):
        signer = InjectedTestSigner()
        rpc = FakeRpc(_deal_response(tee_identity=signer.address), fee_bps=250)
        submitter = DiligenceRoomSubmitter(rpc, CONTRACT_ADDRESS, signer)
        self.assertEqual(submitter.read_fee_bps(), 250)

    def test_submit_result_rejects_over_budget_compute_cost(self):
        signer = InjectedTestSigner()
        submitter = DiligenceRoomSubmitter(
            FakeRpc(_deal_response(tee_identity=signer.address, budget_cap=100)),
            CONTRACT_ADDRESS,
            signer,
        )
        with self.assertRaisesRegex(ChainSubmitterError, "budget"):
            submitter.submit_result(
                deal_id=1,
                score_band="low",
                compute_cost_wei=100,
                result_hash="0x" + "66" * 32,
                authorization_expiry=AUTHORIZATION_EXPIRY,
                verifier_signature=VERIFIER_SIGNATURE,
                compose_hash=COMPOSE_HASH,
            )

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
            compute_cost_wei=10**15,
            result_hash="0x" + "66" * 32,
            authorization_expiry=AUTHORIZATION_EXPIRY,
            verifier_signature=VERIFIER_SIGNATURE,
            compose_hash=COMPOSE_HASH,
        )

        body = json.dumps(receipt.to_public_dict())
        self.assertIn('"raw_secret_egress": false', body)
        self.assertNotIn("private", body.lower())
        self.assertNotIn("card", body.lower())
        self.assertNotIn("api_key", body.lower())

    def test_result_commitment_changes_with_replay_context(self):
        base = ResultCommitment(
            chain_id=31337,
            contract_address=CONTRACT_ADDRESS,
            deal_id=1,
            nonce=7,
            compose_hash=COMPOSE_HASH,
            payload_result_hash="0x" + "66" * 32,
            score_band_value=2,
            compute_cost_wei=10**15,
            expiry=9999999999,
        )
        replay = ResultCommitment(
            chain_id=31337,
            contract_address=CONTRACT_ADDRESS,
            deal_id=1,
            nonce=8,
            compose_hash=COMPOSE_HASH,
            payload_result_hash="0x" + "66" * 32,
            score_band_value=2,
            compute_cost_wei=10**15,
            expiry=9999999999,
        )

        self.assertNotEqual(base.digest(), replay.digest())
        self.assertEqual(base.public_fields()["compute_cost_band"], "1e15-1e18")

    def _base_commitment(self, **overrides) -> ResultCommitment:
        params = dict(
            chain_id=31337,
            contract_address=CONTRACT_ADDRESS,
            deal_id=1,
            nonce=7,
            compose_hash=COMPOSE_HASH,
            payload_result_hash="0x" + "66" * 32,
            score_band_value=2,
            compute_cost_wei=10**15,
            expiry=9999999999,
        )
        params.update(overrides)
        return ResultCommitment(**params)

    def test_reward_transcript_binding_is_backward_compatible(self):
        # Absent reward transcript -> v1 digest, byte-identical to a commitment
        # built without the new field, and no extra public field.
        v1 = self._base_commitment()
        v1_explicit_empty = self._base_commitment(reward_transcript_commitment="")
        self.assertEqual(v1.digest(), v1_explicit_empty.digest())
        self.assertNotIn("reward_transcript_commitment", v1.public_fields())

    def test_reward_transcript_binding_changes_and_binds_digest(self):
        v1 = self._base_commitment()
        commitment = "0x" + "ab" * 32
        v2 = self._base_commitment(reward_transcript_commitment=commitment)
        # Binding a transcript changes the on-chain resultHash (v1 != v2)...
        self.assertNotEqual(v1.digest(), v2.digest())
        # ...and a different transcript yields a different digest (it is bound).
        v2_other = self._base_commitment(reward_transcript_commitment="0x" + "cd" * 32)
        self.assertNotEqual(v2.digest(), v2_other.digest())
        self.assertEqual(
            v2.public_fields()["reward_transcript_commitment"], commitment
        )

    def test_reward_transcript_digest_recomputes_from_public_fields(self):
        commitment = "0x" + "ab" * 32
        v2 = self._base_commitment(reward_transcript_commitment=commitment)
        # Anyone with the bounded public fields can recompute the v2 digest and
        # check it equals the on-chain resultHash.
        recomputed = ResultCommitment(
            chain_id=v2.public_fields()["chain_id"],
            contract_address=v2.public_fields()["contract_address"],
            deal_id=v2.public_fields()["deal_id"],
            nonce=v2.public_fields()["nonce"],
            compose_hash=v2.public_fields()["compose_hash"],
            payload_result_hash=v2.public_fields()["payload_result_hash"],
            score_band_value=v2.public_fields()["score_band_value"],
            compute_cost_wei=10**15,
            expiry=v2.public_fields()["expiry"],
            reward_transcript_commitment=v2.public_fields()["reward_transcript_commitment"],
        )
        self.assertEqual(recomputed.digest(), v2.digest())

    def test_submit_result_binds_reward_transcript_commitment(self):
        signer = InjectedTestSigner()
        commitment = "0x" + "ab" * 32
        receipt = DiligenceRoomSubmitter(
            FakeRpc(_deal_response(tee_identity=signer.address)),
            CONTRACT_ADDRESS,
            signer,
        ).submit_result(
            deal_id=1,
            score_band="medium",
            compute_cost_wei=10**15,
            result_hash="0x" + "66" * 32,
            authorization_expiry=AUTHORIZATION_EXPIRY,
            verifier_signature=VERIFIER_SIGNATURE,
            signer_attestation=_signer_attestation(signer_address=signer.address),
            reward_transcript_commitment=commitment,
        )
        self.assertEqual(receipt.reward_transcript_commitment, commitment)
        self.assertIn("reward_transcript_commitment", receipt.to_public_dict())
        # The submitted resultHash commits to the transcript: recompute v2 and match.
        expected = ResultCommitment(
            chain_id=receipt.chain_id,
            contract_address=receipt.contract_address,
            deal_id=receipt.deal_id,
            nonce=receipt.nonce,
            compose_hash=receipt.compose_hash,
            payload_result_hash=receipt.payload_result_hash,
            score_band_value=receipt.score_band_value,
            compute_cost_wei=10**15,
            expiry=receipt.expiry,
            reward_transcript_commitment=commitment,
        )
        self.assertEqual(receipt.result_hash, expected.digest())

    def test_submit_result_uses_signer_attestation_compose_hash(self):
        signer = InjectedTestSigner()
        receipt = DiligenceRoomSubmitter(
            FakeRpc(_deal_response(tee_identity=signer.address)),
            CONTRACT_ADDRESS,
            signer,
        ).submit_result(
            deal_id=1,
            score_band="medium",
            compute_cost_wei=10**15,
            result_hash="0x" + "66" * 32,
            authorization_expiry=AUTHORIZATION_EXPIRY,
            verifier_signature=VERIFIER_SIGNATURE,
            signer_attestation=_signer_attestation(signer_address=signer.address),
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

    def test_result_authorization_digest_matches_contract_shape(self):
        digest = result_authorization_digest(
            chain_id=31337,
            contract_address=CONTRACT_ADDRESS,
            deal_id=1,
            tee_identity="0x" + "aa" * 20,
            compose_hash=COMPOSE_HASH,
            score_band="medium",
            compute_cost_wei=10**15,
            result_hash="0x" + "66" * 32,
            authorization_expiry=AUTHORIZATION_EXPIRY,
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
