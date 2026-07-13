import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from eth_account import Account
from eth_account.messages import encode_defunct

from tinker_delegate.chain_submitter import (
    SignerAttestationEvidence,
    signer_attestation_report_data,
)
from tinker_delegate.config import Settings
from tinker_delegate.result_verifier import (
    DstackResultVerifierSigner,
    ResultAuthorizationRequest,
    ResultVerifierError,
    ResultVerifierPolicy,
    VerifierSignerUnavailable,
    authorize_result_submission,
)


COMPOSE_HASH = "0x" + "99" * 32
CONTRACT_ADDRESS = "0x" + "55" * 20
RESULT_HASH = "0x" + "66" * 32
QUOTE_HASH = "0x" + "88" * 32


class InjectedVerifierSigner:
    custody = "injected_verifier_test_signer"

    def __init__(self):
        self._account = Account.create("dnai-wikigen-result-verifier-test")
        self.address = self._account.address

    def sign_authorization_digest(self, digest: str) -> str:
        signed = self._account.sign_message(encode_defunct(hexstr=digest))
        return "0x" + bytes(signed.signature).hex()


def _attestation(*, signer_address: str, chain_id: int = 31337, compose_hash: str = COMPOSE_HASH):
    report_data = "0x" + signer_attestation_report_data(
        signer_address=signer_address,
        chain_id=chain_id,
        contract_address=CONTRACT_ADDRESS,
    ).hex()
    return SignerAttestationEvidence(
        mode="tdx",
        signer_address=signer_address,
        chain_id=chain_id,
        contract_address=CONTRACT_ADDRESS,
        report_data=report_data,
        quote_report_data=report_data,
        quote_hash=QUOTE_HASH,
        quote_size=5006,
        compose_hash=compose_hash,
        app_id="app-ok",
        os_image_hash="os-ok",
    )


def _policy(**overrides):
    values = {
        "allowed_compose_hashes": (COMPOSE_HASH,),
        "allowed_app_ids": ("app-ok",),
        "allowed_os_image_hashes": ("os-ok",),
        "authorization_ttl_seconds": 300,
    }
    values.update(overrides)
    return ResultVerifierPolicy(**values)


def _request(tee_identity: str):
    return ResultAuthorizationRequest(
        chain_id=31337,
        contract_address=CONTRACT_ADDRESS,
        deal_id=4,
        tee_identity=tee_identity,
        compose_hash=COMPOSE_HASH,
        score_band="high",
        compute_cost_wei=10**15,
        result_hash=RESULT_HASH,
    )


class ResultVerifierTest(unittest.TestCase):
    def test_authorizes_matching_attested_result_context(self):
        tee_account = Account.create("tee")
        verifier = InjectedVerifierSigner()
        authorization = authorize_result_submission(
            _request(tee_account.address),
            signer_attestation=_attestation(signer_address=tee_account.address),
            policy=_policy(),
            verifier_signer=verifier,
            now=1_800_000_000,
        )

        recovered = Account.recover_message(
            encode_defunct(hexstr=authorization.authorization_digest),
            signature=bytes.fromhex(authorization.verifier_signature[2:]),
        )
        body = authorization.to_public_dict()

        self.assertTrue(authorization.authorized)
        self.assertEqual(recovered.lower(), verifier.address.lower())
        self.assertEqual(authorization.authorization_expiry, 1_800_000_300)
        self.assertEqual(authorization.tee_identity.lower(), tee_account.address.lower())
        self.assertEqual(authorization.compose_hash, COMPOSE_HASH)
        self.assertEqual(authorization.score_band_value, 3)
        self.assertEqual(authorization.verifier_address.lower(), verifier.address.lower())
        self.assertEqual(authorization.verifier_custody, "injected_verifier_test_signer")
        self.assertEqual(authorization.signer_attestation_hash, QUOTE_HASH)
        self.assertEqual(authorization.signer_attestation_quote_size, 5006)
        self.assertRegex(authorization.policy_hash, r"^0x[0-9a-f]{64}$")
        self.assertFalse(authorization.raw_secret_egress)
        self.assertIn("verifier_signature", body)
        self.assertNotIn("private", str(body).lower())

    def test_rejects_unapproved_compose_or_app_identity(self):
        tee_account = Account.create("tee")
        verifier = InjectedVerifierSigner()

        with self.assertRaisesRegex(ResultVerifierError, "compose hash"):
            authorize_result_submission(
                _request(tee_account.address),
                signer_attestation=_attestation(signer_address=tee_account.address),
                policy=_policy(allowed_compose_hashes=("0x" + "77" * 32,)),
                verifier_signer=verifier,
                now=1,
            )

        with self.assertRaisesRegex(ResultVerifierError, "app ID"):
            authorize_result_submission(
                _request(tee_account.address),
                signer_attestation=_attestation(signer_address=tee_account.address),
                policy=_policy(allowed_app_ids=("app-other",)),
                verifier_signer=verifier,
                now=1,
            )

    def test_rejects_mismatched_quote_context(self):
        tee_account = Account.create("tee")
        verifier = InjectedVerifierSigner()

        with self.assertRaisesRegex(ResultVerifierError, "chain id mismatch"):
            authorize_result_submission(
                _request(tee_account.address),
                signer_attestation=_attestation(signer_address=tee_account.address, chain_id=84532),
                policy=_policy(),
                verifier_signer=verifier,
                now=1,
            )

    def test_rejects_revoked_quote_or_signer(self):
        tee_account = Account.create("tee")
        verifier = InjectedVerifierSigner()

        with self.assertRaisesRegex(ResultVerifierError, "quote hash is revoked"):
            authorize_result_submission(
                _request(tee_account.address),
                signer_attestation=_attestation(signer_address=tee_account.address),
                policy=_policy(revoked_quote_hashes=(QUOTE_HASH,)),
                verifier_signer=verifier,
                now=1,
            )

        with self.assertRaisesRegex(ResultVerifierError, "TEE signer is revoked"):
            authorize_result_submission(
                _request(tee_account.address),
                signer_attestation=_attestation(signer_address=tee_account.address),
                policy=_policy(revoked_signer_addresses=(tee_account.address,)),
                verifier_signer=verifier,
                now=1,
            )

    def test_rejects_self_approval_and_missing_policy(self):
        tee_account = Account.create("tee")

        class SameAddressVerifier(InjectedVerifierSigner):
            def __init__(self, address):
                self._account = Account.create("other-key")
                self.address = address

        with self.assertRaisesRegex(ResultVerifierError, "distinct"):
            authorize_result_submission(
                _request(tee_account.address),
                signer_attestation=_attestation(signer_address=tee_account.address),
                policy=_policy(),
                verifier_signer=SameAddressVerifier(tee_account.address),
                now=1,
            )

        with self.assertRaisesRegex(ResultVerifierError, "allowed compose hashes"):
            authorize_result_submission(
                _request(tee_account.address),
                signer_attestation=_attestation(signer_address=tee_account.address),
                policy=_policy(allowed_compose_hashes=()),
                verifier_signer=InjectedVerifierSigner(),
                now=1,
            )

    def test_dstack_verifier_signer_fails_closed_outside_dstack_mode(self):
        with patch("tinker_delegate.result_verifier.is_dstack_enabled", return_value=False):
            with self.assertRaisesRegex(VerifierSignerUnavailable, "dstack mode"):
                DstackResultVerifierSigner.from_settings(Settings())

    def test_cli_authorize_result_has_no_private_key_flag(self):
        project_dir = Path(__file__).resolve().parents[1]
        for command in ("authorize-result", "result-verifier-address"):
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tinker_delegate.main",
                    command,
                    "--help",
                ],
                check=True,
                cwd=project_dir,
                text=True,
                capture_output=True,
            )
            help_body = result.stdout.lower()
            self.assertIn(command, help_body)
            self.assertNotIn("private-key", help_body)
            self.assertNotIn("mnemonic", help_body)
            self.assertNotIn("seed", help_body)


if __name__ == "__main__":
    unittest.main()
