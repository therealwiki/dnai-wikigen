import subprocess
import sys
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from eth_account import Account
from eth_account.messages import encode_defunct

from tinker_delegate.chain_submitter import (
    DealRead,
    SignerAttestationEvidence,
    attestation_authorization_digest,
    canonical_public_result_hash,
    signer_attestation_report_data,
)
from tinker_delegate.config import Settings
from tinker_delegate.result_verifier import (
    DstackResultVerifierSigner,
    INDEPENDENT_ATTESTATION_VERDICT_SCHEMA,
    INDEPENDENT_ATTESTATION_VERIFICATION_METHOD,
    IndependentAttestationVerdict,
    ResultAuthorizationRequest,
    ResultVerifierError,
    ResultVerifierPolicy,
    VerifierSignerUnavailable,
    authorize_result_submission,
    independent_attestation_verdict_digest,
    independent_attestation_verdict_from_public_dict,
)


COMPOSE_HASH = "0x" + "99" * 32
CONTRACT_ADDRESS = "0x" + "55" * 20
QUOTE_HASH = "0x" + "88" * 32
QVL_POLICY_HASH = "0x" + "77" * 32
CHALLENGE_ID = "0x" + "66" * 32
CHALLENGE_DIGEST = "0x" + "44" * 32
CVM_ID = "cvm-main-runtime-0001"
DEPLOYMENT_INTENT_SHA256 = "sha256:" + "41" * 32
RELEASE_AUTHORITY_SHA256 = "sha256:" + "42" * 32
CEREMONY_NONCE = "0x" + "43" * 32
MEASUREMENT_POLICY_SHA256 = "sha256:" + "44" * 32
APP_ID = "45" * 20
OS_IMAGE_HASH = "46" * 32


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
        app_id=APP_ID,
        os_image_hash=OS_IMAGE_HASH,
    )


def _policy(**overrides):
    values = {
        "allowed_compose_hashes": (COMPOSE_HASH,),
        "allowed_app_ids": (APP_ID,),
        "allowed_os_image_hashes": (OS_IMAGE_HASH,),
        "authorization_ttl_seconds": 300,
        "attestation_release_policy_hash": QVL_POLICY_HASH,
        "attestation_domain": "main_runtime_cvm",
        "attestation_cvm_id": CVM_ID,
        "attestation_deployment_intent_sha256": DEPLOYMENT_INTENT_SHA256,
        "attestation_release_authority_sha256": RELEASE_AUTHORITY_SHA256,
        "attestation_ceremony_nonce": CEREMONY_NONCE,
        "attestation_measurement_policy_sha256": MEASUREMENT_POLICY_SHA256,
        "allow_unverified_local_attestation": True,
    }
    values.update(overrides)
    return ResultVerifierPolicy(**values)


def _request(tee_identity: str):
    deal = DealRead(
        seller="0x" + "11" * 20,
        buyer="0x" + "22" * 20,
        reserve_price=10**15,
        budget_cap=10**17,
        expiry=2_000_000_000,
        state=1,
        artifact_hash="0x" + "33" * 32,
        tee_identity=tee_identity,
        score_band=0,
        compute_cost=0,
        fee=0,
        result_hash="0x" + "00" * 32,
    )
    return ResultAuthorizationRequest(
        chain_id=31337,
        contract_address=CONTRACT_ADDRESS,
        deal_id=4,
        deal=deal,
        fee_bps=100,
        compute_settlement_policy_enabled=True,
        compose_hash=COMPOSE_HASH,
        score_band="high",
        compute_cost_wei=10**15,
    )


def _independent_verdict(
    *,
    tee_identity: str,
    verifier: Account,
    signing_account: Account | None = None,
    verified: bool = True,
    issued_at: int = 1_800_000_000,
    expires_at: int = 1_800_000_120,
    request: ResultAuthorizationRequest | None = None,
) -> IndependentAttestationVerdict:
    evidence = _attestation(signer_address=tee_identity)
    authorization_request = request or _request(tee_identity)
    result_hash = canonical_public_result_hash(
        chain_id=authorization_request.chain_id,
        contract_address=authorization_request.contract_address,
        deal_id=authorization_request.deal_id,
        deal=authorization_request.deal,
        compose_hash=authorization_request.compose_hash,
        score_band=authorization_request.score_band,
        compute_cost_wei=authorization_request.compute_cost_wei,
    )
    qvl_authorization_expiry = min(expires_at, issued_at + 90)
    qvl_authorization_digest = attestation_authorization_digest(
        chain_id=authorization_request.chain_id,
        contract_address=authorization_request.contract_address,
        deal_id=authorization_request.deal_id,
        deal=authorization_request.deal,
        compose_hash=authorization_request.compose_hash,
        score_band=authorization_request.score_band,
        compute_cost_wei=authorization_request.compute_cost_wei,
        attestation_release_policy_hash=QVL_POLICY_HASH,
        attestation_evidence_hash=evidence.quote_hash,
        authorization_expiry=qvl_authorization_expiry,
    )
    signer = signing_account or verifier
    qvl_authorization_signature = signer.sign_message(
        encode_defunct(hexstr=qvl_authorization_digest)
    ).signature
    unsigned = IndependentAttestationVerdict(
        schema=INDEPENDENT_ATTESTATION_VERDICT_SCHEMA,
        verification_method=INDEPENDENT_ATTESTATION_VERIFICATION_METHOD,
        verified=verified,
        chain_id=evidence.chain_id,
        domain="main_runtime_cvm",
        profile="diligence",
        cvm_id=CVM_ID,
        deployment_intent_sha256=DEPLOYMENT_INTENT_SHA256,
        release_authority_sha256=RELEASE_AUTHORITY_SHA256,
        ceremony_nonce=CEREMONY_NONCE,
        measurement_policy_sha256=MEASUREMENT_POLICY_SHA256,
        release_policy_hash=QVL_POLICY_HASH,
        challenge_id=CHALLENGE_ID,
        challenge_digest=CHALLENGE_DIGEST,
        challenge_issued_at=issued_at,
        challenge_expires_at=expires_at,
        quote_hash=evidence.quote_hash,
        report_data=evidence.report_data,
        compose_hash=evidence.compose_hash,
        app_id=evidence.app_id,
        os_image_hash=evidence.os_image_hash,
        signer_address=tee_identity,
        contract_address=evidence.contract_address,
        issued_at=issued_at,
        activation_evidence_lease_expires_at=expires_at,
        expires_at=expires_at,
        verifier_address=verifier.address,
        verifier_signature="0x" + "00" * 65,
        qvl_deal_id=authorization_request.deal_id,
        qvl_evaluator_policy_commitment=(
            authorization_request.deal.evaluator_policy_commitment
        ),
        qvl_result_hash=result_hash,
        qvl_attestation_evidence_hash=evidence.quote_hash,
        qvl_authorization_expiry=qvl_authorization_expiry,
        qvl_authorization_digest=qvl_authorization_digest,
        qvl_authorization_signature="0x" + qvl_authorization_signature.hex(),
    )
    signature = signer.sign_message(
        encode_defunct(hexstr=independent_attestation_verdict_digest(unsigned))
    ).signature
    return replace(unsigned, verifier_signature="0x" + signature.hex())


def _resign_independent_verdict(
    verdict: IndependentAttestationVerdict,
    signer: Account,
    **changes,
) -> IndependentAttestationVerdict:
    unsigned = replace(
        verdict,
        **changes,
        verifier_signature="0x" + "00" * 65,
    )
    signature = signer.sign_message(
        encode_defunct(hexstr=independent_attestation_verdict_digest(unsigned))
    ).signature
    return replace(unsigned, verifier_signature="0x" + bytes(signature).hex())


class ResultVerifierTest(unittest.TestCase):
    def test_authorizes_matching_attested_result_context(self):
        tee_account = Account.create("tee")
        verifier = InjectedVerifierSigner()
        qvl_verifier = Account.create("qvl-verifier")
        verdict = _independent_verdict(
            tee_identity=tee_account.address,
            verifier=qvl_verifier,
        )
        authorization = authorize_result_submission(
            _request(tee_account.address),
            signer_attestation=_attestation(signer_address=tee_account.address),
            policy=_policy(
                trusted_attestation_verifier_addresses=(qvl_verifier.address,),
            ),
            verifier_signer=verifier,
            independent_verdict=verdict,
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
        self.assertEqual(
            authorization.result_hash,
            canonical_public_result_hash(
                chain_id=31337,
                contract_address=CONTRACT_ADDRESS,
                deal_id=4,
                deal=_request(tee_account.address).deal,
                compose_hash=COMPOSE_HASH,
                score_band="high",
                compute_cost_wei=10**15,
            ),
        )
        self.assertRegex(authorization.policy_hash, r"^0x[0-9a-f]{64}$")
        self.assertFalse(authorization.raw_secret_egress)
        self.assertIn("verifier_signature", body)
        self.assertNotIn("private", str(body).lower())

    def test_rejects_non_policy_compute_and_has_no_caller_result_hash_field(self):
        tee_account = Account.create("tee")
        request = _request(tee_account.address)
        self.assertFalse(hasattr(request, "result_hash"))
        with self.assertRaisesRegex(ResultVerifierError, "deterministic"):
            authorize_result_submission(
                replace(request, compute_cost_wei=request.compute_cost_wei + 1),
                signer_attestation=_attestation(signer_address=tee_account.address),
                policy=_policy(),
                verifier_signer=InjectedVerifierSigner(),
                now=1,
            )

    def test_rejects_contract_without_compute_policy_gate(self):
        tee_account = Account.create("tee")
        request = replace(
            _request(tee_account.address),
            compute_settlement_policy_enabled=False,
        )

        with self.assertRaisesRegex(ResultVerifierError, "not enabled"):
            authorize_result_submission(
                request,
                signer_attestation=_attestation(signer_address=tee_account.address),
                policy=_policy(),
                verifier_signer=InjectedVerifierSigner(),
                now=1,
            )

    def test_production_authorization_requires_fresh_authenticated_qvl_verdict(self):
        tee_account = Account.create("tee")
        result_verifier = InjectedVerifierSigner()
        qvl_verifier = Account.create("qvl-verifier")
        verdict = _independent_verdict(
            tee_identity=tee_account.address,
            verifier=qvl_verifier,
        )

        authorization = authorize_result_submission(
            _request(tee_account.address),
            signer_attestation=_attestation(signer_address=tee_account.address),
            policy=_policy(
                allow_unverified_local_attestation=False,
                trusted_attestation_verifier_addresses=(qvl_verifier.address,),
            ),
            verifier_signer=result_verifier,
            independent_verdict=verdict,
            now=1_800_000_030,
        )

        self.assertTrue(authorization.attestation_verdict_authenticated)
        self.assertEqual(
            authorization.attestation_verification_method,
            INDEPENDENT_ATTESTATION_VERIFICATION_METHOD,
        )
        self.assertEqual(
            authorization.attestation_verifier_address.lower(),
            qvl_verifier.address.lower(),
        )
        self.assertEqual(
            authorization.attestation_verdict_hash,
            independent_attestation_verdict_digest(verdict),
        )

    def test_rejects_verdict_issued_exactly_at_challenge_expiry(self):
        tee_account = Account.create("tee")
        result_verifier = InjectedVerifierSigner()
        qvl_verifier = Account.create("qvl-verifier")
        verdict = _independent_verdict(
            tee_identity=tee_account.address,
            verifier=qvl_verifier,
        )
        verdict = _resign_independent_verdict(
            verdict,
            qvl_verifier,
            challenge_expires_at=verdict.issued_at,
        )

        with self.assertRaisesRegex(ResultVerifierError, "challenge lifetime"):
            authorize_result_submission(
                _request(tee_account.address),
                signer_attestation=_attestation(
                    signer_address=tee_account.address
                ),
                policy=_policy(
                    allow_unverified_local_attestation=False,
                    trusted_attestation_verifier_addresses=(
                        qvl_verifier.address,
                    ),
                ),
                verifier_signer=result_verifier,
                independent_verdict=verdict,
                now=verdict.issued_at,
            )

    def test_production_rejects_missing_or_false_independent_verdict(self):
        tee_account = Account.create("tee")
        result_verifier = InjectedVerifierSigner()
        qvl_verifier = Account.create("qvl-verifier")
        policy = _policy(
            allow_unverified_local_attestation=False,
            trusted_attestation_verifier_addresses=(qvl_verifier.address,),
        )
        evidence = _attestation(signer_address=tee_account.address)

        with self.assertRaisesRegex(ResultVerifierError, "independent.*required"):
            authorize_result_submission(
                _request(tee_account.address),
                signer_attestation=evidence,
                policy=policy,
                verifier_signer=result_verifier,
                now=1_800_000_030,
            )

        false_verdict = _independent_verdict(
            tee_identity=tee_account.address,
            verifier=qvl_verifier,
            verified=False,
        )
        with self.assertRaisesRegex(ResultVerifierError, "not verified"):
            authorize_result_submission(
                _request(tee_account.address),
                signer_attestation=evidence,
                policy=policy,
                verifier_signer=result_verifier,
                independent_verdict=false_verdict,
                now=1_800_000_030,
            )

    def test_rejects_self_asserted_or_forged_attestation_verdict(self):
        tee_account = Account.create("tee")
        result_verifier = InjectedVerifierSigner()
        attacker = Account.create("attacker")
        evidence = _attestation(signer_address=tee_account.address)

        self_asserted = _independent_verdict(
            tee_identity=tee_account.address,
            verifier=tee_account,
        )
        with self.assertRaisesRegex(ResultVerifierError, "independent from"):
            authorize_result_submission(
                _request(tee_account.address),
                signer_attestation=evidence,
                policy=_policy(
                    allow_unverified_local_attestation=False,
                    trusted_attestation_verifier_addresses=(tee_account.address,),
                ),
                verifier_signer=result_verifier,
                independent_verdict=self_asserted,
                now=1_800_000_030,
            )

        trusted = Account.create("trusted-qvl")
        forged = _independent_verdict(
            tee_identity=tee_account.address,
            verifier=trusted,
            signing_account=attacker,
        )
        with self.assertRaisesRegex(ResultVerifierError, "not authenticated"):
            authorize_result_submission(
                _request(tee_account.address),
                signer_attestation=evidence,
                policy=_policy(
                    allow_unverified_local_attestation=False,
                    trusted_attestation_verifier_addresses=(trusted.address,),
                ),
                verifier_signer=result_verifier,
                independent_verdict=forged,
                now=1_800_000_030,
            )

    def test_independent_verdict_parser_is_exact_and_rejects_downgrade_fields(self):
        tee_account = Account.create("tee")
        qvl_verifier = Account.create("qvl-verifier")
        verdict = _independent_verdict(
            tee_identity=tee_account.address,
            verifier=qvl_verifier,
        )
        payload = verdict.to_public_dict()
        parsed = independent_attestation_verdict_from_public_dict(payload)
        self.assertEqual(parsed.to_public_dict(), payload)
        self.assertEqual(
            independent_attestation_verdict_digest(parsed),
            independent_attestation_verdict_digest(verdict),
        )
        payload["service_verified"] = True
        with self.assertRaisesRegex(ResultVerifierError, "unexpected fields"):
            independent_attestation_verdict_from_public_dict(payload)

    def test_independent_verdict_parser_requires_canonical_phala_identity_hashes(self):
        tee_account = Account.create("tee")
        qvl_verifier = Account.create("qvl-verifier")
        verdict = _independent_verdict(
            tee_identity=tee_account.address,
            verifier=qvl_verifier,
        )
        for field, value, message in (
            ("app_id", "0x" + APP_ID, "Phala app ID"),
            ("app_id", "0" * 40, "Phala app ID"),
            ("os_image_hash", "0x" + OS_IMAGE_HASH, "OS image hash"),
            ("os_image_hash", "0" * 64, "OS image hash"),
        ):
            with self.subTest(field=field, value=value):
                payload = verdict.to_public_dict()
                payload[field] = value
                with self.assertRaisesRegex(ResultVerifierError, message):
                    independent_attestation_verdict_from_public_dict(payload)

    def test_independent_verdict_rejects_every_cross_lineage_mutation(self):
        tee_account = Account.create("tee")
        result_verifier = InjectedVerifierSigner()
        qvl_verifier = Account.create("qvl-verifier")
        evidence = _attestation(signer_address=tee_account.address)
        verdict = _independent_verdict(
            tee_identity=tee_account.address,
            verifier=qvl_verifier,
        )
        policy = _policy(
            allow_unverified_local_attestation=False,
            trusted_attestation_verifier_addresses=(qvl_verifier.address,),
        )
        mutations = {
            "chain_id": 84_532,
            "domain": "independent_metering_cvm",
            "profile": "arena",
            "cvm_id": "cvm-cross-domain-0001",
            "deployment_intent_sha256": "sha256:" + "51" * 32,
            "release_authority_sha256": "sha256:" + "52" * 32,
            "ceremony_nonce": "0x" + "53" * 32,
            "measurement_policy_sha256": "sha256:" + "54" * 32,
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                with self.assertRaisesRegex(ResultVerifierError, "context mismatch"):
                    authorize_result_submission(
                        _request(tee_account.address),
                        signer_attestation=evidence,
                        policy=policy,
                        verifier_signer=result_verifier,
                        independent_verdict=replace(verdict, **{field: value}),
                        now=1_800_000_030,
                    )

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
