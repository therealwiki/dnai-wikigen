import json
import subprocess
import sys
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path

from eth_account import Account
from eth_account.messages import encode_defunct
from eth_hash.auto import keccak

from tinker_delegate.chain_submitter import signer_attestation_report_data
from tinker_delegate.governance_plan import (
    DILIGENCE_ADMISSION_TIMELOCK_SECONDS,
    PROPOSE_COMPOSE_HASH_SELECTOR,
    PROPOSE_TEE_IDENTITY_SELECTOR,
    build_governance_plan_from_authorization,
    build_governance_plan_from_public_dict,
    build_governance_plan_from_verdict,
    governance_expectation_hash,
)
from tinker_delegate.result_verifier import (
    INDEPENDENT_ATTESTATION_VERDICT_SCHEMA,
    INDEPENDENT_ATTESTATION_VERIFICATION_METHOD,
    IndependentAttestationExpectation,
    IndependentAttestationVerdict,
    ResultVerifierError,
    independent_attestation_verdict_digest,
)


CONTRACT = "0x" + "55" * 20
TEE = "0x90F79bf6EB2c4f870365E785982E1f101E93b906"
COMPOSE = "0x" + "e5" * 32
QUOTE_HASH = "0x" + "66" * 32
APP_ID = "45" * 20
OS_IMAGE_HASH = "46" * 32
CHAIN_ID = 84532
NOW = 1_800_000_030
QVL_RELEASE_POLICY_HASH = "0x" + "77" * 32
CHALLENGE_ID = "0x" + "88" * 32
CHALLENGE_DIGEST = "0x" + "99" * 32
CHALLENGE_ISSUED_AT = 1_800_000_000
CHALLENGE_EXPIRES_AT = 1_800_000_120
CVM_ID = "cvm-main-runtime-0001"
DEPLOYMENT_INTENT_SHA256 = "sha256:" + "41" * 32
RELEASE_AUTHORITY_SHA256 = "sha256:" + "42" * 32
CEREMONY_NONCE = "0x" + "43" * 32
MEASUREMENT_POLICY_SHA256 = "sha256:" + "44" * 32


def _report_data(
    *,
    tee_identity: str = TEE,
    chain_id: int = CHAIN_ID,
    contract_address: str = CONTRACT,
) -> str:
    return "0x" + signer_attestation_report_data(
        signer_address=tee_identity,
        chain_id=chain_id,
        contract_address=contract_address,
    ).hex()


def _expectation(qvl_address: str, **overrides) -> IndependentAttestationExpectation:
    values = {
        "trusted_verifier_addresses": (qvl_address,),
        "chain_id": CHAIN_ID,
        "domain": "main_runtime_cvm",
        "profile": "diligence",
        "cvm_id": CVM_ID,
        "deployment_intent_sha256": DEPLOYMENT_INTENT_SHA256,
        "release_authority_sha256": RELEASE_AUTHORITY_SHA256,
        "ceremony_nonce": CEREMONY_NONCE,
        "measurement_policy_sha256": MEASUREMENT_POLICY_SHA256,
        "release_policy_hash": QVL_RELEASE_POLICY_HASH,
        "challenge_id": CHALLENGE_ID,
        "challenge_digest": CHALLENGE_DIGEST,
        "challenge_issued_at": CHALLENGE_ISSUED_AT,
        "challenge_expires_at": CHALLENGE_EXPIRES_AT,
        "quote_hash": QUOTE_HASH,
        "report_data": _report_data(),
        "compose_hash": COMPOSE,
        "app_id": APP_ID,
        "os_image_hash": OS_IMAGE_HASH,
        "signer_address": TEE,
        "contract_address": CONTRACT,
        "max_age_seconds": 300,
    }
    values.update(overrides)
    if any(
        key in overrides
        for key in ("signer_address", "chain_id", "contract_address")
    ) and "report_data" not in overrides:
        values["report_data"] = _report_data(
            tee_identity=values["signer_address"],
            chain_id=values["chain_id"],
            contract_address=values["contract_address"],
        )
    return IndependentAttestationExpectation(**values)


def _verdict(
    qvl_account,
    *,
    signing_account=None,
    issued_at: int = 1_800_000_000,
    expires_at: int = 1_800_000_120,
    **overrides,
) -> IndependentAttestationVerdict:
    values = {
        "schema": INDEPENDENT_ATTESTATION_VERDICT_SCHEMA,
        "verification_method": INDEPENDENT_ATTESTATION_VERIFICATION_METHOD,
        "verified": True,
        "chain_id": CHAIN_ID,
        "domain": "main_runtime_cvm",
        "profile": "diligence",
        "cvm_id": CVM_ID,
        "deployment_intent_sha256": DEPLOYMENT_INTENT_SHA256,
        "release_authority_sha256": RELEASE_AUTHORITY_SHA256,
        "ceremony_nonce": CEREMONY_NONCE,
        "measurement_policy_sha256": MEASUREMENT_POLICY_SHA256,
        "release_policy_hash": QVL_RELEASE_POLICY_HASH,
        "challenge_id": CHALLENGE_ID,
        "challenge_digest": CHALLENGE_DIGEST,
        "challenge_issued_at": issued_at,
        "challenge_expires_at": expires_at,
        "quote_hash": QUOTE_HASH,
        "report_data": _report_data(),
        "compose_hash": COMPOSE,
        "app_id": APP_ID,
        "os_image_hash": OS_IMAGE_HASH,
        "signer_address": TEE,
        "contract_address": CONTRACT,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "verifier_address": qvl_account.address,
        "verifier_signature": "0x" + "00" * 65,
    }
    values.update(overrides)
    values.setdefault("activation_evidence_lease_expires_at", values["expires_at"])
    unsigned = IndependentAttestationVerdict(**values)
    digest = independent_attestation_verdict_digest(unsigned)
    signer = signing_account or qvl_account
    signature = signer.sign_message(encode_defunct(hexstr=digest)).signature
    return replace(unsigned, verifier_signature="0x" + bytes(signature).hex())


class GovernancePlanTest(unittest.TestCase):
    def setUp(self) -> None:
        self.qvl = Account.create("governance-qvl")
        self.expectation = _expectation(self.qvl.address)
        self.verdict = _verdict(self.qvl)

    def test_plan_requires_and_records_authenticated_full_verdict(self):
        plan = build_governance_plan_from_verdict(
            self.verdict,
            expectation=self.expectation,
            now=NOW,
        )

        self.assertEqual(
            [call.function for call in plan.calls],
            [
                "proposeComposeHash",
                "activateComposeHash",
                "proposeTeeIdentity",
                "activateTeeIdentity",
                "freezeComposeAdditions",
                "freezeTeeIdentityAdditions",
            ],
        )
        self.assertEqual([call.phase for call in plan.calls], [1, 2, 2, 3, 3, 3])
        self.assertEqual(
            plan.admission_timelock_seconds,
            DILIGENCE_ADMISSION_TIMELOCK_SECONDS,
        )
        self.assertEqual(plan.chain_id, CHAIN_ID)
        self.assertEqual(plan.contract_address.lower(), CONTRACT.lower())
        self.assertEqual(plan.tee_identity.lower(), TEE.lower())
        self.assertEqual(plan.compose_hash, COMPOSE)
        self.assertEqual(plan.app_id, APP_ID)
        self.assertEqual(plan.os_image_hash, OS_IMAGE_HASH)
        self.assertEqual(plan.quote_hash, QUOTE_HASH)
        self.assertEqual(plan.report_data, _report_data())
        self.assertEqual(
            plan.attestation_verifier_address.lower(), self.qvl.address.lower()
        )
        self.assertEqual(
            plan.attestation_verdict_digest,
            independent_attestation_verdict_digest(self.verdict),
        )
        self.assertEqual(plan.policy_hash, governance_expectation_hash(self.expectation))
        self.assertTrue(plan.attestation_verdict_authenticated)
        self.assertTrue(plan.requires_developer_broadcast)
        self.assertFalse(plan.raw_secret_egress)

    def test_calldata_matches_selectors_and_external_pins(self):
        plan = build_governance_plan_from_verdict(
            self.verdict,
            expectation=self.expectation,
            now=NOW,
        )
        compose_call = plan.calls[0]
        identity_call = plan.calls[2]

        expected_compose = "0x" + (
            PROPOSE_COMPOSE_HASH_SELECTOR + bytes.fromhex("e5" * 32)
        ).hex()
        self.assertEqual(compose_call.calldata, expected_compose)
        self.assertTrue(
            compose_call.calldata.startswith(
                "0x" + keccak(b"proposeComposeHash(bytes32)")[:4].hex()
            )
        )
        tee_word = bytes(12) + bytes.fromhex(TEE[2:])
        expected_identity = "0x" + (
            PROPOSE_TEE_IDENTITY_SELECTOR
            + tee_word
            + bytes.fromhex("e5" * 32)
        ).hex()
        self.assertEqual(identity_call.calldata, expected_identity)

    def test_output_is_bounded_and_omits_signed_evidence(self):
        plan = build_governance_plan_from_verdict(
            self.verdict,
            expectation=self.expectation,
            now=NOW,
        )
        body = plan.to_public_dict()
        blob = json.dumps(body)

        self.assertIn("--account dev", blob)
        self.assertNotIn("--private-key", blob)
        self.assertNotIn("--unlocked", blob)
        self.assertNotIn("verifier_signature", blob)
        self.assertNotIn(self.verdict.verifier_signature[2:], blob)
        self.assertFalse(body["raw_secret_egress"])

    def test_legacy_trusted_boolean_paths_never_emit_calldata(self):
        forged = {
            "authorized": True,
            "attestation_verdict_authenticated": True,
            "contract_address": CONTRACT,
            "tee_identity": TEE,
            "compose_hash": COMPOSE,
        }
        with self.assertRaisesRegex(ResultVerifierError, "not governance evidence"):
            build_governance_plan_from_public_dict(forged)
        with self.assertRaisesRegex(ResultVerifierError, "not governance evidence"):
            build_governance_plan_from_authorization(forged)

    def test_all_exact_release_and_cvm_bindings_are_enforced(self):
        mismatches = {
            "quote_hash": "0x" + "77" * 32,
            "compose_hash": "0x" + "88" * 32,
            "app_id": "47" * 20,
            "os_image_hash": "48" * 32,
            "signer_address": "0x" + "91" * 20,
            "chain_id": 1,
            "contract_address": "0x" + "92" * 20,
        }
        for field, value in mismatches.items():
            with self.subTest(field=field):
                expectation = _expectation(self.qvl.address, **{field: value})
                with self.assertRaisesRegex(ResultVerifierError, "context mismatch"):
                    build_governance_plan_from_verdict(
                        self.verdict,
                        expectation=expectation,
                        now=NOW,
                    )

    def test_report_data_pin_must_be_canonical_for_signer_chain_contract(self):
        expectation = _expectation(
            self.qvl.address,
            report_data="0x" + "99" * 32,
        )

        with self.assertRaisesRegex(ResultVerifierError, "canonical"):
            build_governance_plan_from_verdict(
                self.verdict,
                expectation=expectation,
                now=NOW,
            )

    def test_verdict_cannot_self_declare_its_trust_root(self):
        attacker = Account.create("attacker-qvl")
        attacker_verdict = _verdict(attacker)

        with self.assertRaisesRegex(ResultVerifierError, "not trusted"):
            build_governance_plan_from_verdict(
                attacker_verdict,
                expectation=self.expectation,
                now=NOW,
            )

    def test_forged_signature_is_rejected(self):
        attacker = Account.create("signature-attacker")
        forged = _verdict(self.qvl, signing_account=attacker)

        with self.assertRaisesRegex(ResultVerifierError, "not authenticated"):
            build_governance_plan_from_verdict(
                forged,
                expectation=self.expectation,
                now=NOW,
            )

    def test_expired_future_stale_and_overlong_verdicts_are_rejected(self):
        cases = (
            ("expired", _verdict(self.qvl, issued_at=NOW - 60, expires_at=NOW)),
            ("future-dated", _verdict(self.qvl, issued_at=NOW + 31, expires_at=NOW + 60)),
            ("lifetime exceeds", _verdict(self.qvl, issued_at=NOW, expires_at=NOW + 301)),
            (
                "stale",
                _verdict(self.qvl, issued_at=NOW - 301, expires_at=NOW + 1),
            ),
        )
        for message, verdict in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ResultVerifierError, message):
                    build_governance_plan_from_verdict(
                        verdict,
                        expectation=self.expectation,
                        now=NOW,
                    )

    def test_missing_external_release_pins_fail_closed(self):
        for field in ("app_id", "os_image_hash"):
            with self.subTest(field=field):
                expectation = _expectation(self.qvl.address, **{field: ""})
                with self.assertRaises(ResultVerifierError):
                    build_governance_plan_from_verdict(
                        self.verdict,
                        expectation=expectation,
                        now=NOW,
                    )
        with self.assertRaisesRegex(ResultVerifierError, "trusted"):
            build_governance_plan_from_verdict(
                self.verdict,
                expectation=_expectation(
                    self.qvl.address,
                    trusted_verifier_addresses=(),
                ),
                now=NOW,
            )


class GovernancePlanCliTest(unittest.TestCase):
    def _command(
        self,
        verdict_path: Path,
        qvl_address: str,
        verdict: IndependentAttestationVerdict | None = None,
    ) -> list[str]:
        challenge = verdict or _verdict(Account.create("cli-command-challenge"))
        return [
            sys.executable,
            "-m",
            "tinker_delegate.main",
            "governance-approval-plan",
            str(verdict_path),
            "--trusted-attestation-verifier-address",
            qvl_address,
            "--expected-chain-id",
            str(CHAIN_ID),
            "--expected-contract-address",
            CONTRACT,
            "--expected-tee-identity",
            TEE,
            "--expected-cvm-domain",
            "main_runtime_cvm",
            "--expected-cvm-id",
            CVM_ID,
            "--expected-deployment-intent-sha256",
            DEPLOYMENT_INTENT_SHA256,
            "--expected-release-authority-sha256",
            RELEASE_AUTHORITY_SHA256,
            "--expected-ceremony-nonce",
            CEREMONY_NONCE,
            "--expected-measurement-policy-sha256",
            MEASUREMENT_POLICY_SHA256,
            "--expected-compose-hash",
            COMPOSE,
            "--expected-app-id",
            APP_ID,
            "--expected-os-image-hash",
            OS_IMAGE_HASH,
            "--expected-quote-hash",
            QUOTE_HASH,
            "--expected-attestation-release-policy-hash",
            QVL_RELEASE_POLICY_HASH,
            "--expected-attestation-challenge-id",
            challenge.challenge_id,
            "--expected-attestation-challenge-digest",
            challenge.challenge_digest,
            "--expected-attestation-challenge-issued-at",
            str(challenge.challenge_issued_at),
            "--expected-attestation-challenge-expires-at",
            str(challenge.challenge_expires_at),
        ]

    def test_cli_authenticates_verdict_before_emitting_plan(self):
        qvl = Account.create("cli-qvl")
        now = int(time.time())
        verdict = _verdict(qvl, issued_at=now - 1, expires_at=now + 119)
        with tempfile.TemporaryDirectory() as tmp:
            verdict_path = Path(tmp) / "verdict.json"
            output_path = Path(tmp) / "plan.json"
            verdict_path.write_text(
                json.dumps(verdict.to_public_dict()),
                encoding="utf-8",
            )
            command = self._command(verdict_path, qvl.address, verdict) + [
                "--output",
                str(output_path),
            ]
            result = subprocess.run(
                command,
                cwd=Path(__file__).resolve().parents[1],
                check=False,
                text=True,
                capture_output=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            plan = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertTrue(plan["attestation_verdict_authenticated"])
            self.assertEqual(
                [call["function"] for call in plan["calls"]],
                [
                    "proposeComposeHash",
                    "activateComposeHash",
                    "proposeTeeIdentity",
                    "activateTeeIdentity",
                    "freezeComposeAdditions",
                    "freezeTeeIdentityAdditions",
                ],
            )
            self.assertEqual(plan["admission_timelock_seconds"], 172800)
            self.assertNotIn("verifier_signature", json.dumps(plan))

    def test_cli_rejects_forged_boolean_summary_without_emitting_plan(self):
        qvl = Account.create("cli-qvl")
        forged = {
            "authorized": True,
            "attestation_verdict_authenticated": True,
            "contract_address": CONTRACT,
            "tee_identity": TEE,
            "compose_hash": COMPOSE,
            "trusted_attestation_verifier_addresses": [qvl.address],
        }
        with tempfile.TemporaryDirectory() as tmp:
            verdict_path = Path(tmp) / "forged.json"
            output_path = Path(tmp) / "plan.json"
            verdict_path.write_text(json.dumps(forged), encoding="utf-8")
            result = subprocess.run(
                self._command(verdict_path, qvl.address)
                + ["--output", str(output_path)],
                cwd=Path(__file__).resolve().parents[1],
                check=False,
                text=True,
                capture_output=True,
            )

            self.assertEqual(result.returncode, 1)
            self.assertFalse(output_path.exists())
            self.assertNotIn("cast send", result.stdout)

    def test_cli_requires_external_trusted_verifier_argument(self):
        qvl = Account.create("cli-qvl")
        now = int(time.time())
        verdict = _verdict(qvl, issued_at=now - 1, expires_at=now + 119)
        with tempfile.TemporaryDirectory() as tmp:
            verdict_path = Path(tmp) / "verdict.json"
            verdict_path.write_text(
                json.dumps(verdict.to_public_dict()),
                encoding="utf-8",
            )
            command = self._command(verdict_path, qvl.address, verdict)
            index = command.index("--trusted-attestation-verifier-address")
            del command[index : index + 2]
            result = subprocess.run(
                command,
                cwd=Path(__file__).resolve().parents[1],
                check=False,
                text=True,
                capture_output=True,
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("trusted-attestation-verifier-address", result.stderr)


if __name__ == "__main__":
    unittest.main()
