"""Bounded dstack writer-evidence command tests."""

from __future__ import annotations

import io
import json
import unittest
from contextlib import contextmanager
from dataclasses import replace
from unittest.mock import patch

from eth_account import Account
from eth_account.messages import encode_defunct
import httpx

from tinker_delegate.config import Settings
from tinker_delegate.execution_policy_anchor_cli import (
    EVIDENCE_SCHEMA,
    WRITER_KEY_PATH,
    AnchorWriterEvidenceError,
    HttpsAnchorWriterQvlClient,
    collect_anchor_writer_attestation,
    collect_anchor_writer_evidence,
    main,
)
from tinker_delegate.result_verifier import (
    INDEPENDENT_ATTESTATION_VERDICT_SCHEMA,
    INDEPENDENT_ATTESTATION_VERIFICATION_METHOD,
    IndependentAttestationVerdict,
    independent_attestation_verdict_digest,
)
from tinker_delegate.qvl_freshness import (
    CHALLENGE_SCHEMA,
    QvlChallenge,
    qvl_challenge_digest,
)


ANCHOR = "0x" + "11" * 20
RELEASE = "0x" + "22" * 32
COMPOSE = "0x" + "33" * 32
OS_IMAGE = "44" * 32
KEY_MATERIAL = b"private-test-key-material-which-must-not-egress"
NOW = 1_800_000_000
QVL_POLICY = "0x" + "55" * 32
QVL_ACCOUNT = Account.from_key(bytes.fromhex("66" * 32))
QVL_ADDRESS = QVL_ACCOUNT.address.lower()
CVM_ID = "cvm-main-runtime-0001"
DEPLOYMENT_INTENT_SHA256 = "sha256:" + "41" * 32
RELEASE_AUTHORITY_SHA256 = "sha256:" + "42" * 32
CEREMONY_NONCE = "0x" + "43" * 32
MEASUREMENT_POLICY_SHA256 = "sha256:" + "44" * 32
QVL_CLIENT_LINEAGE = {
    "chain_id": 84_532,
    "cvm_id": CVM_ID,
    "deployment_intent_sha256": DEPLOYMENT_INTENT_SHA256,
    "release_authority_sha256": RELEASE_AUTHORITY_SHA256,
    "ceremony_nonce": CEREMONY_NONCE,
    "measurement_policy_sha256": MEASUREMENT_POLICY_SHA256,
}


def _signed_challenge(signer=QVL_ACCOUNT) -> QvlChallenge:
    unsigned = QvlChallenge(
        schema=CHALLENGE_SCHEMA,
        chain_id=84_532,
        domain="main_runtime_cvm",
        profile="execution_policy_anchor_writer",
        cvm_id=CVM_ID,
        deployment_intent_sha256=DEPLOYMENT_INTENT_SHA256,
        release_authority_sha256=RELEASE_AUTHORITY_SHA256,
        ceremony_nonce=CEREMONY_NONCE,
        measurement_policy_sha256=MEASUREMENT_POLICY_SHA256,
        release_policy_hash=QVL_POLICY,
        challenge_id="0x" + "77" * 32,
        challenge_digest="0x" + "01" * 32,
        issued_at=NOW,
        expires_at=NOW + 120,
        verifier_address=signer.address.lower(),
        verifier_signature="0x" + "00" * 65,
    )
    digest = qvl_challenge_digest(unsigned)
    signed = signer.sign_message(encode_defunct(hexstr=digest))
    return replace(
        unsigned,
        challenge_digest=digest,
        verifier_signature="0x" + bytes(signed.signature).hex(),
    )


def _settings(**overrides) -> Settings:
    values = {
        "execution_policy_anchor_address": ANCHOR,
        "execution_policy_anchor_writer_release_commitment": RELEASE,
        "execution_policy_anchor_writer_key_path": WRITER_KEY_PATH,
        "execution_policy_anchor_writer_qvl_url": "https://anchor-qvl.example.test/verify",
        "execution_policy_anchor_writer_qvl_verifier_address": QVL_ADDRESS,
        "execution_policy_anchor_writer_qvl_release_policy_hash": QVL_POLICY,
        "execution_policy_anchor_writer_qvl_max_verdict_age_seconds": 300,
        "main_runtime_cvm_id": CVM_ID,
        "release_deployment_intent_sha256": DEPLOYMENT_INTENT_SHA256,
        "release_authority_sha256": RELEASE_AUTHORITY_SHA256,
        "release_ceremony_nonce": CEREMONY_NONCE,
        "anchor_writer_qvl_measurement_policy_sha256": MEASUREMENT_POLICY_SHA256,
    }
    values.update(overrides)
    return Settings(**values)


def _details(report_data: bytes):
    return {
        "quote": "0x" + "ab" * 1024,
        "quote_report_data": "0x" + report_data.hex(),
        "app_id": "45" * 20,
        "compose_hash": COMPOSE,
        "os_image_hash": OS_IMAGE,
    }


class _FakeQvl:
    def __init__(self, *, signer=QVL_ACCOUNT, mutate=None):
        self.signer = signer
        self.mutate = mutate
        self.challenge = _signed_challenge()
        self.packets = []
        self.closed = False

    def issue_challenge(self):
        return self.challenge

    def verify(self, packet, challenge):
        self.packets.append(packet)
        evidence = packet.evidence
        verdict = IndependentAttestationVerdict(
            schema=INDEPENDENT_ATTESTATION_VERDICT_SCHEMA,
            verification_method=INDEPENDENT_ATTESTATION_VERIFICATION_METHOD,
            verified=True,
            chain_id=challenge.chain_id,
            domain=challenge.domain,
            profile=challenge.profile,
            cvm_id=challenge.cvm_id,
            deployment_intent_sha256=challenge.deployment_intent_sha256,
            release_authority_sha256=challenge.release_authority_sha256,
            ceremony_nonce=challenge.ceremony_nonce,
            measurement_policy_sha256=challenge.measurement_policy_sha256,
            release_policy_hash=challenge.release_policy_hash,
            challenge_id=challenge.challenge_id,
            challenge_digest=challenge.challenge_digest,
            challenge_issued_at=challenge.issued_at,
            challenge_expires_at=challenge.expires_at,
            quote_hash=evidence.quote_sha256,
            report_data=evidence.report_data,
            compose_hash=evidence.compose_hash,
            app_id=evidence.app_id,
            os_image_hash=evidence.os_image_hash,
            signer_address=evidence.writer_address,
            contract_address=evidence.anchor_address,
            issued_at=NOW,
            activation_evidence_lease_expires_at=NOW + 120,
            expires_at=NOW + 120,
            verifier_address=self.signer.address.lower(),
            verifier_signature="0x" + "00" * 65,
        )
        if self.mutate is not None:
            verdict = self.mutate(verdict)
        digest = independent_attestation_verdict_digest(verdict)
        signed = self.signer.sign_message(encode_defunct(hexstr=digest))
        return replace(
            verdict,
            verifier_signature="0x" + bytes(signed.signature).hex(),
        )

    def close(self):
        self.closed = True


@contextmanager
def _dstack_context():
    with (
        patch(
            "tinker_delegate.execution_policy_anchor_cli.dstack_utils.is_dstack_enabled",
            return_value=True,
        ),
        patch(
            "tinker_delegate.execution_policy_anchor_cli.dstack_utils.is_dstack_simulator",
            return_value=False,
        ),
        patch(
            "tinker_delegate.execution_policy_anchor.dstack_utils.is_dstack_enabled",
            return_value=True,
        ),
        patch(
            "tinker_delegate.execution_policy_anchor.dstack_utils.is_dstack_simulator",
            return_value=False,
        ),
        patch(
            "tinker_delegate.execution_policy_anchor.dstack_utils.derive_storage_key",
            return_value=KEY_MATERIAL,
        ),
        patch(
            "tinker_delegate.execution_policy_anchor_cli.dstack_utils.get_attestation_details",
            side_effect=_details,
        ),
    ):
        yield


class AnchorWriterEvidenceCliTest(unittest.TestCase):
    def test_collects_exact_dstack_address_and_bounded_app_evidence(self):
        with (
            patch(
                "tinker_delegate.execution_policy_anchor_cli.dstack_utils.is_dstack_enabled",
                return_value=True,
            ),
            patch(
                "tinker_delegate.execution_policy_anchor_cli.dstack_utils.is_dstack_simulator",
                return_value=False,
            ),
            patch(
                "tinker_delegate.execution_policy_anchor.dstack_utils.is_dstack_enabled",
                return_value=True,
            ),
            patch(
                "tinker_delegate.execution_policy_anchor.dstack_utils.is_dstack_simulator",
                return_value=False,
            ),
            patch(
                "tinker_delegate.execution_policy_anchor.dstack_utils.derive_storage_key",
                return_value=KEY_MATERIAL,
            ) as derive,
            patch(
                "tinker_delegate.execution_policy_anchor_cli.dstack_utils.get_attestation_details",
                side_effect=_details,
            ),
        ):
            qvl = _FakeQvl()
            evidence = collect_anchor_writer_evidence(
                _settings(), qvl_client=qvl, now=NOW
            )

        body = evidence.to_bounded_dict()
        self.assertEqual(body["schema"], EVIDENCE_SCHEMA)
        self.assertEqual(body["status"], "independent_qvl_verified")
        self.assertRegex(body["writer_address"], r"^0x[0-9a-f]{40}$")
        self.assertEqual(body["anchor_address"], ANCHOR)
        self.assertEqual(body["writer_release_commitment"], RELEASE)
        self.assertEqual(body["writer_key_path"], WRITER_KEY_PATH)
        self.assertEqual(body["app_id"], "45" * 20)
        self.assertEqual(body["compose_hash"], COMPOSE)
        self.assertEqual(body["os_image_hash"], OS_IMAGE)
        self.assertEqual(
            body["quote_report_data"],
            body["report_data"] + body["qvl_verdict"]["challenge_digest"][2:],
        )
        self.assertEqual(body["quote_size"], 1024)
        self.assertEqual(body["qvl_release_policy_hash"], QVL_POLICY)
        self.assertEqual(body["qvl_verifier_address"], QVL_ADDRESS)
        self.assertEqual(body["qvl_verdict"]["verified"], True)
        self.assertEqual(body["raw_quote_egress"], "authenticated_https_qvl_only")
        self.assertFalse(body["raw_quote_in_artifact"])
        self.assertFalse(body["raw_private_key_egress"])
        rendered = json.dumps(body, sort_keys=True)
        self.assertNotIn(KEY_MATERIAL.hex(), rendered)
        self.assertNotIn("ab" * 128, rendered)
        self.assertEqual(len(qvl.packets), 1)
        self.assertIn("ab" * 128, qvl.packets[0].quote)
        derive.assert_called_once_with(WRITER_KEY_PATH)

    def test_requires_real_dstack_and_exact_purpose_path(self):
        with patch(
            "tinker_delegate.execution_policy_anchor_cli.dstack_utils.is_dstack_enabled",
            return_value=False,
        ):
            with self.assertRaisesRegex(
                AnchorWriterEvidenceError, "real_dstack_required"
            ):
                collect_anchor_writer_attestation(
                    _settings(), challenge_digest=_signed_challenge().digest_bytes
                )

        with (
            patch(
                "tinker_delegate.execution_policy_anchor_cli.dstack_utils.is_dstack_enabled",
                return_value=True,
            ),
            patch(
                "tinker_delegate.execution_policy_anchor_cli.dstack_utils.is_dstack_simulator",
                return_value=False,
            ),
        ):
            with self.assertRaisesRegex(
                AnchorWriterEvidenceError, "writer_key_path_invalid"
            ):
                collect_anchor_writer_attestation(
                    _settings(
                        execution_policy_anchor_writer_key_path=(
                            "tinker/compute_execution_identity"
                        )
                    ),
                    challenge_digest=_signed_challenge().digest_bytes,
                )

    def test_malformed_quote_binding_fails_without_sdk_detail(self):
        secret_detail = "quote-secret-should-not-egress"
        with (
            patch(
                "tinker_delegate.execution_policy_anchor_cli.dstack_utils.is_dstack_enabled",
                return_value=True,
            ),
            patch(
                "tinker_delegate.execution_policy_anchor_cli.dstack_utils.is_dstack_simulator",
                return_value=False,
            ),
            patch(
                "tinker_delegate.execution_policy_anchor.dstack_utils.is_dstack_enabled",
                return_value=True,
            ),
            patch(
                "tinker_delegate.execution_policy_anchor.dstack_utils.is_dstack_simulator",
                return_value=False,
            ),
            patch(
                "tinker_delegate.execution_policy_anchor.dstack_utils.derive_storage_key",
                return_value=KEY_MATERIAL,
            ),
            patch(
                "tinker_delegate.execution_policy_anchor_cli.dstack_utils.get_attestation_details",
                side_effect=RuntimeError(secret_detail),
            ),
        ):
            with self.assertRaisesRegex(
                AnchorWriterEvidenceError, "dstack_evidence_invalid"
            ) as caught:
                collect_anchor_writer_attestation(
                    _settings(), challenge_digest=_signed_challenge().digest_bytes
                )
        self.assertNotIn(secret_detail, str(caught.exception))

    def test_cli_emits_one_canonical_line_and_never_raw_quote_or_key(self):
        with (
            patch(
                "tinker_delegate.execution_policy_anchor_cli.dstack_utils.is_dstack_enabled",
                return_value=True,
            ),
            patch(
                "tinker_delegate.execution_policy_anchor_cli.dstack_utils.is_dstack_simulator",
                return_value=False,
            ),
            patch(
                "tinker_delegate.execution_policy_anchor.dstack_utils.is_dstack_enabled",
                return_value=True,
            ),
            patch(
                "tinker_delegate.execution_policy_anchor.dstack_utils.is_dstack_simulator",
                return_value=False,
            ),
            patch(
                "tinker_delegate.execution_policy_anchor.dstack_utils.derive_storage_key",
                return_value=KEY_MATERIAL,
            ),
            patch(
                "tinker_delegate.execution_policy_anchor_cli.dstack_utils.get_attestation_details",
                side_effect=_details,
            ),
            patch(
                "tinker_delegate.execution_policy_anchor_cli.Settings",
                return_value=_settings(),
            ),
            patch(
                "tinker_delegate.execution_policy_anchor_cli.HttpsAnchorWriterQvlClient",
                return_value=_FakeQvl(),
            ),
            patch(
                "tinker_delegate.execution_policy_anchor_cli.time.time",
                return_value=NOW,
            ),
        ):
            stdout = io.StringIO()
            stderr = io.StringIO()
            code = main([], stdout=stdout, stderr=stderr)
        self.assertEqual(code, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(len(stdout.getvalue().splitlines()), 1)
        body = json.loads(stdout.getvalue())
        self.assertEqual(body["schema"], EVIDENCE_SCHEMA)
        self.assertEqual(body["status"], "independent_qvl_verified")
        self.assertEqual(body["qvl_verifier_address"], QVL_ADDRESS)
        self.assertNotIn(KEY_MATERIAL.hex(), stdout.getvalue())
        self.assertNotIn("ab" * 128, stdout.getvalue())

    def test_cli_rejects_payload_arguments_without_reflecting_them(self):
        secret = "private-argument-sentinel"
        stdout = io.StringIO()
        stderr = io.StringIO()
        code = main(
            ["--writer-key", secret], stdout=stdout, stderr=stderr
        )
        self.assertEqual(code, 78)
        self.assertEqual(stdout.getvalue(), "")
        self.assertNotIn(secret, stderr.getvalue())
        body = json.loads(stderr.getvalue())
        self.assertEqual(body["reason_code"], "arguments_not_allowed")

    def test_cli_failure_is_one_bounded_line(self):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            patch(
                "tinker_delegate.execution_policy_anchor_cli.dstack_utils.is_dstack_enabled",
                return_value=False,
            ),
            patch(
                "tinker_delegate.execution_policy_anchor_cli.Settings",
                return_value=_settings(),
            ),
            patch(
                "tinker_delegate.execution_policy_anchor_cli.HttpsAnchorWriterQvlClient",
                return_value=_FakeQvl(),
            ),
        ):
            code = main([], stdout=stdout, stderr=stderr)
        self.assertEqual(code, 78)
        self.assertEqual(stdout.getvalue(), "")
        body = json.loads(stderr.getvalue())
        self.assertEqual(body["status"], "blocked")
        self.assertEqual(body["reason_code"], "real_dstack_required")
        self.assertEqual(
            body["raw_quote_transport_policy"],
            "authenticated_https_qvl_only",
        )
        self.assertFalse(body["raw_quote_in_output"])
        self.assertNotIn("raw_quote_egress", body)
        self.assertEqual(len(stderr.getvalue().splitlines()), 1)

    def test_post_send_invalid_verdict_failure_is_truthful_and_leak_free(self):
        token = "post-send-secret-bearer-" + "z" * 32
        bad_qvl = _FakeQvl(
            mutate=lambda verdict: replace(
                verdict, report_data="0x" + "77" * 32
            )
        )
        with (
            _dstack_context(),
            patch(
                "tinker_delegate.execution_policy_anchor_cli.Settings",
                return_value=_settings(),
            ),
            patch(
                "tinker_delegate.execution_policy_anchor_cli.HttpsAnchorWriterQvlClient",
                return_value=bad_qvl,
            ),
            patch(
                "tinker_delegate.execution_policy_anchor_cli.time.time",
                return_value=NOW,
            ),
            patch.dict(
                "os.environ",
                {"TINKER_EXECUTION_POLICY_ANCHOR_WRITER_QVL_AUTH_TOKEN": token},
            ),
        ):
            stdout = io.StringIO()
            stderr = io.StringIO()
            code = main([], stdout=stdout, stderr=stderr)

        self.assertEqual(code, 78)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(len(bad_qvl.packets), 1)
        body = json.loads(stderr.getvalue())
        self.assertEqual(body["reason_code"], "independent_qvl_verdict_invalid")
        self.assertEqual(
            body["raw_quote_transport_policy"],
            "authenticated_https_qvl_only",
        )
        self.assertFalse(body["raw_quote_in_output"])
        self.assertNotIn("raw_quote_egress", body)
        self.assertNotIn(bad_qvl.packets[0].quote, stderr.getvalue())
        self.assertNotIn(token, stderr.getvalue())

    def test_forged_or_context_drifted_qvl_verdict_fails_closed(self):
        mismatches = (
            lambda verdict: replace(verdict, report_data="0x" + "77" * 32),
            lambda verdict: replace(verdict, compose_hash="0x" + "88" * 32),
            lambda verdict: replace(verdict, verifier_address=ANCHOR),
        )
        for mutate in mismatches:
            with self.subTest(mutate=mutate):
                with _dstack_context():
                    with self.assertRaisesRegex(
                        AnchorWriterEvidenceError,
                        "independent_qvl_verdict_invalid",
                    ):
                        collect_anchor_writer_evidence(
                            _settings(),
                            qvl_client=_FakeQvl(mutate=mutate),
                            now=NOW,
                        )

    def test_https_qvl_transport_is_authenticated_bounded_and_quote_minimized(self):
        challenge = _signed_challenge()
        with _dstack_context():
            packet = collect_anchor_writer_attestation(
                _settings(), challenge_digest=challenge.digest_bytes
            )
        signed = _FakeQvl().verify(packet, challenge).to_public_dict()
        token = "qvl-bearer-secret-" + "x" * 32

        def handler(request):
            self.assertEqual(request.headers["authorization"], f"Bearer {token}")
            if request.url.path == "/challenge":
                self.assertNotIn(packet.quote.encode("ascii"), request.content)
                body = challenge.to_public_dict()
            else:
                self.assertEqual(
                    request.url,
                    httpx.URL("https://anchor-qvl.example.test/verify"),
                )
                self.assertIn(packet.quote.encode("ascii"), request.content)
                body = signed
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                json=body,
            )

        transport = httpx.MockTransport(handler)
        injected = httpx.Client(transport=transport, trust_env=False)
        client = HttpsAnchorWriterQvlClient(
            "https://anchor-qvl.example.test/verify",
            auth_token=token,
            client=injected,
            trusted_verifier_addresses=(QVL_ADDRESS,),
            expected_policy_hash=QVL_POLICY,
            **QVL_CLIENT_LINEAGE,
        )
        with patch("tinker_delegate.qvl_freshness.time.time", return_value=NOW):
            issued = client.issue_challenge()
        verdict = client.verify(packet, issued)
        self.assertEqual(verdict.verifier_address, QVL_ADDRESS)
        self.assertNotIn(token, repr(client))
        self.assertNotIn(packet.quote, json.dumps(verdict.to_public_dict()))
        client.close()
        injected.close()

        with self.assertRaisesRegex(
            AnchorWriterEvidenceError, "independent_qvl_unavailable"
        ):
            HttpsAnchorWriterQvlClient(
                "http://anchor-qvl.example.test/verify",
                auth_token=token,
            )

if __name__ == "__main__":
    unittest.main()
