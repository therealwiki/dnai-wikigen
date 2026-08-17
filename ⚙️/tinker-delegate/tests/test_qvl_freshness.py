from __future__ import annotations

from dataclasses import replace

import pytest
from eth_account import Account
from eth_account.messages import encode_defunct

from tinker_delegate.qvl_freshness import (
    CHALLENGE_SCHEMA,
    QvlChallenge,
    QvlFreshnessError,
    authenticate_qvl_challenge,
    challenge_bound_report_data,
    qvl_challenge_digest,
    qvl_challenge_from_public_dict,
)


NOW = 1_800_000_000
POLICY_HASH = "0x" + "12" * 32
LINEAGE = {
    "expected_chain_id": 84_532,
    "expected_domain": "main_runtime_cvm",
    "expected_cvm_id": "cvm-main-runtime-0001",
    "expected_deployment_intent_sha256": "sha256:" + "41" * 32,
    "expected_release_authority_sha256": "sha256:" + "42" * 32,
    "expected_ceremony_nonce": "0x" + "43" * 32,
    "expected_measurement_policy_sha256": "sha256:" + "44" * 32,
}


def _challenge(*, profile: str = "diligence") -> tuple[QvlChallenge, Account]:
    signer = Account.from_key(bytes.fromhex("34" * 32))
    unsigned = QvlChallenge(
        schema=CHALLENGE_SCHEMA,
        chain_id=LINEAGE["expected_chain_id"],
        domain=LINEAGE["expected_domain"],
        profile=profile,
        cvm_id=LINEAGE["expected_cvm_id"],
        deployment_intent_sha256=LINEAGE["expected_deployment_intent_sha256"],
        release_authority_sha256=LINEAGE["expected_release_authority_sha256"],
        ceremony_nonce=LINEAGE["expected_ceremony_nonce"],
        measurement_policy_sha256=LINEAGE["expected_measurement_policy_sha256"],
        release_policy_hash=POLICY_HASH,
        challenge_id="0x" + "56" * 32,
        challenge_digest="0x" + "01" * 32,
        issued_at=NOW,
        expires_at=NOW + 120,
        verifier_address=signer.address.lower(),
        verifier_signature="0x" + "00" * 65,
    )
    digest = qvl_challenge_digest(unsigned)
    signature = signer.sign_message(encode_defunct(hexstr=digest)).signature
    return (
        replace(
            unsigned,
            challenge_digest=digest,
            verifier_signature="0x" + bytes(signature).hex(),
        ),
        signer,
    )


@pytest.mark.parametrize(
    "profile",
    [
        "diligence",
        "arena",
        "execution_policy_anchor_writer",
        "compute_metering",
        "compute_workload",
        "email_oracle_kms_restart",
    ],
)
def test_signed_challenge_authenticates_for_exact_profile_and_policy(profile):
    challenge, signer = _challenge(profile=profile)
    parsed = qvl_challenge_from_public_dict(challenge.to_public_dict())

    authenticated = authenticate_qvl_challenge(
        parsed,
        expected_profile=profile,
        **LINEAGE,
        trusted_verifier_addresses=(signer.address,),
        expected_policy_hash=POLICY_HASH,
        now=NOW,
    )

    assert authenticated == challenge
    assert challenge_bound_report_data("0x" + "78" * 32, authenticated) == (
        "0x" + "78" * 32 + challenge.challenge_digest[2:]
    )
    assert len(bytes.fromhex(challenge_bound_report_data("0x" + "78" * 32, authenticated)[2:])) == 64


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: replace(value, profile="arena"),
        lambda value: replace(value, release_policy_hash="0x" + "23" * 32),
        lambda value: replace(value, challenge_digest="0x" + "45" * 32),
        lambda value: replace(value, verifier_signature="0x" + "67" * 65),
        lambda value: replace(value, expires_at=NOW),
        lambda value: replace(value, issued_at=NOW + 6, expires_at=NOW + 120),
        lambda value: replace(value, domain="independent_metering_cvm"),
        lambda value: replace(value, cvm_id="cvm-cross-domain-0001"),
        lambda value: replace(value, release_authority_sha256="sha256:" + "68" * 32),
    ],
)
def test_wrong_profile_policy_digest_signature_or_time_fails_closed(mutation):
    challenge, signer = _challenge()
    hostile = mutation(challenge)
    with pytest.raises(QvlFreshnessError):
        authenticate_qvl_challenge(
            hostile,
            expected_profile="diligence",
            **LINEAGE,
            trusted_verifier_addresses=(signer.address,),
            expected_policy_hash=POLICY_HASH,
            now=NOW,
        )


def test_challenge_parser_requires_exact_schema_without_coercion():
    challenge, _signer = _challenge()
    payload = challenge.to_public_dict()
    payload["unexpected"] = True
    with pytest.raises(QvlFreshnessError):
        qvl_challenge_from_public_dict(payload)

    payload = challenge.to_public_dict()
    payload["issued_at"] = True
    with pytest.raises(QvlFreshnessError):
        qvl_challenge_from_public_dict(payload)
