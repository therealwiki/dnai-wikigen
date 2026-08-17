from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from scripts.generate_collaboration_settle_reserved_vector import build_vector


FIXTURE = (
    Path(__file__).parent
    / "fixtures"
    / "collaboration_settle_reserved_calldata_v1.json"
)
AUTHORIZATION_ORDER = (
    "settlement_id",
    "settlement_nonce",
    "funding_reservation_id",
    "release_policy_commitment",
    "room_commitment",
    "room_state_commitment",
    "query_commitment",
    "grant_set_commitment",
    "allocation_commitment",
    "owners_amounts_hash",
    "asset",
    "total",
    "execution_commitment",
    "result_commitment",
    "usage_commitment",
    "attestation_evidence_hash",
    "anchor_resource_hash",
    "anchor_decision_hash",
    "anchor_sequence",
    "expiry",
)


def _fixture() -> dict[str, object]:
    return json.loads(FIXTURE.read_bytes())


def test_frozen_cross_language_vector_matches_production_python_encoder():
    frozen = _fixture()
    assert frozen == build_vector()
    calldata = frozen["expected"]["calldata"]
    raw = bytes.fromhex(calldata[2:])
    assert len(raw) == frozen["expected"]["calldata_byte_length"] == 1_252
    assert "sha256:" + hashlib.sha256(raw).hexdigest() == (
        frozen["expected"]["calldata_sha256"]
    )
    assert calldata[:10] == frozen["expected"]["selector"] == "0xf4ae1db5"


@pytest.mark.skipif(shutil.which("cast") is None, reason="cast not on PATH")
def test_frozen_python_vector_matches_independent_foundry_abi_encoder():
    frozen = _fixture()
    inputs = frozen["input"]
    authorization = inputs["authorization"]
    tuple_argument = "(" + ",".join(
        authorization[field] for field in AUTHORIZATION_ORDER
    ) + ")"
    foundry = subprocess.run(
        [
            "cast",
            "calldata",
            frozen["expected"]["function"],
            authorization["funding_reservation_id"],
            tuple_argument,
            "[" + ",".join(inputs["owners"]) + "]",
            "[" + ",".join(inputs["amounts"]) + "]",
            inputs["settlement_signature"],
            inputs["qvl_signature"],
        ],
        check=True,
        text=True,
        capture_output=True,
    ).stdout.strip().lower()
    assert foundry == frozen["expected"]["calldata"]
