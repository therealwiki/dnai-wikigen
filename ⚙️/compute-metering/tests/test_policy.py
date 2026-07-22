from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from compute_metering.errors import PolicyRejected, StateUnavailable
from compute_metering.policy import (
    compute_rate_policy_commitment,
    load_policy_set,
    validate_policy_set_bytes,
)
from tests.support import NOW, policy_payload, write_policy


def test_checked_in_example_is_canonical_and_commitment_bound():
    project = Path(__file__).resolve().parents[1]
    release = load_policy_set(str((project / "policy-set.example.json").resolve()))
    assert release.policy.chain_id == 84_532
    assert release.policy.rpc_origin == "https://sepolia.base.org"
    assert len(release.policy.asset_policies) == 2
    assert release.policy.allowed_asset_count == 1
    assert release.policy.active_rate_policy_count == 2
    assert release.policy.approved_compose_count == 1
    assert release.policy.approved_tee_identity_count == 1
    assert release.policy.pending_asset_count == 0
    assert release.policy.pending_rate_policy_count == 0
    assert release.policy.pending_compose_count == 0
    for entry in release.policy.asset_policies:
        assert compute_rate_policy_commitment(
            entry, developer_fee_bps=release.policy.developer_fee_bps
        ) == entry.rate_policy_commitment


def test_policy_hash_is_independent_of_input_key_order(tmp_path):
    payload = policy_payload()
    first = write_policy(tmp_path / "first.json", payload)
    second_path = tmp_path / "second.json"
    second_path.write_text(json.dumps(dict(reversed(list(payload.items()))), indent=2), encoding="utf-8")
    second_path.chmod(0o600)
    second = load_policy_set(str(second_path.resolve()))
    assert first.canonical_bytes == second.canonical_bytes
    assert first.policy_set_hash == second.policy_set_hash


@pytest.mark.parametrize(
    "raw",
    [
        b'{"schema":"one","schema":"two"}',
        b'{"outer":{"value":1,"value":2}}',
        b'{"value":NaN}',
        b'{"value":Infinity}',
        b"\xff\xfe",
        b"{",
        b"[]",
    ],
)
def test_duplicate_nonfinite_or_malformed_json_fails_closed(raw):
    with pytest.raises(PolicyRejected):
        validate_policy_set_bytes(raw)


def test_commitment_mismatch_is_rejected():
    payload = policy_payload()
    payload["asset_policies"][0]["rate_policy_commitment"] = "0x" + "99" * 32
    with pytest.raises(PolicyRejected):
        validate_policy_set_bytes(json.dumps(payload).encode())


def test_policy_file_must_be_absolute_regular_nonsymlink_and_private(tmp_path, monkeypatch):
    valid = tmp_path / "policy.json"
    write_policy(valid)

    monkeypatch.chdir(tmp_path)
    with pytest.raises(StateUnavailable):
        load_policy_set("policy.json")

    symlink = tmp_path / "link.json"
    symlink.symlink_to(valid)
    with pytest.raises(StateUnavailable):
        load_policy_set(str(symlink.absolute()))

    with pytest.raises(StateUnavailable):
        load_policy_set(str(tmp_path.resolve()))

    valid.chmod(0o620)
    with pytest.raises(StateUnavailable):
        load_policy_set(str(valid.resolve()))


def test_oversized_policy_is_rejected_before_parse():
    with pytest.raises(PolicyRejected):
        validate_policy_set_bytes(b"{" + b" " * (64 * 1024) + b"}")


@pytest.mark.parametrize(
    "mutation",
    [
        lambda p: p.update({"unexpected": True}),
        lambda p: p.update({"chain_id": "84532"}),
        lambda p: p.update({"chain_id": 8453}),
        lambda p: p.update({"rpc_origin": "http://sepolia.base.org"}),
        lambda p: p.update({"rpc_origin": "https://127.0.0.1"}),
        lambda p: p.update({"rpc_origin": "https://sepolia.base.org/path"}),
        lambda p: p.update({"rpc_origin": "https://sepolia.base.org:443"}),
        lambda p: p.update({"owner": p["developer"]}),
        lambda p: p.update({"owner": "0x" + "00" * 20}),
        lambda p: p.update({"developer_fee_frozen": False}),
        lambda p: p.update({"paused": True}),
        lambda p: p.update({"compose_policy_frozen": False}),
        lambda p: p.update({"tee_identity_additions_frozen": False}),
        lambda p: p.update({"metering_binding_frozen": False}),
        lambda p: p.update({"rate_policy_additions_frozen": False}),
        lambda p: p.update({"asset_additions_frozen": False}),
        lambda p: p.update({"allowed_asset_count": 2}),
        lambda p: p.update({"active_rate_policy_count": 3}),
        lambda p: p.update({"approved_compose_count": 2}),
        lambda p: p.update({"approved_tee_identity_count": 2}),
        lambda p: p.update({"pending_asset_count": 1}),
        lambda p: p.update({"pending_rate_policy_count": 1}),
        lambda p: p.update({"pending_compose_count": 1}),
        lambda p: p.update({"pending_tee_identity_count": 1}),
        lambda p: p.update({"pending_developer_fee_activates_at": 1}),
        lambda p: p.update({"pending_metering_verifier": "0x" + "99" * 20}),
        lambda p: p.update({"pending_metering_policy_set_hash": "0x" + "99" * 32}),
        lambda p: p.update({"pending_metering_binding_activates_at": 1}),
        lambda p: p.update({"developer_fee_bps": 2001}),
        lambda p: p.update({"valid_until": NOW - 4000}),
        lambda p: p.update({"min_submission_window_seconds": 300}),
        lambda p: p["asset_policies"][0].update({"rates": "not-an-array"}),
        lambda p: p["asset_policies"][0]["limits"].update({"max_total_debit": "0"}),
        lambda p: p["asset_policies"][0]["limits"].update({"max_prefill_tokens": 1}),
        lambda p: p["asset_policies"][0]["rates"][0].update({"model": " private model"}),
        lambda p: p["asset_policies"][0]["rates"][0].update({"sample_units_per_million": "01"}),
        lambda p: p["asset_policies"][0]["rates"][0].update(
            {
                "prefill_units_per_million": "0",
                "sample_units_per_million": "0",
                "training_units_per_million": "0",
            }
        ),
    ],
)
def test_schema_rejects_ambiguous_or_weakened_policy_values(mutation):
    payload = policy_payload()
    mutation(payload)
    with pytest.raises(PolicyRejected):
        validate_policy_set_bytes(json.dumps(payload).encode())


def test_rate_entries_must_be_sorted_and_unique():
    payload = policy_payload()
    original = deepcopy(payload["asset_policies"][0]["rates"][0])
    second = deepcopy(original)
    second["model"] = "another-model"
    payload["asset_policies"][0]["rates"] = [original, second]
    with pytest.raises(PolicyRejected):
        validate_policy_set_bytes(json.dumps(payload).encode())

    payload["asset_policies"][0]["rates"] = [original, deepcopy(original)]
    with pytest.raises(PolicyRejected):
        validate_policy_set_bytes(json.dumps(payload).encode())


def test_rate_card_commitment_changes_with_any_economic_field():
    first = policy_payload()
    second = policy_payload()
    second["asset_policies"][0]["rates"][0]["sample_units_per_million"] = "1001"
    from compute_metering.models import AssetRatePolicy

    first_policy = AssetRatePolicy.model_validate(first["asset_policies"][0], strict=True)
    second_policy = AssetRatePolicy.model_validate(second["asset_policies"][0], strict=True)
    assert compute_rate_policy_commitment(
        first_policy, developer_fee_bps=500
    ) != compute_rate_policy_commitment(second_policy, developer_fee_bps=500)


def test_policy_set_requires_exact_native_and_usdc_release_set():
    assert len(validate_policy_set_bytes(json.dumps(policy_payload()).encode()).policy.asset_policies) == 2

    missing = policy_payload()
    missing["asset_policies"] = []
    with pytest.raises(PolicyRejected):
        validate_policy_set_bytes(json.dumps(missing).encode())

    duplicate = policy_payload()
    duplicate["asset_policies"][1]["asset"] = duplicate["asset_policies"][0]["asset"]
    with pytest.raises(PolicyRejected):
        validate_policy_set_bytes(json.dumps(duplicate).encode())

    duplicate_commitment = policy_payload()
    duplicate_commitment["asset_policies"][1]["rate_policy_commitment"] = duplicate_commitment["asset_policies"][0]["rate_policy_commitment"]
    with pytest.raises(PolicyRejected):
        validate_policy_set_bytes(json.dumps(duplicate_commitment).encode())

    unlisted = policy_payload()
    unlisted["asset_policies"][0]["asset"] = "0x" + "99" * 20
    with pytest.raises(PolicyRejected):
        validate_policy_set_bytes(json.dumps(unlisted).encode())

    too_many = policy_payload()
    too_many["asset_policies"].append(deepcopy(too_many["asset_policies"][1]))
    with pytest.raises(PolicyRejected):
        validate_policy_set_bytes(json.dumps(too_many).encode())
