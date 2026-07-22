from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from attestation_qvl.errors import VerifierUnavailable
from attestation_qvl.policy import load_release_policy
from tests.support import NOW, policy_payload, write_policy


def _write_raw(path: Path, raw: bytes) -> None:
    path.write_bytes(raw)
    path.chmod(0o600)


def test_policy_hash_is_canonical_and_includes_default_status(tmp_path):
    first_payload = policy_payload(include_statuses=False)
    first = write_policy(tmp_path / "first.json", first_payload)
    reordered = dict(reversed(list(first_payload.items())))
    second_path = tmp_path / "second.json"
    second_path.write_text(json.dumps(reordered, indent=4), encoding="utf-8")
    second_path.chmod(0o600)
    second = load_release_policy(str(second_path.resolve()))

    assert first.policy.allowed_tcb_statuses == ("OK",)
    assert first.canonical_bytes == second.canonical_bytes
    assert first.policy_hash == second.policy_hash
    assert b'"allowed_tcb_statuses":["OK"]' in first.canonical_bytes


def test_checked_in_example_is_schema_valid():
    project = Path(__file__).resolve().parents[1]
    diligence = load_release_policy(str((project / "release-policy.example.json").resolve()))
    arena = load_release_policy(str((project / "release-policy.arena.example.json").resolve()))
    anchor_writer = load_release_policy(
        str((project / "release-policy.anchor-writer.example.json").resolve())
    )
    compute_metering = load_release_policy(
        str((project / "release-policy.compute-metering.example.json").resolve())
    )
    compute_workload = load_release_policy(
        str((project / "release-policy.compute-workload.example.json").resolve())
    )
    assert (
        diligence.policy.chain_id
        == arena.policy.chain_id
        == anchor_writer.policy.chain_id
        == compute_metering.policy.chain_id
        == compute_workload.policy.chain_id
        == 84_532
    )
    assert diligence.policy.report_data_binding.kind == "diligence_result_signer_v1"
    assert diligence.policy.email_oracle_kms_restart_binding is not None
    assert arena.policy.report_data_binding.kind == "arena_candidate_ingress_v1"
    assert (
        anchor_writer.policy.report_data_binding.kind
        == "execution_policy_anchor_writer_v1"
    )
    assert compute_metering.policy.report_data_binding.kind == "compute_metering_signer_v1"
    assert (
        compute_workload.policy.report_data_binding.kind
        == "compute_workload_recipient_v1"
    )
    assert compute_workload.policy.allowed_signer_addresses == ()
    assert len({
        diligence.policy_hash,
        arena.policy_hash,
        anchor_writer.policy_hash,
        compute_metering.policy_hash,
        compute_workload.policy_hash,
    }) == 5


@pytest.mark.parametrize(
    "raw",
    [
        b'{"schema":"one","schema":"two"}',
        b'{"outer":{"kind":"one","kind":"two"}}',
        b'{"value":NaN}',
        b"\xff\xfe",
        b"{",
    ],
)
def test_policy_rejects_duplicate_nonfinite_or_malformed_json(tmp_path, raw):
    path = tmp_path / "policy.json"
    _write_raw(path, raw)
    with pytest.raises(VerifierUnavailable):
        load_release_policy(str(path.resolve()))


def test_policy_rejects_relative_symlink_directory_and_writable_files(tmp_path, monkeypatch):
    valid = tmp_path / "valid.json"
    write_policy(valid)

    monkeypatch.chdir(tmp_path)
    with pytest.raises(VerifierUnavailable):
        load_release_policy("valid.json")

    symlink = tmp_path / "link.json"
    symlink.symlink_to(valid)
    with pytest.raises(VerifierUnavailable):
        load_release_policy(str(symlink.absolute()))

    with pytest.raises(VerifierUnavailable):
        load_release_policy(str(tmp_path.resolve()))

    valid.chmod(0o620)
    with pytest.raises(VerifierUnavailable):
        load_release_policy(str(valid.resolve()))


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update({"unexpected": True}),
        lambda value: value.update({"chain_id": "84532"}),
        lambda value: value.update({"allowed_signer_addresses": ["0x" + "AA" * 20]}),
        lambda value: value.update({"allowed_signer_addresses": ["0x" + "00" * 20]}),
        lambda value: value.update({"contract_address": "0x" + "00" * 20}),
        lambda value: value.update({"allowed_signer_addresses": value["allowed_signer_addresses"] * 2}),
        lambda value: value.update({"allowed_signer_addresses": "0x" + "22" * 20}),
        lambda value: value.update({"allowed_tcb_statuses": ["OK", "OK"]}),
        lambda value: value.update({"allowed_tcb_statuses": ["UpToDate"]}),
        lambda value: value.update({"allowed_tcb_statuses": ["OUT_OF_DATE"]}),
        lambda value: value.update({"allowed_tcb_statuses": ["REVOKED"]}),
        lambda value: value.update({"allowed_tcb_statuses": ["CONFIGURATION_NEEDED"]}),
        lambda value: value.update({"allowed_tcb_statuses": ["OK", "REVOKED"]}),
        lambda value: value.update({"valid_until": NOW - 700}),
        lambda value: value["measurements"].update({"tee_tcb_svn2": "0f" * 16}),
    ],
)
def test_policy_schema_fails_closed_on_ambiguous_or_weakened_values(tmp_path, mutation):
    payload = deepcopy(policy_payload())
    mutation(payload)
    path = tmp_path / "invalid.json"
    _write_raw(path, json.dumps(payload).encode())
    with pytest.raises(VerifierUnavailable):
        load_release_policy(str(path.resolve()))


def test_arena_binding_requires_canonical_key_id(tmp_path):
    payload = policy_payload(arena=True)
    payload["report_data_binding"]["key_id"] = "sha256:" + "00" * 32
    path = tmp_path / "invalid-arena.json"
    _write_raw(path, json.dumps(payload).encode())
    with pytest.raises(VerifierUnavailable):
        load_release_policy(str(path.resolve()))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("chain_id", 1),
        ("contract_address", "0x" + "00" * 20),
        ("allowed_signer_addresses", ["0x" + "22" * 20, "0x" + "23" * 20]),
    ],
)
def test_compute_metering_policy_pins_base_vault_and_one_signer(tmp_path, field, value):
    payload = policy_payload(compute_metering=True)
    payload[field] = value
    path = tmp_path / f"invalid-compute-{field}.json"
    _write_raw(path, json.dumps(payload).encode())
    with pytest.raises(VerifierUnavailable):
        load_release_policy(str(path.resolve()))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("policy_set_hash", "0x" + "00" * 32),
        ("signer_custody", "operator_key"),
    ],
)
def test_compute_metering_binding_rejects_weak_authority(tmp_path, field, value):
    payload = policy_payload(compute_metering=True)
    payload["report_data_binding"][field] = value
    path = tmp_path / f"invalid-compute-binding-{field}.json"
    _write_raw(path, json.dumps(payload).encode())
    with pytest.raises(VerifierUnavailable):
        load_release_policy(str(path.resolve()))


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update({"chain_id": 1}),
        lambda value: value.update(
            {"allowed_signer_addresses": ["0x" + "22" * 20, "0x" + "23" * 20]}
        ),
        lambda value: value.update(
            {"report_data_binding": policy_payload(arena=True)["report_data_binding"]}
        ),
        lambda value: value["email_oracle_kms_restart_binding"].update(
            {"kms_eip1967_implementation_slot_word": "0x" + "12" * 32}
        ),
        lambda value: value["email_oracle_kms_restart_binding"].update(
            {"registration_block_number": 0}
        ),
        lambda value: value["email_oracle_kms_restart_binding"].update(
            {"kms_proxy_address": "0x" + "00" * 20}
        ),
        lambda value: value["email_oracle_kms_restart_binding"].update(
            {"restart_proof_hash": "0x" + "00" * 32}
        ),
    ],
)
def test_email_kms_restart_binding_is_exact_and_diligence_only(tmp_path, mutation):
    payload = policy_payload(email_restart=True)
    mutation(payload)
    path = tmp_path / "invalid-email-kms.json"
    _write_raw(path, json.dumps(payload).encode())
    with pytest.raises(VerifierUnavailable):
        load_release_policy(str(path.resolve()))


def test_policy_rejects_oversized_file_before_json_parse(tmp_path):
    path = tmp_path / "oversized.json"
    _write_raw(path, b"{" + b" " * (64 * 1024) + b"}")
    with pytest.raises(VerifierUnavailable):
        load_release_policy(str(path.resolve()))
