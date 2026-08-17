from __future__ import annotations

import copy
import json
import math
import re
from collections.abc import Callable
from pathlib import Path

import pytest

from tinker_delegate.execution_policy_release_core import (
    FINAL_RELEASE_AUTHORITY_CORE_DOMAIN,
    FINAL_RELEASE_AUTHORITY_CORE_SCHEMA,
    FINAL_RELEASE_AUTHORITY_CORE_V2_DOMAIN,
    FINAL_RELEASE_AUTHORITY_CORE_V2_SCHEMA,
    MAX_FINAL_RELEASE_AUTHORITY_CORE_BYTES,
    FinalReleaseAuthorityCoreValidationError,
    canonical_historical_final_release_authority_core_v2_bytes,
    canonical_final_release_authority_core_bytes,
    diligence_evaluator_policy_set_root,
    final_release_authority_core_digest,
    historical_final_release_authority_core_v2_digest,
    normalize_historical_final_release_authority_core_v2,
    normalize_final_release_authority_core,
    EXECUTION_POLICY_RELEASE_CORE_DOMAIN,
    EXECUTION_POLICY_RELEASE_CORE_SCHEMA,
    MAX_EXECUTION_POLICY_RELEASE_CORE_BYTES,
    ExecutionPolicyReleaseCoreValidationError,
    canonical_execution_policy_release_core_bytes,
    execution_policy_release_core_digest,
    normalize_execution_policy_release_core,
)

SHARED_V3_FIXTURE_PATH = (
    Path(__file__).resolve().parents[3]
    / "scripts"
    / "execution-policy-release-core-v3-historical.fixture.mjs"
)
SHARED_V3_FIXTURE_SOURCE = SHARED_V3_FIXTURE_PATH.read_text(encoding="utf-8")


def _shared_v3_fixture_string_export(name: str) -> str:
    matches = re.findall(
        rf'export const {re.escape(name)} =\s*"([^"]+)";',
        SHARED_V3_FIXTURE_SOURCE,
    )
    assert len(matches) == 1
    return matches[0]


KNOWN_VECTOR_ID = _shared_v3_fixture_string_export("KNOWN_VECTOR_ID")
KNOWN_DIGEST = _shared_v3_fixture_string_export("KNOWN_DIGEST")
HISTORICAL_V2_KNOWN_VECTOR_ID = (
    "dnai.final-release-authority-core.v2/known-answer-1"
)
HISTORICAL_V2_KNOWN_DIGEST = (
    "d1bab06a461597c4b0d12d9bbf50ea37549c2023b8c37b3e8ef7638b8c874fce"
)
RELEASE_SHA = "0123456789abcdef0123456789abcdef01234567"
APPROVER_ROOT = "013c34f9ab123ac6d7bb6ed0711bddb94806f04c02885cb9c2eeb7af2ac739d7"
USDC = "0x036cbd53842c5426634e7929541ec2318f3dcf7e"


def _address(index: int) -> str:
    return "0x" + format(index, "040x")


def _word(pair: str, *, prefixed: bool = True) -> str:
    return ("0x" if prefixed else "") + pair * 32


def _image(service: str, repository: str, digest_pair: str) -> dict[str, object]:
    return {
        "service": service,
        "image": (
            f"ghcr.io/therealwiki/dnai-wikigen/{repository}@sha256:"
            + digest_pair * 32
        ),
        "source_digest": RELEASE_SHA,
        "source_ref": "refs/heads/main",
        "repo": "therealwiki/dnai-wikigen",
        "signer_workflow": (
            "therealwiki/dnai-wikigen/.github/workflows/build-tee-images.yml"
        ),
        "provenance_attestation": "verified",
        "sbom_attestation": "verified",
    }


def _historical_v2_known_vector() -> dict[str, object]:
    return {
        "schema": "dnai.final-release-authority-core.v2",
        "release_sha": RELEASE_SHA,
        "network": {
            "chain_id": 84_532,
            "public_rpc_url": "https://sepolia.base.org",
        },
        "operator_address": _address(1),
        "deployment_intent_sha256": "sha256:" + "b1" * 32,
        "cvm_launch_intent_sha256": "sha256:" + "e2" * 32,
        "contracts": {
            "diligence_room": {
                "address": _address(2),
                "runtime_code_hash": _word("01"),
                "developer": _address(1),
                "result_verifier": _address(8),
                "attestation_verifier": _address(9),
                "attestation_release_policy_hash": _word("11"),
                "attestation_binding_frozen": True,
                "evaluator_policy_commitments": [
                    _word("b4"),
                    _word("b5"),
                    _word("b6"),
                ],
                "evaluator_policy_set_root": diligence_evaluator_policy_set_root(
                    [_word("b4"), _word("b5"), _word("b6")]
                ),
                "release_admission": {
                    "tee_identity": _address(12),
                    "compose_hash": _word("33", prefixed=False),
                    "approved_tee_identity_count": 1,
                    "approved_compose_count": 1,
                    "additions_frozen": True,
                },
            },
            "challenge_registry": {
                "address": _address(3),
                "runtime_code_hash": _word("02"),
                "owner": _address(1),
                "pending_owner": _address(0),
                "registry_paused": False,
                "minimum_version_review_delay_seconds": 172_800,
                "expected_challenge_count": 1,
            },
            "royalty_distributor": {
                "address": _address(4),
                "runtime_code_hash": _word("03"),
            },
            "tinker_account_encumbrance": {
                "address": _address(5),
                "runtime_code_hash": _word("04"),
                "owner": _address(1),
                "account_commitment": _word("22"),
                "max_add_balance_wei": "1000000000000000000",
                "max_spend_wei": "250000000000000000",
                "approved_compose_hashes": [_word("33")],
                "approved_compose_root": _word("23"),
                "approved_compose_count": 1,
                "managers": [_address(12)],
                "manager_root": _word("24"),
                "manager_count": 1,
                "release_policy_commitment": _word("25"),
                "release_max_add_balance_wei": "1000000000000000000",
                "release_max_spend_wei": "250000000000000000",
                "release_compose_root": _word("23"),
                "release_compose_count": 1,
                "release_manager_root": _word("24"),
                "release_manager_count": 1,
                "release_policy_frozen": True,
                "emergency_halted": False,
                "per_operation_caps": True,
                "custodies_funds": False,
            },
            "compute_credit_vault": {
                "address": _address(6),
                "runtime_code_hash": _word("05"),
                "owner": _address(1),
                "developer": _address(10),
                "metering_verifier": _address(11),
                "metering_qvl_verifier": _address(20),
                "metering_policy_set_hash": _word("56"),
                "metering_binding_frozen": True,
                "developer_fee_bps": 500,
                "tee_identity": _address(12),
                "compose_hash": _word("33", prefixed=False),
                "rate_policies": {
                    "native": {
                        "commitment": _word("44"),
                        "asset": _address(0),
                        "provider": _address(18),
                        "developer_fee_bps": 500,
                    },
                    "erc20": {
                        "commitment": _word("55"),
                        "asset": USDC,
                        "provider": _address(19),
                        "developer_fee_bps": 500,
                    },
                },
            },
            "email_oracle_auth": {
                "address": _address(7),
                "runtime_code_hash": _word("06"),
                "owner": _address(1),
                "consumer_address": _address(12),
                "upgrade_delay_seconds": 172_800,
                "release": {
                    "device_id": _word("a1"),
                    "kms_contract_address": _address(15),
                    "kms_runtime_code_hash": _word("a2"),
                    "kms_implementation_address": _address(16),
                    "kms_implementation_runtime_code_hash": _word("a3"),
                    "kms_registration_tx_hash": _word("a4"),
                    "kms_registration_block": 12_345_678,
                    "kms_registration_block_hash": _word("a5"),
                    "target_boot": {
                        "instance_id": _address(17),
                        "mr_aggregated": _word("a6"),
                        "mr_system": _word("a7"),
                        "os_image_hash": _word("88"),
                        "tcb_status": "UpToDate",
                        "advisory_ids": [],
                        "info_hash": _word("a8"),
                    },
                    "oracle_compose_hash": _word("33"),
                    "consumer_compose_hash": _word("33"),
                    "restart_key_derivation_proof_hash": _word("aa"),
                    "external_evidence_sha256": _word("a9"),
                },
            },
            "usdc": {
                "address": USDC,
                "runtime_code_hash": _word("07"),
                "symbol": "USDC",
                "decimals": 6,
            },
        },
        "cvm": {
            "app_id": "app_release_core_vector_1_🧬",
            "cvm_id": "cvm_release_core_vector_1",
            "compose_hash": _word("33", prefixed=False),
            "local_compose_hash": _word("66", prefixed=False),
            "rendered_compose_sha256": _word("77", prefixed=False),
            "os_image_hash": _word("88", prefixed=False),
            "os_is_dev": False,
            "public_logs": False,
            "public_sysinfo": False,
            "public_tcbinfo": False,
            "tee_identity": _address(12),
            "delegate_url": "https://delegate.example.com",
            "images": [
                _image("oracle", "tee-email-oracle", "c3"),
                _image("delegate", "tinker-delegate", "a1"),
                _image("neko", "neko-chrome", "b2"),
            ],
            "allowed_browser_origins": [
                "https://www.wikigen.me",
                "https://wikigen.me",
                "https://wikigenme.pages.dev",
            ],
            "compute_workload_ingress": {
                "max_verdict_age_seconds": 300,
                "revoked_quote_hashes": [],
            },
            "runtime_controls": {
                "wallet_auth_required": True,
                "runtime_bearer_required": True,
                "durable_compute_store": True,
                "durable_arena_store": True,
                "durable_arena_ingress_store": True,
                "artifact_ciphertext_only": True,
                "plaintext_artifact_endpoint_disabled": True,
                "plaintext_card_endpoint_disabled": True,
                "bootstrap_fail_open_disabled": True,
                "browser_ports_internal_only": True,
                "nondefault_browser_credentials_required": True,
                "project_owned_browser_images": True,
                "oracle_internal_only": True,
                "oracle_runtime_auth_required": True,
                "oracle_health_liveness_only": True,
                "oracle_pin_response_minimized": True,
                "oracle_private_metadata_egress_prohibited": True,
                "oracle_replay_fail_closed": True,
                "provider_dispatch_enabled": False,
                "hostile_candidate_execution_enabled": False,
                "deal_settlement_enabled": False,
                "remote_artifact_evaluator_enabled": False,
                "raw_secret_egress_prohibited": True,
            },
        },
        "arena_registry_bindings": {
            "synthetic-bio-assay-qc@1.0.0": {
                "registry_challenge_id": "1",
                "registry_version": 1,
                "controller_address": _address(1),
                "pending_controller_address": _address(0),
                "lifecycle": "open",
                "paused": False,
                "configuration_frozen": True,
                "catalog_manifest_hash": _word("d1", prefixed=False),
                "metadata_uri": "ipfs://bafy-arena-release-core-vector",
                "metadata_hash": _word("d1"),
                "sealed_artifact_commitment": _word("d2"),
                "evaluator_commitment": _word("d3"),
                "release_policy_commitment": _word("d4"),
            },
        },
        "wallet_auth": {
            "domain": "www.wikigen.me",
            "uri": "https://www.wikigen.me",
            "walletconnect_project_id": "12" * 16,
        },
        "requested_features": {
            "contract_writes": True,
            "artifact_upload": True,
            "compute_console": True,
            "compute_vault_funding": True,
            "compute_vault_authorization": True,
            "compute_workload_upload": True,
            "arena_submission": True,
        },
        "execution_policy": {
            "canonicalization_version": "policy-kernel-canonicalization/v2",
            "approval_schema": "dnai-wikigen/execution-policy-approval/v3",
            "api_schema_version": 3,
            "store_schema_version": 5,
            "approver_hashes": [
                _word("91", prefixed=False),
                _word("a2", prefixed=False),
            ],
            "approver_root_hash": APPROVER_ROOT,
            "rollback_anchor_target": {
                "schema": "dnai.execution-policy-rollback-anchor.v1",
                "chain_id": 84_532,
                "contract_address": _address(13),
                "runtime_code_hash": _word("99"),
                "writer_address": _address(14),
                "writer_custody": "dstack_derived_execution_policy_anchor_writer",
                "writer_key_path": "tinker/execution_policy_anchor_writer",
                "writer_release_commitment": _word("e2"),
                "confirmations": 12,
                "max_block_age_seconds": 3_600,
                "max_future_block_skew_seconds": 30,
                "verification_model": (
                    "single_rpc_reported_finalized_with_confirmation_depth"
                ),
                "independent_rpc_quorum_verified": False,
                "consensus_proof_verified": False,
            },
        },
    }


def _known_vector() -> dict[str, object]:
    opening = "export const KNOWN_VECTOR_JSON = String.raw`\n"
    closing = "\n`;"
    assert SHARED_V3_FIXTURE_SOURCE.count(opening) == 1
    start = SHARED_V3_FIXTURE_SOURCE.index(opening) + len(opening)
    end = SHARED_V3_FIXTURE_SOURCE.index(closing, start)
    assert SHARED_V3_FIXTURE_SOURCE.find(closing, end + len(closing)) == -1
    return json.loads(SHARED_V3_FIXTURE_SOURCE[start:end])


def _rename_arena_catalog_key(value: dict[str, object], replacement: str) -> None:
    bindings = value["arena_registry_bindings"]
    binding = bindings.pop("synthetic-bio-assay-qc@1.0.0")
    bindings[replacement] = binding


def _add_second_arena_binding(value: dict[str, object]) -> None:
    first = value["arena_registry_bindings"]["synthetic-bio-assay-qc@1.0.0"]
    second = copy.deepcopy(first)
    second.update(
        {
            "registry_challenge_id": "2",
            "registry_version": 7,
            "catalog_manifest_hash": _word("e1", prefixed=False),
            "metadata_uri": "ipfs://bafy-second-arena-release-core-vector",
            "metadata_hash": _word("e1"),
            "sealed_artifact_commitment": _word("e2"),
            "evaluator_commitment": _word("e3"),
            "release_policy_commitment": _word("e4"),
        }
    )
    value["arena_registry_bindings"]["a-second-catalog@2.1.0"] = second
    value["contracts"]["challenge_registry"]["expected_challenge_count"] = 2


def test_known_answer_vector_matches_javascript_digest() -> None:
    assert KNOWN_VECTOR_ID == "dnai.final-release-authority-core.v3/known-answer-1"
    assert FINAL_RELEASE_AUTHORITY_CORE_SCHEMA == _known_vector()["schema"]
    assert (
        FINAL_RELEASE_AUTHORITY_CORE_DOMAIN
        == b"dnai-wikigen/final-release-authority-core/v3\0"
    )
    normalized = normalize_final_release_authority_core(_known_vector())
    assert normalized["deployment_intent_sha256"] == "sha256:" + "b1" * 32
    assert normalized["cvm_launch_intent_sha256"] == "sha256:" + "e2" * 32
    assert (
        normalized["execution_policy"]["rollback_anchor_target"][
            "writer_release_commitment"
        ]
        == _word("e2")
    )
    assert [entry["service"] for entry in normalized["cvm"]["images"]] == [
        "delegate",
        "neko",
        "oracle",
    ]
    assert normalized["cvm"]["allowed_browser_origins"] == [
        "https://wikigen.me",
        "https://wikigenme.pages.dev",
        "https://www.wikigen.me",
    ]
    assert list(normalized["arena_registry_bindings"]) == [
        "synthetic-bio-assay-qc@1.0.0"
    ]
    genesis_binding = normalized["arena_registry_bindings"][
        "synthetic-bio-assay-qc@1.0.0"
    ]
    assert genesis_binding["registry_challenge_id"] == "1"
    assert genesis_binding["metadata_hash"] == "0x" + genesis_binding[
        "catalog_manifest_hash"
    ]
    assert normalized["contracts"]["challenge_registry"][
        "expected_challenge_count"
    ] == len(normalized["arena_registry_bindings"])
    canonical = canonical_final_release_authority_core_bytes(_known_vector())
    assert len(canonical) < MAX_FINAL_RELEASE_AUTHORITY_CORE_BYTES
    assert canonical.endswith(b"}")
    assert b"\n" not in canonical
    assert b"app_release_core_vector_1_\\ud83e\\uddec" in canonical
    digest = final_release_authority_core_digest(_known_vector())
    assert digest == KNOWN_DIGEST
    assert execution_policy_release_core_digest(_known_vector()) == KNOWN_DIGEST
    assert EXECUTION_POLICY_RELEASE_CORE_SCHEMA == FINAL_RELEASE_AUTHORITY_CORE_SCHEMA
    assert EXECUTION_POLICY_RELEASE_CORE_DOMAIN == FINAL_RELEASE_AUTHORITY_CORE_DOMAIN
    assert (
        MAX_EXECUTION_POLICY_RELEASE_CORE_BYTES
        == MAX_FINAL_RELEASE_AUTHORITY_CORE_BYTES
    )


def test_historical_v2_known_answer_remains_frozen_for_explicit_replay() -> None:
    value = _historical_v2_known_vector()
    assert (
        HISTORICAL_V2_KNOWN_VECTOR_ID
        == "dnai.final-release-authority-core.v2/known-answer-1"
    )
    assert FINAL_RELEASE_AUTHORITY_CORE_V2_SCHEMA == value["schema"]
    assert (
        FINAL_RELEASE_AUTHORITY_CORE_V2_DOMAIN
        == b"dnai-wikigen/final-release-authority-core/v2\0"
    )
    normalized = normalize_historical_final_release_authority_core_v2(value)
    assert (
        historical_final_release_authority_core_v2_digest(normalized)
        == HISTORICAL_V2_KNOWN_DIGEST
    )
    assert canonical_historical_final_release_authority_core_v2_bytes(normalized)
    assert "tinker_customer" not in normalized["requested_features"]
    assert "collaboration" not in normalized["requested_features"]
    with pytest.raises(FinalReleaseAuthorityCoreValidationError):
        normalize_final_release_authority_core(value)
    with pytest.raises(FinalReleaseAuthorityCoreValidationError):
        normalize_historical_final_release_authority_core_v2(_known_vector())


def test_v2_archival_and_v3_activation_semantics_are_version_pinned() -> None:
    historical = _historical_v2_known_vector()
    assert (
        historical["contracts"]["diligence_room"]["developer"]
        == historical["operator_address"]
    )
    historical_broad_origin = copy.deepcopy(historical)
    historical_broad_origin["cvm"]["delegate_url"] = "https://127.0.0.1:8443"
    assert (
        normalize_historical_final_release_authority_core_v2(
            historical_broad_origin
        )["cvm"]["delegate_url"]
        == "https://127.0.0.1:8443"
    )
    historical_separated_developer = copy.deepcopy(historical)
    historical_separated_developer["contracts"]["diligence_room"][
        "developer"
    ] = _address(21)
    with pytest.raises(
        FinalReleaseAuthorityCoreValidationError,
        match="DiligenceRoom developer must equal operator_address",
    ):
        normalize_historical_final_release_authority_core_v2(
            historical_separated_developer
        )

    current = _known_vector()
    assert (
        current["contracts"]["diligence_room"]["developer"]
        != current["operator_address"]
    )
    current_operator_developer = copy.deepcopy(current)
    current_operator_developer["contracts"]["diligence_room"]["developer"] = (
        current_operator_developer["operator_address"]
    )
    with pytest.raises(
        FinalReleaseAuthorityCoreValidationError,
        match="permanent developer must differ",
    ):
        normalize_final_release_authority_core(current_operator_developer)
    current_broad_origin = copy.deepcopy(current)
    current_broad_origin["cvm"]["delegate_url"] = "https://127.0.0.1:8443"
    with pytest.raises(
        FinalReleaseAuthorityCoreValidationError,
        match="canonical HTTPS origin",
    ):
        normalize_final_release_authority_core(current_broad_origin)


def test_valid_upstream_mutations_change_the_release_core_digest() -> None:
    baseline = execution_policy_release_core_digest(_known_vector())

    source_mutation = copy.deepcopy(_known_vector())
    source_mutation["release_sha"] = "1123456789abcdef0123456789abcdef01234567"
    for entry in source_mutation["cvm"]["images"]:
        entry["source_digest"] = source_mutation["release_sha"]
    assert execution_policy_release_core_digest(source_mutation) != baseline

    contract_mutation = copy.deepcopy(_known_vector())
    contract_mutation["contracts"]["royalty_distributor"]["runtime_code_hash"] = _word(
        "ab"
    )
    assert execution_policy_release_core_digest(contract_mutation) != baseline

    anchor_mutation = copy.deepcopy(_known_vector())
    anchor_mutation["execution_policy"]["rollback_anchor_target"][
        "contract_address"
    ] = _address(22)
    assert execution_policy_release_core_digest(anchor_mutation) != baseline

    metering_policy_mutation = copy.deepcopy(_known_vector())
    metering_policy_mutation["contracts"]["compute_credit_vault"][
        "metering_policy_set_hash"
    ] = _word("57")
    assert execution_policy_release_core_digest(metering_policy_mutation) != baseline

    tinker_policy_mutation = copy.deepcopy(_known_vector())
    tinker_policy_mutation["contracts"]["tinker_account_encumbrance"][
        "max_spend_wei"
    ] = "249999999999999999"
    tinker_policy_mutation["contracts"]["tinker_account_encumbrance"][
        "release_max_spend_wei"
    ] = "249999999999999999"
    assert execution_policy_release_core_digest(tinker_policy_mutation) != baseline

    deployment_intent_mutation = copy.deepcopy(_known_vector())
    deployment_intent_mutation["deployment_intent_sha256"] = (
        "sha256:" + "b3" * 32
    )
    assert execution_policy_release_core_digest(deployment_intent_mutation) != baseline

    launch_intent_mutation = copy.deepcopy(_known_vector())
    launch_intent_mutation["cvm_launch_intent_sha256"] = "sha256:" + "e3" * 32
    launch_intent_mutation["execution_policy"]["rollback_anchor_target"][
        "writer_release_commitment"
    ] = _word("e3")
    assert execution_policy_release_core_digest(launch_intent_mutation) != baseline

    email_delay_mutation = copy.deepcopy(_known_vector())
    email_delay_mutation["contracts"]["email_oracle_auth"][
        "upgrade_delay_seconds"
    ] = 172_801
    assert execution_policy_release_core_digest(email_delay_mutation) != baseline

    email_restart_proof_mutation = copy.deepcopy(_known_vector())
    email_restart_proof_mutation["contracts"]["email_oracle_auth"]["release"][
        "restart_key_derivation_proof_hash"
    ] = _word("ab")
    assert execution_policy_release_core_digest(email_restart_proof_mutation) != baseline

    provider_mutation = copy.deepcopy(_known_vector())
    provider_mutation["contracts"]["compute_credit_vault"]["rate_policies"][
        "native"
    ]["provider"] = _address(22)
    assert execution_policy_release_core_digest(provider_mutation) != baseline

    arena_mutation = copy.deepcopy(_known_vector())
    arena_mutation["arena_registry_bindings"][
        "synthetic-bio-assay-qc@1.0.0"
    ]["sealed_artifact_commitment"] = _word("d5")
    assert execution_policy_release_core_digest(arena_mutation) != baseline

    for key in ("tinker_customer", "collaboration"):
        feature_mutation = copy.deepcopy(_known_vector())
        feature_mutation["requested_features"][key] = True
        assert execution_policy_release_core_digest(feature_mutation) != baseline


def test_tinker_customer_and_collaboration_gates_are_explicit_independent_booleans() -> (
    None
):
    normalized = normalize_final_release_authority_core(_known_vector())
    assert normalized["requested_features"]["compute_console"] is True
    assert normalized["requested_features"]["tinker_customer"] is False
    assert normalized["requested_features"]["collaboration"] is False

    for key, other in (
        ("tinker_customer", "collaboration"),
        ("collaboration", "tinker_customer"),
    ):
        enabled = copy.deepcopy(_known_vector())
        enabled["requested_features"][key] = True
        normalized_enabled = normalize_final_release_authority_core(enabled)
        assert normalized_enabled["requested_features"][key] is True
        assert normalized_enabled["requested_features"][other] is False

        for invalid in (None, 0, 1, "false", "true"):
            malformed = copy.deepcopy(_known_vector())
            malformed["requested_features"][key] = invalid
            with pytest.raises(FinalReleaseAuthorityCoreValidationError):
                normalize_final_release_authority_core(malformed)

        missing = copy.deepcopy(_known_vector())
        del missing["requested_features"][key]
        with pytest.raises(FinalReleaseAuthorityCoreValidationError):
            normalize_final_release_authority_core(missing)

    unknown = copy.deepcopy(_known_vector())
    unknown["requested_features"]["compute_customer_alias"] = False
    with pytest.raises(FinalReleaseAuthorityCoreValidationError):
        normalize_final_release_authority_core(unknown)


def test_unordered_release_sets_normalize_to_one_commitment() -> None:
    permuted = copy.deepcopy(_known_vector())
    permuted["cvm"]["images"].reverse()
    permuted["cvm"]["allowed_browser_origins"].reverse()
    assert execution_policy_release_core_digest(
        permuted
    ) == execution_policy_release_core_digest(_known_vector())

    arena_left = copy.deepcopy(_known_vector())
    _add_second_arena_binding(arena_left)
    arena_right = copy.deepcopy(arena_left)
    arena_right["arena_registry_bindings"] = dict(
        reversed(list(arena_right["arena_registry_bindings"].items()))
    )
    normalized_arena = normalize_execution_policy_release_core(arena_right)[
        "arena_registry_bindings"
    ]
    assert list(normalized_arena) == [
        "a-second-catalog@2.1.0",
        "synthetic-bio-assay-qc@1.0.0",
    ]
    assert execution_policy_release_core_digest(
        arena_left
    ) == execution_policy_release_core_digest(arena_right)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value["contracts"]["challenge_registry"].pop(
            "pending_owner"
        ),
        lambda value: value["contracts"]["challenge_registry"].__setitem__(
            "pending_owner", _address(20)
        ),
        lambda value: value["contracts"]["challenge_registry"].__setitem__(
            "registry_paused", True
        ),
        lambda value: value["contracts"]["challenge_registry"].__setitem__(
            "registry_paused", 0
        ),
        lambda value: value["contracts"]["challenge_registry"].__setitem__(
            "minimum_version_review_delay_seconds", 172_799
        ),
        lambda value: value["contracts"]["challenge_registry"].__setitem__(
            "expected_challenge_count", 0
        ),
        lambda value: value["contracts"]["challenge_registry"].__setitem__(
            "uncommitted_catalog_note", "forbidden"
        ),
    ],
)
def test_challenge_registry_genesis_state_is_exact_active_and_review_delayed(
    mutation: Callable[[dict[str, object]], object],
) -> None:
    candidate = copy.deepcopy(_known_vector())
    mutation(candidate)
    with pytest.raises(FinalReleaseAuthorityCoreValidationError):
        normalize_final_release_authority_core(candidate)


@pytest.mark.parametrize(
    "replacement",
    [
        "Synthetic-bio-assay-qc@1.0.0",
        "synthetic_bio_assay_qc@1.0.0",
        "synthetic-bio-assay-qc@01.0.0",
        "synthetic-bio-assay-qc@1.0",
        "synthetic-bio-assay-qc@1.0.0-beta",
        "synthetic-bio-assay-qc@١.0.0",
        f"{'a' * 65}@1.0.0",
    ],
)
def test_arena_catalog_keys_are_lowercase_ascii_slugs_at_canonical_semver(
    replacement: str,
) -> None:
    candidate = copy.deepcopy(_known_vector())
    _rename_arena_catalog_key(candidate, replacement)
    with pytest.raises(FinalReleaseAuthorityCoreValidationError):
        normalize_final_release_authority_core(candidate)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda binding: binding.pop("controller_address"),
        lambda binding: binding.__setitem__("controller_address", _address(0)),
        lambda binding: binding.__setitem__(
            "pending_controller_address", _address(20)
        ),
        lambda binding: binding.__setitem__("lifecycle", "closed"),
        lambda binding: binding.__setitem__("paused", True),
        lambda binding: binding.__setitem__("configuration_frozen", False),
        lambda binding: binding.__setitem__("registry_challenge_id", "0"),
        lambda binding: binding.__setitem__("registry_challenge_id", "01"),
        lambda binding: binding.__setitem__(
            "registry_challenge_id", str(2**256)
        ),
        lambda binding: binding.__setitem__("registry_version", 0),
        lambda binding: binding.__setitem__("registry_version", 2**32),
        lambda binding: binding.__setitem__("catalog_manifest_hash", "0" * 64),
        lambda binding: binding.__setitem__("metadata_uri", "ipfs://café"),
        lambda binding: binding.__setitem__("metadata_uri", "x" * 257),
        lambda binding: binding.__setitem__("metadata_hash", _word("d5")),
        lambda binding: binding.__setitem__(
            "sealed_artifact_commitment", binding["metadata_hash"]
        ),
        lambda binding: binding.__setitem__(
            "evaluator_commitment", binding["release_policy_commitment"]
        ),
        lambda binding: binding.__setitem__("uncommitted", "forbidden"),
    ],
)
def test_arena_registry_binding_rejects_mutable_or_ambiguous_catalog_state(
    mutation: Callable[[dict[str, object]], object],
) -> None:
    candidate = copy.deepcopy(_known_vector())
    binding = candidate["arena_registry_bindings"][
        "synthetic-bio-assay-qc@1.0.0"
    ]
    mutation(binding)
    with pytest.raises(FinalReleaseAuthorityCoreValidationError):
        normalize_final_release_authority_core(candidate)


def test_arena_registry_ids_are_unique_contiguous_and_match_expected_count() -> None:
    missing = copy.deepcopy(_known_vector())
    missing["arena_registry_bindings"] = {}
    missing["contracts"]["challenge_registry"]["expected_challenge_count"] = 1
    with pytest.raises(FinalReleaseAuthorityCoreValidationError):
        normalize_final_release_authority_core(missing)

    count_drift = copy.deepcopy(_known_vector())
    count_drift["contracts"]["challenge_registry"]["expected_challenge_count"] = 2
    with pytest.raises(FinalReleaseAuthorityCoreValidationError):
        normalize_final_release_authority_core(count_drift)

    noncontiguous = copy.deepcopy(_known_vector())
    _add_second_arena_binding(noncontiguous)
    noncontiguous["arena_registry_bindings"]["a-second-catalog@2.1.0"][
        "registry_challenge_id"
    ] = "3"
    with pytest.raises(FinalReleaseAuthorityCoreValidationError):
        normalize_final_release_authority_core(noncontiguous)

    duplicate = copy.deepcopy(_known_vector())
    _add_second_arena_binding(duplicate)
    duplicate["arena_registry_bindings"]["a-second-catalog@2.1.0"][
        "registry_challenge_id"
    ] = "1"
    with pytest.raises(FinalReleaseAuthorityCoreValidationError):
        normalize_final_release_authority_core(duplicate)


@pytest.mark.parametrize(
    "path,value",
    [
        (("release_manifest_commitment",), _word("fe", prefixed=False)),
        (("review_envelope_sha256",), "sha256:" + "b2" * 32),
        (("execution_policy", "approval_domain"), "forbidden"),
        (
            (
                "execution_policy",
                "rollback_anchor_target",
                "evidence_sha256",
            ),
            _word("fe"),
        ),
    ],
)
def test_extra_fields_are_rejected_at_every_commitment_boundary(
    path: tuple[str, ...], value: object
) -> None:
    candidate = copy.deepcopy(_known_vector())
    cursor = candidate
    for key in path[:-1]:
        cursor = cursor[key]
    cursor[path[-1]] = value
    with pytest.raises(ExecutionPolicyReleaseCoreValidationError):
        execution_policy_release_core_digest(candidate)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.pop("deployment_intent_sha256"),
        lambda value: value.__setitem__(
            "deployment_intent_sha256", "sha256:" + "0" * 64
        ),
        lambda value: value.__setitem__(
            "deployment_intent_sha256", "sha256:" + "AB" * 32
        ),
        lambda value: value.__setitem__("deployment_intent_sha256", "b2" * 32),
    ],
)
def test_deployment_intent_authority_is_exact_lowercase_and_nonzero(
    mutation: Callable[[dict[str, object]], object],
) -> None:
    candidate = copy.deepcopy(_known_vector())
    mutation(candidate)
    with pytest.raises(FinalReleaseAuthorityCoreValidationError):
        normalize_final_release_authority_core(candidate)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.pop("cvm_launch_intent_sha256"),
        lambda value: value.__setitem__(
            "cvm_launch_intent_sha256", "sha256:" + "0" * 64
        ),
        lambda value: value.__setitem__(
            "cvm_launch_intent_sha256", "sha256:" + "E2" * 32
        ),
        lambda value: value.__setitem__("cvm_launch_intent_sha256", "e2" * 32),
        lambda value: value.__setitem__("cvm_launch_intent_sha256_extra", "x"),
    ],
)
def test_cvm_launch_intent_authority_is_exact_lowercase_nonzero_and_closed(
    mutation: Callable[[dict[str, object]], object],
) -> None:
    candidate = copy.deepcopy(_known_vector())
    mutation(candidate)
    with pytest.raises(FinalReleaseAuthorityCoreValidationError):
        normalize_final_release_authority_core(candidate)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda anchor: anchor.pop("writer_release_commitment"),
        lambda anchor: anchor.__setitem__(
            "writer_release_commitment", "0x" + "0" * 64
        ),
        lambda anchor: anchor.__setitem__(
            "writer_release_commitment", _word("e3")
        ),
        lambda anchor: anchor.__setitem__(
            "writer_release_commitment", "0x" + "E2" * 32
        ),
        lambda anchor: anchor.__setitem__("writer_release_commitment_extra", "x"),
    ],
)
def test_anchor_writer_release_commitment_exactly_binds_launch_intent(
    mutation: Callable[[dict[str, object]], object],
) -> None:
    candidate = copy.deepcopy(_known_vector())
    anchor = candidate["execution_policy"]["rollback_anchor_target"]
    mutation(anchor)
    with pytest.raises(FinalReleaseAuthorityCoreValidationError):
        normalize_final_release_authority_core(candidate)


@pytest.mark.parametrize("invalid", [172_799, 31_536_001, 172_800.5, "172800"])
def test_email_oracle_upgrade_delay_is_bounded_and_release_bound(
    invalid: object,
) -> None:
    candidate = copy.deepcopy(_known_vector())
    candidate["contracts"]["email_oracle_auth"]["upgrade_delay_seconds"] = invalid
    with pytest.raises(ExecutionPolicyReleaseCoreValidationError):
        normalize_execution_policy_release_core(candidate)


@pytest.mark.parametrize("mutation", ["missing", "extra"])
def test_email_oracle_upgrade_delay_field_is_exact(mutation: str) -> None:
    candidate = copy.deepcopy(_known_vector())
    email = candidate["contracts"]["email_oracle_auth"]
    if mutation == "missing":
        email.pop("upgrade_delay_seconds")
    else:
        email["upgrade_delay_seconds_note"] = "not committed"
    with pytest.raises(ExecutionPolicyReleaseCoreValidationError):
        normalize_execution_policy_release_core(candidate)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda release: release.pop("restart_key_derivation_proof_hash"),
        lambda release: release.__setitem__(
            "restart_key_derivation_proof_hash", "0x" + "0" * 64
        ),
        lambda release: release.__setitem__(
            "restart_key_derivation_proof_hash", "0x" + "AA" * 32
        ),
        lambda release: release.__setitem__(
            "restart_key_derivation_proof_hash", "aa" * 32
        ),
    ],
)
def test_email_restart_key_derivation_proof_hash_is_exact_nonzero_bytes32(
    mutation: Callable[[dict[str, object]], object],
) -> None:
    candidate = copy.deepcopy(_known_vector())
    release = candidate["contracts"]["email_oracle_auth"]["release"]
    mutation(release)
    with pytest.raises(ExecutionPolicyReleaseCoreValidationError):
        normalize_execution_policy_release_core(candidate)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda admission: admission.__setitem__("tee_identity", _address(20)),
        lambda admission: admission.__setitem__(
            "compose_hash", _word("66", prefixed=False)
        ),
        lambda admission: admission.__setitem__("compose_hash", _word("33")),
        lambda admission: admission.__setitem__("approved_tee_identity_count", 2),
        lambda admission: admission.__setitem__("approved_compose_count", 0),
        lambda admission: admission.__setitem__("additions_frozen", False),
        lambda admission: admission.pop("approved_compose_count"),
    ],
)
def test_diligence_release_admission_is_exact_single_frozen_main_cvm_authority(
    mutation: Callable[[dict[str, object]], object],
) -> None:
    candidate = copy.deepcopy(_known_vector())
    admission = candidate["contracts"]["diligence_room"]["release_admission"]
    mutation(admission)
    with pytest.raises(ExecutionPolicyReleaseCoreValidationError):
        normalize_execution_policy_release_core(candidate)


@pytest.mark.parametrize(
    "field,value",
    [
        ("oracle_compose_hash", _word("66")),
        ("consumer_compose_hash", _word("66")),
        ("oracle_compose_hash", _word("33", prefixed=False)),
        ("consumer_compose_hash", "0x" + "0" * 64),
    ],
)
def test_email_compose_authorities_are_prefixed_and_bound_to_main_cvm(
    field: str, value: object
) -> None:
    candidate = copy.deepcopy(_known_vector())
    candidate["contracts"]["email_oracle_auth"]["release"][field] = value
    with pytest.raises(ExecutionPolicyReleaseCoreValidationError):
        normalize_execution_policy_release_core(candidate)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda vault: vault["rate_policies"]["native"].__setitem__(
            "asset", _address(20)
        ),
        lambda vault: vault["rate_policies"]["erc20"].__setitem__(
            "asset", _address(20)
        ),
        lambda vault: vault["rate_policies"]["native"].__setitem__(
            "developer_fee_bps", 501
        ),
        lambda vault: vault["rate_policies"]["erc20"].__setitem__(
            "developer_fee_bps", 499
        ),
        lambda vault: vault["rate_policies"]["erc20"].__setitem__(
            "commitment", vault["rate_policies"]["native"]["commitment"]
        ),
        lambda vault: vault["rate_policies"]["native"].__setitem__(
            "provider", _address(0)
        ),
        lambda vault: vault["rate_policies"]["erc20"].__setitem__(
            "provider", vault["rate_policies"]["native"]["provider"]
        ),
        lambda vault: vault["rate_policies"]["native"].__setitem__(
            "provider", vault["address"]
        ),
        lambda vault: vault["rate_policies"]["native"].__setitem__(
            "provider", vault["metering_verifier"]
        ),
        lambda vault: vault["rate_policies"].__setitem__("extra", {}),
        lambda vault: vault["rate_policies"]["native"].__setitem__(
            "uncommitted_rate", 1
        ),
    ],
)
def test_compute_rate_policies_bind_assets_fees_providers_and_commitments(
    mutation: Callable[[dict[str, object]], object],
) -> None:
    candidate = copy.deepcopy(_known_vector())
    vault = candidate["contracts"]["compute_credit_vault"]
    mutation(vault)
    with pytest.raises(ExecutionPolicyReleaseCoreValidationError):
        normalize_execution_policy_release_core(candidate)


@pytest.mark.parametrize(
    "legacy_field,legacy_value",
    [
        ("native_rate_policy_commitment", _word("44")),
        ("erc20_asset_address", USDC),
        ("erc20_rate_policy_commitment", _word("55")),
    ],
)
def test_flat_compute_rate_policy_fields_are_retired(
    legacy_field: str, legacy_value: object
) -> None:
    candidate = copy.deepcopy(_known_vector())
    candidate["contracts"]["compute_credit_vault"][legacy_field] = legacy_value
    with pytest.raises(ExecutionPolicyReleaseCoreValidationError):
        normalize_execution_policy_release_core(candidate)


@pytest.mark.parametrize("invalid", [500.5, math.nan, math.inf, -0.0])
def test_floating_point_numbers_are_rejected(invalid: float) -> None:
    candidate = copy.deepcopy(_known_vector())
    candidate["contracts"]["compute_credit_vault"]["developer_fee_bps"] = invalid
    with pytest.raises(ExecutionPolicyReleaseCoreValidationError):
        normalize_execution_policy_release_core(candidate)


def test_lowercase_approver_control_character_and_field_bounds_are_strict() -> None:
    uppercase = copy.deepcopy(_known_vector())
    uppercase["operator_address"] = uppercase["operator_address"].upper()
    with pytest.raises(ExecutionPolicyReleaseCoreValidationError):
        normalize_execution_policy_release_core(uppercase)

    unsorted_approvers = copy.deepcopy(_known_vector())
    unsorted_approvers["execution_policy"]["approver_hashes"].reverse()
    with pytest.raises(ExecutionPolicyReleaseCoreValidationError):
        normalize_execution_policy_release_core(unsorted_approvers)

    bad_root = copy.deepcopy(_known_vector())
    bad_root["execution_policy"]["approver_root_hash"] = _word(
        "ff", prefixed=False
    )
    with pytest.raises(ExecutionPolicyReleaseCoreValidationError):
        normalize_execution_policy_release_core(bad_root)

    control = copy.deepcopy(_known_vector())
    control["cvm"]["app_id"] = "bad\napp"
    with pytest.raises(ExecutionPolicyReleaseCoreValidationError):
        normalize_execution_policy_release_core(control)

    oversized = copy.deepcopy(_known_vector())
    oversized["cvm"]["app_id"] = "x" * 129
    with pytest.raises(ExecutionPolicyReleaseCoreValidationError):
        normalize_execution_policy_release_core(oversized)


@pytest.mark.parametrize(
    "invalid",
    ["1" * 31, "1" * 33, "AB" * 16, "zz" * 16, None, 123],
)
def test_walletconnect_project_id_is_empty_or_exact_lowercase_hex(invalid: object) -> None:
    candidate = copy.deepcopy(_known_vector())
    candidate["wallet_auth"]["walletconnect_project_id"] = invalid
    with pytest.raises(ExecutionPolicyReleaseCoreValidationError):
        normalize_execution_policy_release_core(candidate)


def test_empty_walletconnect_project_id_is_explicitly_allowed() -> None:
    candidate = copy.deepcopy(_known_vector())
    candidate["wallet_auth"]["walletconnect_project_id"] = ""
    normalized = normalize_execution_policy_release_core(candidate)
    assert normalized["wallet_auth"]["walletconnect_project_id"] == ""


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value["contracts"]["diligence_room"].__setitem__(
            "attestation_binding_frozen", False
        ),
        lambda value: value["contracts"]["compute_credit_vault"].__setitem__(
            "metering_binding_frozen", False
        ),
        lambda value: value["contracts"]["tinker_account_encumbrance"].__setitem__(
            "release_policy_frozen", False
        ),
        lambda value: value["contracts"]["tinker_account_encumbrance"].__setitem__(
            "emergency_halted", True
        ),
        lambda value: value["contracts"]["tinker_account_encumbrance"].__setitem__(
            "max_spend_wei", "01"
        ),
        lambda value: value["contracts"]["tinker_account_encumbrance"][
            "managers"
        ].__setitem__(0, _address(20)),
        lambda value: value["cvm"]["runtime_controls"].__setitem__(
            "deal_settlement_enabled", True
        ),
        lambda value: value["cvm"]["runtime_controls"].__setitem__(
            "remote_artifact_evaluator_enabled", True
        ),
        lambda value: value["execution_policy"]["rollback_anchor_target"].__setitem__(
            "writer_address", value["contracts"]["diligence_room"]["result_verifier"]
        ),
        lambda value: value["contracts"]["diligence_room"].__setitem__(
            "attestation_verifier",
            value["contracts"]["compute_credit_vault"]["metering_verifier"],
        ),
        lambda value: value["execution_policy"]["rollback_anchor_target"].__setitem__(
            "writer_address", value["contracts"]["royalty_distributor"]["address"]
        ),
    ],
)
def test_frozen_roots_deal_posture_and_role_separation_are_mandatory(
    mutation: Callable[[dict[str, object]], None],
) -> None:
    candidate = copy.deepcopy(_known_vector())
    mutation(candidate)
    with pytest.raises(ExecutionPolicyReleaseCoreValidationError):
        normalize_execution_policy_release_core(candidate)


def test_ensure_ascii_canonicalization_escapes_non_ascii_text() -> None:
    candidate = copy.deepcopy(_known_vector())
    candidate["cvm"]["app_id"] = "app-é"
    canonical = canonical_execution_policy_release_core_bytes(candidate)
    assert b"app-\\u00e9" in canonical
    assert "é".encode() not in canonical

    astral = canonical_execution_policy_release_core_bytes(_known_vector())
    assert b"app_release_core_vector_1_\\ud83e\\uddec" in astral
    assert "🧬".encode() not in astral
