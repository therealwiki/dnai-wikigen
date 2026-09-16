from __future__ import annotations

import hashlib
import json
import asyncio
import os
from pathlib import Path
from unittest.mock import patch

import pytest
from eth_abi import encode
from eth_hash.auto import keccak

from tinker_delegate.artifacts import artifact_commitment
from tinker_delegate.control_plane import ControlPlane, DealState
from tinker_delegate.deterministic_diligence_evaluator import (
    COMPILED_RECIPES,
    CSV_TABLE_RECIPE,
    SFT_JSONL_RECIPE,
    compile_policy_v1,
)
from tinker_delegate.diligence_evaluator_registry import (
    DESCRIPTOR_SCHEMA,
    DiligenceEvaluatorRegistryError,
    EVALUATOR_POLICY_SET_TYPE,
    build_diligence_evaluator_release_manifest,
    evaluator_policy_set_root,
    load_diligence_evaluator_registry,
)
from tinker_delegate.evaluator import EvaluatorUnavailable, resolve_deal_evaluator
from tinker_delegate.config import Settings


def _digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("ascii")).hexdigest()


def _release(tmp_path):
    digests = {
        "evaluator_bundle_digest_sha256": _digest("reviewed-evaluator-bundle"),
        "entrypoint_digest_sha256": _digest("reviewed-entrypoint"),
        "input_schema_digest_sha256": _digest("reviewed-input-schema"),
        "output_schema_digest_sha256": _digest("reviewed-output-schema"),
    }
    policies = {
        recipe: compile_policy_v1(recipe=recipe, **digests)
        for recipe in COMPILED_RECIPES
    }
    manifest = build_diligence_evaluator_release_manifest(policies)
    raw = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "ascii"
    )
    path = tmp_path / "diligence-evaluator-release.json"
    path.write_bytes(raw)
    registry = load_diligence_evaluator_registry(
        str(path),
        expected_manifest_sha256="sha256:" + hashlib.sha256(raw).hexdigest(),
        expected_policy_set_root=manifest["evaluator_policy_set_root"],
    )
    settings = Settings(
        evaluator_mode="deterministic",
        diligence_evaluator_release_manifest_path=str(path),
        diligence_evaluator_release_manifest_sha256=registry.manifest_sha256,
        diligence_evaluator_policy_set_root=registry.evaluator_policy_set_root,
        diligence_chain_id=84_532,
        diligence_room_address="0x" + "12" * 20,
    )
    return manifest, registry, settings


def test_deterministic_settings_require_exact_manifest_chain_room_and_root(tmp_path):
    path = tmp_path / "release.json"
    path.write_text("{}\n", encoding="ascii")
    valid = {
        "evaluator_mode": "deterministic",
        "diligence_evaluator_release_manifest_path": str(path),
        "diligence_evaluator_release_manifest_sha256": "sha256:" + "11" * 32,
        "diligence_evaluator_policy_set_root": "0x" + "22" * 32,
        "diligence_chain_id": 84_532,
        "diligence_room_address": "0x" + "33" * 20,
        "chain_contract_address": "0x" + "33" * 20,
    }
    Settings(**valid)

    mutations = (
        {"diligence_evaluator_release_manifest_path": ""},
        {"diligence_evaluator_release_manifest_sha256": "sha256:" + "00" * 32},
        {"diligence_evaluator_policy_set_root": "0x" + "00" * 32},
        {"diligence_chain_id": 1},
        {"diligence_room_address": "0x" + "00" * 20},
        {"chain_contract_address": "0x" + "44" * 20},
    )
    for mutation in mutations:
        with pytest.raises(ValueError):
            Settings(**{**valid, **mutation})


def test_dstack_startup_requires_materialized_exact_manifest(tmp_path):
    _manifest, registry, settings = _release(tmp_path)
    path = settings.diligence_evaluator_release_manifest_path
    valid = {
        "evaluator_mode": "deterministic",
        "diligence_evaluator_release_manifest_path": path,
        "diligence_evaluator_release_manifest_sha256": registry.manifest_sha256,
        "diligence_evaluator_policy_set_root": registry.evaluator_policy_set_root,
        "diligence_chain_id": 84_532,
        "diligence_room_address": "0x" + "12" * 20,
        "chain_contract_address": "0x" + "12" * 20,
    }
    from tinker_delegate import config as config_module

    with (
        patch.dict(os.environ, {"DSTACK_ENABLED": "true"}),
        patch.object(
            config_module,
            "PRODUCTION_DILIGENCE_EVALUATOR_MANIFEST_PATH",
            path,
        ),
    ):
        Settings(**valid)
        with pytest.raises(ValueError, match="outside the sealed release volume"):
            Settings(
                **{
                    **valid,
                    "diligence_evaluator_release_manifest_path": path + ".other",
                }
            )
        with pytest.raises(ValueError, match="watcher contract is required"):
            Settings(**{**valid, "chain_contract_address": ""})
        with pytest.raises(ValueError, match="room and watcher contract differ"):
            Settings(
                **{
                    **valid,
                    "chain_contract_address": "0x" + "34" * 20,
                }
            )
        original = Path(path).read_bytes()
        Path(path).write_bytes(original + b" ")
        with pytest.raises(ValueError, match="unavailable or invalid"):
            Settings(**valid)
        Path(path).write_bytes(original)
        with pytest.raises(ValueError, match="unavailable or invalid"):
            Settings(
                **{
                    **valid,
                    "diligence_evaluator_release_manifest_sha256": (
                        "sha256:" + "55" * 32
                    ),
                }
            )
        with pytest.raises(ValueError, match="unavailable or invalid"):
            Settings(
                **{
                    **valid,
                    "diligence_evaluator_policy_set_root": "0x" + "66" * 32,
                }
            )
        Path(path).unlink()
        with pytest.raises(ValueError, match="unavailable or invalid"):
            Settings(**valid)


def test_release_registry_rejects_symlink_manifest(tmp_path):
    _manifest, registry, settings = _release(tmp_path)
    manifest = Path(settings.diligence_evaluator_release_manifest_path)
    link = tmp_path / "manifest-link.json"
    link.symlink_to(manifest)

    with pytest.raises(DiligenceEvaluatorRegistryError, match="release_manifest_unavailable"):
        load_diligence_evaluator_registry(
            str(link),
            expected_manifest_sha256=registry.manifest_sha256,
            expected_policy_set_root=registry.evaluator_policy_set_root,
        )


def test_release_descriptor_array_is_exact_and_root_matches_solidity_abi(tmp_path):
    manifest, registry, _settings = _release(tmp_path)
    descriptors = registry.public_descriptors()

    assert manifest["descriptor_schema"] == DESCRIPTOR_SCHEMA
    assert [item["recipe"] for item in descriptors] == list(COMPILED_RECIPES)
    assert all(item["max_artifact_bytes"] == 1_048_576 for item in descriptors)
    assert all(set(item) == {
        "recipe",
        "policy_commitment",
        "display_schema",
        "max_artifact_bytes",
        "policy_document_sha256",
    } for item in descriptors)
    commitments = tuple(item["policy_commitment"] for item in descriptors)
    sorted_raw = [bytes.fromhex(value[2:]) for value in sorted(commitments)]
    solidity_abi_root = "0x" + keccak(encode(
        ["bytes32", "bytes32[3]"],
        [keccak(EVALUATOR_POLICY_SET_TYPE.encode("ascii")), sorted_raw],
    )).hex()
    assert evaluator_policy_set_root(commitments) == solidity_abi_root
    assert registry.evaluator_policy_set_root == solidity_abi_root


def test_onchain_commitment_selects_exact_recipe_and_never_returns_raw_artifact(tmp_path):
    _manifest, registry, settings = _release(tmp_path)
    csv_descriptor = next(
        item for item in registry.descriptors if item.recipe == CSV_TABLE_RECIPE
    )
    evaluator = resolve_deal_evaluator(
        settings,
        evaluator_policy_commitment=csv_descriptor.policy_commitment,
        dstack_enabled=True,
    )
    private_sentinel = b"private-sentinel"
    artifact = b"sample_id,value\n" + private_sentinel + b",1\nother,2\n"
    secret = bytes.fromhex("42" * 32)
    commitment = artifact_commitment(artifact, secret)
    control_plane = ControlPlane("", enable_tinker_session=False)
    context = control_plane.on_deal_funded(
        "17",
        "buyer",
        "seller",
        10**18,
        10**16,
        commitment,
        csv_descriptor.policy_commitment,
    )
    assert context.session is None
    control_plane.receive_artifact("17", artifact, commitment, secret)
    control_plane._get_tdx_quote = lambda _deal, _result: b"bounded-quote"  # type: ignore[method-assign]

    result = asyncio.run(control_plane.evaluate("17", evaluator))

    assert result.score_band.value == "medium"
    assert private_sentinel.decode() not in repr(result)
    assert context.evaluator_policy_commitment == csv_descriptor.policy_commitment
    assert context.state is DealState.EVALUATED


def test_policy_substitution_and_unsupported_commitment_fail_closed(tmp_path):
    _manifest, registry, settings = _release(tmp_path)
    with pytest.raises(EvaluatorUnavailable, match="^deal evaluator is unavailable$"):
        resolve_deal_evaluator(
            settings,
            evaluator_policy_commitment="0x" + "ff" * 32,
            dstack_enabled=True,
        )

    sft_descriptor = next(
        item for item in registry.descriptors if item.recipe == SFT_JSONL_RECIPE
    )
    evaluator = registry.resolve(sft_descriptor.policy_commitment)
    with pytest.raises(Exception, match="sft_json_invalid"):
        asyncio.run(
            evaluator(
                artifact=b"sample_id,value\nprivate,1\n",
                artifact_type="attacker-csv-substitution",
                session=None,
                budget_cap=10**18,
                reserve_price=1,
            )
        )
