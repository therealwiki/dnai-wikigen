from __future__ import annotations

import base64
import hashlib
import json
import stat
from dataclasses import asdict
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from eth_hash.auto import keccak

from tinker_delegate.tinker_customer_adapter import (
    CustomerAccountPolicy,
    ExpectedTinkerRelease,
    RuntimeEvidencePolicy,
)
from tinker_delegate.tinker_customer_authority import (
    TINKER_CUSTOMER_AUTHORITY_B64_ENV,
    TINKER_CUSTOMER_AUTHORITY_PATH_ENV,
    TINKER_CUSTOMER_AUTHORITY_SHA256_ENV,
    TINKER_CUSTOMER_ENABLED_ENV,
    TINKER_CUSTOMER_SETTLEMENT_KEY_PATH_ENV,
    TINKER_CUSTOMER_SETTLEMENT_SIGNING_KEY_ENV,
    initialize_tinker_customer_authority,
)
from tinker_delegate.tinker_customer_runtime import (
    TINKER_CUSTOMER_RUNTIME_AUTHORITY_SCHEMA,
    TINKER_CUSTOMER_SETTLEMENT_KEY_PATH,
    TinkerCustomerRuntimeError,
)


SETTLEMENT_DOMAIN = (
    b"dnai-wikigen/tinker-customer-settlement-evidence/v1\0"
)


def _digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("ascii")).hexdigest()


def _public_key(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ).hex()


def _settlement_key(material: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(SETTLEMENT_DOMAIN + material).digest()
    )


def _authority(material: bytes) -> dict:
    expected = ExpectedTinkerRelease(
        contract_address="0x" + "11" * 20,
        runtime_code_hash="0x" + keccak(bytes.fromhex("6001600055")).hex(),
        owner="0x" + "22" * 20,
        account_commitment="0x" + "33" * 32,
        account_binding_ceremony_receipt_digest=_digest(
            "account-binding-ceremony"
        ),
        deployment_intent_digest=_digest("deployment-intent"),
        release_policy_commitment="0x" + "44" * 32,
        approved_compose_root="0x" + "55" * 32,
        approved_compose_hashes=("0x" + "66" * 32,),
        manager_root="0x" + "77" * 32,
        managers=("0x" + "88" * 20,),
        max_add_balance_policy_units=10_000_000,
        max_spend_policy_units=5_000_000,
    )
    policy = CustomerAccountPolicy(
        allowed_operations=("training",),
        max_operation_policy_units=5_000_000,
        max_outstanding_policy_units=10_000_000,
        max_lifetime_policy_units=100_000_000,
        credential_max_ttl_seconds=900,
        max_active_credentials=4,
    )
    evidence_policy = RuntimeEvidencePolicy(
        cvm_id_hash=_digest("cvm"),
        measurement_hash=_digest("measurement"),
        qvl_policy_hash=_digest("qvl"),
        release_authority_digest=_digest("release-authority"),
        roles_digest=_digest("roles"),
        customer_policy_digest=policy.digest,
        enabled_operations=("training",),
    )
    runtime_key = Ed25519PrivateKey.generate()
    provisioning_key = Ed25519PrivateKey.generate()
    return {
        "schema": TINKER_CUSTOMER_RUNTIME_AUTHORITY_SCHEMA,
        "status": "enabled",
        "expected_release": asdict(expected),
        "account_policy": asdict(policy),
        "runtime_evidence_policy": asdict(evidence_policy),
        "evidence": {
            "runtime_evidence_path": (
                "/sealed/tinker-customer/runtime-evidence.json"
            ),
            "runtime_evidence_public_key": _public_key(runtime_key),
            "provisioning_directory": (
                "/sealed/tinker-customer/provisioning"
            ),
            "provisioning_public_key": _public_key(provisioning_key),
            "settlement_directory": (
                "/sealed/tinker-customer/settlements"
            ),
            "settlement_public_key": _public_key(
                _settlement_key(material)
            ),
            "state_anchor_resource_hash": "99" * 32,
        },
    }


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _environment(authority: dict, target: Path) -> dict[str, str]:
    raw = _canonical(authority)
    return {
        TINKER_CUSTOMER_ENABLED_ENV: "true",
        TINKER_CUSTOMER_AUTHORITY_B64_ENV: (
            base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
        ),
        TINKER_CUSTOMER_AUTHORITY_PATH_ENV: str(target),
        TINKER_CUSTOMER_AUTHORITY_SHA256_ENV: (
            "sha256:" + hashlib.sha256(raw).hexdigest()
        ),
        TINKER_CUSTOMER_SETTLEMENT_SIGNING_KEY_ENV: "",
        TINKER_CUSTOMER_SETTLEMENT_KEY_PATH_ENV:
            TINKER_CUSTOMER_SETTLEMENT_KEY_PATH,
    }


def _patch_real_dstack(monkeypatch, material: bytes, target: Path) -> None:
    monkeypatch.setattr(
        "tinker_delegate.tinker_customer_authority."
        "PRODUCTION_TINKER_CUSTOMER_AUTHORITY_PATH",
        str(target),
    )
    monkeypatch.setattr(
        "tinker_delegate.tinker_customer_authority."
        "dstack_utils.is_dstack_enabled",
        lambda: True,
    )
    monkeypatch.setattr(
        "tinker_delegate.tinker_customer_authority."
        "dstack_utils.is_dstack_simulator",
        lambda: False,
    )
    monkeypatch.setattr(
        "tinker_delegate.tinker_customer_runtime."
        "dstack_utils.is_dstack_enabled",
        lambda: True,
    )
    monkeypatch.setattr(
        "tinker_delegate.tinker_customer_runtime."
        "dstack_utils.is_dstack_simulator",
        lambda: False,
    )
    monkeypatch.setattr(
        "tinker_delegate.tinker_customer_runtime."
        "dstack_utils.derive_storage_key",
        lambda path: (
            material
            if path == TINKER_CUSTOMER_SETTLEMENT_KEY_PATH
            else b"unexpected"
        ),
    )


def test_initializer_writes_private_exact_bytes_once(
    tmp_path: Path,
    monkeypatch,
) -> None:
    material = b"dstack-settlement-material"
    target = tmp_path / "sealed" / "authority.json"
    authority = _authority(material)
    environment = _environment(authority, target)
    _patch_real_dstack(monkeypatch, material, target)

    first = initialize_tinker_customer_authority(environment)
    replay = initialize_tinker_customer_authority(environment)

    assert first["status"] == "written"
    assert first["authority_written"] is True
    assert replay["status"] == "exact_replay"
    assert replay["authority_written"] is False
    assert target.read_bytes() == _canonical(authority)
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert stat.S_IMODE(target.parent.stat().st_mode) == 0o700
    assert "authority" not in {
        key
        for key in first
        if key not in {"authority_sha256", "authority_written"}
    }
    assert first["raw_authority_egress"] is False
    assert first["raw_secret_egress"] is False


def test_initializer_rejects_digest_or_signer_drift_before_write(
    tmp_path: Path,
    monkeypatch,
) -> None:
    material = b"dstack-settlement-material"
    target = tmp_path / "sealed" / "authority.json"
    authority = _authority(material)
    environment = _environment(authority, target)
    _patch_real_dstack(monkeypatch, material, target)

    mismatched_digest = dict(environment)
    mismatched_digest[TINKER_CUSTOMER_AUTHORITY_SHA256_ENV] = _digest(
        "wrong-authority"
    )
    with pytest.raises(TinkerCustomerRuntimeError, match="SHA-256 differs"):
        initialize_tinker_customer_authority(mismatched_digest)
    assert not target.exists()

    wrong_signer = _environment(_authority(b"other-material"), target)
    with pytest.raises(
        TinkerCustomerRuntimeError,
        match="settlement signer differs",
    ):
        initialize_tinker_customer_authority(wrong_signer)
    assert not target.exists()


def test_initializer_requires_real_dstack_and_forbids_explicit_signer(
    tmp_path: Path,
    monkeypatch,
) -> None:
    material = b"dstack-settlement-material"
    target = tmp_path / "sealed" / "authority.json"
    environment = _environment(_authority(material), target)
    _patch_real_dstack(monkeypatch, material, target)

    monkeypatch.setattr(
        "tinker_delegate.tinker_customer_authority."
        "dstack_utils.is_dstack_simulator",
        lambda: True,
    )
    with pytest.raises(TinkerCustomerRuntimeError, match="simulator"):
        initialize_tinker_customer_authority(environment)

    monkeypatch.setattr(
        "tinker_delegate.tinker_customer_authority."
        "dstack_utils.is_dstack_simulator",
        lambda: False,
    )
    explicit = dict(environment)
    explicit[TINKER_CUSTOMER_SETTLEMENT_SIGNING_KEY_ENV] = "secret-canary"
    with pytest.raises(TinkerCustomerRuntimeError, match="key policy differs"):
        initialize_tinker_customer_authority(explicit)
    assert not target.exists()


def test_disabled_initializer_never_accepts_authority_bytes() -> None:
    assert initialize_tinker_customer_authority(
        {TINKER_CUSTOMER_ENABLED_ENV: "false"}
    )["status"] == "disabled_no_write"
    with pytest.raises(TinkerCustomerRuntimeError, match="disabled"):
        initialize_tinker_customer_authority(
            {
                TINKER_CUSTOMER_ENABLED_ENV: "false",
                TINKER_CUSTOMER_AUTHORITY_B64_ENV: "YQ",
            }
        )
