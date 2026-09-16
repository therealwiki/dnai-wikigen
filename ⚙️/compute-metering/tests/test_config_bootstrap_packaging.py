from __future__ import annotations

import base64
import json
import os
import stat
from pathlib import Path

import pytest
from pydantic import ValidationError

from compute_metering.config import Settings
from compute_metering.errors import StateUnavailable
from compute_metering.policy import load_policy_set
from compute_metering.policy_bootstrap import decode_policy_environment, materialize_policy
from tests.support import TOKEN, policy_payload


def _settings(**overrides):
    values = {
        "policy_set_path": "/run/compute-metering/policy-set.json",
        "rpc_url": "https://sepolia.base.org/private-key-path?token=secret",
        "auth_token": TOKEN,
        "qvl_url": "https://compute-qvl.example.test/verify",
        "qvl_auth_token": "qvl-test-bearer-token-0123456789abcdef",
        "qvl_verifier_address": "0x" + "12" * 20,
        "qvl_release_policy_hash": "0x" + "34" * 32,
        "cvm_id": "cvm-independent-metering-0001",
        "deployment_intent_sha256": "sha256:" + "41" * 32,
        "release_authority_sha256": "sha256:" + "42" * 32,
        "ceremony_nonce": "0x" + "43" * 32,
        "qvl_measurement_policy_sha256": "sha256:" + "44" * 32,
        "state_path": "/var/lib/compute-metering-data/state/replay.sqlite3",
    }
    values.update(overrides)
    return Settings(**values)


def test_settings_are_bounded_secret_safe_and_absolute():
    settings = _settings()
    assert "private-key-path" not in repr(settings)
    assert TOKEN not in repr(settings)
    assert settings.max_concurrency == 4


@pytest.mark.parametrize(
    "field,value",
    [
        ("auth_token", "short"),
        ("auth_token", "x\n" + "a" * 32),
        ("rpc_url", "http://sepolia.base.org"),
        ("rpc_url", "https://user:pass@sepolia.base.org"),
        ("rpc_url", "https://sepolia.base.org/#fragment"),
        ("policy_set_path", "relative.json"),
        ("state_path", "relative.sqlite3"),
        ("cvm_id", "bad cvm id"),
        ("deployment_intent_sha256", "sha256:" + "00" * 32),
        ("release_authority_sha256", "0x" + "42" * 32),
        ("ceremony_nonce", "0x" + "00" * 32),
        ("qvl_measurement_policy_sha256", "sha256:" + "GG" * 32),
        ("max_concurrency", 17),
        ("rate_capacity", 0),
    ],
)
def test_invalid_environment_values_fail_startup(field, value):
    with pytest.raises(ValidationError):
        _settings(**{field: value})


def test_policy_bootstrap_writes_only_canonical_readonly_policy_set(tmp_path):
    parent = tmp_path / "run"
    parent.mkdir(mode=0o700)
    raw = json.dumps(policy_payload(), indent=4).encode()
    encoded = base64.b64encode(raw).decode("ascii")
    decoded = decode_policy_environment(encoded)
    target = parent / "policy-set.json"
    materialized = materialize_policy(encoded, str(target.resolve()))
    assert materialized.policy_set_hash == decoded.policy_set_hash
    assert target.read_bytes() == materialized.canonical_bytes
    assert stat.S_IMODE(target.stat().st_mode) == 0o444
    assert load_policy_set(str(target.resolve())).policy_set_hash == materialized.policy_set_hash


@pytest.mark.parametrize("encoded", ["", "!!!!", "abcd=", "éééé"])
def test_policy_bootstrap_rejects_malformed_base64(encoded):
    with pytest.raises(StateUnavailable):
        decode_policy_environment(encoded)


def test_policy_bootstrap_rejects_wrong_target_or_public_parent(tmp_path):
    raw = json.dumps(policy_payload()).encode()
    encoded = base64.b64encode(raw).decode()
    with pytest.raises(StateUnavailable):
        materialize_policy(encoded, str((tmp_path / "wrong-name.json").resolve()))
    public = tmp_path / "public"
    public.mkdir(mode=0o777)
    public.chmod(0o777)
    with pytest.raises(StateUnavailable):
        materialize_policy(encoded, str((public / "policy-set.json").resolve()))


def test_production_compose_has_independent_phala_security_shape():
    project = Path(__file__).resolve().parents[1]
    compose = (project / "docker-compose.production.yml").read_text(encoding="utf-8")
    assert "METERING_POLICY_SET_B64" in compose
    assert "METERING_POLICY_SET_PATH: /run/compute-metering/policy-set.json" in compose
    assert "METERING_RATE_POLICY_B64" not in compose
    assert "METERING_CVM_ID:" in compose
    assert "METERING_DEPLOYMENT_INTENT_SHA256:" in compose
    assert "METERING_RELEASE_AUTHORITY_SHA256:" in compose
    assert "METERING_CEREMONY_NONCE:" in compose
    assert "METERING_QVL_MEASUREMENT_POLICY_SHA256:" in compose
    assert "@${METERING_IMAGE_DIGEST" in compose
    assert compose.count("network_mode: none") == 2
    assert "source: /var/run/dstack.sock" in compose
    assert "source: metering-state" in compose
    assert "read_only: true" in compose
    assert "cap_add:\n      - CHOWN" in compose
    assert "user: \"65532:65532\"" in compose
    assert "--private-key" not in compose
    assert "tinker-delegate" not in compose


def test_dockerfile_and_build_script_pin_reproducible_inputs():
    project = Path(__file__).resolve().parents[1]
    dockerfile = (project / "Dockerfile").read_text(encoding="utf-8")
    script = (project / "scripts" / "build-reproducible.sh").read_text(encoding="utf-8")
    assert dockerfile.count("python:3.12.13-slim-trixie@sha256:") == 2
    assert "ghcr.io/astral-sh/uv:0.11.28@sha256:" in dockerfile
    assert "uv sync --frozen --no-dev --no-editable" in dockerfile
    assert "--workers\", \"1" in dockerfile
    assert "--no-access-log" in dockerfile
    assert "SOURCE_DATE_EPOCH=1735689600" in script
    assert os.access(project / "scripts" / "build-reproducible.sh", os.X_OK)


def test_readme_uses_exact_claim_and_no_live_attestation_overclaim():
    project = Path(__file__).resolve().parents[1]
    readme = (project / "README.md").read_text(encoding="utf-8")
    assert "attested deterministic metering" in readme
    assert "not a provider-authoritative invoice" in readme.lower()
    assert "not live evidence" in readme.lower()
    assert "dnai.compute-metering-policy-set.v1" in readme
    assert "0x036cbd53842c5426634e7929541ec2318f3dcf7e" in readme
    assert "shared Tinker compose" in readme
