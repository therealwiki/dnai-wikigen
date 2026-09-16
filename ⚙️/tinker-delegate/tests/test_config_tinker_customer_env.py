"""Environment-name regression tests for the Tinker customer release gate."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from tinker_delegate.config import Settings


def test_documented_single_prefix_tinker_customer_environment_is_authoritative() -> None:
    authority_sha256 = "sha256:" + ("ab" * 32)
    environment = {
        "TINKER_CUSTOMER_ENABLED": "true",
        "TINKER_CUSTOMER_AUTHORITY_PATH": (
            "/run/dnai-authority/tinker-customer.json"
        ),
        "TINKER_CUSTOMER_AUTHORITY_SHA256": authority_sha256,
        "TINKER_CUSTOMER_STORE_PATH": "/data/tinker-customer/state.json",
        "TINKER_CUSTOMER_STORE_INTEGRITY_KEY": "s" * 32,
        "TINKER_CUSTOMER_STORE_INTEGRITY_KEY_PATH": (
            "tinker/customer_store_integrity"
        ),
        "TINKER_CUSTOMER_CREDENTIAL_SIGNING_KEY": "c" * 32,
        "TINKER_CUSTOMER_CREDENTIAL_KEY_PATH": "tinker/customer_credentials",
        "TINKER_CUSTOMER_SETTLEMENT_SIGNING_KEY": "e" * 32,
        "TINKER_CUSTOMER_SETTLEMENT_KEY_PATH": (
            "tinker/customer_settlement_evidence"
        ),
    }

    with patch.dict(os.environ, environment, clear=True):
        settings = Settings()

    assert settings.tinker_customer_enabled is True
    assert settings.tinker_customer_authority_path == environment[
        "TINKER_CUSTOMER_AUTHORITY_PATH"
    ]
    assert settings.tinker_customer_authority_sha256 == authority_sha256
    assert settings.tinker_customer_store_path == environment[
        "TINKER_CUSTOMER_STORE_PATH"
    ]
    assert settings.tinker_customer_store_integrity_key == "s" * 32
    assert (
        settings.tinker_customer_store_integrity_key_path
        == "tinker/customer_store_integrity"
    )
    assert settings.tinker_customer_credential_signing_key == "c" * 32
    assert (
        settings.tinker_customer_credential_key_path
        == "tinker/customer_credentials"
    )
    assert settings.tinker_customer_settlement_signing_key == "e" * 32
    assert (
        settings.tinker_customer_settlement_key_path
        == "tinker/customer_settlement_evidence"
    )


def test_accidental_double_prefix_does_not_enable_customer_runtime() -> None:
    with patch.dict(
        os.environ,
        {
            "TINKER_TINKER_CUSTOMER_ENABLED": "true",
            "TINKER_TINKER_CUSTOMER_AUTHORITY_SHA256": (
                "sha256:" + ("cd" * 32)
            ),
        },
        clear=True,
    ):
        settings = Settings()

    assert settings.tinker_customer_enabled is False
    assert settings.tinker_customer_authority_sha256 == ""


def test_missing_or_explicit_false_customer_marker_is_disabled() -> None:
    with patch.dict(os.environ, {}, clear=True):
        assert Settings().tinker_customer_enabled is False
    with patch.dict(
        os.environ,
        {"TINKER_CUSTOMER_ENABLED": "false"},
        clear=True,
    ):
        assert Settings().tinker_customer_enabled is False


def test_empty_customer_marker_is_invalid_instead_of_enabling_runtime() -> None:
    with patch.dict(
        os.environ,
        {"TINKER_CUSTOMER_ENABLED": ""},
        clear=True,
    ), pytest.raises(ValidationError):
        Settings()


def test_python_field_names_remain_valid_for_dependency_injection() -> None:
    settings = Settings(
        tinker_customer_enabled=True,
        tinker_customer_authority_path="/private/authority.json",
        tinker_customer_authority_sha256="sha256:" + ("ef" * 32),
        tinker_customer_store_path="/private/state.json",
    )

    assert settings.tinker_customer_enabled is True
    assert settings.tinker_customer_authority_path == "/private/authority.json"
    assert settings.tinker_customer_store_path == "/private/state.json"
