from __future__ import annotations

import pytest
from pydantic import ValidationError

from attestation_qvl.config import MAX_SERVER_PHASE_BUDGET_SECONDS, Settings
from tests.support import TOKEN


def test_uppercase_production_environment_is_loaded(monkeypatch, tmp_path):
    monkeypatch.setenv("QVL_RELEASE_POLICY_PATH", str((tmp_path / "policy.json").resolve()))
    monkeypatch.setenv("QVL_AUTH_TOKEN", TOKEN)
    monkeypatch.setenv("QVL_PCCS_URL", "https://pccs.phala.network")
    monkeypatch.setenv("QVL_MAX_CONCURRENCY", "7")
    monkeypatch.setenv("QVL_RATE_CAPACITY", "44")
    monkeypatch.setenv("QVL_RATE_REFILL_PER_SECOND", "1.25")
    monkeypatch.setenv("QVL_CHALLENGE_TTL_SECONDS", "45")

    settings = Settings()
    assert settings.release_policy_path.endswith("policy.json")
    assert settings.auth_token.get_secret_value() == TOKEN
    assert settings.pccs_url == "https://pccs.phala.network"
    assert settings.max_concurrency == 7
    assert settings.rate_capacity == 44
    assert settings.rate_refill_per_second == 1.25
    assert settings.challenge_ttl_seconds == 45
    assert settings.request_body_timeout_seconds == 5.0
    assert settings.verification_timeout_seconds == 20.0
    assert (
        settings.request_body_timeout_seconds + settings.verification_timeout_seconds
        <= MAX_SERVER_PHASE_BUDGET_SECONDS
    )
    assert not any("key" in name or "mnemonic" in name for name in Settings.model_fields)


def test_sequential_server_phase_budget_is_bounded(monkeypatch, tmp_path):
    monkeypatch.setenv("QVL_RELEASE_POLICY_PATH", str((tmp_path / "policy.json").resolve()))
    monkeypatch.setenv("QVL_AUTH_TOKEN", TOKEN)
    monkeypatch.setenv("QVL_REQUEST_BODY_TIMEOUT_SECONDS", "5.5")
    monkeypatch.setenv("QVL_VERIFICATION_TIMEOUT_SECONDS", "20")

    with pytest.raises(ValidationError, match="server phase budget"):
        Settings()


@pytest.mark.parametrize(
    ("token", "pccs"),
    [
        ("short", "https://pccs.phala.network"),
        ("x" * 31 + "\n", "https://pccs.phala.network"),
        ("x" * 31 + "é", "https://pccs.phala.network"),
        (TOKEN, "https://pccs.example"),
        (TOKEN, "https://127.0.0.1"),
        (TOKEN, "https://localhost"),
        (TOKEN, "https://pccs.phala.network:443"),
        (TOKEN, "https://pccs.phala.network/"),
        (TOKEN, "http://pccs.example"),
        (TOKEN, "https://user:pass@pccs.phala.network"),
        (TOKEN, "https://pccs.phala.network/path"),
        (TOKEN, "https://pccs.phala.network?query=yes"),
        (TOKEN, "https://pccs.phala.network#fragment"),
    ],
)
def test_secrets_and_pccs_origin_fail_closed(monkeypatch, tmp_path, token, pccs):
    monkeypatch.setenv("QVL_RELEASE_POLICY_PATH", str((tmp_path / "policy.json").resolve()))
    monkeypatch.setenv("QVL_AUTH_TOKEN", token)
    monkeypatch.setenv("QVL_PCCS_URL", pccs)
    with pytest.raises(ValidationError):
        Settings()


def test_recipient_bearers_load_as_optional_distinct_secret_domains(monkeypatch, tmp_path):
    monkeypatch.setenv("QVL_RELEASE_POLICY_PATH", str(tmp_path / "policy.json"))
    monkeypatch.setenv("QVL_AUTH_TOKEN", TOKEN)
    monkeypatch.setenv("QVL_ARTIFACT_RECIPIENT_AUTH_TOKEN", "artifact-recipient-token-0123456789abcdef")
    monkeypatch.setenv("QVL_ARENA_RECIPIENT_AUTH_TOKEN", "arena-recipient-token-0123456789abcdef")
    settings = Settings()
    assert settings.artifact_recipient_auth_token.get_secret_value().startswith("artifact-")
    assert settings.arena_recipient_auth_token.get_secret_value().startswith("arena-")
    assert "0123456789abcdef" not in repr(settings)
    monkeypatch.setenv("QVL_ARTIFACT_RECIPIENT_AUTH_TOKEN", "")
    assert Settings().artifact_recipient_auth_token is None


@pytest.mark.parametrize("token", [TOKEN, "short", "x" * 31 + "\n", "x" * 31 + "é"])
def test_recipient_bearer_must_be_valid_and_distinct_from_runtime(monkeypatch, tmp_path, token):
    monkeypatch.setenv("QVL_RELEASE_POLICY_PATH", str(tmp_path / "policy.json"))
    monkeypatch.setenv("QVL_AUTH_TOKEN", TOKEN)
    monkeypatch.setenv("QVL_ARTIFACT_RECIPIENT_AUTH_TOKEN", token)
    with pytest.raises(ValidationError):
        Settings()


def test_recipient_bearers_must_not_alias_each_other(monkeypatch, tmp_path):
    monkeypatch.setenv("QVL_RELEASE_POLICY_PATH", str(tmp_path / "policy.json"))
    monkeypatch.setenv("QVL_AUTH_TOKEN", TOKEN)
    monkeypatch.setenv("QVL_ARTIFACT_RECIPIENT_AUTH_TOKEN", "shared-recipient-token-0123456789abcdef")
    monkeypatch.setenv("QVL_ARENA_RECIPIENT_AUTH_TOKEN", "shared-recipient-token-0123456789abcdef")
    with pytest.raises(ValidationError):
        Settings()
