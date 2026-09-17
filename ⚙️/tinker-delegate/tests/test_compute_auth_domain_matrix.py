"""Public Compute credentials cannot cross into the legacy paid-proxy domain.

The shared API fixture uses signed wallet challenges, the real file-backed
Compute store, device registration, and X25519/AES-GCM credential delivery.
It is composed here, not inherited, so this file collects only its own matrix.
Only the upstream SDK client boundary is replaced with a zero-call sentinel.
"""

from pathlib import Path
from unittest.mock import patch

import pytest

from tests import test_api_compute as compute_api_fixture
from tinker_delegate import api
from tinker_delegate.tinker_proxy import issue_proxy_token, verify_proxy_token


@pytest.fixture
def auth_domains():
    fixture = compute_api_fixture.ComputeApiTest(methodName="runTest")
    fixture.setUp()
    try:
        api.settings = api.settings.model_copy(
            update={
                "allow_tinker_train_endpoint": True,
                "allow_tinker_smoke_endpoint": True,
                "proxy_jwt_key": "55" * 32,
                "proxy_token_store_key": "66" * 32,
                "proxy_token_store_path": str(
                    Path(fixture.temporary.name) / "proxy-tokens.enc"
                ),
            }
        )
        with (
            patch(
                "tinker_delegate.tinker_training._create_service_client",
                side_effect=AssertionError("training provider must not be called"),
            ) as training_provider,
            patch(
                "tinker_delegate.tinker_smoke._create_service_client",
                side_effect=AssertionError("smoke provider must not be called"),
            ) as smoke_provider,
        ):
            wallet_token = fixture._compute_token()
            wallet_headers = {"Authorization": f"Bearer {wallet_token}"}
            project_id = fixture._project(wallet_headers)
            issued, device_token, _private_key = fixture._credential(
                project_id, wallet_headers
            )
            assert issued["capsule"]["plaintext_token_returned"] is False

            # Positive controls: these are live, correctly scoped credentials,
            # not malformed tokens that would be rejected in every domain.
            for token in (wallet_token, device_token):
                own_domain = fixture.client.get(
                    f"/compute/projects/{project_id}/jobs",
                    headers={"Authorization": f"Bearer {token}"},
                )
                assert own_domain.status_code == 200, own_domain.text
                assert own_domain.json()["jobs"] == []

            _claims, proxy_token = issue_proxy_token(
                api.settings,
                subject="auth-domain-matrix-agent",
                scopes=["tinker:train", "tinker:smoke"],
                ttl_seconds=300,
                scope_limits={
                    "tinker:train": {"max_amount_usd": 0.05},
                    "tinker:smoke": {"max_amount_usd": 0.05},
                },
            )
            for scope in ("tinker:train", "tinker:smoke"):
                assert verify_proxy_token(
                    api.settings, proxy_token, required_scope=scope
                )["valid"] is True

            yield fixture.client, project_id, {
                "wallet": wallet_token,
                "device": device_token,
                "proxy": proxy_token,
            }

            training_provider.assert_not_called()
            smoke_provider.assert_not_called()
    finally:
        fixture.client.close()
        fixture.tearDown()


@pytest.mark.parametrize("token_kind", ["wallet", "device"])
@pytest.mark.parametrize("legacy_route", ["/tinker/train", "/tinker/smoke"])
def test_public_compute_tokens_cannot_authorize_legacy_paid_routes(
    auth_domains, token_kind, legacy_route
):
    client, _project_id, tokens = auth_domains
    response = client.post(
        legacy_route,
        headers={"Authorization": f"Bearer {tokens[token_kind]}"},
        json={"max_usd": 0.05},
    )

    assert response.status_code == 403, response.text
    assert response.json()["detail"] == "invalid proxy token signature"
    assert tokens[token_kind] not in response.text


@pytest.mark.parametrize(
    "method, route, payload",
    [
        ("GET", "/compute/projects", None),
        ("GET", "/compute/projects/{project_id}/jobs", None),
        (
            "POST",
            "/compute/projects/{project_id}/jobs",
            {
                "name": "cross-domain-must-not-reserve",
                "operation": "inference",
                "model": "qwen3_8b",
                "recipe": "qwen3_8b_bounded",
                "max_credits": 10,
                "result_policy": "bounded_summary_receipt",
                "environment_version": "env_v1",
            },
        ),
    ],
    ids=["wallet-console-read", "job-principal-read", "job-principal-create"],
)
def test_valid_proxy_jwt_cannot_authorize_compute_routes(
    auth_domains, method, route, payload
):
    client, project_id, tokens = auth_domains
    response = client.request(
        method,
        route.format(project_id=project_id),
        headers={
            "Authorization": f"Bearer {tokens['proxy']}",
            "Idempotency-Key": "cross-domain-job-create-0001",
        },
        json=payload,
    )

    assert response.status_code == 401, response.text
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert tokens["proxy"] not in response.text
    # A forbidden mutation must not create a job or reserve project credits.
    jobs = client.get(
        f"/compute/projects/{project_id}/jobs",
        headers={"Authorization": f"Bearer {tokens['wallet']}"},
    )
    assert jobs.status_code == 200, jobs.text
    assert jobs.json()["jobs"] == []
    balance = client.get(
        f"/compute/projects/{project_id}/balance",
        headers={"Authorization": f"Bearer {tokens['wallet']}"},
    )
    assert balance.status_code == 200, balance.text
    assert balance.json()["reserved_credits"] == 0
    assert balance.json()["available_credits"] == 0
