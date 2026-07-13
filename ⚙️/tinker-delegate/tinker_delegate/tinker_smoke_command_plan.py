"""Manifest-driven command plan for live Tinker SDK smoke validation.

The plan contains only public deployment identity, environment-variable names,
and command templates. It must never include Tinker project IDs, API keys,
runtime bearer tokens, RPC URLs, run IDs, checkpoint paths, or sample text.
"""

from __future__ import annotations

import json
import math
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


PLAN_VERSION = "tinker_smoke_command_plan/v1"
DEFAULT_REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_MANIFEST_PATH = DEFAULT_REPO_ROOT / "deployments" / "base-sepolia.json"
DEFAULT_COMPOSE_PATH = "docker-compose.tinker-funding-validation.phala.yaml"
NEW_COMPOSE_HASH_PLACEHOLDER = "0x<new-attested-compose-hash-after-project-config-redeploy>"


@dataclass(frozen=True)
class TinkerSmokeCommandPlan:
    ready: bool
    reasons: tuple[str, ...]
    warnings: tuple[str, ...]
    account_access_state: str
    manifest_path: str
    delegate_api_url: str
    current_compose_hash: str
    current_compose_approved: bool | None
    app_id: str
    os_image_hash: str
    encumbrance_contract_address: str
    encumbrance_rpc_env: str
    runtime_auth_env: str
    project_id_env: str
    base_url_env: str
    max_usd: float
    model: str
    rank: int
    output_path_template: str
    redeploy_argv: tuple[str, ...]
    verify_compose_argv: tuple[str, ...]
    approve_compose_argv: tuple[str, ...]
    encumbrance_preflight_argv: tuple[str, ...]
    client_config_install_argv: tuple[str, ...]
    smoke_argv: tuple[str, ...]
    redeploy_shell: str
    verify_compose_shell: str
    approve_compose_shell: str
    encumbrance_preflight_shell: str
    client_config_install_shell: str
    smoke_shell: str
    current_live_client_config: dict[str, Any]
    next_action: str

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "version": PLAN_VERSION,
            "ready": self.ready,
            "reasons": list(self.reasons),
            "warnings": list(self.warnings),
            "account_access_state": self.account_access_state,
            "manifest_path": self.manifest_path,
            "delegate_api_url": self.delegate_api_url,
            "current_compose_hash": self.current_compose_hash,
            "current_compose_approved": self.current_compose_approved,
            "next_compose_hash_placeholder": NEW_COMPOSE_HASH_PLACEHOLDER,
            "app_id": self.app_id,
            "os_image_hash": self.os_image_hash,
            "encumbrance_contract_address": self.encumbrance_contract_address,
            "encumbrance_rpc_env": self.encumbrance_rpc_env,
            "runtime_auth_env": self.runtime_auth_env,
            "project_id_env": self.project_id_env,
            "base_url_env": self.base_url_env,
            "max_usd": self.max_usd,
            "model": self.model,
            "rank": self.rank,
            "next_action": self.next_action,
            "output_path_template": self.output_path_template,
            "env_prerequisites": [
                f"{self.project_id_env} is optional SDK project metadata; set it only when Tinker supplies a project id",
                f"{self.runtime_auth_env} must be set in the operator shell; value is never printed",
                f"{self.encumbrance_rpc_env} must be set in the operator shell; value is never printed",
                "FOUNDRY_KEYSTORE_ACCOUNT must name an encrypted Foundry keystore account; never use a raw private key",
                f"{self.base_url_env} should be set only if Tinker/provider gives a non-default endpoint",
                "Live CVM must run source with GET/PUT /tinker/proxy/client-config before install can succeed",
            ],
            "current_live_client_config": self.current_live_client_config,
            "redeploy_argv": list(self.redeploy_argv),
            "verify_compose_argv": list(self.verify_compose_argv),
            "approve_compose_argv": list(self.approve_compose_argv),
            "encumbrance_preflight_argv": list(self.encumbrance_preflight_argv),
            "client_config_install_argv": list(self.client_config_install_argv),
            "smoke_argv": list(self.smoke_argv),
            "redeploy_shell": self.redeploy_shell,
            "verify_compose_shell": self.verify_compose_shell,
            "approve_compose_shell": self.approve_compose_shell,
            "encumbrance_preflight_shell": self.encumbrance_preflight_shell,
            "client_config_install_shell": self.client_config_install_shell,
            "smoke_shell": self.smoke_shell,
            "operator_note": (
                "Approve the currently attested compose hash before a governed smoke. TINKER_PROJECT_ID is optional "
                "in the official SDK; install it only if Tinker supplies one. Redeploy only when selecting new source, "
                "then attest and approve the new hash before smoke. "
                "Do not mark Tinker training real until the bounded receipt proves run/checkpoint/sample/cleanup."
            ),
            "raw_secret_egress": False,
        }


def build_tinker_smoke_command_plan(
    *,
    manifest_path: str | Path = DEFAULT_MANIFEST_PATH,
    compose_path: str = DEFAULT_COMPOSE_PATH,
    runtime_env_path: str = "../../.env",
    api_env_path: str = "../../.env",
    max_usd: float = 0.05,
    model: str = "Qwen/Qwen3-8B",
    rank: int = 32,
    output_path_template: str = "/tmp/dnai-tinker-smoke-project-id-$(date -u +%Y%m%dT%H%M%SZ).json",
    encumbrance_rpc_env: str = "BASE_SEPOLIA_RPC_URL",
    runtime_auth_env: str = "TINKER_RUNTIME_AUTH_TOKEN",
    project_id_env: str = "TINKER_PROJECT_ID",
    base_url_env: str = "TINKER_BASE_URL",
    account_access_state: str = "",
    env: Mapping[str, str] | None = None,
) -> TinkerSmokeCommandPlan:
    manifest_file = Path(manifest_path)
    manifest = _load_manifest(manifest_file)
    phala = _dict(manifest.get("phala"))
    contracts = _dict(manifest.get("contracts"))
    encumbrance = _dict(contracts.get("tinkerAccountEncumbrance"))
    smoke_evidence = _dict(phala.get("tinkerSdkSmokeEvidence"))
    latest_client_config_deploy = _dict(smoke_evidence.get("latestPinnedClientConfigInstallDeploy"))

    delegate_api_url = _str(_dict(phala.get("endpoints")).get("delegate"))
    current_compose_hash = _str(
        phala.get("composeHash")
        or phala.get("deployHelperComposeHash")
        or smoke_evidence.get("attestedComposeHash")
        or smoke_evidence.get("deployHelperComposeHash")
    )
    app_id = _str(phala.get("appId"))
    os_image_hash = _str(phala.get("osImageHash"))
    encumbrance_address = _str(encumbrance.get("address"))

    env_map = os.environ if env is None else env
    project_id_present = bool(_str(env_map.get(project_id_env)))
    base_url_present = bool(_str(env_map.get(base_url_env)))
    runtime_auth_present = bool(_str(env_map.get(runtime_auth_env)))
    rpc_present = bool(_str(env_map.get(encumbrance_rpc_env)))

    current_compose_approved = _current_compose_approval(
        current_compose_hash=current_compose_hash,
        encumbrance=encumbrance,
        smoke_evidence=smoke_evidence,
        latest_client_config_deploy=latest_client_config_deploy,
    )
    runtime_env = _dict(latest_client_config_deploy.get("runtimeEnv")) or _dict(
        smoke_evidence.get("runtimeEnv")
    )
    live_contains_project_id = runtime_env.get("containsTinkerProjectId") is True
    live_contains_base_url = runtime_env.get("containsTinkerBaseUrl") is True
    current_live_client_config = _bounded_client_config(
        smoke_evidence,
        latest_client_config_deploy=latest_client_config_deploy,
    )

    reasons: list[str] = []
    warnings: list[str] = []
    _require(reasons, delegate_api_url, "missing_delegate_api_url")
    _require(reasons, current_compose_hash, "missing_current_compose_hash")
    _require(reasons, app_id, "missing_phala_app_id")
    _require(reasons, os_image_hash, "missing_phala_os_image_hash")
    _require(reasons, encumbrance_address, "missing_tinker_encumbrance_contract")
    if not runtime_auth_present:
        reasons.append("missing_runtime_auth_env")
    if not rpc_present:
        reasons.append("missing_encumbrance_rpc_env")
    if current_compose_approved is False:
        reasons.append("current_compose_not_approved")
    if base_url_present and not live_contains_base_url:
        reasons.append("live_cvm_missing_tinker_base_url")
    if phala.get("osIsDev") is True:
        warnings.append("phala_cvm_still_reports_dev_os")
    if not live_contains_project_id:
        warnings.append("tinker_project_id_not_configured_optional")
    if live_contains_base_url:
        warnings.append("live_cvm_uses_custom_tinker_base_url")
    # Account access/billing gate (from `account-access-status`). Even with every
    # compose/policy check green, a blocked/gated account cannot run training, so
    # it is a hard readiness blocker; `unknown`/unchecked is only a warning.
    account_access_state = _str(account_access_state)
    if account_access_state in {"access_blocked_billing", "waitlist_or_gated", "payment_required"}:
        reasons.append("tinker_account_access_blocked")
    elif account_access_state in {"", "unknown"}:
        warnings.append("tinker_account_access_unverified")
    _check_spend_cap(reasons, max_usd=max_usd, encumbrance=encumbrance)

    redeploy_argv = (
        "node",
        "scripts/redeploy-phala-cvm.mjs",
        "--app-id",
        app_id or "<missing-app-id>",
        "--compose",
        compose_path,
        "--runtime-env",
        runtime_env_path,
        "--api-env",
        api_env_path,
        "--wait-seconds",
        "480",
        "--self-compose-hash-env",
        "TINKER_ENCUMBRANCE_COMPOSE_HASH",
        "--print-runtime-env-keys",
    )
    allowed_env_args = (
        "--allowed-env",
        "BASE_SEPOLIA_RPC_URL",
        "--allowed-env",
        "ORACLE_RUNTIME_AUTH_KEY_PATH",
        "--allowed-env",
        "TINKER_BROWSER_SESSION_KEY_PATH",
        "--allowed-env",
        "TINKER_DSTACK_KEY_PATH",
        "--allowed-env",
        "TINKER_ENCUMBRANCE_COMPOSE_HASH",
        "--allowed-env",
        "TINKER_FUNDING_RECEIPT_KEY_PATH",
        "--allowed-env",
        "TINKER_ORACLE_AUTH_KEY_PATH",
        "--allowed-env",
        "TINKER_PROXY_REQUIRE_DEPLOYMENT_POLICY",
        "--allowed-env",
        "TINKER_PROXY_REQUIRE_ISSUE_POLICY",
        "--allowed-env",
        "TINKER_RUNTIME_AUTH_KEY_PATH",
        "--allowed-env",
        "TINKER_RUNTIME_AUTH_TOKEN",
        "--allowed-env",
        "TINKER_RUN_METADATA_KEY_PATH",
    )
    if project_id_present:
        allowed_env_args += ("--allowed-env", project_id_env)
    if base_url_present:
        allowed_env_args += ("--allowed-env", base_url_env)

    verify_compose_argv = (
        "uv",
        "run",
        "python",
        "-m",
        "tinker_delegate.main",
        "verify-cvm-attestation",
        delegate_api_url or "<missing-delegate-api-url>",
        "--compose",
        compose_path,
        "--env-file",
        runtime_env_path,
        "--phala-raw-compose",
        *allowed_env_args,
        "--attested-compose-hash",
        NEW_COMPOSE_HASH_PLACEHOLDER,
        "--app-id",
        app_id or "<missing-app-id>",
        "--os-image-hash",
        os_image_hash or "<missing-os-image-hash>",
    )
    governed_compose_hash = _bytes32_arg(current_compose_hash)
    approve_compose_argv = (
        "cast",
        "send",
        encumbrance_address or "<missing-encumbrance-contract>",
        "approveComposeHash(bytes32)",
        governed_compose_hash,
        "--rpc-url",
        f"${{{encumbrance_rpc_env}}}",
        "--account",
        "${FOUNDRY_KEYSTORE_ACCOUNT}",
    )
    encumbrance_preflight_argv = (
        "uv",
        "run",
        "python",
        "-m",
        "tinker_delegate.main",
        "tinker-encumbrance-preflight",
        "--operation",
        "spend-tinker-compute",
        "--amount",
        _format_amount(max_usd),
        "--compose-hash",
        governed_compose_hash,
        "--contract-address",
        encumbrance_address or "<missing-encumbrance-contract>",
        "--rpc-url",
        f"${{{encumbrance_rpc_env}}}",
        "--required",
    )
    client_config_install_argv = (
        "uv",
        "run",
        "python",
        "-m",
        "tinker_delegate.main",
        "tinker-client-config",
        "--api-url",
        delegate_api_url or "<missing-delegate-api-url>",
        "--auth-token-env",
        runtime_auth_env,
        "--project-id-env",
        project_id_env,
        "--base-url-env",
        base_url_env,
        "--install",
    )
    smoke_argv = (
        "uv",
        "run",
        "python",
        "-m",
        "tinker_delegate.main",
        "tinker-smoke",
        "--api-url",
        delegate_api_url or "<missing-delegate-api-url>",
        "--auth-token-env",
        runtime_auth_env,
        "--max-usd",
        _format_amount(max_usd),
        "--model",
        model,
        "--rank",
        str(rank),
        "--compose-hash",
        governed_compose_hash,
        "--require-encumbrance",
        "--output",
        output_path_template,
    )
    next_action = _next_action(
        reasons=reasons,
        project_id_present=project_id_present,
        live_contains_project_id=live_contains_project_id,
    )

    return TinkerSmokeCommandPlan(
        ready=not reasons,
        reasons=tuple(sorted(set(reasons))),
        warnings=tuple(sorted(set(warnings))),
        account_access_state=account_access_state or "unverified",
        manifest_path=str(manifest_file),
        delegate_api_url=delegate_api_url,
        current_compose_hash=current_compose_hash,
        current_compose_approved=current_compose_approved,
        app_id=app_id,
        os_image_hash=os_image_hash,
        encumbrance_contract_address=encumbrance_address,
        encumbrance_rpc_env=encumbrance_rpc_env,
        runtime_auth_env=runtime_auth_env,
        project_id_env=project_id_env,
        base_url_env=base_url_env,
        max_usd=float(max_usd),
        model=model,
        rank=int(rank),
        output_path_template=output_path_template,
        redeploy_argv=redeploy_argv,
        verify_compose_argv=verify_compose_argv,
        approve_compose_argv=approve_compose_argv,
        encumbrance_preflight_argv=encumbrance_preflight_argv,
        client_config_install_argv=client_config_install_argv,
        smoke_argv=smoke_argv,
        redeploy_shell=_shell_command(
            redeploy_argv,
            env_placeholders={project_id_env} if project_id_present else set(),
        ),
        verify_compose_shell=_join_argv(verify_compose_argv, env_placeholders=set()),
        approve_compose_shell=_shell_command(
            approve_compose_argv,
            env_placeholders={encumbrance_rpc_env, "FOUNDRY_KEYSTORE_ACCOUNT"},
        ),
        encumbrance_preflight_shell=_shell_command(
            encumbrance_preflight_argv,
            env_placeholders={encumbrance_rpc_env},
        ),
        client_config_install_shell=_shell_command(
            client_config_install_argv,
            env_placeholders={project_id_env, runtime_auth_env},
        ),
        smoke_shell=_shell_command(smoke_argv, env_placeholders={runtime_auth_env}),
        current_live_client_config=current_live_client_config,
        next_action=next_action,
    )


def _load_manifest(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    body = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(body, dict):
        return {}
    return body


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _str(value: Any) -> str:
    return str(value or "").strip()


def _require(reasons: list[str], value: str, reason: str) -> None:
    if not value:
        reasons.append(reason)


def _bounded_client_config(
    smoke_evidence: dict[str, Any],
    *,
    latest_client_config_deploy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    latest_client_config_deploy = latest_client_config_deploy or {}
    receipt = _dict(smoke_evidence.get("smokeReceipt"))
    config = _dict(receipt.get("clientConfig"))
    installed = _dict(latest_client_config_deploy.get("clientConfigStatus"))
    runtime_env = _dict(latest_client_config_deploy.get("runtimeEnv")) or _dict(
        smoke_evidence.get("runtimeEnv")
    )
    return {
        "api_key_argument": _str(config.get("apiKeyArgument") or config.get("api_key_argument")),
        "project_id_argument": _str(config.get("projectIdArgument") or config.get("project_id_argument")),
        "base_url_argument": _str(config.get("baseUrlArgument") or config.get("base_url_argument")),
        "base_url_host_family": _str(config.get("baseUrlHostFamily") or config.get("base_url_host_family")),
        "contains_tinker_project_id": runtime_env.get("containsTinkerProjectId") is True,
        "contains_tinker_base_url": runtime_env.get("containsTinkerBaseUrl") is True,
        "sealed_project_id_configured": installed.get("projectIdConfigured") is True,
        "sealed_base_url_configured": installed.get("baseUrlConfigured") is True,
        "sealed_store_exists": installed.get("storeExists") is True,
    }


def _current_compose_approval(
    *,
    current_compose_hash: str,
    encumbrance: dict[str, Any],
    smoke_evidence: dict[str, Any],
    latest_client_config_deploy: dict[str, Any],
) -> bool | None:
    current = _normalize_hash(current_compose_hash)
    candidates = (
        (
            latest_client_config_deploy.get("liveComposeHash"),
            latest_client_config_deploy.get("composeApprovedOnChain"),
        ),
        (encumbrance.get("currentFundingComposeHash"), encumbrance.get("pendingComposeHashApproved")),
        (
            _dict(smoke_evidence.get("composeApproval")).get("composeHash"),
            _dict(smoke_evidence.get("composeApproval")).get("approved"),
        ),
    )
    for candidate_hash, approved in candidates:
        if current and _normalize_hash(candidate_hash) == current and isinstance(approved, bool):
            return approved
    return None


def _normalize_hash(value: Any) -> str:
    text = _str(value).lower()
    return text[2:] if text.startswith("0x") else text


def _bytes32_arg(value: str) -> str:
    normalized = _normalize_hash(value)
    if len(normalized) == 64 and all(ch in "0123456789abcdef" for ch in normalized):
        return f"0x{normalized}"
    return NEW_COMPOSE_HASH_PLACEHOLDER


def _check_spend_cap(reasons: list[str], *, max_usd: float, encumbrance: dict[str, Any]) -> None:
    if not math.isfinite(float(max_usd)) or float(max_usd) <= 0:
        reasons.append("invalid_max_usd")
        return
    max_spend_wei = encumbrance.get("maxSpendWei")
    units_per_usd_wei = encumbrance.get("policyUnitsPerUsdWei")
    if max_spend_wei is None or units_per_usd_wei is None:
        return
    try:
        max_units = int(max_spend_wei)
        units_per_usd = int(units_per_usd_wei)
    except (TypeError, ValueError):
        reasons.append("tinker_encumbrance_spend_cap_not_parseable")
        return
    if units_per_usd <= 0:
        reasons.append("tinker_encumbrance_policy_units_invalid")
        return
    requested_units = int(round(float(max_usd) * units_per_usd))
    if requested_units > max_units:
        reasons.append("requested_smoke_amount_exceeds_tinker_encumbrance_cap")


def _format_amount(value: float) -> str:
    return ("%f" % float(value)).rstrip("0").rstrip(".")


def _next_action(*, reasons: list[str], project_id_present: bool, live_contains_project_id: bool) -> str:
    infra_reasons = {
        "missing_delegate_api_url",
        "missing_current_compose_hash",
        "missing_phala_app_id",
        "missing_phala_os_image_hash",
        "missing_tinker_encumbrance_contract",
    }
    if "tinker_account_access_blocked" in reasons:
        return "resolve_tinker_account_activation"
    if any(reason in infra_reasons for reason in reasons):
        return "repair_deployment_manifest"
    if "current_compose_not_approved" in reasons:
        return "approve_current_compose"
    if project_id_present and not live_contains_project_id:
        return "seal_client_config"
    if any(reason.startswith("missing_") for reason in reasons):
        return "set_operator_env"
    if any(reason.startswith("requested_") or reason.startswith("tinker_encumbrance_") for reason in reasons):
        return "repair_encumbrance_policy"
    return "run_smoke_sequence"


def _shell_command(argv: tuple[str, ...], *, env_placeholders: set[str]) -> str:
    lines = [f'test -n "${{{name}:-}}" || (echo "missing {name}" >&2; exit 1)' for name in sorted(env_placeholders)]
    lines.append(_join_argv(argv, env_placeholders=env_placeholders))
    return "\n".join(lines)


def _join_argv(argv: tuple[str, ...], *, env_placeholders: set[str]) -> str:
    rendered: list[str] = []
    placeholders = {f"${{{name}}}" for name in env_placeholders}
    for arg in argv:
        if arg in placeholders:
            rendered.append(f'"{arg}"')
        else:
            rendered.append(_quote(arg))
    return " ".join(rendered)


def _quote(arg: str) -> str:
    if not arg:
        return "''"
    safe = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./:=+,-@<>$")
    if all(ch in safe for ch in arg):
        return arg
    return "'" + arg.replace("'", "'\"'\"'") + "'"
