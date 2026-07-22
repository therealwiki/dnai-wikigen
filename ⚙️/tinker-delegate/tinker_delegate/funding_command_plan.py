"""Manifest-driven command plan for capped Tinker funding validation.

The plan contains only public deployment identity, environment-variable names,
and argv/shell templates. It must never include card fields, runtime bearer
tokens, API keys, OTPs, cookies, or raw browser/session data.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any


PLAN_VERSION = "tinker_funding_command_plan/v1"
DEFAULT_REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_MANIFEST_PATH = DEFAULT_REPO_ROOT / "deployments" / "base-sepolia.json"
TINKER_MIN_ADD_BALANCE_USD = 10.0


@dataclass(frozen=True)
class FundingCommandPlan:
    ready: bool
    reasons: tuple[str, ...]
    warnings: tuple[str, ...]
    amount_dollars: float
    manifest_path: str
    delegate_api_url: str
    compose_hash: str
    app_id: str
    os_image_hash: str
    encumbrance_contract_address: str
    encumbrance_deployment_status: str
    encumbrance_rpc_env: str
    runtime_auth_env: str
    output_dir: str
    validation_id: str
    preflight_argv: tuple[str, ...]
    encumbrance_preflight_argv: tuple[str, ...]
    encumbrance_deploy_dry_run_argv: tuple[str, ...]
    encumbrance_deploy_broadcast_argv: tuple[str, ...]
    packet_argv: tuple[str, ...]
    preflight_shell: str
    encumbrance_preflight_shell: str
    encumbrance_deploy_dry_run_shell: str
    encumbrance_deploy_broadcast_shell: str
    packet_shell: str

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "version": PLAN_VERSION,
            "ready": self.ready,
            "reasons": list(self.reasons),
            "warnings": list(self.warnings),
            "amount_dollars": self.amount_dollars,
            "manifest_path": self.manifest_path,
            "delegate_api_url": self.delegate_api_url,
            "compose_hash": self.compose_hash,
            "app_id": self.app_id,
            "os_image_hash": self.os_image_hash,
            "encumbrance_contract_address": self.encumbrance_contract_address,
            "encumbrance_deployment_status": self.encumbrance_deployment_status,
            "encumbrance_rpc_env": self.encumbrance_rpc_env,
            "runtime_auth_env": self.runtime_auth_env,
            "output_dir": self.output_dir,
            "validation_id": self.validation_id,
            "env_prerequisites": [
                f"{self.runtime_auth_env} must be set in the operator shell; value is never printed",
                f"{self.encumbrance_rpc_env} must be set in the operator shell; value is never printed",
                "FOUNDRY_KEYSTORE_ACCOUNT must name an encrypted Foundry keystore account in .env or the operator shell",
            ],
            "preflight_argv": list(self.preflight_argv),
            "encumbrance_preflight_argv": list(self.encumbrance_preflight_argv),
            "encumbrance_deploy_dry_run_argv": list(self.encumbrance_deploy_dry_run_argv),
            "encumbrance_deploy_broadcast_argv": list(self.encumbrance_deploy_broadcast_argv),
            "packet_argv": list(self.packet_argv),
            "preflight_shell": self.preflight_shell,
            "encumbrance_preflight_shell": self.encumbrance_preflight_shell,
            "encumbrance_deploy_dry_run_shell": self.encumbrance_deploy_dry_run_shell,
            "encumbrance_deploy_broadcast_shell": self.encumbrance_deploy_broadcast_shell,
            "encumbrance_deploy_note": (
                "A missing TinkerAccountEncumbrance requires a new canonical seven-contract fresh release; "
                "these templates do not repair or overwrite one contract in a partial deployment ledger. "
                "Run the explicit BROADCAST=false full-suite dry-run first, then invoke BROADCAST=true only "
                "after reviewing the complete release. The canonical helper uses Foundry --account dev through "
                "the encrypted keystore and must never be given a raw private key."
            ),
            "packet_shell": self.packet_shell,
            "raw_secret_egress": False,
        }


def build_funding_command_plan(
    *,
    manifest_path: str | Path = DEFAULT_MANIFEST_PATH,
    amount_dollars: float = TINKER_MIN_ADD_BALANCE_USD,
    output_dir: str = "./funding-validation-packet",
    validation_id: str = "operator-real-card-validation",
    encumbrance_rpc_env: str = "BASE_SEPOLIA_RPC_URL",
    runtime_auth_env: str = "TINKER_RUNTIME_AUTH_TOKEN",
    include_reauth: bool = True,
    include_add_balance: bool = True,
) -> FundingCommandPlan:
    """Build the bounded operator command plan from deployment evidence."""

    amount = _normalize_amount(amount_dollars)
    manifest_file = Path(manifest_path)
    manifest = _load_manifest(manifest_file)
    phala = _dict(manifest.get("phala"))
    contracts = _dict(manifest.get("contracts"))
    encumbrance = _dict(contracts.get("tinkerAccountEncumbrance"))

    delegate_api_url = _str(_dict(phala.get("endpoints")).get("delegate"))
    funding_evidence = _dict(phala.get("fundingValidationEvidence"))
    compose_hash = _str(funding_evidence.get("attestedComposeHash") or phala.get("composeHash"))
    app_id = _str(phala.get("appId"))
    os_image_hash = _str(phala.get("osImageHash"))
    encumbrance_address = _str(encumbrance.get("address"))
    fresh_contract_suite_required = not encumbrance_address
    encumbrance_deployment_status = (
        "fresh_contract_suite_required" if fresh_contract_suite_required else "existing_contract_recorded"
    )

    reasons: list[str] = []
    warnings: list[str] = []
    _require(reasons, delegate_api_url, "missing_delegate_api_url")
    _require(reasons, compose_hash, "missing_phala_compose_hash")
    _require(reasons, app_id, "missing_phala_app_id")
    _require(reasons, os_image_hash, "missing_phala_os_image_hash")
    _require(reasons, encumbrance_address, "missing_tinker_encumbrance_contract")

    if phala.get("osIsDev") is True:
        warnings.append("phala_cvm_still_reports_dev_os")

    if encumbrance:
        _check_manifest_cap(
            reasons,
            amount=amount,
            max_add_balance_wei=encumbrance.get("maxAddBalanceWei"),
            policy_units_per_usd_wei=encumbrance.get("policyUnitsPerUsdWei"),
        )
        if encumbrance.get("emergencyHalted") is True:
            reasons.append("tinker_encumbrance_emergency_halted")
        approved = encumbrance.get("initialComposeHashApproved")
        if approved is False:
            reasons.append("tinker_encumbrance_initial_compose_hash_not_approved")

    common_identity = (
        "--api-url",
        delegate_api_url or "<missing-delegate-api-url>",
        "--amount",
        _format_amount(amount),
        "--compose-hash",
        compose_hash or "<missing-compose-hash>",
        "--app-id",
        app_id or "<missing-app-id>",
        "--os-image-hash",
        os_image_hash or "<missing-os-image-hash>",
    )
    preflight_argv = (
        "uv",
        "run",
        "python",
        "-m",
        "tinker_delegate.main",
        "funding-preflight",
        *common_identity,
        "--fetch-attestation",
        "--require-add-balance-endpoint",
    )
    encumbrance_preflight_argv = (
        "uv",
        "run",
        "python",
        "-m",
        "tinker_delegate.main",
        "tinker-encumbrance-preflight",
        "--operation",
        "add-balance" if include_add_balance else "add-payment-method",
        "--amount",
        _format_amount(amount),
        "--compose-hash",
        compose_hash or "<missing-compose-hash>",
        "--contract-address",
        encumbrance_address or "<missing-encumbrance-contract>",
        "--rpc-url",
        f"${{{encumbrance_rpc_env}}}",
        "--required",
    )
    deploy_helper = str(
        DEFAULT_REPO_ROOT
        / "⚙️"
        / "tinker-delegate"
        / "contracts"
        / "scripts"
        / "deploy-base-sepolia.sh"
    )
    encumbrance_deploy_dry_run_argv = (
        ("env", "BROADCAST=false", deploy_helper) if fresh_contract_suite_required else ()
    )
    encumbrance_deploy_broadcast_argv = (
        ("env", "BROADCAST=true", deploy_helper) if fresh_contract_suite_required else ()
    )
    packet_argv: tuple[str, ...] = (
        "uv",
        "run",
        "python",
        "-m",
        "tinker_delegate.main",
        "funding-validation-packet",
        "--output-dir",
        output_dir,
        *common_identity,
        "--validation-id",
        validation_id,
        "--fetch-attestation",
        "--require-add-balance-endpoint",
        "--run-card-attempt",
        "--prompt-card",
        "--require-encumbrance",
        "--encumbrance-contract-address",
        encumbrance_address or "<missing-encumbrance-contract>",
        "--encumbrance-rpc-url",
        f"${{{encumbrance_rpc_env}}}",
        "--encumbrance-compose-hash",
        compose_hash or "<missing-compose-hash>",
        "--auth-token-env",
        runtime_auth_env,
    )
    if include_reauth:
        packet_argv += ("--run-reauth-attempt",)
    if include_add_balance:
        packet_argv += ("--run-add-balance-attempt",)

    return FundingCommandPlan(
        ready=not reasons,
        reasons=tuple(sorted(set(reasons))),
        warnings=tuple(warnings),
        amount_dollars=amount,
        manifest_path=str(manifest_file),
        delegate_api_url=delegate_api_url,
        compose_hash=compose_hash,
        app_id=app_id,
        os_image_hash=os_image_hash,
        encumbrance_contract_address=encumbrance_address,
        encumbrance_deployment_status=encumbrance_deployment_status,
        encumbrance_rpc_env=encumbrance_rpc_env,
        runtime_auth_env=runtime_auth_env,
        output_dir=output_dir,
        validation_id=validation_id,
        preflight_argv=preflight_argv,
        encumbrance_preflight_argv=encumbrance_preflight_argv,
        encumbrance_deploy_dry_run_argv=encumbrance_deploy_dry_run_argv,
        encumbrance_deploy_broadcast_argv=encumbrance_deploy_broadcast_argv,
        packet_argv=packet_argv,
        preflight_shell=_shell_command(preflight_argv, env_placeholders=set()),
        encumbrance_preflight_shell=_shell_command(
            encumbrance_preflight_argv,
            env_placeholders={encumbrance_rpc_env},
        ),
        encumbrance_deploy_dry_run_shell=_join_argv(
            encumbrance_deploy_dry_run_argv,
            env_placeholders=set(),
        ),
        encumbrance_deploy_broadcast_shell=_join_argv(
            encumbrance_deploy_broadcast_argv,
            env_placeholders=set(),
        ),
        packet_shell=_shell_command(packet_argv, env_placeholders={encumbrance_rpc_env, runtime_auth_env}),
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


def _normalize_amount(value: float) -> float:
    amount = float(value)
    if not math.isfinite(amount) or amount <= 0:
        raise ValueError("amount must be finite and positive")
    if amount < TINKER_MIN_ADD_BALANCE_USD:
        raise ValueError("amount must be at least Tinker's $10 add-balance minimum")
    if not amount.is_integer():
        raise ValueError("amount must be a whole-dollar value")
    return amount


def _format_amount(value: float) -> str:
    return ("%f" % value).rstrip("0").rstrip(".")


def _check_manifest_cap(
    reasons: list[str],
    *,
    amount: float,
    max_add_balance_wei: Any,
    policy_units_per_usd_wei: Any,
) -> None:
    if max_add_balance_wei is None or policy_units_per_usd_wei is None:
        return
    try:
        max_units = int(max_add_balance_wei)
        units_per_usd = int(policy_units_per_usd_wei)
    except (TypeError, ValueError):
        reasons.append("tinker_encumbrance_cap_not_parseable")
        return
    if units_per_usd <= 0:
        reasons.append("tinker_encumbrance_policy_units_invalid")
        return
    requested_units = int(round(amount * units_per_usd))
    if requested_units > max_units:
        reasons.append("requested_amount_exceeds_tinker_encumbrance_cap")


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
    safe = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./:=+,-@")
    if all(ch in safe for ch in arg):
        return arg
    return "'" + arg.replace("'", "'\"'\"'") + "'"
