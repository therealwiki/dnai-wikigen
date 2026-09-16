"""CLI entrypoint for tinker-delegate automation."""
import argparse
import asyncio
import getpass
import hashlib
import json
import os
import time
import sys
import termios
import tty
from pathlib import Path
from typing import Any

from tinker_delegate.api_key_store import build_api_key_store
from tinker_delegate.config import Settings
from tinker_delegate.oracle_client import OracleClient
from tinker_delegate.redaction import redact_text
from tinker_delegate.runtime_hardening import disable_core_dumps
from tinker_delegate.runtime_state import get_runtime_state, reset_runtime_state, update_runtime_state
from tinker_delegate.signup import AuthAccessBlockedError


def _render_bounded_json(
    payload: Any,
    *,
    forbidden_values: tuple[str, ...] = (),
    public_hex_fields: tuple[str, ...] = (),
    public_decimal_fields: tuple[str, ...] = (),
) -> str:
    """Render JSON only if it does not contain obvious secret-shaped material."""
    rendered = json.dumps(payload, indent=2, default=str)
    redaction_payload = _mask_public_fields(
        payload,
        public_hex_fields=public_hex_fields,
        public_decimal_fields=public_decimal_fields,
    )
    redaction_rendered = json.dumps(redaction_payload, indent=2, default=str)
    if redact_text(redaction_rendered) != redaction_rendered:
        raise ValueError("bounded CLI output contains secret-like material")
    for value in forbidden_values:
        if value and len(value) >= 4 and value in rendered:
            raise ValueError("bounded CLI output contains submitted secret material")
    return rendered


def _mask_public_fields(
    payload: Any,
    *,
    public_hex_fields: tuple[str, ...],
    public_decimal_fields: tuple[str, ...],
) -> Any:
    """Mask explicitly public fields before generic secret-shape checks."""

    if not public_hex_fields and not public_decimal_fields:
        return payload
    hex_allowed = set(public_hex_fields)
    decimal_allowed = set(public_decimal_fields)
    if isinstance(payload, dict):
        return {
            key: (
                f"__public_hex_{key}__"
                if key in hex_allowed and isinstance(value, str) and value.startswith("0x")
                else (
                    f"__public_decimal_{key}__"
                    if key in decimal_allowed
                    and (
                        isinstance(value, int)
                        or (isinstance(value, str) and value.isdecimal())
                    )
                    else _mask_public_fields(
                        value,
                        public_hex_fields=public_hex_fields,
                        public_decimal_fields=public_decimal_fields,
                    )
                )
            )
            for key, value in payload.items()
        }
    if isinstance(payload, list):
        return [
            _mask_public_fields(
                item,
                public_hex_fields=public_hex_fields,
                public_decimal_fields=public_decimal_fields,
            )
            for item in payload
        ]
    return payload


def _emit_bounded_json(
    payload: Any,
    *,
    output_path: str = "",
    forbidden_values: tuple[str, ...] = (),
    public_hex_fields: tuple[str, ...] = (),
    public_decimal_fields: tuple[str, ...] = (),
) -> None:
    rendered = _render_bounded_json(
        payload,
        forbidden_values=forbidden_values,
        public_hex_fields=public_hex_fields,
        public_decimal_fields=public_decimal_fields,
    )
    if output_path:
        Path(output_path).write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)


def _write_secret_text(path: str, value: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(value)
        handle.write("\n")


def _receipt_or_raise(response: dict[str, Any] | Any) -> dict[str, Any]:
    if hasattr(response, "model_dump"):
        response = response.model_dump(mode="json")
    receipt = response.get("attempt_record") if isinstance(response, dict) else None
    if not isinstance(receipt, dict):
        raise ValueError("bounded receipt output requested, but response has no attempt_record")
    proxy_auth_context = response.get("proxy_auth_context")
    if isinstance(proxy_auth_context, dict):
        receipt = dict(receipt)
        receipt["proxy_auth_context"] = proxy_auth_context
    return receipt


def _api_endpoint(api_url: str, path: str) -> str:
    return api_url.rstrip("/") + path


def _runtime_auth_headers(auth_token_env: str) -> dict[str, str]:
    token = os.environ.get(auth_token_env, "")
    return {"Authorization": f"Bearer {token}"} if token else {}


def _masked_prompt(prompt: str) -> str:
    """Read a secret field while echoing one mask character per typed char."""

    stdin = sys.stdin
    stdout = sys.stdout
    if not stdin.isatty() or not stdout.isatty():
        return getpass.getpass(prompt)

    fd = stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    chars: list[str] = []
    stdout.write(prompt)
    stdout.flush()
    try:
        tty.setraw(fd)
        return _read_masked_prompt_chars(lambda: stdin.read(1), stdout.write, stdout.flush, chars)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


def _read_masked_prompt_chars(read_char, write, flush, chars: list[str] | None = None) -> str:
    """Read raw prompt chars and echo masks; split out for deterministic tests."""

    chars = chars if chars is not None else []
    while True:
        ch = read_char()
        if ch in ("\r", "\n"):
            write("\r\n")
            flush()
            return "".join(chars)
        if ch == "\x03":
            raise KeyboardInterrupt
        if ch == "\x04":
            raise EOFError
        if ch in ("\x7f", "\b"):
            if chars:
                chars.pop()
                write("\b \b")
                flush()
            continue
        if ch in ("\x1b", "\x00"):
            continue
        chars.append(ch)
        write("*")
        flush()


def _prompt_billing_card_payload(prompt_fn=_masked_prompt) -> dict[str, str]:
    """Read card fields without placing them in shell history or argv."""
    fields = (
        ("card_number", "Card number", ""),
        ("exp_month", "Expiration month", ""),
        ("exp_year", "Expiration year", ""),
        ("cvc", "CVC", ""),
        ("cardholder_name", "Cardholder name", ""),
        ("address_line1", "Billing address line 1 (optional)", ""),
        ("address_city", "Billing city (optional)", ""),
        ("address_state", "Billing state/region (optional)", ""),
        ("address_postal", "Billing postal code (optional)", ""),
        ("address_country", "Billing country", "US"),
    )
    payload = {}
    for key, label, default in fields:
        suffix = f" [{default}]" if default else ""
        value = prompt_fn(f"{label}{suffix}: ").strip()
        payload[key] = value or default
    return payload


def _add_encumbrance_gate_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--require-encumbrance",
        action="store_true",
        help="Require live TinkerAccountEncumbrance policy approval before prompting for card details",
    )
    parser.add_argument(
        "--encumbrance-contract-address",
        default="",
        help="TinkerAccountEncumbrance address; defaults to TINKER_ENCUMBRANCE_CONTRACT_ADDRESS",
    )
    parser.add_argument(
        "--encumbrance-rpc-url",
        default="",
        help="JSON-RPC URL for encumbrance reads; defaults to TINKER_ENCUMBRANCE_RPC_URL or TINKER_CHAIN_RPC_URL",
    )
    parser.add_argument(
        "--encumbrance-compose-hash",
        default="",
        help="Compose hash to check against TinkerAccountEncumbrance; defaults to --compose-hash or TINKER_ENCUMBRANCE_COMPOSE_HASH",
    )


def _validate_prompt_billing_policy(
    args,
    settings: Settings | None = None,
    *,
    amount_dollars: float | None = None,
) -> None:
    """Require a concrete deployed attestation policy for prompt-based card entry."""
    if args.allow_local_attestation:
        return
    missing = [
        flag
        for flag, attr in (
            ("--compose-hash", "compose_hash"),
            ("--app-id", "app_id"),
            ("--os-image-hash", "os_image_hash"),
        )
        if not getattr(args, attr, "")
    ]
    if missing:
        joined = ", ".join(missing)
        command = getattr(args, "command", "prompt billing")
        raise ValueError(
            f"{command} requires deployed billing attestation expectations "
            f"({joined}) unless --allow-local-attestation is set for local development"
        )
    if getattr(args, "require_encumbrance", False):
        _validate_prompt_encumbrance_policy(args, settings or Settings(), amount_dollars=amount_dollars)


def _validate_prompt_encumbrance_policy(
    args,
    settings: Settings,
    *,
    amount_dollars: float | None,
) -> None:
    """Fail closed before card prompts unless the live encumbrance permits billing."""
    from tinker_delegate.tinker_encumbrance import (
        TinkerEncumbranceError,
        TinkerOperationKind,
        preflight_tinker_operation,
    )

    compose_hash = (
        getattr(args, "encumbrance_compose_hash", "")
        or getattr(args, "compose_hash", "")
        or getattr(settings, "encumbrance_compose_hash", "")
    )
    common_kwargs = {
        "compose_hash": compose_hash,
        "contract_address": getattr(args, "encumbrance_contract_address", ""),
        "rpc_url": getattr(args, "encumbrance_rpc_url", ""),
        "required": True,
    }
    try:
        checks = [
            preflight_tinker_operation(
                settings,
                operation_kind=TinkerOperationKind.ADD_PAYMENT_METHOD,
                amount_dollars=0,
                **common_kwargs,
            )
        ]
        if amount_dollars is not None:
            checks.append(
                preflight_tinker_operation(
                    settings,
                    operation_kind=TinkerOperationKind.ADD_BALANCE,
                    amount_dollars=amount_dollars,
                    **common_kwargs,
                )
            )
    except TinkerEncumbranceError as exc:
        raise ValueError(f"Tinker encumbrance policy check failed: {redact_text(exc)}") from exc

    denied = [check for check in checks if not check.allowed]
    if denied:
        reasons = ", ".join(sorted({check.reason for check in denied}))
        raise ValueError(f"Tinker encumbrance policy denied prompt billing: {reasons}")


def _wait_for_oracle(settings: Settings) -> None:
    """Wait for public liveness and authenticated mailbox readiness."""
    oracle = OracleClient(settings)
    deadline = time.time() + settings.bootstrap_oracle_timeout

    while time.time() < deadline:
        try:
            oracle.health()
            oracle.get_email_status()
            print("[serve] oracle ready")
            return
        except Exception:
            # Do not reflect an HTTP body that could contain provider or
            # mailbox state into delegate logs.
            print("[serve] oracle not ready yet")

        time.sleep(settings.bootstrap_oracle_poll_interval)

    raise RuntimeError(
        f"oracle did not become ready within {settings.bootstrap_oracle_timeout}s"
    )


async def _ensure_api_key(settings: Settings) -> None:
    """Load or bootstrap the Tinker API key before serving."""
    if os.environ.get("TINKER_API_KEY"):
        print("[serve] using TINKER_API_KEY from environment")
        update_runtime_state(
            api_key_available=True,
            api_key_source="environment",
            bootstrap_attempted=False,
            bootstrap_success=False,
            bootstrap_error="",
            bootstrap_error_kind="",
            last_bootstrap_attempt_record=None,
        )
        return

    store = build_api_key_store(settings)
    if store.exists():
        try:
            api_key = store.load()
        except Exception as exc:
            raise RuntimeError(f"failed to load stored API key: {redact_text(exc)}") from exc
        if api_key:
            print(f"[serve] loaded stored API key from {settings.api_key_store_path}")
            update_runtime_state(
                api_key_available=True,
                api_key_source="encrypted_store",
                bootstrap_attempted=False,
                bootstrap_success=False,
                bootstrap_error="",
                bootstrap_error_kind="",
                last_bootstrap_attempt_record=None,
            )
            return

    if not settings.bootstrap_signup:
        print("[serve] no Tinker API key configured or stored")
        update_runtime_state(
            api_key_available=False,
            api_key_source="none",
            bootstrap_attempted=False,
            bootstrap_success=False,
            bootstrap_error="",
            bootstrap_error_kind="",
            last_bootstrap_attempt_record=None,
        )
        return

    _wait_for_oracle(settings)
    print("[serve] no API key found, running signup bootstrap...")
    from tinker_delegate.signup import signup

    update_runtime_state(
        api_key_available=False,
        api_key_source="bootstrap",
        bootstrap_attempted=True,
        bootstrap_success=False,
        bootstrap_error="",
        bootstrap_error_kind="",
        last_bootstrap_attempt_record=None,
    )

    result = await signup(settings)
    if not result.get("stored"):
        update_runtime_state(
            api_key_available=False,
            api_key_source="bootstrap",
            bootstrap_attempted=True,
            bootstrap_success=False,
            bootstrap_error="signup bootstrap did not store an API key",
            bootstrap_error_kind=str(
                result.get("attempt_record", {}).get("outcome", "bootstrap_error")
            ),
            last_bootstrap_attempt_record=result.get("attempt_record"),
        )
        raise RuntimeError("signup bootstrap did not store an API key")

    print(f"[serve] bootstrap complete, API key stored at {settings.api_key_store_path}")
    update_runtime_state(
        api_key_available=True,
        api_key_source="bootstrap",
        bootstrap_attempted=True,
        bootstrap_success=True,
        bootstrap_error="",
        bootstrap_error_kind="",
        last_bootstrap_attempt_record=result.get("attempt_record"),
    )


def _bootstrap_error_kind_from_runtime(exc: Exception) -> str:
    """Preserve bounded bootstrap attempt outcomes when startup catches failures."""

    runtime = get_runtime_state()
    record = runtime.get("last_bootstrap_attempt_record")
    if isinstance(record, dict):
        outcome = record.get("outcome")
        if outcome:
            return str(outcome)
    if isinstance(exc, AuthAccessBlockedError):
        return "auth_access_blocked"
    return "bootstrap_error"


def cli():
    disable_core_dumps()
    parser = argparse.ArgumentParser(description="Tinker delegate — automated account management")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("check", help="Check oracle health and email readiness")
    sub.add_parser("signup", help="Full signup: auth → onboarding → API key")
    sub.add_parser("signin", help="Sign in to existing account")
    sub.add_parser("reauth", help="Refresh Tinker auth through OTP and return bounded receipt")
    selector_map_p = sub.add_parser(
        "selector-map",
        help="Print the bounded Tinker selector/frame/auth-flow map",
    )
    selector_map_p.add_argument(
        "--summary-only",
        action="store_true",
        help="Omit concrete selectors and print only family names/counts/evidence",
    )
    selector_map_p.add_argument("--output", default="", help="Optional output path for bounded JSON")
    selector_probe_p = sub.add_parser(
        "selector-probe",
        help="Read-only bounded probe of current browser pages/frames against selector-map",
    )
    selector_probe_p.add_argument(
        "--no-local-browser-fallback",
        action="store_true",
        help="Fail if the configured remote browser is unavailable instead of launching local Chromium",
    )
    selector_probe_p.add_argument("--output", default="", help="Optional output path for bounded JSON")
    browser_readiness_p = sub.add_parser(
        "browser-readiness",
        help="Bounded readiness diagnostics for browser-control endpoints",
    )
    browser_readiness_p.add_argument("--output", default="", help="Optional output path for bounded JSON")
    synthetic_reward_p = sub.add_parser(
        "synthetic-private-reward-demo",
        help="Run a bounded synthetic hidden-dataset private reward demo",
    )
    synthetic_reward_p.add_argument(
        "--candidate",
        action="append",
        default=[],
        help="Candidate keyword to query; repeat for multiple candidates",
    )
    synthetic_reward_p.add_argument("--output", default="", help="Optional output path for bounded JSON")
    dp_reward_p = sub.add_parser(
        "dp-bounded-reward-demo",
        help="Run a bounded DP-budget private reward demo (release then fail-closed exhaustion)",
    )
    dp_reward_p.add_argument(
        "--candidate", action="append", default=[],
        help="Candidate keyword to query; repeat for multiple candidates",
    )
    dp_reward_p.add_argument("--max-epsilon", type=float, default=1.0, help="Total DP epsilon budget")
    dp_reward_p.add_argument("--epsilon-per-query", type=float, default=0.4, help="Epsilon spent per reward query")
    dp_reward_p.add_argument("--output", default="", help="Optional output path for bounded JSON")

    thresholdout_demo_p = sub.add_parser(
        "thresholdout-demo",
        help="Run a bounded Thresholdout DP-noised reusable-holdout demo (free-track vs. spend-on-divergence)",
    )
    thresholdout_demo_p.add_argument("--max-epsilon", type=float, default=1.5, help="Total DP epsilon budget")
    thresholdout_demo_p.add_argument("--output", default="", help="Optional output path for bounded JSON")
    denoising_reward_p = sub.add_parser(
        "denoising-private-reward-demo",
        help="Run a bounded denoising hidden-holdout private reward demo (candidate programs via sandbox)",
    )
    denoising_reward_p.add_argument("--output", default="", help="Optional output path for bounded JSON")
    denoising_sealed_p = sub.add_parser(
        "denoising-sealed-dataset-demo",
        help=(
            "Seal the denoising dataset, fetch+decrypt it in-boundary, then run the "
            "bounded reward loop over the decrypted cells (public_benchmark label)"
        ),
    )
    denoising_sealed_p.add_argument("--output", default="", help="Optional output path for bounded JSON")
    bio_assay_qc_reward_p = sub.add_parser(
        "bio-assay-qc-reward-demo",
        help="Run a bounded assay-QC program private reward demo (candidate programs via sandbox)",
    )
    bio_assay_qc_reward_p.add_argument("--output", default="", help="Optional output path for bounded JSON")
    policy_gate_p = sub.add_parser(
        "policy-gate",
        help="Evaluate a deterministic bounded corpus policy gate",
    )
    policy_gate_p.add_argument(
        "--request-json",
        default="",
        help="Path to one AccessRequest JSON payload for single-corpus evaluation",
    )
    policy_gate_p.add_argument(
        "--policy-json",
        default="",
        help="Path to one CorpusPolicy JSON payload for single-corpus evaluation",
    )
    policy_gate_p.add_argument(
        "--turn-json",
        default="",
        help="Path to a coordination Turn JSON payload for fan-out evaluation",
    )
    policy_gate_p.add_argument(
        "--policies-json",
        default="",
        help="Path to a JSON object mapping corpus refs to CorpusPolicy payloads",
    )
    policy_gate_p.add_argument("--output", default="", help="Optional output path for bounded JSON")
    consent_decision_p = sub.add_parser(
        "consent-decision",
        help="Apply a source-modeled owner consent decision and emit a bounded receipt",
    )
    consent_decision_p.add_argument(
        "--state-json",
        required=True,
        help="Path to a coordination state JSON payload",
    )
    consent_decision_p.add_argument(
        "--decision-json",
        required=True,
        help="Path to a consent decision JSON payload",
    )
    consent_decision_p.add_argument(
        "--now",
        type=int,
        default=0,
        help="Deterministic timestamp for expiry checks",
    )
    consent_decision_p.add_argument(
        "--require-signature",
        action="store_true",
        help="Fail closed unless the decision JSON carries a verified owner signature",
    )
    consent_decision_p.add_argument(
        "--expected-signer",
        default="",
        help="Optional expected owner signer address; omitted only verifies the declared signer",
    )
    consent_decision_p.add_argument("--output", default="", help="Optional output path for bounded JSON")
    tinker_proxy_status_p = sub.add_parser(
        "tinker-proxy-status",
        help="Return bounded sealed Tinker proxy/client configuration status",
    )
    tinker_proxy_status_p.add_argument(
        "--api-url",
        default="",
        help="Optional deployed Tinker delegate API base URL; omitted inspects local process settings",
    )
    tinker_proxy_status_p.add_argument(
        "--auth-token-env",
        default="TINKER_RUNTIME_AUTH_TOKEN",
        help="Environment variable containing delegate runtime or proxy bearer token for --api-url",
    )
    tinker_proxy_status_p.add_argument("--output", default="", help="Optional output path for bounded JSON")
    tinker_client_config_p = sub.add_parser(
        "tinker-client-config",
        help="Return or seal bounded Tinker SDK client configuration",
    )
    tinker_client_config_p.add_argument(
        "--api-url",
        default="",
        help="Optional deployed Tinker delegate API base URL; omitted reads/writes local sealed config",
    )
    tinker_client_config_p.add_argument(
        "--auth-token-env",
        default="TINKER_RUNTIME_AUTH_TOKEN",
        help="Environment variable containing delegate runtime bearer token for --api-url",
    )
    tinker_client_config_p.add_argument(
        "--install",
        action="store_true",
        help="Seal project/base-url values from environment variables; omitted returns bounded status",
    )
    tinker_client_config_p.add_argument(
        "--project-id-env",
        default="TINKER_PROJECT_ID",
        help="Environment variable containing the Tinker project ID to seal",
    )
    tinker_client_config_p.add_argument(
        "--base-url-env",
        default="TINKER_BASE_URL",
        help="Environment variable containing optional Tinker base URL to seal",
    )
    tinker_client_config_p.add_argument("--output", default="", help="Optional output path for bounded JSON")
    tinker_proxy_policy_p = sub.add_parser(
        "tinker-proxy-issue-policy",
        help="Return or install bounded hash-only Tinker proxy issue policy",
    )
    tinker_proxy_policy_p.add_argument(
        "--api-url",
        default="",
        help="Optional deployed Tinker delegate API base URL; omitted reads/writes local settings",
    )
    tinker_proxy_policy_p.add_argument(
        "--auth-token-env",
        default="TINKER_RUNTIME_AUTH_TOKEN",
        help="Environment variable containing delegate runtime bearer token for --api-url",
    )
    tinker_proxy_policy_p.add_argument(
        "--policy-json",
        default="",
        help="Optional path to hash-only policy JSON to install; omitted returns current status",
    )
    tinker_proxy_policy_p.add_argument("--output", default="", help="Optional output path for bounded JSON")
    tinker_proxy_identity_registry_p = sub.add_parser(
        "tinker-proxy-identity-registry",
        help="Return or install bounded hash-only Tinker proxy identity registry",
    )
    tinker_proxy_identity_registry_p.add_argument(
        "--api-url",
        default="",
        help="Optional deployed Tinker delegate API base URL; omitted reads/writes local settings",
    )
    tinker_proxy_identity_registry_p.add_argument(
        "--auth-token-env",
        default="TINKER_RUNTIME_AUTH_TOKEN",
        help="Environment variable containing delegate runtime bearer token for --api-url",
    )
    tinker_proxy_identity_registry_p.add_argument(
        "--registry-json",
        default="",
        help="Optional path to signed hash-only identity registry JSON to install; omitted returns current status",
    )
    tinker_proxy_identity_registry_p.add_argument("--output", default="", help="Optional output path for bounded JSON")
    tinker_proxy_registry_sign_p = sub.add_parser(
        "sign-tinker-proxy-identity-registry",
        help="Sign a hash-only proxy identity registry with a verifier key from env",
    )
    tinker_proxy_registry_sign_p.add_argument(
        "--registry-json",
        required=True,
        help="Path to unsigned hash-only identity registry JSON",
    )
    tinker_proxy_registry_sign_p.add_argument(
        "--signer-key-env",
        default="TINKER_PROXY_IDENTITY_REGISTRY_SIGNER_KEY",
        help="Environment variable containing verifier Ethereum private key",
    )
    tinker_proxy_registry_sign_p.add_argument(
        "--signed-registry-output",
        required=True,
        help="Path to write normalized signed identity registry JSON",
    )
    tinker_proxy_registry_sign_p.add_argument("--output", default="", help="Optional bounded receipt path")
    tinker_proxy_grant_sign_p = sub.add_parser(
        "sign-tinker-proxy-grant-lifecycle",
        help="Sign a hash-only proxy issue-policy grant lifecycle with a reviewer key from env",
    )
    tinker_proxy_grant_sign_p.add_argument(
        "--grant-json",
        required=True,
        help="Path to one hash-only proxy issue-policy grant JSON",
    )
    tinker_proxy_grant_sign_p.add_argument(
        "--signer-key-env",
        default="TINKER_PROXY_GRANT_REVIEWER_KEY",
        help="Environment variable containing reviewer Ethereum private key",
    )
    tinker_proxy_grant_sign_p.add_argument(
        "--signed-grant-output",
        required=True,
        help="Path to write normalized signed grant JSON",
    )
    tinker_proxy_grant_sign_p.add_argument("--output", default="", help="Optional bounded receipt path")
    tinker_proxy_registry_verify_p = sub.add_parser(
        "verify-tinker-proxy-identity-registry",
        help="Verify a signed hash-only proxy identity registry against an expected signer",
    )
    tinker_proxy_registry_verify_p.add_argument(
        "--registry-json",
        required=True,
        help="Path to signed hash-only identity registry JSON",
    )
    tinker_proxy_registry_verify_p.add_argument(
        "--expected-signer",
        required=True,
        help="Expected verifier Ethereum address",
    )
    tinker_proxy_registry_verify_p.add_argument("--output", default="", help="Optional bounded receipt path")
    tinker_proxy_token_p = sub.add_parser(
        "issue-tinker-proxy-token",
        help="Issue a scoped Tinker proxy JWT encrypted to a recipient public key",
    )
    tinker_proxy_token_p.add_argument(
        "--api-url",
        default="",
        help="Optional deployed Tinker delegate API base URL; omitted issues locally",
    )
    tinker_proxy_token_p.add_argument(
        "--auth-token-env",
        default="TINKER_RUNTIME_AUTH_TOKEN",
        help="Environment variable containing delegate runtime bearer token for --api-url",
    )
    tinker_proxy_token_p.add_argument("--subject", required=True, help="Approved user/agent subject")
    tinker_proxy_token_p.add_argument(
        "--scope",
        action="append",
        required=True,
        help="Proxy scope to include; repeat for multiple scopes",
    )
    tinker_proxy_token_p.add_argument(
        "--recipient-public-key",
        required=True,
        help="Hex X25519 public key for encrypted proxy-token delivery",
    )
    tinker_proxy_token_p.add_argument("--ttl-seconds", type=int, default=None)
    tinker_proxy_token_p.add_argument("--output", default="", help="Optional output path for bounded JSON")
    tinker_proxy_audit_p = sub.add_parser(
        "tinker-proxy-token-audit",
        help="Return bounded Tinker proxy token issue/revoke audit records",
    )
    tinker_proxy_audit_p.add_argument(
        "--api-url",
        default="",
        help="Optional deployed Tinker delegate API base URL; omitted reads the local sealed store",
    )
    tinker_proxy_audit_p.add_argument(
        "--auth-token-env",
        default="TINKER_RUNTIME_AUTH_TOKEN",
        help="Environment variable containing delegate runtime bearer token for --api-url",
    )
    tinker_proxy_audit_p.add_argument("--output", default="", help="Optional output path for bounded JSON")
    verify_proxy_audit_p = sub.add_parser(
        "verify-tinker-proxy-token-audit",
        help="Externally verify bounded proxy token audit records and operation receipts",
    )
    verify_proxy_audit_p.add_argument("--audit-json", required=True, help="Path to bounded proxy-token audit JSON")
    verify_proxy_audit_p.add_argument(
        "--operation-receipt-json",
        action="append",
        default=[],
        help="Path to bounded operation receipt JSON; repeat for multiple receipts",
    )
    verify_proxy_audit_p.add_argument(
        "--require-operation-binding",
        action="store_true",
        help="Fail if an operation receipt lacks bounded proxy_auth_context",
    )
    verify_proxy_audit_p.add_argument("--output", default="", help="Optional output path for bounded JSON")
    tinker_proxy_revoke_p = sub.add_parser(
        "revoke-tinker-proxy-token",
        help="Revoke a Tinker proxy JWT by bounded jwt_id_hash",
    )
    tinker_proxy_revoke_p.add_argument(
        "--api-url",
        default="",
        help="Optional deployed Tinker delegate API base URL; omitted writes the local sealed store",
    )
    tinker_proxy_revoke_p.add_argument(
        "--auth-token-env",
        default="TINKER_RUNTIME_AUTH_TOKEN",
        help="Environment variable containing delegate runtime bearer token for --api-url",
    )
    tinker_proxy_revoke_p.add_argument("--jwt-id-hash", required=True)
    tinker_proxy_revoke_p.add_argument(
        "--reason",
        default="operator_requested",
        help="Bounded revocation reason enum",
    )
    tinker_proxy_revoke_p.add_argument("--output", default="", help="Optional output path for bounded JSON")
    tinker_proxy_keygen_p = sub.add_parser(
        "tinker-proxy-recipient-keygen",
        help="Generate an X25519 recipient keypair for encrypted proxy-token delivery",
    )
    tinker_proxy_keygen_p.add_argument(
        "--private-key-output",
        required=True,
        help="Path to write the recipient private key with mode 0600",
    )
    tinker_proxy_keygen_p.add_argument("--output", default="", help="Optional output path for bounded JSON")
    tinker_proxy_decrypt_p = sub.add_parser(
        "decrypt-tinker-proxy-token",
        help="Decrypt an encrypted proxy-token issuance response into a local token file",
    )
    tinker_proxy_decrypt_p.add_argument(
        "--encrypted-token-json",
        required=True,
        help="Path to JSON returned by issue-tinker-proxy-token",
    )
    tinker_proxy_decrypt_p.add_argument(
        "--private-key-file",
        required=True,
        help="Path to recipient private key file from tinker-proxy-recipient-keygen",
    )
    tinker_proxy_decrypt_p.add_argument(
        "--token-output",
        required=True,
        help="Path to write the decrypted proxy JWT with mode 0600",
    )
    tinker_proxy_decrypt_p.add_argument("--output", default="", help="Optional output path for bounded JSON")
    tinker_smoke_p = sub.add_parser(
        "tinker-smoke",
        help="Run a bounded tiny real Tinker SDK training/checkpoint/sample/cleanup smoke",
    )
    tinker_smoke_p.add_argument(
        "--api-url",
        default="",
        help="Optional deployed Tinker delegate API base URL; omitted runs inside the current process",
    )
    tinker_smoke_p.add_argument(
        "--auth-token-env",
        default="TINKER_RUNTIME_AUTH_TOKEN",
        help="Environment variable containing delegate runtime or scoped proxy bearer token for --api-url",
    )
    tinker_smoke_p.add_argument("--deal-id", default="", help="Optional public/local smoke deal id")
    tinker_smoke_p.add_argument(
        "--max-usd",
        type=float,
        default=None,
        help="Hard cap for this tiny SDK smoke; default is TINKER_REAL_SDK_MAX_USD",
    )
    tinker_smoke_p.add_argument(
        "--model",
        default="",
        help="Base model for the smoke; default is TINKER_REAL_SDK_MODEL",
    )
    tinker_smoke_p.add_argument(
        "--rank",
        type=int,
        default=None,
        help="LoRA rank for the smoke; default is TINKER_REAL_SDK_RANK",
    )
    tinker_smoke_p.add_argument("--ttl-seconds", type=int, default=3600)
    tinker_smoke_p.add_argument(
        "--compose-hash",
        default="",
        help="Compose hash to check against TinkerAccountEncumbrance",
    )
    tinker_smoke_p.add_argument(
        "--require-encumbrance",
        action="store_true",
        help="Require TinkerAccountEncumbrance approval before SDK spend",
    )
    tinker_smoke_p.add_argument("--output", default="", help="Optional output path for bounded JSON")

    # Billing commands
    balance_p = sub.add_parser("balance", help="Get current Tinker account balance")
    balance_p.add_argument(
        "--api-url",
        default="",
        help="Optional deployed Tinker delegate API base URL; omitted uses the local browser session",
    )
    balance_p.add_argument(
        "--auth-token-env",
        default="TINKER_RUNTIME_AUTH_TOKEN",
        help="Environment variable containing delegate runtime bearer token for --api-url",
    )
    balance_p.add_argument("--output", default="", help="Optional output path for bounded JSON")
    sub.add_parser("funding-policy", help="Print bounded Tinker funding-mode policy")

    funding_preflight_p = sub.add_parser(
        "funding-preflight",
        help="Check operator funding validation readiness without card material",
    )
    funding_preflight_p.add_argument(
        "--amount",
        type=float,
        default=None,
        help="Planned add-balance amount in USD to check against the configured cap",
    )
    funding_preflight_p.add_argument(
        "--require-add-balance-endpoint",
        action="store_true",
        help="Require POST /billing/add-balance to be explicitly enabled",
    )
    funding_preflight_p.add_argument(
        "--api-url",
        default="",
        help="Tinker delegate API base URL for billing attestation preflight",
    )
    funding_preflight_p.add_argument(
        "--compose-hash",
        default="",
        help="Expected dstack compose hash for billing attestation",
    )
    funding_preflight_p.add_argument("--app-id", default="", help="Expected dstack app ID")
    funding_preflight_p.add_argument(
        "--os-image-hash",
        default="",
        help="Expected dstack OS image hash",
    )
    funding_preflight_p.add_argument(
        "--allow-local-attestation",
        action="store_true",
        help="Allow local-mode attestation for development preflight only",
    )
    funding_preflight_p.add_argument(
        "--fetch-attestation",
        action="store_true",
        help="Live-fetch and verify /attestation?context=billing",
    )
    funding_preflight_p.add_argument("--output", default="", help="Optional output path for preflight JSON")

    encumbrance_preflight_p = sub.add_parser(
        "tinker-encumbrance-preflight",
        help="Check TinkerAccountEncumbrance policy without card material or browser launch",
    )
    encumbrance_preflight_p.add_argument(
        "--operation",
        required=True,
        choices=("add-payment-method", "add-balance", "spend-tinker-compute", "manual-prefund"),
        help="Tinker account operation to check",
    )
    encumbrance_preflight_p.add_argument(
        "--amount",
        type=float,
        default=None,
        help="USD amount to map into policy units for add-balance checks",
    )
    encumbrance_preflight_p.add_argument(
        "--amount-wei",
        type=int,
        default=None,
        help="Explicit policy amount in wei-style units; overrides --amount",
    )
    encumbrance_preflight_p.add_argument(
        "--compose-hash",
        default="",
        help="Compose hash to check; defaults to TINKER_ENCUMBRANCE_COMPOSE_HASH",
    )
    encumbrance_preflight_p.add_argument(
        "--contract-address",
        default="",
        help="TinkerAccountEncumbrance address; defaults to TINKER_ENCUMBRANCE_CONTRACT_ADDRESS",
    )
    encumbrance_preflight_p.add_argument(
        "--rpc-url",
        default="",
        help="JSON-RPC URL; defaults to TINKER_ENCUMBRANCE_RPC_URL or TINKER_CHAIN_RPC_URL",
    )
    encumbrance_preflight_p.add_argument(
        "--required",
        action="store_true",
        help="Fail closed if no encumbrance contract is configured",
    )
    encumbrance_preflight_p.add_argument("--output", default="", help="Optional output path for preflight JSON")

    funding_command_plan_p = sub.add_parser(
        "funding-command-plan",
        help="Build a bounded manifest-derived operator command plan for capped funding validation",
    )
    funding_command_plan_p.add_argument(
        "--manifest",
        default="",
        help="Deployment manifest path; defaults to repo deployments/base-sepolia.json",
    )
    funding_command_plan_p.add_argument(
        "--amount",
        type=float,
        default=10.0,
        help="Planned add-balance amount in USD for the command plan",
    )
    funding_command_plan_p.add_argument(
        "--output-dir",
        default="./funding-validation-packet",
        help="Packet output directory for the generated command",
    )
    funding_command_plan_p.add_argument(
        "--validation-id",
        default="operator-real-card-validation",
        help="Operator-local validation ID to bind by hash",
    )
    funding_command_plan_p.add_argument(
        "--encumbrance-rpc-env",
        default="BASE_SEPOLIA_RPC_URL",
        help="Environment variable name containing the Base Sepolia RPC URL",
    )
    funding_command_plan_p.add_argument(
        "--runtime-auth-env",
        default="TINKER_RUNTIME_AUTH_TOKEN",
        help="Environment variable name containing the delegate runtime bearer token",
    )
    funding_command_plan_p.add_argument(
        "--skip-reauth",
        action="store_true",
        help="Do not include /auth/reauth in the generated packet command",
    )
    funding_command_plan_p.add_argument(
        "--skip-add-balance",
        action="store_true",
        help="Do not include POST /billing/add-balance in the generated packet command",
    )
    funding_command_plan_p.add_argument("--output", default="", help="Optional output path for bounded JSON")

    tinker_smoke_plan_p = sub.add_parser(
        "tinker-smoke-command-plan",
        help="Build a bounded manifest-derived operator command plan for live Tinker SDK smoke",
    )
    tinker_smoke_plan_p.add_argument(
        "--manifest",
        default="",
        help="Deployment manifest path; defaults to repo deployments/base-sepolia.json",
    )
    tinker_smoke_plan_p.add_argument(
        "--compose",
        default="docker-compose.tinker-funding-validation.phala.yaml",
        help="Compose file path as run from the tinker-delegate directory",
    )
    tinker_smoke_plan_p.add_argument(
        "--runtime-env",
        default="../../.env",
        help="Runtime env file path used by the Phala redeploy helper",
    )
    tinker_smoke_plan_p.add_argument(
        "--api-env",
        default="../../.env",
        help="Phala API env file path used by the Phala redeploy helper",
    )
    tinker_smoke_plan_p.add_argument("--max-usd", type=float, default=0.05)
    tinker_smoke_plan_p.add_argument("--model", default="Qwen/Qwen3-8B")
    tinker_smoke_plan_p.add_argument("--rank", type=int, default=32)
    tinker_smoke_plan_p.add_argument(
        "--account-access-state",
        default="",
        help=(
            "Bounded account access state from `account-access-status` "
            "(active, access_blocked_billing, payment_required, waitlist_or_gated, unknown); "
            "a blocked/gated/payment state makes the plan not ready"
        ),
    )
    tinker_smoke_plan_p.add_argument(
        "--output-path-template",
        default="/tmp/dnai-tinker-smoke-project-id-$(date -u +%Y%m%dT%H%M%SZ).json",
        help="Smoke receipt output template for the generated command",
    )
    tinker_smoke_plan_p.add_argument(
        "--encumbrance-rpc-env",
        default="BASE_SEPOLIA_RPC_URL",
        help="Environment variable name containing the Base Sepolia RPC URL",
    )
    tinker_smoke_plan_p.add_argument(
        "--runtime-auth-env",
        default="TINKER_RUNTIME_AUTH_TOKEN",
        help="Environment variable name containing the delegate runtime bearer token",
    )
    tinker_smoke_plan_p.add_argument(
        "--project-id-env",
        default="TINKER_PROJECT_ID",
        help="Environment variable name containing the Tinker project id; value is never printed",
    )
    tinker_smoke_plan_p.add_argument(
        "--base-url-env",
        default="TINKER_BASE_URL",
        help="Environment variable name for optional provider-specific Tinker base URL",
    )
    tinker_smoke_plan_p.add_argument("--output", default="", help="Optional output path for bounded JSON")

    log_safety_p = sub.add_parser(
        "verify-deployed-log-safety",
        help="Scan deployed logs/console output for card or credential-shaped leakage",
    )
    log_safety_p.add_argument(
        "--logs-file",
        default="-",
        help="Path to logs to scan, or '-' for stdin",
    )
    log_safety_p.add_argument(
        "--source-label",
        default="",
        help="Non-secret label for the scanned log source",
    )
    log_safety_p.add_argument("--output", default="", help="Optional output path for bounded JSON")

    funding_manifest_p = sub.add_parser(
        "funding-manifest",
        help="Build a bounded funding validation manifest from preflight and receipt JSON",
    )
    funding_manifest_p.add_argument("--preflight-json", required=True, help="Path to saved funding-preflight JSON")
    funding_manifest_p.add_argument("--receipt-json", required=True, help="Path to bounded funding receipt JSON")
    funding_manifest_p.add_argument("--validation-id", default="", help="Operator-local validation run ID to hash")
    funding_manifest_p.add_argument("--compose-hash", default="", help="Expected compose hash to bind by hash")
    funding_manifest_p.add_argument("--app-id", default="", help="Expected app ID to bind by hash")
    funding_manifest_p.add_argument("--os-image-hash", default="", help="Expected OS image hash to bind by hash")
    funding_manifest_p.add_argument("--output", default="", help="Optional output path for manifest JSON")

    verify_funding_manifest_p = sub.add_parser(
        "verify-funding-manifest",
        help="Verify a bounded funding manifest against saved preflight and receipt JSON",
    )
    verify_funding_manifest_p.add_argument("--preflight-json", required=True, help="Path to saved funding-preflight JSON")
    verify_funding_manifest_p.add_argument("--receipt-json", required=True, help="Path to bounded funding receipt JSON")
    verify_funding_manifest_p.add_argument("--manifest-json", required=True, help="Path to saved funding manifest JSON")
    verify_funding_manifest_p.add_argument("--validation-id", default="", help="Operator-local validation run ID to hash")
    verify_funding_manifest_p.add_argument("--compose-hash", default="", help="Expected compose hash bound by hash")
    verify_funding_manifest_p.add_argument("--app-id", default="", help="Expected app ID bound by hash")
    verify_funding_manifest_p.add_argument("--os-image-hash", default="", help="Expected OS image hash bound by hash")
    verify_funding_manifest_p.add_argument(
        "--require-ready",
        action="store_true",
        help="Require the saved preflight to be ready",
    )
    verify_funding_manifest_p.add_argument(
        "--allow-card-retention-flag",
        action="store_true",
        help="Do not require no_raw_card_retained=true; development/debug only",
    )
    verify_funding_manifest_p.add_argument("--output", default="", help="Optional output path for verification JSON")

    validation_packet_p = sub.add_parser(
        "funding-validation-packet",
        help="Create a bounded preflight/receipt/manifest/verification packet",
    )
    validation_packet_p.add_argument("--output-dir", required=True, help="Directory for bounded packet JSON artifacts")
    validation_packet_p.add_argument("--api-url", required=True, help="Tinker delegate API base URL")
    validation_packet_p.add_argument("--amount", type=float, default=None, help="Planned add-balance amount in USD")
    validation_packet_p.add_argument("--compose-hash", default="", help="Expected dstack compose hash")
    validation_packet_p.add_argument("--app-id", default="", help="Expected dstack app ID")
    validation_packet_p.add_argument("--os-image-hash", default="", help="Expected dstack OS image hash")
    validation_packet_p.add_argument("--validation-id", default="", help="Operator-local validation run ID to hash")
    validation_packet_p.add_argument("--receipt-json", default="", help="Existing bounded receipt JSON to bind")
    validation_packet_p.add_argument(
        "--add-balance-receipt-json",
        default="",
        help="Existing bounded add-balance receipt JSON to bind",
    )
    validation_packet_p.add_argument(
        "--require-add-balance-endpoint",
        action="store_true",
        help="Require POST /billing/add-balance to be explicitly enabled",
    )
    validation_packet_p.add_argument(
        "--allow-local-attestation",
        action="store_true",
        help="Allow local-mode billing attestation for development only",
    )
    validation_packet_p.add_argument(
        "--auth-token-env",
        default="TINKER_RUNTIME_AUTH_TOKEN",
        help="Environment variable containing delegate runtime bearer token",
    )
    validation_packet_p.add_argument(
        "--fetch-attestation",
        action="store_true",
        help="Live-fetch and verify /attestation?context=billing during preflight",
    )
    _add_encumbrance_gate_args(validation_packet_p)
    validation_packet_p.add_argument(
        "--run-card-attempt",
        action="store_true",
        help="Explicitly run encrypted card submission; requires card fields",
    )
    validation_packet_p.add_argument(
        "--run-reauth-attempt",
        action="store_true",
        help="Explicitly POST /auth/reauth before encrypted card submission",
    )
    validation_packet_p.add_argument(
        "--prompt-card",
        action="store_true",
        help="Prompt interactively for card fields instead of reading card fields from argv",
    )
    validation_packet_p.add_argument(
        "--run-add-balance-attempt",
        action="store_true",
        help="Explicitly POST amount to /billing/add-balance and bind the bounded receipt",
    )
    validation_packet_p.add_argument("--number", default="", help="Test-card number; requires --run-card-attempt")
    validation_packet_p.add_argument("--exp-month", default="", help="Test-card expiration month; requires --run-card-attempt")
    validation_packet_p.add_argument("--exp-year", default="", help="Test-card expiration year; requires --run-card-attempt")
    validation_packet_p.add_argument("--cvc", default="", help="Test-card CVC/CVV; requires --run-card-attempt")
    validation_packet_p.add_argument("--name", default="", help="Test-card cardholder name; requires --run-card-attempt")
    validation_packet_p.add_argument("--address-line1", default="", help="Address line 1")
    validation_packet_p.add_argument("--address-city", default="", help="City")
    validation_packet_p.add_argument("--address-state", default="", help="State")
    validation_packet_p.add_argument("--address-postal", default="", help="Postal code")
    validation_packet_p.add_argument("--address-country", default="US", help="Country (default: US)")

    packet_check_p = sub.add_parser(
        "check-funding-validation-packet",
        help="Replay-check a bounded funding validation packet directory",
    )
    packet_check_p.add_argument("--packet-dir", required=True, help="Funding validation packet directory")
    packet_check_p.add_argument("--validation-id", default="", help="Operator-local validation run ID to hash")
    packet_check_p.add_argument("--compose-hash", default="", help="Expected compose hash bound by hash")
    packet_check_p.add_argument("--app-id", default="", help="Expected app ID bound by hash")
    packet_check_p.add_argument("--os-image-hash", default="", help="Expected OS image hash bound by hash")
    packet_check_p.add_argument(
        "--require-add-balance",
        action="store_true",
        help="Require add-balance receipt, manifest, and verification files",
    )
    packet_check_p.add_argument(
        "--require-deployed-attestation",
        action="store_true",
        help="Require preflight evidence that billing attestation was live-verified as TDX",
    )
    packet_check_p.add_argument("--output", default="", help="Optional output path for checker JSON")

    add_card_p = sub.add_parser("add-card", help="Add payment method (card) to Tinker account")
    add_card_p.add_argument("--number", required=True, help="Card number")
    add_card_p.add_argument("--exp-month", required=True, help="Expiration month (01-12)")
    add_card_p.add_argument("--exp-year", required=True, help="Expiration year (26 or 2026)")
    add_card_p.add_argument("--cvc", required=True, help="CVC/CVV code")
    add_card_p.add_argument("--name", required=True, help="Cardholder name")
    add_card_p.add_argument("--address-line1", default="", help="Address line 1")
    add_card_p.add_argument("--address-city", default="", help="City")
    add_card_p.add_argument("--address-state", default="", help="State")
    add_card_p.add_argument("--address-postal", default="", help="Postal code")
    add_card_p.add_argument("--address-country", default="US", help="Country (default: US)")
    add_card_p.add_argument("--receipt-output", default="", help="Optional output path for bounded receipt JSON")

    add_bal_p = sub.add_parser("add-balance", help="Add credit balance to Tinker account")
    add_bal_p.add_argument("amount", type=float, help="Amount in USD to add")
    add_bal_p.add_argument(
        "--api-url",
        default="",
        help="Optional deployed Tinker delegate API base URL; omitted uses the local browser session",
    )
    add_bal_p.add_argument(
        "--auth-token-env",
        default="TINKER_RUNTIME_AUTH_TOKEN",
        help="Environment variable containing delegate runtime or scoped proxy bearer token for --api-url",
    )
    add_bal_p.add_argument("--receipt-output", default="", help="Optional output path for bounded receipt JSON")
    add_bal_p.add_argument("--output", default="", help="Optional output path for bounded JSON")

    payment_method_status_p = sub.add_parser(
        "payment-method-status",
        help="Query bounded card-on-file status from a deployed delegate",
    )
    payment_method_status_p.add_argument("api_url", help="Tinker delegate API base URL")
    payment_method_status_p.add_argument(
        "--auth-token-env",
        default="TINKER_RUNTIME_AUTH_TOKEN",
        help="Environment variable containing delegate runtime or scoped proxy bearer token",
    )
    payment_method_status_p.add_argument("--output", default="", help="Optional output path for bounded JSON")

    remove_card_p = sub.add_parser(
        "remove-card",
        help="Remove the card-on-file through a deployed delegate",
    )
    remove_card_p.add_argument("api_url", help="Tinker delegate API base URL")
    remove_card_p.add_argument(
        "--auth-token-env",
        default="TINKER_RUNTIME_AUTH_TOKEN",
        help="Environment variable containing delegate runtime bearer token",
    )
    remove_card_p.add_argument("--receipt-output", default="", help="Optional output path for bounded receipt JSON")
    remove_card_p.add_argument("--output", default="", help="Optional output path for bounded JSON")

    add_card_encrypted_p = sub.add_parser(
        "add-card-encrypted",
        help="Verify attestation, encrypt card details, and POST /billing/card/encrypted",
    )
    add_card_encrypted_p.add_argument("api_url", help="Tinker delegate API base URL")
    add_card_encrypted_p.add_argument("--number", required=True, help="Card number")
    add_card_encrypted_p.add_argument("--exp-month", required=True, help="Expiration month (01-12)")
    add_card_encrypted_p.add_argument("--exp-year", required=True, help="Expiration year (26 or 2026)")
    add_card_encrypted_p.add_argument("--cvc", required=True, help="CVC/CVV code")
    add_card_encrypted_p.add_argument("--name", required=True, help="Cardholder name")
    add_card_encrypted_p.add_argument("--address-line1", default="", help="Address line 1")
    add_card_encrypted_p.add_argument("--address-city", default="", help="City")
    add_card_encrypted_p.add_argument("--address-state", default="", help="State")
    add_card_encrypted_p.add_argument("--address-postal", default="", help="Postal code")
    add_card_encrypted_p.add_argument("--address-country", default="US", help="Country (default: US)")
    add_card_encrypted_p.add_argument(
        "--compose-hash",
        default="",
        help="Expected dstack compose hash; required unless --allow-local-attestation is set",
    )
    add_card_encrypted_p.add_argument("--app-id", default="", help="Expected dstack app ID")
    add_card_encrypted_p.add_argument(
        "--os-image-hash",
        default="",
        help="Expected dstack OS image hash",
    )
    add_card_encrypted_p.add_argument(
        "--allow-local-attestation",
        action="store_true",
        help="Allow local-mode attestation for development only",
    )
    add_card_encrypted_p.add_argument(
        "--auth-token-env",
        default="TINKER_RUNTIME_AUTH_TOKEN",
        help="Environment variable containing delegate runtime bearer token",
    )
    add_card_encrypted_p.add_argument("--receipt-output", default="", help="Optional output path for bounded receipt JSON")

    add_card_encrypted_prompt_p = sub.add_parser(
        "add-card-encrypted-prompt",
        help="Prompt for card details, verify attestation, encrypt, and POST /billing/card/encrypted",
    )
    add_card_encrypted_prompt_p.add_argument("api_url", help="Tinker delegate API base URL")
    add_card_encrypted_prompt_p.add_argument(
        "--compose-hash",
        default="",
        help="Expected dstack compose hash; required unless --allow-local-attestation is set",
    )
    add_card_encrypted_prompt_p.add_argument("--app-id", default="", help="Expected dstack app ID")
    add_card_encrypted_prompt_p.add_argument(
        "--os-image-hash",
        default="",
        help="Expected dstack OS image hash; required unless --allow-local-attestation is set",
    )
    add_card_encrypted_prompt_p.add_argument(
        "--allow-local-attestation",
        action="store_true",
        help="Allow local-mode attestation for development only; do not use for real cards",
    )
    add_card_encrypted_prompt_p.add_argument(
        "--auth-token-env",
        default="TINKER_RUNTIME_AUTH_TOKEN",
        help="Environment variable containing delegate runtime bearer token",
    )
    _add_encumbrance_gate_args(add_card_encrypted_prompt_p)
    add_card_encrypted_prompt_p.add_argument(
        "--receipt-output",
        default="",
        help="Optional output path for bounded receipt JSON",
    )

    upload_artifact_p = sub.add_parser(
        "upload-artifact",
        help="Verify attestation, encrypt an artifact, and upload it to a deal",
    )
    upload_artifact_p.add_argument("api_url", help="Tinker delegate API base URL")
    upload_artifact_p.add_argument("deal_id", help="Deal ID to receive the artifact")
    upload_artifact_p.add_argument("artifact_path", help="Path to artifact file")
    upload_artifact_p.add_argument(
        "commitment_receipt_path",
        help="Private v2 commitment receipt JSON; never pass its secret on the command line",
    )
    upload_artifact_p.add_argument(
        "--compose-hash",
        default="",
        help="Expected dstack compose hash; required unless --allow-local-attestation is set",
    )
    upload_artifact_p.add_argument("--app-id", default="", help="Expected dstack app ID")
    upload_artifact_p.add_argument(
        "--os-image-hash",
        default="",
        help="Expected dstack OS image hash",
    )
    upload_artifact_p.add_argument(
        "--allow-local-attestation",
        action="store_true",
        help="Allow local-mode attestation for development only",
    )
    upload_artifact_p.add_argument(
        "--wallet-token-env",
        default="TINKER_WALLET_AUTH_TOKEN",
        help="Environment variable containing the deal-scoped seller wallet token",
    )
    upload_artifact_p.add_argument(
        "--diligence-room-address",
        required=True,
        help="Exact fresh Base Sepolia DiligenceRoom address bound into envelope v3",
    )
    upload_artifact_p.add_argument(
        "--evaluator-policy-commitment",
        required=True,
        help="Exact funded deal evaluator-policy bytes32 bound into envelope v3",
    )

    verify_attestation_p = sub.add_parser(
        "verify-attestation",
        help=(
            "Check /attestation envelope consistency against policy; does not "
            "perform independent Intel DCAP/QVL verification"
        ),
    )
    verify_attestation_p.add_argument("api_url", help="Tinker delegate API base URL")
    verify_attestation_p.add_argument(
        "--compose-hash",
        default="",
        help="Expected dstack compose hash; required unless --allow-local-attestation is set",
    )
    verify_attestation_p.add_argument("--app-id", default="", help="Expected dstack app ID")
    verify_attestation_p.add_argument(
        "--os-image-hash",
        default="",
        help="Expected dstack OS image hash",
    )
    verify_attestation_p.add_argument("--context", default="artifact", help="Expected report context")
    verify_attestation_p.add_argument(
        "--max-age-seconds",
        type=float,
        default=60.0,
        help="Maximum client-side age for fetched evidence",
    )
    verify_attestation_p.add_argument(
        "--allow-local-attestation",
        action="store_true",
        help="Allow local-mode attestation for development only",
    )

    verify_cvm_attestation_p = sub.add_parser(
        "verify-cvm-attestation",
        help=(
            "Match digest-pinned compose input to a CVM evidence envelope; "
            "does not produce an Intel TDX verdict"
        ),
    )
    verify_cvm_attestation_p.add_argument("api_url", help="Tinker delegate API base URL")
    verify_cvm_attestation_p.add_argument("--compose", required=True, help="Docker Compose file")
    verify_cvm_attestation_p.add_argument(
        "--env-file",
        action="append",
        default=[],
        help="Environment file used by docker compose config; repeatable",
    )
    verify_cvm_attestation_p.add_argument(
        "--allowed-env-file",
        default="",
        help="Runtime env file whose keys should be included as allowed_envs",
    )
    verify_cvm_attestation_p.add_argument(
        "--allowed-env",
        action="append",
        default=[],
        help="Runtime env key included as an encrypted Phala allowed_env; repeatable",
    )
    verify_cvm_attestation_p.add_argument(
        "--phala-raw-compose",
        action="store_true",
        help="Hash raw compose source plus allowed_envs, matching Phala deploy",
    )
    verify_cvm_attestation_p.add_argument(
        "--expected-compose-hash",
        default="",
        help="Expected Phala compose hash before checking live attestation",
    )
    verify_cvm_attestation_p.add_argument(
        "--attested-compose-hash",
        default="",
        help="Expected live attestation compose hash when Phala's full app-compose hash differs from local image-policy hash",
    )
    verify_cvm_attestation_p.add_argument("--app-id", default="", help="Expected dstack app ID")
    verify_cvm_attestation_p.add_argument(
        "--os-image-hash",
        default="",
        help="Expected dstack OS image hash",
    )
    verify_cvm_attestation_p.add_argument(
        "--require-image",
        action="append",
        default=[],
        help="Exact digest-pinned image reference required in rendered compose; repeatable",
    )
    verify_cvm_attestation_p.add_argument(
        "--require-image-digest",
        action="append",
        default=[],
        help="Required sha256 image digest in rendered compose; repeatable",
    )
    verify_cvm_attestation_p.add_argument(
        "--context",
        default="artifact",
        help="Expected attestation report context",
    )
    verify_cvm_attestation_p.add_argument(
        "--max-age-seconds",
        type=float,
        default=60.0,
        help="Maximum client-side age for fetched evidence",
    )
    verify_cvm_attestation_p.add_argument(
        "--allow-local-attestation",
        action="store_true",
        help="Allow local-mode attestation for development only",
    )
    verify_cvm_attestation_p.add_argument(
        "--allow-tags",
        action="store_true",
        help="Allow mutable tag images in compose verification; development only",
    )

    verify_deployment_p = sub.add_parser(
        "verify-deployment-bundle",
        help=(
            "Verify GitHub image attestations and check Phala CVM envelope "
            "consistency; TDX remains unverified without independent QVL"
        ),
    )
    verify_deployment_p.add_argument("api_url", help="Tinker delegate API base URL")
    verify_deployment_p.add_argument("--compose", required=True, help="Docker Compose file")
    verify_deployment_p.add_argument(
        "--image",
        action="append",
        default=[],
        help="Digest-pinned GHCR image ref verified by GitHub attestations; repeatable",
    )
    verify_deployment_p.add_argument(
        "--source-digest",
        required=True,
        help="Expected Git commit SHA used by GitHub image attestations",
    )
    verify_deployment_p.add_argument(
        "--source-ref",
        default="",
        help="Optional expected Git ref, for example refs/heads/main",
    )
    verify_deployment_p.add_argument(
        "--repo",
        default="therealwiki/dnai-wikigen",
        help="GitHub repository that owns the image attestations",
    )
    verify_deployment_p.add_argument(
        "--signer-workflow",
        default="therealwiki/dnai-wikigen/.github/workflows/build-tee-images.yml",
        help="Expected GitHub Actions workflow identity for signed attestations",
    )
    verify_deployment_p.add_argument(
        "--env-file",
        action="append",
        default=[],
        help="Environment file used by docker compose config; repeatable",
    )
    verify_deployment_p.add_argument(
        "--allowed-env-file",
        default="",
        help="Runtime env file whose keys should be included as allowed_envs",
    )
    verify_deployment_p.add_argument(
        "--allowed-env",
        action="append",
        default=[],
        help="Runtime env key included as an encrypted Phala allowed_env; repeatable",
    )
    verify_deployment_p.add_argument(
        "--phala-raw-compose",
        action="store_true",
        help="Hash raw compose source plus allowed_envs, matching Phala deploy",
    )
    verify_deployment_p.add_argument(
        "--expected-compose-hash",
        default="",
        help="Expected local compose/image-policy hash before live attestation",
    )
    verify_deployment_p.add_argument(
        "--attested-compose-hash",
        default="",
        help="Expected live Phala attested compose hash",
    )
    verify_deployment_p.add_argument("--app-id", default="", help="Expected dstack app ID")
    verify_deployment_p.add_argument(
        "--os-image-hash",
        default="",
        help="Expected dstack OS image hash",
    )
    verify_deployment_p.add_argument(
        "--require-image-digest",
        action="append",
        default=[],
        help="Additional required sha256 image digest, for sidecars; repeatable",
    )
    verify_deployment_p.add_argument("--context", default="artifact", help="Expected report context")
    verify_deployment_p.add_argument(
        "--max-age-seconds",
        type=float,
        default=60.0,
        help="Maximum client-side age for fetched evidence",
    )
    verify_deployment_p.add_argument(
        "--allow-local-attestation",
        action="store_true",
        help="Allow local-mode attestation for development only",
    )
    verify_deployment_p.add_argument(
        "--allow-tags",
        action="store_true",
        help="Allow mutable tag images in compose verification; development only",
    )
    verify_deployment_p.add_argument("--output", default="", help="Optional output path for bundle JSON")

    verify_compose_p = sub.add_parser(
        "verify-compose-hash",
        help="Render a registry-image compose file and compute its Phala compose hash",
    )
    verify_compose_p.add_argument("--compose", required=True, help="Docker Compose file to render")
    verify_compose_p.add_argument(
        "--env-file",
        action="append",
        default=[],
        help="Environment file used by docker compose config; repeatable",
    )
    verify_compose_p.add_argument(
        "--allowed-env-file",
        default="",
        help="Runtime env file whose keys should be included as allowed_envs",
    )
    verify_compose_p.add_argument(
        "--allowed-env",
        action="append",
        default=[],
        help="Runtime env key included as an encrypted Phala allowed_env; repeatable",
    )
    verify_compose_p.add_argument(
        "--phala-raw-compose",
        action="store_true",
        help="Hash raw compose source plus allowed_envs, matching Phala deploy",
    )
    verify_compose_p.add_argument("--expected-hash", default="", help="Expected Phala compose hash")
    verify_compose_p.add_argument(
        "--allow-tags",
        action="store_true",
        help="Allow mutable tag images; development only",
    )

    encrypt_dataset_p = sub.add_parser(
        "encrypt-dataset",
        help="Envelope-encrypt a dataset file to attested CVM recipient(s); bounded receipt",
    )
    encrypt_dataset_p.add_argument("--in", dest="input_path", required=True, help="Plaintext dataset file")
    encrypt_dataset_p.add_argument("--dataset-id", required=True, help="Stable public dataset id")
    encrypt_dataset_p.add_argument("--task", required=True, help="Public task label")
    encrypt_dataset_p.add_argument(
        "--sensitivity",
        required=True,
        choices=["public_benchmark", "private", "phi"],
        help="Data sensitivity label; drives downstream release policy",
    )
    encrypt_dataset_p.add_argument(
        "--recipient-pubkey",
        action="append",
        default=[],
        help="Recipient CVM attestation-bound X25519 public key (hex); repeatable",
    )
    encrypt_dataset_p.add_argument(
        "--recipient-pubkey-file",
        action="append",
        default=[],
        help="File containing a recipient X25519 public key hex; repeatable",
    )
    encrypt_dataset_p.add_argument("--storage-ref", default="", help="Where the blob will be published, e.g. hf://...")
    encrypt_dataset_p.add_argument("--out-blob", required=True, help="Output path for the ciphertext blob")
    encrypt_dataset_p.add_argument("--out-manifest", required=True, help="Output path for the bounded manifest JSON")
    encrypt_dataset_p.add_argument("--chunk-size", type=int, default=0, help="Chunk size in bytes; 0 uses default")
    encrypt_dataset_p.add_argument("--output", default="", help="Optional path for the bounded receipt JSON")

    verify_dataset_manifest_p = sub.add_parser(
        "verify-dataset-manifest",
        help="Verify a sealed-dataset manifest (schema, sensitivity, recipients, ciphertext hash)",
    )
    verify_dataset_manifest_p.add_argument("--manifest", required=True, help="Manifest JSON path")
    verify_dataset_manifest_p.add_argument("--blob", default="", help="Optional ciphertext blob to hash-bind")
    verify_dataset_manifest_p.add_argument(
        "--expected-signer",
        default="",
        help="If set, require a valid owner signature recovering to this Ethereum address",
    )
    verify_dataset_manifest_p.add_argument("--output", default="", help="Optional path for the bounded receipt JSON")

    verify_reward_run_p = sub.add_parser(
        "verify-reward-run",
        help="Verify an emitted private-reward run packet (certificate + transcript binding)",
    )
    verify_reward_run_p.add_argument(
        "--packet", required=True, help="Run packet JSON path (a private-reward demo output)"
    )
    verify_reward_run_p.add_argument("--output", default="", help="Optional path for the bounded verdict JSON")

    verify_reward_mechanism_p = sub.add_parser(
        "verify-reward-mechanism",
        help="Aggregate third-party mechanism audit: run packet + code/dataset/canary binding",
    )
    verify_reward_mechanism_p.add_argument(
        "--packet", required=True, help="Run packet JSON path (a private-reward demo output)"
    )
    verify_reward_mechanism_p.add_argument(
        "--source",
        action="append",
        default=[],
        help="Reward-env source file path to bind (point 1); repeatable. Omit to skip.",
    )
    verify_reward_mechanism_p.add_argument(
        "--manifest", default="", help="Sealed-dataset manifest JSON path to bind (point 2). Omit to skip."
    )
    verify_reward_mechanism_p.add_argument(
        "--canary-report", default="", help="Canary calibration report JSON path (point 3). Omit to skip."
    )
    verify_reward_mechanism_p.add_argument(
        "--expected-signer", default="", help="Required manifest signer address (0x...) for point 2."
    )
    verify_reward_mechanism_p.add_argument(
        "--witness",
        action="append",
        default=[],
        help="Authorized neutral-witness address (0x...); repeatable. Requires --witness-threshold.",
    )
    verify_reward_mechanism_p.add_argument(
        "--witness-threshold", type=int, default=0, help="M in the M-of-N witness quorum (0 = no quorum)."
    )
    verify_reward_mechanism_p.add_argument(
        "--expected-benchmark", default="", help="Required provenance benchmark_ref (enables the provenance check)."
    )
    verify_reward_mechanism_p.add_argument(
        "--require-provenance", action="store_true", help="Require signed seal-time provenance (point 2b)."
    )
    verify_reward_mechanism_p.add_argument("--output", default="", help="Optional path for the bounded verdict JSON")

    explain_decision_p = sub.add_parser(
        "explain-decision",
        help="Explain a bounded decision reason code (policy reason, never private content)",
    )
    explain_decision_p.add_argument("reason_code", help="A bounded decision reason code")
    explain_decision_p.add_argument("--output", default="", help="Optional path for the bounded explanation JSON")

    sign_dataset_manifest_p = sub.add_parser(
        "sign-dataset-manifest",
        help="Owner/reviewer-sign a sealed-dataset manifest with a signer key from env; bounded receipt",
    )
    sign_dataset_manifest_p.add_argument("--manifest", required=True, help="Manifest JSON path to sign")
    sign_dataset_manifest_p.add_argument("--out", required=True, help="Output path for the signed manifest JSON")
    sign_dataset_manifest_p.add_argument(
        "--signer-key-env",
        default="DATASET_OWNER_SIGNER_PRIVATE_KEY",
        help="Env var holding the signer private key hex (never passed on the CLI)",
    )
    sign_dataset_manifest_p.add_argument("--output", default="", help="Optional path for the bounded receipt JSON")

    witness_sign_dataset_manifest_p = sub.add_parser(
        "witness-sign-dataset-manifest",
        help="Neutral notary co-signs a sealed-dataset manifest (M-of-N quorum); bounded receipt",
    )
    witness_sign_dataset_manifest_p.add_argument("--manifest", required=True, help="Manifest JSON path to co-sign")
    witness_sign_dataset_manifest_p.add_argument("--out", required=True, help="Output path for the co-signed manifest JSON")
    witness_sign_dataset_manifest_p.add_argument(
        "--signer-key-env",
        default="DATASET_WITNESS_SIGNER_PRIVATE_KEY",
        help="Env var holding the witness private key hex (never passed on the CLI)",
    )
    witness_sign_dataset_manifest_p.add_argument("--output", default="", help="Optional path for the bounded receipt JSON")

    verify_dataset_provenance_p = sub.add_parser(
        "verify-dataset-provenance",
        help="Verify a sealed-dataset manifest's signed seal-time provenance; bounded receipt",
    )
    verify_dataset_provenance_p.add_argument("--manifest", required=True, help="Manifest JSON path")
    verify_dataset_provenance_p.add_argument(
        "--expected-signer", default="", help="Required owner signer address (0x...)"
    )
    verify_dataset_provenance_p.add_argument(
        "--expected-benchmark", default="", help="Required provenance benchmark_ref"
    )
    verify_dataset_provenance_p.add_argument("--output", default="", help="Optional path for the bounded receipt JSON")

    dataset_recipient_keygen_p = sub.add_parser(
        "dataset-recipient-keygen",
        help="Generate a recipient X25519 keypair for sealed-dataset delivery (private key saved 0600)",
    )
    dataset_recipient_keygen_p.add_argument(
        "--private-key-output", required=True, help="Path to write the 0600 recipient private key hex"
    )
    dataset_recipient_keygen_p.add_argument("--output", default="", help="Optional path for the bounded receipt JSON")

    publish_dataset_p = sub.add_parser(
        "publish-dataset",
        help="Publish a sealed-dataset blob+manifest to a storage backend; bounded receipt",
    )
    publish_dataset_p.add_argument("--blob", required=True, help="Ciphertext blob path (from encrypt-dataset)")
    publish_dataset_p.add_argument("--manifest", required=True, help="Manifest JSON path (from encrypt-dataset)")
    publish_dataset_p.add_argument(
        "--backend", default="local", choices=["local", "https", "hf", "s3"], help="Storage backend scheme"
    )
    publish_dataset_p.add_argument("--dest", default="", help="Local backend destination directory")
    publish_dataset_p.add_argument("--output", default="", help="Optional path for the bounded receipt JSON")

    fetch_decrypt_dataset_p = sub.add_parser(
        "fetch-decrypt-dataset",
        help="Fetch a sealed dataset from a ref, verify its manifest, and decrypt it with a recipient key",
    )
    fetch_decrypt_dataset_p.add_argument("--ref", required=True, help="Storage ref, e.g. local://... or https://...")
    fetch_decrypt_dataset_p.add_argument(
        "--recipient-key-file", required=True, help="Recipient private key hex file from dataset-recipient-keygen"
    )
    fetch_decrypt_dataset_p.add_argument("--out", required=True, help="Path to write the decrypted plaintext (0600)")
    fetch_decrypt_dataset_p.add_argument(
        "--local-root", default="", help="Root directory for a local:// ref (defaults to the ref's embedded root)"
    )
    fetch_decrypt_dataset_p.add_argument("--output", default="", help="Optional path for the bounded receipt JSON")

    watch_chain_p = sub.add_parser(
        "watch-chain",
        help="Watch DiligenceRoom events and notify the TEE control-plane API",
    )
    watch_chain_p.add_argument("--rpc-url", default="", help="JSON-RPC URL, or TINKER_CHAIN_RPC_URL")
    watch_chain_p.add_argument(
        "--contract-address",
        default="",
        help="DiligenceRoom address, or TINKER_CHAIN_CONTRACT_ADDRESS",
    )
    watch_chain_p.add_argument(
        "--api-url",
        default="",
        help="TEE control-plane API URL, or TINKER_CHAIN_CONTROL_PLANE_URL",
    )
    watch_chain_p.add_argument(
        "--from-block",
        default="",
        help="First block to scan; omit to start at the current safe tip",
    )
    watch_chain_p.add_argument("--poll-interval", type=float, default=None, help="Polling interval in seconds")
    watch_chain_p.add_argument("--confirmations", type=int, default=None, help="Confirmation depth")
    watch_chain_p.add_argument(
        "--cursor-store",
        default="",
        help="Durable cursor JSON path, or TINKER_CHAIN_CURSOR_STORE_PATH",
    )
    watch_chain_p.add_argument(
        "--no-cursor",
        action="store_true",
        help="Disable durable cursor storage for one-off local probes",
    )
    watch_chain_p.add_argument(
        "--cursor-summary",
        action="store_true",
        help="Print bounded cursor summary and exit without polling",
    )
    watch_chain_p.add_argument("--once", action="store_true", help="Poll one range and exit")

    submit_result_p = sub.add_parser(
        "submit-result",
        help="Broadcast DiligenceRoom.submitResult from the dstack-derived TEE signer",
    )
    submit_result_p.add_argument("deal_id", type=int, help="DiligenceRoom deal ID")
    submit_result_p.add_argument(
        "score_band",
        help="Bounded score band: negligible, low, medium, high, or exceptional",
    )
    submit_result_p.add_argument("compute_cost_wei", type=int, help="Bounded compute cost in wei")
    submit_result_p.add_argument(
        "--authorization-expiry",
        type=int,
        required=True,
        help="Unix timestamp after which the verifier authorization is invalid",
    )
    submit_result_p.add_argument(
        "--verifier-signature",
        required=True,
        help="65-byte verifier signature over the DiligenceRoom result authorization digest",
    )
    submit_result_p.add_argument("--rpc-url", default="", help="JSON-RPC URL, or TINKER_CHAIN_RPC_URL")
    submit_result_p.add_argument(
        "--contract-address",
        default="",
        help="DiligenceRoom address, or TINKER_CHAIN_CONTRACT_ADDRESS",
    )
    submit_result_p.add_argument(
        "--gas-limit",
        type=int,
        default=None,
        help="Optional gas limit override; defaults to TINKER_CHAIN_SUBMIT_GAS_LIMIT or eth_estimateGas",
    )

    verifier_address_p = sub.add_parser(
        "result-verifier-address",
        help="Print the dstack-derived DiligenceRoom result verifier address",
    )
    verifier_address_p.add_argument("--output", default="", help="Optional JSON output path")

    authorize_result_p = sub.add_parser(
        "authorize-result",
        help="Issue a bounded verifier authorization for DiligenceRoom.submitResult",
    )
    authorize_result_p.add_argument("deal_id", type=int, help="DiligenceRoom deal ID")
    authorize_result_p.add_argument(
        "score_band",
        help="Bounded score band: negligible, low, medium, high, or exceptional",
    )
    authorize_result_p.add_argument("compute_cost_wei", type=int, help="Bounded compute cost in wei")
    authorize_result_p.add_argument("--contract-address", required=True, help="DiligenceRoom address")
    authorize_result_p.add_argument(
        "--rpc-url",
        default="",
        help="JSON-RPC URL used to read the immutable deal and fee policy",
    )
    authorize_result_p.add_argument("--compose-hash", required=True, help="Approved compose hash for this result")
    authorize_result_p.add_argument(
        "--signer-attestation-json",
        required=True,
        help=(
            "Path to service-produced bounded signer-attestation evidence JSON; "
            "this envelope is not itself an independent TDX verdict"
        ),
    )
    authorize_result_p.add_argument(
        "--independent-verdict-json",
        default="",
        help=(
            "Path to a fresh signed Intel DCAP/QVL verdict from an independent "
            "trusted attestation verifier; required except for the explicit "
            "local-test bypass"
        ),
    )
    authorize_result_p.add_argument(
        "--allow-unverified-local-attestation",
        action="store_true",
        help=(
            "Allow envelope-only authorization on local chain 1337/31337 for "
            "simulator tests; never valid for Base Sepolia or production"
        ),
    )
    authorize_result_p.add_argument(
        "--allow-attestation-verifier-address",
        action="append",
        default=[],
        help=(
            "Trusted signer address for independent DCAP/QVL verdicts; repeat "
            "for key rotation"
        ),
    )
    authorize_result_p.add_argument(
        "--allow-compose-hash",
        action="append",
        default=[],
        help="Allowed compose hash; repeat for multiple approved measurements",
    )
    authorize_result_p.add_argument(
        "--allow-app-id",
        action="append",
        default=[],
        help="Allowed Phala app ID; repeat for multiple approved apps",
    )
    authorize_result_p.add_argument(
        "--allow-os-image-hash",
        action="append",
        default=[],
        help="Optional allowed OS image hash; repeat for multiple approved images",
    )
    authorize_result_p.add_argument(
        "--revoke-quote-hash",
        action="append",
        default=[],
        help="Revoked signer quote hash; repeat for multiple revoked quotes",
    )
    authorize_result_p.add_argument(
        "--revoke-signer-address",
        action="append",
        default=[],
        help="Revoked TEE signer address; repeat for multiple revoked signers",
    )
    authorize_result_p.add_argument(
        "--ttl-seconds",
        type=int,
        default=None,
        help="Authorization TTL; defaults to TINKER_CHAIN_RESULT_AUTHORIZATION_TTL_SECONDS",
    )
    authorize_result_p.add_argument("--output", default="", help="Optional JSON output path")

    governance_plan_p = sub.add_parser(
        "governance-approval-plan",
        help="Authenticate a signed QVL verdict and emit a review-only approval plan",
    )
    governance_plan_p.add_argument(
        "independent_verdict_json",
        help="Path to the complete signed independent Intel TDX DCAP/QVL verdict JSON",
    )
    governance_plan_p.add_argument(
        "--trusted-attestation-verifier-address",
        action="append",
        required=True,
        help="Externally trusted QVL signer address; repeat for key rotation",
    )
    governance_plan_p.add_argument(
        "--expected-chain-id",
        type=int,
        required=True,
        help="Exact release chain ID",
    )
    governance_plan_p.add_argument(
        "--expected-contract-address",
        required=True,
        help="Exact DiligenceRoom address targeted by governance",
    )
    governance_plan_p.add_argument(
        "--expected-tee-identity",
        required=True,
        help="Exact dstack-derived CVM signer address",
    )
    governance_plan_p.add_argument(
        "--expected-cvm-domain",
        required=True,
        help="Exact target workload domain from the signed release authority",
    )
    governance_plan_p.add_argument(
        "--expected-cvm-id",
        required=True,
        help="Exact target workload CVM ID from the signed release authority",
    )
    governance_plan_p.add_argument(
        "--expected-deployment-intent-sha256",
        required=True,
        help="Exact signed deployment-intent digest",
    )
    governance_plan_p.add_argument(
        "--expected-release-authority-sha256",
        required=True,
        help="Exact signed seven-CVM release-authority digest",
    )
    governance_plan_p.add_argument(
        "--expected-ceremony-nonce",
        required=True,
        help="Exact deployment ceremony nonce",
    )
    governance_plan_p.add_argument(
        "--expected-measurement-policy-sha256",
        required=True,
        help="Exact linked QVL measurement-policy digest",
    )
    governance_plan_p.add_argument(
        "--expected-compose-hash",
        required=True,
        help="Exact release compose hash",
    )
    governance_plan_p.add_argument(
        "--expected-app-id",
        required=True,
        help="Exact Phala application ID",
    )
    governance_plan_p.add_argument(
        "--expected-os-image-hash",
        required=True,
        help="Exact release OS image hash",
    )
    governance_plan_p.add_argument(
        "--expected-quote-hash",
        required=True,
        help="Exact SHA-256 hash of the QVL-verified CVM quote",
    )
    governance_plan_p.add_argument(
        "--expected-attestation-release-policy-hash",
        required=True,
        help="Externally pinned QVL release-policy hash for the diligence profile",
    )
    governance_plan_p.add_argument(
        "--expected-attestation-challenge-id",
        required=True,
        help="Exact one-time QVL challenge identifier used for this quote",
    )
    governance_plan_p.add_argument(
        "--expected-attestation-challenge-digest",
        required=True,
        help="Exact QVL challenge digest bound into quote report_data[32:64]",
    )
    governance_plan_p.add_argument(
        "--expected-attestation-challenge-issued-at",
        type=int,
        required=True,
        help="Exact signed challenge issue time",
    )
    governance_plan_p.add_argument(
        "--expected-attestation-challenge-expires-at",
        type=int,
        required=True,
        help="Exact signed challenge expiry time",
    )
    governance_plan_p.add_argument(
        "--max-verdict-age-seconds",
        type=int,
        default=300,
        help="Maximum signed verdict age/lifetime (default: 300)",
    )
    governance_plan_p.add_argument(
        "--keystore-account",
        default="dev",
        help="Foundry keystore account for the cast command templates (default: dev)",
    )
    governance_plan_p.add_argument("--output", default="", help="Optional JSON output path")

    sub.add_parser(
        "account-access-status",
        help="Capture the bounded account access/billing gate (in-process, needs the CVM browser)",
    )

    # API server
    serve_p = sub.add_parser("serve", help="Start the FastAPI server")
    serve_p.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    serve_p.add_argument("--port", type=int, default=8080, help="Bind port (default: 8080)")

    args = parser.parse_args()
    settings = Settings()

    if args.command == "check":
        from tinker_delegate.oracle_client import OracleClient
        oracle = OracleClient(settings)
        health = oracle.health()
        print(json.dumps(health, indent=2))

    elif args.command == "signup":
        from tinker_delegate.signup import signup
        result = asyncio.run(signup(settings))
        print(json.dumps(result, indent=2, default=str))
        sys.exit(0 if result.get("success") else 1)

    elif args.command == "signin":
        from tinker_delegate.signup import signin
        result = asyncio.run(signin(settings))
        print(json.dumps(result, indent=2, default=str))
        sys.exit(0 if result.get("success") else 1)

    elif args.command == "reauth":
        from tinker_delegate.signup import reauth
        result = asyncio.run(reauth(settings))
        print(json.dumps(result, indent=2, default=str))
        sys.exit(0 if result.get("success") else 1)

    elif args.command == "account-access-status":
        from tinker_delegate.billing import get_account_access_status
        result = asyncio.run(get_account_access_status(settings))
        _emit_bounded_json(result)
        sys.exit(0 if result.get("success") else 1)

    elif args.command == "selector-map":
        from tinker_delegate.selector_map import build_selector_map

        result = build_selector_map(include_selectors=not args.summary_only)
        _emit_bounded_json(result, output_path=args.output)

    elif args.command == "selector-probe":
        from tinker_delegate.selector_map import run_live_selector_map_probe

        if args.no_local_browser_fallback:
            settings.local_browser_fallback = False
        try:
            result = run_live_selector_map_probe(settings)
        except Exception:
            result = {
                "surface": "tinker_console_and_stripe_billing",
                "raw_secret_egress": False,
                "bounded_output": True,
                "read_only": True,
                "success": False,
                "error_kind": "browser_unavailable",
                "bounded_message": "selector_probe_browser_unavailable",
            }
            _emit_bounded_json(result, output_path=args.output)
            sys.exit(1)
        _emit_bounded_json(result, output_path=args.output)

    elif args.command == "browser-readiness":
        from tinker_delegate.browser_diagnostics import run_browser_readiness

        result = run_browser_readiness(settings)
        _emit_bounded_json(result, output_path=args.output)
        sys.exit(0 if result.get("success") else 1)

    elif args.command == "synthetic-private-reward-demo":
        from tinker_delegate.private_reward_envs.synthetic_demo import (
            hidden_demo_forbidden_values,
            run_synthetic_hidden_keyword_demo,
        )

        candidates = tuple(args.candidate)
        result = run_synthetic_hidden_keyword_demo(candidates or None)
        _emit_bounded_json(
            result,
            output_path=args.output,
            forbidden_values=hidden_demo_forbidden_values(candidates or None),
        )

    elif args.command == "dp-bounded-reward-demo":
        from tinker_delegate.private_reward_envs.dp_bounded_demo import (
            dp_bounded_demo_forbidden_values,
            run_dp_bounded_reward_demo,
        )

        candidates = tuple(args.candidate)
        result = run_dp_bounded_reward_demo(
            candidates or None,
            max_epsilon=args.max_epsilon,
            epsilon_per_query=args.epsilon_per_query,
        )
        _emit_bounded_json(
            result,
            output_path=args.output,
            forbidden_values=dp_bounded_demo_forbidden_values(candidates or None),
        )

    elif args.command == "thresholdout-demo":
        from tinker_delegate.private_reward_envs.thresholdout_demo import run_thresholdout_demo

        result = run_thresholdout_demo(max_epsilon=args.max_epsilon)
        _emit_bounded_json(result, output_path=args.output)

    elif args.command == "denoising-private-reward-demo":
        from tinker_delegate.private_reward_envs.denoising_demo import (
            denoising_demo_forbidden_values,
            run_denoising_holdout_demo,
        )

        result = run_denoising_holdout_demo()
        _emit_bounded_json(
            result,
            output_path=args.output,
            forbidden_values=denoising_demo_forbidden_values(),
        )

    elif args.command == "denoising-sealed-dataset-demo":
        from tinker_delegate.private_reward_envs.denoising_demo import (
            denoising_demo_forbidden_values,
        )
        from tinker_delegate.private_reward_envs.denoising_sealed_demo import (
            run_denoising_sealed_dataset_demo,
        )

        result = run_denoising_sealed_dataset_demo()
        _emit_bounded_json(
            result,
            output_path=args.output,
            forbidden_values=denoising_demo_forbidden_values(),
        )

    elif args.command == "bio-assay-qc-reward-demo":
        from tinker_delegate.private_reward_envs.bio_assay_program_demo import (
            bio_assay_program_demo_forbidden_values,
            run_bio_assay_program_reward_demo,
        )

        result = run_bio_assay_program_reward_demo()
        _emit_bounded_json(
            result,
            output_path=args.output,
            forbidden_values=bio_assay_program_demo_forbidden_values(),
        )

    elif args.command == "policy-gate":
        from tinker_delegate.policy_gate_receipt import (
            build_policy_gate_receipt,
            build_policy_turn_gate_receipt,
        )

        single_mode = bool(args.request_json or args.policy_json)
        turn_mode = bool(args.turn_json or args.policies_json)
        if single_mode == turn_mode:
            raise SystemExit("provide either --request-json/--policy-json or --turn-json/--policies-json")
        if single_mode:
            if not args.request_json or not args.policy_json:
                raise SystemExit("--request-json and --policy-json must be provided together")
            request_payload = json.loads(Path(args.request_json).read_text(encoding="utf-8"))
            policy_payload = json.loads(Path(args.policy_json).read_text(encoding="utf-8"))
            result = build_policy_gate_receipt(request_payload, policy_payload)
        else:
            if not args.turn_json or not args.policies_json:
                raise SystemExit("--turn-json and --policies-json must be provided together")
            turn_payload = json.loads(Path(args.turn_json).read_text(encoding="utf-8"))
            policies_payload = json.loads(Path(args.policies_json).read_text(encoding="utf-8"))
            result = build_policy_turn_gate_receipt(turn_payload, policies_payload)
        _emit_bounded_json(result, output_path=args.output)

    elif args.command == "consent-decision":
        from tinker_delegate.consent_receipt import build_consent_decision_receipt

        state_payload = json.loads(Path(args.state_json).read_text(encoding="utf-8"))
        decision_payload = json.loads(Path(args.decision_json).read_text(encoding="utf-8"))
        result = build_consent_decision_receipt(
            state_payload,
            decision_payload,
            now=args.now,
            require_signature=args.require_signature,
            expected_signer=args.expected_signer,
        )
        _emit_bounded_json(result, output_path=args.output, forbidden_values=(args.expected_signer,))

    elif args.command == "tinker-smoke":
        payload = {
            "deal_id": args.deal_id,
            "max_usd": args.max_usd,
            "model": args.model,
            "rank": args.rank,
            "ttl_seconds": args.ttl_seconds,
            "compose_hash": args.compose_hash,
            "require_encumbrance": args.require_encumbrance,
        }
        if args.api_url:
            import httpx

            headers = _runtime_auth_headers(args.auth_token_env)
            with httpx.Client(timeout=600.0) as client:
                response = client.post(
                    _api_endpoint(args.api_url, "/tinker/smoke"),
                    json=payload,
                    headers=headers,
                )
            try:
                body = response.json()
            except Exception:
                body = {
                    "surface": "tinker_sdk_smoke",
                    "success": False,
                    "outcome": "remote_non_json_response",
                    "furthest_stage": "remote_http_response",
                    "status_code": response.status_code,
                    "error_kind": "non_json_response",
                    "bounded_message": "remote endpoint returned non-json response",
                    "raw_secret_egress": False,
                }
            _emit_bounded_json(
                body,
                output_path=args.output,
                public_hex_fields=("contract_address", "compose_hash"),
                public_decimal_fields=("amount_wei", "max_amount_wei"),
            )
            sys.exit(0 if response.status_code < 400 and body.get("success") else 1)

        from tinker_delegate.tinker_smoke import TinkerSmokeRequest, run_tinker_sdk_smoke

        result = run_tinker_sdk_smoke(
            settings,
            TinkerSmokeRequest(
                deal_id=args.deal_id,
                max_usd=args.max_usd,
                model=args.model,
                rank=args.rank,
                ttl_seconds=args.ttl_seconds,
                compose_hash=args.compose_hash,
                require_encumbrance=args.require_encumbrance,
            ),
        )
        _emit_bounded_json(
            result,
            output_path=args.output,
            public_hex_fields=("contract_address", "compose_hash"),
            public_decimal_fields=("amount_wei", "max_amount_wei"),
        )
        sys.exit(0 if result.get("success") else 1)

    elif args.command == "tinker-proxy-status":
        if args.api_url:
            import httpx

            headers = _runtime_auth_headers(args.auth_token_env)
            with httpx.Client(timeout=120.0) as client:
                response = client.get(_api_endpoint(args.api_url, "/tinker/proxy/status"), headers=headers)
            try:
                body = response.json()
            except Exception:
                body = {
                    "surface": "tinker_proxy",
                    "success": False,
                    "outcome": "remote_non_json_response",
                    "status_code": response.status_code,
                    "error_kind": "non_json_response",
                    "bounded_message": "remote endpoint returned non-json response",
                    "raw_secret_egress": False,
                }
            _emit_bounded_json(body, output_path=args.output)
            sys.exit(0 if response.status_code < 400 and body.get("success") else 1)

        from tinker_delegate.tinker_proxy import build_tinker_proxy_status

        result = build_tinker_proxy_status(settings)
        _emit_bounded_json(result, output_path=args.output)
        sys.exit(0 if result.get("success") else 1)

    elif args.command == "tinker-client-config":
        project_id = os.environ.get(args.project_id_env, "").strip()
        base_url = os.environ.get(args.base_url_env, "").strip()
        if args.install and not project_id and not base_url:
            result = {
                "surface": "tinker_client_config_install",
                "success": False,
                "error_kind": "missing_client_config_env",
                "bounded_message": "project/base-url environment variables are not configured",
                "project_id_returned": False,
                "base_url_returned": False,
                "raw_secret_egress": False,
            }
            _emit_bounded_json(result, output_path=args.output)
            sys.exit(1)

        if args.api_url:
            import httpx

            headers = _runtime_auth_headers(args.auth_token_env)
            with httpx.Client(timeout=120.0) as client:
                if args.install:
                    response = client.put(
                        _api_endpoint(args.api_url, "/tinker/proxy/client-config"),
                        headers=headers,
                        json={"project_id": project_id, "base_url": base_url},
                    )
                else:
                    response = client.get(
                        _api_endpoint(args.api_url, "/tinker/proxy/client-config"),
                        headers=headers,
                    )
            try:
                body = response.json()
            except Exception:
                body = {
                    "surface": "tinker_client_config",
                    "success": False,
                    "outcome": "remote_non_json_response",
                    "status_code": response.status_code,
                    "error_kind": "non_json_response",
                    "bounded_message": "remote endpoint returned non-json response",
                    "raw_secret_egress": False,
                }
            if response.status_code >= 400:
                detail = body.get("detail", "") if isinstance(body, dict) else ""
                body = {
                    "surface": "tinker_client_config",
                    "success": False,
                    "outcome": "remote_rejected",
                    "status_code": response.status_code,
                    "error_kind": "remote_error",
                    "bounded_message": redact_text(detail or "remote endpoint rejected client config request"),
                    "project_id_returned": False,
                    "base_url_returned": False,
                    "raw_secret_egress": False,
                }
            _emit_bounded_json(body, output_path=args.output, forbidden_values=(project_id, base_url))
            sys.exit(0 if response.status_code < 400 and body.get("success") else 1)

        from tinker_delegate.tinker_client_config_store import (
            build_tinker_client_config_status,
            save_tinker_client_config,
        )

        try:
            result = (
                save_tinker_client_config(settings, project_id=project_id, base_url=base_url)
                if args.install
                else build_tinker_client_config_status(settings)
            )
        except ValueError as exc:
            result = {
                "surface": "tinker_client_config_install" if args.install else "tinker_client_config",
                "success": False,
                "error_kind": "invalid_client_config",
                "bounded_message": redact_text(exc),
                "project_id_returned": False,
                "base_url_returned": False,
                "raw_secret_egress": False,
            }
        _emit_bounded_json(result, output_path=args.output, forbidden_values=(project_id, base_url))
        sys.exit(0 if result.get("success") else 1)

    elif args.command == "tinker-proxy-issue-policy":
        policy = json.loads(Path(args.policy_json).read_text(encoding="utf-8")) if args.policy_json else None
        if args.api_url:
            import httpx

            headers = _runtime_auth_headers(args.auth_token_env)
            with httpx.Client(timeout=120.0) as client:
                if policy is None:
                    response = client.get(_api_endpoint(args.api_url, "/tinker/proxy/issue-policy"), headers=headers)
                else:
                    response = client.put(
                        _api_endpoint(args.api_url, "/tinker/proxy/issue-policy"),
                        headers=headers,
                        json={"policy": policy},
                    )
            try:
                body = response.json()
            except Exception:
                body = {
                    "surface": "tinker_proxy_issue_policy",
                    "success": False,
                    "outcome": "remote_non_json_response",
                    "status_code": response.status_code,
                    "error_kind": "non_json_response",
                    "bounded_message": "remote endpoint returned non-json response",
                    "raw_secret_egress": False,
                }
            _emit_bounded_json(body, output_path=args.output)
            sys.exit(0 if response.status_code < 400 and body.get("success") else 1)

        from tinker_delegate.tinker_proxy import (
            get_proxy_issue_policy_status,
            save_proxy_issue_policy,
        )

        try:
            result = save_proxy_issue_policy(settings, policy) if policy is not None else get_proxy_issue_policy_status(settings)
        except ValueError as exc:
            result = {
                "surface": "tinker_proxy_issue_policy",
                "success": False,
                "error_kind": "invalid_proxy_issue_policy",
                "bounded_message": redact_text(exc),
                "raw_secret_egress": False,
            }
        _emit_bounded_json(result, output_path=args.output)
        sys.exit(0 if result.get("success") else 1)

    elif args.command == "tinker-proxy-identity-registry":
        registry = json.loads(Path(args.registry_json).read_text(encoding="utf-8")) if args.registry_json else None
        if args.api_url:
            import httpx

            headers = _runtime_auth_headers(args.auth_token_env)
            with httpx.Client(timeout=120.0) as client:
                if registry is None:
                    response = client.get(
                        _api_endpoint(args.api_url, "/tinker/proxy/identity-registry"),
                        headers=headers,
                    )
                else:
                    response = client.put(
                        _api_endpoint(args.api_url, "/tinker/proxy/identity-registry"),
                        headers=headers,
                        json={"registry": registry},
                    )
            try:
                body = response.json()
            except Exception:
                body = {
                    "surface": "tinker_proxy_identity_registry",
                    "success": False,
                    "outcome": "remote_non_json_response",
                    "status_code": response.status_code,
                    "error_kind": "non_json_response",
                    "bounded_message": "remote endpoint returned non-json response",
                    "raw_secret_egress": False,
                }
            _emit_bounded_json(body, output_path=args.output)
            sys.exit(0 if response.status_code < 400 and body.get("success") else 1)

        from tinker_delegate.tinker_proxy import (
            get_proxy_identity_registry_status,
            save_proxy_identity_registry,
        )

        try:
            result = (
                save_proxy_identity_registry(settings, registry)
                if registry is not None
                else get_proxy_identity_registry_status(settings)
            )
        except ValueError as exc:
            result = {
                "surface": "tinker_proxy_identity_registry",
                "success": False,
                "error_kind": "invalid_proxy_identity_registry",
                "bounded_message": redact_text(exc),
                "raw_secret_egress": False,
            }
        _emit_bounded_json(result, output_path=args.output)
        sys.exit(0 if result.get("success") else 1)

    elif args.command == "sign-tinker-proxy-identity-registry":
        from tinker_delegate.tinker_proxy import sign_proxy_identity_registry

        signer_private_key = os.environ.get(args.signer_key_env, "").strip()
        if not signer_private_key:
            result = {
                "surface": "tinker_proxy_identity_registry_sign",
                "success": False,
                "error_kind": "missing_signer_key",
                "bounded_message": "signer key environment variable is not configured",
                "private_key_returned": False,
                "raw_secret_egress": False,
            }
            _emit_bounded_json(result, output_path=args.output)
            sys.exit(1)
        registry = json.loads(Path(args.registry_json).read_text(encoding="utf-8"))
        try:
            signed_registry, result = sign_proxy_identity_registry(registry, signer_private_key)
            Path(args.signed_registry_output).write_text(
                json.dumps(signed_registry, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            result = {
                **result,
                "signed_registry_output": str(Path(args.signed_registry_output)),
                "signed_registry_written": True,
                "signed_registry_returned": False,
            }
        except Exception as exc:
            result = {
                "surface": "tinker_proxy_identity_registry_sign",
                "success": False,
                "error_kind": exc.__class__.__name__,
                "bounded_message": redact_text(exc),
                "private_key_returned": False,
                "raw_secret_egress": False,
            }
        _emit_bounded_json(result, output_path=args.output, forbidden_values=(signer_private_key,))
        sys.exit(0 if result.get("success") else 1)

    elif args.command == "verify-tinker-proxy-identity-registry":
        from tinker_delegate.tinker_proxy import verify_signed_proxy_identity_registry

        registry = json.loads(Path(args.registry_json).read_text(encoding="utf-8"))
        try:
            result = verify_signed_proxy_identity_registry(registry, args.expected_signer)
        except Exception as exc:
            result = {
                "surface": "tinker_proxy_identity_registry_verify",
                "success": False,
                "error_kind": exc.__class__.__name__,
                "bounded_message": redact_text(exc),
                "raw_secret_egress": False,
            }
        _emit_bounded_json(result, output_path=args.output, forbidden_values=(args.expected_signer,))
        sys.exit(0 if result.get("success") else 1)

    elif args.command == "sign-tinker-proxy-grant-lifecycle":
        from tinker_delegate.tinker_proxy import sign_proxy_grant_lifecycle

        signer_private_key = os.environ.get(args.signer_key_env, "").strip()
        if not signer_private_key:
            result = {
                "surface": "tinker_proxy_grant_lifecycle_sign",
                "success": False,
                "error_kind": "missing_signer_key",
                "bounded_message": "signer key environment variable is not configured",
                "private_key_returned": False,
                "raw_secret_egress": False,
            }
            _emit_bounded_json(result, output_path=args.output)
            sys.exit(1)
        grant = json.loads(Path(args.grant_json).read_text(encoding="utf-8"))
        try:
            signed_grant, result = sign_proxy_grant_lifecycle(grant, signer_private_key)
            Path(args.signed_grant_output).write_text(
                json.dumps(signed_grant, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            result = {
                **result,
                "signed_grant_output": str(Path(args.signed_grant_output)),
                "signed_grant_written": True,
                "signed_grant_returned": False,
            }
        except Exception as exc:
            result = {
                "surface": "tinker_proxy_grant_lifecycle_sign",
                "success": False,
                "error_kind": exc.__class__.__name__,
                "bounded_message": redact_text(exc),
                "private_key_returned": False,
                "raw_secret_egress": False,
            }
        _emit_bounded_json(result, output_path=args.output, forbidden_values=(signer_private_key,))
        sys.exit(0 if result.get("success") else 1)

    elif args.command == "issue-tinker-proxy-token":
        if args.api_url:
            import httpx

            headers = _runtime_auth_headers(args.auth_token_env)
            with httpx.Client(timeout=120.0) as client:
                response = client.post(
                    _api_endpoint(args.api_url, "/tinker/proxy/token"),
                    headers=headers,
                    json={
                        "subject": args.subject,
                        "scopes": args.scope,
                        "recipient_public_key": args.recipient_public_key,
                        "ttl_seconds": args.ttl_seconds,
                    },
                )
            try:
                body = response.json()
            except Exception:
                body = {
                    "surface": "tinker_proxy_token",
                    "success": False,
                    "outcome": "remote_non_json_response",
                    "status_code": response.status_code,
                    "error_kind": "non_json_response",
                    "bounded_message": "remote endpoint returned non-json response",
                    "plaintext_token_returned": False,
                    "raw_secret_egress": False,
                }
            if response.status_code >= 400:
                detail = body.get("detail", "") if isinstance(body, dict) else ""
                body = {
                    "surface": "tinker_proxy_token",
                    "success": False,
                    "outcome": "remote_rejected",
                    "status_code": response.status_code,
                    "error_kind": "remote_error",
                    "bounded_message": redact_text(detail or "remote endpoint rejected proxy token issuance"),
                    "plaintext_token_returned": False,
                    "raw_secret_egress": False,
                }
            _emit_bounded_json(body, output_path=args.output)
            sys.exit(0 if response.status_code < 400 and body.get("success") else 1)

        from tinker_delegate.tinker_proxy import issue_encrypted_proxy_token

        result = issue_encrypted_proxy_token(
            settings,
            subject=args.subject,
            scopes=args.scope,
            recipient_public_key_hex=args.recipient_public_key,
            ttl_seconds=args.ttl_seconds,
        )
        _emit_bounded_json(result, output_path=args.output)
        sys.exit(0 if result.get("success") else 1)

    elif args.command == "tinker-proxy-token-audit":
        if args.api_url:
            import httpx

            headers = _runtime_auth_headers(args.auth_token_env)
            with httpx.Client(timeout=120.0) as client:
                response = client.get(_api_endpoint(args.api_url, "/tinker/proxy/tokens"), headers=headers)
            body = response.json()
            _emit_bounded_json(body, output_path=args.output)
            sys.exit(0 if response.status_code < 400 else 1)

        from tinker_delegate.tinker_proxy_store import (
            build_proxy_token_store,
            summarize_proxy_token_records,
        )

        result = summarize_proxy_token_records(build_proxy_token_store(settings).load())
        _emit_bounded_json(result, output_path=args.output)
        sys.exit(0)

    elif args.command == "verify-tinker-proxy-token-audit":
        from tinker_delegate.tinker_proxy_audit import verify_proxy_token_audit

        audit = json.loads(Path(args.audit_json).read_text(encoding="utf-8"))
        operation_receipts = [
            json.loads(Path(path).read_text(encoding="utf-8"))
            for path in args.operation_receipt_json
        ]
        result = verify_proxy_token_audit(
            audit=audit,
            operation_receipts=operation_receipts,
            require_operation_binding=args.require_operation_binding,
        ).to_public_dict()
        _emit_bounded_json(result, output_path=args.output)
        sys.exit(0 if result["ok"] else 1)

    elif args.command == "revoke-tinker-proxy-token":
        if args.api_url:
            import httpx

            headers = _runtime_auth_headers(args.auth_token_env)
            with httpx.Client(timeout=120.0) as client:
                response = client.post(
                    _api_endpoint(args.api_url, "/tinker/proxy/token/revoke"),
                    headers=headers,
                    json={"jwt_id_hash": args.jwt_id_hash, "reason": args.reason},
                )
            body = response.json()
            _emit_bounded_json(body, output_path=args.output)
            sys.exit(0 if response.status_code < 400 and body.get("success") else 1)

        from tinker_delegate.tinker_proxy_store import build_proxy_token_store

        try:
            record = build_proxy_token_store(settings).revoke(args.jwt_id_hash, reason=args.reason)
            result = {
                "surface": "tinker_proxy_token_revoke",
                "success": True,
                "record": record,
                "raw_secret_egress": False,
            }
        except ValueError as exc:
            result = {
                "surface": "tinker_proxy_token_revoke",
                "success": False,
                "outcome": "revoke_rejected",
                "error_kind": type(exc).__name__,
                "bounded_message": redact_text(exc),
                "raw_secret_egress": False,
            }
        _emit_bounded_json(result, output_path=args.output)
        sys.exit(0 if result.get("success") else 1)

    elif args.command == "tinker-proxy-recipient-keygen":
        from tinker_delegate.run_metadata_store import stable_hash
        from tinker_delegate.tinker_proxy import generate_proxy_recipient_keypair

        private_key_hex, public_key_hex = generate_proxy_recipient_keypair()
        _write_secret_text(args.private_key_output, private_key_hex)
        result = {
            "surface": "tinker_proxy_recipient_keygen",
            "success": True,
            "public_key": public_key_hex,
            "public_key_hash": stable_hash(
                public_key_hex.lower(), prefix="proxy_recipient_public_key"
            ),
            "private_key_path": str(Path(args.private_key_output)),
            "private_key_saved": True,
            "private_key_returned": False,
            "raw_secret_egress": False,
        }
        _emit_bounded_json(result, output_path=args.output, public_hex_fields=("public_key",))
        sys.exit(0)

    elif args.command == "decrypt-tinker-proxy-token":
        from tinker_delegate.tinker_proxy import decrypt_encrypted_proxy_token

        payload = json.loads(Path(args.encrypted_token_json).read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or not isinstance(payload.get("encrypted_token"), dict):
            result = {
                "surface": "tinker_proxy_token_decrypt",
                "success": False,
                "error_kind": "missing_encrypted_token",
                "bounded_message": "encrypted proxy token envelope is not present",
                "plaintext_token_saved": False,
                "plaintext_token_returned": False,
                "private_key_read": False,
                "private_key_returned": False,
                "raw_secret_egress": False,
            }
            _emit_bounded_json(result, output_path=args.output)
            sys.exit(1)
        private_key_hex = Path(args.private_key_file).read_text(encoding="utf-8").strip()
        try:
            token = decrypt_encrypted_proxy_token(payload, private_key_hex)
            _write_secret_text(args.token_output, token)
            result = {
                "surface": "tinker_proxy_token_decrypt",
                "success": True,
                "token_hash": hashlib.sha256(token.encode("utf-8")).hexdigest(),
                "token_output": str(Path(args.token_output)),
                "plaintext_token_saved": True,
                "plaintext_token_returned": False,
                "private_key_returned": False,
                "raw_secret_egress": False,
            }
        except Exception as exc:
            result = {
                "surface": "tinker_proxy_token_decrypt",
                "success": False,
                "error_kind": exc.__class__.__name__,
                "bounded_message": redact_text(exc),
                "plaintext_token_saved": False,
                "plaintext_token_returned": False,
                "private_key_returned": False,
                "raw_secret_egress": False,
            }
        _emit_bounded_json(result, output_path=args.output, forbidden_values=(private_key_hex,))
        sys.exit(0 if result.get("success") else 1)

    elif args.command == "balance":
        if args.api_url:
            import httpx

            headers = _runtime_auth_headers(args.auth_token_env)
            with httpx.Client(timeout=120.0) as client:
                response = client.get(_api_endpoint(args.api_url, "/billing/balance"), headers=headers)
            body = response.json()
            _emit_bounded_json(body, output_path=args.output)
            sys.exit(0 if response.status_code < 400 and body.get("success") else 1)

        from tinker_delegate.billing import get_balance
        result = asyncio.run(get_balance(settings))
        _emit_bounded_json(result, output_path=args.output)

    elif args.command == "funding-policy":
        from tinker_delegate.funding_policy import funding_policy_status
        print(json.dumps(funding_policy_status(settings).to_public_dict(), indent=2))

    elif args.command == "funding-preflight":
        from tinker_delegate.funding_policy import funding_validation_preflight
        result = funding_validation_preflight(
            settings,
            amount_dollars=args.amount,
            require_add_balance_endpoint=args.require_add_balance_endpoint,
            api_url=args.api_url,
            expected_compose_hash=args.compose_hash,
            expected_app_id=args.app_id,
            expected_os_image_hash=args.os_image_hash,
            allow_local_attestation=args.allow_local_attestation,
            fetch_attestation=args.fetch_attestation,
        )
        _emit_bounded_json(result.to_public_dict(), output_path=args.output)
        sys.exit(0 if result.ready else 1)

    elif args.command == "tinker-encumbrance-preflight":
        from tinker_delegate.tinker_encumbrance import (
            TinkerOperationKind,
            preflight_tinker_operation,
        )

        operation_kinds = {
            "add-payment-method": TinkerOperationKind.ADD_PAYMENT_METHOD,
            "add-balance": TinkerOperationKind.ADD_BALANCE,
            "spend-tinker-compute": TinkerOperationKind.SPEND_TINKER_COMPUTE,
            "manual-prefund": TinkerOperationKind.MANUAL_PREFUND,
        }
        result = preflight_tinker_operation(
            settings,
            operation_kind=operation_kinds[args.operation],
            amount_dollars=args.amount,
            amount_wei=args.amount_wei,
            compose_hash=args.compose_hash,
            contract_address=args.contract_address,
            rpc_url=args.rpc_url,
            required=args.required or None,
        )
        _emit_bounded_json(
            result.to_public_dict(),
            output_path=args.output,
            public_hex_fields=("contract_address", "compose_hash"),
            public_decimal_fields=("amount_wei", "max_amount_wei"),
        )
        sys.exit(0 if result.allowed else 1)

    elif args.command == "funding-command-plan":
        from tinker_delegate.funding_command_plan import (
            DEFAULT_MANIFEST_PATH,
            build_funding_command_plan,
        )

        result = build_funding_command_plan(
            manifest_path=args.manifest or DEFAULT_MANIFEST_PATH,
            amount_dollars=args.amount,
            output_dir=args.output_dir,
            validation_id=args.validation_id,
            encumbrance_rpc_env=args.encumbrance_rpc_env,
            runtime_auth_env=args.runtime_auth_env,
            include_reauth=not args.skip_reauth,
            include_add_balance=not args.skip_add_balance,
        ).to_public_dict()
        _emit_bounded_json(result, output_path=args.output)
        sys.exit(0 if result["ready"] else 1)

    elif args.command == "tinker-smoke-command-plan":
        from tinker_delegate.tinker_smoke_command_plan import (
            DEFAULT_MANIFEST_PATH,
            build_tinker_smoke_command_plan,
        )

        result = build_tinker_smoke_command_plan(
            manifest_path=args.manifest or DEFAULT_MANIFEST_PATH,
            compose_path=args.compose,
            runtime_env_path=args.runtime_env,
            api_env_path=args.api_env,
            max_usd=args.max_usd,
            model=args.model,
            rank=args.rank,
            output_path_template=args.output_path_template,
            encumbrance_rpc_env=args.encumbrance_rpc_env,
            runtime_auth_env=args.runtime_auth_env,
            project_id_env=args.project_id_env,
            base_url_env=args.base_url_env,
            account_access_state=args.account_access_state,
        ).to_public_dict()
        _emit_bounded_json(result, output_path=args.output)
        sys.exit(0 if result["ready"] else 1)

    elif args.command == "verify-deployed-log-safety":
        from tinker_delegate.deployed_log_safety import scan_deployed_log_text

        if args.logs_file == "-":
            text = sys.stdin.read()
        else:
            text = Path(args.logs_file).read_text(encoding="utf-8", errors="replace")
        result = scan_deployed_log_text(text, source_label=args.source_label).to_public_dict()
        _emit_bounded_json(result, output_path=args.output)
        sys.exit(0 if result.get("success") else 1)

    elif args.command == "funding-manifest":
        from tinker_delegate.funding_manifest import build_funding_validation_manifest

        preflight = json.loads(Path(args.preflight_json).read_text(encoding="utf-8"))
        receipt = json.loads(Path(args.receipt_json).read_text(encoding="utf-8"))
        manifest = build_funding_validation_manifest(
            preflight=preflight,
            receipt=receipt,
            validation_id=args.validation_id,
            attestation_policy={
                "compose_hash": args.compose_hash,
                "app_id": args.app_id,
                "os_image_hash": args.os_image_hash,
            },
        ).to_public_dict()
        rendered = json.dumps(manifest, indent=2)
        if args.output:
            Path(args.output).write_text(rendered + "\n", encoding="utf-8")
        else:
            print(rendered)
        sys.exit(0 if manifest["no_raw_card_retained"] else 1)

    elif args.command == "verify-funding-manifest":
        from tinker_delegate.funding_manifest import verify_funding_validation_manifest

        preflight = json.loads(Path(args.preflight_json).read_text(encoding="utf-8"))
        receipt = json.loads(Path(args.receipt_json).read_text(encoding="utf-8"))
        manifest = json.loads(Path(args.manifest_json).read_text(encoding="utf-8"))
        result = verify_funding_validation_manifest(
            preflight=preflight,
            receipt=receipt,
            manifest=manifest,
            validation_id=args.validation_id,
            attestation_policy={
                "compose_hash": args.compose_hash,
                "app_id": args.app_id,
                "os_image_hash": args.os_image_hash,
            },
            require_ready=args.require_ready,
            require_no_raw_card_retained=not args.allow_card_retention_flag,
        )
        _emit_bounded_json(result.to_public_dict(), output_path=args.output)
        sys.exit(0 if result.ok else 1)

    elif args.command == "funding-validation-packet":
        from tinker_delegate.funding_validation_packet import run_funding_validation_packet

        card_fields = {
            "card_number": args.number,
            "exp_month": args.exp_month,
            "exp_year": args.exp_year,
            "cvc": args.cvc,
            "cardholder_name": args.name,
            "address_line1": args.address_line1,
            "address_city": args.address_city,
            "address_state": args.address_state,
            "address_postal": args.address_postal,
            "address_country": args.address_country,
        }
        provided_card_fields = [
            value
            for key, value in card_fields.items()
            if key != "address_country" and value
        ]
        if provided_card_fields and not args.run_card_attempt:
            print("[funding-validation-packet] card fields require --run-card-attempt")
            sys.exit(1)
        if args.prompt_card and provided_card_fields:
            print("[funding-validation-packet] use either --prompt-card or test-card fields, not both")
            sys.exit(1)
        if args.prompt_card and not args.run_card_attempt:
            print("[funding-validation-packet] --prompt-card requires --run-card-attempt")
            sys.exit(1)
        required_card_fields = ("card_number", "exp_month", "exp_year", "cvc", "cardholder_name")
        if args.run_card_attempt and args.prompt_card:
            try:
                _validate_prompt_billing_policy(
                    args,
                    settings,
                    amount_dollars=args.amount if args.run_add_balance_attempt else None,
                )
            except ValueError as exc:
                print(f"[funding-validation-packet] policy rejected: {redact_text(exc)}")
                sys.exit(1)
            card_fields = _prompt_billing_card_payload()
        if args.run_card_attempt and any(not card_fields[field] for field in required_card_fields):
            print("[funding-validation-packet] --run-card-attempt requires card number, expiration, CVC, and name")
            for key in list(card_fields):
                card_fields[key] = ""
            sys.exit(1)
        if args.run_add_balance_attempt and args.amount is None:
            print("[funding-validation-packet] --run-add-balance-attempt requires --amount")
            sys.exit(1)

        result = run_funding_validation_packet(
            settings,
            output_dir=Path(args.output_dir),
            api_url=args.api_url,
            amount_dollars=args.amount,
            expected_compose_hash=args.compose_hash,
            expected_app_id=args.app_id,
            expected_os_image_hash=args.os_image_hash,
            allow_local_attestation=args.allow_local_attestation,
            auth_token=os.environ.get(args.auth_token_env, ""),
            fetch_attestation=args.fetch_attestation,
            require_add_balance_endpoint=args.require_add_balance_endpoint,
            validation_id=args.validation_id,
            receipt_json=Path(args.receipt_json) if args.receipt_json else None,
            add_balance_receipt_json=(
                Path(args.add_balance_receipt_json) if args.add_balance_receipt_json else None
            ),
            run_card_attempt=args.run_card_attempt,
            run_reauth_attempt=args.run_reauth_attempt,
            run_add_balance_attempt=args.run_add_balance_attempt,
            card_data=card_fields if args.run_card_attempt else None,
        )
        _emit_bounded_json(result.to_public_dict())
        sys.exit(0 if result.ok else 1)

    elif args.command == "check-funding-validation-packet":
        from tinker_delegate.funding_validation_packet import check_funding_validation_packet

        result = check_funding_validation_packet(
            packet_dir=Path(args.packet_dir),
            validation_id=args.validation_id,
            expected_compose_hash=args.compose_hash,
            expected_app_id=args.app_id,
            expected_os_image_hash=args.os_image_hash,
            require_add_balance=args.require_add_balance,
            require_deployed_attestation=args.require_deployed_attestation,
        )
        _emit_bounded_json(result.to_public_dict(), output_path=args.output)
        sys.exit(0 if result.ok else 1)

    elif args.command == "add-card":
        from tinker_delegate.card_channel import CardPayload, handle_card_update
        payload = CardPayload(
            card_number=args.number,
            exp_month=args.exp_month,
            exp_year=args.exp_year,
            cvc=args.cvc,
            cardholder_name=args.name,
            address_line1=args.address_line1,
            address_city=args.address_city,
            address_state=args.address_state,
            address_postal=args.address_postal,
            address_country=args.address_country,
        )
        result = asyncio.run(handle_card_update(payload, settings))
        body = result.model_dump(mode="json")
        if args.receipt_output:
            _emit_bounded_json(_receipt_or_raise(body), output_path=args.receipt_output)
        _emit_bounded_json(body)
        sys.exit(0 if result.success else 1)

    elif args.command == "add-balance":
        from tinker_delegate.card_channel import BalancePayload, handle_add_balance
        if args.api_url:
            import httpx

            headers = _runtime_auth_headers(args.auth_token_env)
            with httpx.Client(timeout=120.0) as client:
                response = client.post(
                    _api_endpoint(args.api_url, "/billing/add-balance"),
                    json={"amount_dollars": args.amount},
                    headers=headers,
                )
            body = response.json()
            if args.receipt_output:
                _emit_bounded_json(_receipt_or_raise(body), output_path=args.receipt_output)
            _emit_bounded_json(body, output_path=args.output)
            sys.exit(0 if response.status_code < 400 and body.get("success") else 1)

        payload = BalancePayload(amount_dollars=args.amount)
        result = asyncio.run(handle_add_balance(payload, settings))
        body = result.model_dump(mode="json")
        if args.receipt_output:
            _emit_bounded_json(_receipt_or_raise(body), output_path=args.receipt_output)
        _emit_bounded_json(body, output_path=args.output)
        sys.exit(0 if result.success else 1)

    elif args.command == "payment-method-status":
        import httpx

        headers = _runtime_auth_headers(args.auth_token_env)
        with httpx.Client(timeout=120.0) as client:
            response = client.get(_api_endpoint(args.api_url, "/billing/payment-method-status"), headers=headers)
        body = response.json()
        _emit_bounded_json(body, output_path=args.output)
        sys.exit(0 if response.status_code < 400 and body.get("success") else 1)

    elif args.command == "remove-card":
        import httpx

        headers = _runtime_auth_headers(args.auth_token_env)
        with httpx.Client(timeout=120.0) as client:
            response = client.post(_api_endpoint(args.api_url, "/billing/card/remove"), headers=headers)
        body = response.json()
        if args.receipt_output:
            _emit_bounded_json(_receipt_or_raise(body), output_path=args.receipt_output)
        _emit_bounded_json(body, output_path=args.output)
        sys.exit(0 if response.status_code < 400 and body.get("success") else 1)

    elif args.command == "add-card-encrypted":
        from tinker_delegate.attestation_verifier import AttestationVerificationError
        from tinker_delegate.billing_uploader import (
            BillingCardUploadPolicy,
            upload_billing_card_payload,
        )

        card = {
            "card_number": args.number,
            "exp_month": args.exp_month,
            "exp_year": args.exp_year,
            "cvc": args.cvc,
            "cardholder_name": args.name,
            "address_line1": args.address_line1,
            "address_city": args.address_city,
            "address_state": args.address_state,
            "address_postal": args.address_postal,
            "address_country": args.address_country,
        }
        policy = BillingCardUploadPolicy(
            expected_compose_hash=args.compose_hash,
            expected_app_id=args.app_id,
            expected_os_image_hash=args.os_image_hash,
            allow_local=args.allow_local_attestation,
            chain_id=84532,
            diligence_room_address=args.diligence_room_address,
            evaluator_policy_commitment=args.evaluator_policy_commitment,
            auth_token=os.environ.get(args.auth_token_env, ""),
        )
        try:
            result = upload_billing_card_payload(args.api_url, card, policy)
        except AttestationVerificationError as exc:
            print(f"[add-card-encrypted] attestation rejected: {redact_text(exc)}")
            sys.exit(1)
        except Exception as exc:
            print(f"[add-card-encrypted] update failed: {redact_text(exc)}")
            sys.exit(1)
        finally:
            for key in list(card):
                card[key] = ""

        body = {
            "status_code": result.status_code,
            "response": result.response,
        }
        forbidden_values = (
            args.number,
            args.name,
            args.address_line1,
            args.address_postal,
        )
        if args.receipt_output:
            _emit_bounded_json(
                _receipt_or_raise(result.response),
                output_path=args.receipt_output,
                forbidden_values=forbidden_values,
            )
        _emit_bounded_json(body, forbidden_values=forbidden_values)
        sys.exit(0 if result.response.get("success") else 1)

    elif args.command == "add-card-encrypted-prompt":
        from tinker_delegate.attestation_verifier import AttestationVerificationError
        from tinker_delegate.billing_uploader import (
            BillingCardUploadPolicy,
            upload_billing_card_payload,
        )

        try:
            _validate_prompt_billing_policy(args, settings)
        except ValueError as exc:
            print(f"[add-card-encrypted-prompt] policy rejected: {redact_text(exc)}")
            sys.exit(1)

        card = _prompt_billing_card_payload()
        policy = BillingCardUploadPolicy(
            expected_compose_hash=args.compose_hash,
            expected_app_id=args.app_id,
            expected_os_image_hash=args.os_image_hash,
            allow_local=args.allow_local_attestation,
            auth_token=os.environ.get(args.auth_token_env, ""),
        )
        forbidden_values = tuple(card.values())
        try:
            result = upload_billing_card_payload(args.api_url, card, policy)
        except AttestationVerificationError as exc:
            print(f"[add-card-encrypted-prompt] attestation rejected: {redact_text(exc)}")
            sys.exit(1)
        except Exception as exc:
            print(f"[add-card-encrypted-prompt] update failed: {redact_text(exc)}")
            sys.exit(1)
        finally:
            for key in list(card):
                card[key] = ""

        body = {
            "status_code": result.status_code,
            "response": result.response,
        }
        if args.receipt_output:
            _emit_bounded_json(
                _receipt_or_raise(result.response),
                output_path=args.receipt_output,
                forbidden_values=forbidden_values,
            )
        _emit_bounded_json(body, forbidden_values=forbidden_values)
        sys.exit(0 if result.response.get("success") else 1)

    elif args.command == "upload-artifact":
        from tinker_delegate.artifact_uploader import (
            ArtifactUploadPolicy,
            AttestationVerificationError,
            upload_artifact_file,
        )

        policy = ArtifactUploadPolicy(
            expected_compose_hash=args.compose_hash,
            expected_app_id=args.app_id,
            expected_os_image_hash=args.os_image_hash,
            allow_local=args.allow_local_attestation,
        )
        try:
            result = upload_artifact_file(
                args.api_url,
                args.deal_id,
                args.artifact_path,
                args.commitment_receipt_path,
                policy,
                wallet_auth_token=os.environ.get(args.wallet_token_env, ""),
            )
        except AttestationVerificationError as exc:
            print(f"[upload-artifact] attestation rejected: {redact_text(exc)}")
            sys.exit(1)
        except Exception as exc:
            print(f"[upload-artifact] upload failed: {redact_text(exc)}")
            sys.exit(1)

        print(json.dumps({
            "deal_id": result.deal_id,
            "artifact_hash": result.artifact_hash,
            "ciphertext_sha256": result.ciphertext_sha256,
            "padding_profile": "fixed_1m_v3",
            "exact_plaintext_size_egress": False,
            "status_code": result.status_code,
            "response": result.response,
        }, indent=2))

    elif args.command == "verify-attestation":
        from tinker_delegate.attestation_verifier import (
            AttestationPolicy,
            AttestationVerificationError,
            fetch_and_verify_attestation,
        )

        policy = AttestationPolicy(
            expected_compose_hash=args.compose_hash,
            expected_app_id=args.app_id,
            expected_os_image_hash=args.os_image_hash,
            context=args.context,
            allow_local=args.allow_local_attestation,
            max_age_seconds=args.max_age_seconds,
        )
        try:
            result = fetch_and_verify_attestation(args.api_url, policy)
        except AttestationVerificationError as exc:
            print(f"[verify-attestation] rejected: {redact_text(exc)}")
            sys.exit(1)
        except Exception as exc:
            print(f"[verify-attestation] failed: {redact_text(exc)}")
            sys.exit(1)

        print(json.dumps({
            "mode": result.mode,
            "report_context": result.report_context,
            "report_data": result.report_data,
            "encryption_public_key": result.encryption_public_key,
            "quote_size": result.quote_size,
            "compose_hash": result.compose_hash,
            "app_id": result.app_id,
            "os_image_hash": result.os_image_hash,
            "fetched_at": result.fetched_at,
        }, indent=2))

    elif args.command == "verify-cvm-attestation":
        from tinker_delegate.cvm_attestation import (
            CvmAttestationError,
            CvmAttestationPolicy,
            bundle_to_json,
            verify_cvm_attestation,
        )

        policy = CvmAttestationPolicy(
            api_url=args.api_url,
            compose_path=Path(args.compose),
            env_files=tuple(Path(path) for path in args.env_file),
            allowed_env_file=Path(args.allowed_env_file) if args.allowed_env_file else None,
            allowed_envs=tuple(args.allowed_env),
            context=args.context,
            expected_compose_hash=args.expected_compose_hash,
            expected_attested_compose_hash=args.attested_compose_hash,
            expected_app_id=args.app_id,
            expected_os_image_hash=args.os_image_hash,
            required_images=tuple(args.require_image),
            required_image_digests=tuple(args.require_image_digest),
            allow_local=args.allow_local_attestation,
            allow_tags=args.allow_tags,
            phala_raw_compose=args.phala_raw_compose,
            max_age_seconds=args.max_age_seconds,
        )
        try:
            bundle = verify_cvm_attestation(policy)
        except CvmAttestationError as exc:
            print(f"[verify-cvm-attestation] rejected: {redact_text(exc)}")
            sys.exit(1)
        except Exception as exc:
            print(f"[verify-cvm-attestation] failed: {redact_text(exc)}")
            sys.exit(1)

        print(bundle_to_json(bundle))

    elif args.command == "verify-deployment-bundle":
        from tinker_delegate.deployment_bundle import (
            DeploymentBundleError,
            DeploymentBundlePolicy,
            GithubImagePolicy,
            verify_deployment_bundle,
        )

        image_policies = tuple(
            GithubImagePolicy(
                image=image,
                source_digest=args.source_digest,
                source_ref=args.source_ref,
                repo=args.repo,
                signer_workflow=args.signer_workflow,
            )
            for image in args.image
        )
        policy = DeploymentBundlePolicy(
            api_url=args.api_url,
            compose_path=Path(args.compose),
            images=image_policies,
            env_files=tuple(Path(path) for path in args.env_file),
            allowed_env_file=Path(args.allowed_env_file) if args.allowed_env_file else None,
            allowed_envs=tuple(args.allowed_env),
            context=args.context,
            expected_compose_hash=args.expected_compose_hash,
            expected_attested_compose_hash=args.attested_compose_hash,
            expected_app_id=args.app_id,
            expected_os_image_hash=args.os_image_hash,
            extra_required_image_digests=tuple(args.require_image_digest),
            allow_local=args.allow_local_attestation,
            allow_tags=args.allow_tags,
            phala_raw_compose=args.phala_raw_compose,
            max_age_seconds=args.max_age_seconds,
        )
        try:
            bundle = verify_deployment_bundle(policy)
        except DeploymentBundleError as exc:
            print(f"[verify-deployment-bundle] rejected: {redact_text(exc)}")
            sys.exit(1)
        except Exception as exc:
            print(f"[verify-deployment-bundle] failed: {redact_text(exc)}")
            sys.exit(1)

        _emit_bounded_json(bundle.to_public_dict(), output_path=args.output)

    elif args.command == "verify-compose-hash":
        from tinker_delegate.compose_hash import ComposeHashError, verify_compose_hash

        try:
            result = verify_compose_hash(
                Path(args.compose),
                env_files=[Path(path) for path in args.env_file],
                allowed_env_file=Path(args.allowed_env_file) if args.allowed_env_file else None,
                expected_hash=args.expected_hash,
                allowed_envs=list(args.allowed_env),
                phala_raw_compose=args.phala_raw_compose,
                allow_tags=args.allow_tags,
            )
        except ComposeHashError as exc:
            print(f"[verify-compose-hash] rejected: {redact_text(exc)}")
            sys.exit(1)

        print(json.dumps(result.to_public_dict(), indent=2))

    elif args.command == "encrypt-dataset":
        from tinker_delegate.sealed_dataset import (
            DEFAULT_CHUNK_SIZE,
            SealedDatasetError,
            seal_dataset,
        )

        recipient_keys = list(args.recipient_pubkey)
        for pk_file in args.recipient_pubkey_file:
            recipient_keys.append(Path(pk_file).read_text(encoding="utf-8").strip())
        recipient_keys = [pk.strip() for pk in recipient_keys if pk.strip()]
        if not recipient_keys:
            print("[encrypt-dataset] rejected: at least one --recipient-pubkey is required")
            sys.exit(1)
        try:
            plaintext = Path(args.input_path).read_bytes()
            blob, manifest, receipt = seal_dataset(
                plaintext,
                dataset_id=args.dataset_id,
                task=args.task,
                data_sensitivity=args.sensitivity,
                recipient_public_keys=recipient_keys,
                storage_ref=args.storage_ref or None,
                chunk_size=args.chunk_size or DEFAULT_CHUNK_SIZE,
            )
        except (SealedDatasetError, ValueError) as exc:
            print(f"[encrypt-dataset] rejected: {redact_text(exc)}")
            sys.exit(1)
        Path(args.out_blob).write_bytes(blob)
        Path(args.out_manifest).write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        _emit_bounded_json(receipt, output_path=args.output)
        sys.exit(0)

    elif args.command == "verify-dataset-manifest":
        from tinker_delegate.sealed_dataset import verify_manifest

        manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
        blob = Path(args.blob).read_bytes() if args.blob else None
        result = verify_manifest(
            manifest, blob=blob, expected_signer=args.expected_signer or None
        )
        _emit_bounded_json(result, output_path=args.output)
        sys.exit(0 if result["ok"] else 1)

    elif args.command == "verify-reward-run":
        from tinker_delegate.run_verification import verify_reward_run

        packet = json.loads(Path(args.packet).read_text(encoding="utf-8"))
        result = verify_reward_run(packet)
        _emit_bounded_json(result, output_path=args.output)
        sys.exit(0 if result["verified"] else 1)

    elif args.command == "verify-reward-mechanism":
        from tinker_delegate.run_verification import verify_reward_mechanism

        packet = json.loads(Path(args.packet).read_text(encoding="utf-8"))
        # Each external input is optional; a check runs only when its input is
        # supplied (else it is reported "skipped"). Source paths are hashed the
        # same way the boundary hashed the env module (basename + sha256).
        source_targets = list(args.source) or None
        manifest = (
            json.loads(Path(args.manifest).read_text(encoding="utf-8"))
            if args.manifest
            else None
        )
        canary_report = (
            json.loads(Path(args.canary_report).read_text(encoding="utf-8"))
            if args.canary_report
            else None
        )
        witness_quorum = None
        if args.witness and args.witness_threshold > 0:
            witness_quorum = {
                "authorized_witnesses": list(args.witness),
                "threshold": args.witness_threshold,
            }
        result = verify_reward_mechanism(
            packet,
            source_targets=source_targets,
            manifest=manifest,
            canary_report=canary_report,
            expected_signer=args.expected_signer or None,
            witness_quorum=witness_quorum,
            expected_benchmark=args.expected_benchmark or None,
            require_provenance=bool(args.require_provenance),
        )
        _emit_bounded_json(result, output_path=args.output)
        sys.exit(0 if result["verified"] else 1)

    elif args.command == "explain-decision":
        from tinker_delegate.decision_explainer import explain_decision

        explanation = explain_decision(args.reason_code)
        _emit_bounded_json(explanation.to_public_dict(), output_path=args.output)

    elif args.command == "sign-dataset-manifest":
        from tinker_delegate.sealed_dataset import sign_manifest

        signer_private_key = os.environ.get(args.signer_key_env, "").strip()
        if not signer_private_key:
            result = {
                "surface": "sign_dataset_manifest",
                "success": False,
                "error_kind": "missing_signer_key",
                "bounded_message": f"signer key env var {args.signer_key_env} is not configured",
                "private_key_returned": False,
                "raw_secret_egress": False,
            }
            _emit_bounded_json(result, output_path=args.output)
            sys.exit(1)
        manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
        try:
            signed_manifest, result = sign_manifest(manifest, signer_private_key)
            Path(args.out).write_text(
                json.dumps(signed_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            result = {**result, "signed_manifest_output": str(Path(args.out)), "signed_manifest_written": True}
        except Exception as exc:
            result = {
                "surface": "sign_dataset_manifest",
                "success": False,
                "error_kind": exc.__class__.__name__,
                "bounded_message": redact_text(exc),
                "private_key_returned": False,
                "raw_secret_egress": False,
            }
        _emit_bounded_json(result, output_path=args.output, forbidden_values=(signer_private_key,))
        sys.exit(0 if result.get("success") else 1)

    elif args.command == "witness-sign-dataset-manifest":
        from tinker_delegate.sealed_dataset import add_witness_signature

        witness_private_key = os.environ.get(args.signer_key_env, "").strip()
        if not witness_private_key:
            result = {
                "surface": "witness_sign_dataset_manifest",
                "success": False,
                "error_kind": "missing_signer_key",
                "bounded_message": f"witness key env var {args.signer_key_env} is not configured",
                "private_key_returned": False,
                "raw_secret_egress": False,
            }
            _emit_bounded_json(result, output_path=args.output)
            sys.exit(1)
        manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
        try:
            cosigned_manifest, result = add_witness_signature(manifest, witness_private_key)
            Path(args.out).write_text(
                json.dumps(cosigned_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            result = {**result, "cosigned_manifest_output": str(Path(args.out)), "cosigned_manifest_written": True}
        except Exception as exc:
            result = {
                "surface": "witness_sign_dataset_manifest",
                "success": False,
                "error_kind": exc.__class__.__name__,
                "bounded_message": redact_text(exc),
                "private_key_returned": False,
                "raw_secret_egress": False,
            }
        _emit_bounded_json(result, output_path=args.output, forbidden_values=(witness_private_key,))
        sys.exit(0 if result.get("success") else 1)

    elif args.command == "verify-dataset-provenance":
        from tinker_delegate.sealed_dataset import verify_dataset_provenance

        manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
        result = verify_dataset_provenance(
            manifest,
            expected_signer=args.expected_signer or None,
            expected_benchmark=args.expected_benchmark or None,
        )
        _emit_bounded_json(result, output_path=args.output)
        sys.exit(0 if result.get("ok") else 1)

    elif args.command == "dataset-recipient-keygen":
        from tinker_delegate.run_metadata_store import stable_hash
        from tinker_delegate.sealed_dataset import generate_recipient_keypair, recipient_key_hash

        private_key_hex, public_key_hex = generate_recipient_keypair()
        _write_secret_text(args.private_key_output, private_key_hex)
        result = {
            "surface": "dataset_recipient_keygen",
            "success": True,
            "public_key": public_key_hex,
            "public_key_hash": stable_hash(public_key_hex.lower(), prefix="dataset_recipient_public_key"),
            "recipient_key_hash": recipient_key_hash(public_key_hex),
            "private_key_path": str(Path(args.private_key_output)),
            "private_key_saved": True,
            "private_key_returned": False,
            "raw_secret_egress": False,
        }
        _emit_bounded_json(result, output_path=args.output, public_hex_fields=("public_key",))
        sys.exit(0)

    elif args.command == "publish-dataset":
        from tinker_delegate.dataset_storage import (
            StorageBackendError,
            publish_dataset,
            resolve_backend,
        )

        if args.backend == "local" and not args.dest:
            print("[publish-dataset] rejected: --dest is required for the local backend")
            sys.exit(1)
        try:
            backend = resolve_backend(args.backend, local_root=args.dest or None)
            blob = Path(args.blob).read_bytes()
            manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
            receipt = publish_dataset(blob, manifest, backend)
        except (StorageBackendError, ValueError, OSError) as exc:
            print(f"[publish-dataset] rejected: {redact_text(exc)}")
            sys.exit(1)
        _emit_bounded_json(receipt, output_path=args.output)
        sys.exit(0)

    elif args.command == "fetch-decrypt-dataset":
        from tinker_delegate.dataset_storage import StorageBackendError, fetch_decrypt_dataset

        recipient_key = Path(args.recipient_key_file).read_text(encoding="utf-8").strip()
        try:
            plaintext, receipt = fetch_decrypt_dataset(
                args.ref,
                recipient_key,
                local_root=args.local_root or None,
            )
        except (StorageBackendError, ValueError, OSError) as exc:
            print(f"[fetch-decrypt-dataset] rejected: {redact_text(exc)}")
            sys.exit(1)
        if plaintext is not None:
            out_path = Path(args.out)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(fd, bytes(plaintext))
            finally:
                os.close(fd)
            # Zero the in-memory plaintext buffer after it is persisted.
            for i in range(len(plaintext)):
                plaintext[i] = 0
            receipt["plaintext_path"] = str(out_path)
        _emit_bounded_json(receipt, output_path=args.output)
        sys.exit(0 if receipt.get("decrypted") else 1)

    elif args.command == "watch-chain":
        from tinker_delegate.chain_watcher import (
            ChainEventDispatcher,
            ChainCursorStore,
            ChainWatcher,
            ChainWatcherError,
            JsonRpcLogSource,
            parse_start_block,
        )

        rpc_url = args.rpc_url or settings.chain_rpc_url
        contract_address = args.contract_address or settings.chain_contract_address
        api_url = args.api_url or settings.chain_control_plane_url
        poll_interval = (
            args.poll_interval
            if args.poll_interval is not None
            else settings.chain_poll_interval
        )
        confirmations = (
            args.confirmations
            if args.confirmations is not None
            else settings.chain_confirmations
        )
        from_block = args.from_block or settings.chain_start_block
        cursor_path = args.cursor_store or settings.chain_cursor_store_path
        cursor_store = None if args.no_cursor else ChainCursorStore(cursor_path)

        if args.cursor_summary:
            if cursor_store is None:
                _emit_bounded_json({"cursor_enabled": False, "raw_secret_egress": False})
            else:
                _emit_bounded_json({"cursor_enabled": True, **cursor_store.public_summary()})
            sys.exit(0)

        source = None
        dispatcher = None
        try:
            from tinker_delegate.runtime_auth import resolve_runtime_auth_token

            runtime_auth_token = resolve_runtime_auth_token(settings)
            if not runtime_auth_token:
                raise ChainWatcherError(
                    "watch-chain requires configured or dstack-derived runtime auth"
                )
            source = JsonRpcLogSource(rpc_url, contract_address)
            created_context = cursor_store.load().created_deals if cursor_store is not None else None
            dispatcher = ChainEventDispatcher(
                api_url,
                auth_token=runtime_auth_token,
                created_context=created_context,
            )
            watcher = ChainWatcher(source, dispatcher)
            for summary in watcher.run(
                start_block=parse_start_block(from_block),
                poll_interval=poll_interval,
                confirmations=confirmations,
                once=args.once,
                cursor_store=cursor_store,
            ):
                _emit_bounded_json(summary)
        except ChainWatcherError as exc:
            print(f"[watch-chain] rejected: {redact_text(exc)}")
            sys.exit(1)
        except Exception as exc:
            print(f"[watch-chain] failed: {redact_text(exc)}")
            sys.exit(1)
        finally:
            if dispatcher is not None:
                dispatcher.close()
            if source is not None:
                source.close()

    elif args.command == "result-verifier-address":
        from tinker_delegate.result_verifier import (
            DstackResultVerifierSigner,
            ResultVerifierError,
            VerifierSignerUnavailable,
        )

        try:
            signer = DstackResultVerifierSigner.from_settings(settings)
            _emit_bounded_json(
                {
                    "verifier_address": signer.address,
                    "custody": signer.custody,
                    "raw_secret_egress": False,
                },
                output_path=args.output,
            )
        except VerifierSignerUnavailable as exc:
            print(f"[result-verifier-address] signer unavailable: {redact_text(exc)}")
            sys.exit(1)
        except ResultVerifierError as exc:
            print(f"[result-verifier-address] rejected: {redact_text(exc)}")
            sys.exit(1)
        except Exception as exc:
            print(f"[result-verifier-address] failed: {redact_text(exc)}")
            sys.exit(1)

    elif args.command == "authorize-result":
        from tinker_delegate.chain_submitter import (
            JsonRpcClient,
            read_compute_settlement_policy_enabled_from_chain,
            read_deal_from_chain,
            read_fee_bps_from_chain,
        )
        from tinker_delegate.result_verifier import (
            DstackResultVerifierSigner,
            ResultAuthorizationRequest,
            ResultVerifierError,
            ResultVerifierPolicy,
            VerifierSignerUnavailable,
            authorize_result_submission,
            independent_attestation_verdict_from_public_dict,
            signer_attestation_from_public_dict,
        )

        rpc = None
        try:
            rpc = JsonRpcClient(args.rpc_url or settings.chain_rpc_url)
            chain_id = rpc.chain_id()
            deal = read_deal_from_chain(rpc, args.contract_address, args.deal_id)
            fee_bps = read_fee_bps_from_chain(rpc, args.contract_address)
            compute_policy_enabled = read_compute_settlement_policy_enabled_from_chain(
                rpc,
                args.contract_address,
            )
            attestation_payload = json.loads(
                Path(args.signer_attestation_json).read_text(encoding="utf-8")
            )
            signer_attestation = signer_attestation_from_public_dict(attestation_payload)
            independent_verdict = None
            if args.independent_verdict_json:
                independent_verdict_payload = json.loads(
                    Path(args.independent_verdict_json).read_text(encoding="utf-8")
                )
                independent_verdict = independent_attestation_verdict_from_public_dict(
                    independent_verdict_payload
                )
            policy = ResultVerifierPolicy(
                allowed_compose_hashes=tuple(args.allow_compose_hash),
                allowed_app_ids=tuple(args.allow_app_id),
                allowed_os_image_hashes=tuple(args.allow_os_image_hash),
                revoked_quote_hashes=tuple(args.revoke_quote_hash),
                revoked_signer_addresses=tuple(args.revoke_signer_address),
                authorization_ttl_seconds=(
                    args.ttl_seconds
                    if args.ttl_seconds is not None
                    else settings.chain_result_authorization_ttl_seconds
                ),
                trusted_attestation_verifier_addresses=tuple(
                    args.allow_attestation_verifier_address
                ),
                attestation_release_policy_hash=(
                    settings.chain_attestation_release_policy_hash
                ),
                attestation_domain="main_runtime_cvm",
                attestation_cvm_id=settings.main_runtime_cvm_id,
                attestation_deployment_intent_sha256=(
                    settings.release_deployment_intent_sha256
                ),
                attestation_release_authority_sha256=(
                    settings.release_authority_sha256
                ),
                attestation_ceremony_nonce=settings.release_ceremony_nonce,
                attestation_measurement_policy_sha256=(
                    settings.diligence_qvl_measurement_policy_sha256
                ),
                allow_unverified_local_attestation=(
                    args.allow_unverified_local_attestation
                ),
            )
            request = ResultAuthorizationRequest(
                chain_id=chain_id,
                contract_address=args.contract_address,
                deal_id=args.deal_id,
                deal=deal,
                fee_bps=fee_bps,
                compute_settlement_policy_enabled=compute_policy_enabled,
                compose_hash=args.compose_hash,
                score_band=args.score_band,
                compute_cost_wei=args.compute_cost_wei,
            )
            authorization = authorize_result_submission(
                request,
                signer_attestation=signer_attestation,
                policy=policy,
                verifier_signer=DstackResultVerifierSigner.from_settings(settings),
                independent_verdict=independent_verdict,
            )
            _emit_bounded_json(
                authorization.to_public_dict(),
                output_path=args.output,
                public_hex_fields=("verifier_signature",),
                public_decimal_fields=("compute_cost_wei",),
            )
        except VerifierSignerUnavailable as exc:
            print(f"[authorize-result] signer unavailable: {redact_text(exc)}")
            sys.exit(1)
        except ResultVerifierError as exc:
            print(f"[authorize-result] rejected: {redact_text(exc)}")
            sys.exit(1)
        except Exception as exc:
            print(f"[authorize-result] failed: {redact_text(exc)}")
            sys.exit(1)
        finally:
            if rpc is not None:
                rpc.close()

    elif args.command == "governance-approval-plan":
        from tinker_delegate.chain_submitter import signer_attestation_report_data
        from tinker_delegate.governance_plan import build_governance_plan_from_verdict
        from tinker_delegate.result_verifier import (
            IndependentAttestationExpectation,
            ResultVerifierError,
            independent_attestation_verdict_from_public_dict,
        )

        try:
            verdict_payload = json.loads(
                Path(args.independent_verdict_json).read_text(encoding="utf-8")
            )
            if not isinstance(verdict_payload, dict):
                raise ResultVerifierError("independent verdict JSON must be an object")
            verdict = independent_attestation_verdict_from_public_dict(verdict_payload)
            report_data = "0x" + signer_attestation_report_data(
                signer_address=args.expected_tee_identity,
                chain_id=args.expected_chain_id,
                contract_address=args.expected_contract_address,
            ).hex()
            expectation = IndependentAttestationExpectation(
                trusted_verifier_addresses=tuple(
                    args.trusted_attestation_verifier_address
                ),
                chain_id=args.expected_chain_id,
                domain=args.expected_cvm_domain,
                profile="diligence",
                cvm_id=args.expected_cvm_id,
                deployment_intent_sha256=(
                    args.expected_deployment_intent_sha256
                ),
                release_authority_sha256=(
                    args.expected_release_authority_sha256
                ),
                ceremony_nonce=args.expected_ceremony_nonce,
                measurement_policy_sha256=(
                    args.expected_measurement_policy_sha256
                ),
                release_policy_hash=args.expected_attestation_release_policy_hash,
                challenge_id=args.expected_attestation_challenge_id,
                challenge_digest=args.expected_attestation_challenge_digest,
                challenge_issued_at=args.expected_attestation_challenge_issued_at,
                challenge_expires_at=args.expected_attestation_challenge_expires_at,
                quote_hash=args.expected_quote_hash,
                report_data=report_data,
                compose_hash=args.expected_compose_hash,
                app_id=args.expected_app_id,
                os_image_hash=args.expected_os_image_hash,
                signer_address=args.expected_tee_identity,
                contract_address=args.expected_contract_address,
                max_age_seconds=args.max_verdict_age_seconds,
            )
            plan = build_governance_plan_from_verdict(
                verdict,
                expectation=expectation,
                keystore_account=args.keystore_account,
            )
            _emit_bounded_json(plan.to_public_dict(), output_path=args.output)
        except ResultVerifierError as exc:
            print(f"[governance-approval-plan] rejected: {redact_text(exc)}")
            sys.exit(1)
        except Exception as exc:
            print(f"[governance-approval-plan] failed: {redact_text(exc)}")
            sys.exit(1)

    elif args.command == "submit-result":
        from tinker_delegate.chain_submitter import (
            ChainSubmitterError,
            DiligenceRoomSubmitter,
            DstackEthereumSigner,
            JsonRpcClient,
            SignerUnavailable,
            get_dstack_signer_attestation,
        )

        rpc_url = args.rpc_url or settings.chain_rpc_url
        contract_address = args.contract_address or settings.chain_contract_address
        gas_limit = (
            args.gas_limit
            if args.gas_limit is not None
            else settings.chain_submit_gas_limit
        )
        rpc = None
        try:
            rpc = JsonRpcClient(rpc_url)
            signer = DstackEthereumSigner.from_settings(settings)
            submitter = DiligenceRoomSubmitter(
                rpc,
                contract_address,
                signer,
                gas_limit=gas_limit,
            )
            signer_attestation = get_dstack_signer_attestation(
                signer_address=signer.address,
                chain_id=rpc.chain_id(),
                contract_address=contract_address,
            )
            receipt = submitter.submit_result(
                deal_id=args.deal_id,
                score_band=args.score_band,
                compute_cost_wei=args.compute_cost_wei,
                authorization_expiry=args.authorization_expiry,
                verifier_signature=args.verifier_signature,
                signer_attestation=signer_attestation,
            )
            _emit_bounded_json(receipt.to_public_dict())
        except SignerUnavailable as exc:
            print(f"[submit-result] signer unavailable: {redact_text(exc)}")
            sys.exit(1)
        except ChainSubmitterError as exc:
            print(f"[submit-result] rejected: {redact_text(exc)}")
            sys.exit(1)
        except Exception as exc:
            print(f"[submit-result] failed: {redact_text(exc)}")
            sys.exit(1)
        finally:
            if rpc is not None:
                rpc.close()

    elif args.command == "serve":
        import uvicorn
        reset_runtime_state()
        try:
            asyncio.run(_ensure_api_key(settings))
        except Exception as exc:
            print(f"[serve] bootstrap failed: {redact_text(exc)}")
            update_runtime_state(
                api_key_available=False,
                api_key_source="bootstrap" if settings.bootstrap_signup else "none",
                bootstrap_attempted=settings.bootstrap_signup,
                bootstrap_success=False,
                bootstrap_error=redact_text(exc),
                bootstrap_error_kind=_bootstrap_error_kind_from_runtime(exc),
            )
            if not settings.bootstrap_fail_open:
                sys.exit(1)
        uvicorn.run(
            "tinker_delegate.api:app",
            host=args.host,
            port=args.port,
            log_level="info",
            # The wallet challenge limiter owns forwarded-client identity and
            # accepts it only from explicitly pinned proxy CIDRs. Leaving
            # Uvicorn's generic proxy-header rewriting enabled would erase the
            # direct socket peer before that policy can authenticate it.
            proxy_headers=False,
        )


if __name__ == "__main__":
    cli()
