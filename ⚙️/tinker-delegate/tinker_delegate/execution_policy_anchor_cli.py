"""One-shot independently verified writer evidence for anchor activation.

This command is intentionally not an HTTP endpoint and has no payload-bearing
arguments.  It derives the purpose-separated writer inside a real dstack CVM,
collects one quote bound to the public writer/release context, transmits that
raw quote only to a separately configured bearer-authenticated HTTPS QVL, and
emits a small canonical signed-verdict artifact. Private key material never
leaves dstack and the raw quote never enters stdout, stderr, or the artifact.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from typing import Any, Mapping, Sequence, TextIO

import httpx

from tinker_delegate import dstack_utils
from tinker_delegate.chain_submitter import SignerAttestationEvidence
from tinker_delegate.config import Settings
from tinker_delegate.execution_policy_anchor import (
    BASE_SEPOLIA_CHAIN_ID,
    DstackExecutionPolicyAnchorSigner,
    EXECUTION_POLICY_ANCHOR_WRITER_KEY_PATH,
    ExecutionPolicyAnchorError,
)
from tinker_delegate.result_verifier import (
    INDEPENDENT_ATTESTATION_VERIFICATION_METHOD,
    IndependentAttestationExpectation,
    IndependentAttestationVerdict,
    ResultVerifierError,
    authenticate_independent_attestation_verdict,
    independent_attestation_verdict_from_public_dict,
)
from tinker_delegate.qvl_freshness import (
    QvlChallenge,
    VERIFICATION_REQUEST_SCHEMA,
    authenticate_qvl_challenge,
    challenge_bound_report_data,
    challenge_request,
    qvl_challenge_from_public_dict,
)


EVIDENCE_SCHEMA = "dnai.execution-policy-anchor-writer-qvl-evidence.v2"
REPORT_DATA_SCHEMA = "dnai.execution-policy-anchor-writer-qvl-evidence.v1"
QVL_REQUEST_SCHEMA = VERIFICATION_REQUEST_SCHEMA
QVL_AUTH_TOKEN_ENV = "TINKER_EXECUTION_POLICY_ANCHOR_WRITER_QVL_AUTH_TOKEN"
WRITER_KEY_PATH = EXECUTION_POLICY_ANCHOR_WRITER_KEY_PATH
WRITER_CUSTODY = "dstack_derived_execution_policy_anchor_writer"
MIN_TDX_QUOTE_BYTES = 1024
MAX_TDX_QUOTE_BYTES = 16 * 1024
MAX_QVL_RESPONSE_BYTES = 64 * 1024

_ADDRESS = re.compile(r"^0x[0-9a-f]{40}$")
_BYTES32 = re.compile(r"^0x[0-9a-f]{64}$")
_PRINTABLE_ASCII = re.compile(r"^[\x21-\x7e]{1,128}$")


class AnchorWriterEvidenceError(RuntimeError):
    """Bounded bootstrap failure with no secret-bearing exception context."""


@dataclass(frozen=True)
class AnchorWriterEvidence:
    writer_address: str
    anchor_address: str
    writer_release_commitment: str
    app_id: str
    compose_hash: str
    os_image_hash: str
    report_data: str
    quote_report_data: str
    quote_sha256: str
    quote_size: int

    def to_qvl_expectation(self) -> dict[str, Any]:
        return SignerAttestationEvidence(
            mode="tdx",
            signer_address=self.writer_address,
            chain_id=BASE_SEPOLIA_CHAIN_ID,
            contract_address=self.anchor_address,
            report_data=self.report_data,
            # The shared legacy evidence serializer accepts the static bytes32
            # binding. The authenticated QVL client replaces this field with
            # static_digest || signed_challenge_digest immediately below.
            quote_report_data=self.report_data,
            quote_hash=self.quote_sha256,
            quote_size=self.quote_size,
            compose_hash=self.compose_hash,
            app_id=self.app_id,
            os_image_hash=self.os_image_hash,
        ).to_public_dict()


@dataclass(frozen=True)
class AnchorWriterAttestationPacket:
    evidence: AnchorWriterEvidence
    quote: str


@dataclass(frozen=True)
class VerifiedAnchorWriterEvidence:
    evidence: AnchorWriterEvidence
    qvl_release_policy_hash: str
    verdict: IndependentAttestationVerdict

    def to_bounded_dict(self) -> dict[str, Any]:
        evidence = self.evidence
        return {
            "schema": EVIDENCE_SCHEMA,
            "status": "independent_qvl_verified",
            "chain_id": BASE_SEPOLIA_CHAIN_ID,
            "anchor_address": evidence.anchor_address,
            "writer_address": evidence.writer_address,
            "writer_release_commitment": evidence.writer_release_commitment,
            "writer_key_path": WRITER_KEY_PATH,
            "writer_key_path_sha256": hashlib.sha256(
                b"dnai-wikigen/execution-policy-anchor-writer-key-path/v1\0"
                + WRITER_KEY_PATH.encode("ascii")
            ).hexdigest(),
            "writer_custody": WRITER_CUSTODY,
            "app_id": evidence.app_id,
            "compose_hash": evidence.compose_hash,
            "os_image_hash": evidence.os_image_hash,
            "report_data": evidence.report_data,
            "quote_report_data": evidence.quote_report_data,
            "quote_sha256": "sha256:" + evidence.quote_sha256[2:],
            "quote_size": evidence.quote_size,
            "qvl_release_policy_hash": self.qvl_release_policy_hash,
            "qvl_verifier_address": self.verdict.verifier_address,
            "qvl_verdict": self.verdict.to_public_dict(),
            "verification_method": INDEPENDENT_ATTESTATION_VERIFICATION_METHOD,
            "tdx_measurement_policy": "exact_release_pinned_measurements",
            "raw_quote_egress": "authenticated_https_qvl_only",
            "raw_quote_in_artifact": False,
            "raw_private_key_egress": False,
        }


def writer_evidence_report_data(
    *,
    writer_address: str,
    anchor_address: str,
    writer_release_commitment: str,
) -> bytes:
    payload = {
        "schema": REPORT_DATA_SCHEMA,
        "chain_id": BASE_SEPOLIA_CHAIN_ID,
        "anchor_address": _address(anchor_address),
        "writer_address": _address(writer_address),
        "writer_release_commitment": _bytes32(writer_release_commitment),
        "writer_key_path": WRITER_KEY_PATH,
        "writer_custody": WRITER_CUSTODY,
    }
    return hashlib.sha256(
        b"dnai-wikigen/execution-policy-anchor-writer-evidence/v1\0"
        + _canonical_json(payload)
    ).digest()


def collect_anchor_writer_attestation(
    settings: Settings,
    *,
    challenge_digest: bytes,
) -> AnchorWriterAttestationPacket:
    """Collect one quote and bounded expectation from the same dstack call."""

    if (
        not dstack_utils.is_dstack_enabled()
        or dstack_utils.is_dstack_simulator()
    ):
        raise AnchorWriterEvidenceError("real_dstack_required")
    if str(settings.execution_policy_anchor_writer_key_path or "") != WRITER_KEY_PATH:
        raise AnchorWriterEvidenceError("writer_key_path_invalid")
    try:
        anchor_address = _address(settings.execution_policy_anchor_address)
        release = _bytes32(
            settings.execution_policy_anchor_writer_release_commitment
        )
        signer = DstackExecutionPolicyAnchorSigner.from_settings(settings)
        writer_address = _address(signer.address)
        configured_writer = str(
            settings.execution_policy_anchor_writer_address or ""
        ).strip()
        if configured_writer and _address(configured_writer) != writer_address:
            raise AnchorWriterEvidenceError("configured_writer_mismatch")
        report_data = writer_evidence_report_data(
            writer_address=writer_address,
            anchor_address=anchor_address,
            writer_release_commitment=release,
        )
        if (
            not isinstance(challenge_digest, bytes)
            or len(challenge_digest) != 32
            or not any(challenge_digest)
        ):
            raise AnchorWriterEvidenceError("independent_qvl_unavailable")
        details = dstack_utils.get_attestation_details(report_data + challenge_digest)
        if not isinstance(details, Mapping):
            raise AnchorWriterEvidenceError("dstack_evidence_invalid")
        quote = _hex_bytes(details.get("quote"), "quote")
        if not MIN_TDX_QUOTE_BYTES <= len(quote) <= MAX_TDX_QUOTE_BYTES:
            raise AnchorWriterEvidenceError("dstack_evidence_invalid")
        expected_report_data = "0x" + report_data.hex()
        quote_report_data = _quote_report_data(
            details.get("quote_report_data"),
            expected=report_data,
            challenge_digest=challenge_digest,
        )
        app_id = str(details.get("app_id") or "")
        if not _PRINTABLE_ASCII.fullmatch(app_id):
            raise AnchorWriterEvidenceError("dstack_evidence_invalid")
        evidence = AnchorWriterEvidence(
            writer_address=writer_address,
            anchor_address=anchor_address,
            writer_release_commitment=release,
            app_id=app_id,
            compose_hash=_bytes32(details.get("compose_hash")),
            os_image_hash=_bare_bytes32(details.get("os_image_hash")),
            report_data=expected_report_data,
            quote_report_data=quote_report_data,
            quote_sha256="0x" + hashlib.sha256(quote).hexdigest(),
            quote_size=len(quote),
        )
        return AnchorWriterAttestationPacket(
            evidence=evidence,
            quote="0x" + quote.hex(),
        )
    except AnchorWriterEvidenceError:
        raise
    except ExecutionPolicyAnchorError:
        raise AnchorWriterEvidenceError("dstack_writer_unavailable") from None
    except Exception:
        # SDK and parser exceptions may retain quote/key-derived values. Never
        # propagate them or their chained context to command output.
        raise AnchorWriterEvidenceError("dstack_evidence_invalid") from None


class HttpsAnchorWriterQvlClient:
    """Bounded authenticated transport that never exposes request material."""

    def __init__(
        self,
        url: str,
        *,
        auth_token: str,
        client: httpx.Client | None = None,
        trusted_verifier_addresses: Sequence[str] = (),
        expected_policy_hash: str = "",
        chain_id: int = 0,
        cvm_id: str = "",
        deployment_intent_sha256: str = "",
        release_authority_sha256: str = "",
        ceremony_nonce: str = "",
        measurement_policy_sha256: str = "",
    ) -> None:
        self.url = _https_url(url)
        self.challenge_url = self.url.replace("/verify", "/challenge")
        if (
            not 32 <= len(auth_token.encode("utf-8")) <= 4_096
            or any(ord(character) < 0x21 or ord(character) > 0x7E for character in auth_token)
        ):
            raise AnchorWriterEvidenceError("independent_qvl_unavailable")
        self._auth_token = auth_token
        self._trusted_verifier_addresses = tuple(trusted_verifier_addresses)
        self._expected_policy_hash = expected_policy_hash
        try:
            self._challenge_request = challenge_request(
                "execution_policy_anchor_writer",
                chain_id=chain_id,
                domain="main_runtime_cvm",
                cvm_id=cvm_id,
                deployment_intent_sha256=deployment_intent_sha256,
                release_authority_sha256=release_authority_sha256,
                ceremony_nonce=ceremony_nonce,
                measurement_policy_sha256=measurement_policy_sha256,
            )
        except Exception:
            raise AnchorWriterEvidenceError("independent_qvl_unavailable") from None
        self._client = client or httpx.Client(
            timeout=httpx.Timeout(30.0, connect=10.0),
            follow_redirects=False,
            trust_env=False,
        )
        self._owns_client = client is None

    def __repr__(self) -> str:
        return "HttpsAnchorWriterQvlClient(authenticated=True)"

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def issue_challenge(self) -> QvlChallenge:
        request = self._client.build_request(
            "POST",
            self.challenge_url,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self._auth_token}",
                "Cache-Control": "no-store",
                "Content-Type": "application/json",
            },
            content=_canonical_json(self._challenge_request),
        )
        try:
            response = self._client.send(request, stream=True, follow_redirects=False)
            try:
                content_type = response.headers.get("content-type", "").split(";", 1)[0].lower()
                if (
                    response.status_code != 200
                    or response.history
                    or not (content_type == "application/json" or content_type.endswith("+json"))
                ):
                    raise AnchorWriterEvidenceError("independent_qvl_unavailable")
                raw = _bounded_response(response)
            finally:
                response.close()
            payload = json.loads(raw, object_pairs_hook=_unique_object)
            if not isinstance(payload, dict):
                raise ValueError
            return authenticate_qvl_challenge(
                qvl_challenge_from_public_dict(payload),
                expected_profile="execution_policy_anchor_writer",
                expected_chain_id=int(self._challenge_request["chain_id"]),
                expected_domain=str(self._challenge_request["domain"]),
                expected_cvm_id=str(self._challenge_request["cvm_id"]),
                expected_deployment_intent_sha256=str(
                    self._challenge_request["deployment_intent_sha256"]
                ),
                expected_release_authority_sha256=str(
                    self._challenge_request["release_authority_sha256"]
                ),
                expected_ceremony_nonce=str(self._challenge_request["ceremony_nonce"]),
                expected_measurement_policy_sha256=str(
                    self._challenge_request["measurement_policy_sha256"]
                ),
                trusted_verifier_addresses=self._trusted_verifier_addresses,
                expected_policy_hash=self._expected_policy_hash,
            )
        except AnchorWriterEvidenceError:
            raise
        except Exception:
            raise AnchorWriterEvidenceError("independent_qvl_unavailable") from None

    def verify(
        self,
        packet: AnchorWriterAttestationPacket,
        challenge: QvlChallenge,
    ) -> IndependentAttestationVerdict:
        expectation = packet.evidence.to_qvl_expectation()
        expectation["quote_report_data"] = challenge_bound_report_data(
            packet.evidence.report_data, challenge
        )
        request_payload = {
            "schema": QVL_REQUEST_SCHEMA,
            "challenge": challenge.to_public_dict(),
            "quote": packet.quote,
            "expectation": expectation,
        }
        request = self._client.build_request(
            "POST",
            self.url,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self._auth_token}",
                "Cache-Control": "no-store",
                "Content-Type": "application/json",
            },
            content=_canonical_json(request_payload),
        )
        try:
            response = self._client.send(request, stream=True, follow_redirects=False)
            try:
                content_type = response.headers.get("content-type", "").split(";", 1)[0].lower()
                if (
                    response.status_code != 200
                    or response.history
                    or not (content_type == "application/json" or content_type.endswith("+json"))
                ):
                    raise AnchorWriterEvidenceError("independent_qvl_unavailable")
                raw = bytearray()
                for chunk in response.iter_bytes():
                    if len(chunk) > MAX_QVL_RESPONSE_BYTES - len(raw):
                        raise AnchorWriterEvidenceError("independent_qvl_unavailable")
                    raw.extend(chunk)
            finally:
                response.close()
        except AnchorWriterEvidenceError:
            raise
        except Exception:
            # Transport failures may retain the bearer and raw quote. Never
            # retain them as exception context or render them in supervisor logs.
            raise AnchorWriterEvidenceError("independent_qvl_unavailable") from None
        try:
            payload = json.loads(bytes(raw), object_pairs_hook=_unique_object)
            if not isinstance(payload, dict):
                raise ValueError
            return independent_attestation_verdict_from_public_dict(payload)
        except Exception:
            raise AnchorWriterEvidenceError("independent_qvl_unavailable") from None


def collect_anchor_writer_evidence(
    settings: Settings,
    *,
    qvl_client: HttpsAnchorWriterQvlClient | None = None,
    now: int | None = None,
) -> VerifiedAnchorWriterEvidence:
    """Collect, independently verify, and bound one writer quote artifact."""

    expected_verifier = _address(
        settings.execution_policy_anchor_writer_qvl_verifier_address
    )
    policy_hash = _bytes32(
        settings.execution_policy_anchor_writer_qvl_release_policy_hash
    )
    max_age = settings.execution_policy_anchor_writer_qvl_max_verdict_age_seconds
    if isinstance(max_age, bool) or not isinstance(max_age, int) or not 30 <= max_age <= 900:
        raise AnchorWriterEvidenceError("independent_qvl_policy_invalid")
    owns_client = qvl_client is None
    client = qvl_client
    try:
        if client is None:
            client = HttpsAnchorWriterQvlClient(
                settings.execution_policy_anchor_writer_qvl_url,
                auth_token=os.environ.get(QVL_AUTH_TOKEN_ENV, ""),
                trusted_verifier_addresses=(expected_verifier,),
                expected_policy_hash=policy_hash,
                chain_id=BASE_SEPOLIA_CHAIN_ID,
                cvm_id=settings.main_runtime_cvm_id,
                deployment_intent_sha256=settings.release_deployment_intent_sha256,
                release_authority_sha256=settings.release_authority_sha256,
                ceremony_nonce=settings.release_ceremony_nonce,
                measurement_policy_sha256=(
                    settings.anchor_writer_qvl_measurement_policy_sha256
                ),
            )
        challenge = client.issue_challenge()
        packet = collect_anchor_writer_attestation(
            settings,
            challenge_digest=challenge.digest_bytes,
        )
        verdict = client.verify(packet, challenge)
        checked_at = int(time.time() if now is None else now)
        authenticate_independent_attestation_verdict(
            verdict,
            expectation=IndependentAttestationExpectation(
                trusted_verifier_addresses=(expected_verifier,),
                chain_id=challenge.chain_id,
                domain=challenge.domain,
                profile="execution_policy_anchor_writer",
                cvm_id=challenge.cvm_id,
                deployment_intent_sha256=challenge.deployment_intent_sha256,
                release_authority_sha256=challenge.release_authority_sha256,
                ceremony_nonce=challenge.ceremony_nonce,
                measurement_policy_sha256=challenge.measurement_policy_sha256,
                release_policy_hash=policy_hash,
                challenge_id=challenge.challenge_id,
                challenge_digest=challenge.challenge_digest,
                challenge_issued_at=challenge.issued_at,
                challenge_expires_at=challenge.expires_at,
                quote_hash=packet.evidence.quote_sha256,
                report_data=packet.evidence.report_data,
                compose_hash=packet.evidence.compose_hash,
                app_id=packet.evidence.app_id,
                os_image_hash=packet.evidence.os_image_hash,
                signer_address=packet.evidence.writer_address,
                contract_address=packet.evidence.anchor_address,
                max_age_seconds=max_age,
            ),
            now=checked_at,
        )
    except AnchorWriterEvidenceError:
        raise
    except ResultVerifierError:
        raise AnchorWriterEvidenceError("independent_qvl_verdict_invalid") from None
    except Exception:
        raise AnchorWriterEvidenceError("independent_qvl_unavailable") from None
    finally:
        if owns_client and client is not None:
            client.close()
    return VerifiedAnchorWriterEvidence(
        evidence=packet.evidence,
        qvl_release_policy_hash=policy_hash,
        verdict=verdict,
    )


def build_parser() -> argparse.ArgumentParser:
    return _BoundedArgumentParser(
        prog="tinker-execution-policy-anchor-writer",
        description=(
            "Emit bounded independently QVL-verified ExecutionPolicyAnchor writer evidence"
        ),
    )


class _BoundedArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise AnchorWriterEvidenceError("arguments_not_allowed")


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    output = stdout or sys.stdout
    errors = stderr or sys.stderr
    parser = build_parser()
    try:
        parser.parse_args(list(argv) if argv is not None else None)
        evidence = collect_anchor_writer_evidence(Settings())
    except SystemExit as exc:
        return int(exc.code)
    except AnchorWriterEvidenceError as exc:
        _write_json(
            errors,
            {
                "schema": EVIDENCE_SCHEMA,
                "status": "blocked",
                "reason_code": str(exc),
                "raw_quote_transport_policy": "authenticated_https_qvl_only",
                "raw_quote_in_output": False,
                "raw_private_key_egress": False,
            },
        )
        return 78
    _write_json(output, evidence.to_bounded_dict())
    return 0


def _write_json(stream: TextIO, payload: Mapping[str, Any]) -> None:
    stream.write(_canonical_json(payload).decode("ascii") + "\n")
    stream.flush()


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate key")
        value[key] = item
    return value


def _https_url(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 2_048:
        raise AnchorWriterEvidenceError("independent_qvl_unavailable")
    try:
        parsed = httpx.URL(value)
    except Exception:
        raise AnchorWriterEvidenceError("independent_qvl_unavailable") from None
    if (
        parsed.scheme != "https"
        or not parsed.host
        or parsed.userinfo
        or parsed.query
        or parsed.fragment
        or parsed.path != "/verify"
        or parsed.host in {"localhost", "127.0.0.1", "::1"}
    ):
        raise AnchorWriterEvidenceError("independent_qvl_unavailable")
    return str(parsed)


def _address(value: Any) -> str:
    if not isinstance(value, str):
        raise AnchorWriterEvidenceError("release_binding_invalid")
    result = value.strip().lower()
    if not _ADDRESS.fullmatch(result) or result == "0x" + "00" * 20:
        raise AnchorWriterEvidenceError("release_binding_invalid")
    return result


def _bytes32(value: Any) -> str:
    if not isinstance(value, str):
        raise AnchorWriterEvidenceError("release_binding_invalid")
    result = value.strip().lower()
    if not result.startswith("0x"):
        result = "0x" + result
    if not _BYTES32.fullmatch(result) or result == "0x" + "00" * 32:
        raise AnchorWriterEvidenceError("release_binding_invalid")
    return result


def _bare_bytes32(value: Any) -> str:
    if not isinstance(value, str):
        raise AnchorWriterEvidenceError("release_binding_invalid")
    result = value.strip().lower()
    if result.startswith("0x"):
        result = result[2:]
    if not re.fullmatch(r"[0-9a-f]{64}", result) or result == "0" * 64:
        raise AnchorWriterEvidenceError("release_binding_invalid")
    return result


def _hex_bytes(value: Any, label: str) -> bytes:
    if not isinstance(value, str):
        raise AnchorWriterEvidenceError("dstack_evidence_invalid")
    normalized = value.strip().lower()
    if normalized.startswith("0x"):
        normalized = normalized[2:]
    if len(normalized) % 2 or not re.fullmatch(r"[0-9a-f]+", normalized):
        raise AnchorWriterEvidenceError("dstack_evidence_invalid")
    try:
        return bytes.fromhex(normalized)
    except ValueError:
        raise AnchorWriterEvidenceError("dstack_evidence_invalid") from None


def _quote_report_data(
    value: Any,
    *,
    expected: bytes,
    challenge_digest: bytes,
) -> str:
    raw = _hex_bytes(value, "quote_report_data")
    if len(raw) == 64 and raw[:32] == expected and raw[32:] == challenge_digest:
        return "0x" + raw.hex()
    raise AnchorWriterEvidenceError("dstack_evidence_invalid")


def _bounded_response(response: httpx.Response) -> bytes:
    raw = bytearray()
    for chunk in response.iter_bytes():
        if len(chunk) > MAX_QVL_RESPONSE_BYTES - len(raw):
            raise AnchorWriterEvidenceError("independent_qvl_unavailable")
        raw.extend(chunk)
    return bytes(raw)


if __name__ == "__main__":
    raise SystemExit(main())
