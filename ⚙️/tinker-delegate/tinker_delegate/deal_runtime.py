"""Confirmed-chain deal runtime for bounded evaluation and result settlement.

This process is deliberately separate from the public FastAPI worker.  It
combines the existing confirmed-block watcher, runtime-authenticated internal
deal API, dstack-held transaction signer, policy-bound result verifier, and an
independent DCAP/QVL verdict client without adding a raw-key path.

Only public chain fields and the API's fixed bounded evaluation projection are
persisted.  Artifacts, evaluator metrics, Tinker credentials, dstack key
material, raw quotes, and runtime bearer tokens are never written to the
runtime journal or emitted in cycle summaries.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import stat
import tempfile
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Protocol
from urllib.parse import urljoin, urlparse

import httpx

from tinker_delegate.chain_submitter import (
    ChainSubmitterError,
    DiligenceRoomSubmitter,
    DstackEthereumSigner,
    JsonRpcClient,
    PreparedSubmissionAttempt,
    SignerAttestationEvidence,
    SignerUnavailable,
    SubmitResultReceipt,
    normalize_address,
    normalize_bytes32,
    normalize_optional_bytes32,
    signer_attestation_report_data,
)
from tinker_delegate.chain_watcher import (
    ChainCursorState,
    ChainCursorStore,
    ChainEventDispatcher,
    ChainWatcherError,
    DiligenceRoomEvent,
    JsonRpcLogSource,
    parse_start_block,
)
from tinker_delegate.config import Settings
from tinker_delegate.dstack_utils import (
    get_attestation_details,
    is_dstack_enabled,
    is_dstack_simulator,
)
from tinker_delegate.result_verifier import (
    DstackResultVerifierSigner,
    IndependentAttestationExpectation,
    IndependentAttestationVerdict,
    ResultAuthorizationRequest,
    ResultVerifierError,
    ResultVerifierPolicy,
    VerifierSignerUnavailable,
    authorize_result_submission,
    authenticate_independent_attestation_verdict,
    independent_attestation_verdict_from_public_dict,
)
from tinker_delegate.runtime_auth import (
    RuntimeAuthUnavailable,
    resolve_runtime_auth_token,
)
from tinker_delegate.policy_kernel import POLICY_CANONICALIZATION_VERSION
from tinker_delegate.qvl_freshness import (
    QvlChallenge,
    QvlFreshnessError,
    VERIFICATION_REQUEST_SCHEMA,
    authenticate_qvl_challenge,
    challenge_bound_report_data,
    challenge_request,
    qvl_challenge_from_public_dict,
)


BASE_SEPOLIA_CHAIN_ID = 84_532
LOCAL_CHAIN_IDS = frozenset({1_337, 31_337})
RUNTIME_SCHEMA = "dnai.deal-runtime.v1"
RUNTIME_STATE_SCHEMA = "dnai.deal-runtime-state.v2"
QVL_REQUEST_SCHEMA = VERIFICATION_REQUEST_SCHEMA
TX_HASH_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")

SCORE_BANDS = frozenset({"negligible", "low", "medium", "high", "exceptional"})
QUALITY_BANDS = frozenset(
    {
        "<1% quality-improvement band",
        "1-5% quality-improvement band",
        "5-10% quality-improvement band",
        "10-20% quality-improvement band",
        ">20% quality-improvement band",
    }
)
RECOMMENDATIONS = frozenset({"accept", "reject"})


class DealRuntimeError(RuntimeError):
    """Base error for fail-closed runtime configuration or execution."""


class RuntimeStateError(DealRuntimeError):
    """Raised for malformed or inconsistent durable runtime state."""


class ControlPlaneError(DealRuntimeError):
    """Internal API failure with a bounded, non-secret reason code."""

    def __init__(self, reason_code: str):
        super().__init__(reason_code)
        self.reason_code = reason_code


class ArtifactNotReady(ControlPlaneError):
    pass


class ExecutionPolicyNotReady(ControlPlaneError):
    pass


class EvaluatorNotReady(ControlPlaneError):
    pass


class EvaluationTerminalFailure(ControlPlaneError):
    pass


class ControlPlaneRetryable(ControlPlaneError):
    pass


class DealContextMissing(ControlPlaneError):
    pass


class AttestationVerdictUnavailable(DealRuntimeError):
    """A fresh independent DCAP/QVL verdict could not be obtained."""


class SubmissionRejected(DealRuntimeError):
    """Local or chain policy rejected a result before safe settlement."""


class SubmissionUncertain(DealRuntimeError):
    """Broadcast outcome is ambiguous and must not be retried automatically."""


class SubmissionRetryable(DealRuntimeError):
    """A submission failed before any signed transaction could be broadcast."""


class DealAlreadySubmitted(DealRuntimeError):
    pass


class DealAlreadyResolved(DealRuntimeError):
    pass


class RuntimeStage(str, Enum):
    WAITING_ARTIFACT = "waiting_artifact"
    AWAITING_EXECUTION_POLICY = "awaiting_execution_policy"
    EVALUATOR_UNAVAILABLE = "evaluator_unavailable"
    RETRYABLE = "retryable"
    EVALUATED = "evaluated"
    AWAITING_QVL = "awaiting_qvl"
    SUBMISSION_UNCERTAIN = "submission_uncertain"
    SUBMISSION_REJECTED = "submission_rejected"
    EVALUATION_FAILED = "evaluation_failed"
    SUBMITTED = "submitted"
    RESOLVED = "resolved"


ACTIONABLE_STAGES = frozenset(
    {
        RuntimeStage.WAITING_ARTIFACT,
        RuntimeStage.AWAITING_EXECUTION_POLICY,
        RuntimeStage.EVALUATOR_UNAVAILABLE,
        RuntimeStage.RETRYABLE,
        RuntimeStage.EVALUATED,
        RuntimeStage.AWAITING_QVL,
    }
)


@dataclass(frozen=True)
class BoundedEvaluation:
    """The exact public evaluation projection accepted from the internal API."""

    deal_id: str
    score_band: str
    quality_delta: str
    offer_price: int
    recommendation: str
    confidence: str
    methodology_summary: str
    compute_cost_wei: int
    fee_wei: int

    @classmethod
    def from_public_dict(
        cls,
        payload: dict[str, Any],
        *,
        expected_deal_id: str,
    ) -> "BoundedEvaluation":
        fields = {
            "deal_id",
            "score_band",
            "quality_delta",
            "offer_price",
            "recommendation",
            "confidence",
            "methodology_summary",
            "compute_cost_wei",
            "fee_wei",
        }
        if set(payload) != fields:
            raise ControlPlaneError("evaluation_projection_shape_invalid")
        if not isinstance(payload["deal_id"], str) or payload["deal_id"] != expected_deal_id:
            raise ControlPlaneError("evaluation_deal_binding_invalid")
        if payload["score_band"] not in SCORE_BANDS:
            raise ControlPlaneError("evaluation_score_band_invalid")
        if payload["quality_delta"] not in QUALITY_BANDS:
            raise ControlPlaneError("evaluation_quality_band_invalid")
        if payload["recommendation"] not in RECOMMENDATIONS:
            raise ControlPlaneError("evaluation_recommendation_invalid")
        if payload["confidence"] != "withheld":
            raise ControlPlaneError("evaluation_confidence_not_bounded")
        if payload["methodology_summary"] != "private_evaluator_details_withheld":
            raise ControlPlaneError("evaluation_methodology_not_bounded")
        for name in ("offer_price", "compute_cost_wei", "fee_wei"):
            value = payload[name]
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ControlPlaneError(f"evaluation_{name}_invalid")
        return cls(**payload)

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "deal_id": self.deal_id,
            "score_band": self.score_band,
            "quality_delta": self.quality_delta,
            "offer_price": self.offer_price,
            "recommendation": self.recommendation,
            "confidence": self.confidence,
            "methodology_summary": self.methodology_summary,
            "compute_cost_wei": self.compute_cost_wei,
            "fee_wei": self.fee_wei,
        }


class InternalDealApi:
    """Runtime-authenticated client for the in-CVM deal control-plane API."""

    def __init__(
        self,
        base_url: str,
        *,
        auth_token: str,
        client: httpx.Client | None = None,
    ):
        _validate_http_endpoint(base_url, allow_plain_http=True)
        if not auth_token or "\r" in auth_token or "\n" in auth_token:
            raise DealRuntimeError("configured runtime auth is required")
        self.base_url = base_url.rstrip("/") + "/"
        self._headers = {"Authorization": f"Bearer {auth_token}"}
        self._client = client or httpx.Client(timeout=30.0)
        self._owns_client = client is None

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def get_result(self, deal_id: str) -> BoundedEvaluation | None:
        response = self._request("GET", f"deal/{_normalize_deal_id(deal_id)}/result")
        if response.status_code == 404:
            return None
        if response.status_code != 200:
            raise ControlPlaneRetryable("result_read_unavailable")
        return BoundedEvaluation.from_public_dict(
            _strict_json_object(response, surface="evaluation_result"),
            expected_deal_id=deal_id,
        )

    def execution_policy_current(self, deal_id: str) -> bool:
        """Check the persisted deal-evaluation gate before reading or running.

        The evaluate endpoint repeats this check authoritatively.  This
        preflight also prevents a previously evaluated in-memory result from
        being submitted after its execution-policy decision expires.
        """

        normalized_deal_id = _normalize_deal_id(deal_id)
        response = self._request(
            "POST",
            "policy/status",
            json_body={
                "surface": "deal_evaluation",
                "resource_id": normalized_deal_id,
            },
        )
        if response.status_code in (404, 409, 412, 423):
            return False
        if response.status_code in (400, 503):
            raise ExecutionPolicyNotReady("execution_policy_not_ready")
        if response.status_code != 200:
            raise ControlPlaneRetryable("execution_policy_status_unavailable")
        payload = _strict_json_object(response, surface="execution_policy_status")
        expected = {
            "surface",
            "schema_version",
            "canonicalization_version",
            "approval_domain_hash",
            "approver_root_hash",
            "found",
            "resource_id_hash",
            "current_pass",
            "raw_resource_id_egress",
            "record",
        }
        if set(payload) != expected:
            raise ControlPlaneError("execution_policy_status_shape_invalid")
        if (
            payload["surface"] != "execution_policy_status"
            or payload["schema_version"] != 2
            or payload["canonicalization_version"]
            != POLICY_CANONICALIZATION_VERSION
            or not isinstance(payload["approval_domain_hash"], str)
            or not SHA256_HEX_RE.fullmatch(payload["approval_domain_hash"])
            or not isinstance(payload["approver_root_hash"], str)
            or not SHA256_HEX_RE.fullmatch(payload["approver_root_hash"])
            or not isinstance(payload["found"], bool)
            or not isinstance(payload["current_pass"], bool)
            or payload["raw_resource_id_egress"] is not False
        ):
            raise ControlPlaneError("execution_policy_status_invalid")
        from tinker_delegate.execution_policy_store import execution_resource_hash

        if payload["resource_id_hash"] != execution_resource_hash(
            "deal_evaluation", normalized_deal_id
        ):
            raise ControlPlaneError("execution_policy_resource_binding_invalid")
        if payload["current_pass"]:
            record = payload["record"]
            if (
                payload["found"] is not True
                or not isinstance(record, dict)
                or record.get("surface") != "deal_evaluation"
                or record.get("decision") != "pass"
                or record.get("canonicalization_version")
                != POLICY_CANONICALIZATION_VERSION
                or record.get("approval_domain_hash")
                != payload["approval_domain_hash"]
                or record.get("resource_id_hash") != payload["resource_id_hash"]
                or record.get("raw_policy_egress") is not False
                or record.get("raw_resource_id_egress") is not False
            ):
                raise ControlPlaneError("execution_policy_pass_binding_invalid")
        return payload["current_pass"]

    def evaluate(self, deal_id: str) -> BoundedEvaluation:
        response = self._request("POST", f"deal/{_normalize_deal_id(deal_id)}/evaluate")
        if response.status_code == 200:
            return BoundedEvaluation.from_public_dict(
                _strict_json_object(response, surface="evaluation_result"),
                expected_deal_id=deal_id,
            )
        # The API deliberately emits fixed status codes.  Never echo response
        # bodies here: a future handler regression must not turn an exception or
        # evaluator-authored string into runtime logs.
        if response.status_code == 400:
            raise ArtifactNotReady("artifact_not_ready")
        if response.status_code in (401, 403, 409, 412, 423):
            raise ExecutionPolicyNotReady("execution_policy_not_ready")
        if response.status_code == 404:
            raise DealContextMissing("deal_context_missing")
        if response.status_code == 503:
            raise EvaluatorNotReady("evaluator_unavailable")
        if 500 <= response.status_code <= 599:
            raise EvaluationTerminalFailure("evaluation_failed_inside_boundary")
        raise ControlPlaneRetryable("evaluation_api_rejected")

    def notify_funded(self, context: dict[str, Any]) -> None:
        """Rehydrate public funded context after an API-process restart.

        This cannot recover artifact bytes or an evaluator session. It only
        recreates chain-bound public context so the seller can upload a fresh
        ciphertext for the same immutable artifact commitment.
        """

        expected = {
            "deal_id",
            "buyer",
            "seller",
            "budget_cap",
            "reserve_price",
            "artifact_hash",
        }
        if set(context) != expected:
            raise ControlPlaneError("funded_context_shape_invalid")
        deal_id = _normalize_deal_id(context["deal_id"])
        response = self._request("POST", "deal/notify-funded", json_body=context)
        if response.status_code != 200:
            raise ControlPlaneRetryable("funded_context_rehydration_failed")
        payload = _strict_json_object(response, surface="funded_context")
        if (
            set(payload) != {"deal_id", "state"}
            or payload["deal_id"] != deal_id
            or payload["state"] != "pending_artifact"
        ):
            raise ControlPlaneError("funded_context_response_invalid")

    def quarantine_reorg(self, deal_id: str) -> None:
        """Destroy private state after canonical block-hash divergence."""

        normalized_deal_id = _normalize_deal_id(deal_id)
        response = self._request(
            "POST",
            f"deal/{normalized_deal_id}/chain-reorg",
        )
        if response.status_code != 200:
            raise ControlPlaneRetryable("reorg_quarantine_unavailable")
        payload = _strict_json_object(response, surface="reorg_quarantine")
        if (
            set(payload)
            != {
                "deal_id",
                "quarantined",
                "seller_reupload_required",
                "raw_secret_egress",
            }
            or payload["deal_id"] != normalized_deal_id
            or payload["quarantined"] is not True
            or payload["seller_reupload_required"] is not True
            or payload["raw_secret_egress"] is not False
        ):
            raise ControlPlaneError("reorg_quarantine_response_invalid")

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
    ) -> httpx.Response:
        try:
            return self._client.request(
                method,
                urljoin(self.base_url, path),
                headers=self._headers,
                json=json_body,
            )
        except httpx.TransportError as exc:
            raise ControlPlaneRetryable("control_plane_transport_unavailable") from exc


@dataclass(frozen=True)
class SignerAttestationPacket:
    """Raw quote stays in memory only long enough to reach independent QVL."""

    evidence: SignerAttestationEvidence
    quote: str


class IndependentVerdictProvider(Protocol):
    def issue_challenge(self) -> QvlChallenge:
        """Authenticate a one-time QVL challenge before quote collection."""

    def verify(
        self,
        packet: SignerAttestationPacket,
        challenge: QvlChallenge,
    ) -> IndependentAttestationVerdict:
        """Return a strict, signed independent DCAP/QVL verdict."""


class HttpsIndependentQvlClient:
    """Send one fresh quote to an independently operated DCAP/QVL service."""

    def __init__(
        self,
        url: str,
        *,
        auth_token: str = "",
        client: httpx.Client | None = None,
        allow_plain_http_for_local_test: bool = False,
        trusted_verifier_addresses: tuple[str, ...] = (),
        expected_policy_hash: str = "",
        chain_id: int = 0,
        cvm_id: str = "",
        deployment_intent_sha256: str = "",
        release_authority_sha256: str = "",
        ceremony_nonce: str = "",
        measurement_policy_sha256: str = "",
    ):
        _validate_http_endpoint(url, allow_plain_http=allow_plain_http_for_local_test)
        if urlparse(url).path != "/verify":
            raise DealRuntimeError("QVL endpoint is invalid")
        if (
            not 32 <= len(auth_token.encode("utf-8")) <= 4_096
            or any(ord(character) < 0x21 or ord(character) > 0x7E for character in auth_token)
        ):
            raise DealRuntimeError("QVL auth token is invalid")
        self.url = url
        self.challenge_url = urlparse(url)._replace(path="/challenge").geturl()
        self._headers = {"Authorization": f"Bearer {auth_token}"}
        self._trusted_verifier_addresses = tuple(trusted_verifier_addresses)
        self._expected_policy_hash = expected_policy_hash
        try:
            self._challenge_request = challenge_request(
                "diligence",
                chain_id=chain_id,
                domain="main_runtime_cvm",
                cvm_id=cvm_id,
                deployment_intent_sha256=deployment_intent_sha256,
                release_authority_sha256=release_authority_sha256,
                ceremony_nonce=ceremony_nonce,
                measurement_policy_sha256=measurement_policy_sha256,
            )
        except QvlFreshnessError:
            raise DealRuntimeError("QVL release lineage is invalid") from None
        self._client = client or httpx.Client(timeout=30.0)
        self._owns_client = client is None

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def _post(self, url: str, payload: dict[str, object]) -> dict[str, Any]:
        request = self._client.build_request(
            "POST",
            url,
            headers={
                **self._headers,
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            content=json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("ascii"),
        )
        try:
            response = self._client.send(
                request,
                stream=True,
                follow_redirects=False,
            )
            try:
                content_type = (
                    response.headers.get("content-type", "")
                    .split(";", 1)[0]
                    .lower()
                )
                if (
                    response.status_code != 200
                    or response.history
                    or not (
                        content_type == "application/json"
                        or content_type.endswith("+json")
                    )
                ):
                    raise AttestationVerdictUnavailable("independent_qvl_rejected")
                raw = bytearray()
                for chunk in response.iter_bytes():
                    if len(chunk) > 65_536 - len(raw):
                        raise AttestationVerdictUnavailable(
                            "independent_qvl_response_too_large"
                        )
                    raw.extend(chunk)
            finally:
                response.close()
            decoded = json.loads(
                bytes(raw),
                object_pairs_hook=_unique_json_object,
                parse_constant=_reject_json_constant,
            )
            if not isinstance(decoded, dict):
                raise ValueError
            return decoded
        except AttestationVerdictUnavailable:
            raise
        except Exception:
            # The request may contain a bearer or raw quote. Do not retain it
            # in exception context or allow transport detail into logs.
            raise AttestationVerdictUnavailable("independent_qvl_unavailable") from None

    def issue_challenge(self) -> QvlChallenge:
        try:
            payload = self._post(
                self.challenge_url,
                self._challenge_request,
            )
            return authenticate_qvl_challenge(
                qvl_challenge_from_public_dict(payload),
                expected_profile="diligence",
                expected_chain_id=int(self._challenge_request["chain_id"]),
                expected_domain=str(self._challenge_request["domain"]),
                expected_cvm_id=str(self._challenge_request["cvm_id"]),
                expected_deployment_intent_sha256=str(
                    self._challenge_request["deployment_intent_sha256"]
                ),
                expected_release_authority_sha256=str(
                    self._challenge_request["release_authority_sha256"]
                ),
                expected_ceremony_nonce=str(
                    self._challenge_request["ceremony_nonce"]
                ),
                expected_measurement_policy_sha256=str(
                    self._challenge_request["measurement_policy_sha256"]
                ),
                trusted_verifier_addresses=self._trusted_verifier_addresses,
                expected_policy_hash=self._expected_policy_hash,
            )
        except AttestationVerdictUnavailable:
            raise
        except (httpx.TransportError, QvlFreshnessError, ControlPlaneError, ValueError):
            raise AttestationVerdictUnavailable("independent_qvl_unavailable") from None

    def verify(
        self,
        packet: SignerAttestationPacket,
        challenge: QvlChallenge,
    ) -> IndependentAttestationVerdict:
        evidence = packet.evidence
        expectation = evidence.to_public_dict()
        expectation["quote_report_data"] = challenge_bound_report_data(
            evidence.report_data, challenge
        )
        request = {
            "schema": QVL_REQUEST_SCHEMA,
            "challenge": challenge.to_public_dict(),
            "quote": packet.quote,
            "expectation": expectation,
        }
        try:
            payload = self._post(self.url, request)
            verdict = independent_attestation_verdict_from_public_dict(payload)
            authenticate_independent_attestation_verdict(
                verdict,
                expectation=IndependentAttestationExpectation(
                    trusted_verifier_addresses=self._trusted_verifier_addresses,
                    chain_id=int(self._challenge_request["chain_id"]),
                    domain=str(self._challenge_request["domain"]),
                    profile="diligence",
                    cvm_id=str(self._challenge_request["cvm_id"]),
                    deployment_intent_sha256=str(
                        self._challenge_request["deployment_intent_sha256"]
                    ),
                    release_authority_sha256=str(
                        self._challenge_request["release_authority_sha256"]
                    ),
                    ceremony_nonce=str(self._challenge_request["ceremony_nonce"]),
                    measurement_policy_sha256=str(
                        self._challenge_request["measurement_policy_sha256"]
                    ),
                    release_policy_hash=self._expected_policy_hash,
                    challenge_id=challenge.challenge_id,
                    challenge_digest=challenge.challenge_digest,
                    challenge_issued_at=challenge.issued_at,
                    challenge_expires_at=challenge.expires_at,
                    quote_hash=evidence.quote_hash,
                    report_data=evidence.report_data,
                    compose_hash=evidence.compose_hash,
                    app_id=evidence.app_id,
                    os_image_hash=evidence.os_image_hash,
                    signer_address=evidence.signer_address,
                    contract_address=evidence.contract_address,
                    max_age_seconds=300,
                ),
            )
            return verdict
        except (ControlPlaneError, ResultVerifierError, ValueError) as exc:
            raise AttestationVerdictUnavailable("independent_qvl_verdict_invalid") from exc


def collect_dstack_signer_attestation(
    *,
    signer_address: str,
    chain_id: int,
    contract_address: str,
    challenge_digest: bytes = bytes(32),
) -> SignerAttestationPacket:
    """Collect one quote and derive its bounded signer evidence exactly once.

    Calling ``get_attestation_details`` twice could yield two distinct quote
    hashes.  This collector therefore builds both the local evidence envelope
    and the QVL request from the same quote retrieval.
    """

    if not is_dstack_enabled():
        raise SignerUnavailable("dstack mode is required for signer attestation")
    report_data = signer_attestation_report_data(
        signer_address=signer_address,
        chain_id=chain_id,
        contract_address=contract_address,
    )
    if not isinstance(challenge_digest, bytes) or len(challenge_digest) != 32:
        raise SignerUnavailable("QVL challenge digest is invalid")
    details = get_attestation_details(report_data + challenge_digest)
    quote_bytes = _decode_nonempty_hex(str(details.get("quote") or ""), field="quote")
    expected_report_data = "0x" + report_data.hex()
    observed_report_data = _decode_nonempty_hex(
        str(details.get("quote_report_data") or ""), field="quote_report_data"
    )
    if observed_report_data != report_data + challenge_digest:
        raise SignerUnavailable("QVL challenge report data mismatch")
    evidence = SignerAttestationEvidence(
        mode="tdx",
        signer_address=normalize_address(signer_address),
        chain_id=int(chain_id),
        contract_address=normalize_address(contract_address),
        report_data=expected_report_data,
        quote_report_data=expected_report_data,
        quote_hash="0x" + hashlib.sha256(quote_bytes).hexdigest(),
        quote_size=len(quote_bytes),
        compose_hash=normalize_optional_bytes32(str(details.get("compose_hash") or "")),
        app_id=str(details.get("app_id") or ""),
        os_image_hash=str(details.get("os_image_hash") or ""),
    )
    return SignerAttestationPacket(evidence=evidence, quote="0x" + quote_bytes.hex())


@dataclass(frozen=True)
class SubmissionOutcome:
    tx_hash: str
    result_hash: str


@dataclass(frozen=True)
class SubmissionReconciliation:
    """Exact-hash result of reconciling one already-signed transaction."""

    status: str
    receipt_block: int | None = None
    receipt_block_hash: str = ""
    receipt_status: int | None = None


class ResultCoordinator(Protocol):
    def funded_context(self, deal_id: str) -> dict[str, Any]:
        """Read immutable public chain context for API rehydration."""

    def inspect(self, deal_id: str) -> str:
        """Return funded, submitted, resolved, or unavailable."""

    def submit(
        self,
        evaluation: BoundedEvaluation,
        *,
        before_broadcast: Callable[[PreparedSubmissionAttempt], None] | None = None,
    ) -> SubmissionOutcome:
        """Authorize and broadcast the exact bounded result."""

    def reconcile_submission(
        self,
        *,
        deal_id: str,
        tx_hash: str,
        nonce: int,
    ) -> SubmissionReconciliation:
        """Inspect only the exact prepared hash/nonce; never rebroadcast."""


class ProductionResultCoordinator:
    """Policy-bound dstack authorization and DiligenceRoom submission."""

    def __init__(
        self,
        *,
        rpc: JsonRpcClient,
        submitter: DiligenceRoomSubmitter,
        verifier_signer: Any,
        policy: ResultVerifierPolicy,
        verdict_provider: IndependentVerdictProvider | None,
        attestation_release_policy_hash: str = "",
        allow_unverified_local_attestation: bool = False,
        attestation_collector: Callable[..., SignerAttestationPacket] = collect_dstack_signer_attestation,
    ):
        self.rpc = rpc
        self.submitter = submitter
        self.verifier_signer = verifier_signer
        self.policy = policy
        self.verdict_provider = verdict_provider
        self.attestation_release_policy_hash = attestation_release_policy_hash
        self.allow_unverified_local_attestation = allow_unverified_local_attestation
        self.attestation_collector = attestation_collector
        self.chain_id = rpc.chain_id()
        signer_address = normalize_address(submitter.signer.address)
        verifier_address = normalize_address(verifier_signer.address)
        if signer_address == verifier_address:
            raise DealRuntimeError("result verifier must be distinct from TEE signer")
        onchain_verifier = submitter.read_result_verifier()
        if normalize_address(onchain_verifier) != verifier_address:
            raise DealRuntimeError("dstack result verifier does not match target contract")
        if not policy.allowed_compose_hashes:
            raise DealRuntimeError("allowed compose hashes are required")
        if not policy.allowed_app_ids:
            raise DealRuntimeError("allowed dstack app IDs are required")
        self._require_attestation_binding()
        if self.chain_id not in LOCAL_CHAIN_IDS:
            if allow_unverified_local_attestation:
                raise DealRuntimeError("unverified attestation is local-chain only")
            if not is_dstack_enabled() or is_dstack_simulator():
                raise DealRuntimeError("production settlement requires a real dstack CVM")
            if verdict_provider is None:
                raise DealRuntimeError("an independent DCAP/QVL provider is required")

    def _require_attestation_binding(self) -> None:
        configured_roots = tuple(self.policy.trusted_attestation_verifier_addresses)
        production = self.chain_id not in LOCAL_CHAIN_IDS
        if not production and not configured_roots and not self.attestation_release_policy_hash:
            return
        if len(configured_roots) != 1:
            raise DealRuntimeError(
                "exactly one trusted independent Diligence QVL signer is required"
            )
        if not self.attestation_release_policy_hash:
            raise DealRuntimeError("Diligence QVL release policy hash is required")
        try:
            expected_verifier = normalize_address(configured_roots[0])
            expected_policy_hash = normalize_bytes32(
                self.attestation_release_policy_hash
            )
            onchain_verifier = normalize_address(
                self.submitter.read_attestation_verifier()
            )
            onchain_policy_hash = normalize_bytes32(
                self.submitter.read_attestation_release_policy_hash()
            )
        except ChainSubmitterError as exc:
            raise DealRuntimeError("invalid Diligence attestation binding") from exc
        if int(expected_verifier, 16) == 0:
            raise DealRuntimeError("Diligence QVL signer must be nonzero")
        if expected_verifier != onchain_verifier:
            raise DealRuntimeError(
                "configured Diligence QVL signer does not match frozen on-chain binding"
            )
        if expected_policy_hash != onchain_policy_hash:
            raise DealRuntimeError(
                "configured Diligence QVL policy hash does not match frozen on-chain binding"
            )
        if not self.submitter.read_attestation_binding_frozen():
            raise DealRuntimeError("Diligence QVL binding is not frozen on-chain")
        if expected_verifier in {
            normalize_address(self.submitter.signer.address),
            normalize_address(self.verifier_signer.address),
            normalize_address(self.submitter.contract_address),
        }:
            raise DealRuntimeError("Diligence QVL signer conflicts with a release role")

    @classmethod
    def from_settings(
        cls,
        settings: Settings,
        *,
        rpc_url: str,
        contract_address: str,
        policy: ResultVerifierPolicy,
        verdict_provider: IndependentVerdictProvider | None,
        attestation_release_policy_hash: str = "",
        allow_unverified_local_attestation: bool = False,
    ) -> "ProductionResultCoordinator":
        rpc = JsonRpcClient(rpc_url)
        try:
            signer = DstackEthereumSigner.from_settings(settings)
            submitter = DiligenceRoomSubmitter(
                rpc,
                contract_address,
                signer,
                gas_limit=settings.chain_submit_gas_limit,
            )
            return cls(
                rpc=rpc,
                submitter=submitter,
                verifier_signer=DstackResultVerifierSigner.from_settings(settings),
                policy=policy,
                verdict_provider=verdict_provider,
                attestation_release_policy_hash=attestation_release_policy_hash,
                allow_unverified_local_attestation=allow_unverified_local_attestation,
            )
        except Exception:
            rpc.close()
            raise

    def close(self) -> None:
        self.rpc.close()

    def inspect(self, deal_id: str) -> str:
        deal = self.submitter.read_deal(_deal_id_int(deal_id))
        if deal.state == 1:
            return "funded"
        if deal.state == 2:
            return "submitted"
        if deal.state in (3, 4, 5):
            return "resolved"
        return "unavailable"

    def funded_context(self, deal_id: str) -> dict[str, Any]:
        normalized_deal_id = _normalize_deal_id(deal_id)
        deal = self.submitter.read_deal(int(normalized_deal_id))
        if deal.state == 2:
            raise DealAlreadySubmitted("deal_already_submitted")
        if deal.state in (3, 4, 5):
            raise DealAlreadyResolved("deal_already_resolved")
        if deal.state != 1:
            raise SubmissionRejected("deal_not_funded")
        return {
            "deal_id": normalized_deal_id,
            "buyer": normalize_address(deal.buyer),
            "seller": normalize_address(deal.seller),
            "budget_cap": int(deal.budget_cap),
            "reserve_price": int(deal.reserve_price),
            "artifact_hash": normalize_bytes32(deal.artifact_hash),
        }

    def submit(
        self,
        evaluation: BoundedEvaluation,
        *,
        before_broadcast: Callable[[PreparedSubmissionAttempt], None] | None = None,
    ) -> SubmissionOutcome:
        # Re-read the permanently frozen trust pair immediately before every
        # settlement. Startup validation alone is insufficient across a long-
        # lived process or an accidentally changed RPC target.
        self._require_attestation_binding()
        deal_id = _deal_id_int(evaluation.deal_id)
        deal = self.submitter.read_deal(deal_id)
        if deal.state == 2:
            raise DealAlreadySubmitted("deal_already_submitted")
        if deal.state in (3, 4, 5):
            raise DealAlreadyResolved("deal_already_resolved")
        if deal.state != 1:
            raise SubmissionRejected("deal_not_funded")

        if self.verdict_provider is None:
            challenge = None
        else:
            challenge = self.verdict_provider.issue_challenge()
        packet = self.attestation_collector(
            signer_address=self.submitter.signer.address,
            chain_id=self.chain_id,
            contract_address=self.submitter.contract_address,
            challenge_digest=(challenge.digest_bytes if challenge is not None else bytes(32)),
        )
        independent_verdict = None
        if self.verdict_provider is not None:
            if challenge is None:
                raise AttestationVerdictUnavailable("independent_qvl_challenge_required")
            independent_verdict = self.verdict_provider.verify(packet, challenge)
        elif not (
            self.allow_unverified_local_attestation and self.chain_id in LOCAL_CHAIN_IDS
        ):
            raise AttestationVerdictUnavailable("independent_qvl_verdict_required")

        try:
            authorization = authorize_result_submission(
                ResultAuthorizationRequest(
                    chain_id=self.chain_id,
                    contract_address=self.submitter.contract_address,
                    deal_id=deal_id,
                    deal=deal,
                    fee_bps=self.submitter.read_fee_bps(),
                    compute_settlement_policy_enabled=(
                        self.submitter.read_compute_settlement_policy_enabled()
                    ),
                    compose_hash=packet.evidence.compose_hash,
                    score_band=evaluation.score_band,
                    compute_cost_wei=evaluation.compute_cost_wei,
                ),
                signer_attestation=packet.evidence,
                policy=self.policy,
                verifier_signer=self.verifier_signer,
                independent_verdict=independent_verdict,
            )
        except ResultVerifierError as exc:
            raise SubmissionRejected("result_authorization_rejected") from exc

        prepared_attempt: PreparedSubmissionAttempt | None = None

        def checkpoint(attempt: PreparedSubmissionAttempt) -> None:
            nonlocal prepared_attempt
            prepared_attempt = attempt
            if before_broadcast is not None:
                before_broadcast(attempt)

        try:
            receipt: SubmitResultReceipt = self.submitter.submit_result(
                deal_id=deal_id,
                score_band=evaluation.score_band,
                compute_cost_wei=evaluation.compute_cost_wei,
                authorization_expiry=authorization.authorization_expiry,
                verifier_signature=authorization.verifier_signature,
                signer_attestation=packet.evidence,
                before_broadcast=checkpoint,
            )
        except httpx.TransportError as exc:
            # The remote node may have accepted the raw transaction before the
            # connection failed.  Automatic retry could replace or duplicate a
            # pending submission, so hand control to chain observation.
            if prepared_attempt is not None:
                raise SubmissionUncertain(
                    "submission_broadcast_uncertain"
                ) from exc
            raise SubmissionRetryable(
                "submission_prebroadcast_transport_unavailable"
            ) from exc
        except ChainSubmitterError as exc:
            raise SubmissionRejected("chain_submission_rejected") from exc
        return SubmissionOutcome(tx_hash=receipt.tx_hash, result_hash=receipt.result_hash)

    def reconcile_submission(
        self,
        *,
        deal_id: str,
        tx_hash: str,
        nonce: int,
    ) -> SubmissionReconciliation:
        """Reconcile an ambiguous broadcast without signing or sending again."""

        normalized_hash = _optional_tx_hash(tx_hash)
        if not normalized_hash:
            raise SubmissionRejected("submission_attempt_hash_required")
        if isinstance(nonce, bool) or not isinstance(nonce, int) or nonce < 0:
            raise SubmissionRejected("submission_attempt_nonce_invalid")

        receipt = self.rpc.transaction_receipt(normalized_hash)
        if receipt is not None:
            receipt_hash = _optional_tx_hash(str(receipt.get("transactionHash") or ""))
            block_hash = _optional_nonzero_bytes32(
                str(receipt.get("blockHash") or "")
            )
            block_number = _rpc_quantity(receipt.get("blockNumber"), "receipt block")
            status = _rpc_quantity(receipt.get("status"), "receipt status")
            if (
                receipt_hash != normalized_hash
                or status not in (0, 1)
            ):
                raise SubmissionRejected("submission_receipt_invalid")
            if status == 0:
                return SubmissionReconciliation(
                    status="confirmed_revert",
                    receipt_block=block_number,
                    receipt_block_hash=block_hash,
                    receipt_status=0,
                )
            # A success receipt alone is insufficient when RPC views disagree:
            # also require the contract state to reflect submission/resolution.
            disposition = self.inspect(_normalize_deal_id(deal_id))
            if disposition not in {"submitted", "resolved"}:
                return SubmissionReconciliation(status="rpc_views_inconsistent")
            return SubmissionReconciliation(
                status="confirmed_success",
                receipt_block=block_number,
                receipt_block_hash=block_hash,
                receipt_status=1,
            )

        transaction = self.rpc.transaction_by_hash(normalized_hash)
        if transaction is not None:
            observed_hash = _optional_tx_hash(str(transaction.get("hash") or ""))
            observed_nonce = _rpc_quantity(transaction.get("nonce"), "transaction nonce")
            observed_from = normalize_address(str(transaction.get("from") or ""))
            observed_to = normalize_address(str(transaction.get("to") or ""))
            if (
                observed_hash != normalized_hash
                or observed_nonce != nonce
                or observed_from != normalize_address(self.submitter.signer.address)
                or observed_to != normalize_address(self.submitter.contract_address)
            ):
                raise SubmissionRejected("submission_transaction_binding_invalid")
            return SubmissionReconciliation(status="pending_exact_transaction")

        latest_nonce = self.rpc.nonce(
            normalize_address(self.submitter.signer.address),
            "latest",
        )
        pending_nonce = self.rpc.nonce(
            normalize_address(self.submitter.signer.address),
            "pending",
        )
        if latest_nonce > nonce:
            return SubmissionReconciliation(status="nonce_consumed_without_exact_hash")
        if pending_nonce > nonce:
            return SubmissionReconciliation(status="pending_nonce_without_exact_hash")
        return SubmissionReconciliation(status="exact_transaction_not_found")


@dataclass
class DealRuntimeRecord:
    deal_id: str
    stage: RuntimeStage
    evaluation: BoundedEvaluation | None = None
    funded_block: int | None = None
    funded_tx_hash: str = ""
    funded_log_index: int | None = None
    submission_tx_hash: str = ""
    result_hash: str = ""
    submission_nonce: int | None = None
    submission_attempt_tx_hash: str = ""
    submission_attempt_result_hash: str = ""
    submission_prepared_at: int | None = None
    submission_receipt_block: int | None = None
    submission_receipt_block_hash: str = ""
    submission_receipt_status: int | None = None
    reconciliation_state: str = ""
    attempt_count: int = 0
    last_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "deal_id": self.deal_id,
            "stage": self.stage.value,
            "evaluation": self.evaluation.to_public_dict() if self.evaluation else None,
            "funded_block": self.funded_block,
            "funded_tx_hash": self.funded_tx_hash,
            "funded_log_index": self.funded_log_index,
            "submission_tx_hash": self.submission_tx_hash,
            "result_hash": self.result_hash,
            "submission_nonce": self.submission_nonce,
            "submission_attempt_tx_hash": self.submission_attempt_tx_hash,
            "submission_attempt_result_hash": self.submission_attempt_result_hash,
            "submission_prepared_at": self.submission_prepared_at,
            "submission_receipt_block": self.submission_receipt_block,
            "submission_receipt_block_hash": self.submission_receipt_block_hash,
            "submission_receipt_status": self.submission_receipt_status,
            "reconciliation_state": self.reconciliation_state,
            "attempt_count": self.attempt_count,
            "last_reason": self.last_reason,
            "raw_secret_egress": False,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "DealRuntimeRecord":
        legacy_expected = {
            "deal_id",
            "stage",
            "evaluation",
            "funded_block",
            "funded_tx_hash",
            "funded_log_index",
            "submission_tx_hash",
            "result_hash",
            "attempt_count",
            "last_reason",
            "raw_secret_egress",
        }
        expected = legacy_expected | {
            "submission_nonce",
            "submission_attempt_tx_hash",
            "submission_attempt_result_hash",
            "submission_prepared_at",
            "submission_receipt_block",
            "submission_receipt_block_hash",
            "submission_receipt_status",
            "reconciliation_state",
        }
        if set(payload) == legacy_expected:
            payload = {
                **payload,
                "submission_nonce": None,
                "submission_attempt_tx_hash": "",
                "submission_attempt_result_hash": "",
                "submission_prepared_at": None,
                "submission_receipt_block": None,
                "submission_receipt_block_hash": "",
                "submission_receipt_status": None,
                "reconciliation_state": "",
            }
        if set(payload) != expected or payload.get("raw_secret_egress") is not False:
            raise RuntimeStateError("deal runtime record shape is invalid")
        deal_id = _normalize_deal_id(payload["deal_id"])
        try:
            stage = RuntimeStage(payload["stage"])
        except (TypeError, ValueError) as exc:
            raise RuntimeStateError("deal runtime stage is invalid") from exc
        evaluation_payload = payload["evaluation"]
        evaluation = None
        if evaluation_payload is not None:
            if not isinstance(evaluation_payload, dict):
                raise RuntimeStateError("deal runtime evaluation is invalid")
            try:
                evaluation = BoundedEvaluation.from_public_dict(
                    evaluation_payload,
                    expected_deal_id=deal_id,
                )
            except ControlPlaneError as exc:
                raise RuntimeStateError("deal runtime evaluation is invalid") from exc
        funded_block = _optional_nonnegative_int(payload["funded_block"], "funded_block")
        funded_log_index = _optional_nonnegative_int(payload["funded_log_index"], "funded_log_index")
        attempt_count = _nonnegative_int(payload["attempt_count"], "attempt_count")
        funded_tx_hash = _optional_tx_hash(payload["funded_tx_hash"])
        submission_tx_hash = _optional_tx_hash(payload["submission_tx_hash"])
        result_hash = _optional_nonzero_bytes32(payload["result_hash"])
        submission_nonce = _optional_nonnegative_int(
            payload["submission_nonce"], "submission_nonce"
        )
        submission_attempt_tx_hash = _optional_tx_hash(
            payload["submission_attempt_tx_hash"]
        )
        submission_attempt_result_hash = _optional_nonzero_bytes32(
            payload["submission_attempt_result_hash"]
        )
        submission_prepared_at = _optional_nonnegative_int(
            payload["submission_prepared_at"], "submission_prepared_at"
        )
        submission_receipt_block = _optional_nonnegative_int(
            payload["submission_receipt_block"],
            "submission_receipt_block",
        )
        submission_receipt_block_hash = _optional_nonzero_bytes32(
            payload["submission_receipt_block_hash"]
        )
        submission_receipt_status = payload["submission_receipt_status"]
        if submission_receipt_status not in (None, 0, 1):
            raise RuntimeStateError(
                "deal runtime submission receipt status is invalid"
            )
        reconciliation_state = payload["reconciliation_state"]
        if (
            not isinstance(reconciliation_state, str)
            or len(reconciliation_state) > 80
        ):
            raise RuntimeStateError(
                "deal runtime reconciliation state is invalid"
            )
        last_reason = payload["last_reason"]
        if not isinstance(last_reason, str) or len(last_reason) > 80:
            raise RuntimeStateError("deal runtime reason code is invalid")
        return cls(
            deal_id=deal_id,
            stage=stage,
            evaluation=evaluation,
            funded_block=funded_block,
            funded_tx_hash=funded_tx_hash,
            funded_log_index=funded_log_index,
            submission_tx_hash=submission_tx_hash,
            result_hash=result_hash,
            submission_nonce=submission_nonce,
            submission_attempt_tx_hash=submission_attempt_tx_hash,
            submission_attempt_result_hash=submission_attempt_result_hash,
            submission_prepared_at=submission_prepared_at,
            submission_receipt_block=submission_receipt_block,
            submission_receipt_block_hash=submission_receipt_block_hash,
            submission_receipt_status=submission_receipt_status,
            reconciliation_state=reconciliation_state,
            attempt_count=attempt_count,
            last_reason=last_reason,
        )


@dataclass(frozen=True)
class BlockCheckpoint:
    """Canonical hash endpoints for one completely journaled scan range."""

    from_block: int
    to_block: int
    from_block_hash: str
    to_block_hash: str
    event_deal_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "from_block": self.from_block,
            "to_block": self.to_block,
            "from_block_hash": self.from_block_hash,
            "to_block_hash": self.to_block_hash,
            "event_deal_ids": list(self.event_deal_ids),
        }

    @classmethod
    def from_dict(cls, payload: Any) -> "BlockCheckpoint":
        if not isinstance(payload, dict) or set(payload) != {
            "from_block",
            "to_block",
            "from_block_hash",
            "to_block_hash",
            "event_deal_ids",
        }:
            raise RuntimeStateError("block checkpoint shape is invalid")
        from_block = _nonnegative_int(payload["from_block"], "from_block")
        to_block = _nonnegative_int(payload["to_block"], "to_block")
        if to_block < from_block:
            raise RuntimeStateError("block checkpoint range is invalid")
        deal_ids = payload["event_deal_ids"]
        if (
            not isinstance(deal_ids, list)
            or len(deal_ids) > 10_000
            or len(set(deal_ids)) != len(deal_ids)
        ):
            raise RuntimeStateError("block checkpoint deal IDs are invalid")
        normalized_ids = tuple(
            sorted(
                (_normalize_deal_id(value) for value in deal_ids),
                key=int,
            )
        )
        return cls(
            from_block=from_block,
            to_block=to_block,
            from_block_hash=_required_nonzero_bytes32(
                payload["from_block_hash"],
                "from block hash",
            ),
            to_block_hash=_required_nonzero_bytes32(
                payload["to_block_hash"],
                "to block hash",
            ),
            event_deal_ids=normalized_ids,
        )


class DealRuntimeStateStore:
    """Atomic durable journal containing only public/bounded deal state."""

    schema_version = 2
    max_checkpoints = 128

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.checkpoints: list[BlockCheckpoint] = []
        self.scan_anchor_block: int | None = None

    def load(self) -> dict[str, DealRuntimeRecord]:
        if not self.path.exists():
            self.checkpoints = []
            self.scan_anchor_block = None
            return {}
        self._require_safe_existing_file()
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeStateError("deal runtime state could not be loaded") from exc
        if not isinstance(payload, dict):
            raise RuntimeStateError("deal runtime state must be an object")
        legacy = (
            set(payload)
            == {"schema", "schema_version", "deals", "raw_secret_egress"}
            and payload.get("schema") == RUNTIME_SCHEMA
            and payload.get("schema_version") == 1
        )
        if legacy:
            self.checkpoints = []
            self.scan_anchor_block = None
        else:
            if set(payload) != {
                "schema",
                "schema_version",
                "deals",
                "block_checkpoints",
                "scan_anchor_block",
                "raw_secret_egress",
            }:
                raise RuntimeStateError("deal runtime state shape is invalid")
            if (
                payload["schema"] != RUNTIME_STATE_SCHEMA
                or payload["schema_version"] != self.schema_version
                or not isinstance(payload["block_checkpoints"], list)
                or len(payload["block_checkpoints"]) > self.max_checkpoints
            ):
                raise RuntimeStateError("deal runtime state header is invalid")
            self.checkpoints = [
                BlockCheckpoint.from_dict(item)
                for item in payload["block_checkpoints"]
            ]
            self.scan_anchor_block = _optional_nonnegative_int(
                payload["scan_anchor_block"],
                "scan_anchor_block",
            )
        if (
            payload.get("raw_secret_egress") is not False
            or not isinstance(payload.get("deals"), dict)
        ):
            raise RuntimeStateError("deal runtime state header is invalid")
        records: dict[str, DealRuntimeRecord] = {}
        for key, value in payload["deals"].items():
            if not isinstance(value, dict):
                raise RuntimeStateError("deal runtime record must be an object")
            record = DealRuntimeRecord.from_dict(value)
            if key != record.deal_id:
                raise RuntimeStateError("deal runtime record key mismatch")
            records[key] = record
        return records

    def save(self, records: dict[str, DealRuntimeRecord]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            self._require_safe_existing_file()
        payload = {
            "schema": RUNTIME_STATE_SCHEMA,
            "schema_version": self.schema_version,
            "deals": {
                deal_id: records[deal_id].to_dict()
                for deal_id in sorted(records, key=lambda value: int(value))
            },
            "block_checkpoints": [
                checkpoint.to_dict() for checkpoint in self.checkpoints
            ],
            "scan_anchor_block": self.scan_anchor_block,
            "raw_secret_egress": False,
        }
        encoded = json.dumps(payload, sort_keys=True, indent=2) + "\n"
        fd, temporary = tempfile.mkstemp(
            prefix=f".{self.path.name}.",
            suffix=".tmp",
            dir=self.path.parent,
        )
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(encoded.encode("utf-8"))
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            Path(temporary).unlink(missing_ok=True)
            raise
        os.replace(temporary, self.path)
        os.chmod(self.path, 0o600)
        directory_fd = os.open(self.path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

    def _require_safe_existing_file(self) -> None:
        try:
            info = self.path.lstat()
        except OSError as exc:
            raise RuntimeStateError(
                "deal runtime state metadata is unavailable"
            ) from exc
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise RuntimeStateError("deal runtime state file is unsafe")


class DealRuntimeSingleWriterLease:
    """Kernel-enforced exclusive lease for one deal-runtime state file."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._fd: int | None = None

    @property
    def held(self) -> bool:
        return self._fd is not None

    def acquire(self) -> None:
        if self._fd is not None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            info = self.path.lstat()
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise RuntimeStateError("deal runtime lease file is unsafe")
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(self.path, flags, 0o600)
        except OSError as exc:
            raise RuntimeStateError("deal runtime lease is unavailable") from exc
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise RuntimeStateError("deal runtime lease file is unsafe")
            os.fchmod(fd, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise RuntimeStateError(
                    "deal runtime single-writer lease is already held"
                ) from exc
            marker = (
                json.dumps(
                    {
                        "schema": "dnai.deal-runtime-lease.v1",
                        "pid": os.getpid(),
                        "acquired_at": int(time.time()),
                    },
                    sort_keys=True,
                )
                + "\n"
            ).encode("ascii")
            os.ftruncate(fd, 0)
            os.write(fd, marker)
            os.fsync(fd)
            self._fd = fd
        except Exception:
            os.close(fd)
            raise

    def release(self) -> None:
        fd = self._fd
        if fd is None:
            return
        self._fd = None
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


@dataclass(frozen=True)
class RuntimeCycleSummary:
    scanned_from_block: int | None
    scanned_to_block: int | None
    cursor_advanced: bool
    event_count: int
    funded_observed: int
    evaluated: int
    submitted: int
    resolved: int
    awaiting_artifact: int
    awaiting_execution_policy: int
    awaiting_qvl: int
    retryable: int
    terminal_failures: int

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "schema": RUNTIME_SCHEMA,
            "scanned_from_block": self.scanned_from_block,
            "scanned_to_block": self.scanned_to_block,
            "cursor_advanced": self.cursor_advanced,
            "reorg_policy": "confirmed_block_hash_checkpoint_full_rewind",
            "event_count": self.event_count,
            "funded_observed": self.funded_observed,
            "evaluated": self.evaluated,
            "submitted": self.submitted,
            "resolved": self.resolved,
            "awaiting_artifact": self.awaiting_artifact,
            "awaiting_execution_policy": self.awaiting_execution_policy,
            "awaiting_qvl": self.awaiting_qvl,
            "retryable": self.retryable,
            "terminal_failures": self.terminal_failures,
            "raw_secret_egress": False,
        }


class DealRuntimeService:
    """Drive watcher -> internal evaluation -> authorized chain settlement."""

    def __init__(
        self,
        *,
        source: JsonRpcLogSource,
        dispatcher: ChainEventDispatcher,
        cursor_store: ChainCursorStore,
        state_store: DealRuntimeStateStore,
        control_plane: InternalDealApi,
        result_coordinator: ResultCoordinator,
        start_block: int | None = None,
        confirmations: int = 2,
        max_deals_per_cycle: int = 25,
        lease: DealRuntimeSingleWriterLease | None = None,
    ):
        if confirmations < 0:
            raise DealRuntimeError("confirmations cannot be negative")
        if max_deals_per_cycle <= 0 or max_deals_per_cycle > 1_000:
            raise DealRuntimeError("max deals per cycle is outside the safe bound")
        self.source = source
        self.dispatcher = dispatcher
        self.cursor_store = cursor_store
        self.state_store = state_store
        self.control_plane = control_plane
        self.result_coordinator = result_coordinator
        self.start_block = start_block
        self.confirmations = confirmations
        self.max_deals_per_cycle = max_deals_per_cycle
        self.records = state_store.load()
        self.checkpoints = list(state_store.checkpoints)
        self.scan_anchor_block = state_store.scan_anchor_block
        self.lease = lease or DealRuntimeSingleWriterLease(
            state_store.path.with_suffix(state_store.path.suffix + ".lock")
        )

    def run_once(self) -> RuntimeCycleSummary:
        acquired_here = not self.lease.held
        if acquired_here:
            self.lease.acquire()
        try:
            scan = self._scan_confirmed_events()
            work = self._process_deals()
            counts = self._stage_counts()
            return RuntimeCycleSummary(
                scanned_from_block=scan["from_block"],
                scanned_to_block=scan["to_block"],
                cursor_advanced=scan["cursor_advanced"],
                event_count=scan["event_count"],
                funded_observed=scan["funded_observed"],
                evaluated=work["evaluated"],
                submitted=work["submitted"],
                resolved=counts[RuntimeStage.RESOLVED],
                awaiting_artifact=counts[RuntimeStage.WAITING_ARTIFACT],
                awaiting_execution_policy=counts[
                    RuntimeStage.AWAITING_EXECUTION_POLICY
                ],
                awaiting_qvl=counts[RuntimeStage.AWAITING_QVL],
                retryable=(
                    counts[RuntimeStage.RETRYABLE]
                    + counts[RuntimeStage.EVALUATOR_UNAVAILABLE]
                    + counts[RuntimeStage.SUBMISSION_UNCERTAIN]
                ),
                terminal_failures=(
                    counts[RuntimeStage.EVALUATION_FAILED]
                    + counts[RuntimeStage.SUBMISSION_REJECTED]
                ),
            )
        finally:
            if acquired_here:
                self.lease.release()

    def _scan_confirmed_events(self) -> dict[str, Any]:
        cursor = self.cursor_store.load()
        self._validate_cursor_policy(cursor)
        cursor = self._detect_and_compensate_reorg(cursor)
        if not self.dispatcher.created_context and cursor.created_deals:
            self.dispatcher._created = dict(cursor.created_deals)

        latest = self.source.latest_block()
        safe_tip = max(0, latest - self.confirmations)
        from_block = cursor.next_block if cursor.next_block is not None else self.start_block
        if from_block is None:
            from_block = safe_tip
        if from_block > safe_tip:
            return {
                "from_block": from_block,
                "to_block": safe_tip,
                "cursor_advanced": False,
                "event_count": 0,
                "funded_observed": 0,
            }

        from_hash = self.source.block_hash(from_block)
        to_hash_before = (
            from_hash
            if safe_tip == from_block
            else self.source.block_hash(safe_tip)
        )
        events = self.source.get_events(from_block, safe_tip)
        for event in events:
            observed = self.source.block_hash(event.block_number)
            if event.block_hash and event.block_hash.lower() != observed.lower():
                raise ChainWatcherError(
                    "event block hash changed during confirmed scan"
                )
        to_hash_after = (
            from_hash
            if safe_tip == from_block
            else self.source.block_hash(safe_tip)
        )
        if to_hash_before != to_hash_after:
            raise ChainWatcherError(
                "confirmed scan endpoint changed during observation"
            )
        self.dispatcher.dispatch(events)
        funded_observed = self._observe_events(events)
        checkpoint = BlockCheckpoint(
            from_block=from_block,
            to_block=safe_tip,
            from_block_hash=_required_nonzero_bytes32(
                from_hash,
                "from block hash",
            ),
            to_block_hash=_required_nonzero_bytes32(
                to_hash_after,
                "to block hash",
            ),
            event_deal_ids=tuple(
                sorted(
                    {
                        _normalize_deal_id(event.deal_id)
                        for event in events
                    },
                    key=int,
                )
            ),
        )
        if self.scan_anchor_block is None:
            self.scan_anchor_block = from_block
        self.checkpoints.append(checkpoint)
        if len(self.checkpoints) > self.state_store.max_checkpoints:
            self.checkpoints = [
                self.checkpoints[0],
                *self.checkpoints[-(self.state_store.max_checkpoints - 1) :],
            ]
        self.state_store.checkpoints = list(self.checkpoints)
        self.state_store.scan_anchor_block = self.scan_anchor_block
        # Journal first, cursor second.  A crash between the writes replays
        # idempotent API notifications; the inverse order could lose a funded
        # deal forever.
        self.state_store.save(self.records)
        self.cursor_store.update_after_scan(
            previous=cursor,
            from_block=from_block,
            to_block=safe_tip,
            confirmations=self.confirmations,
            contract_address=self.source.contract_address,
            created_deals=self.dispatcher.created_context,
        )
        return {
            "from_block": from_block,
            "to_block": safe_tip,
            "cursor_advanced": True,
            "event_count": len(events),
            "funded_observed": funded_observed,
        }

    def _detect_and_compensate_reorg(
        self,
        cursor: ChainCursorState,
    ) -> ChainCursorState:
        """Detect canonical divergence and conservatively rewind all deal state."""

        if not self.checkpoints:
            checkpoint = None
            mismatch = False
        else:
            checkpoint = self.checkpoints[-1]
            canonical_hash = self.source.block_hash(checkpoint.to_block)
            mismatch = canonical_hash != checkpoint.to_block_hash
        for record in self.records.values():
            if (
                record.submission_receipt_block is not None
                and record.submission_receipt_block_hash
                and self.source.block_hash(record.submission_receipt_block)
                != record.submission_receipt_block_hash
            ):
                mismatch = True
                break
        if not mismatch:
            return cursor

        # A hash mismatch means at least one prior event/control-plane
        # notification may belong to an orphaned ancestry.  Do not attempt a
        # partial semantic inverse of the contract state machine.  Quarantine
        # every private active context, clear bounded projections, and rebuild
        # from the original scan anchor on the canonical chain.
        for deal_id in sorted(self.records, key=int):
            self.control_plane.quarantine_reorg(deal_id)
        rewind_to = (
            self.scan_anchor_block
            if self.scan_anchor_block is not None
            else (
                self.start_block
                if self.start_block is not None
                else (
                    checkpoint.from_block
                    if checkpoint is not None
                    else 0
                )
            )
        )
        reset = ChainCursorState(
            next_block=rewind_to,
            created_deals={},
            confirmations=max(cursor.confirmations, self.confirmations),
            last_scanned_to_block=None,
            contract_address=self.source.contract_address,
        )
        # Rewind the cursor before removing the mismatched checkpoint. A crash
        # in between therefore re-enters this idempotent compensation path;
        # the inverse order could lose the only evidence that an advanced
        # cursor must be rebuilt.
        self.cursor_store.save(reset)
        self.records = {}
        self.checkpoints = []
        self.state_store.checkpoints = []
        self.state_store.scan_anchor_block = rewind_to
        self.scan_anchor_block = rewind_to
        self.state_store.save(self.records)
        self.dispatcher._created = {}
        return reset

    def _validate_cursor_policy(self, cursor: ChainCursorState) -> None:
        if cursor.contract_address and (
            normalize_address(cursor.contract_address)
            != normalize_address(self.source.contract_address)
        ):
            raise RuntimeStateError("chain cursor belongs to a different contract")
        if cursor.next_block is not None and self.confirmations < cursor.confirmations:
            raise RuntimeStateError("chain confirmation policy cannot be downgraded")

    def _observe_events(self, events: list[DiligenceRoomEvent]) -> int:
        funded_observed = 0
        for event in events:
            deal_id = _normalize_deal_id(event.deal_id)
            record = self.records.get(deal_id)
            if event.name == "DealFunded":
                funded_observed += 1
                if record is None:
                    self.records[deal_id] = DealRuntimeRecord(
                        deal_id=deal_id,
                        stage=RuntimeStage.WAITING_ARTIFACT,
                        funded_block=event.block_number,
                        funded_tx_hash=_optional_tx_hash(event.tx_hash),
                        funded_log_index=event.log_index,
                        last_reason="funded_event_confirmed",
                    )
                continue
            if event.name == "EvaluationSubmitted":
                if record is None:
                    record = DealRuntimeRecord(deal_id=deal_id, stage=RuntimeStage.SUBMITTED)
                    self.records[deal_id] = record
                record.stage = RuntimeStage.SUBMITTED
                record.submission_tx_hash = _optional_tx_hash(event.tx_hash)
                record.result_hash = _optional_nonzero_bytes32(
                    str(event.fields.get("result_hash") or "")
                )
                record.last_reason = "evaluation_submission_confirmed"
                continue
            if event.name in {"DealAccepted", "DealRejected", "DealExpired"}:
                if record is None:
                    record = DealRuntimeRecord(deal_id=deal_id, stage=RuntimeStage.RESOLVED)
                    self.records[deal_id] = record
                record.stage = RuntimeStage.RESOLVED
                record.last_reason = "resolution_event_confirmed"
        return funded_observed

    def _process_deals(self) -> dict[str, int]:
        evaluated = 0
        submitted = 0
        candidates = [
            record
            for record in self.records.values()
            if record.stage in ACTIONABLE_STAGES
            or record.stage == RuntimeStage.SUBMISSION_UNCERTAIN
        ]
        candidates.sort(key=lambda record: int(record.deal_id))
        for record in candidates[: self.max_deals_per_cycle]:
            if record.stage == RuntimeStage.SUBMISSION_UNCERTAIN:
                self._reconcile_uncertain_submission(record)
                self.state_store.save(self.records)
                continue
            record.attempt_count += 1
            try:
                if not self.control_plane.execution_policy_current(record.deal_id):
                    raise ExecutionPolicyNotReady("execution_policy_not_ready")
                evaluation = self.control_plane.get_result(record.deal_id)
                if evaluation is None:
                    evaluation = self.control_plane.evaluate(record.deal_id)
                record.evaluation = evaluation
                record.stage = RuntimeStage.EVALUATED
                record.last_reason = "bounded_evaluation_available"
                self.state_store.save(self.records)
                evaluated += 1

                outcome = self.result_coordinator.submit(
                    evaluation,
                    before_broadcast=lambda attempt, target=record: (
                        self._checkpoint_submission_attempt(target, attempt)
                    ),
                )
                outcome_hash = _optional_tx_hash(outcome.tx_hash)
                outcome_result_hash = _optional_nonzero_bytes32(
                    outcome.result_hash
                )
                if (
                    not record.submission_attempt_tx_hash
                    or outcome_hash != record.submission_attempt_tx_hash
                    or outcome_result_hash
                    != record.submission_attempt_result_hash
                ):
                    raise SubmissionUncertain(
                        "submission_return_binding_invalid"
                    )
                record.stage = RuntimeStage.SUBMISSION_UNCERTAIN
                record.reconciliation_state = "broadcast_returned"
                record.last_reason = "broadcast_returned_awaiting_receipt"
                self._reconcile_uncertain_submission(record)
                if record.stage == RuntimeStage.SUBMITTED:
                    submitted += 1
            except ArtifactNotReady:
                record.stage = RuntimeStage.WAITING_ARTIFACT
                record.last_reason = "artifact_not_ready"
            except ExecutionPolicyNotReady:
                record.stage = RuntimeStage.AWAITING_EXECUTION_POLICY
                record.last_reason = "execution_policy_not_ready"
            except EvaluatorNotReady:
                record.stage = RuntimeStage.EVALUATOR_UNAVAILABLE
                record.last_reason = "evaluator_unavailable"
            except DealContextMissing:
                try:
                    context = self.result_coordinator.funded_context(record.deal_id)
                    self.control_plane.notify_funded(context)
                    record.stage = RuntimeStage.WAITING_ARTIFACT
                    record.last_reason = "funded_context_rehydrated"
                except DealAlreadySubmitted:
                    record.stage = RuntimeStage.SUBMITTED
                    record.last_reason = "chain_already_evaluated"
                except DealAlreadyResolved:
                    record.stage = RuntimeStage.RESOLVED
                    record.last_reason = "chain_already_resolved"
                except (ControlPlaneError, SubmissionRejected):
                    record.stage = RuntimeStage.RETRYABLE
                    record.last_reason = "funded_context_rehydration_failed"
            except ControlPlaneRetryable as exc:
                record.stage = RuntimeStage.RETRYABLE
                record.last_reason = exc.reason_code
            except EvaluationTerminalFailure:
                record.stage = RuntimeStage.EVALUATION_FAILED
                record.last_reason = "evaluation_failed_inside_boundary"
            except AttestationVerdictUnavailable:
                record.stage = RuntimeStage.AWAITING_QVL
                record.last_reason = "independent_qvl_unavailable"
            except DealAlreadySubmitted:
                record.stage = RuntimeStage.SUBMITTED
                record.last_reason = "chain_already_evaluated"
                submitted += 1
            except DealAlreadyResolved:
                record.stage = RuntimeStage.RESOLVED
                record.last_reason = "chain_already_resolved"
            except SubmissionUncertain:
                record.stage = RuntimeStage.SUBMISSION_UNCERTAIN
                record.last_reason = "submission_broadcast_uncertain"
            except SubmissionRetryable:
                record.stage = RuntimeStage.RETRYABLE
                record.last_reason = "submission_prebroadcast_unavailable"
            except (SubmissionRejected, ChainSubmitterError, ResultVerifierError):
                if record.submission_attempt_tx_hash:
                    record.stage = RuntimeStage.SUBMISSION_UNCERTAIN
                    record.last_reason = "post_prepare_submission_uncertain"
                else:
                    record.stage = RuntimeStage.SUBMISSION_REJECTED
                    record.last_reason = "submission_policy_rejected"
            self.state_store.save(self.records)
        return {"evaluated": evaluated, "submitted": submitted}

    def _checkpoint_submission_attempt(
        self,
        record: DealRuntimeRecord,
        attempt: PreparedSubmissionAttempt,
    ) -> None:
        """Durably record exact signed authority before any network send."""

        tx_hash = _optional_tx_hash(attempt.tx_hash)
        result_hash = _optional_nonzero_bytes32(attempt.result_hash)
        nonce = _nonnegative_int(attempt.nonce, "submission nonce")
        prepared_at = _nonnegative_int(
            attempt.prepared_at,
            "submission prepared_at",
        )
        if not tx_hash or not result_hash or prepared_at <= 0:
            raise RuntimeStateError("prepared submission attempt is invalid")
        if record.submission_attempt_tx_hash:
            if (
                record.submission_attempt_tx_hash == tx_hash
                and record.submission_nonce == nonce
                and record.submission_attempt_result_hash == result_hash
            ):
                return
            raise RuntimeStateError(
                "a different prepared submission attempt already exists"
            )
        record.submission_nonce = nonce
        record.submission_attempt_tx_hash = tx_hash
        record.submission_attempt_result_hash = result_hash
        record.submission_prepared_at = prepared_at
        record.stage = RuntimeStage.SUBMISSION_UNCERTAIN
        record.reconciliation_state = "prepared_before_broadcast"
        record.last_reason = "signed_transaction_prepared"
        self.state_store.save(self.records)

    def _reconcile_uncertain_submission(self, record: DealRuntimeRecord) -> None:
        if (
            record.submission_attempt_tx_hash
            and record.submission_nonce is not None
        ):
            try:
                outcome = self.result_coordinator.reconcile_submission(
                    deal_id=record.deal_id,
                    tx_hash=record.submission_attempt_tx_hash,
                    nonce=record.submission_nonce,
                )
            except Exception:
                record.reconciliation_state = "rpc_unavailable"
                record.last_reason = "submission_reconciliation_unavailable"
                return
            record.reconciliation_state = outcome.status
            record.submission_receipt_block = outcome.receipt_block
            record.submission_receipt_block_hash = (
                _optional_nonzero_bytes32(outcome.receipt_block_hash)
                if outcome.receipt_block_hash
                else ""
            )
            record.submission_receipt_status = outcome.receipt_status
            if outcome.status in {"confirmed_success", "confirmed_revert"}:
                if (
                    outcome.receipt_block is None
                    or not outcome.receipt_block_hash
                    or outcome.receipt_block
                    > max(
                        0,
                        self.source.latest_block() - self.confirmations,
                    )
                    or self.source.block_hash(outcome.receipt_block)
                    != outcome.receipt_block_hash
                ):
                    record.reconciliation_state = (
                        "receipt_awaiting_confirmations"
                    )
                    record.last_reason = (
                        "exact_submission_receipt_awaiting_confirmations"
                    )
                    return
            if outcome.status == "confirmed_success":
                record.stage = RuntimeStage.SUBMITTED
                record.submission_tx_hash = (
                    record.submission_attempt_tx_hash
                )
                record.result_hash = record.submission_attempt_result_hash
                record.last_reason = "exact_submission_receipt_confirmed"
            elif outcome.status == "confirmed_revert":
                record.stage = RuntimeStage.SUBMISSION_REJECTED
                record.last_reason = "exact_submission_receipt_reverted"
            elif outcome.status == "pending_exact_transaction":
                record.last_reason = "exact_submission_pending"
            elif outcome.status == "nonce_consumed_without_exact_hash":
                record.last_reason = "submission_nonce_consumed_manual_hold"
            elif outcome.status == "pending_nonce_without_exact_hash":
                record.last_reason = "submission_nonce_pending_manual_hold"
            elif outcome.status == "rpc_views_inconsistent":
                record.last_reason = "submission_rpc_views_inconsistent"
            else:
                record.last_reason = "exact_submission_not_found_manual_hold"
            return

        try:
            disposition = self.result_coordinator.inspect(record.deal_id)
        except Exception:
            record.last_reason = "submission_reconciliation_unavailable"
            return
        if disposition == "submitted":
            record.stage = RuntimeStage.SUBMITTED
            record.last_reason = "chain_evaluation_observed"
        elif disposition == "resolved":
            record.stage = RuntimeStage.RESOLVED
            record.last_reason = "chain_resolution_observed"
        else:
            # Never resend an ambiguous transaction automatically.  An operator
            # can inspect the nonce/receipt and explicitly reset the journal.
            record.last_reason = "submission_requires_operator_reconciliation"

    def _stage_counts(self) -> dict[RuntimeStage, int]:
        counts = {stage: 0 for stage in RuntimeStage}
        for record in self.records.values():
            counts[record.stage] += 1
        return counts


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tinker-deal-runtime",
        description=(
            "Watch confirmed DiligenceRoom events, call the internal bounded "
            "evaluator, obtain independent QVL authorization, and submit results"
        ),
    )
    parser.add_argument("--rpc-url", default="")
    parser.add_argument("--contract-address", default="")
    parser.add_argument("--api-url", default="")
    parser.add_argument("--from-block", default="")
    parser.add_argument("--confirmations", type=int, default=None)
    parser.add_argument("--poll-interval", type=float, default=None)
    parser.add_argument("--cursor-store", default="")
    parser.add_argument("--state-store", default="./data/deal_runtime_state.json")
    parser.add_argument("--max-deals-per-cycle", type=int, default=25)
    parser.add_argument("--expected-chain-id", type=int, default=BASE_SEPOLIA_CHAIN_ID)
    parser.add_argument("--qvl-url", default="")
    parser.add_argument("--allow-compose-hash", action="append", default=[])
    parser.add_argument("--allow-app-id", action="append", default=[])
    parser.add_argument("--allow-os-image-hash", action="append", default=[])
    parser.add_argument(
        "--trusted-attestation-verifier-address",
        action="append",
        default=[],
    )
    parser.add_argument("--attestation-release-policy-hash", default="")
    parser.add_argument("--revoke-quote-hash", action="append", default=[])
    parser.add_argument("--revoke-signer-address", action="append", default=[])
    parser.add_argument("--authorization-ttl-seconds", type=int, default=None)
    parser.add_argument(
        "--allow-unverified-local-attestation",
        action="store_true",
        help="Simulator/local-chain structural testing only; rejected on Base Sepolia",
    )
    parser.add_argument("--once", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        settings = Settings()
    except Exception:
        print(
            json.dumps(
                {
                    "schema": RUNTIME_SCHEMA,
                    "started": False,
                    "reason": "runtime_settings_invalid",
                    "raw_secret_egress": False,
                },
                sort_keys=True,
            ),
            flush=True,
        )
        return 1
    rpc_url = args.rpc_url or settings.chain_rpc_url
    contract_address = args.contract_address or settings.chain_contract_address
    api_url = args.api_url or settings.chain_control_plane_url
    cursor_path = args.cursor_store or settings.chain_cursor_store_path
    confirmations = (
        args.confirmations if args.confirmations is not None else settings.chain_confirmations
    )
    poll_interval = (
        args.poll_interval if args.poll_interval is not None else settings.chain_poll_interval
    )
    if poll_interval <= 0:
        raise SystemExit("poll interval must be positive")

    source = None
    dispatcher = None
    control_plane = None
    coordinator = None
    qvl_client = None
    runtime = None
    try:
        auth_token = resolve_runtime_auth_token(settings)
        if not auth_token:
            raise DealRuntimeError("configured or dstack-derived runtime auth is required")
        source = JsonRpcLogSource(rpc_url, contract_address)
        cursor_store = ChainCursorStore(cursor_path)
        dispatcher = ChainEventDispatcher(
            api_url,
            auth_token=auth_token,
            created_context=cursor_store.load().created_deals,
        )
        control_plane = InternalDealApi(api_url, auth_token=auth_token)

        policy = ResultVerifierPolicy(
            allowed_compose_hashes=tuple(args.allow_compose_hash),
            allowed_app_ids=tuple(args.allow_app_id),
            allowed_os_image_hashes=tuple(args.allow_os_image_hash),
            revoked_quote_hashes=tuple(args.revoke_quote_hash),
            revoked_signer_addresses=tuple(args.revoke_signer_address),
            authorization_ttl_seconds=(
                args.authorization_ttl_seconds
                if args.authorization_ttl_seconds is not None
                else settings.chain_result_authorization_ttl_seconds
            ),
            trusted_attestation_verifier_addresses=tuple(
                args.trusted_attestation_verifier_address
            ),
            attestation_release_policy_hash=(
                args.attestation_release_policy_hash
                or settings.chain_attestation_release_policy_hash
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
            allow_unverified_local_attestation=args.allow_unverified_local_attestation,
        )
        if args.qvl_url:
            # Fixed name prevents selecting an unrelated secret environment
            # variable for delivery to the configured QVL service.
            qvl_token = os.environ.get("TINKER_QVL_AUTH_TOKEN", "")
            qvl_client = HttpsIndependentQvlClient(
                args.qvl_url,
                auth_token=qvl_token,
                allow_plain_http_for_local_test=(
                    args.allow_unverified_local_attestation
                    and args.expected_chain_id in LOCAL_CHAIN_IDS
                ),
                trusted_verifier_addresses=tuple(
                    args.trusted_attestation_verifier_address
                ),
                expected_policy_hash=(
                    args.attestation_release_policy_hash
                    or settings.chain_attestation_release_policy_hash
                ),
                chain_id=args.expected_chain_id,
                cvm_id=settings.main_runtime_cvm_id,
                deployment_intent_sha256=settings.release_deployment_intent_sha256,
                release_authority_sha256=settings.release_authority_sha256,
                ceremony_nonce=settings.release_ceremony_nonce,
                measurement_policy_sha256=(
                    settings.diligence_qvl_measurement_policy_sha256
                ),
            )
        coordinator = ProductionResultCoordinator.from_settings(
            settings,
            rpc_url=rpc_url,
            contract_address=contract_address,
            policy=policy,
            verdict_provider=qvl_client,
            attestation_release_policy_hash=(
                args.attestation_release_policy_hash
                or settings.chain_attestation_release_policy_hash
            ),
            allow_unverified_local_attestation=args.allow_unverified_local_attestation,
        )
        if coordinator.chain_id != args.expected_chain_id:
            raise DealRuntimeError("connected chain ID does not match expected chain ID")
        if coordinator.chain_id not in LOCAL_CHAIN_IDS and confirmations < 2:
            raise DealRuntimeError("production settlement requires at least two confirmations")

        runtime = DealRuntimeService(
            source=source,
            dispatcher=dispatcher,
            cursor_store=cursor_store,
            state_store=DealRuntimeStateStore(args.state_store),
            control_plane=control_plane,
            result_coordinator=coordinator,
            start_block=parse_start_block(args.from_block or settings.chain_start_block),
            confirmations=confirmations,
            max_deals_per_cycle=args.max_deals_per_cycle,
        )
        # Hold the kernel lease for the entire process lifetime.  Per-cycle
        # acquisition remains available for embedded/test callers.
        runtime.lease.acquire()
        while True:
            print(json.dumps(runtime.run_once().to_public_dict(), sort_keys=True), flush=True)
            if args.once:
                return 0
            time.sleep(poll_interval)
    except KeyboardInterrupt:
        return 0
    except (
        AttestationVerdictUnavailable,
        ChainSubmitterError,
        ChainWatcherError,
        DealRuntimeError,
        ResultVerifierError,
        RuntimeAuthUnavailable,
        SignerUnavailable,
        VerifierSignerUnavailable,
        ValueError,
    ) as exc:
        print(
            json.dumps(
                {
                    "schema": RUNTIME_SCHEMA,
                    "started": False,
                    "reason": _bounded_startup_reason(exc),
                    "raw_secret_egress": False,
                },
                sort_keys=True,
            ),
            flush=True,
        )
        return 1
    except Exception:
        # Network libraries and remote JSON-RPC servers may include URLs or
        # arbitrary response strings in exceptions. Never serialize them.
        print(
            json.dumps(
                {
                    "schema": RUNTIME_SCHEMA,
                    "started": False,
                    "reason": "runtime_initialization_or_cycle_failed",
                    "raw_secret_egress": False,
                },
                sort_keys=True,
            ),
            flush=True,
        )
        return 1
    finally:
        if runtime is not None:
            runtime.lease.release()
        if coordinator is not None:
            coordinator.close()
        if qvl_client is not None:
            qvl_client.close()
        if control_plane is not None:
            control_plane.close()
        if dispatcher is not None:
            dispatcher.close()
        if source is not None:
            source.close()


def _strict_json_object(response: httpx.Response, *, surface: str) -> dict[str, Any]:
    if len(response.content) > 65_536:
        raise ControlPlaneError(f"{surface}_response_too_large")
    try:
        payload = response.json()
    except (json.JSONDecodeError, ValueError) as exc:
        raise ControlPlaneError(f"{surface}_response_invalid") from exc
    if not isinstance(payload, dict):
        raise ControlPlaneError(f"{surface}_response_invalid")
    return payload


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("duplicate JSON object key")
        output[key] = value
    return output


def _reject_json_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def _validate_http_endpoint(value: str, *, allow_plain_http: bool) -> None:
    parsed = urlparse(value)
    allowed_schemes = {"https"} | ({"http"} if allow_plain_http else set())
    if (
        parsed.scheme not in allowed_schemes
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise DealRuntimeError("service endpoint is invalid")
    if parsed.scheme == "http" and not _is_internal_http_host(parsed.hostname):
        raise DealRuntimeError("plaintext HTTP is restricted to internal services")


def _normalize_deal_id(value: Any) -> str:
    if not isinstance(value, (str, int)) or isinstance(value, bool):
        raise RuntimeStateError("deal ID is invalid")
    text = str(value)
    if not text.isascii() or not text.isdecimal() or len(text) > 78:
        raise RuntimeStateError("deal ID is invalid")
    parsed = int(text)
    if str(parsed) != text or parsed >= 2**256:
        raise RuntimeStateError("deal ID is invalid")
    return text


def _deal_id_int(value: str) -> int:
    return int(_normalize_deal_id(value))


def _nonnegative_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise RuntimeStateError(f"{field} is invalid")
    return value


def _optional_nonnegative_int(value: Any, field: str) -> int | None:
    if value is None:
        return None
    return _nonnegative_int(value, field)


def _optional_tx_hash(value: Any) -> str:
    if value in (None, ""):
        return ""
    if not isinstance(value, str) or not TX_HASH_RE.fullmatch(value):
        raise RuntimeStateError("transaction hash is invalid")
    return value.lower()


def _optional_nonzero_bytes32(value: Any) -> str:
    if value in (None, ""):
        return ""
    if not isinstance(value, str):
        raise RuntimeStateError("result hash is invalid")
    try:
        return normalize_bytes32(value)
    except ChainSubmitterError as exc:
        raise RuntimeStateError("result hash is invalid") from exc


def _required_nonzero_bytes32(value: Any, field: str) -> str:
    normalized = _optional_nonzero_bytes32(value)
    if not normalized:
        raise RuntimeStateError(f"{field} is required")
    return normalized


def _rpc_quantity(value: Any, field: str) -> int:
    if (
        not isinstance(value, str)
        or not value.startswith("0x")
        or len(value) > 66
    ):
        raise SubmissionRejected(f"{field.replace(' ', '_')}_invalid")
    try:
        parsed = int(value, 16)
    except ValueError as exc:
        raise SubmissionRejected(
            f"{field.replace(' ', '_')}_invalid"
        ) from exc
    if parsed < 0:
        raise SubmissionRejected(f"{field.replace(' ', '_')}_invalid")
    return parsed


def _decode_nonempty_hex(value: str, *, field: str) -> bytes:
    raw = value[2:] if value.startswith(("0x", "0X")) else value
    try:
        decoded = bytes.fromhex(raw)
    except ValueError as exc:
        raise DealRuntimeError(f"{field} is not valid hex") from exc
    if not decoded:
        raise DealRuntimeError(f"{field} is missing")
    if len(decoded) > 65_536:
        raise DealRuntimeError(f"{field} exceeds the size bound")
    return decoded


def _is_internal_http_host(host: str) -> bool:
    normalized = host.rstrip(".").lower()
    if normalized == "localhost" or "." not in normalized:
        return True
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        return normalized.endswith(".internal")
    return bool(address.is_loopback or address.is_private or address.is_link_local)


def _bounded_startup_reason(exc: Exception) -> str:
    if isinstance(exc, RuntimeAuthUnavailable):
        return "runtime_auth_unavailable"
    if isinstance(exc, (SignerUnavailable, VerifierSignerUnavailable)):
        return "dstack_signer_unavailable"
    if isinstance(exc, ChainWatcherError):
        return "chain_watcher_configuration_invalid"
    if isinstance(exc, ChainSubmitterError):
        return "chain_submission_configuration_invalid"
    if isinstance(exc, ResultVerifierError):
        return "result_verifier_configuration_invalid"
    if isinstance(exc, AttestationVerdictUnavailable):
        return "independent_qvl_unavailable"
    if isinstance(exc, RuntimeStateError):
        return "deal_runtime_state_invalid"
    if isinstance(exc, DealRuntimeError):
        reason = str(exc)
        if re.fullmatch(r"[A-Za-z0-9 _-]{1,120}", reason):
            return reason.lower().replace(" ", "_")
        return "deal_runtime_configuration_invalid"
    return "deal_runtime_configuration_invalid"


def _normalize_quote_report_data(value: str, *, expected_report_data: str) -> str:
    raw = _decode_nonempty_hex(value, field="quote report data")
    expected = bytes.fromhex(normalize_bytes32(expected_report_data)[2:])
    if raw == expected:
        return "0x" + expected.hex()
    if len(raw) == 64 and raw[:32] == expected and raw[32:] == (b"\x00" * 32):
        return "0x" + expected.hex()
    raise DealRuntimeError("quote report data does not match signer context")


if __name__ == "__main__":
    raise SystemExit(main())
