"""Authenticate, verify, sign, and durably commit one metering decision."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from .chain import BaseSepoliaStateVerifier
from .errors import SignerUnavailable
from .identity_attestation import (
    HttpsComputeMeteringQvlClient,
    MeteringIdentityAttestor,
    compute_metering_attestation_evidence_hash,
)
from .models import (
    ComputeMeteringAuthorizationRequest,
    MeteringDecision,
    MeteringRequest,
)
from .policy import LoadedPolicySet, canonical_json_bytes
from .replay import DurableReplayStore
from .signing import MeteringSigner, validate_canonical_signature
from .usage import semantic_request_hash, verify_usage_envelope


@dataclass(frozen=True)
class ComputeMeter:
    release: LoadedPolicySet
    signer: MeteringSigner
    chain: BaseSepoliaStateVerifier
    replay: DurableReplayStore
    identity_attestor: MeteringIdentityAttestor
    qvl_client: HttpsComputeMeteringQvlClient

    async def meter(self, request: MeteringRequest) -> bytes:
        usage = request.usage
        verify_usage_envelope(usage, expected_tee_identity=self.release.policy.tee_identity)
        request_hash = semantic_request_hash(request)
        prior = await asyncio.to_thread(
            self.replay.lookup,
            job_id=usage.job_id,
            usage_commitment=usage.usage_commitment,
            request_hash=request_hash,
        )
        if prior is not None:
            return prior

        challenge = await asyncio.to_thread(self.qvl_client.issue_challenge)
        policy = self.release.policy
        attestation = await asyncio.to_thread(
            self.identity_attestor.attest,
            metering_verifier=self.signer.address,
            chain_id=policy.chain_id,
            vault_address=policy.vault_address,
            policy_set_hash=self.release.policy_set_hash,
            signer_custody=self.signer.custody,
            challenge=challenge,
        )
        evidence_hash = compute_metering_attestation_evidence_hash(attestation)
        context = await self.chain.verify(
            block=request.block,
            usage=usage,
            attestation_evidence_hash=evidence_hash,
            receipt_expiry_cap=challenge.expires_at,
        )
        authorization = ComputeMeteringAuthorizationRequest(
            schema="dnai.compute-metering-qvl-authorization-request.v1",
            project_id=context.project_id,
            job_id=context.job_id,
            user=context.user,
            asset=context.asset,
            authorization_nonce=str(context.authorization_nonce),
            max_asset_debit=str(context.max_asset_debit),
            actual_asset_debit=str(context.actual_asset_debit),
            authorization_expiry=context.authorization_expiry,
            rate_policy_commitment=context.rate_policy_commitment,
            workload_commitment=context.workload_commitment,
            manifest_commitment=context.manifest_commitment,
            dispatch_intent_commitment=context.dispatch_intent_commitment,
            tee_identity=context.tee_identity,
            compose_hash=context.compose_hash,
            start_commitment=context.start_commitment,
            billable_compute_units=str(context.billable_compute_units),
            usage_started_at=context.usage_started_at,
            usage_ended_at=context.usage_ended_at,
            usage_commitment=context.onchain_usage_commitment,
            metering_policy_set_hash=self.release.policy_set_hash,
            attestation_evidence_hash=context.attestation_evidence_hash,
            receipt_expiry=context.receipt_expiry,
        )
        qvl_verdict = await asyncio.to_thread(
            self.qvl_client.verify,
            attestation,
            authorization,
        )
        if (
            qvl_verdict.qvl_compute_authorization_digest
            != context.metering_qvl_receipt_digest
            or qvl_verdict.qvl_compute_authorization_signature is None
            or qvl_verdict.qvl_compute_attestation_evidence_hash
            != context.attestation_evidence_hash
        ):
            raise SignerUnavailable
        signature = self.signer.sign_digest(context.metering_receipt_digest)
        validate_canonical_signature(signature)
        decision = MeteringDecision(
            schema="dnai.compute-metering-decision.v2",
            classification="attested_dual_verified_metering",
            provider_authoritative_invoice=False,
            chain_id=policy.chain_id,
            vault_address=policy.vault_address,
            pinned_block_number=request.block.number,
            pinned_block_hash=request.block.hash,
            policy_set_hash=self.release.policy_set_hash,
            rate_policy_commitment=context.rate_policy_commitment,
            workload_commitment=context.workload_commitment,
            manifest_commitment=context.manifest_commitment,
            dispatch_intent_commitment=context.dispatch_intent_commitment,
            asset=context.asset,
            job_id=usage.job_id,
            usage_commitment=usage.usage_commitment,
            onchain_usage_commitment=context.onchain_usage_commitment,
            actual_asset_debit=str(context.actual_asset_debit),
            billable_compute_units=str(context.billable_compute_units),
            usage_started_at=context.usage_started_at,
            usage_ended_at=context.usage_ended_at,
            attestation_evidence_hash=context.attestation_evidence_hash,
            receipt_expiry=context.receipt_expiry,
            metering_receipt_digest=context.metering_receipt_digest,
            metering_qvl_receipt_digest=context.metering_qvl_receipt_digest,
            metering_verifier=self.signer.address,
            metering_qvl_verifier=policy.metering_qvl_verifier,
            tee_identity=policy.tee_identity,
            compose_hash=policy.compose_hash,
            raw_secret_egress=False,
            verifier_signature=signature,
            qvl_signature=qvl_verdict.qvl_compute_authorization_signature,
        )
        encoded = canonical_json_bytes(decision.model_dump(mode="json", by_alias=True))
        return await asyncio.to_thread(
            self.replay.record,
            job_id=usage.job_id,
            usage_commitment=usage.usage_commitment,
            request_hash=request_hash,
            decision_json=encoded,
        )
