"""Exact sponsor-wallet handoff for a prefunded Royalty settlement.

The dual-authorized plan already commits the complete contract authorization.
This module adds the deterministic recipient arrays and calldata, then provides
one strict persistence shape.  It never broadcasts a transaction and it never
includes a private key, provider credential, raw TDX quote, or ``cast`` shell
command in the browser handoff.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from tinker_delegate.royalty_distribution_plan import (
    SETTLE_RESERVED_FUNCTION,
    DistributionRecipient,
    RoyaltyDistributionPlan,
)
from tinker_delegate.royalty_settlement_authorization import (
    AuthorizedRoyaltySettlementPlan,
    RoyaltySettlementAuthorizationError,
)


PERSISTENCE_SCHEMA = "dnai.royalty-settlement-wallet-plan-record.v1"
SPONSOR_WALLET_SCHEMA = "dnai.collaboration.royalty-settlement-wallet-plan.v1"
ZERO_BYTES32 = "0x" + "00" * 32
ANCHOR_FINALITY_FIELDS = frozenset(
    {
        "schema",
        "status",
        "verification_model",
        "chain_id",
        "block_number",
        "block_hash",
        "block_timestamp",
        "contract_address",
        "runtime_code_hash",
        "writer",
        "writer_release_commitment",
        "writer_rotations_frozen",
        "paused",
        "global_sequence",
        "global_head",
        "resource_id_hash",
        "resource_decision_head",
        "resource_sequence",
        "decision_hash",
        "decision_sequence",
        "latest_block_number",
        "rpc_finalized_block_number",
        "rpc_finalized_block_hash",
        "minimum_confirmation_depth",
        "observed_confirmation_depth",
        "independent_rpc_quorum_verified",
        "consensus_proof_verified",
        "opaque_commitments_only",
        "raw_resource_id_egress",
        "raw_policy_egress",
    }
)
ANCHOR_FINALITY_UINT_FIELDS = (
    "block_number",
    "block_timestamp",
    "global_sequence",
    "resource_sequence",
    "decision_sequence",
    "latest_block_number",
    "rpc_finalized_block_number",
    "minimum_confirmation_depth",
    "observed_confirmation_depth",
)


class RoyaltySettlementWalletPlanError(ValueError):
    """The wallet plan is malformed or no longer the finalized resource head."""


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except Exception:
        raise RoyaltySettlementWalletPlanError(
            "royalty wallet plan is not canonical JSON"
        ) from None


@dataclass(frozen=True)
class RoyaltySettlementWalletPlan:
    """One immutable, calldata-ready plan for the sponsor wallet."""

    authorized_plan: AuthorizedRoyaltySettlementPlan
    recipients: tuple[DistributionRecipient, ...]
    refund_after: int
    _transaction: RoyaltyDistributionPlan = field(init=False, repr=False)

    @classmethod
    def create(
        cls,
        *,
        authorized_plan: AuthorizedRoyaltySettlementPlan,
        recipients: Sequence[DistributionRecipient],
        refund_after: int,
    ) -> "RoyaltySettlementWalletPlan":
        return cls(
            authorized_plan=authorized_plan,
            recipients=tuple(recipients),
            refund_after=refund_after,
        )

    def __post_init__(self) -> None:
        if not isinstance(self.authorized_plan, AuthorizedRoyaltySettlementPlan):
            raise RoyaltySettlementWalletPlanError(
                "authorized royalty settlement plan is required"
            )
        if (
            isinstance(self.refund_after, bool)
            or not isinstance(self.refund_after, int)
            or self.refund_after < self.authorized_plan.authorization.expiry
            or self.refund_after > 4_102_444_800
        ):
            raise RoyaltySettlementWalletPlanError(
                "royalty reservation refund time does not cover authorization"
            )
        try:
            transaction = self.authorized_plan.build_settle_reserved_broadcast_plan(
                recipients=self.recipients,
            )
        except Exception:
            raise RoyaltySettlementWalletPlanError(
                "royalty settlement calldata could not be derived"
            ) from None
        if (
            not transaction.prefunded
            or transaction.function != SETTLE_RESERVED_FUNCTION
            or transaction.funding_reservation_id == ZERO_BYTES32
            or transaction.contract_address.lower()
            != self.authorized_plan.distributor_address
            or transaction.total_amount != self.authorized_plan.authorization.total
        ):
            raise RoyaltySettlementWalletPlanError(
                "royalty settlement is not the exact prefunded transaction"
            )
        normalized = tuple(
            DistributionRecipient(owner_address=owner, amount=amount)
            for owner, amount in sorted(
                (
                    (recipient.owner_address.lower(), recipient.amount)
                    for recipient in self.recipients
                ),
                key=lambda item: int(item[0][2:], 16),
            )
        )
        object.__setattr__(self, "recipients", normalized)
        object.__setattr__(self, "_transaction", transaction)

    @property
    def plan_commitment(self) -> str:
        return self.authorized_plan.plan_commitment

    @property
    def anchor_resource_hash(self) -> str:
        return self.authorized_plan.authorization.anchor_resource_hash

    @property
    def anchor_decision_hash(self) -> str:
        return self.authorized_plan.authorization.anchor_decision_hash

    @property
    def anchor_sequence(self) -> int:
        return self.authorized_plan.authorization.anchor_sequence

    @property
    def transaction(self) -> RoyaltyDistributionPlan:
        return self._transaction

    def to_persistence_dict(self) -> dict[str, Any]:
        return {
            "schema": PERSISTENCE_SCHEMA,
            "authorized_plan": self.authorized_plan.to_public_dict(),
            "recipients": [
                {
                    "owner_address": recipient.owner_address,
                    "amount": recipient.amount,
                }
                for recipient in self.recipients
            ],
            "refund_after": self.refund_after,
            "transaction": {
                "chain_id": self.authorized_plan.chain_id,
                "to": self._transaction.contract_address.lower(),
                "data": self._transaction.calldata.lower(),
                "value": "0x0",
                "function": self._transaction.function,
            },
        }

    @classmethod
    def from_persistence_dict(
        cls,
        payload: Mapping[str, Any],
    ) -> "RoyaltySettlementWalletPlan":
        if not isinstance(payload, Mapping):
            raise RoyaltySettlementWalletPlanError(
                "royalty wallet plan record must be an object"
            )
        value = dict(payload)
        try:
            if value.get("schema") != PERSISTENCE_SCHEMA:
                raise ValueError
            recipients_value = value["recipients"]
            if not isinstance(recipients_value, list):
                raise ValueError
            recipients = []
            for recipient in recipients_value:
                if not isinstance(recipient, Mapping) or set(recipient) != {
                    "owner_address",
                    "amount",
                }:
                    raise ValueError
                recipients.append(
                    DistributionRecipient(
                        owner_address=recipient["owner_address"],
                        amount=recipient["amount"],
                    )
                )
            restored = cls.create(
                authorized_plan=AuthorizedRoyaltySettlementPlan.from_public_dict(
                    value["authorized_plan"]
                ),
                recipients=recipients,
                refund_after=value["refund_after"],
            )
        except (KeyError, TypeError, ValueError, RoyaltySettlementAuthorizationError):
            raise RoyaltySettlementWalletPlanError(
                "royalty wallet plan record is invalid"
            ) from None
        if _canonical_json(value) != _canonical_json(restored.to_persistence_dict()):
            raise RoyaltySettlementWalletPlanError(
                "royalty wallet plan record drifted"
            )
        return restored

    def to_sponsor_dict(
        self,
        *,
        finalized_anchor: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Return the exact wallet request only for the finalized current head."""

        if not isinstance(finalized_anchor, Mapping):
            raise RoyaltySettlementWalletPlanError(
                "finalized anchor evidence is required"
            )
        anchor_finality = dict(finalized_anchor)
        if set(anchor_finality) != ANCHOR_FINALITY_FIELDS:
            raise RoyaltySettlementWalletPlanError(
                "finalized anchor evidence schema is invalid"
            )
        for field_name in ANCHOR_FINALITY_UINT_FIELDS:
            field_value = anchor_finality[field_name]
            if (
                isinstance(field_value, bool)
                or not isinstance(field_value, int)
                or field_value < 0
                or field_value >= 2**256
            ):
                raise RoyaltySettlementWalletPlanError(
                    "finalized anchor evidence uint is invalid"
                )
        authorization = self.authorized_plan.authorization
        if (
            anchor_finality.get("schema")
            != "dnai-wikigen/execution-policy-anchor-status/v1"
            or anchor_finality.get("status")
            != "rpc_reported_finalized_release_match"
            or anchor_finality.get("chain_id") != self.authorized_plan.chain_id
            or anchor_finality.get("writer_rotations_frozen") is not True
            or anchor_finality.get("paused") is not False
            or anchor_finality.get("independent_rpc_quorum_verified") is not False
            or anchor_finality.get("consensus_proof_verified") is not False
            or anchor_finality.get("opaque_commitments_only") is not True
            or anchor_finality.get("raw_resource_id_egress") is not False
            or anchor_finality.get("raw_policy_egress") is not False
            or anchor_finality.get("resource_id_hash")
            != authorization.anchor_resource_hash[2:]
            or anchor_finality.get("resource_decision_head")
            != authorization.anchor_decision_hash
            or anchor_finality.get("resource_sequence")
            != authorization.anchor_sequence
            or anchor_finality.get("decision_hash")
            != authorization.anchor_decision_hash[2:]
            or anchor_finality.get("decision_sequence")
            != authorization.anchor_sequence
            or anchor_finality.get("global_sequence", 0)
            < authorization.anchor_sequence
        ):
            raise RoyaltySettlementWalletPlanError(
                "royalty settlement plan is not the finalized resource head"
            )
        for field_name in ANCHOR_FINALITY_UINT_FIELDS:
            anchor_finality[field_name] = str(anchor_finality[field_name])
        authorization_dict = {
            "settlement_id": authorization.settlement_id,
            "settlement_nonce": str(authorization.settlement_nonce),
            "funding_reservation_id": authorization.funding_reservation_id,
            "release_policy_commitment": authorization.release_policy_commitment,
            "room_commitment": authorization.room_commitment,
            "room_state_commitment": authorization.room_state_commitment,
            "query_commitment": authorization.query_commitment,
            "grant_set_commitment": authorization.grant_set_commitment,
            "allocation_commitment": authorization.allocation_commitment,
            "owners_amounts_hash": authorization.owners_amounts_hash,
            "asset": authorization.asset_address,
            "total": str(authorization.total),
            "execution_commitment": authorization.execution_commitment,
            "result_commitment": authorization.result_commitment,
            "usage_commitment": authorization.usage_commitment,
            "attestation_evidence_hash": authorization.attestation_evidence_hash,
            "anchor_resource_hash": authorization.anchor_resource_hash,
            "anchor_decision_hash": authorization.anchor_decision_hash,
            "anchor_sequence": str(authorization.anchor_sequence),
            "expiry": str(authorization.expiry),
        }
        return {
            "schema": SPONSOR_WALLET_SCHEMA,
            "chain_id": self.authorized_plan.chain_id,
            "to": self._transaction.contract_address.lower(),
            "data": self._transaction.calldata.lower(),
            "value": "0x0",
            "function": "settleReserved",
            "plan_commitment": self.authorized_plan.plan_commitment,
            "authorization_expires_at": str(authorization.expiry),
            "refund_after": str(self.refund_after),
            "funding_reservation_id": authorization.funding_reservation_id,
            "settlement_id": authorization.settlement_id,
            "settlement_nonce": str(authorization.settlement_nonce),
            "authorization": authorization_dict,
            "owners": [recipient.owner_address for recipient in self.recipients],
            "amounts": [str(recipient.amount) for recipient in self.recipients],
            "settlement_verifier_address": (
                self.authorized_plan.settlement_verifier_address
            ),
            "settlement_authorization_digest": (
                self.authorized_plan.settlement_authorization_digest
            ),
            "settlement_authorization_signature": (
                self.authorized_plan.settlement_authorization_signature
            ),
            "qvl_verifier_address": self.authorized_plan.qvl_verifier_address,
            "qvl_policy_commitment": self.authorized_plan.qvl_policy_commitment,
            "qvl_authorization_digest": (
                self.authorized_plan.qvl_authorization_digest
            ),
            "qvl_authorization_signature": (
                self.authorized_plan.qvl_authorization_signature
            ),
            "qvl_anchor_evidence_commitment": (
                self.authorized_plan.qvl_anchor_evidence_commitment
            ),
            "qvl_verdict_verifier_address": (
                self.authorized_plan.qvl_verdict_verifier_address
            ),
            "qvl_verdict_digest": self.authorized_plan.qvl_verdict_digest,
            "qvl_release_policy_hash": (
                self.authorized_plan.qvl_release_policy_hash
            ),
            "quote_hash": self.authorized_plan.quote_hash,
            "report_data": self.authorized_plan.report_data,
            "compose_hash": self.authorized_plan.compose_hash,
            "app_id": self.authorized_plan.app_id,
            "os_image_hash": self.authorized_plan.os_image_hash,
            "anchor_finality": anchor_finality,
            "sponsor_must_broadcast": True,
            "prefunded": True,
            "raw_quote_egress": False,
            "raw_artifact_egress": False,
            "provider_credential_egress": False,
            "raw_secret_egress": False,
        }
