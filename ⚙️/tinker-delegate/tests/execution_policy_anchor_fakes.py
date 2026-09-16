"""Explicit in-memory chain witness used only by backend unit tests."""

from __future__ import annotations

from dataclasses import replace

from tinker_delegate.execution_policy_anchor import (
    AnchorProjectionRecord,
    ExecutionPolicyAnchorMismatch,
    ExecutionPolicyAnchorSnapshot,
    ExecutionPolicyReleaseMarker,
    ZERO_ADDRESS,
    ZERO_BYTES32,
    compute_anchor_projection,
)


ANCHOR_ADDRESS = "0x" + "a1" * 20
WRITER_ADDRESS = "0x" + "b2" * 20
OWNER_ADDRESS = "0x" + "c3" * 20
RUNTIME_CODE_HASH = "0x" + "d4" * 32
WRITER_RELEASE = "0x" + "e5" * 32


class MemoryExecutionPolicyAnchorGateway:
    """Contract-state emulator; never selected by runtime configuration."""

    def __init__(
        self,
        *,
        read_only: bool = False,
        release_marker: ExecutionPolicyReleaseMarker | None = None,
    ) -> None:
        self.read_only = read_only
        # This class is test-only.  Absence of a marker explicitly opts tests
        # into the historical zero-genesis model; production gateways never
        # expose this escape hatch.
        self.allow_zero_genesis_for_test = release_marker is None
        self.release_marker = release_marker
        self.contract_address = ANCHOR_ADDRESS
        self.writer_address = WRITER_ADDRESS
        self.writer_release_commitment = WRITER_RELEASE
        self.runtime_code_hash = RUNTIME_CODE_HASH
        self.records: list[AnchorProjectionRecord] = []
        self.fail_next_anchor = False
        self.closed = False
        self.snapshot_overrides: dict[str, object] = {}

    def close(self) -> None:
        self.closed = True

    def finalized_snapshot(
        self,
        *,
        resource_id_hash: str = "",
        decision_hash: str = "",
        now: int | None = None,
    ) -> ExecutionPolicyAnchorSnapshot:
        projection = compute_anchor_projection(
            self.records,
            contract_address=self.contract_address,
            writer_address=self.writer_address,
            writer_release_commitment=self.writer_release_commitment,
            release_marker=self.release_marker,
        )
        resource = projection.resource_heads.get(
            resource_id_hash, (ZERO_BYTES32, 0)
        )
        decision_sequence = next(
            (
                (
                    record.chain_sequence
                    or (
                        (self.release_marker.sequence if self.release_marker else 0)
                        + record.sequence
                    )
                )
                for record in self.records
                if record.decision_hash == decision_hash
            ),
            0,
        )
        snapshot = ExecutionPolicyAnchorSnapshot(
            chain_id=84_532,
            block_number=100 + projection.sequence,
            block_hash="0x" + f"{100 + projection.sequence:064x}",
            block_timestamp=1_700_000_000,
            contract_address=self.contract_address,
            runtime_code_hash=self.runtime_code_hash,
            owner=OWNER_ADDRESS,
            pending_owner=ZERO_ADDRESS,
            writer=self.writer_address,
            writer_release_commitment=self.writer_release_commitment,
            pending_writer=ZERO_ADDRESS,
            pending_writer_release_commitment=ZERO_BYTES32,
            pending_writer_activates_at=0,
            writer_rotations_frozen=True,
            paused=False,
            global_sequence=projection.sequence,
            global_head=projection.global_head,
            resource_id_hash=resource_id_hash,
            resource_decision_head=resource[0] if resource_id_hash else "",
            resource_sequence=resource[1] if resource_id_hash else 0,
            decision_hash=decision_hash,
            decision_sequence=decision_sequence,
            latest_block_number=111 + projection.sequence,
            rpc_finalized_block_number=100 + projection.sequence,
            rpc_finalized_block_hash=(
                "0x" + f"{100 + projection.sequence:064x}"
            ),
            minimum_confirmation_depth=12,
            observed_confirmation_depth=12,
        )
        return replace(snapshot, **self.snapshot_overrides)

    latest_snapshot = finalized_snapshot

    def anchor_record(
        self,
        *,
        prefix,
        record: AnchorProjectionRecord,
        now: int | None = None,
    ) -> ExecutionPolicyAnchorSnapshot:
        if self.read_only:
            raise ExecutionPolicyAnchorMismatch("read-only fake cannot anchor")
        if self.fail_next_anchor:
            self.fail_next_anchor = False
            raise ExecutionPolicyAnchorMismatch("injected anchor crash")
        current = compute_anchor_projection(
            self.records,
            contract_address=self.contract_address,
            writer_address=self.writer_address,
            writer_release_commitment=self.writer_release_commitment,
            release_marker=self.release_marker,
        )
        target_sequence = prefix.sequence + 1
        if (
            current != prefix
            or record.sequence != len(self.records) + 1
            or record.chain_sequence not in (0, target_sequence)
        ):
            raise ExecutionPolicyAnchorMismatch("fake anchor CAS mismatch")
        self.records.append(record)
        return self.finalized_snapshot(
            resource_id_hash=record.resource_id_hash,
            decision_hash=record.decision_hash,
            now=now,
        )
