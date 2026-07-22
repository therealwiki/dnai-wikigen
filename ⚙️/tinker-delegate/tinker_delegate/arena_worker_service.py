"""Internal single-owner run loop for the capability-free Arena worker.

This module has no HTTP surface and no permissive bootstrap path. Callers must
construct :class:`ArenaSafeIrWorker` from an authenticated independent QVL
verdict, real dstack key custody, a per-claim finalized ChallengeRegistry gate,
and a persisted execution-policy gate before entering
:func:`run_arena_worker_process`.

The lifetime ``flock`` is deliberately separate from the Arena store lock:

* the store lock serializes short API/worker state transactions; and
* the worker lease elects exactly one evaluator process for the entire run.

If a worker exits or crashes, the kernel releases its lease. A replacement
process reloads the queue and resumes the most advanced nonterminal safe-IR
record before accepting new work.
"""

from __future__ import annotations

import fcntl
import json
import os
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Protocol, TextIO

from tinker_delegate.arena_ingress import (
    ArenaCandidateIngressStore,
    ArenaIngressError,
    ArenaIngressRecipient,
)
from tinker_delegate.arena_safe_ir import SAFE_IR_POLICY_COMMITMENT, SAFE_IR_RUNTIME
from tinker_delegate.arena_safe_worker import (
    ArenaActivationProvider,
    ArenaExecutionPolicyRequest,
    ArenaRegistryClaimGate,
    ArenaSafeIrWorker,
    ArenaSafeWorkerError,
    ArenaSafeWorkerPolicyUnavailable,
    ArenaSafeWorkerRegistryUnavailable,
    ArenaSafeWorkerUnavailable,
    DnaseqVariantQcSafeIrEvaluator,
    RefreshingArenaActivationProvider,
)
from tinker_delegate.arena_store import ArenaStore, ArenaStoreError, QueueState


WORKER_STATUS_SCHEMA_VERSION = 1
EXIT_OK = 0
EXIT_OPERATOR_ERROR = 70
EXIT_ACTIVATION_UNAVAILABLE = 78
MAX_POLL_INTERVAL_SECONDS = 60.0


class ArenaWorkerServiceError(RuntimeError):
    """Fail-closed service error with no candidate-derived detail."""


class ArenaWorkerAlreadyRunning(ArenaWorkerServiceError):
    """Raised when another process owns the durable worker lease."""


class StopSignal(Protocol):
    def is_set(self) -> bool:
        """Return whether the supervisor requested a graceful stop."""


@dataclass(frozen=True)
class ArenaWorkerStatus:
    """Small allowlisted process status suitable for stderr or supervision."""

    state: str
    submission_id: str | None
    final_state: str | None
    recovery: bool
    failure_code: str

    def __post_init__(self) -> None:
        if self.state not in {
            "idle",
            "completed",
            "failed",
            "blocked",
            "operator_error",
            "stopped",
        }:
            raise ArenaWorkerServiceError("Arena worker status state is invalid")
        if self.submission_id is not None and (
            not isinstance(self.submission_id, str)
            or not self.submission_id.startswith("sub_")
            or len(self.submission_id) != 28
        ):
            raise ArenaWorkerServiceError("Arena worker status submission is invalid")
        if self.final_state not in {None, "completed", "failed"}:
            raise ArenaWorkerServiceError("Arena worker final status is invalid")
        if not isinstance(self.recovery, bool):
            raise ArenaWorkerServiceError("Arena worker recovery status is invalid")
        allowed_failure_codes = {
            "none",
            "execution_failed",
            "activation_unavailable",
            "execution_policy_unavailable",
            "challenge_registry_unavailable",
            "durable_state_unavailable",
            "worker_unavailable",
        }
        if self.failure_code not in allowed_failure_codes:
            raise ArenaWorkerServiceError("Arena worker failure code is invalid")

    def to_bounded_dict(self) -> dict[str, Any]:
        return {
            "surface": "arena_safe_worker_status",
            "schema_version": WORKER_STATUS_SCHEMA_VERSION,
            "state": self.state,
            "submission_id": self.submission_id,
            "final_state": self.final_state,
            "recovery": self.recovery,
            "failure_code": self.failure_code,
            "runtime": SAFE_IR_RUNTIME,
            "runtime_policy_commitment": SAFE_IR_POLICY_COMMITMENT,
            "raw_candidate_egress": False,
            "ciphertext_egress": False,
            "selected_controls_egress": False,
            "exact_score_egress": False,
            "exact_timing_egress": False,
            "exception_detail_egress": False,
        }


class ArenaWorkerProcessLease:
    """Kernel-released lifetime lease for exactly one Arena worker process."""

    def __init__(self, arena_store_path: str | Path) -> None:
        store_path = Path(arena_store_path)
        self.path = store_path.with_name(f".{store_path.name}.worker.lock")
        self._fd: int | None = None

    def __enter__(self) -> "ArenaWorkerProcessLease":
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd: int | None = None
        try:
            fd = os.open(self.path, flags, 0o600)
            os.fchmod(fd, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            if fd is not None:
                os.close(fd)
            raise ArenaWorkerAlreadyRunning(
                "another Arena worker process owns the durable lease"
            ) from exc
        except OSError as exc:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
            raise ArenaWorkerServiceError("Arena worker lease is unavailable") from exc
        self._fd = fd
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        del exc_type, exc, traceback
        fd = self._fd
        self._fd = None
        if fd is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)


class PersistedArenaExecutionPolicyGate:
    """Fresh-read adapter for the shared integrity-protected policy store.

    The API is the only writer. The worker constructs a fresh read-only store
    view for every authorization so a long-running separate process cannot use
    a stale pass after a newer hold or deny was atomically persisted.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        integrity_key: bytes,
        expected_approval_domain_hash: str,
        expected_approver_root_hash: str,
        approved_approver_hashes: frozenset[str] | set[str] | tuple[str, ...],
        execution_policy_anchor_gateway: Any,
    ) -> None:
        if not isinstance(path, (str, Path)) or not str(path).strip():
            raise ArenaWorkerServiceError(
                "Arena execution-policy store path is required"
            )
        self.path = Path(path)
        if not isinstance(integrity_key, bytes) or len(integrity_key) < 32:
            raise ArenaWorkerServiceError(
                "Arena execution-policy integrity key is invalid"
            )
        if (
            not isinstance(expected_approval_domain_hash, str)
            or len(expected_approval_domain_hash) != 64
            or any(
                character not in "0123456789abcdef"
                for character in expected_approval_domain_hash
            )
        ):
            raise ArenaWorkerServiceError(
                "Arena execution-policy approval domain is invalid"
            )
        if (
            not isinstance(approved_approver_hashes, (frozenset, set, tuple))
            or not approved_approver_hashes
            or len(approved_approver_hashes) > 64
            or any(
                not isinstance(value, str)
                or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
                for value in approved_approver_hashes
            )
        ):
            raise ArenaWorkerServiceError(
                "Arena execution-policy approver roots are invalid"
            )
        if (
            not isinstance(expected_approver_root_hash, str)
            or len(expected_approver_root_hash) != 64
            or any(
                character not in "0123456789abcdef"
                for character in expected_approver_root_hash
            )
        ):
            raise ArenaWorkerServiceError(
                "Arena execution-policy approver root commitment is invalid"
            )
        self._integrity_key = bytes(integrity_key)
        self._expected_approval_domain_hash = expected_approval_domain_hash
        self._expected_approver_root_hash = expected_approver_root_hash
        self._approved_approver_hashes = frozenset(approved_approver_hashes)
        if not bool(getattr(execution_policy_anchor_gateway, "read_only", False)):
            raise ArenaWorkerServiceError(
                "Arena worker requires a read-only execution-policy anchor verifier"
            )
        self._execution_policy_anchor_gateway = execution_policy_anchor_gateway

    def __repr__(self) -> str:
        return f"PersistedArenaExecutionPolicyGate(path={str(self.path)!r})"

    def close(self) -> None:
        close = getattr(self._execution_policy_anchor_gateway, "close", None)
        if callable(close):
            close()

    def authorize_arena_execution(
        self,
        request: ArenaExecutionPolicyRequest,
        *,
        occurred_at: int,
    ) -> bool:
        with self.authorized_arena_execution_lease(
            request,
            occurred_at=occurred_at,
        ) as authorized:
            return authorized

    @contextmanager
    def authorized_arena_execution_lease(
        self,
        request: ArenaExecutionPolicyRequest,
        *,
        occurred_at: int,
    ):
        """Keep the verified PASS stable through the worker's execution."""

        from tinker_delegate.execution_policy_anchor import (
            AnchoredExecutionPolicyCoordinator,
        )
        from tinker_delegate.execution_policy_store import ExecutionPolicyStore

        if not isinstance(request, ArenaExecutionPolicyRequest):
            raise ArenaWorkerServiceError("Arena execution-policy request is invalid")
        store = ExecutionPolicyStore(
            self.path,
            integrity_key=self._integrity_key,
        )
        coordinator = AnchoredExecutionPolicyCoordinator(
            store, self._execution_policy_anchor_gateway
        )
        with coordinator.authorized_execution_lease(
            surface="arena_execution",
            resource_id=request.submission_id,
            now=occurred_at,
            expected_approval_domain_hash=self._expected_approval_domain_hash,
            expected_approver_root_hash=self._expected_approver_root_hash,
            approved_approver_hashes=self._approved_approver_hashes,
        ):
            yield True


class ArenaSafeWorkerService:
    """Bounded polling facade around one authenticated safe-IR worker."""

    def __init__(
        self,
        *,
        arena_store: ArenaStore,
        worker: ArenaSafeIrWorker,
        poll_interval_seconds: float = 1.0,
    ) -> None:
        if not isinstance(arena_store, ArenaStore):
            raise ArenaWorkerServiceError("Arena durable store is required")
        if not isinstance(worker, ArenaSafeIrWorker):
            raise ArenaWorkerServiceError("Arena safe-IR worker is required")
        if (
            isinstance(poll_interval_seconds, bool)
            or not isinstance(poll_interval_seconds, (int, float))
            or not 0.05 <= float(poll_interval_seconds) <= MAX_POLL_INTERVAL_SECONDS
        ):
            raise ArenaWorkerServiceError("Arena worker poll interval is invalid")
        self.arena_store = arena_store
        self.worker = worker
        self.poll_interval_seconds = float(poll_interval_seconds)

    def run_once(self, *, occurred_at: int) -> ArenaWorkerStatus:
        """Select one item; refresh every external gate at its safe boundary."""

        record = self.arena_store.next_safe_ir_work_item()
        if record is None:
            return ArenaWorkerStatus(
                state="idle",
                submission_id=None,
                final_state=None,
                recovery=False,
                failure_code="none",
            )
        recovery = record.state != QueueState.SUBMITTED
        receipt = self.worker.process_submission(
            record.submission_id,
            occurred_at=occurred_at,
        )
        return ArenaWorkerStatus(
            state=receipt.final_state,
            submission_id=receipt.submission_id,
            final_state=receipt.final_state,
            recovery=recovery,
            failure_code=receipt.failure_code,
        )

    def close(self) -> None:
        self.worker.close()


def build_verified_arena_worker_service(
    *,
    arena_store_path: str | Path,
    ingress_store_path: str | Path,
    recipient: ArenaIngressRecipient,
    evaluator: DnaseqVariantQcSafeIrEvaluator,
    activation_provider: ArenaActivationProvider,
    registry_claim_gate: ArenaRegistryClaimGate,
    execution_policy_store_path: str | Path,
    execution_policy_integrity_key: bytes,
    execution_policy_approval_domain_hash: str,
    execution_policy_approver_root_hash: str,
    execution_policy_approved_approver_hashes: frozenset[str] | set[str] | tuple[str, ...],
    execution_policy_anchor_gateway: Any,
    poll_interval_seconds: float = 1.0,
) -> ArenaSafeWorkerService:
    """Build the service around concrete per-job QVL and registry refreshes."""

    arena_store = ArenaStore(arena_store_path)
    ingress_store = ArenaCandidateIngressStore(ingress_store_path)
    if not isinstance(activation_provider, RefreshingArenaActivationProvider):
        raise ArenaWorkerServiceError(
            "Arena production service requires the refreshing QVL provider"
        )
    if registry_claim_gate is None or not callable(
        getattr(registry_claim_gate, "authorize_arena_claim", None)
    ):
        raise ArenaWorkerServiceError(
            "Arena production service requires the finalized registry claim gate"
        )
    policy_gate = PersistedArenaExecutionPolicyGate(
        execution_policy_store_path,
        integrity_key=execution_policy_integrity_key,
        expected_approval_domain_hash=execution_policy_approval_domain_hash,
        expected_approver_root_hash=execution_policy_approver_root_hash,
        approved_approver_hashes=execution_policy_approved_approver_hashes,
        execution_policy_anchor_gateway=execution_policy_anchor_gateway,
    )
    worker = ArenaSafeIrWorker(
        arena_store=arena_store,
        ingress_store=ingress_store,
        recipient=recipient,
        evaluator=evaluator,
        activation_provider=activation_provider,
        execution_policy_gate=policy_gate,
        registry_claim_gate=registry_claim_gate,
    )
    return ArenaSafeWorkerService(
        arena_store=arena_store,
        worker=worker,
        poll_interval_seconds=poll_interval_seconds,
    )


def write_bounded_worker_status(status: ArenaWorkerStatus, stream: TextIO) -> None:
    """Write one canonical status line without exception or private detail."""

    encoded = json.dumps(
        status.to_bounded_dict(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    stream.write(encoded + "\n")
    stream.flush()


def run_arena_worker_process(
    service: ArenaSafeWorkerService,
    *,
    status_sink: Callable[[ArenaWorkerStatus], None],
    heartbeat_sink: Callable[[ArenaWorkerStatus, int], None] | None = None,
    stop_signal: StopSignal | None = None,
    now: Callable[[], int] | None = None,
    wait: Callable[[float], None] | None = None,
    max_iterations: int | None = None,
) -> int:
    """Dedicated internal process entrypoint with one lifetime worker lease.

    The entrypoint never accepts an activation boolean, raw quote, or unsafe
    runtime selector. Dependency construction must already have authenticated
    the independent verdict, finalized registry claim gate, and persisted
    execution-policy gate.
    """

    if not isinstance(service, ArenaSafeWorkerService):
        raise ArenaWorkerServiceError("Arena worker service is required")
    if not callable(status_sink):
        raise ArenaWorkerServiceError("Arena bounded status sink is required")
    if heartbeat_sink is not None and not callable(heartbeat_sink):
        raise ArenaWorkerServiceError("Arena worker heartbeat sink is invalid")
    if max_iterations is not None and (
        isinstance(max_iterations, bool)
        or not isinstance(max_iterations, int)
        or max_iterations < 1
    ):
        raise ArenaWorkerServiceError("Arena max_iterations is invalid")
    clock = now or (lambda: int(time.time()))
    waiter = wait or time.sleep
    iterations = 0
    idle_reported = False

    with ArenaWorkerProcessLease(service.arena_store.path):
        while True:
            if stop_signal is not None and stop_signal.is_set():
                stopped = ArenaWorkerStatus(
                    state="stopped",
                    submission_id=None,
                    final_state=None,
                    recovery=False,
                    failure_code="none",
                )
                if heartbeat_sink is not None:
                    heartbeat_sink(stopped, clock())
                status_sink(stopped)
                return EXIT_OK
            occurred_at = clock()
            try:
                status = service.run_once(occurred_at=occurred_at)
            except ArenaSafeWorkerPolicyUnavailable as exc:
                del exc
                blocked = ArenaWorkerStatus(
                    state="blocked",
                    submission_id=None,
                    final_state=None,
                    recovery=False,
                    failure_code="execution_policy_unavailable",
                )
                if heartbeat_sink is not None:
                    heartbeat_sink(blocked, occurred_at)
                status_sink(blocked)
                return EXIT_ACTIVATION_UNAVAILABLE
            except ArenaSafeWorkerRegistryUnavailable as exc:
                del exc
                blocked = ArenaWorkerStatus(
                    state="blocked",
                    submission_id=None,
                    final_state=None,
                    recovery=False,
                    failure_code="challenge_registry_unavailable",
                )
                if heartbeat_sink is not None:
                    heartbeat_sink(blocked, occurred_at)
                status_sink(blocked)
                return EXIT_ACTIVATION_UNAVAILABLE
            except ArenaSafeWorkerUnavailable as exc:
                del exc
                blocked = ArenaWorkerStatus(
                    state="blocked",
                    submission_id=None,
                    final_state=None,
                    recovery=False,
                    failure_code="activation_unavailable",
                )
                if heartbeat_sink is not None:
                    heartbeat_sink(blocked, occurred_at)
                status_sink(blocked)
                return EXIT_ACTIVATION_UNAVAILABLE
            except (ArenaStoreError, ArenaIngressError) as exc:
                del exc
                failed = ArenaWorkerStatus(
                    state="operator_error",
                    submission_id=None,
                    final_state=None,
                    recovery=False,
                    failure_code="durable_state_unavailable",
                )
                if heartbeat_sink is not None:
                    heartbeat_sink(failed, occurred_at)
                status_sink(failed)
                return EXIT_OPERATOR_ERROR
            except ArenaSafeWorkerError as exc:
                del exc
                failed = ArenaWorkerStatus(
                    state="operator_error",
                    submission_id=None,
                    final_state=None,
                    recovery=False,
                    failure_code="worker_unavailable",
                )
                if heartbeat_sink is not None:
                    heartbeat_sink(failed, occurred_at)
                status_sink(failed)
                return EXIT_OPERATOR_ERROR

            iterations += 1
            if heartbeat_sink is not None:
                # Unlike the human-facing status stream, presence is refreshed
                # on every idle poll so a healthy quiet worker does not age out.
                heartbeat_sink(status, occurred_at)
            if status.state == "idle":
                if not idle_reported:
                    status_sink(status)
                    idle_reported = True
            else:
                status_sink(status)
                idle_reported = False
            if max_iterations is not None and iterations >= max_iterations:
                return EXIT_OK
            if status.state == "idle":
                waiter(service.poll_interval_seconds)
