"""Local HTTP/storage regressions; registry authority is synthetic, not TDX proof."""

from concurrent.futures import ThreadPoolExecutor
import json
from threading import Event
import time
from unittest.mock import patch

import pytest

import test_arena_api as fixtures
from tinker_delegate import api
from tinker_delegate.arena_store import (
    ArenaIdempotencyConflict,
    ArenaSubmissionIngressGuard,
    ArenaStoreError,
    ArenaStore,
    BIO_CHALLENGE_ID,
    BIO_CHALLENGE_VERSION,
    SubmissionIdentity,
    default_challenge_catalog,
)
from tinker_delegate.arena_ingress import (
    ArenaCandidateEnvelope,
    ArenaIngressError,
    build_arena_candidate_binding,
)
from tinker_delegate.arena_store import SubmissionManifest


@pytest.fixture
def arena():
    case = fixtures.ArenaApiTest()
    case.setUp()
    try:
        yield case
    finally:
        case.tearDown()


def _post(case, payload, token, key):
    return case.client.post(
        f"/arena/challenges/{BIO_CHALLENGE_ID}/versions/"
        f"{BIO_CHALLENGE_VERSION}/submissions",
        json=payload,
        headers={"Authorization": f"Bearer {token}", "Idempotency-Key": key},
    )


def _terminate(case, submission_id, token, terminal):
    if terminal == "cancelled":
        result = case.client.post(
            f"/arena/challenges/{BIO_CHALLENGE_ID}/versions/"
            f"{BIO_CHALLENGE_VERSION}/submissions/{submission_id}/cancel",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert result.status_code == 200, result.text
        return
    transitions = [("policy_screen", "policy_check_started")]
    if terminal == "withheld":
        transitions.append(("withheld", "policy_withheld"))
    else:
        transitions.extend([
            ("queued", "policy_passed"),
            (terminal, "queue_expired" if terminal == "expired" else "retry_exhausted"),
        ])
    for state, reason in transitions:
        result = case.client.post(
            f"/arena/internal/submissions/{submission_id}/transition",
            json={"to_state": state, "reason": reason},
            headers=case._runtime_headers(),
        )
        assert result.status_code == 200, result.text


@pytest.mark.parametrize("terminal", ["cancelled", "expired", "withheld", "dead_letter"])
def test_terminal_exact_replay_cannot_recreate_unlinked_ciphertext(arena, terminal):
    token = arena._arena_token()
    key = f"terminal-replay-{terminal}"
    payload = arena._submission_payload(key=key)
    first = _post(arena, payload, token, key)
    assert first.status_code == 200, first.text
    submission_id = first.json()["submission"]["submission_id"]
    _terminate(arena, submission_id, token, terminal)
    store = api._get_arena_store()
    before = store.get_submission(submission_id)
    assert before.state.value == terminal
    assert before.ciphertext_state.value == "unlinked"
    assert list((arena.ingress_path / "envelopes").glob("*.json")) == []

    # Reopen durable state: an in-memory replay fence is insufficient.
    api._arena_store_instance = None
    api._arena_store_instance_path = ""
    ingress = api._get_arena_ingress()
    with patch.object(ingress, "ingest", wraps=ingress.ingest) as ingest:
        replay = _post(arena, payload, token, key)
    assert replay.status_code == 409, replay.text
    ingest.assert_not_called()
    assert store.get_submission(submission_id) == before
    assert list((arena.ingress_path / "envelopes").glob("*.json")) == []
    assert store.ciphertext_cleanup_candidates() == ()
    assert "sealed://" not in replay.text
    assert payload["envelope"]["ciphertext"] not in replay.text


def test_ingress_guard_preserves_active_replay_and_queue_failure_retry(arena):
    token = arena._arena_token()
    key = "retry-after-queue-failure"
    payload = arena._submission_payload(key=key)
    store = api._get_arena_store()
    with patch.object(store, "submit", side_effect=OSError("synthetic failure")):
        failed = _post(arena, payload, token, key)
    assert failed.status_code == 503, failed.text
    assert list((arena.ingress_path / "envelopes").glob("*.json")) == []
    first = _post(arena, payload, token, key)
    assert first.status_code == 200, first.text
    assert first.json()["created"] is True
    replay = _post(arena, payload, token, key)
    assert replay.status_code == 200, replay.text
    assert replay.json()["created"] is False
    assert replay.json()["candidate_ingress"]["created"] is False
    assert len(list((arena.ingress_path / "envelopes").glob("*.json"))) == 1


def test_terminal_retry_does_not_bypass_pending_ciphertext_cleanup(arena):
    token = arena._arena_token()
    key = "terminal-cleanup-pending"
    payload = arena._submission_payload(key=key)
    first = _post(arena, payload, token, key)
    assert first.status_code == 200, first.text
    submission_id = first.json()["submission"]["submission_id"]
    ingress = api._get_arena_ingress()
    with patch.object(ingress.store, "_unlink_blob_entry", side_effect=OSError("synthetic unlink failure")):
        _terminate(arena, submission_id, token, "cancelled")
    store = api._get_arena_store()
    before = store.get_submission(submission_id)
    assert before.ciphertext_state.value == "erasure_retry_required"
    blobs = list((arena.ingress_path / "envelopes").glob("*.json"))
    assert len(blobs) == 1
    with patch.object(ingress, "ingest", wraps=ingress.ingest) as ingest:
        replay = _post(arena, payload, token, key)
    assert replay.status_code == 409, replay.text
    ingest.assert_not_called()
    assert store.get_submission(submission_id) == before
    assert list((arena.ingress_path / "envelopes").glob("*.json")) == blobs
    cleaned = api._cleanup_arena_submission_ciphertext(
        store, submission_id, occurred_at=int(time.time())
    )
    assert cleaned.ciphertext_state.value == "unlinked"
    assert list((arena.ingress_path / "envelopes").glob("*.json")) == []


@pytest.mark.parametrize("terminal", ["cancelled", "expired"])
def test_ingress_and_queue_replay_hold_lock_against_concurrent_terminalization(arena, terminal):
    token = arena._arena_token()
    key = f"concurrent-terminal-{terminal}"
    payload = arena._submission_payload(key=key)
    first = _post(arena, payload, token, key)
    assert first.status_code == 200, first.text
    submission_id = first.json()["submission"]["submission_id"]
    if terminal == "expired":
        for state, reason in [("policy_screen", "policy_check_started"), ("queued", "policy_passed")]:
            moved = arena.client.post(
                f"/arena/internal/submissions/{submission_id}/transition",
                json={"to_state": state, "reason": reason},
                headers=arena._runtime_headers(),
            )
            assert moved.status_code == 200, moved.text
    store = api._get_arena_store()
    # A separate instance has a separate RLock. Only the durable flock can
    # serialize it against the HTTP request's ingress/queue critical section.
    other_store = ArenaStore(arena.store_path, integrity_key=store._integrity_key)
    ingress = api._get_arena_ingress()
    entered_ingress = Event()
    release_ingress = Event()
    attempted_terminal_lock = Event()
    acquired_terminal_lock = Event()
    real_ingest = ingress.ingest
    real_acquire = other_store._acquire_file_lock

    def paused_ingest(**kwargs):
        entered_ingress.set()
        assert release_ingress.wait(5), "test did not release candidate ingress"
        return real_ingest(**kwargs)

    def acquire_terminal_lock():
        attempted_terminal_lock.set()
        descriptor = real_acquire()
        acquired_terminal_lock.set()
        return descriptor

    def terminalize():
        if terminal == "expired":
            return other_store.transition_submission(
                submission_id, "expired", reason="queue_expired", occurred_at=int(time.time())
            )
        return other_store.cancel_owner_submission(
            submission_id,
            wallet_address=arena.submitter.address.lower(),
            challenge_id=BIO_CHALLENGE_ID,
            challenge_version=BIO_CHALLENGE_VERSION,
            occurred_at=int(time.time()),
        )

    with ThreadPoolExecutor(max_workers=2) as pool, patch.object(ingress, "ingest", side_effect=paused_ingest):
        replay_future = pool.submit(_post, arena, payload, token, key)
        try:
            assert entered_ingress.wait(5), "HTTP replay did not enter ingress"
            with patch.object(other_store, "_acquire_file_lock", side_effect=acquire_terminal_lock):
                terminal_future = pool.submit(terminalize)
                try:
                    assert attempted_terminal_lock.wait(5), "terminal operation did not attempt the durable lock"
                    assert not acquired_terminal_lock.wait(0.1), "terminal transition interleaved with candidate ingress"
                finally:
                    release_ingress.set()
                replay = replay_future.result(timeout=5)
                assert replay.status_code == 200, replay.text
                terminal_future.result(timeout=5)
        finally:
            release_ingress.set()
    assert acquired_terminal_lock.is_set()
    cleaned = api._cleanup_arena_submission_ciphertext(
        other_store, submission_id, occurred_at=int(time.time())
    )
    assert cleaned.state.value == terminal
    assert cleaned.ciphertext_state.value == "unlinked"
    assert list((arena.ingress_path / "envelopes").glob("*.json")) == []
    assert _post(arena, payload, token, key).status_code == 409
    assert list((arena.ingress_path / "envelopes").glob("*.json")) == []


def _interrupt_fresh_rollback(case, failure):
    token = case._arena_token()
    key = f"orphan-recovery-{failure}"
    payload = case._submission_payload(key=key)
    store = api._get_arena_store()
    ingress = api._get_arena_ingress()
    real_persist = ingress.store._persist_index

    def fail_finalization(records):
        if not records:
            raise OSError("synthetic rollback index finalization failure")
        return real_persist(records)

    rollback_patch = (
        patch.object(ingress.store, "_unlink_blob_entry", side_effect=OSError("synthetic rollback unlink failure"))
        if failure == "unlink"
        else patch.object(ingress.store, "_persist_index", side_effect=fail_finalization)
    )
    with patch.object(store, "submit", side_effect=OSError("synthetic queue write failure")), rollback_patch:
        failed = _post(case, payload, token, key)
    assert failed.status_code == 503, failed.text
    assert failed.json()["detail"] == "Arena coordinated persistence rollback failed"
    assert store._state.submissions == {}
    assert store._state.idempotency == {}
    index = json.loads((case.ingress_path / "index.json").read_text())
    assert len(index["records"]) == 1
    assert index["records"][0]["storage_state"] == "unlink_pending"
    assert len(list((case.ingress_path / "envelopes").glob("*.json"))) == (1 if failure == "unlink" else 0)
    # Recovery must rely on persisted state rather than an in-memory flag.
    api._arena_store_instance = None
    api._arena_store_instance_path = ""
    api._arena_ingress_service_instance = None
    api._arena_ingress_service_identity = None
    return token, key, payload, index["records"][0]


@pytest.mark.parametrize("failure", ["unlink", "index_finalization"])
def test_exact_retry_recovers_unowned_pending_ingress_after_interrupted_rollback(arena, failure):
    token, key, payload, pending = _interrupt_fresh_rollback(arena, failure)
    recovered = _post(arena, payload, token, key)
    assert recovered.status_code == 200, recovered.text
    assert recovered.json()["created"] is True
    assert recovered.json()["candidate_ingress"]["created"] is True
    assert recovered.json()["candidate_ingress"]["ciphertext_sha256"] == pending["ciphertext_sha256"]
    index = json.loads((arena.ingress_path / "index.json").read_text())
    assert len(index["records"]) == 1
    assert index["records"][0]["storage_state"] == "retained"
    assert index["records"][0]["request_hash"] == pending["request_hash"]
    assert len(list((arena.ingress_path / "envelopes").glob("*.json"))) == 1
    replay = _post(arena, payload, token, key)
    assert replay.status_code == 200, replay.text
    assert replay.json()["created"] is False
    assert replay.json()["candidate_ingress"]["created"] is False


@pytest.mark.parametrize("failure", ["unlink", "index_finalization"])
def test_orphan_recovery_rejects_changed_envelope_without_altering_reservation(arena, failure):
    token, key, payload, _ = _interrupt_fresh_rollback(arena, failure)
    changed = arena._submission_payload(key=key, commitment_byte="b")
    ingress = api._get_arena_ingress()
    before = arena._ingress_snapshot()
    with patch.object(ingress.store, "_unlink_blob_entry", wraps=ingress.store._unlink_blob_entry) as unlink:
        rejected = _post(arena, changed, token, key)
    assert rejected.status_code == 409, rejected.text
    unlink.assert_not_called()
    assert arena._ingress_snapshot() == before
    assert changed["envelope"]["ciphertext"] not in rejected.text
    assert "sealed://" not in rejected.text
    assert _post(arena, payload, token, key).status_code == 200


@pytest.mark.parametrize("recovery_failure", ["unlink", "empty_blob_write", "retained_index"])
def test_failed_exact_recovery_keeps_original_pending_binding_for_retry(arena, recovery_failure):
    token, key, payload, pending = _interrupt_fresh_rollback(arena, "unlink")
    ingress = api._get_arena_ingress()
    real_persist = ingress.store._persist_index

    def fail_retained_index(records):
        if any(record.storage_state == "retained" for record in records.values()):
            raise OSError("synthetic recovery index failure")
        return real_persist(records)

    if recovery_failure == "unlink":
        fault = patch.object(ingress.store, "_unlink_blob_entry", side_effect=OSError("synthetic recovery unlink failure"))
    elif recovery_failure == "empty_blob_write":
        fault = patch("tinker_delegate.arena_ingress._write_all", side_effect=OSError("synthetic empty recovery write"))
    else:
        fault = patch.object(ingress.store, "_persist_index", side_effect=fail_retained_index)
    with fault:
        failed = _post(arena, payload, token, key)
    assert failed.status_code == 503, failed.text
    assert failed.json()["detail"] == "Arena candidate ingress is unavailable"
    index = json.loads((arena.ingress_path / "index.json").read_text())
    assert index["records"] == [pending]
    assert api._get_arena_store()._state.submissions == {}
    assert payload["envelope"]["ciphertext"] not in failed.text
    assert "sealed://" not in failed.text

    api._arena_ingress_service_instance = None
    api._arena_ingress_service_identity = None
    reopened = api._get_arena_ingress()
    with pytest.raises(ArenaIngressError, match="Unknown Arena sealed reference"):
        reopened.store.load_envelope(pending["sealed_reference"])
    changed = arena._submission_payload(key=key, commitment_byte="b")
    assert _post(arena, changed, token, key).status_code == 409
    recovered = _post(arena, payload, token, key)
    assert recovered.status_code == 200, recovered.text
    assert recovered.json()["candidate_ingress"]["created"] is True


def test_recovered_blob_is_still_rolled_back_if_queue_retry_fails(arena):
    token, key, payload, _ = _interrupt_fresh_rollback(arena, "index_finalization")
    store = api._get_arena_store()
    with patch.object(store, "submit", side_effect=OSError("synthetic repeated queue failure")):
        failed = _post(arena, payload, token, key)
    assert failed.status_code == 503, failed.text
    assert failed.json()["detail"] == "Arena durable store write failed"
    assert json.loads((arena.ingress_path / "index.json").read_text())["records"] == []
    assert list((arena.ingress_path / "envelopes").glob("*.json")) == []
    assert store._state.submissions == {}
    assert _post(arena, payload, token, key).status_code == 200


def test_existing_active_queue_row_cannot_authorize_orphan_recovery(arena):
    token = arena._arena_token()
    key = "active-row-is-not-orphaned"
    payload = arena._submission_payload(key=key)
    first = _post(arena, payload, token, key)
    assert first.status_code == 200, first.text
    store = api._get_arena_store()
    before = store.get_submission(first.json()["submission"]["submission_id"])
    ingress = api._get_arena_ingress()
    # Emulate an interrupted privileged erasure without changing the queue row.
    # Its existing owner must outweigh the ingress index's pending state.
    with patch.object(ingress.store, "_unlink_blob_entry", side_effect=OSError("synthetic interrupted erase")):
        with pytest.raises(ArenaIngressError):
            ingress.store.erase_envelope(before.encrypted_reference)
    snapshot = arena._ingress_snapshot()
    with patch.object(ingress.store, "_unlink_blob_entry", wraps=ingress.store._unlink_blob_entry) as unlink:
        replay = _post(arena, payload, token, key)
    assert replay.status_code == 409, replay.text
    unlink.assert_not_called()
    assert arena._ingress_snapshot() == snapshot
    assert store.get_submission(before.submission_id) == before


def _binding_for_payload(case, key, payload):
    challenge = default_challenge_catalog().get(BIO_CHALLENGE_ID, BIO_CHALLENGE_VERSION)
    # Reproduce the server-derived personal identity, not a payload override.
    import hashlib
    address = case.submitter.address.lower()
    identity = SubmissionIdentity(address, "personal-" + hashlib.sha256(
        b"arena-personal-project:" + address.encode("ascii")
    ).hexdigest()[:32])
    ingress = api._get_arena_ingress()
    binding = build_arena_candidate_binding(
        challenge=challenge,
        identity=identity,
        candidate_commitment=payload["candidate_commitment"],
        manifest=SubmissionManifest.from_mapping(payload["manifest"]),
        recipient=ingress.recipient,
        idempotency_key=key,
        registry_authorization_sha256=case._registry_snapshot(challenge).sha256,
    )
    return ingress, identity, binding, ArenaCandidateEnvelope.from_mapping(payload["envelope"])


def test_orphan_recovery_requires_an_issued_live_exact_guard_not_a_boolean(arena):
    token, key, payload, _ = _interrupt_fresh_rollback(arena, "unlink")
    ingress, identity, binding, envelope = _binding_for_payload(arena, key, payload)
    store = api._get_arena_store()
    snapshot = arena._ingress_snapshot()
    rejected_flag = _post(arena, {**payload, "allow_orphan_recovery": True}, token, key)
    assert rejected_flag.status_code == 422
    with pytest.raises(ArenaStoreError, match="must be issued"):
        ArenaSubmissionIngressGuard(None, store, identity, BIO_CHALLENGE_ID, BIO_CHALLENGE_VERSION, key, "0" * 64)
    for fake_guard in (True, {"allow_orphan_recovery": True}):
        with pytest.raises(ArenaIngressError, match="guard is invalid"):
            ingress.store.put(binding=binding, envelope=envelope, queue_guard=fake_guard)
    with pytest.raises(ArenaIngressError, match="no longer accepts ingress replay"):
        ingress.store.put(binding=binding, envelope=envelope)

    with store.submission_ingress_guard(
        challenge_id=BIO_CHALLENGE_ID, challenge_version=BIO_CHALLENGE_VERSION,
        identity=identity, idempotency_key=key,
    ) as expired_guard:
        pass
    with pytest.raises(ArenaIdempotencyConflict, match="exact live queue guard"):
        ingress.store.put(binding=binding, envelope=envelope, queue_guard=expired_guard)
    with store.submission_ingress_guard(
        challenge_id=BIO_CHALLENGE_ID, challenge_version=BIO_CHALLENGE_VERSION,
        identity=identity, idempotency_key="another-key",
    ) as wrong_guard:
        with pytest.raises(ArenaIdempotencyConflict, match="exact live queue guard"):
            ingress.store.put(binding=binding, envelope=envelope, queue_guard=wrong_guard)
    with store.submission_ingress_guard(
        challenge_id=BIO_CHALLENGE_ID, challenge_version=BIO_CHALLENGE_VERSION,
        identity=identity, idempotency_key=key,
    ) as thread_bound_guard, ThreadPoolExecutor(max_workers=1) as pool:
        attempted = pool.submit(
            ingress.store.put, binding=binding, envelope=envelope,
            queue_guard=thread_bound_guard,
        )
        with pytest.raises(ArenaIdempotencyConflict, match="exact live queue guard"):
            attempted.result(timeout=5)
    assert arena._ingress_snapshot() == snapshot
    assert _post(arena, payload, token, key).status_code == 200
