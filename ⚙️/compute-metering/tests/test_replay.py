from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

import pytest

from compute_metering.errors import ReplayConflict, StateUnavailable
from compute_metering.replay import DurableReplayStore
from tests.support import JOB_ID, decision_bytes, write_policy


KEY = b"k" * 32
USAGE = "0x" + "ee" * 32
REQUEST = "0x" + "fa" * 32


def _store(tmp_path: Path, *, key: bytes = KEY, policy_set_hash: str | None = None):
    release = write_policy(tmp_path / "policy-set.json")
    state = tmp_path / "state"
    state.mkdir(mode=0o700, exist_ok=True)
    state.chmod(0o700)
    store = DurableReplayStore(
        path=str(state / "replay.sqlite3"),
        policy_set_hash=policy_set_hash or release.policy_set_hash,
        _integrity_key=key,
    )
    return release, store


def test_record_then_exact_lookup_returns_identical_canonical_bytes(tmp_path):
    release, store = _store(tmp_path)
    try:
        decision = decision_bytes(release)
        recorded = store.record(
            job_id=JOB_ID,
            usage_commitment=USAGE,
            request_hash=REQUEST,
            decision_json=decision,
        )
        assert recorded == decision
        assert store.lookup(job_id=JOB_ID, usage_commitment=USAGE, request_hash=REQUEST) == decision
        assert store.record(
            job_id=JOB_ID,
            usage_commitment=USAGE,
            request_hash=REQUEST,
            decision_json=decision,
        ) == decision
    finally:
        store.close()


@pytest.mark.parametrize(
    ("job", "usage", "request_hash"),
    [
        (JOB_ID, "0x" + "01" * 32, REQUEST),
        ("0x" + "02" * 32, USAGE, REQUEST),
        (JOB_ID, USAGE, "0x" + "03" * 32),
    ],
)
def test_job_usage_or_request_reuse_with_different_context_is_conflict(tmp_path, job, usage, request_hash):
    release, store = _store(tmp_path)
    try:
        store.record(
            job_id=JOB_ID,
            usage_commitment=USAGE,
            request_hash=REQUEST,
            decision_json=decision_bytes(release),
        )
        with pytest.raises(ReplayConflict):
            store.lookup(job_id=job, usage_commitment=usage, request_hash=request_hash)
    finally:
        store.close()


def test_replay_survives_clean_restart_and_policy_binding(tmp_path):
    release, store = _store(tmp_path)
    path = store.path
    decision = decision_bytes(release)
    store.record(job_id=JOB_ID, usage_commitment=USAGE, request_hash=REQUEST, decision_json=decision)
    store.close()

    reopened = DurableReplayStore(path=path, policy_set_hash=release.policy_set_hash, _integrity_key=KEY)
    try:
        assert reopened.lookup(job_id=JOB_ID, usage_commitment=USAGE, request_hash=REQUEST) == decision
    finally:
        reopened.close()

    with pytest.raises(StateUnavailable):
        DurableReplayStore(path=path, policy_set_hash="0x" + "04" * 32, _integrity_key=KEY)
    with pytest.raises(StateUnavailable):
        DurableReplayStore(path=path, policy_set_hash=release.policy_set_hash, _integrity_key=b"z" * 32)


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE decisions SET decision_json = X'7b7d' WHERE sequence = 1",
        "UPDATE decisions SET row_mac = zeroblob(32) WHERE sequence = 1",
        "UPDATE decisions SET chain_mac = zeroblob(32) WHERE sequence = 1",
        "UPDATE metadata SET mac = zeroblob(32) WHERE name = 'chain_state'",
        "DELETE FROM decisions WHERE sequence = 1",
    ],
)
def test_tampering_deletion_or_chain_damage_fails_restart(tmp_path, sql):
    release, store = _store(tmp_path)
    path = store.path
    store.record(
        job_id=JOB_ID,
        usage_commitment=USAGE,
        request_hash=REQUEST,
        decision_json=decision_bytes(release),
    )
    store.close()
    connection = sqlite3.connect(path)
    connection.execute(sql)
    connection.commit()
    connection.close()
    with pytest.raises(StateUnavailable):
        DurableReplayStore(path=path, policy_set_hash=release.policy_set_hash, _integrity_key=KEY)


def test_in_process_deletion_is_detected_before_lookup_or_new_signature(tmp_path):
    release, store = _store(tmp_path)
    try:
        store.record(
            job_id=JOB_ID,
            usage_commitment=USAGE,
            request_hash=REQUEST,
            decision_json=decision_bytes(release),
        )
        store._db.execute("DELETE FROM decisions WHERE sequence = 1")
        with pytest.raises(StateUnavailable):
            store.lookup(job_id=JOB_ID, usage_commitment=USAGE, request_hash=REQUEST)
    finally:
        store.close()


def test_record_rejects_noncanonical_or_cross_key_decision(tmp_path):
    release, store = _store(tmp_path)
    try:
        decision = decision_bytes(release)
        with pytest.raises(StateUnavailable):
            store.record(
                job_id="0x" + "09" * 32,
                usage_commitment=USAGE,
                request_hash=REQUEST,
                decision_json=decision,
            )
        with pytest.raises(StateUnavailable):
            store.record(
                job_id=JOB_ID,
                usage_commitment=USAGE,
                request_hash=REQUEST,
                decision_json=json.dumps(json.loads(decision), indent=2).encode(),
            )
        with pytest.raises(StateUnavailable):
            store.record(
                job_id=JOB_ID,
                usage_commitment=USAGE,
                request_hash="not-a-hash",
                decision_json=decision,
            )
    finally:
        store.close()


def test_database_parent_and_file_permissions_fail_closed(tmp_path):
    release = write_policy(tmp_path / "policy-set.json")
    public = tmp_path / "public"
    public.mkdir(mode=0o777)
    public.chmod(0o777)
    with pytest.raises(StateUnavailable):
        DurableReplayStore(
            path=str(public / "replay.sqlite3"),
            policy_set_hash=release.policy_set_hash,
            _integrity_key=KEY,
        )

    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    target = state / "target.sqlite3"
    target.touch(mode=0o600)
    link = state / "replay.sqlite3"
    link.symlink_to(target)
    with pytest.raises(StateUnavailable):
        DurableReplayStore(path=str(link), policy_set_hash=release.policy_set_hash, _integrity_key=KEY)


def test_integrity_key_never_appears_in_repr(tmp_path):
    _release, store = _store(tmp_path)
    try:
        assert "kkkk" not in repr(store)
        assert repr(KEY) not in repr(store)
    finally:
        store.close()
