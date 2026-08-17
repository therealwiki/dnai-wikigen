from __future__ import annotations

import base64
import json
import stat

import pytest

from attestation_qvl.errors import VerifierUnavailable
from attestation_qvl.policy import load_release_policy
from attestation_qvl.policy_bootstrap import (
    MAX_POLICY_B64_CHARS,
    decode_policy_environment,
    materialize_policy,
)
from tests.support import policy_payload


def _encoded(payload: dict[str, object]) -> str:
    return base64.b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode("ascii")


def test_bootstrap_materializes_only_canonical_root_owned_compatible_file(tmp_path):
    target = tmp_path / "release-policy.json"
    release = materialize_policy(_encoded(policy_payload()), str(target.resolve()))
    loaded = load_release_policy(str(target.resolve()))
    mode = stat.S_IMODE(target.stat().st_mode)

    assert target.read_bytes() == release.canonical_bytes
    assert loaded.policy_hash == release.policy_hash
    assert mode == 0o444
    assert mode & (stat.S_IWGRP | stat.S_IWOTH) == 0


@pytest.mark.parametrize(
    "encoded",
    [
        "not+canonical/base64===",
        "A" * (MAX_POLICY_B64_CHARS + 1),
        base64.b64encode(b'{"schema":"a","schema":"b"}').decode(),
        base64.b64encode(b"{}").decode(),
    ],
)
def test_bootstrap_rejects_malformed_oversized_duplicate_or_invalid_policy(encoded):
    with pytest.raises(VerifierUnavailable):
        decode_policy_environment(encoded)


def test_bootstrap_rejects_relative_target_and_writable_parent(tmp_path):
    with pytest.raises(VerifierUnavailable):
        materialize_policy(_encoded(policy_payload()), "release-policy.json")
    tmp_path.chmod(0o777)
    try:
        with pytest.raises(VerifierUnavailable):
            materialize_policy(
                _encoded(policy_payload()),
                str((tmp_path / "release-policy.json").resolve()),
            )
    finally:
        tmp_path.chmod(0o700)
