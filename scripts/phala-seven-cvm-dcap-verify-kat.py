"""Deterministic KAT for the recorded-second DCAP verifier data path.

This fixture deliberately does not claim Intel verification: it supplies a
minimal in-memory ``dcap_qvl`` test double, imports the exact production source,
and proves that live collateral acquisition and replayed collateral bytes feed
the same explicit verification second into ``py_verify``.  The opened-FD Node
tests separately load and authenticate the real pinned abi3 extension.
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import types


COLLATERAL_JSON = (
    '{"nextUpdate":"2030-01-01T00:00:00Z","schema":"kat.v1"}'
)
VERIFICATION_SECOND = 1_900_000_000
EXPECTED = {
    "collateral_sha256":
        "sha256:6c93e4b045e141aeb5b6a02c4c23e772552a84528e5f30c996ca016c2a42ffc7",
    "measurements_sha256":
        "sha256:009f360e600a98bded234d15f3a0871953057c452edcb219d8745e97a579ef81",
    "policy_sha256":
        "sha256:47765642e5f9bc8f041dd5ba70a371d03765b454cb9413eb3574df838f79bdd7",
    "report_data": "0x" + "42" * 64,
}


class _Collateral:
    def __init__(self, text: str) -> None:
        self.text = text

    def to_json(self) -> str:
        return self.text


class _Report:
    report_data = bytes([0x42]) * 64


class _ParsedQuote:
    report = _Report()

    @staticmethod
    def is_tdx() -> bool:
        return True

    @staticmethod
    def quote_type() -> str:
        return "TDX"


class _Verified:
    status = "OK"


def _load_production_source():
    calls = []
    fake = types.ModuleType("dcap_qvl")
    fake.parse_quote = lambda _raw: _ParsedQuote()

    async def get_collateral(url, raw):
        calls.append(("get", url, len(raw)))
        return _Collateral(COLLATERAL_JSON)

    def collateral_from_json(text):
        calls.append(("from_json", text))
        return _Collateral(text)

    def verify_with_collateral(raw, collateral, verification_time):
        calls.append(
            ("verify", len(raw), collateral.to_json(), verification_time)
        )
        return _Verified()

    fake.get_collateral = get_collateral
    fake.collateral_from_json = collateral_from_json
    fake.verify_with_collateral = verify_with_collateral
    sys.modules["dcap_qvl"] = fake
    source = Path(__file__).with_name("phala-seven-cvm-dcap-verify.py")
    spec = importlib.util.spec_from_file_location("dnai_dcap_verifier_kat", source)
    if spec is None or spec.loader is None:
        raise AssertionError("production DCAP verifier source cannot be imported")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, calls


def _policy(module):
    for field in module.BASE_MEASUREMENT_FIELDS:
        byte_length = module.MEASUREMENT_LENGTHS.get(field, 96) // 2
        setattr(_Report, field, bytes(byte_length))
    policy = {
        "schema": module.MEASUREMENT_POLICY_SCHEMA,
        "domain": "diligence_qvl_cvm",
        "profile": "diligence",
        "deployment_intent_sha256": "sha256:" + "11" * 32,
        "reference_id": "kat-dcap-0001",
        "mr_td": "00" * 48,
        "mr_config_id": "00" * 48,
        "mr_owner": "00" * 48,
        "mr_owner_config": "00" * 48,
        "rt_mr0": "00" * 48,
        "rt_mr1": "00" * 48,
        "rt_mr2": "00" * 48,
        "rt_mr3": "00" * 48,
        "td_attributes": "00" * 8,
        "td_attributes_required_mask": "00" * 8,
        "td_attributes_forbidden_mask": "01" + "00" * 7,
        "xfam": "00" * 8,
        "xfam_required_mask": "00" * 8,
        "xfam_forbidden_mask": "00" * 8,
    }
    digest = "sha256:" + hashlib.sha256(
        module.MEASUREMENT_POLICY_DIGEST_DOMAIN
        + module._canonical_json_bytes(policy)
    ).hexdigest()
    return policy, digest


def main() -> int:
    module, calls = _load_production_source()
    policy, policy_sha256 = _policy(module)
    raw_quote = bytes(1_024)
    live = asyncio.run(module._verify(
        raw_quote,
        policy,
        policy_sha256,
        VERIFICATION_SECOND,
        None,
    ))
    replay = asyncio.run(module._verify(
        raw_quote,
        policy,
        policy_sha256,
        VERIFICATION_SECOND,
        COLLATERAL_JSON,
    ))
    if live != replay:
        raise AssertionError("live and historical DCAP data paths diverged")
    expected_calls = [
        ("get", module.PCCS_URL, 1_024),
        ("verify", 1_024, COLLATERAL_JSON, VERIFICATION_SECOND),
        ("from_json", COLLATERAL_JSON),
        ("verify", 1_024, COLLATERAL_JSON, VERIFICATION_SECOND),
    ]
    if calls != expected_calls:
        raise AssertionError("collateral or exact verification second drifted")
    summary = {
        "collateral_sha256":
            live["historical_dcap_replay"]["collateral_sha256"],
        "measurements_sha256": live["measurements_sha256"],
        "policy_sha256": policy_sha256,
        "report_data": live["report_data"],
    }
    if summary != EXPECTED:
        raise AssertionError("recorded-second DCAP KAT vector drifted")
    for invalid_time in (True, 0, 4_102_444_801):
        try:
            asyncio.run(module._verify(
                raw_quote,
                policy,
                policy_sha256,
                invalid_time,
                COLLATERAL_JSON,
            ))
        except ValueError:
            pass
        else:
            raise AssertionError("invalid verification second was accepted")
    print(json.dumps(EXPECTED, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
