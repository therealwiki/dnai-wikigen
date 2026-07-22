from __future__ import annotations

from types import SimpleNamespace

import dcap_qvl
import pytest

from attestation_qvl.errors import VerificationRejected, VerifierUnavailable
from attestation_qvl.qvl import (
    BASE_MEASUREMENT_FIELDS,
    V15_MEASUREMENT_FIELDS,
    DcapQvlBackend,
)
from tests.support import measurement_bytes


class ParsedQuote:
    def __init__(self, *, report: object, is_tdx: bool = True, quote_type: str = "TDX"):
        self.report = report
        self._is_tdx = is_tdx
        self._quote_type = quote_type

    def is_tdx(self) -> bool:
        return self._is_tdx

    def quote_type(self) -> str:
        return self._quote_type


def _report(*, v15: bool = False, incomplete_v15: bool = False) -> object:
    values = measurement_bytes(v15=v15)
    if incomplete_v15:
        values["tee_tcb_svn2"] = bytes.fromhex("0f" * 16)
    values["report_data"] = bytes.fromhex("aa" * 32) + bytes(32)
    return SimpleNamespace(**values)


def test_pinned_official_binding_exposes_the_consumed_v052_shape():
    assert dcap_qvl.__version__ == "0.5.2"
    assert callable(dcap_qvl.parse_quote)
    assert callable(dcap_qvl.get_collateral_and_verify)
    assert {"status", "advisory_ids", "ppid"} <= set(dcap_qvl.VerifiedReport.__dict__)
    assert set(BASE_MEASUREMENT_FIELDS) <= set(dcap_qvl.TdReport10.__dict__)
    assert set(BASE_MEASUREMENT_FIELDS + V15_MEASUREMENT_FIELDS) <= set(dcap_qvl.TdReport15.__dict__)


@pytest.mark.asyncio
@pytest.mark.parametrize("v15", [False, True])
async def test_adapter_uses_same_raw_quote_and_extracts_exact_tdx_fields(monkeypatch, v15):
    raw_quote = b"q" * 2048
    parsed = ParsedQuote(report=_report(v15=v15))
    calls: list[tuple[bytes, str]] = []

    monkeypatch.setattr(dcap_qvl, "parse_quote", lambda value: parsed)

    async def verify(value: bytes, pccs_url: str):
        calls.append((value, pccs_url))
        return SimpleNamespace(status="OK")

    monkeypatch.setattr(dcap_qvl, "get_collateral_and_verify", verify)
    result = await DcapQvlBackend("https://pccs.example").verify(raw_quote)

    expected_fields = set(BASE_MEASUREMENT_FIELDS)
    if v15:
        expected_fields.update(V15_MEASUREMENT_FIELDS)
    assert calls == [(raw_quote, "https://pccs.example")]
    assert result.quote_type == "TDX"
    assert result.status == "OK"
    assert result.report_data == bytes.fromhex("aa" * 32) + bytes(32)
    assert set(result.measurements) == expected_fields


@pytest.mark.asyncio
async def test_adapter_rejects_non_tdx_before_collateral_lookup(monkeypatch):
    monkeypatch.setattr(
        dcap_qvl,
        "parse_quote",
        lambda _value: ParsedQuote(report=_report(), is_tdx=False, quote_type="SGX"),
    )
    called = False

    async def verify(_value: bytes, _pccs_url: str):
        nonlocal called
        called = True

    monkeypatch.setattr(dcap_qvl, "get_collateral_and_verify", verify)
    with pytest.raises(VerificationRejected):
        await DcapQvlBackend("https://pccs.example").verify(b"q" * 2048)
    assert called is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "report,status",
    [
        (_report(incomplete_v15=True), "OK"),
        (_report(), object()),
    ],
)
async def test_adapter_never_stringifies_malformed_status_or_partial_v15(monkeypatch, report, status):
    monkeypatch.setattr(dcap_qvl, "parse_quote", lambda _value: ParsedQuote(report=report))

    async def verify(_value: bytes, _pccs_url: str):
        return SimpleNamespace(status=status)

    monkeypatch.setattr(dcap_qvl, "get_collateral_and_verify", verify)
    with pytest.raises(VerificationRejected):
        await DcapQvlBackend("https://pccs.example").verify(b"q" * 2048)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (ValueError("malformed quote"), VerificationRejected),
        (RuntimeError("PCCS unavailable"), VerifierUnavailable),
    ],
)
async def test_adapter_maps_failures_to_fixed_internal_categories(monkeypatch, error, expected):
    monkeypatch.setattr(dcap_qvl, "parse_quote", lambda _value: ParsedQuote(report=_report()))

    async def verify(_value: bytes, _pccs_url: str):
        raise error

    monkeypatch.setattr(dcap_qvl, "get_collateral_and_verify", verify)
    with pytest.raises(expected):
        await DcapQvlBackend("https://pccs.example").verify(b"q" * 2048)
