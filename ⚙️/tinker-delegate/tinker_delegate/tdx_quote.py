"""Structural parser for Intel TDX (DCAP v4) attestation quotes.

Extracts the report-data and measurement registers embedded in a raw TDX quote
so a verifier can bind the quote *bytes* to an expected report-data value,
instead of trusting a separately-claimed report-data field alongside an opaque
quote blob.

SCOPE / TRUST BOUNDARY
----------------------
This performs STRUCTURAL parsing only. It does NOT verify the Intel signature or
certificate chain — that trust root stays delegated to the Intel QVL / dstack
SDK (see CLAUDE.md: never self-host TEE verification crypto). On its own this
parser establishes no trust. It is a fail-closed, defense-in-depth check:
extract report_data from the quote and require it to equal the expected value.

Because the check is `extracted == expected`, a wrong offset or an unrecognised
format can only make the gate STRICTER (reject a good quote), never accept a
forged one — the safe failure direction for a security gate.

Offsets follow the Intel TDX DCAP quote layout for **quote version 4**, **TEE
type TDX (0x81)**, TD report body TD10/TD15. `report_data` sits at the same
absolute offset for TD10 (584-byte body) and TD15 (648-byte body) because
TD15's extra fields (`tee_tcb_svn2`, `mr_servicetd`) are appended *after*
report_data. This module extracts only fields at or before report_data, so it
is body-length agnostic and does not touch the signature section.

Validated against synthetic spec-layout quotes; not yet cross-checked against a
captured production quote. Version 5 quotes and non-TDX TEE types fail closed.
"""
from __future__ import annotations

from dataclasses import dataclass

_HEADER_LEN = 48
_TEE_TYPE_TDX = 0x00000081
_SUPPORTED_VERSIONS = (4,)

# Absolute byte offsets within a v4 TDX quote (48-byte header + TD report body).
_OFF_MR_TD = 184
_OFF_RTMR0 = 376
_OFF_RTMR1 = 424
_OFF_RTMR2 = 472
_OFF_RTMR3 = 520
_OFF_REPORT_DATA = 568
_END_REPORT_DATA = 632  # report_data occupies [568:632] (64 bytes)

_REGISTER_LEN = 48
_REPORT_DATA_LEN = 64


class TdxQuoteError(ValueError):
    """Raised when bytes do not parse as a supported TDX quote."""


@dataclass(frozen=True)
class TdxQuoteFields:
    """Bounded structural fields extracted from a TDX quote.

    All measurement values are raw bytes; no raw quote signature material is
    retained. `report_data` is the full 64-byte TD report field.
    """

    version: int
    tee_type: int
    mr_td: bytes
    rtmrs: tuple[bytes, bytes, bytes, bytes]
    report_data: bytes


def parse_tdx_quote(quote: bytes) -> TdxQuoteFields:
    """Structurally parse a v4 TDX quote, failing closed on anything else.

    Raises `TdxQuoteError` for non-bytes, truncated buffers, unsupported quote
    versions, or non-TDX TEE types. Does not verify the Intel signature.
    """
    if not isinstance(quote, (bytes, bytearray)):
        raise TdxQuoteError("quote must be bytes")
    quote = bytes(quote)
    if len(quote) < _END_REPORT_DATA:
        raise TdxQuoteError(
            f"quote too short for a TDX report body: {len(quote)} < {_END_REPORT_DATA}"
        )
    version = int.from_bytes(quote[0:2], "little")
    tee_type = int.from_bytes(quote[4:8], "little")
    if version not in _SUPPORTED_VERSIONS:
        raise TdxQuoteError(f"unsupported quote version {version}")
    if tee_type != _TEE_TYPE_TDX:
        raise TdxQuoteError(f"not a TDX quote (tee_type=0x{tee_type:08x})")

    def _reg(off: int) -> bytes:
        return quote[off : off + _REGISTER_LEN]

    return TdxQuoteFields(
        version=version,
        tee_type=tee_type,
        mr_td=_reg(_OFF_MR_TD),
        rtmrs=(_reg(_OFF_RTMR0), _reg(_OFF_RTMR1), _reg(_OFF_RTMR2), _reg(_OFF_RTMR3)),
        report_data=quote[_OFF_REPORT_DATA:_END_REPORT_DATA],
    )


def extract_report_data(quote: bytes) -> bytes:
    """Return the 64-byte report_data embedded in a v4 TDX quote (fail closed)."""
    return parse_tdx_quote(quote).report_data
