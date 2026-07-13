"""Tests for the structural TDX (DCAP v4) quote parser and its use as a
fail-closed report-data binding check in the attestation verifier.

Synthetic quotes place each field at its LITERAL absolute offset (independent
of the parser's own offset constants), so a divergence between the two fails.
"""
import unittest

from tinker_delegate.attestation_verifier import (
    AttestationPolicy,
    AttestationVerificationError,
    verify_attestation_envelope,
)
from tinker_delegate.card_channel import get_attestation
from tinker_delegate.tdx_quote import TdxQuoteError, extract_report_data, parse_tdx_quote

_TEE_TYPE_TDX = 0x00000081


def _synthetic_tdx_quote(
    *,
    report_data: bytes,
    mr_td: bytes = b"\x11" * 48,
    rtmrs=(b"\x20" * 48, b"\x21" * 48, b"\x22" * 48, b"\x23" * 48),
    version: int = 4,
    tee_type: int = _TEE_TYPE_TDX,
    total_len: int = 700,
) -> bytes:
    """Build a spec-layout v4 TDX quote with fields at their literal offsets."""
    assert len(report_data) == 64
    buf = bytearray(b"\x00" * total_len)
    buf[0:2] = version.to_bytes(2, "little")
    buf[4:8] = tee_type.to_bytes(4, "little")
    buf[184:232] = mr_td
    buf[376:424] = rtmrs[0]
    buf[424:472] = rtmrs[1]
    buf[472:520] = rtmrs[2]
    buf[520:568] = rtmrs[3]
    buf[568:632] = report_data
    return bytes(buf)


class TdxQuoteParserTest(unittest.TestCase):
    def test_extracts_report_data_and_registers_at_spec_offsets(self):
        report_data = bytes(range(64))
        quote = _synthetic_tdx_quote(
            report_data=report_data,
            mr_td=b"\xab" * 48,
            rtmrs=(b"\x01" * 48, b"\x02" * 48, b"\x03" * 48, b"\x04" * 48),
        )
        fields = parse_tdx_quote(quote)
        self.assertEqual(fields.version, 4)
        self.assertEqual(fields.tee_type, _TEE_TYPE_TDX)
        self.assertEqual(fields.report_data, report_data)
        self.assertEqual(fields.mr_td, b"\xab" * 48)
        self.assertEqual(fields.rtmrs[0], b"\x01" * 48)
        self.assertEqual(fields.rtmrs[3], b"\x04" * 48)
        self.assertEqual(extract_report_data(quote), report_data)

    def test_rejects_unsupported_version(self):
        quote = _synthetic_tdx_quote(report_data=b"\x00" * 64, version=5)
        with self.assertRaisesRegex(TdxQuoteError, "unsupported quote version 5"):
            parse_tdx_quote(quote)

    def test_rejects_non_tdx_tee_type(self):
        quote = _synthetic_tdx_quote(report_data=b"\x00" * 64, tee_type=0x00000000)
        with self.assertRaisesRegex(TdxQuoteError, "not a TDX quote"):
            parse_tdx_quote(quote)

    def test_rejects_truncated_quote(self):
        quote = _synthetic_tdx_quote(report_data=b"\x00" * 64)[:600]
        with self.assertRaisesRegex(TdxQuoteError, "too short"):
            parse_tdx_quote(quote)

    def test_rejects_non_bytes(self):
        with self.assertRaisesRegex(TdxQuoteError, "must be bytes"):
            parse_tdx_quote("not-bytes")  # type: ignore[arg-type]


def _tdx_envelope_with_real_quote(**quote_kwargs) -> dict:
    """A valid tdx envelope whose `quote` embeds the envelope's report_data."""
    attestation = get_attestation("artifact")
    attestation.update({
        "mode": "tdx",
        "verified": True,
        "compose_hash": "compose-ok",
        "app_id": "app-ok",
        "os_image_hash": "os-ok",
    })
    rd32 = bytes.fromhex(attestation["report_data"])
    quote = _synthetic_tdx_quote(report_data=rd32 + b"\x00" * 32, **quote_kwargs)
    attestation["quote"] = quote.hex()
    return attestation


class AttestationQuoteBindingTest(unittest.TestCase):
    def _policy(self) -> AttestationPolicy:
        return AttestationPolicy(expected_compose_hash="compose-ok")

    def test_accepts_matching_embedded_report_data(self):
        attestation = _tdx_envelope_with_real_quote()
        result = verify_attestation_envelope(
            attestation, self._policy(), enforce_quote_binding=True
        )
        self.assertEqual(result.report_data, attestation["report_data"])

    def test_rejects_embedded_report_data_mismatch(self):
        attestation = _tdx_envelope_with_real_quote()
        # Corrupt the report_data embedded in the quote (flip a byte at offset 568).
        raw = bytearray(bytes.fromhex(attestation["quote"]))
        raw[568] ^= 0xFF
        attestation["quote"] = bytes(raw).hex()
        with self.assertRaisesRegex(AttestationVerificationError, "embedded in the quote"):
            verify_attestation_envelope(attestation, self._policy(), enforce_quote_binding=True)

    def test_rejects_unparseable_quote_when_enforced(self):
        attestation = _tdx_envelope_with_real_quote(version=5)
        with self.assertRaisesRegex(AttestationVerificationError, "does not parse as a TDX"):
            verify_attestation_envelope(attestation, self._policy(), enforce_quote_binding=True)

    def test_default_off_ignores_unparseable_quote(self):
        # Opaque simulator quote; enforcement off (default) must still pass.
        attestation = get_attestation("artifact")
        attestation.update({
            "mode": "tdx", "verified": True, "quote": "aa",
            "compose_hash": "compose-ok", "app_id": "app-ok", "os_image_hash": "os-ok",
        })
        result = verify_attestation_envelope(attestation, self._policy())
        self.assertEqual(result.mode, "tdx")


if __name__ == "__main__":
    unittest.main()
