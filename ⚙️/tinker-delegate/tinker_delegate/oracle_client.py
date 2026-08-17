"""Client for the TEE email oracle API."""
import hashlib
import secrets

import httpx

from tinker_delegate.config import Settings
from tinker_delegate.dstack_utils import derive_storage_key, is_dstack_enabled


ORACLE_CALLER_IDENTITY = "tinker-delegate.signup"


class OracleClient:
    """Thin wrapper around the email oracle HTTP API."""

    def __init__(self, settings: Settings):
        self.base_url = settings.oracle_url.rstrip("/")
        self.auth_token = settings.oracle_auth_token or self._derive_auth_token(settings)
        self._client = httpx.Client(timeout=30.0)

    def _derive_auth_token(self, settings: Settings) -> str:
        if not is_dstack_enabled():
            return ""
        key = derive_storage_key(settings.oracle_auth_key_path)
        return hashlib.sha256(b"email-oracle-runtime-auth:" + key).hexdigest()

    def _headers(self) -> dict[str, str]:
        if not self.auth_token:
            return {}
        return {"Authorization": f"Bearer {self.auth_token}"}

    def health(self) -> dict:
        resp = self._client.get(f"{self.base_url}/health")
        resp.raise_for_status()
        data = resp.json()
        if data != {"service": "tee-email-oracle", "status": "ok"}:
            raise RuntimeError("email oracle returned a non-liveness health shape")
        return data

    def get_email_status(self) -> dict:
        """Get the oracle's commitment-only mailbox readiness receipt."""
        resp = self._client.get(f"{self.base_url}/email", headers=self._headers())
        resp.raise_for_status()
        data = resp.json()
        expected_fields = {
            "oracle_ready",
            "oracle_email_commitment",
            "commitment_scheme",
            "raw_email_egress",
            "timestamp",
        }
        if set(data) != expected_fields:
            raise RuntimeError("email oracle returned a non-allowlisted status shape")
        commitment = data.get("oracle_email_commitment")
        if (
            data.get("oracle_ready") is not True
            or data.get("commitment_scheme") != "dnai-wikigen/oracle-email/v1"
            or data.get("raw_email_egress") is not False
            or not isinstance(commitment, str)
            or len(commitment) != 64
            or any(character not in "0123456789abcdef" for character in commitment)
        ):
            raise RuntimeError("email oracle returned an invalid bounded status")
        return data

    def get_email(self) -> str:
        """Fail closed: raw mailbox addresses never leave the oracle API."""

        self.get_email_status()
        raise RuntimeError(
            "raw oracle email egress is disabled; configure TINKER_EMAIL inside the CVM"
        )

    def get_pin(
        self,
        max_age_seconds: int = 300,
        nonce: str = "",
        caller_identity: str = ORACLE_CALLER_IDENTITY,
        reason: str = "tinker-auth",
        delete_after: bool = False,
    ) -> dict | None:
        """Poll for a PIN/OTP from the inbox.

        Returns dict with 'pin' key on success, None if no matching email found.
        """
        if caller_identity != ORACLE_CALLER_IDENTITY:
            raise ValueError("unsupported email-oracle caller identity")
        resp = self._client.post(
            f"{self.base_url}/pin",
            headers=self._headers(),
            json={
                "target_service": "tinker",
                "expected_sender": "no-reply@thinkingmachines.ai",
                "expected_subject_contains": "",
                "max_age_seconds": max_age_seconds,
                "extract_pattern": r"\b\d{6}\b",
                "nonce": nonce or secrets.token_urlsafe(24),
                "caller_identity": caller_identity,
                "reason": reason,
                "delete_after": delete_after,
            },
        )
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        data = resp.json()
        expected_fields = {
            "pin",
            "request_hash",
            "attestation_report_data",
            "tdx_quote",
        }
        if set(data) != expected_fields:
            raise RuntimeError("email oracle returned a non-allowlisted OTP shape")
        pin = data.get("pin")
        if (
            not isinstance(pin, str)
            or len(pin) != 6
            or not pin.isascii()
            or not pin.isdigit()
        ):
            raise RuntimeError("email oracle returned an invalid OTP")
        for field in ("request_hash", "attestation_report_data"):
            value = data.get(field)
            if (
                not isinstance(value, str)
                or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
            ):
                raise RuntimeError(f"email oracle returned an invalid {field}")
        quote = data.get("tdx_quote")
        if not isinstance(quote, str) or len(quote) > 262_144:
            raise RuntimeError("email oracle returned an invalid TDX quote")
        quote_hex = quote[2:] if quote.startswith("0x") else quote
        if quote_hex and (
            len(quote_hex) % 2 != 0
            or any(character not in "0123456789abcdefABCDEF" for character in quote_hex)
        ):
            raise RuntimeError("email oracle returned an invalid TDX quote")
        return data

    def list_inbox(self, count: int = 5) -> list:
        """Fail closed: the oracle has no mailbox-listing API."""

        del count
        raise RuntimeError(
            "mailbox listing is permanently disabled; use the scoped OTP capability"
        )
