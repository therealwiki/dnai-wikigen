"""IMAP client for polling inbox and extracting verification pins."""

import email
import imaplib
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.header import decode_header


from email_oracle.config import Settings
from email_oracle.cred_store import EmailCredentials
from email_oracle.redaction import hash_text


@dataclass
class ExtractedPin:
    pin: str
    email_id: str
    subject: str
    sender: str
    received_at: str
    body_snippet: str


class IMAPClient:
    """Long-lived IMAP connection for pin extraction."""

    def __init__(self, creds: EmailCredentials, settings: Settings):
        self.creds = creds
        self.settings = settings
        self._conn: imaplib.IMAP4_SSL | None = None

    def connect(self) -> None:
        """Establish IMAP connection."""
        print(f"[imap] connecting to {self.settings.cockli_imap_host}:{self.settings.cockli_imap_port}")
        self._conn = imaplib.IMAP4_SSL(
            self.settings.cockli_imap_host,
            self.settings.cockli_imap_port,
        )
        self._conn.login(self.creds.imap_login, self.creds.password)
        self._conn.select("INBOX")
        print("[imap] connected and selected INBOX")

    def disconnect(self) -> None:
        if self._conn:
            try:
                self._conn.close()
                self._conn.logout()
            except Exception:
                pass
            self._conn = None

    def _ensure_connected(self) -> imaplib.IMAP4_SSL:
        if self._conn is None:
            self.connect()
        # NOOP to check connection is alive
        try:
            self._conn.noop()
        except Exception:
            print("[imap] connection lost, reconnecting")
            self.connect()
        return self._conn

    def _decode_header(self, raw: str | None) -> str:
        if not raw:
            return ""
        parts = decode_header(raw)
        decoded = []
        for part, charset in parts:
            if isinstance(part, bytes):
                decoded.append(part.decode(charset or "utf-8", errors="replace"))
            else:
                decoded.append(part)
        return " ".join(decoded)

    def _extract_body(self, msg: email.message.Message) -> str:
        """Extract plain text body from email message."""
        if msg.is_multipart():
            for part in msg.walk():
                ct = part.get_content_type()
                if ct == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        return payload.decode(charset, errors="replace")
                elif ct == "text/html":
                    # Strip HTML tags as last resort
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        html = payload.decode(charset, errors="replace")
                        return re.sub(r"<[^>]+>", " ", html)
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                return payload.decode(charset, errors="replace")
        return ""

    def search_and_extract(
        self,
        from_filter: str = "",
        subject_contains: str = "",
        max_age_seconds: int = 300,
        extract_pattern: str = r"\b\d{6}\b",
    ) -> ExtractedPin | None:
        """Search inbox for matching emails and extract a pin.

        Args:
            from_filter: Filter by sender address (substring match)
            subject_contains: Filter by subject (substring match)
            max_age_seconds: Only consider emails newer than this
            extract_pattern: Regex pattern to extract the pin from body

        Returns:
            ExtractedPin if found, None otherwise.
        """
        conn = self._ensure_connected()

        # Build IMAP search criteria
        criteria = []
        if from_filter:
            criteria.append(f'FROM "{from_filter}"')
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=max_age_seconds)
        criteria.append(f'SINCE "{cutoff.strftime("%d-%b-%Y")}"')

        search_str = " ".join(criteria) if criteria else "ALL"
        print(
            "[imap] searching "
            f"from_filter_set={bool(from_filter)} "
            f"from_filter_hash={hash_text(from_filter) if from_filter else ''} "
            f"subject_filter_set={bool(subject_contains)} "
            f"subject_filter_hash={hash_text(subject_contains) if subject_contains else ''} "
            f"max_age_seconds={max_age_seconds}"
        )

        _, data = conn.search(None, search_str)
        msg_ids = data[0].split() if data[0] else []

        if not msg_ids:
            print("[imap] no matching emails found")
            return None

        # Process newest first
        for msg_id in reversed(msg_ids):
            _, msg_data = conn.fetch(msg_id, "(RFC822)")
            if not msg_data or not msg_data[0]:
                continue

            raw_email = msg_data[0][1]
            msg = email.message_from_bytes(raw_email)

            # Decode headers
            subject = self._decode_header(msg.get("Subject"))
            sender = self._decode_header(msg.get("From"))
            date_str = msg.get("Date", "")

            # Subject filter
            if subject_contains and subject_contains.lower() not in subject.lower():
                continue

            # Extract body
            body = self._extract_body(msg)

            # Try to extract pin
            match = re.search(extract_pattern, body)
            if match:
                pin = match.group()
                print(
                    "[imap] extracted pin from matching email "
                    f"subject_hash={hash_text(subject)} sender_hash={hash_text(sender)}"
                )
                return ExtractedPin(
                    pin=pin,
                    email_id=msg_id.decode() if isinstance(msg_id, bytes) else str(msg_id),
                    subject=subject,
                    sender=sender,
                    received_at=date_str,
                    body_snippet=body[:200],
                )

        print("[imap] no pin found in matching emails")
        return None

    def list_recent(self, max_age_seconds: int = 3600, limit: int = 20) -> list[dict]:
        """List recent emails (for debugging / health check)."""
        conn = self._ensure_connected()

        cutoff = datetime.now(timezone.utc) - timedelta(seconds=max_age_seconds)
        _, data = conn.search(None, f'SINCE "{cutoff.strftime("%d-%b-%Y")}"')
        msg_ids = data[0].split() if data[0] else []

        results = []
        for msg_id in reversed(msg_ids[-limit:]):
            _, msg_data = conn.fetch(msg_id, "(RFC822 FLAGS)")
            if not msg_data or not msg_data[0]:
                continue
            raw_email = msg_data[0][1]
            msg = email.message_from_bytes(raw_email)
            results.append({
                "id": msg_id.decode() if isinstance(msg_id, bytes) else str(msg_id),
                "from": self._decode_header(msg.get("From")),
                "subject": self._decode_header(msg.get("Subject")),
                "date": msg.get("Date", ""),
            })

        return results

    def delete_email(self, email_id: str) -> None:
        """Mark email as deleted and expunge."""
        conn = self._ensure_connected()
        conn.store(email_id.encode(), "+FLAGS", "\\Deleted")
        conn.expunge()
        print(f"[imap] deleted email {email_id}")
