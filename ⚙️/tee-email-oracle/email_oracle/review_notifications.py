"""Internal, release-bound Human Review email notifications.

The public delegate never receives reviewer email addresses.  It submits one
hash-only ticket reference and exact release binding to this internal router;
this module resolves a role-to-recipient policy delivered through Phala's
encrypted environment, authorizes the measured email-oracle consumer on Base
Sepolia, and sends a fixed-content message. Public descriptors commit only the
encrypted-environment key name and canonical policy digest, never recipient
values. The decrypted policy exists only in the measured CVM process.

Delivery uses conservative at-most-once semantics.  A durable authenticated
receipt is reserved immediately before the SMTP DATA operation.  If the
process or transport cannot prove whether SMTP accepted the message, the
receipt remains ``ambiguous`` and the same idempotency key is never sent again
automatically.
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import smtplib
import ssl
import stat
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, replace
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Iterator, Protocol

from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.routing import APIRoute
from pydantic import BaseModel, Field, SecretStr, ValidationError, model_validator
from starlette.responses import JSONResponse, Response

from email_oracle.chain_auth import check_consumer_authorization
from email_oracle.config import Settings
from email_oracle.cred_store import EmailCredentials
from email_oracle.dstack_utils import derive_storage_key


REVIEW_NOTIFICATION_CALLER_IDENTITY = "tinker-delegate.review-operations"
REVIEW_NOTIFICATION_REQUEST_SCHEMA = "dnai.review-notification-request.v1"
REVIEW_NOTIFICATION_RECEIPT_SCHEMA = "dnai.review-notification-receipt.v1"
REVIEW_NOTIFICATION_RECIPIENTS_SCHEMA = "dnai.review-notification-recipients.v1"
REVIEW_NOTIFICATION_STORE_SCHEMA = "dnai.review-notification-receipt-store.v1"
REVIEW_NOTIFICATION_IDEMPOTENCY_DOMAIN = (
    b"dnai-wikigen/review-notification-idempotency/v1\0"
)
REVIEW_NOTIFICATION_RECIPIENTS_DOMAIN = (
    b"dnai-wikigen/review-notification-recipients/v1\0"
)
REVIEW_NOTIFICATION_RECEIPT_DOMAIN = (
    b"dnai-wikigen/review-notification-receipt/v1\0"
)
REVIEW_NOTIFICATION_STORE_DOMAIN = (
    b"dnai-wikigen/review-notification-receipt-store/v1\0"
)
REVIEW_NOTIFICATION_ROLES = frozenset(
    {
        "access-review-officer",
        "expert-in-the-loop",
        "biosecurity-review",
        "ethics-legal-reviewer",
    }
)
_EMAIL_LOCAL = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}$")
_DNS_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_HASH = re.compile(r"^[0-9a-f]{64}$")
_SHA256 = re.compile(r"^sha256:(?!0{64}$)[0-9a-f]{64}$")
_BYTES32 = re.compile(r"^0x(?!0{64}$)[0-9a-f]{64}$")
_MAX_REQUEST_BYTES = 16_384
_MAX_STORE_BYTES = 8 * 1024 * 1024
_MAX_RECEIPTS = 100_000
_NO_STORE_CACHE_CONTROL = "no-store, max-age=0"


class ReviewNotificationError(ValueError):
    """The request, release binding, recipient policy, or receipt is invalid."""


class ReviewNotificationUnavailable(RuntimeError):
    """Notification delivery could not safely begin and may be retried later."""


class ReviewNotificationAmbiguous(RuntimeError):
    """SMTP delivery may have happened; automatic retry is forbidden."""


class ReviewNotificationRequest(BaseModel):
    schema_value: str = Field(
        alias="schema",
        pattern=r"^dnai\.review-notification-request\.v1$",
    )
    event: str = Field(pattern=r"^pending$")
    ticket_ref_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    routed_role: str = Field(min_length=2, max_length=64)
    opened_at: int = Field(ge=1, strict=True)
    expires_at: int = Field(ge=1, strict=True)
    authority_context_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    release_binding: dict[str, Any]
    idempotency_key: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_exact_request(self) -> "ReviewNotificationRequest":
        if self.routed_role not in REVIEW_NOTIFICATION_ROLES:
            raise ValueError("unsupported review role")
        if self.expires_at <= self.opened_at:
            raise ValueError("review expiry must follow opening")
        expected = review_notification_idempotency_key(self.unsigned_dict())
        if not hmac.compare_digest(self.idempotency_key, expected):
            raise ValueError("notification idempotency key is invalid")
        return self

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema_value,
            "event": self.event,
            "ticket_ref_hash": self.ticket_ref_hash,
            "routed_role": self.routed_role,
            "opened_at": self.opened_at,
            "expires_at": self.expires_at,
            "authority_context_hash": self.authority_context_hash,
            "release_binding": self.release_binding,
        }

    model_config = {"extra": "forbid", "populate_by_name": True}


class ReviewNotificationReceipt(BaseModel):
    schema_value: str = Field(
        REVIEW_NOTIFICATION_RECEIPT_SCHEMA,
        alias="schema",
    )
    idempotency_key: str = Field(pattern=r"^[0-9a-f]{64}$")
    receipt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    status: str = Field(pattern=r"^delivered$")
    idempotent: bool
    raw_review_reason_egress: bool = False
    raw_artifact_egress: bool = False
    raw_reviewer_identity_egress: bool = False

    model_config = {"extra": "forbid", "populate_by_name": True}


@dataclass(frozen=True)
class ReviewNotificationRecord:
    idempotency_key: str
    request_sha256: str
    status: str
    reserved_at: int
    delivered_at: int = 0
    receipt_sha256: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "idempotency_key": self.idempotency_key,
            "request_sha256": self.request_sha256,
            "status": self.status,
            "reserved_at": self.reserved_at,
            "delivered_at": self.delivered_at,
            "receipt_sha256": self.receipt_sha256,
        }


@dataclass(frozen=True)
class ReviewRecipientPolicy:
    recipients_by_role: dict[str, tuple[str, ...]]
    policy_sha256: str

    def recipients_for_role(self, role: str) -> tuple[str, ...]:
        try:
            return self.recipients_by_role[role]
        except KeyError as exc:
            raise ReviewNotificationError("notification role has no recipients") from exc


class SMTPConnection(Protocol):
    def send_message(
        self,
        message: EmailMessage,
        *,
        from_addr: str,
        to_addrs: list[str],
    ) -> Any:
        """Submit one complete SMTP transaction."""


class NotificationMailer(Protocol):
    @contextmanager
    def connect(
        self,
        credentials: EmailCredentials,
    ) -> Iterator[SMTPConnection]:
        """Authenticate before the receipt is reserved."""


class SmtpNotificationMailer:
    def __init__(self, settings: Settings) -> None:
        self.host = settings.review_notification_smtp_host
        self.port = settings.review_notification_smtp_port
        self.timeout = settings.review_notification_smtp_timeout_seconds

    @contextmanager
    def connect(
        self,
        credentials: EmailCredentials,
    ) -> Iterator[SMTPConnection]:
        connection: smtplib.SMTP_SSL | None = None
        try:
            connection = smtplib.SMTP_SSL(
                self.host,
                self.port,
                timeout=self.timeout,
                context=ssl.create_default_context(),
            )
            connection.login(credentials.imap_login, credentials.password)
            yield connection
        except (OSError, smtplib.SMTPException, TimeoutError) as exc:
            raise ReviewNotificationUnavailable(
                "SMTP notification boundary is unavailable"
            ) from exc
        finally:
            if connection is not None:
                try:
                    connection.quit()
                except Exception:
                    try:
                        connection.close()
                    except Exception:
                        pass


class ReviewNotificationReceiptStore:
    """Authenticated, crash-conservative idempotency receipts."""

    def __init__(self, path: str | Path, key: bytes) -> None:
        if not isinstance(key, bytes) or len(key) != 32:
            raise ReviewNotificationUnavailable("notification receipt key is unavailable")
        self.path = Path(path)
        self.key = key
        self._thread_lock = threading.Lock()

    def reserve(
        self,
        *,
        idempotency_key: str,
        request_sha256: str,
        now: int,
    ) -> tuple[ReviewNotificationRecord, bool]:
        _require_hash(idempotency_key, "notification idempotency key")
        _require_hash(request_sha256, "notification request digest")
        with self._lease():
            records = self._load_unlocked()
            existing = records.get(idempotency_key)
            if existing is not None:
                if not hmac.compare_digest(existing.request_sha256, request_sha256):
                    raise ReviewNotificationError(
                        "notification idempotency identity is already bound"
                    )
                return existing, True
            if len(records) >= _MAX_RECEIPTS:
                raise ReviewNotificationUnavailable(
                    "notification receipt capacity is exhausted"
                )
            # Ambiguous is the safe durable pre-send state. A crash at any point
            # after this write can suppress a notification, but cannot duplicate it.
            record = ReviewNotificationRecord(
                idempotency_key=idempotency_key,
                request_sha256=request_sha256,
                status="ambiguous",
                reserved_at=int(now),
            )
            records[idempotency_key] = record
            self._write_unlocked(records)
            return record, False

    def mark_delivered(
        self,
        *,
        idempotency_key: str,
        request_sha256: str,
        receipt_sha256: str,
        now: int,
    ) -> ReviewNotificationRecord:
        _require_hash(receipt_sha256, "notification receipt digest")
        with self._lease():
            records = self._load_unlocked()
            record = records.get(idempotency_key)
            if (
                record is None
                or not hmac.compare_digest(record.request_sha256, request_sha256)
            ):
                raise ReviewNotificationAmbiguous(
                    "notification receipt reservation is unavailable"
                )
            if record.status == "delivered":
                if not hmac.compare_digest(record.receipt_sha256, receipt_sha256):
                    raise ReviewNotificationError(
                        "notification receipt identity changed"
                    )
                return record
            if record.status != "ambiguous":
                raise ReviewNotificationError("notification receipt status is invalid")
            delivered = replace(
                record,
                status="delivered",
                delivered_at=int(now),
                receipt_sha256=receipt_sha256,
            )
            records[idempotency_key] = delivered
            self._write_unlocked(records)
            return delivered

    @contextmanager
    def _lease(self) -> Iterator[None]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self.path.with_name(f".{self.path.name}.lock")
        with self._thread_lock:
            descriptor = -1
            try:
                flags = (
                    os.O_RDWR
                    | os.O_CREAT
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0)
                )
                descriptor = os.open(lock_path, flags, 0o600)
                details = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(details.st_mode)
                    or stat.S_IMODE(details.st_mode) != 0o600
                    or details.st_uid != os.geteuid()
                    or details.st_nlink != 1
                ):
                    raise ReviewNotificationUnavailable(
                        "notification receipt lease is invalid"
                    )
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                yield
            except (ReviewNotificationError, ReviewNotificationUnavailable):
                raise
            except OSError as exc:
                raise ReviewNotificationUnavailable(
                    "notification receipt lease is unavailable"
                ) from exc
            finally:
                if descriptor >= 0:
                    try:
                        fcntl.flock(descriptor, fcntl.LOCK_UN)
                    finally:
                        os.close(descriptor)

    def _load_unlocked(self) -> dict[str, ReviewNotificationRecord]:
        try:
            descriptor = os.open(
                self.path,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
        except FileNotFoundError:
            return {}
        except OSError as exc:
            raise ReviewNotificationUnavailable(
                "notification receipt store is unavailable"
            ) from exc
        try:
            details = os.fstat(descriptor)
            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_size <= 0
                or details.st_size > _MAX_STORE_BYTES
                or details.st_uid != os.geteuid()
                or details.st_nlink != 1
            ):
                raise ReviewNotificationUnavailable(
                    "notification receipt store is invalid"
                )
            raw = b""
            remaining = _MAX_STORE_BYTES + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(65_536, remaining))
                if not chunk:
                    break
                raw += chunk
                remaining -= len(chunk)
        finally:
            os.close(descriptor)
        if len(raw) > _MAX_STORE_BYTES:
            raise ReviewNotificationUnavailable(
                "notification receipt store is too large"
            )
        try:
            document = json.loads(
                raw,
                object_pairs_hook=_reject_duplicate_json_keys,
            )
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            RecursionError,
            ReviewNotificationError,
            ValueError,
        ) as exc:
            raise ReviewNotificationUnavailable(
                "notification receipt store is invalid"
            ) from exc
        if (
            not isinstance(document, dict)
            or set(document) != {"schema", "records", "integrity"}
            or document.get("schema") != REVIEW_NOTIFICATION_STORE_SCHEMA
            or not isinstance(document.get("records"), list)
            or len(document["records"]) > _MAX_RECEIPTS
            or not isinstance(document.get("integrity"), str)
        ):
            raise ReviewNotificationUnavailable(
                "notification receipt store is invalid"
            )
        unsigned = {
            "schema": document["schema"],
            "records": document["records"],
        }
        expected_integrity = _store_integrity(unsigned, self.key)
        if not hmac.compare_digest(document["integrity"], expected_integrity):
            raise ReviewNotificationUnavailable(
                "notification receipt store integrity failed"
            )
        records: dict[str, ReviewNotificationRecord] = {}
        for item in document["records"]:
            record = _record_from_dict(item)
            if record.idempotency_key in records:
                raise ReviewNotificationUnavailable(
                    "notification receipt store contains duplicates"
                )
            records[record.idempotency_key] = record
        return records

    def _write_unlocked(
        self,
        records: dict[str, ReviewNotificationRecord],
    ) -> None:
        ordered = [
            records[key].to_dict()
            for key in sorted(records)
        ]
        unsigned = {
            "schema": REVIEW_NOTIFICATION_STORE_SCHEMA,
            "records": ordered,
        }
        document = {
            **unsigned,
            "integrity": _store_integrity(unsigned, self.key),
        }
        payload = (
            json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("ascii")
        if len(payload) > _MAX_STORE_BYTES:
            raise ReviewNotificationUnavailable(
                "notification receipt store is too large"
            )
        directory = -1
        temporary_name = f".{self.path.name}.{secrets.token_hex(12)}.tmp"
        try:
            directory = os.open(
                self.path.parent,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
            descriptor = os.open(
                temporary_name,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                0o600,
                dir_fd=directory,
            )
            try:
                view = memoryview(payload)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise OSError("short receipt-store write")
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            try:
                current = os.stat(
                    self.path.name,
                    dir_fd=directory,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                current = None
            if current is not None and (
                not stat.S_ISREG(current.st_mode)
                or current.st_uid != os.geteuid()
                or current.st_nlink != 1
            ):
                raise ReviewNotificationUnavailable(
                    "notification receipt store target is invalid"
                )
            os.replace(
                temporary_name,
                self.path.name,
                src_dir_fd=directory,
                dst_dir_fd=directory,
            )
            os.fsync(directory)
        except ReviewNotificationUnavailable:
            raise
        except OSError as exc:
            raise ReviewNotificationUnavailable(
                "notification receipt store could not be persisted"
            ) from exc
        finally:
            if directory >= 0:
                try:
                    os.unlink(temporary_name, dir_fd=directory)
                except FileNotFoundError:
                    pass
                except OSError:
                    pass
                os.close(directory)


class ReviewNotificationService:
    def __init__(
        self,
        settings: Settings,
        credentials: EmailCredentials,
        *,
        store: ReviewNotificationReceiptStore | None = None,
        mailer: NotificationMailer | None = None,
        clock=time.time,
    ) -> None:
        if not settings.review_notifications_enabled:
            raise ReviewNotificationUnavailable("review notifications are disabled")
        self.settings = settings
        self.credentials = credentials
        self.sender = _normalize_email(credentials.email)
        self.policy = review_recipient_policy(settings)
        self.store = store or ReviewNotificationReceiptStore(
            settings.review_notification_receipt_store_path,
            review_notification_receipt_key(settings),
        )
        self.mailer = mailer or SmtpNotificationMailer(settings)
        self.clock = clock

    def deliver(
        self,
        request: ReviewNotificationRequest,
    ) -> ReviewNotificationReceipt:
        _validate_release_binding(request.release_binding, self.settings)
        request_sha256 = hashlib.sha256(
            b"dnai-wikigen/review-notification-request/v1\0"
            + _canonical_json(request.model_dump(by_alias=True))
        ).hexdigest()
        recipients = self.policy.recipients_for_role(request.routed_role)
        message = _review_notification_message(
            request,
            sender=self.sender,
        )

        # SMTP connection/auth occurs before reservation. Failures here are
        # known-pre-send and may safely be retried with the same key.
        with self.mailer.connect(self.credentials) as connection:
            record, existing = self.store.reserve(
                idempotency_key=request.idempotency_key,
                request_sha256=request_sha256,
                now=int(self.clock()),
            )
            if existing:
                if record.status == "delivered":
                    return _public_receipt(record, idempotent=True)
                raise ReviewNotificationAmbiguous(
                    "notification delivery outcome is ambiguous"
                )
            try:
                refused = connection.send_message(
                    message,
                    from_addr=self.sender,
                    to_addrs=list(recipients),
                )
                # smtplib returns a mapping for recipients rejected after the
                # transaction begins. Some recipients may already have
                # accepted the message, so the only safe state is ambiguous:
                # never claim full delivery and never retry automatically.
                if refused:
                    raise ReviewNotificationAmbiguous(
                        "notification delivery outcome is ambiguous"
                    )
            except Exception as exc:
                # The durable reservation intentionally remains ambiguous.
                raise ReviewNotificationAmbiguous(
                    "notification delivery outcome is ambiguous"
                ) from exc

        receipt_sha256 = hashlib.sha256(
            REVIEW_NOTIFICATION_RECEIPT_DOMAIN
            + _canonical_json(
                {
                    "idempotency_key": request.idempotency_key,
                    "request_sha256": request_sha256,
                    "status": "delivered",
                }
            )
        ).hexdigest()
        record = self.store.mark_delivered(
            idempotency_key=request.idempotency_key,
            request_sha256=request_sha256,
            receipt_sha256=receipt_sha256,
            now=int(self.clock()),
        )
        return _public_receipt(record, idempotent=False)


class _ReviewNotificationNoStoreRoute(APIRoute):
    """Keep every bounded endpoint response out of intermediary caches."""

    def get_route_handler(self):  # type: ignore[no-untyped-def]
        route_handler = super().get_route_handler()

        async def no_store_route_handler(request: Request) -> Response:
            try:
                response = await route_handler(request)
            except HTTPException as exc:
                # FastAPI discards headers assigned to an injected Response
                # when an HTTPException is raised. Materialize the bounded
                # error here so success and every intentional error share the
                # exact same cache policy.
                headers = dict(exc.headers or {})
                headers["Cache-Control"] = _NO_STORE_CACHE_CONTROL
                return JSONResponse(
                    status_code=exc.status_code,
                    content={"detail": exc.detail},
                    headers=headers,
                )
            response.headers["Cache-Control"] = _NO_STORE_CACHE_CONTROL
            return response

        return no_store_route_handler


router = APIRouter(route_class=_ReviewNotificationNoStoreRoute)
_notification_service: ReviewNotificationService | None = None
_notification_service_lock = threading.Lock()


@router.post(
    "/review/notifications",
    response_model=ReviewNotificationReceipt,
    response_model_exclude_none=True,
)
async def send_review_notification(
    request: Request,
    authorization: str = Header(default=""),
) -> ReviewNotificationReceipt:
    """Send one fixed, hash-only reviewer notification inside the oracle."""

    # Imported lazily to keep the router independently testable and avoid a
    # module-import cycle while email_oracle.api constructs the FastAPI app.
    from email_oracle import api as oracle_api

    settings = oracle_api.state.settings
    if settings is None or not settings.review_notifications_enabled:
        raise HTTPException(503, "Review notification delivery is unavailable")
    if not oracle_api._runtime_auth_enabled():
        raise HTTPException(503, "Review notification runtime auth is unavailable")
    oracle_api.require_runtime_auth(authorization)
    if not hmac.compare_digest(
        settings.review_notification_caller_identity,
        REVIEW_NOTIFICATION_CALLER_IDENTITY,
    ):
        raise HTTPException(
            503,
            "Review notification release authorization is unavailable",
        )

    content_length = request.headers.get("content-length", "")
    if content_length:
        try:
            declared = int(content_length)
        except ValueError:
            raise HTTPException(400, "Review notification request is invalid") from None
        if declared < 0 or declared > _MAX_REQUEST_BYTES:
            raise HTTPException(413, "Review notification request is too large")
    raw = await _read_bounded_request_body(request)
    try:
        document = json.loads(raw, object_pairs_hook=_reject_duplicate_json_keys)
        parsed = ReviewNotificationRequest.model_validate(document)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ValidationError,
        ReviewNotificationError,
        ValueError,
    ):
        # Pydantic's default 422 body includes submitted values. This generic
        # response cannot echo an attempted reason, artifact, or identity.
        raise HTTPException(400, "Review notification request is invalid") from None

    authorization_settings = settings.model_copy(
        update={
            "auth_expected_caller_identity": (
                settings.review_notification_caller_identity
            )
        }
    )
    try:
        consumer = check_consumer_authorization(
            authorization_settings,
            caller_identity=REVIEW_NOTIFICATION_CALLER_IDENTITY,
            required=True,
        )
    except Exception:
        raise HTTPException(
            503,
            "Review notification release authorization is unavailable",
        ) from None
    if getattr(consumer, "checked", False) is not True:
        raise HTTPException(
            503,
            "Review notification release authorization is unavailable",
        )
    if getattr(consumer, "allowed", False) is not True:
        raise HTTPException(
            403,
            "Review notification release authorization was denied",
        )
    if oracle_api.state.creds is None:
        raise HTTPException(503, "Review notification delivery is unavailable")

    try:
        service = _review_notification_service(
            settings,
            oracle_api.state.creds,
        )
        receipt = service.deliver(parsed)
    except ReviewNotificationAmbiguous:
        raise HTTPException(
            409,
            "Review notification delivery is ambiguous; automatic retry is held",
        ) from None
    except ReviewNotificationError:
        raise HTTPException(409, "Review notification request was rejected") from None
    except ReviewNotificationUnavailable:
        raise HTTPException(503, "Review notification delivery is unavailable") from None
    return receipt


def reset_review_notification_service() -> None:
    """Test/startup helper; production configuration is immutable per process."""

    global _notification_service
    with _notification_service_lock:
        _notification_service = None


async def _read_bounded_request_body(request: Request) -> bytes:
    chunks: list[bytes] = []
    received = 0
    async for chunk in request.stream():
        received += len(chunk)
        if received > _MAX_REQUEST_BYTES:
            # Do not call request.body(): chunked/no-length inputs must be
            # rejected as soon as the cap is crossed, before the remainder is
            # buffered in CVM memory.
            raise HTTPException(413, "Review notification request is too large")
        if chunk:
            chunks.append(chunk)
    if received == 0:
        raise HTTPException(400, "Review notification request is invalid")
    return b"".join(chunks)


def _review_notification_service(
    settings: Settings,
    credentials: EmailCredentials,
) -> ReviewNotificationService:
    global _notification_service
    with _notification_service_lock:
        if _notification_service is None:
            _notification_service = ReviewNotificationService(
                settings,
                credentials,
            )
        return _notification_service


def review_recipient_policy(settings: Settings) -> ReviewRecipientPolicy:
    configured = settings.review_notification_recipients_json
    raw = (
        configured.get_secret_value()
        if isinstance(configured, SecretStr)
        else configured
    )
    expected_sha256 = settings.review_notification_recipients_sha256
    if (
        not isinstance(raw, str)
        or not raw
        or len(raw.encode("utf-8")) > 65_536
        or not _SHA256.fullmatch(expected_sha256)
    ):
        raise ReviewNotificationUnavailable(
            "review notification recipients are unavailable"
        )
    try:
        document = json.loads(raw, object_pairs_hook=_reject_duplicate_json_keys)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ReviewNotificationError,
        ValueError,
    ) as exc:
        raise ReviewNotificationUnavailable(
            "review notification recipients are invalid"
        ) from exc
    if (
        not isinstance(document, dict)
        or set(document) != {"schema", "roles"}
        or document.get("schema") != REVIEW_NOTIFICATION_RECIPIENTS_SCHEMA
        or not isinstance(document.get("roles"), list)
        or len(document["roles"]) != len(REVIEW_NOTIFICATION_ROLES)
    ):
        raise ReviewNotificationUnavailable(
            "review notification recipients are invalid"
        )
    recipients_by_role: dict[str, tuple[str, ...]] = {}
    normalized_roles: list[dict[str, Any]] = []
    all_recipients: set[str] = set()
    for entry in document["roles"]:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"role", "recipients"}
            or entry.get("role") not in REVIEW_NOTIFICATION_ROLES
            or entry["role"] in recipients_by_role
            or not isinstance(entry.get("recipients"), list)
            or not 1 <= len(entry["recipients"]) <= 16
        ):
            raise ReviewNotificationUnavailable(
                "review notification recipients are invalid"
            )
        normalized = tuple(
            sorted(_normalize_email(value) for value in entry["recipients"])
        )
        if len(set(normalized)) != len(normalized):
            raise ReviewNotificationUnavailable(
                "review notification recipients are invalid"
            )
        all_recipients.update(normalized)
        recipients_by_role[entry["role"]] = normalized
        normalized_roles.append(
            {"role": entry["role"], "recipients": list(normalized)}
        )
    if set(recipients_by_role) != REVIEW_NOTIFICATION_ROLES or len(all_recipients) > 64:
        raise ReviewNotificationUnavailable(
            "review notification recipients are invalid"
        )
    normalized_document = {
        "schema": REVIEW_NOTIFICATION_RECIPIENTS_SCHEMA,
        "roles": sorted(normalized_roles, key=lambda item: item["role"]),
    }
    actual_sha256 = "sha256:" + hashlib.sha256(
        REVIEW_NOTIFICATION_RECIPIENTS_DOMAIN
        + _canonical_json(normalized_document)
    ).hexdigest()
    if not hmac.compare_digest(actual_sha256, expected_sha256):
        raise ReviewNotificationUnavailable(
            "review notification recipient binding changed"
        )
    return ReviewRecipientPolicy(
        recipients_by_role=recipients_by_role,
        policy_sha256=actual_sha256,
    )


def review_recipient_policy_sha256(document: dict[str, Any]) -> str:
    """Return the digest of a valid canonical recipient document."""

    synthetic = Settings(
        review_notifications_enabled=True,
        review_notification_recipients_json=json.dumps(document),
        review_notification_recipients_sha256="sha256:" + "1" * 64,
    )
    configured = synthetic.review_notification_recipients_json
    raw = (
        configured.get_secret_value()
        if isinstance(configured, SecretStr)
        else configured
    )
    try:
        parsed = json.loads(raw, object_pairs_hook=_reject_duplicate_json_keys)
    except Exception as exc:
        raise ReviewNotificationError("recipient policy is invalid") from exc
    if not isinstance(parsed, dict) or not isinstance(parsed.get("roles"), list):
        raise ReviewNotificationError("recipient policy is invalid")
    roles: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in parsed["roles"]:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"role", "recipients"}
            or entry.get("role") not in REVIEW_NOTIFICATION_ROLES
            or entry["role"] in seen
            or not isinstance(entry.get("recipients"), list)
            or not 1 <= len(entry["recipients"]) <= 16
        ):
            raise ReviewNotificationError("recipient policy is invalid")
        seen.add(entry["role"])
        recipients = sorted(_normalize_email(value) for value in entry["recipients"])
        if len(recipients) != len(set(recipients)):
            raise ReviewNotificationError("recipient policy is invalid")
        roles.append({"role": entry["role"], "recipients": recipients})
    if seen != REVIEW_NOTIFICATION_ROLES:
        raise ReviewNotificationError("recipient policy is invalid")
    normalized = {
        "schema": REVIEW_NOTIFICATION_RECIPIENTS_SCHEMA,
        "roles": sorted(roles, key=lambda item: item["role"]),
    }
    return "sha256:" + hashlib.sha256(
        REVIEW_NOTIFICATION_RECIPIENTS_DOMAIN + _canonical_json(normalized)
    ).hexdigest()


def review_notification_receipt_key(settings: Settings) -> bytes:
    explicit = settings.review_notification_receipt_store_key
    if explicit:
        try:
            key = bytes.fromhex(explicit)
        except ValueError as exc:
            raise ReviewNotificationUnavailable(
                "notification receipt key is unavailable"
            ) from exc
        if len(key) != 32:
            raise ReviewNotificationUnavailable(
                "notification receipt key is unavailable"
            )
        return key
    if not settings.dstack_enabled:
        raise ReviewNotificationUnavailable(
            "notification receipt key is unavailable"
        )
    try:
        key = derive_storage_key(settings.review_notification_receipt_key_path)
    except Exception as exc:
        raise ReviewNotificationUnavailable(
            "notification receipt key is unavailable"
        ) from exc
    if not isinstance(key, bytes) or len(key) != 32:
        raise ReviewNotificationUnavailable(
            "notification receipt key is unavailable"
        )
    return key


def review_notification_idempotency_key(payload: dict[str, Any]) -> str:
    return hashlib.sha256(
        REVIEW_NOTIFICATION_IDEMPOTENCY_DOMAIN + _canonical_json(payload)
    ).hexdigest()


def _validate_release_binding(binding: dict[str, Any], settings: Settings) -> None:
    expected = {
        "chain_id": 84_532,
        "wallet_domain": "www.wikigen.me",
        "wallet_uri": "https://www.wikigen.me",
        "main_runtime_cvm_id": settings.review_notification_main_runtime_cvm_id,
        "deployment_intent_sha256": (
            settings.review_notification_deployment_intent_sha256
        ),
        "release_authority_sha256": (
            settings.review_notification_release_authority_sha256
        ),
        "ceremony_nonce": settings.review_notification_ceremony_nonce,
        "policy_sha256": settings.review_notification_policy_sha256,
        "active_reviewers_sha256": (
            settings.review_notification_active_reviewers_sha256
        ),
        "genesis_acceptance_sha256": (
            settings.review_notification_genesis_acceptance_sha256
        ),
        "current_status_epoch": (
            settings.review_notification_current_status_epoch
        ),
        "current_status_sha256": (
            settings.review_notification_current_status_sha256
        ),
    }
    if not isinstance(binding, dict) or set(binding) != set(expected):
        raise ReviewNotificationError("review notification release binding changed")
    for key, expected_value in expected.items():
        actual_value = binding[key]
        # Python considers True == 1. Release bindings do not: accepting that
        # equivalence would make a non-canonical JSON type release-valid.
        if type(actual_value) is not type(expected_value) or actual_value != expected_value:
            raise ReviewNotificationError(
                "review notification release binding changed"
            )


def _review_notification_message(
    request: ReviewNotificationRequest,
    *,
    sender: str,
) -> EmailMessage:
    message = EmailMessage()
    message["From"] = sender
    # Recipient addresses exist only in the SMTP envelope.
    message["To"] = "undisclosed-recipients:;"
    message["Subject"] = "Wikigen Human Review: action requested"
    message["Message-ID"] = (
        f"<review-{request.idempotency_key}@notifications.wikigen.invalid>"
    )
    message["Auto-Submitted"] = "auto-generated"
    message.set_content(
        "\n".join(
            (
                "A bounded Human Review ticket is awaiting action.",
                "",
                f"Role: {request.routed_role}",
                f"Ticket reference: {request.ticket_ref_hash}",
                f"Opened at (Unix): {request.opened_at}",
                f"Expires at (Unix): {request.expires_at}",
                "Review: https://www.wikigen.me/#/review",
                "",
                (
                    "This notification contains no review reason, artifact "
                    "content, submitter identity, or reviewer identity."
                ),
            )
        )
    )
    return message


def _public_receipt(
    record: ReviewNotificationRecord,
    *,
    idempotent: bool,
) -> ReviewNotificationReceipt:
    if record.status != "delivered" or not _HASH.fullmatch(record.receipt_sha256):
        raise ReviewNotificationError("notification receipt is not delivered")
    return ReviewNotificationReceipt(
        idempotency_key=record.idempotency_key,
        receipt_sha256=record.receipt_sha256,
        status="delivered",
        idempotent=idempotent,
    )


def _record_from_dict(value: Any) -> ReviewNotificationRecord:
    if not isinstance(value, dict) or set(value) != {
        "idempotency_key",
        "request_sha256",
        "status",
        "reserved_at",
        "delivered_at",
        "receipt_sha256",
    }:
        raise ReviewNotificationUnavailable("notification receipt record is invalid")
    _require_hash(value["idempotency_key"], "notification idempotency key")
    _require_hash(value["request_sha256"], "notification request digest")
    status_value = value["status"]
    if status_value not in {"ambiguous", "delivered"}:
        raise ReviewNotificationUnavailable("notification receipt status is invalid")
    reserved_at = value["reserved_at"]
    delivered_at = value["delivered_at"]
    if (
        not isinstance(reserved_at, int)
        or isinstance(reserved_at, bool)
        or reserved_at <= 0
        or not isinstance(delivered_at, int)
        or isinstance(delivered_at, bool)
        or delivered_at < 0
    ):
        raise ReviewNotificationUnavailable("notification receipt time is invalid")
    receipt_sha256 = value["receipt_sha256"]
    if status_value == "ambiguous":
        if delivered_at != 0 or receipt_sha256 != "":
            raise ReviewNotificationUnavailable(
                "ambiguous notification receipt is invalid"
            )
    elif (
        delivered_at < reserved_at
        or not isinstance(receipt_sha256, str)
        or not _HASH.fullmatch(receipt_sha256)
    ):
        raise ReviewNotificationUnavailable(
            "delivered notification receipt is invalid"
        )
    return ReviewNotificationRecord(
        idempotency_key=value["idempotency_key"],
        request_sha256=value["request_sha256"],
        status=status_value,
        reserved_at=reserved_at,
        delivered_at=delivered_at,
        receipt_sha256=receipt_sha256,
    )


def _store_integrity(unsigned: dict[str, Any], key: bytes) -> str:
    return "hmac-sha256:" + hmac.new(
        key,
        REVIEW_NOTIFICATION_STORE_DOMAIN + _canonical_json(unsigned),
        hashlib.sha256,
    ).hexdigest()


def _normalize_email(value: Any) -> str:
    if not isinstance(value, str) or not 3 <= len(value) <= 254:
        raise ReviewNotificationUnavailable(
            "review notification recipients are invalid"
        )
    if value != value.strip() or any(character in value for character in "\r\n\x00"):
        raise ReviewNotificationUnavailable(
            "review notification recipients are invalid"
        )
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ReviewNotificationUnavailable(
            "review notification recipients are invalid"
        ) from exc
    if value.count("@") != 1:
        raise ReviewNotificationUnavailable(
            "review notification recipients are invalid"
        )
    local, domain = value.rsplit("@", 1)
    labels = domain.split(".")
    if (
        not _EMAIL_LOCAL.fullmatch(local)
        or not 1 <= len(domain) <= 253
        or len(labels) < 2
        or any(not _DNS_LABEL.fullmatch(label) for label in labels)
    ):
        raise ReviewNotificationUnavailable(
            "review notification recipients are invalid"
        )
    return f"{local.lower()}@{domain.lower()}"


def _require_hash(value: Any, label: str) -> None:
    if not isinstance(value, str) or not _HASH.fullmatch(value):
        raise ReviewNotificationUnavailable(f"{label} is invalid")


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ReviewNotificationError("JSON repeats a field")
        value[key] = item
    return value


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
