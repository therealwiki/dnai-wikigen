"""Fixed public failures for the QVL HTTP boundary."""

from __future__ import annotations


class QvlServiceError(Exception):
    """Base error whose public representation never includes exception detail."""

    status_code = 500
    public_code = "internal_error"


class InvalidRequest(QvlServiceError):
    status_code = 400
    public_code = "invalid_request"


class VerificationRejected(QvlServiceError):
    status_code = 400
    public_code = "verification_rejected"


class Unauthorized(QvlServiceError):
    status_code = 401
    public_code = "unauthorized"


class NotFound(QvlServiceError):
    status_code = 404
    public_code = "not_found"


class NotEnabled(QvlServiceError):
    status_code = 404
    public_code = "not_enabled"


class MethodNotAllowed(QvlServiceError):
    status_code = 405
    public_code = "method_not_allowed"


class RequestTooLarge(QvlServiceError):
    status_code = 413
    public_code = "request_too_large"


class CapacityExceeded(QvlServiceError):
    status_code = 429
    public_code = "capacity_exceeded"


class VerifierUnavailable(QvlServiceError):
    status_code = 503
    public_code = "verifier_unavailable"
