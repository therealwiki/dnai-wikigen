"""Fixed public failures for the bounded metering boundary."""

from __future__ import annotations


class MeteringError(Exception):
    status_code = 500
    public_code = "internal_error"


class InvalidRequest(MeteringError):
    status_code = 400
    public_code = "invalid_request"


class RequestTooLarge(MeteringError):
    status_code = 413
    public_code = "request_too_large"


class Unauthorized(MeteringError):
    status_code = 401
    public_code = "unauthorized"


class CapacityExceeded(MeteringError):
    status_code = 429
    public_code = "capacity_exceeded"


class UsageRejected(MeteringError):
    status_code = 400
    public_code = "usage_rejected"


class PolicyRejected(MeteringError):
    status_code = 400
    public_code = "policy_rejected"


class ChainStateRejected(MeteringError):
    status_code = 409
    public_code = "chain_state_rejected"


class ReplayConflict(MeteringError):
    status_code = 409
    public_code = "replay_conflict"


class UpstreamUnavailable(MeteringError):
    status_code = 503
    public_code = "upstream_unavailable"


class SignerUnavailable(MeteringError):
    status_code = 503
    public_code = "signer_unavailable"


class StateUnavailable(MeteringError):
    status_code = 503
    public_code = "state_unavailable"


class NotFound(MeteringError):
    status_code = 404
    public_code = "not_found"


class NotEnabled(MeteringError):
    status_code = 404
    public_code = "not_enabled"


class MethodNotAllowed(MeteringError):
    status_code = 405
    public_code = "method_not_allowed"
