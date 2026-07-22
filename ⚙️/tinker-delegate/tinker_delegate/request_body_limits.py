"""Pre-buffer ASGI body limits for private ciphertext ingress routes.

Pydantic field bounds are still required, but validation starts only after
Starlette has assembled the request body.  This middleware counts every ASGI
``http.request`` chunk first and rejects both declared and streamed oversize
bodies without reflecting any submitted bytes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Awaitable, Callable, Iterable, Pattern


ARTIFACT_UPLOAD_REQUEST_MAX_BYTES = 2_101_248
COMPUTE_WORKLOAD_REQUEST_MAX_BYTES = 1_425_408


@dataclass(frozen=True)
class RouteBodyLimit:
    method: str
    path: Pattern[str]
    max_bytes: int


DEFAULT_ROUTE_BODY_LIMITS = (
    RouteBodyLimit(
        method="POST",
        path=re.compile(r"^/deal/[^/]+/artifact(?:/encrypted)?$"),
        max_bytes=ARTIFACT_UPLOAD_REQUEST_MAX_BYTES,
    ),
    RouteBodyLimit(
        method="POST",
        path=re.compile(r"^/compute/projects/[^/]+/workloads$"),
        max_bytes=COMPUTE_WORKLOAD_REQUEST_MAX_BYTES,
    ),
)


class _RequestBodyTooLarge(Exception):
    pass


class _MalformedContentLength(Exception):
    pass


class RouteBodyLimitMiddleware:
    """Apply exact route-specific byte caps before framework body buffering."""

    def __init__(self, app, limits: Iterable[RouteBodyLimit] = DEFAULT_ROUTE_BODY_LIMITS):
        self.app = app
        self.limits = tuple(limits)

    @staticmethod
    async def _respond(send: Callable[[dict], Awaitable[None]], status: int, detail: bytes) -> None:
        body = b'{"detail":"' + detail + b'"}'
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": (
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ),
            }
        )
        await send({"type": "http.response.body", "body": body, "more_body": False})

    @staticmethod
    def _declared_length(scope: dict) -> int | None:
        values = [
            value
            for name, value in scope.get("headers", ())
            if name.lower() == b"content-length"
        ]
        if not values:
            return None
        if len(values) != 1 or re.fullmatch(rb"(?:0|[1-9][0-9]*)", values[0]) is None:
            raise _MalformedContentLength
        return int(values[0])

    def _limit_for(self, scope: dict) -> int | None:
        method = str(scope.get("method", "")).upper()
        path = str(scope.get("path", ""))
        for limit in self.limits:
            if method == limit.method and limit.path.fullmatch(path):
                return limit.max_bytes
        return None

    async def __call__(self, scope: dict, receive, send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        limit = self._limit_for(scope)
        if limit is None:
            await self.app(scope, receive, send)
            return
        try:
            declared = self._declared_length(scope)
        except _MalformedContentLength:
            await self._respond(send, 400, b"invalid Content-Length")
            return
        if declared is not None and declared > limit:
            await self._respond(send, 413, b"request body exceeds route limit")
            return

        received = 0
        response_started = False

        async def limited_receive() -> dict:
            nonlocal received
            message = await receive()
            if message.get("type") == "http.request":
                chunk = message.get("body", b"")
                received += len(chunk)
                if received > limit:
                    raise _RequestBodyTooLarge
                if not message.get("more_body", False) and declared is not None and received != declared:
                    raise _MalformedContentLength
            return message

        async def tracking_send(message: dict) -> None:
            nonlocal response_started
            if message.get("type") == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except _RequestBodyTooLarge:
            if response_started:  # pragma: no cover - defensive for non-body-parsing apps
                raise
            await self._respond(send, 413, b"request body exceeds route limit")
        except _MalformedContentLength:
            if response_started:  # pragma: no cover - defensive for non-body-parsing apps
                raise
            await self._respond(send, 400, b"Content-Length does not match request body")
