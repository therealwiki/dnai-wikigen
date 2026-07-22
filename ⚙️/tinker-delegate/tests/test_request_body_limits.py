import unittest

from tinker_delegate.request_body_limits import (
    ARTIFACT_UPLOAD_REQUEST_MAX_BYTES,
    COMPUTE_WORKLOAD_REQUEST_MAX_BYTES,
    DEFAULT_ROUTE_BODY_LIMITS,
    RouteBodyLimitMiddleware,
)


def _scope(path: str, *, content_length: int | str | None = None) -> dict:
    headers = []
    if content_length is not None:
        headers.append((b"content-length", str(content_length).encode("ascii")))
    return {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "https",
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": b"",
        "headers": headers,
        "client": ("127.0.0.1", 1),
        "server": ("test", 443),
    }


class RequestBodyLimitTest(unittest.IsolatedAsyncioTestCase):
    async def _invoke(self, path: str, chunks: list[bytes], *, content_length=None):
        messages = [
            {
                "type": "http.request",
                "body": chunk,
                "more_body": index < len(chunks) - 1,
            }
            for index, chunk in enumerate(chunks)
        ] or [{"type": "http.request", "body": b"", "more_body": False}]
        received_by_app = bytearray()
        sent = []

        async def downstream(_scope, receive, send):
            while True:
                message = await receive()
                received_by_app.extend(message.get("body", b""))
                if not message.get("more_body", False):
                    break
            await send({"type": "http.response.start", "status": 204, "headers": []})
            await send({"type": "http.response.body", "body": b"", "more_body": False})

        async def receive():
            return messages.pop(0)

        async def send(message):
            sent.append(message)

        middleware = RouteBodyLimitMiddleware(downstream, DEFAULT_ROUTE_BODY_LIMITS)
        await middleware(
            _scope(path, content_length=content_length),
            receive,
            send,
        )
        return sent, received_by_app, messages

    async def test_declared_artifact_oversize_rejects_before_receive(self):
        sent, received, remaining = await self._invoke(
            "/deal/7/artifact/encrypted",
            [b"must-not-be-read"],
            content_length=ARTIFACT_UPLOAD_REQUEST_MAX_BYTES + 1,
        )
        self.assertEqual(sent[0]["status"], 413)
        self.assertEqual(received, b"")
        self.assertEqual(len(remaining), 1)

    async def test_missing_content_length_stream_is_counted_and_rejected(self):
        sent, received, _remaining = await self._invoke(
            "/deal/7/artifact/encrypted",
            [b"x" * ARTIFACT_UPLOAD_REQUEST_MAX_BYTES, b"y"],
        )
        self.assertEqual(sent[0]["status"], 413)
        self.assertNotIn(b"y", received)

    async def test_lying_content_length_is_rejected(self):
        sent, _received, _remaining = await self._invoke(
            "/deal/7/artifact/encrypted",
            [b"{}"],
            content_length=1,
        )
        self.assertEqual(sent[0]["status"], 400)

    async def test_exact_declared_length_reaches_application(self):
        sent, received, _remaining = await self._invoke(
            "/deal/7/artifact/encrypted",
            [b"{", b"}"],
            content_length=2,
        )
        self.assertEqual(sent[0]["status"], 204)
        self.assertEqual(received, b"{}")

    async def test_compute_route_has_its_distinct_frozen_cap(self):
        self.assertLess(
            COMPUTE_WORKLOAD_REQUEST_MAX_BYTES,
            ARTIFACT_UPLOAD_REQUEST_MAX_BYTES,
        )
        sent, _received, remaining = await self._invoke(
            "/compute/projects/prj_1/workloads",
            [b"not-read"],
            content_length=COMPUTE_WORKLOAD_REQUEST_MAX_BYTES + 1,
        )
        self.assertEqual(sent[0]["status"], 413)
        self.assertEqual(len(remaining), 1)

    async def test_compute_chunked_oversize_without_length_is_counted(self):
        sent, received, _remaining = await self._invoke(
            "/compute/projects/prj_1/workloads",
            [b"x" * COMPUTE_WORKLOAD_REQUEST_MAX_BYTES, b"private-tail"],
        )
        self.assertEqual(sent[0]["status"], 413)
        self.assertNotIn(b"private-tail", received)

    async def test_compute_lying_content_length_is_rejected(self):
        sent, _received, _remaining = await self._invoke(
            "/compute/projects/prj_1/workloads",
            [b"{}"],
            content_length=1,
        )
        self.assertEqual(sent[0]["status"], 400)

    async def test_unlisted_route_is_not_intercepted(self):
        sent, received, _remaining = await self._invoke(
            "/unlisted",
            [b"x" * (ARTIFACT_UPLOAD_REQUEST_MAX_BYTES + 1)],
        )
        self.assertEqual(sent[0]["status"], 204)
        self.assertEqual(len(received), ARTIFACT_UPLOAD_REQUEST_MAX_BYTES + 1)


if __name__ == "__main__":
    unittest.main()
