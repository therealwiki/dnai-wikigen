import concurrent.futures
import socket
import threading
import time
import unittest
from unittest.mock import patch

import httpx
import uvicorn

from tinker_delegate import api
from tinker_delegate.config import Settings


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class ApiEventLoopTest(unittest.TestCase):
    def setUp(self):
        self.original_settings = api.settings

    def tearDown(self):
        api.settings = self.original_settings

    def test_attestation_is_not_blocked_by_slow_oracle_health(self):
        api.settings = Settings()

        def slow_health(_self):
            time.sleep(1.5)
            return {"oracle_ready": False, "bounded_message": "slow_oracle"}

        port = _free_port()
        config = uvicorn.Config(
            api.app,
            host="127.0.0.1",
            port=port,
            log_level="warning",
            lifespan="off",
        )
        server = uvicorn.Server(config)
        thread = threading.Thread(target=server.run, daemon=True)

        with patch("tinker_delegate.api.OracleClient.health", slow_health):
            thread.start()
            try:
                deadline = time.time() + 5
                while time.time() < deadline and not server.started:
                    time.sleep(0.05)
                self.assertTrue(server.started)

                base_url = f"http://127.0.0.1:{port}"
                with (
                    httpx.Client(timeout=3.0) as client,
                    concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor,
                ):
                    health_future = executor.submit(client.get, f"{base_url}/health")
                    time.sleep(0.1)

                    start = time.monotonic()
                    attestation = client.get(f"{base_url}/attestation?context=billing")
                    elapsed = time.monotonic() - start

                    self.assertEqual(attestation.status_code, 200)
                    self.assertLess(elapsed, 1.0)
                    self.assertEqual(health_future.result().status_code, 200)
            finally:
                server.should_exit = True
                thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
