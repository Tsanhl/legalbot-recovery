from __future__ import annotations

import json
import threading
import unittest
import urllib.error
import urllib.request

from backend.app.model_runtime.config import ModelRuntimeConfig
from backend.app.model_runtime.service import create_server


class ModelRuntimeServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.server = create_server(ModelRuntimeConfig(mode="stub", port=0))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.base_url = f"http://{host}:{port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def get(self, path: str) -> tuple[int, dict]:
        with urllib.request.urlopen(self.base_url + path, timeout=2) as response:
            return response.status, json.load(response)

    def post(self, path: str, payload: dict) -> tuple[int, dict]:
        request = urllib.request.Request(
            self.base_url + path,
            method="POST",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=2) as response:
            return response.status, json.load(response)

    def test_health_and_generation_contract(self) -> None:
        status, health = self.get("/api/v1/health")
        self.assertEqual(status, 200)
        self.assertEqual(health["api_version"], "v1")
        self.assertTrue(health["stub_mode"])

        status, generated = self.post(
            "/api/v1/generate",
            {
                "request_id": "http-1",
                "mode": "draft",
                "payload": {"prompt": "Hello"},
                "messages": [{"role": "user", "content": "Hello"}],
                "max_tokens": 16,
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(generated["request_id"], "http-1")
        self.assertEqual(generated["api_version"], "v1")
        self.assertTrue(generated["deterministic"])
        self.assertIn("model_version", generated)
        self.assertIn("raw_text", generated)
        self.assertEqual(generated["rubric_scores"], {})

    def test_invalid_request_returns_typed_error(self) -> None:
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.post(
                "/api/v1/generate",
                {
                    "request_id": "bad",
                    "mode": "draft",
                    "payload": {},
                    "messages": [],
                },
            )
        self.assertEqual(caught.exception.code, 400)
        payload = json.load(caught.exception)
        self.assertEqual(payload["api_version"], "v1")
        self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_unversioned_route_is_not_exposed(self) -> None:
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.get("/v1/health")
        self.assertEqual(caught.exception.code, 404)

    def test_client_disconnect_after_generation_is_logged_not_traced(self) -> None:
        from unittest.mock import MagicMock

        from backend.app.model_runtime.service import ModelRuntimeRequestHandler

        handler = ModelRuntimeRequestHandler.__new__(ModelRuntimeRequestHandler)
        handler.send_response = MagicMock()
        handler.send_header = MagicMock()
        handler.end_headers = MagicMock()
        handler.wfile = MagicMock()
        handler.wfile.write.side_effect = BrokenPipeError()
        with self.assertLogs("legalbot.model_runtime", level="INFO") as logs:
            written = handler._send_json(
                200, {"ok": True}, after_generation=True, request_id="req-disconnect"
            )
        self.assertFalse(written)
        joined = "\n".join(logs.output)
        self.assertIn("client_disconnected_after_generation", joined)
        self.assertIn("treat_as_verified", joined)


if __name__ == "__main__":
    unittest.main()
