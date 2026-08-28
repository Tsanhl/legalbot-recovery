from __future__ import annotations

import unittest

from backend.app.model_runtime.adapters import RequestLimitError, StubModelBackend
from backend.app.model_runtime.config import ModelRuntimeConfig, SafeMemoryConfig
from backend.app.model_runtime.contracts import GenerateRequest


def request(request_id: str = "r1", content: str = "What is a trust?") -> GenerateRequest:
    return GenerateRequest.from_dict(
        {
            "request_id": request_id,
            "mode": "draft",
            "payload": {"prompt": content},
            "messages": [{"role": "user", "content": content}],
            "max_tokens": 20,
            "temperature": 0,
            "seed": 7,
        }
    )


class StubBackendTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = ModelRuntimeConfig(
            mode="stub",
            memory=SafeMemoryConfig(
                context_window_tokens=512,
                max_output_tokens=64,
                prefill_step_size=64,
            ),
        )
        self.backend = StubModelBackend(self.config)

    def test_same_request_is_bit_for_bit_deterministic(self) -> None:
        first = self.backend.generate(request())
        second = self.backend.generate(request())
        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertIn("Deterministic stub response", first.raw_text)
        self.assertTrue(first.deterministic)

    def test_payload_change_changes_stub_digest(self) -> None:
        self.assertNotEqual(
            self.backend.generate(request(content="A")).raw_text,
            self.backend.generate(request(content="B")).raw_text,
        )

    def test_safe_output_cap_is_enforced(self) -> None:
        oversized = GenerateRequest.from_dict(
            {
                "request_id": "large",
                "mode": "draft",
                "payload": {"prompt": "x"},
                "messages": [{"role": "user", "content": "x"}],
                "max_tokens": 65,
            }
        )
        with self.assertRaises(RequestLimitError):
            self.backend.generate(oversized)

    def test_health_discloses_stub_mode(self) -> None:
        health = self.backend.health()
        self.assertEqual(health.status, "ok")
        self.assertTrue(health.stub_mode)
        self.assertTrue(health.model_loaded)


if __name__ == "__main__":
    unittest.main()
