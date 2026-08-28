from __future__ import annotations

import os
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.app.model_runtime.config import (
    ModelRuntimeConfig,
    SafeMemoryConfig,
)
from backend.app.model_runtime.contracts import ContractError, GenerateRequest


class GenerateRequestTests(unittest.TestCase):
    def test_valid_request_round_trips(self) -> None:
        payload = {
            "request_id": "case-17",
            "mode": "draft",
            "payload": {"task": "essay"},
            "messages": [
                {"role": "system", "content": "Answer carefully."},
                {"role": "user", "content": "Explain consideration."},
            ],
            "max_tokens": 700,
            "temperature": 0,
            "top_p": 1,
            "seed": 44,
            "stop": ["END"],
        }
        request = GenerateRequest.from_dict(payload)
        self.assertEqual(request.request_id, "case-17")
        self.assertEqual(request.messages[-1].role, "user")
        self.assertEqual(request.to_dict(), payload)

    def test_rejects_unknown_fields_and_missing_user(self) -> None:
        with self.assertRaisesRegex(ContractError, "unknown request"):
            GenerateRequest.from_dict(
                {
                    "request_id": "x",
                    "mode": "draft",
                    "payload": {},
                    "messages": [{"role": "user", "content": "x"}],
                    "surprise": True,
                }
            )
        with self.assertRaisesRegex(ContractError, "at least one user"):
            GenerateRequest.from_dict(
                {
                    "request_id": "x",
                    "mode": "draft",
                    "payload": {},
                    "messages": [{"role": "assistant", "content": "x"}],
                }
            )

    def test_rejects_late_system_message(self) -> None:
        with self.assertRaisesRegex(ContractError, "only as the first"):
            GenerateRequest.from_dict(
                {
                    "request_id": "x",
                    "mode": "draft",
                    "payload": {},
                    "messages": [
                        {"role": "user", "content": "x"},
                        {"role": "system", "content": "late"},
                    ],
                }
            )

    def test_payload_prompt_can_supply_messages(self) -> None:
        request = GenerateRequest.from_dict(
            {
                "request_id": "payload-only",
                "mode": "repair",
                "payload": {"prompt": "Repair section two."},
            }
        )
        self.assertEqual(request.mode, "repair")
        self.assertEqual(request.messages[0].content, "Repair section two.")

    def test_semantic_verify_mode_is_allowed(self) -> None:
        request = GenerateRequest.from_dict(
            {
                "request_id": "semantic-1",
                "mode": "semantic_verify",
                "payload": {"issue_id": "issue-01"},
                "messages": [
                    {"role": "system", "content": "Return JSON only."},
                    {"role": "user", "content": '{"proposition":"consideration"}'},
                ],
            }
        )
        self.assertEqual(request.mode, "semantic_verify")


class RuntimeConfigTests(unittest.TestCase):
    def test_default_memory_profile_is_bounded(self) -> None:
        memory = SafeMemoryConfig()
        self.assertEqual(memory.context_window_tokens, 8192)
        self.assertEqual(memory.max_output_tokens, 2048)
        self.assertTrue(memory.to_dict()["single_flight_generation"])

    def test_non_loopback_binding_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "loopback"):
            ModelRuntimeConfig(host="0.0.0.0")

    def test_environment_cannot_raise_absolute_context_cap(self) -> None:
        with (
            patch.dict(os.environ, {"LEGALBOT_MODEL_CONTEXT_TOKENS": "9000"}),
            self.assertRaisesRegex(ValueError, "between 512 and 8192"),
        ):
            SafeMemoryConfig.from_env()

    def test_paths_are_resolved_without_requiring_old_project(self) -> None:
        config = ModelRuntimeConfig(model_path=Path("models/runtime/example"))
        self.assertTrue(config.model_path.is_absolute())


if __name__ == "__main__":
    unittest.main()
