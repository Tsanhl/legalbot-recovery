"""Frozen, development-only provider selection for the existing AnswerRunner.

All routes inherit the same prompt construction and output checks from the
Qwen gateway. They differ only in transport and verified provider identity.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import tempfile
from contextvars import ContextVar, Token
from pathlib import Path
from typing import Any

import httpx

from .config import Settings
from .evaluation.ge_development_chat_authority import load_development_chat_route
from .runtime_adapters import LoopbackModelGateway


def _transport_projection(messages: list[dict[str, Any]], sent_content: str) -> dict[str, str]:
    return {
        "sent_content": sent_content,
        "sent_content_sha256": hashlib.sha256(sent_content.encode("utf-8")).hexdigest(),
        "source_messages_sha256": hashlib.sha256(
            json.dumps(messages, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
    }


class LocalEndpointGateway(LoopbackModelGateway):
    def __init__(self, settings: Settings, route: dict[str, Any]) -> None:
        super().__init__(settings)
        self.url = str(route["endpoint"]).rstrip("/")
        self.expected_model = str(route["model_id"])
        self.expected_version = str(route.get("model_version", route["model_id"]))
        self.allow_test_stub = False

    def _validated_model_version(self, body: dict[str, Any]) -> str:
        observed = str(body.get("model_version") or "")
        if observed != self.expected_version or "stub_mode" in body.get("warnings", []):
            raise RuntimeError("linked local model identity differs from frozen route")
        return observed


class HostedEvidenceGateway(LoopbackModelGateway):
    """Bounded hosted profile; does not inherit the local 9B memory budget."""

    max_question_chars = 30_000
    assessment_character_budget = 8_000
    evidence_character_budget = 45_000
    evidence_token_budget = 15_000
    repair_evidence_character_budget = 45_000
    repair_evidence_token_budget = 15_000
    input_token_budget = 24_000
    output_token_budget = 8_192


class OpenAIResponsesGateway(HostedEvidenceGateway):
    def __init__(self, settings: Settings, route: dict[str, Any]) -> None:
        super().__init__(settings)
        self.expected_model = str(route["model_id"])
        self.endpoint = str(route["endpoint"])
        self.allow_test_stub = False

    async def health(self) -> bool:
        # A configured key is not evidence of provider capability; a real
        # request still has to pass identity, JSON and all answer gates.
        return bool(os.environ.get("OPENAI_API_KEY"))

    def _validated_model_version(self, body: dict[str, Any]) -> str:
        observed = str(body.get("model_version") or "")
        if observed != self.expected_model:
            raise RuntimeError("hosted API model identity differs from frozen route")
        return f"openai:{observed}"

    async def _generate(self, envelope: dict[str, Any]) -> dict[str, Any]:
        key = os.environ.get("OPENAI_API_KEY", "")
        if not key:
            raise RuntimeError("hosted API credential is unavailable")
        messages = envelope.get("messages")
        if not isinstance(messages, list) or len(messages) != 2:
            raise ValueError("frozen provider prompt is incomplete")
        request_body = {
            "model": self.expected_model,
            "instructions": str(messages[0]["content"]),
            "input": str(messages[1]["content"]),
            "text": {"format": {"type": "json_object"}},
            "store": False,
            "tools": [],
            "background": False,
            "max_output_tokens": self.output_token_budget,
        }
        async with httpx.AsyncClient(
            timeout=self._timeout, trust_env=False, follow_redirects=False,
        ) as client:
            response = await client.post(
                self.endpoint,
                json=request_body,
                headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            )
            response.raise_for_status()
        value = response.json()
        if not isinstance(value, dict) or value.get("status") != "completed":
            raise RuntimeError("hosted API generation did not complete")
        if value.get("model") != self.expected_model:
            raise RuntimeError("hosted API returned a different model")
        parts = [
            item.get("text")
            for message in value.get("output", [])
            if isinstance(message, dict) and message.get("type") == "message"
            for item in message.get("content", [])
            if isinstance(item, dict) and item.get("type") == "output_text"
        ]
        if len(parts) != 1 or not isinstance(parts[0], str):
            raise RuntimeError("hosted API output was not one JSON text message")
        structured = json.loads(parts[0])
        if not isinstance(structured, dict):
            raise ValueError("hosted API output was not a JSON object")
        usage = value.get("usage") or {}
        return {
            "structured": structured,
            "raw_text": parts[0],
            "model_version": str(value["model"]),
            "finish_reason": "stop",
            "warnings": [],
            "usage": {
                "input_tokens": int(usage.get("input_tokens") or 0),
                "output_tokens": int(usage.get("output_tokens") or 0),
                "total_tokens": int(usage.get("total_tokens") or 0),
            },
            "transport_projection": _transport_projection(
                messages,
                json.dumps(request_body, ensure_ascii=False, sort_keys=True,
                           separators=(",", ":")),
            ),
        }


class AnthropicMessagesGateway(HostedEvidenceGateway):
    def __init__(self, settings: Settings, route: dict[str, Any]) -> None:
        super().__init__(settings)
        self.expected_model = str(route["model_id"])
        self.endpoint = str(route["endpoint"])
        self.allow_test_stub = False

    async def health(self) -> bool:
        return bool(os.environ.get("ANTHROPIC_API_KEY"))

    def _validated_model_version(self, body: dict[str, Any]) -> str:
        observed = str(body.get("model_version") or "")
        if observed != self.expected_model:
            raise RuntimeError("Anthropic model identity differs from frozen route")
        return f"anthropic:{observed}"

    async def _generate(self, envelope: dict[str, Any]) -> dict[str, Any]:
        key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not key:
            raise RuntimeError("Anthropic API credential is unavailable")
        messages = envelope.get("messages")
        if not isinstance(messages, list) or len(messages) != 2:
            raise ValueError("frozen provider prompt is incomplete")
        request_body = {
            "model": self.expected_model, "max_tokens": 8192,
            "system": (
                "Return exactly {\"payload\": \"...\"}, where payload is the JSON-encoded "
                "answer object requested below.\n\n" + str(messages[0]["content"])
            ),
            "messages": [{"role": "user", "content": str(messages[1]["content"])}],
            "output_config": {"format": {"type": "json_schema", "schema": {
                "type": "object", "properties": {"payload": {"type": "string"}},
                "required": ["payload"], "additionalProperties": False,
            }}},
        }
        async with httpx.AsyncClient(timeout=self._timeout, trust_env=False, follow_redirects=False) as client:
            response = await client.post(
                self.endpoint, json=request_body,
                headers={"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
            )
            response.raise_for_status()
        value = response.json()
        if not isinstance(value, dict) or value.get("model") != self.expected_model or value.get("stop_reason") != "end_turn":
            raise RuntimeError("Anthropic generation did not finish with the frozen model")
        parts = [part.get("text") for part in value.get("content", [])
                 if isinstance(part, dict) and part.get("type") == "text"]
        if len(parts) != 1 or not isinstance(parts[0], str):
            raise RuntimeError("Anthropic output was not one JSON text message")
        wrapper = json.loads(parts[0])
        if not isinstance(wrapper, dict) or set(wrapper) != {"payload"} or not isinstance(wrapper["payload"], str):
            raise ValueError("Anthropic output did not match the strict envelope")
        structured = json.loads(wrapper["payload"])
        if not isinstance(structured, dict):
            raise ValueError("Anthropic output was not a JSON object")
        usage = value.get("usage") or {}
        return {
            "structured": structured, "raw_text": wrapper["payload"],
            "model_version": str(value["model"]), "finish_reason": "stop", "warnings": [],
            "usage": {"input_tokens": int(usage.get("input_tokens") or 0),
                      "output_tokens": int(usage.get("output_tokens") or 0)},
            "transport_projection": _transport_projection(messages, json.dumps(
                request_body, ensure_ascii=False, sort_keys=True, separators=(",", ":"))),
        }


class GeminiGenerateContentGateway(HostedEvidenceGateway):
    def __init__(self, settings: Settings, route: dict[str, Any]) -> None:
        super().__init__(settings)
        self.expected_model = str(route["model_id"])
        self.endpoint = str(route["endpoint"])
        self.allow_test_stub = False

    async def health(self) -> bool:
        return bool(os.environ.get("GEMINI_API_KEY"))

    def _validated_model_version(self, body: dict[str, Any]) -> str:
        observed = str(body.get("model_version") or "")
        if observed != self.expected_model:
            raise RuntimeError("Gemini model identity differs from frozen route")
        return f"gemini:{observed}"

    async def _generate(self, envelope: dict[str, Any]) -> dict[str, Any]:
        key = os.environ.get("GEMINI_API_KEY", "")
        if not key:
            raise RuntimeError("Gemini API credential is unavailable")
        messages = envelope.get("messages")
        if not isinstance(messages, list) or len(messages) != 2:
            raise ValueError("frozen provider prompt is incomplete")
        request_body = {
            "systemInstruction": {"parts": [{"text": str(messages[0]["content"])}]},
            "contents": [{"role": "user", "parts": [{"text": str(messages[1]["content"])}]}],
            "generationConfig": {"responseMimeType": "application/json", "candidateCount": 1},
        }
        async with httpx.AsyncClient(timeout=self._timeout, trust_env=False, follow_redirects=False) as client:
            response = await client.post(
                self.endpoint, json=request_body,
                headers={"x-goog-api-key": key, "content-type": "application/json"},
            )
            response.raise_for_status()
        value = response.json()
        if not isinstance(value, dict) or value.get("modelVersion") != self.expected_model:
            raise RuntimeError("Gemini model identity differs from frozen route")
        candidates = value.get("candidates")
        if not isinstance(candidates, list) or len(candidates) != 1 or candidates[0].get("finishReason") != "STOP":
            raise RuntimeError("Gemini generation did not finish normally")
        parts = candidates[0].get("content", {}).get("parts", [])
        if not isinstance(parts, list) or len(parts) != 1 or not isinstance(parts[0].get("text"), str):
            raise RuntimeError("Gemini output was not one JSON text message")
        structured = json.loads(parts[0]["text"])
        if not isinstance(structured, dict):
            raise ValueError("Gemini output was not a JSON object")
        usage = value.get("usageMetadata") or {}
        return {
            "structured": structured, "raw_text": parts[0]["text"],
            "model_version": str(value["modelVersion"]), "finish_reason": "stop", "warnings": [],
            "usage": {"input_tokens": int(usage.get("promptTokenCount") or 0),
                      "output_tokens": int(usage.get("candidatesTokenCount") or 0),
                      "total_tokens": int(usage.get("totalTokenCount") or 0)},
            "transport_projection": _transport_projection(messages, json.dumps(
                request_body, ensure_ascii=False, sort_keys=True, separators=(",", ":"))),
        }


class CodexBridgeGateway(HostedEvidenceGateway):
    """Dedicated ephemeral Codex CLI transport with an isolated workspace.

    It requires an operator-supplied OS isolation wrapper. Without one this
    route fails closed; a bare Codex process may read ambient host files.
    """

    def __init__(self, settings: Settings, route: dict[str, Any]) -> None:
        super().__init__(settings)
        self.expected_model = str(route["model_id"])
        self.auth_mode = str(route.get("auth_mode") or "dedicated_api_key")
        self.allow_test_stub = False
        self.wrapper = str(settings.project_root / "scripts" / "legalbot_codex_isolation_wrapper.py")

    @staticmethod
    def _signin_auth_path() -> Path:
        return Path.home() / ".codex" / "auth.json"

    async def health(self) -> bool:
        transport_ready = bool(
            Path(self.wrapper).is_file() and os.access(self.wrapper, os.X_OK)
            and shutil.which("codex")
        )
        if not transport_ready:
            return False
        if self.auth_mode == "chatgpt_signin":
            auth = self._signin_auth_path()
            return auth.is_file() and not auth.is_symlink() and auth.stat().st_mode & 0o077 == 0
        return bool(os.environ.get("LEGALBOT_CODEX_BRIDGE_KEY"))

    def _validated_model_version(self, body: dict[str, Any]) -> str:
        observed = str(body.get("model_version") or "")
        if observed != self.expected_model:
            raise RuntimeError("Codex model identity differs from frozen route")
        # CLI -m proves the requested model, not the provider's actual served
        # snapshot. Preserve that limit in the answer identity.
        return f"codex-requested:{observed}"

    async def _generate(self, envelope: dict[str, Any]) -> dict[str, Any]:
        if not await self.health():
            raise RuntimeError("Codex bridge requires configured sign-in or dedicated key and OS isolation wrapper")
        messages = envelope.get("messages")
        if not isinstance(messages, list) or len(messages) != 2:
            raise ValueError("frozen Codex prompt is incomplete")
        prompt = (
            "Return one JSON object with exactly one key named payload. "
            "The payload value must be a JSON-encoded string containing the requested "
            "answer object. Do not use tools, files, shell commands, network retrieval "
            "or outside context.\n\n"
            + str(messages[0]["content"]) + "\n\n" + str(messages[1]["content"])
        )
        with tempfile.TemporaryDirectory(prefix="legalbot-codex-") as directory:
            root = Path(directory).resolve()
            codex_home = root / "codex-bridge-home"
            codex_home.mkdir(mode=0o700)
            signin_auth: Path | None = None
            if self.auth_mode == "chatgpt_signin":
                signin_auth = self._signin_auth_path()
                (codex_home / "auth.json").symlink_to(signin_auth)
            schema = root / "schema.json"
            answer = root / "answer.json"
            schema.write_text(json.dumps({
                "type": "object", "properties": {"payload": {"type": "string"}},
                "required": ["payload"], "additionalProperties": False,
            }), encoding="utf-8")
            env = {
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "HOME": str(root),
                "CODEX_HOME": str(codex_home),
                "TMPDIR": str(root),
            }
            if signin_auth is not None:
                env["LEGALBOT_CODEX_SIGNED_IN_AUTH"] = str(signin_auth)
            else:
                env["OPENAI_API_KEY"] = os.environ["LEGALBOT_CODEX_BRIDGE_KEY"]
            command = [
                self.wrapper, "codex", "exec", "--ephemeral", "--ignore-user-config",
                "--ignore-rules", "--sandbox", "read-only", "--skip-git-repo-check",
                "-c", "shell_environment_policy.inherit=none",
                "-c", "shell_environment_policy.ignore_default_excludes=false",
                "-c", "features.shell_tool=false",
                "-c", "features.unified_exec=false",
                "-c", "features.apps=false",
                "-c", "features.hooks=false",
                "-c", "agents.enabled=false",
                "-C", str(root), "-m", self.expected_model,
                "--output-schema", str(schema), "--output-last-message", str(answer), "-",
            ]
            process = await asyncio.create_subprocess_exec(
                *command, stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
                cwd=root, env=env,
            )
            try:
                await asyncio.wait_for(process.communicate(prompt.encode("utf-8")), timeout=300)
            except TimeoutError:
                process.kill()
                await process.wait()
                raise RuntimeError("Codex bridge timed out") from None
            if process.returncode != 0 or not answer.is_file():
                raise RuntimeError("Codex bridge failed without a verified JSON result")
            raw = answer.read_text(encoding="utf-8")
            wrapper = json.loads(raw)
            if not isinstance(wrapper, dict) or set(wrapper) != {"payload"} or not isinstance(wrapper["payload"], str):
                raise ValueError("Codex bridge output did not match the strict envelope")
            structured = json.loads(wrapper["payload"])
            if not isinstance(structured, dict):
                raise ValueError("Codex bridge output was not a JSON object")
            return {
                "structured": structured, "raw_text": wrapper["payload"],
                "model_version": self.expected_model, "finish_reason": "stop",
                "warnings": [], "usage": {},
                "transport_projection": _transport_projection(messages, prompt),
            }


class RoutedModelGateway:
    """Task-local route selection; concurrent jobs cannot change each other's model."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.qwen = LoopbackModelGateway(settings)
        self._selected: ContextVar[LoopbackModelGateway | None] = ContextVar(
            "legalbot_selected_model_gateway", default=None
        )
        self._routes: dict[str, LoopbackModelGateway] = {}

    def select(self, route_id: str) -> Token[LoopbackModelGateway | None]:
        route = load_development_chat_route(self.settings, route_id)
        gateway = self._routes.get(route_id)
        if gateway is None:
            kind = route["kind"]
            if kind == "qwen_local":
                gateway = self.qwen
            elif kind == "local_endpoint":
                gateway = LocalEndpointGateway(self.settings, route)
            elif kind == "hosted_api":
                gateway = OpenAIResponsesGateway(self.settings, route)
            elif kind == "anthropic_api":
                gateway = AnthropicMessagesGateway(self.settings, route)
            elif kind == "gemini_api":
                gateway = GeminiGenerateContentGateway(self.settings, route)
            else:
                gateway = CodexBridgeGateway(self.settings, route)
            self._routes[route_id] = gateway
        return self._selected.set(gateway)

    def reset(self, token: Token[LoopbackModelGateway | None]) -> None:
        self._selected.reset(token)

    def _current(self) -> LoopbackModelGateway:
        return self._selected.get() or self.qwen

    @property
    def assessment_character_budget(self) -> int:
        return self._current().assessment_character_budget

    @property
    def selected_model_id(self) -> str:
        return str(getattr(self._current(), "expected_model", self.settings.model_id))

    @property
    def selected_generation_config_sha256(self) -> str:
        return self._current()._generation_config_sha256()

    async def health(self) -> bool:
        return await self._current().health()

    async def draft(self, **kwargs: Any) -> Any:
        return await self._current().draft(**kwargs)

    async def repair(self, **kwargs: Any) -> Any:
        return await self._current().repair(**kwargs)

    async def invoke_json(self, **kwargs: Any) -> Any:
        return await self._current().invoke_json(**kwargs)
