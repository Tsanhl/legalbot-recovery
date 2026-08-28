"""Dependency-free request and response contracts for model-runtime API v1."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

API_VERSION = "v1"
ALLOWED_ROLES = frozenset({"system", "user", "assistant"})
ALLOWED_GENERATION_MODES = frozenset({"draft", "repair", "semantic_verify", "query_rewrite"})
MAX_MESSAGES = 64
MAX_MESSAGE_CHARS = 250_000
MAX_REQUEST_ID_CHARS = 128
MAX_STOP_SEQUENCES = 16
MAX_STOP_CHARS = 128


class ContractError(ValueError):
    """Raised when an API payload violates the public v1 contract."""


def _expect_mapping(value: Any, field_name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ContractError(f"{field_name} must be a JSON object")
    return value


def _reject_unknown(payload: Mapping[str, Any], allowed: set[str], where: str) -> None:
    unknown = sorted(set(payload) - allowed)
    if unknown:
        raise ContractError(f"unknown {where} field(s): {', '.join(unknown)}")


@dataclass(frozen=True, slots=True)
class Message:
    role: str
    content: str

    @classmethod
    def from_dict(cls, value: Any) -> Message:
        payload = _expect_mapping(value, "message")
        _reject_unknown(payload, {"role", "content"}, "message")
        role = payload.get("role")
        content = payload.get("content")
        if role not in ALLOWED_ROLES:
            raise ContractError("message.role must be system, user, or assistant")
        if not isinstance(content, str) or not content.strip():
            raise ContractError("message.content must be a non-empty string")
        if len(content) > MAX_MESSAGE_CHARS:
            raise ContractError(f"message.content exceeds the {MAX_MESSAGE_CHARS}-character limit")
        return cls(role=role, content=content)

    def to_dict(self) -> dict[str, str]:
        return {"role": self.role, "content": self.content}


@dataclass(frozen=True, slots=True)
class GenerateRequest:
    request_id: str
    mode: str
    payload: Mapping[str, Any]
    messages: tuple[Message, ...]
    max_tokens: int = 512
    temperature: float = 0.0
    top_p: float = 1.0
    seed: int = 0
    stop: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, value: Any) -> GenerateRequest:
        payload = _expect_mapping(value, "request")
        _reject_unknown(
            payload,
            {
                "request_id",
                "mode",
                "payload",
                "messages",
                "max_tokens",
                "temperature",
                "top_p",
                "seed",
                "stop",
            },
            "request",
        )

        request_id = payload.get("request_id")
        if not isinstance(request_id, str) or not request_id.strip():
            raise ContractError("request_id must be a non-empty string")
        if len(request_id) > MAX_REQUEST_ID_CHARS:
            raise ContractError(f"request_id exceeds the {MAX_REQUEST_ID_CHARS}-character limit")

        mode = payload.get("mode")
        if mode not in ALLOWED_GENERATION_MODES:
            raise ContractError("mode must be draft, repair, semantic_verify, or query_rewrite")

        generation_payload = payload.get("payload")
        if not isinstance(generation_payload, Mapping):
            raise ContractError("payload must be a JSON object")
        try:
            # Also rejects objects that only happen to implement Mapping but are not JSON.
            json_payload = dict(generation_payload)
            json.dumps(json_payload, ensure_ascii=False)
        except (TypeError, ValueError) as exc:
            raise ContractError("payload must contain only JSON values") from exc

        raw_messages = payload.get("messages")
        if raw_messages is None:
            raw_messages = generation_payload.get("messages")
        if raw_messages is None and isinstance(generation_payload.get("prompt"), str):
            raw_messages = [{"role": "user", "content": generation_payload["prompt"]}]
        if not isinstance(raw_messages, Sequence) or isinstance(raw_messages, str | bytes):
            raise ContractError("messages must be a JSON array")
        if not raw_messages or len(raw_messages) > MAX_MESSAGES:
            raise ContractError(f"messages must contain between 1 and {MAX_MESSAGES} items")
        messages = tuple(Message.from_dict(item) for item in raw_messages)
        if not any(message.role == "user" for message in messages):
            raise ContractError("messages must include at least one user message")
        if any(message.role == "system" for message in messages[1:]):
            raise ContractError("a system message is allowed only as the first message")

        max_tokens = payload.get("max_tokens", 512)
        if isinstance(max_tokens, bool) or not isinstance(max_tokens, int):
            raise ContractError("max_tokens must be an integer")
        if max_tokens < 1:
            raise ContractError("max_tokens must be positive")

        temperature = payload.get("temperature", 0.0)
        if isinstance(temperature, bool) or not isinstance(temperature, int | float):
            raise ContractError("temperature must be a number")
        temperature = float(temperature)
        if not 0.0 <= temperature <= 2.0:
            raise ContractError("temperature must be between 0 and 2")

        top_p = payload.get("top_p", 1.0)
        if isinstance(top_p, bool) or not isinstance(top_p, int | float):
            raise ContractError("top_p must be a number")
        top_p = float(top_p)
        if not 0.0 < top_p <= 1.0:
            raise ContractError("top_p must be greater than 0 and at most 1")

        seed = payload.get("seed", 0)
        if isinstance(seed, bool) or not isinstance(seed, int):
            raise ContractError("seed must be an integer")
        if not 0 <= seed <= 0xFFFFFFFF:
            raise ContractError("seed must be between 0 and 4294967295")

        raw_stop = payload.get("stop", [])
        if not isinstance(raw_stop, Sequence) or isinstance(raw_stop, str | bytes):
            raise ContractError("stop must be a JSON array")
        if len(raw_stop) > MAX_STOP_SEQUENCES:
            raise ContractError(f"stop may contain at most {MAX_STOP_SEQUENCES} sequences")
        stop: list[str] = []
        for item in raw_stop:
            if not isinstance(item, str) or not item:
                raise ContractError("each stop sequence must be a non-empty string")
            if len(item) > MAX_STOP_CHARS:
                raise ContractError(f"stop sequences may not exceed {MAX_STOP_CHARS} characters")
            stop.append(item)

        return cls(
            request_id=request_id,
            mode=mode,
            payload=json_payload,
            messages=messages,
            max_tokens=max_tokens,
            temperature=temperature,
            top_p=top_p,
            seed=seed,
            stop=tuple(stop),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "mode": self.mode,
            "payload": dict(self.payload),
            "messages": [message.to_dict() for message in self.messages],
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "top_p": self.top_p,
            "seed": self.seed,
            "stop": list(self.stop),
        }


@dataclass(frozen=True, slots=True)
class Usage:
    input_tokens: int
    output_tokens: int

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    def to_dict(self) -> dict[str, int]:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens": self.total_tokens,
        }


@dataclass(frozen=True, slots=True)
class GenerateResponse:
    request_id: str
    model_version: str
    backend: str
    raw_text: str
    structured: Mapping[str, Any]
    rubric_scores: Mapping[str, float]
    finish_reason: str
    usage: Usage
    generation_ms: int
    deterministic: bool
    time_to_first_token_ms: int | None = None
    peak_memory_gb: float | None = None
    warnings: tuple[str, ...] = ()
    api_version: str = API_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "api_version": self.api_version,
            "request_id": self.request_id,
            "model_version": self.model_version,
            "backend": self.backend,
            "raw_text": self.raw_text,
            "structured": dict(self.structured),
            "rubric_scores": dict(self.rubric_scores),
            "finish_reason": self.finish_reason,
            "usage": self.usage.to_dict(),
            "generation_ms": self.generation_ms,
            "time_to_first_token_ms": self.time_to_first_token_ms,
            "deterministic": self.deterministic,
            "peak_memory_gb": self.peak_memory_gb,
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True, slots=True)
class HealthResponse:
    status: str
    backend: str
    model_id: str
    model_loaded: bool
    stub_mode: bool
    memory_profile: Mapping[str, Any]
    detail: str | None = None
    api_version: str = API_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "api_version": self.api_version,
            "status": self.status,
            "backend": self.backend,
            "model_id": self.model_id,
            "model_loaded": self.model_loaded,
            "stub_mode": self.stub_mode,
            "memory_profile": dict(self.memory_profile),
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class ErrorResponse:
    code: str
    message: str
    request_id: str | None = None
    api_version: str = API_VERSION
    details: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "api_version": self.api_version,
            "request_id": self.request_id,
            "error": {
                "code": self.code,
                "message": self.message,
                "details": dict(self.details),
            },
        }
