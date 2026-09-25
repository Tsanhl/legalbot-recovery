"""Frozen, development-only route selection for the existing AnswerRunner.

The owner removed the hosted-API and Codex routes on 25 September 2026; the
only answering route is the local Qwen gateway. Route selection stays
task-local so a job still verifies its frozen route before running.
"""

from __future__ import annotations

from contextvars import ContextVar, Token
from typing import Any

from .config import Settings
from .evaluation.ge_development_chat_authority import load_development_chat_route
from .runtime_adapters import LoopbackModelGateway


class RoutedModelGateway:
    """Task-local route selection; concurrent jobs cannot change each other's model."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.qwen = LoopbackModelGateway(settings)
        self._selected: ContextVar[LoopbackModelGateway | None] = ContextVar(
            "legalbot_selected_model_gateway", default=None
        )

    def select(
        self, route_id: str, *, connection_id: str | None = None, connection_store: Any = None,
    ) -> Token[LoopbackModelGateway | None]:
        route = load_development_chat_route(self.settings, route_id)
        if route["kind"] != "qwen_local":
            raise RuntimeError("development_chat_route_not_authorised")
        if connection_id is not None:
            from .evaluation.ge_development_chat_authority import route_sha256

            connection = connection_store.get(connection_id)
            if connection["route_id"] != route_id or connection["route_sha256"] != route_sha256(route):
                raise RuntimeError("connection_route_changed")
        return self._selected.set(self.qwen)

    def reset(self, token: Token[LoopbackModelGateway | None]) -> None:
        self._selected.reset(token)

    def _current(self) -> LoopbackModelGateway:
        return self._selected.get() or self.qwen

    @property
    def assessment_character_budget(self) -> int:
        return self._current().assessment_character_budget

    @property
    def compact_assessment_rules(self) -> bool:
        return bool(getattr(self._current(), "compact_assessment_rules", False))

    @property
    def evidence_character_budget(self) -> int:
        return self._current().evidence_character_budget

    @property
    def evidence_token_budget(self) -> int:
        return self._current().evidence_token_budget

    @property
    def selected_model_id(self) -> str:
        return str(getattr(self._current(), "expected_model", self.settings.model_id))

    @property
    def claim_review_concurrency(self) -> int:
        return int(getattr(self._current(), "claim_review_concurrency", 1))

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
