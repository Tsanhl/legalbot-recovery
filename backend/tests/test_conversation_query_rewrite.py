from __future__ import annotations

import hashlib
from typing import Any

import pytest

from app.conversations import ConversationMessage, ConversationQueryRewriter


def _message(content: str) -> ConversationMessage:
    return ConversationMessage(
        id="message-history-1",
        conversation_id="conversation-1",
        ordinal=1,
        role="user",
        content=content,
        content_sha256=hashlib.sha256(content.encode()).hexdigest(),
        estimated_tokens=20,
        job_id="job-history-1",
        answer_id=None,
        created_at="2026-08-28T00:00:00+00:00",
    )


class _Model:
    def __init__(self, value: dict[str, Any]) -> None:
        self.value = value
        self.calls = 0

    async def invoke_json(self, **_: Any) -> tuple[str, dict[str, Any]]:
        self.calls += 1
        return "invocation-1", self.value


@pytest.mark.asyncio
async def test_rewrite_resolves_follow_up_without_creating_evidence() -> None:
    model = _Model(
        {
            "standalone_query": "I bought a defective laptop. What refund remedies are available?",
            "used_message_ids": ["message-history-1"],
        }
    )
    rewriter = ConversationQueryRewriter(model, enabled=True)
    result = await rewriter.rewrite(
        question="What remedies are available?",
        history=(_message("I bought a defective laptop."),),
    )
    assert result.status == "rewritten"
    assert result.used_message_ids == ("message-history-1",)
    assert result.safe_metadata()["conversation_is_evidence"] is False
    assert "evidence" not in result.__dataclass_fields__


@pytest.mark.asyncio
async def test_rewrite_rejects_evidence_fields_and_invented_amounts() -> None:
    history = (_message("I bought a defective laptop."),)
    for value in (
        {
            "standalone_query": "I bought a £900 defective laptop. What remedies are available?",
            "used_message_ids": ["message-history-1"],
        },
        {
            "standalone_query": "I bought a defective laptop. What remedies are available?",
            "used_message_ids": ["message-history-1"],
            "evidence_ids": ["fake"],
        },
    ):
        result = await ConversationQueryRewriter(_Model(value), enabled=True).rewrite(
            question="What remedies are available?",
            history=history,
        )
        assert result.status == "fallback"
        assert result.query == "What remedies are available?"


@pytest.mark.asyncio
async def test_disabled_rewrite_never_calls_model() -> None:
    model = _Model({})
    result = await ConversationQueryRewriter(model, enabled=False).rewrite(
        question="What remedies are available?",
        history=(_message("I bought a defective laptop."),),
    )
    assert result.status == "disabled"
    assert model.calls == 0
