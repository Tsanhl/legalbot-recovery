from __future__ import annotations

import hashlib
from types import SimpleNamespace

import httpx
import pytest

from app.api.main import app
from app.config import Settings
from app.conversations import ConversationStore
from app.research.freshness import KnowledgeFreshnessCoordinator


class _Admitter:
    def __init__(self, database) -> None:
        self.database = database

    def admit(self, request):
        identity = hashlib.sha256(repr(request).encode()).hexdigest()
        return self.database.enqueue_research_task(
            task_id=f"research-{identity[:40]}",
            idempotency_key=identity,
            task_type=request.task_type.value,
            trigger_kind=request.trigger.value,
            priority_band=request.priority.value,
            subject=request.subject,
            jurisdiction=request.jurisdiction,
            as_of_date=request.as_of_date.isoformat(),
            query_sha256=request.query_sha256 or "d" * 64,
            source_id=request.source_id,
            authority_identity_id=request.authority_identity_id,
        )


@pytest.mark.asyncio
async def test_conversation_window_api_exposes_explicit_omission_metadata(
    database, cipher, tmp_path
) -> None:
    settings = Settings(
        project_root=tmp_path,
        test_mode=True,
        conversation_window_max_messages=2,
    )
    conversations = ConversationStore.from_settings(database, cipher, settings)
    conversation_id = conversations.create_session("conversation-api-1")
    for value in ("one", "two", "three"):
        conversations.append_message(conversation_id, role="user", content=value)
    previous = getattr(app.state, "services", None)
    app.state.services = SimpleNamespace(
        database=database,
        cipher=cipher,
        settings=settings,
        conversations=conversations,
    )
    try:
        transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 4311))
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1:8777",
        ) as client:
            response = await client.get(f"/api/v1/conversation-sessions/{conversation_id}/window")
    finally:
        if previous is None:
            del app.state.services
        else:
            app.state.services = previous

    assert response.status_code == 200
    payload = response.json()
    assert [message["content"] for message in payload["messages"]] == ["two", "three"]
    assert payload["omitted_message_count"] == 1
    assert payload["truncated"] is True
    assert payload["conversation_is_evidence"] is False


@pytest.mark.asyncio
async def test_knowledge_webhook_can_only_enqueue_quarantine_research(
    database, cipher, tmp_path
) -> None:
    settings = Settings(project_root=tmp_path, test_mode=True)
    freshness = KnowledgeFreshnessCoordinator(database, cipher, _Admitter(database))
    previous = getattr(app.state, "services", None)
    app.state.services = SimpleNamespace(
        database=database,
        cipher=cipher,
        settings=settings,
        freshness=freshness,
    )
    try:
        transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 4311))
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1:8777",
        ) as client:
            response = await client.post(
                "/api/v1/internal/knowledge-events",
                json={
                    "event_type": "source_changed",
                    "subject": "contract",
                    "source_id": "legislation_gov_uk",
                    "authority_identity_id": "ukpga:1977:50",
                    "source_date": "1977-07-29",
                    "observed_at": "2026-08-24T12:00:00Z",
                    "safe_payload": {"change_kind": "official_version_observed"},
                },
            )
    finally:
        if previous is None:
            del app.state.services
        else:
            app.state.services = previous

    assert response.status_code == 202
    payload = response.json()
    assert payload["status"] == "queued_for_quarantine"
    assert payload["owner_admission_required"] is True
    assert payload["writes_index"] is False
    assert payload["stages_quarantine_only"] is True
