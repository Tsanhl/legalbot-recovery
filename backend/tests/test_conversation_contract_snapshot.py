from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from app.contracts import ContractSchemaRegistry
from app.conversations import (
    ConversationNotFoundError,
    ConversationPolicy,
    ConversationStore,
    freeze_conversation_snapshot,
)


def _store(database, cipher) -> ConversationStore:
    return ConversationStore(
        database,
        cipher,
        policy=ConversationPolicy(
            retention_days=30,
            hot_cache_ttl_seconds=60,
            hot_cache_max_sessions=4,
            window_max_messages=2,
            window_max_tokens=512,
            session_message_quota=10,
        ),
    )


def test_snapshot_is_selected_sealed_and_contains_no_plaintext(database, cipher) -> None:
    store = _store(database, cipher)
    start = datetime(2026, 9, 1, 5, tzinfo=UTC)
    conversation_id = store.create_session("conversation-contract-1", now=start)
    for ordinal in range(1, 4):
        store.append_message(
            conversation_id,
            role="assistant" if ordinal == 2 else "user",
            content=f"Private snapshot message {ordinal}",
            now=start + timedelta(minutes=ordinal),
        )
    registry = ContractSchemaRegistry.from_project_root(Path.cwd())

    snapshot = freeze_conversation_snapshot(
        store,
        conversation_id=conversation_id,
        owner_scope_sha256="a" * 64,
        registry=registry,
        now=start + timedelta(hours=1),
    )

    registry.validate_new(snapshot)
    assert snapshot["revision"] == 3
    assert snapshot["truncated"] is True
    assert snapshot["omitted_message_count"] == 1
    assert snapshot["omitted_before_ordinal"] == 2
    assert snapshot["truncation_reason"] == "message_limit"
    assert [item["role"] for item in snapshot["messages"]] == [
        "assistant_verified",
        "user",
    ]
    assert "Private snapshot" not in str(snapshot)
    assert all(item["encrypted_content_ref"] == item["message_id"] for item in snapshot["messages"])


def test_unchanged_conversation_snapshot_is_replay_stable(database, cipher) -> None:
    store = _store(database, cipher)
    start = datetime(2026, 9, 1, 6, tzinfo=UTC)
    conversation_id = store.create_session("conversation-contract-2", now=start)
    store.append_message(conversation_id, role="user", content="Stable", now=start)
    registry = ContractSchemaRegistry.from_project_root(Path.cwd())

    first = freeze_conversation_snapshot(
        store,
        conversation_id=conversation_id,
        owner_scope_sha256="b" * 64,
        registry=registry,
        now=start + timedelta(minutes=1),
    )
    second = freeze_conversation_snapshot(
        store,
        conversation_id=conversation_id,
        owner_scope_sha256="b" * 64,
        registry=registry,
        now=start + timedelta(minutes=2),
    )

    assert second == first


def test_snapshot_requires_exact_scope_and_cannot_read_another_conversation(
    database, cipher
) -> None:
    store = _store(database, cipher)
    start = datetime(2026, 9, 1, 7, tzinfo=UTC)
    conversation_id = store.create_session("conversation-contract-3", now=start)
    store.append_message(conversation_id, role="user", content="Scoped", now=start)
    registry = ContractSchemaRegistry.from_project_root(Path.cwd())

    with pytest.raises(ValueError, match="owner scope"):
        freeze_conversation_snapshot(
            store,
            conversation_id=conversation_id,
            owner_scope_sha256="not-a-digest",
            registry=registry,
            now=start,
        )
    with pytest.raises(ConversationNotFoundError):
        freeze_conversation_snapshot(
            store,
            conversation_id="conversation-contract-other",
            owner_scope_sha256="c" * 64,
            registry=registry,
            now=start,
        )
