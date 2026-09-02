from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.contracts import ContractSchemaRegistry
from app.conversations import MatterFactRef, MatterFactStore


def _store(database, cipher) -> MatterFactStore:
    return MatterFactStore(
        database,
        cipher,
        ContractSchemaRegistry.from_project_root(Path.cwd()),
    )


def _session(database, conversation_id: str, now: datetime) -> None:
    stamp = now.isoformat()
    database.execute(
        "INSERT INTO conversation_sessions(id,status,message_count,estimated_tokens,"
        "created_at,updated_at,last_accessed_at,expires_at) "
        "VALUES (?, 'active', 1, 10, ?, ?, ?, ?)",
        (conversation_id, stamp, stamp, stamp, "2026-10-01T00:00:00+00:00"),
    )


def _ref(seed: str = "a") -> tuple[MatterFactRef, ...]:
    return (
        MatterFactRef(
            source_kind="message",
            source_id=f"message-{seed * 8}",
            source_revision=1,
            content_sha256=seed * 64,
            safe_locator="message:1",
        ),
    )


def test_fact_supersession_is_immutable_and_snapshot_is_plaintext_free(database, cipher) -> None:
    store = _store(database, cipher)
    now = datetime(2026, 9, 1, 8, tzinfo=UTC)
    _session(database, "conversation-facts-1", now)
    first = store.append_fact(
        conversation_id="conversation-facts-1",
        owner_scope_sha256="1" * 64,
        fact_key="incident.date",
        data_type="date",
        value="2026-08-01",
        origin="user_statement",
        status="stated",
        refs=_ref("a"),
        created_at=now,
        affected_issue_ids=("issue-limitation",),
        as_of_status="historical",
    )
    second = store.append_fact(
        conversation_id="conversation-facts-1",
        owner_scope_sha256="1" * 64,
        fact_key="incident.date",
        data_type="date",
        value="2026-08-02",
        origin="user_confirmation",
        status="confirmed",
        refs=_ref("b"),
        created_at=now,
        supersedes_fact_id=first,
        affected_issue_ids=("issue-limitation",),
        as_of_status="historical",
    )

    snapshot = store.freeze_snapshot(
        conversation_id="conversation-facts-1",
        owner_scope_sha256="1" * 64,
        conversation_revision=1,
    )

    assert [fact["status"] for fact in snapshot["facts"]] == ["superseded", "confirmed"]
    assert snapshot["facts"][1]["supersedes_fact_id"] == first
    assert "2026-08-01" not in str(snapshot)
    assert "2026-08-02" not in str(snapshot)
    assert second == snapshot["facts"][1]["fact_id"]
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        database.execute(
            "UPDATE matter_fact_records SET status='rejected' WHERE id=?",
            (first,),
        )


def test_repeated_fact_requires_supersession_or_explicit_conflict(database, cipher) -> None:
    store = _store(database, cipher)
    now = datetime(2026, 9, 1, 9, tzinfo=UTC)
    _session(database, "conversation-facts-2", now)
    store.append_fact(
        conversation_id="conversation-facts-2",
        owner_scope_sha256="2" * 64,
        fact_key="employment.status",
        data_type="text",
        value="employee",
        origin="user_statement",
        status="stated",
        refs=_ref("c"),
        created_at=now,
    )
    with pytest.raises(RuntimeError, match="supersession"):
        store.append_fact(
            conversation_id="conversation-facts-2",
            owner_scope_sha256="2" * 64,
            fact_key="employment.status",
            data_type="text",
            value="worker",
            origin="user_statement",
            status="stated",
            refs=_ref("d"),
            created_at=now,
        )


def test_unknown_and_scope_rules_fail_closed(database, cipher) -> None:
    store = _store(database, cipher)
    now = datetime(2026, 9, 1, 10, tzinfo=UTC)
    _session(database, "conversation-facts-3", now)
    store.append_fact(
        conversation_id="conversation-facts-3",
        owner_scope_sha256="3" * 64,
        fact_key="claim.amount",
        data_type="money",
        value=None,
        origin="system_placeholder",
        status="unknown",
        refs=_ref("e"),
        created_at=now,
    )
    with pytest.raises(RuntimeError, match="owner scope"):
        store.freeze_snapshot(
            conversation_id="conversation-facts-3",
            owner_scope_sha256="4" * 64,
            conversation_revision=1,
        )
    with pytest.raises(ValueError, match="derivation rule"):
        store.append_fact(
            conversation_id="conversation-facts-3",
            owner_scope_sha256="3" * 64,
            fact_key="claim.deadline",
            data_type="date",
            value="2026-09-30",
            origin="deterministic_derivation",
            status="confirmed",
            refs=_ref("f"),
            created_at=now,
        )
