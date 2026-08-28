from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from app.conversations import (
    ConversationExpiredError,
    ConversationPolicy,
    ConversationQuotaError,
    ConversationStore,
)


def _policy(**updates: int) -> ConversationPolicy:
    values = {
        "retention_days": 30,
        "hot_cache_ttl_seconds": 60,
        "hot_cache_max_sessions": 4,
        "window_max_messages": 3,
        "window_max_tokens": 512,
        "session_message_quota": 10,
    }
    values.update(updates)
    return ConversationPolicy(**values)


def _store(database, cipher, **updates: int) -> ConversationStore:
    return ConversationStore(database, cipher, policy=_policy(**updates))


def _insert_job(database, cipher, job_id: str, *, now: datetime) -> None:
    stamp = now.isoformat()
    database.execute(
        """
        INSERT INTO jobs(
          id,status,stage,progress,encrypted_question,question_summary,request_json,
          route,route_reasons_json,created_at,updated_at
        ) VALUES (?, 'running', 'verifying', 0.9, ?, 'Private encrypted question',
                  '{}', 'direct', '[]', ?, ?)
        """,
        (job_id, cipher.encrypt_text("Owner question"), stamp, stamp),
    )


def test_encrypted_sliding_window_reports_every_omitted_message(database, cipher) -> None:
    store = _store(database, cipher)
    start = datetime(2026, 8, 24, 10, tzinfo=UTC)
    conversation_id = store.create_session("conversation-owner-1", now=start)
    for ordinal in range(1, 6):
        store.append_message(
            conversation_id,
            role="user" if ordinal % 2 else "assistant",
            content=f"Private message {ordinal}",
            now=start + timedelta(minutes=ordinal),
        )

    window = store.window(conversation_id, now=start + timedelta(hours=1))

    assert [item.ordinal for item in window.messages] == [3, 4, 5]
    assert window.total_message_count == 5
    assert window.selected_message_count == 3
    assert window.omitted_message_count == 2
    assert window.truncated is True
    assert window.truncation_reason == "message_window_reached"
    encrypted = database.fetchone(
        "SELECT encrypted_content FROM conversation_messages WHERE conversation_id=? LIMIT 1",
        (conversation_id,),
    )
    assert encrypted is not None
    assert b"Private message" not in bytes(encrypted["encrypted_content"])


def test_oversized_newest_message_is_not_silently_truncated(database, cipher) -> None:
    store = _store(database, cipher, window_max_tokens=128)
    now = datetime(2026, 8, 24, tzinfo=UTC)
    conversation_id = store.create_session("conversation-owner-2", now=now)
    store.append_message(
        conversation_id,
        role="user",
        content="x" * 600,
        now=now,
    )

    window = store.window(conversation_id, now=now + timedelta(seconds=1))

    assert window.messages == ()
    assert window.omitted_message_count == 1
    assert window.truncated is True
    assert window.truncation_reason == "newest_message_exceeds_token_window"


def test_session_quota_and_immutable_message_content_fail_closed(database, cipher) -> None:
    store = _store(database, cipher, session_message_quota=2)
    now = datetime(2026, 8, 24, tzinfo=UTC)
    conversation_id = store.create_session("conversation-owner-3", now=now)
    first = store.append_message(conversation_id, role="user", content="one", now=now)
    store.append_message(conversation_id, role="assistant", content="two", now=now)

    with pytest.raises(ConversationQuotaError):
        store.append_message(conversation_id, role="user", content="three", now=now)
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        database.execute(
            "UPDATE conversation_messages SET encrypted_content=? WHERE id=?",
            (cipher.encrypt_text("replacement"), first.id),
        )


def test_expired_session_is_rejected_and_purged(database, cipher) -> None:
    store = _store(database, cipher)
    start = datetime(2026, 1, 1, tzinfo=UTC)
    conversation_id = store.create_session("conversation-owner-4", now=start)
    store.append_message(conversation_id, role="user", content="expires", now=start)

    with pytest.raises(ConversationExpiredError):
        store.window(conversation_id, now=start + timedelta(days=31))
    assert store.purge_expired(now=start + timedelta(days=31)) == 1
    assert database.fetchone(
        "SELECT id FROM conversation_sessions WHERE id=?", (conversation_id,)
    ) is None
    assert database.fetchone(
        "SELECT id FROM conversation_messages WHERE conversation_id=?", (conversation_id,)
    ) is None


def test_released_answer_projection_is_idempotent(database, cipher) -> None:
    store = _store(database, cipher)
    now = datetime(2026, 8, 24, tzinfo=UTC)
    conversation_id = store.create_session("conversation-owner-5", now=now)
    _insert_job(database, cipher, "job-owner-5", now=now)
    user_message = store.append_message(
        conversation_id,
        role="user",
        content="Owner question",
        job_id="job-owner-5",
        now=now,
    )
    store.bind_user_message_to_job(
        conversation_id=conversation_id,
        message_id=user_message.id,
        job_id="job-owner-5",
        now=now,
    )
    database.execute(
        """
        INSERT INTO answer_versions(
          id,job_id,version_number,version_kind,encrypted_content,word_count,
          release_state,policy_version,model_version,created_at
        ) VALUES ('answer-owner-5','job-owner-5',1,'verified',?,4,
                  'verified_full','test','test',?)
        """,
        (cipher.encrypt_text("Verified owner-only answer."), now.isoformat()),
    )
    database.execute(
        """
        UPDATE jobs SET status='complete',stage='complete',progress=1,
          answer_id='answer-owner-5',release_state='verified_full'
        WHERE id='job-owner-5'
        """
    )

    first = store.append_released_answer("job-owner-5", now=now)
    second = store.append_released_answer("job-owner-5", now=now)

    assert first == second
    window = store.window(conversation_id, now=now)
    assert [item.role for item in window.messages] == ["user", "assistant"]
    assert window.messages[-1].content == "Verified owner-only answer."


def test_job_deletion_clears_links_without_rewriting_durable_messages(
    database, cipher
) -> None:
    store = _store(database, cipher)
    now = datetime(2026, 8, 24, tzinfo=UTC)
    conversation_id = store.create_session("conversation-owner-cleanup", now=now)
    _insert_job(database, cipher, "job-owner-cleanup", now=now)
    user_message = store.append_message(
        conversation_id,
        role="user",
        content="Owner cleanup question",
        job_id="job-owner-cleanup",
        now=now,
    )
    store.bind_user_message_to_job(
        conversation_id=conversation_id,
        message_id=user_message.id,
        job_id="job-owner-cleanup",
        now=now,
    )
    database.execute(
        """
        INSERT INTO answer_versions(
          id,job_id,version_number,version_kind,encrypted_content,word_count,
          release_state,policy_version,model_version,created_at
        ) VALUES ('answer-owner-cleanup','job-owner-cleanup',1,'verified',?,4,
                  'verified_full','test','test',?)
        """,
        (cipher.encrypt_text("Verified cleanup answer."), now.isoformat()),
    )
    database.execute(
        """
        UPDATE jobs SET status='complete',stage='complete',progress=1,
          answer_id='answer-owner-cleanup',release_state='verified_full'
        WHERE id='job-owner-cleanup'
        """
    )
    assistant_message_id = store.append_released_answer("job-owner-cleanup", now=now)
    before = database.fetchall(
        """
        SELECT id,encrypted_content,content_sha256,job_id,answer_id
        FROM conversation_messages WHERE conversation_id=? ORDER BY ordinal
        """,
        (conversation_id,),
    )

    database.execute("DELETE FROM jobs WHERE id='job-owner-cleanup'")

    after = database.fetchall(
        """
        SELECT id,encrypted_content,content_sha256,job_id,answer_id
        FROM conversation_messages WHERE conversation_id=? ORDER BY ordinal
        """,
        (conversation_id,),
    )
    assert assistant_message_id is not None
    assert len(before) == len(after) == 2
    assert [row["id"] for row in after] == [row["id"] for row in before]
    assert [bytes(row["encrypted_content"]) for row in after] == [
        bytes(row["encrypted_content"]) for row in before
    ]
    assert [row["content_sha256"] for row in after] == [
        row["content_sha256"] for row in before
    ]
    assert all(row["job_id"] is None for row in after)
    assert all(row["answer_id"] is None for row in after)


def test_initialize_replaces_legacy_message_update_trigger(database) -> None:
    database.executescript(
        """
        DROP TRIGGER trg_conversation_messages_no_update;
        CREATE TRIGGER trg_conversation_messages_no_update
        BEFORE UPDATE ON conversation_messages
        BEGIN
          SELECT RAISE(ABORT, 'conversation message content is immutable');
        END;
        """
    )

    database.initialize()

    trigger = database.fetchone(
        """
        SELECT sql FROM sqlite_master
        WHERE type='trigger' AND name='trg_conversation_messages_no_update'
        """
    )
    assert trigger is not None
    assert "WHEN OLD.id IS NOT NEW.id" in str(trigger["sql"])
    assert "OLD.job_id IS NOT NULL AND NEW.job_id IS NULL" not in str(trigger["sql"])
