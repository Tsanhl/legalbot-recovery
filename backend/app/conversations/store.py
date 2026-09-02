from __future__ import annotations

import hashlib
import re
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol
from uuid import uuid4

from ..config import Settings
from ..crypto import LocalCipher
from ..db import PUBLIC_RELEASE_STATES, Database
from ..deletion_guard import (
    DeletionAuthorization,
    DeletionBlockedError,
    DeletionGuard,
    DeletionObjectClass,
)

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
_MAX_MESSAGE_CHARACTERS = 200_000


class ConversationError(RuntimeError):
    """Base class for fail-closed conversation-policy errors."""


class ConversationNotFoundError(ConversationError):
    pass


class ConversationExpiredError(ConversationError):
    pass


class ConversationQuotaError(ConversationError):
    pass


def _utc(value: datetime | None = None) -> datetime:
    current = value or datetime.now(UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    return current.astimezone(UTC)


def _parse_utc(value: object) -> datetime:
    parsed = datetime.fromisoformat(str(value))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _estimated_tokens(content: str) -> int:
    """Return a deterministic conservative token estimate without a model tokenizer."""

    return max(1, (len(content.encode("utf-8")) + 2) // 3)


def _require_safe_id(value: str, *, label: str) -> str:
    if not _SAFE_ID.fullmatch(value):
        raise ValueError(f"{label} has an invalid format")
    return value


@dataclass(frozen=True, slots=True)
class ConversationPolicy:
    retention_days: int = 30
    hot_cache_ttl_seconds: int = 604_800
    hot_cache_max_sessions: int = 128
    window_max_messages: int = 24
    window_max_tokens: int = 4096
    session_message_quota: int = 500

    def __post_init__(self) -> None:
        if not 1 <= self.retention_days <= 365:
            raise ValueError("conversation retention is invalid")
        if not 60 <= self.hot_cache_ttl_seconds <= 2_592_000:
            raise ValueError("conversation cache TTL is invalid")
        if not 1 <= self.hot_cache_max_sessions <= 10_000:
            raise ValueError("conversation cache capacity is invalid")
        if not 1 <= self.window_max_messages <= 64:
            raise ValueError("conversation message window is invalid")
        if not 128 <= self.window_max_tokens <= 16_384:
            raise ValueError("conversation token window is invalid")
        if not 2 <= self.session_message_quota <= 10_000:
            raise ValueError("conversation message quota is invalid")


@dataclass(frozen=True, slots=True)
class ConversationMessage:
    id: str
    conversation_id: str
    ordinal: int
    role: Literal["user", "assistant"]
    content: str
    content_sha256: str
    estimated_tokens: int
    job_id: str | None
    answer_id: str | None
    created_at: str


@dataclass(frozen=True, slots=True)
class ConversationWindow:
    conversation_id: str
    messages: tuple[ConversationMessage, ...]
    total_message_count: int
    selected_message_count: int
    selected_estimated_tokens: int
    omitted_message_count: int
    limit_messages: int
    limit_tokens: int
    truncated: bool
    truncation_reason: str | None
    expires_at: str


class ConversationCache(Protocol):
    def get(self, key: tuple[str, int, int, str]) -> ConversationWindow | None: ...

    def put(self, key: tuple[str, int, int, str], value: ConversationWindow) -> None: ...

    def invalidate(self, conversation_id: str) -> None: ...


class InMemoryConversationCache:
    """Small process-local LRU cache; durable content remains encrypted in SQLite."""

    def __init__(self, *, ttl_seconds: int, max_sessions: int) -> None:
        if ttl_seconds < 1 or max_sessions < 1:
            raise ValueError("conversation cache limits must be positive")
        self._ttl_seconds = ttl_seconds
        self._max_sessions = max_sessions
        self._values: OrderedDict[tuple[str, int, int, str], tuple[float, ConversationWindow]] = (
            OrderedDict()
        )
        self._lock = threading.RLock()

    def get(self, key: tuple[str, int, int, str]) -> ConversationWindow | None:
        now = time.monotonic()
        with self._lock:
            item = self._values.pop(key, None)
            if item is None:
                return None
            expires, value = item
            if expires <= now:
                return None
            self._values[key] = item
            return value

    def put(self, key: tuple[str, int, int, str], value: ConversationWindow) -> None:
        with self._lock:
            self._values.pop(key, None)
            self._values[key] = (time.monotonic() + self._ttl_seconds, value)
            while len(self._values) > self._max_sessions:
                self._values.popitem(last=False)

    def invalidate(self, conversation_id: str) -> None:
        with self._lock:
            stale = [key for key in self._values if key[0] == conversation_id]
            for key in stale:
                self._values.pop(key, None)


class ConversationStore:
    """Encrypted relational conversation log with explicit sliding-window limits.

    Conversation messages are context only.  They are never evidence and this
    class does not place them into an answer-model prompt.  Prompt admission is
    separately frozen and certified at the Phase-2B gate.
    """

    def __init__(
        self,
        database: Database,
        cipher: LocalCipher,
        *,
        policy: ConversationPolicy | None = None,
        cache: ConversationCache | None = None,
        deletion_guard: DeletionGuard | None = None,
    ) -> None:
        self.database = database
        self.cipher = cipher
        self.policy = policy or ConversationPolicy()
        self.cache = cache or InMemoryConversationCache(
            ttl_seconds=self.policy.hot_cache_ttl_seconds,
            max_sessions=self.policy.hot_cache_max_sessions,
        )
        self.deletion_guard = deletion_guard or DeletionGuard()

    @classmethod
    def from_settings(
        cls,
        database: Database,
        cipher: LocalCipher,
        settings: Settings,
        *,
        deletion_guard: DeletionGuard | None = None,
    ) -> ConversationStore:
        policy = ConversationPolicy(
            retention_days=settings.conversation_retention_days,
            hot_cache_ttl_seconds=settings.conversation_hot_cache_ttl_seconds,
            hot_cache_max_sessions=settings.conversation_hot_cache_max_sessions,
            window_max_messages=settings.conversation_window_max_messages,
            window_max_tokens=settings.conversation_window_max_tokens,
            session_message_quota=settings.conversation_session_message_quota,
        )
        return cls(database, cipher, policy=policy, deletion_guard=deletion_guard)

    def create_session(
        self,
        conversation_id: str | None = None,
        *,
        now: datetime | None = None,
    ) -> str:
        identifier = _require_safe_id(
            conversation_id or f"conversation-{uuid4()}", label="conversation ID"
        )
        stamp = _utc(now)
        expires = stamp + timedelta(days=self.policy.retention_days)
        with self.database.transaction() as connection:
            existing = connection.execute(
                "SELECT status,expires_at FROM conversation_sessions WHERE id=?",
                (identifier,),
            ).fetchone()
            if existing is not None:
                if (
                    str(existing["status"]) != "active"
                    or _parse_utc(existing["expires_at"]) <= stamp
                ):
                    raise ConversationExpiredError(identifier)
                return identifier
            connection.execute(
                """
                INSERT INTO conversation_sessions(
                  id,status,message_count,estimated_tokens,created_at,updated_at,
                  last_accessed_at,expires_at
                ) VALUES (?, 'active', 0, 0, ?, ?, ?, ?)
                """,
                (
                    identifier,
                    stamp.isoformat(),
                    stamp.isoformat(),
                    stamp.isoformat(),
                    expires.isoformat(),
                ),
            )
        return identifier

    def append_message(
        self,
        conversation_id: str,
        *,
        role: Literal["user", "assistant"],
        content: str,
        job_id: str | None = None,
        answer_id: str | None = None,
        now: datetime | None = None,
    ) -> ConversationMessage:
        identifier = _require_safe_id(conversation_id, label="conversation ID")
        if role not in {"user", "assistant"}:
            raise ValueError("conversation role is invalid")
        if not content.strip():
            raise ValueError("conversation message cannot be blank")
        if len(content) > _MAX_MESSAGE_CHARACTERS:
            raise ConversationQuotaError("conversation message exceeds the content quota")
        if job_id is not None:
            _require_safe_id(job_id, label="job ID")
        if answer_id is not None:
            _require_safe_id(answer_id, label="answer ID")
        stamp = _utc(now)
        expiry = stamp + timedelta(days=self.policy.retention_days)
        tokens = _estimated_tokens(content)
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        message_id = f"message-{uuid4()}"
        encrypted = self.cipher.encrypt_text(content)
        with self.database.transaction() as connection:
            session = connection.execute(
                "SELECT * FROM conversation_sessions WHERE id=?", (identifier,)
            ).fetchone()
            if session is None:
                raise ConversationNotFoundError(identifier)
            if str(session["status"]) != "active" or _parse_utc(session["expires_at"]) <= stamp:
                raise ConversationExpiredError(identifier)
            if int(session["message_count"]) >= self.policy.session_message_quota:
                raise ConversationQuotaError("conversation session message quota reached")
            ordinal = int(session["message_count"]) + 1
            connection.execute(
                """
                INSERT INTO conversation_messages(
                  id,conversation_id,ordinal,role,encrypted_content,content_sha256,
                  estimated_tokens,job_id,answer_id,created_at,expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    message_id,
                    identifier,
                    ordinal,
                    role,
                    encrypted,
                    digest,
                    tokens,
                    job_id,
                    answer_id,
                    stamp.isoformat(),
                    expiry.isoformat(),
                ),
            )
            connection.execute(
                """
                UPDATE conversation_sessions
                SET message_count=?,estimated_tokens=estimated_tokens+?,updated_at=?,
                    last_accessed_at=?,expires_at=?
                WHERE id=?
                """,
                (
                    ordinal,
                    tokens,
                    stamp.isoformat(),
                    stamp.isoformat(),
                    expiry.isoformat(),
                    identifier,
                ),
            )
        self.cache.invalidate(identifier)
        return ConversationMessage(
            id=message_id,
            conversation_id=identifier,
            ordinal=ordinal,
            role=role,
            content=content,
            content_sha256=digest,
            estimated_tokens=tokens,
            job_id=job_id,
            answer_id=answer_id,
            created_at=stamp.isoformat(),
        )

    def bind_user_message_to_job(
        self,
        *,
        conversation_id: str,
        message_id: str,
        job_id: str,
        now: datetime | None = None,
    ) -> None:
        identifier = _require_safe_id(conversation_id, label="conversation ID")
        _require_safe_id(message_id, label="message ID")
        _require_safe_id(job_id, label="job ID")
        stamp = _utc(now).isoformat()
        with self.database.transaction() as connection:
            message = connection.execute(
                "SELECT * FROM conversation_messages WHERE id=?", (message_id,)
            ).fetchone()
            job = connection.execute("SELECT id FROM jobs WHERE id=?", (job_id,)).fetchone()
            if (
                message is None
                or job is None
                or str(message["conversation_id"]) != identifier
                or str(message["role"]) != "user"
            ):
                raise ValueError("conversation job binding is invalid")
            existing = connection.execute(
                "SELECT * FROM conversation_job_bindings WHERE job_id=?", (job_id,)
            ).fetchone()
            if existing is not None:
                if (
                    str(existing["conversation_id"]) != identifier
                    or str(existing["user_message_id"]) != message_id
                ):
                    raise ConversationError("job already belongs to another conversation message")
                return
            connection.execute(
                """
                INSERT INTO conversation_job_bindings(
                  job_id,conversation_id,user_message_id,created_at
                ) VALUES (?, ?, ?, ?)
                """,
                (job_id, identifier, message_id, stamp),
            )

    def append_released_answer(self, job_id: str, *, now: datetime | None = None) -> str | None:
        """Idempotently project an ordinary released answer into its conversation."""

        _require_safe_id(job_id, label="job ID")
        binding = self.database.fetchone(
            "SELECT * FROM conversation_job_bindings WHERE job_id=?", (job_id,)
        )
        if binding is None:
            return None
        if binding["assistant_message_id"] not in (None, ""):
            return str(binding["assistant_message_id"])
        answer = self.database.fetchone(
            """
            SELECT av.* FROM answer_versions av JOIN jobs j ON j.answer_id=av.id
            WHERE j.id=? AND av.job_id=?
            """,
            (job_id, job_id),
        )
        if answer is None or str(answer["release_state"] or "") not in PUBLIC_RELEASE_STATES:
            return None
        existing = self.database.fetchone(
            """
            SELECT id FROM conversation_messages
            WHERE conversation_id=? AND job_id=? AND role='assistant'
            """,
            (str(binding["conversation_id"]), job_id),
        )
        if existing is None:
            content = self.cipher.decrypt_text(bytes(answer["encrypted_content"]))
            message = self.append_message(
                str(binding["conversation_id"]),
                role="assistant",
                content=content,
                job_id=job_id,
                answer_id=str(answer["id"]),
                now=now,
            )
            message_id = message.id
        else:
            message_id = str(existing["id"])
        stamp = _utc(now).isoformat()
        with self.database.transaction() as connection:
            current = connection.execute(
                "SELECT assistant_message_id FROM conversation_job_bindings WHERE job_id=?",
                (job_id,),
            ).fetchone()
            if current is None:
                raise ConversationError("conversation job binding disappeared")
            if current["assistant_message_id"] in (None, ""):
                connection.execute(
                    """
                    UPDATE conversation_job_bindings
                    SET assistant_message_id=?,completed_at=? WHERE job_id=?
                    """,
                    (message_id, stamp, job_id),
                )
            elif str(current["assistant_message_id"]) != message_id:
                raise ConversationError("job has a different assistant message")
        return message_id

    def window(
        self,
        conversation_id: str,
        *,
        max_messages: int | None = None,
        max_tokens: int | None = None,
        now: datetime | None = None,
    ) -> ConversationWindow:
        identifier = _require_safe_id(conversation_id, label="conversation ID")
        message_limit = min(
            max(1, max_messages or self.policy.window_max_messages),
            self.policy.window_max_messages,
        )
        token_limit = min(
            max(1, max_tokens or self.policy.window_max_tokens),
            self.policy.window_max_tokens,
        )
        stamp = _utc(now)
        session = self.database.fetchone(
            "SELECT * FROM conversation_sessions WHERE id=?", (identifier,)
        )
        if session is None:
            raise ConversationNotFoundError(identifier)
        if str(session["status"]) != "active" or _parse_utc(session["expires_at"]) <= stamp:
            raise ConversationExpiredError(identifier)
        cache_key = (identifier, message_limit, token_limit, str(session["updated_at"]))
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached
        rows = self.database.fetchall(
            """
            SELECT * FROM conversation_messages
            WHERE conversation_id=? ORDER BY ordinal DESC LIMIT ?
            """,
            (identifier, message_limit),
        )
        selected_newest: list[ConversationMessage] = []
        selected_tokens = 0
        truncation_reason: str | None = None
        for row in rows:
            tokens = int(row["estimated_tokens"])
            if selected_tokens + tokens > token_limit:
                truncation_reason = (
                    "newest_message_exceeds_token_window"
                    if not selected_newest
                    else "token_window_reached"
                )
                break
            content = self.cipher.decrypt_text(bytes(row["encrypted_content"]))
            if hashlib.sha256(content.encode("utf-8")).hexdigest() != row["content_sha256"]:
                raise ConversationError("conversation message digest mismatch")
            selected_newest.append(
                ConversationMessage(
                    id=str(row["id"]),
                    conversation_id=identifier,
                    ordinal=int(row["ordinal"]),
                    role=str(row["role"]),  # type: ignore[arg-type]
                    content=content,
                    content_sha256=str(row["content_sha256"]),
                    estimated_tokens=tokens,
                    job_id=str(row["job_id"]) if row["job_id"] is not None else None,
                    answer_id=(str(row["answer_id"]) if row["answer_id"] is not None else None),
                    created_at=str(row["created_at"]),
                )
            )
            selected_tokens += tokens
        selected = tuple(reversed(selected_newest))
        total = int(session["message_count"])
        omitted = max(0, total - len(selected))
        if omitted and truncation_reason is None:
            truncation_reason = "message_window_reached"
        result = ConversationWindow(
            conversation_id=identifier,
            messages=selected,
            total_message_count=total,
            selected_message_count=len(selected),
            selected_estimated_tokens=selected_tokens,
            omitted_message_count=omitted,
            limit_messages=message_limit,
            limit_tokens=token_limit,
            truncated=omitted > 0,
            truncation_reason=truncation_reason,
            expires_at=str(session["expires_at"]),
        )
        self.database.execute(
            "UPDATE conversation_sessions SET last_accessed_at=? WHERE id=?",
            (stamp.isoformat(), identifier),
        )
        self.cache.put(cache_key, result)
        return result

    def close_session(self, conversation_id: str, *, now: datetime | None = None) -> None:
        identifier = _require_safe_id(conversation_id, label="conversation ID")
        changed = self.database.execute(
            """
            UPDATE conversation_sessions SET status='closed',updated_at=?
            WHERE id=? AND status='active'
            """,
            (_utc(now).isoformat(), identifier),
        )
        if (
            changed.rowcount == 0
            and self.database.fetchone(
                "SELECT id FROM conversation_sessions WHERE id=?", (identifier,)
            )
            is None
        ):
            raise ConversationNotFoundError(identifier)
        self.cache.invalidate(identifier)

    def purge_expired(
        self,
        *,
        now: datetime | None = None,
        authorization: DeletionAuthorization | None = None,
    ) -> int:
        stamp = _utc(now).isoformat()
        rows = self.database.fetchall(
            "SELECT id FROM conversation_sessions WHERE expires_at<=?", (stamp,)
        )
        for row in rows:
            self.database.execute(
                "UPDATE conversation_sessions SET status='expired' WHERE id=? AND status='active'",
                (str(row["id"]),),
            )
        if authorization is None:
            return 0
        deleted = 0
        for row in rows:
            identifier = str(row["id"])
            try:
                self.deletion_guard.require(
                    object_class=DeletionObjectClass.CONVERSATION_SESSION,
                    object_id=identifier,
                    authorization=authorization,
                    now=now,
                )
            except DeletionBlockedError:
                continue
            with self.database.transaction() as connection:
                cursor = connection.execute(
                    "DELETE FROM conversation_sessions WHERE id=? AND expires_at<=?",
                    (identifier, stamp),
                )
            if cursor.rowcount:
                self.cache.invalidate(identifier)
                deleted += 1
        return deleted
