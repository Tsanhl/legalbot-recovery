"""Local browser sessions and the session-owned Qwen connection.

Only opaque IDs reach the browser. Hosted-API keys and the Codex route were
removed on 25 September 2026; a connection now only binds a session to the
frozen local Qwen route and owns that session's conversations and jobs.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from .crypto import LocalCipher
from .db import Database

COOKIE = "legalbot_session"
SESSION_SECONDS = 30 * 86400

_SCHEMA = """
CREATE TABLE IF NOT EXISTS chat_browser_sessions (
 id TEXT PRIMARY KEY, token_sha256 TEXT UNIQUE NOT NULL, expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS chat_connections (
 id TEXT PRIMARY KEY, session_id TEXT NOT NULL, route_id TEXT NOT NULL,
 route_sha256 TEXT NOT NULL, remembered INTEGER NOT NULL, secret BLOB,
 expires_at REAL NOT NULL, disconnected INTEGER NOT NULL DEFAULT 0,
 test_status TEXT NOT NULL DEFAULT 'untested', tested_at REAL
);
CREATE TABLE IF NOT EXISTS chat_owned_conversations (
 id TEXT PRIMARY KEY, session_id TEXT NOT NULL, created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS chat_owned_jobs (
 job_id TEXT PRIMARY KEY, session_id TEXT NOT NULL, connection_id TEXT NOT NULL,
 conversation_id TEXT NOT NULL, input_sha256 TEXT NOT NULL,
 idempotency_sha256 TEXT UNIQUE NOT NULL
);
"""


class ConnectionUnavailable(ValueError):
    pass


class ConnectionStore:
    def __init__(self, database: Database, cipher: LocalCipher) -> None:
        self.db, self.cipher = database, cipher
        self.db.executescript(_SCHEMA)

    def session(self, token: str | None) -> str:
        row = self.db.fetchone(
            "SELECT id FROM chat_browser_sessions WHERE token_sha256=? AND expires_at>?",
            (hashlib.sha256((token or "").encode()).hexdigest(), time.time()),
        )
        if row is None:
            raise ConnectionUnavailable("Session expired; reconnect in this browser")
        return str(row["id"])

    def create_session(self) -> tuple[str, str]:
        token, identifier = secrets.token_urlsafe(32), "session-" + uuid4().hex
        self.db.execute(
            "INSERT INTO chat_browser_sessions VALUES (?,?,?)",
            (
                identifier,
                hashlib.sha256(token.encode()).hexdigest(),
                time.time() + SESSION_SECONDS,
            ),
        )
        return identifier, token

    def create(self, session: str, route: dict[str, Any]) -> dict[str, Any]:
        from .evaluation.ge_development_chat_authority import route_sha256

        if route["kind"] != "qwen_local":
            raise ConnectionUnavailable("Only the local Qwen route is available")
        identifier = "connection-" + uuid4().hex
        # remembered/secret columns are retained for schema compatibility only.
        self.db.execute(
            "INSERT INTO chat_connections(id,session_id,route_id,route_sha256,remembered,secret,expires_at) VALUES (?,?,?,?,?,?,?)",
            (identifier, session, route["route_id"], route_sha256(route), 0, None,
             time.time() + SESSION_SECONDS),
        )
        return self.public(self.get(identifier, session))

    def get(self, identifier: str, session: str | None = None) -> Any:
        row = self.db.fetchone(
            "SELECT c.* FROM chat_connections c JOIN chat_browser_sessions s ON s.id=c.session_id WHERE c.id=? AND c.disconnected=0 AND c.expires_at>? AND s.expires_at>?",
            (identifier, time.time(), time.time()),
        )
        if row is None or (session is not None and row["session_id"] != session):
            raise ConnectionUnavailable("Connection unavailable in this session")
        return row

    @staticmethod
    def public(row: Any) -> dict[str, Any]:
        return {
            key: row[key]
            for key in ("id", "route_id", "expires_at", "test_status", "tested_at")
        }

    def list(self, session: str) -> list[dict[str, Any]]:
        return [
            self.public(row)
            for row in self.db.fetchall(
                "SELECT * FROM chat_connections WHERE session_id=? AND disconnected=0 AND expires_at>? ORDER BY rowid",
                (session, time.time()),
            )
        ]

    def disconnect(self, identifier: str, session: str) -> None:
        self.get(identifier, session)
        self.db.execute(
            "UPDATE chat_connections SET disconnected=1,secret=NULL WHERE id=?", (identifier,)
        )

    def claim_conversation(self, identifier: str, session: str) -> None:
        self.db.execute(
            "INSERT OR IGNORE INTO chat_owned_conversations VALUES (?,?,?)",
            (identifier, session, time.time()),
        )
        self.require_conversation(identifier, session)

    def require_conversation(self, identifier: str, session: str) -> None:
        row = self.db.fetchone(
            "SELECT o.session_id,c.status,c.expires_at FROM chat_owned_conversations o "
            "LEFT JOIN conversation_sessions c ON c.id=o.id WHERE o.id=?", (identifier,)
        )
        if row is None or row["session_id"] != session:
            raise ConnectionUnavailable("Conversation unavailable in this session")
        if row["expires_at"] is not None and (
            row["status"] != "active"
            or datetime.fromisoformat(row["expires_at"]) <= datetime.now(UTC)
        ):
            raise ConnectionUnavailable("Conversation expired or closed")

    def require_job(self, identifier: str, session: str) -> Any:
        row = self.db.fetchone("SELECT * FROM chat_owned_jobs WHERE job_id=?", (identifier,))
        if row is None or row["session_id"] != session:
            raise ConnectionUnavailable("Job unavailable in this session")
        return row


def request_digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
