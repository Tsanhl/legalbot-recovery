"""Local browser sessions and per-connection credentials shared by API and worker.

Only opaque IDs reach the browser. Temporary keys are encrypted with LocalCipher;
remembered keys must use the native OS vault (no plaintext keyring fallback).
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from typing import Any
from uuid import uuid4

from .crypto import LocalCipher
from .db import Database

COOKIE = "legalbot_session"
SESSION_SECONDS = 30 * 86400
TEMP_SECONDS = 8 * 3600

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
    def __init__(self, database: Database, cipher: LocalCipher, *, vault: Any = None) -> None:
        self.db, self.cipher, self._vault = database, cipher, vault
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

    def vault(self) -> Any:
        if self._vault is not None:
            return self._vault
        import keyring

        backend = keyring.get_keyring()
        if not type(backend).__module__.startswith(
            ("keyring.backends.macOS", "keyring.backends.Windows", "keyring.backends.SecretService")
        ):
            raise ConnectionUnavailable(
                "A native operating-system credential store is required to remember a key"
            )
        return backend

    def create(
        self, session: str, route: dict[str, Any], *, secret: str | None, remember: bool
    ) -> dict[str, Any]:
        from .evaluation.ge_development_chat_authority import route_sha256

        remote_api = route["kind"] in {"hosted_api", "anthropic_api", "gemini_api"}
        if remote_api and (not secret or not 8 <= len(secret) <= 4096):
            raise ConnectionUnavailable("Enter an API key for the selected provider")
        if not remote_api and secret:
            raise ConnectionUnavailable("This route does not accept an API key")
        identifier = "connection-" + uuid4().hex
        encrypted = None
        if secret:
            if remember:
                self.vault().set_password("LegalBot.connections", identifier, secret)
            else:
                encrypted = self.cipher.encrypt_text(secret)
        try:
            self.db.execute(
                "INSERT INTO chat_connections(id,session_id,route_id,route_sha256,remembered,secret,expires_at) VALUES (?,?,?,?,?,?,?)",
                (
                    identifier,
                    session,
                    route["route_id"],
                    route_sha256(route),
                    int(remember),
                    encrypted,
                    time.time() + (SESSION_SECONDS if remember else TEMP_SECONDS),
                ),
            )
        except Exception:
            if secret and remember:
                self.vault().delete_password("LegalBot.connections", identifier)
            raise
        return self.public(self.get(identifier, session))

    def get(self, identifier: str, session: str | None = None) -> Any:
        row = self.db.fetchone(
            "SELECT c.* FROM chat_connections c JOIN chat_browser_sessions s ON s.id=c.session_id WHERE c.id=? AND c.disconnected=0 AND c.expires_at>? AND s.expires_at>?",
            (identifier, time.time(), time.time()),
        )
        if row is None or (session is not None and row["session_id"] != session):
            raise ConnectionUnavailable("Connection unavailable in this session")
        return row

    def secret(self, identifier: str) -> str:
        row = self.get(identifier)
        if row["remembered"]:
            return self.vault().get_password("LegalBot.connections", identifier) or ""
        return self.cipher.decrypt_text(bytes(row["secret"])) if row["secret"] else ""

    @staticmethod
    def public(row: Any) -> dict[str, Any]:
        return {
            key: row[key]
            for key in ("id", "route_id", "remembered", "expires_at", "test_status", "tested_at")
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
        row = self.get(identifier, session)
        # Revoke durable access first, even if the native vault is unavailable.
        self.db.execute(
            "UPDATE chat_connections SET disconnected=1,secret=NULL WHERE id=?", (identifier,)
        )
        if row["remembered"]:
            try:
                self.vault().delete_password("LegalBot.connections", identifier)
            except Exception:
                raise ConnectionUnavailable(
                    "Connection revoked; credential-store deletion requires attention"
                ) from None

    def claim_conversation(self, identifier: str, session: str) -> None:
        self.db.execute(
            "INSERT OR IGNORE INTO chat_owned_conversations VALUES (?,?,?)",
            (identifier, session, time.time()),
        )
        self.require_conversation(identifier, session)

    def require_conversation(self, identifier: str, session: str) -> None:
        row = self.db.fetchone(
            "SELECT session_id FROM chat_owned_conversations WHERE id=?", (identifier,)
        )
        if row is None or row["session_id"] != session:
            raise ConnectionUnavailable("Conversation unavailable in this session")

    def require_job(self, identifier: str, session: str) -> Any:
        row = self.db.fetchone("SELECT * FROM chat_owned_jobs WHERE job_id=?", (identifier,))
        if row is None or row["session_id"] != session:
            raise ConnectionUnavailable("Job unavailable in this session")
        return row


def request_digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
