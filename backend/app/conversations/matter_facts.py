"""Encrypted, immutable structured matter facts and selected snapshots."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from ..contracts import ContractSchemaRegistry, canonical_json_bytes, seal_contract
from ..crypto import LocalCipher
from ..db import Database
from .store import ConversationNotFoundError

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,254}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

FactDataType = Literal[
    "date",
    "datetime",
    "money",
    "integer",
    "decimal",
    "boolean",
    "text",
    "identifier",
    "location",
    "party_role",
    "duration",
]
FactOrigin = Literal[
    "user_statement",
    "document_extraction",
    "deterministic_derivation",
    "user_confirmation",
    "system_placeholder",
]
FactStatus = Literal[
    "stated",
    "extracted",
    "confirmed",
    "disputed",
    "unknown",
    "superseded",
    "rejected",
    "scope_stale",
]
AsOfStatus = Literal["current", "historical", "unknown", "not_applicable"]


@dataclass(frozen=True, slots=True)
class MatterFactRef:
    source_kind: Literal["message", "upload", "fact"]
    source_id: str
    source_revision: int
    content_sha256: str
    safe_locator: str | None = None

    def as_contract(self) -> dict[str, Any]:
        return {
            "source_kind": self.source_kind,
            "source_id": self.source_id,
            "source_revision": self.source_revision,
            "content_sha256": self.content_sha256,
            "safe_locator": self.safe_locator,
        }


def _require_sha256(value: str, *, label: str) -> str:
    if _SHA256.fullmatch(value) is None:
        raise ValueError(f"{label} digest is malformed")
    return value


def _require_safe_id(value: str, *, label: str) -> str:
    if _SAFE_ID.fullmatch(value) is None:
        raise ValueError(f"{label} is malformed")
    return value


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


class MatterFactStore:
    """Append-only structured fact ledger scoped to one encrypted conversation."""

    def __init__(
        self,
        database: Database,
        cipher: LocalCipher,
        registry: ContractSchemaRegistry,
    ) -> None:
        self.database = database
        self.cipher = cipher
        self.registry = registry

    def append_fact(
        self,
        *,
        conversation_id: str,
        owner_scope_sha256: str,
        fact_key: str,
        data_type: FactDataType,
        value: str | None,
        origin: FactOrigin,
        status: FactStatus,
        refs: tuple[MatterFactRef, ...],
        created_at: datetime,
        affected_issue_ids: tuple[str, ...] = (),
        effective_from: str | None = None,
        effective_to: str | None = None,
        as_of_status: AsOfStatus = "unknown",
        supersedes_fact_id: str | None = None,
        conflict_group_id: str | None = None,
        derivation_rule_sha256: str | None = None,
    ) -> str:
        conversation_id = _require_safe_id(conversation_id, label="conversation ID")
        fact_key = _require_safe_id(fact_key, label="fact key")
        _require_sha256(owner_scope_sha256, label="owner scope")
        if not refs:
            raise ValueError("matter fact requires at least one source reference")
        if len({(ref.source_kind, ref.source_id, ref.source_revision) for ref in refs}) != len(
            refs
        ):
            raise ValueError("matter fact references must be unique")
        for ref in refs:
            _require_safe_id(ref.source_id, label="fact reference source ID")
            _require_sha256(ref.content_sha256, label="fact reference content")
            if ref.source_revision < 1:
                raise ValueError("fact reference revision must be positive")
        if len(affected_issue_ids) != len(set(affected_issue_ids)):
            raise ValueError("affected issue IDs must be unique")
        for issue_id in affected_issue_ids:
            _require_safe_id(issue_id, label="affected issue ID")
        if status == "unknown":
            if value is not None:
                raise ValueError("unknown matter fact cannot contain a value")
        elif value is None or not value.strip():
            raise ValueError("non-unknown matter fact requires a value")
        if origin == "deterministic_derivation":
            if derivation_rule_sha256 is None:
                raise ValueError("deterministic matter fact requires a derivation rule")
            _require_sha256(derivation_rule_sha256, label="derivation rule")
        elif derivation_rule_sha256 is not None:
            _require_sha256(derivation_rule_sha256, label="derivation rule")
        if supersedes_fact_id is not None:
            _require_safe_id(supersedes_fact_id, label="superseded fact ID")
        if conflict_group_id is not None:
            _require_safe_id(conflict_group_id, label="conflict group ID")

        stamp = _utc(created_at).isoformat()
        value_sha256 = hashlib.sha256(value.encode("utf-8")).hexdigest() if value else None
        encrypted = self.cipher.encrypt_text(value) if value is not None else None
        refs_json = json.dumps(
            [ref.as_contract() for ref in refs],
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        with self.database.transaction() as connection:
            session = connection.execute(
                "SELECT id,status FROM conversation_sessions WHERE id=?",
                (conversation_id,),
            ).fetchone()
            if session is None:
                raise ConversationNotFoundError(conversation_id)
            if str(session["status"]) != "active":
                raise RuntimeError("matter fact conversation is not active")
            scope_rows = connection.execute(
                "SELECT DISTINCT owner_scope_sha256 FROM matter_fact_records "
                "WHERE conversation_id=?",
                (conversation_id,),
            ).fetchall()
            if any(str(row["owner_scope_sha256"]) != owner_scope_sha256 for row in scope_rows):
                raise RuntimeError("matter fact owner scope differs")
            existing = connection.execute(
                "SELECT * FROM matter_fact_records WHERE conversation_id=? "
                "AND owner_scope_sha256=? AND fact_key=? ORDER BY revision",
                (conversation_id, owner_scope_sha256, fact_key),
            ).fetchall()
            revision = len(existing) + 1
            if supersedes_fact_id is not None:
                predecessor = connection.execute(
                    "SELECT * FROM matter_fact_records WHERE id=?",
                    (supersedes_fact_id,),
                ).fetchone()
                already_superseded = connection.execute(
                    "SELECT id FROM matter_fact_records WHERE supersedes_fact_id=?",
                    (supersedes_fact_id,),
                ).fetchone()
                if (
                    predecessor is None
                    or str(predecessor["conversation_id"]) != conversation_id
                    or str(predecessor["owner_scope_sha256"]) != owner_scope_sha256
                    or str(predecessor["fact_key"]) != fact_key
                    or already_superseded is not None
                ):
                    raise RuntimeError("matter fact supersession is invalid")
            elif existing and (conflict_group_id is None or status != "disputed"):
                raise RuntimeError(
                    "a repeated active fact requires explicit supersession or a disputed conflict"
                )
            identity_material = {
                "schema": "legalbot.matter-fact-record-identity.v1",
                "conversation_id": conversation_id,
                "owner_scope_sha256": owner_scope_sha256,
                "fact_key": fact_key,
                "revision": revision,
                "value_sha256": value_sha256,
                "origin": origin,
                "status": status,
                "supersedes_fact_id": supersedes_fact_id,
                "conflict_group_id": conflict_group_id,
                "fact_refs": [ref.as_contract() for ref in refs],
                "created_at": stamp,
            }
            identity = hashlib.sha256(canonical_json_bytes(identity_material)).hexdigest()
            fact_id = f"matter-fact-{identity[:40]}"
            connection.execute(
                """
                INSERT INTO matter_fact_records(
                  id,conversation_id,owner_scope_sha256,fact_key,data_type,
                  encrypted_value,value_sha256,origin,status,revision,
                  supersedes_fact_id,conflict_group_id,affected_issue_ids_json,
                  effective_from,effective_to,as_of_status,derivation_rule_sha256,
                  fact_refs_json,created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    fact_id,
                    conversation_id,
                    owner_scope_sha256,
                    fact_key,
                    data_type,
                    encrypted,
                    value_sha256,
                    origin,
                    status,
                    revision,
                    supersedes_fact_id,
                    conflict_group_id,
                    json.dumps(list(affected_issue_ids), separators=(",", ":")),
                    effective_from,
                    effective_to,
                    as_of_status,
                    derivation_rule_sha256,
                    refs_json,
                    stamp,
                ),
            )
        return fact_id

    def freeze_snapshot(
        self,
        *,
        conversation_id: str,
        owner_scope_sha256: str,
        conversation_revision: int,
    ) -> dict[str, Any]:
        conversation_id = _require_safe_id(conversation_id, label="conversation ID")
        _require_sha256(owner_scope_sha256, label="owner scope")
        if conversation_revision < 0:
            raise ValueError("conversation revision cannot be negative")
        session = self.database.fetchone(
            "SELECT id,updated_at FROM conversation_sessions WHERE id=?",
            (conversation_id,),
        )
        if session is None:
            raise ConversationNotFoundError(conversation_id)
        other_scope = self.database.fetchone(
            "SELECT owner_scope_sha256 FROM matter_fact_records WHERE conversation_id=? "
            "AND owner_scope_sha256<>? LIMIT 1",
            (conversation_id, owner_scope_sha256),
        )
        if other_scope is not None:
            raise RuntimeError("matter fact owner scope differs")
        rows = self.database.fetchall(
            "SELECT * FROM matter_fact_records WHERE conversation_id=? "
            "AND owner_scope_sha256=? ORDER BY fact_key,revision,id",
            (conversation_id, owner_scope_sha256),
        )
        superseded = {
            str(row["supersedes_fact_id"])
            for row in rows
            if row["supersedes_fact_id"] not in (None, "")
        }
        facts: list[dict[str, Any]] = []
        for row in rows:
            refs = json.loads(str(row["fact_refs_json"]))
            issues = json.loads(str(row["affected_issue_ids_json"]))
            fact_id = str(row["id"])
            status = "superseded" if fact_id in superseded else str(row["status"])
            facts.append(
                {
                    "fact_id": fact_id,
                    "fact_key": str(row["fact_key"]),
                    "data_type": str(row["data_type"]),
                    "encrypted_value_ref": None if status == "unknown" else fact_id,
                    "value_sha256": None if status == "unknown" else row["value_sha256"],
                    "origin": str(row["origin"]),
                    "status": status,
                    "revision": int(row["revision"]),
                    "supersedes_fact_id": row["supersedes_fact_id"],
                    "conflict_group_id": row["conflict_group_id"],
                    "affected_issue_ids": issues,
                    "temporal_scope": {
                        "effective_from": row["effective_from"],
                        "effective_to": row["effective_to"],
                        "as_of_status": str(row["as_of_status"]),
                    },
                    "derivation_rule_sha256": row["derivation_rule_sha256"],
                    "created_at": str(row["created_at"]),
                    "fact_refs": refs,
                }
            )
        created_at = str(rows[-1]["created_at"]) if rows else str(session["updated_at"])
        identity_material = {
            "schema": "legalbot.matter-fact-snapshot-identity.v2",
            "conversation_id": conversation_id,
            "owner_scope_sha256": owner_scope_sha256,
            "conversation_revision": conversation_revision,
            "facts": facts,
            "created_at": created_at,
        }
        identity = hashlib.sha256(canonical_json_bytes(identity_material)).hexdigest()
        snapshot = seal_contract(
            {
                "schema": "legalbot.matter-fact-snapshot.v2",
                "snapshot_id": f"matter-fact-snapshot-{identity[:40]}",
                "conversation_id": conversation_id,
                "owner_scope_sha256": owner_scope_sha256,
                "conversation_revision": conversation_revision,
                "created_at": created_at,
                "facts": facts,
            }
        )
        self.registry.validate_new(snapshot)
        return snapshot


__all__ = [
    "AsOfStatus",
    "FactDataType",
    "FactOrigin",
    "FactStatus",
    "MatterFactRef",
    "MatterFactStore",
]
