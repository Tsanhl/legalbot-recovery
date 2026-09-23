"""Record user statements and literal money/date mentions without invented roles."""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..contracts.schema_registry import ContractSchemaRegistry
from .matter_facts import MatterFactRef, MatterFactStore


def record_message_facts(services: Any, message: Any, session_id: str) -> None:
    registry = ContractSchemaRegistry.from_project_root(Path(__file__).resolve().parents[3])
    ledger = MatterFactStore(services.database, services.cipher, registry)
    ref = MatterFactRef("message", message.id, 1, message.content_sha256)
    mentions = [("statement", "text", message.content)]
    patterns = {
        "money": r"(?:[£$€]\s?\d[\d,]*(?:\.\d{2})?)",
        "date": r"\b(?:\d{1,2}\s+(?:January|February|March|April|May|June|July|August|September|October|November|December)(?:\s+\d{4})?|\d{4}-\d{2}-\d{2})\b",
    }
    for kind, pattern in patterns.items():
        mentions.extend(
            (f"{kind}-{i}", "text", match.group())
            for i, match in enumerate(re.finditer(pattern, message.content, re.I))
        )
    for key, kind, value in mentions:
        ledger.append_fact(
            conversation_id=message.conversation_id,
            owner_scope_sha256=hashlib.sha256(session_id.encode()).hexdigest(),
            fact_key=f"{message.id}:{key}",
            data_type=kind,
            value=value,
            origin="user_statement",
            status="stated",
            refs=(ref,),
            created_at=datetime.now(UTC),
        )
    # Literal mentions intentionally do not infer a year, currency jurisdiction,
    # payment status, contractual role or that a newer message supersedes an old fact.
