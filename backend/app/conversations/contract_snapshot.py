"""Selected-schema conversation snapshots for the Phase-2 request chain."""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from typing import Any

from ..contracts import ContractSchemaRegistry, canonical_json_bytes, seal_contract
from .store import ConversationStore

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _truncation_reason(value: str | None) -> str:
    if value is None:
        return "none"
    if value == "message_window_reached":
        return "message_limit"
    if value in {"token_window_reached", "newest_message_exceeds_token_window"}:
        return "token_limit"
    raise RuntimeError(f"unsupported conversation truncation reason: {value}")


def freeze_conversation_snapshot(
    store: ConversationStore,
    *,
    conversation_id: str,
    owner_scope_sha256: str,
    registry: ContractSchemaRegistry,
    max_messages: int | None = None,
    max_tokens: int | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Freeze one encrypted-reference-only ConversationSnapshot v1.

    The object contains message identities and digests, never decrypted message
    content. The caller must supply the exact owner-scope capability digest; a
    missing or malformed scope cannot be inferred from a local username.
    """

    if _SHA256.fullmatch(owner_scope_sha256) is None:
        raise ValueError("owner scope digest is malformed")
    observed_at = now or datetime.now(UTC)
    if observed_at.tzinfo is None:
        observed_at = observed_at.replace(tzinfo=UTC)
    observed_at = observed_at.astimezone(UTC)
    window = store.window(
        conversation_id,
        max_messages=max_messages,
        max_tokens=max_tokens,
        now=observed_at,
    )
    session = store.database.fetchone(
        "SELECT id,updated_at FROM conversation_sessions WHERE id=?",
        (window.conversation_id,),
    )
    if session is None or str(session["id"]) != window.conversation_id:
        raise RuntimeError("conversation snapshot session identity changed")

    messages = [
        {
            "message_id": message.id,
            "ordinal": message.ordinal,
            "revision": 1,
            "role": "assistant_verified" if message.role == "assistant" else "user",
            "encrypted_content_ref": message.id,
            "content_sha256": message.content_sha256,
            "created_at": message.created_at,
        }
        for message in window.messages
    ]
    omitted_before_ordinal: int | None = None
    if window.omitted_message_count:
        omitted_before_ordinal = (
            window.messages[0].ordinal
            if window.messages
            else window.total_message_count + 1
        )
    identity_material = {
        "schema": "legalbot.conversation-snapshot-identity.v1",
        "conversation_id": window.conversation_id,
        "owner_scope_sha256": owner_scope_sha256,
        "revision": window.total_message_count,
        "messages": messages,
        "truncated": window.truncated,
        "omitted_message_count": window.omitted_message_count,
        "omitted_before_ordinal": omitted_before_ordinal,
        "truncation_reason": _truncation_reason(window.truncation_reason),
        "estimated_tokens": window.selected_estimated_tokens,
    }
    snapshot_identity = hashlib.sha256(canonical_json_bytes(identity_material)).hexdigest()
    snapshot = seal_contract(
        {
            "schema": "legalbot.conversation-snapshot.v1",
            "snapshot_id": f"conversation-snapshot-{snapshot_identity[:40]}",
            "conversation_id": window.conversation_id,
            "owner_scope_sha256": owner_scope_sha256,
            "revision": window.total_message_count,
            # The session update is the immutable freeze coordinate for this
            # revision. Re-reading unchanged state produces identical bytes.
            "created_at": str(session["updated_at"]),
            "messages": messages,
            "truncated": window.truncated,
            "omitted_message_count": window.omitted_message_count,
            "omitted_before_ordinal": omitted_before_ordinal,
            "truncation_reason": _truncation_reason(window.truncation_reason),
            "estimated_tokens": window.selected_estimated_tokens,
        }
    )
    registry.validate_new(snapshot)
    return snapshot


__all__ = ["freeze_conversation_snapshot"]
