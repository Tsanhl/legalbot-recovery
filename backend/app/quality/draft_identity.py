"""Canonical, prose-free identity for one complete structured draft.

The digest covers every field of :class:`StructuredDraft`, including
non-material claims and limitations. Review artifacts retain only the digest;
the source draft prose remains in its existing encrypted/runtime boundary.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from ..types import StructuredDraft

SOURCE_DRAFT_IDENTITY_SCHEMA = "legalbot.structured-draft-source-identity.v1"


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def source_draft_sha256(draft: StructuredDraft) -> str:
    """Hash the exact complete StructuredDraft under a versioned identity schema."""

    return hashlib.sha256(
        _canonical_json(
            {
                "schema": SOURCE_DRAFT_IDENTITY_SCHEMA,
                "draft": draft.model_dump(mode="json"),
            }
        )
    ).hexdigest()
