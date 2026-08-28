"""Deterministic sanitation for parser output before any durable text storage."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping
from dataclasses import replace
from typing import Any

from .models import Annotation, ParseResult, ParseStatus, Revision, StructuralBlock

TEXT_SANITATION_SCHEMA = "legalbot.text-sanitation.v3"

# Horizontal tab, line feed and carriage return are the only permitted C0
# characters. Parsers may use them as structure before their normal whitespace
# cleanup. DEL is rejected alongside the unsafe C0 range.
_FORBIDDEN_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_CP1252_C1_REPAIRS: dict[int, str] = {
    0x80: "€",
    0x81: " ",
    0x82: "‚",
    0x83: "ƒ",
    0x84: "„",
    0x85: "…",
    0x86: "†",
    0x87: "‡",
    0x88: "ˆ",
    0x89: "‰",
    0x8A: "Š",
    0x8B: "‹",
    0x8C: "Œ",
    0x8D: " ",
    0x8E: "Ž",
    0x8F: " ",
    0x90: " ",
    0x91: "‘",
    0x92: "’",
    0x93: "“",
    0x94: "”",
    0x95: "•",
    0x96: "–",
    0x97: "—",
    0x98: "˜",
    0x99: "™",
    0x9A: "š",
    0x9B: "›",
    0x9C: "œ",
    0x9D: " ",
    0x9E: "ž",
    0x9F: "Ÿ",
}
_INVISIBLE_FORMAT_REPAIRS: dict[int, str] = {
    0x00AD: "",  # soft hyphen inside a word
    0x200B: " ",  # zero-width space is a word boundary
    0x2060: "",  # word joiner inside a word
    0xFEFF: "",  # stray BOM / zero-width no-break space
}


def sanitize_text(value: str) -> str:
    """Replace unsafe controls without joining words and normalise line endings."""

    value = value.replace("\r\n", "\n").replace("\r", "\n")
    value = value.translate(_CP1252_C1_REPAIRS)
    value = value.translate(_INVISIBLE_FORMAT_REPAIRS)
    value = _FORBIDDEN_CONTROL_RE.sub(" ", value)
    value = "".join(
        character
        if character == "\n" or unicodedata.category(character) not in {"Cc", "Cf"}
        else " "
        for character in value
    )
    value = re.sub(r"[ \t]+", " ", value)
    value = re.sub(r" *\n *", "\n", value)
    return value.strip()


def has_forbidden_controls(value: str) -> bool:
    return _FORBIDDEN_CONTROL_RE.search(value) is not None or any(
        character != "\n" and unicodedata.category(character) in {"Cc", "Cf"} for character in value
    )


def sanitize_parse_result(parsed: ParseResult) -> ParseResult:
    """Return an idempotently sanitised parse result across every text stream."""

    blocks: list[StructuralBlock] = []
    for block in parsed.body_blocks:
        text = sanitize_text(block.text)
        if not text:
            continue
        heading_path = tuple(clean for item in block.heading_path if (clean := sanitize_text(item)))
        blocks.append(
            replace(
                block,
                text=text,
                heading_path=heading_path,
                source_anchor=(sanitize_text(block.source_anchor) if block.source_anchor else None),
                metadata=_sanitize_metadata(block.metadata),
            )
        )

    comments: list[Annotation] = []
    for ordinal, comment in enumerate(parsed.comments, 1):
        text = sanitize_text(comment.text)
        if not text:
            continue
        comments.append(
            replace(
                comment,
                annotation_id=sanitize_text(comment.annotation_id)
                or f"sanitized-comment-{ordinal}",
                text=text,
                author_alias=(
                    sanitize_text(comment.author_alias) if comment.author_alias else None
                ),
                created_at=(sanitize_text(comment.created_at) if comment.created_at else None),
                anchor=(sanitize_text(comment.anchor) if comment.anchor else None),
                metadata=_sanitize_metadata(comment.metadata),
            )
        )

    revisions: list[Revision] = []
    for ordinal, revision in enumerate(parsed.revisions, 1):
        text = sanitize_text(revision.text)
        if not text:
            continue
        revisions.append(
            replace(
                revision,
                revision_id=sanitize_text(revision.revision_id) or f"sanitized-revision-{ordinal}",
                operation=sanitize_text(revision.operation) or "unknown",
                text=text,
                author_alias=(
                    sanitize_text(revision.author_alias) if revision.author_alias else None
                ),
                created_at=(sanitize_text(revision.created_at) if revision.created_at else None),
                anchor=(sanitize_text(revision.anchor) if revision.anchor else None),
                metadata=_sanitize_metadata(revision.metadata),
            )
        )

    diagnostics = tuple(clean for item in parsed.diagnostics if (clean := sanitize_text(item)))
    status = parsed.status
    if status is ParseStatus.READY and not blocks:
        status = ParseStatus.INVALID
        diagnostics = (*diagnostics, "sanitation_empty_body")
    return ParseResult(
        status,
        parsed.document_format,
        tuple(blocks),
        tuple(comments),
        tuple(revisions),
        diagnostics,
    )


def _sanitize_metadata(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        clean_key: _sanitize_metadata_value(item)
        for key, item in value.items()
        if (clean_key := sanitize_text(str(key)))
    }


def _sanitize_metadata_value(value: Any) -> Any:
    if isinstance(value, str):
        return sanitize_text(value)
    if isinstance(value, Mapping):
        return _sanitize_metadata(value)
    if isinstance(value, tuple):
        return tuple(_sanitize_metadata_value(item) for item in value)
    if isinstance(value, list):
        return [_sanitize_metadata_value(item) for item in value]
    return value
