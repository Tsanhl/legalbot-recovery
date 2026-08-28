"""Identity contract for Live60 contiguous repair spans.

v1 artifacts remain byte-identical on disk and are rejected as new gold.
v2 derives ``repair_span_id`` from the full identity tuple. This module never
seals expert gold and never reconstructs spliced parents.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

REPAIR_SPAN_SCHEMA_V2 = "legalbot.live60-repair-span.v2"
HELD_SPAN_REPAIR_SCHEMA_V1 = "legalbot.live60-held-span-contiguous-repair.v1"
HELD_SPAN_REPAIR_SCHEMA_V2 = "legalbot.live60-held-span-contiguous-repair.v2"
IPFDA_DOTS_PARENT = "chunk-0bdcbc97ae11975ac1032cc3c6974aeaad9e43a7"

IDENTITY_FIELD_NAMES = (
    "parent_chunk_id",
    "source_version_id",
    "legal_authority_id",
    "official_snapshot_sha256",
    "required_sublocator",
    "role",
    "markdown_text",
    "derivation_manifest_sha256",
    "stable_source_id",
    "source_type",
    "jurisdiction",
    "legal_locator",
)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def derivation_manifest_sha256(manifest: Mapping[str, Any]) -> str:
    return sha256_text(canonical_json(manifest))


def parent_identity(provision: Mapping[str, Any], chunk: Mapping[str, Any]) -> dict[str, str]:
    authority = str(provision.get("authority_identity_id") or "")
    stable = str(provision.get("stable_source_id") or chunk.get("stable_source_id") or "")
    if not stable and authority:
        stable = "".join(ch if ch.isalnum() or ch in "._:-" else "-" for ch in authority.casefold())
    return {
        "parent_chunk_id": str(chunk.get("chunk_id") or ""),
        "source_version_id": str(chunk.get("source_version_id") or ""),
        "legal_authority_id": authority,
        "official_snapshot_sha256": str(
            chunk.get("document_content_sha256")
            or provision.get("expected_document_content_sha256")
            or ""
        ),
        "stable_source_id": stable,
        "source_type": str(
            provision.get("source_type") or chunk.get("source_type") or "legislation"
        ),
        "jurisdiction": str(
            provision.get("jurisdiction") or chunk.get("jurisdiction") or "England and Wales"
        ),
    }


def identity_tuple(
    *,
    parent_chunk_id: str,
    source_version_id: str,
    legal_authority_id: str,
    official_snapshot_sha256: str,
    required_sublocator: str,
    role: str,
    markdown_text: str,
    derivation_manifest_sha256: str,
    stable_source_id: str,
    source_type: str,
    jurisdiction: str,
    legal_locator: str,
) -> tuple[str, ...]:
    return (
        parent_chunk_id,
        source_version_id,
        legal_authority_id,
        official_snapshot_sha256,
        required_sublocator,
        role,
        markdown_text,
        derivation_manifest_sha256,
        stable_source_id,
        source_type,
        jurisdiction,
        legal_locator,
    )


def repair_span_identity_v2(
    *,
    parent_chunk_id: str,
    source_version_id: str,
    legal_authority_id: str,
    official_snapshot_sha256: str,
    required_sublocator: str,
    role: str,
    markdown_text: str,
    derivation_manifest_sha256: str,
    stable_source_id: str,
    source_type: str,
    jurisdiction: str,
    legal_locator: str,
) -> tuple[str, ...]:
    """Deterministic v2 identity including immutable source fields."""

    return identity_tuple(
        parent_chunk_id=parent_chunk_id,
        source_version_id=source_version_id,
        legal_authority_id=legal_authority_id,
        official_snapshot_sha256=official_snapshot_sha256,
        required_sublocator=required_sublocator,
        role=role,
        markdown_text=markdown_text,
        derivation_manifest_sha256=derivation_manifest_sha256,
        stable_source_id=stable_source_id,
        source_type=source_type,
        jurisdiction=jurisdiction,
        legal_locator=legal_locator,
    )


def identity_complete(values: Mapping[str, Any]) -> bool:
    return all(str(values.get(name) or "").strip() for name in IDENTITY_FIELD_NAMES)


def repair_span_id_v1(*, parent_chunk_id: str, sublocator: str, text: str) -> str:
    return f"repair-span-{sha256_text(f'{parent_chunk_id}|{sublocator}|{text}')}"


def repair_span_id_v2(*, identity: tuple[str, ...]) -> str:
    return f"repair-span-{sha256_text('|'.join(identity))}"


def is_v1_repair_envelope(repair: Mapping[str, Any] | None) -> bool:
    schema = str((repair or {}).get("schema") or "")
    return schema == HELD_SPAN_REPAIR_SCHEMA_V1 or (
        schema != HELD_SPAN_REPAIR_SCHEMA_V2
        and any(
            str(item.get("schema") or "") != REPAIR_SPAN_SCHEMA_V2
            for item in (repair or {}).get("repairs", ())
        )
    )


def is_v1_repair_span(item: Mapping[str, Any]) -> bool:
    return str(item.get("schema") or "") != REPAIR_SPAN_SCHEMA_V2


def computed_repair_span_id(item: Mapping[str, Any]) -> str:
    manifest = item.get("derivation_manifest") or {}
    manifest_sha = str(item.get("derivation_manifest_sha256") or "")
    if isinstance(manifest, Mapping) and not manifest_sha:
        manifest_sha = derivation_manifest_sha256(manifest)
    return repair_span_id_v2(
        identity=repair_span_identity_v2(
            parent_chunk_id=str(item.get("parent_chunk_id") or ""),
            source_version_id=str(item.get("source_version_id") or ""),
            legal_authority_id=str(item.get("legal_authority_id") or ""),
            official_snapshot_sha256=str(item.get("official_snapshot_sha256") or ""),
            required_sublocator=str(item.get("required_sublocator") or ""),
            role=str(item.get("role") or ""),
            markdown_text=str(item.get("markdown_text") or ""),
            derivation_manifest_sha256=manifest_sha,
            stable_source_id=str(item.get("stable_source_id") or ""),
            source_type=str(item.get("source_type") or ""),
            jurisdiction=str(item.get("jurisdiction") or ""),
            legal_locator=str(item.get("legal_locator") or item.get("required_sublocator") or ""),
        )
    )


def dots_only_parent_excluded(item: Mapping[str, Any]) -> bool:
    return (
        str(item.get("parent_chunk_id") or "") == IPFDA_DOTS_PARENT
        and item.get("gold_eligible_candidate") is not True
    )
