"""Exact catalogue spans after V2 source admission.

Source APPROVE does not qualify an issue. This module only binds official
bytes to hash-exact catalogue chunks. Semantic verification remains separate.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import date
from typing import Any

from .live30 import assert_safe_evaluation_payload
from .live_suite import sealed_sha256
from .live_suite_evidence_pack import _chunks_for_source
from .live_suite_final_check import _eligible_row
from .live_suite_official_bind import (
    extract_legislation_subsections,
    locator_covers,
    match_official_to_chunks,
)

ADMITTED_SPAN_BIND_SCHEMA = "legalbot.admitted-source-exact-span.v2"


def _span_identity(row: Any) -> dict[str, Any]:
    return {
        "chunk_id": str(row["chunk_id"]),
        "content_sha256": str(row["text_sha256"]),
        "jurisdiction": str(row["jurisdiction"] or "England and Wales"),
        "legal_authority_id": str(row["authority_identity_id"] or ""),
        "legal_locator": str(row["locator"] or ""),
        "legal_role": "statutory_text",
        "source_type": "legislation",
        "source_version_id": str(row["source_version_id"]),
        "stable_source_id": str(row["stable_source_id"] or ""),
    }


def exact_spans_for_admitted_source(
    *,
    official_xml: bytes,
    chunk_rows: Sequence[Any],
    as_of_date: date,
    connection: Any | None = None,
) -> dict[str, Any]:
    """Return hash-exact span identities. Never sets VERIFIED or ACTIVE."""

    eligible: list[Any] = []
    for row in chunk_rows:
        if connection is None:
            eligible.append(row)
            continue
        kept = _eligible_row(
            connection=connection,
            row=row,
            chunk_id=str(row["chunk_id"]),
            source_type="legislation",
            as_of_date=as_of_date,
            exclusions=Counter(),
        )
        if kept is not None:
            eligible.append(kept)
    subsections = extract_legislation_subsections(official_xml.decode("utf-8", errors="replace"))
    matched: dict[str, Any] = {}
    for locator, official_text in subsections.items():
        rows = [row for row in eligible if locator_covers(str(row["locator"] or ""), locator)]
        window = match_official_to_chunks(official_text=official_text, rows=rows or eligible)
        for row in window:
            matched[str(row["chunk_id"])] = _span_identity(row)
    if not matched and eligible:
        joined = " ".join(subsections.values())
        window = match_official_to_chunks(official_text=joined, rows=eligible)
        for row in window:
            matched[str(row["chunk_id"])] = _span_identity(row)
    spans = list(matched.values())
    payload = {
        "schema": ADMITTED_SPAN_BIND_SCHEMA,
        "exact_match": bool(spans),
        "span_count": len(spans),
        "exact_gold_spans": spans,
        "issue_qualified": False,
        "final_verification_status": "HOLD",
        "reason_code": (
            "source_admitted_semantic_pending"
            if spans
            else "source_admitted_exact_span_or_semantic_pending"
        ),
        "writes_active": False,
        "writes_o04": False,
    }
    payload["seal_sha256"] = sealed_sha256(
        {key: value for key, value in payload.items() if key != "exact_gold_spans"}
    )
    assert_safe_evaluation_payload(
        {key: value for key, value in payload.items() if key != "exact_gold_spans"}
    )
    return payload


def bind_admitted_pack_spans(
    *,
    connection: Any,
    decisions: Sequence[Mapping[str, Any]],
    official_bytes_by_url: Mapping[str, bytes],
    as_of_date: date,
) -> dict[str, Any]:
    """Map each APPROVE decision onto exact spans for its affected issue rows."""

    cache: dict[str, list[Any]] = {}
    by_row: dict[str, dict[str, Any]] = {}
    matched_sources = 0
    for item in decisions:
        if str(item.get("decision") or "") != "APPROVE":
            continue
        source_version_id = str(item.get("source_version_id") or "")
        url = str(item.get("official_source_url") or "")
        raw = official_bytes_by_url.get(url)
        if not source_version_id or raw is None:
            continue
        rows = _chunks_for_source(connection, source_version_id, cache=cache)
        bound = exact_spans_for_admitted_source(
            official_xml=raw,
            chunk_rows=rows,
            as_of_date=as_of_date,
            connection=connection,
        )
        if bound["exact_match"]:
            matched_sources += 1
        for row_id in item.get("affected_row_ids") or ():
            by_row[str(row_id)] = bound
    payload = {
        "schema": "legalbot.admitted-source-span-bind-batch.v2",
        "matched_source_count": matched_sources,
        "affected_row_count": len(by_row),
        "rows_with_exact_spans": sum(
            1 for item in by_row.values() if item.get("exact_match") is True
        ),
        "issue_gold_minted": False,
        "writes_active": False,
        "by_row": by_row,
    }
    payload["seal_sha256"] = sealed_sha256(
        {key: value for key, value in payload.items() if key != "by_row"}
    )
    return payload
