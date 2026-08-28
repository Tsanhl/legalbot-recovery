"""Ingest unmatched official bytes as catalogue candidates, then exact-match.

Catalogue absence is not by itself a knowledge gap. Downloaded official files
already inside configured source roots may be ingested as new source versions.
This module never approves gold, writes ACTIVE, or invents spans.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from ..config import Settings
from ..crypto import LocalCipher
from ..db import Database
from .live30 import assert_safe_evaluation_payload
from .live_suite_span_accuracy import check_user_span_exact_match

OFFICIAL_MATERIALISE_SCHEMA = "legalbot.live60-official-candidate-materialise.v1"


def materialise_official_paths(
    *,
    settings: Settings,
    database: Database,
    cipher: LocalCipher,
    paths: Sequence[Path],
    scan_id: str,
) -> dict[str, Any]:
    """Ingest named official files that already sit in configured source roots."""

    from ..ingestion.service import ingest_explicit_paths

    ingested = ingest_explicit_paths(
        settings,
        database,
        cipher,
        scan_id,
        paths,
    )
    payload = {
        "schema": OFFICIAL_MATERIALISE_SCHEMA,
        "scan_id": scan_id,
        "path_count": len(paths),
        "ingested": ingested,
        "approved": False,
        "gold": False,
        "automatic_knowledge_gap": False,
        "writes_active": False,
        "writes_o04": False,
    }
    assert_safe_evaluation_payload(
        {key: value for key, value in payload.items() if key != "ingested"}
    )
    return payload


def exact_match_materialised_span(
    *,
    chunk_id: str,
    content_sha256: str,
    legal_locator: str,
    source_version_id: str | None = None,
    catalog_path: Path | None = None,
    repair: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Exact-match after ingest. A catalogue miss stays a candidate, not a gap."""

    report = check_user_span_exact_match(
        chunk_id=chunk_id,
        content_sha256=content_sha256,
        legal_locator=legal_locator,
        source_version_id=source_version_id,
        catalog_path=catalog_path,
        repair=repair,
        require_gold_eligible=False,
    )
    matched = report.get("exact_match") is True
    payload = {
        "schema": "legalbot.live60-official-candidate-exact-match.v1",
        "exact_match": matched,
        "bind_status": "gold_eligible_candidate" if matched else "official_candidate_unmatched",
        "automatic_knowledge_gap": False,
        "gold": False,
        "writes_active": False,
        "report": report,
    }
    assert_safe_evaluation_payload(
        {key: value for key, value in payload.items() if key != "report"}
    )
    return payload


def classify_unmatched_official_candidate(
    *,
    row_id: str,
    reason: str,
    ingested: bool,
) -> dict[str, Any]:
    """Keep unmatched official bytes as candidates until a verified disposition."""

    payload = {
        "row_id": row_id,
        "disposition": "pending_official_materialisation",
        "verification_status": "HOLD",
        "automatic_knowledge_gap": False,
        "ingested": ingested,
        "reason_code": reason or "official_bytes_no_catalogue_or_repair_hash",
        "invented_span": False,
        "writes_active": False,
    }
    assert_safe_evaluation_payload(payload)
    return payload
