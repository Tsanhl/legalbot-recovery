"""Create-only lexical research packets for unresolved Phase-2A issue rows.

The source catalogue is opened immutable/read-only.  This module neither embeds
material nor persists a search index, and every candidate remains advisory
until proposition-level owner approval and the later candidate admission gate.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer  # type: ignore[import-untyped]

from ..retrieval.source_manifest import approved_source_manifest_sha256

RESEARCH_PACKET_SCHEMA = "legalbot.v111.phase2a.unresolved-research-packets.v1"
ROW_PACKET_SCHEMA = "legalbot.v111.phase2a.unresolved-research-row.v1"
EXPECTED_REMAINING_INPUT_COUNT = 537
EXPECTED_PRIOR_APPROVAL_COUNT = 35
EXPECTED_OUTPUT_COUNT = 502
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def sealed_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_research_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_research_input_must_be_object")
    return value


def _verify_content_seal(value: Mapping[str, Any], field: str, code: str) -> str:
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if not _SHA256.fullmatch(supplied) or supplied != sealed_sha256(material):
        raise ValueError(code)
    return supplied


def _write_exclusive(path: Path, raw: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def subject_routes(subject: str) -> frozenset[str]:
    """Map one benchmark subject to conservative catalogue subject lanes."""

    lowered = subject.casefold()
    routes: set[str] = {"general"}
    rules: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = (
        (("contract", "sale of goods", "agency"), ("contract", "commercial")),
        (("consumer", "credit", "product liability"), ("consumer", "contract")),
        (("tort", "occupiers", "product liability"), ("tort", "professional negligence")),
        (("criminal evidence",), ("criminal evidence", "criminal")),
        (("criminal", "cybercrime", "corporate fraud", "crypto"), ("criminal",)),
        (("professional", "tax", "construction"), ("professional negligence",)),
        (("employment", "pensions", "restructuring"), ("pensions", "eu and internal market")),
        (("land", "leasehold", "housing", "planning"), ("land", "civil litigation")),
        (
            (
                "public law",
                "constitutional",
                "human rights",
                "immigration",
                "surveillance",
                "education",
                "procurement",
                "environmental",
                "planning",
            ),
            ("constitutional", "civil litigation"),
        ),
        (
            ("company", "corporate", "insolvency", "partnership", "crypto"),
            ("company and insolvency", "commercial", "trusts"),
        ),
        (("family",), ("family",)),
        (("trust", "equity", "restitution", "charity"), ("trusts", "land")),
        (
            ("civil litigation", "privilege", "cross-border", "collective redress"),
            ("civil litigation", "private international law"),
        ),
        (
            ("intellectual property", "artificial intelligence", "data protection", "privacy"),
            ("intellectual property", "ai and data protection"),
        ),
        (("wills", "succession"), ("wills and succession", "trusts")),
        (("competition", "digital markets"), ("competition", "consumer")),
        (("medical",), ("medical law", "professional negligence")),
        (
            ("commercial", "insurance", "arbitration", "sports", "shipping", "energy"),
            ("commercial", "mediation and ADR", "private international law", "contract"),
        ),
        (("financial services", "investment"), ("financial services", "professional negligence")),
        (("defamation", "confidential information", "media"), ("ai and data protection",)),
    )
    for needles, additions in rules:
        if any(needle in lowered for needle in needles):
            routes.update(additions)
    return frozenset(routes)


@dataclass(frozen=True, slots=True)
class ResearchSource:
    source_version_id: str
    authority_identity_id: str
    stable_identifier: str
    title: str
    canonical_citation: str
    canonical_url: str
    subject: str
    version_sha256: str
    as_of_date: str | None
    currentness_status: str
    identity_verified: bool
    currentness_verified: bool
    family: str


@dataclass(frozen=True, slots=True)
class ResearchSpan:
    source: ResearchSource
    locator: str
    chunk_ids: tuple[str, ...]
    chunk_text_sha256s: tuple[str, ...]
    text: str
    span_bundle_sha256: str


def _official_family(stable_identifier: str) -> str:
    if stable_identifier.startswith("neutral-citation:"):
        return "case"
    return "legislation_or_procedural_instrument"


def _open_catalogue(path: Path) -> sqlite3.Connection:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_research_catalogue_missing")
    connection = sqlite3.connect(f"file:{path.resolve()}?mode=ro&immutable=1", uri=True)
    connection.row_factory = sqlite3.Row
    return connection


def _select_sources(connection: sqlite3.Connection, target_date: date) -> tuple[ResearchSource, ...]:
    rows = connection.execute(
        """
        WITH eligible AS (
          SELECT
            sv.*,
            COALESCE(json_extract(sv.metadata_json, '$.canonical_citation'), sv.title, '')
              AS canonical_citation,
            COALESCE(json_extract(sv.metadata_json, '$.subject_primary_candidate'), 'general')
              AS catalogue_subject,
            COALESCE(json_extract(sv.metadata_json, '$.identity_verified'), 0)
              AS metadata_identity_verified,
            COALESCE(json_extract(sv.metadata_json, '$.currentness_verified'), 0)
              AS metadata_currentness_verified,
            ROW_NUMBER() OVER (
              PARTITION BY sv.authority_identity_id
              ORDER BY
                CASE
                  WHEN sv.as_of_date=? AND sv.currentness_status='latest_available_revised_snapshot'
                    THEN 0
                  WHEN sv.currentness_status='point_in_time' THEN 1
                  WHEN sv.currentness_status='latest_available_revised_snapshot' THEN 2
                  ELSE 3
                END,
                sv.created_at DESC,
                sv.id
            ) AS choice_rank
          FROM source_versions sv
          JOIN documents d ON d.id=sv.document_id
          WHERE sv.review_status='approved'
            AND d.status='citable'
            AND d.lane='primary_authority'
            AND sv.authority_identity_id IS NOT NULL
            AND sv.authority_identity_id<>''
            AND (sv.as_of_date IS NULL OR sv.as_of_date<=?)
            AND (
              sv.stable_identifier LIKE 'neutral-citation:%'
              OR sv.stable_identifier LIKE 'ukpga:%'
              OR sv.stable_identifier LIKE 'uksi:%'
              OR sv.stable_identifier LIKE 'eur:%'
            )
        )
        SELECT * FROM eligible WHERE choice_rank=1 ORDER BY authority_identity_id
        """,
        (target_date.isoformat(), target_date.isoformat()),
    ).fetchall()
    sources = tuple(
        ResearchSource(
            source_version_id=str(row["id"]),
            authority_identity_id=str(row["authority_identity_id"]),
            stable_identifier=str(row["stable_identifier"]),
            title=str(row["title"] or "Untitled official authority"),
            canonical_citation=str(row["canonical_citation"] or row["title"] or ""),
            canonical_url=str(row["canonical_url"] or ""),
            subject=str(row["catalogue_subject"] or "general"),
            version_sha256=str(row["version_sha256"]),
            as_of_date=(str(row["as_of_date"]) if row["as_of_date"] else None),
            currentness_status=str(row["currentness_status"]),
            identity_verified=bool(row["metadata_identity_verified"]),
            currentness_verified=bool(row["metadata_currentness_verified"]),
            family=_official_family(str(row["stable_identifier"])),
        )
        for row in rows
    )
    if not sources or len({item.authority_identity_id for item in sources}) != len(sources):
        raise ValueError("phase2a_research_source_selection_invalid")
    return sources


def _load_spans(
    connection: sqlite3.Connection, sources: Sequence[ResearchSource]
) -> tuple[ResearchSpan, ...]:
    by_id = {source.source_version_id: source for source in sources}
    placeholders = ",".join("?" for _ in by_id)
    rows = connection.execute(
        f"""
        SELECT id, source_version_id, ordinal, locator, text_sha256, markdown_text
        FROM chunks
        WHERE source_version_id IN ({placeholders})
        ORDER BY source_version_id, locator, ordinal, id
        """,
        tuple(by_id),
    )
    grouped: dict[tuple[str, str], list[sqlite3.Row]] = defaultdict(list)
    for row in rows:
        grouped[(str(row["source_version_id"]), str(row["locator"]))].append(row)
    spans: list[ResearchSpan] = []
    for (source_version_id, locator), chunks in sorted(grouped.items()):
        source = by_id[source_version_id]
        chunk_ids = tuple(str(chunk["id"]) for chunk in chunks)
        chunk_hashes = tuple(str(chunk["text_sha256"]) for chunk in chunks)
        text = "\n".join(str(chunk["markdown_text"]).strip() for chunk in chunks).strip()
        if not text:
            continue
        identity = {
            "source_version_id": source_version_id,
            "authority_identity_id": source.authority_identity_id,
            "locator": locator,
            "chunk_ids": list(chunk_ids),
            "chunk_text_sha256s": list(chunk_hashes),
        }
        spans.append(
            ResearchSpan(
                source=source,
                locator=locator,
                chunk_ids=chunk_ids,
                chunk_text_sha256s=chunk_hashes,
                text=text,
                span_bundle_sha256=sealed_sha256(identity),
            )
        )
    if not spans:
        raise ValueError("phase2a_research_source_spans_empty")
    return tuple(spans)


def _load_cases(path: Path) -> dict[str, dict[str, Any]]:
    cases: dict[str, dict[str, Any]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        value = json.loads(line)
        case_id = str(value.get("case_id") or "")
        if not case_id or case_id in cases:
            raise ValueError("phase2a_research_case_registry_invalid")
        cases[case_id] = value
    if len(cases) != 60:
        raise ValueError("phase2a_research_case_registry_count_invalid")
    return cases


def _candidate_manifest_authorities(path: Path) -> tuple[str, frozenset[str], frozenset[str]]:
    value = _load_object(path)
    digest = approved_source_manifest_sha256(value)
    if value.get("manifest_sha256") != digest:
        raise ValueError("phase2a_research_candidate_manifest_invalid")
    entries = value.get("sources")
    if not isinstance(entries, list):
        raise ValueError("phase2a_research_candidate_sources_invalid")
    return (
        digest,
        frozenset(str(item.get("authority_identity_id") or "") for item in entries),
        frozenset(str(item.get("source_version_id") or "") for item in entries),
    )


def _display_text(value: str, *, maximum: int = 5_000) -> tuple[str, bool]:
    normalized = " ".join(value.split())
    if len(normalized) <= maximum:
        return normalized, False
    return normalized[:maximum].rstrip(), True


def _rank_rows(
    *,
    rows: Sequence[Mapping[str, Any]],
    cases: Mapping[str, Mapping[str, Any]],
    spans: Sequence[ResearchSpan],
    candidate_authorities: frozenset[str],
    candidate_versions: frozenset[str],
    limit: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    documents = [
        " ".join(
            (
                span.source.subject,
                span.source.subject,
                span.source.title,
                span.source.canonical_citation,
                span.locator,
                span.text,
            )
        )
        for span in spans
    ]
    vectorizer = TfidfVectorizer(
        lowercase=True,
        strip_accents="unicode",
        stop_words="english",
        ngram_range=(1, 2),
        min_df=1,
        max_features=120_000,
        sublinear_tf=True,
        norm="l2",
    )
    matrix = vectorizer.fit_transform(documents)
    subject_indices: dict[str, np.ndarray[Any, np.dtype[np.int64]]] = {}
    for subject in {span.source.subject for span in spans}:
        subject_indices[subject] = np.asarray(
            [index for index, span in enumerate(spans) if span.source.subject == subject],
            dtype=np.int64,
        )

    packets: list[dict[str, Any]] = []
    candidate_count = 0
    score_values: list[float] = []
    for ordinal, row in enumerate(rows, start=1):
        case_id = str(row.get("case_id") or str(row.get("row_id") or "").split(":", 1)[0])
        case = cases.get(case_id)
        if case is None:
            raise ValueError("phase2a_research_row_case_missing")
        issue_label = str(row.get("issue_label") or "")
        legal_domain = str(row.get("legal_domain") or case.get("subject") or "")
        query_text = " ".join(
            (
                issue_label,
                issue_label,
                issue_label,
                legal_domain,
                str(case.get("question") or ""),
            )
        )
        query = vectorizer.transform([query_text])
        scores = np.asarray((matrix @ query.T).toarray()).reshape(-1)
        allowed_routes = subject_routes(legal_domain)
        allowed_arrays = [
            subject_indices[route] for route in allowed_routes if route in subject_indices
        ]
        allowed = (
            np.unique(np.concatenate(allowed_arrays))
            if allowed_arrays
            else np.arange(len(spans), dtype=np.int64)
        )
        ordered = allowed[np.argsort(scores[allowed], kind="stable")[::-1]]
        selected: list[dict[str, Any]] = []
        authority_counts: Counter[str] = Counter()
        for index in ordered:
            score = float(scores[int(index)])
            if score <= 0.0:
                break
            span = spans[int(index)]
            authority_id = span.source.authority_identity_id
            if authority_counts[authority_id] >= 2:
                continue
            authority_counts[authority_id] += 1
            display, truncated = _display_text(span.text)
            material = {
                "rank": len(selected) + 1,
                "lexical_tfidf_score": round(score, 8),
                "advisory_only_not_qualified": True,
                "source_version_id": span.source.source_version_id,
                "authority_identity_id": authority_id,
                "stable_identifier": span.source.stable_identifier,
                "title": span.source.title,
                "canonical_citation": span.source.canonical_citation,
                "canonical_url": span.source.canonical_url,
                "source_family": span.source.family,
                "catalogue_subject": span.source.subject,
                "version_sha256": span.source.version_sha256,
                "as_of_date": span.source.as_of_date,
                "currentness_status": span.source.currentness_status,
                "identity_verified": span.source.identity_verified,
                "currentness_verified": span.source.currentness_verified,
                "later_treatment_review_required": span.source.family == "case",
                "locator": span.locator,
                "chunk_ids": list(span.chunk_ids),
                "chunk_text_sha256s": list(span.chunk_text_sha256s),
                "span_bundle_sha256": span.span_bundle_sha256,
                "candidate_span_text": display,
                "candidate_span_text_truncated": truncated,
                "already_in_sealed_candidate": (
                    authority_id in candidate_authorities
                    or span.source.source_version_id in candidate_versions
                ),
            }
            selected.append(
                {**material, "candidate_record_content_sha256": sealed_sha256(material)}
            )
            score_values.append(score)
            candidate_count += 1
            if len(selected) >= limit:
                break
        row_material = {
            "schema": ROW_PACKET_SCHEMA,
            "ordinal": ordinal,
            "row_id": row.get("row_id"),
            "case_id": case_id,
            "issue_id": row.get("issue_id"),
            "issue_label": issue_label,
            "issue_label_sha256": row.get("issue_label_sha256"),
            "legal_domain": legal_domain,
            "source_evidence_state": row.get("evidence_state"),
            "source_required_action": row.get("required_action"),
            "allowed_catalogue_subjects": sorted(allowed_routes),
            "candidate_count": len(selected),
            "candidates": selected,
            "owner_or_qualified_reviewer_decision_required": True,
            "ai_recommendation_may_not_admit_or_qualify": True,
            "technical_qualification_assigned": False,
        }
        packets.append(
            {**row_material, "row_packet_content_sha256": sealed_sha256(row_material)}
        )
    metrics = {
        "candidate_record_count": candidate_count,
        "rows_with_no_lexical_candidate": sum(not packet["candidates"] for packet in packets),
        "minimum_candidate_score": (
            round(min(score_values), 8) if score_values else None
        ),
        "maximum_candidate_score": (
            round(max(score_values), 8) if score_values else None
        ),
    }
    return packets, metrics


def build_research_packets(
    *,
    remaining_inventory_path: Path,
    approved_35_path: Path,
    cases_path: Path,
    candidate_manifest_path: Path,
    catalogue_path: Path,
    target_date: date,
    output_root: Path,
    candidate_limit: int = 8,
) -> dict[str, Any]:
    """Build sealed advisory packets without changing any source or gate state."""

    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_research_output_already_exists")
    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_research_output_mode_invalid")
    if not 1 <= candidate_limit <= 20:
        raise ValueError("phase2a_research_candidate_limit_invalid")

    remaining = _load_object(remaining_inventory_path)
    approved = _load_object(approved_35_path)
    remaining_sha256 = _verify_content_seal(
        remaining,
        "artifact_content_sha256",
        "phase2a_research_remaining_inventory_seal_invalid",
    )
    approved_sha256 = _verify_content_seal(
        approved,
        "approved_package_content_sha256",
        "phase2a_research_prior_approval_seal_invalid",
    )
    remaining_rows = remaining.get("rows")
    approved_rows = approved.get("decisions")
    if (
        remaining.get("row_count") != EXPECTED_REMAINING_INPUT_COUNT
        or not isinstance(remaining_rows, list)
        or len(remaining_rows) != EXPECTED_REMAINING_INPUT_COUNT
        or approved.get("item_count") != EXPECTED_PRIOR_APPROVAL_COUNT
        or not isinstance(approved_rows, list)
        or len(approved_rows) != EXPECTED_PRIOR_APPROVAL_COUNT
    ):
        raise ValueError("phase2a_research_input_count_invalid")
    approved_ids = {str(item.get("row_id") or "") for item in approved_rows}
    unresolved = [row for row in remaining_rows if str(row.get("row_id") or "") not in approved_ids]
    if len(approved_ids) != EXPECTED_PRIOR_APPROVAL_COUNT or len(unresolved) != EXPECTED_OUTPUT_COUNT:
        raise ValueError("phase2a_research_unresolved_set_invalid")
    unresolved.sort(key=lambda item: int(item.get("ordinal") or 0))

    cases = _load_cases(cases_path)
    candidate_manifest_sha256, candidate_authorities, candidate_versions = (
        _candidate_manifest_authorities(candidate_manifest_path)
    )
    with _open_catalogue(catalogue_path) as connection:
        sources = _select_sources(connection, target_date)
        spans = _load_spans(connection, sources)
    packets, rank_metrics = _rank_rows(
        rows=unresolved,
        cases=cases,
        spans=spans,
        candidate_authorities=candidate_authorities,
        candidate_versions=candidate_versions,
        limit=candidate_limit,
    )
    source_selection = [
        {
            "source_version_id": source.source_version_id,
            "authority_identity_id": source.authority_identity_id,
            "stable_identifier": source.stable_identifier,
            "version_sha256": source.version_sha256,
            "as_of_date": source.as_of_date,
            "currentness_status": source.currentness_status,
            "identity_verified": source.identity_verified,
            "currentness_verified": source.currentness_verified,
            "family": source.family,
            "catalogue_subject": source.subject,
        }
        for source in sources
    ]
    material: dict[str, Any] = {
        "schema": RESEARCH_PACKET_SCHEMA,
        "status": "ADVISORY_LEXICAL_RESEARCH_COMPLETE_OWNER_REVIEW_REQUIRED",
        "target_date": target_date.isoformat(),
        "row_count": len(packets),
        "source_authority_count": len(sources),
        "source_span_group_count": len(spans),
        "candidate_limit_per_row": candidate_limit,
        "source_remaining_inventory_content_sha256": remaining_sha256,
        "source_prior_approved_35_content_sha256": approved_sha256,
        "source_cases_file_sha256": _file_sha256(cases_path),
        "sealed_candidate_source_manifest_sha256": candidate_manifest_sha256,
        "selected_source_registry_sha256": sealed_sha256(source_selection),
        "catalogue_opened_immutable_read_only": True,
        "persistent_research_index_created": False,
        "embedding_model_invoked": False,
        "answer_model_invoked": False,
        "source_admission_authorized": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
        "rank_metrics": rank_metrics,
        "rows": packets,
    }
    artifact = {**material, "artifact_content_sha256": sealed_sha256(material)}
    _write_exclusive(
        output_root / "UNRESOLVED-502-LEXICAL-RESEARCH-PACKETS.json",
        json.dumps(artifact, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
        + b"\n",
    )
    _write_exclusive(
        output_root / "OUTCOME.txt",
        b"PHASE 2A RESEARCH PACKETS PREPARED - OWNER REVIEW REQUIRED; NO SOURCE ADMISSION OR PHASE 2B\n",
    )
    return artifact
