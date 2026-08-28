#!/usr/bin/env python3
"""Build context-safe exact-chunk evidence for all 448 unresolved issues.

The prior planner could choose a wrong provision from a broad scenario and
could discard a relevant long section wholesale.  This create-only recovery
uses the issue label as the primary query, searches the immutable target-date
catalogue, retains one useful prior exact selection where available, and
projects only whole chunks.  Any omitted chunks are disclosed and sealed; no
text is silently truncated.

The result is advisory evidence input only.  It cannot decide materiality,
admit a source, mutate a candidate, qualify a row, or authorize a later gate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import stat
import sys
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer  # type: ignore[import-untyped]

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.evaluation.phase2a_research_packets import (  # noqa: E402
    ResearchSource,
    ResearchSpan,
    _candidate_manifest_authorities,
    _load_cases,
    _load_spans,
    _open_catalogue,
    _select_sources,
    subject_routes,
)
from scripts import build_v111_phase2a_authority_plan_advisory as planner  # noqa: E402
from scripts import resolve_v111_phase2a_authority_plan_locators as prior_resolver  # noqa: E402

OWNER_REVIEW_ROOT = PROJECT_ROOT / "data" / "evaluations" / "phase2a-owner-review"
DEFAULT_REMAINING = planner.DEFAULT_REMAINING
DEFAULT_CASES = planner.DEFAULT_CASES
DEFAULT_PRIOR_LOCATORS = (
    OWNER_REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-25-r51c-context-safe-locator-resolution"
    / "DETERMINISTIC-LOCATOR-RESOLUTION-448.json"
)
DEFAULT_CANDIDATE_MANIFEST = (
    PROJECT_ROOT
    / "data/indexes/builds/current-law-ew-full-fp16-v111-20260818-a"
    / "approved-source-manifest.json"
)
DEFAULT_CATALOGUE = PROJECT_ROOT / "data" / "catalog.sqlite3"
DEFAULT_OUTPUT = OWNER_REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-25-r60g-targeted-global-recovery"

EXPECTED_REMAINING_CONTENT_SHA256 = planner.EXPECTED_REMAINING_CONTENT_SHA256
EXPECTED_CASES_FILE_SHA256 = planner.EXPECTED_CASES_FILE_SHA256
EXPECTED_CANDIDATE_MANIFEST_SHA256 = (
    "d2c1434fd5fc44d4f2f7e4f7629293f646bb28ed9b8466687feb6c470ea53ac0"
)
EXPECTED_CATALOGUE_FILE_SHA256 = prior_resolver.EXPECTED_CATALOGUE_FILE_SHA256
EXPECTED_ISSUE_COUNT = 448
TARGET_CEILING_DATE = prior_resolver.TARGET_CEILING_DATE

MAX_GLOBAL_CANDIDATES_RECORDED = 12
MAX_LEXICAL_CANDIDATE_POOL_PER_ROW = 512
MAX_GLOBAL_SELECTIONS_PER_ROW = 2
MAX_PRIOR_SELECTIONS_PER_ROW = 2
MAX_SELECTIONS_PER_ROW = MAX_GLOBAL_SELECTIONS_PER_ROW + MAX_PRIOR_SELECTIONS_PER_ROW
MAX_CHUNKS_PER_SELECTION = 4
MAX_CHARACTERS_PER_SELECTION = 2_200
MAX_CHUNKS_PER_ROW = 10
MAX_CHARACTERS_PER_ROW = 6_500

_TOKEN = re.compile(r"[a-z0-9]+(?:['’-][a-z0-9]+)?", re.IGNORECASE)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_STOP = frozenset(
    {
        "a",
        "an",
        "and",
        "as",
        "at",
        "by",
        "for",
        "from",
        "in",
        "of",
        "on",
        "or",
        "the",
        "to",
        "with",
    }
)


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sealed(value: Any) -> str:
    return _sha256(_canonical_json(value))


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_targeted_recovery_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_targeted_recovery_input_must_be_object")
    return value


def _verify_seal(value: Mapping[str, Any], field: str, code: str) -> str:
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if not _SHA256.fullmatch(supplied) or supplied != _sealed(material):
        raise ValueError(code)
    return supplied


def _write_exclusive(path: Path, raw: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _normalized(value: str) -> str:
    return " ".join(_TOKEN.findall(value.casefold().replace("’", "'")))


def _query_tokens(issue_label: str) -> frozenset[str]:
    return frozenset(
        token for token in _TOKEN.findall(issue_label.casefold()) if token not in _STOP
    )


def _token_coverage(issue_label: str, text: str) -> float:
    wanted = _query_tokens(issue_label)
    if not wanted:
        return 0.0
    observed = frozenset(_TOKEN.findall(text.casefold()))
    return len(wanted & observed) / len(wanted)


def _exact_label_present(issue_label: str, text: str) -> bool:
    label = _normalized(issue_label)
    return bool(label and label in _normalized(text))


def _direct_rule_signal(text: str) -> bool:
    lowered = " ".join(text.casefold().split())
    return any(
        marker in lowered
        for marker in (
            " is to be treated as including ",
            " shall ",
            " must ",
            " is liable ",
            " is entitled ",
            " may apply ",
            " the court may ",
            " it is an offence ",
        )
    )


def _cross_reference_like(source: ResearchSource, text: str, direct_rule: bool) -> bool:
    if source.family == "case" or direct_rule:
        return False
    lowered = text.casefold()
    return len(re.findall(r"\bsection\s+\d+[a-z]?\b", lowered)) >= 2


def _source_allowed(
    source: ResearchSource,
    *,
    candidate_authorities: frozenset[str],
    candidate_versions: frozenset[str],
) -> bool:
    if not source.identity_verified:
        return False
    if source.family != "case":
        return source.currentness_verified
    return (
        source.authority_identity_id in candidate_authorities
        or source.source_version_id in candidate_versions
    )


def _rank_global_spans(
    *,
    issue_rows: Sequence[Mapping[str, Any]],
    cases: Mapping[str, Mapping[str, Any]],
    spans: Sequence[ResearchSpan],
    candidate_authorities: frozenset[str],
    candidate_versions: frozenset[str],
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Any]]:
    """Return issue-label-first advisory candidates with transparent scores."""

    eligible = tuple(
        span
        for span in spans
        if _source_allowed(
            span.source,
            candidate_authorities=candidate_authorities,
            candidate_versions=candidate_versions,
        )
    )
    if not eligible:
        raise ValueError("phase2a_targeted_recovery_eligible_spans_empty")
    documents = [
        " ".join(
            (
                span.source.title,
                span.source.title,
                span.source.canonical_citation,
                span.locator,
                span.locator,
                span.locator,
                span.source.subject,
                span.text,
            )
        )
        for span in eligible
    ]
    vectorizer = TfidfVectorizer(
        lowercase=True,
        strip_accents="unicode",
        stop_words="english",
        ngram_range=(1, 3),
        min_df=1,
        max_features=160_000,
        sublinear_tf=True,
        norm="l2",
    )
    matrix = vectorizer.fit_transform(documents)
    by_row: dict[str, list[dict[str, Any]]] = {}
    positive_scores: list[float] = []
    for row in issue_rows:
        row_id = str(row["item_id"])
        issue_label = str(row["issue_label"])
        legal_domain = str(row["legal_domain"])
        case_id = row_id.split(":", 1)[0]
        case = cases.get(case_id)
        if case is None:
            raise ValueError("phase2a_targeted_recovery_case_missing")
        query_text = " ".join(
            (
                *(issue_label for _ in range(10)),
                legal_domain,
                legal_domain,
                str(case.get("subject") or ""),
                str(case.get("question") or ""),
            )
        )
        lexical = np.asarray((matrix @ vectorizer.transform([query_text]).T).toarray()).reshape(-1)
        scored: list[tuple[float, float, float, float, float, float, int]] = []
        allowed_subjects = subject_routes(legal_domain)
        # Phrase and token coverage are deliberately evaluated only for a
        # bounded, deterministically ordered lexical pool.  Re-tokenizing all
        # 23k source spans for every one of the 448 rows is both wasteful and
        # unnecessary: an exact issue-label phrase necessarily has positive
        # lexical overlap and enters this generously sized pool.
        lexical_order = np.argsort(lexical, kind="stable")[::-1]
        candidate_pool = lexical_order[:MAX_LEXICAL_CANDIDATE_POOL_PER_ROW]
        for raw_index in candidate_pool:
            index = int(raw_index)
            base = float(lexical[index])
            if base <= 0.0:
                break
            span = eligible[index]
            combined = " ".join(
                (
                    span.source.title,
                    span.source.canonical_citation,
                    span.locator,
                    span.text,
                )
            )
            coverage = _token_coverage(issue_label, combined)
            phrase = 1.0 if _exact_label_present(issue_label, combined) else 0.0
            route = 1.0 if span.source.subject in allowed_subjects else 0.0
            direct_rule = 1.0 if _direct_rule_signal(span.text) else 0.0
            cross_reference = (
                1.0 if _cross_reference_like(span.source, span.text, bool(direct_rule)) else 0.0
            )
            title_domain = _token_coverage(legal_domain, span.source.title)
            phrase_weight = 0.10 if cross_reference else 0.75
            score = (
                base
                + (phrase_weight * phrase)
                + (0.30 * coverage)
                + (0.04 * route)
                + (0.15 * direct_rule)
                + (0.15 * title_domain)
            )
            if score > 0:
                scored.append(
                    (
                        score,
                        phrase,
                        coverage,
                        direct_rule,
                        1.0 - cross_reference,
                        title_domain,
                        index,
                    )
                )
        scored.sort(
            key=lambda item: (
                item[0],
                item[1],
                item[2],
                item[3],
                item[4],
                item[5],
                eligible[item[6]].source.authority_identity_id,
                eligible[item[6]].locator,
            ),
            reverse=True,
        )
        selected: list[dict[str, Any]] = []
        authority_counts: Counter[str] = Counter()
        for (
            score,
            phrase,
            coverage,
            direct_rule,
            not_cross_reference,
            title_domain,
            index,
        ) in scored:
            span = eligible[index]
            authority_id = span.source.authority_identity_id
            if authority_counts[authority_id] >= 4:
                continue
            authority_counts[authority_id] += 1
            material = {
                "rank": len(selected) + 1,
                "combined_advisory_score": round(score, 8),
                "lexical_tfidf_score": round(float(lexical[index]), 8),
                "exact_issue_label_phrase_present": bool(phrase),
                "issue_label_token_coverage": round(coverage, 8),
                "direct_rule_signal_present": bool(direct_rule),
                "cross_reference_like": not bool(not_cross_reference),
                "source_title_domain_token_coverage": round(title_domain, 8),
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
                "already_in_sealed_candidate": (
                    authority_id in candidate_authorities
                    or span.source.source_version_id in candidate_versions
                ),
                "advisory_only_not_qualified": True,
            }
            selected.append({**material, "candidate_record_content_sha256": _sealed(material)})
            positive_scores.append(score)
            if len(selected) == MAX_GLOBAL_CANDIDATES_RECORDED:
                break
        if not selected:
            raise ValueError("phase2a_targeted_recovery_row_has_no_candidate")
        by_row[row_id] = selected
    return by_row, {
        "eligible_span_count": len(eligible),
        "candidate_record_count": sum(len(items) for items in by_row.values()),
        "minimum_combined_advisory_score": round(min(positive_scores), 8),
        "maximum_combined_advisory_score": round(max(positive_scores), 8),
    }


def _chunk_rows(
    connection: sqlite3.Connection,
    *,
    source_version_id: str,
    chunk_ids: Sequence[str],
) -> list[dict[str, Any]]:
    if not chunk_ids or len(set(chunk_ids)) != len(chunk_ids):
        raise ValueError("phase2a_targeted_recovery_chunk_ids_invalid")
    placeholders = ",".join("?" for _ in chunk_ids)
    rows = connection.execute(
        f"""
        SELECT id, source_version_id, ordinal, heading_path, locator, text_sha256,
               markdown_text, token_count, metadata_json, stream
        FROM chunks
        WHERE source_version_id=? AND id IN ({placeholders})
        """,
        (source_version_id, *chunk_ids),
    ).fetchall()
    by_id = {str(row["id"]): row for row in rows}
    if set(by_id) != set(chunk_ids):
        raise ValueError("phase2a_targeted_recovery_chunk_missing")
    exact: list[dict[str, Any]] = []
    for chunk_id in chunk_ids:
        row = by_id[chunk_id]
        text = str(row["markdown_text"] or "")
        supplied_sha256 = str(row["text_sha256"] or "")
        if not text or supplied_sha256 != _sha256(text.encode("utf-8")):
            raise ValueError("phase2a_targeted_recovery_chunk_hash_invalid")
        try:
            heading_value = json.loads(str(row["heading_path"] or "[]"))
            heading = (
                " > ".join(str(item) for item in heading_value)
                if isinstance(heading_value, list)
                else str(heading_value)
            )
        except json.JSONDecodeError:
            heading = str(row["heading_path"] or "")
        exact.append(
            {
                "chunk_id": chunk_id,
                "ordinal": int(row["ordinal"]),
                "locator": str(row["locator"] or ""),
                "heading_path": heading,
                "text": text,
                "text_sha256": supplied_sha256,
                "token_count": int(row["token_count"]),
                "stream": str(row["stream"] or ""),
                "metadata_json_sha256": _sha256(str(row["metadata_json"] or "{}").encode()),
            }
        )
    return exact


def _chunk_score(issue_label: str, chunk: Mapping[str, Any]) -> tuple[float, int, int]:
    text = " ".join(
        (
            str(chunk.get("locator") or ""),
            str(chunk.get("heading_path") or ""),
            str(chunk.get("text") or ""),
        )
    )
    score = (4.0 if _exact_label_present(issue_label, text) else 0.0) + (
        3.0 * _token_coverage(issue_label, text)
    )
    return score, -len(str(chunk.get("text") or "")), -int(chunk.get("ordinal") or 0)


def _label_linked_direct_rule(issue_label: str, chunks: Sequence[Mapping[str, Any]]) -> bool:
    """Require label relevance and rule language inside the same whole chunk."""

    return any(
        _token_coverage(issue_label, str(chunk.get("text") or "")) >= 0.5
        and _direct_rule_signal(str(chunk.get("text") or ""))
        for chunk in chunks
    )


def _project_whole_chunks(
    *,
    issue_label: str,
    chunks: Sequence[Mapping[str, Any]],
    character_budget: int,
    chunk_budget: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Project whole chunks and seal the explicitly omitted identity set."""

    all_chunks = [dict(chunk) for chunk in chunks]
    ordered = sorted(
        all_chunks,
        key=lambda chunk: (_chunk_score(issue_label, chunk), str(chunk["chunk_id"])),
        reverse=True,
    )
    selected: list[dict[str, Any]] = []
    used = 0
    limit_count = min(MAX_CHUNKS_PER_SELECTION, max(0, chunk_budget))
    limit_chars = min(MAX_CHARACTERS_PER_SELECTION, max(0, character_budget))
    for chunk in ordered:
        text_length = len(str(chunk["text"]))
        if len(selected) >= limit_count:
            break
        if text_length > limit_chars - used:
            continue
        selected.append(chunk)
        used += text_length
    selected_ids = {str(chunk["chunk_id"]) for chunk in selected}
    omitted = [
        {
            "chunk_id": str(chunk["chunk_id"]),
            "text_sha256": str(chunk["text_sha256"]),
        }
        for chunk in all_chunks
        if str(chunk["chunk_id"]) not in selected_ids
    ]
    metadata = {
        "available_exact_chunk_count": len(all_chunks),
        "available_exact_chunk_text_characters": sum(
            len(str(chunk["text"])) for chunk in all_chunks
        ),
        "selected_exact_chunk_count": len(selected),
        "selected_exact_chunk_text_characters": used,
        "whole_chunks_only": True,
        "silent_text_truncation": False,
        "complete_locator_result_used": not omitted,
        "projection_policy": "ISSUE_LABEL_PHRASE_AND_TOKEN_COVERAGE_WHOLE_CHUNKS",
        "all_chunk_identities_sha256": _sealed(
            [
                {
                    "chunk_id": str(chunk["chunk_id"]),
                    "text_sha256": str(chunk["text_sha256"]),
                }
                for chunk in all_chunks
            ]
        ),
        "omitted_chunk_count": len(omitted),
        "omitted_chunk_identities_sha256": _sealed(omitted),
    }
    return selected, metadata


def _source_identity(source: ResearchSource) -> dict[str, Any]:
    return {
        "id": source.source_version_id,
        "authority_identity_id": source.authority_identity_id,
        "version_sha256": source.version_sha256,
        "title": source.title,
        "canonical_url": source.canonical_url,
        "stable_identifier": source.stable_identifier,
        "source_date": source.as_of_date,
        "as_of_date": source.as_of_date,
        "currentness_status": source.currentness_status,
        "review_status": "approved",
        "document_status": "citable",
        "lane": "primary_authority",
    }


def _prior_selection_score(issue_label: str, selection: Mapping[str, Any]) -> float:
    chunks = selection.get("exact_chunks")
    if not isinstance(chunks, list) or not chunks:
        return -1.0
    return max(_chunk_score(issue_label, chunk)[0] for chunk in chunks if isinstance(chunk, dict))


def build_targeted_recovery(
    *,
    remaining_path: Path,
    cases_path: Path,
    prior_locators_path: Path,
    candidate_manifest_path: Path,
    catalogue_path: Path,
    output_root: Path,
) -> dict[str, Any]:
    """Build one sealed all-448 targeted recovery artifact."""

    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_targeted_recovery_output_already_exists")
    issue_rows, remaining_sha256 = planner._load_issue_rows(remaining_path)
    if remaining_sha256 != EXPECTED_REMAINING_CONTENT_SHA256:
        raise ValueError("phase2a_targeted_recovery_remaining_identity_invalid")
    if _sha256_file(cases_path) != EXPECTED_CASES_FILE_SHA256:
        raise ValueError("phase2a_targeted_recovery_cases_identity_invalid")
    cases = _load_cases(cases_path)
    if len(cases) != 60:
        raise ValueError("phase2a_targeted_recovery_case_count_invalid")

    prior = _load_object(prior_locators_path)
    prior_sha256 = _verify_seal(
        prior,
        "artifact_content_sha256",
        "phase2a_targeted_recovery_prior_locator_seal_invalid",
    )
    if (
        prior.get("planned_record_count") != EXPECTED_ISSUE_COUNT
        or prior.get("catalogue_file_sha256") != EXPECTED_CATALOGUE_FILE_SHA256
        or prior.get("target_ceiling_date") != TARGET_CEILING_DATE.isoformat()
        or prior.get("owner_decisions_applied") is not False
        or prior.get("source_admission_authorized") is not False
        or prior.get("candidate_mutated") is not False
    ):
        raise ValueError("phase2a_targeted_recovery_prior_locator_boundary_invalid")
    prior_by_row = {
        str(row.get("row_id") or ""): row
        for row in prior.get("records", [])
        if isinstance(row, dict)
    }
    if len(prior_by_row) != EXPECTED_ISSUE_COUNT:
        raise ValueError("phase2a_targeted_recovery_prior_locator_inventory_invalid")

    manifest_sha256, candidate_authorities, candidate_versions = _candidate_manifest_authorities(
        candidate_manifest_path
    )
    if manifest_sha256 != EXPECTED_CANDIDATE_MANIFEST_SHA256:
        raise ValueError("phase2a_targeted_recovery_candidate_manifest_invalid")
    if _sha256_file(catalogue_path) != EXPECTED_CATALOGUE_FILE_SHA256:
        raise ValueError("phase2a_targeted_recovery_catalogue_identity_invalid")

    with _open_catalogue(catalogue_path) as connection:
        sources = _select_sources(connection, TARGET_CEILING_DATE)
        spans = _load_spans(connection, sources)
        source_by_id = {source.source_version_id: source for source in sources}
        span_by_identity = {
            (span.source.source_version_id, span.span_bundle_sha256): span for span in spans
        }
        global_by_row, rank_metrics = _rank_global_spans(
            issue_rows=issue_rows,
            cases=cases,
            spans=spans,
            candidate_authorities=candidate_authorities,
            candidate_versions=candidate_versions,
        )
        records: list[dict[str, Any]] = []
        projected_prior_count = 0
        projected_global_count = 0
        rows_with_omissions = 0
        rows_with_non_candidate_source = 0
        for ordinal, issue in enumerate(issue_rows, start=1):
            row_id = str(issue["item_id"])
            issue_label = str(issue["issue_label"])
            candidates = global_by_row[row_id]
            selections: list[dict[str, Any]] = []
            remaining_characters = MAX_CHARACTERS_PER_ROW
            remaining_chunks = MAX_CHUNKS_PER_ROW
            seen: set[tuple[str, str]] = set()

            prior_selections = [
                item
                for item in prior_by_row[row_id].get("resolved_selections", [])
                if isinstance(item, dict) and bool(item.get("exact_chunks"))
            ]
            prior_selections.sort(
                key=lambda item: (
                    _prior_selection_score(issue_label, item),
                    str(item.get("authority_identity_id") or ""),
                    str(item.get("canonical_locator") or ""),
                ),
                reverse=True,
            )
            useful_prior = [
                selection
                for selection in prior_selections
                if _prior_selection_score(issue_label, selection) > 0.0
            ]
            for prior_selection in useful_prior[:MAX_PRIOR_SELECTIONS_PER_ROW]:
                source = prior_selection.get("source_identity")
                chunks = prior_selection.get("exact_chunks")
                if not isinstance(source, dict) or not isinstance(chunks, list):
                    raise ValueError("phase2a_targeted_recovery_prior_selection_invalid")
                projected, projection = _project_whole_chunks(
                    issue_label=issue_label,
                    chunks=chunks,
                    character_budget=remaining_characters,
                    chunk_budget=remaining_chunks,
                )
                if not projected:
                    continue
                identity = (
                    str(source.get("id") or ""),
                    str(prior_selection.get("canonical_locator") or ""),
                )
                seen.add(identity)
                selection_material = {
                    "selection_origin": "PRIOR_EXACT_SELECTION_REPROJECTED",
                    "authority_identity_id": prior_selection["authority_identity_id"],
                    "locator_hint": prior_selection.get("locator_hint"),
                    "canonical_locator": prior_selection.get("canonical_locator"),
                    "resolution_status": "TARGETED_WHOLE_CHUNK_PROJECTION_FOUND",
                    "source_identity": source,
                    "candidate_source_metadata": prior_selection.get("candidate_source_metadata"),
                    **projection,
                    "exact_chunks": projected,
                }
                selections.append(
                    {
                        **selection_material,
                        "selection_content_sha256": _sealed(selection_material),
                    }
                )
                projected_prior_count += 1
                remaining_characters -= projection["selected_exact_chunk_text_characters"]
                remaining_chunks -= projection["selected_exact_chunk_count"]

            prepared_global: list[
                tuple[
                    dict[str, Any],
                    ResearchSource,
                    ResearchSpan,
                    list[dict[str, Any]],
                    bool,
                ]
            ] = []
            for candidate in candidates:
                source_version_id = str(candidate["source_version_id"])
                span = span_by_identity.get(
                    (source_version_id, str(candidate["span_bundle_sha256"]))
                )
                source = source_by_id.get(source_version_id)
                if span is None or source is None:
                    raise ValueError("phase2a_targeted_recovery_global_span_missing")
                chunks = _chunk_rows(
                    connection,
                    source_version_id=source_version_id,
                    chunk_ids=list(span.chunk_ids),
                )
                prepared_global.append(
                    (
                        candidate,
                        source,
                        span,
                        chunks,
                        _label_linked_direct_rule(issue_label, chunks),
                    )
                )
            prepared_global.sort(
                key=lambda item: (
                    item[4],
                    item[0].get("cross_reference_like") is not True,
                    float(item[0]["combined_advisory_score"]),
                    -int(item[0]["rank"]),
                ),
                reverse=True,
            )
            for candidate, source, span, chunks, label_linked_rule in prepared_global:
                if (
                    sum(
                        item.get("selection_origin") == "GLOBAL_ISSUE_LABEL_RECOVERY"
                        for item in selections
                    )
                    >= MAX_GLOBAL_SELECTIONS_PER_ROW
                ):
                    break
                source_version_id = str(candidate["source_version_id"])
                identity = (source_version_id, str(candidate["locator"]))
                if identity in seen:
                    continue
                projected, projection = _project_whole_chunks(
                    issue_label=issue_label,
                    chunks=chunks,
                    character_budget=remaining_characters,
                    chunk_budget=remaining_chunks,
                )
                if not projected:
                    continue
                source_identity = _source_identity(source)
                metadata = {
                    "canonical_citation": source.canonical_citation,
                    "canonical_url": source.canonical_url,
                    "identity_verified": source.identity_verified,
                    "currentness_verified": source.currentness_verified,
                    "later_treatment_review_required": source.family == "case",
                    "already_in_sealed_candidate": candidate["already_in_sealed_candidate"],
                    "candidate_record_content_sha256": candidate["candidate_record_content_sha256"],
                    "span_bundle_sha256": candidate["span_bundle_sha256"],
                    "combined_advisory_score": candidate["combined_advisory_score"],
                    "label_linked_direct_rule_in_same_whole_chunk": (label_linked_rule),
                }
                selection_material = {
                    "selection_origin": "GLOBAL_ISSUE_LABEL_RECOVERY",
                    "authority_identity_id": source.authority_identity_id,
                    "locator_hint": span.locator,
                    "canonical_locator": prior_resolver.canonical_locator(span.locator),
                    "resolution_status": "TARGETED_WHOLE_CHUNK_PROJECTION_FOUND",
                    "source_identity": source_identity,
                    "candidate_source_metadata": metadata,
                    **projection,
                    "exact_chunks": projected,
                }
                selections.append(
                    {
                        **selection_material,
                        "selection_content_sha256": _sealed(selection_material),
                    }
                )
                seen.add(identity)
                projected_global_count += 1
                remaining_characters -= projection["selected_exact_chunk_text_characters"]
                remaining_chunks -= projection["selected_exact_chunk_count"]
                if remaining_characters <= 0 or remaining_chunks <= 0:
                    break
            if not selections:
                raise ValueError("phase2a_targeted_recovery_no_projected_evidence")
            if any(item["omitted_chunk_count"] for item in selections):
                rows_with_omissions += 1
            if any(
                item.get("candidate_source_metadata", {}).get("already_in_sealed_candidate")
                is False
                for item in selections
            ):
                rows_with_non_candidate_source += 1
            record_material = {
                "schema": "legalbot.v111.phase2a.targeted-global-recovery-row.v7",
                "ordinal": ordinal,
                "row_id": row_id,
                "issue_label": issue_label,
                "legal_domain": issue["legal_domain"],
                "issue_label_query_sha256": _sha256((issue_label + "\n").encode("utf-8")),
                "global_advisory_candidates": candidates,
                "resolved_selections": selections,
                "semantic_proposition_support_verified": False,
                "owner_outcome": None,
                "owner_decision_required": True,
                "technical_qualification_assigned": False,
                "source_admission_authorized": False,
                "candidate_mutated": False,
                "phase2b_authorized": False,
                "development30_authorized": False,
            }
            records.append({**record_material, "record_content_sha256": _sealed(record_material)})

    if len(records) != EXPECTED_ISSUE_COUNT:
        raise ValueError("phase2a_targeted_recovery_output_inventory_invalid")
    source_registry = [
        {
            "source_version_id": source.source_version_id,
            "authority_identity_id": source.authority_identity_id,
            "version_sha256": source.version_sha256,
            "as_of_date": source.as_of_date,
            "currentness_status": source.currentness_status,
            "identity_verified": source.identity_verified,
            "currentness_verified": source.currentness_verified,
            "family": source.family,
        }
        for source in sources
    ]
    artifact_material = {
        "schema": "legalbot.v111.phase2a.targeted-global-recovery-448.v7",
        "status": "TARGETED_WHOLE_CHUNK_RECOVERY_COMPLETE_SEMANTIC_REVIEW_REQUIRED",
        "target_ceiling_date": TARGET_CEILING_DATE.isoformat(),
        "source_remaining_content_sha256": remaining_sha256,
        "source_cases_file_sha256": EXPECTED_CASES_FILE_SHA256,
        "source_prior_locator_content_sha256": prior_sha256,
        "source_candidate_manifest_sha256": manifest_sha256,
        "source_catalogue_file_sha256": EXPECTED_CATALOGUE_FILE_SHA256,
        "source_registry_sha256": _sealed(source_registry),
        "builder_code_file_sha256": _sha256_file(Path(__file__).resolve()),
        "issue_count": len(records),
        "source_authority_count": len(sources),
        "source_span_group_count": len(spans),
        "rank_metrics": rank_metrics,
        "projection_metrics": {
            "projected_prior_selection_count": projected_prior_count,
            "projected_global_selection_count": projected_global_count,
            "rows_with_explicit_omitted_chunk_set": rows_with_omissions,
            "rows_with_at_least_one_non_candidate_source": (rows_with_non_candidate_source),
        },
        "policy": {
            "issue_label_primary_query": True,
            "maximum_lexical_candidate_pool_per_row": (MAX_LEXICAL_CANDIDATE_POOL_PER_ROW),
            "scenario_text_used_for_first_stage_ranking": True,
            "scenario_text_used_once_beneath_tenfold_issue_label_weight": True,
            "catalogue_opened_immutable_read_only": True,
            "target_date_source_selection": True,
            "new_case_sources_considered": False,
            "whole_chunks_only": True,
            "silent_text_truncation": False,
            "omitted_chunk_sets_sealed": True,
            "maximum_selections_per_row": MAX_SELECTIONS_PER_ROW,
            "maximum_chunks_per_row": MAX_CHUNKS_PER_ROW,
            "maximum_characters_per_row": MAX_CHARACTERS_PER_ROW,
        },
        "records": records,
        "semantic_proposition_support_verified": False,
        "owner_decisions_applied": False,
        "technical_qualification_assigned": False,
        "source_admission_authorized": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    artifact = {
        **artifact_material,
        "artifact_content_sha256": _sealed(artifact_material),
    }
    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_targeted_recovery_output_mode_invalid")
    artifact_raw = _pretty_json(artifact)
    outcome_raw = (
        b"TARGETED GLOBAL WHOLE-CHUNK RECOVERY COMPLETE FOR 448 ISSUES. "
        b"SEMANTIC AND OWNER REVIEW REQUIRED; NO SOURCE ADMISSION OR GATE AUTHORIZATION.\n"
    )
    _write_exclusive(output_root / "TARGETED-GLOBAL-RECOVERY-448.json", artifact_raw)
    _write_exclusive(output_root / "OUTCOME.txt", outcome_raw)
    sums = (
        f"{_sha256(artifact_raw)}  TARGETED-GLOBAL-RECOVERY-448.json\n"
        f"{_sha256(outcome_raw)}  OUTCOME.txt\n"
    ).encode()
    _write_exclusive(output_root / "SHA256SUMS.txt", sums)
    return artifact


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--remaining", type=Path, default=DEFAULT_REMAINING)
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASES)
    parser.add_argument("--prior-locators", type=Path, default=DEFAULT_PRIOR_LOCATORS)
    parser.add_argument("--candidate-manifest", type=Path, default=DEFAULT_CANDIDATE_MANIFEST)
    parser.add_argument("--catalogue", type=Path, default=DEFAULT_CATALOGUE)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    result = build_targeted_recovery(
        remaining_path=args.remaining.resolve(strict=True),
        cases_path=args.cases.resolve(strict=True),
        prior_locators_path=args.prior_locators.resolve(strict=True),
        candidate_manifest_path=args.candidate_manifest.resolve(strict=True),
        catalogue_path=args.catalogue.resolve(strict=True),
        output_root=args.output_root.resolve(),
    )
    print(
        json.dumps(
            {
                "output_root": str(args.output_root),
                "issue_count": result["issue_count"],
                "rank_metrics": result["rank_metrics"],
                "projection_metrics": result["projection_metrics"],
                "artifact_content_sha256": result["artifact_content_sha256"],
                "phase2b_authorized": result["phase2b_authorized"],
                "development30_authorized": result["development30_authorized"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
