#!/usr/bin/env python3
"""Build deterministic exact-block packets for the r103 source-link review.

The packet builder performs no semantic legal decision.  It verifies the
sealed r102 routing ledger and r103 quarantine, joins each of the 26 source
links to the immutable case question, and selects full official blocks using
only locator and lexical rules.  Every row remains for advisory and owner
review; nothing is admitted, indexed, embedded, qualified, or authorized.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import stat
from collections import Counter, defaultdict
from collections.abc import Mapping
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
R102_PATH = (
    REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-26-r102-post-r101-research-routing"
    / "POST-R101-RESEARCH-ROUTING-364.json"
)
R103_ROOT = (
    PROJECT_ROOT / "data/quarantine/2026-08-26/phase2a-post-r101-official-source-research-r103"
)
R103_MANIFEST_PATH = R103_ROOT / "QUARANTINE-MANIFEST.json"
CASES_PATH = PROJECT_ROOT / "benchmarks/evaluation/live-evaluation-60-v1/cases.jsonl"
DEFAULT_OUTPUT_ROOT = (
    REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-26-r104b-context-aware-source-review-packets"
)
EXPECTED_INPUTS = {
    R102_PATH: (
        "artifact_content_sha256",
        "eef0de2cfb5e1be2ab9279c4acbe064f288cdfa24418d1d444b1d6830d18af0b",
        "a636daf079e44ab6e51ff98fae3c8ae375949f8054764b71c9697c85583f6062",
    ),
    R103_MANIFEST_PATH: (
        "manifest_content_sha256",
        "aee3cf90510f0b99d0885ddf0423a201cee25d03309096a05baeb3cbe82ae2ad",
        "af1b9ef8b9060497d4e4420edb313e6b7ce173aad817a515bdef1dfc4a892e53",
    ),
}
EXPECTED_CASES_FILE_SHA256 = "78a738afd920ff840dcedeb0fd3fd5ca81035f499a0630d351d49e7c6cd3777a"
EXPECTED_SOURCE_COUNT = 16
EXPECTED_LINK_COUNT = 26
EXPECTED_UNIQUE_ROW_COUNT = 22
MAX_CANDIDATE_BLOCKS = 40
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TOKEN = re.compile(r"[a-z0-9]+")
_QUESTION_SEGMENT_SPLIT = re.compile(r"(?:\r?\n)+|(?<=[.!?])\s+")
_NUMBERED_HINT = re.compile(r"^(?:p|para|paragraph)\s+(?P<number>[1-9]\d*)$", re.I)
_LOCATOR_NUMBER = re.compile(r"^(?:paragraph|section) (?P<number>[1-9]\d*)$")
_STOPWORDS = frozenset(
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
        "into",
        "of",
        "on",
        "or",
        "the",
        "to",
        "with",
        "status",
        "action",
    }
)
_BOUNDARY_FIELDS = (
    "automatic_source_admission",
    "automatic_gold_change",
    "automatic_indexing",
    "automatic_embedding",
    "candidate_mutated",
    "technical_qualification_assigned",
    "phase2b_authorized",
    "development30_authorized",
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
        raise ValueError("phase2a_r104_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_r104_input_must_be_object")
    return value


def _load_verified(path: Path) -> dict[str, Any]:
    field, expected_content, expected_file = EXPECTED_INPUTS[path]
    if _sha256_file(path) != expected_file:
        raise ValueError("phase2a_r104_input_file_digest_invalid")
    value = _load_object(path)
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if (
        not _SHA256.fullmatch(supplied)
        or supplied != expected_content
        or supplied != _sealed(material)
    ):
        raise ValueError("phase2a_r104_input_content_seal_invalid")
    return value


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


def _load_cases() -> dict[str, dict[str, Any]]:
    if CASES_PATH.is_symlink() or _sha256_file(CASES_PATH) != EXPECTED_CASES_FILE_SHA256:
        raise ValueError("phase2a_r104_cases_identity_invalid")
    cases: dict[str, dict[str, Any]] = {}
    for line in CASES_PATH.read_text(encoding="utf-8").splitlines():
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError("phase2a_r104_case_record_invalid")
        case_id = str(value.get("case_id") or "")
        if not case_id or case_id in cases:
            raise ValueError("phase2a_r104_case_identity_invalid")
        cases[case_id] = value
    if len(cases) != 60:
        raise ValueError("phase2a_r104_case_count_invalid")
    return cases


def _verify_extraction(record: Mapping[str, Any]) -> dict[str, Any]:
    raw_member = str(record.get("raw_quarantine_member") or "")
    extraction_member = str(record.get("extraction_member") or "")
    if (
        not raw_member
        or not extraction_member
        or Path(raw_member).name != raw_member
        or Path(extraction_member).name != extraction_member
    ):
        raise ValueError("phase2a_r104_quarantine_member_invalid")
    raw_path = R103_ROOT / raw_member
    extraction_path = R103_ROOT / extraction_member
    if (
        raw_path.is_symlink()
        or extraction_path.is_symlink()
        or _sha256_file(raw_path) != record.get("raw_sha256")
        or _sha256_file(extraction_path) != record.get("extraction_file_sha256")
    ):
        raise ValueError("phase2a_r104_quarantine_member_digest_invalid")
    extraction = _load_object(extraction_path)
    material = dict(extraction)
    supplied = str(material.pop("artifact_content_sha256", ""))
    if (
        supplied != record.get("extraction_content_sha256")
        or supplied != _sealed(material)
        or extraction.get("automatically_admitted") is not False
        or extraction.get("automatically_indexed") is not False
        or extraction.get("automatically_embedded") is not False
    ):
        raise ValueError("phase2a_r104_extraction_seal_invalid")
    return extraction


def _query_terms(issue_label: str) -> tuple[str, ...]:
    return tuple(
        dict.fromkeys(
            token
            for token in _TOKEN.findall(issue_label.casefold())
            if token not in _STOPWORDS and len(token) > 2
        )
    )


def _normalise_token(token: str) -> str:
    """Apply a deliberately small deterministic inflection normalisation."""

    token = token.casefold()
    if len(token) > 4 and token.endswith("ies"):
        return f"{token[:-3]}y"
    if len(token) > 4 and token.endswith("s") and not token.endswith("ss"):
        return token[:-1]
    return token


def _normalised_meaningful_terms(text: str) -> tuple[str, ...]:
    return tuple(
        dict.fromkeys(
            normalised
            for token in _TOKEN.findall(text.casefold())
            if token not in _STOPWORDS and len(token) > 3
            if len(normalised := _normalise_token(token)) > 3
        )
    )


def _question_segment_candidates(
    *, question: str, blocks: list[dict[str, Any]], per_segment_limit: int = 8
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    """Return deterministic block candidates for each meaningful question segment.

    This is not a semantic assessment.  It protects broad issue labels from
    suppressing a fact-specific sentence in a long, multi-issue scenario.
    """

    block_terms: dict[str, set[str]] = {}
    document_frequency: Counter[str] = Counter()
    for block in blocks:
        locator = str(block.get("locator") or "")
        terms = set(_normalised_meaningful_terms(str(block.get("text") or "")))
        block_terms[locator] = terms
        document_frequency.update(terms)

    raw_segments = [
        segment.strip(" \t\r\n-\u2022") for segment in _QUESTION_SEGMENT_SPLIT.split(question)
    ]
    segments = [
        (index, segment, set(_normalised_meaningful_terms(segment)))
        for index, segment in enumerate(raw_segments, start=1)
        if segment.strip(" \t\r\n-\u2022")
    ]
    selected: dict[str, dict[str, Any]] = {}
    qualifying_segment_count = 0
    for segment_index, segment, segment_terms in segments:
        if len(segment_terms) < 4:
            continue
        ranked: list[tuple[int, int, int, dict[str, Any], tuple[str, ...]]] = []
        for block_ordinal, block in enumerate(blocks, start=1):
            locator = str(block.get("locator") or "")
            overlap = tuple(sorted(segment_terms & block_terms[locator]))
            if len(overlap) < 2:
                continue
            weighted_overlap = sum(
                max(
                    1,
                    round(8 * math.log((len(blocks) + 1) / (document_frequency[term] + 1))),
                )
                for term in overlap
            )
            union_size = len(segment_terms | block_terms[locator])
            jaccard_basis_points = round(10_000 * len(overlap) / union_size) if union_size else 0
            score = weighted_overlap * 10_000 + len(overlap) * 100 + jaccard_basis_points
            ranked.append((score, len(overlap), block_ordinal, block, overlap))
        ranked.sort(key=lambda item: (-item[0], -item[1], item[2]))
        if not ranked:
            continue
        qualifying_segment_count += 1
        for segment_rank, (score, _overlap_count, _ordinal, block, overlap) in enumerate(
            ranked[:per_segment_limit], start=1
        ):
            locator = str(block["locator"])
            candidate = {
                "question_segment_index": segment_index,
                "question_segment_sha256": _sha256(segment.encode("utf-8")),
                "question_segment_rank": segment_rank,
                "question_segment_score": score,
                "overlap_terms": list(overlap),
            }
            prior = selected.get(locator)
            if prior is None or (
                candidate["question_segment_score"],
                -candidate["question_segment_rank"],
                -candidate["question_segment_index"],
            ) > (
                prior["question_segment_score"],
                -prior["question_segment_rank"],
                -prior["question_segment_index"],
            ):
                selected[locator] = candidate
    diagnostics = {
        "question_segment_count": len(segments),
        "qualifying_question_segment_count": qualifying_segment_count,
        "question_segment_candidate_count": len(selected),
        "per_segment_candidate_limit": per_segment_limit,
    }
    return selected, diagnostics


def _context_query_terms(
    *, question: str, blocks: list[dict[str, Any]], issue_terms: tuple[str, ...]
) -> tuple[tuple[str, ...], dict[str, int]]:
    document_frequency: Counter[str] = Counter()
    for block in blocks:
        document_frequency.update(set(_TOKEN.findall(str(block.get("text") or "").casefold())))
    ordered = tuple(
        dict.fromkeys(
            token
            for token in _TOKEN.findall(question.casefold())
            if token not in _STOPWORDS
            and token not in issue_terms
            and len(token) > 3
            and document_frequency[token] > 0
        )
    )
    terms = ordered[:128]
    block_count = len(blocks)
    weights = {
        token: max(
            1,
            round(4 * math.log((block_count + 1) / (document_frequency[token] + 1))),
        )
        for token in terms
    }
    return terms, weights


def _lexical_score(
    text: str,
    *,
    issue_label: str,
    terms: tuple[str, ...],
    context_terms: tuple[str, ...],
    context_term_weights: Mapping[str, int],
) -> int:
    lowered = text.casefold()
    score = 500 if issue_label.casefold() in lowered else 0
    counts = Counter(_TOKEN.findall(lowered))
    for term in terms:
        score += min(counts[term], 3) * 20
        if term.rstrip("s") and term.rstrip("s") in lowered:
            score += 2
    if terms and all(term in lowered for term in terms):
        score += 120
    for term in context_terms:
        score += min(counts[term], 2) * context_term_weights[term]
    return score


def _resolved_hint_locator(
    hint: str, *, source_class: str, by_locator: Mapping[str, Mapping[str, Any]]
) -> str | None:
    match = _NUMBERED_HINT.fullmatch(hint.strip())
    if match is None:
        return None
    number = int(match.group("number"))
    prefix = "paragraph" if "JUDGMENT" in source_class else "section"
    locator = f"{prefix} {number}"
    return locator if locator in by_locator else None


def _candidate_blocks(
    *,
    extraction: Mapping[str, Any],
    row_id: str,
    issue_label: str,
    case_question: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    raw_blocks = extraction.get("blocks")
    hints_by_row = extraction.get("locator_hints_by_row")
    if not isinstance(raw_blocks, list) or not isinstance(hints_by_row, Mapping):
        raise ValueError("phase2a_r104_extraction_records_invalid")
    blocks = [dict(block) for block in raw_blocks if isinstance(block, dict)]
    by_locator = {str(block.get("locator") or ""): block for block in blocks}
    if len(by_locator) != len(blocks):
        raise ValueError("phase2a_r104_block_locator_collision")
    hints = hints_by_row.get(row_id)
    if not isinstance(hints, list) or not hints:
        raise ValueError("phase2a_r104_row_locator_hints_missing")
    terms = _query_terms(issue_label)
    context_terms, context_term_weights = _context_query_terms(
        question=case_question,
        blocks=blocks,
        issue_terms=terms,
    )
    segment_candidates, segment_diagnostics = _question_segment_candidates(
        question=case_question,
        blocks=blocks,
    )
    scored: list[tuple[int, int, dict[str, Any]]] = []
    exact_phrase_count = 0
    for ordinal, block in enumerate(blocks, start=1):
        text = str(block.get("text") or "")
        if _sha256(text.encode("utf-8")) != block.get("text_sha256"):
            raise ValueError("phase2a_r104_block_text_digest_invalid")
        score = _lexical_score(
            text,
            issue_label=issue_label,
            terms=terms,
            context_terms=context_terms,
            context_term_weights=context_term_weights,
        )
        exact_phrase_count += issue_label.casefold() in text.casefold()
        scored.append((score, ordinal, block))
    scored.sort(key=lambda item: (-item[0], item[1]))

    selected: dict[str, dict[str, Any]] = {}
    reasons: dict[str, set[str]] = defaultdict(set)
    resolved_hints: list[dict[str, Any]] = []
    for hint in hints:
        locator = _resolved_hint_locator(
            str(hint),
            source_class=str(extraction.get("source_class") or ""),
            by_locator=by_locator,
        )
        resolved_hints.append(
            {
                "supplied_hint": hint,
                "resolved_locator": locator,
                "resolved": locator is not None,
            }
        )
        if locator is None:
            continue
        selected[locator] = dict(by_locator[locator])
        reasons[locator].add("SUPPLIED_LOCATOR_EXACT")
        numbered = _LOCATOR_NUMBER.fullmatch(locator)
        if numbered is None:
            continue
        number = int(numbered.group("number"))
        prefix = locator.split(" ", 1)[0]
        for adjacent in (number - 1, number + 1):
            adjacent_locator = f"{prefix} {adjacent}"
            if adjacent_locator in by_locator:
                selected[adjacent_locator] = dict(by_locator[adjacent_locator])
                reasons[adjacent_locator].add("SUPPLIED_LOCATOR_ADJACENT")

    for _score, _ordinal, block in scored:
        locator = str(block["locator"])
        if issue_label.casefold() in str(block["text"]).casefold():
            selected[locator] = dict(block)
            reasons[locator].add("EXACT_ISSUE_PHRASE")
        if len(selected) >= MAX_CANDIDATE_BLOCKS:
            break
        selected[locator] = dict(block)
        reasons[locator].add("LEXICAL_TOP")
    for locator in segment_candidates:
        selected[locator] = dict(by_locator[locator])
        reasons[locator].add("QUESTION_SEGMENT_OVERLAP")
    if len(selected) > MAX_CANDIDATE_BLOCKS:
        ranked_locators = {
            str(block["locator"]): (score, ordinal) for score, ordinal, block in scored
        }
        selected_order = sorted(
            selected,
            key=lambda locator: (
                "SUPPLIED_LOCATOR_EXACT" not in reasons[locator],
                "EXACT_ISSUE_PHRASE" not in reasons[locator],
                "QUESTION_SEGMENT_OVERLAP" not in reasons[locator],
                -segment_candidates.get(locator, {}).get("question_segment_score", 0),
                -ranked_locators[locator][0],
                ranked_locators[locator][1],
            ),
        )[:MAX_CANDIDATE_BLOCKS]
        selected = {locator: selected[locator] for locator in selected_order}
        reasons = defaultdict(set, {locator: reasons[locator] for locator in selected_order})

    scored_by_locator = {
        str(block["locator"]): (score, ordinal) for score, ordinal, block in scored
    }
    ordered = sorted(
        selected.values(),
        key=lambda block: (
            "SUPPLIED_LOCATOR_EXACT" not in reasons[str(block["locator"])],
            "EXACT_ISSUE_PHRASE" not in reasons[str(block["locator"])],
            "QUESTION_SEGMENT_OVERLAP" not in reasons[str(block["locator"])],
            -segment_candidates.get(str(block["locator"]), {}).get("question_segment_score", 0),
            -scored_by_locator[str(block["locator"])][0],
            scored_by_locator[str(block["locator"])][1],
        ),
    )
    candidates: list[dict[str, Any]] = []
    for rank, block in enumerate(ordered, start=1):
        locator = str(block["locator"])
        text = str(block["text"])
        candidates.append(
            {
                "rank": rank,
                "block_id": f"block-{block['text_sha256'][:24]}",
                "locator": locator,
                "element_id": block.get("element_id"),
                "exact_text": text,
                "exact_text_sha256": block["text_sha256"],
                "character_count": len(text),
                "lexical_score": scored_by_locator[locator][0],
                "question_segment_match": segment_candidates.get(locator),
                "selection_reasons": sorted(reasons[locator]),
            }
        )
    diagnostics = {
        "query_terms": list(terms),
        "context_query_terms": list(context_terms),
        "context_query_term_weights": context_term_weights,
        "source_block_count": len(blocks),
        "exact_issue_phrase_occurrence_count": exact_phrase_count,
        "supplied_locator_resolutions": resolved_hints,
        "all_supplied_locators_resolved": all(item["resolved"] for item in resolved_hints),
        "selected_candidate_count": len(candidates),
        **segment_diagnostics,
    }
    return candidates, diagnostics


def build_packets(output_root: Path = DEFAULT_OUTPUT_ROOT) -> dict[str, Any]:
    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_r104_output_already_exists")
    r102 = _load_verified(R102_PATH)
    manifest = _load_verified(R103_MANIFEST_PATH)
    cases = _load_cases()
    if (
        r102.get("row_count") != 364
        or manifest.get("record_count") != EXPECTED_SOURCE_COUNT
        or manifest.get("row_link_count") != EXPECTED_LINK_COUNT
        or any(manifest.get(field) is not False for field in _BOUNDARY_FIELDS)
    ):
        raise ValueError("phase2a_r104_input_boundary_invalid")
    route_rows = r102.get("rows")
    source_records = manifest.get("records")
    if (
        not isinstance(route_rows, list)
        or len(route_rows) != 364
        or not isinstance(source_records, list)
        or len(source_records) != EXPECTED_SOURCE_COUNT
    ):
        raise ValueError("phase2a_r104_input_records_invalid")
    by_route = {str(row["row_id"]): row for row in route_rows}
    if len(by_route) != 364:
        raise ValueError("phase2a_r104_route_identity_collision")

    rows: list[dict[str, Any]] = []
    locator_counts: Counter[str] = Counter()
    phrase_positive_count = 0
    for source_record in source_records:
        if not isinstance(source_record, Mapping):
            raise ValueError("phase2a_r104_source_record_invalid")
        extraction = _verify_extraction(source_record)
        contexts = extraction.get("issue_contexts")
        if not isinstance(contexts, list):
            raise ValueError("phase2a_r104_issue_contexts_invalid")
        for context in contexts:
            if not isinstance(context, Mapping):
                raise ValueError("phase2a_r104_issue_context_invalid")
            row_id = str(context.get("row_id") or "")
            case_id = row_id.split(":", 1)[0]
            case = cases.get(case_id)
            route = by_route.get(row_id)
            issue_label = str(context.get("issue_label") or "")
            if (
                case is None
                or route is None
                or (
                    case.get("question_sha256") != route.get("case_question_sha256")
                    and route.get("case_question_sha256") is not None
                )
                or source_record.get("authority_identity_id")
                not in route.get("effective_outside_candidate_authority_ids", [])
            ):
                raise ValueError("phase2a_r104_row_join_invalid")
            question = str(case.get("question") or "")
            if _sha256(question.encode("utf-8")) != case.get("question_sha256"):
                raise ValueError("phase2a_r104_case_question_digest_invalid")
            candidates, diagnostics = _candidate_blocks(
                extraction=extraction,
                row_id=row_id,
                issue_label=issue_label,
                case_question=question,
            )
            locator_counts[
                "ALL_RESOLVED"
                if diagnostics["all_supplied_locators_resolved"]
                else "ONE_OR_MORE_UNRESOLVED"
            ] += 1
            phrase_positive_count += diagnostics["exact_issue_phrase_occurrence_count"] > 0
            material = {
                "schema": "legalbot.v111.phase2a.source-review-packet-row.v2",
                "row_source_link_id": _sha256(
                    f"{row_id}\n{source_record['authority_identity_id']}\n".encode()
                ),
                "row_id": row_id,
                "case_id": case_id,
                "case_question": question,
                "case_question_sha256": case["question_sha256"],
                "subject": case.get("subject"),
                "task_type": case.get("task_type"),
                "issue_label": issue_label,
                "legal_domain": context.get("legal_domain"),
                "research_route": context.get("research_route"),
                "authority_identity_id": source_record["authority_identity_id"],
                "canonical_authority_identity_id": source_record["canonical_authority_identity_id"],
                "source_title": source_record["source_title"],
                "source_date": source_record["source_date"],
                "source_class": source_record["source_class"],
                "official_url": source_record["final_url"],
                "source_representation_sha256": source_record["raw_sha256"],
                "source_extraction_content_sha256": source_record["extraction_content_sha256"],
                "deterministic_diagnostics": diagnostics,
                "candidate_blocks": candidates,
                "semantic_assessment": None,
                "recommended_atomic_proposition": None,
                "recommended_exact_span_binding": None,
                "owner_outcome": None,
                "owner_decision_required": True,
                "source_admission_authorized": False,
                "technical_qualification_assigned": False,
            }
            rows.append({**material, "record_content_sha256": _sealed(material)})

    if (
        len(rows) != EXPECTED_LINK_COUNT
        or len({row["row_source_link_id"] for row in rows}) != EXPECTED_LINK_COUNT
        or len({row["row_id"] for row in rows}) != EXPECTED_UNIQUE_ROW_COUNT
    ):
        raise ValueError("phase2a_r104_row_inventory_invalid")
    material = {
        "schema": "legalbot.v111.phase2a.source-review-packets-26.v2",
        "status": "CONTEXT_AWARE_DETERMINISTIC_OFFICIAL_BLOCK_PACKETS_READY_FOR_ADVISORY_REVIEW",
        "source_r102_content_sha256": r102["artifact_content_sha256"],
        "source_r103_manifest_content_sha256": manifest["manifest_content_sha256"],
        "source_cases_file_sha256": EXPECTED_CASES_FILE_SHA256,
        "source_count": EXPECTED_SOURCE_COUNT,
        "row_source_link_count": len(rows),
        "unique_row_count": len({row["row_id"] for row in rows}),
        "locator_resolution_counts": dict(sorted(locator_counts.items())),
        "exact_issue_phrase_positive_link_count": phrase_positive_count,
        "maximum_candidate_blocks_per_link": MAX_CANDIDATE_BLOCKS,
        "rows": sorted(
            rows,
            key=lambda row: (row["row_id"], row["authority_identity_id"]),
        ),
        "semantic_review_performed": False,
        "owner_decisions_applied": False,
        "source_admission_authorized": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "technical_qualification_assigned": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    artifact = {**material, "artifact_content_sha256": _sealed(material)}
    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_r104_output_mode_invalid")
    files = {
        "DETERMINISTIC-SOURCE-REVIEW-PACKETS-26.json": _pretty_json(artifact),
        "OUTCOME.txt": (
            b"26 DETERMINISTIC OFFICIAL-SOURCE REVIEW PACKETS READY. NO SEMANTIC "
            b"DECISION, OWNER DECISION, SOURCE ADMISSION, INDEXING, OR GATE CHANGE.\n"
        ),
    }
    for name, raw in files.items():
        _write_exclusive(output_root / name, raw)
    sums = "".join(f"{_sha256_file(output_root / name)}  {name}\n" for name in sorted(files))
    _write_exclusive(output_root / "SHA256SUMS.txt", sums.encode("utf-8"))
    return artifact


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    args = parser.parse_args()
    artifact = build_packets(args.output_root)
    print(
        json.dumps(
            {
                "artifact_content_sha256": artifact["artifact_content_sha256"],
                "row_source_link_count": artifact["row_source_link_count"],
                "unique_row_count": artifact["unique_row_count"],
                "locator_resolution_counts": artifact["locator_resolution_counts"],
                "exact_issue_phrase_positive_link_count": artifact[
                    "exact_issue_phrase_positive_link_count"
                ],
                "semantic_review_performed": False,
                "source_admission_authorized": False,
                "phase2b_authorized": False,
                "development30_authorized": False,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
