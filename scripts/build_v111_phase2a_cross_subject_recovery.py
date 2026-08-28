#!/usr/bin/env python3
"""Find current non-case evidence for the 37 history-only Phase-2A rows.

The original lexical packets conservatively restricted catalogue subjects.
This create-only pass searches every current, identity-verified non-case span
in the same read-only catalogue.  Results remain advisory and cannot qualify a
row, admit a source, mutate the sealed candidate, or authorize a later phase.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import date
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer

from app.evaluation.phase2a_research_packets import (
    ResearchSpan,
    _candidate_manifest_authorities,
    _display_text,
    _load_cases,
    _load_spans,
    _open_catalogue,
    _select_sources,
    sealed_sha256,
    subject_routes,
)

EXPECTED_REMAINDER_DIGEST = (
    "a7f7359c3ff12da02ee4056532198d39417459c9e20aac602f64437fb7cf5aa6"
)
EXPECTED_CASES_FILE_SHA256 = (
    "78a738afd920ff840dcedeb0fd3fd5ca81035f499a0630d351d49e7c6cd3777a"
)
EXPECTED_CANDIDATE_MANIFEST_DIGEST = (
    "d2c1434fd5fc44d4f2f7e4f7629293f646bb28ed9b8466687feb6c470ea53ac0"
)
EXPECTED_CATALOGUE_FILE_SHA256 = (
    "8c700c3e8f9cc77abe4b03cf5011624db9ff14a74f02f3a37b59c1fcf595a10d"
)
EXPECTED_REMAINDER_ROWS = 448
EXPECTED_TARGET_ROWS = 37
DEFAULT_LIMIT = 12
OUTPUT_NAME = "CROSS-SUBJECT-CURRENT-OFFICIAL-CANDIDATES-37.json"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode()


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_cross_subject_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_cross_subject_input_must_be_object")
    return value


def _verify_seal(value: Mapping[str, Any], field: str, code: str) -> str:
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


def _target_rows(remainder: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows = remainder.get("rows")
    if not isinstance(rows, list) or len(rows) != EXPECTED_REMAINDER_ROWS:
        raise ValueError("phase2a_cross_subject_remainder_rows_invalid")
    targets: list[dict[str, Any]] = []
    for raw in rows:
        if not isinstance(raw, dict):
            raise ValueError("phase2a_cross_subject_remainder_row_invalid")
        material = dict(raw)
        supplied = str(material.pop("row_packet_content_sha256", ""))
        if supplied != sealed_sha256(material):
            raise ValueError("phase2a_cross_subject_remainder_row_seal_invalid")
        candidates = raw.get("candidates")
        if not isinstance(candidates, list) or not candidates:
            raise ValueError("phase2a_cross_subject_remainder_candidates_invalid")
        has_current_noncase = any(
            isinstance(candidate, dict)
            and candidate.get("source_family") != "case"
            and candidate.get("identity_verified") is True
            and candidate.get("currentness_verified") is True
            and candidate.get("later_treatment_review_required") is not True
            for candidate in candidates
        )
        if not has_current_noncase:
            targets.append(raw)
    if len(targets) != EXPECTED_TARGET_ROWS:
        raise ValueError("phase2a_cross_subject_target_fingerprint_changed")
    return targets


def _rank_rows(
    *,
    rows: Sequence[Mapping[str, Any]],
    cases: Mapping[str, Mapping[str, Any]],
    spans: Sequence[ResearchSpan],
    candidate_authorities: frozenset[str],
    candidate_versions: frozenset[str],
    limit: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    eligible = tuple(
        span
        for span in spans
        if span.source.family != "case"
        and span.source.identity_verified
        and span.source.currentness_verified
    )
    if not eligible:
        raise ValueError("phase2a_cross_subject_current_noncase_spans_empty")
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
        for span in eligible
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
    packets: list[dict[str, Any]] = []
    all_scores: list[float] = []
    authorities: set[str] = set()
    for ordinal, row in enumerate(rows, start=1):
        case_id = str(row.get("case_id") or "")
        case = cases.get(case_id)
        if case is None:
            raise ValueError("phase2a_cross_subject_case_missing")
        issue_label = str(row.get("issue_label") or "")
        legal_domain = str(row.get("legal_domain") or "")
        query_text = " ".join(
            (
                issue_label,
                issue_label,
                issue_label,
                legal_domain,
                str(case.get("question") or ""),
            )
        )
        scores = np.asarray((matrix @ vectorizer.transform([query_text]).T).toarray()).reshape(-1)
        ordered = np.argsort(scores, kind="stable")[::-1]
        allowed = subject_routes(legal_domain)
        selected: list[dict[str, Any]] = []
        authority_counts: Counter[str] = Counter()
        for index in ordered:
            score = float(scores[int(index)])
            if score <= 0.0:
                break
            span = eligible[int(index)]
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
                "outside_original_subject_route": span.source.subject not in allowed,
                "version_sha256": span.source.version_sha256,
                "as_of_date": span.source.as_of_date,
                "currentness_status": span.source.currentness_status,
                "identity_verified": span.source.identity_verified,
                "currentness_verified": span.source.currentness_verified,
                "later_treatment_review_required": False,
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
            all_scores.append(score)
            authorities.add(authority_id)
            if len(selected) == limit:
                break
        row_material = {
            "schema": "legalbot.v111.phase2a.cross-subject-recovery-row.v1",
            "ordinal": ordinal,
            "source_ordinal": row.get("ordinal"),
            "row_id": row.get("row_id"),
            "case_id": case_id,
            "issue_id": row.get("issue_id"),
            "issue_label": issue_label,
            "issue_label_sha256": row.get("issue_label_sha256"),
            "legal_domain": legal_domain,
            "original_allowed_catalogue_subjects": sorted(allowed),
            "candidate_count": len(selected),
            "candidates": selected,
            "owner_or_qualified_reviewer_decision_required": True,
            "technical_qualification_assigned": False,
        }
        packets.append(
            {**row_material, "row_packet_content_sha256": sealed_sha256(row_material)}
        )
    metrics = {
        "eligible_current_noncase_span_count": len(eligible),
        "candidate_record_count": sum(len(packet["candidates"]) for packet in packets),
        "unique_candidate_authority_count": len(authorities),
        "rows_with_no_positive_lexical_candidate": sum(
            not packet["candidates"] for packet in packets
        ),
        "rows_with_at_least_one_outside_original_subject_candidate": sum(
            any(candidate["outside_original_subject_route"] for candidate in packet["candidates"])
            for packet in packets
        ),
        "rows_with_at_least_one_existing_candidate_source": sum(
            any(candidate["already_in_sealed_candidate"] for candidate in packet["candidates"])
            for packet in packets
        ),
        "minimum_candidate_score": round(min(all_scores), 8) if all_scores else None,
        "maximum_candidate_score": round(max(all_scores), 8) if all_scores else None,
    }
    return packets, metrics


def build_cross_subject_recovery(
    *,
    remainder_path: Path,
    cases_path: Path,
    candidate_manifest_path: Path,
    catalogue_path: Path,
    target_date: date,
    output_root: Path,
    candidate_limit: int = DEFAULT_LIMIT,
) -> dict[str, Any]:
    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_cross_subject_output_already_exists")
    if not 1 <= candidate_limit <= 20:
        raise ValueError("phase2a_cross_subject_candidate_limit_invalid")
    remainder = _load_object(remainder_path)
    remainder_digest = _verify_seal(
        remainder,
        "artifact_content_sha256",
        "phase2a_cross_subject_remainder_seal_invalid",
    )
    if remainder_digest != EXPECTED_REMAINDER_DIGEST:
        raise ValueError("phase2a_cross_subject_remainder_identity_invalid")
    if _sha256_file(cases_path) != EXPECTED_CASES_FILE_SHA256:
        raise ValueError("phase2a_cross_subject_cases_identity_invalid")
    if _sha256_file(catalogue_path) != EXPECTED_CATALOGUE_FILE_SHA256:
        raise ValueError("phase2a_cross_subject_catalogue_identity_invalid")
    rows = _target_rows(remainder)
    cases = _load_cases(cases_path)
    manifest_digest, candidate_authorities, candidate_versions = (
        _candidate_manifest_authorities(candidate_manifest_path)
    )
    if manifest_digest != EXPECTED_CANDIDATE_MANIFEST_DIGEST:
        raise ValueError("phase2a_cross_subject_candidate_manifest_identity_invalid")
    with _open_catalogue(catalogue_path) as connection:
        sources = _select_sources(connection, target_date)
        spans = _load_spans(connection, sources)
    packets, metrics = _rank_rows(
        rows=rows,
        cases=cases,
        spans=spans,
        candidate_authorities=candidate_authorities,
        candidate_versions=candidate_versions,
        limit=candidate_limit,
    )
    material = {
        "schema": "legalbot.v111.phase2a.cross-subject-recovery-37.v1",
        "status": "ADVISORY_CROSS_SUBJECT_RECOVERY_COMPLETE_OWNER_REVIEW_REQUIRED",
        "target_date": target_date.isoformat(),
        "row_count": len(packets),
        "candidate_limit_per_row": candidate_limit,
        "source_remainder_content_sha256": remainder_digest,
        "source_cases_file_sha256": EXPECTED_CASES_FILE_SHA256,
        "source_candidate_manifest_sha256": manifest_digest,
        "source_catalogue_file_sha256": EXPECTED_CATALOGUE_FILE_SHA256,
        "source_authority_count": len(sources),
        "source_span_group_count": len(spans),
        "catalogue_opened_immutable_read_only": True,
        "subject_filter_disabled_for_recovery": True,
        "only_identity_and_currentness_verified_noncase_sources_considered": True,
        "rank_metrics": metrics,
        "rows": packets,
        "embedding_model_invoked": False,
        "answer_model_invoked": False,
        "source_admission_authorized": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    artifact = {**material, "artifact_content_sha256": sealed_sha256(material)}
    raw = _pretty_json(artifact)
    progress_material = {
        "schema": "legalbot.v111.phase2a.cross-subject-recovery-progress.v1",
        "status": "PHASE2A_REMEDIATION_CONTINUES_OWNER_REVIEW_REQUIRED",
        "artifact_content_sha256": artifact["artifact_content_sha256"],
        "artifact_file_sha256": hashlib.sha256(raw).hexdigest(),
        "summary": metrics,
        "technical_qualification_assigned": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    progress = {
        **progress_material,
        "progress_content_sha256": sealed_sha256(progress_material),
    }
    progress_raw = _pretty_json(progress)
    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_cross_subject_output_mode_invalid")
    _write_exclusive(output_root / OUTPUT_NAME, raw)
    _write_exclusive(output_root / "PHASE2A-CROSS-SUBJECT-PROGRESS.json", progress_raw)
    _write_exclusive(
        output_root / "SHA256SUMS",
        (
            f"{hashlib.sha256(raw).hexdigest()}  {OUTPUT_NAME}\n"
            f"{hashlib.sha256(progress_raw).hexdigest()}  PHASE2A-CROSS-SUBJECT-PROGRESS.json\n"
        ).encode(),
    )
    return progress


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--remainder", type=Path, required=True)
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--candidate-manifest", type=Path, required=True)
    parser.add_argument("--catalogue", type=Path, required=True)
    parser.add_argument("--target-date", type=date.fromisoformat, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--candidate-limit", type=int, default=DEFAULT_LIMIT)
    args = parser.parse_args()
    progress = build_cross_subject_recovery(
        remainder_path=args.remainder.resolve(strict=True),
        cases_path=args.cases.resolve(strict=True),
        candidate_manifest_path=args.candidate_manifest.resolve(strict=True),
        catalogue_path=args.catalogue.resolve(strict=True),
        target_date=args.target_date,
        output_root=args.output_root.resolve(),
        candidate_limit=args.candidate_limit,
    )
    print(json.dumps(progress, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
