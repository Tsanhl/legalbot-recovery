#!/usr/bin/env python3
"""Validate non-authorizing Phase-2A proposition-reconciliation drafts.

The validator binds draft rows to the final blocked all-585 partition and to
the sealed successor source manifest.  It intentionally does not assign legal
qualification, apply owner decisions, admit sources, mutate a candidate, or
authorize Phase 2B.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BLOCKED_MACHINE_ROOT = PROJECT_ROOT / (
    "data/evaluations/phase2a-owner-review/"
    "LegalBot-Phase2A-2026-08-27-final-owner-review-blocked/machine"
)
DEFAULT_QUALIFICATION = BLOCKED_MACHINE_ROOT / (
    "qualification/DETERMINISTIC-ALL585-QUALIFICATION.json"
)
DEFAULT_SOURCE_MANIFEST = BLOCKED_MACHINE_ROOT / ("candidate/approved-source-manifest.json")

EXPECTED_SCHEMA = "legalbot.v111.phase2a.proposition-reconciliation-working.v1"
PENDING_STATUSES = {"OWNER_DECISION_REQUIRED", "BLOCKED_MATERIAL_GAP"}
PROPOSITION_STATUSES = {
    "READY_FOR_EVIDENCE_REVIEW",
    "NEEDS_PROPOSITION_SPLIT",
    "NEEDS_LEGAL_RESEARCH",
}
EVIDENCE_FITS = {"FULL", "PARTIAL", "NONE", "UNASSESSED"}
FALSE_GATE_FIELDS = {
    "automatic_source_admission",
    "automatic_indexing",
    "automatic_embedding",
    "candidate_mutated",
    "owner_decisions_applied",
    "technical_qualification_assigned",
    "phase2b_authorized",
}


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _content_sha256(value: dict[str, Any], field: str) -> str:
    payload = dict(value)
    payload.pop(field, None)
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"required regular file unavailable: {path}")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(f"JSON object required: {path}")
    return value


def _require_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"non-empty text required: {label}")
    return value.strip()


def _qualification_rows(path: Path) -> dict[str, dict[str, Any]]:
    qualification = _load_object(path)
    rows = qualification.get("rows")
    if not isinstance(rows, list) or len(rows) != 585:
        raise ValueError("final all-585 qualification identity changed")
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("invalid qualification row")
        row_id = _require_text(row.get("row_id"), "qualification.row_id")
        if row_id in result:
            raise ValueError(f"duplicate qualification row: {row_id}")
        result[row_id] = row
    return result


def _candidate_sources(path: Path) -> dict[str, dict[str, Any]]:
    manifest = _load_object(path)
    sources = manifest.get("sources")
    if not isinstance(sources, list) or len(sources) != 251:
        raise ValueError("sealed successor source scope changed")
    result: dict[str, dict[str, Any]] = {}
    for source in sources:
        if not isinstance(source, dict):
            raise ValueError("invalid candidate source record")
        source_version_id = _require_text(
            source.get("source_version_id"), "candidate.source_version_id"
        )
        if source_version_id in result:
            raise ValueError(f"duplicate candidate source version: {source_version_id}")
        result[source_version_id] = source
    return result


def _validate_evidence(
    evidence: Any,
    *,
    row_id: str,
    candidate_sources: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    if not isinstance(evidence, list):
        raise ValueError(f"selected_local_evidence must be a list: {row_id}")
    validated: list[dict[str, Any]] = []
    for index, item in enumerate(evidence):
        if not isinstance(item, dict):
            raise ValueError(f"invalid local evidence item: {row_id}[{index}]")
        source_version_id = _require_text(
            item.get("source_version_id"),
            f"{row_id}.selected_local_evidence[{index}].source_version_id",
        )
        if source_version_id not in candidate_sources:
            raise ValueError(
                f"claimed local evidence is outside sealed candidate: {row_id} {source_version_id}"
            )
        authority_identity_id = _require_text(
            item.get("authority_identity_id"),
            f"{row_id}.selected_local_evidence[{index}].authority_identity_id",
        )
        expected_authority = str(
            candidate_sources[source_version_id].get("authority_identity_id") or ""
        )
        if authority_identity_id != expected_authority:
            raise ValueError(f"authority/source mismatch: {row_id} {source_version_id}")
        span_identity = item.get("span_id") or item.get("chunk_id")
        _require_text(span_identity, f"{row_id}.evidence span identity")
        digest = item.get("exact_text_sha256") or item.get("chunk_text_sha256")
        digest = _require_text(digest, f"{row_id}.evidence text digest")
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise ValueError(f"invalid evidence SHA-256: {row_id}")
        validated.append(item)
    return validated


def validate_draft(
    draft_path: Path,
    *,
    qualification_path: Path = DEFAULT_QUALIFICATION,
    source_manifest_path: Path = DEFAULT_SOURCE_MANIFEST,
) -> dict[str, Any]:
    draft = _load_object(draft_path)
    if draft.get("schema") != EXPECTED_SCHEMA:
        raise ValueError(f"unexpected draft schema: {draft_path}")
    for field in FALSE_GATE_FIELDS:
        if draft.get(field) is not False:
            raise ValueError(f"working draft must explicitly set {field}=false")

    scope_case_ids = draft.get("scope_case_ids")
    if not isinstance(scope_case_ids, list) or not scope_case_ids:
        raise ValueError("scope_case_ids must be a non-empty list")
    scope = {_require_text(case_id, "scope_case_id") for case_id in scope_case_ids}
    if len(scope) != len(scope_case_ids):
        raise ValueError("duplicate scope case identity")

    qualification_rows = _qualification_rows(qualification_path)
    candidate_sources = _candidate_sources(source_manifest_path)
    expected_ids = {
        row_id
        for row_id, row in qualification_rows.items()
        if row.get("case_id") in scope and row.get("qualification_status") in PENDING_STATUSES
    }

    records = draft.get("records")
    if not isinstance(records, list):
        raise ValueError("records must be a list")
    seen: set[str] = set()
    counts = {status: 0 for status in PROPOSITION_STATUSES}
    fit_counts = {fit: 0 for fit in EVIDENCE_FITS}
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("invalid proposition draft record")
        row_id = _require_text(record.get("row_id"), "record.row_id")
        if row_id in seen:
            raise ValueError(f"duplicate draft row: {row_id}")
        seen.add(row_id)
        if row_id not in expected_ids:
            raise ValueError(f"draft row outside pending frozen scope: {row_id}")
        frozen = qualification_rows[row_id]
        for field in ("case_id", "issue_id", "issue_label", "qualification_status"):
            if record.get(field) != frozen.get(field):
                raise ValueError(f"frozen row field mismatch: {row_id}.{field}")

        proposition_status = record.get("proposition_status")
        if proposition_status not in PROPOSITION_STATUSES:
            raise ValueError(f"invalid proposition status: {row_id}")
        counts[str(proposition_status)] += 1
        proposition = record.get("canonical_atomic_proposition")
        if proposition_status == "READY_FOR_EVIDENCE_REVIEW":
            _require_text(proposition, f"{row_id}.canonical_atomic_proposition")
        elif proposition is not None and not isinstance(proposition, str):
            raise ValueError(f"invalid proposition placeholder: {row_id}")

        fit = record.get("local_evidence_fit")
        if fit not in EVIDENCE_FITS:
            raise ValueError(f"invalid local evidence fit: {row_id}")
        fit_counts[str(fit)] += 1
        evidence = _validate_evidence(
            record.get("selected_local_evidence"),
            row_id=row_id,
            candidate_sources=candidate_sources,
        )
        if fit == "FULL" and not evidence:
            raise ValueError(f"FULL local evidence fit requires exact evidence: {row_id}")
        if fit in {"NONE", "UNASSESSED"} and evidence:
            raise ValueError(f"{fit} local evidence fit cannot select evidence: {row_id}")
        if record.get("owner_outcome") is not None:
            raise ValueError(f"working draft cannot apply owner outcome: {row_id}")
        record_digest = _require_text(
            record.get("record_content_sha256"), f"{row_id}.record_content_sha256"
        )
        if record_digest != _content_sha256(record, "record_content_sha256"):
            raise ValueError(f"record content digest mismatch: {row_id}")

    if seen != expected_ids:
        missing = sorted(expected_ids - seen)
        extra = sorted(seen - expected_ids)
        raise ValueError(f"draft scope is incomplete; missing={missing} extra={extra}")
    artifact_digest = draft.get("artifact_content_sha256")
    if artifact_digest is not None and artifact_digest != _content_sha256(
        draft, "artifact_content_sha256"
    ):
        raise ValueError("draft artifact content digest mismatch")

    return {
        "draft_path": str(draft_path),
        "case_count": len(scope),
        "record_count": len(records),
        "proposition_status_counts": counts,
        "local_evidence_fit_counts": fit_counts,
        "valid": True,
        "owner_decisions_applied": False,
        "technical_qualification_assigned": False,
        "phase2b_authorized": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("drafts", nargs="+", type=Path)
    args = parser.parse_args()
    results = [validate_draft(path) for path in args.drafts]
    print(json.dumps(results, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
