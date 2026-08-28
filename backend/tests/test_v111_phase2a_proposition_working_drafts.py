from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from scripts import validate_v111_phase2a_proposition_working_drafts as validator


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _sealed_record(record: dict[str, object]) -> dict[str, object]:
    result = dict(record)
    result["record_content_sha256"] = hashlib.sha256(
        _canonical_json(result)
    ).hexdigest()
    return result


def _draft_for_live30_q01() -> dict[str, object]:
    qualification = json.loads(validator.DEFAULT_QUALIFICATION.read_text())
    frozen_rows = [
        row
        for row in qualification["rows"]
        if row["case_id"] == "live30-q01"
        and row["qualification_status"] in validator.PENDING_STATUSES
    ]
    records = [
        _sealed_record(
            {
                "row_id": frozen["row_id"],
                "case_id": frozen["case_id"],
                "issue_id": frozen["issue_id"],
                "issue_label": frozen["issue_label"],
                "qualification_status": frozen["qualification_status"],
                "canonical_atomic_proposition": None,
                "proposition_status": "NEEDS_LEGAL_RESEARCH",
                "local_evidence_fit": "NONE",
                "selected_local_evidence": [],
                "rejected_candidate_reasons": [],
                "required_research": [
                    "Identify the controlling rule and exact authority."
                ],
                "proposition_version_conflicts": [],
                "owner_outcome": None,
            }
        )
        for frozen in frozen_rows
    ]
    return {
        "schema": validator.EXPECTED_SCHEMA,
        "scope_case_ids": ["live30-q01"],
        "input_file_sha256s": {},
        "records": records,
        "automatic_source_admission": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "owner_decisions_applied": False,
        "technical_qualification_assigned": False,
        "phase2b_authorized": False,
    }


def test_accepts_complete_non_authorizing_draft(tmp_path: Path) -> None:
    draft = _draft_for_live30_q01()
    path = tmp_path / "draft.json"
    path.write_bytes(_canonical_json(draft))

    result = validator.validate_draft(path)

    assert result["valid"] is True
    assert result["record_count"] == len(draft["records"])
    assert result["phase2b_authorized"] is False


def test_rejects_owner_outcome_in_working_draft(tmp_path: Path) -> None:
    draft = _draft_for_live30_q01()
    record = dict(draft["records"][0])
    record["owner_outcome"] = "APPROVE"
    draft["records"] = [_sealed_record(record), *draft["records"][1:]]
    path = tmp_path / "draft.json"
    path.write_bytes(_canonical_json(draft))

    with pytest.raises(ValueError, match="cannot apply owner outcome"):
        validator.validate_draft(path)


def test_rejects_incomplete_case_scope(tmp_path: Path) -> None:
    draft = _draft_for_live30_q01()
    draft["records"] = draft["records"][:-1]
    path = tmp_path / "draft.json"
    path.write_bytes(_canonical_json(draft))

    with pytest.raises(ValueError, match="draft scope is incomplete"):
        validator.validate_draft(path)
