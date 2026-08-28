from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from scripts import apply_v111_phase2a_consolidated_substantive_owner_approval as approval


def _load(path: Path) -> dict[str, object]:
    value = json.loads(path.read_bytes())
    assert isinstance(value, dict)
    return value


def _expected_reply() -> str:
    return (
        approval.DEFAULT_SOURCE_ROOT / "OWNER-APPROVAL-PROMPT.txt"
    ).read_text(encoding="utf-8").strip()


def test_exact_r94_approval_records_scope_and_keeps_later_gates_closed(
    tmp_path: Path,
) -> None:
    source_batch = (
        approval.DEFAULT_SOURCE_ROOT / "OWNER-SUBSTANTIVE-DECISION-BATCH.json"
    )
    source_before = approval._sha256_file(source_batch)
    output = tmp_path / "approved"

    result = approval.apply_approval(
        source_root=approval.DEFAULT_SOURCE_ROOT,
        predecessor_root=approval.DEFAULT_PREDECESSOR_ROOT,
        output_root=output,
        owner_reply=_expected_reply(),
        owner_decision_date="2026-08-25",
        recorded_at=datetime(2026, 8, 25, 16, 0, tzinfo=UTC),
    )

    assert result["source_r94_batch_content_sha256"] == approval.EXPECTED_BATCH_DIGEST
    assert result["approved_candidate_binding_count"] == 84
    assert result["approved_judgment_disposition_count"] == 20
    assert result["approved_source_admission_count"] == 20
    assert result["remaining_material_gap_count"] == 364
    assert result["phase2b_authorized"] is False
    assert result["development30_authorized"] is False
    assert approval._sha256_file(source_batch) == source_before

    source_scope = _load(output / "APPROVED-SOURCE-ADMISSIONS-20.json")
    assert source_scope["record_count"] == 20
    assert source_scope["automatic_indexing"] is False
    assert source_scope["automatic_embedding"] is False
    assert source_scope["candidate_build_authorized"] is False
    records = source_scope["records"]
    assert isinstance(records, list)
    assert len({record["source_key"] for record in records}) == 20
    assert all(record["source_admission_authorized"] is True for record in records)
    assert all(record["automatic_indexing"] is False for record in records)

    remaining = _load(output / "REMAINING-MATERIAL-GAPS-364.json")
    inventory = _load(output / "POST-R94-PHASE2A-INVENTORY.json")
    assert remaining["record_count"] == 364
    assert remaining["owner_approved"] is False
    assert inventory["recorded_issue_count"] == 221
    assert inventory["pending_issue_count"] == 364
    assert inventory["patents_final_decision_pending"] is True
    assert inventory["successor_candidate_built"] is False
    assert inventory["phase2b_authorized"] is False

    for path in output.glob("*.json"):
        value = _load(path)
        field = (
            "package_content_sha256"
            if path.name == "PACKAGE-INDEX.json"
            else "artifact_content_sha256"
        )
        assert approval._verify_seal(value, field, "invalid")


def test_r94_approval_rejects_nonexact_owner_reply(tmp_path: Path) -> None:
    output = tmp_path / "rejected"
    with pytest.raises(ValueError, match="owner_reply_not_exact"):
        approval.apply_approval(
            source_root=approval.DEFAULT_SOURCE_ROOT,
            predecessor_root=approval.DEFAULT_PREDECESSOR_ROOT,
            output_root=output,
            owner_reply="OK",
            owner_decision_date="2026-08-25",
            recorded_at=datetime(2026, 8, 25, tzinfo=UTC),
        )
    assert not output.exists()


def test_r94_approval_is_create_only(tmp_path: Path) -> None:
    output = tmp_path / "existing"
    output.mkdir()
    with pytest.raises(ValueError, match="output_already_exists"):
        approval.apply_approval(
            source_root=approval.DEFAULT_SOURCE_ROOT,
            predecessor_root=approval.DEFAULT_PREDECESSOR_ROOT,
            output_root=output,
            owner_reply=_expected_reply(),
            owner_decision_date="2026-08-25",
            recorded_at=datetime(2026, 8, 25, tzinfo=UTC),
        )
