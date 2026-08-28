from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from scripts import apply_v111_phase2a_post_r110_owner_approval as approval


def _load(path: Path) -> dict[str, object]:
    value = json.loads(path.read_bytes())
    assert isinstance(value, dict)
    return value


def test_exact_r111_approval_records_scope_and_keeps_later_gates_closed(
    tmp_path: Path,
) -> None:
    source_batch = (
        approval.DEFAULT_SOURCE_ROOT
        / "OWNER-SOURCE-CURRENTNESS-DECISION-BATCH.json"
    )
    remaining_source = (
        approval.DEFAULT_PREDECESSOR_ROOT / "REMAINING-MATERIAL-GAPS-364.json"
    )
    source_before = approval._sha256_file(source_batch)
    remaining_before = remaining_source.read_bytes()
    output = tmp_path / "approved"

    result = approval.apply_approval(
        source_root=approval.DEFAULT_SOURCE_ROOT,
        review_root=approval.DEFAULT_REVIEW_ROOT,
        predecessor_root=approval.DEFAULT_PREDECESSOR_ROOT,
        output_root=output,
        owner_reply=approval.OWNER_REPLY,
        owner_decision_date="2026-08-26",
        recorded_at=datetime(2026, 8, 26, 12, 0, tzinfo=UTC),
    )

    assert result["source_r111_batch_content_sha256"] == (
        approval.EXPECTED_BATCH_DIGEST
    )
    assert result["approved_mapping_disposition_count"] == 26
    assert result["approved_affected_row_count"] == 22
    assert result["approved_new_source_admission_count"] == 5
    assert result["cumulative_approved_source_admission_count"] == 25
    assert result["remaining_material_gap_count"] == 364
    assert result["phase2b_advance_intent_recorded"] is True
    assert result["automatic_indexing"] is False
    assert result["automatic_embedding"] is False
    assert result["candidate_build_authorized"] is False
    assert result["phase2b_authorized"] is False
    assert result["development30_authorized"] is False
    assert approval._sha256_file(source_batch) == source_before
    assert remaining_source.read_bytes() == remaining_before
    assert (output / "REMAINING-MATERIAL-GAPS-364.json").read_bytes() == (
        remaining_before
    )

    sources = _load(output / "APPROVED-SOURCE-ADMISSIONS-5.json")
    assert sources["record_count"] == 5
    records = sources["records"]
    assert isinstance(records, list)
    assert len({record["source_key"] for record in records}) == 5
    assert all(record["source_admission_authorized"] is True for record in records)
    assert all(record["automatic_indexing"] is False for record in records)
    assert all(record["automatic_embedding"] is False for record in records)
    assert all(record["candidate_build_authorized"] is False for record in records)

    cumulative = _load(output / "CUMULATIVE-APPROVED-SOURCE-ADMISSIONS-25.json")
    assert cumulative["record_count"] == 25
    cumulative_records = cumulative["records"]
    assert isinstance(cumulative_records, list)
    assert len({record["source_key"] for record in cumulative_records}) == 25

    inventory = _load(output / "POST-R111-PHASE2A-INVENTORY.json")
    assert inventory["recorded_issue_count"] == 221
    assert inventory["pending_issue_count"] == 364
    assert inventory["source_scope_finalized"] is False
    assert inventory["successor_candidate_built"] is False
    assert inventory["phase2b_authorized"] is False

    intent = _load(output / "PHASE2B-ADVANCE-INTENT.json")
    assert intent["status"] == (
        "ADVANCE_CONDITIONAL_INTENT_RECORDED_NOT_GATE_ACTIVATION"
    )
    assert intent["final_phase2a_digest_exists"] is False
    assert intent["final_phase2a_digest_owner_adopted"] is False
    assert intent["phase2b_authorized"] is False
    assert intent["development30_authorized"] is False


def test_approval_normalizes_only_trailing_whitespace(tmp_path: Path) -> None:
    reply = "\n".join(f"{line}  " for line in approval.OWNER_REPLY.splitlines())
    result = approval.apply_approval(
        source_root=approval.DEFAULT_SOURCE_ROOT,
        review_root=approval.DEFAULT_REVIEW_ROOT,
        predecessor_root=approval.DEFAULT_PREDECESSOR_ROOT,
        output_root=tmp_path / "approved",
        owner_reply=reply,
        owner_decision_date="2026-08-26",
        recorded_at=datetime(2026, 8, 26, tzinfo=UTC),
    )
    assert result["approved_new_source_admission_count"] == 5


def test_r111_approval_rejects_changed_reply(tmp_path: Path) -> None:
    output = tmp_path / "rejected"
    with pytest.raises(ValueError, match="owner_reply_not_exact"):
        approval.apply_approval(
            source_root=approval.DEFAULT_SOURCE_ROOT,
            review_root=approval.DEFAULT_REVIEW_ROOT,
            predecessor_root=approval.DEFAULT_PREDECESSOR_ROOT,
            output_root=output,
            owner_reply=approval.OWNER_REPLY.replace(
                "continued Phase 2A only.",
                "continued Phase 2B only.",
            ),
            owner_decision_date="2026-08-26",
            recorded_at=datetime(2026, 8, 26, tzinfo=UTC),
        )
    assert not output.exists()


def test_r111_approval_is_create_only(tmp_path: Path) -> None:
    output = tmp_path / "existing"
    output.mkdir()
    with pytest.raises(ValueError, match="output_already_exists"):
        approval.apply_approval(
            source_root=approval.DEFAULT_SOURCE_ROOT,
            review_root=approval.DEFAULT_REVIEW_ROOT,
            predecessor_root=approval.DEFAULT_PREDECESSOR_ROOT,
            output_root=output,
            owner_reply=approval.OWNER_REPLY,
            owner_decision_date="2026-08-26",
            recorded_at=datetime(2026, 8, 26, tzinfo=UTC),
        )
