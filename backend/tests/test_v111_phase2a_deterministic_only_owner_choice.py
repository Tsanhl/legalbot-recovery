from datetime import UTC, datetime
from pathlib import Path

import pytest
from scripts import apply_v111_phase2a_deterministic_only_owner_choice as choice
from scripts import plan_v111_phase2a_material_gap_research as planner


def test_complete_corrective_audit_is_exact() -> None:
    audit = choice._load_audit()

    assert audit["artifact_content_sha256"] == choice.EXPECTED_AUDIT_CONTENT_SHA256
    assert audit["over_cap_row_count"] == 38
    assert audit["over_cap_results_admissible_as_substantive_evidence"] is False
    assert audit["phase2b_authorized"] is False


def test_option_a_records_deterministic_only_scope(tmp_path: Path) -> None:
    output = tmp_path / "owner-choice"

    result = choice.apply_choice(
        output_root=output,
        recorded_at=datetime(2026, 8, 27, tzinfo=UTC),
    )

    planner._verify_seal(
        result,
        "receipt_content_sha256",
        "test_deterministic_owner_choice_receipt_invalid",
    )
    assert result["selected_methodology"] == "DETERMINISTIC_ONLY_PATH"
    assert result["further_planner_or_advisory_model_invocations_authorized"] is False
    assert result["deterministic_official_source_and_exact_span_work_authorized"] is True
    assert result["phase2a_continuation_authorized"] is True
    assert result["unseen_source_admissions_approved"] is False
    assert result["phase2b_authorized"] is False
    assert (output / "OWNER-REPLY-VERBATIM.txt").read_text() == "A\n"


def test_only_exact_option_a_is_accepted(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="phase2a_deterministic_owner_choice_reply_invalid"):
        choice.apply_choice(
            output_root=tmp_path / "invalid",
            recorded_at=datetime(2026, 8, 27, tzinfo=UTC),
            owner_reply="B",
        )
