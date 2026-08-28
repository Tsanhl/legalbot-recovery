from __future__ import annotations

from pathlib import Path

from scripts import build_v111_phase2a_no_reliance_judgment_advisory as advisory


def test_no_reliance_packet_is_exact_and_non_authorizing(tmp_path: Path) -> None:
    result = advisory.build_no_reliance_advisory(
        judgments_path=advisory.DEFAULT_JUDGMENTS,
        sources_path=advisory.DEFAULT_SOURCES,
        output_root=tmp_path / "packet",
    )

    assert result["judgment_recommendation_count"] == 6
    assert {row["source_version_id"] for row in result["judgment_recommendations"]} == (
        advisory.EXPECTED_NO_RELIANCE_SOURCE_VERSION_IDS
    )
    assert result["dependent_quarantine_lead_recommendation_count"] == 4
    assert {
        row["lead_id"] for row in result["dependent_quarantine_lead_recommendations"]
    } == advisory.EXPECTED_QUARANTINE_LEAD_IDS
    assert result["remaining_conditional_later_treatment_lead_count"] == 5
    assert result["absence_of_reliance_proves_no_later_treatment"] is False
    assert all(row["owner_outcome"] is None for row in result["judgment_recommendations"])
    assert result["source_admission_authorized"] is False
    assert result["candidate_mutated"] is False
    assert result["phase2b_authorized"] is False
    assert result["development30_authorized"] is False


def test_no_reliance_packet_is_create_only(tmp_path: Path) -> None:
    output = tmp_path / "existing"
    output.mkdir()
    try:
        advisory.build_no_reliance_advisory(
            judgments_path=advisory.DEFAULT_JUDGMENTS,
            sources_path=advisory.DEFAULT_SOURCES,
            output_root=output,
        )
    except ValueError as exc:
        assert str(exc) == "phase2a_no_reliance_output_already_exists"
    else:
        raise AssertionError("existing output was overwritten")
