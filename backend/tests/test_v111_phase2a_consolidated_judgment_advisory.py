from __future__ import annotations

from pathlib import Path

import pytest
from scripts import build_v111_phase2a_consolidated_judgment_advisory as advisory


def test_consolidates_all_20_and_exactly_nine_non_admitted_sources(
    tmp_path: Path,
) -> None:
    result = advisory.build_consolidated_judgment_advisory(
        base_path=advisory.BASE_REGISTER,
        no_reliance_path=advisory.NO_RELIANCE,
        original_relationships_path=advisory.ORIGINAL_RELATIONSHIPS,
        additional_relationships_path=advisory.ADDITIONAL_RELATIONSHIPS,
        bounded_search_log_path=advisory.BOUNDED_SEARCH_LOG,
        output_root=tmp_path / "packet",
    )

    assert result["record_count"] == 20
    assert result["category_counts"] == {
        "BOUNDED_OFFICIAL_SEARCH_NO_MATERIAL_LEAD_IDENTIFIED": 5,
        "EXACT_LATER_TREATMENT_RELATIONSHIP_IDENTIFIED": 9,
        "NO_585_PROPOSITION_RELIANCE": 6,
    }
    assert result["source_admission_proposal_count"] == 9
    assert (
        len(
            {
                proposal["source_lead_content_sha256"]
                for proposal in result["source_admission_proposals"]
            }
        )
        == 9
    )
    for row in result["records"]:
        assert row["owner_outcome"] is None
        assert row["owner_decision_required"] is True
        assert row["phase2b_authorized"] is False
        assert row["development30_authorized"] is False
    for proposal in result["source_admission_proposals"]:
        assert proposal["owner_source_admission_outcome"] is None
        assert proposal["source_admitted"] is False
        assert proposal["indexed"] is False
        assert proposal["embedded"] is False
        assert proposal["candidate_mutated"] is False
    assert result["owner_decisions_applied"] is False
    assert result["source_admission_authorized"] is False
    assert result["phase2b_authorized"] is False
    assert result["development30_authorized"] is False


def test_consolidated_judgment_output_is_create_only(tmp_path: Path) -> None:
    output = tmp_path / "existing"
    output.mkdir()

    with pytest.raises(ValueError, match="output_already_exists"):
        advisory.build_consolidated_judgment_advisory(
            base_path=advisory.BASE_REGISTER,
            no_reliance_path=advisory.NO_RELIANCE,
            original_relationships_path=advisory.ORIGINAL_RELATIONSHIPS,
            additional_relationships_path=advisory.ADDITIONAL_RELATIONSHIPS,
            bounded_search_log_path=advisory.BOUNDED_SEARCH_LOG,
            output_root=output,
        )
