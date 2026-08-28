from __future__ import annotations

from pathlib import Path

from scripts import build_v111_phase2a_targeted_treatment_relationships_advisory as advisory


def test_targeted_relationships_bind_exact_context_without_authorizing(
    tmp_path: Path,
) -> None:
    result = advisory.build_treatment_relationships(
        leads_path=advisory.DEFAULT_LEADS,
        no_reliance_path=advisory.DEFAULT_NO_RELIANCE,
        output_root=tmp_path / "packet",
    )

    assert result["record_count"] == 5
    assert result["classification_counts"] == {"AFFIRMED": 4, "LIMITED": 1}
    assert {row["lead_id"] for row in result["records"]} == set(
        advisory.EXPECTED_RELATIONSHIPS
    )
    for row in result["records"]:
        context = row["exact_treatment_context"]
        assert row["target_neutral_citation"] in context["exact_text"]
        assert all(phrase in context["exact_text"] for phrase in row["explicit_required_phrases"])
        assert row["owner_outcome"] is None
        assert row["proposition_level_materiality_approved"] is False
        assert row["source_admitted"] is False
        assert row["phase2b_authorized"] is False
        assert row["development30_authorized"] is False
    assert result["targeted_search_is_exhaustive"] is False
    assert result["source_admission_authorized"] is False
    assert result["candidate_mutated"] is False


def test_targeted_relationship_packet_is_create_only(tmp_path: Path) -> None:
    output = tmp_path / "existing"
    output.mkdir()
    try:
        advisory.build_treatment_relationships(
            leads_path=advisory.DEFAULT_LEADS,
            no_reliance_path=advisory.DEFAULT_NO_RELIANCE,
            output_root=output,
        )
    except ValueError as exc:
        assert str(exc) == "phase2a_treatment_output_already_exists"
    else:
        raise AssertionError("existing output was overwritten")
