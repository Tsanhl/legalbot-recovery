from __future__ import annotations

from pathlib import Path

import pytest
from scripts import (
    build_v111_phase2a_additional_treatment_relationships_advisory as advisory,
)


def test_additional_relationships_bind_exact_context_without_authorizing(
    tmp_path: Path,
) -> None:
    result = advisory.build_additional_relationships(
        sequana_manifest_path=advisory.SEQUANA_MANIFEST,
        additional_manifest_path=advisory.ADDITIONAL_MANIFEST,
        original_manifest_path=advisory.ORIGINAL_MANIFEST,
        output_root=tmp_path / "packet",
    )

    assert result["record_count"] == 5
    assert result["classification_counts"] == {
        "AFFIRMED": 3,
        "DISTINGUISHED": 1,
        "LIMITED": 1,
    }
    assert {row["target_neutral_citation"] for row in result["records"]} == {
        "[2020] UKSC 31",
        "[2021] UKSC 20",
        "[2021] UKSC 29",
        "[2022] UKSC 25",
    }
    for row in result["records"]:
        combined = "\n".join(span["exact_text"] for span in row["exact_treatment_spans"])
        assert row["target_neutral_citation"] in combined
        assert all(phrase in combined for phrase in row["explicit_required_phrases"])
        assert row["owner_outcome"] is None
        assert row["proposition_level_materiality_approved"] is False
        assert row["source_admitted"] is False
        assert row["indexed"] is False
        assert row["embedded"] is False
        assert row["phase2b_authorized"] is False
        assert row["development30_authorized"] is False
    assert result["targeted_search_is_exhaustive"] is False
    assert result["source_admission_authorized"] is False
    assert result["candidate_mutated"] is False


def test_additional_relationship_packet_is_create_only(tmp_path: Path) -> None:
    output = tmp_path / "existing"
    output.mkdir()

    with pytest.raises(ValueError, match="output_already_exists"):
        advisory.build_additional_relationships(
            sequana_manifest_path=advisory.SEQUANA_MANIFEST,
            additional_manifest_path=advisory.ADDITIONAL_MANIFEST,
            original_manifest_path=advisory.ORIGINAL_MANIFEST,
            output_root=output,
        )
