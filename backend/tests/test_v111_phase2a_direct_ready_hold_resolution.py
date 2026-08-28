from __future__ import annotations

from pathlib import Path

from scripts import build_v111_phase2a_direct_ready_hold_resolution as resolution


def _build(tmp_path: Path) -> dict:
    return resolution.build_resolution(
        direct_path=resolution.DEFAULT_DIRECT,
        four_path=resolution.DEFAULT_FOUR,
        uber_unison_path=resolution.DEFAULT_UBER_UNISON,
        output_path=tmp_path / "resolution.json",
    )


def test_all_direct_ready_rows_have_exact_owner_advisory_basis(tmp_path: Path) -> None:
    result = _build(tmp_path)

    assert result["status"] == "ALL_45_EXACT_OWNER_DECISION_READY_NOT_ADOPTED"
    assert result["record_count"] == 45
    assert result["no_additional_hold_row_count"] == 34
    assert result["held_row_with_exact_advisory_count"] == 11
    assert result["held_row_missing_advisory_count"] == 0
    assert result["owner_decisions_applied"] is False
    assert result["holds_cleared"] is False
    assert result["automatic_embedding"] is False
    assert result["phase2b_authorized"] is False

    held = [
        row
        for row in result["records"]
        if row["original_currentness_hold_present"] or row["original_later_treatment_hold_present"]
    ]
    assert len(held) == 11
    assert all(row["supporting_advisory_dependencies"] for row in held)
    assert all(row["owner_outcome"] is None for row in result["records"])


def test_direct_ready_hold_resolution_is_create_only(tmp_path: Path) -> None:
    output = tmp_path / "resolution.json"
    output.write_text("occupied", encoding="utf-8")

    try:
        resolution.build_resolution(
            direct_path=resolution.DEFAULT_DIRECT,
            four_path=resolution.DEFAULT_FOUR,
            uber_unison_path=resolution.DEFAULT_UBER_UNISON,
            output_path=output,
        )
    except ValueError as exc:
        assert str(exc) == "phase2a_direct_resolution_output_already_exists"
    else:
        raise AssertionError("existing output was overwritten")
