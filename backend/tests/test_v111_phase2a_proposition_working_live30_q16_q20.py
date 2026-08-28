from __future__ import annotations

from pathlib import Path

from scripts import build_v111_phase2a_proposition_working_live30_q16_q20 as builder
from scripts import validate_v111_phase2a_proposition_working_drafts as validator


def test_builds_complete_non_authorizing_q16_q20_draft(tmp_path: Path) -> None:
    output = tmp_path / "live30-q16-q20.json"
    result = builder.build(output_path=output)

    assert len(result["records"]) == 24
    assert result["owner_decisions_applied"] is False
    assert result["candidate_mutated"] is False
    assert result["phase2b_authorized"] is False
    assert validator.validate_draft(output)["record_count"] == 24


def test_q16_q20_builder_refuses_overwrite(tmp_path: Path) -> None:
    output = tmp_path / "live30-q16-q20.json"
    builder.build(output_path=output)

    try:
        builder.build(output_path=output)
    except FileExistsError:
        pass
    else:
        raise AssertionError("working draft must not overwrite existing evidence")
