from __future__ import annotations

from pathlib import Path

import pytest
from scripts import build_v111_phase2a_consolidated_substantive_owner_batch as batch


def test_consolidated_batch_is_exact_and_non_authorizing(tmp_path: Path) -> None:
    result = batch.build(output_root=tmp_path / "owner-batch")

    summary = result["decision_summary"]
    assert summary["candidate_exact_binding_decision_count"] == 84
    assert summary["judgment_later_treatment_decision_count"] == 20
    assert summary["total_unique_source_admission_count"] == 20
    assert summary["unresolved_material_gap_row_count"] == 364
    assert result["owner_approved"] is False
    assert result["phase2b_authorized"] is False

    owner_batch = batch._load(tmp_path / "owner-batch/OWNER-SUBSTANTIVE-DECISION-BATCH.json")
    assert (
        batch._verify_artifact(
            "test",
            owner_batch,
            result["owner_batch_content_sha256"],
        )
        == result["owner_batch_content_sha256"]
    )
    assert len(owner_batch["candidate_exact_binding_decisions"]) == 84
    assert len(owner_batch["unresolved_material_gap_rows"]) == 364
    assert owner_batch["source_admission_authorized"] is False
    assert owner_batch["candidate_mutated"] is False
    assert owner_batch["development30_authorized"] is False


def test_owner_prompt_binds_exact_digest(tmp_path: Path) -> None:
    result = batch.build(output_root=tmp_path / "owner-batch")
    prompt = (tmp_path / "owner-batch/OWNER-APPROVAL-PROMPT.txt").read_text(encoding="utf-8")

    assert result["owner_batch_content_sha256"] in prompt
    assert "364 unresolved material-gap rows" in prompt
    assert "Phase 2B" in prompt
    assert "I APPROVE THIS EXACT DIGEST-BOUND PHASE-2A BATCH" in prompt


def test_consolidated_batch_refuses_existing_output() -> None:
    with pytest.raises(ValueError, match="phase2a_consolidated_batch_output_exists"):
        batch.build(output_root=batch.PROJECT_ROOT)
