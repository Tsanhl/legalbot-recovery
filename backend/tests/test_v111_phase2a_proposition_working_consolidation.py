from __future__ import annotations

from pathlib import Path

import pytest
from scripts import build_v111_phase2a_proposition_working_live30_q16_q20 as builder
from scripts import consolidate_v111_phase2a_proposition_working_drafts as consolidation


def test_partial_consolidation_reports_exact_missing_scope(tmp_path: Path) -> None:
    draft = tmp_path / "live30-q16-q20.json"
    builder.build(output_path=draft)

    result = consolidation.consolidate([draft])

    assert result["covered_row_count"] == 24
    assert result["missing_row_count"] == 337
    assert result["status"] == "PARTIAL_NON_AUTHORIZING_WORKING_LEDGER"
    assert result["owner_decisions_applied"] is False
    assert result["phase2b_authorized"] is False


def test_consolidation_rejects_duplicate_draft_rows(tmp_path: Path) -> None:
    draft = tmp_path / "live30-q16-q20.json"
    builder.build(output_path=draft)

    with pytest.raises(ValueError, match="duplicate row across"):
        consolidation.consolidate([draft, draft])


def test_complete_gate_rejects_partial_ledger(tmp_path: Path) -> None:
    draft = tmp_path / "live30-q16-q20.json"
    builder.build(output_path=draft)

    with pytest.raises(ValueError, match="reconciliation incomplete"):
        consolidation.consolidate([draft], require_complete=True)
