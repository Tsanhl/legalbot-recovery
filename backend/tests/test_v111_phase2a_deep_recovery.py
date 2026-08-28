from __future__ import annotations

import json
from pathlib import Path

import pytest
from scripts.build_v111_phase2a_deep_recovery import select_deep_recovery_rows

ROOT = Path(__file__).resolve().parents[2]
OWNER_REVIEW = ROOT / "data" / "evaluations" / "phase2a-owner-review"
REMAINDER = (
    OWNER_REVIEW / "LegalBot-Phase2AB-2026-08-24-r29" / "REMAINING-448-RESEARCH-PACKETS.json"
)
ADVISORY = (
    OWNER_REVIEW
    / "LegalBot-Phase2AB-2026-08-24-r36-independent-advisory"
    / "INDEPENDENT-RERANKER-ADVISORY-448.json"
)
BASELINE = OWNER_REVIEW / "LegalBot-Phase2AB-2026-08-24-r4" / "owner-reviewed-issues-585.json"


def _load(path: Path) -> dict:
    return json.loads(path.read_bytes())


def test_deep_recovery_selection_is_exact_and_diagnostic_only() -> None:
    selected = select_deep_recovery_rows(
        remainder=_load(REMAINDER),
        advisory=_load(ADVISORY),
        baseline=_load(BASELINE),
    )

    assert len(selected) == 176
    assert len({row["row_id"] for row in selected}) == 176
    assert "live30-q23:issue-03" in {row["row_id"] for row in selected}
    assert "live60-q41:issue-01" in {row["row_id"] for row in selected}


def test_deep_recovery_rejects_invalid_advisory_scores() -> None:
    advisory = _load(ADVISORY)
    advisory["rows"][0]["ranked_candidates"][0]["reranker_score"] = 2.0

    with pytest.raises(ValueError, match="advisory_score_invalid"):
        select_deep_recovery_rows(
            remainder=_load(REMAINDER),
            advisory=advisory,
            baseline=_load(BASELINE),
        )
