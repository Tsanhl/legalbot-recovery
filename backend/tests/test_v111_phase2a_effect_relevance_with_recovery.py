from __future__ import annotations

import json
from pathlib import Path

import pytest
from scripts.build_v111_phase2a_effect_relevance_with_recovery import (
    OUTPUT_NAME,
    build_effect_relevance_with_recovery,
)

ROOT = Path(__file__).resolve().parents[2]
OWNER_REVIEW = ROOT / "data" / "evaluations" / "phase2a-owner-review"
EFFECTS = (
    OWNER_REVIEW
    / "LegalBot-Phase2AB-2026-08-24-r4"
    / "owner-reviewed-legislative-effects-1896.json"
)
BASELINE = (
    OWNER_REVIEW
    / "LegalBot-Phase2AB-2026-08-24-r17"
    / "UNRESOLVED-502-LEXICAL-RESEARCH-PACKETS.json"
)
RECOVERY = (
    OWNER_REVIEW
    / "LegalBot-Phase2AB-2026-08-24-r37-cross-subject"
    / "CROSS-SUBJECT-CURRENT-OFFICIAL-CANDIDATES-37.json"
)


def test_builds_all_516_without_making_effect_decisions(tmp_path: Path) -> None:
    progress = build_effect_relevance_with_recovery(
        effects_path=EFFECTS,
        baseline_research_path=BASELINE,
        recovery_path=RECOVERY,
        output_root=tmp_path / "output",
    )
    artifact = json.loads((tmp_path / "output" / OUTPUT_NAME).read_bytes())
    summary = progress["summary"]
    assert artifact["effect_count"] == 516
    assert (
        summary["no_same_authority_candidate"]
        + summary["same_authority_without_exact_provision_intersection"]
        + summary["exact_provision_intersection"]
        == 516
    )
    assert summary["owner_decision_required"] == 516
    assert summary["owner_decision_recorded"] == 0
    assert artifact["automatic_materiality_decision"] is False
    assert artifact["automatic_source_admission"] is False
    assert artifact["candidate_mutated"] is False
    assert artifact["phase2b_authorized"] is False
    assert all(effect["owner_decision_required"] is True for effect in artifact["effects"])


def test_create_only_refuses_existing_output(tmp_path: Path) -> None:
    output = tmp_path / "output"
    output.mkdir()
    with pytest.raises(ValueError, match="phase2a_effect_recovery_output_already_exists"):
        build_effect_relevance_with_recovery(
            effects_path=EFFECTS,
            baseline_research_path=BASELINE,
            recovery_path=RECOVERY,
            output_root=output,
        )
