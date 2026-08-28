from __future__ import annotations

import json
from pathlib import Path

import pytest
from scripts.build_v111_phase2a_effect_relevance_packets import (
    EXPECTED_EFFECTS_DIGEST,
    OUTPUT_NAME,
    _most_specific_provision_facts,
    _pretty_json,
    _sealed,
    build_effect_relevance_packets,
)

ROOT = Path(__file__).resolve().parents[2]
OWNER_REVIEW = ROOT / "data" / "evaluations" / "phase2a-owner-review"
EFFECTS = (
    OWNER_REVIEW
    / "LegalBot-Phase2AB-2026-08-24-r4"
    / "owner-reviewed-legislative-effects-1896.json"
)
RESEARCH = (
    OWNER_REVIEW
    / "LegalBot-Phase2AB-2026-08-24-r17"
    / "UNRESOLVED-502-LEXICAL-RESEARCH-PACKETS.json"
)


def _build(tmp_path: Path) -> dict[str, object]:
    return build_effect_relevance_packets(
        effects_path=EFFECTS,
        research_packets_path=RESEARCH,
        output_root=tmp_path / "output",
    )


def test_builds_all_516_owner_review_packets_without_changing_a_gate(
    tmp_path: Path,
) -> None:
    progress = _build(tmp_path)
    artifact = json.loads((tmp_path / "output" / OUTPUT_NAME).read_bytes())

    assert progress["effect_count"] == 516
    assert artifact["summary"] == {
        "exact_provision_intersection": 0,
        "no_same_authority_candidate": 7,
        "owner_decision_recorded": 0,
        "owner_decision_required": 516,
        "same_authority_without_exact_provision_intersection": 509,
    }
    assert len(artifact["effects"]) == 516
    assert len({item["effect_record_key"] for item in artifact["effects"]}) == 516
    assert artifact["automatic_materiality_decision"] is False
    assert artifact["automatic_source_admission"] is False
    assert artifact["automatic_indexing"] is False
    assert artifact["automatic_embedding"] is False
    assert artifact["candidate_mutated"] is False
    assert artifact["phase2b_authorized"] is False
    assert artifact["development30_authorized"] is False
    assert all(item["owner_decision_required"] is True for item in artifact["effects"])
    assert all(item["indexed"] is False for item in artifact["effects"])
    assert all(item["embedded"] is False for item in artifact["effects"])


def test_most_specific_comparison_does_not_allow_schedule_laundering() -> None:
    affected = _most_specific_provision_facts("s. 66(1) Sch. 8")
    unrelated = _most_specific_provision_facts("schedule 8")

    assert [fact.normalized_value for fact in affected] == ["section:66(1)"]
    assert [fact.normalized_value for fact in unrelated] == ["schedule:8"]
    assert {fact.identity for fact in affected}.isdisjoint(
        fact.identity for fact in unrelated
    )


def test_rejects_resealed_input_that_changes_the_exact_approved_baseline(
    tmp_path: Path,
) -> None:
    effects = json.loads(EFFECTS.read_bytes())
    assert effects.pop("artifact_content_sha256") == EXPECTED_EFFECTS_DIGEST
    effects["automatic_source_admission"] = True
    effects["artifact_content_sha256"] = _sealed(effects)
    tampered = tmp_path / "tampered-effects.json"
    tampered.write_bytes(_pretty_json(effects))

    with pytest.raises(
        ValueError,
        match="phase2a_effect_relevance_effects_boundary_invalid",
    ):
        build_effect_relevance_packets(
            effects_path=tampered,
            research_packets_path=RESEARCH,
            output_root=tmp_path / "output",
        )


def test_create_only_output_refuses_an_existing_directory(tmp_path: Path) -> None:
    output = tmp_path / "output"
    output.mkdir()
    with pytest.raises(ValueError, match="phase2a_effect_relevance_output_already_exists"):
        build_effect_relevance_packets(
            effects_path=EFFECTS,
            research_packets_path=RESEARCH,
            output_root=output,
        )
