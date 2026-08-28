from __future__ import annotations

import json
from pathlib import Path

import pytest
from scripts import (
    finalize_v111_phase2a_post_r94_deterministic_held_gap as held_gap,
)


def test_exact_source_contract_is_fail_closed() -> None:
    r100, repair, diagnostic, r98d = held_gap._load_and_verify_sources(
        r100_root=held_gap.DEFAULT_R100_ROOT,
        r98d_root=held_gap.DEFAULT_R98D_ROOT,
    )
    assert r100["artifact_content_sha256"] == held_gap.EXPECTED_R100_CONTENT_SHA256
    assert repair["artifact_content_sha256"] == (held_gap.EXPECTED_R100_REPAIR_CONTENT_SHA256)
    assert diagnostic["diagnostic_content_sha256"] == (
        held_gap.EXPECTED_R100_DIAGNOSTIC_CONTENT_SHA256
    )
    assert r98d["artifact_content_sha256"] == held_gap.EXPECTED_R98D_CONTENT_SHA256


def test_deterministic_resolution_completes_361_without_authorizing_gate(
    tmp_path: Path,
) -> None:
    output = tmp_path / "r101"
    artifact = held_gap.build_resolution(output_root=output)
    assert artifact["row_count"] == 361
    assert artifact["remaining_held_row_count"] == 0
    assert artifact["assessment_counts"] == {
        "DIRECT_EXACT_SPAN_ADVISORY": 34,
        "MATERIAL_GAP_ADVISORY": 323,
        "PARTIAL_EXACT_SPAN_ADVISORY": 4,
    }
    disposition = artifact["deterministic_held_gap_disposition"]
    assert disposition["row_id"] == held_gap.HELD_ROW_ID
    assert disposition["assessment"] == "MATERIAL_GAP_ADVISORY"
    assert disposition["additional_model_invocations"] == 0
    assert disposition["owner_decision_required"] is True
    assert artifact["owner_decisions_applied"] is False
    assert artifact["source_admission_authorized"] is False
    assert artifact["automatic_indexing"] is False
    assert artifact["automatic_embedding"] is False
    assert artifact["candidate_mutated"] is False
    assert artifact["phase2b_authorized"] is False
    assert artifact["development30_authorized"] is False
    persisted = json.loads((output / "COMPLETE-EXACT-SPAN-ADVISORY-361.json").read_bytes())
    assert persisted == artifact
    assert (output / "SHA256SUMS.txt").is_file()


def test_resolution_is_create_only(tmp_path: Path) -> None:
    output = tmp_path / "r101"
    held_gap.build_resolution(output_root=output)
    with pytest.raises(ValueError, match="phase2a_r101_output_already_exists"):
        held_gap.build_resolution(output_root=output)
