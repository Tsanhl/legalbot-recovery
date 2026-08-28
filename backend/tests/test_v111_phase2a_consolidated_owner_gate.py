from __future__ import annotations

import json
from pathlib import Path

from scripts import build_v111_phase2a_consolidated_owner_gate as gate


def _build(tmp_path: Path) -> tuple[dict[str, object], Path]:
    output = tmp_path / "owner-gate"
    result = gate.build_consolidated_owner_gate(
        remediation_root=gate.DEFAULT_REMEDIATION_ROOT,
        effects_path=gate.DEFAULT_EFFECTS_PATH,
        approval_48_path=gate.DEFAULT_APPROVAL_48_PATH,
        approval_35_path=gate.DEFAULT_APPROVAL_35_PATH,
        approval_54_path=gate.DEFAULT_APPROVAL_54_PATH,
        remainder_path=gate.DEFAULT_REMAINDER_PATH,
        source_custody_path=gate.DEFAULT_SOURCE_CUSTODY_PATH,
        reranker_intent_path=gate.DEFAULT_RERANKER_INTENT_PATH,
        reranker_path=gate.DEFAULT_RERANKER_PATH,
        deep_comparison_path=gate.DEFAULT_DEEP_COMPARISON_PATH,
        effect_recovery_path=gate.DEFAULT_EFFECT_RECOVERY_PATH,
        judgment_path=gate.DEFAULT_JUDGMENT_PATH,
        targeted_leads_path=gate.DEFAULT_TARGETED_LEADS_PATH,
        byte_mismatch_path=gate.DEFAULT_BYTE_MISMATCH_PATH,
        fresh_quarantine_manifest_path=gate.DEFAULT_FRESH_QUARANTINE_MANIFEST_PATH,
        output_root=output,
    )
    return result, output


def test_consolidated_gate_accounts_for_every_required_record(tmp_path: Path) -> None:
    result, output = _build(tmp_path)
    overview = json.loads(
        (output / "PHASE2A-CONSOLIDATED-OWNER-GATE.json").read_bytes()
    )
    decisions = json.loads((output / "OWNER-DECISION-BATCH-1058.json").read_bytes())

    assert result["issue_counts"] == {"total": 585, "recorded": 137, "pending": 448}
    assert result["legislative_effect_counts"] == {
        "total": 1896,
        "recorded": 1380,
        "pending": 516,
    }
    assert result["judgment_counts"] == {"total": 20, "pending": 20, "targeted_leads": 9}
    assert result["byte_mismatch_counts"] == {
        "total": 65,
        "semantic_text_identical": 64,
        "changed_text": 1,
    }
    assert decisions["item_count"] == 1058
    assert decisions["category_counts"] == {
        "issue": 448,
        "legislative_effect": 516,
        "judgment": 20,
        "legislation_byte_mismatch": 65,
        "source_admission": 9,
    }
    assert decisions["immediately_approvable_deterministic_recommendation_count"] == 580
    assert overview["unavailable_official_record_count"] == 3


def test_consolidated_gate_remains_fail_closed(tmp_path: Path) -> None:
    result, output = _build(tmp_path)
    overview = json.loads(
        (output / "PHASE2A-CONSOLIDATED-OWNER-GATE.json").read_bytes()
    )
    source_register = json.loads(
        (output / "SOURCE-CUSTODY-AND-ADMISSION-REGISTER.json").read_bytes()
    )
    matrix = json.loads((output / "COMPLETE-REMEDIATION-MATRIX-585.json").read_bytes())

    assert result["phase2b_authorized"] is False
    assert result["development30_authorized"] is False
    assert overview["successor_candidate_built"] is False
    assert overview["common_cutoff_supportable"] is False
    assert source_register["automatic_source_admission"] is False
    assert source_register["automatic_indexing"] is False
    assert source_register["automatic_embedding"] is False
    assert source_register["candidate_mutated"] is False
    assert matrix["technical_qualification_rerun_complete"] is False
    assert all(row["owner_adopted_qualified"] is False for row in matrix["rows"])


def test_consolidated_gate_machine_index_and_checksums_verify(tmp_path: Path) -> None:
    result, output = _build(tmp_path)
    index = json.loads((output / "MACHINE-PACKAGE-INDEX.json").read_bytes())
    material = dict(index)
    supplied = material.pop("machine_package_content_sha256")

    assert supplied == result["machine_package_content_sha256"]
    assert supplied == gate._sealed(material)
    for name, expected in index["files"].items():
        path = output / name
        assert path.is_file()
        assert gate._sha256_file(path) == expected["sha256"]
        assert path.stat().st_size == expected["bytes"]
    for line in (output / "SHA256SUMS.txt").read_text().splitlines():
        digest, name = line.split("  ", 1)
        assert gate._sha256_file(output / name) == digest


def test_consolidated_gate_is_create_only(tmp_path: Path) -> None:
    _result, output = _build(tmp_path)
    try:
        gate.build_consolidated_owner_gate(
            remediation_root=gate.DEFAULT_REMEDIATION_ROOT,
            effects_path=gate.DEFAULT_EFFECTS_PATH,
            approval_48_path=gate.DEFAULT_APPROVAL_48_PATH,
            approval_35_path=gate.DEFAULT_APPROVAL_35_PATH,
            approval_54_path=gate.DEFAULT_APPROVAL_54_PATH,
            remainder_path=gate.DEFAULT_REMAINDER_PATH,
            source_custody_path=gate.DEFAULT_SOURCE_CUSTODY_PATH,
            reranker_intent_path=gate.DEFAULT_RERANKER_INTENT_PATH,
            reranker_path=gate.DEFAULT_RERANKER_PATH,
            deep_comparison_path=gate.DEFAULT_DEEP_COMPARISON_PATH,
            effect_recovery_path=gate.DEFAULT_EFFECT_RECOVERY_PATH,
            judgment_path=gate.DEFAULT_JUDGMENT_PATH,
            targeted_leads_path=gate.DEFAULT_TARGETED_LEADS_PATH,
            byte_mismatch_path=gate.DEFAULT_BYTE_MISMATCH_PATH,
            fresh_quarantine_manifest_path=gate.DEFAULT_FRESH_QUARANTINE_MANIFEST_PATH,
            output_root=output,
        )
    except ValueError as exc:
        assert str(exc) == "phase2a_consolidated_output_already_exists"
    else:
        raise AssertionError("create-only gate accepted an existing output root")
