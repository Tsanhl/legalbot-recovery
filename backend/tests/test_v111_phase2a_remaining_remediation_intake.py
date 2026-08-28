from __future__ import annotations

import hashlib
import json
from pathlib import Path

from scripts import build_v111_phase2a_remaining_remediation_intake as builder


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def test_builds_exact_non_authorizing_remaining_intake(tmp_path: Path) -> None:
    output = tmp_path / "intake"
    result = builder.build_intake(output_root=output)

    assert result["blocked_delivery_content_sha256"] == (
        "b72f7c14740ad1624cb0a86cf0da070a3349203369001a92d6f2c6f467d6d1d2"
    )
    assert result["issue_scope"]["preserved_evidence_ready_count"] == 224
    assert result["issue_scope"]["owner_decision_required_count"] == 263
    assert result["issue_scope"]["material_exact_span_gap_count"] == 98
    assert result["issue_scope"]["remaining_issue_work_count"] == 361
    assert len(result["issue_scope"]["records"]) == 361
    assert len({row["row_id"] for row in result["issue_scope"]["records"]}) == 361

    assert result["source_scope"]["held_successor_source_version_count"] == 251
    assert result["source_scope"]["held_successor_authority_identity_count"] == 249
    assert result["source_scope"]["deduplicated_currentness_authority_count"] == 184
    assert result["source_scope"]["judgment_later_treatment_authority_count"] == 133
    assert result["source_scope"]["legislation_currentness_authority_count"] == 51

    policy = result["policy_and_representation_scope"]
    assert policy["pending_legislative_effect_count"] == 516
    assert policy["pending_legislation_representation_mismatch_count"] == 65
    assert policy["legacy_judgment_later_treatment_subset_count"] == 20

    constraints = result["execution_constraints"]
    assert constraints["planner_or_answer_model_calls_authorized"] is False
    assert constraints["bulk_find_case_law_computational_analysis_authorized"] is False
    assert constraints["automatic_source_admission"] is False
    assert constraints["automatic_indexing"] is False
    assert constraints["automatic_embedding"] is False
    assert constraints["source_scan_authorized"] is False
    assert constraints["successor_candidate_build_authorized"] is False
    assert constraints["phase2b_authorized"] is False

    sealed = dict(result)
    digest = sealed.pop("artifact_content_sha256")
    assert digest == hashlib.sha256(_canonical_json(sealed)).hexdigest()
    assert (output / "PACKAGE-INDEX.json").is_file()
    assert (output / "SHA256SUMS.txt").is_file()


def test_create_only_output_refuses_overwrite(tmp_path: Path) -> None:
    output = tmp_path / "intake"
    builder.build_intake(output_root=output)
    try:
        builder.build_intake(output_root=output)
    except FileExistsError:
        pass
    else:
        raise AssertionError("immutable intake must refuse overwrite")
