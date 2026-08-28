from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = PROJECT_ROOT / "scripts/build_v111_phase2a_fact_only_fallback_coverage_advisory.py"


def _load_builder():
    spec = importlib.util.spec_from_file_location("phase2a_fact_only_fallback_builder", SCRIPT_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError("builder import failed")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


builder = _load_builder()


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _canonical(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _verify_seal(value: dict[str, Any], field: str = "artifact_content_sha256") -> None:
    material = dict(value)
    observed = material.pop(field)
    assert observed == hashlib.sha256(_canonical(material)).hexdigest()


@pytest.fixture()
def built(tmp_path: Path) -> Path:
    output_root = tmp_path / "advisory"
    return builder.build(output_root)


def test_audit_covers_exact_585_rows_and_only_two_fallback_rows(built: Path) -> None:
    advisory = _load(built / builder.ADVISORY_NAME)

    assert advisory["registry_binding"] == {
        "case_count": 60,
        "row_count": 585,
        "cases_file_sha256": builder.EXPECTED_CASES_FILE_SHA256,
        "manifest_file_sha256": builder.EXPECTED_MANIFEST_FILE_SHA256,
        "matrix_row_set_matches_registry": True,
    }
    assert advisory["audit_counts"] == {
        "registry_row_count": 585,
        "exact_remediation_decision_count": 361,
        "rows_outside_exact_remediation_decision_packet": 224,
        "direct_exact_local_span_decision_count": 45,
        "official_research_decision_count": 316,
        "strict_fact_only_remaining_blocker_row_count": 1,
        "no_legal_claim_matter_fact_exception_row_count": 1,
        "total_safe_fallback_eligible_row_count": 2,
        "safe_fallback_prohibited_or_not_required_row_count": 583,
    }
    assert advisory["coverage_verdict"]["eligible_row_ids"] == [
        "live60-q58:issue-09",
        "live60-q58:issue-14",
    ]
    assert advisory["coverage_verdict"]["coverage_complete_for_exact_585_row_audit"] is True
    assert advisory["remaining_583_row_policy"]["row_count"] == 583
    assert advisory["remaining_583_row_policy"]["automatic_safe_fallback_eligibility"] is False


def test_project_rescue_is_the_only_strict_fact_only_remaining_blocker(built: Path) -> None:
    advisory = _load(built / builder.ADVISORY_NAME)
    classification = advisory["classification_contract"]
    rows = {row["row_id"]: row for row in advisory["eligible_rows"]}
    row = rows["live60-q58:issue-14"]

    assert classification["strict_fact_only_row_ids"] == ["live60-q58:issue-14"]
    assert row["eligibility_class"] == "STRICT_FACT_ONLY_REMAINING_BLOCKER"
    assert row["registry_ordinal"] == 533
    assert row["contract_content_sha256"] == (builder.EXPECTED_PROJECT_RESCUE_CONTRACT_SHA256)
    assert row["required_missing_information_categories"] == list(
        builder.MISSING_INFORMATION_CATEGORIES
    )
    assert len(row["required_missing_information_categories"]) == 8
    assert row["required_user_message"] == builder.SAFE_FALLBACK_MESSAGE
    assert row["knowledge_gap_event"] is False
    assert row["matter_information_gap_event"] is True
    assert row["material_legal_claim_released"] is False
    assert row["underlying_legal_source_hold_hidden_by_fallback"] is False
    assert "SUBSTANTIVE_PROJECT_RESCUE_ADVICE" in row["prohibited_outputs"]
    assert "LEGAL_CITATION" in row["prohibited_outputs"]
    assert "EVIDENCE_SPAN" in row["prohibited_outputs"]


def test_performance_bond_qualifies_only_as_no_legal_claim_exception(built: Path) -> None:
    advisory = _load(built / builder.ADVISORY_NAME)
    rows = {row["row_id"]: row for row in advisory["eligible_rows"]}
    row = rows["live60-q58:issue-09"]

    assert row["eligibility_class"] == ("NO_LEGAL_CLAIM_MATTER_FACT_FALLBACK_EXCEPTION")
    assert row["strict_fact_only_in_original_361_packet"] is False
    assert row["registry_ordinal"] == 528
    assert row["contract_content_sha256"] == (builder.EXPECTED_PERFORMANCE_BOND_CONTRACT_SHA256)
    assert row["bound_held9_advisory_content_sha256"] == (
        builder.PERFORMANCE_BOND_HELD9_ADVISORY_CONTENT_SHA256
    )
    assert row["required_missing_information_categories"] == list(
        builder.PERFORMANCE_BOND_MISSING_INFORMATION_CATEGORIES
    )
    assert len(row["required_missing_information_categories"]) == 7
    assert row["required_user_message"] == (builder.PERFORMANCE_BOND_SAFE_FALLBACK_MESSAGE)
    assert row["knowledge_gap_event"] is False
    assert row["matter_information_gap_event"] is True
    assert row["material_legal_claim_released"] is False
    assert row["retained_underlying_holds"] == {
        "currentness_hold_retained": True,
        "later_treatment_hold_retained": True,
        "underlying_substantive_answer_not_qualified": True,
    }
    for prohibited in (
        "PERFORMANCE_BOND_CLASSIFICATION",
        "DEMAND_COMPLIANCE_CONCLUSION",
        "FRAUD_EXCEPTION_CONCLUSION",
        "INJUNCTION_MERITS_CONCLUSION",
        "SHANGHAI_OR_WUHAN_LEGAL_RULE",
        "LEGAL_CITATION",
        "EVIDENCE_SPAN",
        "SOURCE_VERSION_BINDING",
    ):
        assert prohibited in row["prohibited_outputs"]


def test_essay_and_dual_legal_source_gap_rows_are_not_broadened(built: Path) -> None:
    advisory = _load(built / builder.ADVISORY_NAME)
    examples = advisory["explicit_non_eligible_examples"]

    assert len(examples) == 8
    assert all(row["safe_fallback_prohibited"] is True for row in examples)
    assert {row["blocker_class"] for row in examples} == {
        "LEGAL_AUTHORITY_GAP",
        "DUAL_LEGAL_SOURCE_AND_MATTER_FACT_HOLD",
    }
    q51 = next(row for row in examples if row["row_id"] == "live60-q51:issue-05")
    assert q51["question_kind"] == "PROBLEM"
    assert q51["blocker_class"] == "DUAL_LEGAL_SOURCE_AND_MATTER_FACT_HOLD"
    assert "cannot hide" in q51["reason"]
    essays = [row for row in examples if row["question_kind"] == "ESSAY"]
    assert len(essays) == 7
    assert advisory["classification_contract"]["essay_fallback_prohibited"] is True
    assert (
        advisory["classification_contract"]["dual_legal_source_and_fact_gap_fallback_prohibited"]
        is True
    )


def test_advisory_and_package_are_self_sealed_and_non_authorizing(built: Path) -> None:
    advisory = _load(built / builder.ADVISORY_NAME)
    package = _load(built / builder.PACKAGE_NAME)

    _verify_seal(advisory)
    _verify_seal(package)
    assert package["advisory_content_sha256"] == advisory["artifact_content_sha256"]
    assert package["eligible_row_ids"] == [
        "live60-q58:issue-09",
        "live60-q58:issue-14",
    ]
    for field, value in builder._NO_EXECUTION_FLAGS.items():
        assert value is False
        assert advisory[field] is False
        assert package[field] is False
    assert advisory["phase_scope"] == "PHASE2A_ONLY"
    assert advisory["advisory_effect"] == (
        "NO_EXECUTION_NO_OWNER_DECISION_NO_PRODUCTION_QUALIFICATION"
    )
    assert package["advisory_effect"] == advisory["advisory_effect"]

    checksums = (built / builder.CHECKSUMS_NAME).read_text(encoding="utf-8")
    for name in (builder.ADVISORY_NAME, builder.PACKAGE_NAME):
        expected = hashlib.sha256((built / name).read_bytes()).hexdigest()
        assert f"{expected}  {name}\n" in checksums


def test_output_is_create_only_and_cli_help_does_not_create_artifacts(
    built: Path, tmp_path: Path
) -> None:
    with pytest.raises(FileExistsError):
        builder.build(built)

    help_result = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), "--help"],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert help_result.returncode == 0
    assert "fact-only fallback coverage advisory" in help_result.stdout
    assert list(tmp_path.glob("**/*.json")) == list(built.glob("*.json"))
