from __future__ import annotations

import hashlib
import json
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from scripts import build_v111_phase2a_held9_surviving_support_advisory as builder


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    assert isinstance(value, dict)
    return value


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture(scope="module")
def built_package(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, dict[str, Any]]:
    review_root = tmp_path_factory.mktemp("held9-review")
    output = review_root / builder.DEFAULT_OUTPUT_ROOT.name
    original_review_root = builder.OUTPUT_REVIEW_ROOT
    builder.OUTPUT_REVIEW_ROOT = review_root
    try:
        result = builder.build_advisory(
            output_root=output,
            created_at=datetime(2026, 8, 28, 12, 0, tzinfo=UTC),
        )
        yield output, result
    finally:
        builder.OUTPUT_REVIEW_ROOT = original_review_root


def test_package_is_sealed_private_and_checksum_complete(
    built_package: tuple[Path, dict[str, Any]],
) -> None:
    output, result = built_package
    assert sorted(path.name for path in output.iterdir()) == [
        builder.ADVISORY_NAME,
        builder.PACKAGE_NAME,
        builder.CHECKSUMS_NAME,
    ]
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    for path in output.iterdir():
        assert not path.is_symlink()
        assert stat.S_IMODE(path.stat().st_mode) == 0o600

    advisory = _load(output / builder.ADVISORY_NAME)
    package = _load(output / builder.PACKAGE_NAME)
    advisory_seal = advisory.pop("artifact_content_sha256")
    package_seal = package.pop("package_content_sha256")
    assert advisory_seal == builder._sealed(advisory)
    assert package_seal == builder._sealed(package)
    assert advisory_seal == result["advisory_content_sha256"]
    assert package_seal == result["package_content_sha256"]

    expected_checksums = (
        f"{_sha256(output / builder.ADVISORY_NAME)}  {builder.ADVISORY_NAME}\n"
        f"{_sha256(output / builder.PACKAGE_NAME)}  {builder.PACKAGE_NAME}\n"
    )
    assert (output / builder.CHECKSUMS_NAME).read_text() == expected_checksums


def test_exact_five_holds_and_nine_rows_are_bound(
    built_package: tuple[Path, dict[str, Any]],
) -> None:
    output, _ = built_package
    advisory = _load(output / builder.ADVISORY_NAME)
    assert advisory["scope"] == {
        "audit_pass_original_universe_count": 231,
        "defective_representation_count": 16,
        "exact_row_count": 9,
        "exact_row_ids": sorted(item["row_id"] for item in builder.ROW_OUTCOMES),
        "existing_candidate_source_count": 3,
        "held_proposal_count": 5,
        "surviving_audit_pass_or_warning_proposal_count": 9,
    }
    holds = advisory["five_unresolved_held_proposals"]
    assert {item["proposal_id"] for item in holds} == {
        item["proposal_id"] for item in builder.HELD_SPECS
    }
    for item in holds:
        assert item["representation_excluded"] is True
        assert item["source_admission_authorized"] is False
        assert item["currentness_hold_retained"] is True
        assert item["later_treatment_hold_retained"] is True
        assert item["legal_rule_release_prohibited"] is True


def test_all_sixteen_defective_representations_are_exactly_excluded(
    built_package: tuple[Path, dict[str, Any]],
) -> None:
    output, _ = built_package
    advisory = _load(output / builder.ADVISORY_NAME)
    rejected = advisory["sixteen_defective_original_representations_excluded"]
    assert len(rejected) == 16
    assert len({item["original_proposal_id"] for item in rejected}) == 16
    assert all(item["excluded"] is True for item in rejected)
    assert all(item["source_admission_authorized"] is False for item in rejected)
    assert all(item["audit_failure_reason_codes"] for item in rejected)


def test_surviving_representation_hashes_verdicts_and_locators_are_exact(
    built_package: tuple[Path, dict[str, Any]],
) -> None:
    output, _ = built_package
    advisory = _load(output / builder.ADVISORY_NAME)
    actual = {
        item["proposal_id"]: item
        for item in advisory["surviving_pass_or_pass_with_warning_representations"]
    }
    assert set(actual) == {item["proposal_id"] for item in builder.SURVIVOR_SPECS}
    for expected in builder.SURVIVOR_SPECS:
        item = actual[expected["proposal_id"]]
        assert item["proposal_content_sha256"] == expected["proposal_content_sha256"]
        assert item["proposed_source_version_id"] == expected["source_version_id"]
        assert item["raw_sha256"] == expected["raw_sha256"]
        assert item["canonical_content_sha256"] == expected["canonical_content_sha256"]
        assert item["binding_record_content_sha256"] == expected["binding_record_content_sha256"]
        assert item["audit_record_content_sha256"] == expected["audit_record_content_sha256"]
        assert item["audit_verdict"] == expected["audit_verdict"]
        assert item["audit_warning_reason_codes"] == expected["audit_warning_reason_codes"]
        assert item["row_locator_bindings"] == expected["row_locators"]


def test_existing_candidate_sources_and_exact_locators_are_bound(
    built_package: tuple[Path, dict[str, Any]],
) -> None:
    output, _ = built_package
    advisory = _load(output / builder.ADVISORY_NAME)
    actual = {
        item["source_version_id"]: item for item in advisory["surviving_existing_candidate_sources"]
    }
    assert set(actual) == {item["source_version_id"] for item in builder.CANDIDATE_SOURCE_SPECS}
    for expected in builder.CANDIDATE_SOURCE_SPECS:
        item = actual[expected["source_version_id"]]
        assert item["content_sha256"] == expected["content_sha256"]
        assert item["authority_identity_id"] == expected["authority_identity_id"]
        assert item["row_locators"] == expected["row_locators"]
        assert item["candidate_existing"] is True


def test_essay_rows_cannot_use_safe_fallback(
    built_package: tuple[Path, dict[str, Any]],
) -> None:
    output, _ = built_package
    advisory = _load(output / builder.ADVISORY_NAME)
    essays = [item for item in advisory["row_outcomes"] if item["question_kind"] == "ESSAY"]
    assert len(essays) == 7
    assert all(item["safe_fallback_eligible"] is False for item in essays)
    assert all(item["safe_fallback_prohibited"] is True for item in essays)
    assert all(item["excluded_unsupported_components"] for item in essays)


def test_q51_remains_dual_source_and_fact_hold(
    built_package: tuple[Path, dict[str, Any]],
) -> None:
    output, _ = built_package
    advisory = _load(output / builder.ADVISORY_NAME)
    q51 = next(item for item in advisory["row_outcomes"] if item["row_id"] == "live60-q51:issue-05")
    assert q51["outcome"] == "DUAL_LEGAL_SOURCE_AND_MATTER_FACT_HOLD"
    assert q51["blocker_class"] == "DUAL_LEGAL_SOURCE_AND_MATTER_FACT_HOLD"
    assert q51["safe_fallback_eligible"] is False
    assert q51["safe_fallback_prohibited"] is True
    assert q51["missing_matter_facts"]
    assert "Goodwin" in q51["excluded_unsupported_components"][0]


def test_q58_fact_fallback_releases_no_legal_claim_and_wuhan_stays_held(
    built_package: tuple[Path, dict[str, Any]],
) -> None:
    output, _ = built_package
    advisory = _load(output / builder.ADVISORY_NAME)
    q58 = next(item for item in advisory["row_outcomes"] if item["row_id"] == "live60-q58:issue-09")
    assert q58["reason_code"] == "INSUFFICIENT_MATTER_FACTS_FOR_PERFORMANCE_BOND_ADVICE"
    assert q58["ui_cta"] == "SUPPLY_BOND_AND_DEMAND_DOCUMENTS_AND_ESCALATE_QUALIFIED_HUMAN"
    assert q58["knowledge_gap_event"] is False
    assert q58["matter_information_gap_event"] is True
    assert q58["fallback_releases_material_legal_claim"] is False
    assert q58["cross_row_owner_decision_required"] is True
    assert q58["wuhan_source_admission_authorized"] is False
    assert q58["currentness_hold_retained"] is True
    assert q58["later_treatment_hold_retained"] is True
    assert q58["legal_rule_release_prohibited"] is True
    assert q58["citation_release_prohibited"] is True
    assert q58["evidence_span_release_prohibited"] is True

    wuhan = next(
        item
        for item in advisory["surviving_pass_or_pass_with_warning_representations"]
        if item["proposal_id"] == "proposed-source-4454eee65cc76c0a988198a1"
    )
    assert (
        wuhan["proposal_content_sha256"]
        == "0e0b4015fe6e2fecd4e9fadf43370dad28d9313e64fda6c7ed5f09bfa61a98b4"
    )
    assert wuhan["cross_row_candidate_only"] is True
    assert wuhan["cross_row_owner_decision_required"] is True
    assert wuhan["legal_rule_release_prohibited"] is True


def test_every_execution_or_mutation_flag_is_false_and_output_is_private(
    built_package: tuple[Path, dict[str, Any]],
) -> None:
    output, _ = built_package
    texts = []
    for name in (builder.ADVISORY_NAME, builder.PACKAGE_NAME):
        value = _load(output / name)
        builder._verify_no_execution_flags(value)
        texts.append(json.dumps(value, ensure_ascii=False).casefold())
    combined = "\n".join(texts)
    assert "/users/" not in combined
    assert "hltsang" not in combined
    assert "legalbot-new" not in combined
    assert "file://" not in combined


def test_create_only_builder_refuses_replace_without_changing_files(
    built_package: tuple[Path, dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    output, _ = built_package
    before = {path.name: _sha256(path) for path in output.iterdir()}
    monkeypatch.setattr(builder, "OUTPUT_REVIEW_ROOT", output.parent)
    with pytest.raises(ValueError, match="held9_output_already_exists"):
        builder.build_advisory(
            output_root=output,
            created_at=datetime(2026, 8, 28, 12, 0, tzinfo=UTC),
        )
    assert {path.name: _sha256(path) for path in output.iterdir()} == before


def test_exact_loader_fails_closed_on_wrong_digest() -> None:
    with pytest.raises(ValueError, match="test_file_digest_mismatch"):
        builder._load_exact(
            builder.ORIGINAL_PATH,
            expected_file_sha256="0" * 64,
            seal_field="artifact_content_sha256",
            expected_content_sha256=builder.EXPECTED_INPUTS["original"]["content_sha256"],
            code="test",
        )


def test_naive_created_at_is_rejected_before_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "review" / "held9"
    output.parent.mkdir()
    monkeypatch.setattr(builder, "OUTPUT_REVIEW_ROOT", output.parent)
    with pytest.raises(ValueError, match="held9_created_at_must_be_aware"):
        builder.build_advisory(
            output_root=output,
            created_at=datetime(2026, 8, 28, 12, 0),
        )
    assert not output.exists()
