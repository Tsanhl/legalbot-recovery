from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from scripts import build_v111_phase2a_held_missing_source_advisory as builder


def _load(file_path: Path) -> dict:
    return json.loads(file_path.read_text(encoding="utf-8"))


def _content_sha256(value: dict, field: str) -> str:
    material = dict(value)
    material.pop(field)
    raw = (
        json.dumps(material, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def test_builds_exact_create_only_28_row_advisory(tmp_path: Path) -> None:
    output = tmp_path / "held-missing-source-advisory"
    paths = builder.build_artifacts(output)

    advisory = _load(paths["advisory"])
    assert advisory["artifact_content_sha256"] == _content_sha256(
        advisory, "artifact_content_sha256"
    )
    assert advisory["scope"]["source_present_but_assessment_held_row_ids"] == list(builder.HELD8)
    assert advisory["scope"]["missing_source_identity_row_ids"] == list(builder.MISSING20)
    assert advisory["scope"]["source_present_but_assessment_held_set_sha256"] == (
        builder.HELD8_SET_SHA256
    )
    assert advisory["scope"]["missing_source_identity_set_sha256"] == (builder.MISSING20_SET_SHA256)
    assert len(advisory["rows"]) == 28
    assert len({row["row_id"] for row in advisory["rows"]}) == 28
    assert advisory["result_counts"] == {
        "new_source_admission_representations_proposed": 9,
        "no_valid_missing_source_requirement_owner_rewrite_or_exclusion": 7,
        "row_advisory_count": 28,
        "rows_automatically_qualified": 0,
        "rows_with_any_retained_hold": 28,
        "source_topology_resolved_owner_action_required": 17,
        "unavailable_or_incomplete_official_source_gap_retained": 4,
    }
    assert all(row["material_gap_cleared"] is False for row in advisory["rows"])
    assert all(row["owner_decision_required"] is True for row in advisory["rows"])
    assert all(row["answer_release_eligible"] is False for row in advisory["rows"])
    assert all(value is False for value in builder.NO_EXECUTION.values())
    assert all(advisory[key] is False for key in builder.NO_EXECUTION)


def test_source_manifest_seals_roles_and_identity_correction(tmp_path: Path) -> None:
    paths = builder.build_artifacts(tmp_path / "advisory")
    manifest = _load(paths["source_manifest"])
    assert manifest["artifact_content_sha256"] == _content_sha256(
        manifest, "artifact_content_sha256"
    )
    assert manifest["record_count"] == 15
    assert manifest["evidence_role_counts"] == {
        "FAILED_ROUTE_DIAGNOSTIC_NOT_EVIDENCE": 1,
        "IDENTITY_LANDING_ONLY_NOT_PROPOSITION_EVIDENCE": 2,
        "MISIDENTIFIED_SOURCE_DIAGNOSTIC_NOT_ADMISSION": 2,
        "PROPOSED_OWNER_ADMISSION_REPRESENTATION": 9,
        "RESEARCH_ONLY_PERSUASIVE_JURISDICTION_HOLD": 1,
    }
    correction = manifest["identity_corrections"][0]
    assert correction["rejected_identity_id"] == "uksi:2024:1377"
    assert correction["correct_identity_id"] == "uksi:2024:234"
    assert correction["automatic_substitution"] is False
    by_member = {record["member"]: record for record in manifest["records"]}
    assert by_member["015-uksi-2024-234-made.xml"]["raw_sha256"] == (
        "2dffdcfcde1772e24746ca79d5845b26fd3de35f567fd30976c3335868129b98"
    )
    assert by_member["004-simon-v-lyder-2019-ukpc-38.pdf"]["evidence_role"] == (
        "RESEARCH_ONLY_PERSUASIVE_JURISDICTION_HOLD"
    )
    assert by_member["003-aib-group-2014-uksc-58-wrong-media-type.html"]["evidence_role"] == (
        "FAILED_ROUTE_DIAGNOSTIC_NOT_EVIDENCE"
    )


def test_retry_ledger_is_bounded_and_create_only(tmp_path: Path) -> None:
    output = tmp_path / "advisory"
    paths = builder.build_artifacts(output)
    ledger = _load(paths["retry_ledger"])
    assert ledger["artifact_content_sha256"] == _content_sha256(ledger, "artifact_content_sha256")
    assert ledger["prior_failure_count"] == 12
    assert all(item["unchanged_retry_prohibited"] for item in ledger["prior_failures"])
    assert all(item["unchanged_retry_prohibited"] for item in ledger["additional_diagnostics"])
    with pytest.raises(FileExistsError):
        builder.build_artifacts(output)


def test_package_checksums_and_no_private_paths(tmp_path: Path) -> None:
    paths = builder.build_artifacts(tmp_path / "advisory")
    package = _load(paths["package"])
    assert package["package_content_sha256"] == _content_sha256(package, "package_content_sha256")
    checksums = paths["checksums"].read_text(encoding="utf-8")
    for record in package["artifacts"]:
        assert record["file_sha256"] in checksums
    combined = "\n".join(
        file_path.read_text(encoding="utf-8")
        for file_path in paths.values()
        if file_path.suffix in {".json", ".txt"}
    )
    assert "/Users/" not in combined
    assert "/private/" not in combined
    assert "file://" not in combined
