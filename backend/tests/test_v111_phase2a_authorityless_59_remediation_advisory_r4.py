from __future__ import annotations

import hashlib
import json
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from scripts import build_v111_phase2a_authorityless_59_remediation_advisory_r4 as builder


@pytest.fixture(scope="module")
def advisory() -> dict:
    return builder.build_advisory()


def _content_sha(value: dict, field: str) -> str:
    material = dict(value)
    material.pop(field, None)
    raw = (
        json.dumps(material, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    return hashlib.sha256(raw).hexdigest()


def _rows(advisory: dict) -> dict[str, dict]:
    return {row["row_id"]: row for row in advisory["row_advisories"]}


def _recommendations(advisory: dict) -> list[tuple[str, dict]]:
    return [
        (row["row_id"], recommendation)
        for row in advisory["row_advisories"]
        for recommendation in row["component_recommendations"]
    ]


def _all_spans(advisory: dict) -> list[dict]:
    spans = []
    for repair in advisory["mandatory_independent_audit_repairs"]:
        spans.extend(repair["frozen_evidence_span_proposals"])
    for row in advisory["row_advisories"]:
        for repair in row["retained_full_component_repairs"]:
            spans.extend(repair["frozen_evidence_span_proposals"])
        for recommendation in row["component_recommendations"]:
            spans.extend(recommendation.get("frozen_evidence_span_proposals", []))
            coverage = recommendation.get("coverage_basis", {})
            spans.extend(coverage.get("frozen_evidence_span_proposals", []))
    return spans


def test_exact_topology_lineage_and_residual_arithmetic(advisory: dict) -> None:
    assert advisory["artifact_content_sha256"] == _content_sha(advisory, "artifact_content_sha256")
    assert advisory["supersedes_advisory_content_sha256"] == (builder.R3_ADVISORY_CONTENT_SHA256)
    assert len(advisory["row_ids"]) == len(set(advisory["row_ids"])) == 59
    assert advisory["row_id_set_sha256"] == (
        "45a35173be61cce0e472db89e979d9834125baa868bf96c78ae5e3f0fbb8f376"
    )
    counts = advisory["counts"]
    assert counts["original_blocking_component_count"] == 80
    assert counts["original_none_component_count"] == 63
    assert counts["original_partial_component_count"] == 17
    assert counts["retained_original_component_blocker_count"] == 65
    assert counts["retained_none_component_blocker_count"] == 49
    assert counts["retained_partial_component_blocker_count"] == 16
    assert counts["residual_material_gap_row_count"] == 52
    assert counts["future_owner_consideration_support_ready_row_count"] == 7
    assert advisory["topology_derivation"]["r3_residual_material_gap_row_count"] == 55
    assert advisory["topology_derivation"]["r4_resolved_r3_residual_row_count"] == 3


def test_published_r4_is_the_exact_immutable_build(advisory: dict) -> None:
    path = builder.OUTPUT_ROOT / builder.ADVISORY_NAME
    assert hashlib.sha256(path.read_bytes()).hexdigest() == (
        "327450b2ce6d71cef38937b5de5eff80c5e2c3b1e6c5188005b29ad708206305"
    )
    published = json.loads(path.read_bytes())
    assert published == advisory
    assert published["artifact_content_sha256"] == (
        "ac13025b77561fd0b02ab49e3d25f72b2eec137e65fd10aa1360d3725049cb68"
    )


def test_exact_three_resolved_rows_and_exact_52_residual_set(advisory: dict) -> None:
    rows = _rows(advisory)
    assert set(advisory["resolved_r3_residual_row_ids"]) == {
        "live30-q12:issue-06",
        "live30-q16:issue-06",
        "live30-q30:issue-02",
    }
    assert set(advisory["residual_material_gap_row_ids"]) == {
        row_id for row_id, row in rows.items() if row["material_legal_support_gap"]
    }
    assert len(advisory["residual_material_gap_row_ids"]) == 52
    for row_id in advisory["resolved_r3_residual_row_ids"]:
        assert rows[row_id]["material_legal_support_gap"] is False
        assert (
            rows[row_id]["legal_component_coverage_complete_after_exact_action_if_owner_adopted"]
            is True
        )
        assert rows[row_id]["qualification_eligible"] is False
        assert rows[row_id]["answer_release_eligible"] is False


def test_all_80_components_still_dispositioned_exactly_once(advisory: dict) -> None:
    r3_disk = json.loads(builder.R3_ADVISORY_PATH.read_bytes())
    observed = [
        (
            row_id,
            recommendation["before"]["component_ordinal"],
            recommendation["before"]["proposition_text_sha256"],
        )
        for row_id, recommendation in _recommendations(advisory)
    ]
    expected = [
        (
            row_id,
            recommendation["before"]["component_ordinal"],
            recommendation["before"]["proposition_text_sha256"],
        )
        for row_id, recommendation in _recommendations(r3_disk)
    ]
    assert sorted(observed) == sorted(expected)
    assert len(observed) == len(set(observed)) == 80
    assert (
        sum(
            recommendation["component_material_blocker_after_owner_adoption"]
            for _, recommendation in _recommendations(advisory)
        )
        == 65
    )


def test_r3_safe_four_exclusions_and_nine_matter_splits_are_preserved(
    advisory: dict,
) -> None:
    recommendations = _recommendations(advisory)
    safe_exclusions = {
        (row_id, item["before"]["component_ordinal"])
        for row_id, item in recommendations
        if item["action"] == "EXCLUDE_EXACT_FALSE_OR_OVERBROAD_COMPONENT"
    }
    safe_matter = {
        (row_id, item["before"]["component_ordinal"])
        for row_id, item in recommendations
        if item["action"] == "SPLIT_REMOVE_CASE_FACT_APPLICATION_TO_MATTER_INTAKE"
    }
    assert safe_exclusions == builder.r3.SAFE_EXCLUSION_KEYS
    assert safe_matter == builder.r3.SAFE_MATTER_KEYS
    assert len(safe_exclusions) == 4
    assert len(safe_matter) == 9


def test_q58_section_7_1_correction_is_exact_and_span_bound(advisory: dict) -> None:
    repair = next(
        item
        for item in advisory["mandatory_independent_audit_repairs"]
        if item["row_id"] == "live60-q58:issue-10"
    )
    assert repair["exact_locator_added"] == "section 7(1)"
    assert "Section 7(1) preserves any third-party right or remedy" in repair["after_proposition"]
    span = repair["frozen_evidence_span_proposals"][0]
    assert span["authority_identity_id"] == "ukpga:1999:31"
    assert span["exact_locator"] == "section 7(1)"
    assert span["supporting_excerpts"] == [
        {
            "text": (
                "Section 1 does not affect any right or remedy of a third party that "
                "exists or is available apart from this Act."
            ),
            "normalised_text_sha256": hashlib.sha256(
                b"Section 1 does not affect any right or remedy of a third party that "
                b"exists or is available apart from this Act."
            ).hexdigest(),
            "verified_in_bound_source_bytes": True,
        }
    ]
    component = next(
        item
        for item in _rows(advisory)["live60-q58:issue-10"]["retained_full_component_inventory"]
        if item["component_ordinal"] == 1
    )
    assert "section 7(1)" in component["authorities"][0]["exact_locators"]


def test_q59_section_49c_timing_correction_is_exact_and_span_bound(
    advisory: dict,
) -> None:
    repair = next(
        item
        for item in advisory["mandatory_independent_audit_repairs"]
        if item["row_id"] == "live60-q59:issue-18"
    )
    assert repair["timing_contract"] == {
        "application_may_be_considered_before_infringement_decision": True,
        "approval_only_after_infringement_decision": True,
        "cma_decision_same_time_approval_permitted": True,
    }
    proposition = repair["after_proposition"]
    assert "may consider the application before" in proposition
    assert "may approve only after" in proposition
    assert "at the same time as the decision" in proposition
    assert "applies to the CMA for approval after" not in proposition
    span = repair["frozen_evidence_span_proposals"][0]
    assert span["authority_identity_id"] == "ukpga:1998:41"
    assert span["exact_locator"] == "section 49C(1)-(2)"
    assert len(span["supporting_excerpts"]) == 4
    assert all(item["verified_in_bound_source_bytes"] for item in span["supporting_excerpts"])


def test_q12_campbell_gap_is_narrowed_to_exact_bloomberg_support(
    advisory: dict,
) -> None:
    row = _rows(advisory)["live30-q12:issue-06"]
    assert row["source_binding_material_holds"] == []
    repair = row["retained_full_component_repairs"][0]
    assert repair["repair"] == ("NARROW_TO_BLOOMBERG_ONLY_REMOVE_UNAVAILABLE_CAMPBELL_DEPENDENCY")
    component = next(
        item for item in row["retained_full_component_inventory"] if item["component_ordinal"] == 2
    )
    assert {item["authority_identity_id"] for item in component["authorities"]} == {
        "neutral-citation:[2022] UKSC 5"
    }
    assert "freestanding direct Convention claim" in component["proposition"]
    assert repair["frozen_evidence_span_proposals"][0]["exact_locator"] == (
        "paragraphs 45-49, especially paragraph 45"
    )


def test_q16_false_necessary_intestacy_is_excluded_with_exact_coverage(
    advisory: dict,
) -> None:
    row = _rows(advisory)["live30-q16:issue-06"]
    recommendation = next(
        item
        for item in row["component_recommendations"]
        if item["before"]["component_ordinal"] == 3
    )
    assert recommendation["action"] == (
        "EXCLUDE_FALSE_NECESSARY_INTESTACY_AND_RETAIN_MATTER_INTAKE"
    )
    assert recommendation["after_legal_propositions"] == []
    assert len(recommendation["after_nonlegal_requirements"]) == 1
    assert {
        span["exact_locator"]
        for span in recommendation["coverage_basis"]["frozen_evidence_span_proposals"]
    } == {"section 20", "section 49(1)", "section 46(1)"}
    assert recommendation["component_material_blocker_after_owner_adoption"] is False


def test_q30_partial_is_narrowed_to_osborn_and_facts_are_intake(
    advisory: dict,
) -> None:
    row = _rows(advisory)["live30-q30:issue-02"]
    recommendation = next(
        item
        for item in row["component_recommendations"]
        if item["before"]["component_ordinal"] == 5
    )
    assert recommendation["before"]["support_fit"] == "PARTIAL"
    assert recommendation["action"] == (
        "OWNER_REWRITE_TO_EXACT_BOUND_SOURCE_TEXT_AND_SPLIT_MATTER_INTAKE"
    )
    assert recommendation["after_legal_propositions"][0]["proposition"] == builder.Q30_AFTER
    assert len(recommendation["after_nonlegal_requirements"]) == 1
    assert recommendation["after_nonlegal_requirements"][0]["lane"] == (
        "NONAUTHORITATIVE_MATTER_INTAKE_ONLY"
    )
    span = recommendation["frozen_evidence_span_proposals"][0]
    assert span["authority_identity_id"] == "neutral-citation:[2013] UKSC 61"
    assert span["exact_locator"] == "paragraphs 67-72, especially paragraph 68"


def test_every_frozen_span_excerpt_is_reverified_in_exact_bound_bytes(
    advisory: dict,
) -> None:
    spans = _all_spans(advisory)
    # q58/q59 repairs appear both in the global audit ledger and their row repair
    # lists, so there are nine references to seven unique sealed span proposals.
    assert len({span["span_proposal_content_sha256"] for span in spans}) == 7
    bindings = {item["record_content_sha256"]: item for item in advisory["source_byte_bindings"]}
    for span in spans:
        assert span["span_proposal_content_sha256"] == _content_sha(
            span, "span_proposal_content_sha256"
        )
        binding = bindings[span["source_binding_content_sha256"]]
        path = builder._binding_path(binding)
        assert hashlib.sha256(path.read_bytes()).hexdigest() == span["representation_file_sha256"]
        source_text, _ = builder.r2._representation_text(path)
        normalized_source = builder.r2._normalise_text(source_text)
        assert (
            hashlib.sha256(normalized_source.encode()).hexdigest()
            == span["derived_normalized_representation_text_sha256"]
        )
        for excerpt in span["supporting_excerpts"]:
            normalized = builder.r2._normalise_text(excerpt["text"])
            assert normalized in normalized_source
            assert (
                hashlib.sha256(normalized.encode()).hexdigest() == excerpt["normalised_text_sha256"]
            )


def test_all_seven_ready_rows_have_all_retained_full_sources_byte_bound(
    advisory: dict,
) -> None:
    rows = _rows(advisory)
    ready = {
        row_id
        for row_id, row in rows.items()
        if row["legal_component_coverage_complete_after_exact_action_if_owner_adopted"]
    }
    assert ready == builder.FUTURE_SUPPORT_READY_ROWS
    assert len(ready) == 7
    binding_by_content = {
        item["record_content_sha256"]: item for item in advisory["source_byte_bindings"]
    }
    for row_id in ready:
        assert rows[row_id]["retained_release_hold_codes"]
        for component in rows[row_id]["retained_full_component_inventory"]:
            assert component["coverage_role"] == ("RELIED_ON_FOR_EXACT_ISSUE_DIMENSION_COVERAGE_R4")
            for authority in component["authorities"]:
                assert authority["source_byte_binding_status"] == "EXACT_LOCAL_BYTE_BOUND_R4"
                binding = binding_by_content[authority["source_binding_content_sha256"]]
                assert binding["relied_on_for_support"] is True
                assert binding["representation_byte_hash_verified"] is True


def test_sources_roles_holds_and_all_127_full_inventory_records(advisory: dict) -> None:
    assert len(advisory["source_byte_bindings"]) == advisory["counts"]["source_byte_binding_count"]
    assert len({item["authority_identity_id"] for item in advisory["source_byte_bindings"]}) == len(
        advisory["source_byte_bindings"]
    )
    assert all(item["source_roles"] for item in advisory["source_byte_bindings"])
    assert all(item["source_admitted_by_r4"] is False for item in advisory["source_byte_bindings"])
    full = [
        component
        for row in advisory["row_advisories"]
        for component in row["retained_full_component_inventory"]
    ]
    assert len(full) == 127
    r3_disk = json.loads(builder.R3_ADVISORY_PATH.read_bytes())
    r3_rows = _rows(r3_disk)
    for row in advisory["row_advisories"]:
        assert {
            item["record_content_sha256"]
            for item in row["all_unclassified_upstream_holds_retained"]
        } == {
            item["record_content_sha256"]
            for item in r3_rows[row["row_id"]]["all_unclassified_upstream_holds_retained"]
        }


def test_56_no_execution_flags_recursive_boundary_and_privacy(advisory: dict) -> None:
    assert len(builder.NO_EXECUTION_FLAGS) == 56
    for field in builder.NO_EXECUTION_FLAGS:
        assert advisory[field] is False
    assert builder._recursive_no_execution_violations(advisory) == []
    assert advisory["recursive_no_execution_control"] == {
        "authoritative_field_count": 56,
        "recursive_violations": [],
        "verified": True,
    }
    raw = json.dumps(advisory, ensure_ascii=False)
    assert "/Users/" not in raw
    assert "LegalBot-New" not in raw
    assert "hltsang" not in raw
    assert advisory["qualification_run"] is False
    assert advisory["answer_release_eligible"] is False
    assert advisory["answer_released"] is False


def test_create_only_private_atomic_publication(tmp_path: Path) -> None:
    output = tmp_path / "authorityless-r4"
    result = builder.publish(output)
    assert result["status"].startswith("IMMUTABLE_NO_GO_52")
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    assert {path.name for path in output.iterdir()} == {
        builder.ADVISORY_NAME,
        builder.PACKAGE_NAME,
        builder.CHECKSUMS_NAME,
    }
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in output.iterdir())
    for line in (output / builder.CHECKSUMS_NAME).read_text().splitlines():
        digest, name = line.split("  ", 1)
        assert hashlib.sha256((output / name).read_bytes()).hexdigest() == digest
    with pytest.raises(FileExistsError):
        builder.publish(output)


def test_direct_cli_verify_runs_outside_repository(tmp_path: Path) -> None:
    result = subprocess.run(
        [sys.executable, str(Path(builder.__file__).resolve()), "verify"],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["counts"]["row_count"] == 59
    assert payload["counts"]["residual_material_gap_row_count"] == 52
    assert payload["status"].startswith("IMMUTABLE_NO_GO_52")
