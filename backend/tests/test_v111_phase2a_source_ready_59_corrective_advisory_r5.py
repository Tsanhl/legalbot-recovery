from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

from scripts import build_v111_phase2a_source_ready_59_corrective_advisory_r5 as builder


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def test_r5_is_fail_closed_with_exact_topology_and_no_false_eligibility() -> None:
    advisory, holds, coverage, audit, residuals, _ = builder.build_advisory()
    assert advisory["status"] == ("NOT_APPROVAL_READY_65_COMPONENT_BLOCKERS_REMAIN_ACROSS_55_ROWS")
    assert advisory["counts"]["row_count"] == 59
    assert advisory["counts"]["blocking_component_input_count"] == 72
    assert advisory["counts"]["qualification_eligible_row_count"] == 0
    assert advisory["counts"]["residual_blocker_count"] == 65
    assert advisory["counts"]["residual_row_count"] == 55
    assert advisory["counts"]["whole_row_support_ready_for_owner_consideration_count"] == 4
    assert coverage["record_count"] == 12
    assert coverage["additional_exact_exclusion_coverage_proof"]
    assert residuals["record_count"] == 65
    assert residuals["residual_row_count"] == 55
    assert holds["record_count"] == 180
    assert holds["disposition_counts"] == {
        "MATTER_INFO": 80,
        "RETAINED_RELEASE": 100,
    }
    assert audit["corrections"]["all_row_qualification_eligibility_false"]
    assert audit["corrections"]["audit_only_whole_schedule_locator_removed"]
    for row in advisory["row_advisories"]:
        assert row["qualification_eligible"] is False
        assert row["qualification_eligibility_not_predeclared"] is True
    for artifact in (advisory, holds, coverage, audit, residuals):
        assert builder.r2._recursive_no_execution_violations(artifact) == []


def test_r5_matter_contracts_are_exact_non_answers_and_other_six_stay_blocked() -> None:
    advisory, _, coverage, _, _, _ = builder.build_advisory()
    recommendations = {
        (row["row_id"], item["component_ordinal"]): item
        for row in advisory["row_advisories"]
        for item in row["component_recommendations"]
    }
    actions = Counter(item["action"] for item in recommendations.values())
    assert actions == {
        "PROPOSE_MATTER_INFORMATION_GAP_NON_ANSWER_WITH_BOUND_LEGAL_RULES": 6,
        "RETAIN_BLOCKER_MATTER_SCOPE_CONTRACT_UNSUPPORTED": 6,
        "RETAIN_BLOCKER_WITH_SUPPLEMENTARY_ATTRIBUTED_GUIDANCE_SNAPSHOT": 6,
        "OWNER_EXCLUDE_DEMONSTRABLY_OVERBROAD_PROPOSITION": 1,
        "RETAIN_BLOCKER_PROPOSITION_COMPLETE_SUPPORT_REQUIRED": 53,
    }
    bound_hashes = {row["record_content_sha256"] for row in coverage["records"]}
    assert len(bound_hashes) == 12
    for key in builder.MATTER_COVERAGE_COMPONENTS:
        item = recommendations[key]
        contract = item["proposed_non_answer_contract"]
        assert set(item["retained_full_component_proof_content_sha256s"]) <= bound_hashes
        assert contract["reason_code"] == "MATTER_INFORMATION_INSUFFICIENT"
        assert contract["matter_information_gap_event"] is True
        assert contract["knowledge_gap_event"] is False
        assert contract["offer_qualified_human_legal_review"] is True
        assert contract["legal_claim_released"] is False
        assert contract["citation_released"] is False
        assert contract["evidence_span_released"] is False
        assert contract["answer_model_output_allowed"] is False
        assert contract["owner_adopted"] is False
        assert contract["applied"] is False
        assert contract["evaluation_contract_mutated"] is False
    for key, reason in builder.BLOCKED_MATTER_COMPONENTS.items():
        item = recommendations[key]
        assert item["action"] == "RETAIN_BLOCKER_MATTER_SCOPE_CONTRACT_UNSUPPORTED"
        assert item["blocker_reason_code"] == reason
        assert item["proposed_non_answer_contract"] is None
    app = recommendations[("live30-q18:issue-01", 4)]
    assert "PSR_APP_SCHEME_RULE_EFFECTIVE_DATE" in app["blocker_reason_code"]


def test_r5_coverage_proofs_bind_exact_bytes_locators_and_spans() -> None:
    _, _, coverage, audit, _, _ = builder.build_advisory()
    assert coverage["status"] == "12_RELIED_FULL_COMPONENTS_EXACTLY_BYTE_AND_SPAN_BOUND"
    for proof in [
        *coverage["records"],
        coverage["additional_exact_exclusion_coverage_proof"],
    ]:
        assert proof["exact_byte_and_span_binding_complete"] is True
        assert proof["source_spans"]
        for source in proof["source_spans"]:
            assert len(source["representation_file_sha256"]) == 64
            assert source["source_binding_content_sha256"]
            assert source["frozen_spans"]
            for span in source["frozen_spans"]:
                assert span["exact_locator"]
                assert span["supporting_excerpts"]
                assert all(item["text"] for item in span["supporting_excerpts"])
                assert all(
                    len(item["normalised_text_sha256"]) == 64
                    for item in span["supporting_excerpts"]
                )
    simon = coverage["supplemental_source_bindings"][0]
    assert simon["authority_identity_id"] == "neutral-citation:[2014] EWCA Civ 280"
    assert simon["representation_file_sha256"] == (
        "9ff2282a9b730bd32d8febb842da0c0f23617c541b11b891dcef98a3a438e49a"
    )
    assert simon["canonical_content_sha256"] == (
        "ee3916913d58c1ca3e1d2a2055c416251cafe95903073b3e367d5b0b8d3d58cc"
    )
    pd31b = coverage["pd31b_disposition"]
    assert pd31b["raw_representation_available"] is False
    assert pd31b["affected_row_retained_blocked"] == "live30-q30:issue-04"
    assert audit["corrections"]["pd31b_row_retained_because_official_representation_unavailable"]


def test_r5_charity_guidance_is_supplementary_and_primary_dimensions_block() -> None:
    advisory, _, _, _, residuals, _ = builder.build_advisory()
    charity = [
        item
        for row in advisory["row_advisories"]
        for item in row["component_recommendations"]
        if item["action"] == "RETAIN_BLOCKER_WITH_SUPPLEMENTARY_ATTRIBUTED_GUIDANCE_SNAPSHOT"
    ]
    assert len(charity) == 6
    assert all(item["after_propositions"] == [] for item in charity)
    assert all(item["supplementary_attributed_guidance_snapshot"] for item in charity)
    assert all(item["supplementary_frozen_evidence_spans"] for item in charity)
    assert all(item["removed_primary_dimensions_remain_blockers"] for item in charity)
    assert all(item["contract_or_scope_mutation_proposed"] is False for item in charity)
    residual_keys = {(row["row_id"], row["component_ordinal"]) for row in residuals["records"]}
    assert set(builder.r4.CHARITY_AFTER) <= residual_keys


def test_r5_publish_is_immutable_and_checksummed(tmp_path: Path) -> None:
    result = builder.publish(tmp_path / "r5")
    output = Path(result["output"])
    package = json.loads((output / builder.PACKAGE_NAME).read_text())
    for record in package["artifacts"]:
        assert _sha256((output / record["member"]).read_bytes()) == record["file_sha256"]
    checksum_lines = (output / builder.CHECKSUMS_NAME).read_text().splitlines()
    assert len(checksum_lines) == package["artifact_count"] + 1
    assert result["status"].startswith("NOT_APPROVAL_READY_")
