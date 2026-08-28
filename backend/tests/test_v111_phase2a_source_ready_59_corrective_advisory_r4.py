from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

from scripts import build_v111_phase2a_source_ready_59_corrective_advisory_r4 as builder

from app.ingestion.models import ParseStatus
from app.ingestion.parsers import ParserRegistry


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def test_r4_exact_topology_holds_and_fail_closed_boundary() -> None:
    advisory, holds, derivatives, audit, residuals, members = builder.build_advisory()

    assert advisory["status"].startswith("NOT_APPROVAL_READY_")
    assert advisory["counts"] == {
        "row_count": 59,
        "blocking_component_input_count": 72,
        "attributed_guidance_scope_supersession_count": 6,
        "matter_intake_scope_supersession_count": 12,
        "demonstrably_overbroad_exclusion_count": 1,
        "retained_blocker_count": 53,
        "residual_material_gap_row_count": 48,
        "support_complete_row_if_owner_adopts_exact_scope_count": 11,
        "r2_hold_record_count": 180,
        "source_byte_binding_count": 77,
        "govuk_canonical_derivative_count": 4,
        "no_execution_field_count": 56,
    }
    recommendations = [
        component
        for row in advisory["row_advisories"]
        for component in row["component_recommendations"]
    ]
    assert len(recommendations) == 72
    assert Counter(row["action"] for row in recommendations) == {
        "OWNER_SCOPE_SUPERSESSION_TO_ATTRIBUTED_OFFICIAL_GUIDANCE": 6,
        "OWNER_SCOPE_SUPERSESSION_TO_NON_AUTHORITATIVE_MATTER_INTAKE": 12,
        "OWNER_EXCLUDE_DEMONSTRABLY_OVERBROAD_PROPOSITION": 1,
        "RETAIN_BLOCKER_PROPOSITION_COMPLETE_SUPPORT_REQUIRED": 53,
    }
    assert all(row["eligibility_pre_owner_adoption"] is False for row in recommendations)
    assert all(row["owner_adopted"] is False and row["applied"] is False for row in recommendations)
    assert len(holds["records"]) == 180
    assert len({row["r2_hold_record_content_sha256"] for row in holds["records"]}) == 180
    assert {row["disposition"] for row in holds["records"]} <= {
        "RESOLVED",
        "RETAINED_RELEASE",
        "MATTER_INFO",
        "OUTSIDE_EXPLICIT_SCOPE",
    }
    assert all(row["operative"] is True and row["resolved"] is False for row in holds["records"])
    assert residuals["record_count"] == 53
    assert residuals["residual_row_count"] == 48
    assert len(derivatives["records"]) == len(members) == 4
    for artifact in (advisory, holds, derivatives, audit, residuals):
        assert builder.r2._recursive_no_execution_violations(artifact) == []


def test_r4_repairs_exact_no_go_fingerprints() -> None:
    advisory, _, derivatives, audit, _, _ = builder.build_advisory()
    defect_records = {
        (row["row_id"], row["component_ordinal"]): row for row in audit["defect_records"]
    }
    assert set(defect_records) == set(builder.DEFECT_DIMENSIONS)
    assert len(defect_records) == 17
    assert (
        sum(
            row["r4_disposition"] == "EXACT_OWNER_SCOPE_SUPERSESSION_RECOMMENDED_NOT_APPLIED"
            for row in defect_records.values()
        )
        == 6
    )
    assert (
        sum(
            row["r4_disposition"] == "RETAIN_BLOCKER_NO_INCOMPLETE_REWRITE"
            for row in defect_records.values()
        )
        == 11
    )
    assert audit["r3_unsealed_external_research"]["hash_kind_counts"] == {
        "JUDGMENT": 9,
        "LIVE_RESPONSE": 4,
        "SEARCH_RESPONSE": 2,
    }
    assert audit["r3_unsealed_external_research"]["no_later_treatment_conclusion_carried_forward"]
    assert audit["legislation_date_control"]["required_exact_as_of_date"] == "2026-08-14"
    assert audit["legislation_date_control"]["r4_legislation_propositions_proposed"] == 0
    assert audit["sale_of_goods_act_1979_effects_control"]["candidate_unapplied_effect_count"] == 1
    assert audit["schedule_3_control"]["whole_schedule_locator_carried_forward"] is False
    assert audit["schedule_3_control"]["exact_paragraphs_adopted"] == []

    cc27 = next(
        row
        for row in derivatives["records"]
        if "decision-making-for-charity-trustees" in row["authority_identity_id"]
    )
    assert cc27["raw_representation_file_sha256"] == (
        "c911599d93369ae7bf1ae8e0c27adef3eadb8bc71ceba707167f934b45dbf5e4"
    )
    assert cc27["modified_at"].startswith("2024-09-09")
    assert cc27["cc27_metadata_correction"] == "PUBLISHED_AND_LAST_UPDATED_2024_09_09"

    by_key = {
        (row["row_id"], component["component_ordinal"]): component
        for row in advisory["row_advisories"]
        for component in row["component_recommendations"]
    }
    for key in builder.LEGISLATION_DEFECT_KEYS:
        assert by_key[key]["after_propositions"] == []
        assert by_key[key]["legislation_proposition_control"] == {
            "r3_undated_legislation_proposition_revoked": True,
            "r4_legislation_proposition_proposed": False,
            "required_as_of_date_for_any_future_proposition": "2026-08-14",
        }
    for key in {
        ("live60-q37:issue-07", 1),
        ("live60-q37:issue-08", 1),
    }:
        assert (
            by_key[key]["schedule_3_atomic_locator_control"][
                "whole_schedule_3_locator_carried_forward"
            ]
            is False
        )


def test_r4_govuk_derivatives_are_byte_bound_and_parser_compatible(tmp_path: Path) -> None:
    advisory, _, derivatives, _, _, members = builder.build_advisory()
    derivative_by_id = {row["authority_identity_id"]: row for row in derivatives["records"]}
    for record in derivatives["records"]:
        raw = members[record["canonical_derivative_member"]]
        assert _sha256(raw) == record["canonical_derivative_file_sha256"]
        parsed = ParserRegistry.default().parse(raw, filename="official-guidance.md")
        assert parsed.status is ParseStatus.READY
        assert parsed.body_blocks

    charity = [
        component
        for row in advisory["row_advisories"]
        for component in row["component_recommendations"]
        if component["action"] == "OWNER_SCOPE_SUPERSESSION_TO_ATTRIBUTED_OFFICIAL_GUIDANCE"
    ]
    assert len(charity) == 6
    for component in charity:
        assert (
            component["exact_owner_scope_supersession_recommendation"]["original_issue_preserved"]
            is False
        )
        assert component["before_after_diff"]["unified_diff"]
        for span in component["frozen_evidence_span_proposals"]:
            derivative = derivative_by_id[span["authority_identity_id"]]
            assert (
                span["canonical_derivative_record_content_sha256"]
                == derivative["record_content_sha256"]
            )
            assert (
                span["canonical_derivative_file_sha256"]
                == derivative["canonical_derivative_file_sha256"]
            )
            assert all(
                excerpt["verified_in_parser_compatible_derivative"] is True
                for excerpt in span["supporting_excerpts"]
            )

    result = builder.publish(tmp_path / "sealed-r4")
    assert result["status"].startswith("NOT_APPROVAL_READY_")
    output = Path(result["output"])
    package = json.loads((output / builder.PACKAGE_NAME).read_text())
    for record in package["artifacts"]:
        assert _sha256((output / record["member"]).read_bytes()) == record["file_sha256"]
    checksum_lines = (output / builder.CHECKSUMS_NAME).read_text().splitlines()
    assert len(checksum_lines) == package["artifact_count"] + 1


def test_r4_scope_changes_are_exact_and_do_not_claim_release() -> None:
    advisory, _, _, _, _, _ = builder.build_advisory()
    by_key = {
        (row["row_id"], component["component_ordinal"]): component
        for row in advisory["row_advisories"]
        for component in row["component_recommendations"]
    }
    assert set(builder.CHARITY_AFTER) == {
        key
        for key, value in by_key.items()
        if value["action"] == "OWNER_SCOPE_SUPERSESSION_TO_ATTRIBUTED_OFFICIAL_GUIDANCE"
    }
    assert set(builder.MATTER_INTAKE) == {
        key
        for key, value in by_key.items()
        if value["action"] == "OWNER_SCOPE_SUPERSESSION_TO_NON_AUTHORITATIVE_MATTER_INTAKE"
    }
    excluded = by_key[("live30-q13:issue-02", 2)]
    assert excluded["row_specific_redundancy_and_coverage_proof"]
    assert all(
        authority["representation_file_sha256"]
        for proof in excluded["row_specific_redundancy_and_coverage_proof"]
        for authority in proof["authority_bindings"]
    )
    matter = by_key[("live30-q18:issue-05", 3)]
    assert matter["after_propositions"] == []
    assert matter["matter_information_gap_remains"] is True
    assert (
        matter["exact_owner_scope_supersession_recommendation"][
            "no_legal_rule_advice_citation_or_evidence_span"
        ]
        is True
    )
    assert advisory["answer_release_authorized"] is False
    assert advisory["answer_released"] is False
    assert advisory["qualification_run"] is False
