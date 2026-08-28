from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from scripts import build_v111_phase2a_source_ready_59_remediation_advisory_r2 as builder


def _content_sha(value: dict, field: str = "artifact_content_sha256") -> str:
    material = dict(value)
    material.pop(field)
    raw = (
        json.dumps(material, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    return hashlib.sha256(raw).hexdigest()


@pytest.fixture(scope="module")
def built() -> tuple[dict, dict, dict]:
    return builder.build_advisory()


def test_boundary_is_derived_from_three_sealed_partitions(
    built: tuple[dict, dict, dict],
) -> None:
    advisory, topology, _ = built
    assert topology["artifact_content_sha256"] == _content_sha(topology)
    assert topology["derivation"] == ("SEALED_R3_MINUS_EXPLICIT_AUTHORITYLESS_AND_HELD_PARTITIONS")
    assert topology["partition_sets_disjoint"] is True
    assert topology["partition_sets_exhaust_r3"] is True
    assert topology["r3_row_count"] == 146
    assert topology["authorityless_row_count"] == 59
    assert topology["held_missing_row_count"] == 28
    assert topology["source_ready_row_count"] == 59
    assert topology["source_ready_blocking_component_count"] == 72
    assert topology["source_ready_row_id_set_sha256"] == (
        "265da7032985c7d978d49c6cb3d602d28551743f9c453f22651a3863753b31a3"
    )
    assert advisory["source_ready_row_ids"] == topology["source_ready_row_ids"]


def test_every_partial_or_none_component_is_retained(
    built: tuple[dict, dict, dict],
) -> None:
    advisory, _, _ = built
    recommendations = [
        component
        for row in advisory["row_advisories"]
        for component in row["component_recommendations"]
    ]
    assert len(recommendations) == 72
    assert {row["upstream_support_fit"] for row in recommendations} <= {
        "PARTIAL",
        "NONE",
    }
    assert {row["action"] for row in recommendations} == {"RETAIN_BLOCKER_RESEARCH_REQUIRED"}
    assert all(row["after_propositions"] == [] for row in recommendations)
    assert all(row["frozen_evidence_span_proposals"] == [] for row in recommendations)
    assert advisory["counts"]["retained_blocking_component_count"] == 72
    assert advisory["counts"]["excluded_component_count"] == 0
    assert advisory["counts"]["narrowed_component_count"] == 0
    assert advisory["counts"]["upgraded_to_full_component_count"] == 0
    assert advisory["decision_boundary"]["preexisting_full_components_used_as_redundancy"] is False
    assert all(row["material_gap"] is True for row in advisory["row_advisories"])
    assert all(row["qualification_eligible"] is False for row in advisory["row_advisories"])


def test_no_go_rows_and_span_defects_are_explicitly_reversed(
    built: tuple[dict, dict, dict],
) -> None:
    advisory, _, audit = built
    assert audit["artifact_content_sha256"] == _content_sha(audit)
    assert audit["superseded_r1_content_sha256"] == (
        "df95f0ddfa8cad3117cef0f6bd64781ffe299c377e65d4e3ea8ee9d358d89725"
    )
    assert audit["superseded_r1_preserved"] is True
    assert audit["superseded_r1_disposition"] == "NO_GO_NEVER_APPLY_NEVER_CONSOLIDATE"
    assert (
        audit["independent_audit_text_sha256"]
        == hashlib.sha256(audit["independent_audit_text"].encode()).hexdigest()
    )
    by_id = {row["row_id"]: row for row in advisory["row_advisories"]}
    for row_id in builder.PRIMARY_CLEAR_LOSS_ROWS:
        assert all(
            "P0_PRIMARY_CLEAR_LOSS_REVERSED" in item["audit_tags"]
            for item in by_id[row_id]["component_recommendations"]
        )
    for row_id in builder.ADDITIONAL_CLEAR_LOSS_ROWS:
        assert all(
            "P0_ADDITIONAL_CLEAR_LOSS_REVERSED" in item["audit_tags"]
            for item in by_id[row_id]["component_recommendations"]
        )
    for row_id in builder.INCOMPLETE_REWRITE_ROWS:
        assert all(
            "P0_INCOMPLETE_REWRITE_REVOKED" in item["audit_tags"]
            for item in by_id[row_id]["component_recommendations"]
        )
    for row_id, ordinal in builder.EXCERPT_OMISSION_COMPONENTS:
        item = next(
            item
            for item in by_id[row_id]["component_recommendations"]
            if item["component_ordinal"] == ordinal
        )
        assert "P1_INCOMPLETE_EXCERPT_SPAN_REVOKED" in item["audit_tags"]


def test_sources_are_byte_bound_role_classified_and_hash_complete(
    built: tuple[dict, dict, dict],
) -> None:
    advisory, _, _ = built
    sources = advisory["source_byte_bindings"]
    assert len(sources) == 77
    assert all(source["representation_byte_hash_verified"] is True for source in sources)
    assert all(source["representation_file_sha256"] for source in sources)
    assert all(source["derived_normalized_representation_text_sha256"] for source in sources)
    missing_upstream = [
        source for source in sources if source["upstream_canonical_content_sha256"] is None
    ]
    assert len(missing_upstream) == 8
    assert all(
        source["canonical_hash_resolution"] == "DERIVED_TEXT_HASH_BOUND_UPSTREAM_CANONICAL_ABSENT"
        for source in missing_upstream
    )
    gov_guidance = [
        source
        for source in sources
        if source["official_source_role"] == "OFFICIAL_REGULATOR_GUIDANCE_NON_PRIMARY"
    ]
    assert len(gov_guidance) == 4
    assert all(
        source["authority_identity_id"].startswith("official-url:https://gov.uk/")
        for source in gov_guidance
    )
    assert {source["official_source_role"] for source in sources} == {
        "PRIMARY_JUDGMENT_OFFICIAL",
        "PRIMARY_LEGISLATION_OFFICIAL",
        "OFFICIAL_REGULATOR_GUIDANCE_NON_PRIMARY",
    }


def test_qualification_holds_are_retained_per_source(
    built: tuple[dict, dict, dict],
) -> None:
    advisory, _, _ = built
    counts = advisory["counts"]
    assert counts["currentness_hold_row_count"] == 28
    assert counts["later_treatment_hold_row_count"] == 19
    assert counts["treatment_status_text_variant_hold_row_count"] == 2
    assert counts["extent_hold_row_count"] == 11
    assert counts["effects_or_commencement_hold_row_count"] == 17
    assert counts["jurisdiction_hold_row_count"] == 5
    ledger = advisory["per_source_qualification_hold_resolutions"]
    assert len(ledger) == 77
    assert all(item["owner_adoption_alone_cannot_make_full"] is True for item in ledger)
    assert all(
        resolution["resolution"] == "RETAIN_OPERATIVE_UNRESOLVED_QUALIFIED_REVIEW_REQUIRED"
        for item in ledger
        for resolution in item["category_resolutions"]
    )
    correction = advisory["locator_corrections"][0]
    assert correction["authority_identity_id"] == "uksi:2001:1090"
    assert correction["superseded_r1_locator"] == "regulation 7 and Schedule 2"
    assert correction["corrected_locator"] == "regulation 7(1)-(10)"
    assert correction["r2_use"] == "LOCATOR_CORRECTION_ONLY_COMPONENT_REMAINS_BLOCKED"


def test_exhaustive_recursive_no_execution_control(
    built: tuple[dict, dict, dict],
) -> None:
    advisory, _, audit = built
    assert len(builder.NO_EXECUTION_FLAGS) == 56
    assert advisory["recursive_no_execution_control"]["authoritative_field_count"] == 56
    assert builder._recursive_no_execution_violations(advisory) == []
    assert builder._recursive_no_execution_violations(audit) == []
    for field in builder.NO_EXECUTION_FLAGS:
        assert advisory[field] is False
        assert audit[field] is False
    probe = {"nested": {"embedding_run": True}}
    assert builder._recursive_no_execution_violations(probe) == ["$.nested.embedding_run"]


def test_publish_is_create_only_and_checksum_complete(
    tmp_path: Path, built: tuple[dict, dict, dict]
) -> None:
    output = tmp_path / "r2"
    receipt = builder.publish(output)
    assert receipt["status"] == "CREATE_ONLY_R2_RETAINS_ALL_72_BLOCKERS_NOT_OWNER_ADOPTED"
    expected = {
        builder.TOPOLOGY_NAME,
        builder.AUDIT_NAME,
        builder.ADVISORY_NAME,
        builder.PACKAGE_NAME,
        builder.CHECKSUMS_NAME,
    }
    assert {path.name for path in output.iterdir()} == expected
    checksum_lines = (output / builder.CHECKSUMS_NAME).read_text().splitlines()
    assert len(checksum_lines) == 4
    for line in checksum_lines:
        expected_sha, name = line.split("  ", 1)
        assert hashlib.sha256((output / name).read_bytes()).hexdigest() == expected_sha
    with pytest.raises(FileExistsError):
        builder.publish(output)
