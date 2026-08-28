from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from scripts import build_v111_phase2a_source_ready_59_substantive_advisory as builder


def _content_sha(value: dict, field: str = "artifact_content_sha256") -> str:
    material = dict(value)
    material.pop(field)
    raw = (
        json.dumps(material, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    return hashlib.sha256(raw).hexdigest()


@pytest.fixture(scope="module")
def built() -> tuple[dict, dict]:
    return builder.build_advisory()


def _components(advisory: dict) -> list[dict]:
    return [
        component
        for row in advisory["row_advisories"]
        for component in row["component_recommendations"]
    ]


def test_exact_r2_baseline_and_topology(built: tuple[dict, dict]) -> None:
    advisory, research = built
    assert advisory["artifact_content_sha256"] == _content_sha(advisory)
    assert research["artifact_content_sha256"] == _content_sha(research)
    assert advisory["r2_baseline_content_sha256"] == builder.R2_CONTENT_SHA256
    assert advisory["source_ready_row_id_set_sha256"] == (
        "265da7032985c7d978d49c6cb3d602d28551743f9c453f22651a3863753b31a3"
    )
    assert advisory["counts"]["row_count"] == 59
    assert advisory["counts"]["blocking_component_input_count"] == 72
    assert len(advisory["row_advisories"]) == 59
    assert len(_components(advisory)) == 72


def test_all_components_receive_exactly_one_fail_closed_outcome(
    built: tuple[dict, dict],
) -> None:
    advisory, _ = built
    components = _components(advisory)
    actions = [component["action"] for component in components]
    assert actions.count("OWNER_REWRITE_TO_EXACT_BOUND_SOURCE_TEXT") == 17
    assert actions.count("RETAIN_BLOCKER_RESEARCH_REQUIRED") == 55
    assert not any("EXCLUDE" in action for action in actions)
    keys = {(component["row_id"], component["component_ordinal"]) for component in components}
    assert len(keys) == 72
    assert set(builder.SAFE_AFTER) == set(builder.r1.REWRITES)


def test_rewrites_have_exact_diff_and_proposition_complete_bound_spans(
    built: tuple[dict, dict],
) -> None:
    advisory, research = built
    research_by_id = {row["authority_identity_id"]: row for row in research["records"]}
    bindings = {row["authority_identity_id"]: row for row in advisory["source_byte_bindings"]}
    rewrites = [
        component
        for component in _components(advisory)
        if component["action"] == "OWNER_REWRITE_TO_EXACT_BOUND_SOURCE_TEXT"
    ]
    assert len(rewrites) == 17
    for component in rewrites:
        key = (component["row_id"], component["component_ordinal"])
        after = component["after_propositions"][0]
        assert after["proposition"] == builder.SAFE_AFTER[key]
        assert (
            after["proposition_text_sha256"]
            == hashlib.sha256(after["proposition"].encode()).hexdigest()
        )
        assert after["proposed_support_fit"] == "FULL_IF_EXACT_OWNER_ADOPTED"
        assert component["component_support_complete_if_owner_adopted"] is True
        assert component["material_gap_after_owner_adoption"] is False
        assert component["answer_release_eligible"] is False
        assert component["retained_release_hold_codes"]
        assert component["frozen_evidence_span_proposals"]
        for span in component["frozen_evidence_span_proposals"]:
            identity = span["authority_identity_id"]
            assert (
                span["source_binding_content_sha256"] == bindings[identity]["record_content_sha256"]
            )
            assert (
                span["representation_file_sha256"]
                == bindings[identity]["representation_file_sha256"]
            )
            assert (
                span["dated_currentness_treatment_record_content_sha256"]
                == (research_by_id[identity]["record_content_sha256"])
            )
            assert span["evidence_span_frozen_for_execution"] is False
            assert all(
                excerpt["verified_in_bound_source_bytes"] is True
                for excerpt in span["supporting_excerpts"]
            )


def test_unsafe_r1_exclusions_are_not_revived(built: tuple[dict, dict]) -> None:
    advisory, _ = built
    by_key = {
        (component["row_id"], component["component_ordinal"]): component
        for component in _components(advisory)
    }
    r1_exclusions = {
        (row["row_id"], component["before"]["component_ordinal"])
        for row in builder.r1.build_advisory()["row_advisories"]
        for component in row["component_recommendations"]
        if component["action"] == "EXCLUDE_EXACT_UNSUPPORTED_COMPONENT"
    }
    assert len(r1_exclusions) == 55
    assert all(by_key[key]["action"] == "RETAIN_BLOCKER_RESEARCH_REQUIRED" for key in r1_exclusions)
    assert advisory["counts"]["retained_blocking_component_count"] == 55
    assert advisory["counts"]["residual_material_gap_row_count"] == 43
    assert len(advisory["residual_blocking_components"]) == 55


def test_currentness_and_later_treatment_are_dated_and_bounded(
    built: tuple[dict, dict],
) -> None:
    advisory, research = built
    assert research["research_date"] == "2026-08-28"
    assert research["source_count"] == 14
    records = {row["authority_identity_id"]: row for row in research["records"]}
    tas = records["neutral-citation:[2018] EWCA Crim 2603"]
    ingenious = records["neutral-citation:[2016] UKSC 54"]
    assert tas["result_count"] == 6
    assert len(tas["later_treatments"]) == 5
    assert ingenious["result_count"] == 13
    assert len(ingenious["later_treatments"]) == 4
    assert all(
        row["later_treatment_owner_recommendation"]
        == "NO_CONTRARY_TREATMENT_IN_EXACT_CITATION_RESULT_SET"
        for row in (tas, ingenious)
    )
    guidance = [
        row
        for row in research["records"]
        if row["snapshot_class"] == "LIVE_OFFICIAL_GUIDANCE_PAGE_CHECKED_2026_08_28"
    ]
    assert len(guidance) == 4
    assert all(row["live_response_sha256"] for row in guidance)
    statutes = [
        row
        for row in research["records"]
        if row["snapshot_class"] == "OFFICIAL_REVISED_TEXT_SNAPSHOT_AS_AT_2026_08_14"
    ]
    assert len(statutes) == 8
    assert all(
        "DATED_SOURCE_TEXT_ONLY_NO_BROADER_CURRENT_LAW_INFERENCE"
        in row["retained_release_hold_codes"]
        for row in statutes
    )
    assert advisory["decision_boundary"]["dated_or_historical_framing_required"] is True


def test_row_qualification_boundary_distinguishes_support_from_release_holds(
    built: tuple[dict, dict],
) -> None:
    advisory, _ = built
    rows = advisory["row_advisories"]
    support_complete = [row for row in rows if row["component_support_complete_if_owner_adopted"]]
    residual = [row for row in rows if row["material_gap_after_owner_adoption"]]
    assert len(support_complete) == 16
    assert len(residual) == 43
    assert all(row["qualification_eligible_if_owner_adopted"] for row in support_complete)
    assert all(row["answer_release_eligible"] is False for row in rows)
    assert advisory["status"] == (
        "SUBSTANTIVE_PARTIAL_PROGRESS_NOT_APPROVAL_READY_55_COMPONENT_BLOCKERS_REMAIN"
    )


def test_recursive_no_execution_boundary(built: tuple[dict, dict]) -> None:
    advisory, research = built
    assert len(builder.r2.NO_EXECUTION_FLAGS) == 56
    assert builder.r2._recursive_no_execution_violations(advisory) == []
    assert builder.r2._recursive_no_execution_violations(research) == []
    for field in builder.r2.NO_EXECUTION_FLAGS:
        assert advisory[field] is False
        assert research[field] is False


def test_publish_is_create_only_private_and_checksum_complete(
    tmp_path: Path, built: tuple[dict, dict]
) -> None:
    output = tmp_path / "substantive-r3"
    receipt = builder.publish(output)
    assert receipt["status"].endswith("55_COMPONENT_BLOCKERS_REMAIN")
    expected = {
        builder.ADVISORY_NAME,
        builder.RESEARCH_NAME,
        builder.PACKAGE_NAME,
        builder.CHECKSUMS_NAME,
    }
    assert {path.name for path in output.iterdir()} == expected
    assert output.stat().st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in output.iterdir())
    for line in (output / builder.CHECKSUMS_NAME).read_text().splitlines():
        expected_sha, name = line.split("  ", 1)
        assert hashlib.sha256((output / name).read_bytes()).hexdigest() == expected_sha
    with pytest.raises(FileExistsError):
        builder.publish(output)
