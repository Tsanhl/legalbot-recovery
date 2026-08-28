from __future__ import annotations

import hashlib
import json
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from scripts import build_v111_phase2a_authorityless_59_remediation_advisory_r3 as builder


@pytest.fixture(scope="module")
def advisory() -> dict:
    return builder.build_advisory()


def _content_sha(value: dict, field: str) -> str:
    material = dict(value)
    material.pop(field, None)
    raw = (
        json.dumps(material, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode()
    return hashlib.sha256(raw).hexdigest()


def _recommendations(advisory: dict) -> list[tuple[str, dict]]:
    return [
        (row["row_id"], item)
        for row in advisory["row_advisories"]
        for item in row["component_recommendations"]
    ]


def test_exact_59_row_80_blocker_topology_and_arithmetic(advisory: dict) -> None:
    assert advisory["artifact_content_sha256"] == _content_sha(
        advisory, "artifact_content_sha256"
    )
    assert len(advisory["row_ids"]) == len(set(advisory["row_ids"])) == 59
    assert advisory["row_id_set_sha256"] == (
        "45a35173be61cce0e472db89e979d9834125baa868bf96c78ae5e3f0fbb8f376"
    )
    counts = advisory["counts"]
    assert counts["original_blocking_component_count"] == 80
    assert counts["original_none_component_count"] == 63
    assert counts["original_partial_component_count"] == 17
    assert counts["safe_exact_exclusion_count"] == 4
    assert counts["safe_matter_application_split_count"] == 9
    assert counts["retained_original_component_blocker_count"] == 67
    assert counts["retained_partial_component_blocker_count"] == 17
    assert counts["retained_none_component_blocker_count"] == 50
    assert 4 + 9 + 67 == 80
    assert advisory["topology_derivation"]["blockers_dispositioned_exactly_once"] is True


def test_published_r3_is_the_exact_immutable_build(advisory: dict) -> None:
    path = builder.OUTPUT_ROOT / builder.ADVISORY_NAME
    assert hashlib.sha256(path.read_bytes()).hexdigest() == (
        "6cb7696369ae2a509af91c5dc9fa08b610fcc09d0fc6f93c42ada07734aa54e4"
    )
    published = json.loads(path.read_bytes())
    assert published == advisory
    assert published["artifact_content_sha256"] == (
        "a3e4cdfc84db910a23a1c26b471c4febac82910f45f1b30a09c3d5256cf3a18a"
    )


def test_all_80_upstream_blockers_are_dispositioned_once(advisory: dict) -> None:
    r3 = json.loads(builder.r2.R3_PATH.read_bytes())
    exact_rows = {row["row_id"]: row for row in r3["rows"]}
    observed = [
        (row_id, item["before"]["component_ordinal"], item["before"]["proposition_text_sha256"])
        for row_id, item in _recommendations(advisory)
    ]
    expected = [
        (row_id, component["component_ordinal"], component["proposition_text_sha256"])
        for row_id in advisory["row_ids"]
        for component in exact_rows[row_id]["blocking_components"]
    ]
    assert sorted(observed) == sorted(expected)
    assert len(observed) == len(set(observed)) == 80


def test_only_exact_13_actions_clear_component_level_blockers(advisory: dict) -> None:
    action_keys: dict[str, set[str]] = {}
    for row_id, item in _recommendations(advisory):
        assert item["recommendation_content_sha256"] == _content_sha(
            item, "recommendation_content_sha256"
        )
        key = f"{row_id}#component-{item['before']['component_ordinal']}"
        action_keys.setdefault(item["action"], set()).add(key)
    policy = advisory["semantic_policy"]
    assert action_keys["EXCLUDE_EXACT_FALSE_OR_OVERBROAD_COMPONENT"] == set(
        policy["safe_exclusion_component_keys"]
    )
    assert action_keys["SPLIT_REMOVE_CASE_FACT_APPLICATION_TO_MATTER_INTAKE"] == set(
        policy["safe_matter_application_component_keys"]
    )
    retained = {
        key
        for action, keys in action_keys.items()
        if action
        in {
            "SPLIT_MATTER_INTAKE_AND_RETAIN_LEGAL_RULE_BLOCKER",
            "RETAIN_COMPONENT_BLOCKER_EXACT_PROPOSITION_SUPPORT_REQUIRED",
        }
        for key in keys
    }
    assert len(retained) == 67
    assert retained.isdisjoint(
        set(policy["safe_exclusion_component_keys"])
        | set(policy["safe_matter_application_component_keys"])
    )


def test_42_mixed_components_preserve_both_intake_and_legal_blocker(advisory: dict) -> None:
    mixed = [
        item
        for _, item in _recommendations(advisory)
        if item["action"] == "SPLIT_MATTER_INTAKE_AND_RETAIN_LEGAL_RULE_BLOCKER"
    ]
    assert len(mixed) == 42
    for item in mixed:
        assert len(item["after_nonlegal_requirements"]) == 1
        assert len(item["after_legal_propositions"]) == 1
        retained = item["after_legal_propositions"][0]
        assert retained["proposition"] == item["before"]["proposition"]
        assert retained["status"] == "RETAINED_BLOCKER_EXACT_PROPOSITION_SUPPORT_REQUIRED"
        assert retained["may_be_cleared_by_unrelated_full_component"] is False
        assert item["component_material_blocker_after_owner_adoption"] is True


def test_all_partial_components_and_invalid_none_exclusions_remain_blocked(
    advisory: dict,
) -> None:
    retained_exclusions = [
        item
        for _, item in _recommendations(advisory)
        if item["action"] == "RETAIN_COMPONENT_BLOCKER_EXACT_PROPOSITION_SUPPORT_REQUIRED"
    ]
    assert len(retained_exclusions) == 25
    support = [item["before"]["support_fit"] for item in retained_exclusions]
    assert support.count("PARTIAL") == 17
    assert support.count("NONE") == 8
    for item in retained_exclusions:
        assert len(item["after_legal_propositions"]) == 1
        assert item["after_legal_propositions"][0]["proposition"] == item["before"][
            "proposition"
        ]
        assert item["component_material_blocker_after_owner_adoption"] is True


def test_four_issue_dimension_gaps_and_q12_source_gap_are_fail_closed(
    advisory: dict,
) -> None:
    rows = {row["row_id"]: row for row in advisory["row_advisories"]}
    assert {
        row_id
        for row_id, row in rows.items()
        if row["row_issue_dimension_coverage_holds"]
    } == {
        "live30-q12:issue-05",
        "live30-q13:issue-01",
        "live60-q47:issue-09",
        "live60-q60:issue-31",
    }
    for row_id in {
        "live30-q12:issue-05",
        "live30-q13:issue-01",
        "live60-q47:issue-09",
        "live60-q60:issue-31",
    }:
        hold = rows[row_id]["row_issue_dimension_coverage_holds"][0]
        assert hold["effect"] == "MATERIAL_SUPPORT_CLEARANCE_BLOCKED"
        assert hold["may_be_cleared_by_unrelated_full_component"] is False
        assert rows[row_id]["material_legal_support_gap"] is True
    assert rows["live30-q12:issue-06"]["source_binding_material_holds"] == [
        {
            "code": "RETAINED_FULL_SOURCE_BYTE_NOT_RESOLVED",
            "authority_identity_id": "neutral-citation:[2004] UKHL 22",
            "effect": "MATERIAL_SUPPORT_CLEARANCE_BLOCKED",
        }
    ]


def test_127_full_components_are_inventory_not_blanket_clearance(advisory: dict) -> None:
    full_components = [
        component
        for row in advisory["row_advisories"]
        for component in row["retained_full_component_inventory"]
    ]
    assert len(full_components) == 127
    relied = [
        component
        for component in full_components
        if component["coverage_role"] == "RELIED_ON_FOR_EXACT_ISSUE_DIMENSION_COVERAGE"
    ]
    assert relied
    assert all(component["does_not_clear_different_component"] is True for component in full_components)
    for component in relied:
        assert component["authorities"]
        assert all(
            authority["source_byte_binding_status"] == "EXACT_LOCAL_BYTE_BOUND"
            and authority["source_binding_content_sha256"]
            for authority in component["authorities"]
        )


def test_exact_source_roles_release_holds_and_readiness_partition(advisory: dict) -> None:
    bindings = advisory["source_byte_bindings"]
    assert len(bindings) == 23
    assert len({item["authority_identity_id"] for item in bindings}) == 23
    assert sum(item["relied_on_for_support"] for item in bindings) == 5
    assert sum(not item["relied_on_for_support"] for item in bindings) == 18
    for item in bindings:
        assert item["record_content_sha256"] == _content_sha(
            item, "record_content_sha256"
        )
        assert item["representation_byte_hash_verified"] is True
        assert item["source_admitted_by_r3"] is False
        assert item["answer_release_effect"] == "NONE"
        assert item["source_roles"]
    rows = {row["row_id"]: row for row in advisory["row_advisories"]}
    ready = {
        row_id
        for row_id, row in rows.items()
        if row["legal_component_coverage_complete_after_exact_action_if_owner_adopted"]
    }
    assert ready == builder.FUTURE_SUPPORT_READY_ROWS
    assert len(ready) == 4
    assert {row_id for row_id in ready if rows[row_id]["retained_release_hold_codes"]} == ready
    assert all(rows[row_id]["material_legal_support_gap"] is False for row_id in ready)
    assert all(rows[row_id]["qualification_eligible"] is False for row_id in ready)
    assert all(rows[row_id]["answer_release_eligible"] is False for row_id in ready)


def test_all_holds_lineage_and_56_no_execution_flags_are_preserved(advisory: dict) -> None:
    r3 = json.loads(builder.r2.R3_PATH.read_bytes())
    exact_rows = {row["row_id"]: row for row in r3["rows"]}
    for row in advisory["row_advisories"]:
        assert {
            hold["record_content_sha256"]
            for hold in row["all_unclassified_upstream_holds_retained"]
        } == {
            hold["record_content_sha256"]
            for hold in exact_rows[row["row_id"]]["unclassified_unresolved_holds"]
        }
    assert advisory["supersedes_advisory_content_sha256"] == builder.R2_ADVISORY_CONTENT_SHA256
    assert any(
        item["kind"] == "sealed_r2_builder_dependency"
        and item["file_sha256"] == builder.R2_BUILDER_FILE_SHA256
        for item in advisory["input_lineage"]
    )
    assert len(builder.NO_EXECUTION_FLAGS) == 56
    for field, expected in builder.NO_EXECUTION_FLAGS.items():
        assert expected is False
        assert advisory[field] is False


def test_review_artifact_has_no_absolute_or_backup_paths(advisory: dict) -> None:
    raw = json.dumps(advisory, ensure_ascii=False)
    assert "/Users/" not in raw
    assert "LegalBot-New" not in raw
    assert "hltsang" not in raw


def test_create_only_private_publication_and_complete_checksums(
    tmp_path: Path,
) -> None:
    output = tmp_path / "authorityless-r3"
    result = builder.publish(output)
    assert result["status"].startswith("IMMUTABLE_NO_GO")
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    assert {path.name for path in output.iterdir()} == {
        builder.ADVISORY_NAME,
        builder.PACKAGE_NAME,
        builder.CHECKSUMS_NAME,
    }
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in output.iterdir())
    checksum_lines = (output / builder.CHECKSUMS_NAME).read_text().splitlines()
    assert len(checksum_lines) == 2
    for line in checksum_lines:
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
    assert payload["counts"]["residual_material_blocker_row_count"] == 55
    assert payload["status"].startswith("IMMUTABLE_NO_GO")
