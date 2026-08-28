from __future__ import annotations

import hashlib
import json
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from scripts import build_v111_phase2a_authorityless_59_remediation_advisory as builder


def _content_sha(value: dict, field: str = "artifact_content_sha256") -> str:
    material = dict(value)
    material.pop(field, None)
    raw = (
        json.dumps(material, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode()
    return hashlib.sha256(raw).hexdigest()


def _all_recommendations(advisory: dict) -> list[dict]:
    return [
        recommendation
        for row in advisory["row_advisories"]
        for recommendation in row["component_recommendations"]
    ]


def test_exact_row_set_and_topology_correction() -> None:
    advisory = builder.build_advisory()
    assert advisory["artifact_content_sha256"] == _content_sha(advisory)
    assert len(advisory["row_ids"]) == 59
    assert advisory["row_id_set_sha256"] == (
        "45a35173be61cce0e472db89e979d9834125baa868bf96c78ae5e3f0fbb8f376"
    )
    assert advisory["counts"]["original_blocking_component_count"] == 80
    assert advisory["counts"]["original_none_component_count"] == 63
    assert advisory["counts"]["original_partial_component_count"] == 17
    assert advisory["counts"]["authority_list_empty_none_component_count"] == 61
    assert advisory["counts"]["authority_present_none_component_count"] == 2
    assert advisory["topology_correction"][
        "authority_present_but_relevance_insufficient_component_keys"
    ] == [
        "live30-q18:issue-08#component-5",
        "live30-q18:issue-08#component-7",
    ]
    assert advisory["topology_correction"]["no_blocker_omitted"] is True
    assert advisory["supersedes_advisory_content_sha256"] == (
        "a3950fca2a66e623d08379955acd84c2cc0c61e71ce2af3fa4568f2a51161768"
    )


def test_every_r3_blocker_is_dispositioned_exactly_once() -> None:
    advisory = builder.build_advisory()
    r3 = json.loads(builder.R3_PATH.read_bytes())
    r3_rows = {row["row_id"]: row for row in r3["rows"]}
    observed: list[tuple[str, int, str]] = []
    expected: list[tuple[str, int, str]] = []
    for row in advisory["row_advisories"]:
        for recommendation in row["component_recommendations"]:
            before = recommendation["before"]
            observed.append(
                (
                    row["row_id"],
                    before["component_ordinal"],
                    before["proposition_text_sha256"],
                )
            )
            assert recommendation["recommendation_content_sha256"] == _content_sha(
                recommendation, "recommendation_content_sha256"
            )
        for component in r3_rows[row["row_id"]]["blocking_components"]:
            expected.append(
                (
                    row["row_id"],
                    component["component_ordinal"],
                    component["proposition_text_sha256"],
                )
            )
    assert sorted(observed) == sorted(expected)
    assert len(observed) == len(set(observed)) == 80


def test_exact_actions_and_no_support_upgrade() -> None:
    advisory = builder.build_advisory()
    recommendations = _all_recommendations(advisory)
    actions = [item["action"] for item in recommendations]
    assert actions.count("EXCLUDE_EXACT_UNSUPPORTED_COMPONENT") == 29
    assert actions.count("RECLASSIFY_AS_NONLEGAL_MATTER_INFORMATION_REQUIREMENT") == 51
    for recommendation in recommendations:
        assert recommendation["after_legal_propositions"] == []
        assert recommendation["new_source_contracts"] == []
        assert recommendation["new_frozen_evidence_span_proposals"] == []
        assert recommendation["owner_adoption_required"] is True
        assert recommendation["applied"] is False
        if recommendation["before"]["support_fit"] == "PARTIAL":
            assert recommendation["action"] == "EXCLUDE_EXACT_UNSUPPORTED_COMPONENT"
            assert recommendation["reason_code"] == (
                "PARTIAL_SUPPORT_NOT_UPGRADED_ROW_RETAINS_FULL_COMPONENTS"
            )


def test_nonlegal_requirements_are_sealed_and_lane_restricted() -> None:
    advisory = builder.build_advisory()
    requirements = [
        requirement
        for recommendation in _all_recommendations(advisory)
        for requirement in recommendation["after_nonlegal_requirements"]
    ]
    assert len(requirements) == 51
    for requirement in requirements:
        assert requirement["requirement_content_sha256"] == _content_sha(
            requirement, "requirement_content_sha256"
        )
        assert requirement["lane"] == "NONAUTHORITATIVE_MATTER_INTAKE_ONLY"
        assert requirement["may_enter_legal_authority_lane"] is False
        assert requirement["may_create_evidence_span"] is False
        assert requirement["may_be_cited_as_law"] is False
        assert requirement["may_release_a_legal_claim"] is False


def test_inspected_sources_are_exact_local_bytes_but_create_no_binding() -> None:
    advisory = builder.build_advisory()
    bindings = advisory["inspected_source_byte_bindings"]
    assert len(bindings) == 18
    assert len({row["authority_identity_id"] for row in bindings}) == 18
    assert {row["source_origin"] for row in bindings} == {
        "EXACT_OWNER_ADOPTED_MATERIALIZATION_PLAN",
        "SEALED_251_SOURCE_CANDIDATE",
    }
    for binding in bindings:
        assert binding["record_content_sha256"] == _content_sha(
            binding, "record_content_sha256"
        )
        assert binding["representation_byte_hash_verified"] is True
        assert binding["inspection_only"] is True
        assert binding["new_source_proposed"] is False
        assert binding["new_evidence_span_proposed"] is False
        assert binding["support_fit_not_upgraded"] is True
    assert advisory["replacement_source_contract"] == {
        "new_primary_authority_bindings": [],
        "new_source_admission_proposals": [],
        "new_frozen_evidence_span_proposals": [],
        "reason": (
            "Every row retains pre-existing FULL legal components. Incomplete, "
            "irrelevant, unsupported, empirical, policy and case-specific outcome "
            "components are not upgraded by relevance or by additional authority."
        ),
    }


def test_every_row_retains_preexisting_full_support_and_all_holds() -> None:
    advisory = builder.build_advisory()
    r3 = json.loads(builder.R3_PATH.read_bytes())
    r3_rows = {row["row_id"]: row for row in r3["rows"]}
    full_total = 0
    for row in advisory["row_advisories"]:
        assert row["preexisting_full_components_retained"]
        full_total += len(row["preexisting_full_components_retained"])
        assert {
            hold["record_content_sha256"]
            for hold in row["all_unclassified_holds_retained"]
        } == {
            hold["record_content_sha256"]
            for hold in r3_rows[row["row_id"]]["unclassified_unresolved_holds"]
        }
        assert row["fallback_eligible"] is False
        assert row["owner_decision_applied"] is False
    assert full_total == advisory["counts"][
        "preexisting_full_component_retained_count"
    ] == 127


def test_no_execution_fallback_or_phase2b_authority() -> None:
    advisory = builder.build_advisory()
    assert len(builder.NO_EXECUTION_FLAGS) == 56
    assert {
        "all585_qualification_authorized",
        "o04_authorized",
        "o04_run",
        "owner_adoption_recorded",
        "owner_certification60_authorized",
        "owner_certification60_run",
        "owner_decision_application_authorized",
        "qualification_run",
        "retrieval_reattestation_authorized",
        "validation30_unsealed",
    } <= builder.NO_EXECUTION_FLAGS.keys()
    for field, expected in builder.NO_EXECUTION_FLAGS.items():
        assert advisory[field] is expected
    assert advisory["decision_boundary"]["one_execution_chain_total"] == 1
    assert advisory["decision_boundary"]["execution_chain_consumed"] == 0
    assert advisory["decision_boundary"]["execution_chain_remaining"] == 1
    assert advisory["decision_boundary"]["no_blanket_fallback"] is True
    assert advisory["counts"]["new_fallback_row_count"] == 0
    assert advisory["counts"]["unresolved_blocker_count_if_exact_recommendations_owner_adopted"] == 0


def test_review_json_has_no_absolute_or_old_project_paths() -> None:
    raw = json.dumps(builder.build_advisory(), ensure_ascii=False)
    assert "/Users/" not in raw
    assert "LegalBot-New" not in raw
    assert "hltsang" not in raw


def test_publish_is_create_only_private_and_checksum_complete(tmp_path: Path) -> None:
    output = tmp_path / "advisory"
    result = builder.publish(output)
    assert result["status"].startswith("CREATE_ONLY")
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    assert {path.name for path in output.iterdir()} == {
        builder.ADVISORY_NAME,
        builder.PACKAGE_NAME,
        builder.CHECKSUMS_NAME,
    }
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in output.iterdir())
    checksum_lines = (output / builder.CHECKSUMS_NAME).read_text().splitlines()
    assert len(checksum_lines) == 2
    assert {line.split("  ", 1)[1] for line in checksum_lines} == {
        builder.ADVISORY_NAME,
        builder.PACKAGE_NAME,
    }
    with pytest.raises(FileExistsError):
        builder.publish(output)


def test_publish_failure_before_rename_leaves_no_partial_final_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "advisory"

    def fail_fsync(_descriptor: int) -> None:
        raise OSError("injected fsync failure")

    monkeypatch.setattr(builder.os, "fsync", fail_fsync)
    with pytest.raises(OSError, match="injected fsync failure"):
        builder.publish(output)
    assert not output.exists()
    assert list(tmp_path.iterdir()) == []


def test_direct_cli_runs_from_outside_repository(tmp_path: Path) -> None:
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
    assert payload["counts"]["original_blocking_component_count"] == 80
