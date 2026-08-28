from __future__ import annotations

import hashlib
import json
import stat
from collections import Counter
from pathlib import Path

import pytest
from scripts import (
    build_v111_phase2a_held_missing_28_substantive_remediation_advisory_r2 as builder,
)


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


def _recommendations(advisory: dict) -> list[dict]:
    return [item for row in advisory["rows"] for item in row["blocker_recommendations"]]


def test_exact_28_row_41_blocker_ordinal_hash_partition_once(
    built: tuple[dict, dict, dict],
) -> None:
    advisory, _, _ = built
    r3 = json.loads(builder.r1_builder.R3_PATH.read_bytes())
    cohort = {row["row_id"] for row in advisory["rows"]}
    expected = {
        (
            row["row_id"],
            component["component_ordinal"],
            component["proposition_text_sha256"],
        )
        for row in r3["rows"]
        if row["row_id"] in cohort
        for component in row["blocking_components"]
    }
    recommendations = _recommendations(advisory)
    observed = {
        (
            item["row_id"],
            item["component_ordinal"],
            item["baseline_proposition_text_sha256"],
        )
        for item in recommendations
    }
    assert len(advisory["rows"]) == 28
    assert len(recommendations) == len(expected) == len(observed) == 41
    assert observed == expected
    assert advisory["artifact_content_sha256"] == _content_sha(advisory)


def test_corrective_partition_retains_legal_routes_and_only_six_meta_exclusions(
    built: tuple[dict, dict, dict],
) -> None:
    advisory, _, _ = built
    recommendations = _recommendations(advisory)
    assert Counter(item["action"] for item in recommendations) == {
        "REPLACE_WITH_EXACT_NARROW_SOURCE_BOUND_PROPOSITION": 11,
        "REPLACE_WITH_EXACT_SOURCE_BOUND_PROPOSITION_AND_RETAIN_RESIDUAL": 6,
        "RETAIN_OPERATIVE_LEGAL_ROUTE_BLOCKER": 18,
        "EXCLUDE_EXACT_NONLEGAL_OR_META_COMPONENT": 6,
    }
    excluded = {
        builder._key(item["row_id"], item["component_ordinal"])
        for item in recommendations
        if item["action"] == "EXCLUDE_EXACT_NONLEGAL_OR_META_COMPONENT"
    }
    assert excluded == set(builder.EXCLUSION_PROOFS)
    assert excluded.isdisjoint(builder.INVALID_R1_EXCLUSIONS)
    assert excluded.isdisjoint(builder.PROVE_OR_REVERSE)
    assert advisory["counts"]["residual_blocker_count"] == 24
    assert advisory["counts"]["residual_row_count"] == 22
    assert len(advisory["residual_blocker_keys"]) == 24
    for item in recommendations:
        assert item["missing_source_is_exclusion_proof"] is False
        if item["action"] == "EXCLUDE_EXACT_NONLEGAL_OR_META_COMPONENT":
            assert item["exclusion_proof_class"]
            assert item["exclusion_coverage_proof"]
            assert item["exclusion_does_not_remove_safety_boundary"] is True
            assert item["clears_exact_original_blocker_if_owner_adopted"] is True
        if item["action"] == "RETAIN_OPERATIVE_LEGAL_ROUTE_BLOCKER":
            assert item["residual_qualification_blocker"] is True
            assert item["clears_exact_original_blocker_if_owner_adopted"] is False
            assert item["evidence_span_proposals"] == []


def test_exact_independent_audit_defects_are_applied(
    built: tuple[dict, dict, dict],
) -> None:
    advisory, _, _ = built
    by_key = {
        builder._key(item["row_id"], item["component_ordinal"]): item
        for item in _recommendations(advisory)
    }

    self_defence = by_key[builder._key("live30-q04:issue-07", 1)]
    assert self_defence["action"] == "REPLACE_WITH_EXACT_NARROW_SOURCE_BOUND_PROPOSITION"
    assert {span["authority_identity_id"] for span in self_defence["evidence_span_proposals"]} == {
        "ukpga:1967:58",
        "ukpga:2008:4",
    }
    assert "Criminal Law Act 1967" in self_defence["after_propositions"][0]["proposition"]
    assert "Criminal Justice Act 1967" not in self_defence["after_propositions"][0]["proposition"]

    duress = by_key[builder._key("live30-q04:issue-07", 4)]
    assert duress["residual_qualification_blocker"] is True
    assert "do not state" in duress["after_propositions"][0]["proposition"]
    assert "murder or attempted murder" in duress["residual_scope"]

    q37 = by_key[builder._key("live60-q37:issue-06", 1)]
    assert q37["residual_qualification_blocker"] is True
    assert q37["evidence_span_proposals"][0]["exact_locators"] == [
        "regulation 1",
        "regulation 5(1)",
    ]
    assert "regs 6-46 as relevant" not in json.dumps(q37)
    assert "Parts 4-8" not in json.dumps(q37)

    q40 = by_key[builder._key("live60-q40:issue-09", 1)]
    assert q40["evidence_span_proposals"][0]["exact_locators"] == ["section 31(4)(a)-(b)"]
    assert q40["residual_qualification_blocker"] is True
    assert "interim relief" in q40["residual_scope"].lower()

    q50 = by_key[builder._key("live60-q50:issue-06", 5)]
    q50_text = json.dumps(q50)
    assert "AIG Europe" in q50_text
    assert "Various Eateries" in q50_text
    assert "actual insuring clause" in q50_text
    assert q50["residual_qualification_blocker"] is False

    assert by_key[builder._key("live60-q42:issue-03", 3)]["action"] == (
        "RETAIN_OPERATIVE_LEGAL_ROUTE_BLOCKER"
    )
    axa = by_key[builder._key("live60-q59:issue-17", 3)]
    assert "does not itself supply CAT aggregate-damages distribution rules" in json.dumps(axa)


def test_every_proposed_full_or_partial_has_primary_bytes_and_frozen_exact_spans(
    built: tuple[dict, dict, dict],
) -> None:
    advisory, _, _ = built
    binding_by_hash = {item["record_content_sha256"]: item for item in advisory["source_bindings"]}
    assert len(binding_by_hash) == advisory["counts"]["active_source_binding_count"] == 19
    used_hashes = set()
    for item in _recommendations(advisory):
        if item["action"].startswith("REPLACE"):
            assert item["after_propositions"]
            assert item["evidence_span_proposals"]
        for span in item["evidence_span_proposals"]:
            used_hashes.add(span["source_binding_content_sha256"])
            assert span["source_binding_content_sha256"] in binding_by_hash
            assert span["primary_official_bytes_bound"] is True
            assert span["exact_locators"]
            assert span["supporting_excerpts"]
            assert all(
                excerpt["verified_in_primary_official_bytes"] is True
                for excerpt in span["supporting_excerpts"]
            )
            assert span["jurisdiction"]
            assert span["source_role"]
            assert span["currentness_finding"]
            assert span["later_treatment_finding"]
            assert span["frozen_exact_span_for_owner_decision"] is True
            assert span["frozen_for_execution"] is False
    assert used_hashes == set(binding_by_hash)
    for binding in binding_by_hash.values():
        assert binding["primary_official_bytes_bound"] is True
        assert len(binding["representation_file_sha256"]) == 64
        assert len(binding["normalized_representation_text_sha256"]) == 64
        assert binding["answer_release_eligible"] is False


def test_nine_representation_links_are_component_exact_and_loose_links_removed(
    built: tuple[dict, dict, dict],
) -> None:
    _, manifest, _ = built
    records = {item["authority_identity_id"]: item for item in manifest["representations"]}
    assert len(records) == manifest["representation_count"] == 9
    unused = {
        "neutral-citation:[2014] UKSC 58",
        "official-url:https://www.justice.gov.uk/courts/procedure-rules/civil/rules/part-46-costs-special-cases",
        "official-url:https://www.justice.gov.uk/courts/procedure-rules/civil/rules/part-57a-business-and-property-courts/practice-direction-57ad-disclosure-in-the-business-and-property-courts",
    }
    for identity in unused:
        assert records[identity]["component_bindings"] == []
        assert records[identity]["affected_row_ids"] == []
        assert records[identity]["admission_recommended"] is False
    sra = records[
        "official-url:https://www.sra.org.uk/solicitors/standards-regulations/code-conduct-solicitors"
    ]
    assert [(item["row_id"], item["component_ordinal"]) for item in sra["component_bindings"]] == [
        ("live30-q05:issue-07", 1)
    ]
    for record in records.values():
        for link in record["component_bindings"]:
            assert len(link["baseline_proposition_text_sha256"]) == 64
            assert len(link["recommendation_content_sha256"]) == 64
            assert len(link["span_proposal_content_sha256"]) == 64
            assert link["exact_locators"]
    correction = manifest["identity_correction"]
    assert correction["accepted_identity_id"] == "uksi:2024:234"
    assert correction["accepted_exact_locators"] == ["regulation 1", "regulation 5(1)"]
    assert correction["rejected_identity_id"] == "uksi:2024:1377"
    assert correction["whole_part_or_regulations_6_to_46_locator_banned"] is True
    assert manifest["artifact_content_sha256"] == _content_sha(manifest)


def test_r1_is_explicitly_sealed_no_go(built: tuple[dict, dict, dict]) -> None:
    advisory, manifest, no_go = built
    assert advisory["r1_status"] == "NO_GO_NEVER_ADOPT_NEVER_CONSOLIDATE"
    assert no_go["status"] == "R1_NO_GO_NEVER_ADOPT_NEVER_CONSOLIDATE"
    assert no_go["r1_advisory_file_sha256"] == builder.R1_ADVISORY_FILE_SHA256
    assert no_go["r1_advisory_content_sha256"] == builder.R1_ADVISORY_CONTENT_SHA256
    assert no_go["r1_package_content_sha256"] == builder.R1_PACKAGE_CONTENT_SHA256
    assert no_go["r2_advisory_content_sha256"] == advisory["artifact_content_sha256"]
    assert no_go["r2_source_manifest_content_sha256"] == manifest["artifact_content_sha256"]
    assert no_go["artifact_content_sha256"] == _content_sha(no_go)


def test_recursive_65_field_no_execution_control_is_exhaustive(
    built: tuple[dict, dict, dict],
) -> None:
    advisory, manifest, no_go = built
    assert len(builder.STANDARD_NO_EXECUTION_FLAGS) == 56
    assert len(builder.NO_EXECUTION) == 65
    for artifact in (advisory, manifest, no_go):
        control = artifact["recursive_no_execution_control"]
        assert control["standard_authoritative_field_count"] == 56
        assert control["total_verified_field_count"] == 65
        assert builder.r1_builder._recursive_no_execution_violations(artifact) == []
        for field in builder.NO_EXECUTION:
            assert artifact[field] is False
    for field in builder.NO_EXECUTION:
        assert builder.r1_builder._recursive_no_execution_violations({"nested": {field: True}}) == [
            f"$.nested.{field}"
        ]


def test_publish_is_private_atomic_create_only_and_checksum_complete(
    tmp_path: Path,
) -> None:
    output = tmp_path / "immutable-r2"
    result = builder.publish(output)
    assert result["status"] == "CREATE_ONLY_NON_AUTHORIZING_NOT_EXECUTED"
    expected_names = {
        builder.ADVISORY_NAME,
        builder.SOURCE_MANIFEST_NAME,
        builder.R1_NO_GO_NAME,
        builder.PACKAGE_NAME,
        builder.CHECKSUMS_NAME,
    }
    assert {path.name for path in output.iterdir()} == expected_names
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in output.iterdir())
    assert not any(path.is_symlink() for path in output.rglob("*"))
    checksum_lines = (output / builder.CHECKSUMS_NAME).read_text().splitlines()
    assert len(checksum_lines) == 4
    for line in checksum_lines:
        expected_sha, name = line.split("  ", 1)
        assert hashlib.sha256((output / name).read_bytes()).hexdigest() == expected_sha
    package = json.loads((output / builder.PACKAGE_NAME).read_bytes())
    assert package["artifact_count"] == 3
    assert package["package_content_sha256"] == _content_sha(package, "package_content_sha256")
    assert builder.r1_builder._recursive_no_execution_violations(package) == []
    rendered = "\n".join(path.read_text() for path in output.iterdir())
    assert "/Users/" not in rendered
    assert "hltsang" not in rendered.casefold()
    assert "LegalBot-New" not in rendered
    with pytest.raises(FileExistsError):
        builder.publish(output)
