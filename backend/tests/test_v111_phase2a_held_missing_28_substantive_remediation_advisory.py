from __future__ import annotations

import hashlib
import json
import stat
from collections import Counter
from pathlib import Path

import pytest
from scripts import (
    build_v111_phase2a_held_missing_28_substantive_remediation_advisory as builder,
)


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


def test_exact_28_row_41_blocker_partition_is_covered_once(
    built: tuple[dict, dict],
) -> None:
    advisory, _ = built
    r3 = json.loads(builder.R3_PATH.read_bytes())
    expected = {
        (
            row["row_id"],
            component["component_ordinal"],
            component["proposition_text_sha256"],
        )
        for row in r3["rows"]
        if row["row_id"] in {item["row_id"] for item in advisory["rows"]}
        for component in row["blocking_components"]
    }
    observed = {
        (
            recommendation["row_id"],
            recommendation["component_ordinal"],
            recommendation["baseline_proposition_text_sha256"],
        )
        for row in advisory["rows"]
        for recommendation in row["blocker_recommendations"]
    }
    assert len(advisory["rows"]) == 28
    assert len(expected) == len(observed) == 41
    assert observed == expected
    assert advisory["artifact_content_sha256"] == _content_sha(advisory)


def test_rewrite_and_exclusion_contracts_are_complete(
    built: tuple[dict, dict],
) -> None:
    advisory, _ = built
    recommendations = [item for row in advisory["rows"] for item in row["blocker_recommendations"]]
    counts = Counter(item["action"] for item in recommendations)
    assert counts == {
        "REPLACE_WITH_EXACT_NARROW_SOURCE_BOUND_PROPOSITION": 17,
        "EXCLUDE_EXACT_UNSUPPORTED_COMPONENT": 24,
    }
    row_categories = Counter()
    for row in advisory["rows"]:
        actions = {item["action"] for item in row["blocker_recommendations"]}
        if len(actions) == 2:
            row_categories["MIXED_REWRITE_AND_EXCLUSION"] += 1
        elif next(iter(actions)).startswith("REPLACE"):
            row_categories["REWRITE_ONLY"] += 1
        else:
            row_categories["EXCLUSION_ONLY"] += 1
        assert row["residual_qualification_blocker_predeclared"] is False
        assert row["answer_release_eligible"] is False
    assert row_categories == {
        "REWRITE_ONLY": 8,
        "EXCLUSION_ONLY": 14,
        "MIXED_REWRITE_AND_EXCLUSION": 6,
    }

    for item in recommendations:
        assert item["clears_exact_original_blocker_if_owner_adopted"] is True
        assert item["owner_adopted"] is False
        assert item["applied"] is False
        if item["action"].startswith("REPLACE"):
            assert item["after_propositions"]
            assert item["evidence_span_proposals"]
            for span in item["evidence_span_proposals"]:
                assert span["primary_official_bytes_bound"] is True
                assert span["locator_attested_by_sealed_upstream"] is True
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
                assert span["proposal_payload_immutable"] is True
                assert span["frozen_for_execution"] is False
        else:
            assert item["after_propositions"] == []
            assert item["evidence_span_proposals"] == []
            assert item["issue_coverage"]


def test_every_rewrite_source_is_primary_byte_and_text_bound(
    built: tuple[dict, dict],
) -> None:
    advisory, _ = built
    sources = advisory["source_bindings"]
    assert len(sources) == advisory["counts"]["unique_rewrite_source_count"] == 19
    assert {source["authority_identity_id"] for source in sources} == set(
        builder.SOURCE_SUPPORTING_EXCERPTS
    )
    for source in sources:
        assert source["primary_official_bytes_bound"] is True
        assert len(source["representation_file_sha256"]) == 64
        assert len(source["normalized_representation_text_sha256"]) == 64
        assert source["representation_text_extraction_mode"]
        assessment = source["legal_assessment_recommendation"]
        assert assessment["jurisdiction"]
        assert assessment["source_role"]
        assert assessment["currentness_finding"]
        assert assessment["later_treatment_finding"]
        assert source["assessment_owner_adopted"] is False
        assert source["answer_release_eligible"] is False


def test_four_formerly_retained_rows_have_only_permitted_substitutes(
    built: tuple[dict, dict],
) -> None:
    advisory, _ = built
    by_id = {row["row_id"]: row for row in advisory["rows"]}

    def identities(row_id: str) -> set[str]:
        return {
            span["authority_identity_id"]
            for item in by_id[row_id]["blocker_recommendations"]
            for span in item["evidence_span_proposals"]
        }

    assert identities("live30-q28:issue-05") == {"neutral-citation:[2025] UKSC 22"}
    assert identities("live60-q40:issue-09") == {"ukpga:1981:54"}
    assert identities("live60-q42:issue-03") == {"neutral-citation:[2026] EWHC 877 (Comm)"}
    assert identities("live60-q50:issue-06") == {
        "neutral-citation:[2017] UKSC 18",
        "neutral-citation:[2024] EWCA Civ 10",
    }
    rendered = json.dumps(
        {
            key: by_id[key]["blocker_recommendations"]
            for key in (
                "live30-q28:issue-05",
                "live60-q40:issue-09",
                "live60-q42:issue-03",
                "live60-q50:issue-06",
            )
        },
        sort_keys=True,
    )
    assert "Etridge representation" in rendered
    assert "interim-relief test" in rendered
    assert "employee-waiver formulation" in rendered
    assert "Lloyds TSB bytes are not relied upon" in rendered


def test_nine_representations_and_si_identity_correction_are_exact(
    built: tuple[dict, dict],
) -> None:
    _, manifest = built
    baseline = json.loads(builder.BASELINE_SOURCE_MANIFEST_PATH.read_bytes())
    expected = {
        record["authority_identity_id"]: record
        for record in baseline["records"]
        if record["evidence_role"] == "PROPOSED_OWNER_ADMISSION_REPRESENTATION"
    }
    observed = {record["authority_identity_id"]: record for record in manifest["representations"]}
    assert len(expected) == len(observed) == 9
    assert set(observed) == set(expected)
    for identity, record in observed.items():
        upstream = expected[identity]
        assert record["representation_file_sha256"] == upstream["raw_sha256"]
        assert record["source_binding"]["representation_file_sha256"] == upstream["raw_sha256"]
        assert (
            record["source_binding_content_sha256"]
            == record["source_binding"]["record_content_sha256"]
        )
        assert record["representation_byte_identity_verified"] is True
        assert record["source_admitted"] is False
        assert record["materialized"] is False
        assert record["indexed"] is False
        assert record["embedded"] is False
    correction = manifest["identity_correction"]
    assert correction["accepted_identity_id"] == "uksi:2024:234"
    assert correction["rejected_identity_id"] == "uksi:2024:1377"
    assert correction["rejected_mapping"] is True
    assert manifest["artifact_content_sha256"] == _content_sha(manifest)


def test_recursive_no_execution_control_is_exhaustive(
    built: tuple[dict, dict],
) -> None:
    advisory, manifest = built
    assert len(builder.STANDARD_NO_EXECUTION_FLAGS) == 56
    assert len(builder.NO_EXECUTION) == 65
    for artifact in (advisory, manifest):
        control = artifact["recursive_no_execution_control"]
        assert control["standard_authoritative_field_count"] == 56
        assert control["total_verified_field_count"] == 65
        assert builder._recursive_no_execution_violations(artifact) == []
        for field in builder.NO_EXECUTION:
            assert artifact[field] is False
    for field in builder.NO_EXECUTION:
        assert builder._recursive_no_execution_violations({"nested": {field: True}}) == [
            f"$.nested.{field}"
        ]


def test_publish_is_private_create_only_and_checksum_complete(tmp_path: Path) -> None:
    output = tmp_path / "immutable-r1"
    result = builder.publish(output)
    assert result["status"] == "CREATE_ONLY_NON_AUTHORIZING_NOT_EXECUTED"
    expected_names = {
        builder.ADVISORY_NAME,
        builder.SOURCE_MANIFEST_NAME,
        builder.PACKAGE_NAME,
        builder.CHECKSUMS_NAME,
    }
    assert {path.name for path in output.iterdir()} == expected_names
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in output.iterdir())
    assert not any(path.is_symlink() for path in output.rglob("*"))
    checksum_lines = (output / builder.CHECKSUMS_NAME).read_text().splitlines()
    assert len(checksum_lines) == 3
    for line in checksum_lines:
        expected_sha, name = line.split("  ", 1)
        assert hashlib.sha256((output / name).read_bytes()).hexdigest() == expected_sha
    package = json.loads((output / builder.PACKAGE_NAME).read_bytes())
    assert package["package_content_sha256"] == _content_sha(package, "package_content_sha256")
    assert builder._recursive_no_execution_violations(package) == []
    rendered = "\n".join(path.read_text() for path in output.iterdir())
    assert "/Users/" not in rendered
    assert "hltsang" not in rendered.casefold()
    assert "LegalBot-New" not in rendered
    with pytest.raises(FileExistsError):
        builder.publish(output)
