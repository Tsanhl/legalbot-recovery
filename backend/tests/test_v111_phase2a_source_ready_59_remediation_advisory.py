from __future__ import annotations

import hashlib
import json
import stat
from pathlib import Path

import pytest
from scripts import build_v111_phase2a_source_ready_59_remediation_advisory as builder


def _content_sha(value: dict, field: str = "artifact_content_sha256") -> str:
    material = dict(value)
    material.pop(field, None)
    raw = (
        json.dumps(material, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    return hashlib.sha256(raw).hexdigest()


def test_exact_source_ready_cohort_and_routes() -> None:
    advisory = builder.build_advisory()
    assert advisory["artifact_content_sha256"] == _content_sha(advisory)
    assert len(advisory["source_ready_row_ids"]) == 59
    assert advisory["source_ready_row_id_set_sha256"] == (
        "265da7032985c7d978d49c6cb3d602d28551743f9c453f22651a3863753b31a3"
    )
    assert advisory["counts"] == {
        "row_count": 59,
        "original_blocking_component_count": 72,
        "rewrite_row_count": 16,
        "rewrite_component_count": 17,
        "exact_exclusion_row_count": 43,
        "exact_exclusion_component_count": 55,
        "preexisting_full_component_retained_count": 87,
        "unique_authority_identity_count": 77,
        "materialization_plan_source_count": 52,
        "sealed_candidate_source_count": 25,
        "unresolved_source_identity_count": 0,
        "new_fallback_row_count": 0,
    }


def test_every_rewrite_has_verified_immutable_span_payload() -> None:
    advisory = builder.build_advisory()
    rewrites = []
    exclusions = []
    for row in advisory["row_advisories"]:
        for recommendation in row["component_recommendations"]:
            assert recommendation["applied"] is False
            assert recommendation["owner_adoption_required"] is True
            assert recommendation["recommendation_content_sha256"] == _content_sha(
                recommendation, "recommendation_content_sha256"
            )
            if recommendation["action"] == "REPLACE_WITH_EXACT_NARROW_SOURCE_TEXT":
                rewrites.append(recommendation)
                assert recommendation["after_propositions"]
                assert recommendation["frozen_evidence_span_proposals"]
                for span in recommendation["frozen_evidence_span_proposals"]:
                    assert span["span_proposal_content_sha256"] == _content_sha(
                        span, "span_proposal_content_sha256"
                    )
                    assert span["proposal_payload_immutable"] is True
                    assert span["owner_adopted"] is False
                    assert span["evidence_span_frozen_for_execution"] is False
                    assert all(
                        excerpt["verified_in_bound_source_bytes"] is True
                        for excerpt in span["supporting_excerpts"]
                    )
            else:
                exclusions.append(recommendation)
                assert recommendation["action"] == "EXCLUDE_EXACT_UNSUPPORTED_COMPONENT"
                assert recommendation["after_propositions"] == []
                assert recommendation["frozen_evidence_span_proposals"] == []
    assert len(rewrites) == 17
    assert len(exclusions) == 55


def test_all_sources_are_local_hash_verified_and_no_source_is_unresolved() -> None:
    advisory = builder.build_advisory()
    sources = advisory["source_byte_bindings"]
    assert len(sources) == 77
    assert len({source["authority_identity_id"] for source in sources}) == 77
    assert all(source["representation_byte_hash_verified"] is True for source in sources)
    origins = {source["source_origin"] for source in sources}
    assert origins == {
        "EXACT_OWNER_ADOPTED_MATERIALIZATION_PLAN",
        "SEALED_251_SOURCE_CANDIDATE",
    }
    assert all(
        source["record_content_sha256"] == _content_sha(source, "record_content_sha256")
        for source in sources
    )


def test_no_execution_or_fallback_authority_is_created() -> None:
    advisory = builder.build_advisory()
    for field, expected in builder.NO_EXECUTION_FLAGS.items():
        assert advisory[field] is expected
    assert advisory["decision_boundary"]["execution_chain_consumed"] == 0
    assert advisory["decision_boundary"]["execution_chain_remaining"] == 1
    assert advisory["decision_boundary"]["no_blanket_fallback"] is True
    assert all(row["fallback_eligible"] is False for row in advisory["row_advisories"])


def test_review_json_contains_no_absolute_or_old_project_paths() -> None:
    raw = json.dumps(builder.build_advisory(), ensure_ascii=False)
    assert "/Users/" not in raw
    assert "LegalBot-New" not in raw
    assert "hltsang" not in raw


def test_publish_is_create_only_and_private(tmp_path: Path) -> None:
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
    with pytest.raises(FileExistsError):
        builder.publish(output)
