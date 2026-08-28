from __future__ import annotations

import hashlib
import json
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from scripts import build_v111_phase2a_mutu_alternative_support_advisory as builder


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    assert isinstance(value, dict)
    return value


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture(scope="module")
def built_package(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, dict[str, Any]]:
    review_root = tmp_path_factory.mktemp("mutu-alternative-review")
    output = review_root / builder.DEFAULT_OUTPUT_ROOT.name
    original_review_root = builder.OUTPUT_REVIEW_ROOT
    builder.OUTPUT_REVIEW_ROOT = review_root
    try:
        result = builder.build_advisory(
            output_root=output,
            created_at=datetime(2026, 8, 28, 13, 0, tzinfo=UTC),
        )
        yield output, result
    finally:
        builder.OUTPUT_REVIEW_ROOT = original_review_root


def test_package_is_sealed_private_and_checksum_complete(
    built_package: tuple[Path, dict[str, Any]],
) -> None:
    output, result = built_package
    assert sorted(path.name for path in output.iterdir()) == [
        builder.ADVISORY_NAME,
        builder.PACKAGE_NAME,
        builder.CHECKSUMS_NAME,
    ]
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    for path in output.iterdir():
        assert not path.is_symlink()
        assert stat.S_IMODE(path.stat().st_mode) == 0o600

    advisory = _load(output / builder.ADVISORY_NAME)
    package = _load(output / builder.PACKAGE_NAME)
    advisory_seal = advisory.pop("artifact_content_sha256")
    package_seal = package.pop("package_content_sha256")
    assert advisory_seal == builder._sealed(advisory)
    assert package_seal == builder._sealed(package)
    assert advisory_seal == result["advisory_content_sha256"]
    assert package_seal == result["package_content_sha256"]

    expected_checksums = (
        f"{_sha256(output / builder.ADVISORY_NAME)}  {builder.ADVISORY_NAME}\n"
        f"{_sha256(output / builder.PACKAGE_NAME)}  {builder.PACKAGE_NAME}\n"
    )
    assert (output / builder.CHECKSUMS_NAME).read_text() == expected_checksums


def test_three_changed_transport_holds_are_distinct_and_final(
    built_package: tuple[Path, dict[str, Any]],
) -> None:
    output, _ = built_package
    advisory = _load(output / builder.ADVISORY_NAME)
    holds = advisory["changed_single_attempt_transport_holds"]
    assert [item["revision"] for item in holds] == ["r1", "r2", "r3"]
    assert len({item["attempt_identity_sha256"] for item in holds}) == 3
    assert len({item["failure_fingerprint"] for item in holds}) == 3
    assert all(item["attempt_count"] == 1 for item in holds)
    assert all(item["retry_run"] is False for item in holds)
    assert all(item["hold_retained"] is True for item in holds)

    mutu = advisory["mutu_defective_representation_and_final_hold"]
    assert mutu["proposal_id"] == builder.MUTU_PROPOSAL_SPEC["proposal_id"]
    assert mutu["audit_verdict"] == "FAIL"
    assert mutu["representation_excluded"] is True
    assert mutu["final_transport_hold"] is True
    assert mutu["retry_prohibited"] is True
    assert mutu["fetch_prohibited"] is True
    assert mutu["source_admission_authorized"] is False
    assert mutu["legal_claim_release_prohibited"] is True


def test_exact_two_essay_rows_and_component_hashes_are_bound(
    built_package: tuple[Path, dict[str, Any]],
) -> None:
    output, _ = built_package
    advisory = _load(output / builder.ADVISORY_NAME)
    rows = {item["row_id"]: item for item in advisory["row_outcomes"]}
    assert set(rows) == set(builder.ROW_SPECS)
    for row_id, expected in builder.ROW_SPECS.items():
        row = rows[row_id]
        assert row["question_kind"] == "ESSAY"
        assert row["decision_content_sha256"] == expected["decision_content_sha256"]
        assert (
            row["proposition_record_content_sha256"]
            == expected["proposition_record_content_sha256"]
        )
        assert row["queue_record_content_sha256"] == expected["queue_record_content_sha256"]
        assert row["row_outcome"] == "IRREDUCIBLE_LEGAL_AUTHORITY_BLOCKER"
        assert row["row_proposition_complete"] is False
        assert row["safe_fallback_eligible"] is False
        assert row["safe_fallback_prohibited"] is True
        for actual, component in zip(row["components"], expected["components"], strict=True):
            assert actual["proposition"] == component["proposition"]
            assert actual["proposition_content_sha256"] == builder._sealed(
                {"proposition": component["proposition"]}
            )


def test_q53_issue04_keeps_only_supported_subsets(
    built_package: tuple[Path, dict[str, Any]],
) -> None:
    output, _ = built_package
    advisory = _load(output / builder.ADVISORY_NAME)
    row = next(item for item in advisory["row_outcomes"] if item["row_id"] == "live60-q53:issue-04")
    assert [item["alternative_support_outcome"] for item in row["components"]] == [
        "SUPPORTED_ONLY_TO_ORIGINAL_PARTIAL_SCOPE",
        "FULLY_SUPPORTED_WITHIN_ENGLISH_ACT_SCOPE",
        "PARTIAL_MECHANICS_ONLY_IRREDUCIBLE_ECHR_GAP",
    ]
    assert row["components"][0]["support_refs"] == ["braganza"]
    assert row["components"][1]["support_refs"] == ["arbitration_act_1996"]
    assert row["components"][2]["support_refs"] == ["cas_code"]
    assert len(row["components"][2]["unsupported_claims"]) == 3


def test_q53_issue11_retains_irreducible_convention_gap(
    built_package: tuple[Path, dict[str, Any]],
) -> None:
    output, _ = built_package
    advisory = _load(output / builder.ADVISORY_NAME)
    row = next(item for item in advisory["row_outcomes"] if item["row_id"] == "live60-q53:issue-11")
    assert [item["alternative_support_outcome"] for item in row["components"]] == [
        "FULLY_SUPPORTED_AS_RULE_TEXT_NOT_SWISS_LAW_DETAIL",
        "FULLY_SUPPORTED_WITHIN_ENGLISH_ACT_SCOPE",
        "IRREDUCIBLE_ECHR_AND_SWISS_SUPERVISION_GAP",
    ]
    assert row["components"][2]["support_refs"] == []
    assert len(row["components"][2]["unsupported_claims"]) == 3
    assert advisory["irreducible_blocker"]["alternative_source_selected"] is False
    assert advisory["irreducible_blocker"]["qualification_eligible"] is False


def test_verified_support_sources_bind_exact_hashes_and_locators(
    built_package: tuple[Path, dict[str, Any]],
) -> None:
    output, _ = built_package
    advisory = _load(output / builder.ADVISORY_NAME)
    sources = {item["source_ref"]: item for item in advisory["verified_local_support_sources"]}
    assert set(sources) == set(builder.PROPOSAL_SOURCE_SPECS)
    for source_ref, expected in builder.PROPOSAL_SOURCE_SPECS.items():
        actual = sources[source_ref]
        assert actual["proposal_id"] == expected["proposal_id"]
        assert actual["proposal_content_sha256"] == expected["proposal_content_sha256"]
        assert actual["proposed_source_version_id"] == expected["source_version_id"]
        assert actual["raw_sha256"] == expected["raw_sha256"]
        assert actual["canonical_content_sha256"] == expected["canonical_content_sha256"]
        assert actual["binding_record_content_sha256"] == expected["binding_record_content_sha256"]
        assert actual["audit_record_content_sha256"] == expected["audit_record_content_sha256"]
        assert actual["audit_verdict"] == expected["audit_verdict"]
        assert actual["row_locator_bindings"] == {
            row_id: list(locators) for row_id, locators in expected["row_locators"].items()
        }
        assert actual["source_admission_authorized"] is False

    assert sources["cas_code"]["audit_verdict"] == "PASS_WITH_WARNING"
    assert sources["cas_code"]["audit_warning_reason_codes"] == [
        "TAS_NOISY_SEARCH_OVERLAY_RULE_BODY_PRESENT"
    ]


def test_arbitration_act_candidate_chunks_are_exact_and_eligible(
    built_package: tuple[Path, dict[str, Any]],
) -> None:
    output, _ = built_package
    advisory = _load(output / builder.ADVISORY_NAME)
    chunks = advisory["exact_arbitration_act_candidate_spans"]
    assert len(chunks) == len(builder.ARBITRATION_ACT_CHUNKS)
    assert {(item["chunk_id"], item["locator"], item["content_sha256"]) for item in chunks} == set(
        builder.ARBITRATION_ACT_CHUNKS
    )
    assert all(item["canonical_chunk_sha256"] == item["content_sha256"] for item in chunks)
    assert all(item["canonical_chunk_sha256_binding"] == "bound" for item in chunks)
    assert all(item["currentness_verified"] is True for item in chunks)
    assert all(item["retrieval_eligible"] is True for item in chunks)


def test_human_rights_act_is_not_treated_as_substitute_authority(
    built_package: tuple[Path, dict[str, Any]],
) -> None:
    output, _ = built_package
    advisory = _load(output / builder.ADVISORY_NAME)
    insufficient = {
        item["source_ref"]: item["reason"]
        for item in advisory["semantically_insufficient_local_sources"]
    }
    assert "human_rights_act_1998" in insufficient
    assert "does not prove" in insufficient["human_rights_act_1998"]
    assert advisory["fallback_contract"] == {
        "essay_safe_fallback_prohibited": True,
        "fallback_used": False,
        "missing_matter_facts_reclassification_prohibited": True,
    }


def test_every_execution_or_mutation_flag_is_false_and_output_is_private(
    built_package: tuple[Path, dict[str, Any]],
) -> None:
    output, _ = built_package
    texts = []
    for name in (builder.ADVISORY_NAME, builder.PACKAGE_NAME):
        value = _load(output / name)
        builder._verify_no_execution_flags(value)
        texts.append(json.dumps(value, ensure_ascii=False).casefold())
    combined = "\n".join(texts)
    assert "/users/" not in combined
    assert "hltsang" not in combined
    assert "legalbot-new" not in combined
    assert "file://" not in combined


def test_create_only_builder_refuses_replace_without_changing_files(
    built_package: tuple[Path, dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    output, _ = built_package
    before = {path.name: _sha256(path) for path in output.iterdir()}
    monkeypatch.setattr(builder, "OUTPUT_REVIEW_ROOT", output.parent)
    with pytest.raises(ValueError, match="mutu_output_already_exists"):
        builder.build_advisory(
            output_root=output,
            created_at=datetime(2026, 8, 28, 13, 0, tzinfo=UTC),
        )
    assert {path.name: _sha256(path) for path in output.iterdir()} == before


def test_exact_loader_and_timestamp_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(ValueError, match="test_file_digest_mismatch"):
        builder._load_exact(
            builder.ORIGINAL_PATH,
            expected_file_sha256="0" * 64,
            seal_field="artifact_content_sha256",
            expected_content_sha256=builder.EXPECTED_INPUTS["original"]["content_sha256"],
            code="test",
        )

    output = tmp_path / "review" / "mutu-alternative"
    output.parent.mkdir()
    monkeypatch.setattr(builder, "OUTPUT_REVIEW_ROOT", output.parent)
    with pytest.raises(ValueError, match="mutu_created_at_must_be_aware"):
        builder.build_advisory(
            output_root=output,
            created_at=datetime(2026, 8, 28, 13, 0),
        )
    assert not output.exists()
