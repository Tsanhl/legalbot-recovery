from __future__ import annotations

import json
from pathlib import Path

import pytest
from scripts import build_v111_phase2a_post_r110_owner_decision_batch as builder


def test_batch_is_exact_complete_and_non_authorizing(tmp_path: Path) -> None:
    output = tmp_path / "r111"
    batch = builder.build(output)

    summary = batch["decision_summary"]
    assert summary["row_source_link_decision_count"] == 26
    assert summary["affected_unique_row_count"] == 22
    assert summary["mapping_recommendation_counts"] == {
        "RECOMMEND_PARTIAL_BINDING_AND_SOURCE_ADMISSION": 2,
        "RECOMMEND_PARTIAL_EXISTING_SOURCE_BINDING": 1,
        "RECOMMEND_REJECT_MAPPING": 21,
        "RECOMMEND_SUPERSEDE_WITH_CURRENT_AUTHORITY": 2,
    }
    assert summary["proposition_level_source_admission_count"] == 5
    assert summary["currentness_metadata_only_decision_count"] == 1
    assert summary["same_adapter_false_negative_count"] == 4
    assert (
        tuple(row["authority_identity_id"] for row in batch["source_admission_decisions"])
        == builder.SOURCE_IDS
    )
    assert all(
        batch[field] is False
        for field in (
            "owner_approved",
            "owner_decisions_applied",
            "source_admission_authorized",
            "automatic_indexing",
            "automatic_embedding",
            "candidate_mutated",
            "technical_qualification_assigned",
            "phase2b_authorized",
            "development30_authorized",
        )
    )


def test_batch_binds_exact_r110_and_seals_all_decisions(tmp_path: Path) -> None:
    batch = builder.build(tmp_path / "r111")

    assert batch["source_r110_artifact_content_sha256"] == (builder.R110_CONTENT_SHA256)
    assert batch["source_r110_file_sha256"] == builder.R110_FILE_SHA256
    for row in batch["mapping_decisions"]:
        material = dict(row)
        supplied = material.pop("decision_content_sha256")
        assert supplied == builder._sealed(material)
    for row in batch["source_admission_decisions"]:
        material = dict(row)
        supplied = material.pop("decision_content_sha256")
        assert supplied == builder._sealed(material)
        assert row["source_admission_authorized"] is False
        assert row["automatic_indexing"] is False
        assert row["automatic_embedding"] is False


def test_owner_prompt_is_digest_bound_and_scope_limited(tmp_path: Path) -> None:
    output = tmp_path / "r111"
    batch = builder.build(output)
    prompt = (output / builder.PROMPT_NAME).read_text(encoding="utf-8")

    assert batch["artifact_content_sha256"] in prompt
    assert "26 source-mapping dispositions" in prompt
    assert "exactly these 5 official sources" in prompt
    assert "Phase 2B" in prompt
    assert "I APPROVE THIS EXACT DIGEST-BOUND PHASE-2A BATCH" in prompt


def test_artifacts_and_recursive_checksums_are_valid(tmp_path: Path) -> None:
    output = tmp_path / "r111"
    batch = builder.build(output)
    persisted = json.loads((output / builder.BATCH_NAME).read_bytes())

    assert persisted == batch
    material = dict(persisted)
    supplied = material.pop("artifact_content_sha256")
    assert supplied == builder._sealed(material)
    for line in (output / "SHA256SUMS.txt").read_text().splitlines():
        digest, name = line.split("  ", 1)
        assert builder._sha256_file(output / name) == digest


def test_builder_is_create_only(tmp_path: Path) -> None:
    output = tmp_path / "r111"
    builder.build(output)
    with pytest.raises(ValueError, match="phase2a_r111_output_already_exists"):
        builder.build(output)


def test_main_persists_failure_and_returns_nonzero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "failed-r111"

    def fail(_output: Path) -> dict[str, object]:
        raise ValueError("synthetic_r111_failure")

    monkeypatch.setattr(builder, "build", fail)
    assert builder.main(["--output-root", str(output)]) == 1
    failure = json.loads((output / "FAILURE.json").read_bytes())
    assert failure["affected_stage"] == "PHASE2A_POST_R110_OWNER_DECISION_GATE"
    assert failure["root_cause_status"] == "DEBUG_REQUIRED"
    assert failure["source_admission_authorized"] is False
    assert failure["phase2b_authorized"] is False
    material = dict(failure)
    supplied = material.pop("failure_content_sha256")
    assert supplied == builder._sealed(material)
