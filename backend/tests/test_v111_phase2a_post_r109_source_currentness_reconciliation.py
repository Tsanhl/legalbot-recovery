from __future__ import annotations

import json
from pathlib import Path

import pytest
from scripts import (
    build_v111_phase2a_post_r109_source_currentness_reconciliation as builder,
)


def test_reconciliation_is_complete_atomic_and_gate_closed(tmp_path: Path) -> None:
    output = tmp_path / "r110"
    artifact = builder.build_reconciliation(output)

    assert artifact["row_source_link_count"] == 26
    assert artifact["unique_row_count"] == 22
    assert artifact["recommendation_counts"] == {
        "RECOMMEND_PARTIAL_BINDING_AND_SOURCE_ADMISSION": 2,
        "RECOMMEND_PARTIAL_EXISTING_SOURCE_BINDING": 1,
        "RECOMMEND_REJECT_MAPPING": 21,
        "RECOMMEND_SUPERSEDE_WITH_CURRENT_AUTHORITY": 2,
    }
    assert artifact["same_adapter_false_negative_count"] == 4
    assert artifact["source_admission_proposal_count"] == 5
    assert {
        proposal["authority_identity_id"] for proposal in artifact["source_admission_proposals"]
    } == {
        "neutral-citation:[2021] UKSC 3",
        "neutral-citation:[2025] UKSC 22",
        "neutral-citation:[2025] EWHC 38 (Ch)",
        "neutral-citation:[2012] EWHC 1257 (Ch)",
        "uksi:2006:246",
    }
    assert all(
        proposal["source_admission_authorized"] is False
        and proposal["automatically_indexed"] is False
        and proposal["automatically_embedded"] is False
        for proposal in artifact["source_admission_proposals"]
    )
    assert all(
        artifact[field] is False
        for field in (
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


def test_every_positive_binding_is_exact_and_material_facts_are_supported(
    tmp_path: Path,
) -> None:
    artifact = builder.build_reconciliation(tmp_path / "r110")

    for proposal in artifact["source_admission_proposals"]:
        assert proposal["exact_proposition_bindings"]
        for binding in proposal["exact_proposition_bindings"]:
            assert not builder.non_atomic_material_claim_reasons(binding["atomic_proposition"])
            proposition_facts = {
                (fact["kind"], fact["normalized_value"])
                for fact in binding["proposition_material_facts"]
            }
            span_facts = {
                (fact["kind"], fact["normalized_value"]) for fact in binding["span_material_facts"]
            }
            assert proposition_facts <= span_facts
            assert binding["quote_end"] > binding["quote_start"]
            assert len(binding["substantive_token_overlap"]) >= 2


def test_same_adapter_false_negatives_are_not_used_as_gate(tmp_path: Path) -> None:
    artifact = builder.build_reconciliation(tmp_path / "r110")
    false_negatives = [
        row for row in artifact["reconciled_links"] if row["same_adapter_false_negative"]
    ]

    assert [row["ordinal"] for row in false_negatives] == [2, 6, 8, 24]
    assert all(row["same_adapter_advisory_assessment"] == "UNRELATED" for row in false_negatives)
    assert artifact["same_adapter_review_used_as_gate"] is False


def test_artifact_and_recursive_checksums_are_sealed(tmp_path: Path) -> None:
    output = tmp_path / "r110"
    artifact = builder.build_reconciliation(output)
    persisted = json.loads((output / builder.OUTPUT_NAME).read_bytes())

    assert persisted == artifact
    material = dict(persisted)
    supplied = material.pop("artifact_content_sha256")
    assert supplied == builder._sealed(material)
    for line in (output / "SHA256SUMS.txt").read_text().splitlines():
        digest, name = line.split("  ", 1)
        assert builder._sha256_file(output / name) == digest


def test_builder_is_create_only(tmp_path: Path) -> None:
    output = tmp_path / "r110"
    builder.build_reconciliation(output)
    with pytest.raises(ValueError, match="phase2a_r110_output_already_exists"):
        builder.build_reconciliation(output)


def test_main_persists_failure_before_reraising(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "failed-r110"

    def fail(_output: Path) -> dict[str, object]:
        raise ValueError("synthetic_r110_failure")

    monkeypatch.setattr(builder, "build_reconciliation", fail)
    with pytest.raises(ValueError, match="synthetic_r110_failure"):
        builder.main(["--output-root", str(output)])

    failure = json.loads((output / "FAILURE.json").read_bytes())
    assert failure["affected_stage"] == ("PHASE2A_POST_R109_SOURCE_CURRENTNESS_RECONCILIATION")
    assert failure["root_cause_status"] == "DEBUG_REQUIRED"
    assert failure["source_admission_authorized"] is False
    assert failure["phase2b_authorized"] is False
    material = dict(failure)
    supplied = material.pop("failure_content_sha256")
    assert supplied == builder._sealed(material)
