from __future__ import annotations

import json
from pathlib import Path

import pytest
from scripts import build_v111_phase2a_post_r103_source_review_packets as packets


def test_packets_bind_all_source_links_without_semantic_decision(tmp_path: Path) -> None:
    output = tmp_path / "r104"
    artifact = packets.build_packets(output)

    assert artifact["source_count"] == 16
    assert artifact["row_source_link_count"] == 26
    assert artifact["unique_row_count"] == 22
    assert artifact["locator_resolution_counts"] == {
        "ALL_RESOLVED": 25,
        "ONE_OR_MORE_UNRESOLVED": 1,
    }
    assert artifact["exact_issue_phrase_positive_link_count"] == 3
    assert len({row["row_source_link_id"] for row in artifact["rows"]}) == 26
    assert all(
        artifact[field] is False
        for field in (
            "semantic_review_performed",
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
    assert all(row["owner_outcome"] is None for row in artifact["rows"])
    persisted = json.loads((output / "DETERMINISTIC-SOURCE-REVIEW-PACKETS-26.json").read_bytes())
    assert persisted == artifact


def test_packets_expose_relevant_text_and_stale_locator(tmp_path: Path) -> None:
    artifact = packets.build_packets(tmp_path / "r104")
    by_link = {(row["row_id"], row["authority_identity_id"]): row for row in artifact["rows"]}

    undue = by_link[("live30-q28:issue-05", "neutral-citation:[2009] EWHC 1076 (Ch)")]
    assert undue["deterministic_diagnostics"]["exact_issue_phrase_occurrence_count"] == 20
    assert any(
        "EXACT_ISSUE_PHRASE" in block["selection_reasons"] for block in undue["candidate_blocks"]
    )

    heard = by_link[("live60-q34:issue-01", "neutral-citation:[2007] EWCA Crim 125")]
    assert heard["source_title"] == "Heard, R. v"
    assert heard["deterministic_diagnostics"]["exact_issue_phrase_occurrence_count"] == 0

    stale = by_link[("live60-q33:issue-06", "neutral-citation:[2014] EWCA Civ 685")]
    assert stale["deterministic_diagnostics"]["all_supplied_locators_resolved"] is False
    assert stale["deterministic_diagnostics"]["supplied_locator_resolutions"] == [
        {"supplied_hint": "p 37", "resolved_locator": None, "resolved": False}
    ]

    getty = by_link[("live30-q30:issue-16", "neutral-citation:[2025] EWHC 38 (Ch)")]
    getty_paragraph_90 = next(
        block for block in getty["candidate_blocks"] if block["locator"] == "paragraph 90"
    )
    assert "QUESTION_SEGMENT_OVERLAP" in getty_paragraph_90["selection_reasons"]
    assert getty_paragraph_90["question_segment_match"] is not None
    assert {
        "copyright",
        "output",
        "reproduce",
    }.issubset(getty_paragraph_90["question_segment_match"]["overlap_terms"])


def test_legislation_alias_is_preserved_without_new_admission(tmp_path: Path) -> None:
    artifact = packets.build_packets(tmp_path / "r104")
    rows = [row for row in artifact["rows"] if row["authority_identity_id"] == "ukpga:1957:31"]
    assert len(rows) == 2
    assert {row["canonical_authority_identity_id"] for row in rows} == {"ukpga:Eliz2:5-6:31"}
    assert all(row["source_admission_authorized"] is False for row in rows)


def test_packet_builder_is_create_only(tmp_path: Path) -> None:
    output = tmp_path / "r104"
    packets.build_packets(output)
    with pytest.raises(ValueError, match="phase2a_r104_output_already_exists"):
        packets.build_packets(output)
