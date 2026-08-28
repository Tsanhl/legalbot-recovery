from __future__ import annotations

import json
from pathlib import Path

import pytest
from scripts.build_v111_phase2a_official_source_research_queue import (
    DEFAULT_LEDGER,
    build_queue,
    write_new,
)


def test_official_source_research_queue_is_complete_and_non_authorizing() -> None:
    artifact = build_queue()

    assert artifact["row_count"] == 316
    assert artifact["ready_full_rows_not_queued"] == 45
    assert artifact["research_route_counts"] == {
        "EXACT_OFFICIAL_SOURCE_OR_SPAN_REQUIRED": 7,
        "LEGAL_RESEARCH_AND_EXACT_OFFICIAL_SOURCES_REQUIRED": 123,
        "PROPOSITION_SPLIT_AND_EXACT_OFFICIAL_SOURCES_REQUIRED": 186,
    }
    assert len({record["row_id"] for record in artifact["records"]}) == 316
    for field in (
        "official_research_performed",
        "new_source_selected",
        "automatic_source_admission",
        "automatic_indexing",
        "automatic_embedding",
        "candidate_mutated",
        "owner_decisions_applied",
        "technical_qualification_assigned",
        "phase2b_authorized",
    ):
        assert artifact[field] is False


def test_official_source_research_queue_rows_bind_the_361_ledger() -> None:
    ledger = json.loads(DEFAULT_LEDGER.read_text())
    records = {record["row_id"]: record for record in ledger["records"]}
    artifact = build_queue()

    for queued in artifact["records"]:
        source = records[queued["row_id"]]
        assert queued["proposition_record_content_sha256"] == source["record_content_sha256"]
        assert queued["owner_outcome"] is None
        assert queued["official_primary_sources_only"] is True


def test_official_source_research_queue_write_is_create_only(tmp_path: Path) -> None:
    output = tmp_path / "queue.json"
    artifact = build_queue()
    write_new(output, artifact)

    with pytest.raises(FileExistsError):
        write_new(output, artifact)
