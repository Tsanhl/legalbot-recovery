from __future__ import annotations

import sqlite3
from pathlib import Path

from scripts import resolve_v111_phase2a_authority_plan_locators as resolver


def test_canonical_locator_is_conservative() -> None:
    assert resolver.canonical_locator("s 60(7)") == "section 60"
    assert resolver.canonical_locator("Section 11") == "section 11"
    assert resolver.canonical_locator("Sch 2") == "schedule 2"
    assert resolver.canonical_locator("page 032") == "p 32"
    assert resolver.canonical_locator("Part I > Explanatory provisions") == (
        "explanatory provisions"
    )


def test_locator_chunks_require_exact_source_version_and_verified_text_hash(
    tmp_path: Path,
) -> None:
    path = tmp_path / "catalogue.sqlite3"
    connection = sqlite3.connect(path)
    connection.execute(
        """
        CREATE TABLE chunks (
          id TEXT PRIMARY KEY, source_version_id TEXT, ordinal INTEGER,
          heading_path TEXT, locator TEXT, text_sha256 TEXT,
          markdown_text TEXT, token_count INTEGER, metadata_json TEXT,
          stream TEXT
        )
        """
    )
    text = "section 11 A term must satisfy the requirement of reasonableness."
    connection.execute(
        "INSERT INTO chunks VALUES (?,?,?,?,?,?,?,?,?,?)",
        (
            "chunk-1",
            "source-version-1",
            1,
            "[]",
            "section 11",
            resolver._sha256(text.encode()),
            text,
            12,
            "{}",
            "body",
        ),
    )
    connection.commit()
    connection.close()

    readonly = resolver._open_catalogue(path)
    try:
        rows = resolver._locator_chunks(
            readonly,
            source_version_id="source-version-1",
            locator_hint="s 11(1)",
        )
    finally:
        readonly.close()
    assert [row["chunk_id"] for row in rows] == ["chunk-1"]
    assert rows[0]["text_sha256"] == resolver._sha256(text.encode())


def test_planner_locator_results_are_complete_or_explicitly_rejected() -> None:
    small = [{"text": "a" * 100}, {"text": "b" * 100}]
    accepted, accepted_metadata = resolver._bounded_planner_chunks(
        small, remaining_characters=500, remaining_chunks=2
    )
    assert accepted == small
    assert accepted_metadata == {
        "available_exact_chunk_count": 2,
        "available_exact_chunk_text_characters": 200,
        "complete_locator_result_within_bound": True,
    }

    rejected, rejected_metadata = resolver._bounded_planner_chunks(
        small, remaining_characters=150, remaining_chunks=2
    )
    assert rejected == []
    assert rejected_metadata["available_exact_chunk_count"] == 2
    assert rejected_metadata["available_exact_chunk_text_characters"] == 200
    assert rejected_metadata["complete_locator_result_within_bound"] is False

    rejected_by_chunk_budget, chunk_metadata = resolver._bounded_planner_chunks(
        small, remaining_characters=500, remaining_chunks=1
    )
    assert rejected_by_chunk_budget == []
    assert chunk_metadata["complete_locator_result_within_bound"] is False


def test_fallback_candidate_results_are_complete_or_explicitly_rejected() -> None:
    chunks = [{"text": "a" * 100}, {"text": "b" * 100}]
    accepted, accepted_metadata = resolver._bounded_fallback_chunks(
        chunks, remaining_characters=200, remaining_chunks=2
    )
    assert accepted == chunks
    assert accepted_metadata["complete_candidate_result_within_bound"] is True

    rejected, rejected_metadata = resolver._bounded_fallback_chunks(
        chunks, remaining_characters=199, remaining_chunks=2
    )
    assert rejected == []
    assert rejected_metadata["available_exact_chunk_count"] == 2
    assert rejected_metadata["available_exact_chunk_text_characters"] == 200
    assert rejected_metadata["complete_candidate_result_within_bound"] is False


def test_source_candidate_prefers_verified_current_version() -> None:
    chosen = resolver._choose_source_candidate(
        [
            {
                "authority_identity_id": "ukpga:1:1",
                "source_version_id": "old",
                "identity_verified": True,
                "currentness_verified": False,
                "as_of_date": "2020-01-01",
            },
            {
                "authority_identity_id": "ukpga:1:1",
                "source_version_id": "current",
                "identity_verified": True,
                "currentness_verified": True,
                "as_of_date": "2026-08-14",
            },
        ],
        "ukpga:1:1",
    )
    assert chosen is not None
    assert chosen["source_version_id"] == "current"


def test_source_candidate_prefers_in_ceiling_version_over_later_snapshot() -> None:
    chosen = resolver._choose_source_candidate(
        [
            {
                "authority_identity_id": "ukpga:1:1",
                "source_version_id": "after-ceiling",
                "identity_verified": True,
                "currentness_verified": True,
                "as_of_date": "2026-08-17",
            },
            {
                "authority_identity_id": "ukpga:1:1",
                "source_version_id": "at-ceiling",
                "identity_verified": True,
                "currentness_verified": True,
                "as_of_date": "2026-08-14",
            },
        ],
        "ukpga:1:1",
    )
    assert chosen is not None
    assert chosen["source_version_id"] == "at-ceiling"


def test_explicit_source_or_snapshot_date_after_ceiling_is_rejected() -> None:
    assert resolver._record_is_after_target_ceiling(
        {"as_of_date": "2026-08-15"}
    )
    assert resolver._record_is_after_target_ceiling(
        {"source_date": "2026-08-15", "as_of_date": ""}
    )
    assert resolver._record_is_after_target_ceiling(
        {"stable_identifier": "ukpga:1990:18:latest-available@2026-08-17"}
    )
    assert resolver._record_is_after_target_ceiling(
        {"canonical_url": "https://www.legislation.gov.uk/x/2026-08-15/data.xml"}
    )
    assert not resolver._record_is_after_target_ceiling(
        {"source_date": "2026-08-14", "as_of_date": "2026-08-14"}
    )
    assert not resolver._record_is_after_target_ceiling(
        {"source_date": "unknown", "as_of_date": None}
    )


def test_fallback_candidates_are_bounded_row_specific_and_stable() -> None:
    candidates = [
        {
            "source_version_id": "source-1",
            "authority_identity_id": "authority-1",
            "locator": "section 1",
            "identity_verified": True,
        },
        {
            "source_version_id": "source-1",
            "authority_identity_id": "authority-1",
            "locator": "section 1",
            "identity_verified": True,
        },
        {
            "source_version_id": "source-2",
            "authority_identity_id": "authority-2",
            "locator": "section 2",
            "identity_verified": False,
        },
        {
            "source_version_id": "source-after-ceiling",
            "authority_identity_id": "authority-after-ceiling",
            "locator": "section 2A",
            "identity_verified": True,
            "as_of_date": "2026-08-15",
        },
        {
            "source_version_id": "source-3",
            "authority_identity_id": "authority-3",
            "locator": "section 3",
            "identity_verified": True,
        },
        {
            "source_version_id": "source-4",
            "authority_identity_id": "authority-4",
            "locator": "section 4",
            "identity_verified": True,
        },
        {
            "source_version_id": "source-5",
            "authority_identity_id": "authority-5",
            "locator": "section 5",
            "identity_verified": True,
        },
    ]
    selected = resolver._fallback_candidates(candidates)
    assert [candidate["source_version_id"] for candidate in selected] == [
        "source-1",
        "source-3",
        "source-4",
    ]


def test_candidate_chunks_require_ordered_ids_and_matching_hashes(tmp_path: Path) -> None:
    path = tmp_path / "catalogue.sqlite3"
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute(
        """
        CREATE TABLE chunks (
          id TEXT PRIMARY KEY, source_version_id TEXT, ordinal INTEGER,
          heading_path TEXT, locator TEXT, text_sha256 TEXT,
          markdown_text TEXT, token_count INTEGER, metadata_json TEXT,
          stream TEXT
        )
        """
    )
    texts = {"chunk-1": "first exact text", "chunk-2": "second exact text"}
    for ordinal, chunk_id in enumerate(("chunk-1", "chunk-2"), start=1):
        text = texts[chunk_id]
        connection.execute(
            "INSERT INTO chunks VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                chunk_id,
                "source-version-1",
                ordinal,
                "[]",
                "section 1",
                resolver._sha256(text.encode()),
                text,
                3,
                "{}",
                "body",
            ),
        )
    connection.commit()
    candidate = {
        "chunk_ids": ["chunk-2", "chunk-1"],
        "chunk_text_sha256s": [
            resolver._sha256(texts["chunk-2"].encode()),
            resolver._sha256(texts["chunk-1"].encode()),
        ],
    }
    try:
        chunks = resolver._candidate_chunks(
            connection,
            source_version_id="source-version-1",
            candidate=candidate,
        )
    finally:
        connection.close()
    assert [chunk["chunk_id"] for chunk in chunks] == ["chunk-2", "chunk-1"]
