from __future__ import annotations

import sqlite3

import pytest
from scripts import apply_v111_phase2a_consolidated_source_admissions as admissions
from scripts import recover_v111_phase2a_consolidated_source_admission as recovery


@pytest.fixture(scope="module")
def plan() -> dict[str, object]:
    return recovery.build_recovery_plan()


def test_admission_plan_binds_the_exact_completed_scan(
    plan: dict[str, object],
) -> None:
    assert plan["source_scan_id"] == "18dded91dadf9fa0"
    assert (
        plan["source_scan_manifest_sha256"]
        == "fb6e0d82ff205e74052aa0f536049702e84c8af86624305f5fa03e19eb6e820d"
    )
    assert (
        plan["staging_artifact_content_sha256"]
        == "edd0c6e6a0e26ee776193ceb9256a8a2f5dbc92520dc5ad2346e012e0941e68c"
    )


def test_admission_plan_freezes_the_deduplicated_successor_scope(
    plan: dict[str, object],
) -> None:
    assert plan["committed_source_count"] == 166
    assert plan["successor_source_count"] == 251
    assert plan["successor_body_chunk_count"] == 222_200
    records = plan["committed_sources"]
    assert isinstance(records, list)
    assert len({record["source_version_id"] for record in records}) == 166
    assert all(record["body_chunk_count"] > 0 for record in records)
    assert (
        sum(record["authority_identity_id"].startswith(("ukpga:", "uksi:")) for record in records)
        == 51
    )
    assert (
        sum(record["authority_identity_id"].startswith("neutral-citation:") for record in records)
        == 115
    )


def test_the_two_preidentified_canonical_switch_bindings_remain_exact(
    plan: dict[str, object],
) -> None:
    records = plan["committed_sources"]
    assert isinstance(records, list)
    preidentified = {
        record["authority_identity_id"]: record["content_sha256"]
        for record in records
        if record["authority_identity_id"]
        in {"neutral-citation:[2013] UKSC 67", "neutral-citation:[2024] UKSC 1"}
    }
    assert preidentified == {
        "neutral-citation:[2013] UKSC 67": (
            "b5a28ad75682036f495ca4dd091fb3193412b922e06b6851abafff16b2cc3ba9"
        ),
        "neutral-citation:[2024] UKSC 1": (
            "5a9d6655226b44743b0f14b027c1d94acac9f80c697d0f8038a38bc478db088a"
        ),
    }


def test_planning_is_read_only_and_all_later_gates_remain_closed(
    plan: dict[str, object],
) -> None:
    connection = sqlite3.connect(f"file:{admissions.CATALOGUE_PATH}?mode=ro", uri=True)
    try:
        admitted_versions = {
            row[0]
            for row in connection.execute(
                "SELECT id FROM source_versions WHERE review_status='approved'"
            )
        }
    finally:
        connection.close()
    records = plan["committed_sources"]
    assert isinstance(records, list)
    assert admitted_versions.issuperset(record["source_version_id"] for record in records)
    assert plan["admission_transaction_replayed"] is False
    assert plan["candidate_build_started"] is False
    assert plan["answer_release_eligible"] is False
    assert plan["successor_must_remain_non_active"] is True
    assert plan["active_or_previous_write_authorized"] is False
    assert plan["phase2b_authorized"] is False
    assert plan["development30_authorized"] is False


def test_canonical_switch_never_clears_an_unrelated_authority() -> None:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.executescript(
        """
        CREATE TABLE documents(
          id TEXT PRIMARY KEY,
          representation_group_id TEXT,
          retrieval_canonical INTEGER,
          status TEXT,
          lane TEXT,
          duplicate_of TEXT,
          jurisdiction TEXT,
          updated_at TEXT
        );
        CREATE TABLE source_versions(
          id TEXT PRIMARY KEY,
          document_id TEXT,
          metadata_json TEXT,
          review_status TEXT,
          superseded_by TEXT,
          stable_identifier TEXT,
          authority_identity_id TEXT,
          title TEXT,
          canonical_url TEXT,
          currentness_status TEXT,
          licence_name TEXT,
          licence_url TEXT
        );
        CREATE TABLE reviews(
          id TEXT PRIMARY KEY,
          review_type TEXT,
          target_id TEXT,
          status TEXT,
          reason TEXT,
          decision_note TEXT,
          created_at TEXT,
          decided_at TEXT
        );
        INSERT INTO documents VALUES
          ('target-doc','shared-parser-group',0,'citable','primary_authority',NULL,
           'United Kingdom','2026-08-27T00:00:00+00:00'),
          ('unrelated-doc','shared-parser-group',1,'citable','primary_authority',NULL,
           'England and Wales','2026-08-27T00:00:00+00:00');
        INSERT INTO source_versions VALUES
          ('target-sv','target-doc','{}','staged',NULL,'neutral-citation:[2024] UKSC 30',
           'neutral-citation:[2024] UKSC 30','Target','','historical','',''),
          ('unrelated-sv','unrelated-doc','{}','approved',NULL,
           'neutral-citation:[2025] EWCA Civ 99',
           'neutral-citation:[2025] EWCA Civ 99','Unrelated','','historical','','');
        """
    )
    item = {
        "source_version_id": "target-sv",
        "document_id": "target-doc",
        "stable_identifier": "neutral-citation:[2024] UKSC 30",
        "authority_identity_id": "neutral-citation:[2024] UKSC 30",
        "title": "Target",
        "canonical_url": "",
        "currentness_status": "historical",
        "licence_name": admissions.OGL_NAME,
        "licence_url": admissions.OGL_URL,
        "jurisdiction": "United Kingdom",
        "source_family": "official_judgment",
        "content_sha256": "a" * 64,
        "approval_origins": ["OWNER_TEST"],
        "retained_hold_codes": ["CURRENTNESS_NOT_VERIFIED"],
        "rights_basis": "official_uk_court_ogl_v3",
    }

    admissions._apply_catalogue(connection, {"admitted_sources": [item]})

    rows = connection.execute("SELECT id,retrieval_canonical FROM documents ORDER BY id").fetchall()
    assert {row["id"]: row["retrieval_canonical"] for row in rows} == {
        "target-doc": 1,
        "unrelated-doc": 1,
    }


def test_postcommit_recovery_is_bounded_and_never_replays_admission() -> None:
    plan = recovery.build_recovery_plan()
    assert plan["committed_source_count"] == 166
    assert plan["committed_review_count"] == 166
    assert plan["successor_source_count"] == 251
    assert plan["successor_body_chunk_count"] == 222_200
    assert plan["source_bytes_changed"] is False
    assert plan["chunks_changed"] is False
    assert plan["source_scan_repeated"] is False
    assert plan["source_scope_changed"] is False
    assert plan["admission_transaction_replayed"] is False
    assert plan["candidate_build_started"] is False
    assert plan["phase2b_authorized"] is False
    if recovery.OUTPUT_ROOT.exists():
        assert plan["status"] == "COMMITTED_ADMISSION_ALREADY_VERIFIED"
        assert plan["repair_required_count"] == 0
    else:
        assert plan["status"] == "TARGETED_ONE_ROW_METADATA_REPAIR_READY"
        assert plan["repair_required_count"] == 1
        assert plan["repair_document_ids"] == [recovery.TARGET_DOCUMENT_ID]
