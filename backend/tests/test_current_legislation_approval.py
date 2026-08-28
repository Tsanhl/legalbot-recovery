from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType


def _load_script() -> ModuleType:
    path = Path(__file__).resolve().parents[2] / "scripts" / "approve_current_legislation.py"
    spec = importlib.util.spec_from_file_location("approve_current_legislation_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _seed_identical_occurrences(database) -> None:
    old_at = "2026-08-12T00:00:00+00:00"
    new_at = "2026-08-14T00:00:00+00:00"
    content_sha = "a" * 64
    version_sha = "b" * 64
    for document_id, status, canonical, duplicate_of, created_at in (
        ("old-doc", "citable", 1, None, old_at),
        ("new-doc", "duplicate", 0, "old-doc", new_at),
    ):
        database.execute(
            """
            INSERT INTO documents(
              id,content_sha256,source_identity_id,representation_group_id,
              safe_display_name,media_type,status,lane,subject_primary,jurisdiction,
              duplicate_of,retrieval_canonical,created_at,updated_at
            ) VALUES (?,?,?,?,?,'application/xml',?,'primary_authority','general',
                      'United Kingdom',?,?,?,?)
            """,
            (
                document_id,
                content_sha,
                f"content-sha256:{content_sha}",
                f"representation-{document_id}",
                f"source-{document_id}.xml",
                status,
                duplicate_of,
                canonical,
                created_at,
                created_at,
            ),
        )
    for source_id, document_id, stable_id, review_status, created_at in (
        (
            "old-source",
            "old-doc",
            "ukpga:1967:7:latest-available@2026-08-12",
            "approved",
            old_at,
        ),
        (
            "new-source",
            "new-doc",
            f"local-path-sha256:{'c' * 64}",
            "staged",
            new_at,
        ),
    ):
        database.execute(
            """
            INSERT INTO source_versions(
              id,document_id,version_sha256,canonical_markdown_path,title,
              stable_identifier,currentness_status,review_status,
              processing_fingerprint,metadata_json,created_at
            ) VALUES (?,?,?,?,? ,?,'unknown',?, ?,?,?)
            """,
            (
                source_id,
                document_id,
                version_sha,
                f"data/vault/{source_id}.md",
                "Misrepresentation Act 1967",
                stable_id,
                review_status,
                "d" * 64,
                json.dumps({"material_type_candidate": "legislation"}),
                created_at,
            ),
        )
        database.execute(
            """
            INSERT INTO chunks(
              id,source_version_id,ordinal,locator,text_sha256,markdown_text,token_count
            ) VALUES (?,?,0,'section 1',?,'Verified official text.',3)
            """,
            (f"chunk-{source_id}", source_id, "e" * 64),
        )


def _rows(database):
    return database.fetchall(
        """
        SELECT d.lane,d.jurisdiction,d.status,d.retrieval_canonical,
               d.id AS document_id,d.subject_primary,d.duplicate_of,
               d.content_sha256 AS document_content_sha256,
               sv.id AS source_version_id,sv.version_sha256,sv.stable_identifier,
               sv.created_at,sv.review_status AS source_review_status,
               sv.metadata_json,NULL AS review_id,NULL AS card_status,
               (SELECT COUNT(*) FROM chunks c WHERE c.source_version_id=sv.id) AS chunk_count,
               (SELECT group_concat(c.markdown_text,' ') FROM chunks c
                WHERE c.source_version_id=sv.id) AS local_text
        FROM documents d
        JOIN source_versions sv ON sv.document_id=d.id AND sv.superseded_by IS NULL
        WHERE d.content_sha256=?
        """,
        ("a" * 64,),
    )


def test_identical_current_snapshot_rolls_forward_as_a_new_immutable_occurrence(
    database, cipher
) -> None:
    module = _load_script()
    _seed_identical_occurrences(database)

    successor, predecessor, reasons = module._resolve_catalogue_occurrence(
        _rows(database),
        identity="ukpga/1967/7",
        current_as_of_date="2026-08-14",
    )

    assert reasons == []
    assert successor["source_version_id"] == "new-source"
    assert predecessor["source_version_id"] == "old-source"
    review_id = module._prepare_identical_rollforward(
        database,
        successor=successor,
        predecessor=predecessor,
        reviewed_subject="contract",
    )
    old_doc = database.fetchone("SELECT * FROM documents WHERE id='old-doc'")
    new_doc = database.fetchone("SELECT * FROM documents WHERE id='new-doc'")
    old_source = database.fetchone("SELECT * FROM source_versions WHERE id='old-source'")
    assert old_doc["retrieval_canonical"] == 0
    assert old_doc["duplicate_of"] == "new-doc"
    assert new_doc["retrieval_canonical"] == 1
    assert new_doc["duplicate_of"] is None
    assert new_doc["status"] == "citable"
    assert new_doc["subject_primary"] == "contract"
    assert old_source["superseded_by"] == "new-source"
    assert (
        database.fetchone("SELECT status FROM reviews WHERE id=?", (review_id,))["status"]
        == "pending"
    )

    manifest = {
        "as_of_date": "2026-08-14",
        "licence": {
            "name": "Open Government Licence",
            "version": "3.0",
            "url": "https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/",
        },
    }
    item = {"identity": "ukpga/1967/7", "title": "Misrepresentation Act 1967"}
    assert database.decide_review(
        review_id,
        "approved",
        None,
        module._source_approval(item, manifest),
        encrypted_note=cipher.encrypt_text("verified official snapshot"),
    )
    current = database.fetchone("SELECT * FROM source_versions WHERE id='new-source'")
    assert current["review_status"] == "approved"
    assert current["stable_identifier"].endswith("@2026-08-14")


def test_identical_rollforward_fails_closed_when_lineage_is_ambiguous(database) -> None:
    module = _load_script()
    _seed_identical_occurrences(database)
    database.execute("UPDATE source_versions SET review_status='staged' WHERE id='old-source'")

    successor, predecessor, reasons = module._resolve_catalogue_occurrence(
        _rows(database),
        identity="ukpga/1967/7",
        current_as_of_date="2026-08-14",
    )

    assert successor is None
    assert predecessor is None
    assert reasons == ["catalogue_identity_not_unique"]


def test_current_snapshot_ignores_identical_as_enacted_representation(database) -> None:
    module = _load_script()
    _seed_identical_occurrences(database)
    database.execute(
        "UPDATE source_versions SET stable_identifier=?,review_status='approved' "
        "WHERE id='new-source'",
        ("ukpga:1967:7:latest-available@2026-08-14",),
    )
    database.execute(
        """
        INSERT INTO source_versions(
          id,document_id,version_sha256,canonical_markdown_path,title,
          stable_identifier,currentness_status,review_status,
          processing_fingerprint,metadata_json,created_at
        ) VALUES ('enacted-source','old-doc',?,'data/vault/enacted.md',
                  'Misrepresentation Act 1967','ukpga:1967:7:enacted',
                  'historical','approved',?,'{}','2026-08-12T00:00:01+00:00')
        """,
        ("f" * 64, "1" * 64),
    )

    current, predecessor, reasons = module._resolve_catalogue_occurrence(
        _rows(database),
        identity="ukpga/1967/7",
        current_as_of_date="2026-08-14",
    )

    assert reasons == []
    assert predecessor is None
    assert current["source_version_id"] == "new-source"


def test_rollforward_review_id_is_stable_and_privacy_safe() -> None:
    module = _load_script()
    first = module._review_id("source-version-opaque")
    assert first == module._review_id("source-version-opaque")
    assert first.startswith("review-current-legislation-")
    assert "/" not in first
    assert len(first.rsplit("-", 1)[-1]) == 40


def test_superseded_pending_review_is_closed_without_deletion(database) -> None:
    module = _load_script()
    database.execute(
        """
        INSERT INTO reviews(id,review_type,target_id,status,reason,created_at)
        VALUES ('approved-card','source_version','source-1','approved','verified',CURRENT_TIMESTAMP),
               ('stale-card','source_version','source-1','pending','scan card',CURRENT_TIMESTAMP)
        """
    )

    module._close_superseded_pending_reviews(
        database,
        source_version_id="source-1",
        approved_review_id="approved-card",
    )

    stale = database.fetchone("SELECT * FROM reviews WHERE id='stale-card'")
    assert stale["status"] == "rejected"
    assert stale["decided_at"] is not None
    assert "Superseded" in stale["reason"]


def test_rollforward_lineage_can_be_recovered_after_idempotent_reapply(database) -> None:
    module = _load_script()
    _seed_identical_occurrences(database)
    successor, predecessor, reasons = module._resolve_catalogue_occurrence(
        _rows(database),
        identity="ukpga/1967/7",
        current_as_of_date="2026-08-14",
    )
    assert reasons == []
    module._prepare_identical_rollforward(
        database,
        successor=successor,
        predecessor=predecessor,
        reviewed_subject="contract",
    )

    recovered = module._rollforward_predecessor_id(
        database,
        source_version_id="new-source",
        existing_official_snapshot={},
    )
    assert recovered == "old-source"
    persisted = module._official_snapshot_metadata(
        {"unapplied_effect_count": 0},
        predecessor_source_version_id=recovered,
        predecessor_bytes_unchanged=True,
    )
    assert persisted["identical_bytes_supersedes_source_version_id"] == "old-source"
    assert persisted["supersedes_source_version_id"] == "old-source"


def test_changed_snapshot_predecessor_is_versioned_without_claiming_identical_bytes(
    database,
) -> None:
    module = _load_script()
    _seed_identical_occurrences(database)
    database.execute(
        "UPDATE documents SET content_sha256=? WHERE id='new-doc'",
        ("9" * 64,),
    )
    predecessors = module._active_snapshot_predecessors(
        database,
        identity="ukpga/1967/7",
        current_as_of_date="2026-08-14",
        successor_source_version_id="new-source",
    )
    assert [row["source_version_id"] for row in predecessors] == ["old-source"]
    snapshot = module._official_snapshot_metadata(
        {"unapplied_effect_count": 0},
        predecessor_source_version_id="old-source",
        predecessor_bytes_unchanged=False,
    )
    assert snapshot["supersedes_source_version_id"] == "old-source"
    assert snapshot["source_bytes_unchanged_from_predecessor"] is False
    assert "identical_bytes_supersedes_source_version_id" not in snapshot
