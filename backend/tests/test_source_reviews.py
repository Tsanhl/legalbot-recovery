from __future__ import annotations

import json
from datetime import date

import pytest

from app.api.main import _safe_public_identifier_candidate
from app.db import utc_iso


def _stage_source_review(database) -> None:
    now = utc_iso()
    database.execute(
        """
        INSERT INTO documents(
          id, content_sha256, source_identity_id, safe_display_name, media_type,
          status, lane, subject_primary, jurisdiction, created_at, updated_at
        ) VALUES ('review-doc', ?, 'identity', 'source-abc.pdf', 'application/pdf',
                  'citable', 'primary_authority', 'public', 'England and Wales', ?, ?)
        """,
        ("a" * 64, now, now),
    )
    database.execute(
        """
        INSERT INTO source_versions(
          id, document_id, version_sha256, canonical_markdown_path, title,
          metadata_json, created_at
        ) VALUES ('review-source', 'review-doc', ?, 'data/vault/hash',
                  'Example Act 2026', ?, ?)
        """,
        (
            "b" * 64,
            json.dumps({"identity_verified": False, "currentness_verified": False}),
            now,
        ),
    )
    database.execute(
        """
        INSERT INTO chunks(
          id, source_version_id, ordinal, locator, text_sha256, markdown_text, token_count
        ) VALUES ('review-chunk', 'review-source', 0, 's 1', ?,
                  'Section 1 states the reviewed proposition.', 6)
        """,
        ("c" * 64,),
    )
    database.execute(
        """
        INSERT INTO reviews(id, review_type, target_id, status, reason, created_at)
        VALUES ('review-source-card', 'source_version', 'review-source', 'pending',
                'identity check', ?)
        """,
        (now,),
    )


def _stage_internal_source_review(database, *, lane: str, status: str, key: str) -> None:
    now = utc_iso()
    database.execute(
        """
        INSERT INTO documents(
          id, content_sha256, source_identity_id, safe_display_name, media_type,
          status, lane, subject_primary, jurisdiction, created_at, updated_at
        ) VALUES (?, ?, ?, ?, 'text/markdown', ?, ?, 'contract',
                  'England and Wales', ?, ?)
        """,
        (
            f"{key}-doc",
            "d" * 64,
            f"local-representation-sha256:{'e' * 64}",
            f"source-{key}.md",
            status,
            lane,
            now,
            now,
        ),
    )
    database.execute(
        """
        INSERT INTO source_versions(
          id, document_id, version_sha256, canonical_markdown_path, title,
          metadata_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            f"{key}-source",
            f"{key}-doc",
            "f" * 64,
            f"data/vault/{key}",
            f"Internal {key}",
            json.dumps({"identity_verified": False, "currentness_verified": False}),
            now,
        ),
    )
    database.execute(
        """
        INSERT INTO chunks(
          id, source_version_id, ordinal, locator, text_sha256, markdown_text, token_count
        ) VALUES (?, ?, 0, 'section 1', ?, 'Internal teaching proposition.', 3)
        """,
        (f"{key}-chunk", f"{key}-source", "1" * 64),
    )
    database.execute(
        """
        INSERT INTO reviews(id, review_type, target_id, status, reason, created_at)
        VALUES (?, 'source_version', ?, 'pending', 'identity check', ?)
        """,
        (f"{key}-review", f"{key}-source", now),
    )


def test_source_approval_requires_identity_currentness_and_oscola_metadata(database) -> None:
    _stage_source_review(database)
    with pytest.raises(ValueError, match="requires verified citation identity"):
        database.decide_review("review-source-card", "approved", "blind approve")

    review = database.fetchone("SELECT status FROM reviews WHERE id='review-source-card'")
    source = database.fetchone("SELECT review_status FROM source_versions WHERE id='review-source'")
    assert review is not None and review["status"] == "pending"
    assert source is not None and source["review_status"] == "staged"

    with pytest.raises(ValueError, match="public or bibliographic"):
        database.decide_review(
            "review-source-card",
            "approved",
            "hashed local identity is not legal authority",
            {
                "identity_verified": True,
                "currentness_verified": True,
                "stable_identifier": f"content-sha256:{'a' * 64}",
                "as_of_date": date.today().isoformat(),
                "currentness_status": "current",
                "material_type": "legislation",
                "citation_data": {
                    "source_type": "legislation",
                    "title": "Example Act 2026",
                },
            },
        )

    with pytest.raises(ValueError, match="Structured OSCOLA"):
        database.decide_review(
            "review-source-card",
            "approved",
            "citation is still missing",
            {
                "identity_verified": True,
                "currentness_verified": True,
                "stable_identifier": "ukpga:2026:1",
                "as_of_date": date.today().isoformat(),
                "currentness_status": "current",
                "material_type": "legislation",
            },
        )

    approval = {
        "identity_verified": True,
        "currentness_verified": True,
        "stable_identifier": "ukpga:2026:1",
        "as_of_date": date.today().isoformat(),
        "currentness_status": "current",
        "material_type": "legislation",
        "citation_data": {
            "source_type": "legislation",
            "title": "Example Act 2026",
            "provision": "s 1",
        },
        "canonical_url": "https://www.legislation.gov.uk/ukpga/2026/1",
        "licence_name": "Open Government Licence v3.0",
        "licence_url": "https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/",
    }
    assert database.decide_review(
        "review-source-card", "approved", "official identity checked", approval
    )

    source = database.fetchone("SELECT * FROM source_versions WHERE id='review-source'")
    assert source is not None
    metadata = json.loads(source["metadata_json"])
    assert source["review_status"] == "approved"
    assert source["stable_identifier"] == "ukpga:2026:1"
    assert source["currentness_status"] == "current"
    assert metadata["identity_verified"] is True
    assert metadata["currentness_verified"] is True
    assert metadata["material_type"] == "legislation"
    assert metadata["canonical_citation"] == "Example Act 2026, s 1"


@pytest.mark.parametrize(
    ("lane", "status", "material_type"),
    [
        ("private_teaching", "private_teaching", "tutorial"),
        ("assessment_guidance", "assessment_guidance", "rubric"),
    ],
)
def test_internal_source_approval_uses_private_identity_without_oscola(
    database, lane: str, status: str, material_type: str
) -> None:
    _stage_internal_source_review(database, lane=lane, status=status, key=lane)
    review_id = f"{lane}-review"
    source_id = f"{lane}-source"

    approval = {
        "identity_verified": True,
        "stable_identifier": f"content-sha256:{'d' * 64}",
        "identity_title": f"Reviewed {material_type}",
        "currentness_status": "not_applicable",
        "material_type": material_type,
    }
    assert database.decide_review(review_id, "approved", "internal identity checked", approval)

    source = database.fetchone("SELECT * FROM source_versions WHERE id=?", (source_id,))
    assert source is not None
    metadata = json.loads(source["metadata_json"])
    assert source["review_status"] == "approved"
    assert source["stable_identifier"] == f"content-sha256:{'d' * 64}"
    assert source["as_of_date"] is None
    assert source["currentness_status"] == "not_applicable"
    assert metadata["identity_verified"] is True
    assert metadata["currentness_verified"] is False
    assert metadata["currentness_applicable"] is False
    assert metadata["authority_eligible"] is False
    assert metadata["citation_rendering_enabled"] is False
    assert metadata["identity_title"] == f"Reviewed {material_type}"
    assert metadata["citation_data"] == {}
    assert metadata["canonical_citation"] is None


def test_internal_source_rejects_public_citation_payload_and_legal_currentness(database) -> None:
    _stage_internal_source_review(
        database,
        lane="private_teaching",
        status="private_teaching",
        key="lecture",
    )
    base = {
        "identity_verified": True,
        "stable_identifier": f"content-sha256:{'d' * 64}",
        "identity_title": "Reviewed lecture",
        "currentness_status": "not_applicable",
        "material_type": "lecture",
    }
    with pytest.raises(ValueError, match="must not include OSCOLA"):
        database.decide_review(
            "lecture-review",
            "approved",
            "do not fabricate citation metadata",
            {**base, "citation_data": {"source_type": "book", "title": "Lecture"}},
        )
    with pytest.raises(ValueError, match="not applicable"):
        database.decide_review(
            "lecture-review",
            "approved",
            "do not treat lecture as current law",
            {**base, "currentness_verified": True},
        )


def test_admin_review_query_exposes_safe_source_context_without_paths(database) -> None:
    _stage_source_review(database)
    row = database.admin_reviews()[0]
    assert row["safe_display_name"] == "source-abc.pdf"
    assert row["source_preview"] == "Section 1 states the reviewed proposition."
    assert row["lane"] == "primary_authority"
    assert "encrypted_path" not in row


def test_superseded_source_review_is_history_only_and_successor_can_be_approved(
    database,
) -> None:
    now = utc_iso()
    database.execute(
        """
        INSERT INTO documents(
          id, content_sha256, source_identity_id, safe_display_name, media_type,
          status, lane, subject_primary, jurisdiction, created_at, updated_at
        ) VALUES ('successor-doc', ?, ?, 'source-successor.md', 'text/markdown',
                  'private_teaching', 'private_teaching', 'contract',
                  'England and Wales', ?, ?)
        """,
        ("a" * 64, f"content-sha256:{'a' * 64}", now, now),
    )
    for source_id, fingerprint in (
        ("predecessor-source", "1" * 64),
        ("successor-source", "2" * 64),
    ):
        database.execute(
            """
            INSERT INTO source_versions(
              id, document_id, version_sha256, canonical_markdown_path, title,
              processing_fingerprint, metadata_json, created_at
            ) VALUES (?, 'successor-doc', ?, ?, 'Reviewed tutorial', ?, '{}', ?)
            """,
            (
                source_id,
                "a" * 64,
                f"data/vault/{source_id}",
                fingerprint,
                now,
            ),
        )
        database.execute(
            """
            INSERT INTO reviews(id, review_type, target_id, status, reason, created_at)
            VALUES (?, 'source_version', ?, 'pending', 'identity check', ?)
            """,
            (f"review-{source_id}", source_id, now),
        )
    database.execute(
        "UPDATE source_versions SET superseded_by='successor-source' WHERE id='predecessor-source'"
    )
    database.execute(
        """
        INSERT INTO reviews(id, review_type, target_id, status, reason, created_at)
        VALUES ('review-online-predecessor', 'online_source_version', 'predecessor-source',
                'pending', 'frozen online evidence check', ?)
        """,
        (now,),
    )

    visible = database.admin_reviews()
    assert [row["target_id"] for row in visible] == ["successor-source"]
    assert database.admin_review_count(status="pending") == 1
    assert database.admin_overview()["pending_reviews"] == 1
    assert (
        database.fetchone("SELECT status FROM reviews WHERE id='review-predecessor-source'")[
            "status"
        ]
        == "pending"
    )
    with pytest.raises(ValueError, match="superseded"):
        database.decide_review(
            "review-predecessor-source",
            "approved",
            "stale decision must not apply",
            {
                "identity_verified": True,
                "stable_identifier": f"content-sha256:{'a' * 64}",
                "identity_title": "Reviewed tutorial",
                "currentness_status": "not_applicable",
                "material_type": "tutorial",
            },
        )
    with pytest.raises(ValueError, match="superseded"):
        database.decide_review(
            "review-online-predecessor",
            "approved",
            "hidden online predecessor must not be decided",
        )
    assert (
        database.fetchone("SELECT status FROM reviews WHERE id='review-predecessor-source'")[
            "status"
        ]
        == "pending"
    )

    assert database.decide_review(
        "review-successor-source",
        "approved",
        "current representation checked",
        {
            "identity_verified": True,
            "stable_identifier": f"content-sha256:{'a' * 64}",
            "identity_title": "Reviewed tutorial",
            "currentness_status": "not_applicable",
            "material_type": "tutorial",
        },
    )
    assert database.admin_sources()[0]["review_status"] == "approved"
    assert (
        database.fetchone(
            "SELECT review_status FROM source_versions WHERE id='predecessor-source'"
        )["review_status"]
        == "staged"
    )


def test_public_identifier_prefill_accepts_only_parser_shaped_values() -> None:
    candidate = {
        "scheme": "neutral_citation",
        "value": "[2025] EWCA Civ 12",
        "stable_identifier": "neutral-citation:[2025] EWCA Civ 12",
    }
    assert _safe_public_identifier_candidate(candidate) == candidate
    assert (
        _safe_public_identifier_candidate(
            {**candidate, "stable_identifier": "local-path-sha256:" + "a" * 64}
        )
        is None
    )
    assert _safe_public_identifier_candidate(
        {
            "scheme": "doi",
            "value": "10.1234/example.2025.1",
            "stable_identifier": "doi:10.1234/example.2025.1",
        }
    ) == {
        "scheme": "doi",
        "value": "10.1234/example.2025.1",
        "stable_identifier": "doi:10.1234/example.2025.1",
    }


def test_plaintext_review_note_is_never_persisted(database) -> None:
    _stage_internal_source_review(
        database,
        lane="private_teaching",
        status="private_teaching",
        key="note-storage",
    )
    assert database.decide_review("note-storage-review", "rejected", "private reviewer explanation")
    row = database.fetchone(
        "SELECT decision_note,encrypted_decision_note FROM reviews WHERE id=?",
        ("note-storage-review",),
    )
    assert row is not None
    assert row["decision_note"] == "[redacted]"
    assert row["encrypted_decision_note"] is None
