from __future__ import annotations

import hashlib
import json
from datetime import date

import pytest

from app.case_proposition_reviews import (
    CasePropositionReviewManifest,
    case_review_manifest_sha256,
    immutable_import_report,
    materialise_case_proposition_reviews,
    write_immutable_import_report,
)
from app.db import utc_iso
from app.quality.evidence import evidence_span_eligible_for_drafting
from app.retrieval.service import (
    _catalogue_row_to_indexed,
    _indexed_to_lance_row,
    _lance_row_to_indexed,
)
from app.types import (
    CasePropositionReview,
    EvidenceSpan,
    MaterialLane,
    case_proposition_review_sha256,
)


def _seed_case(database) -> tuple[str, str, str]:
    now = utc_iso()
    text = "Reviewed case proposition."
    prompt_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
    database.execute(
        """
        INSERT INTO documents(
          id,content_sha256,source_identity_id,safe_display_name,media_type,
          status,lane,subject_primary,jurisdiction,created_at,updated_at
        ) VALUES ('review-case-doc',?,'review-case-identity','source-case.md','text/markdown',
                  'citable','primary_authority','contract','England and Wales',?,?)
        """,
        ("1" * 64, now, now),
    )
    source_metadata = {
        "identity_verified": True,
        "currentness_verified": False,
        "eligible_for_model_use": True,
        "authority_eligible": True,
        "citation_data": {
            "source_type": "case",
            "case_name": "Example v Example",
            "neutral_citation": "[2025] UKSC 1",
        },
        "canonical_citation": "Example v Example [2025] UKSC 1",
    }
    database.execute(
        """
        INSERT INTO source_versions(
          id,document_id,authority_identity_id,version_sha256,
          canonical_markdown_path,title,source_date,as_of_date,canonical_url,
          stable_identifier,currentness_status,licence_name,review_status,
          metadata_json,created_at
        ) VALUES (
          'review-case-version','review-case-doc','neutral-citation:[2025] UKSC 1',?,
          'data/vault/review-case/source.md','Example v Example','2025-01-01',
          '2025-01-01','https://example.invalid/judgment',
          'neutral-citation:[2025] UKSC 1','historical',
          'Open Government Licence v3.0','approved',?,?
        )
        """,
        ("2" * 64, json.dumps(source_metadata), now),
    )
    database.execute(
        """
        INSERT INTO chunks(
          id,source_version_id,ordinal,heading_path,locator,text_sha256,
          markdown_text,token_count,stream,metadata_json
        ) VALUES (
          'review-case-chunk','review-case-version',0,'[]','paragraph 42',?,
          ?,4,'body',?
        )
        """,
        (
            hashlib.sha256(text.encode("utf-8")).hexdigest(),
            text,
            json.dumps({"legal_role": "holding_ratio"}),
        ),
    )
    return text, prompt_hash, now


def _review(prompt_hash: str) -> CasePropositionReview:
    value = {
        "schema": "legalbot.case-proposition-currentness-review.v1",
        "source_version_id": "review-case-version",
        "chunk_id": "review-case-chunk",
        "legal_locator": "paragraph 42",
        "exact_span_sha256": prompt_hash,
        "proposition_hash": "3" * 64,
        "legal_role": "holding_ratio",
        "later_treatment_reviewed_as_of_date": "2026-08-14",
        "later_treatment_status": "confirmed_current",
        "contrary_or_limiting_authority_ids": [],
        "reviewer_role": "england_wales_qualified_barrister",
        "reviewer_ref": f"reviewer:{'4' * 64}",
        "review_scope": "ordinary",
        "second_review_status": "not_required",
        "second_reviewer_ref": None,
    }
    value["seal_sha256"] = case_proposition_review_sha256(value)
    return CasePropositionReview.model_validate(value)


def _manifest(review: CasePropositionReview) -> CasePropositionReviewManifest:
    value = {
        "schema": "legalbot.case-proposition-review-manifest.v1",
        "manifest_id": "case-review-pack-test-v1",
        "purpose": "case_proposition_currentness",
        "approval_status": "expert_approved",
        "approval_reviewer_role": "england_wales_qualified_solicitor",
        "approval_reviewer_ref": f"reviewer:{'5' * 64}",
        "independent_second_review_status": "confirmed",
        "independent_second_reviewer_role": ("england_wales_qualified_legal_academic"),
        "independent_second_reviewer_ref": f"reviewer:{'6' * 64}",
        "material_disagreement_status": "none",
        "adjudication_ref": None,
        "review_count": 1,
        "reviews": [review.model_dump(mode="json", by_alias=True)],
    }
    value["seal_sha256"] = case_review_manifest_sha256(value)
    return CasePropositionReviewManifest.model_validate(value)


def _indexed_row(database, text: str) -> dict[str, object]:
    source = database.fetchone("SELECT * FROM source_versions WHERE id='review-case-version'")
    chunk = database.fetchone("SELECT * FROM chunks WHERE id='review-case-chunk'")
    assert source is not None and chunk is not None
    return {
        "source_metadata_json": source["metadata_json"],
        "chunk_metadata_json": chunk["metadata_json"],
        "lane": "primary_authority",
        "jurisdiction": "England and Wales",
        "markdown_text": text,
        "currentness_status": "historical",
        "stable_identifier": "neutral-citation:[2025] UKSC 1",
        "source_identity_id": "review-case-identity",
        "chunk_id": "review-case-chunk",
        "text_sha256": chunk["text_sha256"],
        "source_version_id": "review-case-version",
        "version_sha256": source["version_sha256"],
        "representation_group_id": "review-case-representation",
        "retrieval_canonical": 1,
        "locator": "paragraph 42",
        "stream": "body",
        "subject_primary": "contract",
        "title": "Example v Example",
        "canonical_url": "https://example.invalid/judgment",
        "source_date": "2025-01-01",
        "as_of_date": "2025-01-01",
        "heading_path": "[]",
    }


def test_unreviewed_case_is_held_then_sealed_import_propagates_to_candidate(
    database,
) -> None:
    text, prompt_hash, _now = _seed_case(database)
    review = _review(prompt_hash)
    manifest = _manifest(review)
    unreviewed = EvidenceSpan(
        id="case-evidence",
        source_version_id=review.source_version_id,
        chunk_id=review.chunk_id,
        text=text,
        locator=review.legal_locator,
        lane=MaterialLane.PRIMARY_AUTHORITY,
        jurisdiction="England and Wales",
        subject="contract",
        citation_data={"source_type": "case"},
        currentness_status="historical",
        content_sha256=prompt_hash,
        index_build_id="future-build",
        legal_role="holding_ratio",
        identity_verified=True,
        currentness_verified=False,
    )
    assert not evidence_span_eligible_for_drafting(unreviewed, as_of_date=date(2026, 8, 14))

    dry_run = materialise_case_proposition_reviews(database, manifest, apply=False)
    assert dry_run["audit_status"] == "dry_run"
    assert json.loads(
        database.fetchone("SELECT metadata_json FROM chunks WHERE id=?", (review.chunk_id,))[
            "metadata_json"
        ]
    ) == {"legal_role": "holding_ratio"}

    first = materialise_case_proposition_reviews(database, manifest, apply=True)
    second = materialise_case_proposition_reviews(database, manifest, apply=True)
    assert first["audit_status"] == "applied"
    assert first["applied_count"] == 1
    assert second["audit_status"] == "already_applied"
    assert second["already_present_count"] == 1
    assert immutable_import_report(first) == immutable_import_report(second)

    indexed = _catalogue_row_to_indexed(_indexed_row(database, text), (0.0,) * 1024)
    lance_row = _indexed_to_lance_row(indexed)
    assert lance_row["canonical_chunk_sha256"] == prompt_hash
    assert lance_row["content_sha256"] == prompt_hash
    assert lance_row["canonical_chunk_sha256_binding"] == "bound"
    restored = _lance_row_to_indexed(lance_row)
    assert restored.metadata["canonical_chunk_sha256"] == prompt_hash
    assert restored.metadata["canonical_chunk_sha256_binding"] == "bound"
    review_payloads = restored.metadata["case_currentness_reviews"]
    assert review_payloads[0]["seal_sha256"] == review.seal_sha256
    assert restored.metadata["case_currentness_manifest_seals"] == [manifest.seal_sha256]
    reviewed = unreviewed.model_copy(
        update={
            "case_currentness_reviews": tuple(
                CasePropositionReview.model_validate(item) for item in review_payloads
            ),
            "case_currentness_manifest_seals": tuple(
                restored.metadata["case_currentness_manifest_seals"]
            ),
        }
    )
    assert evidence_span_eligible_for_drafting(reviewed, as_of_date=date(2026, 8, 14))
    source = database.fetchone(
        "SELECT review_status,metadata_json FROM source_versions WHERE id=?",
        (review.source_version_id,),
    )
    assert source is not None and source["review_status"] == "approved"
    assert json.loads(source["metadata_json"])["currentness_verified"] is False
    assert (
        database.fetchone(
            "SELECT manifest_sha256 FROM case_proposition_review_imports WHERE manifest_sha256=?",
            (manifest.seal_sha256,),
        )
        is not None
    )


def test_catalogue_conversion_rejects_mismatched_canonical_text_hash(database) -> None:
    text, _prompt_hash, _now = _seed_case(database)
    row = _indexed_row(database, text)
    row["text_sha256"] = "f" * 64

    with pytest.raises(ValueError, match="canonical chunk SHA-256 does not match"):
        _catalogue_row_to_indexed(row, (0.0,) * 1024)


def test_import_rejects_wrong_span_hash_without_partial_audit(database) -> None:
    _text, _prompt_hash, _now = _seed_case(database)
    manifest = _manifest(_review("7" * 64))
    with pytest.raises(ValueError, match="exact-span hash"):
        materialise_case_proposition_reviews(database, manifest, apply=True)
    assert database.fetchone("SELECT * FROM case_proposition_review_imports") is None


def test_import_rejects_corrupt_duplicate_manifest_provenance(database) -> None:
    _text, prompt_hash, _now = _seed_case(database)
    database.execute(
        "UPDATE chunks SET metadata_json=? WHERE id='review-case-chunk'",
        (
            json.dumps(
                {
                    "legal_role": "holding_ratio",
                    "case_currentness_review_manifest_seals": ["8" * 64, "8" * 64],
                }
            ),
        ),
    )

    with pytest.raises(ValueError, match="manifest seals are invalid"):
        materialise_case_proposition_reviews(database, _manifest(_review(prompt_hash)), apply=True)
    assert database.fetchone("SELECT * FROM case_proposition_review_imports") is None


def test_import_audit_artifact_is_immutable_and_idempotent(tmp_path) -> None:
    path = tmp_path / "review-import.json"
    report = {"schema": "safe-test", "manifest_sha256": "a" * 64}
    write_immutable_import_report(path, report)
    write_immutable_import_report(path, report)
    with pytest.raises(RuntimeError, match="different bytes"):
        write_immutable_import_report(path, {**report, "manifest_sha256": "b" * 64})
