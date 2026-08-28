from __future__ import annotations

import hashlib
import json
from datetime import date

import pytest
from scripts.hold_historical_case_currentness import (
    apply_currentness_holds,
    case_policy_metadata,
)

from app.currentness import (
    HISTORICAL_CASE_CURRENTNESS_POLICY,
    apply_historical_case_treatment_hold,
    case_present_law_currentness_qualifies,
)
from app.db import _validate_source_approval, utc_iso
from app.ingestion.models import Jurisdiction, MaterialLane
from app.retrieval.models import IndexedChunk
from app.retrieval.service import (
    _answer_retrieval_eligible,
    _indexed_to_lance_row,
    _lance_row_to_indexed,
)
from app.types import (
    CasePropositionReview,
    case_proposition_review_sha256,
)


def _citation() -> dict[str, str]:
    return {
        "source_type": "case",
        "case_name": "R (UNISON) v Lord Chancellor",
        "neutral_citation": "[2017] UKSC 51",
    }


def _review_value(**updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema": "legalbot.case-proposition-currentness-review.v1",
        "source_version_id": "case-version",
        "chunk_id": "case-chunk",
        "legal_locator": "paragraph 42",
        "exact_span_sha256": "a" * 64,
        "proposition_hash": "b" * 64,
        "legal_role": "holding_ratio",
        "later_treatment_reviewed_as_of_date": "2026-08-14",
        "later_treatment_status": "confirmed_current",
        "contrary_or_limiting_authority_ids": [],
        "reviewer_role": "england_wales_qualified_barrister",
        "reviewer_ref": f"reviewer:{'c' * 64}",
        "review_scope": "ordinary",
        "second_review_status": "not_required",
        "second_reviewer_ref": None,
    }
    value.update(updates)
    value["seal_sha256"] = case_proposition_review_sha256(value)
    return value


def _review(**updates: object) -> CasePropositionReview:
    return CasePropositionReview.model_validate(_review_value(**updates))


def test_case_requires_explicit_issue_specific_later_treatment() -> None:
    held = apply_historical_case_treatment_hold(
        {"identity_verified": True, "currentness_verified": True}
    )
    assert held["currentness_verified"] is False
    assert held["currentness_policy_version"] == HISTORICAL_CASE_CURRENTNESS_POLICY
    assert not case_present_law_currentness_qualifies(
        citation_data=_citation(),
        currentness_status="historical",
        source_metadata=held,
    )
    assert not case_present_law_currentness_qualifies(
        citation_data=_citation(),
        currentness_status="later_treatment_checked",
        source_metadata={**held, "currentness_verified": True},
    )
    assert not case_present_law_currentness_qualifies(
        citation_data=_citation(),
        currentness_status="later_treatment_checked",
        source_metadata={
            **held,
            "currentness_verified": True,
            "subsequent_treatment_verified": True,
        },
    )
    unverified_identity = apply_historical_case_treatment_hold(
        {"identity_verified": False, "currentness_verified": True}
    )
    assert unverified_identity["identity_verified"] is False


def test_exact_sealed_case_proposition_review_qualifies_only_its_coordinates() -> None:
    review = _review()
    coordinates = {
        "citation_data": _citation(),
        "currentness_status": "historical",
        "source_metadata": {"currentness_verified": False},
        "identity_verified": True,
        "source_version_id": "case-version",
        "chunk_id": "case-chunk",
        "legal_locator": "paragraph 42",
        "exact_span_sha256": "a" * 64,
        "proposition_hash": "b" * 64,
        "legal_role": "holding_ratio",
        "as_of_date": date(2026, 8, 14),
        "reviews": (review,),
    }
    assert case_present_law_currentness_qualifies(**coordinates)
    for key, mismatch in (
        ("source_version_id", "case-version-other"),
        ("chunk_id", "case-chunk-other"),
        ("legal_locator", "paragraph 43"),
        ("exact_span_sha256", "d" * 64),
        ("proposition_hash", "e" * 64),
        ("legal_role", "binding_legal_rule"),
        ("as_of_date", date(2026, 8, 13)),
        ("identity_verified", False),
    ):
        assert not case_present_law_currentness_qualifies(**{**coordinates, key: mismatch})


def test_case_proposition_review_rejects_tampering_and_named_reviewer() -> None:
    tampered = _review_value()
    tampered["proposition_hash"] = "f" * 64
    with pytest.raises(ValueError, match="seal does not match"):
        CasePropositionReview.model_validate(tampered)

    with pytest.raises(ValueError, match="reviewer_ref"):
        _review(reviewer_ref="Jane Smith")


def test_critical_or_disputed_case_proposition_requires_independent_second_review() -> None:
    with pytest.raises(ValueError, match="requires confirmed second review"):
        _review(review_scope="critical")
    with pytest.raises(ValueError, match="must be independent"):
        _review(
            review_scope="disputed",
            second_review_status="confirmed",
            second_reviewer_ref=f"reviewer:{'c' * 64}",
        )

    reviewed = _review(
        review_scope="critical",
        second_review_status="confirmed",
        second_reviewer_ref=f"reviewer:{'d' * 64}",
    )
    assert reviewed.qualifies_for_present_law


def test_qualified_current_review_requires_limiting_authority_and_holds_noncurrent() -> None:
    with pytest.raises(ValueError, match="must bind limiting authority"):
        _review(later_treatment_status="qualified_current")
    assert not _review(later_treatment_status="not_current").qualifies_for_present_law


def test_historical_case_remains_retrievable_for_identity_but_not_current_law() -> None:
    source_metadata = {
        "identity_verified": True,
        "currentness_verified": True,
        "subsequent_treatment_verified": False,
        "eligible_for_model_use": True,
        "ai_use_policy": "unreviewed",
    }
    assert _answer_retrieval_eligible(
        catalog_lane="primary_authority",
        citation_data=_citation(),
        currentness_status="historical",
        source_metadata=source_metadata,
    )
    assert _answer_retrieval_eligible(
        catalog_lane="primary_authority",
        citation_data=_citation(),
        currentness_status="later_treatment_checked",
        source_metadata={**source_metadata, "subsequent_treatment_verified": True},
    )
    assert not _answer_retrieval_eligible(
        catalog_lane="primary_authority",
        citation_data=_citation(),
        currentness_status="historical",
        source_metadata={**source_metadata, "identity_verified": False},
    )


@pytest.mark.parametrize("status", ["historical", "historical_as_enacted", "as-enacted"])
def test_historical_statutory_instrument_is_not_answer_retrieval_eligible(
    status: str,
) -> None:
    assert not _answer_retrieval_eligible(
        catalog_lane="primary_authority",
        citation_data={
            "source_type": "statutory_instrument",
            "title": "Example Regulations 2026",
            "si_number": "2026/1",
        },
        currentness_status=status,
        source_metadata={
            "identity_verified": True,
            "currentness_verified": True,
            "eligible_for_model_use": True,
            "ai_use_policy": "approved",
        },
    )


def test_unreviewed_case_rights_remain_metadata_only() -> None:
    metadata, status = case_policy_metadata(
        {
            "identity_verified": True,
            "currentness_verified": True,
            "eligible_for_model_use": True,
            "authority_eligible": True,
        },
        licence_name=None,
    )

    assert status == "metadata_only_unreviewed_rights"
    assert metadata["currentness_verified"] is False
    assert metadata["eligible_for_model_use"] is False
    assert metadata["authority_eligible"] is False
    assert metadata["full_text_runtime_eligible"] is False
    assert metadata["rights_review_required"] is True


def test_generic_review_cannot_claim_case_currentness() -> None:
    approval = {
        "identity_verified": True,
        "currentness_verified": True,
        "stable_identifier": "neutral-citation:[2017] UKSC 51",
        "as_of_date": "2017-07-26",
        "currentness_status": "historical",
        "material_type": "case",
        "citation_data": _citation(),
        "licence_name": "Open Government Licence v3.0",
    }
    with pytest.raises(ValueError, match="Generic source review cannot approve case"):
        _validate_source_approval(approval, expected_lane="primary_authority")
    with pytest.raises(ValueError, match="must remain currentness_verified=false"):
        _validate_source_approval(
            approval,
            expected_lane="primary_authority",
            trusted_case_snapshot_approval=True,
        )

    reviewed_snapshot = _validate_source_approval(
        {**approval, "currentness_verified": False},
        expected_lane="primary_authority",
        trusted_case_snapshot_approval=True,
    )
    assert reviewed_snapshot["currentness_verified"] is False
    assert reviewed_snapshot["authority_eligible"] is True


def test_audited_database_migration_is_idempotent(database) -> None:
    now = utc_iso()
    database.execute(
        """
        INSERT INTO documents(
          id,content_sha256,source_identity_id,safe_display_name,media_type,
          status,lane,subject_primary,jurisdiction,created_at,updated_at
        ) VALUES ('case-doc',?,'case-identity','source-case.pdf','application/pdf',
                  'citable','primary_authority','trusts','England and Wales',?,?)
        """,
        ("a" * 64, now, now),
    )
    metadata = {
        "identity_verified": True,
        "currentness_verified": True,
        "citation_data": _citation(),
    }
    database.execute(
        """
        INSERT INTO source_versions(
          id,document_id,version_sha256,canonical_markdown_path,title,
          stable_identifier,currentness_status,review_status,metadata_json,created_at
        ) VALUES ('case-version','case-doc',?,'data/vault/aa/source.md',
                  'Example v Example','neutral-citation:[2017] UKSC 51',
                  'historical','approved',?,?)
        """,
        ("b" * 64, json.dumps(metadata), now),
    )
    database.execute(
        """
        UPDATE source_versions
        SET licence_name='Open Government Licence v3.0'
        WHERE id='case-version'
        """
    )

    first = apply_currentness_holds(database, apply=True)
    second = apply_currentness_holds(database, apply=True)
    stored = json.loads(
        database.fetchone("SELECT metadata_json FROM source_versions WHERE id='case-version'")[
            "metadata_json"
        ]
    )

    assert first["historical_case_source_versions"] == 1
    assert first["changed"] == 1
    assert second["changed"] == 0
    assert second["already_held"] == 1
    assert stored["currentness_verified"] is False
    assert stored["subsequent_treatment_check_required"] is True
    assert stored["subsequent_treatment_verified"] is False


def test_database_preserves_sealed_case_review_without_changing_source_status(
    database, evidence
) -> None:
    review = _review(
        source_version_id=evidence.source_version_id,
        chunk_id=evidence.chunk_id,
        legal_locator=evidence.locator,
        exact_span_sha256=evidence.content_sha256,
    )
    case_span = evidence.model_copy(
        update={
            "citation_data": _citation(),
            "currentness_verified": False,
            "case_currentness_reviews": (review,),
            "case_currentness_manifest_seals": ("d" * 64,),
        }
    )
    database.store_evidence([case_span.model_dump(mode="json")])

    stored = database.fetchone(
        "SELECT currentness_verified, case_currentness_reviews_json, "
        "case_currentness_manifest_seals_json "
        "FROM evidence_spans WHERE id=?",
        (case_span.id,),
    )
    source = database.fetchone(
        "SELECT review_status FROM source_versions WHERE id=?",
        (evidence.source_version_id,),
    )
    assert stored is not None
    stored_reviews = json.loads(stored["case_currentness_reviews_json"])
    assert stored["currentness_verified"] == 0
    assert stored_reviews[0]["seal_sha256"] == review.seal_sha256
    assert json.loads(stored["case_currentness_manifest_seals_json"]) == ["d" * 64]
    assert source is not None and source["review_status"] == "approved"


def test_case_review_survives_disposable_lance_row_round_trip() -> None:
    review = _review()
    text = "Reviewed proposition span."
    text_sha256 = hashlib.sha256(text.encode("utf-8")).hexdigest()
    indexed = IndexedChunk(
        chunk_id="case-chunk",
        text=text,
        vector=(0.0,) * 1024,
        jurisdiction=Jurisdiction.ENGLAND_WALES,
        material_lane=MaterialLane.PRIMARY_AUTHORITY,
        subject="public and constitutional",
        review_state="approved",
        source_identity="neutral-citation:[2017] UKSC 51",
        content_sha256=text_sha256,
        metadata={
            "source_version_id": "case-version",
            "representation_group_id": "case-representation",
            "stream": "body",
            "locator": "paragraph 42",
            "catalog_lane": "primary_authority",
            "catalog_jurisdiction": "England and Wales",
            "citation_data": _citation(),
            "canonical_citation": "[2017] UKSC 51",
            "currentness_status": "historical",
            "identity_verified": True,
            "currentness_verified": False,
            "legal_role": "holding_ratio",
            "case_currentness_reviews": [review.model_dump(mode="json", by_alias=True)],
            "case_currentness_manifest_seals": ["d" * 64],
            "retrieval_eligible": True,
            "source_date": "2017-07-26",
            "as_of_date": "2017-07-26",
            "canonical_chunk_sha256": text_sha256,
        },
    )

    restored = _lance_row_to_indexed(_indexed_to_lance_row(indexed))

    assert restored.metadata["legal_role"] == "holding_ratio"
    assert restored.metadata["case_currentness_reviews"] == [
        review.model_dump(mode="json", by_alias=True)
    ]
    assert restored.metadata["case_currentness_manifest_seals"] == ["d" * 64]
