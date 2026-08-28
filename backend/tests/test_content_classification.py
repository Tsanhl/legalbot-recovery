from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.config import Settings
from app.ingestion import service as ingestion_service
from app.ingestion.chunking import StructuralChunker
from app.ingestion.models import (
    BlockKind,
    DocumentFormat,
    ParseResult,
    ParseStatus,
    StructuralBlock,
)
from app.ingestion.service import (
    _chunk_locator,
    _classify,
    _refine_classification,
    scan_configured_sources,
)


def _write(root: Path, relative: str, text: str) -> None:
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


def test_content_overrides_misleading_folders_and_keeps_ambiguous_private(
    tmp_path: Path, database, cipher, monkeypatch
) -> None:
    law = tmp_path / "Law"
    _write(
        law,
        "Assessment/Course/case.md",
        """# IN THE SUPREME COURT

Neutral Citation Number: [2025] UKSC 9

## APPROVED JUDGMENT

[1] The first explicit judgment paragraph.

[2] The second explicit judgment paragraph.
""",
    )
    _write(
        law,
        "Assessment/Course/article.md",
        """# A Legal Research Article

## Abstract

This article examines a legal doctrine.

Keywords: doctrine, remedies

DOI: 10.1234/EXAMPLE.2025.1
""",
    )
    _write(
        law,
        "Assessment/Course/statute.md",
        """# Example Act 2025

2025 CHAPTER 4

Section 1 Duty to act

Section 2 Remedy
""",
    )
    _write(
        law,
        "Assessment/student-answer.md",
        """# Student answer

The answer cites [2025] UKSC 9 but is not the judgment or marker feedback.
""",
    )
    _write(law, "Misc/ambiguous.md", "# Notes\n\nPossibly relevant ideas only.")
    _write(
        law,
        "Misc/biolaw.md",
        """# Bioethics and biolaw

Gene editing, genomic medicine, neuroscience and health data raise linked questions.
""",
    )
    monkeypatch.setenv("LEGALBOT_SOURCE_ROOTS", str(law))
    settings = Settings(project_root=tmp_path, test_mode=True)

    result = scan_configured_sources(settings, database, cipher, "content-aware-scan")
    assert result["files_accounted"] == 6

    rows = database.fetchall(
        """
        SELECT d.id, d.lane, d.subject_primary, d.subject_secondary_json,
               d.source_identity_id, sv.metadata_json,
               (SELECT COUNT(*) FROM chunks c WHERE c.source_version_id=sv.id) AS chunks
        FROM documents d JOIN source_versions sv ON sv.document_id=d.id
        ORDER BY d.id
        """
    )
    by_type = {json.loads(row["metadata_json"])["material_type_candidate"]: row for row in rows}
    assert by_type["case"]["lane"] == "primary_authority"
    assert str(by_type["case"]["source_identity_id"]).startswith("neutral-citation-sha256:")
    assert by_type["journal"]["lane"] == "scholarship"
    assert str(by_type["journal"]["source_identity_id"]).startswith("doi-sha256:")
    assert by_type["legislation"]["lane"] == "primary_authority"
    assert by_type["assessment"]["lane"] == "assessment_guidance"
    assert by_type["assessment"]["chunks"] == 0
    assert by_type["course_note"]["lane"] == "private_teaching"

    biolaw = next(row for row in rows if row["subject_primary"] == "biolaw")
    secondaries = set(json.loads(biolaw["subject_secondary_json"]))
    assert {"medical law", "criminal", "ai and data protection"} <= secondaries

    for row in rows:
        metadata = json.loads(row["metadata_json"])
        classification_payload = json.dumps(
            {
                "codes": metadata["classification_signal_codes"],
                "confidence": metadata["classification_confidence"],
                "material_type": metadata["material_type_candidate"],
                "subject_codes": metadata["subject_signal_codes"],
            }
        )
        assert "/Users/" not in classification_payload
        assert "AliceOwner" not in classification_payload

    case_metadata = json.loads(by_type["case"]["metadata_json"])
    journal_metadata = json.loads(by_type["journal"]["metadata_json"])
    assert case_metadata["public_identifier_candidate"] == {
        "scheme": "neutral_citation",
        "stable_identifier": "neutral-citation:[2025] UKSC 9",
        "value": "[2025] UKSC 9",
    }
    assert journal_metadata["public_identifier_candidate"]["stable_identifier"] == (
        "doi:10.1234/example.2025.1"
    )

    case_locators = {
        row["locator"]
        for row in database.fetchall(
            """
            SELECT c.locator FROM chunks c JOIN source_versions sv ON sv.id=c.source_version_id
            JOIN documents d ON d.id=sv.document_id
            WHERE d.source_identity_id LIKE 'neutral-citation-sha256:%'
            """
        )
    }
    assert {"para 1", "para 2"} <= case_locators
    legislation_locators = {
        row["locator"]
        for row in database.fetchall(
            """
            SELECT c.locator FROM chunks c JOIN source_versions sv ON sv.id=c.source_version_id
            WHERE json_extract(sv.metadata_json, '$.material_type_candidate')='legislation'
            """
        )
    }
    assert {"section 1", "section 2"} <= legislation_locators


def test_locator_uses_only_explicit_anchor_then_page_fallback() -> None:
    parsed = ParseResult(
        ParseStatus.READY,
        DocumentFormat.PDF,
        body_blocks=(
            StructuralBlock(0, BlockKind.PARAGRAPH, "[12] Express paragraph text.", page=4),
            StructuralBlock(1, BlockKind.PARAGRAPH, "Ordinary unnumbered text.", page=5),
            StructuralBlock(2, BlockKind.HEADING, "Regulation 3(1)(b) Duty", page=6),
        ),
    )
    chunks = StructuralChunker(max_chars=500, min_chars=20).chunk_body(
        parsed, document_sha256="a" * 64
    )
    locators = [
        _chunk_locator(
            chunk.heading_path,
            chunk.page_start,
            chunk.page_end,
            ordinal,
            chunk.metadata,
        )
        for ordinal, chunk in enumerate(chunks)
    ]
    assert "para 12" in locators
    assert "regulation 3(1)(b)" in locators
    assert "p 5" in locators
    assert all(locator != "para 5" for locator in locators)


def test_international_journal_paths_keep_exact_jurisdiction_and_scholarship_lane() -> None:
    brazil = _classify(
        Path(
            "Law/Commercial law/Journals/International Company and Commercial Law Review/"
            "Brazil financial services law.pdf"
        )
    )
    assert brazil.lane.value == "scholarship"
    assert brazil.subject == "financial services"
    assert "commercial" in brazil.subject_secondary
    assert brazil.jurisdiction == "Brazil"
    assert brazil.ingestion_jurisdiction.value == "comparative"

    cross_border = _classify(
        Path(
            "Law/Commercial law/Journals/International Company and Commercial Law Review/"
            "South Africa and Australia insolvency study.pdf"
        )
    )
    assert cross_border.jurisdiction == "Comparative"
    assert cross_border.ingestion_jurisdiction.value == "comparative"

    eu = _classify(Path("Law/Commercial law/Journals/European Union competition law.pdf"))
    assert eu.jurisdiction == "European Union"
    assert eu.ingestion_jurisdiction.value == "european_union"


def test_case_path_is_not_demoted_by_incidental_official_guidance_words() -> None:
    classified = _classify(
        Path(
            "Law/Official Legislation/England and Wales/judgments/"
            "ewca-crim-2015-351-data.xml"
        )
    )
    parsed = ParseResult(
        ParseStatus.READY,
        DocumentFormat.XML,
        body_blocks=(
            StructuralBlock(
                0,
                BlockKind.PARAGRAPH,
                "Judgment of the Court. The House of Lords report was considered.",
            ),
            StructuralBlock(
                1,
                BlockKind.PARAGRAPH,
                "The appeal is determined for the reasons that follow.",
            ),
        ),
    )

    refined = _refine_classification(classified, parsed)

    assert refined.lane.value == "primary_authority"
    assert refined.material_type_candidate == "case"
    assert refined.reason == "path_candidate_content_unconfirmed"


@pytest.mark.parametrize(
    "publication_type", ["Journal Article", "Case Comment", "Legislative Comment"]
)
def test_named_journal_header_prevents_cited_law_and_generic_assessment_misrouting(
    publication_type: str, tmp_path: Path, database, cipher, monkeypatch
) -> None:
    law = tmp_path / "Law"
    _write(
        law,
        "Commercial law/Journals/International Company and Commercial Law Review/"
        "Brazil financial services law assessment of risk management.md",
        """# Brazil financial services law - assessment of risk management

{publication_type}

International Company and Commercial Law Review

I.C.C.L.R. 2026, 37(5), 225-245

The article discusses [2025] UKSC 9, the Companies Act 2006 and official guidance.
It quotes numbered passages such as [1] and [2], but it is not a judgment or legislation.
""",
    )
    monkeypatch.setenv("LEGALBOT_SOURCE_ROOTS", str(law))
    scan_configured_sources(
        Settings(project_root=tmp_path, test_mode=True), database, cipher, "journal-guard"
    )

    row = database.fetchone(
        """
        SELECT d.lane, sv.metadata_json
        FROM documents d JOIN source_versions sv ON sv.document_id=d.id
        """
    )
    assert row is not None and row["lane"] == "scholarship"
    metadata = json.loads(row["metadata_json"])
    assert metadata["classification_reason"] == "journal_content_high_confidence"
    assert metadata["material_type_candidate"] == "journal"


def test_official_legislation_pack_subject_folders_are_distinct() -> None:
    expected = {
        "Financial services law": "financial services",
        "Consumer law": "consumer",
        "Criminal evidence law": "criminal evidence",
        "Company law": "company and insolvency",
        "Wills and succession law": "wills and succession",
        "Civil litigation law": "civil litigation",
        "Professional negligence law": "professional negligence",
    }
    for folder, subject in expected.items():
        classified = _classify(
            Path(
                f"Law/Official Legislation/United Kingdom/As Enacted/{folder}/Example Act 2026.pdf"
            )
        )
        assert classified.lane.value == "primary_authority"
        assert classified.jurisdiction == "United Kingdom"
        assert classified.subject == subject


@pytest.mark.parametrize(
    ("opening", "expected_type"),
    [
        (
            "Financial Services and Markets Act 2000. An Act to regulate markets. "
            "Be it enacted by the Queen’s most Excellent Majesty, as follows. "
            "The Civil Procedure Rules 1998 may apply to section 1.",
            "legislation",
        ),
        (
            "CHAPTER 19. An Act to consolidate enactments relating to trustees. "
            "B e it enacted by the K in g’s m ost Excellent Majesty.",
            "legislation",
        ),
        (
            "Equality Act 2010. An Act to harmonise equality law. "
            "B e it enacted by the Queen’s m ost Excellent Majesty, as follows.",
            "legislation",
        ),
    ],
)
def test_official_act_headers_are_legislation_despite_incidental_rules_language(
    opening: str,
    expected_type: str,
    tmp_path: Path,
    database,
    cipher,
    monkeypatch,
) -> None:
    law = tmp_path / "Law"
    _write(
        law,
        "Official Legislation/United Kingdom/As Enacted/Trusts law/Example Act 2000.md",
        f"# Example Act 2000\n\n{opening}",
    )
    monkeypatch.setenv("LEGALBOT_SOURCE_ROOTS", str(law))
    scan_configured_sources(
        Settings(project_root=tmp_path, test_mode=True), database, cipher, "official-act-header"
    )
    row = database.fetchone("SELECT metadata_json FROM source_versions")
    assert row is not None
    metadata = json.loads(row["metadata_json"])
    assert metadata["classification_confidence"] == "high"
    assert metadata["material_type_candidate"] == expected_type


def test_keyboard_interrupt_closes_scan_as_a_resumable_failure(
    tmp_path: Path, database, cipher, monkeypatch
) -> None:
    law = tmp_path / "Law"
    _write(law, "contract/authority.md", "# Authority\n\nVerified source text.")
    monkeypatch.setenv("LEGALBOT_SOURCE_ROOTS", str(law))

    def interrupt(**_kwargs) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(ingestion_service, "_ingest_file", interrupt)
    with pytest.raises(KeyboardInterrupt):
        scan_configured_sources(
            Settings(project_root=tmp_path, test_mode=True), database, cipher, "interrupt-test"
        )

    row = database.fetchone(
        "SELECT status, error_code FROM source_scans WHERE id=?", ("interrupt-test",)
    )
    assert row is not None and row["status"] == "failed"
    assert row["error_code"] == "KeyboardInterrupt"


def test_explicit_ai_use_prohibition_is_rejected_before_index_eligibility(
    tmp_path: Path, database, cipher, monkeypatch
) -> None:
    law = tmp_path / "Law"
    _write(
        law,
        "Pensions/Seminar 1.md",
        """# Seminar 1

This handbook explains pension rights and trustee duties.

Use for artificial intelligence model training or response generation is strictly prohibited.
""",
    )
    monkeypatch.setenv("LEGALBOT_SOURCE_ROOTS", str(law))
    scan_configured_sources(
        Settings(project_root=tmp_path, test_mode=True), database, cipher, "rights-guard"
    )

    row = database.fetchone(
        """
        SELECT sv.review_status, sv.metadata_json, r.status AS review_state
        FROM source_versions sv
        JOIN reviews r ON r.target_id=sv.id AND r.review_type='source_version'
        """
    )
    assert row is not None
    metadata = json.loads(row["metadata_json"])
    assert row["review_status"] == "rejected"
    assert row["review_state"] == "rejected"
    assert metadata["ai_use_policy"] == "prohibited"
    assert metadata["eligible_for_model_use"] is False


def test_seminar_handbook_discussing_authorities_remains_private_teaching(
    tmp_path: Path, database, cipher, monkeypatch
) -> None:
    law = tmp_path / "Law"
    _write(
        law,
        "Trusts law/Seminar 1 handbook.md",
        """# Seminar 1 Handbook

## Learning outcomes

This seminar analyses [2014] UKSC 45 and legislation but remains a teaching outline.
""",
    )
    monkeypatch.setenv("LEGALBOT_SOURCE_ROOTS", str(law))
    scan_configured_sources(
        Settings(project_root=tmp_path, test_mode=True),
        database,
        cipher,
        "teaching-handbook",
    )

    row = database.fetchone(
        """
        SELECT d.lane,sv.metadata_json FROM source_versions sv
        JOIN documents d ON d.id=sv.document_id
        WHERE sv.superseded_by IS NULL
        """
    )
    assert row is not None and row["lane"] == "private_teaching"
    assert json.loads(row["metadata_json"])["material_type_candidate"] == "seminar"


def test_case_folder_and_cited_neutral_citation_do_not_relabel_commentary(
    tmp_path: Path, database, cipher, monkeypatch
) -> None:
    law = tmp_path / "Law"
    _write(
        law,
        "Cases/commentary.md",
        """# Commentary on mediation

This article discusses PGF II SA v OMFS Company 1 Ltd [2013] EWCA Civ 1288.
It evaluates the implications of that authority but is not a judgment.
""",
    )
    monkeypatch.setenv("LEGALBOT_SOURCE_ROOTS", str(law))
    scan_configured_sources(Settings(project_root=tmp_path, test_mode=True), database, cipher, "s")

    metadata = json.loads(database.fetchone("SELECT metadata_json FROM source_versions")[0])
    assert metadata["classification_confidence"] != "high"
    assert "public_identifier_candidate" not in metadata


def test_incompatible_approval_is_requeued_but_compatible_review_survives(
    tmp_path: Path, database, cipher, monkeypatch
) -> None:
    law = tmp_path / "Law" / "Assessment"
    _write(
        law,
        "judgment.md",
        """# IN THE COURT OF APPEAL

Neutral Citation Number: [2025] EWCA Civ 12

## APPROVED JUDGMENT

[1] Express paragraph.
""",
    )
    monkeypatch.setenv("LEGALBOT_SOURCE_ROOTS", str(tmp_path / "Law"))
    settings = Settings(project_root=tmp_path, test_mode=True)
    scan_configured_sources(settings, database, cipher, "classification-review-1")
    version = database.fetchone("SELECT id, metadata_json FROM source_versions")
    assert version is not None
    metadata = json.loads(version["metadata_json"])
    metadata.update(
        {
            "classification_schema": "legacy",
            "material_type": "marker_feedback",
            "identity_verified": True,
            "currentness_verified": False,
        }
    )
    database.execute("UPDATE documents SET lane='assessment_guidance'")
    database.execute(
        "UPDATE source_versions SET review_status='approved', stable_identifier='legacy', metadata_json=?",
        (json.dumps(metadata),),
    )
    database.execute("UPDATE reviews SET status='approved'")

    scan_configured_sources(settings, database, cipher, "classification-review-2")
    source = database.fetchone(
        "SELECT review_status, stable_identifier, metadata_json FROM source_versions"
    )
    review = database.fetchone(
        "SELECT status, reason FROM reviews WHERE review_type='source_version'"
    )
    assert source is not None and review is not None
    assert source["review_status"] == "staged"
    assert str(source["stable_identifier"]).startswith("local-path-sha256:")
    assert json.loads(source["metadata_json"])["identity_verified"] is False
    assert review["status"] == "pending"
    assert "classification changed" in str(review["reason"]).casefold()

    compatible = json.loads(source["metadata_json"])
    compatible.update(
        {
            "classification_schema": "legacy",
            "material_type": "case",
            "identity_verified": True,
            "currentness_verified": True,
        }
    )
    database.execute(
        "UPDATE source_versions SET review_status='approved', stable_identifier='neutral-citation:[2025] EWCA Civ 12', metadata_json=?",
        (json.dumps(compatible),),
    )
    database.execute("UPDATE reviews SET status='approved'")
    scan_configured_sources(settings, database, cipher, "classification-review-3")
    assert database.fetchone("SELECT review_status FROM source_versions")["review_status"] == (
        "approved"
    )
    assert (
        database.fetchone("SELECT status FROM reviews WHERE review_type='source_version'")["status"]
        == "approved"
    )
