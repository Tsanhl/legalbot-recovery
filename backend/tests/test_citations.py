from __future__ import annotations

from datetime import date

import pytest

from app.citations.oscola import CitationMetadataError, render_answer, render_oscola
from app.types import StructuredClaimDraft, StructuredDraft, StructuredSectionDraft, TaskType


@pytest.mark.parametrize(
    ("metadata", "locator", "expected"),
    [
        (
            {
                "source_type": "case",
                "case_name": "Corr v IBC Vehicles Ltd",
                "neutral_citation": "[2008] UKHL 13",
                "report_citation": "[2008] 1 AC 884",
            },
            "para 42",
            "*Corr v IBC Vehicles Ltd* [2008] UKHL 13, [2008] 1 AC 884 [42]",
        ),
        (
            {
                "source_type": "case",
                "case_name": "Page v Smith",
                "report_citation": "[1996] AC 155",
                "court_identifier": "HL",
            },
            "p 160",
            "*Page v Smith* [1996] AC 155 (HL) 160",
        ),
        (
            {
                "source_type": "case",
                "case_name": "Court v Despalliers",
                "neutral_citation": "[2009] EWHC 3340",
                "neutral_court_identifier": "Ch",
                "report_citation": "[2010] 2 All ER 451",
            },
            "paras 42-45",
            "*Court v Despalliers* [2009] EWHC 3340 (Ch), [2010] 2 All ER 451 [42]–[45]",
        ),
        (
            {
                "source_type": "case",
                "case_name": "Stubbs v Sayer",
                "decision_date": "1990-11-08",
                "court_identifier": "CA",
            },
            None,
            "*Stubbs v Sayer* (CA, 8 November 1990)",
        ),
        (
            {"source_type": "legislation", "title": "Human Rights Act 1998"},
            "section 15(1)(b)",
            "Human Rights Act 1998, s 15(1)(b)",
        ),
        (
            {
                "source_type": "statutory_instrument",
                "title": "Eggs and Chicks (England) Regulations 2009",
                "instrument_number": "SI 2009/2163",
            },
            "regulation 7(2)",
            "Eggs and Chicks (England) Regulations 2009, SI 2009/2163, reg 7(2)",
        ),
        (
            {"source_type": "rule", "title": "CPR", "provision": "5.2(1)(b)"},
            None,
            "CPR 5.2(1)(b)",
        ),
    ],
)
def test_primary_sources_match_official_oscola_examples(
    metadata: dict[str, object], locator: str | None, expected: str
) -> None:
    assert render_oscola(metadata, locator) == expected


@pytest.mark.parametrize(
    ("metadata", "locator", "expected"),
    [
        (
            {
                "source_type": "journal",
                "author": "Paul Craig",
                "title": "Theory, “Pure Theory” and Values in Public Law",
                "year": "2005",
                "year_format": "square",
                "journal": "PL",
                "first_page": "440",
            },
            "p 441",
            "Paul Craig, ‘Theory, “Pure Theory” and Values in Public Law’ [2005] PL 440, 441",
        ),
        (
            {
                "source_type": "journal",
                "author": "Alison L Young",
                "title": "In Defence of Due Deference",
                "year": "2009",
                "year_format": "round",
                "volume": "72",
                "journal": "MLR",
                "first_page": "554",
            },
            None,
            "Alison L Young, ‘In Defence of Due Deference’ (2009) 72 MLR 554",
        ),
        (
            {
                "source_type": "book",
                "author": "K Zweigert and H Kötz",
                "title": "An Introduction to Comparative Law",
                "translator": "Tony Weir tr",
                "edition": "3rd edn",
                "publisher": "OUP",
                "year": "1998",
            },
            None,
            "K Zweigert and H Kötz, *An Introduction to Comparative Law* (Tony Weir tr, 3rd edn, OUP 1998)",
        ),
        (
            {
                "source_type": "book",
                "author": "Adrian Briggs",
                "title": "Agreements on Jurisdiction and Choice of Law",
                "publisher": "OUP",
                "year": "2008",
            },
            "para 4.51",
            "Adrian Briggs, *Agreements on Jurisdiction and Choice of Law* (OUP 2008) para 4.51",
        ),
        (
            {
                "source_type": "book_chapter",
                "author": "Donal Nolan and John Davies",
                "title": "Torts and Equitable Wrongs",
                "editor": "Andrew Burrows",
                "editor_role": "ed",
                "book_title": "Principles of the Law of Obligations",
                "publisher": "OUP",
                "year": "2015",
            },
            "para 2.87",
            "Donal Nolan and John Davies, ‘Torts and Equitable Wrongs’ in Andrew Burrows (ed), *Principles of the Law of Obligations* (OUP 2015) para 2.87",
        ),
    ],
)
def test_secondary_sources_match_official_oscola_examples(
    metadata: dict[str, object], locator: str | None, expected: str
) -> None:
    assert render_oscola(metadata, locator) == expected


@pytest.mark.parametrize(
    ("metadata", "locator", "expected"),
    [
        (
            {
                "source_type": "web",
                "author": "Cyclefree",
                "title": "Is This Really Necessary, Minister?",
                "website": "Legal Feminist",
                "publication_date": "27 April 2023",
                "url": "https://perma.cc/3THK-P4AX",
            },
            None,
            "Cyclefree, ‘Is This Really Necessary, Minister?’ (*Legal Feminist*, 27 April 2023) <https://perma.cc/3THK-P4AX>",
        ),
        (
            {
                "source_type": "official_guidance",
                "author_or_body": "Cabinet Office",
                "title": "Ministerial Code",
                "publication_date": "December 2022",
                "title_style": "quoted",
            },
            None,
            "Cabinet Office, ‘Ministerial Code’ (December 2022)",
        ),
        (
            {
                "source_type": "web",
                "author": "Geert van Calster",
                "title": "Rechtbank Noord Holland on Applicable Law",
                "website": "GAVC Law",
                "publication_date": "15 July 2023",
                "url": "https://gavclaw.com/article",
                "accessed": "2023-07-21",
            },
            None,
            "Geert van Calster, ‘Rechtbank Noord Holland on Applicable Law’ (*GAVC Law*, 15 July 2023) <https://gavclaw.com/article> accessed 21 July 2023",
        ),
        (
            {
                "source_type": "report",
                "report_type": "law_commission",
                "author_or_body": "Law Commission",
                "title": "Reforming Bribery",
                "report_number": "Law Com No 313",
                "year": "2008",
            },
            "paras 3.12-3.17",
            "Law Commission, *Reforming Bribery* (Law Com No 313, 2008) paras 3.12–3.17",
        ),
        (
            {
                "source_type": "report",
                "report_type": "command_paper",
                "author_or_body": "Department for Science, Innovation & Technology",
                "title": "A Pro-innovation Approach to AI Regulation",
                "report_number": "CP 815",
                "year": "2023",
            },
            "paras 23-25",
            "Department for Science, Innovation & Technology, *A Pro-innovation Approach to AI Regulation* (CP 815, 2023) paras 23–25",
        ),
        (
            {
                "source_type": "report",
                "report_type": "select_committee",
                "author_or_body": "Health Committee",
                "title": "Patient Safety",
                "session": "HC 2008–2009",
                "paper_number": "151–I",
            },
            "paras 173-175",
            "Health Committee, *Patient Safety* (HC 2008–2009, 151–I) paras 173–175",
        ),
        (
            {
                "source_type": "parliamentary",
                "parliamentary_type": "hansard",
                "house": "HC",
                "date": "1977-02-03",
                "volume": "389",
                "columns": "973-76",
            },
            None,
            "HC Deb 3 February 1977, vol 389, cols 973–76",
        ),
        (
            {
                "source_type": "parliamentary",
                "parliamentary_type": "bill_debate",
                "title": "Health Bill",
                "date": "30 January 2007",
                "columns": "12-15",
            },
            None,
            "Health Bill Deb 30 January 2007, cols 12–15",
        ),
    ],
)
def test_official_web_report_and_parliamentary_examples(
    metadata: dict[str, object], locator: str | None, expected: str
) -> None:
    assert render_oscola(metadata, locator) == expected


def test_model_cannot_get_a_citation_without_verified_metadata() -> None:
    with pytest.raises(CitationMetadataError):
        render_oscola({"source_type": "case", "case_name": "Imaginary"})


@pytest.mark.parametrize(
    "metadata",
    [
        {
            "source_type": "case",
            "case_name": "Page v Smith",
            "report_citation": "[1996] AC 155",
        },
        {
            "source_type": "statutory_instrument",
            "title": "Example Regulations 2026",
        },
        {
            "source_type": "journal",
            "author": "A Author",
            "title": "Article",
            "year": "2026",
            "journal": "LQR",
            "first_page": "1",
        },
        {
            "source_type": "web",
            "title": "Changing Page",
            "website": "Official Site",
            "url": "https://example.gov.uk/changing-page",
        },
        {
            "source_type": "web",
            "title": "Downloaded File",
            "website": "Official Site",
            "url": "https://example.gov.uk/report.pdf",
            "accessed": "11 August 2026",
        },
    ],
)
def test_incomplete_or_noncompliant_metadata_fails_closed(metadata: dict[str, object]) -> None:
    with pytest.raises(CitationMetadataError):
        render_oscola(metadata)


def test_renderer_places_full_parenthetical_after_claim(evidence) -> None:
    """Default OSCOLA sits immediately after the supporting sentence body."""
    evidence = evidence.model_copy(
        update={
            "locator": "section 15(1)(b)",
            "citation_data": {
                "source_type": "legislation",
                "title": "Example Act 2026",
            },
            "canonical_citation": "Example Act 2026",
        }
    )
    item = StructuredDraft(
        title="Answer",
        task_type=TaskType.GENERAL,
        jurisdiction="England and Wales",
        as_of_date=date(2026, 8, 11),
        sections=[
            StructuredSectionDraft(
                id="s1",
                heading="Rule",
                claims=[
                    StructuredClaimDraft(
                        id="c1", text="The proposition applies.", evidence_ids=[evidence.id]
                    )
                ],
            )
        ],
    )
    rendered = render_answer(item, {evidence.id: evidence})
    assert (
        "The proposition applies ([Example Act 2026, s 15(1)(b)](#evidence-evidence-1))."
        in rendered.markdown
    )
    # Existing project inline style: body (OSCOLA)terminal-punctuation — not a trailing footnote block.
    assert "The proposition applies (" in rendered.markdown
    assert rendered.markdown.count("Example Act 2026, s 15(1)(b)") == 1


def test_renderer_rejects_canonical_identity_mismatch(evidence) -> None:
    item = StructuredDraft(
        title="Answer",
        task_type=TaskType.GENERAL,
        jurisdiction="England and Wales",
        as_of_date=date(2026, 8, 11),
        sections=[
            StructuredSectionDraft(
                id="s1",
                heading="Rule",
                claims=[
                    StructuredClaimDraft(
                        id="c1", text="The proposition applies.", evidence_ids=[evidence.id]
                    )
                ],
            )
        ],
    )
    mismatched = evidence.model_copy(update={"canonical_citation": "Invented Act 2026"})
    with pytest.raises(CitationMetadataError, match="does not match"):
        render_answer(item, {mismatched.id: mismatched})
