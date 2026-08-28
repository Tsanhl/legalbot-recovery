from __future__ import annotations

from pathlib import Path

from app.cli import parser
from app.evaluation.live_suite_remaining_search import (
    CASELAW_SITE,
    LEGISLATION_SITE,
    _kind_and_open,
    _search_question,
    build_remaining_search_document,
)


def test_search_question_is_a_question() -> None:
    question = _search_question(
        subject="consumer",
        topic="rejection",
        open_name="Consumer Rights Act 2015 sections 20, 22 and 24",
        site=LEGISLATION_SITE,
    )
    assert question.endswith("?")
    assert "rejection" in question
    assert "Consumer Rights Act 2015" in question


def test_look_here_points_to_operative_equality_and_pace_targets() -> None:
    site, open_name = _kind_and_open(
        subject="employment and equality",
        topic="direct discrimination",
        sources=("Equality Act 2010",),
    )
    assert site == LEGISLATION_SITE
    assert "section 13" in open_name
    site, open_name = _kind_and_open(
        subject="criminal evidence",
        topic="confessions",
        sources=("Criminal Justice Act 2003",),
    )
    assert "section 76" in open_name
    site, open_name = _kind_and_open(
        subject="tort",
        topic="omissions",
        sources=(),
    )
    assert site == CASELAW_SITE
    assert "Stovin" in open_name


def test_search_document_does_not_claim_gold() -> None:
    pack = {
        "schema": "legalbot.live60-remaining-selected-search.v1",
        "as_of_date": "2026-08-16",
        "selected_remaining_issue_count": 1,
        "action_counts": {"reject_keep_gap": 1},
        "rows": [
            {
                "row_id": "live30-q03:issue-03",
                "case_id": "live30-q03",
                "issue_id": "issue-03",
                "subject": "tort",
                "topic": "omissions",
                "owner_action": "reject_keep_gap",
                "search_site": CASELAW_SITE,
                "open_first": "Stovin v Wise [1996] AC 923",
                "search_question": (
                    "What is the current UK Supreme Court, House of Lords or other "
                    "binding England-and-Wales paragraph that states the legal rule "
                    "on omissions in tort?"
                ),
                "paste_query": 'site:caselaw.nationalarchives.gov.uk "omissions" Stovin',
                "rejected_locators": [],
                "rejected_sources": [],
                "copy_instruction": "Copy the operative paragraph.",
                "extra_instruction": "If the answer is case law, record later treatment.",
            }
        ],
    }
    document = build_remaining_search_document(pack)
    text = "\n".join(paragraph.text for paragraph in document.paragraphs)
    assert "search worksheet only" in text
    assert "not gold" in text
    assert "omissions" in text
    assert document.core_properties.author == ""


def test_cli_registers_remaining_search_pack() -> None:
    args = parser().parse_args(
        [
            "live60-remaining-search-pack",
            "--imported",
            "reviewed.json",
            "--draft",
            "draft.json",
            "--out",
            "search.docx",
        ]
    )
    assert args.command == "live60-remaining-search-pack"
    assert Path(args.out).name == "search.docx"
