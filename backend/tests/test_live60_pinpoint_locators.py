from __future__ import annotations

from app.evaluation.live_suite_tick_draft import parse_issue_pinpoint_locators


def test_parse_issue_pinpoint_locators_extracts_sections_articles_and_ranges() -> None:
    assert parse_issue_pinpoint_locators("ss 2, 18, 47A-47E") == (
        "section 2",
        "section 18",
        "section 47A",
    )
    assert parse_issue_pinpoint_locators("Arts 5, 6, 9, 12-15, 22A-22D, 25, 32-34 and 82") == (
        "article 5",
        "article 6",
        "article 9",
        "article 12",
        "article 22A",
        "article 25",
        "article 32",
        "article 82",
    )
    assert parse_issue_pinpoint_locators("s 8") == ("section 8",)
    assert parse_issue_pinpoint_locators("regs 67-77 and related provisions") == ("regulation 67",)
    assert parse_issue_pinpoint_locators("pinpoint paragraph review required") == ()
    assert parse_issue_pinpoint_locators("jurisdiction and enforcement framework") == ()
