from __future__ import annotations

import json
from pathlib import Path

import pytest
from scripts import collect_v111_phase2a_targeted_later_treatment as collector

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PLAN = PROJECT_ROOT / "config/phase2a_targeted_later_treatment_sources.v1.json"
ADDITIONAL_PLAN = (
    PROJECT_ROOT / "config/phase2a_targeted_later_treatment_sources.2026-08-25.additional.v1.json"
)


def test_plan_is_exact_targeted_non_admitting_scope() -> None:
    plan = json.loads(PLAN.read_bytes())

    items = collector._validate_plan(plan)

    assert len(items) == 9
    assert {target for item in items for target in item["target_neutral_citations"]} == {
        "[2002] UKHL 12",
        "[2015] UKSC 66",
        "[2021] UKSC 5",
        "[2021] UKSC 21",
        "[2023] UKSC 48",
        "[2024] UKSC 28",
        "[2015] UKSC 67",
    }
    assert plan["bulk_search"] is False
    assert plan["owner_source_admission_required"] is True
    assert plan["automatic_source_admission"] is False
    assert plan["automatic_indexing"] is False
    assert plan["automatic_embedding"] is False
    assert plan["phase2b_authorized"] is False
    assert plan["development30_authorized"] is False


def test_official_later_treatment_allowlist_is_fail_closed() -> None:
    assert collector._safe_url("https://www.supremecourt.uk/cases/judgments/uksc-2024-0130")
    assert collector._safe_url("https://www.jcpc.uk/cases/judgments/jcpc-2023-0088")
    with pytest.raises(ValueError, match="outside_allowlist"):
        collector._safe_url("https://supremecourt.uk.evil.example/cases/a")
    with pytest.raises(ValueError, match="outside_allowlist"):
        collector._safe_url("http://www.supremecourt.uk/cases/a")
    with pytest.raises(ValueError, match="forbidden_component"):
        collector._safe_url("https://www.supremecourt.uk/cases/a#fragment")
    with pytest.raises(ValueError, match="path_invalid"):
        collector._safe_url("https://www.supremecourt.uk/news/a")


def test_citation_presence_requires_candidate_and_every_target() -> None:
    item = {
        "candidate_neutral_citation": "[2024] UKSC 1",
        "target_neutral_citations": ["[2021] UKSC 21", "[2021] UKSC 20"],
    }

    incomplete = collector._citation_presence(
        item=item,
        page_text="Judgment [2024] UKSC 1 applies [2021] UKSC 21.",
        pdf_text="",
    )
    complete = collector._citation_presence(
        item=item,
        page_text="Judgment [2024] UKSC 1 applies [2021] UKSC 21.",
        pdf_text="It also discusses [2021] UKSC 20.",
    )

    assert incomplete["all_required_citations_found"] is False
    assert incomplete["missing_citations"] == ["[2021] UKSC 20"]
    assert complete["all_required_citations_found"] is True
    assert complete["missing_citations"] == []


def test_provisional_relationship_cannot_be_written_as_a_conclusion() -> None:
    plan = json.loads(PLAN.read_bytes())
    plan["items"][0]["provisional_relationship"] = "DISPLACED"

    with pytest.raises(ValueError, match="plan_item_invalid"):
        collector._validate_plan(plan)


def test_additional_plan_pins_primeo_interim_pdf_and_remains_non_admitting() -> None:
    plan = json.loads(ADDITIONAL_PLAN.read_bytes())

    items = collector._validate_plan(plan)

    assert len(items) == 3
    assert plan["expected_item_count"] == 3
    assert {target for item in items for target in item["target_neutral_citations"]} == {
        "[2020] UKSC 31",
        "[2021] UKSC 20",
        "[2021] UKSC 29",
    }
    primeo = next(item for item in items if item["lead_id"] == "later-treatment-lead-012")
    assert primeo["official_judgment_url"].endswith(
        "jcpc_2019_0089_judgment_previous_f6a9fb479e.pdf"
    )
    assert plan["automatic_source_admission"] is False
    assert plan["automatic_indexing"] is False
    assert plan["automatic_embedding"] is False


def test_pinned_judgment_must_be_allowlisted_pdf() -> None:
    plan = json.loads(ADDITIONAL_PLAN.read_bytes())
    plan["items"][1]["official_judgment_url"] = "https://jcpc.uk/uploads/not-a-judgment.txt"

    with pytest.raises(ValueError, match="pinned_judgment_not_pdf"):
        collector._validate_plan(plan)


def test_exact_citation_spans_bind_html_and_pdf_contexts() -> None:
    html = b"<html><body><p>32. Applied [2021] UKSC 20 here.</p></body></html>"

    spans = collector._exact_citation_spans(
        page_html=html,
        pdf_raw=b"",
        target_citations=["[2021] UKSC 20"],
    )

    assert len(spans) == 1
    assert spans[0]["matched_target_citations"] == ["[2021] UKSC 20"]
    assert spans[0]["exact_text_is_contiguous_in_representation"] is True
