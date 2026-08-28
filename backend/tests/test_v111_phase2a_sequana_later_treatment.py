from __future__ import annotations

import json
from pathlib import Path

import pytest
from scripts import collect_v111_phase2a_sequana_later_treatment as collector

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PLAN = PROJECT_ROOT / "config/phase2a_targeted_later_treatment_sources.2026-08-25.v1.json"


def test_plan_is_exact_one_source_non_admitting_scope() -> None:
    plan = json.loads(PLAN.read_bytes())

    item = collector._validate_plan(plan)

    assert item["lead_id"] == "later-treatment-lead-010"
    assert item["candidate_neutral_citation"] == "[2025] UKPC 34"
    assert item["target_neutral_citations"] == ["[2022] UKSC 25"]
    assert plan["bulk_search"] is False
    assert plan["owner_source_admission_required"] is True
    assert plan["automatic_source_admission"] is False
    assert plan["automatic_indexing"] is False
    assert plan["automatic_embedding"] is False
    assert plan["phase2b_authorized"] is False
    assert plan["development30_authorized"] is False


def test_allowlist_is_exact_and_fail_closed() -> None:
    assert collector._safe_url("https://jcpc.uk/cases/judgments/jcpc-2024-0077")
    with pytest.raises(ValueError, match="outside_allowlist"):
        collector._safe_url("https://jcpc.uk.evil.example/cases/judgments/jcpc-2024-0077")
    with pytest.raises(ValueError, match="outside_allowlist"):
        collector._safe_url("http://jcpc.uk/cases/judgments/jcpc-2024-0077")
    with pytest.raises(ValueError, match="forbidden_component"):
        collector._safe_url("https://jcpc.uk/cases/judgments/jcpc-2024-0077#paragraph-31")
    with pytest.raises(ValueError, match="path_invalid"):
        collector._safe_url("https://jcpc.uk/news/jcpc-2024-0077")


def test_exact_target_paragraph_requires_literal_citation() -> None:
    html = b"""
    <html><body>
      <p>31. It was confirmed most recently in BTI 2014 LLC v Sequana SA
      [2022] UKSC 25, [2024] AC 211.</p>
      <p>This similar-looking paragraph does not contain the citation.</p>
    </body></html>
    """

    paragraphs = collector._exact_target_paragraphs(
        html,
        target_citations=["[2022] UKSC 25"],
    )

    assert len(paragraphs) == 1
    assert paragraphs[0]["text_is_contiguous_dom_paragraph"] is True
    assert "[2022] UKSC 25" in paragraphs[0]["exact_text"]
    assert len(paragraphs[0]["exact_text_sha256"]) == 64


def test_plan_cannot_preapprove_or_admit_source() -> None:
    plan = json.loads(PLAN.read_bytes())
    plan["automatic_source_admission"] = True

    with pytest.raises(ValueError, match="plan_boundary_invalid"):
        collector._validate_plan(plan)
