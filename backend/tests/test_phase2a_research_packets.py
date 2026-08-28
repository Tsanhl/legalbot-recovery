from __future__ import annotations

from app.evaluation.phase2a_research_packets import subject_routes


def test_subject_routes_are_conservative_and_multi_domain() -> None:
    assert {"contract", "commercial", "general"}.issubset(subject_routes("contract"))
    assert {
        "company and insolvency",
        "trusts",
        "criminal",
        "general",
    }.issubset(subject_routes("crypto exchange collapse"))
    assert {"constitutional", "civil litigation", "general"}.issubset(
        subject_routes("immigration asylum and human rights")
    )


def test_unknown_subject_remains_in_general_official_lane() -> None:
    assert subject_routes("unmapped specialist topic") == frozenset({"general"})
