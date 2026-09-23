from __future__ import annotations

from app.evaluation.ge_fresh_visible_codex_evaluation import CASES, SOURCES


def test_fresh_codex_topology_is_exact_and_disjoint() -> None:
    assert len(CASES) == 23
    assert len(SOURCES) == 23
    assert len({case.case_id for case in CASES}) == 23
    assert len({case.topic for case in CASES}) == 23
    assert len({source.key for source in SOURCES}) == 23
    assert {case.coverage_kind for case in CASES} == {
        "LEGAL_TOPIC",
        "PUBLIC_ACCESS_DOMAIN",
    }


def test_every_fresh_case_has_bounded_controls_and_evidence() -> None:
    source_keys = {source.key for source in SOURCES}
    for case in CASES:
        assert set(case.source_keys) <= source_keys
        assert case.required_points
        assert case.material_limits
        assert case.prohibited_overclaims
