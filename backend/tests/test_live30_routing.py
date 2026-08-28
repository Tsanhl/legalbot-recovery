from pathlib import Path

from app.evaluation.live30 import load_live30_suite
from app.evaluation.live30_coverage import _subject_routing_readiness
from app.orchestration.classifier import classify_subject, classify_subjects
from app.orchestration.routing import decide_route
from app.orchestration.runner import _section_retrieval_subject
from app.retrieval.service import _query_subjects
from app.types import TaskType


def test_live30_route_contract_matches_all_owner_supplied_cases() -> None:
    project_root = Path(__file__).resolve().parents[2]
    suite = load_live30_suite(
        project_root / "benchmarks/evaluation/live-evaluation-30-v1/cases.jsonl"
    )

    observed = {
        case.case_id: decide_route(
            case.question,
            case.word_target,
            TaskType(case.task_type),
        ).route.value
        for case in suite.cases
    }

    assert observed == {case.case_id: case.expected_research_route for case in suite.cases}


def test_live30_subject_contract_has_no_unsafe_incompatible_narrow_filter() -> None:
    project_root = Path(__file__).resolve().parents[2]
    suite = load_live30_suite(
        project_root / "benchmarks" / "evaluation" / "live-evaluation-30-v1" / "cases.jsonl"
    )

    readiness = {case.case_id: _subject_routing_readiness(case) for case in suite.cases}

    assert all(
        state in {"compatible", "explicit_broad_fallback"} and passed
        for state, passed, _observed in readiness.values()
    )
    assert not [
        case_id
        for case_id, (state, _passed, _observed) in readiness.items()
        if state == "incompatible_narrow_filter"
    ]


def test_distinctive_live30_subject_families_are_recognised_without_incidental_matches() -> None:
    project_root = Path(__file__).resolve().parents[2]
    suite = load_live30_suite(
        project_root / "benchmarks" / "evaluation" / "live-evaluation-30-v1" / "cases.jsonl"
    )
    cases = {case.case_id: case for case in suite.cases}

    assert classify_subject(cases["live30-q03"].question) == "tort"
    assert classify_subject(cases["live30-q18"].question) == "banking fraud and restitution"
    assert classify_subject(cases["live30-q21"].question) == "public procurement and administrative"
    assert classify_subject(cases["live30-q22"].question) == "environmental and climate"
    assert classify_subject(cases["live30-q23"].question) == "data protection and privacy"
    assert (
        classify_subject(cases["live30-q24"].question) == "legal ethics and artificial intelligence"
    )
    assert classify_subject(cases["live30-q25"].question) == "insolvency and corporate transactions"
    assert classify_subject(cases["live30-q26"].question) == "construction and commercial"
    assert (
        classify_subject(cases["live30-q28"].question)
        == "land trusts family property and insolvency"
    )
    assert (
        classify_subject(cases["live30-q29"].question)
        == "corporate fraud regulation and litigation"
    )
    assert (
        classify_subject(cases["live30-q30"].question)
        == "multi-area artificial intelligence litigation"
    )

    # One incidental phrase cannot activate a multi-domain family.
    assert "multi-area artificial intelligence litigation" not in classify_subjects(
        "The narrow question refers to risk scores."
    )


def test_composite_question_keeps_broad_fallback_for_unclassified_sections() -> None:
    project_root = Path(__file__).resolve().parents[2]
    suite = load_live30_suite(
        project_root / "benchmarks" / "evaluation" / "live-evaluation-30-v1" / "cases.jsonl"
    )
    question = next(case.question for case in suite.cases if case.case_id == "live30-q30")
    recognised = classify_subjects(question)

    assert len(recognised) > 1
    assert (
        _section_retrieval_subject(
            "Remedies, procedure and strategy",
            whole_question_subject=classify_subject(question),
            recognised_subjects=recognised,
        )
        is None
    )


def test_composite_live30_taxonomy_expands_to_multiple_catalogue_subjects() -> None:
    composite_families = (
        "banking fraud and restitution",
        "public procurement and administrative",
        "environmental and climate",
        "data protection and privacy",
        "legal ethics and artificial intelligence",
        "insolvency and corporate transactions",
        "construction and commercial",
        "land trusts family property and insolvency",
        "corporate fraud regulation and litigation",
        "multi-area artificial intelligence litigation",
    )

    for family in composite_families:
        catalogue_subjects = _query_subjects(family)
        assert len(catalogue_subjects) >= 2
        assert "general" not in catalogue_subjects
