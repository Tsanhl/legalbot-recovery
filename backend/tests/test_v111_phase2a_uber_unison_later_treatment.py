from __future__ import annotations

import copy

import pytest
from lxml import etree
from scripts import collect_v111_phase2a_uber_unison_later_treatment as collector


def test_uber_unison_plan_is_bounded_and_non_authorizing() -> None:
    plan = collector._load_plan(collector.DEFAULT_PLAN)
    targets = collector._validate_plan(plan)

    assert len(targets) == 2
    assert sum(len(target["candidates"]) for target in targets) == 4
    assert {row for target in targets for row in target["row_ids"]} == {
        "live60-q31:issue-01",
        "live60-q31:issue-02",
        "live30-q27:issue-02",
        "live30-q27:issue-08",
    }
    assert plan["bulk_search"] is False
    assert plan["owner_outcomes_applied"] is False
    assert plan["automatic_source_admission"] is False
    assert plan["automatic_embedding"] is False
    assert plan["phase2b_authorized"] is False


def test_uber_unison_plan_rejects_authorizing_mutation() -> None:
    plan = copy.deepcopy(collector._load_plan(collector.DEFAULT_PLAN))
    plan["automatic_embedding"] = True

    with pytest.raises(ValueError, match="phase2a_uber_unison_plan_boundary_invalid"):
        collector._validate_plan(plan)


def test_legacy_number_only_paragraph_is_bound_without_inventing_eid() -> None:
    root = etree.fromstring(
        b'<akomaNtoso xmlns="http://docs.oasis-open.org/legaldocml/ns/akn/3.0">'
        b"<judgment><body><paragraph><num>80.</num><content>Bound official text.</content>"
        b"</paragraph></body></judgment></akomaNtoso>"
    )

    spans = collector._paragraph_spans(root, ["para_80"], source_sha256="a" * 64)

    assert spans[0]["locator_method"] == "AKN_CHILD_NUM"
    assert spans[0]["exact_text"] == "80.Bound official text."
