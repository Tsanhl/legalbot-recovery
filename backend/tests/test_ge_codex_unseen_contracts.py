"""Synthetic contract tests only; no case banks, source captures or model calls."""

from __future__ import annotations

import hashlib
from copy import deepcopy

import pytest

from app.evaluation.ge_codex_unseen_contracts import (
    FACTUAL_CHECKS,
    QUALITY_FLOORS,
    QUALITY_MAX,
    CodexUnseenContractError,
    validate_cases,
    validate_review,
    validate_system_review,
)
from app.evaluation.ge_everyday_unseen import SYSTEM_FAMILIES, coverage_slots, creation_contract

ANSWER_HASH = hashlib.sha256(b"Synthetic answer for validator tests only.").hexdigest()
SOURCES = {"source-a", "source-b"}
MANDATORY_CHECKS = (
    "integrity_chain", "claim_evidence_support", "user_fact_provenance",
    "jurisdiction_scope", "requested_date_and_currentness",
    "citation_and_quotation_identity", "privacy_and_instruction_isolation",
)
WAIVER_REASONS = {
    "dates_amounts_and_deadlines": "The reviewed answer and source-a contain no amounts or deadlines to verify.",
    "contradiction_and_counterauthority": "The reviewed source-a and source-b disclose no conflicting authority for the claim.",
    "safety_and_urgent_action": "The supplied facts and reviewed answer disclose no urgent action or safety issue.",
}


def make_case(slot: dict) -> dict:
    return {
        "case_id": slot["slot_id"],
        "domain": slot.get("domain", "system"),
        "family": slot["family"],
        "question": f"Synthetic fixture {slot['slot_id']}",
        "follow_up": "Synthetic follow-up correction.",
        "uploads": [{"title": "Synthetic receipt", "format": "PDF", "pages": ["Fixture page."]}],
        "secondary_domains": ["consumer" if slot.get("domain") != "consumer" else "contract-law"],
    }


@pytest.fixture
def review() -> dict:
    return {
        "answer_sha256": ANSWER_HASH,
        "checks": dict.fromkeys(FACTUAL_CHECKS, "PASS"),
        "material_claims": [{
            "text": "Synthetic material proposition, not legal advice.",
            "verdict": "SUPPORTED", "source_ids": ["source-a"],
        }],
        "unclaimed_assertions_count": 0,
        "omissions": [],
        "source_currentness": "PASS",
        "scores": dict(QUALITY_MAX),
    }


def assert_factual_hold(row: object, sources: object = SOURCES) -> dict:
    result = validate_review(row, ANSWER_HASH, sources)
    assert result["factual_pass"] is False
    assert result["quality_pass"] is False
    assert result["total_score"] is None
    assert result["hold_reasons"]
    return result


def test_public_quality_contract_and_historical_check_names_are_preserved() -> None:
    contract = creation_contract()
    assert contract["quality_maxima"] == QUALITY_MAX
    assert contract["critical_floors"] == QUALITY_FLOORS
    assert sum(QUALITY_MAX.values()) == 100
    assert FACTUAL_CHECKS == (
        "integrity_chain", "claim_evidence_support", "user_fact_provenance",
        "jurisdiction_scope", "requested_date_and_currentness", "dates_amounts_and_deadlines",
        "citation_and_quotation_identity", "contradiction_and_counterauthority",
        "safety_and_urgent_action", "privacy_and_instruction_isolation",
    )


def test_full_public_assignment_and_system_slots_use_only_synthetic_placeholders() -> None:
    legal = coverage_slots()
    system = [{"slot_id": f"system:{i:02d}", "family": family, "domain": "system"}
              for i, family in enumerate(SYSTEM_FAMILIES, 1)]
    slots = legal + system
    cases = [make_case(slot) for slot in slots]
    before = deepcopy((cases, slots))
    assert len(legal) == 420 and len(system) == 23
    assert validate_cases(cases, slots) is None
    assert (cases, slots) == before
    assert validate_cases(cases[:1], slots[:1]) is None


@pytest.mark.parametrize("change", ["missing", "extra", "duplicate", "unassigned", "aliased", "swapped_family", "slot_id"])
def test_exact_assignment_cannot_be_relabelled_or_tampered(change: str) -> None:
    slots = coverage_slots()[:2]
    cases = [make_case(slot) for slot in slots]
    if change == "missing":
        cases.pop()
    elif change == "extra":
        cases.append(deepcopy(cases[0]))
    elif change == "duplicate":
        cases[1] = deepcopy(cases[0])
    elif change == "unassigned":
        cases[0]["case_id"] = "other:01:narrative"
    elif change == "aliased":
        cases[0]["case_id"] += " "
    elif change == "swapped_family":
        cases[0]["family"] = coverage_slots()[2]["family"]
    else:
        cases[0]["slot_id"] = slots[1]["slot_id"]
    before = deepcopy((cases, slots))
    with pytest.raises(CodexUnseenContractError):
        validate_cases(cases, slots)
    assert (cases, slots) == before


@pytest.mark.parametrize("field,value", [
    ("domain", "consumer"), ("family", "other"), ("family", None),
    ("variant", "narrative"), ("synthetic_upload_required", False),
    ("multi_turn_required", False), ("cross_issue_required", False),
    ("multi_turn_required", 1),
])
def test_worker_metadata_cannot_override_document_cross_issue_assignment(field: str, value: object) -> None:
    slot = coverage_slots()[11]
    case = make_case(slot)
    case[field] = value
    with pytest.raises(CodexUnseenContractError):
        validate_cases([case], [slot])


@pytest.mark.parametrize("field,value", [
    ("question", " \n\t"), ("question", "!?"), ("question", "\u200b"), ("question", 1),
    ("follow_up", ""), ("follow_up", "  \n"), ("follow_up", None),
    ("uploads", []), ("uploads", {}), ("uploads", ["file.pdf"]),
    ("uploads", [{"title": " ", "format": "PDF", "pages": ["page"]}]),
    ("uploads", [{"title": "doc", "format": "pdf", "pages": ["page"]}]),
    ("uploads", [{"title": "doc", "format": "DOCX", "pages": ["page"]}]),
    ("uploads", [{"title": "doc", "format": "PDF", "pages": []}]),
    ("uploads", [{"title": "doc", "format": "PDF", "pages": "page"}]),
    ("uploads", [{"title": "doc", "format": "PDF", "pages": ["ok", " "]}]),
    ("uploads", [{"title": "doc", "format": "PNG", "pages": [None]}]),
    ("secondary_domains", []), ("secondary_domains", "consumer"),
    ("secondary_domains", [""]), ("secondary_domains", ["consumer", "consumer"]),
    ("secondary_domains", ["administrative-law"]),
])
def test_document_multiturn_and_cross_issue_fields_are_enforced(field: str, value: object) -> None:
    slot = coverage_slots()[11]
    case = make_case(slot)
    case[field] = value
    with pytest.raises(CodexUnseenContractError):
        validate_cases([case], [slot])


def test_narrative_can_omit_upload_content_and_followup_but_not_the_fields() -> None:
    slot = coverage_slots()[0]
    case = make_case(slot)
    case.update(follow_up="", uploads=[], secondary_domains=[])
    validate_cases([case], [slot])
    for field in ("question", "follow_up", "uploads", "secondary_domains", "family", "case_id"):
        incomplete = {name: value for name, value in case.items() if name != field}
        with pytest.raises(CodexUnseenContractError):
            validate_cases([incomplete], [slot])


@pytest.mark.parametrize("format", ["PDF", "PNG"])
def test_both_upload_formats_and_multiple_pages_are_valid(format: str) -> None:
    slot = coverage_slots()[11]
    case = make_case(slot)
    case.update({name: slot[name] for name in ("variant", "synthetic_upload_required", "multi_turn_required", "cross_issue_required")})
    case["uploads"][0].update(format=format, pages=["First page", "Second page"])
    validate_cases([case], [slot])


@pytest.mark.parametrize("other", [
    "CAN I request a review of this decision after receiving the written notice?!",
    "Can I\u200b request a review of this decision after receiving the written notice?",
    "Ｃａｎ I request a review of this decision after receiving the written notice?",
    "Can I request a review of this decision after receiving the formal notice?",
])
def test_lightly_duplicated_questions_across_assignments_are_rejected(other: str) -> None:
    slots = coverage_slots()[:2]
    cases = [make_case(slot) for slot in slots]
    cases[0]["question"] = "Can I request a review of this decision after receiving the written notice?"
    cases[1]["question"] = other
    with pytest.raises(CodexUnseenContractError, match="duplicated normalized question"):
        validate_cases(cases, slots)


def test_similar_opening_does_not_reject_distinct_questions() -> None:
    slots = coverage_slots()[:2]
    cases = [make_case(slot) for slot in slots]
    cases[0]["question"] = "Can I request a review of this decision after receiving the written notice?"
    cases[1]["question"] = "Can I request repairs from my landlord when water leaks into the bedroom?"
    validate_cases(cases, slots)


@pytest.mark.parametrize("slots,cases", [
    ([], []), ({}, []), ([None], [{}]), ([{}], [{}]),
    ([{"slot_id": [], "family": "a"}], [{}]),
    ([{"slot_id": "a", "family": "a", "multi_turn_required": "false"}], [{}]),
    ([{"slot_id": "a", "family": "a", "domain": None}], [{}]),
    ([{"slot_id": "a", "family": "a"}] * 2, [{}, {}]),
    ([{"slot_id": "a", "family": "a"}], None),
    ([{"slot_id": "a", "family": "a"}], [None]),
    ([{"slot_id": "a", "family": "a"}], [{"case_id": []}]),
    ([{}] * 444, [{}] * 444),
])
def test_malformed_assignments_fail_with_contract_error(slots: object, cases: object) -> None:
    with pytest.raises(CodexUnseenContractError):
        validate_cases(cases, slots)


def test_exact_complete_review_passes_without_mutation(review: dict) -> None:
    before = deepcopy(review)
    sources_before = set(SOURCES)
    assert validate_review(review, ANSWER_HASH, SOURCES) == {
        "factual_pass": True, "quality_pass": True, "total_score": 100.0, "hold_reasons": [],
    }
    assert review == before and sources_before == SOURCES


@pytest.mark.parametrize("value", [None, "", "a" * 64, ANSWER_HASH.upper(), "g" * 64, [], True])
def test_exact_answer_hash_binding_cannot_be_tampered(review: dict, value: object) -> None:
    review["answer_sha256"] = value
    assert "ANSWER_HASH_MISMATCH_OR_INVALID" in assert_factual_hold(review)["hold_reasons"]


@pytest.mark.parametrize("value", [None, "", "not-a-digest", "G" * 64, [], True])
def test_matching_malformed_hashes_are_not_binding(review: dict, value: object) -> None:
    review["answer_sha256"] = value
    assert validate_review(review, value, SOURCES)["factual_pass"] is False


@pytest.mark.parametrize("field", [
    "answer_sha256", "checks", "material_claims", "unclaimed_assertions_count",
    "omissions", "source_currentness",
])
def test_required_factual_declarations_cannot_be_omitted(review: dict, field: str) -> None:
    del review[field]
    assert_factual_hold(review)


@pytest.mark.parametrize("check", FACTUAL_CHECKS)
def test_each_required_factual_check_is_required_even_with_replacement(review: dict, check: str) -> None:
    del review["checks"][check]
    review["checks"]["extra_check"] = "PASS"
    assert f"MISSING_FACTUAL_CHECK:{check}" in assert_factual_hold(review)["hold_reasons"]


@pytest.mark.parametrize("value", ["FAIL", "HOLD", "UNREVIEWED", "pass", True, None, [], {}])
def test_bad_or_unresolved_check_values_block_quality(review: dict, value: object) -> None:
    review["checks"][FACTUAL_CHECKS[0]] = value
    assert_factual_hold(review)


def test_all_not_applicable_cannot_launder_a_full_score(review: dict) -> None:
    review["checks"] = dict.fromkeys(FACTUAL_CHECKS, "NOT_APPLICABLE")
    review["applicability_reasons"] = dict.fromkeys(
        FACTUAL_CHECKS, "The reviewer asserts the supplied evidence does not engage this check.",
    )
    review.update(factual_pass=True, quality_pass=True, total_score=100, needs_legal_currentness=False)
    before = deepcopy(review)
    result = assert_factual_hold(review)
    assert {f"FACTUAL_CHECK_NOT_PASS:{check}" for check in MANDATORY_CHECKS}.issubset(result["hold_reasons"])
    assert review == before


@pytest.mark.parametrize("check", MANDATORY_CHECKS)
def test_mandatory_checks_cannot_be_waived_with_a_reason(review: dict, check: str) -> None:
    review["checks"][check] = "NOT_APPLICABLE"
    review["applicability_reasons"] = {check: "The reviewer asserts no relevant issue arises from the supplied evidence."}
    assert assert_factual_hold(review)["hold_reasons"] == [f"FACTUAL_CHECK_NOT_PASS:{check}"]


@pytest.mark.parametrize("check", tuple(WAIVER_REASONS))
def test_evidence_bound_optional_waiver_preserves_valid_review(review: dict, check: str) -> None:
    review["checks"][check] = "NOT_APPLICABLE"
    review["applicability_reasons"] = {check: WAIVER_REASONS[check]}
    before = deepcopy(review)
    assert validate_review(review, ANSWER_HASH, SOURCES) == {
        "factual_pass": True, "quality_pass": True, "total_score": 100.0, "hold_reasons": [],
    }
    assert review == before


def test_all_three_optional_checks_can_be_waived_with_individual_reasons(review: dict) -> None:
    review["checks"].update(dict.fromkeys(WAIVER_REASONS, "NOT_APPLICABLE"))
    review["applicability_reasons"] = dict(WAIVER_REASONS)
    assert validate_review(review, ANSWER_HASH, SOURCES)["quality_pass"] is True


@pytest.mark.parametrize("check", tuple(WAIVER_REASONS))
@pytest.mark.parametrize("reason", [None, "", " \n\t", True, 0, [], {}, "N/A", "NOT_APPLICABLE", "..."])
def test_optional_waiver_requires_a_nonblank_explanation(review: dict, check: str, reason: object) -> None:
    review["checks"][check] = "NOT_APPLICABLE"
    review["applicability_reasons"] = {check: reason}
    assert f"MISSING_OR_INVALID_APPLICABILITY_REASON:{check}" in assert_factual_hold(review)["hold_reasons"]


@pytest.mark.parametrize("check", tuple(WAIVER_REASONS))
@pytest.mark.parametrize("reasons", [None, [], "No relevant issue", {}, {"other_check": "No relevant issue in source-a."}])
def test_optional_waiver_requires_a_mapping_entry_for_that_check(review: dict, check: str, reasons: object) -> None:
    review["checks"][check] = "NOT_APPLICABLE"
    assert_factual_hold(review)  # An absent field must not silently waive the check.
    review["applicability_reasons"] = reasons
    assert_factual_hold(review)


@pytest.mark.parametrize("field", ["source_currentness", "requested_date_and_currentness"])
@pytest.mark.parametrize("needs_currentness", [False, None, "false"])
def test_generic_currentness_flag_cannot_bypass_either_currentness_gate(review: dict, field: str, needs_currentness: object) -> None:
    review["needs_legal_currentness"] = needs_currentness
    if field == "source_currentness":
        review[field] = "NOT_APPLICABLE"
        expected = "SOURCE_CURRENTNESS_NOT_PASS"
    else:
        review["checks"][field] = "NOT_APPLICABLE"
        expected = f"FACTUAL_CHECK_NOT_PASS:{field}"
    review["applicability_reasons"] = {field: "The reviewer labels this a generic question requiring no currentness review."}
    assert expected in assert_factual_hold(review)["hold_reasons"]


def test_extra_checks_are_validated_and_not_applicable_is_explicit(review: dict) -> None:
    review["checks"]["additional_check"] = "NOT_APPLICABLE"
    review["checks"]["dates_amounts_and_deadlines"] = "NOT_APPLICABLE"
    review["applicability_reasons"] = {
        "additional_check": "The additional upload check has no uploaded document to examine.",
        "dates_amounts_and_deadlines": WAIVER_REASONS["dates_amounts_and_deadlines"],
    }
    assert validate_review(review, ANSWER_HASH, SOURCES)["quality_pass"] is True
    review["checks"]["additional_check"] = "HOLD"
    assert_factual_hold(review)


@pytest.mark.parametrize("field,value", [
    ("checks", {}), ("checks", []), ("checks", None),
    ("material_claims", []), ("material_claims", {}), ("material_claims", None),
    ("material_claims", [None]), ("material_claims", [{}]),
    ("omissions", None), ("omissions", {}), ("omissions", ""),
    ("omissions", ["Unaddressed controlling issue"]),
])
def test_empty_or_malformed_review_never_false_passes(review: dict, field: str, value: object) -> None:
    review[field] = value
    review.update(factual_pass=True, quality_pass=True, total_score=100, hold_reasons=[])
    assert_factual_hold(review)


@pytest.mark.parametrize("row", [None, [], "", 1, {}, {"scores": dict(QUALITY_MAX)}])
def test_invalid_review_objects_fail_closed(row: object) -> None:
    assert_factual_hold(row)


@pytest.mark.parametrize("value", [None, False, True, 0.0, "0", -1, 1, [], {}])
def test_unclaimed_assertions_require_explicit_integer_zero(review: dict, value: object) -> None:
    review["unclaimed_assertions_count"] = value
    assert "UNCLAIMED_ASSERTIONS_NOT_DECLARED_ZERO" in assert_factual_hold(review)["hold_reasons"]


@pytest.mark.parametrize("value", [None, "HOLD", "FAIL", "NOT_APPLICABLE", True, "PASS ", {}])
def test_source_currentness_requires_explicit_pass(review: dict, value: object) -> None:
    review["source_currentness"] = value
    assert "SOURCE_CURRENTNESS_NOT_PASS" in assert_factual_hold(review)["hold_reasons"]


@pytest.mark.parametrize("field,value", [
    ("text", " "), ("text", None), ("text", 1),
    ("verdict", "UNSUPPORTED"), ("verdict", "CONTRADICTED"), ("verdict", "UNVERIFIED"),
    ("verdict", "PASS"), ("verdict", []),
    ("source_ids", []), ("source_ids", "source-a"), ("source_ids", None),
    ("source_ids", ["unknown"]), ("source_ids", ["source-a", "unknown"]),
    ("source_ids", ["source-a", "source-a"]), ("source_ids", [[]]),
])
def test_every_material_claim_requires_supported_text_and_known_sources(review: dict, field: str, value: object) -> None:
    second = deepcopy(review["material_claims"][0])
    second[field] = value
    review["material_claims"].append(second)
    assert_factual_hold(review)


@pytest.mark.parametrize("sources", [None, "source-a", {"source-a": "unverified"}, ["source-a", []], ["source-a", "source-a"], []])
def test_invalid_or_empty_source_registry_cannot_support_claims(review: dict, sources: object) -> None:
    assert_factual_hold(review, sources)


def test_claim_relabelling_does_not_waive_evidence(review: dict) -> None:
    review["material_claims"][0].update(claim_type="USER_FACT", is_legal=False, source_ids=[])
    assert_factual_hold(review)


@pytest.mark.parametrize("name", tuple(QUALITY_FLOORS))
def test_each_critical_floor_blocks_even_a_high_total(review: dict, name: str) -> None:
    review["scores"][name] = QUALITY_FLOORS[name] - 0.01
    result = validate_review(review, ANSWER_HASH, SOURCES)
    assert result["factual_pass"] is True and result["quality_pass"] is False
    assert result["total_score"] > 70
    assert f"QUALITY_CRITICAL_FLOOR:{name}" in result["hold_reasons"]


def test_total_and_floor_boundaries_are_inclusive_without_rounding_up(review: dict) -> None:
    review["scores"] = {name: maximum * 0.7 for name, maximum in QUALITY_MAX.items()}
    result = validate_review(review, ANSWER_HASH, SOURCES)
    assert result["quality_pass"] is True and result["total_score"] == 70.0
    review["scores"]["organisation_and_plain_language"] -= 0.00001
    result = validate_review(review, ANSWER_HASH, SOURCES)
    assert result["factual_pass"] is True and result["quality_pass"] is False
    assert result["total_score"] < 70
    assert result["hold_reasons"] == ["QUALITY_TOTAL_BELOW_70"]


@pytest.mark.parametrize("value", [True, False, "25", None, [], {}, -1, 25.01, float("nan"), float("inf"), -float("inf"), 10**1000])
def test_scores_must_be_finite_bounded_numbers(review: dict, value: object) -> None:
    review["scores"]["legal_and_factual_accuracy"] = value
    result = validate_review(review, ANSWER_HASH, SOURCES)
    assert result["factual_pass"] is True and result["quality_pass"] is False
    assert result["total_score"] is None and result["hold_reasons"]


@pytest.mark.parametrize("change", ["missing", "extra", "absent", "list"])
def test_all_seven_quality_dimensions_are_required(review: dict, change: str) -> None:
    if change == "missing":
        del review["scores"]["traceability_and_citations"]
    elif change == "extra":
        review["scores"]["bonus"] = 100
    elif change == "absent":
        del review["scores"]
    else:
        review["scores"] = list(QUALITY_MAX.values())
    result = validate_review(review, ANSWER_HASH, SOURCES)
    assert result["factual_pass"] is True and result["quality_pass"] is False
    assert result["total_score"] is None


@pytest.mark.parametrize("field,value", [("case_type", "system"), ("case_type", "unknown"), ("behavior_checks", {"safe": True}), ("system_pass", True), ("behavior_pass", True)])
def test_system_payload_cannot_launder_a_legal_quality_pass(review: dict, field: str, value: object) -> None:
    review[field] = value
    assert "SYSTEM_REVIEW_NOT_LEGAL" in assert_factual_hold(review)["hold_reasons"]


def system_review() -> dict:
    return {"case_type": "system", "answer_sha256": ANSWER_HASH,
            "behavior_checks": {"honest_hold": True, "no_unauthorised_sending": True}}


SYSTEM_CHECKS = ("honest_hold", "no_unauthorised_sending")


def test_system_result_is_only_a_boolean_and_never_a_legal_pass() -> None:
    row = system_review()
    before = deepcopy(row)
    assert validate_system_review(row, ANSWER_HASH, SYSTEM_CHECKS) is True
    assert row == before
    assert_factual_hold(row)


@pytest.mark.parametrize("change", ["hash", "missing_check", "extra_check", "empty", "truthy", "string", "hold", "case_type", "scores", "claims", "pretend_pass"])
def test_system_behavior_requires_exact_complete_boolean_checks(change: str) -> None:
    row = system_review()
    if change == "hash":
        row["answer_sha256"] = "a" * 64
    elif change == "missing_check":
        del row["behavior_checks"]["honest_hold"]
    elif change == "extra_check":
        row["behavior_checks"]["extra"] = True
    elif change == "empty":
        row["behavior_checks"] = {}
    elif change in ("truthy", "string", "hold"):
        row["behavior_checks"]["honest_hold"] = {"truthy": 1, "string": "PASS", "hold": False}[change]
    elif change == "case_type":
        row["case_type"] = "legal"
    elif change == "scores":
        row["scores"] = dict(QUALITY_MAX)
    elif change == "claims":
        row["material_claims"] = []
    else:
        row["quality_pass"] = True
    assert validate_system_review(row, ANSWER_HASH, SYSTEM_CHECKS) is False


@pytest.mark.parametrize("checks", [[], None, "honest_hold", ["honest_hold", "honest_hold"], [None]])
def test_system_expected_checks_cannot_be_empty_or_malformed(checks: object) -> None:
    assert validate_system_review(system_review(), ANSWER_HASH, checks) is False
