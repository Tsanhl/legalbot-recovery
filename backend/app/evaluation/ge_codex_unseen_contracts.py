"""Pure validation for the new Codex bank; no custody, IO or execution authority.

Callers supply the assigned public slots and independently bound answer/source
identities. These checks validate declarations, not the truth of legal analysis.
No historical bank, runtime or filesystem is consulted.
"""

from __future__ import annotations

import math
import re
import unicodedata
from collections.abc import Collection, Mapping, Sequence
from difflib import SequenceMatcher
from types import MappingProxyType
from typing import Any, TypedDict

FACTUAL_CHECKS = (
    "integrity_chain",
    "claim_evidence_support",
    "user_fact_provenance",
    "jurisdiction_scope",
    "requested_date_and_currentness",
    "dates_amounts_and_deadlines",
    "citation_and_quotation_identity",
    "contradiction_and_counterauthority",
    "safety_and_urgent_action",
    "privacy_and_instruction_isolation",
)
MANDATORY_FACTUAL_CHECKS = (
    "integrity_chain",
    "claim_evidence_support",
    "user_fact_provenance",
    "jurisdiction_scope",
    "requested_date_and_currentness",
    "citation_and_quotation_identity",
    "privacy_and_instruction_isolation",
)
QUALITY_MAX: Mapping[str, float] = MappingProxyType({
    "legal_and_factual_accuracy": 25.0,
    "issue_coverage_and_reasoning": 15.0,
    "authority_and_currentness": 15.0,
    "practical_steps_and_urgency": 15.0,
    "uncertainty_limits_and_clarification": 10.0,
    "organisation_and_plain_language": 10.0,
    "traceability_and_citations": 10.0,
})
QUALITY_FLOORS: Mapping[str, float] = MappingProxyType({
    "legal_and_factual_accuracy": 17.5,
    "authority_and_currentness": 10.5,
    "practical_steps_and_urgency": 9.0,
})
_CHECK_VALUES = ("PASS", "FAIL", "HOLD", "NOT_APPLICABLE")
_CLAIM_VERDICTS = ("SUPPORTED", "UNSUPPORTED", "CONTRADICTED", "UNVERIFIED")
_REQUIREMENTS = ("synthetic_upload_required", "multi_turn_required", "cross_issue_required")
_SYSTEM_FIELDS = ("behavior_checks", "behavior_pass", "system_pass")
_MAX_CASES = 420 + 23


class CodexUnseenContractError(ValueError):
    """Assigned cases are incomplete, malformed, duplicated or relabelled."""


class ReviewResult(TypedDict):
    factual_pass: bool
    quality_pass: bool
    total_score: float | None
    hold_reasons: list[str]


def _nonblank(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _names(value: Any) -> bool:
    return (
        isinstance(value, list | tuple | set | frozenset)
        and all(_nonblank(item) for item in value)
        and len(set(value)) == len(value)
    )


def _hash_matches(row: Mapping[str, Any], expected: Any) -> bool:
    return (
        isinstance(expected, str)
        and re.fullmatch(r"[0-9a-f]{64}", expected) is not None
        and isinstance(row.get("answer_sha256"), str)
        and row["answer_sha256"] == expected
    )


def _question_tokens(question: str) -> tuple[str, ...]:
    normal = unicodedata.normalize("NFKC", question).casefold()
    normal = "".join(char for char in normal if unicodedata.category(char) != "Cf")
    return tuple(re.findall(r"[^\W_]+", normal))


def _applicability_reason(value: Any) -> bool:
    if not _nonblank(value):
        return False
    explanation = " ".join(_question_tokens(value))
    # Reject empty/placeholder declarations; whether the explanation is supported
    # by the case evidence remains the evidence-bound reviewer's responsibility.
    return bool(explanation) and explanation not in (
        "na", "n a", "none", "not applicable", "not needed", "not required",
    )


def _light_duplicate(left: tuple[str, ...], right: tuple[str, ...]) -> bool:
    if left == right:
        return True
    # Detect small wording edits as well as punctuation/case/spacing changes.
    # Short, substantively different questions should not be fuzzy-matched.
    if min(len(left), len(right)) < 8:
        return False
    matcher = SequenceMatcher(None, left, right, autojunk=False)
    return (
        matcher.real_quick_ratio() >= 0.92
        and matcher.quick_ratio() >= 0.92
        and matcher.ratio() >= 0.92
    )


def validate_cases(
    cases: Sequence[Mapping[str, Any]], expected_slots: Sequence[Mapping[str, Any]]
) -> None:
    """Validate an exact assigned batch (1..443); raise on its first defect.

    Each slot has slot_id/family, with optional domain, variant and requirement
    flags as in ge_everyday_unseen.coverage_slots(). Each case has case_id,
    family, question, follow_up, uploads and secondary_domains, plus domain when
    assigned. Uploaded pages are nonblank text strings, format is PDF or PNG.
    Slot metadata in a case cannot override its assignment. This is lexical
    duplicate detection, not proof of semantic novelty or actual rendered files.
    """
    if not isinstance(expected_slots, list | tuple) or not 1 <= len(expected_slots) <= _MAX_CASES:
        raise CodexUnseenContractError("expected_slots must contain 1..443 assigned objects")
    if not isinstance(cases, list | tuple) or len(cases) != len(expected_slots):
        raise CodexUnseenContractError("case count differs from assigned slots")
    assigned: dict[str, Mapping[str, Any]] = {}
    for slot in expected_slots:
        if not isinstance(slot, Mapping) or not _nonblank(slot.get("slot_id")):
            raise CodexUnseenContractError("invalid assigned slot_id")
        if not _nonblank(slot.get("family")):
            raise CodexUnseenContractError("invalid assigned family")
        if slot["slot_id"] in assigned:
            raise CodexUnseenContractError("duplicate assigned slot_id")
        for name in _REQUIREMENTS:
            if name in slot and type(slot[name]) is not bool:
                raise CodexUnseenContractError(f"invalid assigned {name}")
        for name in ("domain", "variant", "case_type"):
            if name in slot and not _nonblank(slot[name]):
                raise CodexUnseenContractError(f"invalid assigned {name}")
        assigned[slot["slot_id"]] = slot

    seen: set[str] = set()
    questions: list[tuple[str, ...]] = []
    for case in cases:
        if not isinstance(case, Mapping) or not _nonblank(case.get("case_id")):
            raise CodexUnseenContractError("invalid case_id")
        case_id = case["case_id"]
        if case_id not in assigned:
            raise CodexUnseenContractError("case_id is not an exact assigned slot_id")
        if case_id in seen:
            raise CodexUnseenContractError("duplicate case_id")
        seen.add(case_id)
        slot = assigned[case_id]
        if "slot_id" in case and case["slot_id"] != case_id:
            raise CodexUnseenContractError("case slot_id differs from case_id")
        for name in ("family", "domain"):
            if name in slot and case.get(name) != slot[name]:
                raise CodexUnseenContractError(f"case changed assigned {name}")
        for name in ("variant", "case_type", *_REQUIREMENTS):
            if name in case and (
                name not in slot or type(case[name]) is not type(slot[name])
                or case[name] != slot[name]
            ):
                raise CodexUnseenContractError(f"case changed assigned {name}")

        if not _nonblank(case.get("question")):
            raise CodexUnseenContractError("question must be nonblank text")
        tokens = _question_tokens(case["question"])
        if not tokens:
            raise CodexUnseenContractError("question has no words")
        if any(_light_duplicate(tokens, other) for other in questions):
            raise CodexUnseenContractError("lightly duplicated normalized question")
        questions.append(tokens)
        if not isinstance(case.get("follow_up"), str):
            raise CodexUnseenContractError("follow_up must be text")
        if slot.get("multi_turn_required") is True and not _nonblank(case["follow_up"]):
            raise CodexUnseenContractError("multi-turn slot requires a nonblank follow_up")

        uploads = case.get("uploads")
        if not isinstance(uploads, list):
            raise CodexUnseenContractError("uploads must be a list")
        if (slot.get("synthetic_upload_required") is True or slot.get("variant") == "document") and not uploads:
            raise CodexUnseenContractError("document slot requires uploads")
        for upload in uploads:
            if not isinstance(upload, Mapping) or not _nonblank(upload.get("title")):
                raise CodexUnseenContractError("upload requires a nonblank title")
            if upload.get("format") not in ("PDF", "PNG"):
                raise CodexUnseenContractError("upload format must be PDF or PNG")
            pages = upload.get("pages")
            if not isinstance(pages, list) or not pages or not all(_nonblank(page) for page in pages):
                raise CodexUnseenContractError("upload pages must be nonempty strings")

        domains = case.get("secondary_domains")
        if not isinstance(domains, list) or not _names(domains):
            raise CodexUnseenContractError("secondary_domains must be distinct nonblank strings")
        if slot.get("cross_issue_required") is True and not domains:
            raise CodexUnseenContractError("cross-issue slot requires secondary_domains")
        if case.get("domain") in domains:
            raise CodexUnseenContractError("secondary_domains must differ from the primary domain")


def validate_review(
    row: Mapping[str, Any], answer_sha256: str, source_ids: Collection[str]
) -> ReviewResult:
    """Return fail-closed legal review results without modifying inputs.

    Required row fields: answer_sha256, checks (all FACTUAL_CHECKS), material_claims
    (nonempty list of text/verdict/source_ids objects), omissions (list),
    unclaimed_assertions_count (integer zero), and scores (all QUALITY_MAX keys).
    MANDATORY_FACTUAL_CHECKS require explicit PASS. The other three factual checks
    may be NOT_APPLICABLE only with applicability_reasons mapping each waived
    check to a nonblank substantive explanation grounded in the reviewed evidence.
    Additional checks use the same waiver rule. All-PASS rows may omit this field.
    The count declares material assertions remaining outside the reviewed claim
    list; absence is not zero. Every material claim must cite supplied source IDs,
    including fact/document provenance where needed; relabelling cannot waive it.
    source_currentness must explicitly be PASS to obtain a full pass. Neither
    currentness gate can be waived by needs_legal_currentness or a generic-question
    label. Missing/unresolved currentness holds the factual gate. case_type, if present,
    must be 'legal'. System behavior belongs to validate_system_review().

    total_score is None until the factual gate and score schema both pass. Scores
    cannot compensate for a factual hold. Identity/source capture verification and
    finding undeclared assertions require the caller/reviewer; this has no answer
    text or source bytes with which to independently verify those declarations.
    """
    reasons: list[str] = []
    result: ReviewResult = {
        "factual_pass": False, "quality_pass": False,
        "total_score": None, "hold_reasons": reasons,
    }
    if not isinstance(row, Mapping):
        reasons.append("INVALID_REVIEW_OBJECT")
        return result
    if row.get("case_type", "legal") != "legal" or any(name in row for name in _SYSTEM_FIELDS):
        reasons.append("SYSTEM_REVIEW_NOT_LEGAL")
        return result
    if not _hash_matches(row, answer_sha256):
        reasons.append("ANSWER_HASH_MISMATCH_OR_INVALID")
    known_sources = set(source_ids) if _names(source_ids) else set()
    if not _names(source_ids):
        reasons.append("INVALID_SOURCE_IDS")
    if row.get("source_currentness") != "PASS":
        reasons.append("SOURCE_CURRENTNESS_NOT_PASS")

    checks = row.get("checks")
    if not isinstance(checks, dict) or not checks:
        reasons.append("MISSING_OR_EMPTY_FACTUAL_CHECKS")
        checks = {}
    for name in FACTUAL_CHECKS:
        if name not in checks:
            reasons.append(f"MISSING_FACTUAL_CHECK:{name}")
    applicability_reasons = row.get("applicability_reasons", {})
    if not isinstance(applicability_reasons, Mapping):
        reasons.append("INVALID_APPLICABILITY_REASONS")
        applicability_reasons = {}
    for index, (name, value) in enumerate(checks.items()):
        if value not in _CHECK_VALUES:
            reasons.append(f"INVALID_FACTUAL_CHECK_VALUE:{index}")
        elif value not in ("PASS", "NOT_APPLICABLE"):
            reasons.append(f"FACTUAL_CHECK_NOT_PASS:{name if name in FACTUAL_CHECKS else index}")
        elif value == "NOT_APPLICABLE":
            if name in MANDATORY_FACTUAL_CHECKS:
                reasons.append(f"FACTUAL_CHECK_NOT_PASS:{name}")
            elif not _applicability_reason(applicability_reasons.get(name)):
                reasons.append(f"MISSING_OR_INVALID_APPLICABILITY_REASON:{name if name in FACTUAL_CHECKS else index}")

    count = row.get("unclaimed_assertions_count")
    if type(count) is not int or count != 0:
        reasons.append("UNCLAIMED_ASSERTIONS_NOT_DECLARED_ZERO")
    omissions = row.get("omissions")
    if not isinstance(omissions, list):
        reasons.append("MISSING_OR_INVALID_OMISSIONS")
    elif omissions:
        reasons.append("MATERIAL_OMISSIONS_PRESENT")

    claims = row.get("material_claims")
    if not isinstance(claims, list) or not claims:
        reasons.append("MISSING_OR_EMPTY_MATERIAL_CLAIMS")
        claims = []
    for index, claim in enumerate(claims):
        if not isinstance(claim, Mapping):
            reasons.append(f"INVALID_MATERIAL_CLAIM:{index}")
            continue
        if not _nonblank(claim.get("text")):
            reasons.append(f"MISSING_CLAIM_TEXT:{index}")
        verdict = claim.get("verdict")
        if verdict not in _CLAIM_VERDICTS:
            reasons.append(f"INVALID_CLAIM_VERDICT:{index}")
        elif verdict != "SUPPORTED":
            reasons.append(f"CLAIM_NOT_SUPPORTED:{index}")
        refs = claim.get("source_ids")
        if not isinstance(refs, list) or not refs or not _names(refs):
            reasons.append(f"MISSING_OR_INVALID_CLAIM_SOURCES:{index}")
        elif not set(refs).issubset(known_sources):
            reasons.append(f"UNKNOWN_CLAIM_SOURCE:{index}")

    if reasons:
        return result
    result["factual_pass"] = True
    scores = row.get("scores")
    if not isinstance(scores, dict) or set(scores) != set(QUALITY_MAX):
        reasons.append("INVALID_QUALITY_SCORE_KEYS")
        return result
    for name, maximum in QUALITY_MAX.items():
        value = scores[name]
        if type(value) not in (int, float) or not 0 <= value <= maximum:
            reasons.append(f"INVALID_QUALITY_SCORE:{name}")
    if reasons:
        return result
    total = math.fsum(scores.values())
    result["total_score"] = total
    if total < 70:
        reasons.append("QUALITY_TOTAL_BELOW_70")
    for name, floor in QUALITY_FLOORS.items():
        if scores[name] < floor:
            reasons.append(f"QUALITY_CRITICAL_FLOOR:{name}")
    result["quality_pass"] = not reasons
    return result


def validate_system_review(
    row: Mapping[str, Any], answer_sha256: str, expected_checks: Collection[str]
) -> bool:
    """Score system behavior only: exact hash, exact checks, literal True values.

    Required row fields: case_type='system', answer_sha256, behavior_checks.
    expected_checks must come from the assigned scenario, not the review. Empty,
    missing or surplus checks and mixed legal score payloads return False. This
    boolean must be counted in the separate system denominator, never legal scores.
    """
    if not isinstance(row, Mapping) or row.get("case_type") != "system":
        return False
    if not _hash_matches(row, answer_sha256) or not _names(expected_checks) or not expected_checks:
        return False
    if any(name in row for name in (
        "checks", "material_claims", "scores", "factual_pass", "quality_pass", "total_score",
    )):
        return False
    checks = row.get("behavior_checks")
    return (
        isinstance(checks, dict)
        and set(checks) == set(expected_checks)
        and all(value is True for value in checks.values())
    )
