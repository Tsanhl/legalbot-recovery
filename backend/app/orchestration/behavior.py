"""Deterministic A2 failure-reason router. Runs before model invocation."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from ..privacy import prompt_injection_hits
from ..types import ReleaseState


class FailureReasonCode(StrEnum):
    OUTSIDE_PRODUCT_JURISDICTION = "outside_product_jurisdiction"
    MISSING_USER_FACTS = "missing_user_facts"
    MISSING_DOCUMENT = "missing_document"
    ENCRYPTED_OR_UNREADABLE_UPLOAD = "encrypted_or_unreadable_upload"
    ENTIRELY_UNSAFE = "entirely_unsafe"
    MIXED_SAFE_UNSAFE = "mixed_safe_unsafe"
    INDEX_NOT_READY = "index_not_ready"
    RETRIEVER_UNAVAILABLE = "retriever_unavailable"
    HEALTHY_RETRIEVAL_ZERO_HITS = "healthy_retrieval_zero_hits"
    EVIDENCE_INSUFFICIENT = "evidence_insufficient"
    RELEVANCE_THRESHOLD_POLICY_NOT_FROZEN = "relevance_threshold_policy_not_frozen"
    NO_THRESHOLD_QUALIFIED_EVIDENCE = "no_threshold_qualified_evidence"
    PROCEED = "proceed"


class BehaviorAction(StrEnum):
    REFUSE = "refuse"
    CLARIFY = "clarify"
    VERIFIED_LIMITED = "verified_limited"
    MIXED = "mixed"
    PROCEED_TO_MODEL = "proceed_to_model"


_MISSING_FACT_CUES = (
    "the parties",
    "the claimant",
    "the defendant",
    "advise",
    "problem question",
    "consider whether",
)
_FACT_MARKERS = (
    "dated",
    "in 19",
    "in 20",
    "£",
    " pounds",
    "limited",
    " plc",
    " llp",
    " mr ",
    " mrs ",
    " ms ",
    "between ",
)
_DOCUMENT_CUES = (
    "attach",
    "the contract",
    "the will",
    "the lease",
    "the agreement",
    "the judgment",
    "this clause",
    "the instrument",
)


@dataclass(frozen=True, slots=True)
class BehaviorSignals:
    question: str
    jurisdiction: str = "England and Wales"
    upload_unreadable: bool = False
    upload_encrypted: bool = False
    index_ready: bool = True
    retriever_available: bool = True
    retrieval_attempted: bool = False
    retrieval_hit_count: int = 0
    qualifying_evidence_count: int = 0
    unsafe_question: bool = False
    unsafe_upload: bool = False
    mixed_unsafe_remainder: bool = False
    missing_named_document: bool = False
    current_law_escalation_approved: bool = False
    retrieval_failure_code: str | None = None


@dataclass(frozen=True, slots=True)
class BehaviorDecision:
    reason_code: FailureReasonCode
    action: BehaviorAction
    invoke_model: bool
    release_state: ReleaseState | None
    user_message: str
    limitations: tuple[str, ...] = ()
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def is_verified_limited(self) -> bool:
        return self.action == BehaviorAction.VERIFIED_LIMITED


def route_behavior(signals: BehaviorSignals) -> BehaviorDecision:
    """Choose a named pre-model outcome. Never invents legal gold."""

    if signals.jurisdiction.casefold().strip() not in {
        "england and wales",
        "england & wales",
        "e&w",
    }:
        return BehaviorDecision(
            FailureReasonCode.OUTSIDE_PRODUCT_JURISDICTION,
            BehaviorAction.CLARIFY,
            False,
            None,
            "LegalBot v1 is limited to England and Wales. A Scotland, Northern Ireland, or other-jurisdiction answer was not attempted.",
            ("outside_product_jurisdiction: no model call and no cross-jurisdiction inference.",),
        )

    if signals.unsafe_question and not signals.mixed_unsafe_remainder:
        return BehaviorDecision(
            FailureReasonCode.ENTIRELY_UNSAFE,
            BehaviorAction.REFUSE,
            False,
            None,
            "This request cannot be answered because it is unsafe. No model call was made.",
            ("The request was refused under the injection, exfiltration or disallowed-task rule.",),
        )
    if signals.upload_encrypted or signals.upload_unreadable:
        return BehaviorDecision(
            FailureReasonCode.ENCRYPTED_OR_UNREADABLE_UPLOAD,
            BehaviorAction.CLARIFY,
            False,
            None,
            "Please provide a usable, unencrypted copy of the attached material. The model was not invoked.",
            ("An attached file was encrypted, unreadable, or failed local parsing.",),
        )
    if (
        _missing_user_facts(signals.question)
        and not signals.unsafe_question
        and not signals.mixed_unsafe_remainder
    ):
        return BehaviorDecision(
            FailureReasonCode.MISSING_USER_FACTS,
            BehaviorAction.CLARIFY,
            False,
            None,
            "Please supply the missing facts (dates, parties, amounts, or the governing jurisdiction) before a legal answer can be attempted.",
            ("The issue plan requires facts that the question does not contain.",),
        )
    if not signals.retriever_available:
        return BehaviorDecision(
            FailureReasonCode.RETRIEVER_UNAVAILABLE,
            BehaviorAction.VERIFIED_LIMITED,
            False,
            ReleaseState.VERIFIED_LIMITED,
            "Retrieval is unavailable. This is an infrastructure limitation, not a request for clarification.",
            ("The retriever could not be constructed; no model call was made.",),
        )
    if not signals.index_ready:
        return BehaviorDecision(
            FailureReasonCode.INDEX_NOT_READY,
            BehaviorAction.VERIFIED_LIMITED,
            False,
            ReleaseState.VERIFIED_LIMITED,
            "The serving index is not ready. Catalogue or chunks may exist, but no ACTIVE generation is selected. Do not ask the user for more facts.",
            ("index_not_ready: ACTIVE pointer or catalogue serving generation is absent.",),
        )
    if signals.missing_named_document:
        return BehaviorDecision(
            FailureReasonCode.MISSING_DOCUMENT,
            BehaviorAction.CLARIFY,
            False,
            None,
            "The named instrument is not in the approved corpus. Please identify the exact document; Find Case Law full text will not be fetched.",
            ("A required primary instrument is absent from the approved authority set.",),
        )
    if signals.unsafe_question and signals.mixed_unsafe_remainder:
        if signals.qualifying_evidence_count > 0:
            return BehaviorDecision(
                FailureReasonCode.MIXED_SAFE_UNSAFE,
                BehaviorAction.MIXED,
                True,
                ReleaseState.VERIFIED_LIMITED,
                "The unsafe portion is refused. The model may be invoked only for the supported safe remainder.",
                (
                    "Unsafe remainder refused; safe remainder may be answered from existing evidence only.",
                ),
            )
        return BehaviorDecision(
            FailureReasonCode.MIXED_SAFE_UNSAFE,
            BehaviorAction.VERIFIED_LIMITED,
            False,
            ReleaseState.VERIFIED_LIMITED,
            "The unsafe portion is refused. No supported evidence exists for the remainder, so no model call was made.",
            ("Unsafe remainder refused; no evidence for a safe subset.",),
        )
    if signals.retrieval_failure_code == "relevance_threshold_policy_not_frozen":
        return BehaviorDecision(
            FailureReasonCode.RELEVANCE_THRESHOLD_POLICY_NOT_FROZEN,
            BehaviorAction.VERIFIED_LIMITED,
            False,
            ReleaseState.HELD_FOR_REVIEW,
            "The calibrated retrieval relevance policy is not frozen, so no answer model was invoked.",
            (
                "relevance_threshold_policy_not_frozen: retrieval may not supply answer evidence.",
            ),
        )
    if signals.retrieval_failure_code == "no_threshold_qualified_evidence":
        return BehaviorDecision(
            FailureReasonCode.NO_THRESHOLD_QUALIFIED_EVIDENCE,
            BehaviorAction.VERIFIED_LIMITED,
            False,
            ReleaseState.HELD_FOR_REVIEW,
            "Retrieved material did not meet the frozen relevance threshold, so no answer model was invoked.",
            (
                "no_threshold_qualified_evidence: below-threshold sources were logged as a knowledge gap, not used as legal evidence.",
            ),
        )
    if signals.retrieval_attempted and signals.retrieval_hit_count == 0:
        extra = (
            "An approved current-law gap flag was recorded."
            if signals.current_law_escalation_approved
            else "No qualifying spans were retrieved against a healthy index."
        )
        return BehaviorDecision(
            FailureReasonCode.HEALTHY_RETRIEVAL_ZERO_HITS,
            BehaviorAction.VERIFIED_LIMITED,
            False,
            ReleaseState.VERIFIED_LIMITED,
            f"No qualifying source spans were found. {extra}",
            ("healthy_retrieval_zero_hits: verified_limited evidence path; model not invoked.",),
            {"current_law_escalation_approved": signals.current_law_escalation_approved},
        )
    if signals.retrieval_attempted and signals.qualifying_evidence_count == 0:
        return BehaviorDecision(
            FailureReasonCode.EVIDENCE_INSUFFICIENT,
            BehaviorAction.VERIFIED_LIMITED,
            False,
            ReleaseState.VERIFIED_LIMITED,
            "Retrieved candidates did not survive identity, currentness, jurisdiction or safety qualification.",
            ("evidence_insufficient: verified_limited; model not invoked.",),
        )
    return BehaviorDecision(
        FailureReasonCode.PROCEED,
        BehaviorAction.PROCEED_TO_MODEL,
        True,
        None,
        "Deterministic policy allows model invocation on frozen qualified evidence.",
    )


def question_is_entirely_unsafe(question: str) -> bool:
    return bool(prompt_injection_hits(question))


def _missing_user_facts(question: str) -> bool:
    text = f" {question.casefold()} "
    if not any(cue in text for cue in _MISSING_FACT_CUES):
        return False
    if any(marker in text for marker in _FACT_MARKERS):
        return False
    return not any(char.isdigit() for char in question)


def looks_like_missing_document(question: str, retrieval_hit_count: int) -> bool:
    text = question.casefold()
    return retrieval_hit_count == 0 and any(cue in text for cue in _DOCUMENT_CUES)
