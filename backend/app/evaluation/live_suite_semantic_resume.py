"""Resume sealed semantic HOLDs. A retry cannot be forced to VERIFIED."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Literal

from .live30 import assert_safe_evaluation_payload
from .live_suite import sealed_sha256

SEMANTIC_RESUME_SCHEMA = "legalbot.semantic-hold-resume.v1"
SemanticHoldCause = Literal[
    "TECHNICAL_MODEL_TIMEOUT",
    "CLIENT_DISCONNECT",
    "MODEL_OUTPUT_PARSE_FAILURE",
    "MODEL_RUNTIME_FAILURE",
    "SEMANTIC_VERIFIER_SCHEMA_FAILURE",
    "EVIDENCE_PROMPT_TRUNCATION",
    "WRONG_EVIDENCE_SELECTION",
    "PROPOSITION_TOO_BROAD",
    "PARTIAL_SUPPORT",
    "UNSUPPORTED",
    "SUPPORTED",
    "CONTRADICTION",
    "CURRENTNESS_UNRESOLVED",
    "CONTRARY_AUTHORITY_UNRESOLVED",
    "OTHER",
]


def classify_semantic_hold_cause(record: Mapping[str, Any]) -> SemanticHoldCause:
    error = str(record.get("error") or record.get("exception") or "")
    lowered = error.casefold()
    if "disconnect" in lowered or "broken pipe" in lowered or "connection reset" in lowered:
        return "CLIENT_DISCONNECT"
    if "timeout" in lowered:
        return "TECHNICAL_MODEL_TIMEOUT"
    if "truncat" in lowered or "budget" in lowered:
        return "EVIDENCE_PROMPT_TRUNCATION"
    if "schema" in lowered:
        return "SEMANTIC_VERIFIER_SCHEMA_FAILURE"
    if "422" in error or "runtime" in lowered:
        nested = record.get("semantic_result")
        if not isinstance(nested, Mapping):
            return "MODEL_RUNTIME_FAILURE"
    nested = record.get("semantic_result")
    if not isinstance(nested, Mapping):
        if "parse" in lowered:
            return "MODEL_OUTPUT_PARSE_FAILURE"
        return "OTHER"
    result = str(nested.get("result") or "")
    if int(nested.get("contradiction_count") or 0) > 0:
        return "CONTRADICTION"
    if result == "unsupported":
        return "UNSUPPORTED"
    if result == "supported":
        return "SUPPORTED"
    if result == "knowledge_gap":
        spans = record.get("exact_gold_spans") or ()
        return "PARTIAL_SUPPORT" if spans else "UNSUPPORTED"
    if result == "limited":
        return "PARTIAL_SUPPORT"
    if result == "HOLD":
        return "OTHER"
    return "OTHER"


def resume_semantic_hold(
    record: Mapping[str, Any],
    *,
    force_verified: bool = False,
) -> dict[str, Any]:
    if force_verified:
        raise ValueError("a failed semantic retry cannot be forced to VERIFIED")
    nested = record.get("semantic_result")
    if not isinstance(nested, Mapping) or not nested.get("seal_sha256"):
        raise ValueError("semantic HOLD has no sealed verifier result to resume")
    result = str(nested.get("result") or "")
    payload = {
        "schema": SEMANTIC_RESUME_SCHEMA,
        "row_id": record.get("row_id"),
        "issue_id": record.get("issue_id"),
        "resumed": True,
        "fresh_invocation": False,
        "final_verification_status": "HOLD",
        "semantic_result": result,
        "semantic_result_seal_sha256": nested.get("seal_sha256"),
        "cause": classify_semantic_hold_cause(record),
        "forced_verified": False,
        "writes_active": False,
        "writes_o04": False,
    }
    payload["seal_sha256"] = sealed_sha256(payload)
    assert_safe_evaluation_payload(payload)
    return payload
