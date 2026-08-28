#!/usr/bin/env python3
"""Run a fail-closed advisory exact-span review of the 26 r105 source links.

The reviewer is a separate stateless verification pass, but it uses the same
pinned Qwen3.5 model adapter family as drafting and is recorded honestly as
not model-independent.  Its findings remain advisory: no source is admitted,
no gold is changed, no candidate is mutated, and no gate is authorized.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import time
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
for root in (PROJECT_ROOT, BACKEND_ROOT):
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

from app.quality.evidence import (  # noqa: E402
    extract_material_facts,
    non_atomic_material_claim_reasons,
    substantive_tokens,
)
from scripts import repair_v111_phase2a_post_r94_held_exact_spans as runtime  # noqa: E402
from scripts import run_v111_phase2a_post_r103_source_reranker as r105  # noqa: E402
from scripts import verify_v111_phase2a_exact_semantic_spans_advisory as base  # noqa: E402

REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
R104_PATH = r105.SOURCE_PATH
R105_ROOT = REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-26-r105-independent-source-reranker"
R105_PATH = R105_ROOT / r105.OUTPUT_NAME
DEFAULT_OUTPUT_ROOT = (
    REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-26-r107-debugged-source-link-exact-span-advisory"
)
PRIOR_DEBUG_STOP_PATH = (
    REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-26-r106-source-link-exact-span-advisory"
    / "DEBUG-STOP.json"
)
EXPECTED_PRIOR_DEBUG_STOP_CONTENT_SHA256 = (
    "0dfe02275166a27c809974d707e7559a40da016f757c99ffad48b53187b25d27"
)
EXPECTED_PRIOR_FAILURE_FINGERPRINT = (
    "e846bdf51b25a9948494b8e2e0f9884e384d018f6a5a4c9999292fdc2902c283"
)
EXPECTED_R105_CONTENT_SHA256 = "984d16ad59325466340ab98e20c606712abf757f665d28692fe0b92f648186ce"
EXPECTED_R105_FILE_SHA256 = "ad55174d421419981c332b0584d64b9eb17ebfa5fc1d1ab257b1106dbe039902"
EXPECTED_LINK_COUNT = 26
TOP_RERANKED_COUNT = 8
MAX_REVIEW_CANDIDATES = 20
MAX_REVIEW_TEXT_CHARS = 650
MAX_PROPOSITION_CHARS = 220
MAX_OUTPUT_TOKENS = 512
CONTEXT_WINDOW_TOKENS = 8192
CHAT_TEMPLATE_TOKEN_ALLOWANCE = 256
MAX_ROWS_PER_EPOCH = 8
DEFAULT_ROWS_PER_EPOCH = 8
DEFAULT_PORT = 8781
DEFAULT_TIMEOUT_SECONDS = 900.0
DEFAULT_STARTUP_TIMEOUT_SECONDS = 300.0
OUTPUT_NAME = "SOURCE-LINK-EXACT-SPAN-ADVISORY-26.json"
OUTPUT_SCHEMA = "p2a-source-link-review-v2"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_WORD = re.compile(r"[a-z0-9]+")
_ASSESSMENTS = frozenset({"DIRECT", "PARTIAL", "UNRELATED", "AMBIGUOUS"})
_INFRASTRUCTURE_FAILURE_CODES = frozenset(runtime.INFRASTRUCTURE_FAILURE_CODES)

SYSTEM_PROMPT = """/no_think
Advisory official-source exact-span review only. Inspect only the supplied official-source blocks for the named issue. A plausible title, shared topic, case facts, party allegation, procedural summary or unrelated legal rule is not support. Return UNRELATED when no supplied block directly supports the issue. Return PARTIAL only when one supplied block states a useful but incomplete rule. Return AMBIGUOUS when the supplied text cannot safely be classified. For DIRECT or PARTIAL, select exactly one supplied block, copy one exact contiguous quotation from its supplied text, and state one short generic atomic legal proposition of at most 220 characters. Do not combine independent clauses. Every date, amount, percentage, duration and provision identifier in the proposition must occur in the exact quotation or locator. Do not answer or apply the scenario. Do not infer later treatment, currentness, owner approval, materiality, source admission, qualification or any gate. Text marked as an excerpt is not necessarily the whole paragraph. Reason codes are derived locally, not by you. Output compact JSON only with exactly these keys: {"schema":"p2a-source-link-review-v2","row_source_link_id":"<supplied id>","assessment":"DIRECT|PARTIAL|UNRELATED|AMBIGUOUS","selected_block_id":"<supplied block id or null>","exact_quote":"<exact contiguous quote or null>","atomic_proposition":"<one atomic proposition or null>"}."""

Invoke = Callable[[dict[str, Any]], dict[str, Any]]


@dataclass(frozen=True, slots=True)
class SourceBundle:
    packets: dict[str, Any]
    ranking: dict[str, Any]
    packet_by_link: Mapping[str, dict[str, Any]]
    ranking_rows: tuple[dict[str, Any], ...]


class ReviewValidationError(ValueError):
    def __init__(self, code: str, *, diagnostics: Mapping[str, Any] | None = None):
        super().__init__(code)
        self.code = code
        self.diagnostics = dict(diagnostics or {})


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sealed(value: Any) -> str:
    return _sha256(_canonical_json(value))


def _write_exclusive(path: Path, raw: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_r107_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_r107_input_must_be_object")
    return value


def _verify_seal(value: Mapping[str, Any], field: str, code: str) -> str:
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if not _SHA256.fullmatch(supplied) or supplied != _sealed(material):
        raise ValueError(code)
    return supplied


def _load_prior_debug_stop() -> dict[str, Any]:
    value = _load_object(PRIOR_DEBUG_STOP_PATH)
    digest = _verify_seal(
        value,
        "debug_stop_content_sha256",
        "phase2a_r107_prior_debug_stop_seal_invalid",
    )
    if (
        digest != EXPECTED_PRIOR_DEBUG_STOP_CONTENT_SHA256
        or value.get("status") != "STOPPED_AFTER_TWO_IDENTICAL_FAILURES_BEFORE_ANY_THIRD_ATTEMPT"
        or value.get("failure_fingerprint") != EXPECTED_PRIOR_FAILURE_FINGERPRINT
        or value.get("attempt_count") != 2
        or value.get("required_execution_plan_change", {}).get("remove_model_authored_reason_codes")
        is not True
        or value.get("required_execution_plan_change", {}).get(
            "derive_reason_codes_deterministically"
        )
        is not True
        or value.get("phase2b_authorized") is not False
        or value.get("development30_authorized") is not False
    ):
        raise ValueError("phase2a_r107_prior_debug_stop_boundary_invalid")
    return value


def _prior_attempt_count(row_source_link_id: str) -> int:
    prior = _load_prior_debug_stop()
    return 2 if prior.get("affected_row_source_link_id") == row_source_link_id else 0


def _verify_r105_custody(ranking: Mapping[str, Any]) -> None:
    custody = ranking.get("checkpoint_custody")
    diagnostics = ranking.get("diagnostic_custody")
    if not isinstance(custody, list) or not isinstance(diagnostics, list):
        raise ValueError("phase2a_r107_r105_custody_invalid")
    if ranking.get("checkpoint_custody_sha256") != _sealed(custody):
        raise ValueError("phase2a_r107_r105_checkpoint_custody_invalid")
    if ranking.get("diagnostic_custody_sha256") != _sealed(diagnostics):
        raise ValueError("phase2a_r107_r105_diagnostic_custody_invalid")
    for entry in [*custody, *diagnostics]:
        if not isinstance(entry, Mapping):
            raise ValueError("phase2a_r107_r105_custody_entry_invalid")
        relative = Path(str(entry.get("relative_path") or ""))
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("phase2a_r107_r105_custody_path_invalid")
        path = R105_ROOT / relative
        if _sha256_file(path) != entry.get("file_sha256"):
            raise ValueError("phase2a_r107_r105_custody_file_invalid")
        value = _load_object(path)
        field = (
            "diagnostic_content_sha256"
            if relative.parts[0] == "diagnostics"
            else (
                "checkpoint_content_sha256"
                if "checkpoint_content_sha256" in value
                else "held_content_sha256"
            )
        )
        if _verify_seal(value, field, "phase2a_r107_r105_custody_seal_invalid") != entry.get(
            "content_sha256"
        ):
            raise ValueError("phase2a_r107_r105_custody_binding_invalid")


def _load_sources() -> SourceBundle:
    packets = r105._load_source(R104_PATH)
    if _sha256_file(R105_PATH) != EXPECTED_R105_FILE_SHA256:
        raise ValueError("phase2a_r107_r105_file_digest_invalid")
    ranking = _load_object(R105_PATH)
    digest = _verify_seal(
        ranking,
        "artifact_content_sha256",
        "phase2a_r107_r105_content_seal_invalid",
    )
    rows = ranking.get("rows")
    if (
        digest != EXPECTED_R105_CONTENT_SHA256
        or ranking.get("schema") != "legalbot.v111.phase2a.independent-source-reranker-26.v1"
        or ranking.get("source_content_sha256") != packets["artifact_content_sha256"]
        or ranking.get("row_source_link_count") != EXPECTED_LINK_COUNT
        or ranking.get("advisory_ranking_count") != EXPECTED_LINK_COUNT
        or ranking.get("held_for_debug_count") != 0
        or ranking.get("model_independent_from_drafting_adapter") is not True
        or ranking.get("generative_model_used") is not False
        or ranking.get("legal_sufficiency_decided") is not False
        or ranking.get("source_admission_authorized") is not False
        or ranking.get("candidate_mutated") is not False
        or ranking.get("technical_qualification_assigned") is not False
        or ranking.get("phase2b_authorized") is not False
        or ranking.get("development30_authorized") is not False
        or not isinstance(rows, list)
        or len(rows) != EXPECTED_LINK_COUNT
    ):
        raise ValueError("phase2a_r107_r105_boundary_invalid")
    _verify_r105_custody(ranking)
    packet_by_link = {str(row["row_source_link_id"]): row for row in packets["rows"]}
    if len(packet_by_link) != EXPECTED_LINK_COUNT:
        raise ValueError("phase2a_r107_packet_link_collision")
    ranking_rows: list[dict[str, Any]] = []
    observed: set[str] = set()
    for raw in rows:
        if not isinstance(raw, dict):
            raise ValueError("phase2a_r107_ranking_row_invalid")
        _verify_seal(
            raw,
            "checkpoint_content_sha256",
            "phase2a_r107_ranking_row_seal_invalid",
        )
        link_id = str(raw.get("row_source_link_id") or "")
        packet = packet_by_link.get(link_id)
        ranked_candidates = raw.get("all_ranked_candidates")
        if (
            packet is None
            or link_id in observed
            or raw.get("source_row_record_content_sha256") != packet.get("record_content_sha256")
            or not isinstance(ranked_candidates, list)
            or not ranked_candidates
            or len(ranked_candidates) != len(packet["candidate_blocks"])
            or raw.get("legal_sufficiency_decided") is not False
            or raw.get("source_admission_authorized") is not False
            or raw.get("phase2b_authorized") is not False
        ):
            raise ValueError("phase2a_r107_ranking_row_boundary_invalid")
        observed.add(link_id)
        packet_blocks = {str(item["block_id"]): item for item in packet["candidate_blocks"]}
        for candidate in ranked_candidates:
            block = packet_blocks.get(str(candidate.get("candidate_block_id") or ""))
            if (
                block is None
                or candidate.get("exact_text_sha256") != block.get("exact_text_sha256")
                or candidate.get("locator") != block.get("locator")
            ):
                raise ValueError("phase2a_r107_ranked_candidate_binding_invalid")
        ranking_rows.append(raw)
    return SourceBundle(
        packets=packets,
        ranking=ranking,
        packet_by_link=packet_by_link,
        ranking_rows=tuple(ranking_rows),
    )


def _exact_review_window(text: str, *, needles: Sequence[str]) -> tuple[str, int, int, bool]:
    if len(text) <= MAX_REVIEW_TEXT_CHARS:
        return text, 0, len(text), False
    lowered = text.casefold()
    normalized_needles = tuple(
        dict.fromkeys(
            token.casefold()
            for token in needles
            if isinstance(token, str) and len(token.strip()) > 2
        )
    )
    positions = [
        position for needle in normalized_needles if (position := lowered.find(needle)) >= 0
    ]
    candidate_starts = {0, max(0, len(text) - MAX_REVIEW_TEXT_CHARS)}
    candidate_starts.update(
        min(max(0, position - MAX_REVIEW_TEXT_CHARS // 3), len(text) - MAX_REVIEW_TEXT_CHARS)
        for position in positions
    )

    def score(start: int) -> tuple[int, int, int]:
        window = lowered[start : start + MAX_REVIEW_TEXT_CHARS]
        hits = sum(needle in window for needle in normalized_needles)
        occurrences = sum(window.count(needle) for needle in normalized_needles)
        return hits, occurrences, -start

    start = max(candidate_starts, key=score)
    end = min(len(text), start + MAX_REVIEW_TEXT_CHARS)
    if start > 0:
        next_boundary = text.find(" ", start)
        if 0 <= next_boundary < end:
            start = next_boundary + 1
    end = min(len(text), start + MAX_REVIEW_TEXT_CHARS)
    if end < len(text):
        prior_boundary = text.rfind(" ", start, end)
        if prior_boundary > start:
            end = prior_boundary
    return text[start:end], start, end, True


def _protected_priority(candidate: Mapping[str, Any]) -> tuple[int, int, int, int]:
    reasons = set(candidate.get("deterministic_selection_reasons") or [])
    segment = candidate.get("question_segment_match")
    segment_score = (
        int(segment.get("question_segment_score") or 0) if isinstance(segment, Mapping) else 0
    )
    return (
        int("SUPPLIED_LOCATOR_EXACT" in reasons),
        int("EXACT_ISSUE_PHRASE" in reasons),
        segment_score,
        -int(candidate.get("model_rank") or 0),
    )


def _review_pool(
    *, ranking_row: Mapping[str, Any], packet_row: Mapping[str, Any]
) -> list[dict[str, Any]]:
    packet_blocks = {str(block["block_id"]): block for block in packet_row["candidate_blocks"]}
    ranked = list(ranking_row["all_ranked_candidates"])
    selected: list[Mapping[str, Any]] = list(ranked[:TOP_RERANKED_COUNT])
    observed = {str(candidate["candidate_block_id"]) for candidate in selected}
    protected = [
        candidate
        for candidate in ranked
        if set(candidate.get("deterministic_selection_reasons") or [])
        & {
            "SUPPLIED_LOCATOR_EXACT",
            "EXACT_ISSUE_PHRASE",
            "QUESTION_SEGMENT_OVERLAP",
        }
    ]
    protected.sort(key=_protected_priority, reverse=True)
    for candidate in protected:
        block_id = str(candidate["candidate_block_id"])
        if block_id in observed:
            continue
        selected.append(candidate)
        observed.add(block_id)
        if len(selected) == MAX_REVIEW_CANDIDATES:
            break
    issue_needles = _WORD.findall(str(packet_row.get("issue_label") or "").casefold())
    output: list[dict[str, Any]] = []
    for candidate in selected:
        block_id = str(candidate["candidate_block_id"])
        block = packet_blocks[block_id]
        segment = candidate.get("question_segment_match")
        segment_needles = (
            list(segment.get("overlap_terms") or []) if isinstance(segment, Mapping) else []
        )
        exact_text = str(block["exact_text"])
        review_text, start, end, truncated = _exact_review_window(
            exact_text,
            needles=[*segment_needles, *issue_needles],
        )
        output.append(
            {
                "block_id": block_id,
                "locator": block["locator"],
                "text": review_text,
                "review_text_sha256": _sha256(review_text.encode("utf-8")),
                "review_text_start": start,
                "review_text_end": end,
                "review_text_truncated": truncated,
                "full_text_sha256": block["exact_text_sha256"],
                "full_text_character_count": block["character_count"],
                "independent_reranker_score": candidate["reranker_score"],
                "independent_reranker_rank": candidate["model_rank"],
                "deterministic_selection_reasons": candidate["deterministic_selection_reasons"],
                "question_segment_match": segment,
            }
        )
    return output


def _row_input(*, ranking_row: Mapping[str, Any], packet_row: Mapping[str, Any]) -> dict[str, Any]:
    candidates = _review_pool(ranking_row=ranking_row, packet_row=packet_row)
    return {
        "schema": "legalbot.v111.phase2a.source-link-review-input.v1",
        "row_source_link_id": packet_row["row_source_link_id"],
        "row_id": packet_row["row_id"],
        "issue_label": packet_row["issue_label"],
        "legal_domain": packet_row["legal_domain"],
        "scenario": packet_row["case_question"],
        "scenario_sha256": packet_row["case_question_sha256"],
        "authority_identity_id": packet_row["authority_identity_id"],
        "canonical_authority_identity_id": packet_row["canonical_authority_identity_id"],
        "source_title": packet_row["source_title"],
        "source_date": packet_row["source_date"],
        "source_representation_sha256": packet_row["source_representation_sha256"],
        "candidates": candidates,
        "candidate_count": len(candidates),
        "top_reranked_candidate_count": TOP_RERANKED_COUNT,
        "protected_deterministic_candidates_carried_forward": True,
        "legal_sufficiency_predecided": False,
        "owner_decision_requested_from_model": False,
    }


def _model_input(row_input: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema": "legalbot.v111.phase2a.source-link-model-input.v1",
        "row_source_link_id": row_input["row_source_link_id"],
        "row_id": row_input["row_id"],
        "issue_label": row_input["issue_label"],
        "legal_domain": row_input["legal_domain"],
        "scenario": row_input["scenario"],
        "authority_identity_id": row_input["authority_identity_id"],
        "source_title": row_input["source_title"],
        "candidates": [
            {
                "block_id": candidate["block_id"],
                "locator": candidate["locator"],
                "text": candidate["text"],
                "text_is_excerpt": candidate["review_text_truncated"],
                "independent_reranker_score": candidate["independent_reranker_score"],
                "independent_reranker_rank": candidate["independent_reranker_rank"],
                "deterministic_selection_reasons": candidate["deterministic_selection_reasons"],
            }
            for candidate in row_input["candidates"]
        ],
        "legal_sufficiency_predecided": False,
        "owner_decision_requested_from_model": False,
    }


def _token_budget_evidence(source: SourceBundle) -> dict[str, Any]:
    from tokenizers import Tokenizer

    tokenizer_path = PROJECT_ROOT / "models/runtime/Qwen3.5-9B-4bit/tokenizer.json"
    tokenizer = Tokenizer.from_file(str(tokenizer_path))
    rows = []
    for ranking_row in source.ranking_rows:
        packet_row = source.packet_by_link[str(ranking_row["row_source_link_id"])]
        row_input = _row_input(ranking_row=ranking_row, packet_row=packet_row)
        user = json.dumps(
            _model_input(row_input),
            ensure_ascii=False,
            separators=(",", ":"),
        )
        content_tokens = len(tokenizer.encode(f"{SYSTEM_PROMPT}\n{user}").ids)
        conservative_total = content_tokens + MAX_OUTPUT_TOKENS + CHAT_TEMPLATE_TOKEN_ALLOWANCE
        rows.append(
            {
                "row_source_link_id": row_input["row_source_link_id"],
                "content_tokens": content_tokens,
                "conservative_total_tokens": conservative_total,
            }
        )
    maximum = max(int(row["conservative_total_tokens"]) for row in rows)
    if maximum > CONTEXT_WINDOW_TOKENS:
        raise ValueError("phase2a_r107_preflight_context_budget_exceeded")
    material = {
        "schema": "legalbot.v111.phase2a.r107-token-budget-preflight.v1",
        "tokenizer_file_sha256": _sha256_file(tokenizer_path),
        "context_window_tokens": CONTEXT_WINDOW_TOKENS,
        "maximum_output_tokens": MAX_OUTPUT_TOKENS,
        "chat_template_token_allowance": CHAT_TEMPLATE_TOKEN_ALLOWANCE,
        "maximum_conservative_total_tokens": maximum,
        "rows": rows,
        "silent_truncation_permitted": False,
    }
    return {**material, "preflight_content_sha256": _sealed(material)}


def _envelope(row_input: Mapping[str, Any]) -> tuple[dict[str, Any], str]:
    request_id = str(uuid4())
    user = json.dumps(
        _model_input(row_input),
        ensure_ascii=False,
        separators=(",", ":"),
    )
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user},
    ]
    return (
        {
            "request_id": request_id,
            "mode": "semantic_verify",
            "payload": {"messages": messages},
            "messages": messages,
            "max_tokens": MAX_OUTPUT_TOKENS,
            "temperature": 0.0,
            "top_p": 1.0,
            "seed": 0,
            "stop": [],
        },
        request_id,
    )


def _material_fact_records(text: str) -> list[dict[str, str]]:
    return [
        {
            "kind": fact.kind,
            "normalized_value": fact.normalized_value,
            "matched_text": fact.matched_text,
        }
        for fact in extract_material_facts(text)
    ]


def _validate_supported(
    *, output: Mapping[str, Any], row_input: Mapping[str, Any]
) -> dict[str, Any]:
    block_id = output.get("selected_block_id")
    quote = output.get("exact_quote")
    proposition = output.get("atomic_proposition")
    if not all(
        isinstance(value, str) and value.strip() for value in (block_id, quote, proposition)
    ):
        raise ReviewValidationError("positive_review_fields_invalid")
    proposition = " ".join(str(proposition).split())
    if len(proposition) > MAX_PROPOSITION_CHARS:
        raise ReviewValidationError("atomic_proposition_too_long")
    atomicity = non_atomic_material_claim_reasons(proposition)
    if atomicity:
        raise ReviewValidationError(
            "non_atomic_material_claim",
            diagnostics={"atomicity_reasons": list(atomicity)},
        )
    candidate_by_id = {
        str(candidate["block_id"]): candidate for candidate in row_input["candidates"]
    }
    candidate = candidate_by_id.get(str(block_id))
    if candidate is None:
        raise ReviewValidationError("selected_block_outside_frozen_candidates")
    quote_start_in_review_text = str(candidate["text"]).find(str(quote))
    if quote_start_in_review_text < 0:
        raise ReviewValidationError("exact_quote_not_contiguous_in_bound_block")
    quote_start = int(candidate["review_text_start"]) + quote_start_in_review_text
    quote_end = quote_start + len(str(quote))
    proposition_facts = {fact.identity for fact in extract_material_facts(proposition)}
    span_facts = {
        fact.identity for fact in extract_material_facts(f"{quote}\n{candidate['locator']}")
    }
    unsupported = sorted(proposition_facts - span_facts)
    if unsupported:
        raise ReviewValidationError(
            "unsupported_material_fact",
            diagnostics={"unsupported_material_facts": [list(item) for item in unsupported]},
        )
    proposition_tokens = set(substantive_tokens(proposition))
    quote_tokens = set(substantive_tokens(str(quote)))
    shared = proposition_tokens & quote_tokens
    smaller = min(len(proposition_tokens), len(quote_tokens))
    if not shared or (len(shared) < 2 and len(shared) / max(1, smaller) < 0.2):
        raise ReviewValidationError(
            "unrelated_evidence",
            diagnostics={"shared_substantive_token_count": len(shared)},
        )
    segment = candidate.get("question_segment_match")
    segment_terms = (
        " ".join(str(item) for item in segment.get("overlap_terms") or [])
        if isinstance(segment, Mapping)
        else ""
    )
    issue_anchor_tokens = set(substantive_tokens(f"{row_input['issue_label']} {segment_terms}"))
    if issue_anchor_tokens and not proposition_tokens & issue_anchor_tokens:
        raise ReviewValidationError(
            "unrelated_evidence",
            diagnostics={
                "reason": "atomic_proposition_has_no_issue_or_scenario_segment_anchor",
                "issue_anchor_tokens": sorted(issue_anchor_tokens),
            },
        )
    return {
        "assessment": output["assessment"],
        "atomic_proposition": proposition,
        "exact_span_binding": {
            "block_id": block_id,
            "locator": candidate["locator"],
            "full_text_sha256": candidate["full_text_sha256"],
            "quote": quote,
            "quote_sha256": _sha256(str(quote).encode("utf-8")),
            "quote_start": quote_start,
            "quote_end": quote_end,
            "proposition_material_facts": _material_fact_records(proposition),
            "span_material_facts": _material_fact_records(f"{quote}\n{candidate['locator']}"),
        },
    }


def _safe_structured_diagnostics(
    structured: Any, *, row_input: Mapping[str, Any]
) -> dict[str, Any]:
    if not isinstance(structured, Mapping):
        return {"structured_type": type(structured).__name__}
    keys = [str(key) for key in structured]
    raw_assessment = structured.get("assessment")
    assessment = (
        raw_assessment.upper()
        if isinstance(raw_assessment, str) and re.fullmatch(r"[A-Za-z_]{1,32}", raw_assessment)
        else None
    )
    return {
        "structured_keys": sorted(keys),
        "structured_field_types": {
            str(key): type(value).__name__ for key, value in structured.items()
        },
        "schema_matches": structured.get("schema") == OUTPUT_SCHEMA,
        "row_source_link_id_matches": (
            structured.get("row_source_link_id") == row_input["row_source_link_id"]
        ),
        "normalized_assessment_if_safe": assessment,
        "assessment_allowed": assessment in _ASSESSMENTS,
        "positive_field_nullness": {
            field: structured.get(field) is None
            for field in (
                "selected_block_id",
                "exact_quote",
                "atomic_proposition",
            )
        },
        "prose_values_persisted": False,
    }


def _validate_response(
    *, body: Mapping[str, Any], row_input: Mapping[str, Any], request_id: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    if body.get("request_id") != request_id:
        raise ReviewValidationError("model_request_identity_mismatch")
    if (
        body.get("model_version") != base.EXPECTED_MODEL_VERSION
        or body.get("backend") != base.MODEL_BACKEND
        or body.get("deterministic") is not True
    ):
        raise ReviewValidationError("model_runtime_identity_invalid")
    finish_reason = str(body.get("finish_reason") or "").casefold()
    if finish_reason in {
        "length",
        "max_tokens",
        "token_limit",
        "context_length",
        "truncated",
    }:
        raise ReviewValidationError("model_output_truncated")
    warnings = body.get("warnings")
    usage = body.get("usage")
    if not isinstance(warnings, list) or "stub_mode" in warnings:
        raise ReviewValidationError("model_warning_contract_invalid")
    if not isinstance(usage, Mapping) or any(
        isinstance(usage.get(field), bool)
        or not isinstance(usage.get(field), int)
        or int(usage[field]) < 0
        for field in ("input_tokens", "output_tokens", "total_tokens")
    ):
        raise ReviewValidationError("model_usage_invalid")
    peak = body.get("peak_memory_gb")
    if peak is not None and (
        isinstance(peak, bool)
        or not isinstance(peak, int | float)
        or float(peak) > base.MAX_PEAK_MEMORY_GB
    ):
        raise ReviewValidationError("model_peak_memory_exceeded")
    structured = body.get("structured")
    required_keys = {
        "schema",
        "row_source_link_id",
        "assessment",
        "selected_block_id",
        "exact_quote",
        "atomic_proposition",
    }
    if not isinstance(structured, Mapping) or set(structured) != required_keys:
        raise ReviewValidationError(
            "structured_output_keys_invalid",
            diagnostics=_safe_structured_diagnostics(
                structured,
                row_input=row_input,
            ),
        )
    raw_assessment = structured.get("assessment")
    assessment = raw_assessment.upper() if isinstance(raw_assessment, str) else None
    if (
        structured.get("schema") != OUTPUT_SCHEMA
        or structured.get("row_source_link_id") != row_input["row_source_link_id"]
        or assessment not in _ASSESSMENTS
    ):
        raise ReviewValidationError(
            "structured_output_contract_invalid",
            diagnostics=_safe_structured_diagnostics(
                structured,
                row_input=row_input,
            ),
        )
    normalized_output = {**dict(structured), "assessment": assessment}
    if assessment in {"DIRECT", "PARTIAL"}:
        finding = _validate_supported(output=normalized_output, row_input=row_input)
    else:
        if any(
            structured.get(field) is not None
            for field in ("selected_block_id", "exact_quote", "atomic_proposition")
        ):
            raise ReviewValidationError("negative_review_fields_must_be_null")
        finding = {
            "assessment": assessment,
            "atomic_proposition": None,
            "exact_span_binding": None,
        }
    raw = str(body.get("raw_text") or "")
    finding.update(
        {
            "finding_codes": [
                {
                    "DIRECT": "model_direct_exact_span_advisory",
                    "PARTIAL": "model_partial_exact_span_advisory",
                    "UNRELATED": "model_unrelated_source_advisory",
                    "AMBIGUOUS": "model_ambiguous_source_advisory",
                }[assessment]
            ],
            "finding_codes_derived_deterministically": True,
            "owner_outcome": None,
            "owner_decision_required": True,
            "source_admission_authorized": False,
            "technical_qualification_assigned": False,
        }
    )
    metrics = {
        "input_tokens": usage["input_tokens"],
        "output_tokens": usage["output_tokens"],
        "total_tokens": usage["total_tokens"],
        "generation_ms": body.get("generation_ms"),
        "time_to_first_token_ms": body.get("time_to_first_token_ms"),
        "peak_memory_gb": body.get("peak_memory_gb"),
        "finish_reason": finish_reason,
        "raw_output_sha256": _sha256(raw.encode("utf-8")),
        "raw_output_character_count": len(raw),
    }
    return finding, metrics


def _error_code(exc: BaseException) -> str:
    if isinstance(exc, ReviewValidationError):
        return exc.code
    return runtime._error_code(exc)


def _checkpoint_name(ordinal: int, link_id: str) -> str:
    return f"{ordinal:02d}-{link_id[:24]}.json"


def _review_one(
    *,
    ordinal: int,
    ranking_row: Mapping[str, Any],
    packet_row: Mapping[str, Any],
    invoke: Invoke,
    runtime_identity_sha256: str,
    output_root: Path,
    epoch_id: str,
) -> tuple[dict[str, Any], bool]:
    row_input = _row_input(ranking_row=ranking_row, packet_row=packet_row)
    input_sha256 = _sealed(row_input)
    model_input_sha256 = _sealed(_model_input(row_input))
    prior_attempt_count = _prior_attempt_count(str(packet_row["row_source_link_id"]))
    fingerprints: list[str] = []
    for attempt in (1, 2):
        envelope, request_id = _envelope(row_input)
        body: dict[str, Any] | None = None
        started = time.perf_counter()
        try:
            body = invoke(envelope)
            finding, metrics = _validate_response(
                body=body,
                row_input=row_input,
                request_id=request_id,
            )
        except Exception as exc:
            code = _error_code(exc)
            fingerprint = _sealed(
                {
                    "schema": "legalbot.v111.phase2a.r107-failure-fingerprint.v1",
                    "row_source_link_id": packet_row["row_source_link_id"],
                    "input_content_sha256": input_sha256,
                    "prompt_sha256": _sha256((SYSTEM_PROMPT + "\n").encode("utf-8")),
                    "runtime_identity_sha256": runtime_identity_sha256,
                    "error_code": code,
                }
            )
            fingerprints.append(fingerprint)
            diagnostic_material = {
                "schema": "legalbot.v111.phase2a.r107-rejected-attempt.v1",
                "ordinal": ordinal,
                "row_id": packet_row["row_id"],
                "row_source_link_id": packet_row["row_source_link_id"],
                "runtime_epoch_id": epoch_id,
                "attempt": attempt,
                "prior_attempt_count_under_superseded_plan": prior_attempt_count,
                "total_attempt_ordinal_for_link": prior_attempt_count + attempt,
                "input_content_sha256": input_sha256,
                "request_id": request_id,
                "error_code": code,
                "validation_diagnostics": (
                    dict(exc.diagnostics) if isinstance(exc, ReviewValidationError) else {}
                ),
                "failure_fingerprint": fingerprint,
                "same_failure_fingerprint_as_prior_attempt": (
                    len(fingerprints) == 2 and fingerprints[0] == fingerprints[1]
                ),
                "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
                "response_received": body is not None,
                "raw_output_sha256": (
                    _sha256(str(body.get("raw_text") or "").encode("utf-8")) if body else None
                ),
                "raw_output_persisted": False,
                "hidden_reasoning_persisted": False,
                "debug_required_before_any_third_attempt": attempt == 2,
                "owner_decision_assigned": False,
                "source_admission_authorized": False,
                "technical_qualification_assigned": False,
                "phase2b_authorized": False,
                "development30_authorized": False,
            }
            diagnostic = {
                **diagnostic_material,
                "diagnostic_content_sha256": _sealed(diagnostic_material),
            }
            _write_exclusive(
                output_root
                / "diagnostics"
                / (
                    f"{_checkpoint_name(ordinal, str(packet_row['row_source_link_id']))[:-5]}"
                    f"-a{attempt}.json"
                ),
                _pretty_json(diagnostic),
            )
            if attempt == 1:
                continue
            finding = {
                "assessment": "HELD_FOR_DEBUG_BEFORE_ANY_THIRD_ATTEMPT",
                "atomic_proposition": None,
                "exact_span_binding": None,
                "finding_codes": [code],
                "owner_outcome": None,
                "owner_decision_required": True,
                "source_admission_authorized": False,
                "technical_qualification_assigned": False,
            }
            metrics = None
            break
        else:
            break
    held = finding["assessment"] == "HELD_FOR_DEBUG_BEFORE_ANY_THIRD_ATTEMPT"
    checkpoint_material = {
        "schema": "legalbot.v111.phase2a.r107-source-link-review-checkpoint.v1",
        "ordinal": ordinal,
        "row_id": packet_row["row_id"],
        "row_source_link_id": packet_row["row_source_link_id"],
        "authority_identity_id": packet_row["authority_identity_id"],
        "runtime_epoch_id": epoch_id,
        "source_packet_record_content_sha256": packet_row["record_content_sha256"],
        "source_ranking_checkpoint_content_sha256": ranking_row["checkpoint_content_sha256"],
        "input_content_sha256": input_sha256,
        "model_input_content_sha256": model_input_sha256,
        "candidate_count": row_input["candidate_count"],
        "candidate_ids": [item["block_id"] for item in row_input["candidates"]],
        "prompt_sha256": _sha256((SYSTEM_PROMPT + "\n").encode("utf-8")),
        "runtime_identity_sha256": runtime_identity_sha256,
        "attempt_count": len(fingerprints) if held else len(fingerprints) + 1,
        "prior_attempt_count_under_superseded_plan": prior_attempt_count,
        "total_attempt_count_for_link": (
            prior_attempt_count + (len(fingerprints) if held else len(fingerprints) + 1)
        ),
        "prior_debug_stop_content_sha256": (
            EXPECTED_PRIOR_DEBUG_STOP_CONTENT_SHA256 if prior_attempt_count else None
        ),
        "execution_plan_materially_changed": True,
        "failure_fingerprints": fingerprints,
        "same_failure_fingerprint_twice": (
            len(fingerprints) == 2 and fingerprints[0] == fingerprints[1]
        ),
        "debug_required_before_any_third_attempt": held,
        "finding": finding,
        "model_metrics": metrics,
        "reviewer_execution_mode": "separate_verification_pass_same_model_adapter",
        "model_independent_reviewer": False,
        "raw_model_output_persisted": False,
        "hidden_reasoning_persisted": False,
        "owner_decision_assigned": False,
        "source_admission_authorized": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "technical_qualification_assigned": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    checkpoint = {
        **checkpoint_material,
        "checkpoint_content_sha256": _sealed(checkpoint_material),
    }
    _write_exclusive(
        output_root
        / "checkpoints"
        / _checkpoint_name(ordinal, str(packet_row["row_source_link_id"])),
        _pretty_json(checkpoint),
    )
    abort_epoch = bool(
        held
        and finding["finding_codes"]
        and finding["finding_codes"][0] in _INFRASTRUCTURE_FAILURE_CODES
    )
    return checkpoint, abort_epoch


def _prepare_output_root(output_root: Path, *, resume: bool) -> None:
    if output_root.exists() or output_root.is_symlink():
        if not resume or output_root.is_symlink() or not output_root.is_dir():
            raise ValueError("phase2a_r107_output_already_exists")
    else:
        output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_r107_output_mode_invalid")
    for name in ("checkpoints", "diagnostics", "runtime-epochs"):
        path = output_root / name
        path.mkdir(mode=0o700, exist_ok=True)
        if path.is_symlink() or stat.S_IMODE(path.stat().st_mode) != 0o700:
            raise ValueError("phase2a_r107_output_subdirectory_invalid")


def _runtime_identity(base_identity: Mapping[str, Any]) -> dict[str, Any]:
    material = {
        "schema": "legalbot.v111.phase2a.r107-runtime-identity.v1",
        "underlying_runtime_identity": dict(base_identity),
        "model_id": base.EXPECTED_MODEL_ID,
        "model_version": base.EXPECTED_MODEL_VERSION,
        "backend": base.MODEL_BACKEND,
        "prompt_sha256": _sha256((SYSTEM_PROMPT + "\n").encode("utf-8")),
        "request_configuration": {
            "mode": "semantic_verify",
            "max_tokens": MAX_OUTPUT_TOKENS,
            "temperature": 0.0,
            "top_p": 1.0,
            "seed": 0,
        },
        "stateless_advisory_review": True,
        "reviewer_execution_mode": "separate_verification_pass_same_model_adapter",
        "model_independent_reviewer": False,
        "same_model_adapter_family_as_drafting": True,
        "maximum_rows_per_process_epoch": MAX_ROWS_PER_EPOCH,
    }
    return {**material, "runtime_identity_sha256": _sealed(material)}


def _intent_material(
    *, source: SourceBundle, runtime_identity: Mapping[str, Any]
) -> dict[str, Any]:
    token_budget = _token_budget_evidence(source)
    prior_debug_stop = _load_prior_debug_stop()
    return {
        "schema": "legalbot.v111.phase2a.r107-source-link-review-intent.v1",
        "status": (
            "DEBUGGED_CHANGED_PLAN_ADVISORY_EXACT_SPAN_REVIEW_ONLY_OWNER_DECISIONS_REQUIRED"
        ),
        "source_r104_content_sha256": source.packets["artifact_content_sha256"],
        "source_r104_file_sha256": _sha256_file(R104_PATH),
        "source_r105_content_sha256": source.ranking["artifact_content_sha256"],
        "source_r105_file_sha256": _sha256_file(R105_PATH),
        "prior_r106_debug_stop_content_sha256": prior_debug_stop["debug_stop_content_sha256"],
        "prior_repeated_failure_fingerprint": prior_debug_stop["failure_fingerprint"],
        "prior_affected_row_source_link_id": prior_debug_stop["affected_row_source_link_id"],
        "prior_attempt_count": prior_debug_stop["attempt_count"],
        "execution_plan_change": {
            "model_authored_reason_codes_removed": True,
            "reason_codes_derived_deterministically": True,
            "safe_structural_validation_diagnostics_persisted": True,
            "new_output_schema": OUTPUT_SCHEMA,
            "new_prompt_sha256": _sha256((SYSTEM_PROMPT + "\n").encode("utf-8")),
            "historical_r106_preserved": True,
        },
        "row_source_link_count": EXPECTED_LINK_COUNT,
        "prompt_sha256": _sha256((SYSTEM_PROMPT + "\n").encode("utf-8")),
        "review_code_file_sha256": _sha256_file(Path(__file__).resolve()),
        "evidence_validator_file_sha256": _sha256_file(
            PROJECT_ROOT / "backend/app/quality/evidence.py"
        ),
        "runtime_identity": dict(runtime_identity),
        "runtime_identity_sha256": runtime_identity["runtime_identity_sha256"],
        "token_budget_preflight": token_budget,
        "token_budget_preflight_content_sha256": token_budget["preflight_content_sha256"],
        "silent_truncation_permitted": False,
        "maximum_attempts_per_link": 2,
        "debug_required_before_any_third_attempt": True,
        "maximum_review_candidates": MAX_REVIEW_CANDIDATES,
        "top_reranked_candidates_carried_forward": TOP_RERANKED_COUNT,
        "protected_deterministic_candidates_carried_forward": True,
        "exact_contiguous_quote_required": True,
        "atomic_material_claim_required": True,
        "material_fact_binding_required": True,
        "reviewer_execution_mode": "separate_verification_pass_same_model_adapter",
        "model_independent_reviewer": False,
        "raw_model_output_persisted": False,
        "hidden_reasoning_persisted": False,
        "owner_decisions_applied": False,
        "source_admission_authorized": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "technical_qualification_assigned": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }


def _initialize_or_verify_intent(
    *, output_root: Path, source: SourceBundle, runtime_identity: Mapping[str, Any]
) -> dict[str, Any]:
    path = output_root / "INTENT.json"
    expected = _intent_material(source=source, runtime_identity=runtime_identity)
    if path.exists():
        value = _load_object(path)
        _verify_seal(value, "intent_content_sha256", "phase2a_r107_intent_invalid")
        material = dict(value)
        material.pop("intent_content_sha256", None)
        material.pop("started_at", None)
        if material != expected:
            raise ValueError("phase2a_r107_resume_identity_mismatch")
        return value
    material = {
        **expected,
        "started_at": datetime.now(UTC).isoformat(timespec="seconds"),
    }
    value = {**material, "intent_content_sha256": _sealed(material)}
    _write_exclusive(path, _pretty_json(value))
    return value


def _load_checkpoints(*, output_root: Path, source: SourceBundle) -> dict[str, dict[str, Any]]:
    completed: dict[str, dict[str, Any]] = {}
    expected_links = [str(row["row_source_link_id"]) for row in source.ranking_rows]
    for path in sorted((output_root / "checkpoints").glob("*.json")):
        value = _load_object(path)
        _verify_seal(
            value,
            "checkpoint_content_sha256",
            "phase2a_r107_checkpoint_invalid",
        )
        link_id = str(value.get("row_source_link_id") or "")
        if (
            value.get("schema") != "legalbot.v111.phase2a.r107-source-link-review-checkpoint.v1"
            or link_id not in expected_links
            or link_id in completed
        ):
            raise ValueError("phase2a_r107_checkpoint_boundary_invalid")
        completed[link_id] = value
    if list(completed) != expected_links[: len(completed)]:
        raise ValueError("phase2a_r107_checkpoint_order_invalid")
    return completed


def _write_epoch_receipt(
    *,
    output_root: Path,
    epoch_number: int,
    epoch_id: str,
    started_at: str,
    processed: Sequence[str],
    aborted: bool,
    identity: Mapping[str, Any] | None,
    log_path: Path,
    stop_mode: str,
    exit_code: int,
    error_code: str | None,
) -> dict[str, Any]:
    material = {
        "schema": "legalbot.v111.phase2a.r107-runtime-epoch.v1",
        "epoch_number": epoch_number,
        "runtime_epoch_id": epoch_id,
        "started_at": started_at,
        "completed_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "processed_row_source_link_ids": list(processed),
        "processed_count": len(processed),
        "maximum_rows_per_epoch": MAX_ROWS_PER_EPOCH,
        "aborted_after_infrastructure_failure": aborted,
        "runtime_identity_sha256": (identity.get("runtime_identity_sha256") if identity else None),
        "runtime_log_file_sha256": _sha256_file(log_path),
        "runtime_log_raw_model_output_persisted": False,
        "stop_mode": stop_mode,
        "exit_code": exit_code,
        "epoch_error_code": error_code,
        "owner_decision_assigned": False,
        "source_admission_authorized": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    receipt = {**material, "epoch_content_sha256": _sealed(material)}
    _write_exclusive(
        output_root / "runtime-epochs" / f"{epoch_number:03d}.json",
        _pretty_json(receipt),
    )
    return receipt


def _next_epoch_number(output_root: Path) -> int:
    receipts = sorted((output_root / "runtime-epochs").glob("[0-9][0-9][0-9].json"))
    for expected, path in enumerate(receipts, start=1):
        if path.stem != f"{expected:03d}":
            raise ValueError("phase2a_r107_epoch_sequence_invalid")
        value = _load_object(path)
        _verify_seal(
            value,
            "epoch_content_sha256",
            "phase2a_r107_epoch_receipt_invalid",
        )
    return len(receipts)


def _finalize(*, output_root: Path, source: SourceBundle) -> dict[str, Any]:
    checkpoints = _load_checkpoints(output_root=output_root, source=source)
    if len(checkpoints) != EXPECTED_LINK_COUNT:
        raise ValueError("phase2a_r107_cannot_finalize_incomplete")
    findings = [checkpoint["finding"] for checkpoint in checkpoints.values()]
    counts = Counter(str(finding["assessment"]) for finding in findings)
    checkpoint_custody = []
    for path in sorted((output_root / "checkpoints").glob("*.json")):
        value = _load_object(path)
        checkpoint_custody.append(
            {
                "relative_path": f"checkpoints/{path.name}",
                "file_sha256": _sha256_file(path),
                "content_sha256": value["checkpoint_content_sha256"],
            }
        )
    diagnostic_custody = []
    for path in sorted((output_root / "diagnostics").glob("*.json")):
        value = _load_object(path)
        _verify_seal(
            value,
            "diagnostic_content_sha256",
            "phase2a_r107_diagnostic_invalid",
        )
        diagnostic_custody.append(
            {
                "relative_path": f"diagnostics/{path.name}",
                "file_sha256": _sha256_file(path),
                "content_sha256": value["diagnostic_content_sha256"],
            }
        )
    epochs = []
    for path in sorted((output_root / "runtime-epochs").glob("*.json")):
        value = _load_object(path)
        _verify_seal(
            value,
            "epoch_content_sha256",
            "phase2a_r107_epoch_receipt_invalid",
        )
        epochs.append(value)
    intent = _load_object(output_root / "INTENT.json")
    _verify_seal(intent, "intent_content_sha256", "phase2a_r107_intent_invalid")
    held_count = counts.get("HELD_FOR_DEBUG_BEFORE_ANY_THIRD_ATTEMPT", 0)
    material = {
        "schema": "legalbot.v111.phase2a.r107-source-link-exact-span-advisory-26.v1",
        "status": (
            "ADVISORY_SOURCE_LINK_REVIEW_COMPLETE_OWNER_DECISIONS_REQUIRED"
            if not held_count
            else "ADVISORY_SOURCE_LINK_REVIEW_HELD_DEBUG_REQUIRED"
        ),
        "source_r104_content_sha256": source.packets["artifact_content_sha256"],
        "source_r105_content_sha256": source.ranking["artifact_content_sha256"],
        "source_intent_content_sha256": intent["intent_content_sha256"],
        "row_source_link_count": EXPECTED_LINK_COUNT,
        "assessment_counts": dict(sorted(counts.items())),
        "held_for_debug_count": held_count,
        "findings": [
            {
                "ordinal": checkpoint["ordinal"],
                "row_id": checkpoint["row_id"],
                "row_source_link_id": checkpoint["row_source_link_id"],
                "authority_identity_id": checkpoint["authority_identity_id"],
                **checkpoint["finding"],
                "checkpoint_content_sha256": checkpoint["checkpoint_content_sha256"],
            }
            for checkpoint in checkpoints.values()
        ],
        "checkpoint_custody": checkpoint_custody,
        "checkpoint_custody_sha256": _sealed(checkpoint_custody),
        "diagnostic_custody": diagnostic_custody,
        "diagnostic_custody_sha256": _sealed(diagnostic_custody),
        "runtime_epoch_count": len(epochs),
        "runtime_epoch_content_sha256s": [epoch["epoch_content_sha256"] for epoch in epochs],
        "reviewer_execution_mode": "separate_verification_pass_same_model_adapter",
        "model_independent_reviewer": False,
        "same_model_adapter_family_as_drafting": True,
        "findings_are_advisory_only": True,
        "owner_decisions_applied": False,
        "source_admission_authorized": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "technical_qualification_assigned": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    final = {**material, "artifact_content_sha256": _sealed(material)}
    _write_exclusive(output_root / OUTPUT_NAME, _pretty_json(final))
    outcome = (
        "26 SOURCE-LINK ADVISORY REVIEWS COMPLETE; OWNER DECISIONS REQUIRED. "
        "NO ADMISSION, INDEXING, QUALIFICATION, OR GATE CHANGE.\n"
        if not held_count
        else "SOURCE-LINK ADVISORY REVIEW HELD FOR DEBUG. NO GATE CHANGE.\n"
    )
    _write_exclusive(output_root / "OUTCOME.txt", outcome.encode("utf-8"))
    paths = sorted(
        path for path in output_root.rglob("*") if path.is_file() and path.name != "SHA256SUMS.txt"
    )
    sums = "".join(f"{_sha256_file(path)}  {path.relative_to(output_root)}\n" for path in paths)
    _write_exclusive(output_root / "SHA256SUMS.txt", sums.encode("utf-8"))
    return final


def run_managed_review(
    *,
    output_root: Path,
    port: int,
    timeout_seconds: float,
    startup_timeout_seconds: float,
    rows_per_epoch: int,
    resume: bool,
) -> dict[str, Any]:
    if not 1 <= rows_per_epoch <= MAX_ROWS_PER_EPOCH:
        raise ValueError("phase2a_r107_rows_per_epoch_invalid")
    if not 1024 <= port <= 65535:
        raise ValueError("phase2a_r107_port_invalid")
    source = _load_sources()
    _prepare_output_root(output_root, resume=resume)
    python = runtime._model_runtime_python()
    epoch_number = _next_epoch_number(output_root)
    while len(_load_checkpoints(output_root=output_root, source=source)) < EXPECTED_LINK_COUNT:
        epoch_number += 1
        epoch_id = f"r107-epoch-{epoch_number:03d}-{uuid4()}"
        started_at = datetime.now(UTC).isoformat(timespec="seconds")
        log_path = output_root / "runtime-epochs" / f"{epoch_number:03d}.log"
        descriptor = os.open(
            log_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        processed: list[str] = []
        aborted = False
        identity: dict[str, Any] | None = None
        process: subprocess.Popen[bytes] | None = None
        stop_mode = "not_started"
        exit_code = -1
        epoch_error: BaseException | None = None
        with os.fdopen(descriptor, "wb") as log_handle:
            process = subprocess.Popen(
                [str(python), "-m", "app.model_runtime"],
                cwd=PROJECT_ROOT,
                env=runtime._runtime_environment(port=port),
                stdin=subprocess.DEVNULL,
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            try:
                invoke, base_identity = runtime._wait_for_runtime(
                    process=process,
                    port=port,
                    timeout_seconds=timeout_seconds,
                    startup_timeout_seconds=startup_timeout_seconds,
                )
                identity = _runtime_identity(base_identity)
                _initialize_or_verify_intent(
                    output_root=output_root,
                    source=source,
                    runtime_identity=identity,
                )
                completed = _load_checkpoints(output_root=output_root, source=source)
                pending = [
                    row for row in source.ranking_rows if row["row_source_link_id"] not in completed
                ][:rows_per_epoch]
                for ranking_row in pending:
                    link_id = str(ranking_row["row_source_link_id"])
                    packet_row = source.packet_by_link[link_id]
                    ordinal = [str(row["row_source_link_id"]) for row in source.ranking_rows].index(
                        link_id
                    ) + 1
                    checkpoint, abort = _review_one(
                        ordinal=ordinal,
                        ranking_row=ranking_row,
                        packet_row=packet_row,
                        invoke=invoke,
                        runtime_identity_sha256=identity["runtime_identity_sha256"],
                        output_root=output_root,
                        epoch_id=epoch_id,
                    )
                    processed.append(link_id)
                    print(
                        json.dumps(
                            {
                                "event": "source_link_review_complete",
                                "ordinal": ordinal,
                                "row_id": packet_row["row_id"],
                                "assessment": checkpoint["finding"]["assessment"],
                                "completed_count": len(completed) + len(processed),
                                "row_source_link_count": EXPECTED_LINK_COUNT,
                                "runtime_epoch_id": epoch_id,
                            },
                            sort_keys=True,
                        ),
                        flush=True,
                    )
                    if abort:
                        aborted = True
                        break
            except BaseException as exc:
                epoch_error = exc
            finally:
                if process is not None:
                    stop_mode, exit_code = runtime._stop_runtime(process)
        _write_epoch_receipt(
            output_root=output_root,
            epoch_number=epoch_number,
            epoch_id=epoch_id,
            started_at=started_at,
            processed=processed,
            aborted=aborted,
            identity=identity,
            log_path=log_path,
            stop_mode=stop_mode,
            exit_code=exit_code,
            error_code=_error_code(epoch_error) if epoch_error is not None else None,
        )
        if epoch_error is not None:
            raise epoch_error
        if not processed:
            raise RuntimeError("phase2a_r107_epoch_completed_without_row")
    return _finalize(output_root=output_root, source=source)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--timeout-seconds", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument(
        "--startup-timeout-seconds",
        type=float,
        default=DEFAULT_STARTUP_TIMEOUT_SECONDS,
    )
    parser.add_argument(
        "--rows-per-epoch",
        type=int,
        default=DEFAULT_ROWS_PER_EPOCH,
    )
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    final = run_managed_review(
        output_root=args.output_root.resolve(),
        port=args.port,
        timeout_seconds=args.timeout_seconds,
        startup_timeout_seconds=args.startup_timeout_seconds,
        rows_per_epoch=args.rows_per_epoch,
        resume=bool(args.resume),
    )
    print(
        json.dumps(
            {
                "artifact_content_sha256": final["artifact_content_sha256"],
                "row_source_link_count": final["row_source_link_count"],
                "assessment_counts": final["assessment_counts"],
                "held_for_debug_count": final["held_for_debug_count"],
                "model_independent_reviewer": False,
                "source_admission_authorized": False,
                "phase2b_authorized": False,
                "development30_authorized": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
