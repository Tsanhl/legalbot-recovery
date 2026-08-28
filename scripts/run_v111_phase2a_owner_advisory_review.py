#!/usr/bin/env python3
"""Run the pinned, advisory-only Phase-2A review of the remaining 448 rows.

The model may rank only preselected official-source excerpts.  Deterministic
validation controls every persisted recommendation.  The command never makes
an owner decision, qualifies an issue, admits a source, mutates a candidate,
or authorizes Phase 2B or Development 30.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import stat
import subprocess
import sys
import time
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

import httpx

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.model_runtime.config import (  # noqa: E402
    PINNED_RUNTIME_MODEL_VERSION,
    PINNED_RUNTIME_REPO,
)

EXPECTED_REMAINDER_DIGEST = (
    "a7f7359c3ff12da02ee4056532198d39417459c9e20aac602f64437fb7cf5aa6"
)
EXPECTED_CASES_FILE_SHA256 = (
    "78a738afd920ff840dcedeb0fd3fd5ca81035f499a0630d351d49e7c6cd3777a"
)
EXPECTED_PROMPT_SHA256 = (
    "41e3e6ae5024e6512dc77551f3cee6344c94d2b16c6621209ece89fd9f2cb123"
)
EXPECTED_ROW_COUNT = 448
MODEL_BACKEND = "mlx_lm"
REVIEWER_EXECUTION_MODE = (
    "separate_verification_pass_same_model_adapter_as_drafting_not_model_independent"
)
OUTPUT_SCHEMA = "legalbot.phase2a.owner-advisory-row-output.v3"
MAX_CANDIDATES = 6
MAX_SELECTED = MAX_CANDIDATES
MAX_EXCERPT_CHARS = 900
MAX_INPUT_ESTIMATED_TOKENS = 6000
MAX_OUTPUT_TOKENS = 256
MAX_PEAK_MEMORY_GB = 12.0
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ROW_ID = re.compile(r"^(?:live30|live60)-q[0-9]{2}:issue-[0-9]{2}$")
_SAFE_REASON = re.compile(r"^[a-z0-9][a-z0-9_]{0,127}$")
_WORD = re.compile(r"[A-Za-z][A-Za-z'-]{3,}")
_STOP_WORDS = frozenset(
    {
        "about",
        "after",
        "again",
        "against",
        "being",
        "between",
        "could",
        "during",
        "from",
        "have",
        "into",
        "legal",
        "might",
        "must",
        "question",
        "should",
        "their",
        "there",
        "these",
        "they",
        "this",
        "under",
        "what",
        "when",
        "where",
        "which",
        "with",
        "would",
    }
)

SEMANTIC_ASSESSMENTS = frozenset(
    {
        "POTENTIALLY_RELEVANT_EXISTING_SPAN",
        "PARTIAL_SUPPORT_RESEARCH_NEEDED",
        "UNRELATED_CANDIDATES",
        "AMBIGUOUS_ISSUE_SCOPE",
    }
)
FINDING_CODES = frozenset(
    {
        "exact_issue_terms_present",
        "question_context_supported",
        "partial_support_only",
        "candidates_unrelated",
        "issue_scope_ambiguous",
    }
)
DETERMINISTIC_FINDING_CODES = frozenset(
    {"candidate_version_unverified", "case_later_treatment_required"}
)


class AdvisoryValidationError(ValueError):
    """One machine-safe validation code for a rejected model response."""

    def __init__(self, code: str):
        if not _SAFE_REASON.fullmatch(code):
            raise ValueError("phase2a_advisory_validation_code_invalid")
        self.code = code
        super().__init__(code)


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _pretty_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sealed(value: Any) -> str:
    return _sha256(_canonical_json(value))


def _write_exclusive(path: Path, raw: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
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
        raise ValueError("phase2a_advisory_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_advisory_input_must_be_object")
    return value


def _verify_seal(value: dict[str, Any], field: str, code: str) -> str:
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if not _SHA256.fullmatch(supplied) or supplied != _sealed(material):
        raise ValueError(code)
    return supplied


def _load_cases(path: Path) -> dict[str, dict[str, Any]]:
    if _sha256_file(path) != EXPECTED_CASES_FILE_SHA256:
        raise ValueError("phase2a_advisory_cases_file_identity_invalid")
    cases: dict[str, dict[str, Any]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if not isinstance(row, dict):
            raise ValueError("phase2a_advisory_case_row_invalid")
        case_id = str(row.get("case_id") or "")
        if not case_id or case_id in cases or not str(row.get("question") or "").strip():
            raise ValueError("phase2a_advisory_case_registry_invalid")
        cases[case_id] = row
    if len(cases) != 60:
        raise ValueError("phase2a_advisory_case_count_invalid")
    return cases


def _read_prompt(path: Path) -> tuple[str, str]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_advisory_prompt_missing")
    digest = _sha256_file(path)
    if digest != EXPECTED_PROMPT_SHA256:
        raise ValueError("phase2a_advisory_prompt_identity_invalid")
    text = path.read_text(encoding="utf-8")
    if not text.strip():
        raise ValueError("phase2a_advisory_prompt_empty")
    return text, digest


def _estimate_tokens(text: str) -> int:
    byte_estimate = (len(text.encode("utf-8")) + 2) // 3
    word_estimate = (len(text.split()) * 3 + 1) // 2
    return max(1, byte_estimate, word_estimate)


def _salient_excerpt(text: str, *, issue_label: str, question: str) -> tuple[str, bool]:
    clean = " ".join(text.split())
    if len(clean) <= MAX_EXCERPT_CHARS:
        return clean, False
    needles = []
    seen: set[str] = set()
    for token in _WORD.findall(f"{issue_label} {question}"):
        lowered = token.casefold()
        if lowered in _STOP_WORDS or lowered in seen:
            continue
        seen.add(lowered)
        needles.append(lowered)
        if len(needles) >= 12:
            break
    lowered_text = clean.casefold()
    positions = sorted(
        {
            position
            for needle in needles
            if (position := lowered_text.find(needle)) >= 0
        }
    )
    windows: list[str] = []
    for position in positions[:3]:
        start = max(0, position - 135)
        end = min(len(clean), position + 315)
        window = clean[start:end].strip()
        if window and not any(window in existing or existing in window for existing in windows):
            windows.append(window)
    marker = " [EXCERPT OMITTED; FULL SPAN HASH IS BINDING] "
    if not windows:
        windows = [clean[:540].rstrip(), clean[-300:].lstrip()]
    excerpt = marker.join(windows)
    if len(excerpt) > MAX_EXCERPT_CHARS:
        excerpt = excerpt[: MAX_EXCERPT_CHARS - len(marker) - 180].rstrip()
        excerpt = f"{excerpt}{marker}{clean[-180:].lstrip()}"
    return excerpt, True


def _build_row_input(row: Mapping[str, Any], case: Mapping[str, Any]) -> dict[str, Any]:
    row_id = str(row.get("row_id") or "")
    if not _ROW_ID.fullmatch(row_id):
        raise ValueError("phase2a_advisory_row_id_invalid")
    candidates = row.get("candidates")
    if not isinstance(candidates, list) or not candidates:
        raise ValueError("phase2a_advisory_row_candidates_missing")
    issue_label = str(row.get("issue_label") or "")
    question = str(case.get("question") or "")
    selected: list[dict[str, Any]] = []
    for candidate in candidates[:MAX_CANDIDATES]:
        if not isinstance(candidate, dict):
            raise ValueError("phase2a_advisory_candidate_invalid")
        text = str(candidate.get("candidate_span_text") or "")
        excerpt, truncated = _salient_excerpt(
            text,
            issue_label=issue_label,
            question=question,
        )
        selected.append(
            {
                "rank": candidate.get("rank"),
                "authority_identity_id": candidate.get("authority_identity_id"),
                "canonical_citation": candidate.get("canonical_citation"),
                "locator": candidate.get("locator"),
                "span_bundle_sha256": candidate.get("span_bundle_sha256"),
                "candidate_record_content_sha256": candidate.get(
                    "candidate_record_content_sha256"
                ),
                "identity_verified": candidate.get("identity_verified"),
                "currentness_verified": candidate.get("currentness_verified"),
                "later_treatment_review_required": candidate.get(
                    "later_treatment_review_required"
                ),
                "already_in_sealed_candidate": candidate.get(
                    "already_in_sealed_candidate"
                ),
                "full_span_text_sha256": _sha256((text + "\n").encode("utf-8")),
                "full_span_character_count": len(text),
                "excerpt": excerpt,
                "excerpt_sha256": _sha256((excerpt + "\n").encode("utf-8")),
                "excerpt_truncated": truncated,
            }
        )
    payload = {
        "schema": "legalbot.phase2a.owner-advisory-row-input.v1",
        "row_id": row_id,
        "case_id": row.get("case_id"),
        "legal_domain": row.get("legal_domain"),
        "issue_label": issue_label,
        "case_question": question,
        "source_evidence_state": row.get("source_evidence_state"),
        "source_required_action": row.get("source_required_action"),
        "candidates_provided": selected,
        "provided_candidate_ranks": [item["rank"] for item in selected],
        "omitted_candidate_ranks": [
            candidate.get("rank")
            for candidate in candidates[MAX_CANDIDATES:]
            if isinstance(candidate, dict)
        ],
        "excerpt_truncation_is_explicit": True,
        "full_span_hash_is_binding": True,
        "owner_decision_required": True,
        "technical_qualification_forbidden": True,
        "source_admission_forbidden": True,
        "gate_authorization_forbidden": True,
    }
    return payload


def _model_config() -> dict[str, Any]:
    return {
        "model_id": PINNED_RUNTIME_REPO,
        "model_version": PINNED_RUNTIME_MODEL_VERSION,
        "backend": MODEL_BACKEND,
        "mode": "semantic_verify",
        "temperature": 0.0,
        "top_p": 1.0,
        "seed": 0,
        "stop": [],
        "max_output_tokens": MAX_OUTPUT_TOKENS,
        "runtime_context_tokens": 8192,
        "runtime_max_output_tokens": 2048,
        "runtime_prefill_step_size": 512,
        "runtime_kv_cache_bits": 4,
        "runtime_kv_group_size": 64,
        "runtime_clear_cache_after_request": True,
        "reviewer_execution_mode": REVIEWER_EXECUTION_MODE,
        "model_independent_reviewer": False,
        "transient_phase2a_transport": "literal_loopback_http",
        "phase2b_uds_transport_activated": False,
        "phase2b_3gib_free_memory_admission_activated": False,
        "model_semantic_assessments": sorted(SEMANTIC_ASSESSMENTS),
        "model_semantic_finding_codes": sorted(FINDING_CODES),
        "deterministic_metadata_finding_codes": sorted(DETERMINISTIC_FINDING_CODES),
    }


def _build_envelope(
    *,
    system_prompt: str,
    row_input: dict[str, Any],
    validation_error: str | None,
) -> tuple[dict[str, Any], str, int]:
    user_payload = dict(row_input)
    if validation_error is not None:
        user_payload["repair_of_rejected_advisory_output"] = True
        user_payload["deterministic_validation_error"] = validation_error
        user_payload["repair_must_change_the_invalid_field_combination"] = True
    messages = [
        {"role": "system", "content": system_prompt},
        {
            "role": "user",
            "content": json.dumps(user_payload, ensure_ascii=False, sort_keys=True),
        },
    ]
    estimated_tokens = _estimate_tokens("\n".join(item["content"] for item in messages))
    if estimated_tokens > MAX_INPUT_ESTIMATED_TOKENS:
        raise ValueError("phase2a_advisory_prompt_budget_exceeded")
    request_id = str(uuid4())
    envelope = {
        "request_id": request_id,
        "mode": "semantic_verify",
        "payload": {**user_payload, "messages": messages},
        "messages": messages,
        "max_tokens": MAX_OUTPUT_TOKENS,
        "temperature": 0.0,
        "top_p": 1.0,
        "seed": 0,
        "stop": [],
    }
    return envelope, request_id, estimated_tokens


def _available_memory_bytes() -> int | None:
    if platform.system() == "Linux":
        try:
            for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) * 1024
        except (OSError, ValueError, IndexError):
            return None
    if platform.system() == "Darwin":
        vm_stat = Path("/usr/bin/vm_stat")
        if not vm_stat.is_file() or vm_stat.is_symlink():
            return None
        try:
            completed = subprocess.run(
                [str(vm_stat)],
                check=True,
                capture_output=True,
                text=True,
                timeout=5,
                env={"LC_ALL": "C"},
            )
            header, *lines = completed.stdout.splitlines()
            match = re.search(r"page size of ([0-9]+) bytes", header)
            if match is None:
                return None
            pages: dict[str, int] = {}
            for line in lines:
                key, separator, value = line.partition(":")
                if separator:
                    pages[key] = int(value.strip().rstrip("."))
            available_pages = sum(
                pages.get(key, 0)
                for key in ("Pages free", "Pages inactive", "Pages speculative")
            )
            return available_pages * int(match.group(1)) if available_pages > 0 else None
        except (OSError, ValueError, subprocess.SubprocessError):
            return None
    return None


def _http_invoker(model_url: str, timeout_seconds: float) -> Callable[[dict[str, Any]], dict[str, Any]]:
    parsed = urlparse(model_url)
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("phase2a_advisory_model_url_must_be_literal_loopback")
    base = model_url.rstrip("/")
    with httpx.Client(
        timeout=httpx.Timeout(connect=5, read=timeout_seconds, write=30, pool=5),
        trust_env=False,
        follow_redirects=False,
    ) as client:
        health = client.get(f"{base}/api/v1/health")
        body = health.json()
        if (
            health.status_code != 200
            or not isinstance(body, dict)
            or body.get("backend") != MODEL_BACKEND
            or body.get("model_id") != PINNED_RUNTIME_REPO
            or body.get("model_loaded") is not True
            or body.get("stub_mode") is not False
            or body.get("memory_profile")
            != {
                "clear_cache_after_request": True,
                "context_window_tokens": 8192,
                "kv_cache_bits": 4,
                "kv_group_size": 64,
                "max_output_tokens": 2048,
                "prefill_step_size": 512,
                "single_flight_generation": True,
            }
        ):
            raise RuntimeError("phase2a_advisory_pinned_model_unavailable")

    def invoke(envelope: dict[str, Any]) -> dict[str, Any]:
        with httpx.Client(
            timeout=httpx.Timeout(connect=5, read=timeout_seconds, write=30, pool=5),
            trust_env=False,
            follow_redirects=False,
        ) as client:
            response = client.post(f"{base}/api/v1/generate", json=envelope)
            response.raise_for_status()
            value = response.json()
        if not isinstance(value, dict):
            raise AdvisoryValidationError("model_response_not_object")
        return value

    return invoke


def _validated_output(
    *,
    body: Mapping[str, Any],
    row_input: Mapping[str, Any],
    request_id: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if body.get("request_id") != request_id:
        raise AdvisoryValidationError("model_request_identity_mismatch")
    if body.get("model_version") != PINNED_RUNTIME_MODEL_VERSION:
        raise AdvisoryValidationError("model_version_mismatch")
    if body.get("backend") != MODEL_BACKEND:
        raise AdvisoryValidationError("model_backend_mismatch")
    if body.get("deterministic") is not True:
        raise AdvisoryValidationError("model_output_not_deterministic")
    warnings = body.get("warnings")
    if not isinstance(warnings, list) or "stub_mode" in warnings:
        raise AdvisoryValidationError("model_warning_contract_invalid")
    finish = str(body.get("finish_reason") or "").casefold()
    if finish in {"length", "max_tokens", "token_limit", "context_length", "truncated"}:
        raise AdvisoryValidationError("model_output_truncated")
    peak = body.get("peak_memory_gb")
    if peak is not None and (not isinstance(peak, int | float) or float(peak) > MAX_PEAK_MEMORY_GB):
        raise AdvisoryValidationError("model_peak_memory_exceeded")
    usage = body.get("usage")
    if not isinstance(usage, dict):
        raise AdvisoryValidationError("model_usage_missing")
    for field in ("input_tokens", "output_tokens", "total_tokens"):
        value = usage.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise AdvisoryValidationError("model_usage_invalid")
    structured = body.get("structured")
    if not isinstance(structured, dict):
        raise AdvisoryValidationError("structured_output_missing")
    expected_keys = {
        "schema",
        "row_id",
        "semantic_assessment",
        "selected_candidate_ranks",
        "finding_codes",
    }
    if set(structured) != expected_keys:
        raise AdvisoryValidationError("structured_output_keys_invalid")
    if structured.get("schema") != OUTPUT_SCHEMA:
        raise AdvisoryValidationError("structured_output_schema_invalid")
    if structured.get("row_id") != row_input.get("row_id"):
        raise AdvisoryValidationError("structured_output_row_mismatch")
    semantic_assessment = structured.get("semantic_assessment")
    if semantic_assessment not in SEMANTIC_ASSESSMENTS:
        raise AdvisoryValidationError("structured_semantic_assessment_invalid")
    ranks = structured.get("selected_candidate_ranks")
    if (
        not isinstance(ranks, list)
        or len(ranks) > MAX_SELECTED
        or any(isinstance(value, bool) or not isinstance(value, int) for value in ranks)
        or len(set(ranks)) != len(ranks)
    ):
        raise AdvisoryValidationError("structured_candidate_ranks_invalid")
    offered = {
        int(candidate["rank"]): candidate
        for candidate in row_input["candidates_provided"]
        if isinstance(candidate, dict) and isinstance(candidate.get("rank"), int)
    }
    if any(rank not in offered for rank in ranks):
        raise AdvisoryValidationError("structured_candidate_rank_outside_input")
    codes = structured.get("finding_codes")
    if (
        not isinstance(codes, list)
        or not 1 <= len(codes) <= 3
        or any(not isinstance(code, str) or code not in FINDING_CODES for code in codes)
        or len(set(codes)) != len(codes)
    ):
        raise AdvisoryValidationError("structured_finding_codes_invalid")
    selected = [offered[rank] for rank in ranks]
    if semantic_assessment == "POTENTIALLY_RELEVANT_EXISTING_SPAN" and (
        not selected
        or not ({"exact_issue_terms_present", "question_context_supported"} & set(codes))
    ):
        raise AdvisoryValidationError("potential_relevance_assessment_boundary_invalid")
    if semantic_assessment == "UNRELATED_CANDIDATES" and (
        selected or codes != ["candidates_unrelated"]
    ):
        raise AdvisoryValidationError("unrelated_assessment_boundary_invalid")
    if semantic_assessment == "AMBIGUOUS_ISSUE_SCOPE" and (
        selected or codes != ["issue_scope_ambiguous"]
    ):
        raise AdvisoryValidationError("ambiguous_assessment_boundary_invalid")
    if semantic_assessment == "PARTIAL_SUPPORT_RESEARCH_NEEDED" and (
        "partial_support_only" not in codes
        or (selected and "candidates_unrelated" in codes)
    ):
        raise AdvisoryValidationError("partial_support_assessment_boundary_invalid")
    if not selected and (
        "exact_issue_terms_present" in codes or "question_context_supported" in codes
    ):
        raise AdvisoryValidationError("support_finding_without_candidate")
    if "candidates_unrelated" in codes and (
        selected
        or "exact_issue_terms_present" in codes
        or "question_context_supported" in codes
        or "partial_support_only" in codes
    ):
        raise AdvisoryValidationError("contradictory_finding_codes")
    metrics = {
        "input_tokens": usage["input_tokens"],
        "output_tokens": usage["output_tokens"],
        "total_tokens": usage["total_tokens"],
        "generation_ms": body.get("generation_ms"),
        "time_to_first_token_ms": body.get("time_to_first_token_ms"),
        "peak_memory_gb": peak,
        "finish_reason": finish,
        "raw_output_sha256": _sha256(
            str(body.get("raw_text") or "").encode("utf-8")
        ),
        "raw_output_character_count": len(str(body.get("raw_text") or "")),
    }
    return dict(structured), metrics


def _effective_recommendation(
    *,
    semantic_assessment: str,
    selected_candidates: Sequence[Mapping[str, Any]],
) -> str:
    if semantic_assessment == "AMBIGUOUS_ISSUE_SCOPE":
        return "CLARIFY_ISSUE_SCOPE"
    if semantic_assessment == "UNRELATED_CANDIDATES":
        return "REJECT_UNRELATED_CANDIDATES"
    if any(
        candidate.get("later_treatment_review_required") is True
        for candidate in selected_candidates
    ):
        return "REVIEW_CASE_LATER_TREATMENT"
    if semantic_assessment == "PARTIAL_SUPPORT_RESEARCH_NEEDED" or any(
        candidate.get("identity_verified") is not True
        or candidate.get("currentness_verified") is not True
        for candidate in selected_candidates
    ):
        return "RESEARCH_ADDITIONAL_OFFICIAL_AUTHORITY"
    return "REVIEW_EXISTING_SPAN_BINDING"


def _owner_note(recommendation: str, ranks: Sequence[int]) -> str:
    rendered = ", ".join(str(rank) for rank in ranks) or "none"
    notes = {
        "REVIEW_EXISTING_SPAN_BINDING": (
            f"Owner to inspect full exact candidate rank(s) {rendered} for a possible issue-to-span binding."
        ),
        "RESEARCH_ADDITIONAL_OFFICIAL_AUTHORITY": (
            f"Candidate rank(s) {rendered} are advisory partial context; targeted official-source research remains required."
        ),
        "REVIEW_CASE_LATER_TREATMENT": (
            f"Owner to inspect case candidate rank(s) {rendered} after a complete later-treatment review."
        ),
        "CLARIFY_ISSUE_SCOPE": "Owner clarification of the issue scope is required before source binding.",
        "REJECT_UNRELATED_CANDIDATES": (
            "The supplied lexical candidates were rejected for binding; targeted official-source research remains required."
        ),
    }
    return notes[recommendation]


def _error_code(exc: BaseException) -> str:
    if isinstance(exc, AdvisoryValidationError):
        return exc.code
    if isinstance(exc, RuntimeError | ValueError) and exc.args:
        value = str(exc.args[0]).casefold().replace("-", "_")
        if _SAFE_REASON.fullmatch(value):
            return value
    value = re.sub(r"(?<!^)(?=[A-Z])", "_", type(exc).__name__).casefold()
    return value if _SAFE_REASON.fullmatch(value) else "phase2a_advisory_unknown_failure"


def _failure_fingerprint(*, row_id: str, input_sha256: str, error_code: str) -> str:
    return _sealed(
        {
            "schema": "legalbot.phase2a.owner-advisory-failure-fingerprint.v1",
            "row_id": row_id,
            "input_content_sha256": input_sha256,
            "prompt_sha256": EXPECTED_PROMPT_SHA256,
            "model_config_sha256": _sealed(_model_config()),
            "error_code": error_code,
        }
    )


def _checkpoint_name(ordinal: int, row_id: str) -> str:
    opaque = _sha256((row_id + "\n").encode("utf-8"))[:24]
    return f"{ordinal:04d}-{opaque}.json"


def _review_one(
    *,
    ordinal: int,
    row: dict[str, Any],
    case: dict[str, Any],
    system_prompt: str,
    invoke: Callable[[dict[str, Any]], dict[str, Any]],
    checkpoints_root: Path,
    diagnostics_root: Path,
) -> dict[str, Any]:
    row_input = _build_row_input(row, case)
    input_sha256 = _sealed(row_input)
    prior_error: str | None = None
    fingerprints: list[str] = []
    for attempt in (1, 2):
        envelope, request_id, estimated_tokens = _build_envelope(
            system_prompt=system_prompt,
            row_input=row_input,
            validation_error=prior_error,
        )
        started = time.perf_counter()
        body: dict[str, Any] | None = None
        try:
            body = invoke(envelope)
            output, metrics = _validated_output(
                body=body,
                row_input=row_input,
                request_id=request_id,
            )
        except Exception as exc:
            error = _error_code(exc)
            fingerprint = _failure_fingerprint(
                row_id=str(row_input["row_id"]),
                input_sha256=input_sha256,
                error_code=error,
            )
            fingerprints.append(fingerprint)
            diagnostic_material = {
                "schema": "legalbot.phase2a.owner-advisory-rejected-attempt.v1",
                "ordinal": ordinal,
                "row_id": row_input["row_id"],
                "attempt": attempt,
                "input_content_sha256": input_sha256,
                "request_id": request_id,
                "error_code": error,
                "failure_fingerprint": fingerprint,
                "same_failure_fingerprint_as_prior_attempt": (
                    len(fingerprints) == 2 and fingerprints[0] == fingerprints[1]
                ),
                "elapsed_ms": round((time.perf_counter() - started) * 1000),
                "response_received": body is not None,
                "raw_output_sha256": (
                    _sha256(str(body.get("raw_text") or "").encode("utf-8"))
                    if body is not None
                    else None
                ),
                "raw_output_persisted": False,
                "hidden_reasoning_persisted": False,
                "owner_decision_assigned": False,
                "technical_qualification_assigned": False,
                "source_admission_authorized": False,
                "phase2b_authorized": False,
                "development30_authorized": False,
            }
            diagnostic = {
                **diagnostic_material,
                "diagnostic_content_sha256": _sealed(diagnostic_material),
            }
            _write_exclusive(
                diagnostics_root / f"{_checkpoint_name(ordinal, str(row_input['row_id']))[:-5]}-a{attempt}.json",
                _pretty_json(diagnostic),
            )
            prior_error = error
            if attempt == 1:
                continue
            held_material = {
                "schema": "legalbot.phase2a.owner-advisory-held-row.v1",
                "ordinal": ordinal,
                "row_id": row_input["row_id"],
                "source_row_packet_content_sha256": row.get("row_packet_content_sha256"),
                "input_content_sha256": input_sha256,
                "status": "HELD_FOR_DEBUG_BEFORE_ANY_THIRD_ATTEMPT",
                "attempt_count": 2,
                "failure_fingerprints": fingerprints,
                "same_failure_fingerprint_twice": fingerprints[0] == fingerprints[1],
                "debug_required_before_third_attempt": True,
                "owner_decision_assigned": False,
                "technical_qualification_assigned": False,
                "source_admission_authorized": False,
                "phase2b_authorized": False,
                "development30_authorized": False,
            }
            held = {**held_material, "held_content_sha256": _sealed(held_material)}
            _write_exclusive(
                checkpoints_root / _checkpoint_name(ordinal, str(row_input["row_id"])),
                _pretty_json(held),
            )
            return held
        selected_by_rank = {
            int(candidate["rank"]): candidate
            for candidate in row["candidates"]
            if isinstance(candidate, dict) and isinstance(candidate.get("rank"), int)
        }
        ranks = output["selected_candidate_ranks"]
        deterministic_codes = []
        selected_input_candidates = {
            int(candidate["rank"]): candidate
            for candidate in row_input["candidates_provided"]
            if isinstance(candidate, dict) and isinstance(candidate.get("rank"), int)
        }
        selected_input = [selected_input_candidates[rank] for rank in ranks]
        if any(
            candidate.get("later_treatment_review_required") is True
            for candidate in selected_input
        ):
            deterministic_codes.append("case_later_treatment_required")
        if any(
            candidate.get("identity_verified") is not True
            or candidate.get("currentness_verified") is not True
            for candidate in selected_input
        ):
            deterministic_codes.append("candidate_version_unverified")
        if not set(deterministic_codes).issubset(DETERMINISTIC_FINDING_CODES):
            raise AssertionError("deterministic advisory finding set escaped its contract")
        effective_recommendation = _effective_recommendation(
            semantic_assessment=output["semantic_assessment"],
            selected_candidates=selected_input,
        )
        checkpoint_material = {
            "schema": "legalbot.phase2a.owner-advisory-row-checkpoint.v3",
            "ordinal": ordinal,
            "row_id": row_input["row_id"],
            "source_row_packet_content_sha256": row.get("row_packet_content_sha256"),
            "input_content_sha256": input_sha256,
            "prompt_sha256": EXPECTED_PROMPT_SHA256,
            "model_config_sha256": _sealed(_model_config()),
            "reviewer_execution_mode": REVIEWER_EXECUTION_MODE,
            "attempt_count": attempt,
            "repaired_after_rejected_output": attempt == 2,
            "request_id": request_id,
            "model_output": output,
            "model_semantic_assessment": output["semantic_assessment"],
            "effective_owner_review_recommendation": effective_recommendation,
            "model_semantic_finding_codes": output["finding_codes"],
            "deterministic_finding_codes": deterministic_codes,
            "combined_finding_codes": [*output["finding_codes"], *deterministic_codes],
            "deterministic_owner_review_note": _owner_note(effective_recommendation, ranks),
            "selected_candidates": [selected_by_rank[rank] for rank in ranks],
            "model_metrics": metrics,
            "estimated_input_tokens_before_invocation": estimated_tokens,
            "raw_model_output_persisted": False,
            "hidden_reasoning_persisted": False,
            "advisory_only": True,
            "owner_decision_required": True,
            "owner_decision_assigned": False,
            "technical_qualification_assigned": False,
            "source_admission_authorized": False,
            "candidate_mutated": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        checkpoint = {
            **checkpoint_material,
            "checkpoint_content_sha256": _sealed(checkpoint_material),
        }
        _write_exclusive(
            checkpoints_root / _checkpoint_name(ordinal, str(row_input["row_id"])),
            _pretty_json(checkpoint),
        )
        return checkpoint
    raise AssertionError("unreachable advisory attempt loop")


def _load_checkpoint(path: Path) -> dict[str, Any]:
    value = _load_object(path)
    if value.get("schema") == "legalbot.phase2a.owner-advisory-row-checkpoint.v3":
        _verify_seal(
            value,
            "checkpoint_content_sha256",
            "phase2a_advisory_checkpoint_seal_invalid",
        )
    elif value.get("schema") == "legalbot.phase2a.owner-advisory-held-row.v1":
        _verify_seal(
            value,
            "held_content_sha256",
            "phase2a_advisory_held_seal_invalid",
        )
    else:
        raise ValueError("phase2a_advisory_checkpoint_schema_invalid")
    return value


def run_review(
    *,
    remainder_path: Path,
    cases_path: Path,
    prompt_path: Path,
    output_root: Path,
    invoke: Callable[[dict[str, Any]], dict[str, Any]],
    started_at: datetime,
    resume: bool = False,
) -> dict[str, Any]:
    """Run or resume all 448 advisory rows with append-only checkpoints."""

    if started_at.tzinfo is None:
        raise ValueError("phase2a_advisory_started_at_naive")
    remainder = _load_object(remainder_path)
    remainder_digest = _verify_seal(
        remainder,
        "artifact_content_sha256",
        "phase2a_advisory_remainder_seal_invalid",
    )
    rows = remainder.get("rows")
    if (
        remainder_digest != EXPECTED_REMAINDER_DIGEST
        or remainder.get("row_count") != EXPECTED_ROW_COUNT
        or not isinstance(rows, list)
        or len(rows) != EXPECTED_ROW_COUNT
        or remainder.get("technical_qualification_assigned") is not False
        or remainder.get("automatic_source_admission") is not False
        or remainder.get("automatic_indexing") is not False
        or remainder.get("automatic_embedding") is not False
        or remainder.get("candidate_mutated") is not False
        or remainder.get("phase2b_authorized") is not False
        or remainder.get("development30_authorized") is not False
    ):
        raise ValueError("phase2a_advisory_remainder_boundary_invalid")
    cases = _load_cases(cases_path)
    system_prompt, prompt_sha256 = _read_prompt(prompt_path)
    if len({str(row.get("row_id") or "") for row in rows if isinstance(row, dict)}) != len(rows):
        raise ValueError("phase2a_advisory_row_set_invalid")

    intent_path = output_root / "INTENT.json"
    if output_root.exists() or output_root.is_symlink():
        if not resume or output_root.is_symlink() or not output_root.is_dir():
            raise ValueError("phase2a_advisory_output_already_exists")
        intent = _load_object(intent_path)
        _verify_seal(
            intent,
            "intent_content_sha256",
            "phase2a_advisory_intent_seal_invalid",
        )
        if (
            intent.get("source_remainder_content_sha256") != remainder_digest
            or intent.get("source_cases_file_sha256") != EXPECTED_CASES_FILE_SHA256
            or intent.get("prompt_sha256") != prompt_sha256
            or intent.get("model_config_sha256") != _sealed(_model_config())
        ):
            raise ValueError("phase2a_advisory_resume_identity_mismatch")
    else:
        output_root.mkdir(parents=True, mode=0o700)
        if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
            raise ValueError("phase2a_advisory_output_mode_invalid")
        intent_material = {
            "schema": "legalbot.phase2a.owner-advisory-review-intent.v3",
            "status": "ADVISORY_REVIEW_ONLY_NO_OWNER_DECISIONS",
            "started_at": started_at.astimezone(UTC).isoformat(timespec="seconds"),
            "source_remainder_content_sha256": remainder_digest,
            "source_remainder_file_sha256": _sha256_file(remainder_path),
            "source_cases_file_sha256": EXPECTED_CASES_FILE_SHA256,
            "prompt_sha256": prompt_sha256,
            "model_config": _model_config(),
            "model_config_sha256": _sealed(_model_config()),
            "model_adapter_file_sha256": _sha256_file(
                BACKEND_ROOT / "app" / "model_runtime" / "adapters.py"
            ),
            "reviewer_execution_mode": REVIEWER_EXECUTION_MODE,
            "model_independent_reviewer": False,
            "phase2b_uds_transport_activated": False,
            "phase2b_3gib_free_memory_admission_activated": False,
            "row_count": EXPECTED_ROW_COUNT,
            "maximum_attempts_per_row": 2,
            "debug_required_before_any_third_attempt": True,
            "raw_model_output_persisted": False,
            "hidden_reasoning_persisted": False,
            "owner_decisions_applied": False,
            "technical_qualification_assigned": False,
            "source_admission_authorized": False,
            "candidate_mutated": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        intent = {**intent_material, "intent_content_sha256": _sealed(intent_material)}
        _write_exclusive(intent_path, _pretty_json(intent))
    checkpoints_root = output_root / "checkpoints"
    diagnostics_root = output_root / "diagnostics"
    checkpoints_root.mkdir(mode=0o700, exist_ok=True)
    diagnostics_root.mkdir(mode=0o700, exist_ok=True)
    if (output_root / "OWNER-ADVISORY-REVIEW-448.json").exists():
        raise ValueError("phase2a_advisory_review_already_finalized")

    results: list[dict[str, Any]] = []
    for ordinal, raw in enumerate(rows, start=1):
        if not isinstance(raw, dict):
            raise ValueError("phase2a_advisory_row_invalid")
        row = raw
        row_id = str(row.get("row_id") or "")
        checkpoint_path = checkpoints_root / _checkpoint_name(ordinal, row_id)
        if checkpoint_path.exists():
            checkpoint = _load_checkpoint(checkpoint_path)
            if (
                checkpoint.get("ordinal") != ordinal
                or checkpoint.get("row_id") != row_id
                or checkpoint.get("source_row_packet_content_sha256")
                != row.get("row_packet_content_sha256")
            ):
                raise ValueError("phase2a_advisory_checkpoint_binding_invalid")
            results.append(checkpoint)
            continue
        case_id = str(row.get("case_id") or "")
        case = cases.get(case_id)
        if case is None:
            raise ValueError("phase2a_advisory_row_case_missing")
        results.append(
            _review_one(
                ordinal=ordinal,
                row=row,
                case=case,
                system_prompt=system_prompt,
                invoke=invoke,
                checkpoints_root=checkpoints_root,
                diagnostics_root=diagnostics_root,
            )
        )

    held = [item for item in results if item.get("schema", "").endswith("held-row.v1")]
    passed = [item for item in results if item.get("schema", "").endswith("row-checkpoint.v3")]
    recommendation_counts = Counter(
        str(item["effective_owner_review_recommendation"]) for item in passed
    )
    semantic_assessment_counts = Counter(
        str(item["model_semantic_assessment"]) for item in passed
    )
    final_rows: list[dict[str, Any]] = []
    for item in results:
        if item in held:
            final_rows.append(
                {
                    "ordinal": item["ordinal"],
                    "row_id": item["row_id"],
                    "status": item["status"],
                    "held_content_sha256": item["held_content_sha256"],
                    "owner_decision_required": True,
                }
            )
        else:
            final_rows.append(
                {
                    "ordinal": item["ordinal"],
                    "row_id": item["row_id"],
                    "status": "ADVISORY_RECOMMENDATION_READY_OWNER_DECISION_REQUIRED",
                    "model_semantic_assessment": item["model_semantic_assessment"],
                    "recommendation": item["effective_owner_review_recommendation"],
                    "selected_candidate_ranks": item["model_output"][
                        "selected_candidate_ranks"
                    ],
                    "model_semantic_finding_codes": item["model_semantic_finding_codes"],
                    "deterministic_finding_codes": item["deterministic_finding_codes"],
                    "finding_codes": item["combined_finding_codes"],
                    "deterministic_owner_review_note": item[
                        "deterministic_owner_review_note"
                    ],
                    "selected_candidates": item["selected_candidates"],
                    "checkpoint_content_sha256": item["checkpoint_content_sha256"],
                    "owner_decision_required": True,
                }
            )
    final_material = {
        "schema": "legalbot.phase2a.owner-advisory-review-448.v3",
        "status": (
            "ADVISORY_AI_REVIEW_COMPLETE_OWNER_DECISIONS_REQUIRED"
            if not held
            else "ADVISORY_AI_REVIEW_COMPLETE_WITH_HELD_ROWS_DEBUG_REQUIRED"
        ),
        "source_intent_content_sha256": intent["intent_content_sha256"],
        "source_remainder_content_sha256": remainder_digest,
        "prompt_sha256": prompt_sha256,
        "model_config_sha256": _sealed(_model_config()),
        "reviewer_execution_mode": REVIEWER_EXECUTION_MODE,
        "model_independent_reviewer": False,
        "row_count": len(results),
        "advisory_recommendation_count": len(passed),
        "held_for_debug_count": len(held),
        "repaired_recommendation_count": sum(
            item.get("repaired_after_rejected_output") is True for item in passed
        ),
        "recommendation_counts": dict(sorted(recommendation_counts.items())),
        "semantic_assessment_counts": dict(sorted(semantic_assessment_counts.items())),
        "rows": final_rows,
        "raw_model_output_persisted": False,
        "hidden_reasoning_persisted": False,
        "owner_decisions_applied": False,
        "technical_qualification_assigned": False,
        "source_admission_authorized": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    final = {**final_material, "artifact_content_sha256": _sealed(final_material)}
    _write_exclusive(output_root / "OWNER-ADVISORY-REVIEW-448.json", _pretty_json(final))
    outcome = (
        "PHASE 2A ADVISORY REVIEW COMPLETE — OWNER DECISIONS REQUIRED; NO PHASE 2B\n"
        if not held
        else "PHASE 2A ADVISORY REVIEW HELD ROWS REQUIRE DEBUG — NO PHASE 2B\n"
    )
    _write_exclusive(output_root / "OUTCOME.txt", outcome.encode("utf-8"))
    files = sorted(
        path for path in output_root.iterdir() if path.is_file() and path.name != "SHA256SUMS.txt"
    )
    _write_exclusive(
        output_root / "SHA256SUMS.txt",
        "".join(f"{_sha256_file(path)}  {path.name}\n" for path in files).encode(),
    )
    return {
        "output_root": str(output_root),
        "artifact_content_sha256": final["artifact_content_sha256"],
        "row_count": len(results),
        "advisory_recommendation_count": len(passed),
        "held_for_debug_count": len(held),
        "repaired_recommendation_count": final["repaired_recommendation_count"],
        "recommendation_counts": final["recommendation_counts"],
        "owner_decisions_applied": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }


def _persist_failure(output_root: Path, exc: BaseException) -> None:
    try:
        output_root.mkdir(parents=True, mode=0o700, exist_ok=True)
        path = output_root / "FAILURE.json"
        if path.exists():
            return
        material = {
            "schema": "legalbot.phase2a.owner-advisory-run-failure.v1",
            "error_code": _error_code(exc),
            "exception_type": type(exc).__name__,
            "owner_decisions_applied": False,
            "technical_qualification_assigned": False,
            "source_admission_authorized": False,
            "candidate_mutated": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        _write_exclusive(
            path,
            _pretty_json({**material, "failure_content_sha256": _sealed(material)}),
        )
    except Exception:
        return


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--remainder", required=True, type=Path)
    parser.add_argument("--cases", required=True, type=Path)
    parser.add_argument("--prompt", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--model-url", default="http://127.0.0.1:8789")
    parser.add_argument("--timeout-seconds", type=float, default=300.0)
    parser.add_argument("--resume", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.timeout_seconds <= 0:
            raise ValueError("phase2a_advisory_timeout_invalid")
        invoke = _http_invoker(str(args.model_url), float(args.timeout_seconds))
        result = run_review(
            remainder_path=args.remainder.resolve(strict=True),
            cases_path=args.cases.resolve(strict=True),
            prompt_path=args.prompt.resolve(strict=True),
            output_root=args.output_root.resolve(),
            invoke=invoke,
            started_at=datetime.now(UTC),
            resume=bool(args.resume),
        )
    except Exception as exc:
        _persist_failure(args.output_root.resolve(), exc)
        raise
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
