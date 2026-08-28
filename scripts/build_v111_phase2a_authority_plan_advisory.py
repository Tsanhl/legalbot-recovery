#!/usr/bin/env python3
"""Build advisory-only authority plans for the 448 unresolved Phase-2A issues.

The planner is intentionally narrower than legal qualification.  It may point
an owner to an authority already present in the sealed catalogue, or record a
likely gap.  It cannot bind a proposition, decide materiality, admit a source,
mutate a candidate, or authorize Phase 2B or Development 30.

Every model output is constrained to authority identifiers supplied in the
request.  Raw model text and hidden reasoning are not persisted.  Malformed
output receives at most one targeted repair; two materially identical failure
fingerprints hold that batch before any third attempt.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import time
from collections import Counter, defaultdict
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

import httpx

PROJECT_ROOT = Path(__file__).resolve().parents[1]
OWNER_REVIEW_ROOT = PROJECT_ROOT / "data" / "evaluations" / "phase2a-owner-review"
DEFAULT_REMAINING = (
    OWNER_REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-25-r49-safe-subset-approved"
    / "REMAINING-SUBSTANTIVE-OWNER-DECISIONS-478.json"
)
DEFAULT_ORIGINAL = (
    OWNER_REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-24-r29" / "REMAINING-448-RESEARCH-PACKETS.json"
)
DEFAULT_DEEP = (
    OWNER_REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-24-r40-deep-recovery"
    / "DEEP-CURRENT-OFFICIAL-CANDIDATES-176.json"
)
DEFAULT_CASES = PROJECT_ROOT / "benchmarks" / "evaluation" / "live-evaluation-60-v1" / "cases.jsonl"
DEFAULT_OUTPUT = OWNER_REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-25-r50-authority-plan-advisory"

EXPECTED_REMAINING_CONTENT_SHA256 = (
    "da2fa31552199958143516b6804fc5d744988b451571c8cd9900f3095a3723a2"
)
EXPECTED_ORIGINAL_CONTENT_SHA256 = (
    "a7f7359c3ff12da02ee4056532198d39417459c9e20aac602f64437fb7cf5aa6"
)
EXPECTED_DEEP_CONTENT_SHA256 = "692cdafd0e10f8b864a96cc35165cb20441dc099b52a2f2cad90b38befcbbbf1"
EXPECTED_CASES_FILE_SHA256 = "78a738afd920ff840dcedeb0fd3fd5ca81035f499a0630d351d49e7c6cd3777a"
EXPECTED_ISSUE_COUNT = 448
EXPECTED_CASE_COUNT = 60
EXPECTED_MODEL_ID = "mlx-community/Qwen3.5-9B-4bit"
EXPECTED_MODEL_VERSION = "mlx-community/Qwen3.5-9B-4bit@8b2b98c00a6b"
MODEL_BACKEND = "mlx_lm"
OUTPUT_SCHEMA = "p2a-plan-v1"
BATCH_SIZE = 4
MAX_SELECTIONS = 2
MAX_LOCATOR_LENGTH = 160
MAX_OUTPUT_TOKENS = 700
MAX_PEAK_MEMORY_GB = 12.0
REVIEWER_EXECUTION_MODE = (
    "separate_advisory_authority_planner_same_model_adapter_as_drafting_not_model_independent"
)

SYSTEM_PROMPT = """/no_think
Advisory evidence planner only. Do not answer the scenario, state a legal rule, decide materiality, or explain. For each issue select at most two supplied authority IDs likely to contain the direct controlling proposition, with a short locator hint. Never invent an authority ID. If none of the supplied authorities is likely to contain direct primary support, mark GAP and select none. Use NONMATERIAL only when the issue is genuinely an analytical or presentation dimension rather than a legal proposition. Distinguish contractual limitation clauses from statutory limitation periods. Distinguish England-and-Wales provisions from Scotland-only provisions. Output JSON only with exactly: {"schema":"p2a-plan-v1","case_id":"<supplied case id>","rows":[{"row_id":"<supplied row id>","assessment":"FOUND|GAP|NONMATERIAL","selections":[{"id":"<supplied authority id>","locator":"<short locator>"}]}]}. Include each supplied row exactly once."""

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_CODE = re.compile(r"^[a-z0-9][a-z0-9_]{0,127}$")
_ROW_ID = re.compile(r"^(?:live30|live60)-q[0-9]{2}:issue-[0-9]{2}$")
_PROHIBITED_LOCATOR = re.compile(r"(?:/users/|file:|https?://|\\x00)", re.IGNORECASE)

Invoke = Callable[[dict[str, Any]], dict[str, Any]]


class AdvisoryValidationError(ValueError):
    """A stable machine-safe validation error."""

    def __init__(self, code: str):
        if not _SAFE_CODE.fullmatch(code):
            raise ValueError("phase2a_authority_plan_error_code_invalid")
        self.code = code
        super().__init__(code)


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sealed(value: Any) -> str:
    return _sha256(_canonical_json(value))


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


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
        raise ValueError("phase2a_authority_plan_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_authority_plan_input_must_be_object")
    return value


def _verify_seal(value: Mapping[str, Any], field: str, code: str) -> str:
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if not _SHA256.fullmatch(supplied) or supplied != _sealed(material):
        raise ValueError(code)
    return supplied


def _load_cases(path: Path) -> dict[str, dict[str, Any]]:
    if _sha256_file(path) != EXPECTED_CASES_FILE_SHA256:
        raise ValueError("phase2a_authority_plan_cases_identity_invalid")
    cases: dict[str, dict[str, Any]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if not isinstance(row, dict):
            raise ValueError("phase2a_authority_plan_case_row_invalid")
        case_id = str(row.get("case_id") or "")
        if case_id in cases or not case_id or not str(row.get("question") or "").strip():
            raise ValueError("phase2a_authority_plan_case_registry_invalid")
        cases[case_id] = row
    if len(cases) != EXPECTED_CASE_COUNT:
        raise ValueError("phase2a_authority_plan_case_count_invalid")
    return cases


def _load_issue_rows(path: Path) -> tuple[list[dict[str, Any]], str]:
    remaining = _load_object(path)
    content_sha256 = _verify_seal(
        remaining,
        "artifact_content_sha256",
        "phase2a_authority_plan_remaining_seal_invalid",
    )
    items = remaining.get("items")
    if (
        content_sha256 != EXPECTED_REMAINING_CONTENT_SHA256
        or remaining.get("item_count") != 478
        or remaining.get("category_counts")
        != {
            "issue": 448,
            "judgment": 20,
            "legislation_byte_mismatch": 1,
            "source_admission": 9,
        }
        or not isinstance(items, list)
        or remaining.get("owner_decisions_applied") is not False
        or remaining.get("source_admission_authorized") is not False
        or remaining.get("candidate_mutated") is not False
        or remaining.get("phase2b_authorized") is not False
        or remaining.get("development30_authorized") is not False
    ):
        raise ValueError("phase2a_authority_plan_remaining_boundary_invalid")
    issue_rows = [
        dict(row) for row in items if isinstance(row, dict) and row.get("category") == "issue"
    ]
    row_ids = [str(row.get("item_id") or "") for row in issue_rows]
    if (
        len(issue_rows) != EXPECTED_ISSUE_COUNT
        or len(set(row_ids)) != EXPECTED_ISSUE_COUNT
        or any(not _ROW_ID.fullmatch(row_id) for row_id in row_ids)
        or any(row.get("owner_outcome") is not None for row in issue_rows)
    ):
        raise ValueError("phase2a_authority_plan_issue_boundary_invalid")
    return issue_rows, content_sha256


def _load_candidate_rows(
    original_path: Path,
    deep_path: Path,
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, str]]:
    original = _load_object(original_path)
    deep = _load_object(deep_path)
    original_sha256 = _verify_seal(
        original,
        "artifact_content_sha256",
        "phase2a_authority_plan_original_seal_invalid",
    )
    deep_sha256 = _verify_seal(
        deep,
        "artifact_content_sha256",
        "phase2a_authority_plan_deep_seal_invalid",
    )
    if (
        original_sha256 != EXPECTED_ORIGINAL_CONTENT_SHA256
        or original.get("row_count") != EXPECTED_ISSUE_COUNT
        or deep_sha256 != EXPECTED_DEEP_CONTENT_SHA256
        or deep.get("row_count") != 176
    ):
        raise ValueError("phase2a_authority_plan_candidate_boundary_invalid")
    by_row: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for artifact in (original, deep):
        rows = artifact.get("rows")
        if not isinstance(rows, list):
            raise ValueError("phase2a_authority_plan_candidate_rows_invalid")
        for row in rows:
            if not isinstance(row, dict) or not _ROW_ID.fullmatch(str(row.get("row_id") or "")):
                raise ValueError("phase2a_authority_plan_candidate_row_invalid")
            candidates = row.get("candidates")
            if not isinstance(candidates, list):
                raise ValueError("phase2a_authority_plan_candidates_invalid")
            for candidate in candidates:
                if not isinstance(candidate, dict):
                    raise ValueError("phase2a_authority_plan_candidate_invalid")
                authority_id = str(candidate.get("authority_identity_id") or "")
                if not authority_id or not str(candidate.get("title") or "").strip():
                    raise ValueError("phase2a_authority_plan_candidate_identity_invalid")
                by_row[str(row["row_id"])].append(dict(candidate))
    return dict(by_row), {"original": original_sha256, "deep": deep_sha256}


def _batch_rows(issue_rows: Sequence[Mapping[str, Any]]) -> list[list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    case_order: list[str] = []
    for row in issue_rows:
        case_id = str(row.get("case_id") or "")
        if case_id not in grouped:
            case_order.append(case_id)
        grouped[case_id].append(dict(row))
    batches: list[list[dict[str, Any]]] = []
    for case_id in case_order:
        rows = grouped[case_id]
        for start in range(0, len(rows), BATCH_SIZE):
            batches.append(rows[start : start + BATCH_SIZE])
    if sum(len(batch) for batch in batches) != EXPECTED_ISSUE_COUNT:
        raise ValueError("phase2a_authority_plan_batch_coverage_invalid")
    return batches


def _short_locator(value: object) -> str | None:
    text = " ".join(str(value or "").split())
    if not text:
        return None
    if len(text) > 96:
        parts = [part.strip() for part in text.split(">") if part.strip()]
        text = parts[-1] if parts else text[:96]
    return text[:96]


def _authority_catalogue(
    batch: Sequence[Mapping[str, Any]],
    candidates_by_row: Mapping[str, Sequence[Mapping[str, Any]]],
) -> list[dict[str, Any]]:
    catalogue: dict[str, dict[str, Any]] = {}
    for row in batch:
        row_id = str(row["item_id"])
        for candidate in candidates_by_row.get(row_id, ()):
            authority_id = str(candidate.get("authority_identity_id") or "")
            item = catalogue.setdefault(
                authority_id,
                {
                    "id": authority_id,
                    "title": str(candidate.get("title") or ""),
                    "citation": str(candidate.get("canonical_citation") or ""),
                    "family": str(candidate.get("source_family") or ""),
                    "currentness_verified": candidate.get("currentness_verified") is True,
                    "locator_examples": [],
                },
            )
            locator = _short_locator(candidate.get("locator"))
            if (
                locator
                and locator not in item["locator_examples"]
                and len(item["locator_examples"]) < 5
            ):
                item["locator_examples"].append(locator)
    return list(catalogue.values())


def _build_input(
    *,
    batch_ordinal: int,
    batch: Sequence[Mapping[str, Any]],
    case: Mapping[str, Any],
    candidates_by_row: Mapping[str, Sequence[Mapping[str, Any]]],
    repair_error_code: str | None,
) -> dict[str, Any]:
    rows = [
        {
            "row_id": row["item_id"],
            "issue_label": row["issue_label"],
            "legal_domain": row["legal_domain"],
        }
        for row in batch
    ]
    value: dict[str, Any] = {
        "schema": "legalbot.v111.phase2a.authority-plan-input.v1",
        "batch_ordinal": batch_ordinal,
        "case_id": case["case_id"],
        "subject": case["subject"],
        "scenario": case["question"],
        "rows": rows,
        "authorities": _authority_catalogue(batch, candidates_by_row),
        "advisory_only": True,
        "owner_decision_required": True,
        "qualification_forbidden": True,
        "source_admission_forbidden": True,
        "gate_authorization_forbidden": True,
    }
    if repair_error_code is not None:
        value["repair_of_rejected_output"] = True
        value["deterministic_validation_error"] = repair_error_code
        value["repair_instruction"] = "Return only the exact compact JSON schema."
    return value


def _envelope(row_input: Mapping[str, Any]) -> tuple[dict[str, Any], str]:
    request_id = str(uuid4())
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": json.dumps(row_input, ensure_ascii=False, separators=(",", ":")),
        },
    ]
    return (
        {
            "request_id": request_id,
            "mode": "semantic_verify",
            "payload": {**dict(row_input), "messages": messages},
            "messages": messages,
            "max_tokens": MAX_OUTPUT_TOKENS,
            "temperature": 0.0,
            "top_p": 1.0,
            "seed": 0,
            "stop": [],
        },
        request_id,
    )


def _http_invoker(model_url: str, timeout_seconds: float) -> Invoke:
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
        raise ValueError("phase2a_authority_plan_model_url_must_be_literal_loopback")
    base = model_url.rstrip("/")
    with httpx.Client(
        timeout=httpx.Timeout(connect=5, read=timeout_seconds, write=30, pool=5),
        trust_env=False,
        follow_redirects=False,
    ) as client:
        response = client.get(f"{base}/api/v1/health")
        body = response.json()
    if (
        response.status_code != 200
        or not isinstance(body, dict)
        or body.get("backend") != MODEL_BACKEND
        or body.get("model_id") != EXPECTED_MODEL_ID
        or body.get("model_loaded") is not True
        or body.get("stub_mode") is not False
    ):
        raise RuntimeError("phase2a_authority_plan_pinned_model_unavailable")

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


def _validate_model_response(
    *,
    body: Mapping[str, Any],
    row_input: Mapping[str, Any],
    request_id: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if body.get("request_id") != request_id:
        raise AdvisoryValidationError("model_request_identity_mismatch")
    if body.get("model_version") != EXPECTED_MODEL_VERSION:
        raise AdvisoryValidationError("model_version_mismatch")
    if body.get("backend") != MODEL_BACKEND or body.get("deterministic") is not True:
        raise AdvisoryValidationError("model_runtime_identity_invalid")
    finish_reason = str(body.get("finish_reason") or "").casefold()
    if finish_reason in {"length", "max_tokens", "token_limit", "context_length", "truncated"}:
        raise AdvisoryValidationError("model_output_truncated")
    warnings = body.get("warnings")
    if not isinstance(warnings, list) or "stub_mode" in warnings:
        raise AdvisoryValidationError("model_warning_contract_invalid")
    peak = body.get("peak_memory_gb")
    if peak is not None and (
        isinstance(peak, bool)
        or not isinstance(peak, int | float)
        or float(peak) > MAX_PEAK_MEMORY_GB
    ):
        raise AdvisoryValidationError("model_peak_memory_exceeded")
    usage = body.get("usage")
    if not isinstance(usage, dict) or any(
        isinstance(usage.get(field), bool)
        or not isinstance(usage.get(field), int)
        or int(usage[field]) < 0
        for field in ("input_tokens", "output_tokens", "total_tokens")
    ):
        raise AdvisoryValidationError("model_usage_invalid")
    structured = body.get("structured")
    if not isinstance(structured, dict) or set(structured) != {"schema", "case_id", "rows"}:
        raise AdvisoryValidationError("structured_output_keys_invalid")
    if structured.get("schema") != OUTPUT_SCHEMA or structured.get("case_id") != row_input.get(
        "case_id"
    ):
        raise AdvisoryValidationError("structured_output_identity_invalid")
    supplied_rows = [str(row["row_id"]) for row in row_input["rows"]]
    supplied_authorities = {str(item["id"]) for item in row_input["authorities"]}
    output_rows = structured.get("rows")
    if not isinstance(output_rows, list) or len(output_rows) != len(supplied_rows):
        raise AdvisoryValidationError("structured_output_row_count_invalid")
    normalized: list[dict[str, Any]] = []
    observed: list[str] = []
    for output in output_rows:
        if not isinstance(output, dict) or set(output) != {"row_id", "assessment", "selections"}:
            raise AdvisoryValidationError("structured_output_row_keys_invalid")
        row_id = str(output.get("row_id") or "")
        assessment = output.get("assessment")
        selections = output.get("selections")
        if row_id not in supplied_rows or assessment not in {"FOUND", "GAP", "NONMATERIAL"}:
            raise AdvisoryValidationError("structured_output_row_invalid")
        if not isinstance(selections, list) or len(selections) > MAX_SELECTIONS:
            raise AdvisoryValidationError("structured_output_selections_invalid")
        if assessment == "FOUND" and not selections:
            raise AdvisoryValidationError("structured_output_found_without_selection")
        if assessment in {"GAP", "NONMATERIAL"} and selections:
            raise AdvisoryValidationError("structured_output_nonfound_with_selection")
        normalized_selections: list[dict[str, str]] = []
        for selection in selections:
            if not isinstance(selection, dict) or set(selection) != {"id", "locator"}:
                raise AdvisoryValidationError("structured_output_selection_keys_invalid")
            authority_id = str(selection.get("id") or "")
            locator = " ".join(str(selection.get("locator") or "").split())
            if authority_id not in supplied_authorities:
                raise AdvisoryValidationError("structured_output_invented_authority")
            if (
                not locator
                or len(locator) > MAX_LOCATOR_LENGTH
                or _PROHIBITED_LOCATOR.search(locator)
            ):
                raise AdvisoryValidationError("structured_output_locator_invalid")
            normalized_selections.append({"authority_id": authority_id, "locator_hint": locator})
        observed.append(row_id)
        normalized.append(
            {
                "row_id": row_id,
                "assessment": assessment,
                "selections": normalized_selections,
                "owner_outcome": None,
                "owner_decision_required": True,
                "technical_qualification_assigned": False,
            }
        )
    if len(set(observed)) != len(observed) or set(observed) != set(supplied_rows):
        raise AdvisoryValidationError("structured_output_row_set_invalid")
    normalized.sort(key=lambda row: supplied_rows.index(row["row_id"]))
    raw = str(body.get("raw_text") or "")
    metrics = {
        "input_tokens": usage["input_tokens"],
        "output_tokens": usage["output_tokens"],
        "total_tokens": usage["total_tokens"],
        "generation_ms": body.get("generation_ms"),
        "time_to_first_token_ms": body.get("time_to_first_token_ms"),
        "peak_memory_gb": peak,
        "finish_reason": finish_reason,
        "raw_output_sha256": _sha256(raw.encode("utf-8")),
        "raw_output_character_count": len(raw),
    }
    return normalized, metrics


def _error_code(exc: BaseException) -> str:
    if isinstance(exc, AdvisoryValidationError):
        return exc.code
    if isinstance(exc, RuntimeError | ValueError) and exc.args:
        value = str(exc.args[0]).casefold().replace("-", "_")
        if _SAFE_CODE.fullmatch(value):
            return value
    value = re.sub(r"(?<!^)(?=[A-Z])", "_", type(exc).__name__).casefold()
    return value if _SAFE_CODE.fullmatch(value) else "phase2a_authority_plan_unknown_failure"


def _checkpoint_name(ordinal: int, batch: Sequence[Mapping[str, Any]]) -> str:
    row_ids = "\n".join(str(row["item_id"]) for row in batch)
    return f"{ordinal:03d}-{_sha256((row_ids + chr(10)).encode())[:24]}.json"


def _review_batch(
    *,
    ordinal: int,
    batch: Sequence[Mapping[str, Any]],
    case: Mapping[str, Any],
    candidates_by_row: Mapping[str, Sequence[Mapping[str, Any]]],
    invoke: Invoke,
    checkpoints_root: Path,
    diagnostics_root: Path,
) -> dict[str, Any]:
    prior_error: str | None = None
    fingerprints: list[str] = []
    source_row_hashes = [str(row["record_content_sha256"]) for row in batch]
    for attempt in (1, 2):
        row_input = _build_input(
            batch_ordinal=ordinal,
            batch=batch,
            case=case,
            candidates_by_row=candidates_by_row,
            repair_error_code=prior_error,
        )
        input_sha256 = _sealed(row_input)
        envelope, request_id = _envelope(row_input)
        started = time.perf_counter()
        body: dict[str, Any] | None = None
        try:
            body = invoke(envelope)
            plans, metrics = _validate_model_response(
                body=body,
                row_input=row_input,
                request_id=request_id,
            )
        except Exception as exc:
            error = _error_code(exc)
            fingerprint = _sealed(
                {
                    "schema": "legalbot.v111.phase2a.authority-plan-failure-fingerprint.v1",
                    "batch_ordinal": ordinal,
                    "row_ids": [str(row["item_id"]) for row in batch],
                    "input_content_sha256": input_sha256,
                    "prompt_sha256": _sha256((SYSTEM_PROMPT + "\n").encode()),
                    "model_version": EXPECTED_MODEL_VERSION,
                    "error_code": error,
                }
            )
            fingerprints.append(fingerprint)
            diagnostic_material = {
                "schema": "legalbot.v111.phase2a.authority-plan-rejected-attempt.v1",
                "batch_ordinal": ordinal,
                "row_ids": [str(row["item_id"]) for row in batch],
                "attempt": attempt,
                "input_content_sha256": input_sha256,
                "request_id": request_id,
                "error_code": error,
                "failure_fingerprint": fingerprint,
                "same_failure_fingerprint_as_prior_attempt": (
                    len(fingerprints) == 2 and fingerprints[0] == fingerprints[1]
                ),
                "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
                "response_received": body is not None,
                "raw_output_sha256": (
                    _sha256(str(body.get("raw_text") or "").encode()) if body else None
                ),
                "raw_output_persisted": False,
                "hidden_reasoning_persisted": False,
                "owner_decision_assigned": False,
                "technical_qualification_assigned": False,
                "source_admission_authorized": False,
                "candidate_mutated": False,
                "phase2b_authorized": False,
                "development30_authorized": False,
            }
            diagnostic = {
                **diagnostic_material,
                "diagnostic_content_sha256": _sealed(diagnostic_material),
            }
            stem = _checkpoint_name(ordinal, batch)[:-5]
            _write_exclusive(
                diagnostics_root / f"{stem}-a{attempt}.json",
                _pretty_json(diagnostic),
            )
            prior_error = error
            if attempt == 1:
                continue
            held_material = {
                "schema": "legalbot.v111.phase2a.authority-plan-held-batch.v1",
                "batch_ordinal": ordinal,
                "case_id": case["case_id"],
                "row_ids": [str(row["item_id"]) for row in batch],
                "source_row_record_content_sha256s": source_row_hashes,
                "status": "HELD_FOR_DEBUG_BEFORE_ANY_THIRD_ATTEMPT",
                "attempt_count": 2,
                "failure_fingerprints": fingerprints,
                "same_failure_fingerprint_twice": fingerprints[0] == fingerprints[1],
                "debug_required_before_third_attempt": True,
                "owner_decision_assigned": False,
                "technical_qualification_assigned": False,
                "source_admission_authorized": False,
                "candidate_mutated": False,
                "phase2b_authorized": False,
                "development30_authorized": False,
            }
            held = {**held_material, "held_content_sha256": _sealed(held_material)}
            _write_exclusive(
                checkpoints_root / _checkpoint_name(ordinal, batch),
                _pretty_json(held),
            )
            return held
        checkpoint_material = {
            "schema": "legalbot.v111.phase2a.authority-plan-checkpoint.v1",
            "batch_ordinal": ordinal,
            "case_id": case["case_id"],
            "row_ids": [str(row["item_id"]) for row in batch],
            "source_row_record_content_sha256s": source_row_hashes,
            "input_content_sha256": input_sha256,
            "prompt_sha256": _sha256((SYSTEM_PROMPT + "\n").encode()),
            "model_version": EXPECTED_MODEL_VERSION,
            "reviewer_execution_mode": REVIEWER_EXECUTION_MODE,
            "attempt_count": attempt,
            "repaired_after_rejected_output": attempt == 2,
            "plans": plans,
            "model_metrics": metrics,
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
            checkpoints_root / _checkpoint_name(ordinal, batch),
            _pretty_json(checkpoint),
        )
        return checkpoint
    raise AssertionError("unreachable authority-plan attempt loop")


def _load_checkpoint(path: Path) -> dict[str, Any]:
    value = _load_object(path)
    if value.get("schema") == "legalbot.v111.phase2a.authority-plan-checkpoint.v1":
        _verify_seal(value, "checkpoint_content_sha256", "authority_plan_checkpoint_invalid")
    elif value.get("schema") == "legalbot.v111.phase2a.authority-plan-held-batch.v1":
        _verify_seal(value, "held_content_sha256", "authority_plan_held_invalid")
    else:
        raise ValueError("phase2a_authority_plan_checkpoint_schema_invalid")
    return value


def build_authority_plans(
    *,
    remaining_path: Path,
    original_path: Path,
    deep_path: Path,
    cases_path: Path,
    output_root: Path,
    invoke: Invoke,
    started_at: datetime,
    resume: bool = False,
) -> dict[str, Any]:
    """Build or resume the append-only advisory authority-plan package."""

    if started_at.tzinfo is None:
        raise ValueError("phase2a_authority_plan_started_at_naive")
    issue_rows, remaining_sha256 = _load_issue_rows(remaining_path)
    candidates_by_row, candidate_hashes = _load_candidate_rows(original_path, deep_path)
    cases = _load_cases(cases_path)
    batches = _batch_rows(issue_rows)
    if any(str(row["case_id"]) not in cases for row in issue_rows):
        raise ValueError("phase2a_authority_plan_case_reference_invalid")

    intent_path = output_root / "INTENT.json"
    if output_root.exists() or output_root.is_symlink():
        if not resume or output_root.is_symlink() or not output_root.is_dir():
            raise ValueError("phase2a_authority_plan_output_already_exists")
        intent = _load_object(intent_path)
        _verify_seal(intent, "intent_content_sha256", "authority_plan_intent_invalid")
        if (
            intent.get("source_remaining_content_sha256") != remaining_sha256
            or intent.get("source_original_content_sha256") != candidate_hashes["original"]
            or intent.get("source_deep_content_sha256") != candidate_hashes["deep"]
            or intent.get("prompt_sha256") != _sha256((SYSTEM_PROMPT + "\n").encode())
        ):
            raise ValueError("phase2a_authority_plan_resume_identity_mismatch")
    else:
        output_root.mkdir(parents=True, mode=0o700)
        if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
            raise ValueError("phase2a_authority_plan_output_mode_invalid")
        intent_material = {
            "schema": "legalbot.v111.phase2a.authority-plan-intent.v1",
            "status": "ADVISORY_AUTHORITY_PLANNING_ONLY_NO_OWNER_DECISIONS",
            "started_at": started_at.astimezone(UTC).isoformat(timespec="seconds"),
            "source_remaining_content_sha256": remaining_sha256,
            "source_remaining_file_sha256": _sha256_file(remaining_path),
            "source_original_content_sha256": candidate_hashes["original"],
            "source_deep_content_sha256": candidate_hashes["deep"],
            "source_cases_file_sha256": EXPECTED_CASES_FILE_SHA256,
            "prompt_sha256": _sha256((SYSTEM_PROMPT + "\n").encode()),
            "model_id": EXPECTED_MODEL_ID,
            "model_version": EXPECTED_MODEL_VERSION,
            "reviewer_execution_mode": REVIEWER_EXECUTION_MODE,
            "model_independent_reviewer": False,
            "independent_reranker_completed_separately": True,
            "issue_count": EXPECTED_ISSUE_COUNT,
            "batch_count": len(batches),
            "maximum_rows_per_batch": BATCH_SIZE,
            "maximum_attempts_per_batch": 2,
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
    final_path = output_root / "ADVISORY-AUTHORITY-PLANS-448.json"
    if final_path.exists():
        raise ValueError("phase2a_authority_plan_already_finalized")

    results: list[dict[str, Any]] = []
    for ordinal, batch in enumerate(batches, start=1):
        checkpoint_path = checkpoints_root / _checkpoint_name(ordinal, batch)
        if checkpoint_path.exists():
            if not resume:
                raise ValueError("phase2a_authority_plan_checkpoint_exists_without_resume")
            results.append(_load_checkpoint(checkpoint_path))
            continue
        case = cases[str(batch[0]["case_id"])]
        results.append(
            _review_batch(
                ordinal=ordinal,
                batch=batch,
                case=case,
                candidates_by_row=candidates_by_row,
                invoke=invoke,
                checkpoints_root=checkpoints_root,
                diagnostics_root=diagnostics_root,
            )
        )

    plans: list[dict[str, Any]] = []
    held_rows: list[str] = []
    for result in results:
        if result.get("schema") == "legalbot.v111.phase2a.authority-plan-held-batch.v1":
            held_rows.extend(str(row_id) for row_id in result["row_ids"])
        else:
            plans.extend(dict(plan) for plan in result["plans"])
    if len(plans) + len(held_rows) != EXPECTED_ISSUE_COUNT:
        raise ValueError("phase2a_authority_plan_final_coverage_invalid")
    assessment_counts = Counter(str(plan["assessment"]) for plan in plans)
    final_material = {
        "schema": "legalbot.v111.phase2a.advisory-authority-plans-448.v1",
        "status": (
            "ADVISORY_AUTHORITY_PLANS_COMPLETE_OWNER_DECISIONS_REQUIRED"
            if not held_rows
            else "ADVISORY_AUTHORITY_PLANS_COMPLETE_WITH_HELD_BATCHES_DEBUG_REQUIRED"
        ),
        "source_intent_content_sha256": intent["intent_content_sha256"],
        "source_remaining_content_sha256": remaining_sha256,
        "reviewer_execution_mode": REVIEWER_EXECUTION_MODE,
        "model_independent_reviewer": False,
        "independent_reranker_completed_separately": True,
        "issue_count": EXPECTED_ISSUE_COUNT,
        "planned_issue_count": len(plans),
        "held_issue_count": len(held_rows),
        "held_row_ids": held_rows,
        "assessment_counts": dict(sorted(assessment_counts.items())),
        "plans": plans,
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
    _write_exclusive(final_path, _pretty_json(final))
    outcome = (
        f"ADVISORY AUTHORITY PLANS: {len(plans)}/448 PLANNED; "
        f"{len(held_rows)} HELD. OWNER DECISIONS STILL REQUIRED. "
        "PHASE 2B AND DEVELOPMENT 30 NOT AUTHORIZED.\n"
    )
    _write_exclusive(output_root / "OUTCOME.txt", outcome.encode())
    names = ["INTENT.json", "ADVISORY-AUTHORITY-PLANS-448.json", "OUTCOME.txt"]
    sums = "".join(f"{_sha256_file(output_root / name)}  {name}\n" for name in names)
    _write_exclusive(output_root / "SHA256SUMS.txt", sums.encode())
    return final


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--remaining", type=Path, default=DEFAULT_REMAINING)
    parser.add_argument("--original", type=Path, default=DEFAULT_ORIGINAL)
    parser.add_argument("--deep", type=Path, default=DEFAULT_DEEP)
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASES)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--model-url", default="http://127.0.0.1:8779")
    parser.add_argument("--timeout-seconds", type=float, default=240.0)
    parser.add_argument("--resume", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = _arguments()
    invoke = _http_invoker(args.model_url, args.timeout_seconds)
    result = build_authority_plans(
        remaining_path=args.remaining,
        original_path=args.original,
        deep_path=args.deep,
        cases_path=args.cases,
        output_root=args.output_root,
        invoke=invoke,
        started_at=datetime.now(UTC),
        resume=args.resume,
    )
    print(
        json.dumps(
            {
                "output_root": str(args.output_root),
                "status": result["status"],
                "planned_issue_count": result["planned_issue_count"],
                "held_issue_count": result["held_issue_count"],
                "assessment_counts": result["assessment_counts"],
                "artifact_content_sha256": result["artifact_content_sha256"],
                "phase2b_authorized": result["phase2b_authorized"],
                "development30_authorized": result["development30_authorized"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
