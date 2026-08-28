#!/usr/bin/env python3
"""Run one debugged repair attempt for the five rows held by r67."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import time
from collections import Counter
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.quality.evidence import extract_material_facts  # noqa: E402
from scripts import verify_v111_phase2a_exact_semantic_spans_advisory as verifier  # noqa: E402

OWNER_REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
R67_ROOT = (
    OWNER_REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-25-r67-candidate-bound-exact-semantic-span-advisory"
)
R67_ARTIFACT_PATH = R67_ROOT / "ADVISORY-EXACT-SEMANTIC-SPANS-448.json"
DEFAULT_OUTPUT = (
    OWNER_REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-25-r68-debugged-held-row-repair"
)
EXPECTED_R67_ARTIFACT_CONTENT_SHA256 = (
    "b2f300a89895faa46a91c393a9171202b056ef4ae52942083bfb00f42f0ad732"
)
HELD_ROW_IDS = (
    "live30-q01:issue-07",
    "live30-q16:issue-06",
    "live30-q30:issue-09",
    "live60-q51:issue-02",
    "live60-q51:issue-03",
)
EXPECTED_ERROR_HISTORY = {
    "live30-q01:issue-07": (
        "structured_output_proposition_too_long",
        "structured_output_non_atomic_proposition",
    ),
    "live30-q16:issue-06": (
        "structured_output_proposition_too_long",
        "structured_output_proposition_too_long",
    ),
    "live30-q30:issue-09": (
        "structured_output_proposition_too_long",
        "structured_output_proposition_too_long",
    ),
    "live60-q51:issue-02": (
        "structured_output_unsupported_material_fact",
        "structured_output_unsupported_material_fact",
    ),
    "live60-q51:issue-03": (
        "structured_output_unsupported_material_fact",
        "structured_output_unsupported_material_fact",
    ),
}
STRICT_PROPOSITION_CHARACTERS = 180
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

SYSTEM_PROMPT = """/no_think
Debugged advisory exact-span repair only. This is one new-plan attempt for a row already held after two rejected outputs. Use the supplied scenario only to disambiguate the issue; do not answer or apply the scenario. Inspect only the supplied exact sealed-candidate span options. Return GAP unless one span directly supports one short atomic rule for the contextualized issue. A DIRECT or PARTIAL proposition must be one independent clause, one sentence, and at most 180 characters. Do not join separate rules with and/or. Use only material-fact identities listed in allowed_material_fact_identities; do not add a source-title year, date, amount, percentage, duration, or provision identifier merely because it appears in metadata. If a necessary fact is not allowed, return GAP. Never invent a chunk or span ID. Do not decide owner approval, legal materiality, source admission, qualification, or any gate. Output compact JSON only with exactly: {"schema":"p2a-exact-span-id-v2","case_id":"<supplied case id>","rows":[{"row_id":"<supplied row id>","assessment":"DIRECT|PARTIAL|GAP","proposition":"<one atomic proposition of at most 180 characters or empty>","support":{"chunk_id":"<supplied chunk id>","span_id":"<supplied span id>"}|null}]}. Include the supplied row exactly once."""


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


def _sealed(value: Any) -> str:
    return _sha256(_canonical_json(value))


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_held_repair_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_held_repair_input_must_be_object")
    return value


def _verify_seal(value: Mapping[str, Any], field: str, code: str) -> str:
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if not _SHA256.fullmatch(supplied) or supplied != _sealed(material):
        raise ValueError(code)
    return supplied


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


def _diagnostic_history() -> tuple[dict[str, list[dict[str, Any]]], list[str]]:
    by_row: dict[str, list[dict[str, Any]]] = {row_id: [] for row_id in HELD_ROW_IDS}
    file_sha256s: list[str] = []
    for path in sorted((R67_ROOT / "diagnostics").glob("*.json")):
        value = _load_object(path)
        _verify_seal(
            value,
            "diagnostic_content_sha256",
            "phase2a_held_repair_prior_diagnostic_invalid",
        )
        row_ids = value.get("row_ids")
        if isinstance(row_ids, list) and len(row_ids) == 1 and row_ids[0] in by_row:
            by_row[str(row_ids[0])].append(value)
            file_sha256s.append(_sha256_file(path))
    for row_id, records in by_row.items():
        records.sort(key=lambda row: int(row["attempt"]))
        if (
            len(records) != 2
            or tuple(str(row["error_code"]) for row in records)
            != EXPECTED_ERROR_HISTORY[row_id]
            or [int(row["attempt"]) for row in records] != [1, 2]
        ):
            raise ValueError("phase2a_held_repair_prior_history_changed")
    return by_row, file_sha256s


def _held_checkpoints() -> dict[str, dict[str, Any]]:
    held: dict[str, dict[str, Any]] = {}
    for path in sorted((R67_ROOT / "checkpoints").glob("*.json")):
        value = _load_object(path)
        if value.get("schema") != "legalbot.v111.phase2a.exact-span-held-batch.v1":
            continue
        _verify_seal(
            value,
            "held_content_sha256",
            "phase2a_held_repair_prior_checkpoint_invalid",
        )
        row_ids = value.get("row_ids")
        if not isinstance(row_ids, list) or len(row_ids) != 1:
            raise ValueError("phase2a_held_repair_prior_checkpoint_scope_invalid")
        held[str(row_ids[0])] = value
    if set(held) != set(HELD_ROW_IDS):
        raise ValueError("phase2a_held_repair_prior_held_scope_changed")
    return held


def _allowed_facts(row: Mapping[str, Any]) -> list[str]:
    identities: set[str] = set()
    for source in row["evidence_candidates"]:
        for chunk in source["chunks"]:
            locator = str(chunk.get("locator") or "")
            for span in chunk["exact_span_options"]:
                for fact in extract_material_facts(
                    f"{span['exact_text']}\n{locator}"
                ):
                    identities.add(fact.identity)
    return sorted(identities)


def _repair_input(
    *, row: Mapping[str, Any], case: Mapping[str, Any], history: list[dict[str, Any]]
) -> dict[str, Any]:
    value = verifier._build_input(
        batch_ordinal=1,
        rows=[row],
        case=case,
        repair_error_code=None,
    )
    value.update(
        {
            "schema": "legalbot.v111.phase2a.debugged-held-repair-input.v1",
            "debugged_third_attempt_under_new_execution_plan": True,
            "prior_attempt_count": 2,
            "prior_error_codes": [str(item["error_code"]) for item in history],
            "prior_failure_fingerprints": [
                str(item["failure_fingerprint"]) for item in history
            ],
            "strict_proposition_character_limit": STRICT_PROPOSITION_CHARACTERS,
            "allowed_material_fact_identities": _allowed_facts(row),
            "return_gap_when_direct_atomic_support_is_unavailable": True,
            "no_additional_repair_attempt_under_this_plan": True,
        }
    )
    return value


def _envelope(row_input: Mapping[str, Any]) -> tuple[dict[str, Any], str]:
    request_id = str(uuid4())
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": json.dumps(
                row_input, ensure_ascii=False, separators=(",", ":")
            ),
        },
    ]
    return (
        {
            "request_id": request_id,
            "mode": "semantic_verify",
            "payload": {**dict(row_input), "messages": messages},
            "messages": messages,
            "max_tokens": verifier.MAX_OUTPUT_TOKENS,
            "temperature": 0.0,
            "top_p": 1.0,
            "seed": 0,
            "stop": [],
        },
        request_id,
    )


def _error_code(exc: BaseException) -> str:
    if isinstance(exc, verifier.SemanticValidationError):
        return exc.code
    return verifier._error_code(exc)


def repair_held_rows(
    *, output_root: Path, model_url: str, timeout_seconds: float
) -> dict[str, Any]:
    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_held_repair_output_already_exists")
    r67 = _load_object(R67_ARTIFACT_PATH)
    r67_digest = _verify_seal(
        r67,
        "artifact_content_sha256",
        "phase2a_held_repair_r67_artifact_invalid",
    )
    if (
        r67_digest != EXPECTED_R67_ARTIFACT_CONTENT_SHA256
        or r67.get("held_batch_count") != len(HELD_ROW_IDS)
        or r67.get("owner_decisions_applied") is not False
        or r67.get("candidate_mutated") is not False
    ):
        raise ValueError("phase2a_held_repair_r67_boundary_invalid")
    histories, diagnostic_file_sha256s = _diagnostic_history()
    prior_held = _held_checkpoints()
    rows, _, cases, upstream_held, candidate_sources, hashes = verifier._load_inputs(
        locators_path=verifier.DEFAULT_LOCATORS,
        plans_path=verifier.DEFAULT_PLANS,
        remaining_path=verifier.DEFAULT_REMAINING,
        cases_path=verifier.DEFAULT_CASES,
        candidate_manifest_path=verifier.DEFAULT_CANDIDATE_MANIFEST,
    )
    if upstream_held:
        raise ValueError("phase2a_held_repair_upstream_planner_held")
    records = {
        str(item["row_id"]): item
        for item in verifier._load_object(verifier.DEFAULT_LOCATORS)["records"]
    }
    issues = {str(item["item_id"]): item for item in rows}
    projected: dict[str, dict[str, Any]] = {}
    for row_id in HELD_ROW_IDS:
        value = verifier._review_row(
            issues[row_id], records[row_id], candidate_sources
        )
        if value is None:
            raise ValueError("phase2a_held_repair_projection_missing")
        projected[row_id] = value

    invoke, runtime_identity = verifier._http_invoker(model_url, timeout_seconds)
    runtime_sha256 = _verify_seal(
        runtime_identity,
        "runtime_identity_sha256",
        "phase2a_held_repair_runtime_identity_invalid",
    )
    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_held_repair_output_mode_invalid")
    checkpoints = output_root / "checkpoints"
    diagnostics = output_root / "diagnostics"
    checkpoints.mkdir(mode=0o700)
    diagnostics.mkdir(mode=0o700)

    intent_material = {
        "schema": "legalbot.v111.phase2a.debugged-held-repair-intent.v1",
        "status": "ONE_DEBUGGED_NEW_PLAN_ATTEMPT_PER_HELD_ROW",
        "started_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "source_r67_artifact_content_sha256": r67_digest,
        "source_r67_artifact_file_sha256": _sha256_file(R67_ARTIFACT_PATH),
        "source_r67_held_content_sha256s": [
            str(prior_held[row_id]["held_content_sha256"])
            for row_id in HELD_ROW_IDS
        ],
        "source_r67_diagnostic_file_sha256s": diagnostic_file_sha256s,
        "source_locator_content_sha256": hashes["locators"],
        "source_remaining_content_sha256": hashes["remaining"],
        "source_candidate_manifest_sha256": hashes["candidate_manifest"],
        "source_candidate_manifest_file_sha256": hashes[
            "candidate_manifest_file"
        ],
        "held_row_ids": list(HELD_ROW_IDS),
        "prior_error_history": {
            row_id: list(EXPECTED_ERROR_HISTORY[row_id]) for row_id in HELD_ROW_IDS
        },
        "root_cause_classes": {
            "proposition_shape": [
                "live30-q01:issue-07",
                "live30-q16:issue-06",
                "live30-q30:issue-09",
            ],
            "unsupported_source_metadata_fact": [
                "live60-q51:issue-02",
                "live60-q51:issue-03",
            ],
        },
        "new_execution_plan": {
            "maximum_proposition_characters": STRICT_PROPOSITION_CHARACTERS,
            "one_independent_clause": True,
            "allowed_material_fact_identities_explicit": True,
            "source_title_year_not_evidence_unless_in_exact_span": True,
            "gap_required_if_direct_atomic_support_unavailable": True,
            "attempts_per_row": 1,
        },
        "prompt_sha256": _sha256((SYSTEM_PROMPT + "\n").encode()),
        "repair_code_file_sha256": _sha256_file(Path(__file__).resolve()),
        "verifier_code_file_sha256": _sha256_file(verifier.VERIFIER_CODE_PATH),
        "evidence_validator_code_file_sha256": _sha256_file(
            verifier.EVIDENCE_VALIDATOR_CODE_PATH
        ),
        "runtime_identity": runtime_identity,
        "runtime_identity_sha256": runtime_sha256,
        "model_independent_reviewer": False,
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
    _write_exclusive(output_root / "INTENT.json", _pretty_json(intent))

    findings: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    for ordinal, row_id in enumerate(HELD_ROW_IDS, start=1):
        row = projected[row_id]
        case = cases[row_id.split(":", 1)[0]]
        row_input = _repair_input(
            row=row,
            case=case,
            history=histories[row_id],
        )
        input_sha256 = _sealed(row_input)
        envelope, request_id = _envelope(row_input)
        started = time.perf_counter()
        body: dict[str, Any] | None = None
        try:
            body = invoke(envelope)
            normalized, metrics = verifier._validate_model_response(
                body=body,
                row_input=row_input,
                request_id=request_id,
            )
            if len(normalized) != 1:
                raise verifier.SemanticValidationError(
                    "held_repair_finding_count_invalid"
                )
            proposition = normalized[0].get("atomic_proposition")
            if isinstance(proposition, str) and len(proposition) > STRICT_PROPOSITION_CHARACTERS:
                raise verifier.SemanticValidationError(
                    "held_repair_proposition_over_180",
                    diagnostics={
                        "proposition_character_count": len(proposition),
                        "maximum_proposition_characters": (
                            STRICT_PROPOSITION_CHARACTERS
                        ),
                    },
                )
        except Exception as exc:
            error = _error_code(exc)
            failure_material = {
                "schema": "legalbot.v111.phase2a.debugged-held-repair-failure.v1",
                "ordinal": ordinal,
                "row_id": row_id,
                "attempt_under_new_plan": 1,
                "total_attempt_ordinal_for_row": 3,
                "input_content_sha256": input_sha256,
                "request_id": request_id,
                "error_code": error,
                "validation_diagnostics": (
                    dict(exc.diagnostics)
                    if isinstance(exc, verifier.SemanticValidationError)
                    else {}
                ),
                "failure_fingerprint": _sealed(
                    {
                        "schema": (
                            "legalbot.v111.phase2a.debugged-held-repair-"
                            "failure-fingerprint.v1"
                        ),
                        "row_id": row_id,
                        "prompt_sha256": intent_material["prompt_sha256"],
                        "runtime_identity_sha256": runtime_sha256,
                        "error_code": error,
                    }
                ),
                "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
                "response_received": body is not None,
                "raw_output_sha256": (
                    _sha256(str(body.get("raw_text") or "").encode())
                    if body
                    else None
                ),
                "raw_output_persisted": False,
                "hidden_reasoning_persisted": False,
                "no_further_attempt_authorized_under_this_plan": True,
                "owner_decision_assigned": False,
                "technical_qualification_assigned": False,
                "source_admission_authorized": False,
                "candidate_mutated": False,
                "phase2b_authorized": False,
                "development30_authorized": False,
            }
            failure = {
                **failure_material,
                "diagnostic_content_sha256": _sealed(failure_material),
            }
            failures.append(failure)
            _write_exclusive(
                diagnostics / f"{ordinal:03d}-{row_id.replace(':', '-')}.json",
                _pretty_json(failure),
            )
            findings.append(
                {
                    "row_id": row_id,
                    "assessment": "HELD_AFTER_DEBUGGED_THIRD_ATTEMPT",
                    "atomic_proposition": None,
                    "exact_span_binding": None,
                    "gap_reason": error.upper(),
                    "owner_outcome": None,
                    "owner_decision_required": True,
                    "technical_qualification_assigned": False,
                }
            )
            continue
        checkpoint_material = {
            "schema": "legalbot.v111.phase2a.debugged-held-repair-checkpoint.v1",
            "ordinal": ordinal,
            "row_id": row_id,
            "attempt_under_new_plan": 1,
            "total_attempt_ordinal_for_row": 3,
            "input_content_sha256": input_sha256,
            "prompt_sha256": intent_material["prompt_sha256"],
            "runtime_identity_sha256": runtime_sha256,
            "finding": normalized[0],
            "model_metrics": metrics,
            "raw_model_output_persisted": False,
            "hidden_reasoning_persisted": False,
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
            checkpoints / f"{ordinal:03d}-{row_id.replace(':', '-')}.json",
            _pretty_json(checkpoint),
        )
        findings.append(normalized[0])

    counts = Counter(str(item["assessment"]) for item in findings)
    material = {
        "schema": "legalbot.v111.phase2a.debugged-held-repairs-5.v1",
        "status": (
            "ALL_FIVE_HELD_ROWS_RESOLVED_UNDER_DEBUGGED_PLAN"
            if not failures
            else "DEBUGGED_REPAIR_COMPLETE_WITH_REMAINING_HELD_ROWS"
        ),
        "source_intent_content_sha256": intent["intent_content_sha256"],
        "source_r67_artifact_content_sha256": r67_digest,
        "row_count": len(HELD_ROW_IDS),
        "assessment_counts": dict(sorted(counts.items())),
        "failure_count": len(failures),
        "failure_diagnostic_content_sha256s": [
            str(item["diagnostic_content_sha256"]) for item in failures
        ],
        "findings": findings,
        "supersedes_only_r67_held_rows": list(HELD_ROW_IDS),
        "raw_model_output_persisted": False,
        "hidden_reasoning_persisted": False,
        "owner_decisions_applied": False,
        "technical_qualification_assigned": False,
        "source_admission_authorized": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    artifact = {**material, "artifact_content_sha256": _sealed(material)}
    _write_exclusive(output_root / "DEBUGGED-HELD-REPAIRS-5.json", _pretty_json(artifact))
    _write_exclusive(
        output_root / "OUTCOME.txt",
        (
            f"{artifact['status']}. ALL OWNER DECISIONS REMAIN REQUIRED.\n"
        ).encode(),
    )
    names = ["INTENT.json", "DEBUGGED-HELD-REPAIRS-5.json", "OUTCOME.txt"]
    sums = "".join(
        f"{_sha256_file(output_root / name)}  {name}\n" for name in names
    ).encode()
    _write_exclusive(output_root / "SHA256SUMS.txt", sums)
    return artifact


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--model-url", default="http://127.0.0.1:8779")
    parser.add_argument("--timeout-seconds", type=float, default=300.0)
    args = parser.parse_args()
    result = repair_held_rows(
        output_root=args.output_root.resolve(),
        model_url=args.model_url,
        timeout_seconds=args.timeout_seconds,
    )
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
