#!/usr/bin/env python3
"""Verify post-r94 recovery candidates against exact bound source spans.

The pinned advisory model may select only a precomputed chunk/span ID.  The
shared deterministic validator then enforces atomicity, exact byte binding,
material-fact support and substantive relatedness.  The reviewer is recorded
honestly as the same model adapter family used for drafting, not as an
independent model reviewer.

This pass cannot decide owner outcomes, qualify rows, admit sources, mutate a
candidate or authorize a later gate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from collections import Counter
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
for root in (PROJECT_ROOT, BACKEND_ROOT):
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

from scripts import verify_v111_phase2a_exact_semantic_spans_advisory as base  # noqa: E402

REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
DEFAULT_RECOVERY = (
    REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-26-r98d-candidate-recovery"
    / "CANDIDATE-RECOVERY-361.json"
)
DEFAULT_CASES = (
    PROJECT_ROOT / "benchmarks/evaluation/live-evaluation-60-v1/cases.jsonl"
)
DEFAULT_OUTPUT_ROOT = (
    REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-26-r99b-exact-span-advisory"
)
EXPECTED_CASES_FILE_SHA256 = (
    "78a738afd920ff840dcedeb0fd3fd5ca81035f499a0630d351d49e7c6cd3777a"
)
EXPECTED_CANDIDATE_MANIFEST_DIGEST = (
    "d2c1434fd5fc44d4f2f7e4f7629293f646bb28ed9b8466687feb6c470ea53ac0"
)
EXPECTED_ISSUE_REGISTRY_DIGEST = (
    "d813a1fdc1b9b6f2d6c67b0ac2c113af696343cc8c619355c74ee8654beca475"
)
EXPECTED_ROW_COUNT = 361
MAX_EVIDENCE_CANDIDATES_PER_ROW = 3
# Keep the shared verifier's proven singleton contract.  Multi-row character
# packing is not a safe proxy for the pinned tokenizer budget: the stopped r99
# run demonstrated inputs below MAX_PROMPT_CHARACTERS that nevertheless exceeded
# the 8,192-token runtime context once the reserved output was included.
MAX_BATCH_SIZE = 1
KNOWN_RECOVERY_STATUSES = frozenset(
    {
        "EXACT_CANDIDATE_CHUNKS_READY_FOR_SPAN_VERIFICATION",
        "NO_EXACT_CANDIDATE_HIT_OFFICIAL_SOURCE_RESEARCH_REQUIRED",
    }
)


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode()


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


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


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_post_r94_span_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_post_r94_span_input_must_be_object")
    return value


def _verify_seal(value: Mapping[str, Any], field: str, code: str) -> str:
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if supplied != _sealed(material):
        raise ValueError(code)
    return supplied


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


def _load_recovery(path: Path) -> tuple[list[dict[str, Any]], str]:
    value = _load_object(path)
    digest = _verify_seal(
        value,
        "artifact_content_sha256",
        "phase2a_post_r94_span_recovery_seal_invalid",
    )
    rows = value.get("rows")
    query_strategy = value.get("deterministic_query_strategy")
    if (
        value.get("schema")
        != "legalbot.v111.phase2a.post-r94-candidate-recovery-361.v2"
        or value.get("row_count") != EXPECTED_ROW_COUNT
        or value.get("candidate_manifest_sha256") != EXPECTED_CANDIDATE_MANIFEST_DIGEST
        or value.get("source_issue_registry_content_sha256")
        != EXPECTED_ISSUE_REGISTRY_DIGEST
        or value.get("deterministic_retrieval_precedes_advisory_ai") is not True
        or value.get("advisory_planner_required") is not False
        or value.get("issue_labels_and_legal_domains_registry_bound") is not True
        or not isinstance(query_strategy, dict)
        or query_strategy.get("sealed_registry_planned_authority_routes_used")
        is not True
        or query_strategy.get("route_diverse_candidate_selection") is not True
        or value.get("threshold_applied") is not False
        or value.get("old_candidate_fallback") is not False
        or value.get("network_answering") is not False
        or value.get("answer_model_invoked") is not False
        or value.get("owner_decisions_applied") is not False
        or value.get("technical_qualification_assigned") is not False
        or value.get("source_admission_authorized") is not False
        or value.get("candidate_mutated") is not False
        or value.get("phase2b_authorized") is not False
        or value.get("development30_authorized") is not False
        or not isinstance(rows, list)
        or len(rows) != EXPECTED_ROW_COUNT
        or any(not isinstance(row, dict) for row in rows)
    ):
        raise ValueError("phase2a_post_r94_span_recovery_boundary_invalid")
    observed: set[str] = set()
    for row in rows:
        _verify_seal(
            row,
            "checkpoint_content_sha256",
            "phase2a_post_r94_span_recovery_row_seal_invalid",
        )
        row_id = str(row.get("row_id") or "")
        if not row_id or row_id in observed:
            raise ValueError("phase2a_post_r94_span_recovery_rows_invalid")
        observed.add(row_id)
        status = str(row.get("status") or "")
        candidates = row.get("candidates")
        if status not in KNOWN_RECOVERY_STATUSES:
            raise ValueError("phase2a_post_r94_span_recovery_status_invalid")
        if (
            not isinstance(candidates, list)
            or row.get("schema")
            != "legalbot.v111.phase2a.post-r94-candidate-recovery-row.v2"
            or row.get("classification") != "DETERMINISTIC_ISSUE_QUERY"
            or row.get("advisory_atomic_proposition") is not None
            or not isinstance(row.get("planned_authority_ids"), list)
            or not isinstance(row.get("planned_source_identities_in_candidate"), list)
            or not isinstance(row.get("planned_authority_ids_outside_candidate"), list)
            or not str(row.get("issue_label") or "").strip()
            or row.get("source_issue_registry_content_sha256")
            != EXPECTED_ISSUE_REGISTRY_DIGEST
            or len(str(row.get("source_issue_registry_row_content_sha256") or ""))
            != 64
            or row.get("technical_qualification_assigned") is not False
            or row.get("owner_decision_required") is not True
        ):
            raise ValueError("phase2a_post_r94_span_recovery_row_boundary_invalid")
        if (status == "EXACT_CANDIDATE_CHUNKS_READY_FOR_SPAN_VERIFICATION") != bool(
            candidates
        ):
            raise ValueError("phase2a_post_r94_span_recovery_status_candidates_invalid")
        seen_chunks: set[str] = set()
        planned_source_identities = {
            str(value)
            for value in row["planned_source_identities_in_candidate"]
            if str(value)
        }
        if len(planned_source_identities) != len(
            row["planned_source_identities_in_candidate"]
        ):
            raise ValueError("phase2a_post_r94_span_planned_identities_invalid")
        observed_planned_source_identities: set[str] = set()
        for expected_rank, candidate in enumerate(candidates, start=1):
            if not isinstance(candidate, dict):
                raise ValueError("phase2a_post_r94_span_candidate_invalid")
            material = dict(candidate)
            supplied = str(material.pop("candidate_content_sha256", ""))
            chunk_id = str(candidate.get("chunk_id") or "")
            if (
                supplied != _sealed(material)
                or candidate.get("rank") != expected_rank
                or not chunk_id
                or chunk_id in seen_chunks
                or not str(candidate.get("authority_identity_id") or "")
                or not str(candidate.get("source_identity") or "")
                or candidate.get("selection_basis")
                not in {
                    "REGISTRY_PLANNED_IDENTITY_DIVERSITY",
                    "GLOBAL_RERANK_FILL",
                }
                or candidate.get("already_in_exact_sealed_candidate") is not True
                or candidate.get("candidate_manifest_source_bound") is not True
                or candidate.get("content_sha256")
                != _sha256(str(candidate.get("text") or "").encode())
            ):
                raise ValueError("phase2a_post_r94_span_candidate_invalid")
            if candidate.get("selection_basis") == "REGISTRY_PLANNED_IDENTITY_DIVERSITY":
                source_identity = str(candidate["source_identity"])
                if source_identity not in planned_source_identities:
                    raise ValueError(
                        "phase2a_post_r94_span_planned_candidate_identity_invalid"
                    )
                observed_planned_source_identities.add(source_identity)
            seen_chunks.add(chunk_id)
        if observed_planned_source_identities != planned_source_identities:
            raise ValueError("phase2a_post_r94_span_planned_candidate_coverage_invalid")
    return [dict(row) for row in rows], digest


def _load_cases(path: Path) -> dict[str, dict[str, Any]]:
    if _sha256_file(path) != EXPECTED_CASES_FILE_SHA256:
        raise ValueError("phase2a_post_r94_span_cases_identity_invalid")
    cases: dict[str, dict[str, Any]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        if not isinstance(item, dict):
            raise ValueError("phase2a_post_r94_span_case_invalid")
        case_id = str(item.get("case_id") or "")
        if not case_id or case_id in cases:
            raise ValueError("phase2a_post_r94_span_case_registry_invalid")
        cases[case_id] = item
    if len(cases) != 60:
        raise ValueError("phase2a_post_r94_span_case_count_invalid")
    return cases


def _static_finding(row: Mapping[str, Any]) -> dict[str, Any] | None:
    status = str(row.get("status") or "")
    row_id = str(row["row_id"])
    if status not in KNOWN_RECOVERY_STATUSES:
        raise ValueError("phase2a_post_r94_span_recovery_status_invalid")
    if status == "EXACT_CANDIDATE_CHUNKS_READY_FOR_SPAN_VERIFICATION":
        return None
    assessment = "MATERIAL_GAP_ADVISORY"
    reason = "NO_EXACT_SEALED_CANDIDATE_HIT"
    return {
        "row_id": row_id,
        "assessment": assessment,
        "atomic_proposition": None,
        "exact_span_binding": None,
        "gap_reason": reason,
        "owner_outcome": None,
        "owner_decision_required": True,
        "technical_qualification_assigned": False,
    }


def _project_review_row(row: Mapping[str, Any]) -> dict[str, Any]:
    candidates = row.get("candidates")
    if not isinstance(candidates, list) or not candidates:
        raise ValueError("phase2a_post_r94_span_review_candidates_missing")
    selected = candidates[:MAX_EVIDENCE_CANDIDATES_PER_ROW]
    omitted = [
        {
            "rank": candidate.get("rank"),
            "chunk_id": candidate.get("chunk_id"),
            "candidate_content_sha256": candidate.get("candidate_content_sha256"),
        }
        for candidate in candidates[MAX_EVIDENCE_CANDIDATES_PER_ROW:]
    ]
    evidence_candidates: list[dict[str, Any]] = []
    for candidate in selected:
        chunk = base._exact_span_partition(
            {
                "chunk_id": candidate["chunk_id"],
                "text": candidate["text"],
                "text_sha256": candidate["content_sha256"],
                "locator": candidate.get("locator"),
                "heading_path": "",
            }
        )
        evidence_candidates.append(
            {
                "authority_identity_id": candidate["authority_identity_id"],
                "source_version_id": candidate["source_version_id"],
                "title": candidate["title"],
                "canonical_url": candidate["canonical_url"],
                "as_of_date": candidate.get("as_of_date"),
                "currentness_status": candidate.get("currentness_status"),
                "candidate_source_metadata": {
                    "already_in_sealed_candidate": True,
                    "currentness_verified": candidate.get("currentness_verified"),
                    "later_treatment_review_required": (
                        candidate.get("currentness_verified") is not True
                    ),
                    "reranker_score": candidate.get("reranker_score"),
                    "rrf_score": candidate.get("rrf_score"),
                    "selection_basis": candidate.get("selection_basis"),
                    "route_evidence": candidate.get("route_evidence"),
                    "candidate_content_sha256": candidate.get(
                        "candidate_content_sha256"
                    ),
                },
                "selection_origin": "POST_R94_SEALED_CANDIDATE_HYBRID_RECOVERY",
                "projection_integrity": {
                    "selected_candidate_rank": candidate["rank"],
                    "selected_candidate_content_sha256": candidate[
                        "candidate_content_sha256"
                    ],
                    "source_text_fully_partitioned": True,
                    "silent_text_truncation": False,
                    "omitted_candidate_count": len(omitted),
                    "omitted_candidate_identities_sha256": _sealed(omitted),
                },
                "chunks": [chunk],
            }
        )
    return {
        "row_id": row["row_id"],
        "issue_label": row["issue_label"],
        "legal_domain": "post-r94-candidate-recovery",
        "advisory_planned_proposition": row.get("advisory_atomic_proposition"),
        "evidence_candidates": evidence_candidates,
    }


def _load_checkpoint(path: Path) -> dict[str, Any]:
    return base._load_checkpoint(path)


def verify_spans(
    *,
    recovery_path: Path,
    cases_path: Path,
    output_root: Path,
    invoke: base.Invoke,
    runtime_identity: Mapping[str, Any],
    started_at: datetime,
    resume: bool = False,
) -> dict[str, Any]:
    if started_at.tzinfo is None:
        raise ValueError("phase2a_post_r94_span_started_at_naive")
    runtime_digest = base._verify_seal(
        runtime_identity,
        "runtime_identity_sha256",
        "phase2a_post_r94_span_runtime_identity_invalid",
    )
    if (
        runtime_identity.get("model_independent_reviewer") is not False
        or runtime_identity.get("model_id") != base.EXPECTED_MODEL_ID
        or runtime_identity.get("expected_model_version") != base.EXPECTED_MODEL_VERSION
    ):
        raise ValueError("phase2a_post_r94_span_runtime_boundary_invalid")
    rows, recovery_digest = _load_recovery(recovery_path)
    cases = _load_cases(cases_path)
    static: dict[str, dict[str, Any]] = {}
    reviewable: list[dict[str, Any]] = []
    for row in rows:
        finding = _static_finding(row)
        if finding is None:
            reviewable.append(_project_review_row(row))
        else:
            static[str(row["row_id"])] = finding

    original_batch_size = base.BATCH_SIZE
    base.BATCH_SIZE = MAX_BATCH_SIZE
    try:
        batches, oversized = base._pack_batches(reviewable, cases)
    finally:
        base.BATCH_SIZE = original_batch_size
    for row in oversized:
        static[str(row["row_id"])] = {
            "row_id": row["row_id"],
            "assessment": "HELD_CONTEXT_BUDGET_NO_TRUNCATION",
            "atomic_proposition": None,
            "exact_span_binding": None,
            "gap_reason": "FULL_EXACT_CHUNK_INPUT_EXCEEDS_CONTEXT_BUDGET",
            "owner_outcome": None,
            "owner_decision_required": True,
            "technical_qualification_assigned": False,
        }

    input_identity = {
        "recovery_content_sha256": recovery_digest,
        "recovery_file_sha256": _sha256_file(recovery_path),
        "cases_file_sha256": EXPECTED_CASES_FILE_SHA256,
        "prompt_sha256": _sha256((base.SYSTEM_PROMPT + "\n").encode()),
        "shared_verifier_code_file_sha256": _sha256_file(Path(base.__file__).resolve()),
        "wrapper_code_file_sha256": _sha256_file(Path(__file__).resolve()),
        "evidence_validator_code_file_sha256": _sha256_file(
            base.EVIDENCE_VALIDATOR_CODE_PATH
        ),
        "runtime_identity_sha256": runtime_digest,
        "maximum_evidence_candidates_per_row": MAX_EVIDENCE_CANDIDATES_PER_ROW,
        "maximum_batch_size": MAX_BATCH_SIZE,
    }
    input_identity_sha256 = _sealed(input_identity)
    intent_path = output_root / "INTENT.json"
    if output_root.exists() or output_root.is_symlink():
        if not resume or output_root.is_symlink() or not output_root.is_dir():
            raise ValueError("phase2a_post_r94_span_output_already_exists")
        intent = _load_object(intent_path)
        _verify_seal(
            intent,
            "intent_content_sha256",
            "phase2a_post_r94_span_intent_invalid",
        )
        if intent.get("input_identity_sha256") != input_identity_sha256:
            raise ValueError("phase2a_post_r94_span_resume_identity_mismatch")
    else:
        output_root.mkdir(parents=True, mode=0o700)
        if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
            raise ValueError("phase2a_post_r94_span_output_mode_invalid")
        intent_material = {
            "schema": "legalbot.v111.phase2a.post-r94-exact-span-intent.v1",
            "status": "ADVISORY_EXACT_SPAN_VERIFICATION_ONLY",
            "started_at": started_at.astimezone(UTC).isoformat(timespec="seconds"),
            "input_identity": input_identity,
            "input_identity_sha256": input_identity_sha256,
            "row_count": EXPECTED_ROW_COUNT,
            "reviewable_row_count": len(reviewable) - len(oversized),
            "static_or_held_row_count": len(static),
            "batch_count": len(batches),
            "reviewer_execution_mode": base.REVIEWER_EXECUTION_MODE,
            "model_independent_reviewer": False,
            "owner_decisions_applied": False,
            "technical_qualification_assigned": False,
            "source_admission_authorized": False,
            "candidate_mutated": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        intent = {**intent_material, "intent_content_sha256": _sealed(intent_material)}
        _write_exclusive(intent_path, _pretty_json(intent))
    checkpoints = output_root / "checkpoints"
    diagnostics = output_root / "diagnostics"
    checkpoints.mkdir(mode=0o700, exist_ok=True)
    diagnostics.mkdir(mode=0o700, exist_ok=True)
    final_path = output_root / "EXACT-SPAN-ADVISORY-361.json"
    if final_path.exists() or final_path.is_symlink():
        raise ValueError("phase2a_post_r94_span_already_finalized")

    checkpoint_results: list[dict[str, Any]] = []
    for ordinal, batch in enumerate(batches, start=1):
        checkpoint_path = checkpoints / base._checkpoint_name(ordinal, batch)
        if checkpoint_path.exists():
            checkpoint_results.append(_load_checkpoint(checkpoint_path))
            continue
        case_id = str(batch[0]["row_id"]).split(":", 1)[0]
        checkpoint_results.append(
            base._review_batch(
                ordinal=ordinal,
                rows=batch,
                case=cases[case_id],
                invoke=invoke,
                checkpoints_root=checkpoints,
                diagnostics_root=diagnostics,
                runtime_identity_sha256=runtime_digest,
            )
        )

    findings_by_id = dict(static)
    held_batch_count = 0
    for checkpoint in checkpoint_results:
        if checkpoint.get("schema") == "legalbot.v111.phase2a.exact-span-held-batch.v1":
            held_batch_count += 1
            for row_id in checkpoint["row_ids"]:
                findings_by_id[str(row_id)] = {
                    "row_id": row_id,
                    "assessment": "HELD_FOR_DEBUG_BEFORE_ANY_THIRD_ATTEMPT",
                    "atomic_proposition": None,
                    "exact_span_binding": None,
                    "gap_reason": "SAME_OR_REPEATED_EXACT_SPAN_VALIDATION_FAILURE",
                    "held_content_sha256": checkpoint["held_content_sha256"],
                    "owner_outcome": None,
                    "owner_decision_required": True,
                    "technical_qualification_assigned": False,
                }
            continue
        for finding in checkpoint["findings"]:
            findings_by_id[str(finding["row_id"])] = dict(finding)
    order = [str(row["row_id"]) for row in rows]
    if set(findings_by_id) != set(order):
        raise ValueError("phase2a_post_r94_span_final_row_set_invalid")
    findings = [findings_by_id[row_id] for row_id in order]
    counts = Counter(str(finding["assessment"]) for finding in findings)
    positive = [
        finding
        for finding in findings
        if str(finding["assessment"]).startswith(("DIRECT_", "PARTIAL_"))
    ]
    currentness_pending = sum(
        1
        for finding in positive
        if finding.get("source_currentness", {}).get(
            "separate_currentness_or_later_treatment_review_still_required"
        )
        is True
    )
    final_material = {
        "schema": "legalbot.v111.phase2a.post-r94-exact-span-advisory-361.v1",
        "status": (
            "ADVISORY_EXACT_SPANS_COMPLETE_OWNER_DECISIONS_REQUIRED"
            if held_batch_count == 0
            else "ADVISORY_EXACT_SPANS_HAVE_HELD_BATCHES_DEBUG_REQUIRED"
        ),
        "source_intent_content_sha256": intent["intent_content_sha256"],
        "source_recovery_content_sha256": recovery_digest,
        "runtime_identity_sha256": runtime_digest,
        "reviewer_execution_mode": base.REVIEWER_EXECUTION_MODE,
        "model_independent_reviewer": False,
        "same_model_adapter_family_as_drafting": True,
        "row_count": len(findings),
        "assessment_counts": dict(sorted(counts.items())),
        "positive_binding_count": len(positive),
        "positive_binding_currentness_or_later_treatment_pending_count": currentness_pending,
        "held_batch_count": held_batch_count,
        "findings": findings,
        "material_fact_validation_enabled": True,
        "atomicity_validation_enabled": True,
        "unrelated_evidence_validation_enabled": True,
        "exact_span_id_binding_enabled": True,
        "silent_truncation": False,
        "owner_decisions_applied": False,
        "technical_qualification_assigned": False,
        "source_admission_authorized": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    final = {**final_material, "artifact_content_sha256": _sealed(final_material)}
    _write_exclusive(final_path, _pretty_json(final))
    _write_exclusive(
        output_root / "OUTCOME.txt",
        b"PHASE 2A POST-R94 EXACT-SPAN ADVISORY COMPLETE - OWNER DECISIONS REQUIRED; NO PHASE 2B\n",
    )
    files = sorted(
        path
        for path in output_root.iterdir()
        if path.is_file() and path.name != "SHA256SUMS.txt"
    )
    _write_exclusive(
        output_root / "SHA256SUMS.txt",
        "".join(f"{_sha256_file(path)}  {path.name}\n" for path in files).encode(),
    )
    return final


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--recovery", type=Path, default=DEFAULT_RECOVERY)
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASES)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--model-url", default="http://127.0.0.1:8779")
    parser.add_argument("--timeout-seconds", type=float, default=240.0)
    parser.add_argument("--resume", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = _arguments()
    invoke, runtime_identity = base._http_invoker(
        args.model_url, args.timeout_seconds
    )
    result = verify_spans(
        recovery_path=args.recovery.resolve(strict=True),
        cases_path=args.cases.resolve(strict=True),
        output_root=args.output_root.resolve(),
        invoke=invoke,
        runtime_identity=runtime_identity,
        started_at=datetime.now(UTC),
        resume=bool(args.resume),
    )
    print(
        json.dumps(
            {
                "output_root": str(args.output_root),
                "artifact_content_sha256": result["artifact_content_sha256"],
                "row_count": result["row_count"],
                "assessment_counts": result["assessment_counts"],
                "held_batch_count": result["held_batch_count"],
                "phase2b_authorized": result["phase2b_authorized"],
                "development30_authorized": result["development30_authorized"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
