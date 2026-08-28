#!/usr/bin/env python3
"""Run a singleton nine-row context-bound safety canary before all 448 rows."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts import verify_v111_phase2a_exact_semantic_spans_advisory as verifier  # noqa: E402

OWNER_REVIEW_ROOT = PROJECT_ROOT / "data" / "evaluations" / "phase2a-owner-review"
DEFAULT_OUTPUT = OWNER_REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-25-r66c-context-bound-safety-canary"
PRIOR_HELD_CANARY = OWNER_REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-25-r61b-exact-span-canary"
PRIOR_FAILURE_FINGERPRINT = "a708c6b984ba6a3ad005588095da70c8e689785c5eee71475c81c5f457e855fd"
PRIOR_GAP_CANARY = OWNER_REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-25-r61c-exact-span-canary"
PRIOR_REPEAT_GAP_CANARY = OWNER_REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-25-r61d-exact-span-canary"
REPEAT_GAP_DEBUG_ROOT = OWNER_REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-25-r61e-repeat-gap-debug"
QUOTE_COPY_DEBUG_ROOT = (
    OWNER_REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-25-r63-singleton-exact-semantic-span-advisory"
)
SOURCE_IDENTITY_DEBUG_ROOT = (
    OWNER_REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-25-r65-span-id-exact-semantic-span-advisory"
)
PRIOR_CANDIDATE_BOUND_CANARY = (
    OWNER_REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-25-r66-candidate-bound-span-id-canary"
)
PRIOR_CONTEXT_BOUND_CANARY = (
    OWNER_REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-25-r66b-context-bound-span-id-canary"
)
PRIOR_GAP_ROW_ID = "live30-q02:issue-03"
CANARY_ROW_IDS = (
    "live30-q01:issue-01",
    "live30-q01:issue-03",
    "live30-q01:issue-04",
    "live30-q01:issue-05",
    "live30-q02:issue-01",
    "live30-q02:issue-02",
    "live30-q02:issue-03",
    "live30-q02:issue-08",
    "live30-q04:issue-02",
)
REQUIRED_GAP_ROW_IDS = frozenset(
    {
        "live30-q01:issue-01",
        "live30-q01:issue-04",
        "live30-q04:issue-02",
    }
)
REQUIRED_SUPPORTED_ROW_IDS = frozenset(
    {
        "live30-q01:issue-03",
        "live30-q02:issue-01",
        "live30-q02:issue-02",
        "live30-q02:issue-03",
        "live30-q02:issue-08",
    }
)
ADVISORY_FLEX_ROW_IDS = (
    frozenset(CANARY_ROW_IDS) - REQUIRED_GAP_ROW_IDS - REQUIRED_SUPPORTED_ROW_IDS
)


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


def run_canary(*, output_root: Path, model_url: str, timeout_seconds: float) -> dict[str, Any]:
    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_exact_span_canary_output_already_exists")
    issue_rows, _issues, cases, held, candidate_sources, hashes = verifier._load_inputs(
        locators_path=verifier.DEFAULT_LOCATORS,
        plans_path=verifier.DEFAULT_PLANS,
        remaining_path=verifier.DEFAULT_REMAINING,
        cases_path=verifier.DEFAULT_CASES,
        candidate_manifest_path=verifier.DEFAULT_CANDIDATE_MANIFEST,
    )
    if held:
        raise ValueError("phase2a_exact_span_canary_upstream_held_rows")
    locator_artifact = verifier._load_object(verifier.DEFAULT_LOCATORS)
    locators_by_id = {str(record["row_id"]): record for record in locator_artifact["records"]}
    issue_by_id = {str(row["item_id"]): row for row in issue_rows}
    if any(row_id not in issue_by_id for row_id in CANARY_ROW_IDS):
        raise ValueError("phase2a_exact_span_canary_row_missing")
    review_rows = [
        verifier._review_row(issue_by_id[row_id], locators_by_id[row_id], candidate_sources)
        for row_id in CANARY_ROW_IDS
    ]
    if any(row is None for row in review_rows):
        raise ValueError("phase2a_exact_span_canary_evidence_missing")
    typed_rows = [row for row in review_rows if isinstance(row, dict)]
    batches = [[row] for row in typed_rows]
    oversized = [
        row
        for row in typed_rows
        if verifier._prompt_characters(
            verifier._build_input(
                batch_ordinal=1,
                rows=[row],
                case=cases[str(row["row_id"]).split(":", 1)[0]],
                repair_error_code="repair_reserve",
            )
        )
        > verifier.MAX_PROMPT_CHARACTERS
    ]
    if (
        oversized
        or len(batches) != len(CANARY_ROW_IDS)
        or any(len(batch) != 1 for batch in batches)
    ):
        raise ValueError("phase2a_exact_span_canary_context_boundary_invalid")
    if any(
        not path.is_dir()
        for path in (
            PRIOR_HELD_CANARY,
            PRIOR_GAP_CANARY,
            PRIOR_REPEAT_GAP_CANARY,
            REPEAT_GAP_DEBUG_ROOT,
            QUOTE_COPY_DEBUG_ROOT,
            SOURCE_IDENTITY_DEBUG_ROOT,
            PRIOR_CANDIDATE_BOUND_CANARY,
            PRIOR_CONTEXT_BOUND_CANARY,
        )
    ):
        raise ValueError("phase2a_exact_span_prior_debug_canary_missing")
    if verifier.MAX_REVIEW_EVIDENCE_CANDIDATES_PER_ROW != 1:
        raise ValueError("phase2a_exact_span_top_one_projection_not_active")
    if verifier.BATCH_SIZE != 1 or verifier.OUTPUT_SCHEMA != "p2a-exact-span-id-v2":
        raise ValueError("phase2a_exact_span_id_singleton_contract_not_active")

    invoke, runtime_identity = verifier._http_invoker(model_url, timeout_seconds)
    runtime_sha256 = str(runtime_identity["runtime_identity_sha256"])
    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_exact_span_canary_output_mode_invalid")
    checkpoints = output_root / "checkpoints"
    diagnostics = output_root / "diagnostics"
    checkpoints.mkdir(mode=0o700)
    diagnostics.mkdir(mode=0o700)

    intent_material = {
        "schema": "legalbot.v111.phase2a.exact-span-canary-intent.v4",
        "status": "ADVISORY_CANARY_ONLY_NO_OWNER_DECISIONS",
        "started_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "row_ids": list(CANARY_ROW_IDS),
        "batch_count": len(batches),
        "execution_plan": (
            "ONE_ROW_PER_BATCH_WITH_TOP_ONE_WHOLE_CHUNK_EXHAUSTIVELY_"
            "PARTITIONED_AND_MODEL_SELECTING_PRECOMPUTED_EXACT_SPAN_ID"
        ),
        "prior_held_canary_path": str(PRIOR_HELD_CANARY.relative_to(PROJECT_ROOT)),
        "prior_failure_fingerprint": PRIOR_FAILURE_FINGERPRINT,
        "prior_failed_multirow_batch_will_not_be_retried": True,
        "prior_gap_canary_path": str(PRIOR_GAP_CANARY.relative_to(PROJECT_ROOT)),
        "prior_repeat_gap_canary_path": str(PRIOR_REPEAT_GAP_CANARY.relative_to(PROJECT_ROOT)),
        "repeat_gap_debug_report_path": str(
            (REPEAT_GAP_DEBUG_ROOT / "DEBUG-REPORT.json").relative_to(PROJECT_ROOT)
        ),
        "repeat_gap_debug_report_file_sha256": _sha256_file(
            REPEAT_GAP_DEBUG_ROOT / "DEBUG-REPORT.json"
        ),
        "quote_copy_debug_report_path": str(
            (QUOTE_COPY_DEBUG_ROOT / "DEBUG-STOP-REPORT.json").relative_to(PROJECT_ROOT)
        ),
        "quote_copy_debug_report_file_sha256": _sha256_file(
            QUOTE_COPY_DEBUG_ROOT / "DEBUG-STOP-REPORT.json"
        ),
        "source_identity_debug_report_path": str(
            (SOURCE_IDENTITY_DEBUG_ROOT / "DEBUG-STOP-REPORT.json").relative_to(PROJECT_ROOT)
        ),
        "source_identity_debug_report_file_sha256": _sha256_file(
            SOURCE_IDENTITY_DEBUG_ROOT / "DEBUG-STOP-REPORT.json"
        ),
        "exact_candidate_membership_audit_path": str(
            (SOURCE_IDENTITY_DEBUG_ROOT / "EXACT-CANDIDATE-MEMBERSHIP-AUDIT.json").relative_to(
                PROJECT_ROOT
            )
        ),
        "exact_candidate_membership_audit_file_sha256": _sha256_file(
            SOURCE_IDENTITY_DEBUG_ROOT / "EXACT-CANDIDATE-MEMBERSHIP-AUDIT.json"
        ),
        "prior_candidate_bound_canary_path": str(
            PRIOR_CANDIDATE_BOUND_CANARY.relative_to(PROJECT_ROOT)
        ),
        "prior_candidate_bound_canary_file_sha256": _sha256_file(
            PRIOR_CANDIDATE_BOUND_CANARY / "CANARY-EXACT-SPANS-9.json"
        ),
        "prior_candidate_bound_debug_correction_path": str(
            (PRIOR_CANDIDATE_BOUND_CANARY / "DEBUG-CORRECTION.json").relative_to(PROJECT_ROOT)
        ),
        "prior_candidate_bound_debug_correction_file_sha256": _sha256_file(
            PRIOR_CANDIDATE_BOUND_CANARY / "DEBUG-CORRECTION.json"
        ),
        "prior_context_bound_canary_path": str(
            PRIOR_CONTEXT_BOUND_CANARY.relative_to(PROJECT_ROOT)
        ),
        "prior_context_bound_canary_file_sha256": _sha256_file(
            PRIOR_CONTEXT_BOUND_CANARY / "CANARY-EXACT-SPANS-9.json"
        ),
        "prior_context_bound_acceptance_correction_path": str(
            (PRIOR_CONTEXT_BOUND_CANARY / "DEBUG-ACCEPTANCE-CORRECTION.json").relative_to(
                PROJECT_ROOT
            )
        ),
        "prior_context_bound_acceptance_correction_file_sha256": _sha256_file(
            PRIOR_CONTEXT_BOUND_CANARY / "DEBUG-ACCEPTANCE-CORRECTION.json"
        ),
        "prior_gap_row_id": PRIOR_GAP_ROW_ID,
        "prior_gap_root_cause": (
            "ADVISORY_FALSE_NEGATIVE_WHILE_LESS_APPLICABLE_SECOND_CANDIDATE_WAS_VISIBLE"
        ),
        "maximum_evidence_candidates_per_row": (verifier.MAX_REVIEW_EVIDENCE_CANDIDATES_PER_ROW),
        "maximum_rows_per_batch": verifier.BATCH_SIZE,
        "model_output_schema": verifier.OUTPUT_SCHEMA,
        "model_selects_precomputed_exact_span_id": True,
        "model_reproduces_quote_text": False,
        "source_locator_content_sha256": hashes["locators"],
        "source_plans_content_sha256": hashes["plans"],
        "source_remaining_content_sha256": hashes["remaining"],
        "source_candidate_manifest_sha256": hashes["candidate_manifest"],
        "source_candidate_manifest_file_sha256": hashes["candidate_manifest_file"],
        "sealed_candidate_source_count": len(candidate_sources),
        "sealed_candidate_sources_only": True,
        "noncandidate_and_unadmitted_sources_excluded": True,
        "scenario_text_supplied_for_issue_scope_disambiguation": True,
        "scenario_answering_and_fact_application_forbidden": True,
        "scenario_aware_prior_selection_preferred_over_issue_label_only_recovery": True,
        "prompt_sha256": _sha256((verifier.SYSTEM_PROMPT + "\n").encode()),
        "verifier_code_file_sha256": _sha256_file(Path(verifier.__file__).resolve()),
        "evidence_validator_code_file_sha256": _sha256_file(verifier.EVIDENCE_VALIDATOR_CODE_PATH),
        "runtime_identity": runtime_identity,
        "runtime_identity_sha256": runtime_sha256,
        "model_independent_reviewer": False,
        "raw_model_output_persisted": False,
        "hidden_reasoning_persisted": False,
        "owner_decisions_applied": False,
        "source_admission_authorized": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    intent = {**intent_material, "intent_content_sha256": _sealed(intent_material)}
    _write_exclusive(output_root / "INTENT.json", _pretty_json(intent))

    results: list[dict[str, Any]] = []
    for ordinal, batch in enumerate(batches, start=1):
        case_id = str(batch[0]["row_id"]).split(":", 1)[0]
        results.append(
            verifier._review_batch(
                ordinal=ordinal,
                rows=batch,
                case=cases[case_id],
                invoke=invoke,
                checkpoints_root=checkpoints,
                diagnostics_root=diagnostics,
                runtime_identity_sha256=runtime_sha256,
            )
        )
    held_batches = [
        result
        for result in results
        if result.get("schema") == "legalbot.v111.phase2a.exact-span-held-batch.v1"
    ]
    findings = [
        finding
        for result in results
        for finding in result.get("findings", [])
        if isinstance(finding, dict)
    ]
    supported = {
        str(finding["row_id"])
        for finding in findings
        if finding.get("assessment")
        in {"DIRECT_EXACT_SPAN_ADVISORY", "PARTIAL_EXACT_SPAN_ADVISORY"}
    }
    gaps = {
        str(finding["row_id"])
        for finding in findings
        if finding.get("assessment") == "MATERIAL_GAP_ADVISORY"
    }
    canary_passed = (
        not held_batches
        and {str(finding["row_id"]) for finding in findings} == set(CANARY_ROW_IDS)
        and supported | gaps == set(CANARY_ROW_IDS)
        and supported >= REQUIRED_SUPPORTED_ROW_IDS
        and gaps >= REQUIRED_GAP_ROW_IDS
        and not REQUIRED_SUPPORTED_ROW_IDS & gaps
        and not REQUIRED_GAP_ROW_IDS & supported
    )
    material = {
        "schema": "legalbot.v111.phase2a.exact-span-canary-9.v4",
        "status": (
            "CANARY_PASSED_REPLACEMENT_ALL_448_ADVISORY_MAY_START"
            if canary_passed
            else "CANARY_STOPPED_FURTHER_DEBUG_REQUIRED"
        ),
        "source_intent_content_sha256": intent["intent_content_sha256"],
        "row_count": len(CANARY_ROW_IDS),
        "supported_row_count": len(supported),
        "supported_row_ids": sorted(supported),
        "required_supported_row_ids": sorted(REQUIRED_SUPPORTED_ROW_IDS),
        "required_gap_row_ids": sorted(REQUIRED_GAP_ROW_IDS),
        "advisory_flex_row_ids": sorted(ADVISORY_FLEX_ROW_IDS),
        "observed_gap_row_ids": sorted(gaps),
        "unexpected_row_ids": sorted(set(CANARY_ROW_IDS) - supported - gaps),
        "held_batch_count": len(held_batches),
        "findings": findings,
        "replacement_all_448_advisory_may_start": canary_passed,
        "owner_decisions_applied": False,
        "technical_qualification_assigned": False,
        "source_admission_authorized": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    artifact = {**material, "artifact_content_sha256": _sealed(material)}
    artifact_raw = _pretty_json(artifact)
    outcome_raw = (
        b"CANDIDATE-BOUND EXACT-SPAN CANARY PASSED; REPLACEMENT ALL-448 ADVISORY MAY START.\n"
        if canary_passed
        else b"CANDIDATE-BOUND EXACT-SPAN CANARY STOPPED; FURTHER ROOT-CAUSE DEBUG REQUIRED.\n"
    )
    _write_exclusive(output_root / "CANARY-EXACT-SPANS-9.json", artifact_raw)
    _write_exclusive(output_root / "OUTCOME.txt", outcome_raw)
    names = ["INTENT.json", "CANARY-EXACT-SPANS-9.json", "OUTCOME.txt"]
    sums = "".join(f"{_sha256_file(output_root / name)}  {name}\n" for name in names).encode()
    _write_exclusive(output_root / "SHA256SUMS.txt", sums)
    return artifact


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--model-url", default="http://127.0.0.1:8779")
    parser.add_argument("--timeout-seconds", type=float, default=300.0)
    args = parser.parse_args()
    result = run_canary(
        output_root=args.output_root.resolve(),
        model_url=args.model_url,
        timeout_seconds=args.timeout_seconds,
    )
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
