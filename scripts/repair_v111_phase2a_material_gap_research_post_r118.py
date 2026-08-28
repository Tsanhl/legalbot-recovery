#!/usr/bin/env python3
"""Continue only unresolved r118 rows under a timeout-debugged singleton plan.

The exact failed r118 run is immutable.  This append-only successor verifies
its intent, crosswalk, 27 checkpoints, 11 diagnostics, and terminal failure;
reuses its 25 accepted plans plus r117's 271 accepted plans; and invokes only
the remaining 68 rows.  Each request is a singleton with a 512-token output
cap and an explicit issue-focus instruction.  Runtime failures stop the whole
path after one attempt.  No owner decision, source admission, candidate
mutation, Phase 2B, or Development 30 authorization can be assigned here.
"""

from __future__ import annotations

import argparse
import json
import stat
import sys
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
for root in (PROJECT_ROOT, BACKEND_ROOT):
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

from scripts import plan_v111_phase2a_material_gap_research as planner  # noqa: E402
from scripts import (  # noqa: E402
    repair_v111_phase2a_material_gap_research_held_rows as r118,
)

REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
R118_ROOT = REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-27-r118-held-gap-singleton-repair"
DEFAULT_OUTPUT = (
    REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-27-r119-post-r118-timeout-debug-singleton-repair"
)
EXPECTED_R118_INTENT_SHA256 = "7df05462de3183fc7f1db610302bd76c60fb19350fe6d69999a7c214b3ab1d3d"
EXPECTED_R118_CROSSWALK_SHA256 = "d72fffdcb669f280cdd11d5499c1ca7d2a3a5ddd7160587c9d6a1ef2d489c31b"
EXPECTED_R118_FAILURE_CONTENT_SHA256 = (
    "11007baa1a62df7914694442f301535c1da2349a3f7f119294fa993a27b5b420"
)
EXPECTED_R118_FAILURE_FINGERPRINT = (
    "be1c295cd5310b0072be67cb9df4fcc5f3ef3e32e1855b61f115e3dc6b82356f"
)
EXPECTED_R118_RUNTIME_FINGERPRINT = (
    "5082f561c363f11dc179227da79ba04950922204d6e0c105d90f033df5eb449d"
)
EXPECTED_R118_CHECKPOINT_COUNT = 27
EXPECTED_R118_DIAGNOSTIC_COUNT = 11
EXPECTED_R118_ACCEPTED_PLAN_COUNT = 25
EXPECTED_REUSED_PLAN_COUNT = 296
EXPECTED_REPAIR_ROW_COUNT = 68
R119_MAX_OUTPUT_TOKENS = 512
TIMEOUT_ROW_ID = "live30-q25:issue-07"
PRIOR_CONTENT_HELD_ROW_ID = "live30-q10:issue-07"


@dataclass(frozen=True, slots=True)
class PostR118Source:
    r117: r118.SourceState
    r118_intent: Mapping[str, Any]
    r118_failure: Mapping[str, Any]
    r118_accepted_plans: tuple[Mapping[str, Any], ...]
    remaining_row_ids: tuple[str, ...]
    crosswalk_records: tuple[Mapping[str, Any], ...]
    r118_checkpoint_sha256s: tuple[str, ...]
    r118_file_sha256s: Mapping[str, str]
    timeout_diagnostic: Mapping[str, Any]


def _load_post_r118_source(root: Path = R118_ROOT) -> PostR118Source:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("phase2a_r119_r118_root_invalid")
    source = r118._load_source_state()
    intent = planner._load_object(root / "INTENT.json")
    intent_digest = planner._verify_seal(
        intent,
        "intent_content_sha256",
        "phase2a_r119_r118_intent_seal_invalid",
    )
    crosswalk = planner._load_object(root / "SOURCE-HELD-CROSSWALK.json")
    crosswalk_digest = planner._verify_seal(
        crosswalk,
        "artifact_content_sha256",
        "phase2a_r119_r118_crosswalk_seal_invalid",
    )
    failure = planner._load_object(root / "FAILURE.json")
    failure_digest = planner._verify_seal(
        failure,
        "failure_content_sha256",
        "phase2a_r119_r118_failure_seal_invalid",
    )
    expected_crosswalk = r118._crosswalk(source)
    if (
        intent_digest != EXPECTED_R118_INTENT_SHA256
        or crosswalk_digest != EXPECTED_R118_CROSSWALK_SHA256
        or failure_digest != EXPECTED_R118_FAILURE_CONTENT_SHA256
        or crosswalk != expected_crosswalk
        or intent.get("source_r117_artifact_content_sha256") != r118.EXPECTED_R117_CONTENT_SHA256
        or intent.get("source_crosswalk_content_sha256") != crosswalk_digest
        or intent.get("repair_row_ids") != list(source.held_row_ids)
        or intent.get("maximum_rows_per_batch") != 1
        or intent.get("maximum_attempts_per_row") != 2
        or intent.get("accepted_r117_rows_will_not_be_reinvoked") is not True
        or failure.get("failure_fingerprint") != EXPECTED_R118_FAILURE_FINGERPRINT
        or failure.get("error_code") != "phase2a_r118_runtime_failure_debug_required"
        or failure.get("completed_checkpoint_count") != EXPECTED_R118_CHECKPOINT_COUNT
        or failure.get("candidate_mutated") is not False
        or failure.get("phase2b_authorized") is not False
        or failure.get("development30_authorized") is not False
    ):
        raise ValueError("phase2a_r119_r118_boundary_invalid")
    if planner._sha256_file(Path(r118.__file__).resolve()) != intent.get("repair_code_file_sha256"):
        raise ValueError("phase2a_r119_r118_repair_code_changed")

    checkpoint_paths = sorted((root / "checkpoints").glob("*.json"))
    if len(checkpoint_paths) != EXPECTED_R118_CHECKPOINT_COUNT:
        raise ValueError("phase2a_r119_r118_checkpoint_count_invalid")
    accepted_plans: list[Mapping[str, Any]] = []
    held_by_id: dict[str, Mapping[str, Any]] = {}
    histories: dict[str, list[Mapping[str, Any]]] = {}
    checkpoint_sha256s: list[str] = []
    observed_diagnostics: set[Path] = set()
    timeout_diagnostic: Mapping[str, Any] | None = None
    for ordinal, path in enumerate(checkpoint_paths, start=1):
        checkpoint = planner._load_checkpoint(path)
        expected_row_id = source.held_row_ids[ordinal - 1]
        if checkpoint.get("batch_ordinal") != ordinal or checkpoint.get("row_ids") != [
            expected_row_id
        ]:
            raise ValueError("phase2a_r119_r118_checkpoint_identity_invalid")
        diagnostics = r118._diagnostics_for_checkpoint(
            source_root=root,
            checkpoint_path=path,
            checkpoint=checkpoint,
        )
        diagnostic_paths = set((root / "diagnostics").glob(f"{path.stem}-a*.json"))
        observed_diagnostics.update(diagnostic_paths)
        histories[expected_row_id] = diagnostics
        if checkpoint.get("schema") == "legalbot.v111.phase2a.gap-plan-checkpoint.v1":
            if (
                len(checkpoint.get("plans", [])) != 1
                or checkpoint["plans"][0].get("row_id") != expected_row_id
                or len(diagnostics) != int(checkpoint.get("attempt_count") or 0) - 1
            ):
                raise ValueError("phase2a_r119_r118_accepted_checkpoint_invalid")
            accepted_plans.append(dict(checkpoint["plans"][0]))
            checkpoint_sha256s.append(str(checkpoint["checkpoint_content_sha256"]))
        else:
            held_by_id[expected_row_id] = checkpoint
            checkpoint_sha256s.append(str(checkpoint["held_content_sha256"]))
            if expected_row_id == TIMEOUT_ROW_ID:
                if len(diagnostics) != 1:
                    raise ValueError("phase2a_r119_r118_timeout_history_invalid")
                timeout_diagnostic = diagnostics[0]
    all_diagnostics = set((root / "diagnostics").glob("*.json"))
    if (
        observed_diagnostics != all_diagnostics
        or len(all_diagnostics) != EXPECTED_R118_DIAGNOSTIC_COUNT
        or len(accepted_plans) != EXPECTED_R118_ACCEPTED_PLAN_COUNT
        or set(held_by_id) != {PRIOR_CONTENT_HELD_ROW_ID, TIMEOUT_ROW_ID}
        or timeout_diagnostic is None
    ):
        raise ValueError("phase2a_r119_r118_projection_invalid")
    first_held = held_by_id[PRIOR_CONTENT_HELD_ROW_ID]
    timeout_held = held_by_id[TIMEOUT_ROW_ID]
    if (
        first_held.get("attempt_count") != 2
        or first_held.get("nonrepairable_runtime_failure") is not False
        or timeout_held.get("attempt_count") != 1
        or timeout_held.get("nonrepairable_runtime_failure") is not True
        or timeout_diagnostic.get("error_code") != "read_timeout"
        or timeout_diagnostic.get("failure_fingerprint") != EXPECTED_R118_RUNTIME_FINGERPRINT
        or timeout_diagnostic.get("response_received") is not False
        or float(timeout_diagnostic.get("elapsed_ms") or 0) < 240_000
    ):
        raise ValueError("phase2a_r119_r118_failure_classification_invalid")

    accepted_ids = {str(plan["row_id"]) for plan in accepted_plans}
    remaining_ids = tuple(row_id for row_id in source.held_row_ids if row_id not in accepted_ids)
    if (
        len(remaining_ids) != EXPECTED_REPAIR_ROW_COUNT
        or remaining_ids[0] != PRIOR_CONTENT_HELD_ROW_ID
        or TIMEOUT_ROW_ID not in remaining_ids
        or any(row_id in accepted_ids for row_id in remaining_ids)
    ):
        raise ValueError("phase2a_r119_remaining_scope_invalid")

    r117_crosswalk = {str(record["row_id"]): record for record in source.crosswalk_records}
    records: list[Mapping[str, Any]] = []
    for row_id in remaining_ids:
        if row_id == PRIOR_CONTENT_HELD_ROW_ID:
            r118_state = "HELD_AFTER_TWO_MALFORMED_OUTPUT_ATTEMPTS"
        elif row_id == TIMEOUT_ROW_ID:
            r118_state = "HELD_AFTER_ONE_READ_TIMEOUT_NO_RETRY"
        else:
            r118_state = "NOT_INVOKED_AFTER_RUNTIME_STOP"
        records.append(
            {
                "row_id": row_id,
                "source_r117": dict(r117_crosswalk[row_id]),
                "source_r118_state": r118_state,
                "source_r118_attempt_error_codes": [
                    str(item["error_code"]) for item in histories.get(row_id, [])
                ],
                "source_r118_failure_fingerprints": [
                    str(item["failure_fingerprint"]) for item in histories.get(row_id, [])
                ],
            }
        )
    top_files = {
        name: planner._sha256_file(root / name)
        for name in ("INTENT.json", "SOURCE-HELD-CROSSWALK.json", "FAILURE.json")
    }
    return PostR118Source(
        r117=source,
        r118_intent=intent,
        r118_failure=failure,
        r118_accepted_plans=tuple(accepted_plans),
        remaining_row_ids=remaining_ids,
        crosswalk_records=tuple(records),
        r118_checkpoint_sha256s=tuple(checkpoint_sha256s),
        r118_file_sha256s=top_files,
        timeout_diagnostic=timeout_diagnostic,
    )


def _debug_report(
    *,
    source: PostR118Source,
    timeout_input: Mapping[str, Any],
    timeout_case: Mapping[str, Any],
) -> dict[str, Any]:
    serialized = json.dumps(timeout_input, ensure_ascii=False, separators=(",", ":"))
    material = {
        "schema": "legalbot.v111.phase2a.r118-timeout-debug-report.v1",
        "source_r118_failure_content_sha256": EXPECTED_R118_FAILURE_CONTENT_SHA256,
        "source_r118_failure_fingerprint": EXPECTED_R118_FAILURE_FINGERPRINT,
        "source_runtime_failure_fingerprint": EXPECTED_R118_RUNTIME_FINGERPRINT,
        "affected_row_id": TIMEOUT_ROW_ID,
        "error_code": "read_timeout",
        "attempt_count": 1,
        "response_received": False,
        "elapsed_ms": source.timeout_diagnostic["elapsed_ms"],
        "prior_max_output_tokens": planner.MAX_OUTPUT_TOKENS,
        "prior_authority_count": len(timeout_input["authorities"]),
        "prior_input_json_characters": len(serialized),
        "prior_message_characters": len(planner.SYSTEM_PROMPT) + len(serialized),
        "scenario_characters": len(str(timeout_case["question"])),
        "root_cause_status": "BOUNDED_LATENCY_RESOURCE_ENVELOPE_EXCEEDED",
        "material_execution_plan_changes": [
            "DO_NOT_RESUME_OR_OVERWRITE_R118",
            "REUSE_25_SUCCESSFUL_R118_PLANS_WITHOUT_REINVOCATION",
            "INVOKE_ONLY_68_UNRESOLVED_OR_UNPROCESSED_ROWS",
            "REDUCE_SINGLETON_MAX_OUTPUT_TOKENS_FROM_900_TO_512",
            "ADD_EXPLICIT_FIRST_ATTEMPT_ISSUE_FOCUS_AND_LENGTH_INSTRUCTION",
            "BIND_FAILURE_FINGERPRINT_TO_THE_CHANGED_EXECUTION_PLAN",
            "STOP_THE_WHOLE_PATH_AFTER_ONE_RUNTIME_FAILURE",
        ],
        "owner_decisions_applied": False,
        "source_admission_authorized": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    return {**material, "artifact_content_sha256": planner._sealed(material)}


def _crosswalk(source: PostR118Source) -> dict[str, Any]:
    material = {
        "schema": "legalbot.v111.phase2a.post-r118-singleton-repair-crosswalk.v1",
        "source_r117_artifact_content_sha256": r118.EXPECTED_R117_CONTENT_SHA256,
        "source_r118_intent_content_sha256": EXPECTED_R118_INTENT_SHA256,
        "source_r118_failure_content_sha256": EXPECTED_R118_FAILURE_CONTENT_SHA256,
        "row_count": len(source.crosswalk_records),
        "records": [dict(record) for record in source.crosswalk_records],
        "reused_plan_count": EXPECTED_REUSED_PLAN_COUNT,
        "reused_rows_will_not_be_reinvoked": True,
        "maximum_output_tokens": R119_MAX_OUTPUT_TOKENS,
        "source_admission_authorized": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    return {**material, "artifact_content_sha256": planner._sealed(material)}


def _load_runtime_inputs(
    *, source: PostR118Source
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    dict[str, dict[str, Any]],
    Sequence[Any],
    frozenset[str],
    str,
    str,
    str,
]:
    gap_rows, triage_digest = planner._load_gap_rows(planner.DEFAULT_TRIAGE)
    cases = planner._load_cases(planner.DEFAULT_CASES)
    candidate, candidate_digest, candidate_file_digest = planner._candidate_authorities(
        planner.DEFAULT_CANDIDATE_MANIFEST
    )
    with planner._open_catalogue(planner.DEFAULT_CATALOGUE) as connection:
        sources = planner._select_sources(connection, planner.TARGET_CEILING_DATE)
    if (
        planner._sealed(planner._selected_source_registry(sources))
        != planner.EXPECTED_SELECTED_SOURCE_REGISTRY_SHA256
    ):
        raise ValueError("phase2a_r119_selected_source_registry_changed")
    by_id = {str(row["row_id"]): row for row in gap_rows}
    repair_rows = [dict(by_id[row_id]) for row_id in source.remaining_row_ids]
    reused = [
        *[dict(plan) for plan in source.r117.accepted_plans],
        *[dict(plan) for plan in source.r118_accepted_plans],
    ]
    if (
        len(reused) != EXPECTED_REUSED_PLAN_COUNT
        or len({str(plan["row_id"]) for plan in reused}) != EXPECTED_REUSED_PLAN_COUNT
        or {str(plan["row_id"]) for plan in reused} & set(source.remaining_row_ids)
        or set(by_id) != {str(plan["row_id"]) for plan in reused} | set(source.remaining_row_ids)
    ):
        raise ValueError("phase2a_r119_source_partition_invalid")
    return (
        repair_rows,
        reused,
        cases,
        sources,
        candidate,
        triage_digest,
        candidate_digest,
        candidate_file_digest,
    )


def _prepare_output(
    *,
    output_root: Path,
    resume: bool,
    intent_material: Mapping[str, Any],
    crosswalk: Mapping[str, Any],
    debug_report: Mapping[str, Any],
) -> dict[str, Any]:
    if output_root.exists() or output_root.is_symlink():
        if not resume or output_root.is_symlink() or not output_root.is_dir():
            raise ValueError("phase2a_r119_output_already_exists")
        if (output_root / "FAILURE.json").exists():
            raise ValueError("phase2a_r119_prior_failure_requires_new_revision")
        intent = planner._load_object(output_root / "INTENT.json")
        planner._verify_seal(intent, "intent_content_sha256", "phase2a_r119_intent_seal_invalid")
        observed_crosswalk = planner._load_object(output_root / "SOURCE-REMAINING-CROSSWALK.json")
        planner._verify_seal(
            observed_crosswalk,
            "artifact_content_sha256",
            "phase2a_r119_crosswalk_seal_invalid",
        )
        observed_debug = planner._load_object(output_root / "DEBUG-REPORT.json")
        planner._verify_seal(
            observed_debug,
            "artifact_content_sha256",
            "phase2a_r119_debug_report_seal_invalid",
        )
        stable = (
            "source_r117_artifact_content_sha256",
            "source_r118_intent_content_sha256",
            "source_r118_failure_content_sha256",
            "source_crosswalk_content_sha256",
            "source_debug_report_content_sha256",
            "repair_row_ids",
            "maximum_output_tokens",
            "prompt_sha256",
            "planner_code_file_sha256",
            "repair_code_file_sha256",
        )
        if (
            any(intent.get(field) != intent_material.get(field) for field in stable)
            or observed_crosswalk != crosswalk
            or observed_debug != debug_report
        ):
            raise ValueError("phase2a_r119_resume_identity_mismatch")
    else:
        output_root.mkdir(parents=True, mode=0o700)
        if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
            raise ValueError("phase2a_r119_output_mode_invalid")
        intent = {
            **dict(intent_material),
            "intent_content_sha256": planner._sealed(intent_material),
        }
        planner._write_exclusive(output_root / "INTENT.json", planner._pretty_json(intent))
        planner._write_exclusive(
            output_root / "SOURCE-REMAINING-CROSSWALK.json",
            planner._pretty_json(crosswalk),
        )
        planner._write_exclusive(
            output_root / "DEBUG-REPORT.json", planner._pretty_json(debug_report)
        )
    (output_root / "checkpoints").mkdir(mode=0o700, exist_ok=True)
    (output_root / "diagnostics").mkdir(mode=0o700, exist_ok=True)
    return intent


def _debug_context(*, row: Mapping[str, Any], record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema": "legalbot.v111.phase2a.post-r118-row-debug-context.v1",
        "source_r118_state": record["source_r118_state"],
        "prior_error_codes": [
            *record["source_r117"]["source_attempt_error_codes"],
            *record["source_r118_attempt_error_codes"],
        ],
        "changed_execution_instruction": (
            f"State only one central governing rule for the supplied issue label "
            f"'{row['issue_label']}'. Include a substantive term from that label, do "
            f"not substitute another scenario doctrine, and keep the proposition at "
            f"or below {planner.MAX_PROPOSITION_CHARACTERS} characters."
        ),
        "maximum_output_tokens": R119_MAX_OUTPUT_TOKENS,
    }


def build_repairs(
    *,
    output_root: Path,
    invoke: planner.Invoke,
    started_at: datetime,
    resume: bool,
) -> dict[str, Any]:
    if started_at.tzinfo is None:
        raise ValueError("phase2a_r119_started_at_naive")
    source = _load_post_r118_source()
    (
        repair_rows,
        reused_plans,
        cases,
        sources,
        candidate,
        triage_digest,
        candidate_digest,
        candidate_file_digest,
    ) = _load_runtime_inputs(source=source)
    timeout_row = next(row for row in repair_rows if row["row_id"] == TIMEOUT_ROW_ID)
    timeout_input = planner._build_input(
        ordinal=1,
        batch=[timeout_row],
        case=cases[str(timeout_row["case_id"])],
        sources=sources,
        candidate_authorities=candidate,
        repair_error=None,
    )
    debug_report = _debug_report(
        source=source,
        timeout_input=timeout_input,
        timeout_case=cases[str(timeout_row["case_id"])],
    )
    crosswalk = _crosswalk(source)
    intent_material = {
        "schema": "legalbot.v111.phase2a.post-r118-singleton-repair-intent.v1",
        "status": "ADVISORY_TIMEOUT_DEBUGGED_SINGLETON_REPAIR_ONLY",
        "started_at": started_at.astimezone(UTC).isoformat(timespec="seconds"),
        "source_r117_artifact_content_sha256": r118.EXPECTED_R117_CONTENT_SHA256,
        "source_r118_intent_content_sha256": EXPECTED_R118_INTENT_SHA256,
        "source_r118_failure_content_sha256": EXPECTED_R118_FAILURE_CONTENT_SHA256,
        "source_r118_file_sha256s": dict(source.r118_file_sha256s),
        "source_r118_checkpoint_content_sha256s": list(source.r118_checkpoint_sha256s),
        "source_crosswalk_content_sha256": crosswalk["artifact_content_sha256"],
        "source_debug_report_content_sha256": debug_report["artifact_content_sha256"],
        "source_triage_content_sha256": triage_digest,
        "source_candidate_manifest_sha256": candidate_digest,
        "source_candidate_manifest_file_sha256": candidate_file_digest,
        "source_selected_registry_sha256": (planner.EXPECTED_SELECTED_SOURCE_REGISTRY_SHA256),
        "reused_plan_count": len(reused_plans),
        "repair_row_count": len(repair_rows),
        "repair_row_ids": [str(row["row_id"]) for row in repair_rows],
        "batch_count": len(repair_rows),
        "maximum_rows_per_batch": 1,
        "maximum_attempts_per_row": 2,
        "maximum_runtime_transport_attempts_per_row": 1,
        "maximum_output_tokens": R119_MAX_OUTPUT_TOKENS,
        "accepted_prior_rows_will_not_be_reinvoked": True,
        "debug_required_before_any_third_attempt": True,
        "prompt_sha256": planner._sha256((planner.SYSTEM_PROMPT + "\n").encode()),
        "planner_code_file_sha256": planner._sha256_file(Path(planner.__file__)),
        "repair_code_file_sha256": planner._sha256_file(Path(__file__).resolve()),
        "model_id": planner.EXPECTED_MODEL_ID,
        "model_version": planner.EXPECTED_MODEL_VERSION,
        "reviewer_execution_mode": planner.REVIEWER_EXECUTION_MODE,
        "model_independent_reviewer": False,
        "owner_decisions_applied": False,
        "source_admission_authorized": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    intent = _prepare_output(
        output_root=output_root,
        resume=resume,
        intent_material=intent_material,
        crosswalk=crosswalk,
        debug_report=debug_report,
    )
    final_path = output_root / "MATERIAL-GAP-RESEARCH-PLANS-364.json"
    repair_path = output_root / "POST-R118-SINGLETON-REPAIR-RESULTS-68.json"
    if final_path.exists() or repair_path.exists():
        raise ValueError("phase2a_r119_already_finalized")

    records = {str(item["row_id"]): item for item in source.crosswalk_records}
    results: list[dict[str, Any]] = []
    for ordinal, row in enumerate(repair_rows, start=1):
        batch = [row]
        path = output_root / "checkpoints" / planner._checkpoint_name(ordinal, batch)
        if path.exists():
            if not resume:
                raise ValueError("phase2a_r119_checkpoint_exists_without_resume")
            checkpoint = planner._load_checkpoint(path)
            if (
                checkpoint.get("batch_ordinal") != ordinal
                or checkpoint.get("row_ids") != [row["row_id"]]
                or checkpoint.get("maximum_output_tokens") != R119_MAX_OUTPUT_TOKENS
            ):
                raise ValueError("phase2a_r119_checkpoint_identity_invalid")
        else:
            checkpoint = planner._review_batch(
                ordinal=ordinal,
                batch=batch,
                case=cases[str(row["case_id"])],
                sources=sources,
                candidate_authorities=candidate,
                invoke=invoke,
                checkpoints_root=output_root / "checkpoints",
                diagnostics_root=output_root / "diagnostics",
                max_output_tokens=R119_MAX_OUTPUT_TOKENS,
                debug_execution_context=_debug_context(row=row, record=records[str(row["row_id"])]),
            )
        results.append(checkpoint)
        if checkpoint.get("nonrepairable_runtime_failure") is True:
            raise RuntimeError("phase2a_r119_runtime_failure_debug_required")

    repaired: list[dict[str, Any]] = []
    remaining_held: list[str] = []
    checkpoint_digests: list[str] = []
    for result in results:
        if result.get("schema") == "legalbot.v111.phase2a.gap-plan-held-batch.v1":
            remaining_held.extend(str(row_id) for row_id in result["row_ids"])
            checkpoint_digests.append(str(result["held_content_sha256"]))
        else:
            repaired.extend(dict(plan) for plan in result["plans"])
            checkpoint_digests.append(str(result["checkpoint_content_sha256"]))
    if len(repaired) + len(remaining_held) != EXPECTED_REPAIR_ROW_COUNT:
        raise ValueError("phase2a_r119_repair_coverage_invalid")
    counts = Counter(str(plan["classification"]) for plan in repaired)
    repair_material = {
        "schema": "legalbot.v111.phase2a.post-r118-singleton-repair-results.v1",
        "status": "ALL_POST_R118_ROWS_PLANNED_UNDER_TIMEOUT_DEBUGGED_PLAN"
        if not remaining_held
        else "TIMEOUT_DEBUGGED_REPAIR_COMPLETE_WITH_REMAINING_HELD_ROWS",
        "source_intent_content_sha256": intent["intent_content_sha256"],
        "source_r118_failure_content_sha256": EXPECTED_R118_FAILURE_CONTENT_SHA256,
        "source_debug_report_content_sha256": debug_report["artifact_content_sha256"],
        "repair_scope_row_count": EXPECTED_REPAIR_ROW_COUNT,
        "repaired_plan_count": len(repaired),
        "remaining_held_row_count": len(remaining_held),
        "remaining_held_row_ids": remaining_held,
        "classification_counts": dict(sorted(counts.items())),
        "checkpoint_content_sha256s": checkpoint_digests,
        "plans": repaired,
        "reused_rows_reinvoked": False,
        "maximum_output_tokens": R119_MAX_OUTPUT_TOKENS,
        "owner_decisions_applied": False,
        "source_admission_authorized": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    repair_artifact = {
        **repair_material,
        "artifact_content_sha256": planner._sealed(repair_material),
    }
    planner._write_exclusive(repair_path, planner._pretty_json(repair_artifact))

    gap_rows, _ = planner._load_gap_rows(planner.DEFAULT_TRIAGE)
    merged = r118._merge_plans(
        gap_rows=gap_rows,
        source_plans=reused_plans,
        repair_plans=repaired,
    )
    if len(merged) + len(remaining_held) != planner.EXPECTED_GAP_COUNT:
        raise ValueError("phase2a_r119_merged_coverage_invalid")
    merged_counts = Counter(str(plan["classification"]) for plan in merged)
    selected_ids = {
        str(selection["authority_identity_id"])
        for plan in merged
        for selection in plan["selections"]
    }
    merged_material = {
        "schema": "legalbot.v111.phase2a.material-gap-research-plans-post-r118-repair.v1",
        "status": "ADVISORY_GAP_PLANS_COMPLETE_OWNER_DECISIONS_AND_EVIDENCE_REVIEW_REQUIRED"
        if not remaining_held
        else "ADVISORY_GAP_PLANS_HAVE_REMAINING_HELD_ROWS_DEBUG_REQUIRED",
        "source_r117_artifact_content_sha256": r118.EXPECTED_R117_CONTENT_SHA256,
        "source_r118_failure_content_sha256": EXPECTED_R118_FAILURE_CONTENT_SHA256,
        "source_repair_artifact_content_sha256": repair_artifact["artifact_content_sha256"],
        "source_triage_content_sha256": triage_digest,
        "reviewer_execution_mode": planner.REVIEWER_EXECUTION_MODE,
        "model_independent_reviewer": False,
        "row_count": planner.EXPECTED_GAP_COUNT,
        "reused_plan_count": len(reused_plans),
        "repaired_plan_count": len(repaired),
        "planned_row_count": len(merged),
        "remaining_held_row_count": len(remaining_held),
        "remaining_held_row_ids": remaining_held,
        "classification_counts": dict(sorted(merged_counts.items())),
        "selected_authority_count": len(selected_ids),
        "plans": merged,
        "proposition_evidence_verified": False,
        "owner_decisions_applied": False,
        "source_admission_authorized": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    final = {
        **merged_material,
        "artifact_content_sha256": planner._sealed(merged_material),
    }
    planner._write_exclusive(final_path, planner._pretty_json(final))
    outcome = (
        f"{repair_artifact['status']}. {len(merged)}/{planner.EXPECTED_GAP_COUNT} "
        "ROWS HAVE ADVISORY PLANS. OWNER DECISIONS AND EVIDENCE VERIFICATION "
        "REMAIN REQUIRED. PHASE 2B AND DEVELOPMENT 30 NOT AUTHORIZED.\n"
    )
    planner._write_exclusive(output_root / "OUTCOME.txt", outcome.encode())
    files = sorted(
        path for path in output_root.rglob("*") if path.is_file() and path.name != "SHA256SUMS.txt"
    )
    sums = "".join(
        f"{planner._sha256_file(path)}  {path.relative_to(output_root)}\n" for path in files
    )
    planner._write_exclusive(output_root / "SHA256SUMS.txt", sums.encode("utf-8"))
    return final


def _persist_failure(output_root: Path, exc: BaseException) -> None:
    try:
        if output_root.is_symlink():
            return
        if output_root.exists():
            if (
                not output_root.is_dir()
                or (output_root / "MATERIAL-GAP-RESEARCH-PLANS-364.json").exists()
            ):
                return
        else:
            output_root.mkdir(parents=True, mode=0o700)
        path = output_root / "FAILURE.json"
        if path.exists() or path.is_symlink():
            return
        error_code = planner._error_code(exc)
        fingerprint_material = {
            "affected_stage": "PHASE2A_POST_R118_SINGLETON_REPAIR",
            "error_code": error_code,
            "source_r118_failure_content_sha256": (EXPECTED_R118_FAILURE_CONTENT_SHA256),
            "planner_code_file_sha256": planner._sha256_file(Path(planner.__file__)),
            "repair_code_file_sha256": planner._sha256_file(Path(__file__).resolve()),
            "maximum_output_tokens": R119_MAX_OUTPUT_TOKENS,
        }
        material = {
            "schema": "legalbot.v111.phase2a.r119-top-level-failure.v1",
            "failure_fingerprint": planner._sealed(fingerprint_material),
            **fingerprint_material,
            "recorded_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "completed_checkpoint_count": len(list((output_root / "checkpoints").glob("*.json"))),
            "completed_work": "PRESERVED_BEFORE_EXCEPTION",
            "root_cause_status": "DEBUG_REQUIRED",
            "required_execution_plan_change": (
                "INSPECT_PERSISTED_DIAGNOSTICS_BEFORE_NEW_REVISION_OR_RETRY"
            ),
            "owner_decisions_applied": False,
            "source_admission_authorized": False,
            "candidate_mutated": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        planner._write_exclusive(
            path,
            planner._pretty_json({**material, "failure_content_sha256": planner._sealed(material)}),
        )
    except BaseException:
        return


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--model-url", default="http://127.0.0.1:8779")
    parser.add_argument("--timeout-seconds", type=float, default=240.0)
    parser.add_argument("--resume", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = _arguments()
    output_root = args.output_root.resolve()
    try:
        invoke = planner._http_invoker(args.model_url, args.timeout_seconds)
        result = build_repairs(
            output_root=output_root,
            invoke=invoke,
            started_at=datetime.now(UTC),
            resume=args.resume,
        )
    except BaseException as exc:
        _persist_failure(output_root, exc)
        raise
    print(
        json.dumps(
            {
                "output_root": str(args.output_root),
                "status": result["status"],
                "row_count": result["row_count"],
                "planned_row_count": result["planned_row_count"],
                "remaining_held_row_count": result["remaining_held_row_count"],
                "artifact_content_sha256": result["artifact_content_sha256"],
                "phase2b_authorized": result["phase2b_authorized"],
                "development30_authorized": result["development30_authorized"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
