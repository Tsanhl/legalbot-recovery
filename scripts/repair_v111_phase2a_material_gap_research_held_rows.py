#!/usr/bin/env python3
"""Repair only the 93 r117 material-gap rows held after bounded attempts.

This is an append-only advisory pass under a materially changed execution
plan.  It verifies the exact r117 artifact and every source checkpoint, reuses
the 271 accepted plans byte-for-byte at the object level, and sends only the 93
held rows to the pinned local reviewer one row at a time.  It cannot decide an
owner outcome, admit a source, mutate a candidate, or authorize a later phase.
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

REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
R117_ROOT = (
    REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-26-r117-post-r116-stemmer-debug-gap-research-plans"
)
R117_ARTIFACT_NAME = "MATERIAL-GAP-RESEARCH-PLANS.json"
EXPECTED_R117_CONTENT_SHA256 = "e80f15aa2c517531581959aafd7bc956a4383c138fc8015613539549c2dd06fd"
EXPECTED_REUSED_PLAN_COUNT = 271
EXPECTED_HELD_ROW_COUNT = 93
EXPECTED_CHECKPOINT_COUNT = 112
DEFAULT_OUTPUT = REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-27-r118-held-gap-singleton-repair"


@dataclass(frozen=True, slots=True)
class SourceState:
    artifact: Mapping[str, Any]
    accepted_plans: tuple[Mapping[str, Any], ...]
    held_row_ids: tuple[str, ...]
    crosswalk_records: tuple[Mapping[str, Any], ...]
    top_level_file_sha256s: Mapping[str, str]


def _verify_top_level_checksums(root: Path) -> dict[str, str]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("phase2a_r118_r117_root_invalid")
    sums_path = root / "SHA256SUMS.txt"
    if sums_path.is_symlink() or not sums_path.is_file():
        raise ValueError("phase2a_r118_r117_checksums_missing")
    expected: dict[str, str] = {}
    for line in sums_path.read_text(encoding="utf-8").splitlines():
        digest, separator, name = line.partition("  ")
        if (
            not separator
            or not planner._SHA256.fullmatch(digest)
            or not name
            or "/" in name
            or name in expected
        ):
            raise ValueError("phase2a_r118_r117_checksums_invalid")
        expected[name] = digest
    required = {"INTENT.json", R117_ARTIFACT_NAME, "OUTCOME.txt"}
    if set(expected) != required:
        raise ValueError("phase2a_r118_r117_checksum_scope_invalid")
    for name, digest in expected.items():
        if planner._sha256_file(root / name) != digest:
            raise ValueError("phase2a_r118_r117_checksum_mismatch")
    return dict(sorted(expected.items()))


def _diagnostics_for_checkpoint(
    *, source_root: Path, checkpoint_path: Path, checkpoint: Mapping[str, Any]
) -> list[dict[str, Any]]:
    stem = checkpoint_path.stem
    paths = sorted((source_root / "diagnostics").glob(f"{stem}-a*.json"))
    values: list[dict[str, Any]] = []
    for expected_attempt, path in enumerate(paths, start=1):
        value = planner._load_object(path)
        planner._verify_seal(
            value,
            "diagnostic_content_sha256",
            "phase2a_r118_r117_diagnostic_seal_invalid",
        )
        if (
            value.get("batch_ordinal") != checkpoint.get("batch_ordinal")
            or value.get("row_ids") != checkpoint.get("row_ids")
            or value.get("attempt") != expected_attempt
        ):
            raise ValueError("phase2a_r118_r117_diagnostic_identity_invalid")
        values.append(value)
    return values


def _load_source_state(source_root: Path = R117_ROOT) -> SourceState:
    top_level = _verify_top_level_checksums(source_root)
    intent = planner._load_object(source_root / "INTENT.json")
    intent_digest = planner._verify_seal(
        intent,
        "intent_content_sha256",
        "phase2a_r118_r117_intent_seal_invalid",
    )
    artifact = planner._load_object(source_root / R117_ARTIFACT_NAME)
    artifact_digest = planner._verify_seal(
        artifact,
        "artifact_content_sha256",
        "phase2a_r118_r117_artifact_seal_invalid",
    )
    if (
        artifact_digest != EXPECTED_R117_CONTENT_SHA256
        or artifact.get("source_intent_content_sha256") != intent_digest
        or artifact.get("row_count") != planner.EXPECTED_GAP_COUNT
        or artifact.get("planned_row_count") != EXPECTED_REUSED_PLAN_COUNT
        or artifact.get("held_row_count") != EXPECTED_HELD_ROW_COUNT
        or artifact.get("phase2b_authorized") is not False
        or artifact.get("development30_authorized") is not False
        or artifact.get("candidate_mutated") is not False
    ):
        raise ValueError("phase2a_r118_r117_boundary_invalid")

    checkpoint_paths = sorted((source_root / "checkpoints").glob("*.json"))
    if len(checkpoint_paths) != EXPECTED_CHECKPOINT_COUNT:
        raise ValueError("phase2a_r118_r117_checkpoint_count_invalid")
    accepted_plans: list[Mapping[str, Any]] = []
    held_row_ids: list[str] = []
    crosswalk_records: list[Mapping[str, Any]] = []
    all_diagnostic_paths: set[Path] = set()
    for expected_ordinal, path in enumerate(checkpoint_paths, start=1):
        checkpoint = planner._load_checkpoint(path)
        if checkpoint.get("batch_ordinal") != expected_ordinal:
            raise ValueError("phase2a_r118_r117_checkpoint_sequence_invalid")
        row_ids = [str(row_id) for row_id in checkpoint.get("row_ids", [])]
        diagnostics = _diagnostics_for_checkpoint(
            source_root=source_root,
            checkpoint_path=path,
            checkpoint=checkpoint,
        )
        all_diagnostic_paths.update((source_root / "diagnostics").glob(f"{path.stem}-a*.json"))
        if checkpoint.get("schema") == "legalbot.v111.phase2a.gap-plan-checkpoint.v1":
            plans = checkpoint.get("plans")
            if (
                not isinstance(plans, list)
                or [str(plan.get("row_id") or "") for plan in plans] != row_ids
                or len(diagnostics) != int(checkpoint.get("attempt_count") or 0) - 1
            ):
                raise ValueError("phase2a_r118_r117_plan_checkpoint_invalid")
            accepted_plans.extend(dict(plan) for plan in plans)
            continue
        if (
            checkpoint.get("attempt_count") != 2
            or len(diagnostics) != 2
            or checkpoint.get("failure_fingerprints")
            != [item["failure_fingerprint"] for item in diagnostics]
        ):
            raise ValueError("phase2a_r118_r117_held_history_invalid")
        for row_id in row_ids:
            held_row_ids.append(row_id)
            crosswalk_records.append(
                {
                    "row_id": row_id,
                    "source_batch_ordinal": expected_ordinal,
                    "source_attempt_count": 2,
                    "source_attempt_error_codes": [str(item["error_code"]) for item in diagnostics],
                    "source_failure_fingerprints": [
                        str(item["failure_fingerprint"]) for item in diagnostics
                    ],
                    "source_same_failure_fingerprint_twice": checkpoint.get(
                        "same_failure_fingerprint_twice"
                    ),
                    "source_held_content_sha256": checkpoint["held_content_sha256"],
                }
            )
    diagnostic_paths = set((source_root / "diagnostics").glob("*.json"))
    if all_diagnostic_paths != diagnostic_paths:
        raise ValueError("phase2a_r118_r117_diagnostic_scope_invalid")

    artifact_plans = artifact.get("plans")
    artifact_held = artifact.get("held_row_ids")
    if (
        not isinstance(artifact_plans, list)
        or not isinstance(artifact_held, list)
        or accepted_plans != artifact_plans
        or held_row_ids != artifact_held
        or len({str(plan["row_id"]) for plan in accepted_plans}) != EXPECTED_REUSED_PLAN_COUNT
        or len(set(held_row_ids)) != EXPECTED_HELD_ROW_COUNT
        or {str(plan["row_id"]) for plan in accepted_plans} & set(held_row_ids)
    ):
        raise ValueError("phase2a_r118_r117_final_projection_invalid")
    return SourceState(
        artifact=artifact,
        accepted_plans=tuple(accepted_plans),
        held_row_ids=tuple(held_row_ids),
        crosswalk_records=tuple(crosswalk_records),
        top_level_file_sha256s=top_level,
    )


def _crosswalk(source: SourceState) -> dict[str, Any]:
    material = {
        "schema": "legalbot.v111.phase2a.r117-held-row-debug-crosswalk.v1",
        "source_r117_artifact_content_sha256": EXPECTED_R117_CONTENT_SHA256,
        "row_count": len(source.crosswalk_records),
        "records": [dict(record) for record in source.crosswalk_records],
        "execution_plan_changes": [
            "FOUR_ROW_HELD_BATCHES_SPLIT_INTO_ONE_ROW_INVOCATIONS",
            "EXACT_ROW_AND_CLASSIFICATION_VALIDATION_CONTEXT_ADDED",
            "EXPLICIT_240_CHARACTER_REPAIR_INSTRUCTION_ADDED",
            "COMPOUND_POSSESSIVE_AND_RECURSIVE_MORPHOLOGY_NORMALIZATION_ADDED",
            "NARROW_DOCUMENTED_ISSUE_ALIASES_ADDED_WITH_NEGATIVE_REGRESSION",
            "INVENTED_AUTHORITY_DETERMINISTIC_FALLBACK_LIMITED_TO_SINGLETONS",
        ],
        "accepted_r117_rows_will_not_be_reinvoked": True,
        "source_admission_authorized": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    return {**material, "artifact_content_sha256": planner._sealed(material)}


def _load_runtime_inputs(
    *,
    source: SourceState,
    triage_path: Path,
    cases_path: Path,
    catalogue_path: Path,
    candidate_manifest_path: Path,
) -> tuple[
    list[dict[str, Any]],
    dict[str, dict[str, Any]],
    Sequence[Any],
    frozenset[str],
    str,
    str,
    str,
]:
    gap_rows, triage_digest = planner._load_gap_rows(triage_path)
    cases = planner._load_cases(cases_path)
    candidate_authorities, candidate_digest, candidate_file_digest = planner._candidate_authorities(
        candidate_manifest_path
    )
    with planner._open_catalogue(catalogue_path) as connection:
        sources = planner._select_sources(connection, planner.TARGET_CEILING_DATE)
    registry_digest = planner._sealed(planner._selected_source_registry(sources))
    if registry_digest != planner.EXPECTED_SELECTED_SOURCE_REGISTRY_SHA256:
        raise ValueError("phase2a_r118_selected_source_registry_changed")
    by_id = {str(row["row_id"]): row for row in gap_rows}
    accepted_ids = {str(plan["row_id"]) for plan in source.accepted_plans}
    held_ids = set(source.held_row_ids)
    if (
        set(by_id) != accepted_ids | held_ids
        or accepted_ids & held_ids
        or any(row_id not in by_id for row_id in source.held_row_ids)
    ):
        raise ValueError("phase2a_r118_source_row_partition_invalid")
    repair_rows = [dict(by_id[row_id]) for row_id in source.held_row_ids]
    return (
        repair_rows,
        cases,
        sources,
        candidate_authorities,
        triage_digest,
        candidate_digest,
        candidate_file_digest,
    )


def _intent_material(
    *,
    started_at: datetime,
    source: SourceState,
    crosswalk_digest: str,
    triage_digest: str,
    candidate_digest: str,
    candidate_file_digest: str,
) -> dict[str, Any]:
    return {
        "schema": "legalbot.v111.phase2a.r117-held-row-singleton-repair-intent.v1",
        "status": "ADVISORY_SINGLETON_REPAIR_ONLY_NO_OWNER_DECISIONS",
        "started_at": started_at.astimezone(UTC).isoformat(timespec="seconds"),
        "source_r117_artifact_content_sha256": EXPECTED_R117_CONTENT_SHA256,
        "source_r117_top_level_file_sha256s": dict(source.top_level_file_sha256s),
        "source_crosswalk_content_sha256": crosswalk_digest,
        "source_triage_content_sha256": triage_digest,
        "source_candidate_manifest_sha256": candidate_digest,
        "source_candidate_manifest_file_sha256": candidate_file_digest,
        "source_selected_registry_sha256": (planner.EXPECTED_SELECTED_SOURCE_REGISTRY_SHA256),
        "source_reused_plan_count": len(source.accepted_plans),
        "repair_row_count": len(source.held_row_ids),
        "repair_row_ids": list(source.held_row_ids),
        "batch_count": len(source.held_row_ids),
        "maximum_rows_per_batch": 1,
        "maximum_attempts_per_row": 2,
        "maximum_runtime_transport_attempts_per_row": 1,
        "debug_required_before_any_third_attempt": True,
        "accepted_r117_rows_will_not_be_reinvoked": True,
        "prompt_sha256": planner._sha256((planner.SYSTEM_PROMPT + "\n").encode()),
        "planner_code_file_sha256": planner._sha256_file(Path(planner.__file__)),
        "repair_code_file_sha256": planner._sha256_file(Path(__file__).resolve()),
        "model_id": planner.EXPECTED_MODEL_ID,
        "model_version": planner.EXPECTED_MODEL_VERSION,
        "reviewer_execution_mode": planner.REVIEWER_EXECUTION_MODE,
        "model_independent_reviewer": False,
        "raw_model_output_persisted": False,
        "hidden_reasoning_persisted": False,
        "owner_decisions_applied": False,
        "source_admission_authorized": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }


def _prepare_output(
    *,
    output_root: Path,
    resume: bool,
    intent_material: Mapping[str, Any],
    crosswalk: Mapping[str, Any],
) -> dict[str, Any]:
    intent_path = output_root / "INTENT.json"
    crosswalk_path = output_root / "SOURCE-HELD-CROSSWALK.json"
    if output_root.exists() or output_root.is_symlink():
        if not resume or output_root.is_symlink() or not output_root.is_dir():
            raise ValueError("phase2a_r118_output_already_exists")
        if (output_root / "FAILURE.json").exists():
            raise ValueError("phase2a_r118_prior_top_level_failure_requires_new_revision")
        intent = planner._load_object(intent_path)
        planner._verify_seal(
            intent,
            "intent_content_sha256",
            "phase2a_r118_intent_seal_invalid",
        )
        source_crosswalk = planner._load_object(crosswalk_path)
        planner._verify_seal(
            source_crosswalk,
            "artifact_content_sha256",
            "phase2a_r118_crosswalk_seal_invalid",
        )
        stable_fields = (
            "source_r117_artifact_content_sha256",
            "source_crosswalk_content_sha256",
            "source_triage_content_sha256",
            "source_candidate_manifest_sha256",
            "source_candidate_manifest_file_sha256",
            "source_selected_registry_sha256",
            "repair_row_ids",
            "prompt_sha256",
            "planner_code_file_sha256",
            "repair_code_file_sha256",
        )
        if any(intent.get(field) != intent_material.get(field) for field in stable_fields):
            raise ValueError("phase2a_r118_resume_identity_mismatch")
        if source_crosswalk != crosswalk:
            raise ValueError("phase2a_r118_resume_crosswalk_mismatch")
    else:
        output_root.mkdir(parents=True, mode=0o700)
        if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
            raise ValueError("phase2a_r118_output_mode_invalid")
        intent = {
            **dict(intent_material),
            "intent_content_sha256": planner._sealed(intent_material),
        }
        planner._write_exclusive(intent_path, planner._pretty_json(intent))
        planner._write_exclusive(crosswalk_path, planner._pretty_json(crosswalk))
    (output_root / "checkpoints").mkdir(mode=0o700, exist_ok=True)
    (output_root / "diagnostics").mkdir(mode=0o700, exist_ok=True)
    return intent


def _merge_plans(
    *,
    gap_rows: Sequence[Mapping[str, Any]],
    source_plans: Sequence[Mapping[str, Any]],
    repair_plans: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    combined = [dict(plan) for plan in (*source_plans, *repair_plans)]
    by_id = {str(plan["row_id"]): plan for plan in combined}
    if len(by_id) != len(combined):
        raise ValueError("phase2a_r118_merged_plan_duplicate")
    order = [str(row["row_id"]) for row in gap_rows]
    return [by_id[row_id] for row_id in order if row_id in by_id]


def build_repairs(
    *,
    source_root: Path,
    triage_path: Path,
    cases_path: Path,
    catalogue_path: Path,
    candidate_manifest_path: Path,
    output_root: Path,
    invoke: planner.Invoke,
    started_at: datetime,
    resume: bool,
) -> dict[str, Any]:
    if started_at.tzinfo is None:
        raise ValueError("phase2a_r118_started_at_naive")
    source = _load_source_state(source_root)
    crosswalk = _crosswalk(source)
    (
        repair_rows,
        cases,
        sources,
        candidate_authorities,
        triage_digest,
        candidate_digest,
        candidate_file_digest,
    ) = _load_runtime_inputs(
        source=source,
        triage_path=triage_path,
        cases_path=cases_path,
        catalogue_path=catalogue_path,
        candidate_manifest_path=candidate_manifest_path,
    )
    intent_material = _intent_material(
        started_at=started_at,
        source=source,
        crosswalk_digest=str(crosswalk["artifact_content_sha256"]),
        triage_digest=triage_digest,
        candidate_digest=candidate_digest,
        candidate_file_digest=candidate_file_digest,
    )
    intent = _prepare_output(
        output_root=output_root,
        resume=resume,
        intent_material=intent_material,
        crosswalk=crosswalk,
    )
    merged_path = output_root / "MATERIAL-GAP-RESEARCH-PLANS-364.json"
    repairs_path = output_root / "SINGLETON-REPAIR-RESULTS-93.json"
    if merged_path.exists() or repairs_path.exists():
        raise ValueError("phase2a_r118_already_finalized")

    checkpoints_root = output_root / "checkpoints"
    diagnostics_root = output_root / "diagnostics"
    results: list[dict[str, Any]] = []
    for ordinal, row in enumerate(repair_rows, start=1):
        batch = [row]
        checkpoint_path = checkpoints_root / planner._checkpoint_name(ordinal, batch)
        if checkpoint_path.exists():
            if not resume:
                raise ValueError("phase2a_r118_checkpoint_exists_without_resume")
            checkpoint = planner._load_checkpoint(checkpoint_path)
            if checkpoint.get("batch_ordinal") != ordinal or checkpoint.get("row_ids") != [
                row["row_id"]
            ]:
                raise ValueError("phase2a_r118_checkpoint_identity_invalid")
        else:
            checkpoint = planner._review_batch(
                ordinal=ordinal,
                batch=batch,
                case=cases[str(row["case_id"])],
                sources=sources,
                candidate_authorities=candidate_authorities,
                invoke=invoke,
                checkpoints_root=checkpoints_root,
                diagnostics_root=diagnostics_root,
            )
        results.append(checkpoint)
        if checkpoint.get("nonrepairable_runtime_failure") is True:
            raise RuntimeError("phase2a_r118_runtime_failure_debug_required")

    repair_plans: list[dict[str, Any]] = []
    remaining_held: list[str] = []
    checkpoint_digests: list[str] = []
    for result in results:
        if result.get("schema") == "legalbot.v111.phase2a.gap-plan-held-batch.v1":
            remaining_held.extend(str(row_id) for row_id in result["row_ids"])
            checkpoint_digests.append(str(result["held_content_sha256"]))
        else:
            repair_plans.extend(dict(plan) for plan in result["plans"])
            checkpoint_digests.append(str(result["checkpoint_content_sha256"]))
    if len(repair_plans) + len(remaining_held) != EXPECTED_HELD_ROW_COUNT:
        raise ValueError("phase2a_r118_repair_coverage_invalid")

    repair_counts = Counter(str(plan["classification"]) for plan in repair_plans)
    repair_material = {
        "schema": "legalbot.v111.phase2a.r117-held-row-singleton-repairs.v1",
        "status": "ALL_R117_HELD_ROWS_PLANNED_UNDER_CHANGED_SINGLETON_PLAN"
        if not remaining_held
        else "SINGLETON_REPAIR_COMPLETE_WITH_REMAINING_HELD_ROWS",
        "source_intent_content_sha256": intent["intent_content_sha256"],
        "source_r117_artifact_content_sha256": EXPECTED_R117_CONTENT_SHA256,
        "source_crosswalk_content_sha256": crosswalk["artifact_content_sha256"],
        "repair_scope_row_count": EXPECTED_HELD_ROW_COUNT,
        "repaired_plan_count": len(repair_plans),
        "remaining_held_row_count": len(remaining_held),
        "remaining_held_row_ids": remaining_held,
        "classification_counts": dict(sorted(repair_counts.items())),
        "checkpoint_content_sha256s": checkpoint_digests,
        "plans": repair_plans,
        "accepted_r117_rows_reinvoked": False,
        "raw_model_output_persisted": False,
        "hidden_reasoning_persisted": False,
        "owner_decisions_applied": False,
        "source_admission_authorized": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    repair = {
        **repair_material,
        "artifact_content_sha256": planner._sealed(repair_material),
    }
    planner._write_exclusive(repairs_path, planner._pretty_json(repair))

    gap_rows, _ = planner._load_gap_rows(triage_path)
    merged_plans = _merge_plans(
        gap_rows=gap_rows,
        source_plans=source.accepted_plans,
        repair_plans=repair_plans,
    )
    if len(merged_plans) + len(remaining_held) != planner.EXPECTED_GAP_COUNT:
        raise ValueError("phase2a_r118_merged_coverage_invalid")
    merged_counts = Counter(str(plan["classification"]) for plan in merged_plans)
    selected_ids = {
        str(selection["authority_identity_id"])
        for plan in merged_plans
        for selection in plan["selections"]
    }
    merged_material = {
        "schema": "legalbot.v111.phase2a.material-gap-research-plans-with-singleton-repairs.v1",
        "status": "ADVISORY_GAP_PLANS_COMPLETE_OWNER_DECISIONS_AND_EVIDENCE_REVIEW_REQUIRED"
        if not remaining_held
        else "ADVISORY_GAP_PLANS_HAVE_REMAINING_HELD_ROWS_DEBUG_REQUIRED",
        "source_r117_artifact_content_sha256": EXPECTED_R117_CONTENT_SHA256,
        "source_repair_artifact_content_sha256": repair["artifact_content_sha256"],
        "source_triage_content_sha256": triage_digest,
        "reviewer_execution_mode": planner.REVIEWER_EXECUTION_MODE,
        "model_independent_reviewer": False,
        "row_count": planner.EXPECTED_GAP_COUNT,
        "reused_r117_plan_count": len(source.accepted_plans),
        "repaired_plan_count": len(repair_plans),
        "planned_row_count": len(merged_plans),
        "remaining_held_row_count": len(remaining_held),
        "remaining_held_row_ids": remaining_held,
        "classification_counts": dict(sorted(merged_counts.items())),
        "selected_authority_count": len(selected_ids),
        "plans": merged_plans,
        "proposition_evidence_verified": False,
        "owner_decisions_applied": False,
        "source_admission_authorized": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    merged = {
        **merged_material,
        "artifact_content_sha256": planner._sealed(merged_material),
    }
    planner._write_exclusive(merged_path, planner._pretty_json(merged))
    outcome = (
        f"{repair['status']}. {len(merged_plans)}/{planner.EXPECTED_GAP_COUNT} "
        "ROWS HAVE ADVISORY PLANS. OWNER DECISIONS AND EVIDENCE VERIFICATION "
        "REMAIN REQUIRED. PHASE 2B AND DEVELOPMENT 30 NOT AUTHORIZED.\n"
    )
    planner._write_exclusive(output_root / "OUTCOME.txt", outcome.encode("utf-8"))
    files = sorted(
        path for path in output_root.rglob("*") if path.is_file() and path.name != "SHA256SUMS.txt"
    )
    sums = "".join(
        f"{planner._sha256_file(path)}  {path.relative_to(output_root)}\n" for path in files
    )
    planner._write_exclusive(output_root / "SHA256SUMS.txt", sums.encode("utf-8"))
    return merged


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
        checkpoint_count = len(list((output_root / "checkpoints").glob("*.json")))
        error_code = planner._error_code(exc)
        fingerprint_material = {
            "affected_stage": "PHASE2A_R117_HELD_ROW_SINGLETON_REPAIR",
            "error_code": error_code,
            "source_r117_artifact_content_sha256": EXPECTED_R117_CONTENT_SHA256,
            "planner_code_file_sha256": planner._sha256_file(Path(planner.__file__)),
            "repair_code_file_sha256": planner._sha256_file(Path(__file__).resolve()),
        }
        material = {
            "schema": "legalbot.v111.phase2a.r118-top-level-failure.v1",
            "failure_fingerprint": planner._sealed(fingerprint_material),
            **fingerprint_material,
            "recorded_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "affected_rows": "UNFINISHED_R117_HELD_SINGLETON_SCOPE",
            "completed_checkpoint_count": checkpoint_count,
            "completed_work": "PRESERVED_BEFORE_EXCEPTION",
            "root_cause_status": "DEBUG_REQUIRED",
            "required_execution_plan_change": (
                "INSPECT_PERSISTED_DIAGNOSTICS_BEFORE_NEW_REVISION_OR_RETRY"
            ),
            "owner_decisions_applied": False,
            "source_admission_authorized": False,
            "automatic_indexing": False,
            "automatic_embedding": False,
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
    parser.add_argument("--source-root", type=Path, default=R117_ROOT)
    parser.add_argument("--triage", type=Path, default=planner.DEFAULT_TRIAGE)
    parser.add_argument("--cases", type=Path, default=planner.DEFAULT_CASES)
    parser.add_argument("--catalogue", type=Path, default=planner.DEFAULT_CATALOGUE)
    parser.add_argument(
        "--candidate-manifest",
        type=Path,
        default=planner.DEFAULT_CANDIDATE_MANIFEST,
    )
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
            source_root=args.source_root.resolve(strict=True),
            triage_path=args.triage.resolve(strict=True),
            cases_path=args.cases.resolve(strict=True),
            catalogue_path=args.catalogue.resolve(strict=True),
            candidate_manifest_path=args.candidate_manifest.resolve(strict=True),
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
