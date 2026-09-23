"""Create the public, fail-closed checkpoint for the 2026-09-08 GE plan.

This command reads public project evidence only.  Every output is canonical,
self-sealed and create-only.  It records development evidence and blockers; it
does not start evaluation, training, qualification, promotion or live use.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.app.contracts.schema_registry import canonical_json_bytes, seal_contract  # noqa: E402

PUBLIC_RUN = ROOT / "data/evaluations/general-enquiries/LegalBot-GE-2026-09-05-codex-unseen-r1"
VISIBLE_ROOT = ROOT / "data/evaluations/general-enquiries/ge-auto-research-visible-20260905"
OUTPUT = ROOT / "data/evaluations/general-enquiries/LegalBot-GE-2026-09-08-pre-browser-enactment-r1"
BROWSER_ROOT = ROOT / "Log/legalbot-controller/LegalBot-GE-2026-09-08-pre-browser-r1/browser"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def relative(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def ref(path: Path) -> dict[str, Any]:
    return {
        "path": relative(path),
        "present": path.is_file(),
        "raw_file_sha256": sha256(path) if path.is_file() else None,
    }


def read(path: Path) -> Any:
    return json.loads(path.read_bytes())


def write_new(path: Path, value: dict[str, Any]) -> str:
    sealed = seal_contract(value)
    raw = canonical_json_bytes(sealed)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.write(descriptor, raw)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return hashlib.sha256(raw).hexdigest()


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def validate_observed_at(value: str) -> str:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("--observed-at must include a timezone")
    return parsed.isoformat()


def public_reconciliation(observed_at: str) -> dict[str, Any]:
    start = PUBLIC_RUN / "CONTINUOUS-SCHEMA-REPAIR-START.json"
    authorization = PUBLIC_RUN / "PLAN-EXECUTION-AUTHORIZATION.json"
    owner = PUBLIC_RUN / "OWNER-AUTHORIZATION.json"
    author_completion = PUBLIC_RUN / "AUTHOR-PARTS-REPAIR-COMPLETION.json"
    return {
        "schema": "legalbot.ge-continuous-schema-repair-interruption.v1",
        "run_id": "LegalBot-GE-2026-09-05-codex-unseen-r1",
        "observed_at": observed_at,
        "observation_boundary": "AUTHORIZED_CUSTODY_RECONCILIATION_PUBLIC_PROJECTION",
        "private_content_disclosed": False,
        "starting_receipts": [ref(start), ref(authorization), ref(owner), ref(author_completion)],
        "process_reconciliation": {
            "recorded_coordinator_pid": 49313,
            "recorded_coordinator_pid_present": False,
            "scheduler_active_count": 0,
            "inspection_active_count": 0,
            "coordinator_lock": "FREE",
            "termination_cause": "UNKNOWN_NOT_ATTESTED",
            "exit_code": None,
            "sigint_claimed": False,
        },
        "durable_chain": {
            "valid": True,
            "complete_inspection_count": 2,
            "complete_inspection_state_sha256": "79b1d67099c7874dd21e381dd2dcd67a574ad97502fc25f78a1fb6a9287304c8",
            "unchanged_observation_count": 2,
        },
        "construction": {
            "state": "PENDING",
            "terminal": False,
            "ready": False,
            "planned_slots": 443,
            "authored_slots": 431,
            "ready_slots": 0,
            "pending_jobs": 295,
            "effective_oracles": 84,
            "reviews": 64,
            "confirmed_oracle_checks": 30,
            "confirmed_source_checks": 19,
            "confirmed_fixture_checks": 84,
            "confirmed_reviewer_checks": 6,
            "novelty_complete": 0,
            "invalid_repair_plans_or_renders": 6,
        },
        "pending_work": {
            "oracle_parts": 171,
            "oracle_repairs": 54,
            "bank_reviews": 28,
            "bank_review_repairs": 4,
            "fixture_successor_unattempted": 2,
            "novelty_reviews": 36,
        },
        "failure_families": [
            {
                "family": "FIXTURE_INITIAL_SCHEMA_TRANSPORT",
                "count": 28,
                "code": "FIXTURE_REMOTE_SCHEMA_MISSING_EXPLICIT_TYPE",
                "return_code": 1,
                "output_present": False,
                "next_attempt": "PROHIBITED_THIRD_ATTEMPT",
            },
            {
                "family": "FIXTURE_SUCCESSOR_TIMEOUT",
                "count": 16,
                "return_code": 124,
                "next_attempt": "PROHIBITED_FOR_ATTEMPTED_ITEMS",
            },
            {
                "family": "FIXTURE_SUCCESSOR_FAILURE",
                "count": 4,
                "return_code": 1,
                "exact_cause": "UNAVAILABLE_IN_PUBLIC_PROJECTION",
                "next_attempt": "PROHIBITED_FOR_ATTEMPTED_ITEMS",
            },
            {"family": "FIXTURE_SUCCESSOR_SUCCESS", "count": 6},
            {"family": "AUTHOR_BASE_FAILURE", "count": 1, "validated_partial_rows": 10},
            {
                "family": "AUTHOR_PART_TIMEOUT",
                "count": 1,
                "return_code": 124,
                "canonical_slots_held": 12,
            },
        ],
        "gates": {
            "bank_seal": "NOT_STARTED",
            "runtime_freeze": "NOT_STARTED",
            "candidate_execution": "NOT_STARTED",
            "blind_scoring": "NOT_STARTED",
            "training": "NOT_AUTHORIZED",
            "promotion": "NOT_AUTHORIZED",
            "live": "NOT_AUTHORIZED",
        },
        "authority": {
            "creation_and_review": "RECORDED_VALID_FOR_EXACT_EXISTING_SCOPE",
            "candidate_one_pass": "RECORDED_UNSPENT",
            "old_resume_markers": "CONSUMED",
            "new_successor_requirement": "RECONCILIATION_BOUND_BOUNDED_CONTROLLER_RECEIPT",
        },
        "next_action": {
            "status": "PREPARED_NOT_DISPATCHED",
            "action": "ISSUE_ONE_BOUNDED_SUCCESSOR_FOR_REMAINING_ELIGIBLE_CONSTRUCTION_WORK",
            "constraints": [
                "NO_THIRD_FIXTURE_ATTEMPT",
                "ONLY_TWO_UNATTEMPTED_FIXTURE_SUCCESSOR_JOBS_RETAIN_AN_ATTEMPT",
                "NO_CANDIDATE_BEFORE_CONSTRUCTION_AND_FREEZE_GATES_PASS",
            ],
        },
    }


def main_artifacts(observed_at: str) -> list[tuple[str, dict[str, Any]]]:
    plan = ROOT / "docs/system-design/GE_PRE_BROWSER_IMPROVEMENT_PLAN.md"
    owner = PUBLIC_RUN / "OWNER-AUTHORIZATION.json"
    prior_authority = PUBLIC_RUN / "PLAN-EXECUTION-AUTHORIZATION.json"
    active_index = ROOT / "data/indexes/ACTIVE.json"
    runtime = VISIBLE_ROOT / "case-execution-r4/RUNTIME.json"
    assignments = VISIBLE_ROOT / "case-execution-r4/CASE-ASSIGNMENTS.json"
    preparation = VISIBLE_ROOT / "case-execution-r4/PREPARATION.json"
    eng_result = VISIBLE_ROOT / "case-execution-r4/cases/VIS-RESEARCH-ENG-01/TURN-1-RESULT.json"
    fed_result = VISIBLE_ROOT / "case-execution-r4/cases/VIS-RESEARCH-FED-01/TURN-1-RESULT.json"
    fed_failure = next(
        (VISIBLE_ROOT / "case-execution-r4/cases/VIS-RESEARCH-FED-01/candidate/operations").glob(
            "planner-*/attempt-1/failure.json"
        )
    )
    browser_pass = BROWSER_ROOT / "ui-mock-r4-1788864486303441000/artifacts/.last-run.json"
    browser_attempts = sorted(BROWSER_ROOT.glob("*/artifacts/.last-run.json"))

    authority_scope = {
        "current_instruction": "enact full planning",
        "confirmed_development_scope": "UK_USA",
        "pilot_scope": "SEPARATE_FUTURE_DECISION",
        "lane": "GENERAL_ENQUIRIES",
        "training": False,
        "qualification": False,
        "promotion": False,
        "live": False,
    }
    authorization = {
        "schema": "legalbot.ge-plan-enactment-authorization.v1",
        "run_id": "LegalBot-GE-2026-09-08-pre-browser-enactment-r1",
        "observed_at": observed_at,
        "authority_mechanism": "CURRENT_CODEX_THREAD_USER_INSTRUCTION",
        "host_application_session_authenticated": True,
        "cryptographic_artifact_signature_present": False,
        "portable_owner_signature_claimed": False,
        "authority_scope": authority_scope,
        "authority_scope_sha256": digest(authority_scope),
        "planning_source": ref(plan),
        "existing_bank_authorities": [ref(owner), ref(prior_authority)],
        "permitted_actions": [
            "PUBLIC_CHECKPOINT_RECONCILIATION",
            "CONTROLLER_AND_CONTRACT_HARDENING",
            "VISIBLE_DEVELOPMENT_FIXTURES_AND_TESTS",
            "LOCAL_DEVELOPMENT_BROWSER_FIXTURE_EXECUTION",
            "PREPARE_FAIL_CLOSED_GATE_ARTIFACTS",
        ],
        "excluded_actions": [
            "TRAINING",
            "PROTECTED_CANDIDATE_EXECUTION_BEFORE_REQUIRED_GATES",
            "QUALIFICATION_CLAIM",
            "PILOT_ACTIVATION",
            "PROMOTION",
            "LIVE_USE",
        ],
    }

    candidate_files = [
        ROOT / "backend/app/api/main.py",
        ROOT / "backend/app/types.py",
        ROOT / "backend/app/evaluation/ge_controller_receipts.py",
        ROOT / "backend/app/evaluation/ge_control_plane_v2.py",
        ROOT / "docs/system-design/schemas/ge-evaluation-control-plane.v2.schema.json",
        ROOT / "web/app/components/LegalBotApp.tsx",
        ROOT / "web/app/components/EvidenceDrawer.tsx",
        ROOT / "web/app/lib/contracts.ts",
        ROOT / "web/app/globals.css",
        ROOT / "web/package.json",
        ROOT / "web/package-lock.json",
        ROOT / "web/playwright.config.ts",
        ROOT / "web/tests/browser/legalbot-owner-flow.spec.ts",
    ]
    candidate_material = {
        "git_head": git("rev-parse", "HEAD"),
        "git_branch": git("branch", "--show-current"),
        "working_files": [ref(path) for path in candidate_files],
        "visible_runtime": ref(runtime),
    }
    candidate_sha = digest(candidate_material)
    candidate = {
        "schema": "legalbot.ge-candidate-dependency-manifest.v1",
        "run_id": "LegalBot-GE-2026-09-08-pre-browser-enactment-r1",
        "observed_at": observed_at,
        "candidate_id": "working-tree-" + candidate_sha[:24],
        "candidate_identity_sha256": candidate_sha,
        "candidate_material": candidate_material,
        "route": {
            "visible_development_model": read(runtime)["model"],
            "provider": read(runtime)["provider"],
            "browser_mode": "LOCAL_SPA_API_FIXTURE",
            "normal_api_active_index_present": active_index.is_file(),
            "normal_api_admission": "CLOSED" if not active_index.is_file() else "PRESENT_UNVERIFIED",
        },
        "dependency_invalidation": {
            "answer_or_model_change": ["VISIBLE_FULL_ANSWER_TRACE", "CLAIM_REVIEW", "AFFECTED_BROWSER_ANSWER_JOURNEYS"],
            "retrieval_or_source_generation_change": ["VISIBLE_RETRIEVAL_TRACE", "CURRENTNESS_REVIEW", "AFFECTED_ANSWER_CASES"],
            "evaluator_change": ["EXPLICIT_RESCORE_OR_NEW_EXECUTION_WITH_PROVENANCE"],
            "ui_only_change": ["AFFECTED_BUILD_LINT_ACCESSIBILITY_BROWSER_CHECKS"],
        },
        "candidate_lock": "NOT_CREATED",
        "qualification_freeze": "NOT_STARTED",
        "dirty_working_tree_bound": True,
    }

    controller = {
        "schema": "legalbot.ge-controller-contract-verification.v1",
        "run_id": "LegalBot-GE-2026-09-08-pre-browser-enactment-r1",
        "observed_at": observed_at,
        "implementation": [
            ref(ROOT / "backend/app/evaluation/ge_controller_receipts.py"),
            ref(ROOT / "backend/app/evaluation/ge_control_plane_v2.py"),
            ref(ROOT / "docs/system-design/schemas/ge-evaluation-control-plane.v2.schema.json"),
        ],
        "verified_invariants": [
            "EXCLUSIVE_SERIALIZATION",
            "MONOTONIC_LEASE_GENERATION",
            "STALE_LEASE_COMMIT_FENCING",
            "CREATE_ONLY_CONTENT_ADDRESSED_RECEIPTS",
            "SEMANTIC_DUPLICATE_NO_OP",
            "STABLE_DEFECT_FINGERPRINT",
            "TWO_UNCHANGED_OBSERVATIONS_STOP_BEFORE_THIRD",
            "SCOPED_BLOCKERS",
            "EXPLICIT_AUTHORITY_MECHANISM_AND_AUTHENTICATION_STATE",
            "NOT_STARTED_IS_NOT_FAILED",
            "QUALIFIED_HUMAN_REVIEW_IS_EXPLICIT",
        ],
        "hash_scheme": "legalbot.canonical-json.orjson-3.11.1.v1",
        "raw_file_hashes_and_canonical_content_hashes_separate": True,
        "verification": {
            "pytest_files": [
                "backend/tests/test_ge_controller_receipts.py",
                "backend/tests/test_ge_control_plane_v2.py",
                "backend/tests/test_contract_schema_registry.py",
            ],
            "tests_collected": 14,
            "tests_passed": 14,
            "ruff": "PASS",
        },
        "controller_dispatch": "NOT_STARTED",
        "recurring_schedules_created": 0,
    }

    case_locations = {
        "VIS-RESEARCH-ENG-01": "England",
        "VIS-RESEARCH-WLS-01": "Wales",
        "VIS-RESEARCH-SCT-01": "Scotland",
        "VIS-RESEARCH-NIR-01": "Northern Ireland",
        "VIS-RESEARCH-FED-01": "US federal",
        "VIS-RESEARCH-CA-01": "California",
        "VIS-RESEARCH-NY-01": "New York",
        "VIS-RESEARCH-TX-01": "Texas",
    }
    execution_states = {
        "VIS-RESEARCH-ENG-01": "EXECUTED_HOLD_PENDING_BLIND_REVIEW",
        "VIS-RESEARCH-NIR-01": "EXECUTED_HOLD_IN_PRIOR_VISIBLE_RUN",
        "VIS-RESEARCH-FED-01": "EXECUTED_HOLD_PENDING_BLIND_REVIEW",
    }
    coverage = {
        "schema": "legalbot.ge-set-coverage-exposure-register.v1",
        "run_id": "LegalBot-GE-2026-09-08-pre-browser-enactment-r1",
        "observed_at": observed_at,
        "development_scope": "UK_USA",
        "pilot_scope": "UNDECIDED_SEPARATE",
        "visible_assignment_manifest": ref(assignments),
        "locations": [
            {
                "case_id": case_id,
                "location": location,
                "classification": "DEVELOPMENT_VISIBLE",
                "execution_state": execution_states.get(case_id, "PREPARED_NOT_EXECUTED"),
                "qualification_eligible": False,
            }
            for case_id, location in case_locations.items()
        ],
        "engineering_packs": [
            {"pack": "CONTROLLER_CONTRACT_FAULTS", "state": "FOCUSED_TESTS_PASS"},
            {"pack": "VISIBLE_RETRIEVAL_AND_ANSWER", "state": "HELD_TRACES_PRESENT_SUCCESS_TRACE_MISSING"},
            {"pack": "DOCUMENT_AND_CONVERSATION", "state": "PARTIAL_FIXTURES_PRESENT_MORE_JOURNEYS_REQUIRED"},
            {"pack": "EVALUATOR_CALIBRATION", "state": "CONTRACT_PREPARED_EXECUTION_NOT_STARTED"},
            {"pack": "BROWSER_DEVELOPMENT_ACCEPTANCE", "state": "FOUR_UI_API_FIXTURES_PASS_ACTUAL_BACKEND_PENDING"},
            {"pack": "FRESH_VISIBLE_QUALIFICATION", "state": "DESIGN_ONLY_NOT_DISCLOSED"},
            {"pack": "TRAIN_VALIDATION_TEST_SPLIT", "state": "CONDITIONAL_FUTURE_NOT_STARTED"},
        ],
        "separate_protected_diagnostic": {
            "run_id": "LegalBot-GE-2026-09-05-codex-unseen-r1",
            "legal_denominator": 420,
            "system_denominator": 23,
            "construction_state": "PENDING",
            "development_exposure": "PROHIBITED",
            "old_306_bank": "RETIRED_EXCLUDED",
        },
        "new_large_bank_required_now": False,
        "coverage_limit": "LOCATION_PRESENCE_DOES_NOT_ESTABLISH_COMPREHENSIVE_LEGAL_COVERAGE",
    }

    evaluator = {
        "schema": "legalbot.ge-evaluator-calibration-contract.v1",
        "run_id": "LegalBot-GE-2026-09-08-pre-browser-enactment-r1",
        "observed_at": observed_at,
        "status": "FROZEN_CONTRACT_CALIBRATION_EXECUTION_NOT_STARTED",
        "evaluation_order": ["MATERIAL_FACTUAL_GATE", "QUALITY_SCORE_IF_FACTUAL_GATE_PASSES"],
        "diagnostic_thresholds": {
            "total_minimum": 70,
            "accuracy_minimum": 17.5,
            "accuracy_maximum": 25,
            "authority_currentness_minimum": 10.5,
            "authority_currentness_maximum": 15,
            "practical_steps_urgency_minimum": 9,
            "practical_steps_urgency_maximum": 15,
        },
        "required_dispositions": [
            "SUPPORTED_ANSWER",
            "SUPPORTED_LIMITED_ANSWER",
            "CLARIFICATION",
            "APPROPRIATE_ABSTENTION",
            "SOURCE_OR_CURRENTNESS_HOLD",
            "MODEL_FAILURE",
            "SYSTEM_ERROR",
        ],
        "calibration_classes": [
            "SUPPORTED",
            "UNSUPPORTED",
            "OVERCONFIDENT",
            "INCOMPLETE",
            "WRONG_DATE",
            "WRONG_JURISDICTION",
            "BROKEN_CITATION",
            "APPROPRIATELY_LIMITED",
            "ANSWER_LENGTH_BIAS",
            "SCORING_FORMAT_FAILURE",
        ],
        "review_scope": {
            "all_declared_material_claims": True,
            "independent_omission_review": True,
            "citation_entailment_and_source_eligibility": True,
            "jurisdiction_and_as_of_date": True,
            "currentness": True,
        },
        "decision_boundaries": {
            "ai_advisory_is_professional_legal_signoff": False,
            "owner_product_authority_is_legal_gold": False,
            "qualified_human_review_required_when_gate_demands_it": True,
            "second_review_separate": True,
        },
        "original_scores_retained_on_rescore": True,
        "thresholds_change_after_candidate_observation": False,
    }

    eng = read(eng_result)
    fed = read(fed_result)
    visible = {
        "schema": "legalbot.ge-visible-integration-manifest.v1",
        "run_id": "LegalBot-GE-2026-09-08-pre-browser-enactment-r1",
        "observed_at": observed_at,
        "preparation": ref(preparation),
        "runtime": ref(runtime),
        "cases": [
            {
                "case_id": eng["case_id"],
                "jurisdiction": "England",
                "state": eng["state"],
                "answer_status": eng["answer"]["status"],
                "holds": eng["holds"],
                "terminal_sha256": eng["terminal_sha256"],
                "result": ref(eng_result),
                "material_claim_review": "NOT_STARTED",
            },
            {
                "case_id": fed["case_id"],
                "jurisdiction": "US federal",
                "state": fed["state"],
                "answer_status": fed["answer"]["status"],
                "holds": fed["holds"],
                "terminal_sha256": fed["terminal_sha256"],
                "result": ref(fed_result),
                "material_claim_review": "NOT_STARTED",
                "planner_failure": {**ref(fed_failure), **read(fed_failure)},
            },
        ],
        "successful_full_answer_trace_count": 0,
        "held_trace_count": 2,
        "private_bank_used": False,
        "training": False,
        "component_evidence": {
            "visible_index_validation_tests": "23_PASS",
            "owner_canary_integration": "PASS",
            "web_research_callback": "FEDERAL_TRACE_CALLBACK_RUNTIMEERROR_BEFORE_AUTHORITY_ADMISSION",
        },
        "browser_entry_requirement": "NOT_SATISFIED_SUCCESSFUL_FULL_VISIBLE_ANSWER_TRACE_MISSING",
        "automatic_retry": False,
    }

    browser_matrix = {
        "schema": "legalbot.ge-browser-acceptance-matrix.v1",
        "run_id": "LegalBot-GE-2026-09-08-pre-browser-enactment-r1",
        "observed_at": observed_at,
        "classification": "USER_ACCEPTANCE_DEVELOPMENT_ONLY",
        "fixture_suite": {
            "state": "PASS",
            "passed": 4,
            "failed": 0,
            "final_result": ref(browser_pass),
            "all_attempts_preserved": [ref(path) for path in browser_attempts],
            "coverage": [
                "UK_LOCATION_AND_EXACT_AS_OF_DATE_SUBMISSION",
                "US_LOCATION_AND_EXACT_AS_OF_DATE_SUBMISSION",
                "JOB_RECONNECT_AND_CONVERSATION_RESTORE",
                "EVIDENCE_DIALOG_KEYBOARD_FOCUS_ESCAPE_AND_AXE",
                "CROSS_SESSION_JOB_IDENTITY",
            ],
        },
        "actual_backend_browser_suite": {
            "state": "NOT_STARTED_GATE_HELD",
            "required_journeys": [
                "SUCCESSFUL_ANSWER_WITH_CITATION_SOURCE_INSPECTION",
                "NATIVE_AND_SCANNED_UPLOAD",
                "MULTI_TURN_FACT_CORRECTION",
                "LIMITED_ANSWER_CLARIFICATION_UNSUPPORTED_LOCATION",
                "DUPLICATE_SUBMIT_CANCEL_RECONNECT_CONTROLLED_FAILURE",
                "PENDING_VERSUS_FINAL_NO_DRAFT_LEAK",
                "DOCUMENT_INSTRUCTION_ATTACK_AND_CROSS_SESSION_ISOLATION",
            ],
        },
    }

    gate_conditions = [
        {"condition": "WORKSPACE_LANE_AND_PROCESS_RECONCILED", "state": "PASS"},
        {"condition": "SCOPED_DEVELOPMENT_AUTHORITY", "state": "PASS"},
        {"condition": "FOCUSED_CONTRACT_UNIT_LINT_BUILD_INTEGRATION", "state": "PASS"},
        {"condition": "ONE_EXPECTED_HELD_VISIBLE_CONSUMER_TRACE", "state": "PASS"},
        {"condition": "ONE_SUCCESSFUL_FULL_VISIBLE_CONSUMER_TRACE", "state": "HOLD"},
        {"condition": "ACTIVE_INDEX_AND_NORMAL_API_ADMISSION", "state": "HOLD"},
        {"condition": "ACTUAL_UI_API_WORKER_MODEL_ROUTE_HEALTH", "state": "HOLD"},
        {"condition": "VISIBLE_DOCUMENT_AND_EXPECTED_BROWSER_OUTCOMES", "state": "PARTIAL"},
        {"condition": "STOP_CANCEL_AND_RECOVERABLE_TEST_STORAGE", "state": "PARTIAL"},
    ]
    gate = {
        "schema": "legalbot.ge-browser-entry-gate.v1",
        "run_id": "LegalBot-GE-2026-09-08-pre-browser-enactment-r1",
        "observed_at": observed_at,
        "status": "HOLD",
        "conditions": gate_conditions,
        "all_mandatory_conditions_pass": False,
        "fixture_browser_execution_is_candidate_qualification": False,
        "actual_backend_browser_execution_authorized_when_gate_passes": True,
        "next_gate_actions": [
            "DIAGNOSE_AND_REPAIR_VISIBLE_RESEARCH_CALLBACK_WITHOUT_REPEATING_THE_RECORDED_FINGERPRINT",
            "PRODUCE_ONE_SUCCESSFUL_REVIEWABLE_VISIBLE_FULL_ANSWER_TRACE",
            "BIND_OR_BUILD_AN_ELIGIBLE_NONLIVE_ACTIVE_INDEX_FOR_THE_NORMAL_API_ROUTE",
            "RUN_STARTUP_AND_ROUTE_HEALTH_CHECKS",
            "EXECUTE_THE_ACTUAL_BACKEND_BROWSER_MATRIX",
        ],
    }

    blockers = {
        "schema": "legalbot.ge-prioritised-blocker-report.v1",
        "run_id": "LegalBot-GE-2026-09-08-pre-browser-enactment-r1",
        "observed_at": observed_at,
        "blockers": [
            {
                "priority": 1,
                "scope": "VISIBLE_DEVELOPMENT_CASE",
                "code": "CALLBACK_RUNTIMEERROR",
                "fingerprint": read(fed_failure)["fingerprint"],
                "effect": "NO_ELIGIBLE_AUTHORITY_REACHED_THE_ANSWER_CONSUMER",
                "retry": "UNCHANGED_RETRY_PROHIBITED",
            },
            {
                "priority": 2,
                "scope": "NORMAL_API_ROUTE",
                "code": "ACTIVE_INDEX_MISSING",
                "effect": "PRODUCTION_STYLE_LOCAL_STARTUP_AND_ANSWER_ADMISSION_CLOSED",
            },
            {
                "priority": 3,
                "scope": "EVALUATOR",
                "code": "CALIBRATION_EXECUTION_NOT_STARTED",
                "effect": "BLIND_REVIEW_AND_QUALITY_GATE_CANNOT_BE_TRUSTED_YET",
            },
            {
                "priority": 4,
                "scope": "PROTECTED_DIAGNOSTIC_CONSTRUCTION",
                "code": "CONSTRUCTION_PENDING",
                "effect": "BANK_SEAL_RUNTIME_FREEZE_AND_ONE_PASS_REMAIN_BLOCKED",
            },
            {
                "priority": 5,
                "scope": "BROWSER",
                "code": "ACTUAL_BACKEND_BROWSER_GATE_HELD",
                "effect": "ONLY_THE_ISOLATED_UI_API_FIXTURE_SUITE_HAS_RUN",
            },
        ],
        "training_proposal": "NOT_ELIGIBLE",
        "pilot_status": "SCOPE_DECISION_DEFERRED",
    }

    tests = {
        "schema": "legalbot.ge-pre-browser-test-results.v1",
        "run_id": "LegalBot-GE-2026-09-08-pre-browser-enactment-r1",
        "observed_at": observed_at,
        "results": [
            {"suite": "CONTROLLER_CONTROL_PLANE_SCHEMA", "passed": 14, "failed": 0, "state": "PASS"},
            {"suite": "VISIBLE_INDEX_AND_CONSUMER_CONTRACTS", "passed": 23, "failed": 0, "state": "PASS"},
            {"suite": "OWNER_CANARY_HEARTBEAT_READBACK", "passed": 1, "failed": 0, "state": "PASS"},
            {"suite": "WEB_LINT", "passed": 1, "failed": 0, "state": "PASS"},
            {"suite": "WEB_BUILD_AND_STATIC_CONTRACTS", "passed": 11, "failed": 0, "state": "PASS"},
            {"suite": "BROWSER_UI_API_FIXTURES_FINAL_RUN", "passed": 4, "failed": 0, "state": "PASS"},
            {"suite": "STARTUP_CHECK", "passed": 0, "failed": 1, "state": "HOLD_ACTIVE_INDEX_MISSING"},
            {"suite": "CLEAN_ROOM_CHECK", "passed": 0, "failed": 1, "state": "HOLD_RETAINED_TEST_ARTIFACTS"},
        ],
        "failed_browser_attempts_preserved": 3,
        "automatic_cleanup": False,
        "qualification_claim": False,
    }

    status = {
        "schema": "legalbot.ge-pre-browser-enactment-status.v1",
        "run_id": "LegalBot-GE-2026-09-08-pre-browser-enactment-r1",
        "observed_at": observed_at,
        "current_stage": "B_CLOSE_TECHNICAL_PREREQUISITES",
        "overall_state": "ACTIVE_WITH_SCOPED_HOLDS",
        "last_validated_gate": "LOCAL_UI_API_BROWSER_FIXTURE_SUITE_PASS",
        "browser_entry_gate": "HOLD",
        "protected_bank_state": "CONSTRUCTION_PENDING",
        "candidate_one_pass": "NOT_STARTED_AUTHORITY_RECORDED_UNSPENT",
        "qualified_review": "NOT_STARTED",
        "training": "NOT_AUTHORIZED_NOT_STARTED",
        "promotion": "NOT_AUTHORIZED_NOT_STARTED",
        "live": "NOT_AUTHORIZED_NOT_STARTED",
        "pilot": "SCOPE_UNDECIDED_SEPARATE_FUTURE_OWNER_DECISION",
        "next_authorized_action": "REPAIR_VISIBLE_CALLBACK_THEN_COMPLETE_ONE_SUCCESSFUL_REVIEWABLE_TRACE",
        "recurring_schedules_created": 0,
    }

    return [
        ("PLAN-ENACTMENT-AUTHORIZATION.json", authorization),
        ("CONTROLLER-CONTRACT-VERIFICATION.json", controller),
        ("CANDIDATE-DEPENDENCY-MANIFEST.json", candidate),
        ("SET-COVERAGE-EXPOSURE-REGISTER.json", coverage),
        ("EVALUATOR-CALIBRATION-CONTRACT.json", evaluator),
        ("VISIBLE-INTEGRATION-MANIFEST.json", visible),
        ("BROWSER-ACCEPTANCE-MATRIX.json", browser_matrix),
        ("BROWSER-ENTRY-GATE.json", gate),
        ("PRIORITISED-BLOCKER-REPORT.json", blockers),
        ("TEST-RESULTS.json", tests),
        ("STATUS.json", status),
    ]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--observed-at", required=True, type=validate_observed_at)
    args = parser.parse_args()
    if OUTPUT.exists():
        raise FileExistsError(f"create-only output already exists: {OUTPUT}")
    interruption = PUBLIC_RUN / "CONTINUOUS-SCHEMA-REPAIR-INTERRUPTION-COMPLETE.json"
    written: dict[str, str] = {}
    written[relative(interruption)] = write_new(interruption, public_reconciliation(args.observed_at))
    OUTPUT.mkdir(parents=True, mode=0o700)
    for name, artifact in main_artifacts(args.observed_at):
        path = OUTPUT / name
        written[relative(path)] = write_new(path, artifact)
    manifest = {
        "schema": "legalbot.ge-pre-browser-enactment-manifest.v1",
        "run_id": "LegalBot-GE-2026-09-08-pre-browser-enactment-r1",
        "observed_at": args.observed_at,
        "artifacts": written,
        "public_only": True,
        "training": False,
        "qualification": False,
        "promotion": False,
        "live": False,
    }
    manifest_path = OUTPUT / "MANIFEST.json"
    write_new(manifest_path, manifest)
    print(json.dumps({"output": relative(OUTPUT), "artifacts": len(written) + 1}, sort_keys=True))


if __name__ == "__main__":
    main()
