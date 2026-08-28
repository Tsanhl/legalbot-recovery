"""Fail-closed API admission for owner-authorised Live60 execution.

V1 production authorization continues to require O-04 and ACTIVE.
V2 evaluation authorization uses a separate evaluation-only path pinned to
the candidate build. It does not write ACTIVE and does not issue O-04.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

from ..config import Settings
from ..crypto import LocalCipher
from ..db import Database
from ..orchestration.classifier import classify_task
from ..orchestration.routing import decide_route
from ..types import QuestionRequest
from .live_suite import LiveEvaluationBundle, load_live_evaluation_bundle
from .live_suite_evaluation_auth import (
    EVALUATION_AUTHORIZATION_V2_SCHEMA,
    load_evaluation_authorization_v2,
    verify_evaluation_runtime_bindings,
)
from .live_suite_execute import (
    live60_evaluation_request_sha256,
    live60_evaluation_request_sha256_v2,
    verify_execution_prerequisites,
)
from .live_suite_http_execute import Live60RuntimeBinding, verify_live60_runtime_bindings
from .live_suite_store import LiveSuiteRunStore

_SAFE_RUN_ID = re.compile(r"^[a-z0-9][a-z0-9._:-]{2,127}$")


@dataclass(frozen=True, slots=True)
class Live60AdmissionBinding:
    request_sha256: str
    expected_route: str
    runtime: Live60RuntimeBinding
    evaluation_mode: bool = False
    candidate_build_id: str | None = None


@dataclass(frozen=True, slots=True)
class Live60EvaluationAdmissionBinding:
    request_sha256: str
    evaluation_run_id: str
    case_id: str
    candidate_build_id: str
    authorization_seal_sha256: str
    overlay_seal_sha256: str
    stage_a_result_sha256: str
    expected_route: str
    as_of_date: str
    writes_active: bool = False


def _run_suite_id(settings: Settings, run_id: str) -> str | None:
    if _SAFE_RUN_ID.fullmatch(run_id) is None:
        raise ValueError("invalid evaluation run identity")
    runs = (settings.e2e_observability_dir / "runs").resolve()
    manifest_path = (runs / run_id / "manifest.json").resolve()
    if not manifest_path.is_relative_to(runs) or not manifest_path.is_file():
        raise ValueError("unknown evaluation run identity")
    value = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("evaluation run manifest is invalid")
    suite_id = value.get("suite_id")
    return str(suite_id) if isinstance(suite_id, str) else None


def _validate_shared_case_contract(
    *,
    bundle: LiveEvaluationBundle,
    case_id: str,
    payload: QuestionRequest,
    as_of_date: str,
) -> str:
    case = bundle.registry.case(case_id)
    plan_case = next(item for item in bundle.run_plan.cases if item.case_id == case_id)
    if plan_case.disposition != "generate_once":
        raise ValueError("Live60 run plan does not authorize this case")
    if hashlib.sha256(payload.question.encode("utf-8")).hexdigest() != case.question_sha256:
        raise ValueError("Live60 question differs from its immutable registry")
    if (
        str(payload.task_type) != case.task_type
        or payload.jurisdiction != case.jurisdiction
        or payload.as_of_date is None
        or payload.as_of_date.isoformat() != as_of_date
        or payload.word_target != case.word_target
        or str(payload.online_mode) != "local_only"
        or payload.upload_ids
    ):
        raise ValueError("Live60 request fields differ from the immutable case contract")
    task_type = classify_task(payload.question, payload.task_type)
    route = decide_route(payload.question, payload.word_target, task_type).route.value
    if route != case.expected_research_route:
        raise ValueError("server route differs from the sealed Live60 route")
    return route


def _admit_evaluation_v2(
    *,
    settings: Settings,
    run_id: str,
    case_id: str,
    payload: QuestionRequest,
    authorization_path: Path,
    bundle: LiveEvaluationBundle,
    database: Database | None = None,
) -> Live60EvaluationAdmissionBinding:
    authorization = load_evaluation_authorization_v2(authorization_path)
    if authorization.evaluation_run_id != run_id:
        raise ValueError("evaluation authorization belongs to another run")
    if case_id not in authorization.authorized_case_ids:
        raise ValueError("coverage-only Live60 case cannot be admitted for generation")
    owned = database
    close_owned = False
    if owned is None:
        owned = Database(settings.database_path)
        close_owned = True
    try:
        row = owned.fetchone(
            "SELECT id, status FROM index_builds WHERE id=?",
            (authorization.candidate_build_id,),
        )
        if row is None or str(row["status"]) not in {"candidate", "active"}:
            raise ValueError("evaluation candidate build is missing or not sealed")
        verify_evaluation_runtime_bindings(
            authorization=authorization,
            candidate_build_id=authorization.candidate_build_id,
            active_build_id=owned.active_index_id(),
            database=owned,
            fallback_to_active=False,
        )
    finally:
        if close_owned:
            owned.close()
    if (
        authorization.suite_manifest_seal_sha256 != bundle.manifest.seal_sha256
        or authorization.run_plan_seal_sha256 != bundle.run_plan.seal_sha256
    ):
        raise ValueError("evaluation authorization is bound to a different suite")
    route = _validate_shared_case_contract(
        bundle=bundle,
        case_id=case_id,
        payload=payload,
        as_of_date=authorization.as_of_date,
    )
    request_sha256 = live60_evaluation_request_sha256_v2(
        bundle=bundle,
        authorization=authorization,
        case_id=case_id,
        route=route,
    )
    return Live60EvaluationAdmissionBinding(
        request_sha256=request_sha256,
        evaluation_run_id=authorization.evaluation_run_id,
        case_id=case_id,
        candidate_build_id=authorization.candidate_build_id,
        authorization_seal_sha256=authorization.seal_sha256,
        overlay_seal_sha256=authorization.overlay_seal_sha256,
        stage_a_result_sha256=authorization.stage_a_result_sha256,
        expected_route=route,
        as_of_date=authorization.as_of_date,
        writes_active=False,
    )


def validate_live60_api_admission(
    *,
    settings: Settings,
    cipher: LocalCipher,
    run_id: str,
    case_id: str,
    payload: QuestionRequest,
    database: Database | None = None,
) -> Live60AdmissionBinding | Live60EvaluationAdmissionBinding | None:
    """Validate Live60 gates. V2 evaluation uses the evaluation-only path."""

    if _run_suite_id(settings, run_id) != "live-evaluation-60-v1":
        return None
    bundle = load_live_evaluation_bundle(
        settings.project_root / "benchmarks/evaluation/live-evaluation-60-v1"
    )
    store = LiveSuiteRunStore(settings.project_root, cipher)
    authorization_path = (
        settings.e2e_observability_dir / "runs" / run_id / "execution-authorization.json"
    )
    if authorization_path.is_file():
        raw_auth = json.loads(authorization_path.read_text(encoding="utf-8"))
        if isinstance(raw_auth, dict) and raw_auth.get("schema") == (
            EVALUATION_AUTHORIZATION_V2_SCHEMA
        ):
            return _admit_evaluation_v2(
                settings=settings,
                run_id=run_id,
                case_id=case_id,
                payload=payload,
                authorization_path=authorization_path,
                bundle=bundle,
                database=database,
            )
    preflight = verify_execution_prerequisites(
        store=store,
        bundle=bundle,
        run_id=run_id,
        authorization_path=authorization_path,
        require_sealed_case_artifacts=True,
    )
    if case_id not in preflight.generated_case_ids:
        raise ValueError("coverage-only Live60 case cannot be admitted for generation")
    if case_id not in preflight.evidence_ready_case_ids:
        raise ValueError("Live60 case is not evidence-ready for model generation")
    route = _validate_shared_case_contract(
        bundle=bundle,
        case_id=case_id,
        payload=payload,
        as_of_date=preflight.run_manifest.as_of_date,
    )
    runtime = verify_live60_runtime_bindings(
        project_root=settings.project_root,
        bundle=bundle,
        preflight=preflight,
        base_url=f"http://{settings.host}:{settings.port}",
    )
    request_sha256 = live60_evaluation_request_sha256(
        bundle=bundle,
        preflight=preflight,
        case_id=case_id,
        route=route,
    )
    return Live60AdmissionBinding(
        request_sha256=request_sha256,
        expected_route=route,
        runtime=runtime,
        evaluation_mode=False,
        candidate_build_id=None,
    )
