#!/usr/bin/env python3
"""Run or resume create-only Stage A v2 against one sealed candidate."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import re
import sys
from collections.abc import Sequence
from datetime import date
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.config import Settings  # noqa: E402
from app.db import Database  # noqa: E402
from app.evaluation.all60_ai_review_batch import (  # noqa: E402
    load_verified_all60_ai_review_batch,
)
from app.evaluation.all60_qualification import (  # noqa: E402
    ExactAll60Qualification,
    load_replayed_exact_all60_qualification,
)
from app.evaluation.candidate_completion_authority import (  # noqa: E402
    load_completion_memory_policy,
)
from app.evaluation.candidate_completion_preflight import (  # noqa: E402
    load_verified_authoritative_completion_preflight,
)
from app.evaluation.candidate_completion_runtime import (  # noqa: E402
    build_local_completion_runtime_binding,
)
from app.evaluation.live_suite import load_live_evaluation_bundle  # noqa: E402
from app.evaluation.live_suite_gold import (  # noqa: E402
    load_suite_expert_qualification,
)
from app.evaluation.live_suite_stage_a_v2_runner import (  # noqa: E402
    run_stage_a_v2_create_only,
)
from app.evaluation.sealed_candidate import (  # noqa: E402
    load_sealed_candidate_identity,
)
from app.observability.live_metrics import load_slo_policy  # noqa: E402
from app.retrieval.pinned_factory import PinnedRetrieverFactory  # noqa: E402
from app.retrieval.retrieval_reattest import _clean_integration_sha  # noqa: E402

DEFAULT_BUNDLE = PROJECT_ROOT / "benchmarks/evaluation/live-evaluation-60-v1"
_SAFE_CODE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--candidate-build-id", required=True)
    parser.add_argument("--as-of-date", required=True, type=date.fromisoformat)
    parser.add_argument("--all60-qualification", required=True, type=Path)
    parser.add_argument("--expert-qualification", required=True, type=Path)
    parser.add_argument("--completion-preflight-run", required=True, type=Path)
    parser.add_argument("--bundle", type=Path, default=DEFAULT_BUNDLE)
    return parser


def _safe_error_code(exc: BaseException) -> str:
    candidate = re.sub(r"(?<!^)(?=[A-Z])", "_", type(exc).__name__).casefold()
    if isinstance(exc, RuntimeError) and exc.args:
        explicit = str(exc.args[0]).strip().casefold().replace("-", "_")
        if _SAFE_CODE.fullmatch(explicit):
            candidate = explicit
    return candidate if _SAFE_CODE.fullmatch(candidate) else "stage_a_failed"


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    settings = Settings(project_root=PROJECT_ROOT)
    database: Database | None = None
    try:
        if settings.online_default != "local_only" or settings.official_research_enabled:
            raise RuntimeError("offline_profile_required")
        if not settings.database_path.is_file():
            raise RuntimeError("catalogue_missing")
        bundle = load_live_evaluation_bundle(args.bundle)
        database = Database(settings.database_path)
        candidate = load_sealed_candidate_identity(
            settings=settings,
            database=database,
            candidate_build_id=str(args.candidate_build_id),
        )
        supplied_qualification = ExactAll60Qualification.model_validate_json(
            args.all60_qualification.read_bytes()
        )
        if supplied_qualification.as_of_date != args.as_of_date:
            raise RuntimeError("all60_qualification_currentness_date_mismatch")
        expert_qualification = load_suite_expert_qualification(
            args.expert_qualification,
            bundle=bundle,
            index_build_id=candidate.build_id,
            as_of_date=args.as_of_date,
            catalog_path=settings.database_path,
        )
        code_revision = _clean_integration_sha(PROJECT_ROOT)
        slo_policy = load_slo_policy(settings.observability_slo_path)
        runtime_binding = build_local_completion_runtime_binding(
            settings=settings,
            candidate=candidate,
            slo_policy_id=slo_policy.policy_id,
            slo_policy_sha256=hashlib.sha256(
                settings.observability_slo_path.read_bytes()
            ).hexdigest(),
            integration_sha=code_revision,
        )
        memory_policy = load_completion_memory_policy(
            settings.completion_memory_policy_path,
            owner_decision_root=settings.owner_decision_root,
            candidate=candidate,
            runtime_binding=runtime_binding,
            integration_sha=code_revision,
        )
        ai_review_batch = load_verified_all60_ai_review_batch(
            evaluation_root=settings.evaluation_dir,
            run_date=supplied_qualification.ai_review_batch_run_date,
            run_id=supplied_qualification.ai_review_batch_run_id,
            bundle=bundle,
            candidate=candidate,
            expert=expert_qualification,
            required_as_of_date=args.as_of_date,
            runtime_binding=runtime_binding,
            memory_policy=memory_policy,
            candidate_build_root=settings.index_dir / "builds" / candidate.build_id,
        )
        all60_qualification = load_replayed_exact_all60_qualification(
            args.all60_qualification,
            bundle=bundle,
            candidate=candidate,
            candidate_build_root=settings.index_dir / "builds" / candidate.build_id,
            expert_qualification_path=args.expert_qualification,
            ai_review_batch=ai_review_batch,
            catalog_path=settings.database_path,
            project_root=PROJECT_ROOT,
            integration_sha=code_revision,
        )
        toolchain = runtime_binding.get("model_toolchain")
        if not isinstance(toolchain, dict):
            raise RuntimeError("completion_preflight_runtime_binding_invalid")
        completion_preflight = load_verified_authoritative_completion_preflight(
            args.completion_preflight_run,
            project_root=PROJECT_ROOT,
            memory_policy=memory_policy,
            expected_candidate_build_id=candidate.build_id,
            expected_candidate_manifest_sha256=candidate.candidate_manifest_sha256,
            expected_integration_sha=code_revision,
            expected_runtime_binding_sha256=str(runtime_binding["seal_sha256"]),
            expected_trusted_toolchain_identity_sha256=str(
                toolchain["trusted_toolchain_identity_sha256"]
            ),
            expected_base_python_runtime_manifest_sha256=str(
                toolchain["base_python_runtime_manifest_sha256"]
            ),
            expected_venv_control_manifest_sha256=str(toolchain["venv_control_manifest_sha256"]),
        )
        if completion_preflight.get("completion_preflight_passed") is not True:
            raise RuntimeError("authoritative_completion_preflight_not_passed")
        retriever = PinnedRetrieverFactory(settings, database).for_build(candidate.build_id)
        code_dirty = False
        result = asyncio.run(
            run_stage_a_v2_create_only(
                run_id=str(args.run_id),
                output_root=settings.evaluation_dir / "stage-a-v2",
                bundle=bundle,
                candidate=candidate,
                all60_qualification=all60_qualification,
                expert_qualification=expert_qualification,
                retriever=retriever,
                as_of_date=args.as_of_date,
                code_revision=code_revision,
                code_dirty=code_dirty,
                database=database,
                completion_preflight_verified_result_sha256=str(
                    completion_preflight["seal_sha256"]
                ),
            )
        )
        passed = result.get("stage_a_passed") is True
        print(
            json.dumps(
                {
                    "run_id": args.run_id,
                    "candidate_build_id": candidate.build_id,
                    "status": result.get("run_status", result.get("status")),
                    "stage_a_passed": passed,
                    "artifact_seal_sha256": result.get("seal_sha256"),
                },
                sort_keys=True,
            )
        )
        return 0 if passed else 2
    except Exception as exc:
        print(
            json.dumps(
                {
                    "run_id": args.run_id,
                    "status": "stopped",
                    "error_code": _safe_error_code(exc),
                },
                sort_keys=True,
            )
        )
        return 2
    finally:
        if database is not None:
            database.close()


if __name__ == "__main__":
    raise SystemExit(main())
