#!/usr/bin/env python3
"""Run the private candidate-pinned 585-issue AI evidence-review batch."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import re
import sys
from collections.abc import Sequence
from datetime import UTC, date, datetime
from pathlib import Path
from uuid import uuid4

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.config import Settings  # noqa: E402
from app.evaluation.all60_ai_review_batch import (  # noqa: E402
    load_verified_all60_ai_review_batch,
    run_authoritative_all60_ai_review_batch,
)
from app.evaluation.all60_evidence_review import (  # noqa: E402
    All60OwnerDecisionRequired,
    load_all60_reviewer_batch_inputs,
)
from app.evaluation.all60_qualification import (  # noqa: E402
    require_trusted_all60_currentness_resolution,
)
from app.evaluation.candidate_completion_authority import (  # noqa: E402
    load_completion_memory_policy,
    load_readonly_sealed_candidate,
)
from app.evaluation.candidate_completion_runtime import (  # noqa: E402
    LoopbackCandidateCompletionLauncher,
    _clean_integration_sha,
    build_local_completion_runtime_binding,
)
from app.evaluation.live_suite import load_live_evaluation_bundle, sealed_sha256  # noqa: E402
from app.evaluation.live_suite_gold import load_suite_expert_qualification  # noqa: E402
from app.evaluation.live_suite_path_b import load_default_v2_repair  # noqa: E402
from app.evaluation.owner_quality_canary_authorization import (  # noqa: E402
    OwnerDecisionRequired,
)
from app.observability.live_metrics import load_slo_policy  # noqa: E402

DEFAULT_BUNDLE = PROJECT_ROOT / "benchmarks/evaluation/live-evaluation-60-v1"
_SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9._:-]{2,127}$")
_SAFE_CODE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--candidate-build-id", required=True)
    parser.add_argument("--as-of-date", required=True, type=date.fromisoformat)
    parser.add_argument("--expert-qualification", required=True, type=Path)
    parser.add_argument("--bundle", type=Path, default=DEFAULT_BUNDLE)
    parser.add_argument("--run-date", type=date.fromisoformat)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--model-start-timeout-seconds", type=float, default=900)
    parser.add_argument(
        "--memory-policy",
        type=Path,
        default=(PROJECT_ROOT / "data/evaluations/policies/completion-memory-policy.json"),
        help="Owner-private 0600 memory envelope; missing authority stops before model launch.",
    )
    parser.add_argument(
        "--owner-decision-root",
        type=Path,
        default=PROJECT_ROOT / "data/evaluations/owner-decisions",
    )
    return parser


def _safe_error_code(exc: BaseException) -> str:
    if isinstance(exc, OwnerDecisionRequired | All60OwnerDecisionRequired):
        return "OWNER_DECISION_REQUIRED"
    if isinstance(exc, RuntimeError) and exc.args:
        explicit = str(exc.args[0]).strip().casefold().replace("-", "_")
        if _SAFE_CODE.fullmatch(explicit):
            return explicit
    candidate = re.sub(r"(?<!^)(?=[A-Z])", "_", type(exc).__name__).casefold()
    return candidate if _SAFE_CODE.fullmatch(candidate) else "all60_ai_review_batch_failed"


async def _run(args: argparse.Namespace) -> dict[str, object]:
    run_id = str(args.run_id)
    if not _SAFE_ID.fullmatch(run_id):
        raise ValueError("all60 review run ID is invalid")
    if args.model_start_timeout_seconds <= 0:
        raise ValueError("model start timeout must be positive")
    settings = Settings(project_root=PROJECT_ROOT)
    if settings.online_default != "local_only" or settings.official_research_enabled:
        raise RuntimeError("offline_profile_required")
    if not settings.database_path.is_file():
        raise RuntimeError("catalogue_missing")
    bundle = load_live_evaluation_bundle(args.bundle.resolve())
    candidate = load_readonly_sealed_candidate(
        settings=settings,
        candidate_build_id=str(args.candidate_build_id),
    )
    expert = load_suite_expert_qualification(
        args.expert_qualification.resolve(),
        bundle=bundle,
        index_build_id=candidate.build_id,
        as_of_date=args.as_of_date,
        catalog_path=settings.database_path,
        repair=load_default_v2_repair(PROJECT_ROOT),
    )
    integration_sha = _clean_integration_sha(PROJECT_ROOT)
    reviewer_inputs = load_all60_reviewer_batch_inputs(
        bundle=bundle,
        candidate=candidate,
        expert=expert,
        required_as_of_date=args.as_of_date,
        candidate_build_root=settings.index_dir / "builds" / candidate.build_id,
    )
    issue_identity_set_sha256 = sealed_sha256(
        {
            "schema": "legalbot.live60-all-issue-identity-set.v1",
            "issue_identity_sha256s": [item.issue_identity_sha256 for item in reviewer_inputs],
        }
    )
    require_trusted_all60_currentness_resolution(
        project_root=PROJECT_ROOT,
        candidate=candidate,
        required_as_of_date=args.as_of_date,
        all60_inventory_sha256=issue_identity_set_sha256,
        integration_sha=integration_sha,
    )
    slo_policy = load_slo_policy(settings.observability_slo_path)
    slo_policy_sha256 = hashlib.sha256(settings.observability_slo_path.read_bytes()).hexdigest()
    runtime_binding = build_local_completion_runtime_binding(
        settings=settings,
        candidate=candidate,
        slo_policy_id=slo_policy.policy_id,
        slo_policy_sha256=slo_policy_sha256,
        integration_sha=integration_sha,
    )
    memory_policy = load_completion_memory_policy(
        args.memory_policy.resolve(),
        owner_decision_root=args.owner_decision_root.resolve(),
        candidate=candidate,
        runtime_binding=runtime_binding,
        integration_sha=integration_sha,
    )
    run_date = args.run_date or datetime.now(UTC).date()
    runtime_session_id = f"all60-review-session-{uuid4().hex}"
    isolation_root = (
        settings.evaluation_dir
        / "completion-preflight-runtime"
        / run_date.isoformat()
        / runtime_session_id
    )
    async with LoopbackCandidateCompletionLauncher(
        settings=settings,
        candidate=candidate,
        run_id=runtime_session_id,
        runtime_binding=runtime_binding,
        memory_policy=memory_policy,
        isolation_root=isolation_root,
        model_start_timeout_seconds=float(args.model_start_timeout_seconds),
    ) as runtime:
        produced = await run_authoritative_all60_ai_review_batch(
            run_id=run_id,
            run_date=run_date,
            bundle=bundle,
            candidate=candidate,
            expert=expert,
            required_as_of_date=args.as_of_date,
            runtime=runtime,
            runtime_binding=runtime_binding,
            memory_policy=memory_policy,
            resume=bool(args.resume),
        )
    verified = load_verified_all60_ai_review_batch(
        evaluation_root=settings.evaluation_dir,
        run_date=run_date,
        run_id=run_id,
        bundle=bundle,
        candidate=candidate,
        expert=expert,
        required_as_of_date=args.as_of_date,
        runtime_binding=runtime_binding,
        memory_policy=memory_policy,
        candidate_build_root=settings.index_dir / "builds" / candidate.build_id,
    )
    if verified.attestation != produced:
        raise RuntimeError("all60_reviewer_post_run_replay_mismatch")
    return verified.attestation.model_dump(mode="json", by_alias=True)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = asyncio.run(_run(args))
    except Exception as exc:
        print(
            json.dumps(
                {
                    "run_id": str(args.run_id),
                    "status": "stopped",
                    "error_code": _safe_error_code(exc),
                    "owner_decision_reason_code": (
                        exc.reason_code
                        if isinstance(exc, OwnerDecisionRequired | All60OwnerDecisionRequired)
                        else None
                    ),
                    "owner_decision_id": (
                        exc.decision_id if isinstance(exc, All60OwnerDecisionRequired) else None
                    ),
                    "writes_active": False,
                    "writes_o04": False,
                    "model_launch_attempted": False
                    if isinstance(exc, OwnerDecisionRequired | All60OwnerDecisionRequired)
                    else None,
                },
                sort_keys=True,
            )
        )
        return 2
    print(
        json.dumps(
            {
                "run_id": str(args.run_id),
                "status": "completed",
                "case_count": result["case_count"],
                "issue_count": result["issue_count"],
                "checkpoint_count": result["checkpoint_count"],
                "artifact_seal_sha256": result["seal_sha256"],
                "qualification_eligible": result["qualification_eligible"],
                "writes_active": False,
                "writes_o04": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
