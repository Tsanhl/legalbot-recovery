#!/usr/bin/env python3
"""Run the sealed candidate's private full-workflow completion preflight."""

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

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.config import Settings  # noqa: E402
from app.evaluation.candidate_completion_authority import (  # noqa: E402
    load_completion_memory_policy,
    load_readonly_sealed_candidate,
    write_create_only_private_safe_json,
)
from app.evaluation.candidate_completion_preflight import (  # noqa: E402
    run_candidate_completion_preflight,
)
from app.evaluation.candidate_completion_runtime import (  # noqa: E402
    LoopbackCandidateCompletionLauncher,
    _clean_integration_sha,
    build_local_completion_runtime_binding,
)
from app.evaluation.live_suite import load_live_evaluation_bundle  # noqa: E402
from app.evaluation.nonrelease_artifacts import sealed_safe_payload  # noqa: E402
from app.evaluation.owner_quality_canary_authorization import (  # noqa: E402
    OwnerDecisionRequired,
)
from app.governance.v111_decision_generation import (  # noqa: E402
    MEMORY_DECISION_OPTIONS,
    require_exact_clean_head,
)
from app.observability.live_metrics import load_slo_policy  # noqa: E402

DEFAULT_BUNDLE = PROJECT_ROOT / "benchmarks/evaluation/live-evaluation-60-v1"
_SAFE_CODE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--candidate-build-id", required=True)
    parser.add_argument("--as-of-date", required=True, type=date.fromisoformat)
    parser.add_argument("--bundle", type=Path, default=DEFAULT_BUNDLE)
    parser.add_argument(
        "--case-id",
        action="append",
        dest="case_ids",
        help=(
            "Add a sealed Live60 case. One deterministic representative per eligible "
            "route/word band is always selected without case-specific preference."
        ),
    )
    parser.add_argument("--model-start-timeout-seconds", type=float, default=900)
    parser.add_argument(
        "--memory-policy",
        type=Path,
        default=(PROJECT_ROOT / "data/evaluations/policies/completion-memory-policy.json"),
        help=(
            "Owner-private 0600 sealed memory envelope. Missing policy stops "
            "with OWNER_DECISION_REQUIRED; no default thresholds are inferred."
        ),
    )
    parser.add_argument(
        "--owner-decision-root",
        type=Path,
        default=PROJECT_ROOT / "data/evaluations/owner-decisions",
        help="Private OwnerDecisionStore root containing the exact memory request/resolution.",
    )
    return parser


def _safe_error_code(exc: BaseException) -> str:
    if isinstance(exc, OwnerDecisionRequired):
        return "OWNER_DECISION_REQUIRED"
    if isinstance(exc, RuntimeError) and exc.args:
        explicit = str(exc.args[0]).strip().casefold().replace("-", "_")
        if _SAFE_CODE.fullmatch(explicit):
            return explicit
    candidate = re.sub(r"(?<!^)(?=[A-Z])", "_", type(exc).__name__).casefold()
    return candidate if _SAFE_CODE.fullmatch(candidate) else "completion_preflight_failed"


def _write_owner_stop(args: argparse.Namespace, exc: OwnerDecisionRequired) -> dict[str, object]:
    reason_code = (
        exc.reason_code if _SAFE_CODE.fullmatch(exc.reason_code) else "owner_decision_required"
    )
    payload = sealed_safe_payload(
        {
            "schema": "legalbot.completion-preflight-owner-stop.v1",
            "run_id": str(args.run_id),
            "candidate_build_id": str(args.candidate_build_id),
            "status": "stopped",
            "error_code": "OWNER_DECISION_REQUIRED",
            "reason_code": reason_code,
            # The exact ID is candidate/runtime/host/HEAD-derived by the
            # create-v111-completion-memory-decision command.  This generic
            # stop must not route the owner to the stale fixed v1.11 request.
            "owner_decision_id": None,
            "owner_decision_generator": "create-v111-completion-memory-decision",
            "recommended_option_id": "max-12884901888-min-3221225472",
            "bounded_option_ids": sorted(MEMORY_DECISION_OPTIONS),
            "blocked_action": "candidate_completion_preflight_model_launch",
            "model_launch_attempted": False,
            "writes_active": False,
            "writes_o04": False,
            "created_at": datetime.now(UTC).isoformat(),
        }
    )
    date_root = (
        PROJECT_ROOT
        / "data/evaluations/completion-preflight-owner-stops"
        / datetime.now(UTC).date().isoformat()
    )
    safe_name = hashlib.sha256(str(args.run_id).encode()).hexdigest()[:24]
    write_create_only_private_safe_json(date_root / f"{safe_name}.json", payload)
    return payload


async def _run(args: argparse.Namespace) -> dict[str, object]:
    settings = Settings(project_root=PROJECT_ROOT)
    if not re.fullmatch(r"[a-z0-9][a-z0-9._:-]{2,127}", str(args.run_id)):
        raise ValueError("run ID must be a safe opaque identifier")
    if args.model_start_timeout_seconds <= 0:
        raise ValueError("model start timeout must be positive")
    if not settings.database_path.is_file():
        raise RuntimeError("catalogue_missing")
    bundle = load_live_evaluation_bundle(args.bundle)
    candidate = load_readonly_sealed_candidate(
        settings=settings,
        candidate_build_id=str(args.candidate_build_id),
    )
    slo_policy = load_slo_policy(settings.observability_slo_path)
    slo_policy_sha256 = hashlib.sha256(settings.observability_slo_path.read_bytes()).hexdigest()
    integration_sha = _clean_integration_sha(PROJECT_ROOT)
    require_exact_clean_head(PROJECT_ROOT, integration_sha)
    binding = build_local_completion_runtime_binding(
        settings=settings,
        candidate=candidate,
        slo_policy_id=slo_policy.policy_id,
        slo_policy_sha256=slo_policy_sha256,
        integration_sha=integration_sha,
    )
    memory_policy = load_completion_memory_policy(
        args.memory_policy,
        owner_decision_root=args.owner_decision_root,
        candidate=candidate,
        runtime_binding=binding,
        integration_sha=integration_sha,
    )
    run_date = datetime.now(UTC).date().isoformat()
    output_root = settings.evaluation_dir / "completion-preflight" / run_date
    isolation_root = (
        settings.evaluation_dir / "completion-preflight-runtime" / run_date / str(args.run_id)
    )
    require_exact_clean_head(PROJECT_ROOT, integration_sha)
    async with LoopbackCandidateCompletionLauncher(
        settings=settings,
        candidate=candidate,
        run_id=str(args.run_id),
        runtime_binding=binding,
        memory_policy=memory_policy,
        isolation_root=isolation_root,
        model_start_timeout_seconds=float(args.model_start_timeout_seconds),
    ) as runtime:
        return await run_candidate_completion_preflight(
            run_id=str(args.run_id),
            output_root=output_root,
            bundle=bundle,
            candidate=candidate,
            runtime=runtime,
            runtime_binding=binding,
            slo_policy=slo_policy,
            as_of_date=args.as_of_date,
            memory_policy=memory_policy,
            additional_case_ids=args.case_ids,
        )


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = asyncio.run(_run(args))
    except Exception as exc:
        owner_stop: dict[str, object] | None = None
        if isinstance(exc, OwnerDecisionRequired):
            try:
                owner_stop = _write_owner_stop(args, exc)
            except Exception:
                owner_stop = None
        print(
            json.dumps(
                {
                    "run_id": args.run_id,
                    "status": "stopped",
                    "error_code": _safe_error_code(exc),
                    "owner_decision_reason_code": (
                        exc.reason_code if isinstance(exc, OwnerDecisionRequired) else None
                    ),
                    "owner_stop_artifact_seal_sha256": (
                        owner_stop.get("seal_sha256") if owner_stop is not None else None
                    ),
                },
                sort_keys=True,
            )
        )
        return 2
    passed = result.get("completion_preflight_passed") is True
    print(
        json.dumps(
            {
                "run_id": args.run_id,
                "candidate_build_id": args.candidate_build_id,
                "status": result.get("status"),
                "completion_preflight_passed": passed,
                "artifact_seal_sha256": result.get("seal_sha256"),
            },
            sort_keys=True,
        )
    )
    return 0 if passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
