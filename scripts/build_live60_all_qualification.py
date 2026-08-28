#!/usr/bin/env python3
"""Derive one private exact 60-case/585-issue qualification artifact."""

from __future__ import annotations

import argparse
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
from app.evaluation.all60_evidence_review import (  # noqa: E402
    OWNER_DECISION_REQUIRED,
    All60OwnerDecisionRequired,
    load_all60_reviewer_batch_inputs,
)
from app.evaluation.all60_qualification import (  # noqa: E402
    build_exact_all60_qualification,
    require_trusted_all60_currentness_resolution,
    write_exact_all60_qualification,
)
from app.evaluation.candidate_completion_authority import (  # noqa: E402
    load_completion_memory_policy,
)
from app.evaluation.candidate_completion_runtime import (  # noqa: E402
    build_local_completion_runtime_binding,
)
from app.evaluation.live_suite import (  # noqa: E402
    load_live_evaluation_bundle,
    sealed_sha256,
)
from app.evaluation.live_suite_gold import load_suite_expert_qualification  # noqa: E402
from app.evaluation.live_suite_path_b import load_default_v2_repair  # noqa: E402
from app.evaluation.owner_quality_canary_authorization import (  # noqa: E402
    OwnerDecisionRequired,
)
from app.evaluation.sealed_candidate import load_sealed_candidate_identity  # noqa: E402
from app.observability.live_metrics import load_slo_policy  # noqa: E402
from app.retrieval.retrieval_reattest import _clean_integration_sha  # noqa: E402

DEFAULT_BUNDLE = PROJECT_ROOT / "benchmarks/evaluation/live-evaluation-60-v1"
_SAFE_CODE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-build-id", required=True)
    parser.add_argument("--as-of-date", required=True, type=date.fromisoformat)
    parser.add_argument("--expert-qualification", required=True, type=Path)
    parser.add_argument("--ai-review-batch-run-id", required=True)
    parser.add_argument("--ai-review-batch-run-date", required=True, type=date.fromisoformat)
    parser.add_argument("--output-directory", required=True, type=Path)
    parser.add_argument("--bundle", type=Path, default=DEFAULT_BUNDLE)
    return parser


def _safe_error_code(exc: BaseException) -> str:
    candidate = re.sub(r"(?<!^)(?=[A-Z])", "_", type(exc).__name__).casefold()
    return candidate if _SAFE_CODE.fullmatch(candidate) else "all60_qualification_failed"


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    settings = Settings(project_root=PROJECT_ROOT)
    database: Database | None = None
    try:
        if settings.online_default != "local_only" or settings.official_research_enabled:
            raise RuntimeError("offline_profile_required")
        database = Database(settings.database_path)
        bundle = load_live_evaluation_bundle(args.bundle.resolve())
        candidate = load_sealed_candidate_identity(
            settings=settings,
            database=database,
            candidate_build_id=str(args.candidate_build_id),
        )
        integration_sha = _clean_integration_sha(PROJECT_ROOT)
        expert = load_suite_expert_qualification(
            args.expert_qualification.resolve(),
            bundle=bundle,
            index_build_id=candidate.build_id,
            as_of_date=args.as_of_date,
            catalog_path=settings.database_path,
            repair=load_default_v2_repair(PROJECT_ROOT),
        )
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
        runtime_binding = build_local_completion_runtime_binding(
            settings=settings,
            candidate=candidate,
            slo_policy_id=slo_policy.policy_id,
            slo_policy_sha256=hashlib.sha256(
                settings.observability_slo_path.read_bytes()
            ).hexdigest(),
            integration_sha=integration_sha,
        )
        memory_policy = load_completion_memory_policy(
            settings.completion_memory_policy_path,
            owner_decision_root=settings.owner_decision_root,
            candidate=candidate,
            runtime_binding=runtime_binding,
            integration_sha=integration_sha,
        )
        ai_review_batch = load_verified_all60_ai_review_batch(
            evaluation_root=settings.evaluation_dir,
            run_date=args.ai_review_batch_run_date,
            run_id=str(args.ai_review_batch_run_id),
            bundle=bundle,
            candidate=candidate,
            expert=expert,
            required_as_of_date=args.as_of_date,
            runtime_binding=runtime_binding,
            memory_policy=memory_policy,
            candidate_build_root=settings.index_dir / "builds" / candidate.build_id,
        )
        qualification = build_exact_all60_qualification(
            bundle=bundle,
            candidate=candidate,
            expert_qualification=expert,
            required_as_of_date=args.as_of_date,
            candidate_build_root=settings.index_dir / "builds" / candidate.build_id,
            ai_review_batch=ai_review_batch,
        )
        write_exact_all60_qualification(
            output_directory=args.output_directory.resolve(),
            qualification=qualification,
        )
        print(
            json.dumps(
                {
                    "status": "created",
                    "schema": qualification.schema_name,
                    "candidate_build_id": qualification.candidate_build_id,
                    "case_count": qualification.case_count,
                    "issue_count": qualification.issue_count,
                    "seal_sha256": qualification.seal_sha256,
                },
                sort_keys=True,
            )
        )
        return 0
    except All60OwnerDecisionRequired as exc:
        print(
            json.dumps(
                {
                    "status": "stopped",
                    "state": OWNER_DECISION_REQUIRED,
                    "reason_code": exc.reason_code,
                    "row_id": exc.row_id,
                },
                sort_keys=True,
            )
        )
        return 3
    except OwnerDecisionRequired as exc:
        print(
            json.dumps(
                {
                    "status": "stopped",
                    "state": OWNER_DECISION_REQUIRED,
                    "reason_code": exc.reason_code,
                },
                sort_keys=True,
            )
        )
        return 3
    except Exception as exc:
        print(json.dumps({"status": "stopped", "error_code": _safe_error_code(exc)}))
        return 2
    finally:
        if database is not None:
            database.close()


if __name__ == "__main__":
    raise SystemExit(main())
